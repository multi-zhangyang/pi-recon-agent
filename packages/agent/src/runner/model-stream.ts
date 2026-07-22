import { type AssistantMessage, type Context, streamSimple } from "@pi-recon/repi-ai";
import type { AgentContext, AgentLoopConfig, StreamFn } from "../types.ts";
import { compactConsumedToolResults, defaultMaxConsumedToolResultChars } from "./context-projection.ts";
import { AgentEventDeliveryError, type AgentEventSink, emitAndCollectFailure } from "./events.ts";
import { isRetryableAgentError } from "./recovery-policy.ts";
import { synthesizeAbortedToolCallResults } from "./tool-execution.ts";

/**
 * Stream an assistant response from the LLM.
 * This is where AgentMessage[] gets transformed to Message[] for the LLM.
 *
 * When {@link AgentLoopConfig.streamMaxRetries} is set, a request that fails
 * BEFORE the stream emits any content (no `message_start` reached the consumer)
 * is retried with exponential backoff. This is safe — nothing has been emitted,
 * so there is nothing to duplicate or lose. Once streaming has started, errors
 * are surfaced immediately (partial output is never replayed). A retry is the
 * same turn re-attempted and does NOT count toward `maxTurns`.
 */
export async function streamAssistantResponse(
	context: AgentContext,
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
	streamFn?: StreamFn,
): Promise<AssistantMessage> {
	const maxRetries =
		typeof config.streamMaxRetries === "number" && config.streamMaxRetries > 0
			? Math.floor(config.streamMaxRetries)
			: 0;
	const baseDelay =
		typeof config.streamRetryBaseDelayMs === "number" && config.streamRetryBaseDelayMs > 0
			? config.streamRetryBaseDelayMs
			: 1000;
	const maxDelay =
		typeof config.streamRetryMaxDelayMs === "number" && config.streamRetryMaxDelayMs > 0
			? config.streamRetryMaxDelayMs
			: 30000;
	const isRetryable =
		config.isRetryableStreamError ??
		((message: AssistantMessage) =>
			isRetryableAgentError(message, { contextWindow: config.model.contextWindow, allowUnknown: true }));

	for (let attempt = 0; ; attempt++) {
		// Per-attempt setup: re-resolve context + expiring API key + open a fresh stream.
		let messages = context.messages;
		if (config.transformContext) {
			messages = await config.transformContext(messages, signal);
		}
		messages = compactConsumedToolResults(
			messages,
			config.maxConsumedToolResultChars ?? defaultMaxConsumedToolResultChars(config.model.contextWindow),
		);
		const llmMessages = await config.convertToLlm(messages);
		const llmContext: Context = {
			systemPrompt: context.systemPrompt,
			messages: llmMessages,
			tools: context.tools,
		};
		const streamFunction = streamFn || streamSimple;
		const resolvedApiKey =
			(config.getApiKey ? await config.getApiKey(config.model.provider) : undefined) || config.apiKey;

		const response = await streamFunction(config.model, llmContext, {
			...config,
			apiKey: resolvedApiKey,
			signal,
		});

		let partialMessage: AssistantMessage | null = null;
		let addedPartial = false;
		let finalMessage: AssistantMessage | null = null;

		try {
			for await (const event of response) {
				switch (event.type) {
					case "start":
						partialMessage = event.partial;
						context.messages.push(partialMessage);
						addedPartial = true;
						await emit({ type: "message_start", message: { ...partialMessage } });
						break;

					case "text_start":
					case "text_delta":
					case "text_end":
					case "thinking_start":
					case "thinking_delta":
					case "thinking_end":
					case "toolcall_start":
					case "toolcall_delta":
					case "toolcall_end":
						if (partialMessage) {
							partialMessage = event.partial;
							context.messages[context.messages.length - 1] = partialMessage;
							await emit({
								type: "message_update",
								assistantMessageEvent: event,
								message: { ...partialMessage },
							});
						}
						break;

					case "done":
					case "error": {
						finalMessage = await response.result();
						if (addedPartial) {
							context.messages[context.messages.length - 1] = finalMessage;
						}
						break;
					}
				}
				if (finalMessage) break;
			}
		} catch (streamError) {
			// A throw during streaming — a harness "*" subscriber throwing inside
			// emit on a message_update, or the stream's async iterator throwing
			// mid-stream. If a partial was already streamed, best-effort commit it
			// as an error/aborted message_end BEFORE re-throwing, so the durable
			// transcript retains the partial text the UI already saw AND the
			// consumer's run-failure handler (harness emitRunFailure / Agent
			// handleRunFailure) can observe that a real assistant was already
			// committed and avoid synthesizing a phantom duplicate lifecycle on
			// top of it (opt #97 F1-phantom). Re-throw so the consumer surfaces the
			// error via its run-failure path with only the terminal events that
			// haven't fired yet. (Best-effort emit: a broken sink must not mask the
			// original stream error.)
			if (addedPartial && partialMessage) {
				const deliveryErrors: unknown[] = [];
				partialMessage.stopReason = signal?.aborted ? "aborted" : "error";
				partialMessage.errorMessage = streamError instanceof Error ? streamError.message : String(streamError);
				try {
					await emit({ type: "message_end", message: partialMessage });
				} catch (error) {
					deliveryErrors.push(error);
				}
				// Foundational opt #261 (throw path): if the committed partial
				// already contains COMPLETE toolCall blocks (toolcall_end fired
				// before the throw), synthesize an isError tool_result per id
				// BEFORE re-throwing. The re-throw routes to the consumer's
				// run-failure handler which emits only turn_end/agent_end — without
				// these synthesized results the committed tool_use would be
				// orphaned (no matching tool_result) → the next provider request
				// 400s "tool_use must be followed by tool_result". Best-effort: a
				// broken sink must not mask the original stream error.
				const partial = partialMessage;
				if (partial.content.some((c) => c.type === "toolCall")) {
					try {
						const orphanToolCalls = partial.content.filter((c) => c.type === "toolCall");
						const synthesized = await synthesizeAbortedToolCallResults(
							orphanToolCalls,
							[],
							config,
							emit,
							deliveryErrors,
						);
						for (const result of synthesized) {
							context.messages.push(result);
						}
					} catch {
						// best-effort: never mask the original stream error
					}
				}
				if (deliveryErrors.length > 0) {
					throw new AgentEventDeliveryError(deliveryErrors, streamError);
				}
			}
			throw streamError;
		}

		if (!finalMessage) {
			// Defense-in-depth: the stream ended without a done/error terminal
			// event (e.g. a proxy whose SSE body closed cleanly but never pushed
			// `done`). EventStream.end() with no result argument now REJECTS
			// finalResultPromise (opt #97 F8 — previously it stayed pending, so
			// `await response.result()` hung forever). agentLoop does NOT call
			// result() in this branch (it synthesizes its own error below), so
			// attach a rejection handler to keep F8's rejection from surfacing as
			// an unhandled rejection. The synthesized error is the authoritative
			// surface; the swallowed rejection is just the stream's "no result"
			// signal, which we already handle.
			response.result().catch(() => {});
			if (addedPartial && partialMessage) {
				partialMessage.stopReason = signal?.aborted ? "aborted" : "error";
				partialMessage.errorMessage = signal?.aborted
					? "Operation aborted"
					: "Stream ended without a terminal event";
				finalMessage = partialMessage;
				context.messages[context.messages.length - 1] = finalMessage;
			} else {
				finalMessage = {
					role: "assistant",
					content: [],
					api: config.model.api,
					provider: config.model.provider,
					model: config.model.id,
					usage: {
						input: 0,
						output: 0,
						cacheRead: 0,
						cacheWrite: 0,
						totalTokens: 0,
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
					},
					stopReason: signal?.aborted ? "aborted" : "error",
					errorMessage: signal?.aborted ? "Operation aborted" : "Stream ended without a terminal event",
					timestamp: Date.now(),
				};
				// Leave addedPartial false so the commit path pushes this message
				// and emits message_start + message_end (no partial was streamed).
			}
		}

		// Retry decision: only when the request failed before ANY content reached
		// the consumer (no message_start emitted → nothing to duplicate), retries
		// remain, the run was not aborted, and the error is retryable.
		if (
			finalMessage.stopReason === "error" &&
			!addedPartial &&
			attempt < maxRetries &&
			!signal?.aborted &&
			isRetryable(finalMessage)
		) {
			const delay = Math.min(baseDelay * 2 ** attempt, maxDelay);
			await abortableSleep(delay, signal);
			if (signal?.aborted) {
				// Aborted during backoff: the original failure is no longer the
				// recorded outcome — the user aborted. Rewrite stopReason/errorMessage
				// to "aborted" so the committed message reflects the real cause
				// (mirrors the partial-message abort path below). Pre-fix this
				// committed the error message verbatim, so a user abort during
				// retry backoff was recorded as a transient API error.
				finalMessage.stopReason = "aborted";
				finalMessage.errorMessage = "Operation aborted";
				context.messages.push(finalMessage);
				await emit({ type: "message_start", message: { ...finalMessage } });
				await emit({ type: "message_end", message: finalMessage });
				return finalMessage;
			}
			continue;
		}

		// Commit both lifecycle halves, collecting delivery failures so a broken
		// start listener cannot suppress message_end persistence.
		const deliveryErrors: unknown[] = [];
		if (!addedPartial) {
			context.messages.push(finalMessage);
			await emitAndCollectFailure({ type: "message_start", message: { ...finalMessage } }, emit, deliveryErrors);
		}
		await emitAndCollectFailure({ type: "message_end", message: finalMessage }, emit, deliveryErrors);
		if (deliveryErrors.length > 0) {
			const toolCalls = finalMessage.content.filter((block) => block.type === "toolCall");
			if (toolCalls.length > 0) {
				const synthesized = await synthesizeAbortedToolCallResults(toolCalls, [], config, emit, deliveryErrors);
				context.messages.push(...synthesized);
			}
			throw new AgentEventDeliveryError(deliveryErrors);
		}
		return finalMessage;
	}
}

/**
 * Resolves after `ms` or as soon as `signal` aborts, whichever is first.
 * The timer is unref'd so it never keeps the event loop alive on its own.
 */
function abortableSleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
	if (ms <= 0) return Promise.resolve();
	if (!signal) {
		return new Promise((resolve) => {
			const timer = setTimeout(resolve, ms);
			timer.unref?.();
		});
	}
	if (signal.aborted) return Promise.resolve();
	return new Promise((resolve) => {
		const onAbort = () => {
			clearTimeout(timer);
			signal.removeEventListener("abort", onAbort);
			resolve();
		};
		const timer = setTimeout(() => {
			signal.removeEventListener("abort", onAbort);
			resolve();
		}, ms);
		timer.unref?.();
		signal.addEventListener("abort", onAbort, { once: true });
	});
}

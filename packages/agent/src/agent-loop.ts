/**
 * Agent loop that works with AgentMessage throughout.
 * Transforms to Message[] only at the LLM call boundary.
 */

import {
	type AssistantMessage,
	type Context,
	EventStream,
	type ImageContent,
	streamSimple,
	type TextContent,
	type ToolResultMessage,
	validateToolArguments,
} from "@pi-recon/repi-ai";
import { safeHeadEnd, safeTailStart } from "./harness/utils/truncate.ts";
import type {
	AgentContext,
	AgentEvent,
	AgentLoopConfig,
	AgentMessage,
	AgentTool,
	AgentToolCall,
	AgentToolResult,
	StreamFn,
} from "./types.ts";

export type AgentEventSink = (event: AgentEvent) => Promise<void> | void;

/**
 * Default defense-in-depth cap (in chars) on a tool result's text content at the
 * context boundary. See {@link AgentLoopConfig.maxToolResultChars}.
 */
export const DEFAULT_MAX_TOOL_RESULT_CHARS = 256 * 1024;

/**
 * Start an agent loop with a new prompt message.
 * The prompt is added to the context and events are emitted for it.
 */
export function agentLoop(
	prompts: AgentMessage[],
	context: AgentContext,
	config: AgentLoopConfig,
	signal?: AbortSignal,
	streamFn?: StreamFn,
): EventStream<AgentEvent, AgentMessage[]> {
	const stream = createAgentStream();

	void runAgentLoop(
		prompts,
		context,
		config,
		async (event) => {
			stream.push(event);
		},
		signal,
		streamFn,
	)
		.then((messages) => {
			stream.end(messages);
		})
		.catch(() => {
			// Without this catch, a rejection from runAgentLoop (e.g. a throw in
			// transformContext/convertToLlm/getApiKey, or an emit() failure outside
			// the per-tool try/catch) would both become an unhandled rejection AND
			// leave stream.end() uncalled — so a consumer iterating the EventStream
			// would hang forever. End the stream (resolving its result to []) so
			// consumers unblock; the internal Agent path surfaces real errors via
			// its own lifecycle try/catch (agent.ts runWithLifecycle).
			stream.end([]);
		});

	return stream;
}

/**
 * Continue an agent loop from the current context without adding a new message.
 * Used for retries - context already has user message or tool results.
 *
 * **Important:** The last message in context must convert to a `user` or `toolResult` message
 * via `convertToLlm`. If it doesn't, the LLM provider will reject the request.
 * This cannot be validated here since `convertToLlm` is only called once per turn.
 */
export function agentLoopContinue(
	context: AgentContext,
	config: AgentLoopConfig,
	signal?: AbortSignal,
	streamFn?: StreamFn,
): EventStream<AgentEvent, AgentMessage[]> {
	if (context.messages.length === 0) {
		throw new Error("Cannot continue: no messages in context");
	}

	if (context.messages[context.messages.length - 1].role === "assistant") {
		throw new Error("Cannot continue from message role: assistant");
	}

	const stream = createAgentStream();

	void runAgentLoopContinue(
		context,
		config,
		async (event) => {
			stream.push(event);
		},
		signal,
		streamFn,
	)
		.then((messages) => {
			stream.end(messages);
		})
		.catch(() => {
			// See agentLoop: prevent an unhandled rejection + an EventStream that
			// hangs forever if runAgentLoopContinue rejects.
			stream.end([]);
		});

	return stream;
}

export async function runAgentLoop(
	prompts: AgentMessage[],
	context: AgentContext,
	config: AgentLoopConfig,
	emit: AgentEventSink,
	signal?: AbortSignal,
	streamFn?: StreamFn,
): Promise<AgentMessage[]> {
	const newMessages: AgentMessage[] = [...prompts];
	const currentContext: AgentContext = {
		...context,
		messages: [...context.messages, ...prompts],
	};

	await emit({ type: "agent_start" });
	await emit({ type: "turn_start" });
	for (const prompt of prompts) {
		await emit({ type: "message_start", message: prompt });
		await emit({ type: "message_end", message: prompt });
	}

	await runLoop(currentContext, newMessages, config, signal, emit, streamFn);
	return newMessages;
}

export async function runAgentLoopContinue(
	context: AgentContext,
	config: AgentLoopConfig,
	emit: AgentEventSink,
	signal?: AbortSignal,
	streamFn?: StreamFn,
): Promise<AgentMessage[]> {
	if (context.messages.length === 0) {
		throw new Error("Cannot continue: no messages in context");
	}

	if (context.messages[context.messages.length - 1].role === "assistant") {
		throw new Error("Cannot continue from message role: assistant");
	}

	const newMessages: AgentMessage[] = [];
	// Copy the messages array (not just the context object). runLoop mutates
	// currentContext.messages in place (push + index assignment); a shallow
	// {...context} copy shares the caller's messages array reference, so any
	// future caller passing a long-lived array (e.g. state.messages directly)
	// would have it mutated. runAgentLoop copies explicitly below; match it.
	const currentContext: AgentContext = { ...context, messages: [...context.messages] };

	await emit({ type: "agent_start" });
	await emit({ type: "turn_start" });

	await runLoop(currentContext, newMessages, config, signal, emit, streamFn);
	return newMessages;
}

function createAgentStream(): EventStream<AgentEvent, AgentMessage[]> {
	return new EventStream<AgentEvent, AgentMessage[]>(
		(event: AgentEvent) => event.type === "agent_end",
		(event: AgentEvent) => (event.type === "agent_end" ? event.messages : []),
	);
}

/**
 * Main loop logic shared by agentLoop and agentLoopContinue.
 */
async function runLoop(
	initialContext: AgentContext,
	newMessages: AgentMessage[],
	initialConfig: AgentLoopConfig,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
	streamFn?: StreamFn,
): Promise<void> {
	let currentContext = initialContext;
	let config = initialConfig;
	let firstTurn = true;
	let turnCount = 0;
	const maxTurns = typeof config.maxTurns === "number" && config.maxTurns > 0 ? config.maxTurns : 0;
	const lengthContinueMax =
		typeof config.lengthContinueMaxTurns === "number" && config.lengthContinueMaxTurns > 0
			? Math.floor(config.lengthContinueMaxTurns)
			: 0;
	let lengthContinueCount = 0;
	// Check for steering messages at start (user may have typed while waiting)
	let pendingMessages: AgentMessage[] = (await config.getSteeringMessages?.()) || [];

	// Outer loop: continues when queued follow-up messages arrive after agent would stop
	while (true) {
		let hasMoreToolCalls = true;

		// Inner loop: process tool calls and steering messages
		while (hasMoreToolCalls || pendingMessages.length > 0) {
			if (!firstTurn) {
				await emit({ type: "turn_start" });
			} else {
				firstTurn = false;
			}

			// Process pending messages (inject before next assistant response)
			if (pendingMessages.length > 0) {
				for (const message of pendingMessages) {
					await emit({ type: "message_start", message });
					await emit({ type: "message_end", message });
					currentContext.messages.push(message);
					newMessages.push(message);
				}
				pendingMessages = [];
			}

			// Stream assistant response
			const message = await streamAssistantResponse(currentContext, config, signal, emit, streamFn);
			newMessages.push(message);
			turnCount++;

			if (message.stopReason === "error" || message.stopReason === "aborted") {
				// Foundational opt #261: a streamed assistant that FINALIZED with
				// stopReason "error"/"aborted" can already contain COMPLETE toolCall
				// blocks — a provider rate-limit/5xx landing AFTER the last
				// toolcall_end (the partial carries the accumulated tool_use), a user
				// abort landing after toolcall_end, or the no-terminal-event resolve
				// path (stream ended cleanly without a `done`, line ~515) committing
				// the partial. The assistant (with tool_use) is already committed to
				// the durable transcript via message_end, but this early return emits
				// turn_end/agent_end with NO tool_result for those ids → the
				// transcript is unbalanced → the next provider request 400s
				// ("tool_use must be followed by tool_result"). Mirror the
				// abort-during-execution synthesis (line ~284): synthesize an isError
				// tool_result per un-finalized tool_use id before the terminal events.
				const orphanToolCalls = message.content.filter((c) => c.type === "toolCall");
				const errorToolResults: ToolResultMessage[] = [];
				if (orphanToolCalls.length > 0) {
					const synthesized = await synthesizeAbortedToolCallResults(orphanToolCalls, [], config, emit);
					for (const result of synthesized) {
						errorToolResults.push(result);
						currentContext.messages.push(result);
						newMessages.push(result);
					}
				}
				await emit({ type: "turn_end", message, toolResults: errorToolResults });
				await emit({ type: "agent_end", messages: newMessages });
				return;
			}

			// Check for tool calls
			const toolCalls = message.content.filter((c) => c.type === "toolCall");

			const toolResults: ToolResultMessage[] = [];
			hasMoreToolCalls = false;
			if (toolCalls.length > 0) {
				// Foundational opt #134: a "length" stopReason (max_tokens) can cut a
				// tool_use block off mid-arguments. The provider's parseStreamingJson
				// silently closes the incomplete JSON (e.g.
				// {"command":"rm -rf /opt/da → {"command":"rm -rf /opt/da"}), so the
				// finalized toolCall has TRUNCATED but parseable arguments. Executing
				// it would run a tool (Bash/Edit/...) with a half-completed
				// command/path — destructive and unrecoverable — and the model gets
				// no signal its args were truncated, so it cannot self-correct.
				// Instead, convert each truncated call into an isError tool_result
				// (NOT executed) instructing the model to re-emit the complete call,
				// then loop back (hasMoreToolCalls) so it does — bounded by maxTurns.
				const executedToolBatch =
					message.stopReason === "length"
						? await synthesizeTruncatedToolCallResults(toolCalls, config, signal, emit)
						: await executeToolCalls(currentContext, message, config, signal, emit);
				toolResults.push(...executedToolBatch.messages);
				hasMoreToolCalls = !executedToolBatch.terminate;

				for (const result of toolResults) {
					currentContext.messages.push(result);
					newMessages.push(result);
				}

				// Abort check after tool execution: if the signal fired during tool
				// execution (executeToolCalls breaks on abort but still returns the
				// partial batch pushed above), stop here instead of iterating back
				// into streamAssistantResponse — which would burn one wasted provider
				// request (transformContext + convertToLlm + an immediately-aborted
				// stream) on an already-aborted run.
				if (signal?.aborted) {
					// Foundational opt: the executors break on abort after pushing
					// results only for the tools that got far enough, leaving orphan
					// tool_use blocks whose ids have no matching tool_result. Synthesize
					// an error tool_result for each un-finalized tool_use id so the
					// transcript stays balanced (every tool_use is followed by a
					// tool_result) — otherwise the next request 400s. See
					// synthesizeAbortedToolCallResults for the full rationale.
					const synthesizedAborted = await synthesizeAbortedToolCallResults(toolCalls, toolResults, config, emit);
					for (const result of synthesizedAborted) {
						toolResults.push(result);
						currentContext.messages.push(result);
						newMessages.push(result);
					}
					await emit({ type: "turn_end", message, toolResults });
					await emit({ type: "agent_end", messages: newMessages });
					return;
				}
			}

			await emit({ type: "turn_end", message, toolResults });

			// Foundational turn budget: stop gracefully after the in-flight turn
			// completes when the cap is reached, before another provider request.
			if (maxTurns > 0 && turnCount >= maxTurns) {
				try {
					config.onRunBudgetExceeded?.({ turns: turnCount, maxTurns });
				} catch {
					// Side-effect channel only; never interrupt the stop.
				}
				await emit({ type: "agent_end", messages: newMessages });
				return;
			}

			const nextTurnContext = {
				message,
				toolResults,
				context: currentContext,
				newMessages,
			};
			const nextTurnSnapshot = await config.prepareNextTurn?.(nextTurnContext);
			if (nextTurnSnapshot) {
				currentContext = nextTurnSnapshot.context ?? currentContext;
				config = {
					...config,
					model: nextTurnSnapshot.model ?? config.model,
					reasoning:
						nextTurnSnapshot.thinkingLevel === undefined
							? config.reasoning
							: nextTurnSnapshot.thinkingLevel === "off"
								? undefined
								: nextTurnSnapshot.thinkingLevel,
				};
			}

			if (
				await config.shouldStopAfterTurn?.({
					message,
					toolResults,
					context: currentContext,
					newMessages,
				})
			) {
				await emit({ type: "agent_end", messages: newMessages });
				return;
			}

			// Auto-continue on a length stop (output hit maxTokens) with no tool
			// calls: inject a continuation user message and stream another response
			// so the model resumes its cut-off output. Bounded by
			// lengthContinueMaxTurns and the global maxTurns budget (checked above).
			if (
				message.stopReason === "length" &&
				toolCalls.length === 0 &&
				lengthContinueMax > 0 &&
				lengthContinueCount < lengthContinueMax
			) {
				lengthContinueCount++;
				const continuePrompt =
					config.lengthContinuePrompt ??
					"Continue your previous response exactly where it was cut off. Do not repeat what you already wrote.";
				pendingMessages = [{ role: "user", content: continuePrompt, timestamp: Date.now() } as AgentMessage];
				continue;
			}

			pendingMessages = (await config.getSteeringMessages?.()) || [];
		}

		// Agent would stop here. Check for follow-up messages.
		const followUpMessages = (await config.getFollowUpMessages?.()) || [];
		if (followUpMessages.length > 0) {
			// Set as pending so inner loop processes them
			pendingMessages = followUpMessages;
			continue;
		}

		// No more messages, exit
		break;
	}

	await emit({ type: "agent_end", messages: newMessages });
}

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
async function streamAssistantResponse(
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
	const isRetryable = config.isRetryableStreamError ?? defaultIsRetryableStreamError;

	for (let attempt = 0; ; attempt++) {
		// Per-attempt setup: re-resolve context + expiring API key + open a fresh stream.
		let messages = context.messages;
		if (config.transformContext) {
			messages = await config.transformContext(messages, signal);
		}
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
				partialMessage.stopReason = signal?.aborted ? "aborted" : "error";
				partialMessage.errorMessage = streamError instanceof Error ? streamError.message : String(streamError);
				try {
					await emit({ type: "message_end", message: partialMessage });
				} catch {
					// best-effort: emit sink is broken; don't mask the original error
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
						const synthesized = await synthesizeAbortedToolCallResults(orphanToolCalls, [], config, emit);
						for (const result of synthesized) {
							context.messages.push(result);
						}
					} catch {
						// best-effort: never mask the original stream error
					}
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

		// Commit: emit message_start for messages that arrived without a start
		// event, then message_end.
		if (!addedPartial) {
			context.messages.push(finalMessage);
			await emit({ type: "message_start", message: { ...finalMessage } });
		}
		await emit({ type: "message_end", message: finalMessage });
		return finalMessage;
	}
}

/**
 * Conservative default retry filter: skip obvious permanent failures (auth,
 * quota/billing, model-not-found) and retry everything else, including unknown
 * errors (a pre-stream failure is usually transient). Generic string match —
 * no per-provider special-casing.
 */
const NON_RETRYABLE_STREAM_ERROR_PATTERNS = [
	"401",
	"403",
	"invalid api key",
	"invalid_api_key",
	"unauthorized",
	"unauthorised",
	"authentication",
	"permission_denied",
	"forbidden",
	"usage limit",
	"quota",
	"billing",
	"insufficient_quota",
	"model not found",
	"model_not_found",
	"does not exist",
];

function defaultIsRetryableStreamError(message: AssistantMessage): boolean {
	const text = (message.errorMessage ?? "").toLowerCase();
	if (!text) return true;
	return !NON_RETRYABLE_STREAM_ERROR_PATTERNS.some((p) => text.includes(p));
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

/**
 * Execute tool calls from an assistant message.
 */
async function executeToolCalls(
	currentContext: AgentContext,
	assistantMessage: AssistantMessage,
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
): Promise<ExecutedToolCallBatch> {
	const toolCalls = assistantMessage.content.filter((c) => c.type === "toolCall");
	const hasSequentialToolCall = toolCalls.some(
		(tc) => currentContext.tools?.find((t) => t.name === tc.name)?.executionMode === "sequential",
	);
	if (config.toolExecution === "sequential" || hasSequentialToolCall) {
		return executeToolCallsSequential(currentContext, assistantMessage, toolCalls, config, signal, emit);
	}
	return executeToolCallsParallel(currentContext, assistantMessage, toolCalls, config, signal, emit);
}

type ExecutedToolCallBatch = {
	messages: ToolResultMessage[];
	terminate: boolean;
};

async function executeToolCallsSequential(
	currentContext: AgentContext,
	assistantMessage: AssistantMessage,
	toolCalls: AgentToolCall[],
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
): Promise<ExecutedToolCallBatch> {
	const finalizedCalls: FinalizedToolCallOutcome[] = [];
	const messages: ToolResultMessage[] = [];
	const maxToolResultChars = config.maxToolResultChars ?? DEFAULT_MAX_TOOL_RESULT_CHARS;

	for (const toolCall of toolCalls) {
		await emit({
			type: "tool_execution_start",
			toolCallId: toolCall.id,
			toolName: toolCall.name,
			args: toolCall.arguments,
		});

		const preparation = await prepareToolCall(currentContext, assistantMessage, toolCall, config, signal);
		let finalized: FinalizedToolCallOutcome;
		if (preparation.kind === "immediate") {
			finalized = {
				toolCall,
				result: preparation.result,
				isError: preparation.isError,
			};
		} else {
			const executed = await executePreparedToolCall(preparation, signal, emit);
			finalized = await finalizeExecutedToolCall(
				currentContext,
				assistantMessage,
				preparation,
				executed,
				config,
				signal,
			);
		}

		// Foundational opt #263: the emit awaits here are unguarded. A throw (a
		// broken emit sink, or disk-full in handleAgentEvent→session.appendMessage
		// behind the emit) propagates out of the for loop → executeToolCallsSequential
		// rejects → runLoop (no try/catch at the call site) → handleRunFailure emits
		// turn_end(toolResults:[]) for the committed assistant carrying ALL N
		// tool_use, but tool_results only for [0..i) → the remaining [i..N] tool_use
		// are orphaned → the next provider request 400s ("tool_use must be followed
		// by tool_result"). Mirror the parallel closure pattern (opt #24, line ~830):
		// swallow emit errors best-effort AND still push every toolResultMessage so
		// the batch stays balanced (every tool_use has a tool_result). The committed
		// assistant already carries every tool_use id; we must produce a tool_result
		// for each, regardless of the emit sink's health.
		try {
			await emitToolExecutionEnd(finalized, emit);
		} catch {
			/* broken emit sink: don't abandon the remaining tool_results */
		}
		const toolResultMessage = createToolResultMessage(finalized, maxToolResultChars);
		try {
			await emitToolResultMessage(toolResultMessage, emit);
		} catch {
			/* broken emit sink: don't abandon the remaining tool_results */
		}
		finalizedCalls.push(finalized);
		messages.push(toolResultMessage);

		if (signal?.aborted) {
			break;
		}
	}

	return {
		messages,
		terminate: shouldTerminateToolBatch(finalizedCalls),
	};
}

async function executeToolCallsParallel(
	currentContext: AgentContext,
	assistantMessage: AssistantMessage,
	toolCalls: AgentToolCall[],
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
): Promise<ExecutedToolCallBatch> {
	const finalizedCalls: FinalizedToolCallEntry[] = [];
	const maxToolResultChars = config.maxToolResultChars ?? DEFAULT_MAX_TOOL_RESULT_CHARS;

	for (const toolCall of toolCalls) {
		await emit({
			type: "tool_execution_start",
			toolCallId: toolCall.id,
			toolName: toolCall.name,
			args: toolCall.arguments,
		});

		const preparation = await prepareToolCall(currentContext, assistantMessage, toolCall, config, signal);
		if (preparation.kind === "immediate") {
			const finalized = {
				toolCall,
				result: preparation.result,
				isError: preparation.isError,
			} satisfies FinalizedToolCallOutcome;
			await emitToolExecutionEnd(finalized, emit);
			finalizedCalls.push(finalized);
			if (signal?.aborted) {
				break;
			}
			continue;
		}

		finalizedCalls.push(async () => {
			// Defense-in-depth: never let a parallel-batch closure reject. A throw
			// here (e.g. a broken emit sink on tool_execution_end, or an unexpected
			// throw from a hook path that bypasses its own try/catch) would reject
			// the Promise.all below and discard the ENTIRE batch's tool results —
			// including sibling tools that completed fine. Convert the throw into an
			// error result for THIS tool only and preserve the rest of the batch.
			try {
				const executed = await executePreparedToolCall(preparation, signal, emit);
				const finalized = await finalizeExecutedToolCall(
					currentContext,
					assistantMessage,
					preparation,
					executed,
					config,
					signal,
				);
				await emitToolExecutionEnd(finalized, emit);
				return finalized;
			} catch (error) {
				const finalized: FinalizedToolCallOutcome = {
					toolCall: preparation.toolCall,
					result: createErrorToolResult(error instanceof Error ? error.message : String(error)),
					isError: true,
				};
				try {
					await emitToolExecutionEnd(finalized, emit);
				} catch {
					/* emit sink is broken; nothing more we can do for the UI */
				}
				return finalized;
			}
		});
		if (signal?.aborted) {
			break;
		}
	}

	const orderedFinalizedCalls = await Promise.all(
		finalizedCalls.map((entry) => (typeof entry === "function" ? entry() : Promise.resolve(entry))),
	);
	const messages: ToolResultMessage[] = [];
	for (const finalized of orderedFinalizedCalls) {
		const toolResultMessage = createToolResultMessage(finalized, maxToolResultChars);
		// Foundational opt #263: this post-Promise.all emit is unguarded. A throw
		// here abandons tool_results [i+1..N] → orphaned tool_use → next request 400.
		// Swallow best-effort (matching the sequential executor + opt #24 closure),
		// still push every toolResultMessage so the batch stays balanced.
		try {
			await emitToolResultMessage(toolResultMessage, emit);
		} catch {
			/* broken emit sink: don't abandon the remaining tool_results */
		}
		messages.push(toolResultMessage);
	}

	return {
		messages,
		terminate: shouldTerminateToolBatch(orderedFinalizedCalls),
	};
}

/**
 * Foundational opt #134: synthesize isError tool_results for tool calls whose
 * arguments were truncated by a "length" (max_tokens) stop. Mirrors the
 * sequential executor's emit sequence (tool_execution_start →
 * tool_execution_end → message_start/end) so the UI renders the truncated
 * call, but NEVER executes the tool — the finalized arguments are incomplete
 * (parseStreamingJson closed the unterminated JSON). terminate is false
 * (createErrorToolResult carries no `terminate: true`), so the agent loop
 * iterates and the model re-emits the complete call on the next turn.
 */
async function synthesizeTruncatedToolCallResults(
	toolCalls: AgentToolCall[],
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
): Promise<ExecutedToolCallBatch> {
	const maxToolResultChars = config.maxToolResultChars ?? DEFAULT_MAX_TOOL_RESULT_CHARS;
	const finalizedCalls: FinalizedToolCallOutcome[] = [];
	const messages: ToolResultMessage[] = [];
	for (const toolCall of toolCalls) {
		await emit({
			type: "tool_execution_start",
			toolCallId: toolCall.id,
			toolName: toolCall.name,
			args: toolCall.arguments,
		});
		const finalized: FinalizedToolCallOutcome = {
			toolCall,
			result: createErrorToolResult(
				`Tool "${toolCall.name}" was truncated by max_tokens before its arguments finished streaming. The arguments are incomplete and were NOT executed. Re-emit the complete tool call with the full arguments.`,
			),
			isError: true,
		};
		// Foundational opt #263: swallow emit errors best-effort, still push every
		// toolResultMessage so the batch stays balanced (every truncated tool_use
		// gets a tool_result). Matches the sequential executor.
		try {
			await emitToolExecutionEnd(finalized, emit);
		} catch {
			/* broken emit sink: don't abandon the remaining tool_results */
		}
		const toolResultMessage = createToolResultMessage(finalized, maxToolResultChars);
		try {
			await emitToolResultMessage(toolResultMessage, emit);
		} catch {
			/* broken emit sink: don't abandon the remaining tool_results */
		}
		finalizedCalls.push(finalized);
		messages.push(toolResultMessage);
		if (signal?.aborted) {
			break;
		}
	}
	return {
		messages,
		terminate: shouldTerminateToolBatch(finalizedCalls),
	};
}

/**
 * Foundational opt: abort mid-batch leaves orphan tool_use blocks. The assistant
 * message carrying N tool_use blocks is committed via message_end BEFORE tool
 * execution, but both executors break on `signal?.aborted` after pushing results
 * only for the tools that got far enough. Without synthesizing error tool_results
 * for the un-executed tool_use ids, the next request would send an unbalanced
 * transcript (assistant(N tool_use) + toolResult(M<N)) and the provider would
 * 400 "tool_use must be followed by tool_result". Mirrors
 * synthesizeTruncatedToolCallResults: add an isError tool_result for every
 * toolCall whose id is NOT already in the finalized results. Do NOT strip the
 * assistant — it was committed; only add the missing tool_results.
 */
export async function synthesizeAbortedToolCallResults(
	toolCalls: AgentToolCall[],
	finalizedResults: ToolResultMessage[],
	config: AgentLoopConfig,
	emit: AgentEventSink,
): Promise<ToolResultMessage[]> {
	const maxToolResultChars = config.maxToolResultChars ?? DEFAULT_MAX_TOOL_RESULT_CHARS;
	const finalizedIds = new Set(finalizedResults.map((r) => r.toolCallId));
	const synthesized: ToolResultMessage[] = [];
	for (const toolCall of toolCalls) {
		if (finalizedIds.has(toolCall.id)) continue;
		const finalized: FinalizedToolCallOutcome = {
			toolCall,
			result: createErrorToolResult(
				`Tool "${toolCall.name}" was not executed because the run was aborted mid-batch.`,
			),
			isError: true,
		};
		// Foundational opt #263: swallow emit errors best-effort, still push every
		// synthesized toolResultMessage. This function's WHOLE purpose is to balance
		// orphaned tool_use ids — a throw at iteration i would drop [i+1..N] and
		// leave exactly those ids orphaned (the bug it exists to fix). Matches the
		// executors.
		try {
			await emitToolExecutionEnd(finalized, emit);
		} catch {
			/* broken emit sink: don't abandon the remaining synthesized results */
		}
		const toolResultMessage = createToolResultMessage(finalized, maxToolResultChars);
		try {
			await emitToolResultMessage(toolResultMessage, emit);
		} catch {
			/* broken emit sink: don't abandon the remaining synthesized results */
		}
		synthesized.push(toolResultMessage);
	}
	return synthesized;
}

type PreparedToolCall = {
	kind: "prepared";
	toolCall: AgentToolCall;
	tool: AgentTool<any>;
	args: unknown;
};

type ImmediateToolCallOutcome = {
	kind: "immediate";
	result: AgentToolResult<any>;
	isError: boolean;
};

type ExecutedToolCallOutcome = {
	result: AgentToolResult<any>;
	isError: boolean;
};

type FinalizedToolCallOutcome = {
	toolCall: AgentToolCall;
	result: AgentToolResult<any>;
	isError: boolean;
};

type FinalizedToolCallEntry = FinalizedToolCallOutcome | (() => Promise<FinalizedToolCallOutcome>);

function shouldTerminateToolBatch(finalizedCalls: FinalizedToolCallOutcome[]): boolean {
	return finalizedCalls.length > 0 && finalizedCalls.every((finalized) => finalized.result.terminate === true);
}

function prepareToolCallArguments(tool: AgentTool<any>, toolCall: AgentToolCall): AgentToolCall {
	if (!tool.prepareArguments) {
		return toolCall;
	}
	const preparedArguments = tool.prepareArguments(toolCall.arguments);
	if (preparedArguments === toolCall.arguments) {
		return toolCall;
	}
	return {
		...toolCall,
		arguments: preparedArguments as Record<string, any>,
	};
}

async function prepareToolCall(
	currentContext: AgentContext,
	assistantMessage: AssistantMessage,
	toolCall: AgentToolCall,
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
): Promise<PreparedToolCall | ImmediateToolCallOutcome> {
	const tool = currentContext.tools?.find((t) => t.name === toolCall.name);
	if (!tool) {
		const available = currentContext.tools
			?.map((t) => t.name)
			.filter(Boolean)
			.join(", ");
		const hint = available ? ` Available tools: ${available}.` : "";
		return {
			kind: "immediate",
			result: createErrorToolResult(`Tool "${toolCall.name}" not found.${hint}`),
			isError: true,
		};
	}

	try {
		const preparedToolCall = prepareToolCallArguments(tool, toolCall);
		const validatedArgs = validateToolArguments(tool, preparedToolCall);
		if (config.beforeToolCall) {
			const beforeResult = await config.beforeToolCall(
				{
					assistantMessage,
					toolCall,
					args: validatedArgs,
					context: currentContext,
				},
				signal,
			);
			if (signal?.aborted) {
				return {
					kind: "immediate",
					result: createErrorToolResult("Operation aborted"),
					isError: true,
				};
			}
			if (beforeResult?.block) {
				return {
					kind: "immediate",
					result: createErrorToolResult(beforeResult.reason || "Tool execution was blocked"),
					isError: true,
				};
			}
		}
		if (signal?.aborted) {
			return {
				kind: "immediate",
				result: createErrorToolResult("Operation aborted"),
				isError: true,
			};
		}
		return {
			kind: "prepared",
			toolCall,
			tool,
			args: validatedArgs,
		};
	} catch (error) {
		return {
			kind: "immediate",
			result: createErrorToolResult(error instanceof Error ? error.message : String(error)),
			isError: true,
		};
	}
}

async function executePreparedToolCall(
	prepared: PreparedToolCall,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
): Promise<ExecutedToolCallOutcome> {
	const updateEvents: Promise<void>[] = [];

	try {
		const result = await prepared.tool.execute(
			prepared.toolCall.id,
			prepared.args as never,
			signal,
			(partialResult) => {
				updateEvents.push(
					Promise.resolve(
						emit({
							type: "tool_execution_update",
							toolCallId: prepared.toolCall.id,
							toolName: prepared.toolCall.name,
							args: prepared.toolCall.arguments,
							partialResult,
						}),
					),
				);
			},
		);
		// Update events are best-effort UI notifications (streaming partial
		// output). A broken emit sink must not flip a successful tool into an
		// error or, in the catch below, re-throw uncaught and lose the whole
		// parallel batch. allSettled swallows per-update rejections.
		await Promise.allSettled(updateEvents);
		return { result, isError: false };
	} catch (error) {
		await Promise.allSettled(updateEvents);
		return {
			result: createErrorToolResult(error instanceof Error ? error.message : String(error)),
			isError: true,
		};
	}
}

async function finalizeExecutedToolCall(
	currentContext: AgentContext,
	assistantMessage: AssistantMessage,
	prepared: PreparedToolCall,
	executed: ExecutedToolCallOutcome,
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
): Promise<FinalizedToolCallOutcome> {
	let result = executed.result;
	let isError = executed.isError;

	if (config.afterToolCall) {
		try {
			const afterResult = await config.afterToolCall(
				{
					assistantMessage,
					toolCall: prepared.toolCall,
					args: prepared.args,
					result,
					isError,
					context: currentContext,
				},
				signal,
			);
			if (afterResult) {
				result = {
					content: afterResult.content ?? result.content,
					details: afterResult.details ?? result.details,
					terminate: afterResult.terminate ?? result.terminate,
				};
				isError = afterResult.isError ?? isError;
			}
		} catch (error) {
			result = createErrorToolResult(error instanceof Error ? error.message : String(error));
			isError = true;
		}
	}

	return {
		toolCall: prepared.toolCall,
		result,
		isError,
	};
}

function createErrorToolResult(message: string): AgentToolResult<any> {
	return {
		content: [{ type: "text", text: message }],
		details: {},
	};
}

/**
 * Defense-in-depth: cap any TEXT content block that exceeds `maxChars` before it
 * enters the model's context. Built-in tools self-truncate (~50KB), so this only
 * catches misbehaving custom/MCP extension tools. Head+tail with an elided-count
 * marker (tail holds the final error/exit code/last line). Returns the original
 * array reference when nothing was capped (preserves referential equality).
 * `maxChars <= 0` disables the cap.
 */
export function capToolResultContent(
	content: (TextContent | ImageContent)[],
	maxChars: number,
): (TextContent | ImageContent)[] {
	if (maxChars <= 0) return content;
	let capped = false;
	const next = content.map((block): TextContent | ImageContent => {
		if (block.type !== "text") return block;
		const text = block.text;
		if (text.length <= maxChars) return block;
		capped = true;
		const head = Math.floor(maxChars * 0.45);
		const tail = Math.floor(maxChars * 0.45);
		const elided = text.length - head - tail;
		const headEnd = safeHeadEnd(text, head);
		const tailStart = safeTailStart(text, text.length - tail);
		return {
			type: "text" as const,
			text: `${text.slice(0, headEnd)}\n\n[... ${elided} more characters truncated (tool result exceeded ${maxChars} char safety cap) ...]\n\n${text.slice(tailStart)}`,
		};
	});
	return capped ? next : content;
}

async function emitToolExecutionEnd(finalized: FinalizedToolCallOutcome, emit: AgentEventSink): Promise<void> {
	await emit({
		type: "tool_execution_end",
		toolCallId: finalized.toolCall.id,
		toolName: finalized.toolCall.name,
		result: finalized.result,
		isError: finalized.isError,
	});
}

function createToolResultMessage(finalized: FinalizedToolCallOutcome, maxToolResultChars: number): ToolResultMessage {
	return {
		role: "toolResult",
		toolCallId: finalized.toolCall.id,
		toolName: finalized.toolCall.name,
		content: capToolResultContent(finalized.result.content, maxToolResultChars),
		details: finalized.result.details,
		isError: finalized.isError,
		timestamp: Date.now(),
	};
}

async function emitToolResultMessage(toolResultMessage: ToolResultMessage, emit: AgentEventSink): Promise<void> {
	await emit({ type: "message_start", message: toolResultMessage });
	await emit({ type: "message_end", message: toolResultMessage });
}

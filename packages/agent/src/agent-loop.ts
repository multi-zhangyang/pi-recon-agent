/**
 * Agent loop that works with AgentMessage throughout.
 * Transforms to Message[] only at the LLM call boundary.
 */

import { type AssistantMessage, EventStream, type ToolResultMessage } from "@pi-recon/repi-ai";
import { AgentEventDeliveryError, type AgentEventSink, emitAndCollectFailure } from "./runner/events.ts";
import { streamAssistantResponse } from "./runner/model-stream.ts";
import {
	executeToolCalls,
	synthesizeAbortedToolCallResults,
	synthesizeTruncatedToolCallResults,
} from "./runner/tool-execution.ts";
import type { AgentContext, AgentEvent, AgentLoopConfig, AgentMessage, AgentToolCall, StreamFn } from "./types.ts";

export {
	compactConsumedToolResults,
	DEFAULT_MAX_CONSUMED_TOOL_RESULT_CHARS,
	defaultMaxConsumedToolResultChars,
} from "./runner/context-projection.ts";
export type { AgentEventSink } from "./runner/events.ts";
export { AgentEventDeliveryError } from "./runner/events.ts";
export { capToolResultContent, DEFAULT_MAX_TOOL_RESULT_CHARS } from "./runner/tool-execution.ts";

async function closeTurnAfterDeliveryFailure(
	deliveryErrors: unknown[],
	message: AssistantMessage,
	toolResults: ToolResultMessage[],
	emit: AgentEventSink,
): Promise<never> {
	await emitAndCollectFailure({ type: "turn_end", message, toolResults }, emit, deliveryErrors);
	throw new AgentEventDeliveryError(deliveryErrors);
}

export const DEFAULT_FINAL_TURN_PROMPT =
	"This is the final turn in the current request budget. Do not call tools. Give the user the best complete answer using only evidence already collected, state unresolved gaps briefly, and quote recorded verification/replay commands verbatim. Never invent tools, flags, endpoints, or follow-up commands.";

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
	const newMessages: AgentMessage[] = [];
	const currentContext: AgentContext = {
		...context,
		messages: [...context.messages],
	};

	await emit({ type: "agent_start" });
	await emit({ type: "turn_start" });
	for (const prompt of prompts) {
		if (config.claimMessageDelivery?.(prompt) === false) continue;
		await emit({ type: "message_start", message: prompt });
		await emit({ type: "message_end", message: prompt });
		newMessages.push(prompt);
		currentContext.messages.push(prompt);
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
	const maxTurns =
		typeof config.maxTurns === "number" && config.maxTurns > 0 ? Math.max(1, Math.floor(config.maxTurns)) : 0;
	const lengthContinueMax =
		typeof config.lengthContinueMaxTurns === "number" && config.lengthContinueMaxTurns > 0
			? Math.floor(config.lengthContinueMaxTurns)
			: 0;
	let lengthContinueCount = 0;
	const readOnlyProbeHistory = new Map<string, AgentToolCall>();
	let finalTurnReserved = false;
	let budgetNoticeEmitted = false;
	const internalControlMessages = new WeakSet<object>();
	const notifyBudgetExceeded = (): void => {
		if (budgetNoticeEmitted || maxTurns <= 0) return;
		budgetNoticeEmitted = true;
		try {
			config.onRunBudgetExceeded?.({ turns: turnCount, maxTurns });
		} catch {
			// Side-effect channel only; never interrupt loop settlement.
		}
	};
	const finalTurnMessage = (): AgentMessage => {
		const message = {
			role: "user",
			content: config.finalTurnPrompt ?? DEFAULT_FINAL_TURN_PROMPT,
			timestamp: Date.now(),
		} as AgentMessage;
		internalControlMessages.add(message as object);
		return message;
	};
	// Check for steering messages at start (user may have typed while waiting)
	let pendingMessages: AgentMessage[] = (await config.getSteeringMessages?.()) || [];
	if (config.reserveFinalTurn && maxTurns === 1) {
		currentContext = { ...currentContext, tools: [] };
		pendingMessages = [...pendingMessages, finalTurnMessage()];
		finalTurnReserved = true;
	}

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
					if (config.claimMessageDelivery?.(message) === false) continue;
					const internal = internalControlMessages.has(message as object);
					if (!internal) {
						await emit({ type: "message_start", message });
						await emit({ type: "message_end", message });
						newMessages.push(message);
					}
					currentContext.messages.push(message);
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
				const deliveryErrors: unknown[] = [];
				if (orphanToolCalls.length > 0) {
					const synthesized = await synthesizeAbortedToolCallResults(
						orphanToolCalls,
						[],
						config,
						emit,
						deliveryErrors,
					);
					for (const result of synthesized) {
						errorToolResults.push(result);
						currentContext.messages.push(result);
						newMessages.push(result);
					}
				}
				if (deliveryErrors.length > 0) {
					await closeTurnAfterDeliveryFailure(deliveryErrors, message, errorToolResults, emit);
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
						: await executeToolCalls(currentContext, message, config, signal, emit, readOnlyProbeHistory);
				toolResults.push(...executedToolBatch.messages);
				hasMoreToolCalls = !executedToolBatch.terminate;
				const deliveryErrors = executedToolBatch.deliveryErrors;

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
					const synthesizedAborted = await synthesizeAbortedToolCallResults(
						toolCalls,
						toolResults,
						config,
						emit,
						deliveryErrors,
					);
					for (const result of synthesizedAborted) {
						toolResults.push(result);
						currentContext.messages.push(result);
						newMessages.push(result);
					}
					if (deliveryErrors.length > 0) {
						await closeTurnAfterDeliveryFailure(deliveryErrors, message, toolResults, emit);
					}
					await emit({ type: "turn_end", message, toolResults });
					await emit({ type: "agent_end", messages: newMessages });
					return;
				}
				if (deliveryErrors.length > 0) {
					await closeTurnAfterDeliveryFailure(deliveryErrors, message, toolResults, emit);
				}
			}

			await emit({ type: "turn_end", message, toolResults });

			// A reserved convergence request is always the last request in the run.
			// Tools were removed before it started, so there is no useful continuation
			// to perform even if a provider emits a stale tool call anyway.
			if (finalTurnReserved) {
				notifyBudgetExceeded();
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
			// calls: inject a continuation user message and stream another response.
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
			} else {
				pendingMessages = (await config.getSteeringMessages?.()) || [];
			}

			const wantsAnotherTurn = hasMoreToolCalls || pendingMessages.length > 0;
			if (maxTurns > 0 && turnCount >= maxTurns && wantsAnotherTurn) {
				notifyBudgetExceeded();
				await emit({ type: "agent_end", messages: newMessages });
				return;
			}

			if (config.reserveFinalTurn && maxTurns > 0 && turnCount === maxTurns - 1 && wantsAnotherTurn) {
				currentContext = { ...currentContext, tools: [] };
				pendingMessages = [...pendingMessages, finalTurnMessage()];
				finalTurnReserved = true;
			}
		}

		// Agent would stop here. Check for follow-up messages.
		const followUpMessages = (await config.getFollowUpMessages?.()) || [];
		if (followUpMessages.length > 0) {
			if (maxTurns > 0 && turnCount >= maxTurns) {
				notifyBudgetExceeded();
				await emit({ type: "agent_end", messages: newMessages });
				return;
			}
			// Set as pending so inner loop processes them
			if (config.reserveFinalTurn && maxTurns > 0 && turnCount === maxTurns - 1) {
				currentContext = { ...currentContext, tools: [] };
				pendingMessages = [...followUpMessages, finalTurnMessage()];
				finalTurnReserved = true;
			} else {
				pendingMessages = followUpMessages;
			}
			continue;
		}

		// No more messages, exit
		break;
	}

	await emit({ type: "agent_end", messages: newMessages });
}

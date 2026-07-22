import {
	type AssistantMessage,
	type ImageContent,
	type TextContent,
	type ToolResultMessage,
	validateToolArguments,
} from "@pi-recon/repi-ai";
import { safeHeadEnd, safeTailStart } from "../harness/utils/truncate.ts";
import type { AgentContext, AgentLoopConfig, AgentTool, AgentToolCall, AgentToolResult } from "../types.ts";
import { type AgentEventSink, emitAndCollectFailure } from "./events.ts";

/**
 * Default defense-in-depth cap (in chars) on a tool result's text content at the
 * context boundary. See {@link AgentLoopConfig.maxToolResultChars}.
 */
export const DEFAULT_MAX_TOOL_RESULT_CHARS = 256 * 1024;

/**
 * Execute tool calls from an assistant message.
 */
export async function executeToolCalls(
	currentContext: AgentContext,
	assistantMessage: AssistantMessage,
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
	readOnlyProbeHistory: Map<string, AgentToolCall>,
): Promise<ExecutedToolCallBatch> {
	const toolCalls = assistantMessage.content.filter((c) => c.type === "toolCall");
	const deduplicateReadOnly = config.deduplicateReadOnlyToolCalls !== false;
	const allReadOnly =
		deduplicateReadOnly &&
		toolCalls.length > 0 &&
		toolCalls.every(
			(toolCall) => currentContext.tools?.find((tool) => tool.name === toolCall.name)?.readOnly === true,
		);
	if (!allReadOnly) {
		// A mutating or unknown call invalidates observations collected earlier in
		// this run. When deduplication is enabled, mixed batches run sequentially
		// below so a read before a mutation cannot race with a read after it.
		readOnlyProbeHistory.clear();
	}
	const hasReadOnlyToolCall = toolCalls.some(
		(toolCall) => currentContext.tools?.find((tool) => tool.name === toolCall.name)?.readOnly === true,
	);
	const hasMutationBoundary =
		hasReadOnlyToolCall &&
		toolCalls.some(
			(toolCall) => currentContext.tools?.find((tool) => tool.name === toolCall.name)?.readOnly !== true,
		);
	const hasSequentialToolCall = toolCalls.some(
		(tc) => currentContext.tools?.find((t) => t.name === tc.name)?.executionMode === "sequential",
	);
	if (config.toolExecution === "sequential" || hasSequentialToolCall || (deduplicateReadOnly && hasMutationBoundary)) {
		return executeToolCallsSequential(
			currentContext,
			assistantMessage,
			toolCalls,
			config,
			signal,
			emit,
			allReadOnly ? readOnlyProbeHistory : undefined,
			deduplicateReadOnly,
		);
	}
	return executeToolCallsParallel(
		currentContext,
		assistantMessage,
		toolCalls,
		config,
		signal,
		emit,
		allReadOnly ? readOnlyProbeHistory : undefined,
		deduplicateReadOnly,
	);
}

type ExecutedToolCallBatch = {
	messages: ToolResultMessage[];
	terminate: boolean;
	deliveryErrors: unknown[];
};

type ReadOnlyProbeHistory = Map<string, AgentToolCall>;

function stableToolValue(value: unknown): string {
	if (value === null || typeof value !== "object") {
		return JSON.stringify(value) ?? String(value);
	}
	if (Array.isArray(value)) {
		return `[${value.map((item) => stableToolValue(item)).join(",")}]`;
	}
	return `{${Object.keys(value as Record<string, unknown>)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${stableToolValue((value as Record<string, unknown>)[key])}`)
		.join(",")}}`;
}

function readOnlyProbeKey(toolCall: AgentToolCall): string {
	return `${toolCall.name}:${stableToolValue(toolCall.arguments)}`;
}

function findCoveringReadOnlyProbe(
	tool: AgentTool<any>,
	toolCall: AgentToolCall,
	...histories: Array<ReadOnlyProbeHistory | undefined>
): AgentToolCall | undefined {
	const key = readOnlyProbeKey(toolCall);
	for (const history of histories) {
		const exact = history?.get(key);
		if (exact) return exact;
	}
	if (!tool.readOnlyProbeCovers) return undefined;
	for (const history of histories) {
		if (!history) continue;
		for (const previous of Array.from(history.values()).reverse()) {
			if (previous.name !== toolCall.name) continue;
			try {
				if (tool.readOnlyProbeCovers(previous.arguments, toolCall.arguments)) return previous;
			} catch {
				// A coverage hook is an optimization boundary; failure must fall back to execution.
			}
		}
	}
	return undefined;
}

function createDuplicateReadOnlyProbeOutcome(
	toolCall: AgentToolCall,
	duplicateOfToolCallId: string,
): FinalizedToolCallOutcome {
	return {
		toolCall,
		result: {
			content: [
				{
					type: "text",
					text: `Skipped duplicate read-only probe. A successful invocation already covered this request in tool call ${duplicateOfToolCallId}; reuse that result instead of probing again.`,
				},
			],
			details: { deduplicatedReadOnlyProbe: true, duplicateOfToolCallId },
		},
		isError: false,
	};
}

async function finalizeDuplicateReadOnlyProbe(
	currentContext: AgentContext,
	assistantMessage: AssistantMessage,
	prepared: PreparedToolCall,
	duplicateOfToolCallId: string,
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
): Promise<FinalizedToolCallOutcome> {
	const duplicate = createDuplicateReadOnlyProbeOutcome(prepared.toolCall, duplicateOfToolCallId);
	const finalized = await finalizeExecutedToolCall(
		currentContext,
		assistantMessage,
		prepared,
		{ result: duplicate.result, isError: false },
		config,
		signal,
	);
	return { ...finalized, deduplicatedReadOnlyProbe: true };
}

function rememberReadOnlyProbe(finalized: FinalizedToolCallOutcome, history: ReadOnlyProbeHistory | undefined): void {
	if (!history || finalized.isError || finalized.deduplicatedReadOnlyProbe) return;
	history.set(readOnlyProbeKey(finalized.toolCall), finalized.toolCall);
}

async function executeToolCallsSequential(
	currentContext: AgentContext,
	assistantMessage: AssistantMessage,
	toolCalls: AgentToolCall[],
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
	readOnlyProbeHistory?: ReadOnlyProbeHistory,
	deduplicateWithinBatch = false,
): Promise<ExecutedToolCallBatch> {
	const finalizedCalls: FinalizedToolCallOutcome[] = [];
	const messages: ToolResultMessage[] = [];
	const deliveryErrors: unknown[] = [];
	const maxToolResultChars = config.maxToolResultChars ?? DEFAULT_MAX_TOOL_RESULT_CHARS;
	const batchProbeOwners: ReadOnlyProbeHistory = new Map();

	for (const toolCall of toolCalls) {
		await emitAndCollectFailure(
			{
				type: "tool_execution_start",
				toolCallId: toolCall.id,
				toolName: toolCall.name,
				args: toolCall.arguments,
			},
			emit,
			deliveryErrors,
		);

		const preparation = await prepareToolCall(currentContext, assistantMessage, toolCall, config, signal);
		const activeTool = currentContext.tools?.find((tool) => tool.name === toolCall.name);
		const isReadOnly = activeTool?.readOnly === true;
		if (!isReadOnly) batchProbeOwners.clear();
		let finalized: FinalizedToolCallOutcome;
		if (preparation.kind === "immediate") {
			finalized = {
				toolCall,
				result: preparation.result,
				isError: preparation.isError,
			};
		} else if (isReadOnly && activeTool) {
			const coveringProbe = findCoveringReadOnlyProbe(
				activeTool,
				preparation.toolCall,
				readOnlyProbeHistory,
				batchProbeOwners,
			);
			if (!coveringProbe) {
				const executed = await executePreparedToolCall(preparation, signal, emit);
				finalized = await finalizeExecutedToolCall(
					currentContext,
					assistantMessage,
					preparation,
					executed,
					config,
					signal,
				);
			} else {
				finalized = await finalizeDuplicateReadOnlyProbe(
					currentContext,
					assistantMessage,
					preparation,
					coveringProbe.id,
					config,
					signal,
				);
			}
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
		rememberReadOnlyProbe(finalized, readOnlyProbeHistory);
		if (deduplicateWithinBatch && isReadOnly) rememberReadOnlyProbe(finalized, batchProbeOwners);

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
		await emitToolExecutionEndAndCollectFailure(finalized, emit, deliveryErrors);
		const toolResultMessage = createToolResultMessage(finalized, maxToolResultChars);
		await emitToolResultMessage(toolResultMessage, emit, deliveryErrors);
		finalizedCalls.push(finalized);
		messages.push(toolResultMessage);

		if (signal?.aborted) {
			break;
		}
	}

	return {
		messages,
		terminate: shouldTerminateToolBatch(finalizedCalls),
		deliveryErrors,
	};
}

async function executeToolCallsParallel(
	currentContext: AgentContext,
	assistantMessage: AssistantMessage,
	toolCalls: AgentToolCall[],
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
	readOnlyProbeHistory?: ReadOnlyProbeHistory,
	deduplicateWithinBatch = false,
): Promise<ExecutedToolCallBatch> {
	const finalizedCalls: FinalizedToolCallEntry[] = [];
	const maxToolResultChars = config.maxToolResultChars ?? DEFAULT_MAX_TOOL_RESULT_CHARS;
	const batchProbeOwners: ReadOnlyProbeHistory = new Map();
	const deliveryErrors: unknown[] = [];

	for (const toolCall of toolCalls) {
		await emitAndCollectFailure(
			{
				type: "tool_execution_start",
				toolCallId: toolCall.id,
				toolName: toolCall.name,
				args: toolCall.arguments,
			},
			emit,
			deliveryErrors,
		);

		const preparation = await prepareToolCall(currentContext, assistantMessage, toolCall, config, signal);
		if (preparation.kind === "immediate") {
			const finalized = {
				toolCall,
				result: preparation.result,
				isError: preparation.isError,
			} satisfies FinalizedToolCallOutcome;
			await emitToolExecutionEndAndCollectFailure(finalized, emit, deliveryErrors);
			finalizedCalls.push(finalized);
			if (signal?.aborted) {
				break;
			}
			continue;
		}
		const activeTool = currentContext.tools?.find((tool) => tool.name === toolCall.name);
		const isReadOnly = activeTool?.readOnly === true;
		if (!isReadOnly) batchProbeOwners.clear();
		const probeKey = readOnlyProbeKey(preparation.toolCall);
		const duplicateOf =
			isReadOnly && activeTool
				? findCoveringReadOnlyProbe(activeTool, preparation.toolCall, readOnlyProbeHistory, batchProbeOwners)
				: undefined;
		if (duplicateOf) {
			const finalized = await finalizeDuplicateReadOnlyProbe(
				currentContext,
				assistantMessage,
				preparation,
				duplicateOf.id,
				config,
				signal,
			);
			await emitToolExecutionEndAndCollectFailure(finalized, emit, deliveryErrors);
			finalizedCalls.push(finalized);
			continue;
		}
		if (deduplicateWithinBatch && isReadOnly) batchProbeOwners.set(probeKey, preparation.toolCall);

		finalizedCalls.push(async () => {
			let finalized: FinalizedToolCallOutcome;
			try {
				const executed = await executePreparedToolCall(preparation, signal, emit);
				finalized = await finalizeExecutedToolCall(
					currentContext,
					assistantMessage,
					preparation,
					executed,
					config,
					signal,
				);
			} catch (error) {
				// Preserve sibling results if an unexpected execution/finalization path
				// escapes its local guards. Event delivery is handled separately below.
				finalized = {
					toolCall: preparation.toolCall,
					result: createErrorToolResult(error instanceof Error ? error.message : String(error)),
					isError: true,
				};
			}
			// A listener failure must never rewrite a successful tool outcome.
			await emitToolExecutionEndAndCollectFailure(finalized, emit, deliveryErrors);
			return finalized;
		});
		if (signal?.aborted) {
			break;
		}
	}

	const orderedFinalizedCalls = await Promise.all(
		finalizedCalls.map((entry) => (typeof entry === "function" ? entry() : Promise.resolve(entry))),
	);
	for (const finalized of orderedFinalizedCalls) {
		rememberReadOnlyProbe(finalized, readOnlyProbeHistory);
	}
	const messages: ToolResultMessage[] = [];
	for (const finalized of orderedFinalizedCalls) {
		const toolResultMessage = createToolResultMessage(finalized, maxToolResultChars);
		// Foundational opt #263: this post-Promise.all emit is unguarded. A throw
		// here abandons tool_results [i+1..N] → orphaned tool_use → next request 400.
		// Swallow best-effort (matching the sequential executor + opt #24 closure),
		// still push every toolResultMessage so the batch stays balanced.
		await emitToolResultMessage(toolResultMessage, emit, deliveryErrors);
		messages.push(toolResultMessage);
	}

	return {
		messages,
		terminate: shouldTerminateToolBatch(orderedFinalizedCalls),
		deliveryErrors,
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
export async function synthesizeTruncatedToolCallResults(
	toolCalls: AgentToolCall[],
	config: AgentLoopConfig,
	signal: AbortSignal | undefined,
	emit: AgentEventSink,
): Promise<ExecutedToolCallBatch> {
	const maxToolResultChars = config.maxToolResultChars ?? DEFAULT_MAX_TOOL_RESULT_CHARS;
	const finalizedCalls: FinalizedToolCallOutcome[] = [];
	const messages: ToolResultMessage[] = [];
	const deliveryErrors: unknown[] = [];
	for (const toolCall of toolCalls) {
		await emitAndCollectFailure(
			{
				type: "tool_execution_start",
				toolCallId: toolCall.id,
				toolName: toolCall.name,
				args: toolCall.arguments,
			},
			emit,
			deliveryErrors,
		);
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
		await emitToolExecutionEndAndCollectFailure(finalized, emit, deliveryErrors);
		const toolResultMessage = createToolResultMessage(finalized, maxToolResultChars);
		await emitToolResultMessage(toolResultMessage, emit, deliveryErrors);
		finalizedCalls.push(finalized);
		messages.push(toolResultMessage);
		if (signal?.aborted) {
			break;
		}
	}
	return {
		messages,
		terminate: shouldTerminateToolBatch(finalizedCalls),
		deliveryErrors,
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
	deliveryErrors: unknown[] = [],
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
		await emitToolExecutionEndAndCollectFailure(finalized, emit, deliveryErrors);
		const toolResultMessage = createToolResultMessage(finalized, maxToolResultChars);
		await emitToolResultMessage(toolResultMessage, emit, deliveryErrors);
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
	deduplicatedReadOnlyProbe?: boolean;
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
					...result,
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

async function emitToolExecutionEndAndCollectFailure(
	finalized: FinalizedToolCallOutcome,
	emit: AgentEventSink,
	deliveryErrors: unknown[],
): Promise<void> {
	try {
		await emitToolExecutionEnd(finalized, emit);
	} catch (error) {
		deliveryErrors.push(error);
	}
}

function createToolResultMessage(finalized: FinalizedToolCallOutcome, maxToolResultChars: number): ToolResultMessage {
	return {
		role: "toolResult",
		toolCallId: finalized.toolCall.id,
		toolName: finalized.toolCall.name,
		content: capToolResultContent(finalized.result.content, maxToolResultChars),
		details: finalized.result.details,
		...(finalized.result.addedToolNames?.length ? { addedToolNames: finalized.result.addedToolNames } : {}),
		isError: finalized.isError,
		timestamp: Date.now(),
	};
}

async function emitToolResultMessage(
	toolResultMessage: ToolResultMessage,
	emit: AgentEventSink,
	deliveryErrors: unknown[],
): Promise<void> {
	// Attempt both halves independently. If message_start delivery fails after
	// state reduction, message_end must still persist and pair the tool result.
	await emitAndCollectFailure({ type: "message_start", message: toolResultMessage }, emit, deliveryErrors);
	await emitAndCollectFailure({ type: "message_end", message: toolResultMessage }, emit, deliveryErrors);
}

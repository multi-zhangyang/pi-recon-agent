import type {
	AssistantMessage,
	AssistantMessageEvent,
	ImageContent,
	Message,
	Model,
	SimpleStreamOptions,
	streamSimple,
	TextContent,
	Tool,
	ToolResultMessage,
} from "@pi-recon/repi-ai";
import type { Static, TSchema } from "typebox";

/**
 * Stream function used by the agent loop.
 *
 * Contract:
 * - Must not throw or return a rejected promise for request/model/runtime failures.
 * - Must return an AssistantMessageEventStream.
 * - Failures must be encoded in the returned stream via protocol events and a
 *   final AssistantMessage with stopReason "error" or "aborted" and errorMessage.
 */
export type StreamFn = (
	...args: Parameters<typeof streamSimple>
) => ReturnType<typeof streamSimple> | Promise<ReturnType<typeof streamSimple>>;

/**
 * Configuration for how tool calls from a single assistant message are executed.
 *
 * - "sequential": each tool call is prepared, executed, and finalized before the next one starts.
 * - "parallel": tool calls are prepared sequentially, then allowed tools execute concurrently.
 *   `tool_execution_end` is emitted in tool completion order after each tool is finalized,
 *   while tool-result message artifacts are emitted later in assistant source order.
 */
export type ToolExecutionMode = "sequential" | "parallel";

/**
 * Controls how many queued user messages are injected when the agent loop reaches a queue drain point.
 *
 * - "all": drain and inject every queued message at that point.
 * - "one-at-a-time": drain and inject only the oldest queued message, leaving the rest queued for later drain points.
 */
export type QueueMode = "all" | "one-at-a-time";

/** A single tool call content block emitted by an assistant message. */
export type AgentToolCall = Extract<AssistantMessage["content"][number], { type: "toolCall" }>;

/**
 * Result returned from `beforeToolCall`.
 *
 * Returning `{ block: true }` prevents the tool from executing. The loop emits an error tool result instead.
 * `reason` becomes the text shown in that error result. If omitted, a default blocked message is used.
 */
export interface BeforeToolCallResult {
	block?: boolean;
	reason?: string;
}

/**
 * Partial override returned from `afterToolCall`.
 *
 * Merge semantics are field-by-field:
 * - `content`: if provided, replaces the tool result content array in full
 * - `details`: if provided, replaces the tool result details value in full
 * - `isError`: if provided, replaces the tool result error flag
 * - `terminate`: if provided, replaces the early-termination hint
 *
 * Omitted fields keep the original executed tool result values.
 * There is no deep merge for `content` or `details`.
 */
export interface AfterToolCallResult {
	content?: (TextContent | ImageContent)[];
	details?: unknown;
	isError?: boolean;
	/**
	 * Hint that the agent should stop after the current tool batch.
	 * Early termination only happens when every finalized tool result in the batch sets this to true.
	 */
	terminate?: boolean;
}

/** Context passed to `beforeToolCall`. */
export interface BeforeToolCallContext {
	/** The assistant message that requested the tool call. */
	assistantMessage: AssistantMessage;
	/** The raw tool call block from `assistantMessage.content`. */
	toolCall: AgentToolCall;
	/** Validated tool arguments for the target tool schema. */
	args: unknown;
	/** Current agent context at the time the tool call is prepared. */
	context: AgentContext;
}

/** Context passed to `afterToolCall`. */
export interface AfterToolCallContext {
	/** The assistant message that requested the tool call. */
	assistantMessage: AssistantMessage;
	/** The raw tool call block from `assistantMessage.content`. */
	toolCall: AgentToolCall;
	/** Validated tool arguments for the target tool schema. */
	args: unknown;
	/** The executed tool result before any `afterToolCall` overrides are applied. */
	result: AgentToolResult<any>;
	/** Whether the executed tool result is currently treated as an error. */
	isError: boolean;
	/** Current agent context at the time the tool call is finalized. */
	context: AgentContext;
}

/** Context passed to `shouldStopAfterTurn`. */
export interface ShouldStopAfterTurnContext {
	/** The assistant message that completed the turn. */
	message: AssistantMessage;
	/** Tool result messages passed to the preceding `turn_end` event. */
	toolResults: ToolResultMessage[];
	/** Current agent context after the turn's assistant message and tool results have been appended. */
	context: AgentContext;
	/** Messages that this loop invocation will return if it exits at this point. Prompt runs include the initial prompt messages; continuation runs do not include pre-existing context messages. */
	newMessages: AgentMessage[];
}

/** Replacement runtime state used by the agent loop before starting another provider request. */
export interface AgentLoopTurnUpdate {
	/** Context for the next provider request. */
	context?: AgentContext;
	/** Model for the next provider request. */
	model?: Model<any>;
	/** Thinking level for the next provider request. */
	thinkingLevel?: ThinkingLevel;
}

export interface PrepareNextTurnContext extends ShouldStopAfterTurnContext {}

export interface AgentLoopConfig extends SimpleStreamOptions {
	model: Model<any>;

	/**
	 * Converts AgentMessage[] to LLM-compatible Message[] before each LLM call.
	 *
	 * Each AgentMessage must be converted to a UserMessage, AssistantMessage, or ToolResultMessage
	 * that the LLM can understand. AgentMessages that cannot be converted (e.g., UI-only notifications,
	 * status messages) should be filtered out.
	 *
	 * Contract: must not throw or reject. Return a safe fallback value instead.
	 * Throwing interrupts the low-level agent loop without producing a normal event sequence.
	 *
	 * @example
	 * ```typescript
	 * convertToLlm: (messages) => messages.flatMap(m => {
	 *   if (m.role === "custom") {
	 *     // Convert custom message to user message
	 *     return [{ role: "user", content: m.content, timestamp: m.timestamp }];
	 *   }
	 *   if (m.role === "notification") {
	 *     // Filter out UI-only messages
	 *     return [];
	 *   }
	 *   // Pass through standard LLM messages
	 *   return [m];
	 * })
	 * ```
	 */
	convertToLlm: (messages: AgentMessage[]) => Message[] | Promise<Message[]>;

	/**
	 * Optional lease gate checked immediately before a queued message is emitted.
	 * Return false to drop a cancelled message without persisting it.
	 */
	claimMessageDelivery?: (message: AgentMessage) => boolean;

	/**
	 * Optional transform applied to the context before `convertToLlm`.
	 *
	 * Use this for operations that work at the AgentMessage level:
	 * - Context window management (pruning old messages)
	 * - Injecting context from external sources
	 *
	 * Contract: must not throw or reject. Return the original messages or another
	 * safe fallback value instead.
	 *
	 * @example
	 * ```typescript
	 * transformContext: async (messages) => {
	 *   if (estimateTokens(messages) > MAX_TOKENS) {
	 *     return pruneOldMessages(messages);
	 *   }
	 *   return messages;
	 * }
	 * ```
	 */
	transformContext?: (messages: AgentMessage[], signal?: AbortSignal) => Promise<AgentMessage[]>;

	/**
	 * Resolves an API key dynamically for each LLM call.
	 *
	 * Useful for short-lived OAuth tokens (e.g., GitHub Copilot) that may expire
	 * during long-running tool execution phases.
	 *
	 * Contract: must not throw or reject. Return undefined when no key is available.
	 */
	getApiKey?: (provider: string) => Promise<string | undefined> | string | undefined;

	/**
	 * Called after each turn fully completes and `turn_end` has been emitted.
	 *
	 * If it returns true, the loop emits `agent_end` and exits before polling steering or follow-up queues,
	 * without starting another LLM call. The current assistant response and any tool executions finish normally.
	 *
	 * Use this to request a graceful stop after the current turn, e.g. before context gets too full.
	 *
	 * Contract: must not throw or reject. Throwing interrupts the low-level agent loop without producing a normal event sequence.
	 */
	shouldStopAfterTurn?: (context: ShouldStopAfterTurnContext) => boolean | Promise<boolean>;

	/**
	 * Optional hard cap on the number of assistant turns (provider requests) in a
	 * single run. A "turn" is one streamed assistant response (possibly containing
	 * tool calls that are then executed). When the cap is reached after a turn
	 * completes (turn_end emitted), the loop stops gracefully via `agent_end`
	 * before starting another provider request — the in-flight turn is never cut.
	 *
	 * Undefined / non-positive = unbounded (preserves the default behavior; the
	 * only other turn cap is the `shouldStopAfterTurn` compaction hook).
	 *
	 * Use this as a foundational guard against runaway tool-call loops. To observe
	 * that a run stopped because of the budget (rather than naturally), supply
	 * `onRunBudgetExceeded`.
	 */
	maxTurns?: number;

	/**
	 * Reserve the last request in {@link maxTurns} for a tool-free synthesis turn.
	 *
	 * When the model is still requesting tools with one turn left, the loop removes
	 * tools from the final request and injects {@link finalTurnPrompt}. This keeps a
	 * hard request budget while still producing a user-facing answer. Disabled by
	 * default for backwards compatibility with low-level loop consumers.
	 */
	reserveFinalTurn?: boolean;

	/** Prompt used by the reserved tool-free synthesis turn. */
	finalTurnPrompt?: string;

	/**
	 * Called when the loop stops because `maxTurns` was reached, after the final
	 * `turn_end` and before `agent_end`. Pure side-effect channel (e.g. surface a
	 * "max_turns_exceeded" notice to the consumer); the loop has already decided
	 * to stop. Contract: must not throw or reject.
	 */
	onRunBudgetExceeded?: (info: { turns: number; maxTurns: number }) => void;

	/**
	 * Maximum number of automatic continuation re-prompts when the model stops
	 * with `stopReason === "length"` (output hit the model's `maxTokens` limit)
	 * and the assistant message contains no tool calls.
	 *
	 * When enabled (>0) and a length stop occurs, the loop injects a short
	 * continuation user message and streams another response so the model resumes
	 * its cut-off output instead of ending the turn. Each continuation is a full
	 * provider request that counts toward {@link maxTurns}. The cap bounds the
	 * total continuations per run (0 = disabled, the default — a length stop
	 * ends the turn as before).
	 *
	 * Use {@link lengthContinuePrompt} to customize the injected message.
	 */
	lengthContinueMaxTurns?: number;

	/**
	 * Override the user message injected on a length auto-continue. Defaults to a
	 * concise "continue where you left off" instruction. Ignored when
	 * {@link lengthContinueMaxTurns} is 0/unset.
	 */
	lengthContinuePrompt?: string;

	/**
	 * Maximum number of times to retry a single assistant stream request when the
	 * provider fails BEFORE emitting any content (the common transient case:
	 * connection reset, DNS, 429, 5xx — all surface as `stopReason === "error"`
	 * with no `start`/content event having reached the loop).
	 *
	 * Retries are safe because nothing has been emitted to the consumer yet: no
	 * `message_start`, no deltas. The loop discards the empty error message,
	 * waits with exponential backoff, and re-issues the same request. A retry is
	 * NOT a new turn — it does not count toward {@link maxTurns}.
	 *
	 * Once the stream has started (`message_start` emitted), an error is surfaced
	 * immediately without retry, so partial output is never duplicated or lost.
	 *
	 * 0 / undefined = disabled (default — a stream error ends the turn as before).
	 * Use {@link isRetryableStreamError} to filter which errors are worth retrying,
	 * and {@link streamRetryBaseDelayMs} / {@link streamRetryMaxDelayMs} to shape
	 * the backoff.
	 */
	streamMaxRetries?: number;

	/**
	 * Base delay in ms for stream-request retry backoff. The n-th retry waits
	 * `min(baseDelay * 2^n, maxDelay)`. Default 1000ms. Ignored when
	 * {@link streamMaxRetries} is 0/unset.
	 */
	streamRetryBaseDelayMs?: number;

	/**
	 * Cap in ms for stream-request retry backoff. Default 30000ms. Ignored when
	 * {@link streamMaxRetries} is 0/unset.
	 */
	streamRetryMaxDelayMs?: number;

	/**
	 * Predicate deciding whether a pre-stream error is worth retrying. Receives
	 * the final assistant message (with `stopReason === "error"` and
	 * `errorMessage`). Defaults to a conservative heuristic that skips obvious
	 * permanent failures (auth, quota, model-not-found) and retries everything
	 * else. Ignored when {@link streamMaxRetries} is 0/unset.
	 */
	isRetryableStreamError?: (message: AssistantMessage) => boolean;

	/**
	 * Defense-in-depth cap on the size of a tool result's TEXT content blocks
	 * before it enters the model's context. When a block exceeds this many
	 * characters it is head+tail truncated with an elided-char-count marker.
	 * Non-text (image) blocks are never touched.
	 *
	 * Built-in tools already self-truncate (read/bash/grep ~50KB), so this only
	 * catches misbehaving custom/MCP extension tools that return huge results
	 * and would otherwise blow the context window. Default 262144 chars
	 * (256K) — well above the built-in limits, so well-behaved results are
	 * untouched. Set to 0 to disable the cap. Applied at the context boundary
	 * only (the persisted tool result message); tool-execution events for the
	 * UI keep the original.
	 */
	maxToolResultChars?: number;

	/**
	 * Aggregate text budget for tool results that have already been consumed by a
	 * later assistant turn. The newest, not-yet-consumed tool results remain intact;
	 * older results are compacted only in the provider projection, not in the
	 * transcript or UI events. Set to 0 to disable.
	 */
	maxConsumedToolResultChars?: number;

	/**
	 * Reuse an earlier successful invocation marker when an identical read-only
	 * tool probe is requested again in the same run. Any non-read-only call clears
	 * the probe history. Defaults to true; tools must opt in with `readOnly`.
	 */
	deduplicateReadOnlyToolCalls?: boolean;

	/**
	 * Called after `turn_end` and before the loop decides whether another provider request should start.
	 * Return replacement context/model/thinking state to affect the next turn in this run.
	 * Return undefined to keep using the current context/config.
	 */
	prepareNextTurn?: (
		context: PrepareNextTurnContext,
	) => AgentLoopTurnUpdate | undefined | Promise<AgentLoopTurnUpdate | undefined>;

	/**
	 * Returns steering messages to inject into the conversation mid-run.
	 *
	 * Called after the current assistant turn finishes executing its tool calls, unless `shouldStopAfterTurn` exits first.
	 * If messages are returned, they are added to the context before the next LLM call.
	 * Tool calls from the current assistant message are not skipped.
	 *
	 * Use this for "steering" the agent while it's working.
	 *
	 * Contract: must not throw or reject. Return [] when no steering messages are available.
	 */
	getSteeringMessages?: () => Promise<AgentMessage[]>;

	/**
	 * Returns follow-up messages to process after the agent would otherwise stop.
	 *
	 * Called when the agent has no more tool calls and no steering messages.
	 * If messages are returned, they're added to the context and the agent
	 * continues with another turn.
	 *
	 * Use this for follow-up messages that should wait until the agent finishes.
	 *
	 * Contract: must not throw or reject. Return [] when no follow-up messages are available.
	 */
	getFollowUpMessages?: () => Promise<AgentMessage[]>;

	/**
	 * Tool execution mode.
	 * - "sequential": execute tool calls one by one
	 * - "parallel": preflight tool calls sequentially, then execute allowed tools concurrently;
	 *   emit `tool_execution_end` in tool completion order after each tool is finalized,
	 *   then emit tool-result message artifacts later in assistant source order
	 *
	 * Default: "parallel"
	 */
	toolExecution?: ToolExecutionMode;

	/**
	 * Called before a tool is executed, after arguments have been validated.
	 *
	 * Return `{ block: true }` to prevent execution. The loop emits an error tool result instead.
	 * The hook receives the agent abort signal and is responsible for honoring it.
	 */
	beforeToolCall?: (context: BeforeToolCallContext, signal?: AbortSignal) => Promise<BeforeToolCallResult | undefined>;

	/**
	 * Called after a tool finishes executing, before `tool_execution_end` and tool-result message events are emitted.
	 *
	 * Return an `AfterToolCallResult` to override parts of the executed tool result:
	 * - `content` replaces the full content array
	 * - `details` replaces the full details payload
	 * - `isError` replaces the error flag
	 * - `terminate` replaces the early-termination hint
	 *
	 * Any omitted fields keep their original values. No deep merge is performed.
	 * The hook receives the agent abort signal and is responsible for honoring it.
	 */
	afterToolCall?: (context: AfterToolCallContext, signal?: AbortSignal) => Promise<AfterToolCallResult | undefined>;
}

/**
 * Thinking/reasoning level for models that support it.
 * Note: "xhigh" is only supported by selected model families. Use model thinking-level metadata
 * from @pi-recon/repi-ai to detect support for a concrete model.
 */
export type ThinkingLevel = "off" | "minimal" | "low" | "medium" | "high" | "xhigh";

/**
 * Extensible interface for custom app messages.
 * Apps can extend via declaration merging:
 *
 * @example
 * ```typescript
 * declare module "@mariozechner/agent" {
 *   interface CustomAgentMessages {
 *     artifact: ArtifactMessage;
 *     notification: NotificationMessage;
 *   }
 * }
 * ```
 */
export interface CustomAgentMessages {
	// Empty by default - apps extend via declaration merging
}

/**
 * AgentMessage: Union of LLM messages + custom messages.
 * This abstraction allows apps to add custom message types while maintaining
 * type safety and compatibility with the base LLM messages.
 */
export type AgentMessage = Message | CustomAgentMessages[keyof CustomAgentMessages];

/**
 * Public agent state.
 *
 * `tools` and `messages` use accessor properties so implementations can copy
 * assigned arrays before storing them.
 */
export interface AgentState {
	/** System prompt sent with each model request. */
	systemPrompt: string;
	/** Active model used for future turns. */
	model: Model<any>;
	/** Requested reasoning level for future turns. */
	thinkingLevel: ThinkingLevel;
	/** Available tools. Assigning a new array copies the top-level array. */
	set tools(tools: AgentTool<any>[]);
	get tools(): AgentTool<any>[];
	/** Conversation transcript. Assigning a new array copies the top-level array. */
	set messages(messages: AgentMessage[]);
	get messages(): AgentMessage[];
	/**
	 * True while the agent is processing a prompt or continuation.
	 *
	 * This remains true until awaited `agent_end` listeners settle.
	 */
	readonly isStreaming: boolean;
	/** Partial assistant message for the current streamed response, if any. */
	readonly streamingMessage?: AgentMessage;
	/** Tool call ids currently executing. */
	readonly pendingToolCalls: ReadonlySet<string>;
	/** Error message from the most recent failed or aborted assistant turn, if any. */
	readonly errorMessage?: string;
}

/** Final or partial result produced by a tool. */
export interface AgentToolResult<T> {
	/** Text or image content returned to the model. */
	content: (TextContent | ImageContent)[];
	/** Arbitrary structured details for logs or UI rendering. */
	details: T;
	/** Names of tools introduced by this result and available from this transcript point onward. */
	addedToolNames?: string[];
	/**
	 * Hint that the agent should stop after the current tool batch.
	 * Early termination only happens when every finalized tool result in the batch sets this to true.
	 */
	terminate?: boolean;
}

/** Callback used by tools to stream partial execution updates. */
export type AgentToolUpdateCallback<T = any> = (partialResult: AgentToolResult<T>) => void;

/** Tool definition used by the agent runtime. */
export interface AgentTool<TParameters extends TSchema = TSchema, TDetails = any> extends Tool<TParameters> {
	/** Human-readable label for UI display. */
	label: string;
	/**
	 * Optional compatibility shim for raw tool-call arguments before schema validation.
	 * Must return an object that matches `TParameters`.
	 */
	prepareArguments?: (args: unknown) => Static<TParameters>;
	/** Execute the tool call. Throw on failure instead of encoding errors in `content`. */
	execute: (
		toolCallId: string,
		params: Static<TParameters>,
		signal?: AbortSignal,
		onUpdate?: AgentToolUpdateCallback<TDetails>,
	) => Promise<AgentToolResult<TDetails>>;
	/**
	 * Per-tool execution mode override.
	 * - "sequential": this tool must execute one at a time with other tool calls.
	 * - "parallel": this tool can execute concurrently with other tool calls.
	 *
	 * If omitted, the default execution mode applies.
	 */
	executionMode?: ToolExecutionMode;
	/**
	 * Declares that this tool only observes state. Identical successful calls may
	 * be deduplicated within one agent run until a non-read-only tool is requested.
	 */
	readOnly?: boolean;
	/**
	 * Optional conservative coverage relation for read-only probes. Return true
	 * only when the successful previous call's result contains every observation
	 * the next call would request. The runtime clears probe history at every
	 * mutating/unknown tool boundary.
	 */
	readOnlyProbeCovers?(previous: Static<TParameters>, next: Static<TParameters>): boolean;
}

/** Context snapshot passed into the low-level agent loop. */
export interface AgentContext {
	/** System prompt included with the request. */
	systemPrompt: string;
	/** Transcript visible to the model. */
	messages: AgentMessage[];
	/** Tools available for this run. */
	tools?: AgentTool<any>[];
}

/**
 * Events emitted by the Agent for UI updates.
 *
 * `agent_end` is the last event emitted for a run, but awaited `Agent.subscribe()`
 * listeners for that event are still part of run settlement. The agent becomes
 * idle only after those listeners finish.
 */
export type AgentEvent =
	// Agent lifecycle
	| { type: "agent_start" }
	| { type: "agent_end"; messages: AgentMessage[] }
	// Turn lifecycle - a turn is one assistant response + any tool calls/results
	| { type: "turn_start" }
	| { type: "turn_end"; message: AgentMessage; toolResults: ToolResultMessage[] }
	// Message lifecycle - emitted for user, assistant, and toolResult messages
	| { type: "message_start"; message: AgentMessage }
	// Only emitted for assistant messages during streaming
	| { type: "message_update"; message: AgentMessage; assistantMessageEvent: AssistantMessageEvent }
	| { type: "message_end"; message: AgentMessage }
	// Tool execution lifecycle
	| { type: "tool_execution_start"; toolCallId: string; toolName: string; args: any }
	| { type: "tool_execution_update"; toolCallId: string; toolName: string; args: any; partialResult: any }
	| { type: "tool_execution_end"; toolCallId: string; toolName: string; result: any; isError: boolean };

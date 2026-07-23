import {
	type AssistantMessage,
	type ImageContent,
	type Message,
	type Model,
	type SimpleStreamOptions,
	streamSimple,
	type TextContent,
	type ThinkingBudgets,
	type Transport,
} from "@pi-recon/repi-ai";
import { AgentEventDeliveryError, runAgentLoop, runAgentLoopContinue } from "./agent-loop.ts";
import { PendingMessageQueue } from "./pending-message-queue.ts";
import type {
	AfterToolCallContext,
	AfterToolCallResult,
	AgentContext,
	AgentEvent,
	AgentLoopConfig,
	AgentLoopTurnUpdate,
	AgentMessage,
	AgentState,
	AgentTool,
	BeforeToolCallContext,
	BeforeToolCallResult,
	QueueMode,
	ShouldStopAfterTurnContext,
	StreamFn,
	ToolExecutionMode,
} from "./types.ts";

export type { QueueMode } from "./types.ts";

/**
 * Max concurrent `abort` listeners tolerated on the per-run AbortSignal before
 * Node emits MaxListenersExceededWarning. The run signal is shared by every
 * tool call + provider fetch + retry sleep in the run, so a parallel tool
 * batch legitimately attaches many. Env REPI_RUN_SIGNAL_MAX_LISTENERS; default
 * 50; 0 = unbounded (disable the warning). Negative/invalid → default. (opt #129)
 */
function parseRunSignalMaxListeners(): number {
	const raw = process.env.REPI_RUN_SIGNAL_MAX_LISTENERS;
	if (raw === undefined) return 50;
	const parsed = Number.parseInt(raw, 10);
	if (!Number.isFinite(parsed)) return 50;
	return parsed;
}

// Lazily resolved Node `events` module `setMaxListeners`. The specifier is
// built by concatenation so esbuild's browser bundle CANNOT statically resolve
// `node:events` (which has no browser polyfill) — it stays a runtime dynamic
// import that the browser-smoke build (which never calls prompt()) never
// executes. In Node it resolves to the built-in. `null` = not-yet-resolved,
// `undefined` = resolved but unavailable (non-Node runtime). (opt #129)
let nodeSetMaxListeners: ((n: number, target: AbortSignal) => void) | undefined | null = null;
async function resolveNodeSetMaxListeners(): Promise<typeof nodeSetMaxListeners> {
	if (nodeSetMaxListeners === null) {
		try {
			const mod = (await import("node:" + "events")) as {
				setMaxListeners?: (n: number, ...targets: AbortSignal[]) => void;
			};
			nodeSetMaxListeners = mod.setMaxListeners?.bind(mod);
		} catch {
			nodeSetMaxListeners = undefined;
		}
	}
	return nodeSetMaxListeners;
}

function defaultConvertToLlm(messages: AgentMessage[]): Message[] {
	return messages.filter(
		(message) => message.role === "user" || message.role === "assistant" || message.role === "toolResult",
	);
}

const EMPTY_USAGE = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

const DEFAULT_MODEL = {
	id: "unknown",
	name: "unknown",
	api: "unknown",
	provider: "unknown",
	baseUrl: "",
	reasoning: false,
	input: [],
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
	contextWindow: 0,
	maxTokens: 0,
} satisfies Model<any>;

type MutableAgentState = Omit<AgentState, "isStreaming" | "streamingMessage" | "pendingToolCalls" | "errorMessage"> & {
	isStreaming: boolean;
	streamingMessage?: AgentMessage;
	pendingToolCalls: Set<string>;
	errorMessage?: string;
};

function createMutableAgentState(
	initialState?: Partial<Omit<AgentState, "pendingToolCalls" | "isStreaming" | "streamingMessage" | "errorMessage">>,
): MutableAgentState {
	let tools = initialState?.tools?.slice() ?? [];
	let messages = initialState?.messages?.slice() ?? [];

	return {
		systemPrompt: initialState?.systemPrompt ?? "",
		model: initialState?.model ?? DEFAULT_MODEL,
		thinkingLevel: initialState?.thinkingLevel ?? "off",
		get tools() {
			return tools;
		},
		set tools(nextTools: AgentTool<any>[]) {
			tools = nextTools.slice();
		},
		get messages() {
			return messages;
		},
		set messages(nextMessages: AgentMessage[]) {
			messages = nextMessages.slice();
		},
		isStreaming: false,
		streamingMessage: undefined,
		pendingToolCalls: new Set<string>(),
		errorMessage: undefined,
	};
}

/** Options for constructing an {@link Agent}. */
export interface AgentOptions {
	initialState?: Partial<Omit<AgentState, "pendingToolCalls" | "isStreaming" | "streamingMessage" | "errorMessage">>;
	convertToLlm?: (messages: AgentMessage[]) => Message[] | Promise<Message[]>;
	transformContext?: (messages: AgentMessage[], signal?: AbortSignal) => Promise<AgentMessage[]>;
	streamFn?: StreamFn;
	getApiKey?: (provider: string) => Promise<string | undefined> | string | undefined;
	onPayload?: SimpleStreamOptions["onPayload"];
	onResponse?: SimpleStreamOptions["onResponse"];
	beforeToolCall?: (context: BeforeToolCallContext, signal?: AbortSignal) => Promise<BeforeToolCallResult | undefined>;
	afterToolCall?: (context: AfterToolCallContext, signal?: AbortSignal) => Promise<AfterToolCallResult | undefined>;
	shouldStopAfterTurn?: (context: ShouldStopAfterTurnContext, signal?: AbortSignal) => boolean | Promise<boolean>;
	/**
	 * Optional hard cap on assistant turns per prompt, including internal continue() runs.
	 * Non-positive / undefined = unbounded (default).
	 */
	maxTurns?: number;
	/** See {@link AgentLoopConfig.reserveFinalTurn}. */
	reserveFinalTurn?: boolean;
	/** See {@link AgentLoopConfig.finalTurnPrompt}. */
	finalTurnPrompt?: string;
	/**
	 * Side-effect callback fired when a run stops because {@link maxTurns} was reached.
	 */
	onRunBudgetExceeded?: (info: { turns: number; maxTurns: number }) => void;
	/** See {@link AgentLoopConfig.lengthContinueMaxTurns}. */
	lengthContinueMaxTurns?: number;
	/** See {@link AgentLoopConfig.lengthContinuePrompt}. */
	lengthContinuePrompt?: string;
	/** See {@link AgentLoopConfig.streamMaxRetries}. */
	streamMaxRetries?: number;
	/** See {@link AgentLoopConfig.streamRetryBaseDelayMs}. */
	streamRetryBaseDelayMs?: number;
	/** See {@link AgentLoopConfig.streamRetryMaxDelayMs}. */
	streamRetryMaxDelayMs?: number;
	/** See {@link AgentLoopConfig.isRetryableStreamError}. */
	isRetryableStreamError?: (message: AssistantMessage) => boolean;
	/** See {@link AgentLoopConfig.maxToolResultChars}. */
	maxToolResultChars?: number;
	/** See {@link AgentLoopConfig.maxConsumedToolResultChars}. */
	maxConsumedToolResultChars?: number;
	/** See {@link AgentLoopConfig.deduplicateReadOnlyToolCalls}. */
	deduplicateReadOnlyToolCalls?: boolean;
	prepareNextTurn?: (
		signal?: AbortSignal,
	) => Promise<AgentLoopTurnUpdate | undefined> | AgentLoopTurnUpdate | undefined;
	steeringMode?: QueueMode;
	followUpMode?: QueueMode;
	sessionId?: string;
	thinkingBudgets?: ThinkingBudgets;
	transport?: Transport;
	maxRetryDelayMs?: number;
	toolExecution?: ToolExecutionMode;
}

type ActiveRun = {
	promise: Promise<void>;
	resolve: () => void;
	abortController: AbortController;
};

type PromptTurnBudget = {
	maxTurns: number;
	turnsUsed: number;
	noticeEmitted: boolean;
};

function normalizeMaxTurns(maxTurns: number | undefined): number {
	return typeof maxTurns === "number" && Number.isFinite(maxTurns) && maxTurns > 0
		? Math.max(1, Math.floor(maxTurns))
		: 0;
}

/**
 * Stateful wrapper around the low-level agent loop.
 *
 * `Agent` owns the current transcript, emits lifecycle events, executes tools,
 * and exposes queueing APIs for steering and follow-up messages.
 */
export class Agent {
	private _state: MutableAgentState;
	private readonly listeners = new Set<(event: AgentEvent, signal: AbortSignal) => Promise<void> | void>();
	private readonly steeringQueue: PendingMessageQueue<AgentMessage>;
	private readonly followUpQueue: PendingMessageQueue<AgentMessage>;
	// Per-run terminal-event tracking for handleRunFailure: if a real assistant
	// was already committed (message_end fired) before a throw — e.g. a listener
	// threw inside processEvents on a message_update, or a post-message hook
	// (prepareNextTurn/shouldStopAfterTurn/getSteeringMessages) threw — do NOT
	// synthesize a fresh message_start/message_end. That would double-push a
	// second message_end and a PHANTOM assistant into the durable state on top
	// of the real one. Mirrors opt #97 F1-phantom in the harness emitRunFailure;
	// the loop-level catch already commits the partial via message_end + re-throws
	// (FIX 3 contract), so a committed message is observable here.
	private turnMessageEndEmitted = false;
	private turnEndEmitted = false;
	private agentEndEmitted = false;
	private lastCommittedAssistant?: AssistantMessage;

	public convertToLlm: (messages: AgentMessage[]) => Message[] | Promise<Message[]>;
	public transformContext?: (messages: AgentMessage[], signal?: AbortSignal) => Promise<AgentMessage[]>;
	public streamFn: StreamFn;
	public getApiKey?: (provider: string) => Promise<string | undefined> | string | undefined;
	public onPayload?: SimpleStreamOptions["onPayload"];
	public onResponse?: SimpleStreamOptions["onResponse"];
	public beforeToolCall?: (
		context: BeforeToolCallContext,
		signal?: AbortSignal,
	) => Promise<BeforeToolCallResult | undefined>;
	public afterToolCall?: (
		context: AfterToolCallContext,
		signal?: AbortSignal,
	) => Promise<AfterToolCallResult | undefined>;
	public shouldStopAfterTurn?: (
		context: ShouldStopAfterTurnContext,
		signal?: AbortSignal,
	) => boolean | Promise<boolean>;
	/** Hard cap on assistant turns per prompt, including internal continue() runs. */
	public maxTurns?: number;
	/** Whether maxTurns reserves a final tool-free synthesis request. */
	public reserveFinalTurn?: boolean;
	/** Override prompt for the reserved final synthesis request. */
	public finalTurnPrompt?: string;
	/** Fired when a run stops because maxTurns was reached. */
	public onRunBudgetExceeded?: (info: { turns: number; maxTurns: number }) => void;
	/** Max auto-continue re-prompts on a length stop (0/unset = disabled). */
	public lengthContinueMaxTurns?: number;
	/** Override prompt injected on a length auto-continue. */
	public lengthContinuePrompt?: string;
	/** Max retries of a pre-stream transient failure (0/unset = disabled). */
	public streamMaxRetries?: number;
	/** Base delay ms for stream retry backoff. */
	public streamRetryBaseDelayMs?: number;
	/** Cap ms for stream retry backoff. */
	public streamRetryMaxDelayMs?: number;
	/** Predicate filtering which pre-stream errors are retried. */
	public isRetryableStreamError?: (message: AssistantMessage) => boolean;
	/** Defense-in-depth cap (chars) on tool result text blocks; 0 disables. */
	public maxToolResultChars?: number;
	/** Aggregate provider-context budget for already-consumed tool results. */
	public maxConsumedToolResultChars?: number;
	/** Whether identical read-only probes are deduplicated within a run. */
	public deduplicateReadOnlyToolCalls?: boolean;
	public prepareNextTurn?: (
		signal?: AbortSignal,
	) => Promise<AgentLoopTurnUpdate | undefined> | AgentLoopTurnUpdate | undefined;
	private activeRun?: ActiveRun;
	private promptTurnBudget: PromptTurnBudget | undefined;
	private promptTurnBudgetActive = false;
	/** Session identifier forwarded to providers for cache-aware backends. */
	public sessionId?: string;
	/** Optional per-level thinking token budgets forwarded to the stream function. */
	public thinkingBudgets?: ThinkingBudgets;
	/** Preferred transport forwarded to the stream function. */
	public transport: Transport;
	/** Optional cap for provider-requested retry delays. */
	public maxRetryDelayMs?: number;
	/** Tool execution strategy for assistant messages that contain multiple tool calls. */
	public toolExecution: ToolExecutionMode;

	constructor(options: AgentOptions = {}) {
		this._state = createMutableAgentState(options.initialState);
		this.convertToLlm = options.convertToLlm ?? defaultConvertToLlm;
		this.transformContext = options.transformContext;
		this.streamFn = options.streamFn ?? streamSimple;
		this.getApiKey = options.getApiKey;
		this.onPayload = options.onPayload;
		this.onResponse = options.onResponse;
		this.beforeToolCall = options.beforeToolCall;
		this.afterToolCall = options.afterToolCall;
		this.shouldStopAfterTurn = options.shouldStopAfterTurn;
		this.maxTurns = options.maxTurns;
		this.reserveFinalTurn = options.reserveFinalTurn;
		this.finalTurnPrompt = options.finalTurnPrompt;
		this.onRunBudgetExceeded = options.onRunBudgetExceeded;
		this.lengthContinueMaxTurns = options.lengthContinueMaxTurns;
		this.lengthContinuePrompt = options.lengthContinuePrompt;
		this.streamMaxRetries = options.streamMaxRetries;
		this.streamRetryBaseDelayMs = options.streamRetryBaseDelayMs;
		this.streamRetryMaxDelayMs = options.streamRetryMaxDelayMs;
		this.isRetryableStreamError = options.isRetryableStreamError;
		this.maxToolResultChars = options.maxToolResultChars;
		this.maxConsumedToolResultChars = options.maxConsumedToolResultChars;
		this.deduplicateReadOnlyToolCalls = options.deduplicateReadOnlyToolCalls;
		this.prepareNextTurn = options.prepareNextTurn;
		this.steeringQueue = new PendingMessageQueue<AgentMessage>(options.steeringMode ?? "one-at-a-time");
		this.followUpQueue = new PendingMessageQueue<AgentMessage>(options.followUpMode ?? "one-at-a-time");
		this.sessionId = options.sessionId;
		this.thinkingBudgets = options.thinkingBudgets;
		this.transport = options.transport ?? "auto";
		this.maxRetryDelayMs = options.maxRetryDelayMs;
		this.toolExecution = options.toolExecution ?? "parallel";
	}

	/**
	 * Subscribe to agent lifecycle events.
	 *
	 * Listener promises are awaited in subscription order and are included in
	 * the current run's settlement. Listeners also receive the active abort
	 * signal for the current run.
	 *
	 * `agent_end` is the final emitted event for a run, but the agent does not
	 * become idle until all awaited listeners for that event have settled.
	 */
	subscribe(listener: (event: AgentEvent, signal: AbortSignal) => Promise<void> | void): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	/**
	 * Current agent state.
	 *
	 * Assigning `state.tools` or `state.messages` copies the provided top-level array.
	 */
	get state(): AgentState {
		return this._state;
	}

	/** Controls how queued steering messages are drained. */
	set steeringMode(mode: QueueMode) {
		this.steeringQueue.mode = mode;
	}

	get steeringMode(): QueueMode {
		return this.steeringQueue.mode;
	}

	/** Controls how queued follow-up messages are drained. */
	set followUpMode(mode: QueueMode) {
		this.followUpQueue.mode = mode;
	}

	get followUpMode(): QueueMode {
		return this.followUpQueue.mode;
	}

	/** Queue a message to be injected after the current assistant turn finishes. */
	steer(message: AgentMessage): void {
		this.steeringQueue.enqueue(message);
	}

	/** Queue a message to run only after the agent would otherwise stop. */
	followUp(message: AgentMessage): void {
		this.followUpQueue.enqueue(message);
	}

	/** Remove all queued steering messages. */
	clearSteeringQueue(): void {
		this.steeringQueue.clear();
	}

	/** Remove all queued follow-up messages. */
	clearFollowUpQueue(): void {
		this.followUpQueue.clear();
	}

	/** Remove all queued steering and follow-up messages. */
	clearAllQueues(): void {
		this.clearSteeringQueue();
		this.clearFollowUpQueue();
	}

	/** Returns true when either queue still contains pending messages. */
	hasQueuedMessages(): boolean {
		return this.steeringQueue.hasItems() || this.followUpQueue.hasItems();
	}

	/** Active abort signal for the current run, if any. */
	get signal(): AbortSignal | undefined {
		return this.activeRun?.abortController.signal;
	}

	/** Whether the current explicit prompt has consumed its full assistant-turn budget. */
	get isPromptTurnBudgetExhausted(): boolean {
		return this.remainingPromptTurns() === 0;
	}

	/** Abort the current run, if one is active. */
	abort(): void {
		this.activeRun?.abortController.abort();
	}

	/**
	 * Resolve when the current run and all awaited event listeners have finished.
	 *
	 * This resolves after `agent_end` listeners settle.
	 */
	waitForIdle(): Promise<void> {
		return this.activeRun?.promise ?? Promise.resolve();
	}

	/** Clear transcript state, runtime state, and queued messages. */
	reset(): void {
		if (this.activeRun) {
			throw new Error("Cannot reset while Agent is processing. Abort and wait for completion first.");
		}
		this._state.messages = [];
		this._state.isStreaming = false;
		this._state.streamingMessage = undefined;
		this._state.pendingToolCalls = new Set<string>();
		this._state.errorMessage = undefined;
		this.clearFollowUpQueue();
		this.clearSteeringQueue();
		this.promptTurnBudget = undefined;
		this.promptTurnBudgetActive = false;
	}

	/** Start a new prompt from text, a single message, or a batch of messages. */
	async prompt(message: AgentMessage | AgentMessage[]): Promise<void>;
	async prompt(input: string, images?: ImageContent[]): Promise<void>;
	async prompt(input: string | AgentMessage | AgentMessage[], images?: ImageContent[]): Promise<void> {
		if (this.activeRun) {
			throw new Error(
				"Agent is already processing a prompt. Use steer() or followUp() to queue messages, or wait for completion.",
			);
		}
		const messages = this.normalizePromptInput(input, images);
		this.beginPromptTurnBudget();
		await this.runPromptMessages(messages);
	}

	/** Continue from the current transcript. The last message must be a user or tool-result message. */
	async continue(): Promise<void> {
		if (this.activeRun) {
			throw new Error("Agent is already processing. Wait for completion before continuing.");
		}

		const lastMessage = this._state.messages[this._state.messages.length - 1];
		if (!lastMessage) {
			throw new Error("No messages to continue from");
		}
		if (!this.promptTurnBudgetActive) this.beginPromptTurnBudget();

		const budgetExhausted = this.remainingPromptTurns() === 0;

		if (lastMessage.role === "assistant") {
			if (!this.hasQueuedMessages()) {
				throw new Error("Cannot continue from message role: assistant");
			}
			if (budgetExhausted) {
				this.notifyPromptTurnBudgetExceeded();
				return;
			}
			const queuedSteering = this.steeringQueue.drain();
			if (queuedSteering.length > 0) {
				await this.runPromptMessages(queuedSteering, { skipInitialSteeringPoll: true });
				return;
			}

			const queuedFollowUps = this.followUpQueue.drain();
			if (queuedFollowUps.length > 0) {
				await this.runPromptMessages(queuedFollowUps);
				return;
			}

			throw new Error("Cannot continue from message role: assistant");
		}

		if (budgetExhausted) {
			this.notifyPromptTurnBudgetExceeded();
			return;
		}

		await this.runContinuation();
	}

	private beginPromptTurnBudget(): void {
		const maxTurns = normalizeMaxTurns(this.maxTurns);
		this.promptTurnBudget = maxTurns > 0 ? { maxTurns, turnsUsed: 0, noticeEmitted: false } : undefined;
		this.promptTurnBudgetActive = true;
	}

	private remainingPromptTurns(): number | undefined {
		if (!this.promptTurnBudget) return undefined;
		return Math.max(0, this.promptTurnBudget.maxTurns - this.promptTurnBudget.turnsUsed);
	}

	/** Emit the prompt-budget notification once. Used by session runtimes that stop before another continue(). */
	notifyPromptTurnBudgetExceeded(): void {
		const budget = this.promptTurnBudget;
		if (!budget || budget.noticeEmitted) return;
		budget.noticeEmitted = true;
		try {
			this.onRunBudgetExceeded?.({ turns: budget.turnsUsed, maxTurns: budget.maxTurns });
		} catch {
			// Side-effect channel only; never interrupt loop settlement.
		}
	}

	private normalizePromptInput(
		input: string | AgentMessage | AgentMessage[],
		images?: ImageContent[],
	): AgentMessage[] {
		if (Array.isArray(input)) {
			return input;
		}

		if (typeof input !== "string") {
			return [input];
		}

		const content: Array<TextContent | ImageContent> = [{ type: "text", text: input }];
		if (images && images.length > 0) {
			content.push(...images);
		}
		return [{ role: "user", content, timestamp: Date.now() }];
	}

	private async runPromptMessages(
		messages: AgentMessage[],
		options: { skipInitialSteeringPoll?: boolean } = {},
	): Promise<void> {
		await this.runWithLifecycle(async (signal) => {
			await runAgentLoop(
				messages,
				this.createContextSnapshot(),
				this.createLoopConfig(options),
				(event) => this.processEvents(event),
				signal,
				this.streamFn,
			);
		});
	}

	private async runContinuation(): Promise<void> {
		await this.runWithLifecycle(async (signal) => {
			await runAgentLoopContinue(
				this.createContextSnapshot(),
				this.createLoopConfig(),
				(event) => this.processEvents(event),
				signal,
				this.streamFn,
			);
		});
	}

	private createContextSnapshot(): AgentContext {
		return {
			systemPrompt: this._state.systemPrompt,
			messages: this._state.messages.slice(),
			tools: this._state.tools.slice(),
		};
	}

	private claimQueuedMessageDelivery(message: AgentMessage): boolean {
		if (this.signal?.aborted && (this.steeringQueue.isInFlight(message) || this.followUpQueue.isInFlight(message))) {
			return false;
		}
		const steeringCancelled = this.steeringQueue.consumeCancellation(message);
		const followUpCancelled = this.followUpQueue.consumeCancellation(message);
		if (steeringCancelled || followUpCancelled) return false;
		this.steeringQueue.beginDelivery(message);
		this.followUpQueue.beginDelivery(message);
		return true;
	}

	private createLoopConfig(options: { skipInitialSteeringPoll?: boolean } = {}): AgentLoopConfig {
		let skipInitialSteeringPoll = options.skipInitialSteeringPoll === true;
		const remainingTurns = this.remainingPromptTurns();
		return {
			model: this._state.model,
			reasoning: this._state.thinkingLevel === "off" ? undefined : this._state.thinkingLevel,
			sessionId: this.sessionId,
			onPayload: this.onPayload,
			onResponse: this.onResponse,
			transport: this.transport,
			thinkingBudgets: this.thinkingBudgets,
			maxRetryDelayMs: this.maxRetryDelayMs,
			toolExecution: this.toolExecution,
			maxTurns: remainingTurns,
			reserveFinalTurn: this.reserveFinalTurn,
			finalTurnPrompt: this.finalTurnPrompt,
			onRunBudgetExceeded: this.promptTurnBudget
				? () => this.notifyPromptTurnBudgetExceeded()
				: this.onRunBudgetExceeded,
			lengthContinueMaxTurns: this.lengthContinueMaxTurns,
			lengthContinuePrompt: this.lengthContinuePrompt,
			streamMaxRetries: this.streamMaxRetries,
			streamRetryBaseDelayMs: this.streamRetryBaseDelayMs,
			streamRetryMaxDelayMs: this.streamRetryMaxDelayMs,
			isRetryableStreamError: this.isRetryableStreamError,
			maxToolResultChars: this.maxToolResultChars,
			maxConsumedToolResultChars: this.maxConsumedToolResultChars,
			deduplicateReadOnlyToolCalls: this.deduplicateReadOnlyToolCalls,
			beforeToolCall: this.beforeToolCall,
			afterToolCall: this.afterToolCall,
			shouldStopAfterTurn: this.shouldStopAfterTurn
				? async (context) => (await this.shouldStopAfterTurn?.(context, this.signal)) === true
				: undefined,
			// The low-level loop owns a context snapshot for the duration of a run. Extensions
			// and tool handlers can still update Agent.state between turns (for example,
			// progressive tool activation), so refresh the next provider turn from live state
			// even when the caller did not install a custom prepareNextTurn hook.
			prepareNextTurn: async () => {
				const prepared = await this.prepareNextTurn?.(this.signal);
				return {
					context: prepared?.context ?? this.createContextSnapshot(),
					model: prepared?.model ?? this._state.model,
					thinkingLevel: prepared?.thinkingLevel ?? this._state.thinkingLevel,
				};
			},
			convertToLlm: this.convertToLlm,
			claimMessageDelivery: (message) => this.claimQueuedMessageDelivery(message),
			transformContext: this.transformContext,
			getApiKey: this.getApiKey,
			getSteeringMessages: async () => {
				if (skipInitialSteeringPoll) {
					skipInitialSteeringPoll = false;
					return [];
				}
				return this.steeringQueue.drain();
			},
			getFollowUpMessages: async () => this.followUpQueue.drain(),
		};
	}

	private async runWithLifecycle(executor: (signal: AbortSignal) => Promise<void>): Promise<void> {
		if (this.activeRun) {
			throw new Error("Agent is already processing.");
		}

		const abortController = new AbortController();
		// The per-run AbortSignal is shared by EVERY consumer in the run: each
		// tool call (find/grep/ls/read/bash/exec + MCP + extensions) attaches an
		// `abort` listener, the LLM provider fetch attaches one (per stream +
		// retry), and retry/backoff sleeps attach one each (opt #119 removes on
		// settle but the in-flight count is what matters). A parallel tool batch
		// of N tools → N CONCURRENT listeners on this same signal; once >10 are
		// attached Node emits `MaxListenersExceededWarning` and abort dispatch
		// degrades (the warning also falsely flags a real leak). This signal is
		// DESIGNED for many concurrent consumers, so raise the cap to a generous
		// bound (default 50; env REPI_RUN_SIGNAL_MAX_LISTENERS, 0 = unbounded).
		// Per-listener removal on settle (opt #119 + each tool's cleanup) still
		// bounds the live count to in-flight consumers; this only stops the false
		// warning for legitimate parallel batches. (opt #129)
		const maxListeners = parseRunSignalMaxListeners();
		let resolvePromise = () => {};
		const promise = new Promise<void>((resolve) => {
			resolvePromise = resolve;
		});
		this.activeRun = { promise, resolve: resolvePromise, abortController };

		this._state.isStreaming = true;
		this._state.streamingMessage = undefined;
		this._state.errorMessage = undefined;
		// Reset per-run terminal-event tracking so handleRunFailure starts clean
		// (a prior run's committed message must not suppress this run's failure
		// lifecycle, and a prior turn_end must not skip this run's turn_end).
		this.turnMessageEndEmitted = false;
		this.turnEndEmitted = false;
		this.agentEndEmitted = false;
		this.lastCommittedAssistant = undefined;

		// Apply the raised listener cap AFTER activeRun + isStreaming are set (so
		// a concurrent waitForIdle() sees the active run) but BEFORE the executor
		// runs (so tools/provider attaching `abort` listeners see the raised cap).
		// The dynamic import yields once (cached afterward); doing it before
		// activeRun is set would let a waitForIdle() called right after prompt()
		// observe no active run and resolve prematurely. (opt #129)
		const setMaxListenersFn = await resolveNodeSetMaxListeners();
		if (setMaxListenersFn) {
			if (maxListeners === 0) {
				setMaxListenersFn(Infinity, abortController.signal);
			} else if (maxListeners > 0) {
				setMaxListenersFn(maxListeners, abortController.signal);
			}
		}

		try {
			await executor(abortController.signal);
		} catch (error) {
			// A listener throw or stream error mid-run propagates here. The in-flight
			// LLM fetch is tied to abortController.signal; if we DON'T abort, the
			// provider IIFE keeps streaming (cost/quota leak) and keeps pushing into
			// the EventStream queue (unbounded growth) after the consumer broke out
			// of `for await`. Abort now — unless the user already did — to cancel the
			// fetch ASAP (the provider IIFE catches the resulting AbortError, pushes
			// an "error" event, and stream.end()s, so it terminates cleanly). Capture
			// the ORIGINAL wasAborted first and pass it to handleRunFailure so failure
			// labeling (aborted vs error) stays correct. (opt #116)
			const wasAborted = abortController.signal.aborted;
			if (!wasAborted) abortController.abort();
			try {
				await this.handleRunFailure(error, wasAborted);
			} catch (recoveryError) {
				if (error instanceof AgentEventDeliveryError) {
					throw new AggregateError(
						[error, recoveryError],
						"Agent event delivery failed and terminal recovery also failed",
					);
				}
				throw recoveryError;
			}
			// Provider/runtime failures are represented in-band by the failure
			// assistant. Delivery failures indicate external state may have diverged,
			// so terminal recovery cannot turn them into a successful call result.
			if (error instanceof AgentEventDeliveryError) throw error;
		} finally {
			this.finishRun();
		}
	}

	private async handleRunFailure(error: unknown, aborted: boolean): Promise<void> {
		// If a real assistant message was already committed this run (message_end
		// fired) before the throw, do NOT synthesize a fresh message_start/
		// message_end — that would double-push a SECOND message_end and a PHANTOM
		// assistant into the durable state on top of the real one. Emit only the
		// terminal events that haven't fired yet (turn_end / agent_end) referencing
		// the REAL committed message (whose stopReason/errorMessage the loop-level
		// catch already populated). Mirrors opt #97 F1-phantom in the harness
		// emitRunFailure. The thrown error is surfaced via the returned message's
		// stopReason/errorMessage only when no real message exists.
		//
		// A throwing listener on one lifecycle event must not skip subsequent events
		// — in particular `agent_end` MUST remain the final emitted event (its
		// contract). processEvents awaits each listener and rethrows on the first
		// throw, so an unguarded sequential emit would skip agent_end if a turn_end
		// (or message_start/message_end in the synthetic path) listener threw.
		// Collect the first listener error, continue emitting remaining events, then
		// rethrow so listener errors still surface to the caller (matching the
		// harness executeTurn aggregate-then-rethrow recovery philosophy, opt #97).
		let listenerError: unknown;
		const emit = async (event: AgentEvent): Promise<void> => {
			try {
				await this.processEvents(event);
			} catch (err) {
				if (listenerError === undefined) listenerError = err;
			}
		};
		const committed = this.turnMessageEndEmitted ? this.lastCommittedAssistant : undefined;
		if (committed) {
			if (!this.turnEndEmitted) {
				await emit({ type: "turn_end", message: committed, toolResults: [] });
			}
			if (!this.agentEndEmitted) {
				await emit({ type: "agent_end", messages: [committed] });
			}
			if (listenerError !== undefined) throw listenerError;
			return;
		}
		const failureMessage = {
			role: "assistant",
			content: [{ type: "text", text: "" }],
			api: this._state.model.api,
			provider: this._state.model.provider,
			model: this._state.model.id,
			usage: EMPTY_USAGE,
			stopReason: aborted ? "aborted" : "error",
			errorMessage: error instanceof Error ? error.message : String(error),
			timestamp: Date.now(),
		} satisfies AgentMessage;
		await emit({ type: "message_start", message: failureMessage });
		await emit({ type: "message_end", message: failureMessage });
		await emit({ type: "turn_end", message: failureMessage, toolResults: [] });
		await emit({ type: "agent_end", messages: [failureMessage] });
		if (listenerError !== undefined) throw listenerError;
	}

	private finishRun(): void {
		// A queue drain is committed only by its message_end reducer. Return items
		// that were drained but never committed (budget stop or listener failure).
		this.steeringQueue.restoreUnacknowledged();
		this.followUpQueue.restoreUnacknowledged();
		this.steeringQueue.clearCancellationMarkers();
		this.followUpQueue.clearCancellationMarkers();
		this._state.isStreaming = false;
		this._state.streamingMessage = undefined;
		this._state.pendingToolCalls = new Set<string>();
		this.activeRun?.resolve();
		this.activeRun = undefined;
	}

	/**
	 * Reduce internal state for a loop event, then await listeners.
	 *
	 * `agent_end` only means no further loop events will be emitted. The run is
	 * considered idle later, after all awaited listeners for `agent_end` finish
	 * and `finishRun()` clears runtime-owned state.
	 */
	private async processEvents(event: AgentEvent): Promise<void> {
		switch (event.type) {
			case "turn_start":
				// opt #220: reset the per-turn terminal-event trackers at the start
				// of EACH turn, not just at run start. Pre-fix these were reset only
				// in runWithLifecycle (lines 601-603), so after turn N committed a
				// message (message_end set turnMessageEndEmitted=true +
				// lastCommittedAssistant) and emitted turn_end (turnEndEmitted=true),
				// all three stayed set for turn N+1. If turn N+1 then threw BEFORE its
				// own message_end (transformContext/convertToLlm/getApiKey/streamFn
				// throw, or a shouldStopAfterTurn/getSteeringMessages hook throws),
				// handleRunFailure saw the stale turn-N flags → took the "committed"
				// branch → emitted turn_end/agent_end for the turn-N message and
				// RETURNED without surfacing the turn-N+1 error. The error was
				// swallowed, no errorMessage set, agent state inconsistent. Resetting
				// here routes a later-turn pre-message-end failure to the synthetic
				// failure path that surfaces the error in-band.
				this.turnMessageEndEmitted = false;
				this.turnEndEmitted = false;
				this.lastCommittedAssistant = undefined;
				break;

			case "message_start":
				this._state.streamingMessage = event.message;
				break;

			case "message_update":
				this._state.streamingMessage = event.message;
				break;

			case "message_end":
				this._state.streamingMessage = undefined;
				this._state.messages.push(event.message);
				this.steeringQueue.acknowledge(event.message);
				this.followUpQueue.acknowledge(event.message);
				if (event.message.role === "assistant") {
					if (this.promptTurnBudget) this.promptTurnBudget.turnsUsed++;
					this.lastCommittedAssistant = event.message as AssistantMessage;
					this.turnMessageEndEmitted = true;
				}
				break;

			case "tool_execution_start": {
				const pendingToolCalls = new Set(this._state.pendingToolCalls);
				pendingToolCalls.add(event.toolCallId);
				this._state.pendingToolCalls = pendingToolCalls;
				break;
			}

			case "tool_execution_end": {
				const pendingToolCalls = new Set(this._state.pendingToolCalls);
				pendingToolCalls.delete(event.toolCallId);
				this._state.pendingToolCalls = pendingToolCalls;
				break;
			}

			case "turn_end":
				if (event.message.role === "assistant" && event.message.errorMessage) {
					this._state.errorMessage = event.message.errorMessage;
				}
				this.turnEndEmitted = true;
				break;

			case "agent_end":
				this._state.streamingMessage = undefined;
				this.agentEndEmitted = true;
				break;
		}

		const signal = this.activeRun?.abortController.signal;
		if (!signal) {
			throw new Error("Agent listener invoked outside active run");
		}
		// Snapshot subscribers so changes made by a callback affect only later
		// events, not the event currently being dispatched.
		for (const listener of Array.from(this.listeners)) {
			await listener(event, signal);
		}
	}
}

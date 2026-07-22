import {
	type AssistantMessage,
	type ImageContent,
	type Model,
	type Models,
	type SimpleStreamOptions,
	streamSimple,
	type UserMessage,
} from "@pi-recon/repi-ai";
import { AgentEventDeliveryError, runAgentLoop } from "../agent-loop.ts";
import { PendingMessageQueue } from "../pending-message-queue.ts";
import type {
	AgentContext,
	AgentEvent,
	AgentLoopConfig,
	AgentMessage,
	AgentTool,
	QueueMode,
	StreamFn,
	ThinkingLevel,
} from "../types.ts";
import { collectEntriesForBranchSummary, generateBranchSummary } from "./compaction/branch-summarization.ts";
import {
	compact,
	DEFAULT_COMPACTION_SETTINGS,
	estimateCompactionContext,
	estimateContextTokens,
	prepareCompaction,
	shouldCompact,
} from "./compaction/compaction.ts";
import {
	awaitWithAbort,
	cloneHarnessStreamOptions,
	type HarnessHookHandler,
	reduceBeforeAgentStartHooks,
	reduceBeforeProviderPayloadHooks,
	reduceBeforeProviderRequestHooks,
	reduceContextHooks,
	reduceSessionBeforeHooks,
	reduceToolCallHooks,
	reduceToolResultHooks,
	throwIfAborted,
} from "./hook-reducers.ts";
import { convertToLlm } from "./messages.ts";
import { formatPromptTemplateInvocation } from "./prompt-templates.ts";
import { formatSkillInvocation } from "./skills.ts";
import type {
	AbortResult,
	AgentHarnessEvent,
	AgentHarnessEventResultMap,
	AgentHarnessOptions,
	AgentHarnessOwnEvent,
	AgentHarnessPhase,
	AgentHarnessResources,
	AgentHarnessRunPolicy,
	AgentHarnessStreamOptions,
	BeforeAgentStartEvent,
	CompactionSettings,
	CompactResult,
	ContextEvent,
	ExecutionEnv,
	NavigateTreeResult,
	PendingSessionWrite,
	PromptTemplate,
	Session,
	SessionBeforeCompactEvent,
	SessionBeforeTreeEvent,
	Skill,
	ToolCallEvent,
	ToolResultEvent,
} from "./types.ts";
import { AgentHarnessError, BranchSummaryError, CompactionError, SessionError, toError } from "./types.ts";

function createUserMessage(text: string, images?: ImageContent[]): UserMessage {
	const content: Array<{ type: "text"; text: string } | ImageContent> = [{ type: "text", text }];
	if (images) content.push(...images);
	return { role: "user", content, timestamp: Date.now() };
}

function createFailureMessage(model: Model<any>, error: unknown, aborted: boolean): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text: "" }],
		api: model.api,
		provider: model.provider,
		model: model.id,
		stopReason: aborted ? "aborted" : "error",
		errorMessage: error instanceof Error ? error.message : String(error),
		timestamp: Date.now(),
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
	};
}

function mergeHeaders(...headers: Array<Record<string, string> | undefined>): Record<string, string> | undefined {
	const merged: Record<string, string> = {};
	let hasHeaders = false;
	for (const entry of headers) {
		if (!entry) continue;
		Object.assign(merged, entry);
		hasHeaders = true;
	}
	return hasHeaders ? merged : undefined;
}

function findDuplicateNames(names: string[]): string[] {
	const seen = new Set<string>();
	const duplicates = new Set<string>();
	for (const name of names) {
		if (seen.has(name)) duplicates.add(name);
		seen.add(name);
	}
	return [...duplicates];
}

const SUBSCRIBER_EVENT_TYPE = "*";
const DEFAULT_HARNESS_MAX_TURNS = 20;

type AgentHarnessHandler = HarnessHookHandler;

// Keep run ownership identical to the core Agent lifecycle: one object owns
// cancellation and settlement for the entire operation.
type ActiveHarnessRun = {
	promise: Promise<void>;
	resolve: () => void;
	abortController: AbortController;
};

function normalizeHarnessError(error: unknown, fallbackCode: AgentHarnessError["code"]): AgentHarnessError {
	if (error instanceof AgentHarnessError) return error;
	const cause = toError(error);
	if (cause instanceof SessionError) return new AgentHarnessError("session", cause.message, cause);
	if (cause instanceof CompactionError) return new AgentHarnessError("compaction", cause.message, cause);
	if (cause instanceof BranchSummaryError) return new AgentHarnessError("branch_summary", cause.message, cause);
	return new AgentHarnessError(fallbackCode, cause.message, cause);
}

function normalizeHookError(error: unknown): AgentHarnessError {
	return normalizeHarnessError(error, "hook");
}

class AgentHarnessEventDeliveryError extends AgentHarnessError {
	constructor(message: string, cause: Error) {
		super("hook", message, cause);
		this.name = "AgentHarnessEventDeliveryError";
	}
}

function eventDeliveryError(label: string, errors: Error[]): AgentHarnessEventDeliveryError {
	const cause = errors.length === 1 ? errors[0]! : new AggregateError(errors, label);
	return new AgentHarnessEventDeliveryError(label, cause);
}

async function runEventSettlementSteps(label: string, steps: Array<() => Promise<void>>): Promise<void> {
	const errors: Error[] = [];
	for (const step of steps) {
		try {
			await step();
		} catch (error) {
			errors.push(toError(error));
		}
	}
	if (errors.length === 0) return;
	throw eventDeliveryError(label, errors);
}

interface AgentHarnessTurnState<
	TSkill extends Skill = Skill,
	TPromptTemplate extends PromptTemplate = PromptTemplate,
	TTool extends AgentTool = AgentTool,
> {
	messages: AgentMessage[];
	resources: AgentHarnessResources<TSkill, TPromptTemplate>;
	streamOptions: AgentHarnessStreamOptions;
	sessionId: string;
	systemPrompt: string;
	model: Model<any>;
	thinkingLevel: ThinkingLevel;
	tools: TTool[];
	activeTools: TTool[];
}

export class AgentHarness<
	TSkill extends Skill = Skill,
	TPromptTemplate extends PromptTemplate = PromptTemplate,
	TTool extends AgentTool = AgentTool,
> {
	readonly env: ExecutionEnv;
	private session: Session;
	private phase: AgentHarnessPhase = "idle";
	private activeRun?: ActiveHarnessRun;
	private pendingSessionWrites: PendingSessionWrite[] = [];
	// Per-turn terminal-event tracking for emitRunFailure: if a real assistant
	// message was already committed (message_end fired) before a throw, we must
	// not synthesize a phantom message_start/message_end on top of it. Reset at
	// turn start; set as the corresponding events flow through handleAgentEvent.
	private turnMessageEndEmitted = false;
	private turnEndEmitted = false;
	private agentEndEmitted = false;
	private lastCommittedAssistant?: AssistantMessage;
	private model: Model<any>;
	private thinkingLevel: ThinkingLevel;
	private systemPrompt: AgentHarnessOptions<TSkill, TPromptTemplate, TTool>["systemPrompt"];
	private streamOptions: AgentHarnessStreamOptions;
	private readonly runPolicy: Readonly<AgentHarnessRunPolicy>;
	/** Provider-owned request runtime, when supplied by the host. */
	readonly models?: Models;
	private getApiKeyAndHeaders?: AgentHarnessOptions["getApiKeyAndHeaders"];
	private resources: AgentHarnessResources<TSkill, TPromptTemplate>;
	private tools = new Map<string, TTool>();
	private activeToolNames: string[];
	private readonly steerQueue: PendingMessageQueue<AgentMessage>;
	private readonly followUpQueue: PendingMessageQueue<AgentMessage>;
	private readonly nextTurnQueue: PendingMessageQueue<AgentMessage>;
	private handlers = new Map<string, Set<AgentHarnessHandler>>();
	private disposed = false;

	constructor(options: AgentHarnessOptions<TSkill, TPromptTemplate, TTool>) {
		this.env = options.env;
		this.session = options.session;
		this.resources = options.resources ?? {};
		this.streamOptions = cloneHarnessStreamOptions(options.streamOptions);
		this.runPolicy = {
			maxTurns: DEFAULT_HARNESS_MAX_TURNS,
			reserveFinalTurn: true,
			autoCompaction: true,
			...options.runPolicy,
		};
		this.models = options.models;
		this.systemPrompt = options.systemPrompt;
		this.getApiKeyAndHeaders = options.getApiKeyAndHeaders;
		this.validateUniqueNames(
			(options.tools ?? []).map((tool) => tool.name),
			"Duplicate tool name(s)",
		);
		for (const tool of options.tools ?? []) {
			this.tools.set(tool.name, tool);
		}
		this.model = options.model;
		this.thinkingLevel = options.thinkingLevel ?? "off";
		this.activeToolNames = options.activeToolNames
			? [...options.activeToolNames]
			: (options.tools ?? []).map((tool) => tool.name);
		this.validateUniqueNames(this.activeToolNames, "Duplicate active tool name(s)");
		this.validateToolNames(this.activeToolNames);
		this.steerQueue = new PendingMessageQueue<AgentMessage>(options.steeringMode ?? "one-at-a-time");
		this.followUpQueue = new PendingMessageQueue<AgentMessage>(options.followUpMode ?? "one-at-a-time");
		this.nextTurnQueue = new PendingMessageQueue<AgentMessage>("all");
	}

	private getHandlers(type: string): Set<AgentHarnessHandler> | undefined {
		return this.handlers.get(type);
	}

	private async emitOwn(event: AgentHarnessOwnEvent<TSkill, TPromptTemplate>, signal?: AbortSignal): Promise<void> {
		await this.emitSubscribers(event, signal ?? this.activeRun?.abortController.signal);
	}

	private async emitAny(event: AgentHarnessEvent<TSkill, TPromptTemplate>, signal?: AbortSignal): Promise<void> {
		await this.emitSubscribers(event, signal ?? this.activeRun?.abortController.signal);
	}

	private async emitSubscribers(
		event: AgentHarnessEvent<TSkill, TPromptTemplate>,
		signal?: AbortSignal,
	): Promise<void> {
		// Snapshot registration order and settle every observer while the run is
		// active. Once cancellation starts, observers are best-effort: a plugin
		// that ignores its signal must not pin abort/dispose or terminal settlement.
		// Hooks remain awaited and fail-closed through the reducer boundary.
		const listeners = Array.from(this.getHandlers(SUBSCRIBER_EVENT_TYPE) ?? []);
		const deliverDetached = (listener: AgentHarnessHandler): void => {
			void Promise.resolve()
				.then(() => listener(event, signal))
				.catch(() => undefined);
		};
		if (signal?.aborted) {
			for (const listener of listeners) deliverDetached(listener);
			return;
		}
		const errors: Error[] = [];
		for (let index = 0; index < listeners.length; index++) {
			const listener = listeners[index]!;
			try {
				await awaitWithAbort(
					Promise.resolve().then(() => listener(event, signal)),
					signal,
				);
			} catch (error) {
				if (signal?.aborted) {
					for (const remaining of listeners.slice(index + 1)) deliverDetached(remaining);
					return;
				}
				errors.push(toError(error));
			}
		}
		if (errors.length === 0) return;
		throw eventDeliveryError(`AgentHarness ${event.type} delivery failed`, errors);
	}

	private async emitHook<TType extends keyof AgentHarnessEventResultMap>(
		event: Extract<AgentHarnessOwnEvent<TSkill, TPromptTemplate>, { type: TType }>,
		signal?: AbortSignal,
	): Promise<AgentHarnessEventResultMap[TType] | undefined> {
		const handlers = Array.from(this.getHandlers(event.type as TType) ?? []);
		if (handlers.length === 0) return undefined;
		try {
			// Reducer policy lives in hook-reducers.ts, mirroring mature runners:
			// transforms chain, tool/session vetoes are fail-closed, and later
			// handlers never receive stale pre-transform input.
			switch (event.type) {
				case "context":
					return (await reduceContextHooks(
						handlers,
						event as ContextEvent,
						signal,
					)) as AgentHarnessEventResultMap[TType];
				case "before_agent_start":
					return (await reduceBeforeAgentStartHooks(
						handlers,
						event as BeforeAgentStartEvent<TSkill, TPromptTemplate>,
						signal,
					)) as AgentHarnessEventResultMap[TType];
				case "tool_call":
					return (await reduceToolCallHooks(
						handlers,
						event as ToolCallEvent,
						signal,
					)) as AgentHarnessEventResultMap[TType];
				case "tool_result":
					return (await reduceToolResultHooks(
						handlers,
						event as ToolResultEvent,
						signal,
					)) as AgentHarnessEventResultMap[TType];
				case "session_before_compact":
				case "session_before_tree":
					return (await reduceSessionBeforeHooks(
						handlers,
						event as SessionBeforeCompactEvent | SessionBeforeTreeEvent,
						signal,
					)) as AgentHarnessEventResultMap[TType];
				default:
					return undefined;
			}
		} catch (error) {
			throw normalizeHookError(error);
		}
	}

	private async emitBeforeProviderRequest(
		model: Model<any>,
		sessionId: string,
		streamOptions: AgentHarnessStreamOptions,
		signal?: AbortSignal,
	): Promise<AgentHarnessStreamOptions> {
		const handlers = Array.from(this.getHandlers("before_provider_request") ?? []);
		if (handlers.length === 0) return cloneHarnessStreamOptions(streamOptions);
		try {
			return await reduceBeforeProviderRequestHooks(
				handlers,
				{ type: "before_provider_request", model, sessionId, streamOptions },
				signal,
			);
		} catch (error) {
			throw normalizeHookError(error);
		}
	}

	private async emitBeforeProviderPayload(
		model: Model<any>,
		payload: unknown,
		signal?: AbortSignal,
	): Promise<unknown> {
		const handlers = Array.from(this.getHandlers("before_provider_payload") ?? []);
		if (handlers.length === 0) return payload;
		try {
			return await reduceBeforeProviderPayloadHooks(
				handlers,
				{ type: "before_provider_payload", model, payload },
				signal,
			);
		} catch (error) {
			throw normalizeHookError(error);
		}
	}

	private async emitQueueUpdate(signal?: AbortSignal): Promise<void> {
		await this.emitOwn(
			{
				type: "queue_update",
				steer: this.steerQueue.snapshot(),
				followUp: this.followUpQueue.snapshot(),
				nextTurn: this.nextTurnQueue.snapshot(),
			},
			signal,
		);
	}

	private assertNotDisposed(method: string): void {
		if (this.disposed) {
			throw new AgentHarnessError("invalid_state", `AgentHarness.${method}() called after dispose()`);
		}
	}

	private startRun(phase: Exclude<AgentHarnessPhase, "idle">): ActiveHarnessRun {
		if (this.activeRun || this.phase !== "idle") {
			throw new AgentHarnessError("busy", "AgentHarness is busy");
		}
		let resolve = () => {};
		const promise = new Promise<void>((resolvePromise) => {
			resolve = resolvePromise;
		});
		const run = { promise, resolve, abortController: new AbortController() };
		this.activeRun = run;
		this.phase = phase;
		return run;
	}

	private async settleRun(run: ActiveHarnessRun): Promise<void> {
		try {
			// A setter can enqueue in the microtask gap after one flush resolves but
			// before this continuation runs. Recheck synchronously before exposing
			// idle so the final mutation cannot remain stranded.
			do {
				await this.flushPendingSessionWrites();
			} while (this.pendingSessionWrites.length > 0);
		} finally {
			// Queue delivery commits only after message_end persistence succeeds.
			// Restore anything still in-flight before releasing run ownership.
			this.restoreUnacknowledgedQueues();
			this.steerQueue.clearCancellationMarkers();
			this.followUpQueue.clearCancellationMarkers();
			this.nextTurnQueue.clearCancellationMarkers();
			const ownsActiveRun = this.activeRun === run;
			if (ownsActiveRun) this.activeRun = undefined;
			if (ownsActiveRun || this.disposed) this.phase = "idle";
			run.resolve();
		}
	}

	private restoreUnacknowledgedQueues(): boolean {
		const restoredSteer = this.steerQueue.restoreUnacknowledged();
		const restoredFollowUp = this.followUpQueue.restoreUnacknowledged();
		const restoredNextTurn = this.nextTurnQueue.restoreUnacknowledged();
		return restoredSteer.length + restoredFollowUp.length + restoredNextTurn.length > 0;
	}

	private claimQueuedMessageDelivery(message: AgentMessage): boolean {
		if (
			this.activeRun?.abortController.signal.aborted &&
			(this.steerQueue.isInFlight(message) ||
				this.followUpQueue.isInFlight(message) ||
				this.nextTurnQueue.isInFlight(message))
		) {
			return false;
		}
		const steerCancelled = this.steerQueue.consumeCancellation(message);
		const followUpCancelled = this.followUpQueue.consumeCancellation(message);
		const nextTurnCancelled = this.nextTurnQueue.consumeCancellation(message);
		if (steerCancelled || followUpCancelled || nextTurnCancelled) return false;
		this.steerQueue.beginDelivery(message);
		this.followUpQueue.beginDelivery(message);
		this.nextTurnQueue.beginDelivery(message);
		return true;
	}

	private async createTurnState(signal?: AbortSignal): Promise<AgentHarnessTurnState<TSkill, TPromptTemplate, TTool>> {
		const context = await awaitWithAbort(this.session.buildContext(), signal);
		const resources = this.getResources();
		const sessionMetadata = await awaitWithAbort(this.session.getMetadata(), signal);
		const tools = [...this.tools.values()];
		const activeTools = this.activeToolNames
			.map((name) => this.tools.get(name))
			.filter((tool): tool is TTool => tool !== undefined);
		let systemPrompt = "You are a helpful assistant.";
		if (typeof this.systemPrompt === "string") {
			systemPrompt = this.systemPrompt;
		} else if (this.systemPrompt) {
			systemPrompt = await awaitWithAbort(
				Promise.resolve(
					this.systemPrompt({
						env: this.env,
						session: this.session,
						model: this.model,
						thinkingLevel: this.thinkingLevel,
						activeTools,
						resources,
						signal,
					}),
				),
				signal,
			);
		}
		return {
			messages: context.messages,
			resources,
			streamOptions: cloneHarnessStreamOptions(this.streamOptions),
			sessionId: sessionMetadata.id,
			systemPrompt,
			model: this.model,
			thinkingLevel: this.thinkingLevel,
			tools,
			activeTools,
		};
	}

	private createContext(
		turnState: AgentHarnessTurnState<TSkill, TPromptTemplate, TTool>,
		systemPrompt?: string,
	): AgentContext {
		return {
			systemPrompt: systemPrompt ?? turnState.systemPrompt,
			messages: turnState.messages.slice(),
			tools: turnState.activeTools.slice(),
		};
	}

	private createStreamFn(getTurnState: () => AgentHarnessTurnState<TSkill, TPromptTemplate, TTool>): StreamFn {
		return async (model, context, streamOptions) => {
			const turnState = getTurnState();
			const signal = streamOptions?.signal;
			// Models owns credential resolution. Keep the old callback only when a
			// caller has not supplied a Models runtime.
			const auth = this.models
				? undefined
				: await awaitWithAbort(Promise.resolve(this.getApiKeyAndHeaders?.(model)), signal);
			const snapshotOptions: AgentHarnessStreamOptions = {
				...turnState.streamOptions,
				headers: mergeHeaders(turnState.streamOptions.headers, auth?.headers),
			};
			const resolvedOptions = await this.emitBeforeProviderRequest(
				model,
				turnState.sessionId,
				snapshotOptions,
				signal,
			);
			const providerOptions = {
				cacheRetention: resolvedOptions.cacheRetention,
				headers: resolvedOptions.headers,
				maxRetries: resolvedOptions.maxRetries,
				maxRetryDelayMs: resolvedOptions.maxRetryDelayMs,
				metadata: resolvedOptions.metadata,
				onPayload: async (payload) => await this.emitBeforeProviderPayload(model, payload, signal),
				onResponse: async (response) => {
					const headers = { ...(response.headers as Record<string, string>) };
					await this.emitOwn(
						{ type: "after_provider_response", status: response.status, headers },
						streamOptions?.signal,
					);
				},
				reasoning: streamOptions?.reasoning,
				signal: streamOptions?.signal,
				sessionId: turnState.sessionId,
				timeoutMs: resolvedOptions.timeoutMs,
				transport: resolvedOptions.transport,
			} satisfies SimpleStreamOptions;
			if (this.models) return this.models.streamSimple(model, context, providerOptions);
			return streamSimple(model, context, { ...providerOptions, apiKey: auth?.apiKey });
		};
	}

	private async drainQueuedMessages<T>(queue: PendingMessageQueue<T>): Promise<T[]> {
		const messages = queue.drain();
		if (messages.length === 0) return messages;
		try {
			await this.emitQueueUpdate();
			// abort()/dispose() may clear the batch while a queue subscriber is
			// awaited. Never hand those cancelled items to the agent loop afterward.
			return messages.filter((message) => {
				if (queue.isInFlight(message)) return true;
				queue.consumeCancellation(message);
				return false;
			});
		} catch (error) {
			queue.restoreUnacknowledged();
			throw normalizeHookError(error);
		}
	}

	private createLoopConfig(
		getTurnState: () => AgentHarnessTurnState<TSkill, TPromptTemplate, TTool>,
		setTurnState: (turnState: AgentHarnessTurnState<TSkill, TPromptTemplate, TTool>) => void,
		runSignal: AbortSignal,
	): AgentLoopConfig {
		const turnState = getTurnState();
		return {
			model: turnState.model,
			reasoning: turnState.thinkingLevel === "off" ? undefined : turnState.thinkingLevel,
			claimMessageDelivery: (message) => this.claimQueuedMessageDelivery(message),
			maxTurns: this.runPolicy.maxTurns,
			reserveFinalTurn: this.runPolicy.reserveFinalTurn,
			finalTurnPrompt: this.runPolicy.finalTurnPrompt,
			lengthContinueMaxTurns: this.runPolicy.lengthContinueMaxTurns,
			lengthContinuePrompt: this.runPolicy.lengthContinuePrompt,
			streamMaxRetries: this.runPolicy.streamMaxRetries,
			streamRetryBaseDelayMs: this.runPolicy.streamRetryBaseDelayMs,
			streamRetryMaxDelayMs: this.runPolicy.streamRetryMaxDelayMs,
			isRetryableStreamError: this.runPolicy.isRetryableStreamError,
			maxToolResultChars: this.runPolicy.maxToolResultChars,
			maxConsumedToolResultChars: this.runPolicy.maxConsumedToolResultChars,
			deduplicateReadOnlyToolCalls: this.runPolicy.deduplicateReadOnlyToolCalls,
			onRunBudgetExceeded: this.runPolicy.onBudgetExceeded,
			convertToLlm,
			transformContext: async (messages, signal) => {
				// Skip the O(n) [...messages] spread + hook dispatch when no "context" handler is
				// registered (the common case). emitHook would early-return undefined anyway, but the
				// spread is evaluated as an argument BEFORE emitHook runs — so without this guard every
				// turn paid an O(n) copy (n = total messages) for nothing (O(n²) cumulative over a long
				// session). With handlers present the spread + dispatch are identical to before.
				const handlers = this.getHandlers("context");
				if (!handlers || handlers.size === 0) return messages;
				// Hooks may mutate nested message/content objects. Isolate the full
				// graph so a retry or later provider request cannot write those
				// mutations back into the durable session transcript.
				const result = await this.emitHook(
					{ type: "context", messages: structuredClone(messages) },
					signal ?? runSignal,
				);
				return result?.messages ?? messages;
			},
			beforeToolCall: async ({ toolCall, args }, signal) => {
				const result = await this.emitHook(
					{
						type: "tool_call",
						toolCallId: toolCall.id,
						toolName: toolCall.name,
						input: args as Record<string, unknown>,
					},
					signal ?? runSignal,
				);
				return result ? { block: result.block, reason: result.reason } : undefined;
			},
			afterToolCall: async ({ toolCall, args, result, isError }, signal) => {
				const patch = await this.emitHook(
					{
						type: "tool_result",
						toolCallId: toolCall.id,
						toolName: toolCall.name,
						input: args as Record<string, unknown>,
						content: result.content,
						details: result.details,
						isError,
						terminate: result.terminate,
					},
					signal ?? runSignal,
				);
				return patch
					? { content: patch.content, details: patch.details, isError: patch.isError, terminate: patch.terminate }
					: undefined;
			},
			prepareNextTurn: async () => {
				throwIfAborted(runSignal);
				await this.flushPendingSessionWrites();
				throwIfAborted(runSignal);
				const nextTurnState = await this.createTurnState(runSignal);
				setTurnState(nextTurnState);
				return {
					context: this.createContext(nextTurnState),
					model: nextTurnState.model,
					thinkingLevel: nextTurnState.thinkingLevel,
				};
			},
			getSteeringMessages: async () => this.drainQueuedMessages(this.steerQueue),
			getFollowUpMessages: async () => this.drainQueuedMessages(this.followUpQueue),
		};
	}

	private validateUniqueNames(names: string[], message: string): void {
		const duplicates = findDuplicateNames(names);
		if (duplicates.length > 0)
			throw new AgentHarnessError("invalid_argument", `${message}: ${duplicates.join(", ")}`);
	}

	private validateToolNames(toolNames: string[], tools: Map<string, TTool> = this.tools): void {
		this.validateUniqueNames(toolNames, "Duplicate active tool name(s)");
		const missing = toolNames.filter((name) => !tools.has(name));
		if (missing.length > 0) throw new AgentHarnessError("invalid_argument", `Unknown tool(s): ${missing.join(", ")}`);
	}

	private async flushPendingSessionWrites(): Promise<void> {
		while (this.pendingSessionWrites.length > 0) {
			const write = this.pendingSessionWrites[0]!;
			if (write.type === "message") {
				await this.session.appendMessage(write.message);
			} else if (write.type === "model_change") {
				await this.session.appendModelChange(write.provider, write.modelId);
			} else if (write.type === "thinking_level_change") {
				await this.session.appendThinkingLevelChange(write.thinkingLevel);
			} else if (write.type === "active_tools_change") {
				await this.session.appendActiveToolsChange(write.activeToolNames);
			} else if (write.type === "custom") {
				await this.session.appendCustomEntry(write.customType, write.data);
			} else if (write.type === "custom_message") {
				await this.session.appendCustomMessageEntry(write.customType, write.content, write.display, write.details);
			} else if (write.type === "label") {
				await this.session.appendLabel(write.targetId, write.label);
			} else if (write.type === "session_info") {
				await this.session.appendSessionName(write.name ?? "");
			} else if (write.type === "leaf") {
				await this.session.moveTo(write.targetId);
			}
			this.pendingSessionWrites.shift();
		}
	}

	/** Immutable snapshot of mutations waiting for the current run's next durable save point. */
	getPendingWrites(): readonly PendingSessionWrite[] {
		return structuredClone(this.pendingSessionWrites);
	}

	/** Force queued mutations to durable session storage without ending the active run. */
	async flushPendingWrites(): Promise<void> {
		this.assertNotDisposed("flushPendingWrites");
		try {
			await this.flushPendingSessionWrites();
		} catch (error) {
			throw normalizeHarnessError(error, "session");
		}
	}

	private async handleAgentEvent(event: AgentEvent, signal?: AbortSignal): Promise<void> {
		// Terminal-event tracking is per assistant turn, not per run. A later turn
		// can fail before its own message_end (for example during context
		// transformation or provider setup); retaining the previous turn's flags
		// would make emitRunFailure reuse the old assistant and swallow the new
		// failure. Keep this reset aligned with Agent.processEvents().
		if (event.type === "turn_start") {
			this.turnMessageEndEmitted = false;
			this.turnEndEmitted = false;
			this.agentEndEmitted = false;
			this.lastCommittedAssistant = undefined;
		}
		if (event.type === "message_end") {
			await this.session.appendMessage(event.message);
			this.steerQueue.acknowledge(event.message);
			this.followUpQueue.acknowledge(event.message);
			this.nextTurnQueue.acknowledge(event.message);
			if (event.message.role === "assistant") {
				this.lastCommittedAssistant = event.message as AssistantMessage;
			}
			this.turnMessageEndEmitted = true;
			await this.emitAny(event, signal);
			return;
		}
		if (event.type === "turn_end") {
			// Flush pending session writes BEFORE notifying subscribers, matching
			// the message_end persist-then-emit order above. The prior emit-then-
			// flush order left a window where a subscriber (or a crash) observed
			// turn_end while the turn's pending mutations were still un-persisted.
			const hadPendingMutations = this.pendingSessionWrites.length > 0;
			await this.flushPendingSessionWrites();
			this.turnEndEmitted = true;
			await runEventSettlementSteps("AgentHarness turn settlement failed", [
				() => this.emitAny(event, signal),
				() => this.emitOwn({ type: "save_point", hadPendingMutations }),
			]);
			return;
		}
		if (event.type === "agent_end") {
			await this.flushPendingSessionWrites();
			const restoredQueues = this.restoreUnacknowledgedQueues();
			this.agentEndEmitted = true;
			await runEventSettlementSteps("AgentHarness run settlement failed", [
				() => this.emitAny(event, signal),
				...(restoredQueues ? [() => this.emitQueueUpdate()] : []),
				() => this.emitOwn({ type: "settled", nextTurnCount: this.nextTurnQueue.snapshot().length }, signal),
			]);
			return;
		}
		await this.emitAny(event, signal);
	}

	private async emitRunFailure(
		model: Model<any>,
		error: unknown,
		aborted: boolean,
		signal: AbortSignal,
	): Promise<AgentMessage[]> {
		// If a real assistant message was already committed this turn (message_end
		// fired) before the throw — e.g. the throw came from a post-message hook
		// like shouldStopAfterTurn / getSteeringMessages / prepareNextTurn — do NOT
		// synthesize a fresh message_start/message_end. Doing so would double-push
		// a SECOND message_end and a PHANTOM assistant message into the durable
		// transcript on top of the real one. Only emit the terminal events that
		// haven't fired yet (turn_end / agent_end), referencing the REAL committed
		// message. The thrown error is surfaced to the caller via the returned
		// message's stopReason/errorMessage only when no real message exists.
		let deliveryError: unknown;
		const emit = async (event: AgentEvent): Promise<void> => {
			try {
				await this.handleAgentEvent(event, signal);
			} catch (error) {
				if (deliveryError === undefined) deliveryError = error;
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
			if (deliveryError !== undefined) throw deliveryError;
			return [committed];
		}
		const failureMessage = createFailureMessage(model, error, aborted);
		await emit({ type: "message_start", message: failureMessage });
		await emit({ type: "message_end", message: failureMessage });
		await emit({ type: "turn_end", message: failureMessage, toolResults: [] });
		await emit({ type: "agent_end", messages: [failureMessage] });
		if (deliveryError !== undefined) throw deliveryError;
		return [failureMessage];
	}

	private async executeTurn(
		turnState: AgentHarnessTurnState<TSkill, TPromptTemplate, TTool>,
		text: string,
		options: { images?: ImageContent[] } | undefined,
		abortController: AbortController,
	): Promise<AssistantMessage> {
		// Reset per-turn terminal-event tracking so emitRunFailure starts clean
		// (a prior turn's committed message must not suppress this turn's failure
		// lifecycle, and a prior turn_end must not skip this turn's turn_end).
		this.turnMessageEndEmitted = false;
		this.turnEndEmitted = false;
		this.agentEndEmitted = false;
		this.lastCommittedAssistant = undefined;
		let activeTurnState = turnState;
		let messages: AgentMessage[] = [createUserMessage(text, options?.images)];
		const queuedMessages = await this.drainQueuedMessages(this.nextTurnQueue);
		if (queuedMessages.length > 0) {
			messages = [...queuedMessages, messages[0]!];
		}
		const beforeResult = await this.emitHook(
			{
				type: "before_agent_start",
				prompt: text,
				images: options?.images,
				systemPrompt: turnState.systemPrompt,
				resources: turnState.resources,
			},
			abortController.signal,
		);
		if (beforeResult?.messages) messages = [...messages, ...beforeResult.messages];

		// The caller's ActiveHarnessRun owns this controller before createTurnState,
		// so abort() also covers preflight and before_agent_start.
		const getTurnState = () => activeTurnState;
		const setTurnState = (nextTurnState: AgentHarnessTurnState<TSkill, TPromptTemplate, TTool>) => {
			activeTurnState = nextTurnState;
		};
		const runResultPromise = (async () => {
			try {
				return await runAgentLoop(
					messages,
					this.createContext(turnState, beforeResult?.systemPrompt),
					this.createLoopConfig(getTurnState, setTurnState, abortController.signal),
					(event) => this.handleAgentEvent(event, abortController.signal),
					abortController.signal,
					this.createStreamFn(getTurnState),
				);
			} catch (error) {
				// Abort the in-flight fetch on a mid-turn throw (listener throw / stream
				// error) unless already aborted — same cost-leak / EventStream-buffer-
				// growth rationale as Agent.runWithLifecycle (opt #116). The provider
				// IIFE catches the AbortError and stream.end()s cleanly. Capture the
				// ORIGINAL wasAborted first so emitRunFailure labels the failure
				// (aborted vs error) correctly; the signal is still passed through to
				// the failure lifecycle events (handleAgentEvent does not gate emission
				// on signal.aborted).
				const wasAborted = abortController.signal.aborted;
				if (!wasAborted) abortController.abort();
				try {
					const recovered = await this.emitRunFailure(
						activeTurnState.model,
						error,
						wasAborted,
						abortController.signal,
					);
					if (error instanceof AgentEventDeliveryError || error instanceof AgentHarnessEventDeliveryError)
						throw error;
					return recovered;
				} catch (failureError) {
					if (failureError === error) throw error;
					const cause = new AggregateError(
						[toError(error), toError(failureError)],
						"Agent run failed and failure reporting failed",
					);
					throw new AgentHarnessError("unknown", cause.message, cause);
				}
			}
		})();
		try {
			const newMessages = await runResultPromise;
			for (let i = newMessages.length - 1; i >= 0; i--) {
				const message = newMessages[i]!;
				if (message.role === "assistant") {
					return message;
				}
			}
			throw new AgentHarnessError("invalid_state", "AgentHarness prompt completed without an assistant message");
		} finally {
			await this.flushPendingSessionWrites();
		}
	}

	async prompt(text: string, options?: { images?: ImageContent[] }): Promise<AssistantMessage> {
		this.assertNotDisposed("prompt");
		if (this.phase !== "idle") throw new AgentHarnessError("busy", "AgentHarness is busy");
		const run = this.startRun("turn");
		try {
			await this.maybeAutoCompact(run);
			const turnState = await this.createTurnState(run.abortController.signal);
			return await this.executeTurn(turnState, text, options, run.abortController);
		} catch (error) {
			throw normalizeHarnessError(error, "unknown");
		} finally {
			await this.settleRun(run);
		}
	}

	async skill(name: string, additionalInstructions?: string): Promise<AssistantMessage> {
		this.assertNotDisposed("skill");
		if (this.phase !== "idle") throw new AgentHarnessError("busy", "AgentHarness is busy");
		const run = this.startRun("turn");
		try {
			await this.maybeAutoCompact(run);
			const turnState = await this.createTurnState(run.abortController.signal);
			const skill = (turnState.resources.skills ?? []).find((candidate) => candidate.name === name);
			if (!skill) throw new AgentHarnessError("invalid_argument", `Unknown skill: ${name}`);
			return await this.executeTurn(
				turnState,
				formatSkillInvocation(skill, additionalInstructions),
				undefined,
				run.abortController,
			);
		} catch (error) {
			throw normalizeHarnessError(error, "unknown");
		} finally {
			await this.settleRun(run);
		}
	}

	async promptFromTemplate(name: string, args: string[] = []): Promise<AssistantMessage> {
		this.assertNotDisposed("promptFromTemplate");
		if (this.phase !== "idle") throw new AgentHarnessError("busy", "AgentHarness is busy");
		const run = this.startRun("turn");
		try {
			await this.maybeAutoCompact(run);
			const turnState = await this.createTurnState(run.abortController.signal);
			const template = (turnState.resources.promptTemplates ?? []).find((candidate) => candidate.name === name);
			if (!template) throw new AgentHarnessError("invalid_argument", `Unknown prompt template: ${name}`);
			return await this.executeTurn(
				turnState,
				formatPromptTemplateInvocation(template, args),
				undefined,
				run.abortController,
			);
		} catch (error) {
			throw normalizeHarnessError(error, "unknown");
		} finally {
			await this.settleRun(run);
		}
	}

	async steer(text: string, options?: { images?: ImageContent[] }): Promise<void> {
		this.assertNotDisposed("steer");
		if (this.phase === "idle") throw new AgentHarnessError("invalid_state", "Cannot steer while idle");
		this.steerQueue.enqueue(createUserMessage(text, options?.images));
		await this.emitQueueUpdate();
	}

	async followUp(text: string, options?: { images?: ImageContent[] }): Promise<void> {
		this.assertNotDisposed("followUp");
		if (this.phase === "idle") throw new AgentHarnessError("invalid_state", "Cannot follow up while idle");
		this.followUpQueue.enqueue(createUserMessage(text, options?.images));
		await this.emitQueueUpdate();
	}

	async nextTurn(text: string, options?: { images?: ImageContent[] }): Promise<void> {
		this.assertNotDisposed("nextTurn");
		this.nextTurnQueue.enqueue(createUserMessage(text, options?.images));
		await this.emitQueueUpdate();
	}

	async appendMessage(message: AgentMessage): Promise<void> {
		this.assertNotDisposed("appendMessage");
		try {
			if (this.phase === "idle") {
				await this.session.appendMessage(message);
			} else {
				this.pendingSessionWrites.push({ type: "message", message });
			}
		} catch (error) {
			throw normalizeHarnessError(error, "session");
		}
	}

	private getCompactionSettings(): CompactionSettings {
		return { ...DEFAULT_COMPACTION_SETTINGS, ...this.runPolicy.compactionSettings };
	}

	private async maybeAutoCompact(run: ActiveHarnessRun): Promise<CompactResult | undefined> {
		if (!this.runPolicy.autoCompaction) return undefined;
		const settings = this.getCompactionSettings();
		if (!settings.enabled) return undefined;
		const context = await awaitWithAbort(this.session.buildContext(), run.abortController.signal);
		const contextTokens = estimateContextTokens(context.messages).tokens;
		if (!shouldCompact(contextTokens, this.model.contextWindow, settings)) return undefined;
		return this.performCompaction(run, this.runPolicy.autoCompactionInstructions, settings, true);
	}

	private async performCompaction(
		run: ActiveHarnessRun,
		customInstructions: string | undefined,
		settings: CompactionSettings,
		allowNoop = false,
	): Promise<CompactResult | undefined> {
		const model = this.model;
		if (!model) throw new AgentHarnessError("invalid_state", "No model set for compaction");
		const auth = this.models ? undefined : await this.getApiKeyAndHeaders?.(model);
		if (!this.models && !auth) throw new AgentHarnessError("auth", "No auth available for compaction");
		const branchEntries = await this.session.getBranch();
		const preparationResult = prepareCompaction(branchEntries, settings, model.contextWindow);
		if (!preparationResult.ok) throw preparationResult.error;
		const preparation = preparationResult.value;
		if (
			!preparation ||
			(preparation.messagesToSummarize.length === 0 && preparation.turnPrefixMessages.length === 0)
		) {
			if (allowNoop) return undefined;
			throw new AgentHarnessError("compaction", "Nothing to compact");
		}
		const hookResult = await this.emitHook(
			{
				type: "session_before_compact",
				preparation,
				branchEntries,
				customInstructions,
				signal: run.abortController.signal,
			},
			run.abortController.signal,
		);
		if (hookResult?.cancel) {
			if (allowNoop) return undefined;
			throw new AgentHarnessError("compaction", "Compaction cancelled");
		}
		const provided = hookResult?.compaction;
		const compactResult = provided
			? { ok: true as const, value: provided }
			: this.models
				? await compact(
						preparation,
						this.models,
						model,
						customInstructions,
						run.abortController.signal,
						this.thinkingLevel,
					)
				: await compact(
						preparation,
						model,
						auth!.apiKey,
						auth!.headers,
						customInstructions,
						run.abortController.signal,
						this.thinkingLevel,
					);
		if (!compactResult.ok) throw compactResult.error;
		const result = compactResult.value;
		const contextEstimate = estimateCompactionContext(branchEntries, result);
		if (contextEstimate.afterTokens >= contextEstimate.beforeTokens) {
			throw new AgentHarnessError(
				"compaction",
				`Compaction did not reduce estimated context (${contextEstimate.beforeTokens} -> ${contextEstimate.afterTokens} tokens)`,
			);
		}
		const entryId = await this.session.appendCompaction(
			result.summary,
			result.firstKeptEntryId,
			result.tokensBefore,
			result.details,
			provided !== undefined,
		);
		const entry = await this.session.getEntry(entryId);
		if (entry?.type === "compaction") {
			await this.emitOwn({ type: "session_compact", compactionEntry: entry, fromHook: provided !== undefined });
		}
		return result;
	}

	async compact(customInstructions?: string): Promise<CompactResult> {
		this.assertNotDisposed("compact");
		if (this.phase !== "idle") throw new AgentHarnessError("busy", "compact() requires idle harness");
		const run = this.startRun("compaction");
		try {
			return (await this.performCompaction(run, customInstructions, this.getCompactionSettings()))!;
		} catch (error) {
			throw normalizeHarnessError(error, "compaction");
		} finally {
			await this.settleRun(run);
		}
	}

	async navigateTree(
		targetId: string,
		options?: { summarize?: boolean; customInstructions?: string; replaceInstructions?: boolean; label?: string },
	): Promise<NavigateTreeResult> {
		this.assertNotDisposed("navigateTree");
		if (this.phase !== "idle") throw new AgentHarnessError("busy", "navigateTree() requires idle harness");
		const run = this.startRun("branch_summary");
		try {
			const oldLeafId = await this.session.getLeafId();
			if (oldLeafId === targetId) return { cancelled: false };
			const targetEntry = await this.session.getEntry(targetId);
			if (!targetEntry) throw new AgentHarnessError("invalid_argument", `Entry ${targetId} not found`);
			const { entries, commonAncestorId } = await collectEntriesForBranchSummary(this.session, oldLeafId, targetId);
			const preparation = {
				targetId,
				oldLeafId,
				commonAncestorId,
				entriesToSummarize: entries,
				userWantsSummary: options?.summarize ?? false,
				customInstructions: options?.customInstructions,
				replaceInstructions: options?.replaceInstructions,
				label: options?.label,
			};
			const signal = run.abortController.signal;
			const hookResult = await this.emitHook({ type: "session_before_tree", preparation, signal }, signal);
			if (hookResult?.cancel) return { cancelled: true };
			let summaryEntry: NavigateTreeResult["summaryEntry"];
			let summaryText: string | undefined = hookResult?.summary?.summary;
			let summaryDetails: unknown = hookResult?.summary?.details;
			if (!summaryText && options?.summarize && entries.length > 0) {
				const model = this.model;
				if (!model) throw new AgentHarnessError("invalid_state", "No model set for branch summary");
				const auth = this.models ? undefined : await this.getApiKeyAndHeaders?.(model);
				if (!this.models && !auth) throw new AgentHarnessError("auth", "No auth available for branch summary");
				const summaryOptions = {
					model,
					signal: run.abortController.signal,
					customInstructions: hookResult?.customInstructions ?? options?.customInstructions,
					replaceInstructions: hookResult?.replaceInstructions ?? options?.replaceInstructions,
				};
				const branchSummary = this.models
					? await generateBranchSummary(entries, { ...summaryOptions, models: this.models })
					: await generateBranchSummary(entries, {
							...summaryOptions,
							apiKey: auth!.apiKey,
							headers: auth!.headers,
						});
				if (!branchSummary.ok) {
					if (branchSummary.error.code === "aborted") return { cancelled: true };
					throw new AgentHarnessError("branch_summary", branchSummary.error.message, branchSummary.error);
				}
				summaryText = branchSummary.value.summary;
				summaryDetails = {
					readFiles: branchSummary.value.readFiles,
					modifiedFiles: branchSummary.value.modifiedFiles,
				};
			}
			let editorText: string | undefined;
			let newLeafId: string | null;
			if (targetEntry.type === "message" && targetEntry.message.role === "user") {
				newLeafId = targetEntry.parentId;
				const content = targetEntry.message.content;
				editorText =
					typeof content === "string"
						? content
						: content
								.filter((c): c is { readonly type: "text"; readonly text: string } => c.type === "text")
								.map((c) => c.text)
								.join("");
			} else if (targetEntry.type === "custom_message") {
				newLeafId = targetEntry.parentId;
				editorText =
					typeof targetEntry.content === "string"
						? targetEntry.content
						: targetEntry.content
								.filter((c): c is { readonly type: "text"; readonly text: string } => c.type === "text")
								.map((c) => c.text)
								.join("");
			} else {
				newLeafId = targetId;
			}
			const summaryId = await this.session.moveTo(
				newLeafId,
				summaryText
					? { summary: summaryText, details: summaryDetails, fromHook: hookResult?.summary !== undefined }
					: undefined,
			);
			if (summaryId) {
				const entry = await this.session.getEntry(summaryId);
				if (entry?.type === "branch_summary") summaryEntry = entry;
			}
			await this.emitOwn({
				type: "session_tree",
				newLeafId: await this.session.getLeafId(),
				oldLeafId,
				summaryEntry,
				fromHook: hookResult?.summary !== undefined,
			});
			return { cancelled: false, editorText, summaryEntry };
		} catch (error) {
			throw normalizeHarnessError(error, "branch_summary");
		} finally {
			await this.settleRun(run);
		}
	}

	getModel(): Model<any> {
		return this.model;
	}

	async setModel(model: Model<any>): Promise<void> {
		this.assertNotDisposed("setModel");
		try {
			const previousModel = this.model;
			if (this.phase === "idle") {
				await this.session.appendModelChange(model.provider, model.id);
			} else {
				this.pendingSessionWrites.push({ type: "model_change", provider: model.provider, modelId: model.id });
			}
			this.model = model;
			await this.emitOwn({ type: "model_update", model, previousModel, source: "set" });
		} catch (error) {
			throw normalizeHarnessError(error, "session");
		}
	}

	getThinkingLevel(): ThinkingLevel {
		return this.thinkingLevel;
	}

	async setThinkingLevel(level: ThinkingLevel): Promise<void> {
		this.assertNotDisposed("setThinkingLevel");
		try {
			const previousLevel = this.thinkingLevel;
			if (this.phase === "idle") {
				await this.session.appendThinkingLevelChange(level);
			} else {
				this.pendingSessionWrites.push({ type: "thinking_level_change", thinkingLevel: level });
			}
			this.thinkingLevel = level;
			await this.emitOwn({ type: "thinking_level_update", level, previousLevel });
		} catch (error) {
			throw normalizeHarnessError(error, "session");
		}
	}

	getTools(): TTool[] {
		return [...this.tools.values()];
	}

	async setTools(tools: TTool[], activeToolNames?: string[]): Promise<void> {
		this.assertNotDisposed("setTools");
		try {
			this.validateUniqueNames(
				tools.map((tool) => tool.name),
				"Duplicate tool name(s)",
			);
			const nextTools = new Map(tools.map((tool) => [tool.name, tool]));
			const nextActiveToolNames = activeToolNames ? [...activeToolNames] : this.activeToolNames;
			this.validateToolNames(nextActiveToolNames, nextTools);
			const previousToolNames = [...this.tools.keys()];
			const previousActiveToolNames = [...this.activeToolNames];
			if (this.phase === "idle") {
				await this.session.appendActiveToolsChange(nextActiveToolNames);
			} else {
				this.pendingSessionWrites.push({ type: "active_tools_change", activeToolNames: [...nextActiveToolNames] });
			}
			this.tools = nextTools;
			this.activeToolNames = [...nextActiveToolNames];
			await this.emitOwn({
				type: "tools_update",
				toolNames: [...this.tools.keys()],
				previousToolNames,
				activeToolNames: [...this.activeToolNames],
				previousActiveToolNames,
				source: "set",
			});
		} catch (error) {
			throw normalizeHarnessError(error, "invalid_argument");
		}
	}

	getActiveTools(): TTool[] {
		return this.activeToolNames.map((name) => this.tools.get(name)!);
	}

	async setActiveTools(toolNames: string[]): Promise<void> {
		this.assertNotDisposed("setActiveTools");
		try {
			this.validateToolNames(toolNames);
			const previousToolNames = [...this.tools.keys()];
			const previousActiveToolNames = [...this.activeToolNames];
			if (this.phase === "idle") {
				await this.session.appendActiveToolsChange(toolNames);
			} else {
				this.pendingSessionWrites.push({ type: "active_tools_change", activeToolNames: [...toolNames] });
			}
			this.activeToolNames = [...toolNames];
			await this.emitOwn({
				type: "tools_update",
				toolNames: [...this.tools.keys()],
				previousToolNames,
				activeToolNames: [...this.activeToolNames],
				previousActiveToolNames,
				source: "set",
			});
		} catch (error) {
			throw normalizeHarnessError(error, "invalid_argument");
		}
	}

	getSteeringMode(): QueueMode {
		return this.steerQueue.mode;
	}

	async setSteeringMode(mode: QueueMode): Promise<void> {
		this.assertNotDisposed("setSteeringMode");
		this.steerQueue.mode = mode;
	}

	getFollowUpMode(): QueueMode {
		return this.followUpQueue.mode;
	}

	async setFollowUpMode(mode: QueueMode): Promise<void> {
		this.assertNotDisposed("setFollowUpMode");
		this.followUpQueue.mode = mode;
	}

	getResources(): AgentHarnessResources<TSkill, TPromptTemplate> {
		return {
			skills: this.resources.skills?.slice(),
			promptTemplates: this.resources.promptTemplates?.slice(),
		};
	}

	async setResources(resources: AgentHarnessResources<TSkill, TPromptTemplate>): Promise<void> {
		this.assertNotDisposed("setResources");
		const previousResources = this.getResources();
		this.resources = {
			skills: resources.skills?.slice(),
			promptTemplates: resources.promptTemplates?.slice(),
		};
		await this.emitOwn({ type: "resources_update", resources: this.getResources(), previousResources });
	}

	getStreamOptions(): AgentHarnessStreamOptions {
		return cloneHarnessStreamOptions(this.streamOptions);
	}

	async setStreamOptions(streamOptions: AgentHarnessStreamOptions): Promise<void> {
		this.assertNotDisposed("setStreamOptions");
		this.streamOptions = cloneHarnessStreamOptions(streamOptions);
	}

	async abort(): Promise<AbortResult> {
		const activeRun = this.activeRun;
		const clearedSteer = this.steerQueue.clear();
		const clearedFollowUp = this.followUpQueue.clear();
		activeRun?.abortController.abort();
		const idleAbortController = new AbortController();
		idleAbortController.abort();
		const cancellationSignal = activeRun?.abortController.signal ?? idleAbortController.signal;
		const errors: Error[] = [];
		try {
			await this.emitQueueUpdate(cancellationSignal);
		} catch (error) {
			errors.push(toError(error));
		}
		try {
			await this.waitForIdle();
		} catch (error) {
			errors.push(toError(error));
		}
		try {
			await this.emitOwn({ type: "abort", clearedSteer, clearedFollowUp }, cancellationSignal);
		} catch (error) {
			errors.push(toError(error));
		}
		if (errors.length > 0) {
			const cause = errors.length === 1 ? errors[0]! : new AggregateError(errors, "Abort completed with errors");
			throw normalizeHarnessError(cause, "hook");
		}
		return { clearedSteer, clearedFollowUp };
	}

	async waitForIdle(): Promise<void> {
		await this.activeRun?.promise;
	}

	/**
	 * Tear down the harness: abort any in-flight run/compaction/tree-navigation,
	 * drop all subscribers + hook handlers so no late callbacks fire on a dead
	 * session/env, clear queued messages, and release the execution env. Safe to
	 * call multiple times (idempotent). After dispose(), the run entry points
	 * (prompt/skill/promptFromTemplate/compact/navigateTree) throw invalid_state.
	 */
	async dispose(): Promise<void> {
		if (this.disposed) return;
		this.disposed = true;
		const activeRun = this.activeRun;
		// Invalidate callbacks and public mutation entry points synchronously.
		// Some providers do not settle their response promise immediately on
		// abort, so dispose itself stays non-blocking for an active run.
		this.handlers.clear();
		this.steerQueue.clear();
		this.followUpQueue.clear();
		this.nextTurnQueue.clear();
		activeRun?.abortController.abort();

		const cleanup = async () => {
			if (activeRun) await activeRun.promise.catch(() => undefined);
			try {
				await this.env.cleanup();
			} catch {
				// Best-effort: never let env cleanup failure mask disposal.
			}
		};
		if (activeRun) {
			// The run still owns its AbortController until settleRun(). Deferring
			// cleanup avoids tools/session writes touching an already-cleaned env.
			void cleanup();
			return;
		}
		await cleanup();
	}

	subscribe(
		listener: (event: AgentHarnessEvent<TSkill, TPromptTemplate>, signal?: AbortSignal) => Promise<void> | void,
	): () => void {
		this.assertNotDisposed("subscribe");
		let handlers = this.handlers.get(SUBSCRIBER_EVENT_TYPE);
		if (!handlers) {
			handlers = new Set();
			this.handlers.set(SUBSCRIBER_EVENT_TYPE, handlers);
		}
		handlers.add(listener as AgentHarnessHandler);
		return () => handlers!.delete(listener as AgentHarnessHandler);
	}

	on<TType extends keyof AgentHarnessEventResultMap>(
		type: TType,
		handler: (
			event: Extract<AgentHarnessOwnEvent<TSkill, TPromptTemplate>, { type: TType }>,
			signal?: AbortSignal,
		) => Promise<AgentHarnessEventResultMap[TType]> | AgentHarnessEventResultMap[TType],
	): () => void {
		this.assertNotDisposed("on");
		let handlers = this.handlers.get(type);
		if (!handlers) {
			handlers = new Set();
			this.handlers.set(type, handlers);
		}
		handlers.add(handler as AgentHarnessHandler);
		return () => handlers!.delete(handler as AgentHarnessHandler);
	}
}

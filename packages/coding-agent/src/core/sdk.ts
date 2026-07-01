import { join } from "node:path";
import { Agent, type AgentMessage, DEFAULT_MAX_TOOL_RESULT_CHARS, type ThinkingLevel } from "@pi-recon/repi-agent-core";
import { clampThinkingLevel, type Message, type Model, streamSimple } from "@pi-recon/repi-ai";
import { getAgentDir } from "../config.ts";
import { resolvePath } from "../utils/paths.ts";
import { AgentSession } from "./agent-session.ts";
import { formatNoModelsAvailableMessage } from "./auth-guidance.ts";
import { AuthStorage } from "./auth-storage.ts";
import { DEFAULT_THINKING_LEVEL } from "./defaults.ts";
import type { ExtensionRunner, LoadExtensionsResult, SessionStartEvent, ToolDefinition } from "./extensions/index.ts";
import { convertToLlm } from "./messages.ts";
import { ModelRegistry } from "./model-registry.ts";
import { findInitialModel } from "./model-resolver.ts";
import { mergeProviderAttributionHeaders } from "./provider-attribution.ts";
import type { ResourceLoader } from "./resource-loader.ts";
import { DefaultResourceLoader } from "./resource-loader.ts";
import { getDefaultSessionDir, SessionManager } from "./session-manager.ts";
import { SettingsManager } from "./settings-manager.ts";
import { time } from "./timings.ts";
import {
	createBashTool,
	createCodingTools,
	createEditTool,
	createFindTool,
	createGrepTool,
	createLsTool,
	createReadOnlyTools,
	createReadTool,
	createWriteTool,
	type ToolName,
	withFileMutationQueue,
} from "./tools/index.ts";

export interface CreateAgentSessionOptions {
	/** Working directory for project-local discovery. Default: process.cwd() */
	cwd?: string;
	/** Global config directory. Default: ~/.repi/agent */
	agentDir?: string;

	/** Auth storage for credentials. Default: AuthStorage.create(agentDir/auth.json) */
	authStorage?: AuthStorage;
	/** Model registry. Default: ModelRegistry.create(authStorage, agentDir/models.json) */
	modelRegistry?: ModelRegistry;

	/** Model to use. Default: from settings, else first available */
	model?: Model<any>;
	/** Thinking level. Default: from settings, else 'medium' (clamped to model capabilities) */
	thinkingLevel?: ThinkingLevel;
	/** Models available for cycling (Ctrl+P in interactive mode) */
	scopedModels?: Array<{ model: Model<any>; thinkingLevel?: ThinkingLevel }>;

	/**
	 * Optional default tool suppression mode when no explicit allowlist is provided.
	 *
	 * - "all": start with no tools enabled
	 * - "builtin": disable the default built-in tools (read, bash, edit, write)
	 *   but keep extension/custom tools enabled
	 */
	noTools?: "all" | "builtin";
	/**
	 * Optional allowlist of tool names.
	 *
	 * When omitted, pi enables the default built-in tools (read, bash, edit, write)
	 * and leaves extension/custom tools enabled unless `noTools` changes that default.
	 * When provided, only the listed tool names are enabled.
	 */
	tools?: string[];
	/** Optional denylist of tool names to disable. Applies after `tools` when both are provided. */
	excludeTools?: string[];
	/** Custom tools to register (in addition to built-in tools). */
	customTools?: ToolDefinition[];

	/** Resource loader. When omitted, DefaultResourceLoader is used. */
	resourceLoader?: ResourceLoader;

	/** Session manager. Default: SessionManager.create(cwd) */
	sessionManager?: SessionManager;

	/** Settings manager. Default: SettingsManager.create(cwd, agentDir) */
	settingsManager?: SettingsManager;
	/** Session start event metadata for extension runtime startup. */
	sessionStartEvent?: SessionStartEvent;
	/**
	 * Optional hard cap on assistant turns (provider requests) per run. A "turn"
	 * is one streamed assistant response, possibly followed by tool execution.
	 * When the cap is reached after a turn completes, the run stops gracefully
	 * instead of starting another provider request — the in-flight turn is never
	 * cut. Undefined / non-positive = unbounded (default).
	 *
	 * Falls back to the `REPI_MAX_TURNS` environment variable when omitted. Use as
	 * a foundational guard against runaway tool-call loops.
	 */
	maxTurns?: number;
	/**
	 * Max auto-continue re-prompts when the model stops with `stopReason`
	 * "length" (output hit maxTokens) and no tool calls. 0 = disabled.
	 *
	 * Falls back to the `REPI_LENGTH_CONTINUE_MAX` env var, then a product-mode
	 * default of 3 (else 0). Each continuation counts toward {@link maxTurns}.
	 */
	lengthContinueMaxTurns?: number;
	/**
	 * Max retries of a single assistant stream request when the provider fails
	 * before emitting any content (network/429/5xx). 0 = disabled.
	 *
	 * Falls back to the `REPI_STREAM_MAX_RETRIES` env var, then a product-mode
	 * default of 2 (else 0). A retry is the same turn re-attempted and does not
	 * count toward {@link maxTurns}.
	 */
	streamMaxRetries?: number;
	/**
	 * Defense-in-depth cap (chars) on tool result text blocks before they enter
	 * the model's context. Catches custom/MCP extension tools that return huge
	 * results and would blow the context window. Built-in tools already
	 * self-truncate (~50KB) so they are unaffected.
	 *
	 * Falls back to the `REPI_MAX_TOOL_RESULT_CHARS` env var, then the agent-loop
	 * default (262144 = 256K). Set to 0 to disable the cap.
	 */
	maxToolResultChars?: number;
}

function isRepiProductMode(): boolean {
	return process.env.REPI_PRODUCT === "1" || process.env.REPI_PRIMARY === "1";
}

/**
 * Resolve the per-run assistant-turn cap.
 *
 * Priority: explicit option > `REPI_MAX_TURNS` env var. Non-positive or
 * unparseable values resolve to undefined (unbounded), preserving the default.
 */
function resolveMaxTurns(option?: number): number | undefined {
	if (typeof option === "number" && Number.isFinite(option) && option > 0) {
		return Math.floor(option);
	}
	const raw = process.env.REPI_MAX_TURNS;
	if (raw !== undefined && raw !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed) && parsed > 0) {
			return Math.floor(parsed);
		}
	}
	return undefined;
}

/**
 * Resolve the length auto-continue cap.
 *
 * Priority: explicit option > `REPI_LENGTH_CONTINUE_MAX` env > product-mode
 * default (3) / 0. Non-positive or unparseable values disable the feature.
 */
function resolveLengthContinueMax(option?: number): number | undefined {
	if (typeof option === "number" && Number.isFinite(option)) {
		return option > 0 ? Math.floor(option) : undefined;
	}
	const raw = process.env.REPI_LENGTH_CONTINUE_MAX;
	if (raw !== undefined && raw !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed)) {
			return parsed > 0 ? Math.floor(parsed) : undefined;
		}
	}
	return isRepiProductMode() ? 3 : undefined;
}

/**
 * Resolve the pre-stream transient-error retry cap.
 *
 * Priority: explicit option > `REPI_STREAM_MAX_RETRIES` env > product-mode
 * default (2) / 0. Non-positive or unparseable values disable the feature.
 */
function resolveStreamMaxRetries(option?: number): number | undefined {
	if (typeof option === "number" && Number.isFinite(option)) {
		return option > 0 ? Math.floor(option) : undefined;
	}
	const raw = process.env.REPI_STREAM_MAX_RETRIES;
	if (raw !== undefined && raw !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed)) {
			return parsed > 0 ? Math.floor(parsed) : undefined;
		}
	}
	return isRepiProductMode() ? 2 : undefined;
}

/**
 * Resolve the defense-in-depth tool-result text cap.
 *
 * Priority: explicit option > `REPI_MAX_TOOL_RESULT_CHARS` env > context-scaled
 * default (10% of the active model's context window in chars, capped at the
 * agent-loop's 256K ceiling) > undefined (the agent-loop then applies its 256K
 * default). 0 disables the cap. Unlike the retry/continue resolvers this is NOT
 * product-mode-gated — it is a safety net, on by default for every session.
 *
 * The context-scaled default matters for un-truncating tools (MCP/custom
 * extension tools — the built-in bash/grep/read/find/ls tools self-truncate to
 * ~50KB and hit that first). A fixed 256K (~64K-token) cap on a 128K-window
 * model lets a single un-truncating tool result push an already-full context
 * over the window. Scaling to ~10% of the window means one tool result can add
 * at most ~10% of context, so even at the 85% compaction threshold the next
 * request stays under the window. Large-window models (≥2.56M tokens) keep the
 * 256K ceiling, so nothing tightens for them.
 */
function resolveMaxToolResultChars(option?: number, contextWindow?: number): number | undefined {
	if (typeof option === "number" && Number.isFinite(option)) {
		return option >= 0 ? Math.floor(option) : undefined;
	}
	const raw = process.env.REPI_MAX_TOOL_RESULT_CHARS;
	if (raw !== undefined && raw !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed)) {
			return parsed >= 0 ? Math.floor(parsed) : undefined;
		}
	}
	if (typeof contextWindow === "number" && Number.isFinite(contextWindow) && contextWindow > 0) {
		// 10% of the window in tokens, ×4 chars/token. Capped at the agent-loop's
		// 256K ceiling so large-window models are not loosened beyond the existing
		// default. Math.max(1, ...) guards tiny/zero after flooring.
		const scaled = Math.floor(contextWindow * 0.1 * 4);
		return Math.max(1, Math.min(scaled, DEFAULT_MAX_TOOL_RESULT_CHARS));
	}
	return undefined;
}

/** Result from createAgentSession */
export interface CreateAgentSessionResult {
	/** The created session */
	session: AgentSession;
	/** Extensions result (for UI context setup in interactive mode) */
	extensionsResult: LoadExtensionsResult;
	/** Warning if session was restored with a different model than saved */
	modelFallbackMessage?: string;
}

// Re-exports

export * from "./agent-session-runtime.ts";
export type {
	ExtensionAPI,
	ExtensionCommandContext,
	ExtensionContext,
	ExtensionFactory,
	SlashCommandInfo,
	SlashCommandSource,
	ToolDefinition,
} from "./extensions/index.ts";
export type { PromptTemplate } from "./prompt-templates.ts";
export type { Skill } from "./skills.ts";
export type { Tool } from "./tools/index.ts";

export {
	withFileMutationQueue,
	// Tool factories (for custom cwd)
	createCodingTools,
	createReadOnlyTools,
	createReadTool,
	createBashTool,
	createEditTool,
	createWriteTool,
	createGrepTool,
	createFindTool,
	createLsTool,
	// Pure resolvers (exported for unit testing)
	resolveMaxToolResultChars,
};

// Helper Functions

function getDefaultAgentDir(): string {
	return getAgentDir();
}

/**
 * Create an AgentSession with the specified options.
 *
 * @example
 * ```typescript
 * // Minimal - uses defaults
 * const { session } = await createAgentSession();
 *
 * // With explicit model
 * import { getModel } from '@pi-recon/repi-ai';
 * const { session } = await createAgentSession({
 *   model: getModel('anthropic', 'claude-opus-4-5'),
 *   thinkingLevel: 'high',
 * });
 *
 * // Continue previous session
 * const { session, modelFallbackMessage } = await createAgentSession({
 *   continueSession: true,
 * });
 *
 * // Full control
 * const loader = new DefaultResourceLoader({
 *   cwd: process.cwd(),
 *   agentDir: getAgentDir(),
 *   settingsManager: SettingsManager.create(),
 * });
 * await loader.reload();
 * const { session } = await createAgentSession({
 *   model: myModel,
 *   tools: ["read", "bash"],
 *   resourceLoader: loader,
 *   sessionManager: SessionManager.inMemory(),
 * });
 * ```
 */
export async function createAgentSession(options: CreateAgentSessionOptions = {}): Promise<CreateAgentSessionResult> {
	const cwd = resolvePath(options.cwd ?? options.sessionManager?.getCwd() ?? process.cwd());
	const agentDir = options.agentDir ? resolvePath(options.agentDir) : getDefaultAgentDir();
	let resourceLoader = options.resourceLoader;

	// Use provided or create AuthStorage and ModelRegistry
	const authPath = options.agentDir ? join(agentDir, "auth.json") : undefined;
	const modelsPath = options.agentDir ? join(agentDir, "models.json") : undefined;
	const authStorage = options.authStorage ?? AuthStorage.create(authPath);
	const modelRegistry = options.modelRegistry ?? ModelRegistry.create(authStorage, modelsPath);

	const settingsManager = options.settingsManager ?? SettingsManager.create(cwd, agentDir);
	const sessionManager = options.sessionManager ?? SessionManager.create(cwd, getDefaultSessionDir(cwd, agentDir));

	if (!resourceLoader) {
		resourceLoader = new DefaultResourceLoader({ cwd, agentDir, settingsManager });
		await resourceLoader.reload();
		time("resourceLoader.reload");
	}

	// Check if session has existing data to restore
	const existingSession = sessionManager.buildSessionContext();
	const hasExistingSession = existingSession.messages.length > 0;
	const hasThinkingEntry = sessionManager.getBranch().some((entry) => entry.type === "thinking_level_change");

	let model = options.model;
	let modelFallbackMessage: string | undefined;

	// If session has data, try to restore model from it
	if (!model && hasExistingSession && existingSession.model) {
		const restoredModel = modelRegistry.find(existingSession.model.provider, existingSession.model.modelId);
		if (restoredModel && modelRegistry.hasConfiguredAuth(restoredModel)) {
			model = restoredModel;
		}
		if (!model) {
			modelFallbackMessage = `Could not restore model ${existingSession.model.provider}/${existingSession.model.modelId}`;
		}
	}

	// If still no model, use findInitialModel (checks settings default, then provider defaults)
	if (!model) {
		const result = await findInitialModel({
			scopedModels: [],
			isContinuing: hasExistingSession,
			defaultProvider: settingsManager.getDefaultProvider(),
			defaultModelId: settingsManager.getDefaultModel(),
			defaultThinkingLevel: settingsManager.getDefaultThinkingLevel(),
			modelRegistry,
		});
		model = result.model;
		if (!model) {
			modelFallbackMessage = formatNoModelsAvailableMessage();
		} else if (modelFallbackMessage) {
			modelFallbackMessage += `. Using ${model.provider}/${model.id}`;
		}
	}

	let thinkingLevel = options.thinkingLevel;

	// If session has data, restore thinking level from it
	if (thinkingLevel === undefined && hasExistingSession) {
		thinkingLevel = hasThinkingEntry
			? (existingSession.thinkingLevel as ThinkingLevel)
			: (settingsManager.getDefaultThinkingLevel() ?? DEFAULT_THINKING_LEVEL);
	}

	// Fall back to settings default
	if (thinkingLevel === undefined) {
		thinkingLevel = settingsManager.getDefaultThinkingLevel() ?? DEFAULT_THINKING_LEVEL;
	}

	// Clamp to model capabilities
	if (!model) {
		thinkingLevel = "off";
	} else {
		thinkingLevel = clampThinkingLevel(model, thinkingLevel) as ThinkingLevel;
	}

	const defaultActiveToolNames: ToolName[] = ["read", "bash", "edit", "write"];
	const allowedToolNames = options.tools ?? (options.noTools === "all" ? [] : undefined);
	const excludedToolNames = options.excludeTools;
	const excludedToolNameSet = excludedToolNames ? new Set(excludedToolNames) : undefined;
	const initialActiveToolNames: string[] = (
		options.tools ? [...options.tools] : options.noTools ? [] : defaultActiveToolNames
	).filter((name) => !excludedToolNameSet?.has(name));

	let agent: Agent;

	// Create convertToLlm wrapper that filters images if blockImages is enabled (defense-in-depth)
	const convertToLlmWithBlockImages = (messages: AgentMessage[]): Message[] => {
		const converted = convertToLlm(messages);
		// Check setting dynamically so mid-session changes take effect
		if (!settingsManager.getBlockImages()) {
			return converted;
		}
		// Filter out ImageContent from all messages, replacing with text placeholder
		return converted.map((msg) => {
			if (msg.role === "user" || msg.role === "toolResult") {
				const content = msg.content;
				if (Array.isArray(content)) {
					const hasImages = content.some((c) => c.type === "image");
					if (hasImages) {
						const filteredContent = content
							.map((c) =>
								c.type === "image" ? { type: "text" as const, text: "Image reading is disabled." } : c,
							)
							.filter(
								(c, i, arr) =>
									// Dedupe consecutive "Image reading is disabled." texts
									!(
										c.type === "text" &&
										c.text === "Image reading is disabled." &&
										i > 0 &&
										arr[i - 1].type === "text" &&
										(arr[i - 1] as { type: "text"; text: string }).text === "Image reading is disabled."
									),
							);
						return { ...msg, content: filteredContent };
					}
				}
			}
			return msg;
		});
	};

	const extensionRunnerRef: { current?: ExtensionRunner } = {};

	agent = new Agent({
		initialState: {
			systemPrompt: "",
			model,
			thinkingLevel,
			tools: [],
		},
		convertToLlm: convertToLlmWithBlockImages,
		streamFn: async (model, context, options) => {
			const auth = await modelRegistry.getApiKeyAndHeaders(model);
			if (!auth.ok) {
				throw new Error(auth.error);
			}
			const providerRetrySettings = settingsManager.getProviderRetrySettings();
			const httpIdleTimeoutMs = settingsManager.getHttpIdleTimeoutMs();
			// SDKs treat timeout=0 as 0ms (immediate timeout), not "no timeout".
			// Use max int32 to effectively disable the timeout.
			const effectiveTimeoutMs = httpIdleTimeoutMs === 0 ? 2147483647 : httpIdleTimeoutMs;
			const timeoutMs = options?.timeoutMs ?? providerRetrySettings.timeoutMs ?? effectiveTimeoutMs;
			const websocketConnectTimeoutMs =
				options?.websocketConnectTimeoutMs ?? settingsManager.getWebSocketConnectTimeoutMs();
			return streamSimple(model, context, {
				...options,
				apiKey: auth.apiKey,
				timeoutMs,
				websocketConnectTimeoutMs,
				maxRetries: options?.maxRetries ?? providerRetrySettings.maxRetries,
				maxRetryDelayMs: options?.maxRetryDelayMs ?? providerRetrySettings.maxRetryDelayMs,
				headers: mergeProviderAttributionHeaders(
					model,
					settingsManager,
					options?.sessionId,
					auth.headers,
					options?.headers,
				),
			});
		},
		onPayload: async (payload, _model) => {
			const runner = extensionRunnerRef.current;
			if (!runner?.hasHandlers("before_provider_request")) {
				return payload;
			}
			return runner.emitBeforeProviderRequest(payload);
		},
		onResponse: async (response, _model) => {
			const runner = extensionRunnerRef.current;
			if (!runner?.hasHandlers("after_provider_response")) {
				return;
			}
			await runner.emit({
				type: "after_provider_response",
				status: response.status,
				headers: response.headers,
			});
		},
		sessionId: sessionManager.getSessionId(),
		transformContext: async (messages) => {
			const runner = extensionRunnerRef.current;
			if (!runner) return messages;
			return runner.emitContext(messages);
		},
		steeringMode: settingsManager.getSteeringMode(),
		followUpMode: settingsManager.getFollowUpMode(),
		transport: settingsManager.getTransport(),
		thinkingBudgets: settingsManager.getThinkingBudgets(),
		maxRetryDelayMs: settingsManager.getProviderRetrySettings().maxRetryDelayMs,
		maxTurns: resolveMaxTurns(options?.maxTurns),
		lengthContinueMaxTurns: resolveLengthContinueMax(options?.lengthContinueMaxTurns),
		streamMaxRetries: resolveStreamMaxRetries(options?.streamMaxRetries),
		maxToolResultChars: resolveMaxToolResultChars(options?.maxToolResultChars, model?.contextWindow),
		onRunBudgetExceeded: ({ turns, maxTurns }) => {
			// Pure side-effect channel: surface the budget stop so consumers know
			// the run ended because of the cap rather than finishing naturally.
			process.stderr.write(
				`repi: reached max-turns budget (${turns}/${maxTurns}); stopping before next provider request.\n`,
			);
		},
	});

	// Restore messages if session has existing data
	if (hasExistingSession) {
		agent.state.messages = existingSession.messages;
		if (!hasThinkingEntry) {
			sessionManager.appendThinkingLevelChange(thinkingLevel);
		}
	} else {
		// Save initial model and thinking level for new sessions so they can be restored on resume
		if (model) {
			sessionManager.appendModelChange(model.provider, model.id);
		}
		sessionManager.appendThinkingLevelChange(thinkingLevel);
	}

	const session = new AgentSession({
		agent,
		sessionManager,
		settingsManager,
		cwd,
		scopedModels: options.scopedModels,
		resourceLoader,
		customTools: options.customTools,
		modelRegistry,
		initialActiveToolNames,
		allowedToolNames,
		excludedToolNames,
		extensionRunnerRef,
		sessionStartEvent: options.sessionStartEvent,
	});
	const extensionsResult = resourceLoader.getExtensions();

	return {
		session,
		extensionsResult,
		modelFallbackMessage,
	};
}

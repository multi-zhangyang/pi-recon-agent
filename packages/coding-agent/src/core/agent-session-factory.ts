import { join } from "node:path";
import type { ThinkingLevel } from "@pi-recon/repi-agent-core";
import { clampThinkingLevel, type Model } from "@pi-recon/repi-ai";
import { getAgentDir } from "../config.ts";
import { resolvePath } from "../utils/paths.ts";
import { createSessionAgent } from "./agent-factory.ts";
import { AgentSession } from "./agent-session.ts";
import {
	resolveLengthContinueMax,
	resolveMaxConsumedToolResultChars,
	resolveMaxToolResultChars,
	resolveMaxTurns,
	resolveStreamMaxRetries,
} from "./agent-session-policy.ts";
import { formatNoModelsAvailableMessage } from "./auth-guidance.ts";
import { AuthStorage } from "./auth-storage.ts";
import { DEFAULT_THINKING_LEVEL } from "./defaults.ts";
import type { ExtensionRunner, LoadExtensionsResult, SessionStartEvent, ToolDefinition } from "./extensions/index.ts";
import { ModelRegistry } from "./model-registry.ts";
import { findInitialModel, resolveRepiEnvPreferredModel } from "./model-resolver.ts";
import { ModelRuntime } from "./model-runtime.ts";
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
	/** Compatibility model registry. Default: a facade over {@link modelRuntime}. */
	modelRegistry?: ModelRegistry;
	/**
	 * Canonical provider/auth/stream runtime. By default it loads only explicitly
	 * configured models from agentDir/models.json, REPI_* variables, and extensions.
	 * A legacy custom registry disables this default runtime.
	 */
	modelRuntime?: ModelRuntime;
	/** Dispose an injected model runtime when the returned session is disposed. Defaults to false for injected runtimes. */
	disposeModelRuntime?: boolean;

	/** Model to use. Default: from settings, else first available explicitly configured model. */
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
	/** Reserve the final maxTurns request for a tool-free user-facing synthesis. Default: true when maxTurns is set. */
	reserveFinalTurn?: boolean;
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
	/**
	 * Aggregate chars retained from tool results after a later assistant turn has
	 * consumed them. Provider projection only; session/UI evidence stays complete.
	 * Falls back to `REPI_MAX_CONSUMED_TOOL_RESULT_CHARS`, then a context-scaled cap.
	 */
	maxConsumedToolResultChars?: number;
	/** Deduplicate identical read-only probes within one run. Default: true. */
	deduplicateReadOnlyToolCalls?: boolean;
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

// Public types used by SDK callers.

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
	resolveMaxConsumedToolResultChars,
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
 * // Minimal - model metadata comes from models.json, REPI_*, or extensions.
 * const { session } = await createAgentSession();
 *
 * // Select a model from the explicit runtime configuration.
 * const authStorage = AuthStorage.create();
 * const modelRuntime = await ModelRuntime.create({ credentials: authStorage.asCredentialStore() });
 * const model = modelRuntime.getModel('my-provider', 'my-model');
 * if (!model) throw new Error('Configure my-provider/my-model first');
 * const { session } = await createAgentSession({
 *   authStorage,
 *   modelRuntime,
 *   model,
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
	let ownedRuntime: ModelRuntime | undefined;
	try {
		return await createAgentSessionInternal(options, (runtime) => {
			ownedRuntime = runtime;
		});
	} catch (error) {
		try {
			ownedRuntime?.dispose();
		} catch {
			// Preserve the session initialization error after best-effort cleanup.
		}
		throw error;
	}
}

async function createAgentSessionInternal(
	options: CreateAgentSessionOptions,
	onOwnedRuntime: (runtime: ModelRuntime) => void,
): Promise<CreateAgentSessionResult> {
	const cwd = resolvePath(options.cwd ?? options.sessionManager?.getCwd() ?? process.cwd());
	const agentDir = options.agentDir ? resolvePath(options.agentDir) : getDefaultAgentDir();
	let resourceLoader = options.resourceLoader;

	// Use provided or create AuthStorage and ModelRegistry
	const authPath = options.agentDir ? join(agentDir, "auth.json") : undefined;
	const modelsPath = options.agentDir ? join(agentDir, "models.json") : undefined;
	const authStorage = options.authStorage ?? AuthStorage.create(authPath);
	const createsModelRuntime = !options.modelRuntime && !options.modelRegistry;
	const modelRuntime =
		options.modelRuntime ??
		(options.modelRegistry
			? undefined
			: await ModelRuntime.create({
					credentials: authStorage.asCredentialStore(),
					modelsPath,
				}));
	const ownsModelRuntime = options.disposeModelRuntime ?? createsModelRuntime;
	if (ownsModelRuntime && modelRuntime) onOwnedRuntime(modelRuntime);
	const modelRegistry =
		options.modelRegistry ??
		(modelRuntime
			? ModelRegistry.fromRuntime(authStorage, modelRuntime)
			: ModelRegistry.create(authStorage, modelsPath));

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

	// REPI_* env-only model selection is an explicit runtime override. It must
	// beat saved defaults and restored session models so provider switching works
	// like Claude Code: change exports, start repi, get that model.
	if (!model) {
		model = resolveRepiEnvPreferredModel(modelRegistry);
	}

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

	const extensionRunnerRef: { current?: ExtensionRunner } = {};
	const resolvedMaxTurns = resolveMaxTurns(options.maxTurns);
	const agent = createSessionAgent({
		model,
		thinkingLevel,
		settingsManager,
		sessionManager,
		modelRegistry,
		modelRuntime,
		extensionRunnerRef,
		runPolicy: {
			maxTurns: resolvedMaxTurns,
			reserveFinalTurn: options.reserveFinalTurn ?? resolvedMaxTurns !== undefined,
			lengthContinueMaxTurns: resolveLengthContinueMax(options.lengthContinueMaxTurns),
			streamMaxRetries: resolveStreamMaxRetries(options.streamMaxRetries),
			maxToolResultChars: resolveMaxToolResultChars(options.maxToolResultChars, model?.contextWindow),
			maxConsumedToolResultChars: resolveMaxConsumedToolResultChars(
				options.maxConsumedToolResultChars,
				model?.contextWindow,
			),
			deduplicateReadOnlyToolCalls: options.deduplicateReadOnlyToolCalls ?? true,
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
		modelRuntime,
		ownsModelRuntime,
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

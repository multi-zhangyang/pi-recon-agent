/**
 * Extension runner - executes extensions and manages their lifecycle.
 */

import type { AgentMessage } from "@pi-recon/repi-agent-core";
import type { ImageContent, Model, Provider, TextContent } from "@pi-recon/repi-ai";
import type { KeyId } from "@pi-recon/repi-tui";
import type { ResourceDiagnostic } from "../diagnostics.ts";
import type { KeybindingsConfig } from "../keybindings.ts";
import type { ModelRegistry } from "../model-registry.ts";
import type { Theme } from "../presentation/theme.ts";
import type { SessionManager } from "../session-manager.ts";
import type { BuildSystemPromptOptions } from "../system-prompt.ts";
import { headlessTheme } from "./headless-theme.ts";
import type {
	BeforeAgentStartEvent,
	BeforeAgentStartEventResult,
	BeforeProviderRequestEvent,
	CompactOptions,
	ContextEvent,
	ContextEventResult,
	ContextUsage,
	Extension,
	ExtensionActions,
	ExtensionCommandContext,
	ExtensionCommandContextActions,
	ExtensionContext,
	ExtensionContextActions,
	ExtensionError,
	ExtensionEvent,
	ExtensionFlag,
	ExtensionMode,
	ExtensionRuntime,
	ExtensionShortcut,
	ExtensionUIContext,
	InputEvent,
	InputEventResult,
	InputSource,
	MessageEndEvent,
	MessageEndEventResult,
	MessageRenderer,
	ProviderConfig,
	RegisteredCommand,
	RegisteredTool,
	ReplacedSessionContext,
	ResolvedCommand,
	ResourcesDiscoverEvent,
	ResourcesDiscoverResult,
	SessionBeforeCompactResult,
	SessionBeforeForkResult,
	SessionBeforeSwitchResult,
	SessionBeforeTreeResult,
	SessionShutdownEvent,
	ToolCallEvent,
	ToolCallEventResult,
	ToolResultEvent,
	ToolResultEventResult,
	UserBashEvent,
	UserBashEventResult,
} from "./types.ts";

// Extension shortcuts compete with canonical keybinding ids from keybindings.json.
// Only editor-global shortcuts are reserved here. Picker-specific bindings are not.
const RESERVED_KEYBINDINGS_FOR_EXTENSION_CONFLICTS = [
	"app.interrupt",
	"app.clear",
	"app.exit",
	"app.suspend",
	"app.thinking.cycle",
	"app.model.cycleForward",
	"app.model.cycleBackward",
	"app.model.select",
	"app.tools.expand",
	"app.thinking.toggle",
	"app.editor.external",
	"app.message.followUp",
	"tui.input.submit",
	"tui.select.confirm",
	"tui.select.cancel",
	"tui.input.copy",
	"tui.editor.deleteToLineEnd",
] as const;

type BuiltInKeyBindings = Partial<Record<KeyId, { keybinding: string; restrictOverride: boolean }>>;

const buildBuiltinKeybindings = (resolvedKeybindings: KeybindingsConfig): BuiltInKeyBindings => {
	const builtinKeybindings = {} as BuiltInKeyBindings;
	for (const [keybinding, keys] of Object.entries(resolvedKeybindings)) {
		if (keys === undefined) continue;
		const keyList = Array.isArray(keys) ? keys : [keys];
		const restrictOverride = (RESERVED_KEYBINDINGS_FOR_EXTENSION_CONFLICTS as readonly string[]).includes(keybinding);
		for (const key of keyList) {
			const normalizedKey = key.toLowerCase() as KeyId;
			// If multiple actions bind the same key, the reserved action wins so extensions
			// remain blocked by reserved shortcuts regardless of iteration order.
			const existing = builtinKeybindings[normalizedKey];
			if (existing?.restrictOverride && !restrictOverride) continue;
			builtinKeybindings[normalizedKey] = {
				keybinding,
				restrictOverride,
			};
		}
	}
	return builtinKeybindings;
};

/** Combined result from all before_agent_start handlers */
interface BeforeAgentStartCombinedResult {
	messages?: NonNullable<BeforeAgentStartEventResult["message"]>[];
	systemPrompt?: string;
}

// before_agent_start runs for every user turn. Keep extension-controlled data
// bounded so one buggy or untrusted extension cannot turn a long session into
// an unbounded transcript/system-prompt injection.
const MAX_BEFORE_AGENT_START_MESSAGES = 16;
const MAX_BEFORE_AGENT_START_MESSAGE_CHARS = 8_000;
const MAX_BEFORE_AGENT_START_TOTAL_CHARS = 24_000;
const MAX_EXTENSION_SYSTEM_PROMPT_DELTA_CHARS = 16_000;
const MAX_CONTEXT_HOOK_GROWTH_CHARS = 32_000;
const MAX_CONTEXT_HOOK_ADDED_MESSAGES = 32;
const EXTENSION_TRUNCATION_MARKER = "\n\n[extension content truncated]\n\n";

function estimateContextValue(value: unknown, seen = new WeakSet<object>(), limit = 100_000_000): number {
	if (typeof value === "string") return Math.min(value.length, limit);
	if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") return 8;
	if (typeof value !== "object") return 16;
	if (seen.has(value)) return 0;
	seen.add(value);
	let total = 0;
	if (Array.isArray(value)) {
		for (const item of value) {
			total += estimateContextValue(item, seen, Math.max(0, limit - total));
			if (total >= limit) return limit;
		}
		return total;
	}
	for (const [key, item] of Object.entries(value)) {
		if (key === "details" || key === "timestamp" || key === "display") continue;
		total += key.length + estimateContextValue(item, seen, Math.max(0, limit - total));
		if (total >= limit) return limit;
	}
	return total;
}

function estimateContextMessageChars(message: AgentMessage): number {
	return estimateContextValue(message);
}

function estimateContextMessagesChars(messages: AgentMessage[]): number {
	let total = 0;
	for (const message of messages) {
		total += estimateContextMessageChars(message);
		if (total >= 100_000_000) return 100_000_000;
	}
	return total;
}

function truncateExtensionMiddle(value: string, maxChars: number): string {
	if (value.length <= maxChars) return value;
	const marker = `\n...<truncated ${value.length - maxChars} chars>...\n`;
	if (marker.length >= maxChars) return value.slice(0, maxChars);
	const available = maxChars - marker.length;
	const head = Math.ceil(available / 2);
	return `${value.slice(0, head)}${marker}${value.slice(value.length - (available - head))}`;
}

function boundExtensionText(value: string, maxChars: number): string {
	if (value.length <= maxChars) return value;
	const bounded = `${truncateExtensionMiddle(value, Math.max(1, maxChars - EXTENSION_TRUNCATION_MARKER.length))}${EXTENSION_TRUNCATION_MARKER}`;
	return bounded.length <= maxChars ? bounded : bounded.slice(0, maxChars);
}

function boundBeforeAgentStartMessage(
	message: NonNullable<BeforeAgentStartEventResult["message"]>,
	remainingChars: number,
): NonNullable<BeforeAgentStartEventResult["message"]> | undefined {
	if (remainingChars <= 0) return undefined;
	const maxChars = Math.min(MAX_BEFORE_AGENT_START_MESSAGE_CHARS, remainingChars);
	if (typeof message.content === "string") {
		return { ...message, content: boundExtensionText(message.content, maxChars) };
	}
	let used = 0;
	const content: Array<TextContent | ImageContent> = [];
	for (const part of message.content) {
		const available = maxChars - used;
		if (available <= 0) break;
		if (part.type === "image") {
			if (part.data.length <= available) {
				content.push(part);
				used += part.data.length;
				continue;
			}
			const text = boundExtensionText(
				`[extension image omitted: ${part.mimeType}, ${part.data.length} base64 chars]`,
				available,
			);
			content.push({ type: "text", text });
			used += text.length;
			continue;
		}
		const text = boundExtensionText(part.text, available);
		content.push({ ...part, text });
		used += text.length;
	}
	if (content.length === 0) return undefined;
	return { ...message, content };
}

function boundExtensionSystemPrompt(base: string, candidate: string): string {
	const maxLength = base.length + MAX_EXTENSION_SYSTEM_PROMPT_DELTA_CHARS;
	if (candidate.length <= maxLength) return candidate;
	if (candidate.startsWith(base)) {
		const suffixBudget = Math.max(1, maxLength - base.length - EXTENSION_TRUNCATION_MARKER.length);
		const bounded = `${base}${EXTENSION_TRUNCATION_MARKER}${truncateExtensionMiddle(candidate.slice(base.length), suffixBudget)}`;
		return bounded.length <= maxLength ? bounded : bounded.slice(0, maxLength);
	}
	return boundExtensionText(candidate, maxLength);
}

async function callContextHandlerAbortable<T>(fn: () => Promise<T> | T, signal: AbortSignal): Promise<T> {
	if (signal.aborted) {
		throw new Error("Agent run aborted");
	}

	let cleanup = () => {};
	const abortPromise = new Promise<never>((_resolve, reject) => {
		const onAbort = () => reject(new Error("Agent run aborted"));
		signal.addEventListener("abort", onAbort, { once: true });
		cleanup = () => signal.removeEventListener("abort", onAbort);
	});

	try {
		return await Promise.race([Promise.resolve().then(fn), abortPromise]);
	} finally {
		cleanup();
	}
}

/**
 * Events handled by the generic emit() method.
 * Events with dedicated emitXxx() methods are excluded for stronger type safety.
 */
type RunnerEmitEvent = Exclude<
	ExtensionEvent,
	| ToolCallEvent
	| ToolResultEvent
	| UserBashEvent
	| ContextEvent
	| BeforeProviderRequestEvent
	| BeforeAgentStartEvent
	| MessageEndEvent
	| ResourcesDiscoverEvent
	| InputEvent
>;

type SessionBeforeEvent = Extract<
	RunnerEmitEvent,
	{ type: "session_before_switch" | "session_before_fork" | "session_before_compact" | "session_before_tree" }
>;

type SessionBeforeEventResult =
	| SessionBeforeSwitchResult
	| SessionBeforeForkResult
	| SessionBeforeCompactResult
	| SessionBeforeTreeResult;

type RunnerEmitResult<TEvent extends RunnerEmitEvent> = TEvent extends { type: "session_before_switch" }
	? SessionBeforeSwitchResult | undefined
	: TEvent extends { type: "session_before_fork" }
		? SessionBeforeForkResult | undefined
		: TEvent extends { type: "session_before_compact" }
			? SessionBeforeCompactResult | undefined
			: TEvent extends { type: "session_before_tree" }
				? SessionBeforeTreeResult | undefined
				: undefined;

export type ExtensionErrorListener = (error: ExtensionError) => void;

export type NewSessionHandler = (options?: {
	parentSession?: string;
	setup?: (sessionManager: SessionManager) => Promise<void>;
	withSession?: (ctx: ReplacedSessionContext) => Promise<void>;
}) => Promise<{ cancelled: boolean }>;

export type ForkHandler = (
	entryId: string,
	options?: { position?: "before" | "at"; withSession?: (ctx: ReplacedSessionContext) => Promise<void> },
) => Promise<{ cancelled: boolean }>;

export type NavigateTreeHandler = (
	targetId: string,
	options?: { summarize?: boolean; customInstructions?: string; replaceInstructions?: boolean; label?: string },
) => Promise<{ cancelled: boolean }>;

export type SwitchSessionHandler = (
	sessionPath: string,
	options?: { withSession?: (ctx: ReplacedSessionContext) => Promise<void> },
) => Promise<{ cancelled: boolean }>;

export type ReloadHandler = () => Promise<void>;

export type ShutdownHandler = () => void;

/**
 * Helper function to emit session_shutdown event to extensions.
 * Returns true if the event was emitted, false if there were no handlers.
 */
export async function emitSessionShutdownEvent(
	extensionRunner: ExtensionRunner,
	event: SessionShutdownEvent,
): Promise<boolean> {
	if (extensionRunner.hasHandlers("session_shutdown")) {
		await extensionRunner.emit(event);
		return true;
	}
	return false;
}

const noOpUIContext: ExtensionUIContext = {
	select: async () => undefined,
	confirm: async () => false,
	input: async () => undefined,
	notify: () => {},
	onTerminalInput: () => () => {},
	setStatus: () => {},
	setWorkingMessage: () => {},
	setWorkingVisible: () => {},
	setWorkingIndicator: () => {},
	setHiddenThinkingLabel: () => {},
	setWidget: () => {},
	setFooter: () => {},
	setHeader: () => {},
	setTitle: () => {},
	custom: async () => undefined as never,
	pasteToEditor: () => {},
	setEditorText: () => {},
	getEditorText: () => "",
	editor: async () => undefined,
	addAutocompleteProvider: () => {},
	setEditorComponent: () => {},
	getEditorComponent: () => undefined,
	get theme() {
		return headlessTheme;
	},
	getAllThemes: () => [],
	getTheme: () => undefined,
	setTheme: (_theme: string | Theme) => ({ success: false, error: "UI not available" }),
	getToolsExpanded: () => false,
	setToolsExpanded: () => {},
};

export class ExtensionRunner {
	private extensions: Extension[];
	private runtime: ExtensionRuntime;
	private uiContext: ExtensionUIContext;
	private mode: ExtensionMode = "print";
	private cwd: string;
	private sessionManager: SessionManager;
	private modelRegistry: ModelRegistry;
	private errorListeners: Set<ExtensionErrorListener> = new Set();
	private getModel: () => Model<any> | undefined = () => undefined;
	private isIdleFn: () => boolean = () => true;
	private getSignalFn: () => AbortSignal | undefined = () => undefined;
	private waitForIdleFn: () => Promise<void> = async () => {};
	private abortFn: () => void = () => {};
	private hasPendingMessagesFn: () => boolean = () => false;
	private getContextUsageFn: () => ContextUsage | undefined = () => undefined;
	private compactFn: (options?: CompactOptions) => void = () => {};
	private getSystemPromptFn: () => string = () => "";
	private getSystemPromptOptionsFn: () => BuildSystemPromptOptions = () => ({ cwd: this.cwd });
	private newSessionHandler: NewSessionHandler = async () => ({ cancelled: false });
	private forkHandler: ForkHandler = async () => ({ cancelled: false });
	private navigateTreeHandler: NavigateTreeHandler = async () => ({ cancelled: false });
	private switchSessionHandler: SwitchSessionHandler = async () => ({ cancelled: false });
	private reloadHandler: ReloadHandler = async () => {};
	private shutdownHandler: ShutdownHandler = () => {};
	private shortcutDiagnostics: ResourceDiagnostic[] = [];
	private commandDiagnostics: ResourceDiagnostic[] = [];
	private staleMessage: string | undefined;
	private providerOwners = new Map<string, string>();
	private unregisterOwnedProviderAction: ((name: string, extensionPath: string) => void) | undefined;

	constructor(
		extensions: Extension[],
		runtime: ExtensionRuntime,
		cwd: string,
		sessionManager: SessionManager,
		modelRegistry: ModelRegistry,
	) {
		this.extensions = extensions;
		this.runtime = runtime;
		this.uiContext = noOpUIContext;
		this.cwd = cwd;
		this.sessionManager = sessionManager;
		this.modelRegistry = modelRegistry;
	}

	bindCore(
		actions: ExtensionActions,
		contextActions: ExtensionContextActions,
		providerActions?: {
			registerProvider?: (name: string, config: ProviderConfig) => void;
			registerNativeProvider?: (provider: Provider) => void;
			unregisterProvider?: (name: string) => void;
		},
	): void {
		// Copy actions into the shared runtime (all extension APIs reference this)
		this.runtime.sendMessage = actions.sendMessage;
		this.runtime.sendUserMessage = actions.sendUserMessage;
		this.runtime.appendEntry = actions.appendEntry;
		this.runtime.setSessionName = actions.setSessionName;
		this.runtime.getSessionName = actions.getSessionName;
		this.runtime.setLabel = actions.setLabel;
		this.runtime.getActiveTools = actions.getActiveTools;
		this.runtime.getAllTools = actions.getAllTools;
		this.runtime.setActiveTools = actions.setActiveTools;
		this.runtime.refreshTools = actions.refreshTools;
		this.runtime.getCommands = actions.getCommands;
		this.runtime.setModel = actions.setModel;
		this.runtime.getThinkingLevel = actions.getThinkingLevel;
		this.runtime.setThinkingLevel = actions.setThinkingLevel;

		// Context actions (required)
		this.getModel = contextActions.getModel;
		this.isIdleFn = contextActions.isIdle;
		this.getSignalFn = contextActions.getSignal;
		this.abortFn = contextActions.abort;
		this.hasPendingMessagesFn = contextActions.hasPendingMessages;
		this.shutdownHandler = contextActions.shutdown;
		this.getContextUsageFn = contextActions.getContextUsage;
		this.compactFn = contextActions.compact;
		this.getSystemPromptFn = contextActions.getSystemPrompt;
		this.getSystemPromptOptionsFn = contextActions.getSystemPromptOptions ?? (() => ({ cwd: this.cwd }));

		const registerLegacyProvider = (name: string, config: ProviderConfig, extensionPath: string): void => {
			if (providerActions?.registerProvider) providerActions.registerProvider(name, config);
			else this.modelRegistry.registerProvider(name, config);
			this.providerOwners.set(name, extensionPath);
		};
		const registerNativeProvider = (provider: Provider, extensionPath: string): void => {
			if (!providerActions?.registerNativeProvider || !providerActions.unregisterProvider) {
				throw new Error(
					"Native provider registration requires registerNativeProvider and unregisterProvider runtime actions",
				);
			}
			providerActions.registerNativeProvider(provider);
			this.providerOwners.set(provider.id, extensionPath);
		};
		const unregisterOwnedProvider = (name: string, extensionPath: string): void => {
			if (this.providerOwners.get(name) !== extensionPath) return;
			if (providerActions?.unregisterProvider) providerActions.unregisterProvider(name);
			else this.modelRegistry.unregisterProvider(name);
			this.providerOwners.delete(name);
		};
		this.unregisterOwnedProviderAction = unregisterOwnedProvider;

		// Preserve source order when native and legacy registrations are interleaved.
		const pendingProviders = [
			...this.runtime.pendingProviderRegistrations.map((registration) => ({
				kind: "legacy" as const,
				...registration,
			})),
			...this.runtime.pendingNativeProviderRegistrations.map((registration) => ({
				kind: "native" as const,
				...registration,
			})),
		].sort((left, right) => left.order - right.order);
		for (const registration of pendingProviders) {
			try {
				if (registration.preApplied) {
					this.providerOwners.set(
						registration.kind === "native" ? registration.provider.id : registration.name,
						registration.extensionPath,
					);
					continue;
				}
				if (registration.kind === "native") {
					registerNativeProvider(registration.provider, registration.extensionPath);
				} else {
					registerLegacyProvider(registration.name, registration.config, registration.extensionPath);
				}
			} catch (err) {
				this.emitError({
					extensionPath: registration.extensionPath,
					event: "register_provider",
					error: err instanceof Error ? err.message : String(err),
					stack: err instanceof Error ? err.stack : undefined,
				});
			}
		}
		this.runtime.pendingProviderRegistrations = [];
		this.runtime.pendingNativeProviderRegistrations = [];

		// From this point on, provider registration/unregistration takes effect immediately
		// without requiring a /reload.
		this.runtime.registerProvider = (name, config, extensionPath = "<unknown>") => {
			registerLegacyProvider(name, config, extensionPath);
		};
		this.runtime.registerNativeProvider = (provider, extensionPath = "<unknown>") => {
			registerNativeProvider(provider, extensionPath);
		};
		this.runtime.unregisterProvider = (name, extensionPath = "<unknown>") => {
			unregisterOwnedProvider(name, extensionPath);
		};
	}

	unregisterOwnedProviders(): void {
		const unregister = this.unregisterOwnedProviderAction;
		if (!unregister) return;
		for (const [name, extensionPath] of [...this.providerOwners]) {
			try {
				unregister(name, extensionPath);
			} catch (error) {
				this.emitError({
					extensionPath,
					event: "unregister_provider",
					error: error instanceof Error ? error.message : String(error),
					stack: error instanceof Error ? error.stack : undefined,
				});
			}
		}
	}

	bindCommandContext(actions?: ExtensionCommandContextActions): void {
		if (actions) {
			this.waitForIdleFn = actions.waitForIdle;
			this.newSessionHandler = actions.newSession;
			this.forkHandler = actions.fork;
			this.navigateTreeHandler = actions.navigateTree;
			this.switchSessionHandler = actions.switchSession;
			this.reloadHandler = actions.reload;
			return;
		}

		this.waitForIdleFn = async () => {};
		this.newSessionHandler = async () => ({ cancelled: false });
		this.forkHandler = async () => ({ cancelled: false });
		this.navigateTreeHandler = async () => ({ cancelled: false });
		this.switchSessionHandler = async () => ({ cancelled: false });
		this.reloadHandler = async () => {};
	}

	setUIContext(uiContext?: ExtensionUIContext, mode: ExtensionMode = "print"): void {
		this.uiContext = uiContext ?? noOpUIContext;
		this.mode = mode;
	}

	getUIContext(): ExtensionUIContext {
		return this.uiContext;
	}

	hasUI(): boolean {
		return this.uiContext !== noOpUIContext;
	}

	getExtensionPaths(): string[] {
		return this.extensions.map((e) => e.path);
	}

	/** Get all registered tools from all extensions (first registration per name wins). */
	getAllRegisteredTools(): RegisteredTool[] {
		const toolsByName = new Map<string, RegisteredTool>();
		for (const ext of this.extensions) {
			for (const tool of ext.tools.values()) {
				if (!toolsByName.has(tool.definition.name)) {
					toolsByName.set(tool.definition.name, tool);
				}
			}
		}
		return Array.from(toolsByName.values());
	}

	/** Get a tool definition by name. Returns undefined if not found. */
	getToolDefinition(toolName: string): RegisteredTool["definition"] | undefined {
		for (const ext of this.extensions) {
			const tool = ext.tools.get(toolName);
			if (tool) {
				return tool.definition;
			}
		}
		return undefined;
	}

	getFlags(): Map<string, ExtensionFlag> {
		const allFlags = new Map<string, ExtensionFlag>();
		for (const ext of this.extensions) {
			for (const [name, flag] of ext.flags) {
				if (!allFlags.has(name)) {
					allFlags.set(name, flag);
				}
			}
		}
		return allFlags;
	}

	setFlagValue(name: string, value: boolean | string): void {
		this.runtime.flagValues.set(name, value);
	}

	getFlagValues(): Map<string, boolean | string> {
		return new Map(this.runtime.flagValues);
	}

	getShortcuts(resolvedKeybindings: KeybindingsConfig): Map<KeyId, ExtensionShortcut> {
		this.shortcutDiagnostics = [];
		const builtinKeybindings = buildBuiltinKeybindings(resolvedKeybindings);
		const extensionShortcuts = new Map<KeyId, ExtensionShortcut>();

		const addDiagnostic = (message: string, extensionPath: string) => {
			this.shortcutDiagnostics.push({ type: "warning", message, path: extensionPath });
			if (!this.hasUI()) {
				console.warn(message);
			}
		};

		for (const ext of this.extensions) {
			for (const [key, shortcut] of ext.shortcuts) {
				const normalizedKey = key.toLowerCase() as KeyId;

				const builtInKeybinding = builtinKeybindings[normalizedKey];
				if (builtInKeybinding?.restrictOverride === true) {
					addDiagnostic(
						`Extension shortcut '${key}' from ${shortcut.extensionPath} conflicts with built-in shortcut. Skipping.`,
						shortcut.extensionPath,
					);
					continue;
				}

				if (builtInKeybinding?.restrictOverride === false) {
					addDiagnostic(
						`Extension shortcut conflict: '${key}' is built-in shortcut for ${builtInKeybinding.keybinding} and ${shortcut.extensionPath}. Using ${shortcut.extensionPath}.`,
						shortcut.extensionPath,
					);
				}

				const existingExtensionShortcut = extensionShortcuts.get(normalizedKey);
				if (existingExtensionShortcut) {
					addDiagnostic(
						`Extension shortcut conflict: '${key}' registered by both ${existingExtensionShortcut.extensionPath} and ${shortcut.extensionPath}. Using ${shortcut.extensionPath}.`,
						shortcut.extensionPath,
					);
				}
				extensionShortcuts.set(normalizedKey, shortcut);
			}
		}
		return extensionShortcuts;
	}

	getShortcutDiagnostics(): ResourceDiagnostic[] {
		return this.shortcutDiagnostics;
	}

	invalidate(
		message = "This extension ctx is stale after session replacement or reload. Do not use a captured pi or command ctx after ctx.newSession(), ctx.fork(), ctx.switchSession(), or ctx.reload(). For newSession, fork, and switchSession, move post-replacement work into withSession and use the ctx passed to withSession. For reload, do not use the old ctx after await ctx.reload().",
	): void {
		if (!this.staleMessage) {
			this.staleMessage = message;
			this.runtime.invalidate(message);
		}
	}

	private assertActive(): void {
		if (this.staleMessage) {
			throw new Error(this.staleMessage);
		}
	}

	onError(listener: ExtensionErrorListener): () => void {
		this.errorListeners.add(listener);
		return () => this.errorListeners.delete(listener);
	}

	emitError(error: ExtensionError): void {
		// opt #56 — guard each error listener: a throwing error listener (a misbehaving
		// diagnostics/telemetry consumer) used to (a) prevent all REMAINING error listeners from
		// being notified and (b) propagate out of emitError into the calling emit method's catch
		// block, aborting that emit (e.g. emitContext runs every turn — a throwing error listener
		// there would abort the turn with []). Same doctrine as footer-data-provider's
		// notifyBranchChange (opt #53): swallow per-listener, continue the loop.
		for (const listener of this.errorListeners) {
			try {
				listener(error);
			} catch {
				// One bad error listener must not poison sibling listeners or propagate.
			}
		}
	}

	hasHandlers(eventType: string): boolean {
		for (const ext of this.extensions) {
			const handlers = ext.handlers.get(eventType);
			if (handlers && handlers.length > 0) {
				return true;
			}
		}
		return false;
	}

	getMessageRenderer(customType: string): MessageRenderer | undefined {
		for (const ext of this.extensions) {
			const renderer = ext.messageRenderers.get(customType);
			if (renderer) {
				return renderer;
			}
		}
		return undefined;
	}

	private resolveRegisteredCommands(): ResolvedCommand[] {
		const commands: RegisteredCommand[] = [];
		const counts = new Map<string, number>();

		for (const ext of this.extensions) {
			for (const command of ext.commands.values()) {
				commands.push(command);
				counts.set(command.name, (counts.get(command.name) ?? 0) + 1);
			}
		}

		const seen = new Map<string, number>();
		const takenInvocationNames = new Set<string>();

		return commands.map((command) => {
			const occurrence = (seen.get(command.name) ?? 0) + 1;
			seen.set(command.name, occurrence);

			let invocationName = (counts.get(command.name) ?? 0) > 1 ? `${command.name}:${occurrence}` : command.name;

			if (takenInvocationNames.has(invocationName)) {
				let suffix = occurrence;
				do {
					suffix++;
					invocationName = `${command.name}:${suffix}`;
				} while (takenInvocationNames.has(invocationName));
			}

			takenInvocationNames.add(invocationName);
			return {
				...command,
				invocationName,
			};
		});
	}

	getRegisteredCommands(): ResolvedCommand[] {
		this.commandDiagnostics = [];
		return this.resolveRegisteredCommands();
	}

	getCommandDiagnostics(): ResourceDiagnostic[] {
		return this.commandDiagnostics;
	}

	getCommand(name: string): ResolvedCommand | undefined {
		return this.resolveRegisteredCommands().find((command) => command.invocationName === name);
	}

	/**
	 * Request a graceful shutdown. Called by extension tools and event handlers.
	 * The actual shutdown behavior is provided by the mode via bindExtensions().
	 */
	shutdown(): void {
		this.shutdownHandler();
	}

	getActiveTools(): string[] {
		this.assertActive();
		return this.runtime.getActiveTools();
	}

	/**
	 * Create an ExtensionContext for use in event handlers and tool execution.
	 * Context values are resolved at call time, so changes via bindCore/bindUI are reflected.
	 */
	createContext(): ExtensionContext {
		const runner = this;
		const getModel = this.getModel;
		return {
			get ui() {
				runner.assertActive();
				return runner.uiContext;
			},
			get mode() {
				runner.assertActive();
				return runner.mode;
			},
			get hasUI() {
				runner.assertActive();
				return runner.hasUI();
			},
			get cwd() {
				runner.assertActive();
				return runner.cwd;
			},
			get sessionManager() {
				runner.assertActive();
				return runner.sessionManager;
			},
			get modelRegistry() {
				runner.assertActive();
				return runner.modelRegistry;
			},
			get model() {
				runner.assertActive();
				return getModel();
			},
			isIdle: () => {
				runner.assertActive();
				return runner.isIdleFn();
			},
			get signal() {
				runner.assertActive();
				return runner.getSignalFn();
			},
			abort: () => {
				runner.assertActive();
				runner.abortFn();
			},
			hasPendingMessages: () => {
				runner.assertActive();
				return runner.hasPendingMessagesFn();
			},
			shutdown: () => {
				runner.assertActive();
				runner.shutdownHandler();
			},
			getContextUsage: () => {
				runner.assertActive();
				return runner.getContextUsageFn();
			},
			compact: (options) => {
				runner.assertActive();
				runner.compactFn(options);
			},
			getSystemPrompt: () => {
				runner.assertActive();
				return runner.getSystemPromptFn();
			},
		};
	}

	createCommandContext(): ExtensionCommandContext {
		// Use property descriptors instead of object spread so the guarded getters from
		// createContext() stay lazy. A spread would eagerly read them once and freeze the
		// old values into the returned object, bypassing stale-instance checks.
		const context = Object.defineProperties(
			{},
			Object.getOwnPropertyDescriptors(this.createContext()),
		) as ExtensionCommandContext;
		context.getSystemPromptOptions = () => {
			this.assertActive();
			return this.getSystemPromptOptionsFn();
		};
		context.waitForIdle = () => {
			this.assertActive();
			return this.waitForIdleFn();
		};
		context.newSession = (options) => {
			this.assertActive();
			return this.newSessionHandler(options);
		};
		context.fork = (entryId, options) => {
			this.assertActive();
			return this.forkHandler(entryId, options);
		};
		context.navigateTree = (targetId, options) => {
			this.assertActive();
			return this.navigateTreeHandler(targetId, options);
		};
		context.switchSession = (sessionPath, options) => {
			this.assertActive();
			return this.switchSessionHandler(sessionPath, options);
		};
		context.reload = () => {
			this.assertActive();
			return this.reloadHandler();
		};
		return context;
	}

	private isSessionBeforeEvent(event: RunnerEmitEvent): event is SessionBeforeEvent {
		return (
			event.type === "session_before_switch" ||
			event.type === "session_before_fork" ||
			event.type === "session_before_compact" ||
			event.type === "session_before_tree"
		);
	}

	async emit<TEvent extends RunnerEmitEvent>(event: TEvent): Promise<RunnerEmitResult<TEvent>> {
		const ctx = this.createContext();
		let result: SessionBeforeEventResult | undefined;

		for (const ext of this.extensions) {
			const handlers = ext.handlers.get(event.type);
			if (!handlers || handlers.length === 0) continue;

			for (const handler of handlers) {
				try {
					const handlerResult = await handler(event, ctx);

					if (this.isSessionBeforeEvent(event) && handlerResult) {
						result = handlerResult as SessionBeforeEventResult;
						if (result.cancel) {
							return result as RunnerEmitResult<TEvent>;
						}
					}
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					const stack = err instanceof Error ? err.stack : undefined;
					this.emitError({
						extensionPath: ext.path,
						event: event.type,
						error: message,
						stack,
					});
				}
			}
		}

		return result as RunnerEmitResult<TEvent>;
	}

	async emitMessageEnd(event: MessageEndEvent): Promise<AgentMessage | undefined> {
		const ctx = this.createContext();
		let currentMessage = event.message;
		let modified = false;

		for (const ext of this.extensions) {
			const handlers = ext.handlers.get("message_end");
			if (!handlers || handlers.length === 0) continue;

			for (const handler of handlers) {
				try {
					const currentEvent: MessageEndEvent = { ...event, message: currentMessage };
					const handlerResult = (await handler(currentEvent, ctx)) as MessageEndEventResult | undefined;
					if (!handlerResult?.message) continue;

					if (handlerResult.message.role !== currentMessage.role) {
						this.emitError({
							extensionPath: ext.path,
							event: "message_end",
							error: "message_end handlers must return a message with the same role",
						});
						continue;
					}

					currentMessage = handlerResult.message;
					modified = true;
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					const stack = err instanceof Error ? err.stack : undefined;
					this.emitError({
						extensionPath: ext.path,
						event: "message_end",
						error: message,
						stack,
					});
				}
			}
		}

		return modified ? currentMessage : undefined;
	}

	async emitToolResult(event: ToolResultEvent): Promise<ToolResultEventResult | undefined> {
		const ctx = this.createContext();
		const cloneContent = (content: ToolResultEvent["content"]): ToolResultEvent["content"] =>
			content.map((part) => ({ ...part }));
		// Isolate nested blocks from the executor-owned result. Extensions often
		// mutate hook events in place; that must not silently rewrite the durable
		// tool transcript unless they explicitly return replacement content.
		const currentEvent: ToolResultEvent = { ...event, content: cloneContent(event.content) };
		let modified = false;

		for (const ext of this.extensions) {
			const handlers = ext.handlers.get("tool_result");
			if (!handlers || handlers.length === 0) continue;

			for (const handler of handlers) {
				try {
					const handlerResult = (await handler(currentEvent, ctx)) as ToolResultEventResult | undefined;
					if (!handlerResult) continue;

					if (handlerResult.content !== undefined) {
						currentEvent.content = cloneContent(handlerResult.content);
						modified = true;
					}
					if (handlerResult.details !== undefined) {
						currentEvent.details = handlerResult.details;
						modified = true;
					}
					if (handlerResult.isError !== undefined) {
						currentEvent.isError = handlerResult.isError;
						modified = true;
					}
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					const stack = err instanceof Error ? err.stack : undefined;
					this.emitError({
						extensionPath: ext.path,
						event: "tool_result",
						error: message,
						stack,
					});
				}
			}
		}

		if (!modified) {
			return undefined;
		}

		return {
			content: currentEvent.content,
			details: currentEvent.details,
			isError: currentEvent.isError,
		};
	}

	async emitToolCall(event: ToolCallEvent): Promise<ToolCallEventResult | undefined> {
		const ctx = this.createContext();
		let result: ToolCallEventResult | undefined;

		for (const ext of this.extensions) {
			const handlers = ext.handlers.get("tool_call");
			if (!handlers || handlers.length === 0) continue;

			for (const handler of handlers) {
				try {
					const handlerResult = await handler(event, ctx);

					if (handlerResult) {
						result = handlerResult as ToolCallEventResult;
						if (result.block) {
							return result;
						}
					}
				} catch (err) {
					// opt #56 — route the handler throw to errorListeners (matching every sibling
					// emit method: emit/emitMessageEnd/emitToolResult/emitUserBash/emitContext/...)
					// so extension error telemetry registered via runner.onError() sees tool_call
					// handler failures. Then RE-THROW: the caller (agent-session beforeToolCall →
					// agent-loop prepareToolCall catch) converts a throw into a blocked tool result,
					// and that block-on-throw semantics must be preserved.
					const message = err instanceof Error ? err.message : String(err);
					const stack = err instanceof Error ? err.stack : undefined;
					this.emitError({
						extensionPath: ext.path,
						event: "tool_call",
						error: message,
						stack,
					});
					throw err;
				}
			}
		}

		return result;
	}

	async emitUserBash(event: UserBashEvent): Promise<UserBashEventResult | undefined> {
		const ctx = this.createContext();

		for (const ext of this.extensions) {
			const handlers = ext.handlers.get("user_bash");
			if (!handlers || handlers.length === 0) continue;

			for (const handler of handlers) {
				try {
					const handlerResult = await handler(event, ctx);
					if (handlerResult) {
						return handlerResult as UserBashEventResult;
					}
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					const stack = err instanceof Error ? err.stack : undefined;
					this.emitError({
						extensionPath: ext.path,
						event: "user_bash",
						error: message,
						stack,
					});
				}
			}
		}

		return undefined;
	}

	async emitContext(messages: AgentMessage[]): Promise<AgentMessage[]> {
		// opt #84 — no-handler fast path. emitContext runs EVERY turn (sdk.ts transformContext
		// → agent-loop.ts:387) AND on every retry attempt, and structuredClone(messages) is
		// O(total message blocks) — it deep-traverses the full conversation history. With no
		// "context" handlers registered (the default REPI install — none ship one), the clone
		// exists only to give handlers a mutable copy and to protect the caller's array from
		// handler mutation. With zero handlers there is no mutation, so the clone is pure waste:
		// O(history) per turn × T turns = O(history·T) ≈ quadratic session growth for nothing.
		// Skip it: return the caller's array directly. Behavior is identical — the downstream
		// (convertToLlm at agent-loop.ts:389) reads messages read-only and builds fresh LLM
		// messages; it never mutates the AgentMessage[] returned here. If an extension later
		// registers a "context" handler, hasHandlers flips true and the clone+loop runs as
		// before (additive: default behavior unchanged).
		if (!this.hasHandlers("context")) {
			return messages;
		}
		const ctx = this.createContext();
		const signal = ctx.signal;
		let currentMessages = structuredClone(messages);

		for (const ext of this.extensions) {
			const handlers = ext.handlers.get("context");
			if (!handlers || handlers.length === 0) continue;

			for (const handler of handlers) {
				try {
					const previousChars = estimateContextMessagesChars(currentMessages);
					const previousCount = currentMessages.length;
					const event: ContextEvent = { type: "context", messages: structuredClone(currentMessages) };
					const handlerResult = signal
						? await callContextHandlerAbortable(() => handler(event, ctx), signal)
						: await handler(event, ctx);

					if (handlerResult && (handlerResult as ContextEventResult).messages) {
						const candidate = (handlerResult as ContextEventResult).messages!;
						const candidateChars = estimateContextMessagesChars(candidate);
						const addedMessages = Math.max(0, candidate.length - previousCount);
						if (
							candidateChars > previousChars + MAX_CONTEXT_HOOK_GROWTH_CHARS ||
							addedMessages > MAX_CONTEXT_HOOK_ADDED_MESSAGES
						) {
							this.emitError({
								extensionPath: ext.path,
								event: "context",
								error: `context hook output rejected: growth=${Math.max(0, candidateChars - previousChars)} chars, addedMessages=${addedMessages}`,
							});
							continue;
						}
						currentMessages = candidate;
					}
				} catch (err) {
					if (signal?.aborted) {
						throw err;
					}
					const message = err instanceof Error ? err.message : String(err);
					const stack = err instanceof Error ? err.stack : undefined;
					this.emitError({
						extensionPath: ext.path,
						event: "context",
						error: message,
						stack,
					});
				}
			}
		}

		return currentMessages;
	}

	async emitBeforeProviderRequest(payload: unknown): Promise<unknown> {
		const ctx = this.createContext();
		let currentPayload = payload;

		for (const ext of this.extensions) {
			const handlers = ext.handlers.get("before_provider_request");
			if (!handlers || handlers.length === 0) continue;

			for (const handler of handlers) {
				try {
					const event: BeforeProviderRequestEvent = {
						type: "before_provider_request",
						payload: currentPayload,
					};
					const handlerResult = await handler(event, ctx);
					if (handlerResult !== undefined) {
						currentPayload = handlerResult;
					}
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					const stack = err instanceof Error ? err.stack : undefined;
					this.emitError({
						extensionPath: ext.path,
						event: "before_provider_request",
						error: message,
						stack,
					});
				}
			}
		}

		return currentPayload;
	}

	async emitBeforeAgentStart(
		prompt: string,
		images: ImageContent[] | undefined,
		systemPrompt: string,
		systemPromptOptions: BuildSystemPromptOptions,
	): Promise<BeforeAgentStartCombinedResult | undefined> {
		const baseSystemPrompt = systemPrompt;
		let currentSystemPrompt = systemPrompt;
		const ctx = Object.defineProperties(
			{},
			Object.getOwnPropertyDescriptors(this.createContext()),
		) as ExtensionContext;
		ctx.getSystemPrompt = () => {
			this.assertActive();
			return currentSystemPrompt;
		};
		const messages: NonNullable<BeforeAgentStartEventResult["message"]>[] = [];
		let messageChars = 0;
		let systemPromptModified = false;

		for (const ext of this.extensions) {
			const handlers = ext.handlers.get("before_agent_start");
			if (!handlers || handlers.length === 0) continue;

			for (const handler of handlers) {
				try {
					const event: BeforeAgentStartEvent = {
						type: "before_agent_start",
						prompt,
						images,
						systemPrompt: currentSystemPrompt,
						systemPromptOptions,
					};
					const handlerResult = await handler(event, ctx);

					if (handlerResult) {
						const result = handlerResult as BeforeAgentStartEventResult;
						if (result.message && messages.length < MAX_BEFORE_AGENT_START_MESSAGES) {
							const bounded = boundBeforeAgentStartMessage(
								result.message,
								MAX_BEFORE_AGENT_START_TOTAL_CHARS - messageChars,
							);
							if (bounded) {
								messages.push(bounded);
								messageChars +=
									typeof bounded.content === "string"
										? bounded.content.length
										: bounded.content.reduce(
												(total, part) => total + (part.type === "text" ? part.text.length : 0),
												0,
											);
							}
						}
						if (result.systemPrompt !== undefined) {
							currentSystemPrompt = boundExtensionSystemPrompt(baseSystemPrompt, result.systemPrompt);
							systemPromptModified = true;
						}
					}
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					const stack = err instanceof Error ? err.stack : undefined;
					this.emitError({
						extensionPath: ext.path,
						event: "before_agent_start",
						error: message,
						stack,
					});
				}
			}
		}

		if (messages.length > 0 || systemPromptModified) {
			return {
				messages: messages.length > 0 ? messages : undefined,
				systemPrompt: systemPromptModified ? currentSystemPrompt : undefined,
			};
		}

		return undefined;
	}

	async emitResourcesDiscover(
		cwd: string,
		reason: ResourcesDiscoverEvent["reason"],
	): Promise<{
		skillPaths: Array<{ path: string; extensionPath: string }>;
		promptPaths: Array<{ path: string; extensionPath: string }>;
		themePaths: Array<{ path: string; extensionPath: string }>;
	}> {
		const ctx = this.createContext();
		const skillPaths: Array<{ path: string; extensionPath: string }> = [];
		const promptPaths: Array<{ path: string; extensionPath: string }> = [];
		const themePaths: Array<{ path: string; extensionPath: string }> = [];

		for (const ext of this.extensions) {
			const handlers = ext.handlers.get("resources_discover");
			if (!handlers || handlers.length === 0) continue;

			for (const handler of handlers) {
				try {
					const event: ResourcesDiscoverEvent = { type: "resources_discover", cwd, reason };
					const handlerResult = await handler(event, ctx);
					const result = handlerResult as ResourcesDiscoverResult | undefined;

					if (result?.skillPaths?.length) {
						skillPaths.push(...result.skillPaths.map((path) => ({ path, extensionPath: ext.path })));
					}
					if (result?.promptPaths?.length) {
						promptPaths.push(...result.promptPaths.map((path) => ({ path, extensionPath: ext.path })));
					}
					if (result?.themePaths?.length) {
						themePaths.push(...result.themePaths.map((path) => ({ path, extensionPath: ext.path })));
					}
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					const stack = err instanceof Error ? err.stack : undefined;
					this.emitError({
						extensionPath: ext.path,
						event: "resources_discover",
						error: message,
						stack,
					});
				}
			}
		}

		return { skillPaths, promptPaths, themePaths };
	}

	/** Emit input event. Transforms chain, "handled" short-circuits. */
	async emitInput(
		text: string,
		images: ImageContent[] | undefined,
		source: InputSource,
		streamingBehavior?: "steer" | "followUp",
	): Promise<InputEventResult> {
		const ctx = this.createContext();
		let currentText = text;
		let currentImages = images;

		for (const ext of this.extensions) {
			for (const handler of ext.handlers.get("input") ?? []) {
				try {
					const event: InputEvent = {
						type: "input",
						text: currentText,
						images: currentImages,
						source,
						streamingBehavior,
					};
					const result = (await handler(event, ctx)) as InputEventResult | undefined;
					if (result?.action === "handled") return result;
					if (result?.action === "transform") {
						currentText = result.text;
						currentImages = result.images ?? currentImages;
					}
				} catch (err) {
					this.emitError({
						extensionPath: ext.path,
						event: "input",
						error: err instanceof Error ? err.message : String(err),
						stack: err instanceof Error ? err.stack : undefined,
					});
				}
			}
		}
		return currentText !== text || currentImages !== images
			? { action: "transform", text: currentText, images: currentImages }
			: { action: "continue" };
	}
}

/**
 * Interactive mode for the coding agent.
 * Handles TUI rendering and user interaction, delegating business logic to AgentSession.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AssistantMessage, ImageContent, Model } from "@pi-recon/repi-ai";
import type { AutocompleteProvider, EditorComponent, MarkdownTheme } from "@pi-recon/repi-tui";
import {
	type Component,
	Container,
	type Loader,
	type LoaderIndicatorOptions,
	ProcessTerminal,
	Spacer,
	setKeybindings,
	Text,
	TUI,
} from "@pi-recon/repi-tui";
import chalk from "chalk";
import { APP_NAME, APP_TITLE, IS_REPI_PRODUCT, VERSION } from "../../config.ts";
import type { AgentSession, AgentSessionEvent } from "../../core/agent-session.ts";
import type { AgentSessionRuntime } from "../../core/agent-session-runtime.ts";
import type {
	AutocompleteProviderFactory,
	EditorFactory,
	ExtensionRunner,
	ExtensionUIDialogOptions,
} from "../../core/extensions/index.ts";
import { FooterDataProvider } from "../../core/footer-data-provider.ts";
import { configureHttpDispatcher } from "../../core/http-dispatcher.ts";
import { type AppKeybinding, KeybindingsManager } from "../../core/keybindings.ts";
import {
	getEditorTheme,
	getMarkdownTheme,
	initTheme,
	onThemeChange,
	setRegisteredThemes,
	stopThemeWatcher,
	theme,
} from "../../core/presentation/theme-runtime.ts";
import type { MissingSessionCwdError } from "../../core/session-cwd.ts";
import type { SessionContext, SessionManager } from "../../core/session-manager.ts";
import { killTrackedDetachedChildren } from "../../utils/shell.ts";
import { checkForNewPiVersion, type LatestPiRelease } from "../../utils/version-check.ts";
import type { AssistantMessageComponent } from "./components/assistant-message.ts";
import type { BashExecutionComponent } from "./components/bash-execution.ts";
import type { CountdownTimer } from "./components/countdown-timer.ts";
import { CustomEditor } from "./components/custom-editor.ts";
import type { ExtensionEditorComponent } from "./components/extension-editor.ts";
import type { ExtensionInputComponent } from "./components/extension-input.ts";
import type { ExtensionSelectorComponent } from "./components/extension-selector.ts";
import { FooterComponent } from "./components/footer.ts";
import { formatKeyText, keyDisplayText, keyHint, keyText, rawKeyHint } from "./components/keybinding-hints.ts";
import type { ToolExecutionComponent } from "./components/tool-execution.ts";
import { getTmuxKeyboardWarning, persistClipboardImage, runExternalEditor } from "./external-process-runtime.ts";
import { type InteractiveAuthHost, showInteractiveAuthSelector } from "./interactive-auth-runtime.ts";
import { type InteractiveCommandHost, InteractiveCommandRuntime } from "./interactive-command-runtime.ts";
import {
	type CompactionQueuedMessage,
	type InteractiveCompactionHost,
	interactiveCompactionRuntime,
} from "./interactive-compaction-runtime.ts";
import {
	handleInteractiveEvent,
	type InteractiveEventHost,
	renderInteractiveInitialMessages,
	renderInteractiveSessionContext,
	showInteractiveStatus,
} from "./interactive-event-runtime.ts";
import { type InteractiveExtensionHost, interactiveExtensionRuntime } from "./interactive-extension-runtime.ts";
import {
	ExpandableText,
	type InteractiveResourceHost,
	InteractiveResourceRuntime,
	type ShowLoadedResourcesOptions,
} from "./interactive-resource-runtime.ts";
import {
	type InteractiveSelectorHost,
	InteractiveSelectorRuntime,
	type InteractiveSessionSwitchOptions,
} from "./interactive-selector-runtime.ts";
import { type InteractiveSubmitHost, installInteractiveSubmitHandler } from "./interactive-submit-runtime.ts";

export { isApiKeyLoginProvider } from "./interactive-auth-runtime.ts";

/** Interface for components that can be expanded/collapsed */
interface Expandable {
	setExpanded(expanded: boolean): void;
}

function isExpandable(obj: unknown): obj is Expandable {
	return typeof obj === "object" && obj !== null && "setExpanded" in obj && typeof obj.setExpanded === "function";
}

const DEAD_TERMINAL_ERROR_CODES = new Set(["EIO", "EPIPE", "ENOTCONN"]);

function isDeadTerminalError(error: unknown): boolean {
	if (!error || typeof error !== "object" || !("code" in error)) {
		return false;
	}
	const code = (error as NodeJS.ErrnoException).code;
	return code !== undefined && DEAD_TERMINAL_ERROR_CODES.has(code);
}

function quoteIfNeeded(value: string): string {
	if (value.length > 0 && !/[^a-zA-Z0-9_\-./~:@]/.test(value)) {
		return value;
	}
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function formatResumeCommand(sessionManager: SessionManager): string | undefined {
	if (!process.stdout.isTTY) return undefined;
	if (!sessionManager.isPersisted()) return undefined;

	const sessionFile = sessionManager.getSessionFile();
	if (!sessionFile || !fs.existsSync(sessionFile)) return undefined;

	const args = [APP_NAME];
	if (!sessionManager.usesDefaultSessionDir()) {
		args.push("--session-dir", quoteIfNeeded(sessionManager.getSessionDir()));
	}
	args.push("--session", sessionManager.getSessionId());
	return args.join(" ");
}

/**
 * Options for InteractiveMode initialization.
 */
export interface InteractiveModeOptions {
	/** Providers that were migrated to auth.json (shows warning) */
	migratedProviders?: string[];
	/** Warning message if session model couldn't be restored */
	modelFallbackMessage?: string;
	/** Initial message to send on startup (can include @file content) */
	initialMessage?: string;
	/** Images to attach to the initial message */
	initialImages?: ImageContent[];
	/** Additional messages to send after the initial message */
	initialMessages?: string[];
	/** Force verbose startup (overrides quietStartup setting) */
	verbose?: boolean;
}

export class InteractiveMode {
	private runtimeHost: AgentSessionRuntime;
	private ui: TUI;
	private chatContainer: Container;
	private pendingMessagesContainer: Container;
	private statusContainer: Container;
	private defaultEditor: CustomEditor;
	private editor: EditorComponent;
	/** Mutable bridge state consumed by the split interactive runtimes. */
	editorComponentFactory: EditorFactory | undefined;
	autocompleteProvider: AutocompleteProvider | undefined;
	autocompleteProviderWrappers: AutocompleteProviderFactory[] = [];
	private readonly resourceRuntime: InteractiveResourceRuntime;
	private editorContainer: Container;
	private footer: FooterComponent;
	private footerDataProvider: FooterDataProvider;
	// Stored so the same manager can be injected into custom editors, selectors, and extension UI.
	private keybindings: KeybindingsManager;
	private version: string;
	private isInitialized = false;
	onInputCallback?: (text: string) => void;
	private pendingUserInputs: string[] = [];
	private loadingAnimation: Loader | undefined = undefined;
	workingMessage: string | undefined = undefined;
	workingVisible = true;
	workingIndicatorOptions: LoaderIndicatorOptions | undefined = undefined;
	readonly defaultWorkingMessage = "Working...";
	private readonly defaultHiddenThinkingLabel = "Thinking...";
	hiddenThinkingLabel = this.defaultHiddenThinkingLabel;

	private lastSigintTime = 0;
	private lastEscapeTime = 0;
	anthropicSubscriptionWarningShown = false;

	// Status line tracking (for mutating immediately-sequential status updates)
	lastStatusSpacer: Spacer | undefined = undefined;
	lastStatusText: Text | undefined = undefined;

	// Streaming message tracking
	private streamingComponent: AssistantMessageComponent | undefined = undefined;
	private streamingMessage: AssistantMessage | undefined = undefined;

	// Tool execution tracking: toolCallId -> component
	private pendingTools = new Map<string, ToolExecutionComponent>();

	// Tool output expansion state
	private toolOutputExpanded = false;

	// Thinking block visibility state
	private hideThinkingBlock = false;

	// Agent subscription unsubscribe function
	private unsubscribe?: () => void;
	private signalCleanupHandlers: Array<() => void> = [];

	// Track if editor is in bash mode (text starts with !)
	private isBashMode = false;

	// Track current bash execution component
	private bashComponent: BashExecutionComponent | undefined = undefined;

	// Track pending bash components (shown in pending area, moved to chat on submit)
	private pendingBashComponents: BashExecutionComponent[] = [];

	// Auto-compaction state
	autoCompactionLoader: Loader | undefined = undefined;
	autoCompactionEscapeHandler?: () => void;

	// Auto-retry state
	retryLoader: Loader | undefined = undefined;
	retryCountdown: CountdownTimer | undefined = undefined;
	retryEscapeHandler?: () => void;

	// Messages queued while compaction is running
	compactionQueuedMessages: CompactionQueuedMessage[] = [];

	// Shutdown state
	private shutdownRequested = false;

	// Extension UI state
	extensionSelector: ExtensionSelectorComponent | undefined = undefined;
	extensionInput: ExtensionInputComponent | undefined = undefined;
	extensionEditor: ExtensionEditorComponent | undefined = undefined;
	extensionTerminalInputUnsubscribers = new Set<() => void>();

	// Extension widgets (components rendered above/below the editor)
	extensionWidgetsAbove = new Map<string, Component & { dispose?(): void }>();
	extensionWidgetsBelow = new Map<string, Component & { dispose?(): void }>();
	private widgetContainerAbove!: Container;
	private widgetContainerBelow!: Container;

	// Custom footer from extension (undefined = use built-in footer)
	customFooter: (Component & { dispose?(): void }) | undefined = undefined;

	// Header container that holds the built-in or custom header
	private headerContainer: Container;

	// Built-in header (logo + keybinding hints + changelog)
	private builtInHeader: Component | undefined = undefined;

	// Custom header from extension (undefined = use built-in header)
	private customHeader: (Component & { dispose?(): void }) | undefined = undefined;

	private options: InteractiveModeOptions;
	private readonly commandRuntime: InteractiveCommandRuntime;
	private readonly selectorRuntime: InteractiveSelectorRuntime;

	// Convenience accessors
	private get session(): AgentSession {
		return this.runtimeHost.session;
	}
	private get agent() {
		return this.session.agent;
	}
	private get sessionManager() {
		return this.session.sessionManager;
	}
	private get settingsManager() {
		return this.session.settingsManager;
	}

	constructor(runtimeHost: AgentSessionRuntime, options: InteractiveModeOptions = {}) {
		this.runtimeHost = runtimeHost;
		this.options = options;
		this.runtimeHost.setBeforeSessionInvalidate(() => {
			this.resetExtensionUI();
		});
		this.runtimeHost.setRebindSession(async () => {
			await this.rebindCurrentSession();
		});
		this.version = VERSION;
		this.ui = new TUI(new ProcessTerminal(), this.settingsManager.getShowHardwareCursor());
		this.ui.setClearOnShrink(this.settingsManager.getClearOnShrink());
		this.headerContainer = new Container();
		this.chatContainer = new Container();
		this.pendingMessagesContainer = new Container();
		this.statusContainer = new Container();
		this.widgetContainerAbove = new Container();
		this.widgetContainerBelow = new Container();
		this.keybindings = KeybindingsManager.create();
		setKeybindings(this.keybindings);
		const editorPaddingX = this.settingsManager.getEditorPaddingX();
		const autocompleteMaxVisible = this.settingsManager.getAutocompleteMaxVisible();
		this.defaultEditor = new CustomEditor(this.ui, getEditorTheme(), this.keybindings, {
			paddingX: editorPaddingX,
			autocompleteMaxVisible,
		});
		// opt #142: contain async/sync action-handler errors at the dispatch
		// boundary (no global unhandledRejection handler; uncaughtCrash only
		// handles uncaughtException). Route to showError so one bad key shows an
		// error line instead of crashing / killing the session.
		this.defaultEditor.onActionError = (err) => {
			this.showError(`Action handler error: ${err instanceof Error ? err.message : String(err)}`);
		};
		// opt #145: same containment for the Editor submit dispatch (Enter →
		// submitValue → onSubmit). onSubmit is a large async body with no
		// top-level try/catch; a rejecting submission path (expired auth,
		// command-handler throw) would otherwise become an unhandledRejection
		// crashing the host with the terminal in raw mode.
		this.defaultEditor.onSubmitError = (err) => {
			this.showError(`Submit handler error: ${err instanceof Error ? err.message : String(err)}`);
		};
		this.editor = this.defaultEditor;
		this.editorContainer = new Container();
		this.editorContainer.addChild(this.editor as Component);
		this.footerDataProvider = new FooterDataProvider(this.sessionManager.getCwd());
		this.footer = new FooterComponent(this.session, this.footerDataProvider);
		this.footer.setAutoCompactEnabled(this.session.autoCompactionEnabled);

		// Load hide thinking block setting
		this.hideThinkingBlock = this.settingsManager.getHideThinkingBlock();

		// Register themes from resource loader and initialize
		setRegisteredThemes(this.session.resourceLoader.getThemes().themes);
		initTheme(this.settingsManager.getTheme(), true);
		this.commandRuntime = new InteractiveCommandRuntime(this as unknown as InteractiveCommandHost);
		this.selectorRuntime = new InteractiveSelectorRuntime(this as unknown as InteractiveSelectorHost);
		this.resourceRuntime = new InteractiveResourceRuntime(this as unknown as InteractiveResourceHost);
	}

	async init(): Promise<void> {
		if (this.isInitialized) return;

		this.registerSignalHandlers();

		await this.resourceRuntime.initializeStartupResources();

		if (this.session.scopedModels.length > 0 && (this.options.verbose || !this.settingsManager.getQuietStartup())) {
			const modelList = this.session.scopedModels
				.map((sm) => {
					const thinkingStr = sm.thinkingLevel ? `:${sm.thinkingLevel}` : "";
					return `${sm.model.id}${thinkingStr}`;
				})
				.join(", ");
			const cycleKeys = this.keybindings.getKeys("app.model.cycleForward");
			const cycleHint =
				cycleKeys.length > 0
					? theme.fg("muted", ` (${formatKeyText(cycleKeys.join("/"), { capitalize: true })} to cycle)`)
					: "";
			console.log(theme.fg("dim", `Model scope: ${modelList}${cycleHint}`));
		}

		// Add header container as first child
		this.ui.addChild(this.headerContainer);

		// Add header with keybindings from config (unless silenced)
		if (this.options.verbose || !this.settingsManager.getQuietStartup()) {
			const logo = theme.bold(theme.fg("accent", APP_NAME)) + theme.fg("dim", ` v${this.version}`);

			// Build startup instructions using keybinding hint helpers
			const hint = (keybinding: AppKeybinding, description: string) => keyHint(keybinding, description);

			const expandedInstructions = [
				hint("app.interrupt", "to interrupt"),
				hint("app.clear", "to clear"),
				rawKeyHint(`${keyText("app.clear")} twice`, "to exit"),
				hint("app.exit", "to exit (empty)"),
				hint("app.suspend", "to suspend"),
				keyHint("tui.editor.deleteToLineEnd", "to delete to end"),
				hint("app.thinking.cycle", "to cycle thinking level"),
				rawKeyHint(`${keyText("app.model.cycleForward")}/${keyText("app.model.cycleBackward")}`, "to cycle models"),
				hint("app.model.select", "to select model"),
				hint("app.tools.expand", "to expand tools"),
				hint("app.thinking.toggle", "to expand thinking"),
				hint("app.editor.external", "for external editor"),
				rawKeyHint("/", "for commands"),
				rawKeyHint("!", "to run bash"),
				rawKeyHint("!!", "to run bash (no context)"),
				hint("app.message.followUp", "to queue follow-up"),
				hint("app.message.dequeue", "to edit all queued messages"),
				hint("app.clipboard.pasteImage", "to paste image"),
				rawKeyHint("drop files", "to attach"),
			].join("\n");
			const compactInstructions = [
				hint("app.interrupt", "interrupt"),
				rawKeyHint(`${keyText("app.clear")}/${keyText("app.exit")}`, "clear/exit"),
				rawKeyHint("/", "commands"),
				rawKeyHint("!", "bash"),
				hint("app.tools.expand", "more"),
			].join(theme.fg("muted", " · "));
			const compactOnboarding = theme.fg(
				"dim",
				`Press ${keyText("app.tools.expand")} to show full startup help and loaded resources.`,
			);
			const onboarding = theme.fg(
				"dim",
				`REPI can explain its reverse/pentest workflow, model configuration, tools, sessions, compact/resume, and extension system.`,
			);
			this.builtInHeader = new ExpandableText(
				() => `${logo}\n${compactInstructions}\n${compactOnboarding}\n\n${onboarding}`,
				() => `${logo}\n${expandedInstructions}\n\n${onboarding}`,
				this.getStartupExpansionState(),
				1,
				0,
			);

			// Setup UI layout
			this.headerContainer.addChild(new Spacer(1));
			this.headerContainer.addChild(this.builtInHeader);
			this.headerContainer.addChild(new Spacer(1));
		} else {
			// Minimal header when silenced
			this.builtInHeader = new Text("", 0, 0);
			this.headerContainer.addChild(this.builtInHeader);
		}

		this.ui.addChild(this.chatContainer);
		this.ui.addChild(this.pendingMessagesContainer);
		this.ui.addChild(this.statusContainer);
		this.renderWidgets(); // Initialize with default spacer
		this.ui.addChild(this.widgetContainerAbove);
		this.ui.addChild(this.editorContainer);
		this.ui.addChild(this.widgetContainerBelow);
		this.ui.addChild(this.footer);
		this.ui.setFocus(this.editor);

		this.setupKeyHandlers();
		this.setupEditorSubmitHandler();

		// Start the UI before initializing extensions so session_start handlers can use interactive dialogs
		this.ui.start();
		this.isInitialized = true;

		// Initialize extensions first so resources are shown before messages
		await this.rebindCurrentSession();

		// Render initial messages AFTER showing loaded resources
		this.renderInitialMessages();

		// Set up theme file watcher
		onThemeChange(() => {
			this.ui.invalidate();
			this.updateEditorBorderColor();
			this.ui.requestRender();
		});

		// Set up git branch watcher (uses provider instead of footer)
		this.footerDataProvider.onBranchChange(() => {
			this.ui.requestRender();
		});

		// Initialize available provider count for footer display
		await this.updateAvailableProviderCount();
	}

	/**
	 * Update terminal title with session name and cwd.
	 */
	private updateTerminalTitle(): void {
		const cwdBasename = path.basename(this.sessionManager.getCwd());
		const sessionName = this.sessionManager.getSessionName();
		if (sessionName) {
			this.ui.terminal.setTitle(`${APP_TITLE} - ${sessionName} - ${cwdBasename}`);
		} else {
			this.ui.terminal.setTitle(`${APP_TITLE} - ${cwdBasename}`);
		}
	}

	/**
	 * Run the interactive mode. This is the main entry point.
	 * Initializes the UI, shows warnings, processes initial messages, and starts the interactive loop.
	 */
	async run(): Promise<void> {
		await this.init();

		if (!IS_REPI_PRODUCT) {
			// Start upstream Pi version check asynchronously. repi is an independent product
			// and must not show pi.dev / pi update prompts.
			checkForNewPiVersion(this.version).then((newRelease) => {
				if (newRelease) {
					this.showNewVersionNotification(newRelease);
				}
			});

			// Start package update check asynchronously for upstream Pi only.
			this.resourceRuntime.checkForPackageUpdates().then((updates) => {
				if (updates.length > 0) {
					this.showPackageUpdateNotification(updates);
				}
			});
		}

		// Check tmux keyboard setup asynchronously
		getTmuxKeyboardWarning().then((warning) => {
			if (warning) {
				this.showWarning(warning);
			}
		});

		// Show startup warnings
		const { migratedProviders, modelFallbackMessage, initialMessage, initialImages, initialMessages } = this.options;

		if (migratedProviders && migratedProviders.length > 0) {
			this.showWarning(`Migrated credentials to auth.json: ${migratedProviders.join(", ")}`);
		}

		const modelsJsonError = this.session.modelRegistry.getError();
		if (modelsJsonError) {
			this.showError(`models.json error: ${modelsJsonError}`);
		}

		if (modelFallbackMessage) {
			this.showWarning(modelFallbackMessage);
		}

		void this.maybeWarnAboutAnthropicSubscriptionAuth();

		// Process initial messages
		if (initialMessage) {
			try {
				await this.session.prompt(initialMessage, { images: initialImages });
			} catch (error: unknown) {
				const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
				this.showError(errorMessage);
			}
		}

		if (initialMessages) {
			for (const message of initialMessages) {
				try {
					await this.session.prompt(message);
				} catch (error: unknown) {
					const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
					this.showError(errorMessage);
				}
			}
		}

		// Main interactive loop
		while (true) {
			const userInput = await this.getUserInput();
			try {
				await this.session.prompt(userInput);
			} catch (error: unknown) {
				const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
				this.showError(errorMessage);
			}
		}
	}

	getMarkdownThemeWithSettings(): MarkdownTheme {
		return {
			...getMarkdownTheme(),
			codeBlockIndent: this.settingsManager.getCodeBlockIndent(),
		};
	}

	private setupAutocompleteProvider(): void {
		this.resourceRuntime.setupAutocompleteProvider();
	}

	private showStartupNoticesIfNeeded(): void {
		this.resourceRuntime.showStartupNoticesIfNeeded();
	}

	private showLoadedResources(options?: ShowLoadedResourcesOptions): void {
		this.resourceRuntime.showLoadedResources(options);
	}

	private getStartupExpansionState(): boolean {
		return this.resourceRuntime.getStartupExpansionState();
	}

	// =========================================================================
	// Extension System
	// =========================================================================

	/**
	 * Initialize the extension system with TUI-based UI context.
	 */
	private async bindCurrentSessionExtensions(): Promise<void> {
		await interactiveExtensionRuntime.bindCurrentSessionExtensions(this as unknown as InteractiveExtensionHost);
	}

	private applyRuntimeSettings(): void {
		configureHttpDispatcher(this.settingsManager.getHttpIdleTimeoutMs());
		this.footer.setSession(this.session);
		this.footer.setAutoCompactEnabled(this.session.autoCompactionEnabled);
		this.footerDataProvider.setCwd(this.sessionManager.getCwd());
		this.hideThinkingBlock = this.settingsManager.getHideThinkingBlock();
		this.ui.setShowHardwareCursor(this.settingsManager.getShowHardwareCursor());
		this.ui.setClearOnShrink(this.settingsManager.getClearOnShrink());
		const editorPaddingX = this.settingsManager.getEditorPaddingX();
		const autocompleteMaxVisible = this.settingsManager.getAutocompleteMaxVisible();
		this.defaultEditor.setPaddingX(editorPaddingX);
		this.defaultEditor.setAutocompleteMaxVisible(autocompleteMaxVisible);
		if (this.editor !== this.defaultEditor) {
			this.editor.setPaddingX?.(editorPaddingX);
			this.editor.setAutocompleteMaxVisible?.(autocompleteMaxVisible);
		}
	}

	private async rebindCurrentSession(): Promise<void> {
		this.unsubscribe?.();
		this.unsubscribe = undefined;
		this.applyRuntimeSettings();
		await this.bindCurrentSessionExtensions();
		this.subscribeToAgent();
		await this.updateAvailableProviderCount();
		this.updateEditorBorderColor();
		this.updateTerminalTitle();
	}

	async handleFatalRuntimeError(prefix: string, error: unknown): Promise<never> {
		const message = error instanceof Error ? error.message : String(error);
		this.showError(`${prefix}: ${message}`);
		stopThemeWatcher();
		this.stop();
		process.exit(1);
	}

	/**
	 * Dispose every in-flight ToolExecutionComponent (clearing its render-state
	 * interval — the bash tool's 1s elapsed-display timer) then drop the
	 * pendingTools map. Use ONLY at discard sites where the components have
	 * already been detached from chatContainer (e.g. after chatContainer.clear()
	 * in renderCurrentSessionState / renderSessionContext). Without this, a
	 * session switch / rewind mid-tool-execution leaves the detached component's
	 * 1s interval firing invalidate()+requestRender() on a dead component for the
	 * rest of the session. Do NOT use at sites where the components remain visible
	 * in chatContainer (agent_start / message_end / agent_end) — dispose() clears
	 * the component's children and would blank a still-rendered tool.
	 */
	private clearPendingTools(): void {
		for (const component of this.pendingTools.values()) {
			try {
				component.dispose?.();
			} catch {
				// A failing teardown must not skip the remaining components.
			}
		}
		this.pendingTools.clear();
	}

	/**
	 * Dispose in-flight / deferred BashExecutionComponents and reset their state.
	 * Foundational opt #137: on session switch (renderCurrentSessionState) and
	 * compaction rebuild (renderSessionContext) the chatContainer is cleared but
	 * clear() does NOT dispose children, so a bash command still `"running"` kept
	 * its Loader's 80ms animation interval firing requestRender() on a detached
	 * component (same leak class as opt #47). AND pendingBashComponents was never
	 * reset, so a subsequent flushPendingBashComponents() in the new session would
	 * addChild() the PREVIOUS session's bash components → stale output rendered.
	 * Dispose each (stops the loader interval) and clear both references.
	 */
	private clearPendingBashComponents(): void {
		const components: BashExecutionComponent[] = [];
		if (this.bashComponent) components.push(this.bashComponent);
		components.push(...this.pendingBashComponents);
		for (const component of components) {
			try {
				component.dispose();
			} catch {
				// A failing teardown must not skip the remaining components.
			}
		}
		this.bashComponent = undefined;
		this.pendingBashComponents = [];
	}

	private teardownTransientUiState(): void {
		interactiveExtensionRuntime.teardownTransientUiState(this as unknown as InteractiveExtensionHost);
	}

	renderCurrentSessionState(): void {
		this.teardownTransientUiState();
		this.chatContainer.clear();
		this.pendingMessagesContainer.clear();
		this.compactionQueuedMessages = [];
		this.streamingComponent = undefined;
		this.streamingMessage = undefined;
		this.clearPendingTools();
		this.clearPendingBashComponents();
		this.renderInitialMessages();
	}

	/**
	 * Get a registered tool definition by name (for custom rendering).
	 */
	getRegisteredToolDefinition(toolName: string) {
		return this.session.getToolDefinition(toolName);
	}

	/**
	 * Set up keyboard shortcuts registered by extensions.
	 */
	private setupExtensionShortcuts(extensionRunner: ExtensionRunner): void {
		interactiveExtensionRuntime.setupExtensionShortcuts(this as unknown as InteractiveExtensionHost, extensionRunner);
	}

	private createWorkingLoader(): Loader {
		return interactiveExtensionRuntime.createWorkingLoader(this as unknown as InteractiveExtensionHost);
	}

	private stopWorkingLoader(): void {
		interactiveExtensionRuntime.stopWorkingLoader(this as unknown as InteractiveExtensionHost);
	}

	private resetExtensionUI(): void {
		interactiveExtensionRuntime.resetExtensionUI(this as unknown as InteractiveExtensionHost);
	}

	/**
	 * Render all extension widgets to the widget container.
	 */
	private renderWidgets(): void {
		interactiveExtensionRuntime.renderWidgets(this as unknown as InteractiveExtensionHost);
	}

	private clearExtensionTerminalInputListeners(): void {
		interactiveExtensionRuntime.clearExtensionTerminalInputListeners(this as unknown as InteractiveExtensionHost);
	}

	/**
	 * Show a selector for extensions.
	 */
	private showExtensionSelector(
		title: string,
		options: string[],
		opts?: ExtensionUIDialogOptions,
	): Promise<string | undefined> {
		return interactiveExtensionRuntime.showExtensionSelector(
			this as unknown as InteractiveExtensionHost,
			title,
			options,
			opts,
		);
	}

	/**
	 * Show a confirmation dialog for extensions.
	 */
	private async showExtensionConfirm(
		title: string,
		message: string,
		opts?: ExtensionUIDialogOptions,
	): Promise<boolean> {
		return interactiveExtensionRuntime.showExtensionConfirm(
			this as unknown as InteractiveExtensionHost,
			title,
			message,
			opts,
		);
	}

	private async promptForMissingSessionCwd(error: MissingSessionCwdError): Promise<string | undefined> {
		return interactiveExtensionRuntime.promptForMissingSessionCwd(this as unknown as InteractiveExtensionHost, error);
	}

	/**
	 * Show a multi-line editor for extensions (with Ctrl+G support).
	 */
	private showExtensionEditor(title: string, prefill?: string): Promise<string | undefined> {
		return interactiveExtensionRuntime.showExtensionEditor(
			this as unknown as InteractiveExtensionHost,
			title,
			prefill,
		);
	}

	// =========================================================================
	// Key Handlers
	// =========================================================================

	private setupKeyHandlers(): void {
		// Set up handlers on defaultEditor - they use this.editor for text access
		// so they work correctly regardless of which editor is active
		this.defaultEditor.onEscape = () => {
			if (this.session.isStreaming) {
				this.restoreQueuedMessagesToEditor({ abort: true });
			} else if (this.session.isBashRunning) {
				this.session.abortBash();
			} else if (this.isBashMode) {
				this.editor.setText("");
				this.isBashMode = false;
				this.updateEditorBorderColor();
			} else if (!this.editor.getText().trim()) {
				// Double-escape with empty editor triggers /tree, /fork, or nothing based on setting
				const action = this.settingsManager.getDoubleEscapeAction();
				if (action !== "none") {
					const now = Date.now();
					if (now - this.lastEscapeTime < 500) {
						if (action === "tree") {
							this.showTreeSelector();
						} else {
							this.showUserMessageSelector();
						}
						this.lastEscapeTime = 0;
					} else {
						this.lastEscapeTime = now;
					}
				}
			}
		};

		// Register app action handlers
		this.defaultEditor.onAction("app.clear", () => this.handleCtrlC());
		this.defaultEditor.onCtrlD = () => this.handleCtrlD();
		this.defaultEditor.onAction("app.suspend", () => this.handleCtrlZ());
		this.defaultEditor.onAction("app.thinking.cycle", () => this.cycleThinkingLevel());
		this.defaultEditor.onAction("app.model.cycleForward", () => this.cycleModel("forward"));
		this.defaultEditor.onAction("app.model.cycleBackward", () => this.cycleModel("backward"));

		// Global debug handler on TUI (works regardless of focus)
		this.ui.onDebug = () => this.handleDebugCommand();
		this.defaultEditor.onAction("app.model.select", () => this.showModelSelector());
		this.defaultEditor.onAction("app.tools.expand", () => this.toggleToolOutputExpansion());
		this.defaultEditor.onAction("app.thinking.toggle", () => this.toggleThinkingBlockVisibility());
		this.defaultEditor.onAction("app.editor.external", () => this.openExternalEditor());
		this.defaultEditor.onAction("app.message.followUp", () => this.handleFollowUp());
		this.defaultEditor.onAction("app.message.dequeue", () => this.handleDequeue());
		this.defaultEditor.onAction("app.session.new", () => this.handleClearCommand());
		this.defaultEditor.onAction("app.session.tree", () => this.showTreeSelector());
		this.defaultEditor.onAction("app.session.fork", () => this.showUserMessageSelector());
		this.defaultEditor.onAction("app.session.resume", () => this.showSessionSelector());

		this.defaultEditor.onChange = (text: string) => {
			const wasBashMode = this.isBashMode;
			this.isBashMode = text.trimStart().startsWith("!");
			if (wasBashMode !== this.isBashMode) {
				this.updateEditorBorderColor();
			}
		};

		// Handle clipboard image paste (triggered on Ctrl+V)
		this.defaultEditor.onPasteImage = () => {
			this.handleClipboardImagePaste();
		};
	}

	private async handleClipboardImagePaste(): Promise<void> {
		const filePath = await persistClipboardImage(this.session.sessionManager.getSessionId(), APP_NAME);
		if (!filePath) return;
		this.editor.insertTextAtCursor?.(filePath);
		this.ui.requestRender();
	}

	private setupEditorSubmitHandler(): void {
		installInteractiveSubmitHandler(this as unknown as InteractiveSubmitHost);
	}

	private subscribeToAgent(): void {
		this.unsubscribe = this.session.subscribe(async (event) => {
			await this.handleEvent(event);
		});
	}

	private async handleEvent(event: AgentSessionEvent): Promise<void> {
		await handleInteractiveEvent(this as unknown as InteractiveEventHost, event);
	}

	private showStatus(message: string): void {
		showInteractiveStatus(this as unknown as InteractiveEventHost, message);
	}

	private renderSessionContext(
		sessionContext: SessionContext,
		options: { updateFooter?: boolean; populateHistory?: boolean } = {},
	): void {
		renderInteractiveSessionContext(this as unknown as InteractiveEventHost, sessionContext, options);
	}

	renderInitialMessages(): void {
		renderInteractiveInitialMessages(this as unknown as InteractiveEventHost);
	}

	async getUserInput(): Promise<string> {
		const queuedInput = this.pendingUserInputs.shift();
		if (queuedInput !== undefined) {
			return queuedInput;
		}

		return new Promise((resolve) => {
			this.onInputCallback = (text: string) => {
				this.onInputCallback = undefined;
				resolve(text);
			};
		});
	}

	private rebuildChatFromMessages(): void {
		this.chatContainer.clear();
		const context = this.sessionManager.buildSessionContext();
		this.renderSessionContext(context);
	}

	// =========================================================================
	// Key handlers
	// =========================================================================

	private handleCtrlC(): void {
		const now = Date.now();
		if (now - this.lastSigintTime < 500) {
			void this.shutdown();
		} else {
			this.clearEditor();
			this.lastSigintTime = now;
		}
	}

	private handleCtrlD(): void {
		// Only called when editor is empty (enforced by CustomEditor)
		void this.shutdown();
	}

	/**
	 * Gracefully shutdown the agent.
	 * Stops the TUI before emitting shutdown events so extension UI cleanup cannot
	 * repaint the final frame while the process is exiting.
	 */
	private isShuttingDown = false;

	private async shutdown(options?: { fromSignal?: boolean }): Promise<void> {
		if (this.isShuttingDown) return;
		this.isShuttingDown = true;
		this.unregisterSignalHandlers();

		if (options?.fromSignal) {
			// Signal-triggered shutdown (SIGTERM/SIGHUP). Emit extension cleanup
			// (session_shutdown) BEFORE touching the terminal. Extension teardown
			// such as removing sockets does not write to the tty, so it must not be
			// skipped if a later terminal-restore write fails on a dead or stalled
			// terminal. If the terminal is gone, the restore writes below emit EIO,
			// which the stdout/stderr error handler turns into emergencyTerminalExit;
			// the render loop is already idle, so this cannot hot-spin (see #4144).
			// Foundational opt #136: guard the dispose await — shutdown() is reached
			// via fire-and-forget `void this.shutdown()` at several call sites, and
			// there is no global unhandledRejection handler. A throwing extension
			// session_shutdown teardown would reject here → unhandledRejection →
			// crash BEFORE this.stop() restores the terminal (leaving it in raw mode
			// with no cursor). Contain it: log + proceed to terminal restore + exit.
			try {
				await this.runtimeHost.dispose();
			} catch (err) {
				console.error("Extension dispose error during shutdown:", err);
			}
			await this.ui.terminal.drainInput(1000);
			this.stop();
			process.exit(0);
		}

		// Interactive quit (Ctrl+D, Ctrl+C, /quit, extension shutdown()). Stop the
		// TUI before emitting shutdown events so extension UI cleanup cannot repaint
		// the final frame while the process is exiting.
		// Drain any in-flight Kitty key release events before stopping.
		// This prevents escape sequences from leaking to the parent shell over slow SSH.
		await this.ui.terminal.drainInput(1000);

		this.stop();
		// opt #136: guard dispose — see the fromSignal branch above. A throwing
		// extension teardown must not crash (unhandledRejection, no global handler)
		// before the process exits; the terminal is already restored by this.stop().
		try {
			await this.runtimeHost.dispose();
		} catch (err) {
			console.error("Extension dispose error during shutdown:", err);
		}

		const resumeCommand = formatResumeCommand(this.sessionManager);
		if (resumeCommand) {
			process.stdout.write(`${chalk.dim("To resume this session:")} ${resumeCommand}\n`);
		}

		process.exit(0);
	}

	private emergencyTerminalExit(): never {
		this.isShuttingDown = true;
		this.unregisterSignalHandlers();
		killTrackedDetachedChildren();
		// The terminal is gone. Do not run normal shutdown because TUI and
		// extension cleanup can write restore sequences and re-trigger EIO.
		process.exit(129);
	}

	/**
	 * Last-resort handler for uncaught exceptions. The TUI puts stdin into raw
	 * mode and hides the cursor; without this handler, an uncaught throw from
	 * anywhere (e.g. an extension's async `ChildProcess.on("exit")` callback)
	 * tears down the process while leaving the terminal in raw mode with no
	 * cursor, requiring `stty sane && reset` to recover.
	 *
	 * Unlike emergencyTerminalExit, the terminal is still alive here, so we
	 * call ui.stop() to restore cooked mode, the cursor, and disable bracketed
	 * paste / Kitty / modifyOtherKeys sequences.
	 */
	private uncaughtCrash(error: Error): never {
		if (this.isShuttingDown) {
			process.exit(1);
		}
		this.isShuttingDown = true;
		try {
			this.unregisterSignalHandlers();
		} catch {}
		try {
			killTrackedDetachedChildren();
		} catch {}
		try {
			this.ui.stop();
		} catch {}
		console.error(`${APP_NAME} exiting due to uncaughtException:`);
		console.error(error);
		process.exit(1);
	}

	/**
	 * Check if shutdown was requested and perform shutdown if so.
	 */
	async checkShutdownRequested(): Promise<void> {
		if (!this.shutdownRequested) return;
		await this.shutdown();
	}

	private registerSignalHandlers(): void {
		this.unregisterSignalHandlers();

		const signals: NodeJS.Signals[] = ["SIGTERM"];
		if (process.platform !== "win32") {
			signals.push("SIGHUP");
		}

		for (const signal of signals) {
			const handler = () => {
				// SIGHUP no longer hard-exits: graceful shutdown emits session_shutdown
				// first, then attempts terminal restore. A genuinely dead terminal
				// surfaces as an EIO on the restore writes, which the stdout/stderr
				// error handler converts into emergencyTerminalExit (see #4144, #5080).
				killTrackedDetachedChildren();
				void this.shutdown({ fromSignal: true });
			};
			process.prependListener(signal, handler);
			this.signalCleanupHandlers.push(() => process.off(signal, handler));
		}

		const terminalErrorHandler = (error: Error) => {
			if (isDeadTerminalError(error)) {
				this.emergencyTerminalExit();
			}
			throw error;
		};
		process.stdout.on("error", terminalErrorHandler);
		process.stderr.on("error", terminalErrorHandler);
		this.signalCleanupHandlers.push(() => process.stdout.off("error", terminalErrorHandler));
		this.signalCleanupHandlers.push(() => process.stderr.off("error", terminalErrorHandler));

		// Restore the terminal before the process dies on any uncaught throw.
		// Without this, an unhandled exception from extension code (or anywhere
		// in pi) leaves the terminal in raw mode with no cursor.
		const uncaughtExceptionHandler = (error: Error) => this.uncaughtCrash(error);
		process.prependListener("uncaughtException", uncaughtExceptionHandler);
		this.signalCleanupHandlers.push(() => process.off("uncaughtException", uncaughtExceptionHandler));

		// Foundational opt #268: route unhandled REJECTIONS to the same crash
		// recovery as uncaught exceptions. registerSignalHandlers runs early in
		// init() (before ui.start + rebindCurrentSession), so an uncaughtException
		// during init is recovered — but an awaited rejection (e.g. an extension's
		// session_start handler rejecting in bindCurrentSessionExtensions) is NOT a
		// sync throw: it propagates as a rejected promise up run()→main(), and
		// main(cliArgs) has no .catch() (cli.ts) → it becomes an unhandledRejection.
		// There is NO global unhandledRejection handler (the repo relies on per-site
		// catches; many comments note this gap), so Node's default fires exit(1)
		// WITHOUT calling uncaughtCrash → the terminal is left in raw mode with no
		// cursor (ui.stop never runs), requiring `stty sane && reset` to recover.
		// Mirror the uncaughtException handler so rejections also restore the TUI.
		const unhandledRejectionHandler = (reason: unknown) => {
			this.uncaughtCrash(reason instanceof Error ? reason : new Error(String(reason)));
		};
		process.prependListener("unhandledRejection", unhandledRejectionHandler);
		this.signalCleanupHandlers.push(() => process.off("unhandledRejection", unhandledRejectionHandler));
	}

	private unregisterSignalHandlers(): void {
		for (const cleanup of this.signalCleanupHandlers) {
			cleanup();
		}
		this.signalCleanupHandlers = [];
	}

	private handleCtrlZ(): void {
		if (process.platform === "win32") {
			this.showStatus("Suspend to background is not supported on Windows");
			return;
		}

		// Keep the event loop alive while suspended. Without this, stopping the TUI
		// can leave Node with no ref'ed handles, causing the process to exit on fg
		// before the SIGCONT handler gets a chance to restore the terminal.
		const suspendKeepAlive = setInterval(() => {}, 2 ** 30);

		// Ignore SIGINT while suspended so Ctrl+C in the terminal does not
		// kill the backgrounded process. The handler is removed on resume.
		const ignoreSigint = () => {};
		process.on("SIGINT", ignoreSigint);

		// Set up handler to restore TUI when resumed
		process.once("SIGCONT", () => {
			clearInterval(suspendKeepAlive);
			process.removeListener("SIGINT", ignoreSigint);
			this.ui.start();
			this.ui.requestRender(true);
		});

		try {
			// Stop the TUI (restore terminal to normal mode)
			this.ui.stop();

			// Send SIGTSTP to process group (pid=0 means all processes in group)
			process.kill(0, "SIGTSTP");
		} catch (error) {
			clearInterval(suspendKeepAlive);
			process.removeListener("SIGINT", ignoreSigint);
			throw error;
		}
	}

	private async handleFollowUp(): Promise<void> {
		await interactiveCompactionRuntime.handleFollowUp(this as unknown as InteractiveCompactionHost);
	}

	private handleDequeue(): void {
		interactiveCompactionRuntime.handleDequeue(this as unknown as InteractiveCompactionHost);
	}

	private updateEditorBorderColor(): void {
		if (this.isBashMode) {
			this.editor.borderColor = theme.getBashModeBorderColor();
		} else {
			const level = this.session.thinkingLevel || "off";
			this.editor.borderColor = theme.getThinkingBorderColor(level);
		}
		this.ui.requestRender();
	}

	private cycleThinkingLevel(): void {
		const newLevel = this.session.cycleThinkingLevel();
		if (newLevel === undefined) {
			this.showStatus("Current model does not support thinking");
		} else {
			this.footer.invalidate();
			this.updateEditorBorderColor();
			this.showStatus(`Thinking level: ${newLevel}`);
		}
	}

	private async cycleModel(direction: "forward" | "backward"): Promise<void> {
		try {
			const result = await this.session.cycleModel(direction);
			if (result === undefined) {
				const msg = this.session.scopedModels.length > 0 ? "Only one model in scope" : "Only one model available";
				this.showStatus(msg);
			} else {
				this.footer.invalidate();
				this.updateEditorBorderColor();
				const thinkingStr =
					result.model.reasoning && result.thinkingLevel !== "off" ? ` (thinking: ${result.thinkingLevel})` : "";
				this.showStatus(`Switched to ${result.model.name || result.model.id}${thinkingStr}`);
				void this.maybeWarnAboutAnthropicSubscriptionAuth(result.model);
			}
		} catch (error) {
			this.showError(error instanceof Error ? error.message : String(error));
		}
	}

	private toggleToolOutputExpansion(): void {
		this.setToolsExpanded(!this.toolOutputExpanded);
	}

	private setToolsExpanded(expanded: boolean): void {
		this.toolOutputExpanded = expanded;
		const activeHeader = this.customHeader ?? this.builtInHeader;
		if (isExpandable(activeHeader)) {
			activeHeader.setExpanded(expanded);
		}
		for (const child of this.chatContainer.children) {
			if (isExpandable(child)) {
				child.setExpanded(expanded);
			}
		}
		this.ui.requestRender();
	}

	private toggleThinkingBlockVisibility(): void {
		this.hideThinkingBlock = !this.hideThinkingBlock;
		this.settingsManager.setHideThinkingBlock(this.hideThinkingBlock);

		// Rebuild chat from session messages
		this.chatContainer.clear();
		this.rebuildChatFromMessages();

		// If streaming, re-add the streaming component with updated visibility and re-render
		if (this.streamingComponent && this.streamingMessage) {
			this.streamingComponent.setHideThinkingBlock(this.hideThinkingBlock);
			this.streamingComponent.updateContent(this.streamingMessage);
			this.chatContainer.addChild(this.streamingComponent);
		}

		this.showStatus(`Thinking blocks: ${this.hideThinkingBlock ? "hidden" : "visible"}`);
	}

	private async openExternalEditor(): Promise<void> {
		const result = await runExternalEditor({
			text: this.editor.getExpandedText?.() ?? this.editor.getText(),
			appName: APP_NAME,
			stopTerminal: () => this.ui.stop(),
			startTerminal: () => this.ui.start(),
			requestRender: (full) => this.ui.requestRender(full),
		});
		if (result.status === "no-editor" || result.status === "timed-out") {
			this.showWarning(result.warning);
		} else if (result.status === "updated") {
			this.editor.setText(result.text);
		}
	}

	// =========================================================================
	// UI helpers
	// =========================================================================

	clearEditor(): void {
		this.editor.setText("");
		this.ui.requestRender();
	}

	showError(errorMessage: string): void {
		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(new Text(theme.fg("error", `Error: ${errorMessage}`), 1, 0));
		this.chatContainer.addChild(new Spacer(1));
		this.ui.requestRender();
	}

	showWarning(warningMessage: string): void {
		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(new Text(theme.fg("warning", `Warning: ${warningMessage}`), 1, 0));
		this.ui.requestRender();
	}

	showNewVersionNotification(release: LatestPiRelease): void {
		this.resourceRuntime.showNewVersionNotification(release);
	}

	showPackageUpdateNotification(packages: string[]): void {
		this.resourceRuntime.showPackageUpdateNotification(packages);
	}

	private updatePendingMessagesDisplay(): void {
		interactiveCompactionRuntime.updatePendingMessagesDisplay(this as unknown as InteractiveCompactionHost);
	}

	private restoreQueuedMessagesToEditor(options?: { abort?: boolean; currentText?: string }): number {
		return interactiveCompactionRuntime.restoreQueuedMessagesToEditor(
			this as unknown as InteractiveCompactionHost,
			options,
		);
	}

	private queueCompactionMessage(text: string, mode: "steer" | "followUp"): void {
		interactiveCompactionRuntime.queueCompactionMessage(this as unknown as InteractiveCompactionHost, text, mode);
	}

	private isExtensionCommand(text: string): boolean {
		return interactiveCompactionRuntime.isExtensionCommand(this as unknown as InteractiveCompactionHost, text);
	}

	private async flushCompactionQueue(options?: { willRetry?: boolean }): Promise<void> {
		await interactiveCompactionRuntime.flushCompactionQueue(this as unknown as InteractiveCompactionHost, options);
	}

	/** Move pending bash components from pending area to chat */
	private flushPendingBashComponents(): void {
		interactiveCompactionRuntime.flushPendingBashComponents(this as unknown as InteractiveCompactionHost);
	}

	// Selector entrypoints stay on the mode because editor actions and extension
	// hosts bind to this object, while the workflows live in one owned runtime.
	private showSelector(create: (done: () => void) => { component: Component; focus: Component }): void {
		this.selectorRuntime.showSelector(create);
	}

	private showSettingsSelector(): void {
		this.selectorRuntime.showSettingsSelector();
	}

	private handleModelCommand(searchTerm?: string): Promise<void> {
		return this.selectorRuntime.handleModelCommand(searchTerm);
	}

	private updateAvailableProviderCount(): Promise<void> {
		return this.selectorRuntime.updateAvailableProviderCount();
	}

	private maybeWarnAboutAnthropicSubscriptionAuth(model?: Model<any>): Promise<void> {
		return this.selectorRuntime.maybeWarnAboutAnthropicSubscriptionAuth(model);
	}

	private showTrustSelector(): void {
		this.selectorRuntime.showTrustSelector();
	}

	private showModelSelector(initialSearchInput?: string): void {
		this.selectorRuntime.showModelSelector(initialSearchInput);
	}

	private showModelsSelector(): Promise<void> {
		return this.selectorRuntime.showModelsSelector();
	}

	private showUserMessageSelector(): void {
		this.selectorRuntime.showUserMessageSelector();
	}

	private handleCloneCommand(): Promise<void> {
		return this.selectorRuntime.handleCloneCommand();
	}

	private showTreeSelector(initialSelectedId?: string): void {
		this.selectorRuntime.showTreeSelector(initialSelectedId);
	}

	private showSessionSelector(): void {
		this.selectorRuntime.showSessionSelector();
	}

	private handleResumeSession(
		sessionPath: string,
		options?: InteractiveSessionSwitchOptions,
	): Promise<{ cancelled: boolean }> {
		return this.selectorRuntime.handleResumeSession(sessionPath, options);
	}

	async showOAuthSelector(mode: "login" | "logout"): Promise<void> {
		await showInteractiveAuthSelector(this as unknown as InteractiveAuthHost, mode);
	}

	// =========================================================================
	// Command handlers
	// =========================================================================

	private async handleReloadCommand(): Promise<void> {
		await this.commandRuntime.handleReloadCommand();
	}

	private async handleExportCommand(text: string): Promise<void> {
		await this.commandRuntime.handleExportCommand(text);
	}

	private async handleImportCommand(text: string): Promise<void> {
		await this.commandRuntime.handleImportCommand(text);
	}

	private async handleShareCommand(): Promise<void> {
		await this.commandRuntime.handleShareCommand();
	}

	private async handleCopyCommand(): Promise<void> {
		await this.commandRuntime.handleCopyCommand();
	}

	private handleNameCommand(text: string): void {
		this.commandRuntime.handleNameCommand(text);
	}

	private handleSessionCommand(): void {
		this.commandRuntime.handleSessionCommand();
	}

	private handleContextCommand(): void {
		this.commandRuntime.handleContextCommand();
	}

	private handleAgentsCommand(): void {
		this.commandRuntime.handleAgentsCommand();
	}

	private handleAgentCommand(text: string): void {
		this.commandRuntime.handleAgentCommand(text);
	}

	private async handleSpawnCommand(text: string): Promise<void> {
		await this.commandRuntime.handleSpawnCommand(text);
	}

	private handleMergeCommand(text: string): void {
		this.commandRuntime.handleMergeCommand(text);
	}

	private async handleMcpCommand(text: string): Promise<void> {
		await this.commandRuntime.handleMcpCommand(text);
	}

	private handleChangelogCommand(): void {
		this.commandRuntime.handleChangelogCommand();
	}

	/**
	 * Get capitalized display string for an app keybinding action.
	 */
	getAppKeyDisplay(action: AppKeybinding): string {
		return keyDisplayText(action);
	}

	private handleHotkeysCommand(): void {
		this.commandRuntime.handleHotkeysCommand();
	}

	private async handleClearCommand(): Promise<void> {
		await this.commandRuntime.handleClearCommand();
	}

	private handleDebugCommand(): void {
		this.commandRuntime.handleDebugCommand();
	}

	private handleArminSaysHi(): void {
		this.commandRuntime.handleArminSaysHi();
	}

	private handleDementedDelves(): void {
		this.commandRuntime.handleDementedDelves();
	}

	private async handleBashCommand(command: string, excludeFromContext = false): Promise<void> {
		await this.commandRuntime.handleBashCommand(command, excludeFromContext);
	}

	private async handleCompactCommand(customInstructions?: string): Promise<void> {
		await this.commandRuntime.handleCompactCommand(customInstructions);
	}

	stop(): void {
		this.unregisterSignalHandlers();
		if (this.settingsManager.getShowTerminalProgress()) {
			this.ui.terminal.setProgress(false);
		}
		if (this.loadingAnimation) {
			this.loadingAnimation.stop();
			this.loadingAnimation = undefined;
		}
		this.clearExtensionTerminalInputListeners();
		this.footer.dispose();
		this.footerDataProvider.dispose();
		if (this.unsubscribe) {
			this.unsubscribe();
		}
		if (this.isInitialized) {
			this.ui.stop();
			this.isInitialized = false;
		}
	}
}

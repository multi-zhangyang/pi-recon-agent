import type {
	AutocompleteProvider,
	Component,
	EditorComponent,
	KeyId,
	LoaderIndicatorOptions,
	OverlayHandle,
	OverlayOptions,
	TUI,
} from "@pi-recon/repi-tui";
import { Container, Loader, matchesKey, Spacer, Text } from "@pi-recon/repi-tui";
import type { AgentSession } from "../../core/agent-session.ts";
import type { AgentSessionRuntime } from "../../core/agent-session-runtime.ts";
import type {
	AutocompleteProviderFactory,
	EditorFactory,
	ExtensionCommandContext,
	ExtensionContext,
	ExtensionRunner,
	ExtensionUIContext,
	ExtensionUIDialogOptions,
	ExtensionWidgetOptions,
} from "../../core/extensions/index.ts";
import type { FooterDataProvider, ReadonlyFooterDataProvider } from "../../core/footer-data-provider.ts";
import type { KeybindingsManager } from "../../core/keybindings.ts";
import {
	getAvailableThemesWithPaths,
	getEditorTheme,
	getThemeByName,
	setRegisteredThemes,
	setTheme,
	setThemeInstance,
	type Theme,
	theme,
} from "../../core/presentation/theme-runtime.ts";
import { formatMissingSessionCwdPrompt, type MissingSessionCwdError } from "../../core/session-cwd.ts";
import type { SessionManager } from "../../core/session-manager.ts";
import type { SettingsManager } from "../../core/settings-manager.ts";
import { AssistantMessageComponent } from "./components/assistant-message.ts";
import type { CountdownTimer } from "./components/countdown-timer.ts";
import type { CustomEditor } from "./components/custom-editor.ts";
import { ExtensionEditorComponent } from "./components/extension-editor.ts";
import { ExtensionInputComponent } from "./components/extension-input.ts";
import { ExtensionSelectorComponent } from "./components/extension-selector.ts";
import type { FooterComponent } from "./components/footer.ts";
import { keyText } from "./components/keybinding-hints.ts";

type DisposableComponent = Component & { dispose?(): void };
type SessionSwitchOptions = Parameters<ExtensionCommandContext["switchSession"]>[1];

export type InteractiveExtensionHost = {
	runtimeHost: AgentSessionRuntime;
	ui: TUI;
	chatContainer: Container;
	statusContainer: Container;
	editorContainer: Container;
	widgetContainerAbove: Container;
	widgetContainerBelow: Container;
	headerContainer: Container;
	defaultEditor: CustomEditor;
	editor: EditorComponent;
	editorComponentFactory?: EditorFactory;
	autocompleteProvider?: AutocompleteProvider;
	autocompleteProviderWrappers: AutocompleteProviderFactory[];
	footer: FooterComponent;
	footerDataProvider: FooterDataProvider;
	keybindings: KeybindingsManager;
	session: AgentSession;
	sessionManager: SessionManager;
	settingsManager: SettingsManager;
	loadingAnimation?: Loader;
	workingMessage?: string;
	workingVisible: boolean;
	workingIndicatorOptions?: LoaderIndicatorOptions;
	defaultWorkingMessage: string;
	defaultHiddenThinkingLabel: string;
	hiddenThinkingLabel: string;
	streamingComponent?: AssistantMessageComponent;
	autoCompactionLoader?: Loader;
	autoCompactionEscapeHandler?: () => void;
	retryLoader?: Loader;
	retryCountdown?: CountdownTimer;
	retryEscapeHandler?: () => void;
	shutdownRequested: boolean;
	extensionSelector?: ExtensionSelectorComponent;
	extensionInput?: ExtensionInputComponent;
	extensionEditor?: ExtensionEditorComponent;
	extensionTerminalInputUnsubscribers: Set<() => void>;
	extensionWidgetsAbove: Map<string, DisposableComponent>;
	extensionWidgetsBelow: Map<string, DisposableComponent>;
	customFooter?: DisposableComponent;
	builtInHeader?: Component;
	customHeader?: DisposableComponent;
	toolOutputExpanded: boolean;
	restoreQueuedMessagesToEditor(options?: { abort?: boolean; currentText?: string }): number;
	renderCurrentSessionState(): void;
	renderInitialMessages(): void;
	flushCompactionQueue(options?: { willRetry?: boolean }): Promise<void>;
	handleResumeSession(sessionPath: string, options?: SessionSwitchOptions): Promise<{ cancelled: boolean }>;
	handleReloadCommand(): Promise<void>;
	handleFatalRuntimeError(prefix: string, error: unknown): Promise<never>;
	shutdown(options?: { fromSignal?: boolean }): Promise<void>;
	setupAutocompleteProvider(): void;
	showLoadedResources(options?: { force?: boolean; showDiagnosticsWhenQuiet?: boolean }): void;
	showStartupNoticesIfNeeded(): void;
	updateTerminalTitle(): void;
	toggleToolOutputExpansion(): void;
	setToolsExpanded(expanded: boolean): void;
	showStatus(message: string): void;
	showWarning(message: string): void;
	showError(message: string): void;
};

const MAX_WIDGET_LINES = 10;

function isExpandable(component: unknown): component is { setExpanded(expanded: boolean): void } {
	return (
		typeof component === "object" &&
		component !== null &&
		"setExpanded" in component &&
		typeof component.setExpanded === "function"
	);
}

async function bindCurrentSessionExtensions(host: InteractiveExtensionHost): Promise<void> {
	const uiContext = createExtensionUIContext(host);
	await host.session.bindExtensions({
		uiContext,
		mode: "tui",
		abortHandler: () => {
			host.restoreQueuedMessagesToEditor({ abort: true });
		},
		commandContextActions: {
			waitForIdle: () => host.session.waitForIdle(),
			newSession: async (options) => {
				if (host.loadingAnimation) {
					host.loadingAnimation.stop();
					host.loadingAnimation = undefined;
				}
				host.statusContainer.clear();
				try {
					const result = await host.runtimeHost.newSession(options);
					if (!result.cancelled) {
						host.renderCurrentSessionState();
						host.ui.requestRender();
					}
					return result;
				} catch (error: unknown) {
					return host.handleFatalRuntimeError("Failed to create session", error);
				}
			},
			fork: async (entryId, options) => {
				try {
					const result = await host.runtimeHost.fork(entryId, options);
					if (!result.cancelled) {
						host.renderCurrentSessionState();
						host.editor.setText(result.selectedText ?? "");
						host.showStatus("Forked to new session");
					}
					return { cancelled: result.cancelled };
				} catch (error: unknown) {
					return host.handleFatalRuntimeError("Failed to fork session", error);
				}
			},
			navigateTree: async (targetId, options) => {
				const result = await host.session.navigateTree(targetId, {
					summarize: options?.summarize,
					customInstructions: options?.customInstructions,
					replaceInstructions: options?.replaceInstructions,
					label: options?.label,
				});
				if (result.cancelled) {
					return { cancelled: true };
				}

				host.chatContainer.clear();
				host.renderInitialMessages();
				if (result.editorText && !host.editor.getText().trim()) {
					host.editor.setText(result.editorText);
				}
				host.showStatus("Navigated to selected point");
				void host.flushCompactionQueue({ willRetry: false });
				return { cancelled: false };
			},
			switchSession: async (sessionPath, options) => host.handleResumeSession(sessionPath, options),
			reload: async () => {
				await host.handleReloadCommand();
			},
		},
		shutdownHandler: () => {
			host.shutdownRequested = true;
			if (host.session.isIdle) {
				void host.shutdown();
			}
		},
		onError: (error) => {
			showExtensionError(host, error.extensionPath, error.error, error.stack);
		},
	});

	setRegisteredThemes(host.session.resourceLoader.getThemes().themes);
	host.setupAutocompleteProvider();

	setupExtensionShortcuts(host, host.session.extensionRunner);
	host.showLoadedResources({ force: false, showDiagnosticsWhenQuiet: true });
	host.showStartupNoticesIfNeeded();
}

function teardownTransientUiState(host: InteractiveExtensionHost): void {
	// Restore retry first, then compaction so the original normal handler wins.
	if (host.retryEscapeHandler) {
		host.defaultEditor.onEscape = host.retryEscapeHandler;
		host.retryEscapeHandler = undefined;
	}
	if (host.autoCompactionEscapeHandler) {
		host.defaultEditor.onEscape = host.autoCompactionEscapeHandler;
		host.autoCompactionEscapeHandler = undefined;
	}
	if (host.retryCountdown) {
		try {
			host.retryCountdown.dispose();
		} catch {
			// Best-effort: a failing dispose must not abort the switch.
		}
		host.retryCountdown = undefined;
	}
	if (host.retryLoader) {
		try {
			host.retryLoader.stop();
		} catch {
			// Best-effort.
		}
		host.retryLoader = undefined;
	}
	if (host.autoCompactionLoader) {
		try {
			host.autoCompactionLoader.stop();
		} catch {
			// Best-effort.
		}
		host.autoCompactionLoader = undefined;
	}
	host.statusContainer.clear();
}

function setupExtensionShortcuts(host: InteractiveExtensionHost, extensionRunner: ExtensionRunner): void {
	const shortcuts = extensionRunner.getShortcuts(host.keybindings.getEffectiveConfig());
	if (shortcuts.size === 0) return;

	const createContext = (): ExtensionContext => ({
		ui: createExtensionUIContext(host),
		mode: "tui",
		hasUI: true,
		cwd: host.sessionManager.getCwd(),
		sessionManager: host.sessionManager,
		modelRegistry: host.session.modelRegistry,
		model: host.session.model,
		isIdle: () => host.session.isIdle,
		signal: host.session.agent.signal,
		abort: () => {
			host.restoreQueuedMessagesToEditor({ abort: true });
		},
		hasPendingMessages: () => host.session.pendingMessageCount > 0,
		shutdown: () => {
			host.shutdownRequested = true;
		},
		getContextUsage: () => host.session.getContextUsage(),
		compact: (options) => {
			void (async () => {
				try {
					const result = await host.session.compact(options?.customInstructions);
					options?.onComplete?.(result);
				} catch (error) {
					const err = error instanceof Error ? error : new Error(String(error));
					options?.onError?.(err);
				}
			})();
		},
		getSystemPrompt: () => host.session.systemPrompt,
	});

	host.defaultEditor.onExtensionShortcut = (data: string) => {
		for (const [shortcutStr, shortcut] of shortcuts) {
			if (matchesKey(data, shortcutStr as KeyId)) {
				Promise.resolve(shortcut.handler(createContext())).catch((err) => {
					host.showError(`Shortcut handler error: ${err instanceof Error ? err.message : String(err)}`);
				});
				return true;
			}
		}
		return false;
	};
}

function setExtensionStatus(host: InteractiveExtensionHost, key: string, text: string | undefined): void {
	host.footerDataProvider.setExtensionStatus(key, text);
	host.ui.requestRender();
}

function getWorkingLoaderMessage(host: InteractiveExtensionHost): string {
	return host.workingMessage ?? host.defaultWorkingMessage;
}

function createWorkingLoader(host: InteractiveExtensionHost): Loader {
	return new Loader(
		host.ui,
		(spinner) => theme.fg("accent", spinner),
		(text) => theme.fg("muted", text),
		getWorkingLoaderMessage(host),
		host.workingIndicatorOptions,
	);
}

function stopWorkingLoader(host: InteractiveExtensionHost): void {
	if (host.loadingAnimation) {
		host.loadingAnimation.stop();
		host.loadingAnimation = undefined;
	}
	host.statusContainer.clear();
}

function setWorkingVisible(host: InteractiveExtensionHost, visible: boolean): void {
	host.workingVisible = visible;
	if (!visible) {
		stopWorkingLoader(host);
		host.ui.requestRender();
		return;
	}
	if (host.session.isStreaming && !host.loadingAnimation) {
		host.statusContainer.clear();
		host.loadingAnimation = createWorkingLoader(host);
		host.statusContainer.addChild(host.loadingAnimation);
	}
	host.ui.requestRender();
}

function setWorkingIndicator(host: InteractiveExtensionHost, options?: LoaderIndicatorOptions): void {
	host.workingIndicatorOptions = options;
	host.loadingAnimation?.setIndicator(options);
	host.ui.requestRender();
}

function setHiddenThinkingLabel(host: InteractiveExtensionHost, label?: string): void {
	host.hiddenThinkingLabel = label ?? host.defaultHiddenThinkingLabel;
	for (const child of host.chatContainer.children) {
		if (child instanceof AssistantMessageComponent) {
			child.setHiddenThinkingLabel(host.hiddenThinkingLabel);
		}
	}
	if (host.streamingComponent) {
		host.streamingComponent.setHiddenThinkingLabel(host.hiddenThinkingLabel);
	}
	host.ui.requestRender();
}

function setExtensionWidget(
	host: InteractiveExtensionHost,
	key: string,
	content: string[] | DisposableComponent | ((tui: TUI, thm: Theme) => DisposableComponent) | undefined,
	options?: ExtensionWidgetOptions,
): void {
	const placement = options?.placement ?? "aboveEditor";
	const removeExisting = (map: Map<string, DisposableComponent>) => {
		const existing = map.get(key);
		if (existing?.dispose) existing.dispose();
		map.delete(key);
	};

	removeExisting(host.extensionWidgetsAbove);
	removeExisting(host.extensionWidgetsBelow);

	if (content === undefined) {
		renderWidgets(host);
		return;
	}

	let component: DisposableComponent;
	if (Array.isArray(content)) {
		const container = new Container();
		for (const line of content.slice(0, MAX_WIDGET_LINES)) {
			container.addChild(new Text(line, 1, 0));
		}
		if (content.length > MAX_WIDGET_LINES) {
			container.addChild(new Text(theme.fg("muted", "... (widget truncated)"), 1, 0));
		}
		component = container;
	} else if (typeof content === "function") {
		component = content(host.ui, theme);
	} else {
		component = content;
	}

	const targetMap = placement === "belowEditor" ? host.extensionWidgetsBelow : host.extensionWidgetsAbove;
	targetMap.set(key, component);
	renderWidgets(host);
}

function clearExtensionWidgets(host: InteractiveExtensionHost): void {
	for (const widget of host.extensionWidgetsAbove.values()) {
		widget.dispose?.();
	}
	for (const widget of host.extensionWidgetsBelow.values()) {
		widget.dispose?.();
	}
	host.extensionWidgetsAbove.clear();
	host.extensionWidgetsBelow.clear();
	renderWidgets(host);
}

function resetExtensionUI(host: InteractiveExtensionHost): void {
	if (host.extensionSelector) hideExtensionSelector(host);
	if (host.extensionInput) hideExtensionInput(host);
	if (host.extensionEditor) hideExtensionEditor(host);
	host.ui.hideOverlay();
	clearExtensionTerminalInputListeners(host);
	setExtensionFooter(host, undefined);
	setExtensionHeader(host, undefined);
	clearExtensionWidgets(host);
	host.footerDataProvider.clearExtensionStatuses();
	host.footer.invalidate();
	host.autocompleteProviderWrappers = [];
	setCustomEditorComponent(host, undefined);
	host.setupAutocompleteProvider();
	host.defaultEditor.onExtensionShortcut = undefined;
	host.updateTerminalTitle();
	host.workingMessage = undefined;
	host.workingVisible = true;
	setWorkingIndicator(host);
	if (host.loadingAnimation) {
		host.loadingAnimation.setMessage(`${host.defaultWorkingMessage} (${keyText("app.interrupt")} to interrupt)`);
	}
	setHiddenThinkingLabel(host);
}

function renderWidgets(host: InteractiveExtensionHost): void {
	if (!host.widgetContainerAbove || !host.widgetContainerBelow) return;
	renderWidgetContainer(host.widgetContainerAbove, host.extensionWidgetsAbove, true, true);
	renderWidgetContainer(host.widgetContainerBelow, host.extensionWidgetsBelow, false, false);
	host.ui.requestRender();
}

function renderWidgetContainer(
	container: Container,
	widgets: Map<string, DisposableComponent>,
	spacerWhenEmpty: boolean,
	leadingSpacer: boolean,
): void {
	container.clear();
	if (widgets.size === 0) {
		if (spacerWhenEmpty) container.addChild(new Spacer(1));
		return;
	}
	if (leadingSpacer) container.addChild(new Spacer(1));
	for (const component of widgets.values()) {
		container.addChild(component);
	}
}

function setExtensionFooter(
	host: InteractiveExtensionHost,
	factory: ((tui: TUI, thm: Theme, footerData: ReadonlyFooterDataProvider) => DisposableComponent) | undefined,
): void {
	host.customFooter?.dispose?.();
	if (host.customFooter) host.ui.removeChild(host.customFooter);
	else host.ui.removeChild(host.footer);

	if (factory) {
		host.customFooter = factory(host.ui, theme, host.footerDataProvider);
		host.ui.addChild(host.customFooter);
	} else {
		host.customFooter = undefined;
		host.ui.addChild(host.footer);
	}
	host.ui.requestRender();
}

function setExtensionHeader(
	host: InteractiveExtensionHost,
	factory: ((tui: TUI, thm: Theme) => DisposableComponent) | undefined,
): void {
	if (!host.builtInHeader) return;

	host.customHeader?.dispose?.();
	const currentHeader = host.customHeader || host.builtInHeader;
	const index = host.headerContainer.children.indexOf(currentHeader);

	if (factory) {
		host.customHeader = factory(host.ui, theme);
		if (isExpandable(host.customHeader)) host.customHeader.setExpanded(host.toolOutputExpanded);
		if (index !== -1) host.headerContainer.children[index] = host.customHeader;
		else host.headerContainer.children.unshift(host.customHeader);
	} else {
		host.customHeader = undefined;
		if (isExpandable(host.builtInHeader)) host.builtInHeader.setExpanded(host.toolOutputExpanded);
		if (index !== -1) host.headerContainer.children[index] = host.builtInHeader;
	}
	host.ui.requestRender();
}

function addExtensionTerminalInputListener(
	host: InteractiveExtensionHost,
	handler: (data: string) => { consume?: boolean; data?: string } | undefined,
): () => void {
	const unsubscribe = host.ui.addInputListener(handler);
	host.extensionTerminalInputUnsubscribers.add(unsubscribe);
	return () => {
		unsubscribe();
		host.extensionTerminalInputUnsubscribers.delete(unsubscribe);
	};
}

function clearExtensionTerminalInputListeners(host: InteractiveExtensionHost): void {
	for (const unsubscribe of host.extensionTerminalInputUnsubscribers) unsubscribe();
	host.extensionTerminalInputUnsubscribers.clear();
}

function createExtensionUIContext(host: InteractiveExtensionHost): ExtensionUIContext {
	return {
		select: (title, options, opts) => showExtensionSelector(host, title, options, opts),
		confirm: (title, message, opts) => showExtensionConfirm(host, title, message, opts),
		input: (title, placeholder, opts) => showExtensionInput(host, title, placeholder, opts),
		notify: (message, type) => showExtensionNotify(host, message, type),
		onTerminalInput: (handler) => addExtensionTerminalInputListener(host, handler),
		setStatus: (key, text) => setExtensionStatus(host, key, text),
		setWorkingMessage: (message) => {
			host.workingMessage = message;
			if (host.loadingAnimation) {
				host.loadingAnimation.setMessage(message ?? host.defaultWorkingMessage);
			}
		},
		setWorkingVisible: (visible) => setWorkingVisible(host, visible),
		setWorkingIndicator: (options) => setWorkingIndicator(host, options),
		setHiddenThinkingLabel: (label) => setHiddenThinkingLabel(host, label),
		setWidget: (key, content, options) => setExtensionWidget(host, key, content, options),
		setFooter: (factory) => setExtensionFooter(host, factory),
		setHeader: (factory) => setExtensionHeader(host, factory),
		setTitle: (title) => host.ui.terminal.setTitle(title),
		custom: (factory, options) => showExtensionCustom(host, factory, options),
		pasteToEditor: (text) => host.editor.handleInput(`\x1b[200~${text}\x1b[201~`),
		setEditorText: (text) => host.editor.setText(text),
		getEditorText: () => host.editor.getExpandedText?.() ?? host.editor.getText(),
		editor: (title, prefill) => showExtensionEditor(host, title, prefill),
		addAutocompleteProvider: (factory) => {
			host.autocompleteProviderWrappers.push(factory);
			host.setupAutocompleteProvider();
		},
		setEditorComponent: (factory) => setCustomEditorComponent(host, factory),
		getEditorComponent: () => host.editorComponentFactory,
		get theme() {
			return theme;
		},
		getAllThemes: () => getAvailableThemesWithPaths(),
		getTheme: (name) => getThemeByName(name),
		setTheme: (themeOrName) => {
			if (typeof themeOrName !== "string") {
				setThemeInstance(themeOrName);
				host.ui.requestRender();
				return { success: true };
			}
			const result = setTheme(themeOrName, true);
			if (result.success) {
				if (host.settingsManager.getTheme() !== themeOrName) {
					host.settingsManager.setTheme(themeOrName);
				}
				host.ui.requestRender();
			}
			return result;
		},
		getToolsExpanded: () => host.toolOutputExpanded,
		setToolsExpanded: (expanded) => host.setToolsExpanded(expanded),
	};
}

function showExtensionSelector(
	host: InteractiveExtensionHost,
	title: string,
	options: string[],
	opts?: ExtensionUIDialogOptions,
): Promise<string | undefined> {
	return new Promise((resolve) => {
		if (opts?.signal?.aborted) {
			resolve(undefined);
			return;
		}

		const onAbort = () => {
			hideExtensionSelector(host);
			resolve(undefined);
		};
		opts?.signal?.addEventListener("abort", onAbort, { once: true });

		host.extensionSelector = new ExtensionSelectorComponent(
			title,
			options,
			(option) => {
				opts?.signal?.removeEventListener("abort", onAbort);
				hideExtensionSelector(host);
				resolve(option);
			},
			() => {
				opts?.signal?.removeEventListener("abort", onAbort);
				hideExtensionSelector(host);
				resolve(undefined);
			},
			{
				tui: host.ui,
				timeout: opts?.timeout,
				onToggleToolsExpanded: () => host.toggleToolOutputExpansion(),
			},
		);

		host.editorContainer.clear();
		host.editorContainer.addChild(host.extensionSelector);
		host.ui.setFocus(host.extensionSelector);
		host.ui.requestRender();
	});
}

function hideExtensionSelector(host: InteractiveExtensionHost): void {
	host.extensionSelector?.dispose();
	host.editorContainer.clear();
	host.editorContainer.addChild(host.editor);
	host.extensionSelector = undefined;
	host.ui.setFocus(host.editor);
	host.ui.requestRender();
}

async function showExtensionConfirm(
	host: InteractiveExtensionHost,
	title: string,
	message: string,
	opts?: ExtensionUIDialogOptions,
): Promise<boolean> {
	const result = await showExtensionSelector(host, `${title}\n${message}`, ["Yes", "No"], opts);
	return result === "Yes";
}

async function promptForMissingSessionCwd(
	host: InteractiveExtensionHost,
	error: MissingSessionCwdError,
): Promise<string | undefined> {
	const confirmed = await showExtensionConfirm(
		host,
		"Session cwd not found",
		formatMissingSessionCwdPrompt(error.issue),
	);
	return confirmed ? error.issue.fallbackCwd : undefined;
}

function showExtensionInput(
	host: InteractiveExtensionHost,
	title: string,
	placeholder?: string,
	opts?: ExtensionUIDialogOptions,
): Promise<string | undefined> {
	return new Promise((resolve) => {
		if (opts?.signal?.aborted) {
			resolve(undefined);
			return;
		}

		const onAbort = () => {
			hideExtensionInput(host);
			resolve(undefined);
		};
		opts?.signal?.addEventListener("abort", onAbort, { once: true });

		host.extensionInput = new ExtensionInputComponent(
			title,
			placeholder,
			(value) => {
				opts?.signal?.removeEventListener("abort", onAbort);
				hideExtensionInput(host);
				resolve(value);
			},
			() => {
				opts?.signal?.removeEventListener("abort", onAbort);
				hideExtensionInput(host);
				resolve(undefined);
			},
			{ tui: host.ui, timeout: opts?.timeout },
		);

		host.editorContainer.clear();
		host.editorContainer.addChild(host.extensionInput);
		host.ui.setFocus(host.extensionInput);
		host.ui.requestRender();
	});
}

function hideExtensionInput(host: InteractiveExtensionHost): void {
	host.extensionInput?.dispose();
	host.editorContainer.clear();
	host.editorContainer.addChild(host.editor);
	host.extensionInput = undefined;
	host.ui.setFocus(host.editor);
	host.ui.requestRender();
}

function showExtensionEditor(
	host: InteractiveExtensionHost,
	title: string,
	prefill?: string,
): Promise<string | undefined> {
	return new Promise((resolve) => {
		host.extensionEditor = new ExtensionEditorComponent(
			host.ui,
			host.keybindings,
			title,
			prefill,
			(value) => {
				hideExtensionEditor(host);
				resolve(value);
			},
			() => {
				hideExtensionEditor(host);
				resolve(undefined);
			},
		);

		host.editorContainer.clear();
		host.editorContainer.addChild(host.extensionEditor);
		host.ui.setFocus(host.extensionEditor);
		host.ui.requestRender();
	});
}

function hideExtensionEditor(host: InteractiveExtensionHost): void {
	host.editorContainer.clear();
	host.editorContainer.addChild(host.editor);
	host.extensionEditor = undefined;
	host.ui.setFocus(host.editor);
	host.ui.requestRender();
}

function setCustomEditorComponent(host: InteractiveExtensionHost, factory: EditorFactory | undefined): void {
	host.editorComponentFactory = factory;
	const currentText = host.editor.getText();
	host.editorContainer.clear();

	if (factory) {
		const newEditor = factory(host.ui, getEditorTheme(), host.keybindings);
		newEditor.onSubmit = host.defaultEditor.onSubmit;
		newEditor.onChange = host.defaultEditor.onChange;
		newEditor.setText(currentText);
		if (newEditor.borderColor !== undefined) newEditor.borderColor = host.defaultEditor.borderColor;
		if (newEditor.setPaddingX !== undefined) newEditor.setPaddingX(host.defaultEditor.getPaddingX());
		if (newEditor.setAutocompleteProvider && host.autocompleteProvider) {
			newEditor.setAutocompleteProvider(host.autocompleteProvider);
		}

		const customEditor = newEditor as unknown as Record<string, unknown>;
		if ("actionHandlers" in customEditor && customEditor.actionHandlers instanceof Map) {
			if (!customEditor.onEscape) customEditor.onEscape = () => host.defaultEditor.onEscape?.();
			if (!customEditor.onCtrlD) customEditor.onCtrlD = () => host.defaultEditor.onCtrlD?.();
			if (!customEditor.onPasteImage) customEditor.onPasteImage = () => host.defaultEditor.onPasteImage?.();
			if (!customEditor.onExtensionShortcut) {
				customEditor.onExtensionShortcut = (data: string) => host.defaultEditor.onExtensionShortcut?.(data);
			}
			if (!customEditor.onActionError) {
				customEditor.onActionError = (err: unknown) => host.defaultEditor.onActionError?.(err);
			}
			if (!customEditor.onSubmitError) {
				customEditor.onSubmitError = (err: unknown) => host.defaultEditor.onSubmitError?.(err);
			}
			for (const [action, handler] of host.defaultEditor.actionHandlers) {
				(customEditor.actionHandlers as Map<string, () => void>).set(action, handler);
			}
		}
		host.editor = newEditor;
	} else {
		host.defaultEditor.setText(currentText);
		host.editor = host.defaultEditor;
	}

	host.editorContainer.addChild(host.editor);
	host.ui.setFocus(host.editor);
	host.ui.requestRender();
}

function showExtensionNotify(
	host: InteractiveExtensionHost,
	message: string,
	type?: "info" | "warning" | "error",
): void {
	if (type === "error") host.showError(message);
	else if (type === "warning") host.showWarning(message);
	else host.showStatus(message);
}

async function showExtensionCustom<T>(
	host: InteractiveExtensionHost,
	factory: (
		tui: TUI,
		thm: Theme,
		keybindings: KeybindingsManager,
		done: (result: T) => void,
	) => DisposableComponent | Promise<DisposableComponent>,
	options?: {
		overlay?: boolean;
		overlayOptions?: OverlayOptions | (() => OverlayOptions);
		onHandle?: (handle: OverlayHandle) => void;
	},
): Promise<T> {
	const savedText = host.editor.getText();
	const isOverlay = options?.overlay ?? false;

	const restoreEditor = () => {
		host.editorContainer.clear();
		host.editorContainer.addChild(host.editor);
		host.editor.setText(savedText);
		host.ui.setFocus(host.editor);
		host.ui.requestRender();
	};

	return new Promise((resolve, reject) => {
		let component: DisposableComponent;
		let closed = false;
		const close = (result: T) => {
			if (closed) return;
			closed = true;
			if (isOverlay) host.ui.hideOverlay();
			else restoreEditor();
			resolve(result);
			try {
				component?.dispose?.();
			} catch {
				// Ignore dispose errors after the result has settled.
			}
		};

		Promise.resolve(factory(host.ui, theme, host.keybindings, close))
			.then((created) => {
				if (closed) return;
				component = created;
				if (isOverlay) {
					const resolveOptions = (): OverlayOptions | undefined => {
						if (options?.overlayOptions) {
							return typeof options.overlayOptions === "function"
								? options.overlayOptions()
								: options.overlayOptions;
						}
						const width = (component as { width?: number }).width;
						return width ? { width } : undefined;
					};
					const handle = host.ui.showOverlay(component, resolveOptions());
					options?.onHandle?.(handle);
				} else {
					host.editorContainer.clear();
					host.editorContainer.addChild(component);
					host.ui.setFocus(component);
					host.ui.requestRender();
				}
			})
			.catch((error) => {
				if (closed) return;
				if (!isOverlay) restoreEditor();
				reject(error);
			});
	});
}

function showExtensionError(
	host: InteractiveExtensionHost,
	extensionPath: string,
	error: string,
	stack?: string,
): void {
	const errorMsg = `Extension "${extensionPath}" error: ${error}`;
	host.chatContainer.addChild(new Text(theme.fg("error", errorMsg), 1, 0));
	if (stack) {
		const stackLines = stack
			.split("\n")
			.slice(1)
			.map((line) => theme.fg("dim", `  ${line.trim()}`))
			.join("\n");
		if (stackLines) host.chatContainer.addChild(new Text(stackLines, 1, 0));
	}
	host.ui.requestRender();
}

export const interactiveExtensionRuntime = {
	bindCurrentSessionExtensions,
	teardownTransientUiState,
	setupExtensionShortcuts,
	setExtensionStatus,
	getWorkingLoaderMessage,
	createWorkingLoader,
	stopWorkingLoader,
	setWorkingVisible,
	setWorkingIndicator,
	setHiddenThinkingLabel,
	setExtensionWidget,
	clearExtensionWidgets,
	resetExtensionUI,
	renderWidgets,
	setExtensionFooter,
	setExtensionHeader,
	addExtensionTerminalInputListener,
	clearExtensionTerminalInputListeners,
	createExtensionUIContext,
	showExtensionSelector,
	hideExtensionSelector,
	showExtensionConfirm,
	promptForMissingSessionCwd,
	showExtensionInput,
	hideExtensionInput,
	showExtensionEditor,
	hideExtensionEditor,
	setCustomEditorComponent,
	showExtensionNotify,
	showExtensionCustom,
	showExtensionError,
};

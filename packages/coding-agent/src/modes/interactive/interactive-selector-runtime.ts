import type { Model } from "@pi-recon/repi-ai";
import { type Component, type Container, type EditorComponent, Loader, Spacer, type TUI } from "@pi-recon/repi-tui";
import type { AgentSession } from "../../core/agent-session.ts";
import type { AgentSessionRuntime } from "../../core/agent-session-runtime.ts";
import type { ExtensionCommandContext, ExtensionUIDialogOptions } from "../../core/extensions/index.ts";
import type { FooterDataProvider } from "../../core/footer-data-provider.ts";
import { configureHttpDispatcher, formatHttpIdleTimeoutMs } from "../../core/http-dispatcher.ts";
import type { KeybindingsManager } from "../../core/keybindings.ts";
import { findExactModelReferenceMatch, resolveModelScope } from "../../core/model-resolver.ts";
import { getAvailableThemes, setTheme, theme } from "../../core/presentation/theme-runtime.ts";
import { MissingSessionCwdError } from "../../core/session-cwd.ts";
import { SessionManager } from "../../core/session-manager.ts";
import type { SettingsManager } from "../../core/settings-manager.ts";
import { ProjectTrustStore } from "../../core/trust-manager.ts";
import { AssistantMessageComponent } from "./components/assistant-message.ts";
import type { CustomEditor } from "./components/custom-editor.ts";
import type { FooterComponent } from "./components/footer.ts";
import { keyText } from "./components/keybinding-hints.ts";
import { ModelSelectorComponent } from "./components/model-selector.ts";
import { ScopedModelsSelectorComponent } from "./components/scoped-models-selector.ts";
import { SessionSelectorComponent } from "./components/session-selector.ts";
import { SettingsSelectorComponent } from "./components/settings-selector.ts";
import { ToolExecutionComponent } from "./components/tool-execution.ts";
import { TreeSelectorComponent } from "./components/tree-selector.ts";
import { TrustSelectorComponent } from "./components/trust-selector.ts";
import { UserMessageSelectorComponent } from "./components/user-message-selector.ts";

const ANTHROPIC_SUBSCRIPTION_AUTH_WARNING =
	"Anthropic subscription auth is active. Third-party harness usage draws from extra usage and is billed per token, not your Claude plan limits. Manage extra usage at https://claude.ai/settings/usage.";

function isAnthropicSubscriptionAuthKey(apiKey: string | undefined): boolean {
	return typeof apiKey === "string" && apiKey.startsWith("sk-ant-oat");
}

export type InteractiveSessionSwitchOptions = Parameters<ExtensionCommandContext["switchSession"]>[1];

export type InteractiveSelectorHost = {
	runtimeHost: AgentSessionRuntime;
	ui: TUI;
	chatContainer: Container;
	statusContainer: Container;
	editorContainer: Container;
	defaultEditor: CustomEditor;
	editor: EditorComponent;
	footer: FooterComponent;
	footerDataProvider: FooterDataProvider;
	keybindings: KeybindingsManager;
	session: AgentSession;
	sessionManager: SessionManager;
	settingsManager: SettingsManager;
	hideThinkingBlock: boolean;
	anthropicSubscriptionWarningShown: boolean;
	loadingAnimation?: Loader;
	setupAutocompleteProvider(): void;
	updateEditorBorderColor(): void;
	rebuildChatFromMessages(): void;
	renderCurrentSessionState(): void;
	renderInitialMessages(): void;
	flushCompactionQueue(options?: { willRetry?: boolean }): Promise<void>;
	showExtensionSelector(
		title: string,
		options: string[],
		opts?: ExtensionUIDialogOptions,
	): Promise<string | undefined>;
	showExtensionEditor(title: string, prefill?: string): Promise<string | undefined>;
	promptForMissingSessionCwd(error: MissingSessionCwdError): Promise<string | undefined>;
	handleFatalRuntimeError(prefix: string, error: unknown): Promise<never>;
	handleReloadCommand(): Promise<void>;
	shutdown(options?: { fromSignal?: boolean }): Promise<void>;
	showStatus(message: string): void;
	showWarning(message: string): void;
	showError(message: string): void;
};

/** Owns selector lifecycle and all model/session selector workflows. */
export class InteractiveSelectorRuntime {
	private readonly host: InteractiveSelectorHost;

	constructor(host: InteractiveSelectorHost) {
		this.host = host;
	}

	showSelector(create: (done: () => void) => { component: Component; focus: Component }): void {
		let selectorComponent: Component | undefined;
		const done = () => {
			try {
				selectorComponent?.dispose?.();
			} catch {
				// Teardown must not prevent the editor from being restored.
			}
			this.host.editorContainer.clear();
			this.host.editorContainer.addChild(this.host.editor);
			this.host.ui.setFocus(this.host.editor);
		};
		const { component, focus } = create(done);
		selectorComponent = component;
		this.host.editorContainer.clear();
		this.host.editorContainer.addChild(component);
		this.host.ui.setFocus(focus);
		this.host.ui.requestRender();
	}

	showSettingsSelector(): void {
		const host = this.host;
		this.showSelector((done) => {
			const selector = new SettingsSelectorComponent(
				{
					autoCompact: host.session.autoCompactionEnabled,
					showImages: host.settingsManager.getShowImages(),
					imageWidthCells: host.settingsManager.getImageWidthCells(),
					autoResizeImages: host.settingsManager.getImageAutoResize(),
					blockImages: host.settingsManager.getBlockImages(),
					enableSkillCommands: host.settingsManager.getEnableSkillCommands(),
					steeringMode: host.session.steeringMode,
					followUpMode: host.session.followUpMode,
					transport: host.settingsManager.getTransport(),
					httpIdleTimeoutMs: host.settingsManager.getHttpIdleTimeoutMs(),
					thinkingLevel: host.session.thinkingLevel,
					availableThinkingLevels: host.session.getAvailableThinkingLevels(),
					currentTheme: host.settingsManager.getTheme() || "dark",
					availableThemes: getAvailableThemes(),
					hideThinkingBlock: host.hideThinkingBlock,
					showCacheMissNotices: host.settingsManager.getShowCacheMissNotices(),
					collapseChangelog: host.settingsManager.getCollapseChangelog(),
					enableInstallTelemetry: host.settingsManager.getEnableInstallTelemetry(),
					doubleEscapeAction: host.settingsManager.getDoubleEscapeAction(),
					treeFilterMode: host.settingsManager.getTreeFilterMode(),
					showHardwareCursor: host.settingsManager.getShowHardwareCursor(),
					editorPaddingX: host.settingsManager.getEditorPaddingX(),
					autocompleteMaxVisible: host.settingsManager.getAutocompleteMaxVisible(),
					quietStartup: host.settingsManager.getQuietStartup(),
					clearOnShrink: host.settingsManager.getClearOnShrink(),
					showTerminalProgress: host.settingsManager.getShowTerminalProgress(),
					warnings: host.settingsManager.getWarnings(),
				},
				{
					onAutoCompactChange: (enabled) => {
						host.session.setAutoCompactionEnabled(enabled);
						host.footer.setAutoCompactEnabled(enabled);
					},
					onShowImagesChange: (enabled) => {
						host.settingsManager.setShowImages(enabled);
						for (const child of host.chatContainer.children) {
							if (child instanceof ToolExecutionComponent) child.setShowImages(enabled);
						}
					},
					onImageWidthCellsChange: (width) => {
						host.settingsManager.setImageWidthCells(width);
						for (const child of host.chatContainer.children) {
							if (child instanceof ToolExecutionComponent) child.setImageWidthCells(width);
						}
					},
					onAutoResizeImagesChange: (enabled) => host.settingsManager.setImageAutoResize(enabled),
					onBlockImagesChange: (blocked) => host.settingsManager.setBlockImages(blocked),
					onEnableSkillCommandsChange: (enabled) => {
						host.settingsManager.setEnableSkillCommands(enabled);
						host.setupAutocompleteProvider();
					},
					onSteeringModeChange: (mode) => host.session.setSteeringMode(mode),
					onFollowUpModeChange: (mode) => host.session.setFollowUpMode(mode),
					onTransportChange: (transport) => {
						host.settingsManager.setTransport(transport);
						host.session.agent.transport = transport;
					},
					onHttpIdleTimeoutMsChange: (timeoutMs) => {
						host.settingsManager.setHttpIdleTimeoutMs(timeoutMs);
						configureHttpDispatcher(timeoutMs);
						host.showStatus(`HTTP idle timeout: ${formatHttpIdleTimeoutMs(timeoutMs)}`);
					},
					onThinkingLevelChange: (level) => {
						host.session.setThinkingLevel(level);
						host.footer.invalidate();
						host.updateEditorBorderColor();
					},
					onThemeChange: (themeName) => {
						const result = setTheme(themeName, true);
						host.settingsManager.setTheme(themeName);
						host.ui.invalidate();
						if (!result.success) {
							host.showError(`Failed to load theme "${themeName}": ${result.error}\nFell back to dark theme.`);
						}
					},
					onThemePreview: (themeName) => {
						const result = setTheme(themeName, true);
						if (result.success) {
							host.ui.invalidate();
							host.ui.requestRender();
						}
					},
					onHideThinkingBlockChange: (hidden) => {
						host.hideThinkingBlock = hidden;
						host.settingsManager.setHideThinkingBlock(hidden);
						for (const child of host.chatContainer.children) {
							if (child instanceof AssistantMessageComponent) child.setHideThinkingBlock(hidden);
						}
						host.chatContainer.clear();
						host.rebuildChatFromMessages();
					},
					onShowCacheMissNoticesChange: (shown) => {
						host.settingsManager.setShowCacheMissNotices(shown);
						host.rebuildChatFromMessages();
					},
					onCollapseChangelogChange: (collapsed) => host.settingsManager.setCollapseChangelog(collapsed),
					onEnableInstallTelemetryChange: (enabled) => host.settingsManager.setEnableInstallTelemetry(enabled),
					onQuietStartupChange: (enabled) => host.settingsManager.setQuietStartup(enabled),
					onDoubleEscapeActionChange: (action) => host.settingsManager.setDoubleEscapeAction(action),
					onTreeFilterModeChange: (mode) => host.settingsManager.setTreeFilterMode(mode),
					onShowHardwareCursorChange: (enabled) => {
						host.settingsManager.setShowHardwareCursor(enabled);
						host.ui.setShowHardwareCursor(enabled);
					},
					onEditorPaddingXChange: (padding) => {
						host.settingsManager.setEditorPaddingX(padding);
						host.defaultEditor.setPaddingX(padding);
						if (host.editor !== host.defaultEditor && host.editor.setPaddingX !== undefined) {
							host.editor.setPaddingX(padding);
						}
					},
					onAutocompleteMaxVisibleChange: (maxVisible) => {
						host.settingsManager.setAutocompleteMaxVisible(maxVisible);
						host.defaultEditor.setAutocompleteMaxVisible(maxVisible);
						if (host.editor !== host.defaultEditor && host.editor.setAutocompleteMaxVisible !== undefined) {
							host.editor.setAutocompleteMaxVisible(maxVisible);
						}
					},
					onClearOnShrinkChange: (enabled) => {
						host.settingsManager.setClearOnShrink(enabled);
						host.ui.setClearOnShrink(enabled);
					},
					onShowTerminalProgressChange: (enabled) => host.settingsManager.setShowTerminalProgress(enabled),
					onWarningsChange: (warnings) => host.settingsManager.setWarnings(warnings),
					onCancel: () => {
						done();
						host.ui.requestRender();
					},
				},
			);
			return { component: selector, focus: selector.getSettingsList() };
		});
	}

	async handleModelCommand(searchTerm?: string): Promise<void> {
		if (!searchTerm) {
			this.showModelSelector();
			return;
		}
		const model = await this.findExactModelMatch(searchTerm);
		if (model) {
			try {
				await this.host.session.setModel(model);
				this.host.footer.invalidate();
				this.host.updateEditorBorderColor();
				this.host.showStatus(`Model: ${model.id}`);
				void this.maybeWarnAboutAnthropicSubscriptionAuth(model);
			} catch (error) {
				this.host.showError(error instanceof Error ? error.message : String(error));
			}
			return;
		}
		this.showModelSelector(searchTerm);
	}

	private async findExactModelMatch(searchTerm: string): Promise<Model<any> | undefined> {
		return findExactModelReferenceMatch(searchTerm, await this.getModelCandidates());
	}

	private async getModelCandidates(): Promise<Model<any>[]> {
		if (this.host.session.scopedModels.length > 0) {
			return this.host.session.scopedModels.map((scoped) => scoped.model);
		}
		await this.host.session.modelRegistry.refresh();
		try {
			return await this.host.session.modelRegistry.getAvailable();
		} catch {
			return [];
		}
	}

	async updateAvailableProviderCount(): Promise<void> {
		const models = await this.getModelCandidates();
		this.host.footerDataProvider.setAvailableProviderCount(new Set(models.map((model) => model.provider)).size);
	}

	async maybeWarnAboutAnthropicSubscriptionAuth(
		model: Pick<Model<any>, "provider"> | undefined = this.host.session.model,
	): Promise<void> {
		const host = this.host;
		if (host.settingsManager.getWarnings().anthropicExtraUsage === false) return;
		if (host.anthropicSubscriptionWarningShown) return;
		if (!model || model.provider !== "anthropic") return;

		const storedCredential = host.session.modelRegistry.authStorage.get("anthropic");
		if (storedCredential?.type === "oauth") {
			host.anthropicSubscriptionWarningShown = true;
			host.showWarning(ANTHROPIC_SUBSCRIPTION_AUTH_WARNING);
			return;
		}

		try {
			const apiKey = await host.session.modelRegistry.getApiKeyForProvider(model.provider);
			if (!isAnthropicSubscriptionAuthKey(apiKey)) return;
			host.anthropicSubscriptionWarningShown = true;
			host.showWarning(ANTHROPIC_SUBSCRIPTION_AUTH_WARNING);
		} catch {
			// Authentication lookup failures do not affect model selection.
		}
	}

	showTrustSelector(): void {
		const host = this.host;
		const cwd = host.sessionManager.getCwd();
		const trustStore = new ProjectTrustStore(host.runtimeHost.services.agentDir);
		const savedDecision = trustStore.get(cwd);
		this.showSelector((done) => {
			const selector = new TrustSelectorComponent({
				cwd,
				savedDecision,
				projectTrusted: host.settingsManager.isProjectTrusted(),
				onSelect: (trusted) => {
					trustStore.set(cwd, trusted);
					done();
					host.settingsManager.setProjectTrusted(trusted);
					void host.handleReloadCommand().then(() => {
						host.showStatus(
							`Saved trust decision: ${trusted ? "trusted" : "untrusted"}. Project resources reloaded.`,
						);
					});
				},
				onCancel: () => {
					done();
					host.ui.requestRender();
				},
			});
			return { component: selector, focus: selector };
		});
	}

	showModelSelector(initialSearchInput?: string): void {
		const host = this.host;
		this.showSelector((done) => {
			const selector = new ModelSelectorComponent(
				host.ui,
				host.session.model,
				host.settingsManager,
				host.session.modelRegistry,
				host.session.scopedModels,
				async (model) => {
					try {
						await host.session.setModel(model);
						host.footer.invalidate();
						host.updateEditorBorderColor();
						done();
						host.showStatus(`Model: ${model.id}`);
						void this.maybeWarnAboutAnthropicSubscriptionAuth(model);
					} catch (error) {
						done();
						host.showError(error instanceof Error ? error.message : String(error));
					}
				},
				() => {
					done();
					host.ui.requestRender();
				},
				initialSearchInput,
			);
			return { component: selector, focus: selector };
		});
	}

	async showModelsSelector(): Promise<void> {
		const host = this.host;
		await host.session.modelRegistry.refresh();
		const allModels = host.session.modelRegistry.getAvailable();
		if (allModels.length === 0) {
			host.showStatus("No models available");
			return;
		}

		const sessionScopedModels = host.session.scopedModels;
		let currentEnabledIds: string[] | null = null;
		if (sessionScopedModels.length > 0) {
			currentEnabledIds = sessionScopedModels.map((scoped) => `${scoped.model.provider}/${scoped.model.id}`);
		} else {
			const patterns = host.settingsManager.getEnabledModels();
			if (patterns !== undefined && patterns.length > 0) {
				const scopedModels = await resolveModelScope(patterns, host.session.modelRegistry);
				currentEnabledIds = scopedModels.map((scoped) => `${scoped.model.provider}/${scoped.model.id}`);
			}
		}

		const updateSessionModels = async (enabledIds: string[] | null) => {
			currentEnabledIds = enabledIds === null ? null : [...enabledIds];
			if (enabledIds && enabledIds.length > 0 && enabledIds.length < allModels.length) {
				const newScopedModels = await resolveModelScope(enabledIds, host.session.modelRegistry);
				host.session.setScopedModels(
					newScopedModels.map((scoped) => ({
						model: scoped.model,
						thinkingLevel: scoped.thinkingLevel,
					})),
				);
			} else {
				host.session.setScopedModels([]);
			}
			await this.updateAvailableProviderCount();
			host.ui.requestRender();
		};

		this.showSelector((done) => {
			const selector = new ScopedModelsSelectorComponent(
				{ allModels, enabledModelIds: currentEnabledIds },
				{
					onChange: async (enabledIds) => updateSessionModels(enabledIds),
					onPersist: (enabledIds) => {
						const newPatterns =
							enabledIds === null || enabledIds.length === allModels.length ? undefined : enabledIds;
						host.settingsManager.setEnabledModels(newPatterns ? [...newPatterns] : undefined);
						host.showStatus("Model selection saved to settings");
					},
					onCancel: () => {
						done();
						host.ui.requestRender();
					},
				},
			);
			return { component: selector, focus: selector };
		});
	}

	showUserMessageSelector(): void {
		const host = this.host;
		const userMessages = host.session.getUserMessagesForForking();
		if (userMessages.length === 0) {
			host.showStatus("No messages to fork from");
			return;
		}
		const initialSelectedId = userMessages[userMessages.length - 1]?.entryId;
		this.showSelector((done) => {
			const selector = new UserMessageSelectorComponent(
				userMessages.map((message) => ({ id: message.entryId, text: message.text })),
				async (entryId) => {
					try {
						const result = await host.runtimeHost.fork(entryId);
						if (result.cancelled) {
							done();
							host.ui.requestRender();
							return;
						}
						host.renderCurrentSessionState();
						host.editor.setText(result.selectedText ?? "");
						done();
						host.showStatus("Forked to new session");
					} catch (error: unknown) {
						done();
						host.showError(error instanceof Error ? error.message : String(error));
					}
				},
				() => {
					done();
					host.ui.requestRender();
				},
				initialSelectedId,
			);
			return { component: selector, focus: selector.getMessageList() };
		});
	}

	async handleCloneCommand(): Promise<void> {
		const host = this.host;
		const leafId = host.sessionManager.getLeafId();
		if (!leafId) {
			host.showStatus("Nothing to clone yet");
			return;
		}
		try {
			const result = await host.runtimeHost.fork(leafId, { position: "at" });
			if (result.cancelled) {
				host.ui.requestRender();
				return;
			}
			host.renderCurrentSessionState();
			host.editor.setText("");
			host.showStatus("Cloned to new session");
		} catch (error: unknown) {
			host.showError(error instanceof Error ? error.message : String(error));
		}
	}

	showTreeSelector(initialSelectedId?: string): void {
		const host = this.host;
		const tree = host.sessionManager.getTree();
		const realLeafId = host.sessionManager.getLeafId();
		const initialFilterMode = host.settingsManager.getTreeFilterMode();
		if (tree.length === 0) {
			host.showStatus("No entries in session");
			return;
		}

		this.showSelector((done) => {
			const selector = new TreeSelectorComponent(
				tree,
				realLeafId,
				host.ui.terminal.rows,
				async (entryId) => {
					if (entryId === realLeafId) {
						done();
						host.showStatus("Already at this point");
						return;
					}
					done();
					let wantsSummary = false;
					let customInstructions: string | undefined;
					if (!host.settingsManager.getBranchSummarySkipPrompt()) {
						while (true) {
							const summaryChoice = await host.showExtensionSelector("Summarize branch?", [
								"No summary",
								"Summarize",
								"Summarize with custom prompt",
							]);
							if (summaryChoice === undefined) {
								this.showTreeSelector(entryId);
								return;
							}
							wantsSummary = summaryChoice !== "No summary";
							if (summaryChoice === "Summarize with custom prompt") {
								customInstructions = await host.showExtensionEditor("Custom summarization instructions");
								if (customInstructions === undefined) continue;
							}
							break;
						}
					}

					let summaryLoader: Loader | undefined;
					const originalOnEscape = host.defaultEditor.onEscape;
					if (wantsSummary) {
						host.defaultEditor.onEscape = () => host.session.abortBranchSummary();
						host.chatContainer.addChild(new Spacer(1));
						summaryLoader = new Loader(
							host.ui,
							(spinner) => theme.fg("accent", spinner),
							(text) => theme.fg("muted", text),
							`Summarizing branch... (${keyText("app.interrupt")} to cancel)`,
						);
						host.statusContainer.addChild(summaryLoader);
						host.ui.requestRender();
					}

					try {
						const result = await host.session.navigateTree(entryId, {
							summarize: wantsSummary,
							customInstructions,
						});
						if (result.aborted) {
							host.showStatus("Branch summarization cancelled");
							this.showTreeSelector(entryId);
							return;
						}
						if (result.cancelled) {
							host.showStatus("Navigation cancelled");
							return;
						}
						host.chatContainer.clear();
						host.renderInitialMessages();
						if (result.editorText && !host.editor.getText().trim()) host.editor.setText(result.editorText);
						host.showStatus("Navigated to selected point");
						void host.flushCompactionQueue({ willRetry: false });
					} catch (error) {
						host.showError(error instanceof Error ? error.message : String(error));
					} finally {
						if (summaryLoader) {
							summaryLoader.stop();
							host.statusContainer.clear();
						}
						host.defaultEditor.onEscape = originalOnEscape;
					}
				},
				() => {
					done();
					host.ui.requestRender();
				},
				(entryId, label) => {
					host.sessionManager.appendLabelChange(entryId, label);
					host.ui.requestRender();
				},
				initialSelectedId,
				initialFilterMode,
				(error) =>
					host.showError(`Select handler error: ${error instanceof Error ? error.message : String(error)}`),
			);
			return { component: selector, focus: selector };
		});
	}

	showSessionSelector(): void {
		const host = this.host;
		this.showSelector((done) => {
			const selector = new SessionSelectorComponent(
				(onProgress) =>
					SessionManager.list(host.sessionManager.getCwd(), host.sessionManager.getSessionDir(), onProgress),
				(onProgress) =>
					host.sessionManager.usesDefaultSessionDir()
						? SessionManager.listAll(onProgress)
						: SessionManager.listAll(host.sessionManager.getSessionDir(), onProgress),
				async (sessionPath) => {
					done();
					await this.handleResumeSession(sessionPath);
				},
				() => {
					done();
					host.ui.requestRender();
				},
				() => void host.shutdown(),
				() => host.ui.requestRender(),
				{
					renameSession: async (sessionFilePath: string, nextName: string | undefined) => {
						const next = (nextName ?? "").trim();
						if (!next) return;
						SessionManager.open(sessionFilePath).appendSessionInfo(next);
					},
					showRenameHint: true,
					keybindings: host.keybindings,
					onSelectError: (error) =>
						host.showError(`Select handler error: ${error instanceof Error ? error.message : String(error)}`),
				},
				host.sessionManager.getSessionFile(),
			);
			return { component: selector, focus: selector };
		});
	}

	async handleResumeSession(
		sessionPath: string,
		options?: InteractiveSessionSwitchOptions,
	): Promise<{ cancelled: boolean }> {
		const host = this.host;
		if (host.loadingAnimation) {
			host.loadingAnimation.stop();
			host.loadingAnimation = undefined;
		}
		host.statusContainer.clear();
		try {
			const result = await host.runtimeHost.switchSession(sessionPath, { withSession: options?.withSession });
			if (result.cancelled) return result;
			host.renderCurrentSessionState();
			host.showStatus("Resumed session");
			return result;
		} catch (error: unknown) {
			if (error instanceof MissingSessionCwdError) {
				const selectedCwd = await host.promptForMissingSessionCwd(error);
				if (!selectedCwd) {
					host.showStatus("Resume cancelled");
					return { cancelled: true };
				}
				const result = await host.runtimeHost.switchSession(sessionPath, {
					cwdOverride: selectedCwd,
					withSession: options?.withSession,
				});
				if (result.cancelled) return result;
				host.renderCurrentSessionState();
				host.showStatus("Resumed session in current cwd");
				return result;
			}
			return host.handleFatalRuntimeError("Failed to resume session", error);
		}
	}
}

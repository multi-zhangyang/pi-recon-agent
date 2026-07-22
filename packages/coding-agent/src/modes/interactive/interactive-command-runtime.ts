import * as fs from "node:fs";
import * as path from "node:path";
import type { Component, EditorComponent, Keybinding, MarkdownTheme } from "@pi-recon/repi-tui";
import { Container, type Loader, Markdown, Spacer, Text, type TUI, visibleWidth } from "@pi-recon/repi-tui";
import { APP_NAME, getDebugLogPath, IS_REPI_PRODUCT } from "../../config.ts";
import type { AgentSession } from "../../core/agent-session.ts";
import { type AgentSessionRuntime, SessionImportFileNotFoundError } from "../../core/agent-session-runtime.ts";
import { computeCacheWaste } from "../../core/cache-stats.ts";
import { formatContextBreakdown } from "../../core/context-manager.ts";
import type { ExtensionRunner } from "../../core/extensions/index.ts";
import { configureHttpDispatcher } from "../../core/http-dispatcher.ts";
import type { AppKeybinding, KeybindingsManager } from "../../core/keybindings.ts";
import { setRegisteredThemes, setTheme, theme } from "../../core/presentation/theme-runtime.ts";
import { MissingSessionCwdError } from "../../core/session-cwd.ts";
import type { TruncationResult } from "../../core/tools/truncate.ts";
import { getChangelogPath, parseChangelog } from "../../utils/changelog.ts";
import { copyToClipboard } from "../../utils/clipboard.ts";
import { ArminComponent } from "./components/armin.ts";
import { BashExecutionComponent } from "./components/bash-execution.ts";
import { BorderedLoader } from "./components/bordered-loader.ts";
import type { CustomEditor } from "./components/custom-editor.ts";
import { DynamicBorder } from "./components/dynamic-border.ts";
import { EarendilAnnouncementComponent } from "./components/earendil-announcement.ts";
import { formatTokens } from "./components/footer.ts";
import { formatKeyText, keyDisplayText } from "./components/keybinding-hints.ts";
import { createPrivateGist } from "./external-process-runtime.ts";

export type InteractiveCommandHost = {
	runtimeHost: AgentSessionRuntime;
	session: AgentSession;
	ui: TUI;
	chatContainer: Container;
	pendingMessagesContainer: Container;
	statusContainer: Container;
	editorContainer: Container;
	defaultEditor: CustomEditor;
	editor: EditorComponent;
	keybindings: KeybindingsManager;
	loadingAnimation?: Loader;
	customHeader?: Component;
	builtInHeader?: Component;
	toolOutputExpanded: boolean;
	hideThinkingBlock: boolean;
	bashComponent?: BashExecutionComponent;
	pendingBashComponents: BashExecutionComponent[];
	resetExtensionUI(): void;
	setupAutocompleteProvider(): void;
	setupExtensionShortcuts(extensionRunner: ExtensionRunner): void;
	rebuildChatFromMessages(): void;
	showLoadedResources(options?: { force?: boolean; showDiagnosticsWhenQuiet?: boolean }): void;
	renderCurrentSessionState(): void;
	showExtensionConfirm(title: string, message: string): Promise<boolean>;
	promptForMissingSessionCwd(error: MissingSessionCwdError): Promise<string | undefined>;
	handleFatalRuntimeError(prefix: string, error: unknown): Promise<never>;
	getMarkdownThemeWithSettings(): MarkdownTheme;
	showStatus(message: string): void;
	showWarning(message: string): void;
	showError(message: string): void;
};

function isExpandable(component: unknown): component is { setExpanded(expanded: boolean): void } {
	return (
		typeof component === "object" &&
		component !== null &&
		"setExpanded" in component &&
		typeof component.setExpanded === "function"
	);
}

export class InteractiveCommandRuntime {
	private readonly host: InteractiveCommandHost;

	constructor(host: InteractiveCommandHost) {
		this.host = host;
	}

	private get runtimeHost(): AgentSessionRuntime {
		return this.host.runtimeHost;
	}

	private get session(): AgentSession {
		return this.host.session;
	}

	private get sessionManager() {
		return this.session.sessionManager;
	}

	private get settingsManager() {
		return this.session.settingsManager;
	}

	private get ui(): TUI {
		return this.host.ui;
	}

	private get chatContainer(): Container {
		return this.host.chatContainer;
	}

	private get pendingMessagesContainer(): Container {
		return this.host.pendingMessagesContainer;
	}

	private get statusContainer(): Container {
		return this.host.statusContainer;
	}

	private get editorContainer(): Container {
		return this.host.editorContainer;
	}

	private get defaultEditor(): CustomEditor {
		return this.host.defaultEditor;
	}

	private get editor(): EditorComponent {
		return this.host.editor;
	}

	private get keybindings(): KeybindingsManager {
		return this.host.keybindings;
	}

	private get loadingAnimation(): Loader | undefined {
		return this.host.loadingAnimation;
	}

	private set loadingAnimation(value: Loader | undefined) {
		this.host.loadingAnimation = value;
	}

	private get hideThinkingBlock(): boolean {
		return this.host.hideThinkingBlock;
	}

	private set hideThinkingBlock(value: boolean) {
		this.host.hideThinkingBlock = value;
	}

	private get bashComponent(): BashExecutionComponent | undefined {
		return this.host.bashComponent;
	}

	private set bashComponent(value: BashExecutionComponent | undefined) {
		this.host.bashComponent = value;
	}

	private get pendingBashComponents(): BashExecutionComponent[] {
		return this.host.pendingBashComponents;
	}

	private showStatus(message: string): void {
		this.host.showStatus(message);
	}

	private showWarning(message: string): void {
		this.host.showWarning(message);
	}

	private showError(message: string): void {
		this.host.showError(message);
	}

	private resetExtensionUI(): void {
		this.host.resetExtensionUI();
	}

	private setupAutocompleteProvider(): void {
		this.host.setupAutocompleteProvider();
	}

	private setupExtensionShortcuts(extensionRunner: ExtensionRunner): void {
		this.host.setupExtensionShortcuts(extensionRunner);
	}

	private rebuildChatFromMessages(): void {
		this.host.rebuildChatFromMessages();
	}

	private showLoadedResources(options?: { force?: boolean; showDiagnosticsWhenQuiet?: boolean }): void {
		this.host.showLoadedResources(options);
	}

	private renderCurrentSessionState(): void {
		this.host.renderCurrentSessionState();
	}

	private showExtensionConfirm(title: string, message: string): Promise<boolean> {
		return this.host.showExtensionConfirm(title, message);
	}

	private promptForMissingSessionCwd(error: MissingSessionCwdError): Promise<string | undefined> {
		return this.host.promptForMissingSessionCwd(error);
	}

	private handleFatalRuntimeError(prefix: string, error: unknown): Promise<never> {
		return this.host.handleFatalRuntimeError(prefix, error);
	}

	private getMarkdownThemeWithSettings(): MarkdownTheme {
		return this.host.getMarkdownThemeWithSettings();
	}

	async handleReloadCommand(): Promise<void> {
		if (this.session.isStreaming) {
			this.showWarning("Wait for the current response to finish before reloading.");
			return;
		}
		if (this.session.isCompacting) {
			this.showWarning("Wait for compaction to finish before reloading.");
			return;
		}

		this.resetExtensionUI();

		const reloadBox = new Container();
		const borderColor = (text: string) => theme.fg("border", text);
		reloadBox.addChild(new DynamicBorder(borderColor));
		reloadBox.addChild(new Spacer(1));
		reloadBox.addChild(
			new Text(theme.fg("muted", "Reloading keybindings, extensions, skills, prompts, themes..."), 1, 0),
		);
		reloadBox.addChild(new Spacer(1));
		reloadBox.addChild(new DynamicBorder(borderColor));

		const previousEditor = this.editor;
		this.editorContainer.clear();
		this.editorContainer.addChild(reloadBox);
		this.ui.setFocus(reloadBox);
		this.ui.requestRender(true);
		await new Promise((resolve) => process.nextTick(resolve));

		const dismissReloadBox = (editor: Component) => {
			this.editorContainer.clear();
			this.editorContainer.addChild(editor);
			this.ui.setFocus(editor);
			this.ui.requestRender();
		};

		try {
			await this.session.reload();
			configureHttpDispatcher(this.settingsManager.getHttpIdleTimeoutMs());
			this.keybindings.reload();
			const activeHeader = this.host.customHeader ?? this.host.builtInHeader;
			if (isExpandable(activeHeader)) {
				activeHeader.setExpanded(this.host.toolOutputExpanded);
			}
			setRegisteredThemes(this.session.resourceLoader.getThemes().themes);
			this.hideThinkingBlock = this.settingsManager.getHideThinkingBlock();
			const themeName = this.settingsManager.getTheme();
			const themeResult = themeName ? setTheme(themeName, true) : { success: true };
			if (!themeResult.success) {
				this.showError(`Failed to load theme "${themeName}": ${themeResult.error}\nFell back to dark theme.`);
			}
			const editorPaddingX = this.settingsManager.getEditorPaddingX();
			const autocompleteMaxVisible = this.settingsManager.getAutocompleteMaxVisible();
			this.defaultEditor.setPaddingX(editorPaddingX);
			this.defaultEditor.setAutocompleteMaxVisible(autocompleteMaxVisible);
			if (this.editor !== this.defaultEditor) {
				this.editor.setPaddingX?.(editorPaddingX);
				this.editor.setAutocompleteMaxVisible?.(autocompleteMaxVisible);
			}
			this.ui.setShowHardwareCursor(this.settingsManager.getShowHardwareCursor());
			this.ui.setClearOnShrink(this.settingsManager.getClearOnShrink());
			this.setupAutocompleteProvider();
			const runner = this.session.extensionRunner;
			this.setupExtensionShortcuts(runner);
			this.rebuildChatFromMessages();
			dismissReloadBox(this.editor as Component);
			this.showLoadedResources({
				force: false,
				showDiagnosticsWhenQuiet: true,
			});
			const modelsJsonError = this.session.modelRegistry.getError();
			if (modelsJsonError) {
				this.showError(`models.json error: ${modelsJsonError}`);
			}
			this.showStatus("Reloaded keybindings, extensions, skills, prompts, themes");
		} catch (error) {
			dismissReloadBox(previousEditor as Component);
			this.showError(`Reload failed: ${error instanceof Error ? error.message : String(error)}`);
		}
	}

	async handleExportCommand(text: string): Promise<void> {
		const outputPath = this.getPathCommandArgument(text, "/export");

		try {
			if (outputPath?.endsWith(".jsonl")) {
				const filePath = this.session.exportToJsonl(outputPath);
				this.showStatus(`Session exported to: ${filePath}`);
			} else {
				const filePath = await this.session.exportToHtml(outputPath, theme);
				this.showStatus(`Session exported to: ${filePath}`);
			}
		} catch (error: unknown) {
			this.showError(`Failed to export session: ${error instanceof Error ? error.message : "Unknown error"}`);
		}
	}

	private getPathCommandArgument(text: string, command: "/export" | "/import"): string | undefined {
		if (text === command || !text.startsWith(`${command} `)) return undefined;

		const argsString = text.slice(command.length + 1).trimStart();
		if (!argsString) return undefined;

		const firstChar = argsString[0];
		if (firstChar === '"' || firstChar === "'") {
			const closingQuoteIndex = argsString.indexOf(firstChar, 1);
			if (closingQuoteIndex < 0) return undefined;
			return argsString.slice(1, closingQuoteIndex);
		}

		const firstWhitespaceIndex = argsString.search(/\s/);
		return firstWhitespaceIndex < 0 ? argsString : argsString.slice(0, firstWhitespaceIndex);
	}

	async handleImportCommand(text: string): Promise<void> {
		const inputPath = this.getPathCommandArgument(text, "/import");
		if (!inputPath) {
			this.showError("Usage: /import <path.jsonl>");
			return;
		}

		const confirmed = await this.showExtensionConfirm("Import session", `Replace current session with ${inputPath}?`);
		if (!confirmed) {
			this.showStatus("Import cancelled");
			return;
		}

		try {
			const loadingAnimation = this.loadingAnimation;
			if (loadingAnimation) {
				loadingAnimation.stop();
				this.loadingAnimation = undefined;
			}
			this.statusContainer.clear();
			const result = await this.runtimeHost.importFromJsonl(inputPath);
			if (result.cancelled) {
				this.showStatus("Import cancelled");
				return;
			}
			this.renderCurrentSessionState();
			this.showStatus(`Session imported from: ${inputPath}`);
		} catch (error: unknown) {
			if (error instanceof MissingSessionCwdError) {
				const selectedCwd = await this.promptForMissingSessionCwd(error);
				if (!selectedCwd) {
					this.showStatus("Import cancelled");
					return;
				}
				const result = await this.runtimeHost.importFromJsonl(inputPath, selectedCwd);
				if (result.cancelled) {
					this.showStatus("Import cancelled");
					return;
				}
				this.renderCurrentSessionState();
				this.showStatus(`Session imported from: ${inputPath}`);
				return;
			}
			if (error instanceof SessionImportFileNotFoundError) {
				this.showError(`Failed to import session: ${error.message}`);
				return;
			}
			await this.handleFatalRuntimeError("Failed to import session", error);
		}
	}

	async handleShareCommand(): Promise<void> {
		const loader = new BorderedLoader(this.ui, theme, "Creating gist...");
		this.editorContainer.clear();
		this.editorContainer.addChild(loader);
		this.ui.setFocus(loader);
		this.ui.requestRender();

		let restored = false;
		const restoreEditor = () => {
			if (restored) return;
			restored = true;
			loader.dispose();
			this.editorContainer.clear();
			this.editorContainer.addChild(this.editor);
			this.ui.setFocus(this.editor);
		};

		loader.onAbort = () => {
			restoreEditor();
			this.showStatus("Share cancelled");
		};

		const result = await createPrivateGist({
			appName: APP_NAME,
			signal: loader.signal,
			exportHtml: (filePath) => this.session.exportToHtml(filePath, theme),
		});
		restoreEditor();
		if (result.status === "cancelled") return;

		if (result.status === "success") {
			this.showStatus(`Share URL: ${result.previewUrl}\nGist: ${result.gistUrl}`);
		} else if (result.status === "unavailable") {
			this.showError(result.message);
		} else if (result.status === "error") {
			const prefix = result.stage === "export" ? "Failed to export session" : "Failed to create gist";
			this.showError(`${prefix}: ${result.error instanceof Error ? result.error.message : "Unknown error"}`);
		}
	}

	async handleCopyCommand(): Promise<void> {
		const text = this.session.getLastAssistantText();
		if (!text) {
			this.showError("No agent messages to copy yet.");
			return;
		}

		try {
			await copyToClipboard(text);
			this.showStatus("Copied last agent message to clipboard");
		} catch (error) {
			this.showError(error instanceof Error ? error.message : String(error));
		}
	}

	handleNameCommand(text: string): void {
		const name = text.replace(/^\/name\s*/, "").trim();
		if (!name) {
			const currentName = this.sessionManager.getSessionName();
			if (currentName) {
				this.chatContainer.addChild(new Spacer(1));
				this.chatContainer.addChild(new Text(theme.fg("dim", `Session name: ${currentName}`), 1, 0));
			} else {
				this.showWarning("Usage: /name <name>");
			}
			this.ui.requestRender();
			return;
		}

		this.session.setSessionName(name);
		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(new Text(theme.fg("dim", `Session name set: ${name}`), 1, 0));
		this.ui.requestRender();
	}

	handleSessionCommand(): void {
		const stats = this.session.getSessionStats();
		const sessionName = this.sessionManager.getSessionName();
		const entries = this.sessionManager.getEntries();
		const cacheWaste = computeCacheWaste(entries, this.session.modelRegistry);
		const perModelMap = new Map<string, { key: string; cost: number; tokens: number }>();
		for (const entry of entries) {
			if (entry.type !== "message" || entry.message.role !== "assistant") continue;
			const message = entry.message;
			const usage = message.usage;
			const key = `${message.provider}/${message.responseModel ?? message.model}`;
			let bucket = perModelMap.get(key);
			if (!bucket) {
				bucket = { key, cost: 0, tokens: 0 };
				perModelMap.set(key, bucket);
			}
			bucket.cost += Number.isFinite(usage?.cost?.total) ? usage.cost.total : 0;
			bucket.tokens +=
				(Number.isFinite(usage?.input) ? usage.input : 0) +
				(Number.isFinite(usage?.output) ? usage.output : 0) +
				(Number.isFinite(usage?.cacheRead) ? usage.cacheRead : 0) +
				(Number.isFinite(usage?.cacheWrite) ? usage.cacheWrite : 0);
		}
		const perModel = Array.from(perModelMap.values()).sort((left, right) => right.cost - left.cost);

		let info = `${theme.bold("Session Info")}\n\n`;
		if (sessionName) info += `${theme.fg("dim", "Name:")} ${sessionName}\n`;
		info += `${theme.fg("dim", "File:")} ${stats.sessionFile ?? "In-memory"}\n`;
		info += `${theme.fg("dim", "ID:")} ${stats.sessionId}\n\n`;
		info += `${theme.bold("Messages")}\n`;
		info += `${theme.fg("dim", "Total:")} ${stats.totalMessages}\n`;
		info += `${theme.fg("dim", "User:")} ${stats.userMessages}\n`;
		info += `${theme.fg("dim", "Assistant:")} ${stats.assistantMessages}\n`;
		info += `${theme.fg("dim", "Tools:")} ${stats.toolCalls} calls, ${stats.toolResults} results\n\n`;
		info += `${theme.bold("Tokens")}\n`;
		const { input, cacheRead, cacheWrite } = stats.tokens;
		const promptTokens = input + cacheRead + cacheWrite;
		info += `${theme.fg("dim", "Input:")} ${promptTokens.toLocaleString()}\n`;
		if (promptTokens > 0 && (cacheRead > 0 || cacheWrite > 0)) {
			const hitRate = theme.fg("dim", `(${((cacheRead / promptTokens) * 100).toFixed(1)}%)`);
			info += `  ${theme.fg("dim", "Cached:")} ${cacheRead.toLocaleString()} ${hitRate}\n`;
			const written =
				cacheWrite > 0 ? ` ${theme.fg("dim", `(${cacheWrite.toLocaleString()} written to cache)`)}` : "";
			info += `  ${theme.fg("dim", "Uncached:")} ${(input + cacheWrite).toLocaleString()}${written}\n`;
		}
		info += `${theme.fg("dim", "Output:")} ${stats.tokens.output.toLocaleString()}\n`;
		info += `${theme.fg("dim", "Total:")} ${stats.tokens.total.toLocaleString()}\n`;

		if (stats.cost > 0 || cacheWaste.missedTokens > 0) {
			info += `\n${theme.bold("Cost")}\n`;
			info += `${theme.fg("dim", "Total:")} $${stats.cost.toFixed(3)}`;
			if (perModel.length > 1) {
				for (const item of perModel) {
					info += `\n  ${theme.fg("dim", `${item.key}:`)} $${item.cost.toFixed(3)} ${theme.fg("dim", `(${formatTokens(item.tokens)} tokens)`)}`;
				}
			}
			if (cacheWaste.missedTokens > 0) {
				const missLabel = cacheWaste.missCount === 1 ? "1 miss" : `${cacheWaste.missCount} misses`;
				const detail = `${cacheWaste.missedTokens.toLocaleString()} tokens, ${missLabel}`;
				info +=
					cacheWaste.missedCost >= 0.0001
						? `\n${theme.fg("dim", "Cache Re-billed (included):")} $${cacheWaste.missedCost.toFixed(3)} ${theme.fg("dim", `(${detail})`)}`
						: `\n${theme.fg("dim", "Cache Re-billed (included):")} ${detail}`;
			}
		}

		this.appendCommandOutput(info);
	}

	handleContextCommand(): void {
		this.appendCommandOutput(formatContextBreakdown(this.session.getContextBreakdown()));
	}

	handleAgentsCommand(): void {
		this.appendCommandOutput(this.session.agentThreadManager.formatSpecs());
	}

	handleAgentCommand(text: string): void {
		const args = text.replace(/^\/agent\s*/, "").trim();
		const manager = this.session.agentThreadManager;
		let info: string;
		if (!args) {
			info = manager.formatRuns();
		} else if (args.startsWith("stop ")) {
			const id = args.slice(5).trim() || "latest";
			const stopped = manager.stopRun(id);
			info = stopped ? manager.formatRun(stopped) : `Agent thread not found: ${id}`;
		} else {
			const run = manager.getRun(args || "latest");
			info = run ? manager.formatRun(run) : `Agent thread not found: ${args}`;
		}
		this.appendCommandOutput(info);
	}

	async handleSpawnCommand(text: string): Promise<void> {
		const raw = text.replace(/^\/spawn\s*/, "").trim();
		if (!raw) {
			this.showWarning("Usage: /spawn <explorer|planner|operator|verifier|reverser> <task>");
			return;
		}
		const manager = this.session.agentThreadManager;
		const specs = new Set(manager.listSpecs().map((spec) => spec.name));
		const [first, ...rest] = raw.split(/\s+/);
		const specName = specs.has(first) ? first : "explorer";
		const task = specs.has(first) ? rest.join(" ").trim() : raw;
		if (!task) {
			this.showWarning("Usage: /spawn <spec> <task>");
			return;
		}
		try {
			const manifest = await manager.spawnThread({ specName, task });
			this.appendCommandOutput(manager.formatSpawned(manifest));
		} catch (error) {
			this.showError(error instanceof Error ? error.message : String(error));
		}
	}

	handleMergeCommand(text: string): void {
		const id = text.replace(/^\/merge\s*/, "").trim() || "latest";
		const merged = this.session.agentThreadManager.mergeRun(id);
		this.appendCommandOutput(merged ? merged.text : `Agent thread not found: ${id}`);
	}

	async handleMcpCommand(text: string): Promise<void> {
		const args = text.replace(/^\/mcp\s*/, "").trim();
		const manager = this.session.mcpManager;
		try {
			let info: string;
			if (!args || args === "config" || args === "status") {
				info = manager.formatConfig();
			} else if (args === "list" || args === "tools" || args === "probe") {
				info = manager.formatProbeResults(await manager.probeAll());
				const count = await this.session.refreshMcpToolDefinitions();
				info += `\nregistered_runtime_tools=${count}`;
			} else if (args.startsWith("search ")) {
				const [, serverId, ...queryParts] = args.split(/\s+/);
				const result = await manager.searchTools(serverId ?? "", queryParts.join(" "));
				info = manager.formatToolSearchResult(result);
			} else if (args.startsWith("resources ")) {
				const [, serverId] = args.split(/\s+/);
				info = manager.formatResources(await manager.listResources(serverId ?? ""));
			} else if (args.startsWith("read ") || args.startsWith("resource ") || args.startsWith("read-resource ")) {
				const [subcommand, serverId, ...uriParts] = args.split(/\s+/);
				const result = await manager.readResource(serverId ?? "", uriParts.join(" "));
				info = manager.formatToolResult(result, `MCP ${subcommand}`);
			} else if (args.startsWith("prompts ")) {
				const [, serverId] = args.split(/\s+/);
				info = manager.formatPrompts(await manager.listPrompts(serverId ?? ""));
			} else if (args.startsWith("prompt ") || args.startsWith("get-prompt ")) {
				const [subcommand, serverId, promptName, ...jsonParts] = args.split(/\s+/);
				const jsonText = jsonParts.join(" ").trim();
				const promptArgs = jsonText ? JSON.parse(jsonText) : {};
				const result = await manager.getPrompt(serverId ?? "", promptName ?? "", promptArgs);
				info = manager.formatToolResult(result, `MCP ${subcommand}`);
			} else if (args.startsWith("auth-info ") || args.startsWith("auth ")) {
				const [, serverId] = args.split(/\s+/);
				info = manager.formatAuthInfo(await manager.inspectAuth(serverId ?? ""));
			} else {
				info = manager.formatProbeResults([await manager.probeServer(args)]);
				const count = await this.session.refreshMcpToolDefinitions();
				info += `\nregistered_runtime_tools=${count}`;
			}
			this.appendCommandOutput(info);
		} catch (error) {
			this.showError(error instanceof Error ? error.message : String(error));
		}
	}

	handleChangelogCommand(): void {
		if (IS_REPI_PRODUCT) {
			this.chatContainer.addChild(new Spacer(1));
			this.chatContainer.addChild(new DynamicBorder());
			this.chatContainer.addChild(new Text(theme.bold(theme.fg("accent", "REPI Changelog")), 1, 0));
			this.chatContainer.addChild(new Spacer(1));
			this.chatContainer.addChild(
				new Text("repi is served from this repository. Use git log or README.md for local release notes.", 1, 1),
			);
			this.chatContainer.addChild(new DynamicBorder());
			this.ui.requestRender();
			return;
		}

		const allEntries = parseChangelog(getChangelogPath());
		const changelogMarkdown =
			allEntries.length > 0
				? allEntries
						.reverse()
						.map((entry) => entry.content)
						.join("\n\n")
				: "No changelog entries found.";

		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(new DynamicBorder());
		this.chatContainer.addChild(new Text(theme.bold(theme.fg("accent", "What's New")), 1, 0));
		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(new Markdown(changelogMarkdown, 1, 1, this.getMarkdownThemeWithSettings()));
		this.chatContainer.addChild(new DynamicBorder());
		this.ui.requestRender();
	}

	private getAppKeyDisplay(action: AppKeybinding): string {
		return keyDisplayText(action);
	}

	private getEditorKeyDisplay(action: Keybinding): string {
		return keyDisplayText(action);
	}

	handleHotkeysCommand(): void {
		const cursorUp = this.getEditorKeyDisplay("tui.editor.cursorUp");
		const cursorDown = this.getEditorKeyDisplay("tui.editor.cursorDown");
		const cursorLeft = this.getEditorKeyDisplay("tui.editor.cursorLeft");
		const cursorRight = this.getEditorKeyDisplay("tui.editor.cursorRight");
		const cursorWordLeft = this.getEditorKeyDisplay("tui.editor.cursorWordLeft");
		const cursorWordRight = this.getEditorKeyDisplay("tui.editor.cursorWordRight");
		const cursorLineStart = this.getEditorKeyDisplay("tui.editor.cursorLineStart");
		const cursorLineEnd = this.getEditorKeyDisplay("tui.editor.cursorLineEnd");
		const jumpForward = this.getEditorKeyDisplay("tui.editor.jumpForward");
		const jumpBackward = this.getEditorKeyDisplay("tui.editor.jumpBackward");
		const pageUp = this.getEditorKeyDisplay("tui.editor.pageUp");
		const pageDown = this.getEditorKeyDisplay("tui.editor.pageDown");

		const submit = this.getEditorKeyDisplay("tui.input.submit");
		const newLine = this.getEditorKeyDisplay("tui.input.newLine");
		const deleteWordBackward = this.getEditorKeyDisplay("tui.editor.deleteWordBackward");
		const deleteWordForward = this.getEditorKeyDisplay("tui.editor.deleteWordForward");
		const deleteToLineStart = this.getEditorKeyDisplay("tui.editor.deleteToLineStart");
		const deleteToLineEnd = this.getEditorKeyDisplay("tui.editor.deleteToLineEnd");
		const yank = this.getEditorKeyDisplay("tui.editor.yank");
		const yankPop = this.getEditorKeyDisplay("tui.editor.yankPop");
		const undo = this.getEditorKeyDisplay("tui.editor.undo");
		const tab = this.getEditorKeyDisplay("tui.input.tab");

		const interrupt = this.getAppKeyDisplay("app.interrupt");
		const clear = this.getAppKeyDisplay("app.clear");
		const exit = this.getAppKeyDisplay("app.exit");
		const suspend = this.getAppKeyDisplay("app.suspend");
		const cycleThinkingLevel = this.getAppKeyDisplay("app.thinking.cycle");
		const cycleModelForward = this.getAppKeyDisplay("app.model.cycleForward");
		const selectModel = this.getAppKeyDisplay("app.model.select");
		const expandTools = this.getAppKeyDisplay("app.tools.expand");
		const toggleThinking = this.getAppKeyDisplay("app.thinking.toggle");
		const externalEditor = this.getAppKeyDisplay("app.editor.external");
		const cycleModelBackward = this.getAppKeyDisplay("app.model.cycleBackward");
		const followUp = this.getAppKeyDisplay("app.message.followUp");
		const dequeue = this.getAppKeyDisplay("app.message.dequeue");
		const pasteImage = this.getAppKeyDisplay("app.clipboard.pasteImage");

		let hotkeys = `
**Navigation**
| Key | Action |
|-----|--------|
| \`${cursorUp}\` / \`${cursorDown}\` / \`${cursorLeft}\` / \`${cursorRight}\` | Move cursor / browse history (Up when empty) |
| \`${cursorWordLeft}\` / \`${cursorWordRight}\` | Move by word |
| \`${cursorLineStart}\` | Start of line |
| \`${cursorLineEnd}\` | End of line |
| \`${jumpForward}\` | Jump forward to character |
| \`${jumpBackward}\` | Jump backward to character |
| \`${pageUp}\` / \`${pageDown}\` | Scroll by page |

**Editing**
| Key | Action |
|-----|--------|
| \`${submit}\` | Send message |
| \`${newLine}\` | New line${process.platform === "win32" ? " (Ctrl+Enter on Windows Terminal)" : ""} |
| \`${deleteWordBackward}\` | Delete word backwards |
| \`${deleteWordForward}\` | Delete word forwards |
| \`${deleteToLineStart}\` | Delete to start of line |
| \`${deleteToLineEnd}\` | Delete to end of line |
| \`${yank}\` | Paste the most-recently-deleted text |
| \`${yankPop}\` | Cycle through the deleted text after pasting |
| \`${undo}\` | Undo |

**Other**
| Key | Action |
|-----|--------|
| \`${tab}\` | Path completion / accept autocomplete |
| \`${interrupt}\` | Cancel autocomplete / abort streaming |
| \`${clear}\` | Clear editor (first) / exit (second) |
| \`${exit}\` | Exit (when editor is empty) |
| \`${suspend}\` | Suspend to background |
| \`${cycleThinkingLevel}\` | Cycle thinking level |
| \`${cycleModelForward}\` / \`${cycleModelBackward}\` | Cycle models |
| \`${selectModel}\` | Open model selector |
| \`${expandTools}\` | Toggle tool output expansion |
| \`${toggleThinking}\` | Toggle thinking block visibility |
| \`${externalEditor}\` | Edit message in external editor |
| \`${followUp}\` | Queue follow-up message |
| \`${dequeue}\` | Restore queued messages |
| \`${pasteImage}\` | Paste image from clipboard |
| \`/\` | Slash commands |
| \`!\` | Run bash command |
| \`!!\` | Run bash command (excluded from context) |
`;

		const shortcuts = this.session.extensionRunner.getShortcuts(this.keybindings.getEffectiveConfig());
		if (shortcuts.size > 0) {
			hotkeys += `
**Extensions**
| Key | Action |
|-----|--------|
`;
			for (const [key, shortcut] of shortcuts) {
				const description = shortcut.description ?? shortcut.extensionPath;
				const keyDisplay = formatKeyText(key, { capitalize: true });
				hotkeys += `| \`${keyDisplay}\` | ${description} |\n`;
			}
		}

		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(new DynamicBorder());
		this.chatContainer.addChild(new Text(theme.bold(theme.fg("accent", "Keyboard Shortcuts")), 1, 0));
		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(new Markdown(hotkeys.trim(), 1, 1, this.getMarkdownThemeWithSettings()));
		this.chatContainer.addChild(new DynamicBorder());
		this.ui.requestRender();
	}

	async handleClearCommand(): Promise<void> {
		const loadingAnimation = this.loadingAnimation;
		if (loadingAnimation) {
			loadingAnimation.stop();
			this.loadingAnimation = undefined;
		}
		this.statusContainer.clear();
		try {
			const result = await this.runtimeHost.newSession();
			if (result.cancelled) return;
			this.renderCurrentSessionState();
			this.chatContainer.addChild(new Spacer(1));
			this.chatContainer.addChild(new Text(`${theme.fg("accent", "✓ New session started")}`, 1, 1));
			this.ui.requestRender();
		} catch (error: unknown) {
			await this.handleFatalRuntimeError("Failed to create session", error);
		}
	}

	handleDebugCommand(): void {
		const width = this.ui.terminal.columns;
		const height = this.ui.terminal.rows;
		const allLines = this.ui.render(width);
		const debugLogPath = getDebugLogPath();
		const debugData = [
			`Debug output at ${new Date().toISOString()}`,
			`Terminal: ${width}x${height}`,
			`Total lines: ${allLines.length}`,
			"",
			"=== All rendered lines with visible widths ===",
			...allLines.map((line, index) => `[${index}] (w=${visibleWidth(line)}) ${JSON.stringify(line)}`),
			"",
			"=== Agent messages (JSONL) ===",
			...this.session.messages.map((message) => JSON.stringify(message)),
			"",
		].join("\n");

		fs.mkdirSync(path.dirname(debugLogPath), { recursive: true });
		fs.writeFileSync(debugLogPath, debugData);
		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(
			new Text(`${theme.fg("accent", "✓ Debug log written")}\n${theme.fg("muted", debugLogPath)}`, 1, 1),
		);
		this.ui.requestRender();
	}

	handleArminSaysHi(): void {
		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(new ArminComponent(this.ui));
		this.ui.requestRender();
	}

	handleDementedDelves(): void {
		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(new EarendilAnnouncementComponent());
		this.ui.requestRender();
	}

	async handleBashCommand(command: string, excludeFromContext = false): Promise<void> {
		const eventResult = await this.session.extensionRunner.emitUserBash({
			type: "user_bash",
			command,
			excludeFromContext,
			cwd: this.sessionManager.getCwd(),
		});

		if (eventResult?.result) {
			const result = eventResult.result;
			const component = new BashExecutionComponent(command, this.ui, excludeFromContext);
			this.bashComponent = component;
			if (this.session.isStreaming) {
				this.pendingMessagesContainer.addChild(component);
				this.pendingBashComponents.push(component);
			} else {
				this.chatContainer.addChild(component);
			}
			if (result.output) component.appendOutput(result.output);
			component.setComplete(
				result.exitCode,
				result.cancelled,
				result.truncated ? ({ truncated: true, content: result.output } as TruncationResult) : undefined,
				result.fullOutputPath,
			);
			this.session.recordBashResult(command, result, { excludeFromContext });
			this.bashComponent = undefined;
			this.ui.requestRender();
			return;
		}

		const isDeferred = this.session.isStreaming;
		const component = new BashExecutionComponent(command, this.ui, excludeFromContext);
		this.bashComponent = component;
		if (isDeferred) {
			this.pendingMessagesContainer.addChild(component);
			this.pendingBashComponents.push(component);
		} else {
			this.chatContainer.addChild(component);
		}
		this.ui.requestRender();

		try {
			const result = await this.session.executeBash(
				command,
				(chunk) => {
					const activeComponent = this.bashComponent;
					if (activeComponent) {
						activeComponent.appendOutput(chunk);
						this.ui.requestRender();
					}
				},
				{ excludeFromContext, operations: eventResult?.operations },
			);
			const activeComponent = this.bashComponent;
			if (activeComponent) {
				activeComponent.setComplete(
					result.exitCode,
					result.cancelled,
					result.truncated ? ({ truncated: true, content: result.output } as TruncationResult) : undefined,
					result.fullOutputPath,
				);
			}
		} catch (error) {
			this.bashComponent?.setComplete(undefined, false);
			this.showError(`Bash command failed: ${error instanceof Error ? error.message : "Unknown error"}`);
		}

		this.bashComponent = undefined;
		this.ui.requestRender();
	}

	async handleCompactCommand(customInstructions?: string): Promise<void> {
		const messageCount = this.sessionManager.getEntries().filter((entry) => entry.type === "message").length;
		if (messageCount < 2) {
			this.showWarning("Nothing to compact (no messages yet)");
			return;
		}

		const loadingAnimation = this.loadingAnimation;
		if (loadingAnimation) {
			loadingAnimation.stop();
			this.loadingAnimation = undefined;
		}
		this.statusContainer.clear();
		try {
			await this.session.compact(customInstructions);
		} catch {
			// Compaction failures are surfaced through session events.
		}
	}

	private appendCommandOutput(text: string): void {
		this.chatContainer.addChild(new Spacer(1));
		this.chatContainer.addChild(new Text(text, 1, 0));
		this.ui.requestRender();
	}
}

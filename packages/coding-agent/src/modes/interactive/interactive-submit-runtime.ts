type SubmitEditor = {
	onSubmit?: (text: string) => void | Promise<void>;
	setText(text: string): void;
	addToHistory?(text: string): void;
};

type SubmitSession = {
	isBashRunning: boolean;
	isCompacting: boolean;
	isStreaming: boolean;
	isRetrying: boolean;
	prompt(text: string, options?: { streamingBehavior?: "steer" }): Promise<unknown>;
};

export type InteractiveSubmitHost = {
	defaultEditor: SubmitEditor;
	editor: SubmitEditor;
	session: SubmitSession;
	ui: { requestRender(): void };
	onInputCallback?: (text: string) => void;
	pendingUserInputs: string[];
	isBashMode: boolean;
	showSettingsSelector(): void;
	showModelsSelector(): Promise<void>;
	handleModelCommand(searchTerm?: string): Promise<void>;
	handleExportCommand(text: string): Promise<void>;
	handleImportCommand(text: string): Promise<void>;
	handleShareCommand(): Promise<void>;
	handleCopyCommand(): Promise<void>;
	handleNameCommand(text: string): void;
	handleSessionCommand(): void;
	handleContextCommand(): void;
	handleAgentsCommand(): void;
	handleAgentCommand(text: string): void;
	handleSpawnCommand(text: string): Promise<void>;
	handleMergeCommand(text: string): void;
	handleMcpCommand(text: string): Promise<void>;
	handleChangelogCommand(): void;
	handleHotkeysCommand(): void;
	showUserMessageSelector(): void;
	showSessionSelector(): void;
	handleCloneCommand(): Promise<void>;
	showTreeSelector(): void;
	showTrustSelector(): void;
	showOAuthSelector(mode: "login" | "logout"): void;
	handleClearCommand(): Promise<void>;
	handleCompactCommand(customInstructions?: string): Promise<void>;
	handleReloadCommand(): Promise<void>;
	handleDebugCommand(): void;
	handleArminSaysHi(): void;
	handleDementedDelves(): void;
	shutdown(): Promise<void>;
	showWarning(message: string): void;
	handleBashCommand(command: string, excludeFromContext?: boolean): Promise<void>;
	updateEditorBorderColor(): void;
	isExtensionCommand(text: string): boolean;
	queueCompactionMessage(text: string, mode: "steer" | "followUp"): void;
	updatePendingMessagesDisplay(): void;
	flushPendingBashComponents(): void;
};

/** Install the single input boundary used by the interactive editor. */
export function installInteractiveSubmitHandler(host: InteractiveSubmitHost): void {
	host.defaultEditor.onSubmit = async (input: string) => {
		const text = input.trim();
		if (!text) return;

		if (text === "/settings") {
			host.showSettingsSelector();
			host.editor.setText("");
			return;
		}
		if (text === "/scoped-models") {
			host.editor.setText("");
			await host.showModelsSelector();
			return;
		}
		if (text === "/model" || text.startsWith("/model ")) {
			const searchTerm = text.startsWith("/model ") ? text.slice(7).trim() : undefined;
			host.editor.setText("");
			await host.handleModelCommand(searchTerm);
			return;
		}
		if (text === "/export" || text.startsWith("/export ")) {
			await host.handleExportCommand(text);
			host.editor.setText("");
			return;
		}
		if (text === "/import" || text.startsWith("/import ")) {
			await host.handleImportCommand(text);
			host.editor.setText("");
			return;
		}
		if (text === "/share") {
			await host.handleShareCommand();
			host.editor.setText("");
			return;
		}
		if (text === "/copy") {
			await host.handleCopyCommand();
			host.editor.setText("");
			return;
		}
		if (text === "/name" || text.startsWith("/name ")) {
			host.handleNameCommand(text);
			host.editor.setText("");
			return;
		}
		if (text === "/session") {
			host.handleSessionCommand();
			host.editor.setText("");
			return;
		}
		if (text === "/context") {
			host.handleContextCommand();
			host.editor.setText("");
			return;
		}
		if (text === "/agents") {
			host.handleAgentsCommand();
			host.editor.setText("");
			return;
		}
		if (text === "/agent" || text.startsWith("/agent ")) {
			host.handleAgentCommand(text);
			host.editor.setText("");
			return;
		}
		if (text === "/spawn" || text.startsWith("/spawn ")) {
			host.editor.setText("");
			await host.handleSpawnCommand(text);
			return;
		}
		if (text === "/merge" || text.startsWith("/merge ")) {
			host.handleMergeCommand(text);
			host.editor.setText("");
			return;
		}
		if (text === "/mcp" || text.startsWith("/mcp ")) {
			host.editor.setText("");
			await host.handleMcpCommand(text);
			return;
		}
		if (text === "/changelog") {
			host.handleChangelogCommand();
			host.editor.setText("");
			return;
		}
		if (text === "/hotkeys") {
			host.handleHotkeysCommand();
			host.editor.setText("");
			return;
		}
		if (text === "/fork") {
			host.showUserMessageSelector();
			host.editor.setText("");
			return;
		}
		if (text === "/clone") {
			host.editor.setText("");
			await host.handleCloneCommand();
			return;
		}
		if (text === "/tree") {
			host.showTreeSelector();
			host.editor.setText("");
			return;
		}
		if (text === "/trust") {
			host.showTrustSelector();
			host.editor.setText("");
			return;
		}
		if (text === "/login") {
			host.showOAuthSelector("login");
			host.editor.setText("");
			return;
		}
		if (text === "/logout") {
			host.showOAuthSelector("logout");
			host.editor.setText("");
			return;
		}
		if (text === "/new") {
			host.editor.setText("");
			await host.handleClearCommand();
			return;
		}
		if (text === "/compact" || text.startsWith("/compact ")) {
			const customInstructions = text.startsWith("/compact ") ? text.slice(9).trim() : undefined;
			host.editor.setText("");
			await host.handleCompactCommand(customInstructions);
			return;
		}
		if (text === "/reload") {
			host.editor.setText("");
			await host.handleReloadCommand();
			return;
		}
		if (text === "/debug") {
			host.handleDebugCommand();
			host.editor.setText("");
			return;
		}
		if (text === "/arminsayshi") {
			host.handleArminSaysHi();
			host.editor.setText("");
			return;
		}
		if (text === "/dementedelves") {
			host.handleDementedDelves();
			host.editor.setText("");
			return;
		}
		if (text === "/resume") {
			host.showSessionSelector();
			host.editor.setText("");
			return;
		}
		if (text === "/quit") {
			host.editor.setText("");
			await host.shutdown();
			return;
		}

		if (text.startsWith("!")) {
			const isExcluded = text.startsWith("!!");
			const command = isExcluded ? text.slice(2).trim() : text.slice(1).trim();
			if (command) {
				if (host.session.isBashRunning) {
					host.showWarning("A bash command is already running. Press Esc to cancel it first.");
					host.editor.setText(text);
					return;
				}
				host.editor.addToHistory?.(text);
				await host.handleBashCommand(command, isExcluded);
				host.isBashMode = false;
				host.updateEditorBorderColor();
				return;
			}
		}

		if (host.session.isCompacting) {
			if (host.isExtensionCommand(text)) {
				host.editor.addToHistory?.(text);
				host.editor.setText("");
				await host.session.prompt(text);
			} else {
				host.queueCompactionMessage(text, "steer");
			}
			return;
		}

		if (host.session.isStreaming || host.session.isRetrying) {
			host.editor.addToHistory?.(text);
			host.editor.setText("");
			await host.session.prompt(text, { streamingBehavior: "steer" });
			host.updatePendingMessagesDisplay();
			host.ui.requestRender();
			return;
		}

		host.flushPendingBashComponents();
		if (host.onInputCallback) {
			host.onInputCallback(text);
		} else {
			host.pendingUserInputs.push(text);
		}
		host.editor.addToHistory?.(text);
	};
}

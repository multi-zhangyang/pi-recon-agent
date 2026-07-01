import { Editor, type EditorOptions, type EditorTheme, type TUI } from "@pi-recon/repi-tui";
import type { AppKeybinding, KeybindingsManager } from "../../../core/keybindings.ts";

/**
 * Custom editor that handles app-level keybindings for coding-agent.
 */
export class CustomEditor extends Editor {
	private keybindings: KeybindingsManager;
	public actionHandlers: Map<AppKeybinding, () => void> = new Map();

	// Special handlers that can be dynamically replaced
	public onEscape?: () => void;
	public onCtrlD?: () => void;
	public onPasteImage?: () => void;
	/** Handler for extension-registered shortcuts. Returns true if handled. */
	public onExtensionShortcut?: (data: string) => boolean;
	/**
	 * Foundational opt #142: error sink for app action handlers. The repo has NO
	 * global unhandledRejection handler, and interactive-mode's terminalErrorHandler
	 * (`uncaughtCrash`) only handles `uncaughtException` — so an ASYNC action
	 * handler (e.g. handleFollowUp → session.prompt which re-throws on expired
	 * auth / extension-input-handler throw) whose rejection is dropped at the
	 * dispatch boundary became an `unhandledRejection` that crashes the process
	 * WITHOUT restoring the terminal (raw mode stuck, cursor hidden). A SYNC
	 * throw in a handler became an `uncaughtException` → `uncaughtCrash` exits the
	 * whole session for one transient throw. runHandler() contains BOTH at the
	 * dispatch boundary: try/catch for sync throws + .catch on a returned
	 * thenable for async rejections, routing to this sink (mirrors the already-
	 * guarded extension-shortcut path, interactive-mode.ts ~1764). If unset,
	 * errors fall back to console.error so they never escape unhandled.
	 */
	public onActionError?: (error: unknown) => void;

	constructor(tui: TUI, theme: EditorTheme, keybindings: KeybindingsManager, options?: EditorOptions) {
		super(tui, theme, options);
		this.keybindings = keybindings;
	}

	/**
	 * Invoke an app action handler containing BOTH synchronous throws and
	 * asynchronous rejections at the boundary. Without this a single bad handler
	 * could crash the process (unhandledRejection, terminal left in raw mode) or
	 * kill the session (uncaughtException → uncaughtCrash exit). Routes errors to
	 * onActionError (or console.error fallback) so the editor/TUI keep running.
	 */
	private runHandler(handler: () => void): void {
		try {
			const result = handler() as unknown;
			if (result && typeof (result as Promise<unknown>).then === "function") {
				(result as Promise<unknown>).catch((err: unknown) => {
					if (this.onActionError) this.onActionError(err);
					else console.error("CustomEditor async action handler error:", err);
				});
			}
		} catch (err) {
			if (this.onActionError) this.onActionError(err);
			else console.error("CustomEditor action handler error:", err);
		}
	}

	/**
	 * Register a handler for an app action.
	 */
	onAction(action: AppKeybinding, handler: () => void): void {
		this.actionHandlers.set(action, handler);
	}

	handleInput(data: string): void {
		// Check extension-registered shortcuts first
		if (this.onExtensionShortcut?.(data)) {
			return;
		}

		// Check for paste image keybinding
		if (this.keybindings.matches(data, "app.clipboard.pasteImage")) {
			if (this.onPasteImage) this.runHandler(this.onPasteImage);
			return;
		}

		// Check app keybindings first

		// Escape/interrupt - only if autocomplete is NOT active
		if (this.keybindings.matches(data, "app.interrupt")) {
			if (!this.isShowingAutocomplete()) {
				// Use dynamic onEscape if set, otherwise registered handler
				const handler = this.onEscape ?? this.actionHandlers.get("app.interrupt");
				if (handler) {
					this.runHandler(handler);
					return;
				}
			}
			// Let parent handle escape for autocomplete cancellation
			super.handleInput(data);
			return;
		}

		// Exit (Ctrl+D) - only when editor is empty
		if (this.keybindings.matches(data, "app.exit")) {
			if (this.getText().length === 0) {
				const handler = this.onCtrlD ?? this.actionHandlers.get("app.exit");
				if (handler) {
					this.runHandler(handler);
					return;
				}
			}
			// Fall through to editor handling for delete-char-forward when not empty
		}

		// Check all other app actions
		for (const [action, handler] of this.actionHandlers) {
			if (action !== "app.interrupt" && action !== "app.exit" && this.keybindings.matches(data, action)) {
				this.runHandler(handler);
				return;
			}
		}

		// Pass to parent for editor handling
		super.handleInput(data);
	}
}

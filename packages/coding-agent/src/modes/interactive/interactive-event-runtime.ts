import type { AgentMessage } from "@pi-recon/repi-agent-core";
import type { AssistantMessage, Message } from "@pi-recon/repi-ai";
import {
	type Container,
	type EditorComponent,
	Loader,
	type MarkdownTheme,
	Spacer,
	Text,
	type TUI,
} from "@pi-recon/repi-tui";
import { CONFIG_DIR_NAME } from "../../config.ts";
import { type AgentSession, type AgentSessionEvent, parseSkillBlock } from "../../core/agent-session.ts";
import { CACHE_TTL_MS, type CacheMiss, collectCacheMisses, detectCacheMiss } from "../../core/cache-stats.ts";
import { createCompactionSummaryMessage } from "../../core/messages.ts";
import { theme } from "../../core/presentation/theme-runtime.ts";
import type { SessionContext, SessionManager } from "../../core/session-manager.ts";
import type { SettingsManager } from "../../core/settings-manager.ts";
import type { TruncationResult } from "../../core/tools/truncate.ts";
import { hasProjectTrustInputs } from "../../core/trust-manager.ts";
import { AssistantMessageComponent } from "./components/assistant-message.ts";
import { BashExecutionComponent } from "./components/bash-execution.ts";
import { BranchSummaryMessageComponent } from "./components/branch-summary-message.ts";
import { CompactionSummaryMessageComponent } from "./components/compaction-summary-message.ts";
import { CountdownTimer } from "./components/countdown-timer.ts";
import type { CustomEditor } from "./components/custom-editor.ts";
import { CustomMessageComponent } from "./components/custom-message.ts";
import { type FooterComponent, formatTokens } from "./components/footer.ts";
import { keyText } from "./components/keybinding-hints.ts";
import { SkillInvocationMessageComponent } from "./components/skill-invocation-message.ts";
import { ToolExecutionComponent } from "./components/tool-execution.ts";
import { UserMessageComponent } from "./components/user-message.ts";

export type InteractiveEventHost = {
	isInitialized: boolean;
	ui: TUI;
	chatContainer: Container;
	statusContainer: Container;
	defaultEditor: CustomEditor;
	editor: EditorComponent;
	footer: FooterComponent;
	session: AgentSession;
	sessionManager: SessionManager;
	settingsManager: SettingsManager;
	loadingAnimation?: Loader;
	workingVisible: boolean;
	hiddenThinkingLabel: string;
	hideThinkingBlock: boolean;
	lastStatusSpacer?: Spacer;
	lastStatusText?: Text;
	streamingComponent?: AssistantMessageComponent;
	streamingMessage?: AssistantMessage;
	pendingTools: Map<string, ToolExecutionComponent>;
	toolOutputExpanded: boolean;
	autoCompactionLoader?: Loader;
	autoCompactionEscapeHandler?: () => void;
	retryLoader?: Loader;
	retryCountdown?: CountdownTimer;
	retryEscapeHandler?: () => void;
	init(): Promise<void>;
	stopWorkingLoader(): void;
	createWorkingLoader(): Loader;
	updatePendingMessagesDisplay(): void;
	updateTerminalTitle(): void;
	updateEditorBorderColor(): void;
	getMarkdownThemeWithSettings(): MarkdownTheme;
	getRegisteredToolDefinition(toolName: string): ReturnType<AgentSession["getToolDefinition"]>;
	checkShutdownRequested(): Promise<void>;
	showError(message: string): void;
	rebuildChatFromMessages(): void;
	flushCompactionQueue(options?: { willRetry?: boolean }): Promise<void>;
	clearPendingTools(): void;
	clearPendingBashComponents(): void;
};

export async function handleInteractiveEvent(host: InteractiveEventHost, event: AgentSessionEvent): Promise<void> {
	if (!host.isInitialized) {
		await host.init();
	}

	host.footer.invalidate();

	switch (event.type) {
		case "agent_start":
			host.pendingTools.clear();
			if (host.settingsManager.getShowTerminalProgress()) {
				host.ui.terminal.setProgress(true);
			}
			// Restore main escape handler if retry handler is still active
			// (retry success event fires later, but we need main handler now)
			if (host.retryEscapeHandler) {
				host.defaultEditor.onEscape = host.retryEscapeHandler;
				host.retryEscapeHandler = undefined;
			}
			if (host.retryCountdown) {
				host.retryCountdown.dispose();
				host.retryCountdown = undefined;
			}
			if (host.retryLoader) {
				host.retryLoader.stop();
				host.retryLoader = undefined;
			}
			host.stopWorkingLoader();
			if (host.workingVisible) {
				host.loadingAnimation = host.createWorkingLoader();
				host.statusContainer.addChild(host.loadingAnimation);
			}
			host.ui.requestRender();
			break;

		case "queue_update":
			host.updatePendingMessagesDisplay();
			host.ui.requestRender();
			break;

		case "session_info_changed":
			host.updateTerminalTitle();
			host.footer.invalidate();
			host.ui.requestRender();
			break;

		case "thinking_level_changed":
			host.footer.invalidate();
			host.updateEditorBorderColor();
			break;

		case "message_start":
			if (event.message.role === "custom") {
				addMessageToChat(host, event.message);
				host.ui.requestRender();
			} else if (event.message.role === "user") {
				addMessageToChat(host, event.message);
				host.updatePendingMessagesDisplay();
				host.ui.requestRender();
			} else if (event.message.role === "assistant") {
				host.streamingComponent = new AssistantMessageComponent(
					undefined,
					host.hideThinkingBlock,
					host.getMarkdownThemeWithSettings(),
					host.hiddenThinkingLabel,
				);
				host.streamingMessage = event.message;
				host.chatContainer.addChild(host.streamingComponent);
				host.streamingComponent.updateContent(host.streamingMessage);
				host.ui.requestRender();
			}
			break;

		case "message_update":
			if (host.streamingComponent && event.message.role === "assistant") {
				host.streamingMessage = event.message;
				host.streamingComponent.updateContent(host.streamingMessage);

				for (const content of host.streamingMessage.content) {
					if (content.type === "toolCall") {
						if (!host.pendingTools.has(content.id)) {
							const component = new ToolExecutionComponent(
								content.name,
								content.id,
								content.arguments,
								{
									showImages: host.settingsManager.getShowImages(),
									imageWidthCells: host.settingsManager.getImageWidthCells(),
								},
								host.getRegisteredToolDefinition(content.name),
								host.ui,
								host.sessionManager.getCwd(),
							);
							component.setExpanded(host.toolOutputExpanded);
							host.chatContainer.addChild(component);
							host.pendingTools.set(content.id, component);
						} else {
							const component = host.pendingTools.get(content.id);
							if (component) {
								component.updateArgs(content.arguments);
							}
						}
					}
				}
				host.ui.requestRender();
			}
			break;

		case "message_end":
			if (event.message.role === "user") break;
			if (host.streamingComponent && event.message.role === "assistant") {
				host.streamingMessage = event.message;
				let errorMessage: string | undefined;
				if (host.streamingMessage.stopReason === "aborted") {
					const retryAttempt = host.session.retryAttempt;
					errorMessage =
						retryAttempt > 0
							? `Aborted after ${retryAttempt} retry attempt${retryAttempt > 1 ? "s" : ""}`
							: "Operation aborted";
					host.streamingMessage.errorMessage = errorMessage;
				}
				host.streamingComponent.updateContent(host.streamingMessage);

				if (host.streamingMessage.stopReason === "aborted" || host.streamingMessage.stopReason === "error") {
					if (!errorMessage) {
						errorMessage = host.streamingMessage.errorMessage || "Error";
					}
					for (const [, component] of host.pendingTools.entries()) {
						component.updateResult({
							content: [{ type: "text", text: errorMessage }],
							isError: true,
						});
					}
					host.pendingTools.clear();
				} else {
					// Args are now complete - trigger diff computation for edit tools
					for (const [, component] of host.pendingTools.entries()) {
						component.setArgsComplete();
					}
					maybeShowCacheMissNotice(host, host.streamingMessage);
				}
				host.streamingComponent = undefined;
				host.streamingMessage = undefined;
				host.footer.invalidate();
			}
			host.ui.requestRender();
			break;

		case "tool_execution_start": {
			let component = host.pendingTools.get(event.toolCallId);
			if (!component) {
				component = new ToolExecutionComponent(
					event.toolName,
					event.toolCallId,
					event.args,
					{
						showImages: host.settingsManager.getShowImages(),
						imageWidthCells: host.settingsManager.getImageWidthCells(),
					},
					host.getRegisteredToolDefinition(event.toolName),
					host.ui,
					host.sessionManager.getCwd(),
				);
				component.setExpanded(host.toolOutputExpanded);
				host.chatContainer.addChild(component);
				host.pendingTools.set(event.toolCallId, component);
			}
			component.markExecutionStarted();
			host.ui.requestRender();
			break;
		}

		case "tool_execution_update": {
			const component = host.pendingTools.get(event.toolCallId);
			if (component) {
				component.updateResult({ ...event.partialResult, isError: false }, true);
				host.ui.requestRender();
			}
			break;
		}

		case "tool_execution_end": {
			const component = host.pendingTools.get(event.toolCallId);
			if (component) {
				component.updateResult({ ...event.result, isError: event.isError });
				host.pendingTools.delete(event.toolCallId);
				host.ui.requestRender();
			}
			break;
		}

		case "agent_end":
			if (host.settingsManager.getShowTerminalProgress()) {
				host.ui.terminal.setProgress(false);
			}
			if (host.loadingAnimation) {
				host.loadingAnimation.stop();
				host.loadingAnimation = undefined;
				host.statusContainer.clear();
			}
			if (host.streamingComponent) {
				host.chatContainer.removeChild(host.streamingComponent);
				host.streamingComponent = undefined;
				host.streamingMessage = undefined;
			}
			host.pendingTools.clear();

			host.ui.requestRender();
			break;

		case "agent_settled":
			await host.checkShutdownRequested();
			break;

		case "compaction_start": {
			if (host.settingsManager.getShowTerminalProgress()) {
				host.ui.terminal.setProgress(true);
			}
			// Keep editor active; submissions are queued during compaction.
			host.autoCompactionEscapeHandler = host.defaultEditor.onEscape;
			host.defaultEditor.onEscape = () => {
				host.session.abortCompaction();
			};
			host.statusContainer.clear();
			const cancelHint = `(${keyText("app.interrupt")} to cancel)`;
			const label =
				event.reason === "manual"
					? `Compacting context... ${cancelHint}`
					: `${event.reason === "overflow" ? "Context overflow detected, " : ""}Auto-compacting... ${cancelHint}`;
			host.autoCompactionLoader = new Loader(
				host.ui,
				(spinner) => theme.fg("accent", spinner),
				(text) => theme.fg("muted", text),
				label,
			);
			host.statusContainer.addChild(host.autoCompactionLoader);
			host.ui.requestRender();
			break;
		}

		case "compaction_end": {
			if (host.settingsManager.getShowTerminalProgress()) {
				host.ui.terminal.setProgress(false);
			}
			if (host.autoCompactionEscapeHandler) {
				host.defaultEditor.onEscape = host.autoCompactionEscapeHandler;
				host.autoCompactionEscapeHandler = undefined;
			}
			if (host.autoCompactionLoader) {
				host.autoCompactionLoader.stop();
				host.autoCompactionLoader = undefined;
				host.statusContainer.clear();
			}
			if (event.aborted) {
				if (event.reason === "manual") {
					host.showError("Compaction cancelled");
				} else {
					showInteractiveStatus(host, "Auto-compaction cancelled");
				}
			} else if (event.result) {
				host.chatContainer.clear();
				host.rebuildChatFromMessages();
				addMessageToChat(
					host,
					createCompactionSummaryMessage(
						event.result.summary,
						event.result.tokensBefore,
						new Date().toISOString(),
					),
				);
				host.footer.invalidate();
			} else if (event.errorMessage) {
				if (event.reason === "manual") {
					host.showError(event.errorMessage);
				} else {
					host.chatContainer.addChild(new Spacer(1));
					host.chatContainer.addChild(new Text(theme.fg("error", event.errorMessage), 1, 0));
				}
			}
			void host.flushCompactionQueue({ willRetry: event.willRetry });
			host.ui.requestRender();
			break;
		}

		case "auto_retry_start": {
			// Set up escape to abort retry
			host.retryEscapeHandler = host.defaultEditor.onEscape;
			host.defaultEditor.onEscape = () => {
				host.session.abortRetry();
			};
			// Show retry indicator
			host.statusContainer.clear();
			host.retryCountdown?.dispose();
			const retryMessage = (seconds: number) =>
				`Retrying (${event.attempt}/${event.maxAttempts}) in ${seconds}s... (${keyText("app.interrupt")} to cancel)`;
			host.retryLoader = new Loader(
				host.ui,
				(spinner) => theme.fg("warning", spinner),
				(text) => theme.fg("muted", text),
				retryMessage(Math.ceil(event.delayMs / 1000)),
			);
			host.retryCountdown = new CountdownTimer(
				event.delayMs,
				host.ui,
				(seconds) => {
					host.retryLoader?.setMessage(retryMessage(seconds));
				},
				() => {
					host.retryCountdown = undefined;
				},
			);
			host.statusContainer.addChild(host.retryLoader);
			host.ui.requestRender();
			break;
		}

		case "auto_retry_end": {
			// Restore escape handler
			if (host.retryEscapeHandler) {
				host.defaultEditor.onEscape = host.retryEscapeHandler;
				host.retryEscapeHandler = undefined;
			}
			if (host.retryCountdown) {
				host.retryCountdown.dispose();
				host.retryCountdown = undefined;
			}
			// Stop loader
			if (host.retryLoader) {
				host.retryLoader.stop();
				host.retryLoader = undefined;
				host.statusContainer.clear();
			}
			// Show error only on final failure (success shows normal response)
			if (!event.success) {
				host.showError(`Retry failed after ${event.attempt} attempts: ${event.finalError || "Unknown error"}`);
			}
			host.ui.requestRender();
			break;
		}
	}
}

/** Extract text content from a user message */
function getUserMessageText(message: Message): string {
	if (message.role !== "user") return "";
	const textBlocks =
		typeof message.content === "string"
			? [{ type: "text", text: message.content }]
			: message.content.filter((c: { type: string }) => c.type === "text");
	return textBlocks.map((c) => (c as { text: string }).text).join("");
}

/**
 * Show a status message in the chat.
 *
 * If multiple status messages are emitted back-to-back (without anything else being added to the chat),
 * we update the previous status line instead of appending new ones to avoid log spam.
 */
export function showInteractiveStatus(host: InteractiveEventHost, message: string): void {
	const children = host.chatContainer.children;
	const last = children.length > 0 ? children[children.length - 1] : undefined;
	const secondLast = children.length > 1 ? children[children.length - 2] : undefined;

	if (last && secondLast && last === host.lastStatusText && secondLast === host.lastStatusSpacer) {
		host.lastStatusText.setText(theme.fg("dim", message));
		host.ui.requestRender();
		return;
	}

	const spacer = new Spacer(1);
	const text = new Text(theme.fg("dim", message), 1, 0);
	host.chatContainer.addChild(spacer);
	host.chatContainer.addChild(text);
	host.lastStatusSpacer = spacer;
	host.lastStatusText = text;
	host.ui.requestRender();
}

function addMessageToChat(
	host: InteractiveEventHost,
	message: AgentMessage,
	options?: { populateHistory?: boolean },
): void {
	switch (message.role) {
		case "bashExecution": {
			const component = new BashExecutionComponent(message.command, host.ui, message.excludeFromContext);
			if (message.output) {
				component.appendOutput(message.output);
			}
			component.setComplete(
				message.exitCode,
				message.cancelled,
				message.truncated ? ({ truncated: true } as TruncationResult) : undefined,
				message.fullOutputPath,
			);
			host.chatContainer.addChild(component);
			break;
		}
		case "custom": {
			if (message.display) {
				const renderer = host.session.extensionRunner.getMessageRenderer(message.customType);
				const component = new CustomMessageComponent(message, renderer, host.getMarkdownThemeWithSettings());
				component.setExpanded(host.toolOutputExpanded);
				host.chatContainer.addChild(component);
			}
			break;
		}
		case "compactionSummary": {
			host.chatContainer.addChild(new Spacer(1));
			const component = new CompactionSummaryMessageComponent(message, host.getMarkdownThemeWithSettings());
			component.setExpanded(host.toolOutputExpanded);
			host.chatContainer.addChild(component);
			break;
		}
		case "branchSummary": {
			host.chatContainer.addChild(new Spacer(1));
			const component = new BranchSummaryMessageComponent(message, host.getMarkdownThemeWithSettings());
			component.setExpanded(host.toolOutputExpanded);
			host.chatContainer.addChild(component);
			break;
		}
		case "user": {
			const textContent = getUserMessageText(message);
			if (textContent) {
				if (host.chatContainer.children.length > 0) {
					host.chatContainer.addChild(new Spacer(1));
				}
				const skillBlock = parseSkillBlock(textContent);
				if (skillBlock) {
					// Render skill block (collapsible)
					const component = new SkillInvocationMessageComponent(skillBlock, host.getMarkdownThemeWithSettings());
					component.setExpanded(host.toolOutputExpanded);
					host.chatContainer.addChild(component);
					// Render user message separately if present
					if (skillBlock.userMessage) {
						host.chatContainer.addChild(new Spacer(1));
						const userComponent = new UserMessageComponent(
							skillBlock.userMessage,
							host.getMarkdownThemeWithSettings(),
						);
						host.chatContainer.addChild(userComponent);
					}
				} else {
					const userComponent = new UserMessageComponent(textContent, host.getMarkdownThemeWithSettings());
					host.chatContainer.addChild(userComponent);
				}
				if (options?.populateHistory) {
					host.editor.addToHistory?.(textContent);
				}
			}
			break;
		}
		case "assistant": {
			const assistantComponent = new AssistantMessageComponent(
				message,
				host.hideThinkingBlock,
				host.getMarkdownThemeWithSettings(),
				host.hiddenThinkingLabel,
			);
			host.chatContainer.addChild(assistantComponent);
			break;
		}
		case "toolResult": {
			// Tool results are rendered inline with tool calls, handled separately
			break;
		}
		default: {
			const _exhaustive: never = message;
		}
	}
}

/**
 * Render session context to chat. Used for initial load and rebuild after compaction.
 * @param sessionContext Session context to render
 * @param options.updateFooter Update footer state
 * @param options.populateHistory Add user messages to editor history
 */
export function renderInteractiveSessionContext(
	host: InteractiveEventHost,
	sessionContext: SessionContext,
	options: { updateFooter?: boolean; populateHistory?: boolean } = {},
): void {
	// The chatContainer was cleared by the caller (renderCurrentSessionState /
	// rewind / direct callers) — or this is the initial render with an empty
	// pendingTools — so the pending components are detached. Dispose their
	// render-state intervals (bash 1s elapsed tick) before rebuilding.
	host.clearPendingTools();
	// opt #137: also dispose in-flight bash components (Loader 80ms interval)
	// detached by the caller's chatContainer.clear() and reset their state.
	host.clearPendingBashComponents();
	const renderedPendingTools = new Map<string, ToolExecutionComponent>();
	const cacheMisses = host.settingsManager.getShowCacheMissNotices()
		? collectCacheMisses(host.sessionManager.getEntries(), host.session.modelRegistry)
		: new Map<AssistantMessage, CacheMiss>();

	if (options.updateFooter) {
		host.footer.invalidate();
		host.updateEditorBorderColor();
	}

	for (const message of sessionContext.messages) {
		// Assistant messages need special handling for tool calls
		if (message.role === "assistant") {
			addMessageToChat(host, message);
			// Render tool call components
			for (const content of message.content) {
				if (content.type === "toolCall") {
					const component = new ToolExecutionComponent(
						content.name,
						content.id,
						content.arguments,
						{
							showImages: host.settingsManager.getShowImages(),
							imageWidthCells: host.settingsManager.getImageWidthCells(),
						},
						host.getRegisteredToolDefinition(content.name),
						host.ui,
						host.sessionManager.getCwd(),
					);
					component.setExpanded(host.toolOutputExpanded);
					host.chatContainer.addChild(component);

					if (message.stopReason === "aborted" || message.stopReason === "error") {
						let errorMessage: string;
						if (message.stopReason === "aborted") {
							const retryAttempt = host.session.retryAttempt;
							errorMessage =
								retryAttempt > 0
									? `Aborted after ${retryAttempt} retry attempt${retryAttempt > 1 ? "s" : ""}`
									: "Operation aborted";
						} else {
							errorMessage = message.errorMessage || "Error";
						}
						component.updateResult({ content: [{ type: "text", text: errorMessage }], isError: true });
					} else {
						renderedPendingTools.set(content.id, component);
					}
				}
			}
			if (message.stopReason !== "aborted" && message.stopReason !== "error") {
				const miss = cacheMisses.get(message);
				if (miss) addCacheMissNotice(host, miss);
			}
		} else if (message.role === "toolResult") {
			// Match tool results to pending tool components
			const component = renderedPendingTools.get(message.toolCallId);
			if (component) {
				component.updateResult(message);
				renderedPendingTools.delete(message.toolCallId);
			}
		} else {
			// All other messages use standard rendering
			addMessageToChat(host, message, options);
		}
	}

	for (const [toolCallId, component] of renderedPendingTools) {
		host.pendingTools.set(toolCallId, component);
	}
	host.ui.requestRender();
}

function maybeShowCacheMissNotice(host: InteractiveEventHost, message: AssistantMessage): void {
	if (!host.settingsManager.getShowCacheMissNotices()) return;

	// message_end is forwarded before AgentSession persists this message.
	const miss = detectCacheMiss(host.sessionManager.getEntries(), message, host.session.modelRegistry);
	if (miss) addCacheMissNotice(host, miss);
}

export function addCacheMissNotice(host: InteractiveEventHost, miss: CacheMiss): void {
	if (miss.missedTokens < 20_000 && miss.missedCost < 0.1) return;

	const cost = miss.missedCost >= 0.01 ? ` (~$${miss.missedCost.toFixed(2)})` : "";
	const reBilled = `${formatTokens(miss.missedTokens)} tokens re-billed${cost}`;
	let label = "Cache miss";
	if (miss.modelChanged) {
		label = "Cache miss after model switch";
	} else if (miss.idleMs >= CACHE_TTL_MS) {
		label = `Cache miss after ${Math.round(miss.idleMs / 60_000)}m idle`;
	}
	host.chatContainer.addChild(new Spacer(1));
	host.chatContainer.addChild(new Text(theme.fg("warning", `${label}: ${reBilled}`), 1, 0));
}

export function renderInteractiveInitialMessages(host: InteractiveEventHost): void {
	// Get aligned messages and entries from session context
	const context = host.sessionManager.buildSessionContext();
	renderInteractiveSessionContext(host, context, {
		updateFooter: true,
		populateHistory: true,
	});
	renderProjectTrustWarningIfNeeded(host);

	// Show compaction info if session was compacted
	const allEntries = host.sessionManager.getEntries();
	const compactionCount = allEntries.filter((e) => e.type === "compaction").length;
	if (compactionCount > 0) {
		const times = compactionCount === 1 ? "1 time" : `${compactionCount} times`;
		showInteractiveStatus(host, `Session compacted ${times}`);
	}
}

function renderProjectTrustWarningIfNeeded(host: InteractiveEventHost): void {
	if (host.settingsManager.isProjectTrusted() || !hasProjectTrustInputs(host.sessionManager.getCwd())) {
		return;
	}

	if (host.chatContainer.children.length > 0) {
		host.chatContainer.addChild(new Spacer(1));
	}
	host.chatContainer.addChild(
		new Text(
			theme.fg(
				"warning",
				`This project is not trusted. Project instructions (AGENTS.md/CLAUDE.md), ${CONFIG_DIR_NAME} resources, and project packages are ignored. Use /trust or 'repi trust yes' to save a decision and reload project resources.`,
			),
			1,
			0,
		),
	);
}

import type { Container, EditorComponent, TUI } from "@pi-recon/repi-tui";
import { Spacer, TruncatedText } from "@pi-recon/repi-tui";
import type { AgentSession } from "../../core/agent-session.ts";
import type { AppKeybinding } from "../../core/keybindings.ts";
import { theme } from "../../core/presentation/theme-runtime.ts";
import type { BashExecutionComponent } from "./components/bash-execution.ts";
import type { CustomEditor } from "./components/custom-editor.ts";

export type CompactionQueuedMessage = {
	text: string;
	mode: "steer" | "followUp";
};

type InteractiveEditor = EditorComponent & {
	getExpandedText?: () => string;
	addToHistory?: (text: string) => void;
};

export type InteractiveCompactionHost = {
	session: AgentSession;
	ui: TUI;
	chatContainer: Container;
	pendingMessagesContainer: Container;
	editor: InteractiveEditor;
	defaultEditor: CustomEditor;
	compactionQueuedMessages: CompactionQueuedMessage[];
	pendingBashComponents: BashExecutionComponent[];
	showStatus(message: string): void;
	showError(message: string): void;
	getAppKeyDisplay(action: AppKeybinding): string;
};

async function handleFollowUp(host: InteractiveCompactionHost): Promise<void> {
	const text = (host.editor.getExpandedText?.() ?? host.editor.getText()).trim();
	if (!text) return;

	if (host.session.isCompacting) {
		if (isExtensionCommand(host, text)) {
			host.editor.addToHistory?.(text);
			host.editor.setText("");
			await host.session.prompt(text);
		} else {
			queueCompactionMessage(host, text, "followUp");
		}
		return;
	}

	if (host.session.isStreaming || host.session.isRetrying) {
		host.editor.addToHistory?.(text);
		host.editor.setText("");
		await host.session.prompt(text, { streamingBehavior: "followUp" });
		updatePendingMessagesDisplay(host);
		host.ui.requestRender();
	} else if (host.editor.onSubmit) {
		host.editor.setText("");
		try {
			const ret = host.editor.onSubmit(text) as unknown;
			if (ret && typeof (ret as Promise<unknown>).then === "function") {
				(ret as Promise<unknown>).catch((error: unknown) => host.defaultEditor.onSubmitError?.(error));
			}
		} catch (error) {
			host.defaultEditor.onSubmitError?.(error);
		}
	}
}

function handleDequeue(host: InteractiveCompactionHost): void {
	const restored = restoreQueuedMessagesToEditor(host);
	if (restored === 0) {
		host.showStatus("No queued messages to restore");
	} else {
		host.showStatus(`Restored ${restored} queued message${restored > 1 ? "s" : ""} to editor`);
	}
}

function getAllQueuedMessages(host: InteractiveCompactionHost): { steering: string[]; followUp: string[] } {
	return {
		steering: [
			...host.session.getSteeringMessages(),
			...host.compactionQueuedMessages.filter((message) => message.mode === "steer").map((message) => message.text),
		],
		followUp: [
			...host.session.getFollowUpMessages(),
			...host.compactionQueuedMessages
				.filter((message) => message.mode === "followUp")
				.map((message) => message.text),
		],
	};
}

function clearAllQueues(host: InteractiveCompactionHost): { steering: string[]; followUp: string[] } {
	const { steering, followUp } = host.session.clearQueue();
	const compactionSteering = host.compactionQueuedMessages
		.filter((message) => message.mode === "steer")
		.map((message) => message.text);
	const compactionFollowUp = host.compactionQueuedMessages
		.filter((message) => message.mode === "followUp")
		.map((message) => message.text);
	host.compactionQueuedMessages = [];
	return {
		steering: [...steering, ...compactionSteering],
		followUp: [...followUp, ...compactionFollowUp],
	};
}

function updatePendingMessagesDisplay(host: InteractiveCompactionHost): void {
	host.pendingMessagesContainer.clear();
	const { steering: steeringMessages, followUp: followUpMessages } = getAllQueuedMessages(host);
	if (steeringMessages.length === 0 && followUpMessages.length === 0) return;

	host.pendingMessagesContainer.addChild(new Spacer(1));
	for (const message of steeringMessages) {
		host.pendingMessagesContainer.addChild(new TruncatedText(theme.fg("dim", `Steering: ${message}`), 1, 0));
	}
	for (const message of followUpMessages) {
		host.pendingMessagesContainer.addChild(new TruncatedText(theme.fg("dim", `Follow-up: ${message}`), 1, 0));
	}
	const dequeueHint = host.getAppKeyDisplay("app.message.dequeue");
	host.pendingMessagesContainer.addChild(
		new TruncatedText(theme.fg("dim", `↳ ${dequeueHint} to edit all queued messages`), 1, 0),
	);
}

function restoreQueuedMessagesToEditor(
	host: InteractiveCompactionHost,
	options?: { abort?: boolean; currentText?: string },
): number {
	const { steering, followUp } = clearAllQueues(host);
	const allQueued = [...steering, ...followUp];
	if (allQueued.length === 0) {
		updatePendingMessagesDisplay(host);
		if (options?.abort) host.session.agent.abort();
		return 0;
	}

	const queuedText = allQueued.join("\n\n");
	const currentText = options?.currentText ?? host.editor.getText();
	const combinedText = [queuedText, currentText].filter((text) => text.trim()).join("\n\n");
	host.editor.setText(combinedText);
	updatePendingMessagesDisplay(host);
	if (options?.abort) host.session.agent.abort();
	return allQueued.length;
}

function queueCompactionMessage(host: InteractiveCompactionHost, text: string, mode: "steer" | "followUp"): void {
	host.compactionQueuedMessages.push({ text, mode });
	host.editor.addToHistory?.(text);
	host.editor.setText("");
	updatePendingMessagesDisplay(host);
	host.showStatus("Queued message for after compaction");
}

function isExtensionCommand(host: InteractiveCompactionHost, text: string): boolean {
	if (!text.startsWith("/")) return false;
	const spaceIndex = text.indexOf(" ");
	const commandName = spaceIndex === -1 ? text.slice(1) : text.slice(1, spaceIndex);
	return !!host.session.extensionRunner.getCommand(commandName);
}

async function flushCompactionQueue(host: InteractiveCompactionHost, options?: { willRetry?: boolean }): Promise<void> {
	if (host.compactionQueuedMessages.length === 0) return;

	const queuedMessages = [...host.compactionQueuedMessages];
	host.compactionQueuedMessages = [];
	updatePendingMessagesDisplay(host);

	const restoreQueue = (error: unknown) => {
		host.session.clearQueue();
		host.compactionQueuedMessages = queuedMessages;
		updatePendingMessagesDisplay(host);
		host.showError(
			`Failed to send queued message${queuedMessages.length > 1 ? "s" : ""}: ${
				error instanceof Error ? error.message : String(error)
			}`,
		);
	};

	try {
		if (options?.willRetry) {
			for (const message of queuedMessages) {
				if (isExtensionCommand(host, message.text)) {
					await host.session.prompt(message.text);
				} else if (message.mode === "followUp") {
					await host.session.followUp(message.text);
				} else {
					await host.session.steer(message.text);
				}
			}
			updatePendingMessagesDisplay(host);
			return;
		}

		const firstPromptIndex = queuedMessages.findIndex((message) => !isExtensionCommand(host, message.text));
		if (firstPromptIndex === -1) {
			for (const message of queuedMessages) {
				await host.session.prompt(message.text);
			}
			return;
		}

		const preCommands = queuedMessages.slice(0, firstPromptIndex);
		const firstPrompt = queuedMessages[firstPromptIndex];
		const rest = queuedMessages.slice(firstPromptIndex + 1);

		for (const message of preCommands) {
			await host.session.prompt(message.text);
		}

		const promptPromise = host.session
			.prompt(firstPrompt.text, { streamingBehavior: firstPrompt.mode })
			.catch((error) => {
				restoreQueue(error);
			});

		for (const message of rest) {
			if (isExtensionCommand(host, message.text)) {
				await host.session.prompt(message.text);
			} else if (message.mode === "followUp") {
				await host.session.followUp(message.text);
			} else {
				await host.session.steer(message.text);
			}
		}
		updatePendingMessagesDisplay(host);
		void promptPromise;
	} catch (error) {
		restoreQueue(error);
	}
}

function flushPendingBashComponents(host: InteractiveCompactionHost): void {
	for (const component of host.pendingBashComponents) {
		host.pendingMessagesContainer.removeChild(component);
		host.chatContainer.addChild(component);
	}
	host.pendingBashComponents = [];
}

export const interactiveCompactionRuntime = {
	handleFollowUp,
	handleDequeue,
	updatePendingMessagesDisplay,
	restoreQueuedMessagesToEditor,
	queueCompactionMessage,
	isExtensionCommand,
	flushCompactionQueue,
	flushPendingBashComponents,
};

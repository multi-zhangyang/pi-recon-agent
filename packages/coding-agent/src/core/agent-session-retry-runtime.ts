import { type Agent, type AgentMessage, isRetryableAgentError } from "@pi-recon/repi-agent-core";
import type { AssistantMessage, Model } from "@pi-recon/repi-ai";
import { sleep } from "../utils/sleep.ts";
import type { SettingsManager } from "./settings-manager.ts";

export type AgentSessionRetryEvent =
	| { type: "auto_retry_start"; attempt: number; maxAttempts: number; delayMs: number; errorMessage: string }
	| { type: "auto_retry_end"; success: boolean; attempt: number; finalError?: string };

export interface AgentSessionRetryHost {
	readonly agent: Agent;
	readonly settingsManager: SettingsManager;
	readonly model: Model<any> | undefined;
	emit(event: AgentSessionRetryEvent): void;
}

export class AgentSessionRetryRuntime {
	private readonly host: AgentSessionRetryHost;
	private abortController: AbortController | undefined;
	private attempt = 0;

	constructor(host: AgentSessionRetryHost) {
		this.host = host;
	}

	get retryAttempt(): number {
		return this.attempt;
	}

	get isRetrying(): boolean {
		return this.abortController !== undefined;
	}

	get enabled(): boolean {
		return this.host.settingsManager.getRetryEnabled();
	}

	setEnabled(enabled: boolean): void {
		this.host.settingsManager.setRetryEnabled(enabled);
	}

	abort(): void {
		if (this.abortController) {
			this.abortController.abort();
			return;
		}
		if (this.attempt > 0) this.host.agent.abort();
	}

	finishSuccess(): void {
		if (this.attempt === 0) return;
		this.host.emit({ type: "auto_retry_end", success: true, attempt: this.attempt });
		this.attempt = 0;
	}

	finishFailure(finalError?: string): void {
		if (this.attempt === 0) return;
		this.host.emit({
			type: "auto_retry_end",
			success: false,
			attempt: this.attempt,
			finalError,
		});
		this.attempt = 0;
	}

	willRetry(messages: readonly AgentMessage[]): boolean {
		const settings = this.host.settingsManager.getRetrySettings();
		if (!settings.enabled || this.attempt >= settings.maxRetries) return false;
		for (let index = messages.length - 1; index >= 0; index--) {
			const message = messages[index];
			if (message.role === "assistant") return this.isRetryableError(message as AssistantMessage);
		}
		return false;
	}

	isRetryableError(message: AssistantMessage): boolean {
		return isRetryableAgentError(message, { contextWindow: this.host.model?.contextWindow });
	}

	async prepareRetry(message: AssistantMessage): Promise<boolean> {
		const settings = this.host.settingsManager.getRetrySettings();
		if (!settings.enabled) return false;

		this.attempt++;
		if (this.attempt > settings.maxRetries) {
			this.attempt--;
			return false;
		}

		const delayMs = settings.baseDelayMs * 2 ** (this.attempt - 1);
		const controller = new AbortController();
		this.abortController = controller;
		this.host.emit({
			type: "auto_retry_start",
			attempt: this.attempt,
			maxAttempts: settings.maxRetries,
			delayMs,
			errorMessage: message.errorMessage || "Unknown error",
		});

		try {
			await sleep(delayMs, controller.signal);
		} catch {
			const attempt = this.attempt;
			this.attempt = 0;
			this.host.emit({
				type: "auto_retry_end",
				success: false,
				attempt,
				finalError: "Retry cancelled",
			});
			return false;
		} finally {
			this.abortController = undefined;
		}

		const messages = this.host.agent.state.messages;
		if (messages.at(-1)?.role === "assistant") {
			this.host.agent.state.messages = messages.slice(0, -1);
		}
		return true;
	}
}

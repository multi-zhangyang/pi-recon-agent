/**
 * Session tree navigation runtime.
 *
 * AgentSession owns the live agent and extension runner. This runtime owns the
 * tree transition, branch-summary request, and cancellation state so the
 * session lifecycle does not also have to carry tree-specific orchestration.
 */

import type { AgentMessage, StreamFn } from "@pi-recon/repi-agent-core";
import type { Api, Model, ProviderEnv, ProviderHeaders } from "@pi-recon/repi-ai";
import { collectEntriesForBranchSummary, generateBranchSummary } from "./compaction/index.ts";
import type { SessionBeforeTreeResult, SessionTreeEvent, TreePreparation } from "./extensions/index.ts";
import type { BranchSummaryEntry, SessionManager } from "./session-manager.ts";
import type { SettingsManager } from "./settings-manager.ts";

export interface TreeNavigationOptions {
	summarize?: boolean;
	customInstructions?: string;
	replaceInstructions?: boolean;
	label?: string;
}

export interface TreeNavigationResult {
	editorText?: string;
	cancelled: boolean;
	aborted?: boolean;
	summaryEntry?: BranchSummaryEntry;
}

export interface TreeRequestAuth {
	apiKey?: string;
	headers?: ProviderHeaders;
	env?: ProviderEnv;
}

/** Dependencies required by the tree runtime, kept deliberately narrower than AgentSession. */
export interface AgentSessionTreeHost {
	readonly sessionManager: SessionManager;
	readonly settingsManager: SettingsManager;
	readonly model: Model<Api> | undefined;
	readonly streamFn: StreamFn;
	getRequiredRequestAuth(model: Model<Api>): Promise<TreeRequestAuth>;
	replaceAgentMessages(messages: AgentMessage[]): void;
	hasBeforeTreeHandlers(): boolean;
	emitBeforeTree(preparation: TreePreparation, signal: AbortSignal): Promise<SessionBeforeTreeResult | undefined>;
	emitTree(event: Omit<SessionTreeEvent, "type">): Promise<void>;
}

export class AgentSessionTreeRuntime {
	private readonly host: AgentSessionTreeHost;
	private abortController: AbortController | undefined;

	constructor(host: AgentSessionTreeHost) {
		this.host = host;
	}

	/** Whether a tree transition or its optional branch summary is in progress. */
	get isNavigating(): boolean {
		return this.abortController !== undefined;
	}

	/** Cancel the active tree transition/branch summary request, if any. */
	abort(): void {
		this.abortController?.abort();
	}

	async navigateTree(targetId: string, options: TreeNavigationOptions = {}): Promise<TreeNavigationResult> {
		const oldLeafId = this.host.sessionManager.getLeafId();

		if (targetId === oldLeafId) {
			return { cancelled: false };
		}

		if (options.summarize && !this.host.model) {
			throw new Error("No model available for summarization");
		}

		const targetEntry = this.host.sessionManager.getEntry(targetId);
		if (!targetEntry) {
			throw new Error(`Entry ${targetId} not found`);
		}

		const { entries: entriesToSummarize, commonAncestorId } = collectEntriesForBranchSummary(
			this.host.sessionManager,
			oldLeafId,
			targetId,
		);

		let customInstructions = options.customInstructions;
		let replaceInstructions = options.replaceInstructions;
		let label = options.label;
		const preparation: TreePreparation = {
			targetId,
			oldLeafId,
			commonAncestorId,
			entriesToSummarize,
			userWantsSummary: options.summarize ?? false,
			customInstructions,
			replaceInstructions,
			label,
		};

		const controller = new AbortController();
		this.abortController = controller;

		try {
			let extensionSummary: { summary: string; details?: unknown } | undefined;
			let fromExtension = false;

			if (this.host.hasBeforeTreeHandlers()) {
				const result = await this.host.emitBeforeTree(preparation, controller.signal);
				if (controller.signal.aborted) return { cancelled: true, aborted: true };
				if (result?.cancel) {
					return { cancelled: true };
				}

				if (result?.summary && options.summarize) {
					extensionSummary = result.summary;
					fromExtension = true;
				}

				if (result?.customInstructions !== undefined) customInstructions = result.customInstructions;
				if (result?.replaceInstructions !== undefined) replaceInstructions = result.replaceInstructions;
				if (result?.label !== undefined) label = result.label;
			}

			let summaryText: string | undefined;
			let summaryDetails: unknown;
			if (options.summarize && entriesToSummarize.length > 0 && !extensionSummary) {
				const model = this.host.model!;
				const { apiKey, headers, env } = await this.host.getRequiredRequestAuth(model);
				if (controller.signal.aborted) return { cancelled: true, aborted: true };
				const branchSummarySettings = this.host.settingsManager.getBranchSummarySettings();
				const result = await generateBranchSummary(entriesToSummarize, {
					model,
					apiKey,
					headers,
					env,
					signal: controller.signal,
					customInstructions,
					replaceInstructions,
					reserveTokens: branchSummarySettings.reserveTokens,
					streamFn: this.host.streamFn,
				});
				if (result.aborted) {
					return { cancelled: true, aborted: true };
				}
				if (result.error) {
					throw new Error(result.error);
				}
				summaryText = result.summary;
				summaryDetails = {
					readFiles: result.readFiles || [],
					modifiedFiles: result.modifiedFiles || [],
				};
			} else if (extensionSummary) {
				summaryText = extensionSummary.summary;
				summaryDetails = extensionSummary.details;
			}
			if (controller.signal.aborted) return { cancelled: true, aborted: true };

			let newLeafId: string | null;
			let editorText: string | undefined;
			if (targetEntry.type === "message" && targetEntry.message.role === "user") {
				newLeafId = targetEntry.parentId;
				editorText = extractUserMessageText(targetEntry.message.content);
			} else if (targetEntry.type === "custom_message") {
				newLeafId = targetEntry.parentId;
				editorText = extractUserMessageText(targetEntry.content);
			} else {
				newLeafId = targetId;
			}

			let summaryEntry: BranchSummaryEntry | undefined;
			if (summaryText) {
				const summaryId = this.host.sessionManager.branchWithSummary(
					newLeafId,
					summaryText,
					summaryDetails,
					fromExtension,
				);
				summaryEntry = this.host.sessionManager.getEntry(summaryId) as BranchSummaryEntry;
				if (label) this.host.sessionManager.appendLabelChange(summaryId, label);
			} else if (newLeafId === null) {
				this.host.sessionManager.resetLeaf();
			} else {
				this.host.sessionManager.branch(newLeafId);
			}

			if (label && !summaryText) {
				this.host.sessionManager.appendLabelChange(targetId, label);
			}

			const sessionContext = this.host.sessionManager.buildSessionContext();
			this.host.replaceAgentMessages(sessionContext.messages);
			const newLeaf = this.host.sessionManager.getLeafId();
			await this.host.emitTree({
				newLeafId: newLeaf,
				oldLeafId,
				summaryEntry,
				fromExtension: summaryText ? fromExtension : undefined,
			});

			return { editorText, cancelled: false, summaryEntry };
		} finally {
			// A stale navigation must not clear a newer operation's cancellation state.
			if (this.abortController === controller) this.abortController = undefined;
		}
	}

	getUserMessagesForForking(): Array<{ entryId: string; text: string }> {
		const result: Array<{ entryId: string; text: string }> = [];
		for (const entry of this.host.sessionManager.getEntries()) {
			if (entry.type !== "message" || entry.message.role !== "user") continue;
			const text = extractUserMessageText(entry.message.content);
			if (text) result.push({ entryId: entry.id, text });
		}
		return result;
	}
}

function extractUserMessageText(content: string | Array<{ type: string; text?: string }>): string {
	if (typeof content === "string") return content;
	return content
		.filter((item): item is { type: "text"; text: string } => item.type === "text")
		.map((item) => item.text)
		.join("");
}

/**
 * Session reporting and export runtime.
 *
 * AgentSession owns the live state; this runtime keeps statistics, context
 * accounting, and session serialization out of the lifecycle/state machine.
 */

import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { AgentMessage, AgentState } from "@pi-recon/repi-agent-core";
import type { AssistantMessage, Model } from "@pi-recon/repi-ai";
import { resolvePath } from "../utils/paths.ts";
import { calculateContextTokens, estimateContextTokens } from "./compaction/index.ts";
import { buildContextBreakdown, type ContextBreakdown } from "./context-manager.ts";
import { exportSessionToHtml, type ToolHtmlRenderer } from "./export-html/index.ts";
import { createToolHtmlRenderer } from "./export-html/tool-renderer.ts";
import { headlessTheme } from "./extensions/headless-theme.ts";
import type { ContextUsage, ToolDefinition } from "./extensions/index.ts";
import type { Theme } from "./presentation/theme.ts";
import type { ResourceLoader } from "./resource-loader.ts";
import {
	CURRENT_SESSION_VERSION,
	getLatestCompactionEntry,
	type SessionHeader,
	type SessionManager,
} from "./session-manager.ts";
import type { SettingsManager } from "./settings-manager.ts";
import type { BuildSystemPromptOptions } from "./system-prompt.ts";
import { atomicWriteFileSync } from "./tools/atomic-write.ts";

/** Session statistics exposed by the `/session` command. */
export interface SessionStats {
	sessionFile: string | undefined;
	sessionId: string;
	userMessages: number;
	assistantMessages: number;
	toolCalls: number;
	toolResults: number;
	totalMessages: number;
	tokens: {
		input: number;
		output: number;
		cacheRead: number;
		cacheWrite: number;
		total: number;
	};
	cost: number;
	contextUsage?: ContextUsage;
}

/** Live values needed by the reporting runtime. */
export interface AgentSessionPresentationHost {
	readonly sessionManager: SessionManager;
	readonly settingsManager: SettingsManager;
	readonly resourceLoader: ResourceLoader;
	readonly state: AgentState;
	readonly messages: AgentMessage[];
	readonly model: Model<any> | undefined;
	readonly sessionFile: string | undefined;
	readonly sessionId: string;
	readonly baseSystemPrompt: string;
	readonly baseSystemPromptOptions: BuildSystemPromptOptions | undefined;
	getToolDefinition(name: string): ToolDefinition | undefined;
}

export interface AgentSessionPresentationRuntime {
	getSessionStats(): SessionStats;
	getContextBreakdown(): ContextBreakdown;
	getContextUsage(): ContextUsage | undefined;
	exportToHtml(outputPath?: string, presentationTheme?: Theme): Promise<string>;
	exportToJsonl(outputPath?: string): string;
}

export function exportSessionToJsonl(sessionManager: SessionManager, outputPath?: string): string {
	const filePath = resolvePath(
		outputPath ?? `session-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`,
		process.cwd(),
	);
	const dir = dirname(filePath);
	if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

	const header: SessionHeader = {
		type: "session",
		version: CURRENT_SESSION_VERSION,
		id: sessionManager.getSessionId(),
		timestamp: new Date().toISOString(),
		cwd: sessionManager.getCwd(),
	};
	const lines = [JSON.stringify(header)];
	let prevId: string | null = null;
	for (const entry of sessionManager.getBranch()) {
		lines.push(JSON.stringify({ ...entry, parentId: prevId }));
		prevId = entry.id;
	}
	atomicWriteFileSync(filePath, `${lines.join("\n")}\n`, 0o644);
	return filePath;
}

/** Create the reporting runtime for one AgentSession instance. */
export function createAgentSessionPresentationRuntime(
	host: AgentSessionPresentationHost,
): AgentSessionPresentationRuntime {
	function getContextUsage(): ContextUsage | undefined {
		const model = host.model;
		if (!model) return undefined;

		const contextWindow = model.contextWindow ?? 0;
		if (contextWindow <= 0) return undefined;

		// After compaction, the last assistant usage reflects pre-compaction context size.
		// We can only trust usage from an assistant that responded after the latest compaction.
		// If no such assistant exists, context token count is unknown until the next LLM response.
		const branchEntries = host.sessionManager.getBranch();
		const latestCompaction = getLatestCompactionEntry(branchEntries);

		if (latestCompaction) {
			// Check if there's a valid assistant usage after the compaction boundary.
			const compactionIndex = branchEntries.lastIndexOf(latestCompaction);
			let hasPostCompactionUsage = false;
			for (let i = branchEntries.length - 1; i > compactionIndex; i--) {
				const entry = branchEntries[i];
				if (entry.type === "message" && entry.message.role === "assistant") {
					const assistant = entry.message;
					if (assistant.stopReason !== "aborted" && assistant.stopReason !== "error") {
						const contextTokens = calculateContextTokens(assistant.usage);
						if (contextTokens > 0) {
							hasPostCompactionUsage = true;
							break;
						}
					}
				}
			}

			if (!hasPostCompactionUsage) {
				return { tokens: null, contextWindow, percent: null };
			}
		}

		const estimate = estimateContextTokens(host.messages);
		const percent = (estimate.tokens / contextWindow) * 100;

		return {
			tokens: estimate.tokens,
			contextWindow,
			percent,
		};
	}

	function getSessionStats(): SessionStats {
		let userMessages = 0;
		let assistantMessages = 0;
		let toolResults = 0;
		let totalMessages = 0;
		let toolCalls = 0;
		let totalInput = 0;
		let totalOutput = 0;
		let totalCacheRead = 0;
		let totalCacheWrite = 0;
		let totalCost = 0;

		for (const entry of host.sessionManager.getEntries()) {
			if (entry.type !== "message") continue;
			totalMessages++;
			const message = entry.message;
			if (message.role === "user") {
				userMessages++;
			} else if (message.role === "toolResult") {
				toolResults++;
			} else if (message.role === "assistant") {
				assistantMessages++;
				const assistantMsg = message as AssistantMessage;
				if (Array.isArray(assistantMsg.content)) {
					toolCalls += assistantMsg.content.filter((content) => content.type === "toolCall").length;
				}
				const usage = assistantMsg.usage;
				totalInput += Number.isFinite(usage?.input) ? usage.input : 0;
				totalOutput += Number.isFinite(usage?.output) ? usage.output : 0;
				totalCacheRead += Number.isFinite(usage?.cacheRead) ? usage.cacheRead : 0;
				totalCacheWrite += Number.isFinite(usage?.cacheWrite) ? usage.cacheWrite : 0;
				totalCost += Number.isFinite(usage?.cost?.total) ? usage.cost.total : 0;
			}
		}

		return {
			sessionFile: host.sessionFile,
			sessionId: host.sessionId,
			userMessages,
			assistantMessages,
			toolCalls,
			toolResults,
			totalMessages,
			tokens: {
				input: totalInput,
				output: totalOutput,
				cacheRead: totalCacheRead,
				cacheWrite: totalCacheWrite,
				total: totalInput + totalOutput + totalCacheRead + totalCacheWrite,
			},
			cost: totalCost,
			contextUsage: getContextUsage(),
		};
	}

	function getContextBreakdown(): ContextBreakdown {
		const usage = getContextUsage();
		const model = host.model;
		return buildContextBreakdown({
			messages: host.messages,
			systemPrompt: host.baseSystemPrompt,
			contextFiles: host.baseSystemPromptOptions?.contextFiles ?? host.resourceLoader.getAgentsFiles().agentsFiles,
			skills: host.baseSystemPromptOptions?.skills ?? host.resourceLoader.getSkills().skills,
			model: model ? `${model.provider}/${model.id}` : undefined,
			contextWindow: model?.contextWindow,
			currentTokens: usage?.tokens,
			currentPercent: usage?.percent,
			compactionSettings: host.settingsManager.getCompactionSettings(),
		});
	}

	async function exportToHtml(outputPath?: string, presentationTheme: Theme = headlessTheme): Promise<string> {
		const themeName = host.settingsManager.getTheme();

		const toolRenderer: ToolHtmlRenderer = createToolHtmlRenderer({
			getToolDefinition: (name) => host.getToolDefinition(name),
			theme: presentationTheme,
			cwd: host.sessionManager.getCwd(),
		});

		return await exportSessionToHtml(host.sessionManager, host.state, {
			outputPath,
			themeName,
			toolRenderer,
		});
	}

	function exportToJsonl(outputPath?: string): string {
		return exportSessionToJsonl(host.sessionManager, outputPath);
	}

	return {
		getSessionStats,
		getContextBreakdown,
		getContextUsage,
		exportToHtml,
		exportToJsonl,
	};
}

export type { ContextBreakdown } from "./context-manager.ts";

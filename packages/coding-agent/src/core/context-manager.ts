import type { AgentMessage } from "@pi-recon/repi-agent-core";
import { compactionTriggerTokens, estimateTokens } from "./compaction/compaction.ts";
import type { Skill } from "./skills.ts";
import { formatSkillsForPrompt } from "./skills.ts";

export interface ContextBreakdownItem {
	label: string;
	tokens: number;
	count?: number;
	note?: string;
}

export interface ContextTopConsumer {
	index: number;
	role: string;
	tokens: number;
	preview: string;
}

export interface ContextBreakdown {
	model?: string;
	contextWindow?: number;
	currentTokens?: number | null;
	currentPercent?: number | null;
	triggerTokens?: number;
	triggerPercent?: number;
	warningPercent?: number;
	prompt: ContextBreakdownItem[];
	messages: ContextBreakdownItem[];
	topConsumers: ContextTopConsumer[];
	suggestions: string[];
}

export interface BuildContextBreakdownOptions {
	messages: AgentMessage[];
	systemPrompt?: string;
	contextFiles?: Array<{ path: string; content: string }>;
	skills?: Skill[];
	model?: string;
	contextWindow?: number;
	currentTokens?: number | null;
	currentPercent?: number | null;
	compactionSettings?: {
		enabled: boolean;
		reserveTokens: number;
		keepRecentTokens: number;
		triggerPercent?: number;
		warningPercent?: number;
	};
}

function tokensFromText(text: string | undefined): number {
	return Math.ceil((text?.length ?? 0) / 4);
}

function contentPreview(message: AgentMessage): string {
	let text = "";
	switch (message.role) {
		case "user": {
			const content = message.content;
			text =
				typeof content === "string"
					? content
					: content.map((block) => (block.type === "text" ? block.text : "[image]")).join(" ");
			break;
		}
		case "assistant":
			text = message.content
				.map((block) => {
					if (block.type === "text") return block.text;
					if (block.type === "thinking") return "[thinking]";
					if (block.type === "toolCall") return `[toolCall:${block.name}]`;
					return "";
				})
				.join(" ");
			break;
		case "toolResult":
			text = `${message.toolName} ${message.content.map((block) => (block.type === "text" ? block.text : "[image]")).join(" ")}`;
			break;
		case "custom": {
			const content = message.content;
			text = `${message.customType} ${typeof content === "string" ? content : content.map((block) => (block.type === "text" ? block.text : "[image]")).join(" ")}`;
			break;
		}
		case "bashExecution":
			text = `${message.command} ${message.output}`;
			break;
		case "branchSummary":
		case "compactionSummary":
			text = message.summary;
			break;
	}

	return text.replace(/\s+/g, " ").trim().slice(0, 140) || "(empty)";
}

function categoryForMessage(message: AgentMessage): string {
	switch (message.role) {
		case "user":
			return "User messages";
		case "assistant":
			return "Assistant messages";
		case "toolResult":
			return "Tool results";
		case "custom":
			return "Custom/context messages";
		case "bashExecution":
			return message.excludeFromContext ? "Bash executions (!! excluded)" : "Bash executions";
		case "branchSummary":
			return "Branch summaries";
		case "compactionSummary":
			return "Compaction summaries";
		default:
			return "Other messages";
	}
}

export function buildContextBreakdown(options: BuildContextBreakdownOptions): ContextBreakdown {
	const contextWindow = options.contextWindow && options.contextWindow > 0 ? options.contextWindow : undefined;
	const triggerTokens = contextWindow
		? compactionTriggerTokens(
				contextWindow,
				options.compactionSettings ?? {
					enabled: true,
					reserveTokens: 16384,
					keepRecentTokens: 36000,
					triggerPercent: 85,
					warningPercent: 80,
				},
			)
		: undefined;
	const triggerPercent =
		contextWindow && triggerTokens
			? (triggerTokens / contextWindow) * 100
			: options.compactionSettings?.triggerPercent;

	const contextFiles = options.contextFiles ?? [];
	const skills = options.skills ?? [];
	const skillsIndex = formatSkillsForPrompt(skills, { contextWindow });

	const prompt: ContextBreakdownItem[] = [
		{
			label: "System prompt total",
			tokens: tokensFromText(options.systemPrompt),
			note: "includes base prompt, appended prompt, project instructions and skills index",
		},
		{
			label: "Project instructions",
			tokens: contextFiles.reduce((sum, file) => sum + tokensFromText(file.content), 0),
			count: contextFiles.length,
		},
		{
			label: "Skills index",
			tokens: tokensFromText(skillsIndex),
			count: skills.filter((skill) => !skill.disableModelInvocation).length,
			note: "progressive-disclosure index only; skill bodies are loaded on demand",
		},
	];

	const byCategory = new Map<string, { tokens: number; count: number }>();
	const topConsumers: ContextTopConsumer[] = [];
	options.messages.forEach((message, index) => {
		const tokens = estimateTokens(message);
		const category = categoryForMessage(message);
		const current = byCategory.get(category) ?? { tokens: 0, count: 0 };
		current.tokens += tokens;
		current.count += 1;
		byCategory.set(category, current);
		topConsumers.push({ index, role: message.role, tokens, preview: contentPreview(message) });
	});

	const messages = Array.from(byCategory.entries())
		.map(([label, value]) => ({ label, tokens: value.tokens, count: value.count }))
		.sort((a, b) => b.tokens - a.tokens);

	const suggestions = [
		"Use /compact focus on <current objective> before the next heavy tool run when near the trigger threshold.",
		"Use !! for noisy shell output that should be shown locally but excluded from model context.",
		"Move long logs/HTML/PCAP/tool output to files and keep only artifact paths + decisive lines in chat.",
		"Split noisy exploration into re_swarm/subagent lanes and merge only distilled claims, evidence refs, and unresolved gaps.",
	];

	return {
		model: options.model,
		contextWindow,
		currentTokens: options.currentTokens,
		currentPercent: options.currentPercent,
		triggerTokens,
		triggerPercent,
		warningPercent: options.compactionSettings?.warningPercent,
		prompt,
		messages,
		topConsumers: topConsumers.sort((a, b) => b.tokens - a.tokens).slice(0, 10),
		suggestions,
	};
}

function formatTokens(tokens: number | undefined | null): string {
	if (tokens === null || tokens === undefined || !Number.isFinite(tokens)) return "unknown";
	return Math.round(tokens).toLocaleString();
}

function formatPercent(percent: number | undefined | null): string {
	if (percent === null || percent === undefined || !Number.isFinite(percent)) return "unknown";
	return `${percent.toFixed(1)}%`;
}

export function formatContextBreakdown(breakdown: ContextBreakdown): string {
	const lines: string[] = [];
	lines.push("Context Manager");
	lines.push("");
	lines.push(`Model: ${breakdown.model ?? "unknown"}`);
	lines.push(`Context window: ${formatTokens(breakdown.contextWindow)} tokens`);
	lines.push(
		`Current usage: ${formatTokens(breakdown.currentTokens)} tokens (${formatPercent(breakdown.currentPercent)})`,
	);
	if (breakdown.triggerTokens !== undefined || breakdown.triggerPercent !== undefined) {
		lines.push(
			`Auto compact trigger: ${formatTokens(breakdown.triggerTokens)} tokens (${formatPercent(breakdown.triggerPercent)})`,
		);
	}
	if (breakdown.warningPercent !== undefined) {
		lines.push(`Warning threshold: ${formatPercent(breakdown.warningPercent)}`);
	}

	lines.push("");
	lines.push("Prompt components:");
	for (const item of breakdown.prompt) {
		const count = item.count !== undefined ? ` · count=${item.count}` : "";
		const note = item.note ? ` · ${item.note}` : "";
		lines.push(`- ${item.label}: ${formatTokens(item.tokens)} tokens${count}${note}`);
	}

	lines.push("");
	lines.push("Message categories:");
	if (breakdown.messages.length === 0) {
		lines.push("- none");
	} else {
		for (const item of breakdown.messages) {
			lines.push(`- ${item.label}: ${formatTokens(item.tokens)} tokens · count=${item.count ?? 0}`);
		}
	}

	lines.push("");
	lines.push("Top context consumers:");
	if (breakdown.topConsumers.length === 0) {
		lines.push("- none");
	} else {
		for (const item of breakdown.topConsumers) {
			lines.push(`- #${item.index} ${item.role}: ${formatTokens(item.tokens)} tokens — ${item.preview}`);
		}
	}

	lines.push("");
	lines.push("Suggestions:");
	for (const suggestion of breakdown.suggestions) {
		lines.push(`- ${suggestion}`);
	}

	return lines.join("\n");
}

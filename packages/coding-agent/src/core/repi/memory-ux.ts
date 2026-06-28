import { existsSync, statSync } from "node:fs";
import type { MemoryEventV1, MemoryOutcome } from "./memory-event.ts";
import { repiMemorySettings } from "./memory-runtime.ts";
import { memoryTargetScope } from "./memory-scope.ts";
import type { MemoryRetrievalHit } from "./memory-search.ts";
import {
	caseMemoryPath,
	memoryCorePath,
	memoryEventsPath,
	memoryProceduralPath,
	memoryProjectPath,
	readTextFile as readText,
} from "./storage.ts";
import { truncateMiddle } from "./text.ts";

export type MemoryUxGovernanceActionV16 = "promote" | "demote" | "forget" | "quarantine";

export type MemoryUxWhyRowV16 = {
	eventId: string;
	caseSignature: string;
	score: number;
	outcome: MemoryOutcome;
	route: string;
	target?: string;
	reasons: string[];
	commands: string[];
	lessons: string[];
	governanceCommands: string[];
};

export type MemoryUxGovernanceDecisionV16 = {
	kind: "repi-memory-ux-governance-decision";
	schemaVersion: 1;
	id: string;
	ts: string;
	MemoryUxDashboardV16: true;
	append_only_memory_governance: true;
	action: MemoryUxGovernanceActionV16;
	applied: boolean;
	sourceEventId?: string;
	sourceCaseSignature?: string;
	newEventId?: string;
	reason: string;
	nextCommands: string[];
};

export type MemoryUxDashboardV16 = {
	kind: "repi-memory-ux-dashboard";
	schemaVersion: 1;
	generatedAt: string;
	MemoryUxDashboardV16: true;
	user_visible_memory_status: true;
	recall_explainability: true;
	append_only_memory_governance: true;
	lifecycle_governance_commands: true;
	statusReportPath: string;
	statusBoardPath: string;
	governanceLedgerPath: string;
	query: string;
	route?: string;
	target?: string;
	store: {
		eventCount: number;
		caseCount: number;
		hashChainOk: boolean;
		storeGrade: "pass" | "repairable" | "blocked";
		latestEventHash: string;
	};
	recall: {
		hitCount: number;
		retrievalReportPath: string;
		vectorSearchReportPath: string;
		whyRows: MemoryUxWhyRowV16[];
	};
	quality: {
		status: "pass" | "warn" | "blocked" | "empty";
		rowCount: number;
		promotedEventIds: string[];
		demotedEventIds: string[];
		quarantinedEventIds: string[];
	};
	replay: {
		status: "pass" | "warn" | "blocked" | "empty";
		scenarioCount: number;
		improvedScenarioIds: string[];
		regressedScenarioIds: string[];
	};
	activeKernel: {
		status: "pass" | "warn" | "blocked" | "empty";
		decisionCount: number;
		injectionPackPath: string;
		operatorCommands: string[];
	};
	maturation: {
		status: "pass" | "warn" | "blocked" | "empty";
		rowCount: number;
		promotedEventIds: string[];
		retentionQueueEventIds: string[];
		expiredEventIds: string[];
	};
	supervisor: {
		storeGrade: "pass" | "repairable" | "blocked";
		promotionQueueCount: number;
		demotionQueueCount: number;
		quarantineQueueCount: number;
		expireQueueCount: number;
		mergeQueueCount: number;
		lifecycleBoardPath: string;
		recommendedCommands: string[];
	};
	operatorCommands: string[];
	governanceCommands: string[];
	requiredChecks: string[];
};

export function memoryUxGovernanceCommandsForEvent(event: MemoryEventV1): string[] {
	return [
		`re_memory promote ${event.id} # append verified success feedback for this memory`,
		`re_memory demote ${event.id} # append failure feedback and lower future recall`,
		`re_memory forget ${event.id} # append tombstone/quarantine feedback; does not rewrite history`,
	];
}

export function memoryUxWhyRow(hit: MemoryRetrievalHit): MemoryUxWhyRowV16 {
	return {
		eventId: hit.event.id,
		caseSignature: hit.event.caseSignature,
		score: Number(hit.score.toFixed(2)),
		outcome: hit.event.outcome,
		route: hit.event.route,
		target: hit.event.target,
		reasons: hit.reasons.slice(0, 24),
		commands: hit.event.commands.slice(0, 8),
		lessons: hit.event.lessons.slice(0, 4),
		governanceCommands: memoryUxGovernanceCommandsForEvent(hit.event),
	};
}

export function formatMemoryStatusBoard(report: MemoryUxDashboardV16): string {
	const whyLine = (row: MemoryUxWhyRowV16) =>
		`- event=${row.eventId} score=${row.score.toFixed(1)} outcome=${row.outcome} route=${row.route} case=${row.caseSignature} reasons=${row.reasons.join(",") || "none"}`;
	return [
		"# REPI Memory Status Board",
		"",
		"memory_ux_dashboard:",
		`MemoryUxDashboardV16: ${report.MemoryUxDashboardV16}`,
		`generated_at: ${report.generatedAt}`,
		`query: ${report.query}`,
		`route: ${report.route ?? "none"}`,
		`target: ${report.target ?? "none"}`,
		`user_visible_memory_status: ${report.user_visible_memory_status}`,
		`recall_explainability: ${report.recall_explainability}`,
		`append_only_memory_governance: ${report.append_only_memory_governance}`,
		`store_grade: ${report.store.storeGrade}`,
		`hash_chain_ok: ${report.store.hashChainOk}`,
		`events: ${report.store.eventCount}`,
		`cases: ${report.store.caseCount}`,
		`recall_hits: ${report.recall.hitCount}`,
		`quality_status: ${report.quality.status}`,
		`replay_status: ${report.replay.status}`,
		`active_decisions: ${report.activeKernel.decisionCount}`,
		`maturation_status: ${report.maturation.status}`,
		`supervisor_queues: promote=${report.supervisor.promotionQueueCount} demote=${report.supervisor.demotionQueueCount} quarantine=${report.supervisor.quarantineQueueCount} expire=${report.supervisor.expireQueueCount} merge=${report.supervisor.mergeQueueCount}`,
		`status_report: ${report.statusReportPath}`,
		`governance_ledger: ${report.governanceLedgerPath}`,
		"",
		"why_this_memory:",
		...(report.recall.whyRows.length ? report.recall.whyRows.map(whyLine) : ["- none"]),
		"",
		"operator_commands:",
		...(report.operatorCommands.length ? report.operatorCommands.map((command) => `- ${command}`) : ["- none"]),
		"",
		"governance_commands:",
		...report.governanceCommands.map((command) => `- ${command}`),
		"",
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
		"",
	].join("\n");
}

export function formatMemoryUxDashboard(report: MemoryUxDashboardV16): string {
	return [
		"memory_ux_dashboard:",
		`MemoryUxDashboardV16=${report.MemoryUxDashboardV16}`,
		`user_visible_memory_status=${report.user_visible_memory_status}`,
		`recall_explainability=${report.recall_explainability}`,
		`append_only_memory_governance=${report.append_only_memory_governance}`,
		`query=${report.query}`,
		`store_grade=${report.store.storeGrade}`,
		`hash_chain_ok=${report.store.hashChainOk}`,
		`events=${report.store.eventCount}`,
		`cases=${report.store.caseCount}`,
		`recall_hits=${report.recall.hitCount}`,
		`quality=${report.quality.status}:${report.quality.rowCount}`,
		`replay=${report.replay.status}:${report.replay.scenarioCount}`,
		`active_decisions=${report.activeKernel.decisionCount}`,
		`maturation=${report.maturation.status}:${report.maturation.rowCount}`,
		`queues=promote:${report.supervisor.promotionQueueCount},demote:${report.supervisor.demotionQueueCount},quarantine:${report.supervisor.quarantineQueueCount},expire:${report.supervisor.expireQueueCount},merge:${report.supervisor.mergeQueueCount}`,
		`status_report=${report.statusReportPath}`,
		`status_board=${report.statusBoardPath}`,
		`governance_ledger=${report.governanceLedgerPath}`,
		"why_this_memory:",
		...(report.recall.whyRows.length
			? report.recall.whyRows.map(
					(row) =>
						`- event=${row.eventId} score=${row.score.toFixed(1)} outcome=${row.outcome} route=${row.route} reasons=${row.reasons.join(",") || "none"} commands=${row.commands.length}`,
				)
			: ["- none"]),
		"operator_commands:",
		...(report.operatorCommands.length ? report.operatorCommands.map((command) => `- ${command}`) : ["- none"]),
		"governance_commands:",
		...report.governanceCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}

export function formatMemoryUxGovernanceDecision(
	decision: MemoryUxGovernanceDecisionV16,
	options: { governanceLedgerPath: string },
): string {
	return [
		"memory_ux_governance:",
		`MemoryUxDashboardV16=${decision.MemoryUxDashboardV16}`,
		`append_only_memory_governance=${decision.append_only_memory_governance}`,
		`action=${decision.action}`,
		`applied=${decision.applied}`,
		`source_event=${decision.sourceEventId ?? "none"}`,
		`new_event=${decision.newEventId ?? "none"}`,
		`case_signature=${decision.sourceCaseSignature ?? "none"}`,
		`reason=${decision.reason}`,
		`governance_ledger=${options.governanceLedgerPath}`,
		"next_commands:",
		...decision.nextCommands.map((command) => `- ${command}`),
	].join("\n");
}

export function memoryLineCount(path: string): number {
	const text = readText(path);
	if (!text.trim()) return 0;
	return text.split(/\r?\n/).filter((line) => line.trim()).length;
}

export function memoryFileStatusLine(label: string, path: string): string {
	if (!existsSync(path)) return `${label}=missing`;
	const stat = statSync(path);
	return `${label}=present rows=${memoryLineCount(path)} bytes=${stat.size}`;
}

export function readMemoryNote(path: string, emptyTitle: string, limit = 900): string {
	const text = readText(path).trim();
	if (!text) return `${emptyTitle}=empty`;
	const meaningful = text
		.split(/\r?\n/)
		.filter((line) => {
			const trimmed = line.trim();
			return (
				trimmed && !/^#\s*REPI\s+/i.test(trimmed) && !/^(?:固定偏好|当前 workspace|可复用 workflow)/i.test(trimmed)
			);
		})
		.join("\n")
		.trim();
	if (!meaningful) return `${emptyTitle}=empty`;
	return truncateMiddle(meaningful, limit);
}

export function formatCoreMemoryPacket(): string {
	return [
		"core_memory:",
		readMemoryNote(memoryCorePath(), "core_memory"),
		"project_memory:",
		readMemoryNote(memoryProjectPath(), "project_memory"),
		"procedural_memory:",
		readMemoryNote(memoryProceduralPath(), "procedural_memory"),
	].join("\n");
}

export function formatMemoryRuntimeStatus(
	settings = repiMemorySettings(),
	options: { route?: string; target?: string } = {},
): string {
	return [
		"memory_runtime:",
		`mode=${settings.mode}`,
		`auto_recall=${settings.autoRecall}`,
		`auto_deposit=${settings.autoDepositMode}`,
		`startup_digest=${settings.startupDigest}`,
		`active_recall=${settings.activeRecall}`,
		`context_memory=${settings.contextMemoryMode}`,
		`global_memory_context=${settings.includeGlobalMemoryInContextPack}`,
		`scope_policy=${settings.scopePolicy}`,
		`startup_budget_tokens=${settings.startupBudgetTokens}`,
		`context_budget_tokens=${settings.contextPackBudgetTokens}`,
		`max_startup_items=${settings.maxStartupItems}`,
		`min_recall_score=${settings.minRecallScore}`,
		`raw_transcript_retention=${settings.rawTranscriptRetention}`,
		`route=${options.route ?? "none"}`,
		`target_scope=${options.target ? memoryTargetScope(options.target) : "workspace"}`,
		"raw_history=external_only_by_default",
		memoryFileStatusLine("events", memoryEventsPath()),
		memoryFileStatusLine("case_memory", caseMemoryPath()),
		memoryFileStatusLine("core_memory", memoryCorePath()),
		memoryFileStatusLine("project_memory", memoryProjectPath()),
		memoryFileStatusLine("procedural_memory", memoryProceduralPath()),
	].join("\n");
}

export function formatMemoryIsolationStatus(
	settings = repiMemorySettings(),
	options: { route?: string; target?: string } = {},
): string {
	return [
		formatMemoryRuntimeStatus(settings, options),
		"explicit_recall:",
		"- re_memory search <query>",
		"- re_memory scope <target>",
		"- re_memory active <target>",
	].join("\n");
}

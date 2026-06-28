import { existsSync } from "node:fs";
import { jsonlRecords } from "./jsonl.ts";
import type { MemoryInjectionPacketV1 } from "./memory-distillation.ts";
import type { MemoryEventV1 } from "./memory-event.ts";
import { buildMemoryFeedbackClosureReport, type MemoryFeedbackClosureReportV1 } from "./memory-feedback.ts";
import { type MemoryReplayEvaluatorReportV12, memoryReplayCausalSignals } from "./memory-replay.ts";
import { buildMemoryScopeIsolationReport, memoryRouteMatches, memoryTargetScope } from "./memory-scope.ts";
import { type MemoryRetrievalHit, readMemoryEvents } from "./memory-search.ts";
import { writeFileAtomic } from "./memory-store.ts";
import type { MemoryUsefulnessEvalReportV1 } from "./memory-usefulness.ts";
import type { MemoryVectorSearchHitV1 } from "./memory-vector.ts";
import {
	ensureRepiStorage,
	memoryFeedbackClosureReportPath,
	memoryInjectionPacketPath,
	memoryQualityBoardPath,
	memoryQualityLedgerPath,
	memoryQualityReportPath,
	memoryReplayEvaluatorReportPath,
	memoryRetrievalReportPath,
	memoryUsefulnessEvalReportPath,
	memoryVectorSearchReportPath,
	readJsonObjectFile,
	readTextFile as readText,
} from "./storage.ts";
import { sha256Text, uniqueNonEmpty } from "./text.ts";

export type MemoryQualityLifecycleDecisionV11 = "promote" | "retain" | "demote" | "quarantine" | "expire";

export type MemoryQualitySignalV11 =
	| "retrieved"
	| "vector_hit"
	| "injected"
	| "positive_feedback"
	| "negative_feedback"
	| "pending_feedback"
	| "usefulness_hit"
	| "usefulness_miss"
	| "forbidden_leak"
	| "scope_blocked"
	| "stale_decay"
	| "ab_replay_improved"
	| "ab_replay_regressed";

export type MemoryQualityLedgerRowV11 = {
	kind: "repi-memory-quality-ledger-row";
	schemaVersion: 1;
	seq: number;
	id: string;
	ts: string;
	MemoryQualityLedgerV11: true;
	eventId: string;
	caseSignature: string;
	route: string;
	targetScope: string;
	retrievalCount: number;
	vectorHitCount: number;
	injectedCount: number;
	positiveFeedbackCount: number;
	negativeFeedbackCount: number;
	pendingFeedbackCount: number;
	usefulnessHitCount: number;
	usefulnessMissCount: number;
	forbiddenLeakCount: number;
	scopeBlocked: boolean;
	lastRecalledAt?: string;
	lastInjectedAt?: string;
	lastFeedbackAt?: string;
	baseConfidence: number;
	qualityScore: number;
	lifecycleDecision: MemoryQualityLifecycleDecisionV11;
	signals: MemoryQualitySignalV11[];
	evidenceRefs: string[];
	nextCommands: string[];
	prevHash: string;
	entryHash: string;
};

export type MemoryQualityLedgerReportV11 = {
	kind: "repi-memory-quality-ledger-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryQualityLedgerV11: true;
	active_memory_policy: true;
	quality_score_feedback_loop: true;
	usefulness_feedback_writeback: true;
	reportPath: string;
	ledgerPath: string;
	boardPath: string;
	sourceRetrievalReportPath: string;
	sourceVectorSearchReportPath: string;
	sourceFeedbackClosureReportPath: string;
	sourceUsefulnessEvalReportPath: string;
	eventCount: number;
	rowCount: number;
	averageQualityScore: number;
	promotedEventIds: string[];
	retainedEventIds: string[];
	demotedEventIds: string[];
	quarantinedEventIds: string[];
	expiredEventIds: string[];
	requiredFeedbackEventIds: string[];
	operatorInjectionCommands: string[];
	avoidCommands: string[];
	status: "pass" | "warn" | "blocked" | "empty";
	rows: MemoryQualityLedgerRowV11[];
	requiredChecks: string[];
	policy: {
		MemoryQualityLedgerV11: true;
		activeMemoryPolicy: true;
		qualityScoreFeedbackLoop: true;
		usefulnessFeedbackWriteback: true;
		appendOnlyQualityLedger: true;
		qualityDrivesSedimentation: true;
	};
	nextCommands: string[];
};

export type MemoryQualityUsefulnessReportSource = {
	scenarios?: Array<{
		expectedEventIds?: string[];
		hitAtK?: boolean;
		forbiddenHitIds?: string[];
	}>;
};

export function memoryQualityLedgerRowHash(row: MemoryQualityLedgerRowV11): string {
	const { entryHash: _entryHash, ...withoutHash } = row;
	return sha256Text(JSON.stringify(withoutHash));
}

export function isMemoryQualityLedgerRow(value: unknown): value is MemoryQualityLedgerRowV11 {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as MemoryQualityLedgerRowV11;
	return (
		row.kind === "repi-memory-quality-ledger-row" &&
		row.schemaVersion === 1 &&
		row.MemoryQualityLedgerV11 === true &&
		Number.isInteger(row.seq) &&
		typeof row.id === "string" &&
		typeof row.ts === "string" &&
		typeof row.eventId === "string" &&
		typeof row.caseSignature === "string" &&
		typeof row.route === "string" &&
		typeof row.targetScope === "string" &&
		typeof row.retrievalCount === "number" &&
		typeof row.injectedCount === "number" &&
		typeof row.qualityScore === "number" &&
		typeof row.lifecycleDecision === "string" &&
		Array.isArray(row.signals) &&
		Array.isArray(row.nextCommands) &&
		typeof row.prevHash === "string" &&
		typeof row.entryHash === "string"
	);
}

export function latestMemoryQualityRowsByEvent(
	rows: MemoryQualityLedgerRowV11[],
): Map<string, MemoryQualityLedgerRowV11> {
	const latest = new Map<string, MemoryQualityLedgerRowV11>();
	for (const row of rows) latest.set(row.eventId, row);
	return latest;
}

export function memoryQualityUsefulnessSignals(
	report: MemoryQualityUsefulnessReportSource | undefined,
): Map<string, { hit: number; miss: number; forbidden: number }> {
	const signals = new Map<string, { hit: number; miss: number; forbidden: number }>();
	for (const scenario of report?.scenarios ?? []) {
		for (const expected of scenario.expectedEventIds ?? []) {
			const row = signals.get(expected) ?? { hit: 0, miss: 0, forbidden: 0 };
			if (scenario.hitAtK) row.hit += 1;
			else row.miss += 1;
			signals.set(expected, row);
		}
		for (const forbidden of scenario.forbiddenHitIds ?? []) {
			const row = signals.get(forbidden) ?? { hit: 0, miss: 0, forbidden: 0 };
			row.forbidden += 1;
			signals.set(forbidden, row);
		}
	}
	return signals;
}

export function memoryQualityDecision(input: {
	score: number;
	event: MemoryEventV1;
	negative: number;
	forbidden: number;
	scopeBlocked: boolean;
	ageDays: number;
}): MemoryQualityLifecycleDecisionV11 {
	if (input.scopeBlocked || input.forbidden > 0) return "quarantine";
	if (input.ageDays > 720 && input.score < 45) return "expire";
	if (input.negative > 0 || input.event.outcome === "failure" || input.event.outcome === "blocked" || input.score < 38)
		return "demote";
	if (
		input.score >= 78 &&
		input.event.outcome === "success" &&
		(input.event.quality.replayVerified || input.event.artifactHashes.some((artifact) => artifact.sha256))
	)
		return "promote";
	return "retain";
}

export function formatMemoryQualityLedger(report: MemoryQualityLedgerReportV11): string {
	return [
		"memory_quality_ledger_v11:",
		`MemoryQualityLedgerV11=${report.MemoryQualityLedgerV11}`,
		`active_memory_policy=${report.active_memory_policy}`,
		`quality_score_feedback_loop=${report.quality_score_feedback_loop}`,
		`usefulness_feedback_writeback=${report.usefulness_feedback_writeback}`,
		`status=${report.status}`,
		`events=${report.eventCount}`,
		`rows=${report.rowCount}`,
		`average_quality_score=${report.averageQualityScore}`,
		`promoted=${report.promotedEventIds.length}`,
		`retained=${report.retainedEventIds.length}`,
		`demoted=${report.demotedEventIds.length}`,
		`quarantined=${report.quarantinedEventIds.length}`,
		`expired=${report.expiredEventIds.length}`,
		`required_feedback=${report.requiredFeedbackEventIds.length}`,
		`report=${report.reportPath}`,
		`ledger=${report.ledgerPath}`,
		`board=${report.boardPath}`,
		"operator_injection_commands:",
		...(report.operatorInjectionCommands.length
			? report.operatorInjectionCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"avoid_commands:",
		...(report.avoidCommands.length
			? report.avoidCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"top_quality_rows:",
		...(report.rows.length
			? [...report.rows]
					.sort((left, right) => right.qualityScore - left.qualityScore)
					.slice(0, 12)
					.map(
						(row) =>
							`- event=${row.eventId} decision=${row.lifecycleDecision} score=${row.qualityScore} signals=${row.signals.join(",") || "none"}`,
					)
			: ["- none"]),
		"next_commands:",
		...report.nextCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}

export function readMemoryQualityLedgerRows(): MemoryQualityLedgerRowV11[] {
	ensureRepiStorage();
	return jsonlRecords(memoryQualityLedgerPath(), isMemoryQualityLedgerRow);
}

export function latestMemoryQualityByEvent(): Map<string, MemoryQualityLedgerRowV11> {
	return latestMemoryQualityRowsByEvent(readMemoryQualityLedgerRows());
}

export function memoryQualityReportIds(path: string, key: "id" | "eventId" = "id"): string[] {
	const report = readJsonObjectFile<{ hits?: Array<Record<string, unknown>> }>(path);
	return uniqueNonEmpty(
		(report?.hits ?? []).map((hit) => hit[key]).filter((id): id is string => typeof id === "string"),
		120,
	);
}

export function buildMemoryQualityLedgerReport(
	options: {
		route?: string;
		target?: string;
		retrievalHits?: MemoryRetrievalHit[];
		vectorHits?: MemoryVectorSearchHitV1[];
		injectionEventIds?: string[];
		feedback?: MemoryFeedbackClosureReportV1;
		usefulness?: MemoryUsefulnessEvalReportV1;
		write?: boolean;
	} = {},
): MemoryQualityLedgerReportV11 {
	ensureRepiStorage();
	const generatedAt = new Date().toISOString();
	const previous = latestMemoryQualityByEvent();
	const previousRows = readMemoryQualityLedgerRows();
	let prevHash = previousRows.at(-1)?.entryHash ?? "0".repeat(64);
	let seq = previousRows.length;
	const events = readMemoryEvents().filter((event) => {
		if (options.route && !memoryRouteMatches(event.route, options.route)) return false;
		if (
			options.target &&
			event.target &&
			!memoryTargetScope(event.target).includes(memoryTargetScope(options.target))
		)
			return false;
		return true;
	});
	const retrievalIds = new Set(
		options.retrievalHits?.map((hit) => hit.event.id) ?? memoryQualityReportIds(memoryRetrievalReportPath(), "id"),
	);
	const vectorIds = new Set(
		options.vectorHits?.map((hit) => hit.eventId) ??
			memoryQualityReportIds(memoryVectorSearchReportPath(), "eventId"),
	);
	const injectionIds = new Set(
		options.injectionEventIds ??
			(readJsonObjectFile<MemoryInjectionPacketV1>(memoryInjectionPacketPath())?.entries ?? []).map(
				(entry) => entry.eventId,
			),
	);
	const feedback =
		options.feedback ??
		readJsonObjectFile<MemoryFeedbackClosureReportV1>(memoryFeedbackClosureReportPath()) ??
		buildMemoryFeedbackClosureReport({ write: options.write });
	const feedbackByEvent = new Map((feedback.rows ?? []).map((row) => [row.eventId, row]));
	const usefulness =
		options.usefulness ?? readJsonObjectFile<MemoryUsefulnessEvalReportV1>(memoryUsefulnessEvalReportPath());
	const usefulnessByEvent = memoryQualityUsefulnessSignals(usefulness);
	const replayByEvent = memoryReplayCausalSignals(
		readJsonObjectFile<MemoryReplayEvaluatorReportV12>(memoryReplayEvaluatorReportPath()),
	);
	const scope = buildMemoryScopeIsolationReport({
		route: options.route,
		target: options.target,
		write: options.write,
	});
	const scopeByEvent = new Map(scope.rows.map((row) => [row.eventId, row]));
	const rows: MemoryQualityLedgerRowV11[] = events.map((event) => {
		const prev = previous.get(event.id);
		const feedbackRow = feedbackByEvent.get(event.id);
		const usefulnessSignal = usefulnessByEvent.get(event.id) ?? { hit: 0, miss: 0, forbidden: 0 };
		const replaySignal = replayByEvent.get(event.id) ?? { lift: 0, regressions: 0, score: 0 };
		const wasRetrieved = retrievalIds.has(event.id);
		const wasVectorHit = vectorIds.has(event.id);
		const wasInjected =
			injectionIds.has(event.id) || (feedbackRow?.injectionAction && feedbackRow.injectionAction !== "not_injected");
		const positiveFeedbackCount = Math.max(prev?.positiveFeedbackCount ?? 0, feedbackRow?.positiveFeedbackCount ?? 0);
		const negativeFeedbackCount = Math.max(prev?.negativeFeedbackCount ?? 0, feedbackRow?.negativeFeedbackCount ?? 0);
		const pendingFeedbackCount = Math.max(
			prev?.pendingFeedbackCount ?? 0,
			feedbackRow?.feedbackStatus === "pending" ? 1 : 0,
		);
		const retrievalCount = (prev?.retrievalCount ?? 0) + (wasRetrieved ? 1 : 0);
		const vectorHitCount = (prev?.vectorHitCount ?? 0) + (wasVectorHit ? 1 : 0);
		const injectedCount = Math.max(prev?.injectedCount ?? 0, wasInjected ? 1 : 0);
		const usefulnessHitCount = (prev?.usefulnessHitCount ?? 0) + usefulnessSignal.hit;
		const usefulnessMissCount = (prev?.usefulnessMissCount ?? 0) + usefulnessSignal.miss;
		const forbiddenLeakCount = (prev?.forbiddenLeakCount ?? 0) + usefulnessSignal.forbidden;
		const scopeBlocked = scopeByEvent.get(event.id)?.blocksInjection === true || prev?.scopeBlocked === true;
		const ageDays = Math.max(0, Math.floor((Date.now() - Date.parse(event.ts)) / 86_400_000));
		let score = event.quality.confidence * 52;
		score += event.quality.replayVerified ? 13 : 0;
		score += event.outcome === "success" ? 10 : event.outcome === "repair" ? 6 : 0;
		score += event.artifactHashes.some((artifact) => artifact.sha256) ? 7 : 0;
		score += Math.min(8, retrievalCount * 0.8 + vectorHitCount * 0.6);
		score += Math.min(10, injectedCount * 4 + positiveFeedbackCount * 6 + usefulnessHitCount * 1.5);
		score += Math.min(12, Math.max(0, replaySignal.lift) * 9 + Math.max(0, replaySignal.score - 65) * 0.08);
		score -= Math.min(26, negativeFeedbackCount * 12 + event.quality.failureCount * 4 + forbiddenLeakCount * 18);
		score -= Math.min(24, replaySignal.regressions * 16);
		score -= Math.min(
			18,
			event.quality.decay * 12 + ageDays * 0.025 + usefulnessMissCount * 1.5 + pendingFeedbackCount * 1.2,
		);
		if (event.outcome === "failure" || event.outcome === "blocked") score -= 14;
		if (scopeBlocked) score -= 40;
		const qualityScore = Number(Math.max(0, Math.min(100, score)).toFixed(2));
		const lifecycleDecision = memoryQualityDecision({
			score: qualityScore,
			event,
			negative: negativeFeedbackCount,
			forbidden: forbiddenLeakCount,
			scopeBlocked,
			ageDays,
		});
		const signals: MemoryQualitySignalV11[] = uniqueNonEmpty(
			[
				wasRetrieved ? "retrieved" : undefined,
				wasVectorHit ? "vector_hit" : undefined,
				wasInjected ? "injected" : undefined,
				positiveFeedbackCount ? "positive_feedback" : undefined,
				negativeFeedbackCount ? "negative_feedback" : undefined,
				pendingFeedbackCount ? "pending_feedback" : undefined,
				usefulnessHitCount ? "usefulness_hit" : undefined,
				usefulnessMissCount ? "usefulness_miss" : undefined,
				forbiddenLeakCount ? "forbidden_leak" : undefined,
				scopeBlocked ? "scope_blocked" : undefined,
				ageDays > 365 ? "stale_decay" : undefined,
				replaySignal.lift > 0 ? "ab_replay_improved" : undefined,
				replaySignal.regressions > 0 ? "ab_replay_regressed" : undefined,
			] as Array<MemoryQualitySignalV11 | undefined>,
			16,
		) as MemoryQualitySignalV11[];
		const evidenceRefs = uniqueNonEmpty(
			[
				memoryRetrievalReportPath(),
				memoryVectorSearchReportPath(),
				feedback.feedbackClosureReportPath,
				usefulness?.reportPath,
				existsSync(memoryReplayEvaluatorReportPath()) ? memoryReplayEvaluatorReportPath() : undefined,
				...event.artifactHashes.filter((artifact) => artifact.sha256).map((artifact) => artifact.path),
			],
			24,
		);
		const nextCommands =
			lifecycleDecision === "promote"
				? ["re_memory experience", "re_memory skills", "re_memory distill-promote", "re_context pack"]
				: lifecycleDecision === "retain"
					? [
							pendingFeedbackCount
								? `re_memory append # memory_reuse_feedback_promote event=${event.id}`
								: "re_memory quality",
						]
					: lifecycleDecision === "demote"
						? ["re_memory supervise", "re_memory sediment", "re_autofix plan"]
						: lifecycleDecision === "expire"
							? ["re_memory supervise", "re_memory prune-playbooks"]
							: ["re_memory scope", "re_memory supervise", "re_memory sediment"];
		const base: Omit<MemoryQualityLedgerRowV11, "entryHash"> = {
			kind: "repi-memory-quality-ledger-row",
			schemaVersion: 1,
			seq: ++seq,
			id: `mq:${sha256Text(`${generatedAt}:${event.id}:${qualityScore}:${signals.join(",")}`).slice(0, 24)}`,
			ts: generatedAt,
			MemoryQualityLedgerV11: true,
			eventId: event.id,
			caseSignature: event.caseSignature,
			route: event.route,
			targetScope: memoryTargetScope(event.target),
			retrievalCount,
			vectorHitCount,
			injectedCount,
			positiveFeedbackCount,
			negativeFeedbackCount,
			pendingFeedbackCount,
			usefulnessHitCount,
			usefulnessMissCount,
			forbiddenLeakCount,
			scopeBlocked,
			lastRecalledAt: wasRetrieved || wasVectorHit ? generatedAt : prev?.lastRecalledAt,
			lastInjectedAt: wasInjected ? generatedAt : prev?.lastInjectedAt,
			lastFeedbackAt: feedbackRow?.lastFeedbackAt ?? prev?.lastFeedbackAt,
			baseConfidence: Number(event.quality.confidence.toFixed(4)),
			qualityScore,
			lifecycleDecision,
			signals,
			evidenceRefs,
			nextCommands: uniqueNonEmpty(nextCommands, 12),
			prevHash,
		};
		const row = { ...base, entryHash: "" };
		row.entryHash = memoryQualityLedgerRowHash(row);
		prevHash = row.entryHash;
		return row;
	});
	const byDecision = (decision: MemoryQualityLifecycleDecisionV11) =>
		rows
			.filter((row) => row.lifecycleDecision === decision)
			.map((row) => row.eventId)
			.slice(0, 160);
	const requiredFeedbackEventIds = uniqueNonEmpty(
		rows.filter((row) => row.injectedCount > 0 && row.pendingFeedbackCount > 0).map((row) => row.eventId),
		120,
	);
	const operatorInjectionCommands = uniqueNonEmpty(
		rows
			.filter(
				(row) =>
					row.lifecycleDecision === "promote" || (row.lifecycleDecision === "retain" && row.qualityScore >= 68),
			)
			.flatMap((row) => events.find((event) => event.id === row.eventId)?.commands ?? []),
		24,
	);
	const avoidCommands = uniqueNonEmpty(
		rows
			.filter(
				(row) =>
					row.lifecycleDecision === "demote" ||
					row.lifecycleDecision === "quarantine" ||
					row.lifecycleDecision === "expire",
			)
			.flatMap((row) => events.find((event) => event.id === row.eventId)?.commands ?? []),
		24,
	);
	const averageQualityScore = rows.length
		? Number((rows.reduce((sum, row) => sum + row.qualityScore, 0) / rows.length).toFixed(2))
		: 0;
	const status: MemoryQualityLedgerReportV11["status"] =
		rows.length === 0
			? "empty"
			: rows.some((row) => row.lifecycleDecision === "quarantine" || row.forbiddenLeakCount > 0)
				? "blocked"
				: requiredFeedbackEventIds.length ||
						rows.some((row) => row.lifecycleDecision === "demote" || row.lifecycleDecision === "expire")
					? "warn"
					: "pass";
	const report: MemoryQualityLedgerReportV11 = {
		kind: "repi-memory-quality-ledger-report",
		schemaVersion: 1,
		generatedAt,
		MemoryQualityLedgerV11: true,
		active_memory_policy: true,
		quality_score_feedback_loop: true,
		usefulness_feedback_writeback: true,
		reportPath: memoryQualityReportPath(),
		ledgerPath: memoryQualityLedgerPath(),
		boardPath: memoryQualityBoardPath(),
		sourceRetrievalReportPath: memoryRetrievalReportPath(),
		sourceVectorSearchReportPath: memoryVectorSearchReportPath(),
		sourceFeedbackClosureReportPath: feedback.feedbackClosureReportPath,
		sourceUsefulnessEvalReportPath: usefulness?.reportPath ?? memoryUsefulnessEvalReportPath(),
		eventCount: events.length,
		rowCount: rows.length,
		averageQualityScore,
		promotedEventIds: byDecision("promote"),
		retainedEventIds: byDecision("retain"),
		demotedEventIds: byDecision("demote"),
		quarantinedEventIds: byDecision("quarantine"),
		expiredEventIds: byDecision("expire"),
		requiredFeedbackEventIds,
		operatorInjectionCommands,
		avoidCommands,
		status,
		rows: rows.slice(0, 80),
		requiredChecks: [
			"MemoryQualityLedgerV11",
			"active_memory_policy",
			"quality_score_feedback_loop",
			"usefulness_feedback_writeback",
			"append_only_quality_ledger",
			"memory_quality_drives_sedimentation",
			"memory_quality_in_context_pack",
			"memory_quality_orchestrator_step",
			"memory_ab_replay_feedback",
		],
		policy: {
			MemoryQualityLedgerV11: true,
			activeMemoryPolicy: true,
			qualityScoreFeedbackLoop: true,
			usefulnessFeedbackWriteback: true,
			appendOnlyQualityLedger: true,
			qualityDrivesSedimentation: true,
		},
		nextCommands: uniqueNonEmpty(
			[
				"re_memory quality",
				"re_memory replay",
				"re_memory eval",
				"re_memory feedback",
				requiredFeedbackEventIds.length
					? `re_memory append # close feedback for ${requiredFeedbackEventIds[0]}`
					: undefined,
				operatorInjectionCommands.length
					? "re_operator plan # consumes MemoryQualityLedgerV11 promoted/retained commands"
					: undefined,
				avoidCommands.length ? "re_autofix plan # avoid demoted/quarantined memory commands" : undefined,
				"re_context pack",
			].filter(Boolean) as string[],
			12,
		),
	};
	if (options.write !== false) {
		const before = readText(memoryQualityLedgerPath());
		const body = rows.map((row) => JSON.stringify(row)).join("\n");
		writeFileAtomic(
			memoryQualityLedgerPath(),
			`${before}${before && !before.endsWith("\n") ? "\n" : ""}${body}${body ? "\n" : ""}`,
		);
		writeFileAtomic(memoryQualityReportPath(), `${JSON.stringify(report, null, 2)}\n`);
		writeFileAtomic(
			memoryQualityBoardPath(),
			[
				"# REPI Memory Quality Board",
				"",
				"MemoryQualityLedgerV11: true",
				"active_memory_policy: true",
				"quality_score_feedback_loop: true",
				"usefulness_feedback_writeback: true",
				`generated_at: ${report.generatedAt}`,
				`status: ${report.status}`,
				`average_quality_score: ${report.averageQualityScore}`,
				"",
				"## Promoted",
				...(report.promotedEventIds.length ? report.promotedEventIds.map((id) => `- ${id}`) : ["- none"]),
				"",
				"## Demoted / Quarantined / Expired",
				...(uniqueNonEmpty(
					[...report.demotedEventIds, ...report.quarantinedEventIds, ...report.expiredEventIds],
					120,
				).length
					? uniqueNonEmpty(
							[...report.demotedEventIds, ...report.quarantinedEventIds, ...report.expiredEventIds],
							120,
						).map((id) => `- ${id}`)
					: ["- none"]),
				"",
				"## Pending Feedback",
				...(report.requiredFeedbackEventIds.length
					? report.requiredFeedbackEventIds.map((id) => `- ${id}`)
					: ["- none"]),
				"",
				"## Required Checks",
				...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
				"",
			].join("\n"),
		);
	}
	return report;
}

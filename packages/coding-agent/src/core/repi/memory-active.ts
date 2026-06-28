import { buildMemorySemanticIndex, type MemorySedimentationReportV1 } from "./memory-distillation.ts";
import { buildMemoryFeedbackClosureReport, type MemoryFeedbackClosureReportV1 } from "./memory-feedback.ts";
import { buildMemoryQualityLedgerReport, type MemoryQualityLedgerReportV11 } from "./memory-quality.ts";
import { buildMemoryReplayEvaluatorReport, type MemoryReplayEvaluatorReportV12 } from "./memory-replay.ts";
import {
	buildMemoryScopeIsolationReport,
	type MemoryScopeIsolationReportV1,
	memoryRouteMatches,
	memoryTargetScope,
} from "./memory-scope.ts";
import { readMemoryEvents } from "./memory-search.ts";
import { writeFileAtomic } from "./memory-store.ts";
import { buildMemoryStrategyCapsuleReport, type MemoryStrategyCapsuleReportV13 } from "./memory-strategy.ts";
import {
	ensureRepiStorage,
	memoryActiveInjectionPackPath,
	memoryActiveKernelReportPath,
	memoryActiveStrategyBoardPath,
	memoryFeedbackClosureReportPath,
	memoryQualityReportPath,
	memoryReplayEvaluatorReportPath,
	memorySedimentationReportPath,
	memoryStrategyCapsuleReportPath,
	readJsonObjectFile,
} from "./storage.ts";
import { sha256Text, uniqueNonEmpty } from "./text.ts";

export type MemoryActiveKernelActionV14 =
	| "inject"
	| "reuse"
	| "verify"
	| "repair"
	| "avoid"
	| "quarantine"
	| "wait-feedback"
	| "expire";

export type MemoryActiveKernelSourceV14 = "strategy" | "sedimentation" | "quality" | "feedback" | "supervisor";

export type MemoryActiveKernelDecisionV14 = {
	kind: "repi-memory-active-kernel-decision";
	schemaVersion: 1;
	id: string;
	ts: string;
	MemoryActiveKernelV14: true;
	unified_memory_decision_engine: true;
	active_recall_scheduler: true;
	scope_safe_strategy_injection: true;
	action: MemoryActiveKernelActionV14;
	route: string;
	targetScope: string;
	source: MemoryActiveKernelSourceV14;
	sourceEventIds: string[];
	sourceStrategyCapsuleIds: string[];
	sourceQualityRowIds: string[];
	sourceReplayRowIds: string[];
	activeScore: number;
	causalScore: number;
	qualityScore: number;
	confidence: number;
	commands: string[];
	verifierCommands: string[];
	fallbackCommands: string[];
	avoidCommands: string[];
	evidenceRefs: string[];
	triggerConditions: string[];
	applicabilityBoundary: string[];
	rationale: string[];
	preflightChecks: string[];
	feedbackWritebackCommands: string[];
	compactResumeHints: string[];
	blockers: string[];
	entryHash: string;
};

export type MemoryActiveInjectionPackV14 = {
	kind: "repi-memory-active-injection-pack";
	schemaVersion: 1;
	generatedAt: string;
	MemoryActiveKernelV14: true;
	active_recall_scheduler: true;
	budget: { maxDecisions: number; maxCommands: number; maxTokens: number };
	decisions: MemoryActiveKernelDecisionV14[];
	commands: string[];
	verifierRules: string[];
	fallbackCommands: string[];
	avoidCommands: string[];
	scopeLocks: string[];
	feedbackWriteback: string;
	compactResumeHints: string[];
	requiredChecks: string[];
};

export type MemoryActiveKernelReportV14 = {
	kind: "repi-memory-active-kernel-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryActiveKernelV14: true;
	unified_memory_decision_engine: true;
	active_recall_scheduler: true;
	cross_session_compact_ready: true;
	feedback_driven_promotion: true;
	scope_safe_strategy_injection: true;
	reportPath: string;
	injectionPackPath: string;
	strategyBoardPath: string;
	sourceSedimentationReportPath: string;
	sourceQualityReportPath: string;
	sourceReplayReportPath: string;
	sourceStrategyReportPath: string;
	sourceFeedbackReportPath: string;
	sourceScopeReportPath: string;
	decisionCount: number;
	injectDecisionIds: string[];
	reuseDecisionIds: string[];
	verifyDecisionIds: string[];
	repairDecisionIds: string[];
	avoidDecisionIds: string[];
	quarantineDecisionIds: string[];
	pendingFeedbackDecisionIds: string[];
	expiredDecisionIds: string[];
	operatorInjectionCommands: string[];
	verifierCommands: string[];
	fallbackCommands: string[];
	avoidCommands: string[];
	workerRoutingHints: string[];
	compactResumeHints: string[];
	status: "pass" | "warn" | "blocked" | "empty";
	decisions: MemoryActiveKernelDecisionV14[];
	activeInjectionPack: MemoryActiveInjectionPackV14;
	requiredChecks: string[];
	policy: {
		MemoryActiveKernelV14: true;
		unifiedMemoryDecisionEngine: true;
		activeRecallScheduler: true;
		qualityReplayStrategyFusion: true;
		scopeSafeStrategyInjection: true;
		feedbackDrivenPromotion: true;
		crossSessionCompactReady: true;
	};
	nextCommands: string[];
};

export type MemoryActiveKernelActionInputV14 = {
	score: number;
	source: MemoryActiveKernelSourceV14;
	lifecycle?:
		| "candidate"
		| "promoted"
		| "demoted"
		| "quarantined"
		| "promote"
		| "retain"
		| "demote"
		| "quarantine"
		| "expire";
	sedimentationAction?: "inject" | "retain" | "demote" | "expire" | "quarantine";
	hasCommands: boolean;
	scopeBlocked: boolean;
	pendingFeedback: boolean;
	blockers: string[];
};

export function memoryActiveKernelDecisionHash(decision: Omit<MemoryActiveKernelDecisionV14, "entryHash">): string {
	return sha256Text(JSON.stringify(decision));
}

export function memoryActiveKernelDecisionFrom(
	input: Omit<MemoryActiveKernelDecisionV14, "kind" | "schemaVersion" | "entryHash">,
): MemoryActiveKernelDecisionV14 {
	const decision = {
		kind: "repi-memory-active-kernel-decision" as const,
		schemaVersion: 1 as const,
		...input,
	};
	return { ...decision, entryHash: memoryActiveKernelDecisionHash(decision) };
}

export function memoryActiveKernelActionFromScore(
	input: MemoryActiveKernelActionInputV14,
): MemoryActiveKernelActionV14 {
	if (
		input.scopeBlocked ||
		input.blockers.some((blocker) => /scope_blocked|quarantine|forbidden_leak|cross[_-]scope/i.test(blocker))
	)
		return "quarantine";
	if (input.lifecycle === "quarantined" || input.lifecycle === "quarantine") return "quarantine";
	if (input.lifecycle === "expire" || input.sedimentationAction === "expire") return "expire";
	if (input.lifecycle === "demoted" || input.lifecycle === "demote" || input.sedimentationAction === "demote")
		return "avoid";
	if (input.pendingFeedback && input.score < 78) return "wait-feedback";
	if (!input.hasCommands) return input.score >= 55 ? "verify" : "repair";
	if (
		input.score >= 74 &&
		(input.lifecycle === "promoted" || input.lifecycle === "promote" || input.sedimentationAction === "inject")
	)
		return "inject";
	if (input.score >= 62) return "reuse";
	if (input.score >= 48) return "verify";
	return "repair";
}

export function formatMemoryActiveKernel(report: MemoryActiveKernelReportV14): string {
	return [
		"memory_active_kernel_v14:",
		`MemoryActiveKernelV14=${report.MemoryActiveKernelV14}`,
		`unified_memory_decision_engine=${report.unified_memory_decision_engine}`,
		`active_recall_scheduler=${report.active_recall_scheduler}`,
		`scope_safe_strategy_injection=${report.scope_safe_strategy_injection}`,
		`cross_session_compact_ready=${report.cross_session_compact_ready}`,
		`feedback_driven_promotion=${report.feedback_driven_promotion}`,
		`status=${report.status}`,
		`decisions=${report.decisionCount}`,
		`inject=${report.injectDecisionIds.length}`,
		`reuse=${report.reuseDecisionIds.length}`,
		`verify=${report.verifyDecisionIds.length}`,
		`avoid=${report.avoidDecisionIds.length}`,
		`quarantine=${report.quarantineDecisionIds.length}`,
		`pending_feedback=${report.pendingFeedbackDecisionIds.length}`,
		`report=${report.reportPath}`,
		`active_injection_pack=${report.injectionPackPath}`,
		`board=${report.strategyBoardPath}`,
		"operator_injection_commands:",
		...(report.operatorInjectionCommands.length
			? report.operatorInjectionCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"verifier_commands:",
		...(report.verifierCommands.length
			? report.verifierCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"active_decisions:",
		...(report.decisions.length
			? report.decisions
					.slice(0, 12)
					.map(
						(decision) =>
							`- ${decision.action} score=${decision.activeScore} source=${decision.source} route=${decision.route} target=${decision.targetScope} events=${decision.sourceEventIds.join(",") || "none"}`,
					)
			: ["- none"]),
		"next_commands:",
		...report.nextCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}

export function buildMemoryActiveKernelReport(
	options: {
		route?: string;
		target?: string;
		query?: string;
		sedimentation?: MemorySedimentationReportV1;
		quality?: MemoryQualityLedgerReportV11;
		replay?: MemoryReplayEvaluatorReportV12;
		strategy?: MemoryStrategyCapsuleReportV13;
		feedback?: MemoryFeedbackClosureReportV1;
		scope?: MemoryScopeIsolationReportV1;
		write?: boolean;
		maxDecisions?: number;
	} = {},
): MemoryActiveKernelReportV14 {
	ensureRepiStorage();
	const generatedAt = new Date().toISOString();
	const route = options.route;
	const target = options.target;
	const maxDecisions = options.maxDecisions ?? 12;
	const events = readMemoryEvents();
	const eventById = new Map(events.map((event) => [event.id, event]));
	const sedimentation =
		options.sedimentation ??
		readJsonObjectFile<MemorySedimentationReportV1>(memorySedimentationReportPath()) ??
		buildMemorySemanticIndex({ route, target, maxEntries: 32 });
	const feedback =
		options.feedback ??
		readJsonObjectFile<MemoryFeedbackClosureReportV1>(memoryFeedbackClosureReportPath()) ??
		buildMemoryFeedbackClosureReport({ sedimentation, write: options.write });
	const quality =
		options.quality ??
		readJsonObjectFile<MemoryQualityLedgerReportV11>(memoryQualityReportPath()) ??
		buildMemoryQualityLedgerReport({
			route,
			target,
			injectionEventIds: sedimentation.injectionPacket.entries.map((entry) => entry.eventId),
			feedback,
			write: options.write,
		});
	const replay =
		options.replay ??
		readJsonObjectFile<MemoryReplayEvaluatorReportV12>(memoryReplayEvaluatorReportPath()) ??
		buildMemoryReplayEvaluatorReport({ route, target, query: options.query, quality, write: options.write });
	const strategy =
		options.strategy ??
		readJsonObjectFile<MemoryStrategyCapsuleReportV13>(memoryStrategyCapsuleReportPath()) ??
		buildMemoryStrategyCapsuleReport({ route, target, quality, replay, write: options.write });
	const scope = options.scope ?? buildMemoryScopeIsolationReport({ route, target, events, write: options.write });
	const qualityByEvent = new Map((quality.rows ?? []).map((row) => [row.eventId, row]));
	const feedbackByEvent = new Map((feedback.rows ?? []).map((row) => [row.eventId, row]));
	const scopeByEvent = new Map((scope.rows ?? []).map((row) => [row.eventId, row]));
	const replayRowById = new Map((replay.rows ?? []).map((row) => [row.id, row]));
	const decisions: MemoryActiveKernelDecisionV14[] = [];
	const coveredEvents = new Set<string>();
	const addDecision = (decision: MemoryActiveKernelDecisionV14) => {
		if (options.route && decision.route && !memoryRouteMatches(decision.route, options.route)) return;
		if (options.target && decision.targetScope && !decision.targetScope.includes(memoryTargetScope(options.target)))
			return;
		const key = `${decision.action}:${decision.source}:${decision.sourceEventIds.join(",") || decision.sourceStrategyCapsuleIds.join(",")}:${decision.commands.join("\n")}`;
		if (
			decisions.some(
				(row) =>
					`${row.action}:${row.source}:${row.sourceEventIds.join(",") || row.sourceStrategyCapsuleIds.join(",")}:${row.commands.join("\n")}` ===
					key,
			)
		)
			return;
		for (const eventId of decision.sourceEventIds) coveredEvents.add(eventId);
		decisions.push(decision);
	};
	for (const capsule of strategy.recentCapsules ?? []) {
		const sourceEventIds = uniqueNonEmpty(capsule.sourceQualityEventIds, 24);
		const sourceQualityRows = sourceEventIds.flatMap((eventId) => {
			const row = qualityByEvent.get(eventId);
			return row ? [row] : [];
		});
		const sourceReplayRows = capsule.sourceReplayRowIds.flatMap((rowId) => {
			const row = replayRowById.get(rowId);
			return row ? [row] : [];
		});
		const sourceEvents = sourceEventIds.flatMap((eventId) => {
			const event = eventById.get(eventId);
			return event ? [event] : [];
		});
		const scopeBlocked = sourceEventIds.some((eventId) => scopeByEvent.get(eventId)?.blocksInjection === true);
		const pendingFeedback = sourceEventIds.some(
			(eventId) => feedbackByEvent.get(eventId)?.feedbackStatus === "pending",
		);
		const avgQuality = sourceQualityRows.length
			? sourceQualityRows.reduce((sum, row) => sum + row.qualityScore, 0) / sourceQualityRows.length
			: capsule.qualityScore;
		const avgCausal = sourceReplayRows.length
			? sourceReplayRows.reduce((sum, row) => sum + row.causalScore, 0) / sourceReplayRows.length
			: capsule.causalScore;
		const activeScore = Number(
			Math.max(
				0,
				Math.min(
					100,
					avgCausal * 0.38 +
						avgQuality * 0.34 +
						capsule.confidence * 100 * 0.18 +
						(capsule.recommendedCommands.length ? 7 : 0) +
						(capsule.lifecycle === "promoted"
							? 8
							: capsule.lifecycle === "candidate"
								? 0
								: capsule.lifecycle === "demoted"
									? -20
									: -35),
				),
			).toFixed(2),
		);
		const blockers = uniqueNonEmpty(
			[
				scopeBlocked ? "scope_blocked" : undefined,
				pendingFeedback ? "pending_feedback_after_injection" : undefined,
				capsule.lifecycle === "quarantined" ? "strategy_capsule_quarantined" : undefined,
				capsule.lifecycle === "demoted" ? "strategy_capsule_demoted" : undefined,
				...capsule.executionPolicy.stopConditions.filter(
					(condition) => /scope|poison|contradict/i.test(condition) && capsule.lifecycle !== "promoted",
				),
			],
			16,
		);
		const action = memoryActiveKernelActionFromScore({
			score: activeScore,
			source: "strategy",
			lifecycle: capsule.lifecycle,
			hasCommands: capsule.recommendedCommands.length > 0,
			scopeBlocked,
			pendingFeedback,
			blockers,
		});
		addDecision(
			memoryActiveKernelDecisionFrom({
				id: `mak:strategy:${sha256Text(`${capsule.id}:${action}:${activeScore}`).slice(0, 22)}`,
				ts: generatedAt,
				MemoryActiveKernelV14: true,
				unified_memory_decision_engine: true,
				active_recall_scheduler: true,
				scope_safe_strategy_injection: true,
				action,
				route: capsule.route,
				targetScope: capsule.targetScope,
				source: "strategy",
				sourceEventIds,
				sourceStrategyCapsuleIds: [capsule.id],
				sourceQualityRowIds: sourceQualityRows.map((row) => row.id),
				sourceReplayRowIds: capsule.sourceReplayRowIds,
				activeScore,
				causalScore: Number(avgCausal.toFixed(2)),
				qualityScore: Number(avgQuality.toFixed(2)),
				confidence: capsule.confidence,
				commands: capsule.recommendedCommands,
				verifierCommands: capsule.verifierCommands,
				fallbackCommands: capsule.fallbackCommands,
				avoidCommands: capsule.avoidCommands,
				evidenceRefs: uniqueNonEmpty(
					[
						...capsule.evidenceRefs,
						...sourceEvents.flatMap((event) => event.artifactHashes.map((artifact) => artifact.path)),
					],
					32,
				),
				triggerConditions: capsule.triggerConditions,
				applicabilityBoundary: capsule.applicabilityBoundary,
				rationale: uniqueNonEmpty(
					[
						`strategy_lifecycle=${capsule.lifecycle}`,
						`causal=${avgCausal.toFixed(2)}`,
						`quality=${avgQuality.toFixed(2)}`,
						`active_score=${activeScore}`,
					],
					12,
				),
				preflightChecks: uniqueNonEmpty(
					[...capsule.executionPolicy.preflightChecks, "re_memory active", "re_memory scope"],
					12,
				),
				feedbackWritebackCommands: sourceEventIds
					.map(
						(eventId) =>
							`re_memory append # active_kernel_feedback event=${eventId} decision=${action} score=${activeScore}`,
					)
					.slice(0, 12),
				compactResumeHints: uniqueNonEmpty(
					[
						...capsule.executionPolicy.compactResumeHints,
						"include active-kernel-report and active-injection-pack in ContextPackV2",
					],
					12,
				),
				blockers,
			}),
		);
	}
	for (const entry of sedimentation.entries.slice(0, 80)) {
		if (coveredEvents.has(entry.eventId)) continue;
		const event = eventById.get(entry.eventId);
		const qualityRow = qualityByEvent.get(entry.eventId);
		const feedbackRow = feedbackByEvent.get(entry.eventId);
		const scopeRow = scopeByEvent.get(entry.eventId);
		const activeScore = Number(
			Math.max(
				0,
				Math.min(
					100,
					entry.grade * 0.62 +
						(qualityRow?.qualityScore ?? entry.grade) * 0.28 +
						(entry.verifierRefs.length ? 5 : 0) +
						(entry.artifactRefs.length ? 5 : 0),
				),
			).toFixed(2),
		);
		const blockers = uniqueNonEmpty(
			[
				...entry.blockers,
				scopeRow?.blocksInjection ? "scope_blocked" : undefined,
				feedbackRow?.feedbackStatus === "pending" ? "pending_feedback_after_injection" : undefined,
			],
			16,
		);
		const action = memoryActiveKernelActionFromScore({
			score: activeScore,
			source: "sedimentation",
			lifecycle: qualityRow?.lifecycleDecision,
			sedimentationAction: entry.action,
			hasCommands: Boolean(event?.commands.length),
			scopeBlocked: scopeRow?.blocksInjection === true,
			pendingFeedback: feedbackRow?.feedbackStatus === "pending",
			blockers,
		});
		addDecision(
			memoryActiveKernelDecisionFrom({
				id: `mak:sediment:${sha256Text(`${entry.eventId}:${action}:${activeScore}`).slice(0, 22)}`,
				ts: generatedAt,
				MemoryActiveKernelV14: true,
				unified_memory_decision_engine: true,
				active_recall_scheduler: true,
				scope_safe_strategy_injection: true,
				action,
				route: entry.route,
				targetScope: entry.targetScope,
				source: "sedimentation",
				sourceEventIds: [entry.eventId],
				sourceStrategyCapsuleIds: [],
				sourceQualityRowIds: qualityRow ? [qualityRow.id] : [],
				sourceReplayRowIds: [],
				activeScore,
				causalScore: 0,
				qualityScore: qualityRow?.qualityScore ?? entry.grade,
				confidence: Number(
					(qualityRow?.baseConfidence ?? event?.quality.confidence ?? entry.grade / 100).toFixed(4),
				),
				commands: event?.commands ?? [],
				verifierCommands: entry.verifierRefs,
				fallbackCommands: ["re_memory replay", "re_memory quality", "re_autofix plan"],
				avoidCommands:
					qualityRow && ["demote", "quarantine", "expire"].includes(qualityRow.lifecycleDecision)
						? (event?.commands ?? [])
						: [],
				evidenceRefs: uniqueNonEmpty(
					[...entry.artifactRefs.map((artifact) => artifact.path), ...(qualityRow?.evidenceRefs ?? [])],
					32,
				),
				triggerConditions: uniqueNonEmpty(
					[`route=${entry.route}`, `target_scope=${entry.targetScope}`, `grade>=${Math.floor(entry.grade)}`],
					8,
				),
				applicabilityBoundary: uniqueNonEmpty(
					["same scope as MemoryScopeIsolationV1", ...blockers.map((blocker) => `blocked_when=${blocker}`)],
					12,
				),
				rationale: uniqueNonEmpty(
					[
						`sedimentation_action=${entry.action}`,
						`grade=${entry.grade}`,
						qualityRow ? `quality=${qualityRow.qualityScore}` : undefined,
					],
					12,
				),
				preflightChecks: ["re_memory scope", "re_memory feedback", "re_memory active"],
				feedbackWritebackCommands: [
					`re_memory append # active_kernel_feedback event=${entry.eventId} decision=${action} score=${activeScore}`,
				],
				compactResumeHints: [
					"include active-injection-pack in context pack",
					"rerun re_memory active after resume",
				],
				blockers,
			}),
		);
	}
	for (const row of quality.rows ?? []) {
		if (coveredEvents.has(row.eventId)) continue;
		if (!["demote", "quarantine", "expire"].includes(row.lifecycleDecision) && row.pendingFeedbackCount === 0)
			continue;
		const event = eventById.get(row.eventId);
		const action: MemoryActiveKernelActionV14 =
			row.pendingFeedbackCount > 0
				? "wait-feedback"
				: row.lifecycleDecision === "quarantine"
					? "quarantine"
					: row.lifecycleDecision === "expire"
						? "expire"
						: "avoid";
		addDecision(
			memoryActiveKernelDecisionFrom({
				id: `mak:quality:${sha256Text(`${row.eventId}:${action}:${row.qualityScore}`).slice(0, 22)}`,
				ts: generatedAt,
				MemoryActiveKernelV14: true,
				unified_memory_decision_engine: true,
				active_recall_scheduler: true,
				scope_safe_strategy_injection: true,
				action,
				route: row.route,
				targetScope: row.targetScope,
				source: row.pendingFeedbackCount > 0 ? "feedback" : "quality",
				sourceEventIds: [row.eventId],
				sourceStrategyCapsuleIds: [],
				sourceQualityRowIds: [row.id],
				sourceReplayRowIds: [],
				activeScore: row.qualityScore,
				causalScore: 0,
				qualityScore: row.qualityScore,
				confidence: row.baseConfidence,
				commands: action === "wait-feedback" ? row.nextCommands : [],
				verifierCommands: action === "wait-feedback" ? ["re_memory feedback", "re_verifier matrix"] : [],
				fallbackCommands: ["re_memory quality", "re_memory supervise"],
				avoidCommands:
					action === "avoid" || action === "quarantine" || action === "expire" ? (event?.commands ?? []) : [],
				evidenceRefs: row.evidenceRefs,
				triggerConditions: [`quality_decision=${row.lifecycleDecision}`, `route=${row.route}`],
				applicabilityBoundary: ["do not inject until feedback/quality state changes"],
				rationale: uniqueNonEmpty(
					[
						`quality_score=${row.qualityScore}`,
						`signals=${row.signals.join(",")}`,
						`pending_feedback=${row.pendingFeedbackCount}`,
					],
					8,
				),
				preflightChecks: ["re_memory feedback", "re_memory quality"],
				feedbackWritebackCommands: [`re_memory append # close_active_kernel_feedback event=${row.eventId}`],
				compactResumeHints: ["carry pending feedback decision across compact resume"],
				blockers: uniqueNonEmpty(
					[
						row.scopeBlocked ? "scope_blocked" : undefined,
						row.forbiddenLeakCount ? `forbidden_leak=${row.forbiddenLeakCount}` : undefined,
					],
					8,
				),
			}),
		);
	}
	const sorted = decisions
		.sort((left, right) => {
			const order = (action: MemoryActiveKernelActionV14) =>
				action === "inject"
					? 0
					: action === "reuse"
						? 1
						: action === "verify"
							? 2
							: action === "repair"
								? 3
								: action === "wait-feedback"
									? 4
									: action === "avoid"
										? 5
										: action === "quarantine"
											? 6
											: 7;
			return (
				order(left.action) - order(right.action) ||
				right.activeScore - left.activeScore ||
				left.id.localeCompare(right.id)
			);
		})
		.slice(0, Math.max(maxDecisions, 24));
	const activeDecisions = sorted
		.filter((decision) => ["inject", "reuse", "verify", "repair"].includes(decision.action))
		.slice(0, maxDecisions);
	const byAction = (action: MemoryActiveKernelActionV14) => sorted.filter((decision) => decision.action === action);
	const operatorInjectionCommands = uniqueNonEmpty(
		activeDecisions
			.filter((decision) => decision.action === "inject" || decision.action === "reuse")
			.flatMap((decision) => decision.commands),
		32,
	);
	const verifierCommands = uniqueNonEmpty(
		activeDecisions.flatMap((decision) => decision.verifierCommands),
		24,
	);
	const fallbackCommands = uniqueNonEmpty(
		activeDecisions.flatMap((decision) => decision.fallbackCommands),
		20,
	);
	const avoidCommands = uniqueNonEmpty(
		sorted.flatMap((decision) => decision.avoidCommands),
		32,
	);
	const workerRoutingHints = uniqueNonEmpty(
		sorted.flatMap((decision) => decision.triggerConditions.map((condition) => `active_kernel:${condition}`)),
		24,
	);
	const compactResumeHints = uniqueNonEmpty(
		sorted.flatMap((decision) => decision.compactResumeHints),
		24,
	);
	const activeInjectionPack: MemoryActiveInjectionPackV14 = {
		kind: "repi-memory-active-injection-pack",
		schemaVersion: 1,
		generatedAt,
		MemoryActiveKernelV14: true,
		active_recall_scheduler: true,
		budget: { maxDecisions, maxCommands: 32, maxTokens: 4200 },
		decisions: activeDecisions,
		commands: operatorInjectionCommands,
		verifierRules: verifierCommands,
		fallbackCommands,
		avoidCommands,
		scopeLocks: uniqueNonEmpty(
			activeDecisions.map((decision) => `${decision.route}:${decision.targetScope}`),
			24,
		),
		feedbackWriteback:
			"Every active kernel injected/reused decision must append active_kernel_feedback with event id, outcome, artifact sha256, verifier result, and score delta.",
		compactResumeHints,
		requiredChecks: [
			"MemoryActiveKernelV14",
			"unified_memory_decision_engine",
			"active_recall_scheduler",
			"quality_replay_strategy_fusion",
			"scope_safe_strategy_injection",
			"feedback_driven_promotion",
			"cross_session_compact_ready",
		],
	};
	const status: MemoryActiveKernelReportV14["status"] =
		sorted.length === 0
			? "empty"
			: activeDecisions.length === 0 && (byAction("quarantine").length || byAction("avoid").length)
				? "blocked"
				: byAction("wait-feedback").length ||
						byAction("verify").length ||
						byAction("repair").length ||
						byAction("avoid").length ||
						byAction("quarantine").length
					? "warn"
					: "pass";
	const report: MemoryActiveKernelReportV14 = {
		kind: "repi-memory-active-kernel-report",
		schemaVersion: 1,
		generatedAt,
		MemoryActiveKernelV14: true,
		unified_memory_decision_engine: true,
		active_recall_scheduler: true,
		cross_session_compact_ready: true,
		feedback_driven_promotion: true,
		scope_safe_strategy_injection: true,
		reportPath: memoryActiveKernelReportPath(),
		injectionPackPath: memoryActiveInjectionPackPath(),
		strategyBoardPath: memoryActiveStrategyBoardPath(),
		sourceSedimentationReportPath: sedimentation.injectionPacketPath,
		sourceQualityReportPath: quality.reportPath,
		sourceReplayReportPath: replay.reportPath,
		sourceStrategyReportPath: strategy.reportPath,
		sourceFeedbackReportPath: feedback.feedbackClosureReportPath,
		sourceScopeReportPath: scope.scopeIsolationReportPath,
		decisionCount: sorted.length,
		injectDecisionIds: byAction("inject").map((decision) => decision.id),
		reuseDecisionIds: byAction("reuse").map((decision) => decision.id),
		verifyDecisionIds: byAction("verify").map((decision) => decision.id),
		repairDecisionIds: byAction("repair").map((decision) => decision.id),
		avoidDecisionIds: byAction("avoid").map((decision) => decision.id),
		quarantineDecisionIds: byAction("quarantine").map((decision) => decision.id),
		pendingFeedbackDecisionIds: byAction("wait-feedback").map((decision) => decision.id),
		expiredDecisionIds: byAction("expire").map((decision) => decision.id),
		operatorInjectionCommands,
		verifierCommands,
		fallbackCommands,
		avoidCommands,
		workerRoutingHints,
		compactResumeHints,
		status,
		decisions: sorted,
		activeInjectionPack,
		requiredChecks: activeInjectionPack.requiredChecks,
		policy: {
			MemoryActiveKernelV14: true,
			unifiedMemoryDecisionEngine: true,
			activeRecallScheduler: true,
			qualityReplayStrategyFusion: true,
			scopeSafeStrategyInjection: true,
			feedbackDrivenPromotion: true,
			crossSessionCompactReady: true,
		},
		nextCommands: uniqueNonEmpty(
			[
				"re_memory active",
				operatorInjectionCommands.length ? "re_operator plan # consumes active-kernel injection pack" : undefined,
				verifierCommands.length ? "re_verifier matrix # verify active memory decision before claim" : undefined,
				avoidCommands.length ? "re_autofix plan # avoid/quarantine active-kernel demotions" : undefined,
				"re_context pack",
			].filter(Boolean) as string[],
			12,
		),
	};
	if (options.write !== false) {
		writeFileAtomic(memoryActiveKernelReportPath(), `${JSON.stringify(report, null, 2)}\n`);
		writeFileAtomic(memoryActiveInjectionPackPath(), `${JSON.stringify(activeInjectionPack, null, 2)}\n`);
		writeFileAtomic(
			memoryActiveStrategyBoardPath(),
			[
				"# REPI Memory Active Strategy Board",
				"",
				"MemoryActiveKernelV14: true",
				"unified_memory_decision_engine: true",
				"active_recall_scheduler: true",
				"scope_safe_strategy_injection: true",
				`generated_at: ${generatedAt}`,
				`status: ${status}`,
				"",
				"## Active decisions",
				...(activeDecisions.length
					? activeDecisions.map(
							(decision) =>
								`- ${decision.action} score=${decision.activeScore} route=${decision.route} target=${decision.targetScope} commands=${decision.commands.slice(0, 2).join(" && ") || "none"}`,
						)
					: ["- none"]),
				"",
				"## Avoid / quarantine",
				...(byAction("avoid").length || byAction("quarantine").length || byAction("expire").length
					? [...byAction("avoid"), ...byAction("quarantine"), ...byAction("expire")].map(
							(decision) =>
								`- ${decision.action} score=${decision.activeScore} source=${decision.source} events=${decision.sourceEventIds.join(",") || "none"} blockers=${decision.blockers.join(",") || "none"}`,
						)
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

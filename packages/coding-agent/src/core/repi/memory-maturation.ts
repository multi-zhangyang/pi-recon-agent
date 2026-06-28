import {
	buildMemoryActiveKernelReport,
	type MemoryActiveKernelDecisionV14,
	type MemoryActiveKernelReportV14,
} from "./memory-active.ts";
import { buildMemoryDepositionReport, type MemoryDepositionReportV7 } from "./memory-deposition.ts";
import { buildMemoryDistillPromotionReport, type MemoryDistillPromotionReportV10 } from "./memory-distill.ts";
import type { MemoryEventV1 } from "./memory-event.ts";
import { buildMemoryExperienceReport, type MemoryExperienceReportV8 } from "./memory-experience.ts";
import { buildMemoryQualityLedgerReport, type MemoryQualityLedgerReportV11 } from "./memory-quality.ts";
import { buildMemoryReplayEvaluatorReport, type MemoryReplayEvaluatorReportV12 } from "./memory-replay.ts";
import { memoryRouteMatches, memoryTargetScope } from "./memory-scope.ts";
import { readMemoryEvents } from "./memory-search.ts";
import { buildMemorySkillCapsuleReport, type MemorySkillCapsuleReportV9 } from "./memory-skill.ts";
import { writeFileAtomic } from "./memory-store.ts";
import { buildMemoryStrategyCapsuleReport, type MemoryStrategyCapsuleReportV13 } from "./memory-strategy.ts";
import {
	ensureRepiStorage,
	memoryMaturationActionBoardPath,
	memoryMaturationRuntimeLedgerPath,
	memoryMaturationRuntimeReportPath,
} from "./storage.ts";
import { sha256Text, uniqueNonEmpty } from "./text.ts";

export type MemoryMaturationActionV15 =
	| "promote"
	| "retain"
	| "demote"
	| "quarantine"
	| "feedback-required"
	| "replay-required";

export type MemoryMaturationRetentionActionV15 = "keep" | "rehearse" | "decay" | "expire" | "quarantine" | "feedback";

export type MemoryMaturationRowV15 = {
	kind: "repi-memory-maturation-row";
	schemaVersion: 1;
	id: string;
	ts: string;
	MemoryMaturationRuntimeV15: true;
	automatic_memory_maturation_pipeline: true;
	tool_result_to_strategy_loop: true;
	closed_loop_writeback: true;
	retention_decay_scheduler: true;
	stale_memory_rehearsal_queue: true;
	usefulness_backprop_to_maturation: true;
	action: MemoryMaturationActionV15;
	retentionAction: MemoryMaturationRetentionActionV15;
	stagePath: string[];
	route: string;
	targetScope: string;
	sourceEventIds: string[];
	sourceStrategyCapsuleIds: string[];
	sourceActiveDecisionIds: string[];
	sourceQualityRowIds: string[];
	sourceReplayRowIds: string[];
	maturityScore: number;
	retentionScore: number;
	stalenessDays: number;
	decayPenalty: number;
	lastUsefulAt: string;
	activeScore: number;
	qualityScore: number;
	causalScore: number;
	confidence: number;
	evidenceRefs: string[];
	commands: string[];
	verifierCommands: string[];
	fallbackCommands: string[];
	avoidCommands: string[];
	feedbackCommands: string[];
	retentionCommands: string[];
	nextCommands: string[];
	blockers: string[];
	rationale: string[];
	prevHash: string;
	entryHash: string;
};

export type MemoryMaturationRuntimeReportV15 = {
	kind: "repi-memory-maturation-runtime-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryMaturationRuntimeV15: true;
	automatic_memory_maturation_pipeline: true;
	tool_result_to_strategy_loop: true;
	closed_loop_writeback: true;
	retention_decay_scheduler: true;
	stale_memory_rehearsal_queue: true;
	usefulness_backprop_to_maturation: true;
	promotion_demotion_replay_backed: true;
	cross_session_maturation_ready: true;
	reportPath: string;
	ledgerPath: string;
	actionBoardPath: string;
	sourceDepositionReportPath: string;
	sourceExperienceReportPath: string;
	sourceSkillCapsuleReportPath: string;
	sourceDistillPromotionReportPath: string;
	sourceQualityReportPath: string;
	sourceReplayReportPath: string;
	sourceStrategyReportPath: string;
	sourceActiveKernelReportPath: string;
	rowCount: number;
	promotedEventIds: string[];
	retainedEventIds: string[];
	demotedEventIds: string[];
	quarantinedEventIds: string[];
	pendingFeedbackEventIds: string[];
	replayRequiredEventIds: string[];
	retentionQueueEventIds: string[];
	expiredEventIds: string[];
	operatorCommands: string[];
	verifierCommands: string[];
	fallbackCommands: string[];
	avoidCommands: string[];
	feedbackCommands: string[];
	retentionCommands: string[];
	workerRoutingHints: string[];
	compactResumeHints: string[];
	maturationCoverage: number;
	status: "pass" | "warn" | "blocked" | "empty";
	rows: MemoryMaturationRowV15[];
	requiredChecks: string[];
	policy: {
		MemoryMaturationRuntimeV15: true;
		automaticMemoryMaturationPipeline: true;
		toolResultToStrategyLoop: true;
		closedLoopWriteback: true;
		retentionDecayScheduler: true;
		staleMemoryRehearsalQueue: true;
		usefulnessBackpropToMaturation: true;
		promotionDemotionReplayBacked: true;
		crossSessionMaturationReady: true;
	};
	nextCommands: string[];
};

export type MemoryMaturationRetentionSignalV15 = {
	retentionAction: MemoryMaturationRetentionActionV15;
	retentionScore: number;
	stalenessDays: number;
	decayPenalty: number;
	lastUsefulAt: string;
	retentionCommands: string[];
	rationale: string[];
};

export function memoryMaturationRowHash(row: Omit<MemoryMaturationRowV15, "entryHash">): string {
	return sha256Text(JSON.stringify(row));
}

export function memoryMaturationActionFromDecision(
	decision: MemoryActiveKernelDecisionV14,
	score: number,
): MemoryMaturationActionV15 {
	if (
		decision.action === "quarantine" ||
		decision.blockers.some((blocker) => /scope_blocked|quarantine|forbidden_leak|poison/i.test(blocker))
	)
		return "quarantine";
	if (decision.action === "avoid" || decision.action === "expire") return "demote";
	if (decision.action === "wait-feedback") return "feedback-required";
	if (
		!decision.sourceReplayRowIds.length &&
		decision.causalScore <= 0 &&
		["inject", "reuse"].includes(decision.action)
	)
		return "replay-required";
	if (["inject", "reuse"].includes(decision.action) && score >= 72 && decision.evidenceRefs.length) return "promote";
	return "retain";
}

export function memoryMaturationRowFrom(
	input: Omit<MemoryMaturationRowV15, "kind" | "schemaVersion" | "entryHash">,
): MemoryMaturationRowV15 {
	const row = {
		kind: "repi-memory-maturation-row" as const,
		schemaVersion: 1 as const,
		...input,
	};
	return { ...row, entryHash: memoryMaturationRowHash(row) };
}

export function memoryMaturationDaysSince(timestamp: string | undefined, now: string): number {
	if (!timestamp) return 0;
	const then = Date.parse(timestamp);
	const current = Date.parse(now);
	if (!Number.isFinite(then) || !Number.isFinite(current) || current < then) return 0;
	return Number(((current - then) / 86_400_000).toFixed(2));
}

export function memoryMaturationRetentionSignal(input: {
	action: MemoryMaturationActionV15;
	decision: MemoryActiveKernelDecisionV14;
	sourceEvents: MemoryEventV1[];
	maturityScore: number;
	generatedAt: string;
}): MemoryMaturationRetentionSignalV15 {
	const { action, decision, sourceEvents, maturityScore, generatedAt } = input;
	const lastUsefulCandidates = uniqueNonEmpty(
		[
			...sourceEvents.map((event) => event.quality.lastUsefulAt),
			...sourceEvents.map((event) => event.ts),
			decision.ts,
		],
		16,
	);
	const lastUsefulAt =
		lastUsefulCandidates
			.map((value) => ({ value, ms: Date.parse(value) }))
			.filter((item) => Number.isFinite(item.ms))
			.sort((a, b) => b.ms - a.ms)[0]?.value ?? generatedAt;
	const stalenessDays = memoryMaturationDaysSince(lastUsefulAt, generatedAt);
	const reuseCount = sourceEvents.reduce((sum, event) => sum + Math.max(0, event.quality.reuseCount ?? 0), 0);
	const failureCount = sourceEvents.reduce((sum, event) => sum + Math.max(0, event.quality.failureCount ?? 0), 0);
	const sourceDecay = sourceEvents.reduce((sum, event) => sum + Math.max(0, event.quality.decay ?? 0), 0);
	const stalePenalty = Math.min(28, stalenessDays * 0.18);
	const failurePenalty = Math.min(24, failureCount * 6 + sourceDecay * 100);
	const replayBonus = decision.sourceReplayRowIds.length ? 8 : 0;
	const reuseBonus = Math.min(10, reuseCount * 1.5);
	const feedbackPenalty = action === "feedback-required" ? 6 : 0;
	const replayPenalty = action === "replay-required" ? 8 : 0;
	const decayPenalty = Number(
		Math.max(0, stalePenalty + failurePenalty + feedbackPenalty + replayPenalty - replayBonus - reuseBonus).toFixed(
			2,
		),
	);
	const retentionScore = Number(
		Math.max(0, Math.min(100, maturityScore - decayPenalty + replayBonus + reuseBonus)).toFixed(2),
	);
	let retentionAction: MemoryMaturationRetentionActionV15 = "keep";
	if (
		action === "quarantine" ||
		decision.blockers.some((blocker) => /scope_blocked|quarantine|poison|forbidden/i.test(blocker))
	)
		retentionAction = "quarantine";
	else if ((action === "demote" && retentionScore < 35) || (stalenessDays > 90 && retentionScore < 55))
		retentionAction = "expire";
	else if (action === "demote") retentionAction = "decay";
	else if (action === "feedback-required") retentionAction = "feedback";
	else if (action === "replay-required" || stalenessDays > 30) retentionAction = "rehearse";
	const firstEventId = decision.sourceEventIds[0] ?? decision.id;
	const retentionCommands = uniqueNonEmpty(
		[
			retentionAction === "rehearse" ? `re_memory replay # retention_rehearsal event=${firstEventId}` : undefined,
			retentionAction === "feedback" ? `re_memory feedback # retention_feedback event=${firstEventId}` : undefined,
			retentionAction === "decay" || retentionAction === "expire" || retentionAction === "quarantine"
				? `re_memory supervise # retention_${retentionAction} event=${firstEventId}`
				: undefined,
			retentionAction === "keep" ? `re_memory quality # retention_keep event=${firstEventId}` : undefined,
		],
		8,
	);
	return {
		retentionAction,
		retentionScore,
		stalenessDays,
		decayPenalty,
		lastUsefulAt,
		retentionCommands,
		rationale: [
			`retention_action=${retentionAction}`,
			`retention_score=${retentionScore}`,
			`staleness_days=${stalenessDays}`,
			`decay_penalty=${decayPenalty}`,
			`reuse_count=${reuseCount}`,
			`failure_count=${failureCount}`,
		],
	};
}

export function formatMemoryMaturationRuntime(report: MemoryMaturationRuntimeReportV15): string {
	return [
		"memory_maturation_runtime_v15:",
		`MemoryMaturationRuntimeV15=${report.MemoryMaturationRuntimeV15}`,
		`automatic_memory_maturation_pipeline=${report.automatic_memory_maturation_pipeline}`,
		`tool_result_to_strategy_loop=${report.tool_result_to_strategy_loop}`,
		`closed_loop_writeback=${report.closed_loop_writeback}`,
		`retention_decay_scheduler=${report.retention_decay_scheduler}`,
		`stale_memory_rehearsal_queue=${report.stale_memory_rehearsal_queue}`,
		`usefulness_backprop_to_maturation=${report.usefulness_backprop_to_maturation}`,
		`promotion_demotion_replay_backed=${report.promotion_demotion_replay_backed}`,
		`cross_session_maturation_ready=${report.cross_session_maturation_ready}`,
		`status=${report.status}`,
		`rows=${report.rowCount}`,
		`promoted=${report.promotedEventIds.length}`,
		`retained=${report.retainedEventIds.length}`,
		`demoted=${report.demotedEventIds.length}`,
		`quarantined=${report.quarantinedEventIds.length}`,
		`pending_feedback=${report.pendingFeedbackEventIds.length}`,
		`replay_required=${report.replayRequiredEventIds.length}`,
		`retention_queue=${report.retentionQueueEventIds.length}`,
		`expired=${report.expiredEventIds.length}`,
		`coverage=${report.maturationCoverage}`,
		`report=${report.reportPath}`,
		`ledger=${report.ledgerPath}`,
		`board=${report.actionBoardPath}`,
		"operator_commands:",
		...(report.operatorCommands.length
			? report.operatorCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"feedback_commands:",
		...(report.feedbackCommands.length
			? report.feedbackCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"retention_commands:",
		...(report.retentionCommands.length
			? report.retentionCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"maturation_rows:",
		...(report.rows.length
			? report.rows
					.slice(0, 12)
					.map(
						(row) =>
							`- ${row.action}/${row.retentionAction} maturity=${row.maturityScore} retention=${row.retentionScore} stale=${row.stalenessDays}d stages=${row.stagePath.join("->")} events=${row.sourceEventIds.join(",") || "none"}`,
					)
			: ["- none"]),
		"next_commands:",
		...report.nextCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}

export function buildMemoryMaturationRuntimeReport(
	options: {
		route?: string;
		target?: string;
		query?: string;
		deposition?: MemoryDepositionReportV7;
		experience?: MemoryExperienceReportV8;
		skillCapsules?: MemorySkillCapsuleReportV9;
		distillPromotion?: MemoryDistillPromotionReportV10;
		quality?: MemoryQualityLedgerReportV11;
		replay?: MemoryReplayEvaluatorReportV12;
		strategy?: MemoryStrategyCapsuleReportV13;
		active?: MemoryActiveKernelReportV14;
		write?: boolean;
		maxRows?: number;
	} = {},
): MemoryMaturationRuntimeReportV15 {
	ensureRepiStorage();
	const generatedAt = new Date().toISOString();
	const route = options.route;
	const target = options.target;
	const deposition = options.deposition ?? buildMemoryDepositionReport({ write: options.write });
	const experience = options.experience ?? buildMemoryExperienceReport({ write: options.write, route, target });
	const skillCapsules =
		options.skillCapsules ?? buildMemorySkillCapsuleReport({ write: options.write, route, target });
	const distillPromotion =
		options.distillPromotion ?? buildMemoryDistillPromotionReport({ write: options.write, route, target });
	const quality = options.quality ?? buildMemoryQualityLedgerReport({ write: options.write, route, target });
	const replay =
		options.replay ??
		buildMemoryReplayEvaluatorReport({ write: options.write, route, target, query: options.query, quality });
	const strategy =
		options.strategy ??
		buildMemoryStrategyCapsuleReport({ write: options.write, route, target, quality, replay, skillCapsules });
	const active =
		options.active ??
		buildMemoryActiveKernelReport({
			write: options.write,
			route,
			target,
			query: options.query,
			quality,
			replay,
			strategy,
		});
	const events = readMemoryEvents();
	const eventById = new Map(events.map((event) => [event.id, event]));
	const depositionByMemoryEvent = new Map(
		(deposition.recentEvents ?? [])
			.filter((event) => event.memoryEventId)
			.map((event) => [event.memoryEventId as string, event]),
	);
	const rows: MemoryMaturationRowV15[] = [];
	let prevHash = "0".repeat(64);
	const addRow = (input: Omit<MemoryMaturationRowV15, "kind" | "schemaVersion" | "entryHash" | "prevHash">) => {
		const row = memoryMaturationRowFrom({ ...input, prevHash });
		prevHash = row.entryHash;
		rows.push(row);
	};
	for (const decision of active.decisions.slice(0, options.maxRows ?? 32)) {
		if (route && decision.route && !memoryRouteMatches(decision.route, route)) continue;
		if (target && decision.targetScope && !decision.targetScope.includes(memoryTargetScope(target))) continue;
		const sourceEvents = decision.sourceEventIds.flatMap((eventId) => {
			const event = eventById.get(eventId);
			return event ? [event] : [];
		});
		const hasRuntimeWriteback = decision.sourceEventIds.some((eventId) => depositionByMemoryEvent.has(eventId));
		const maturityScore = Number(
			Math.max(
				0,
				Math.min(
					100,
					decision.activeScore * 0.32 +
						decision.qualityScore * 0.24 +
						decision.causalScore * 0.22 +
						decision.confidence * 100 * 0.12 +
						(decision.evidenceRefs.length ? 5 : 0) +
						(hasRuntimeWriteback ? 5 : 0),
				),
			).toFixed(2),
		);
		const action = memoryMaturationActionFromDecision(decision, maturityScore);
		const retention = memoryMaturationRetentionSignal({ action, decision, sourceEvents, maturityScore, generatedAt });
		const stagePath = uniqueNonEmpty(
			[
				hasRuntimeWriteback ? "runtime-event" : "memory-event",
				"episode",
				"lesson",
				decision.sourceStrategyCapsuleIds.length
					? "strategy-capsule"
					: skillCapsules.capsuleCount
						? "skill-capsule"
						: undefined,
				"active-decision",
				retention.retentionAction !== "keep" ? "retention-decay" : undefined,
				action === "feedback-required" ? "feedback-closure" : undefined,
				action === "replay-required" || retention.retentionAction === "rehearse" ? "ab-replay" : undefined,
			],
			10,
		);
		const feedbackCommands = uniqueNonEmpty(
			[
				...decision.feedbackWritebackCommands,
				action === "promote"
					? `re_memory append outcome=success replayVerified=true playbookCandidate=true # maturation_promote ${decision.sourceEventIds[0] ?? decision.id}`
					: undefined,
				action === "demote" || action === "quarantine"
					? `re_memory append outcome=failure confidence=0.7 # maturation_demote ${decision.sourceEventIds[0] ?? decision.id}`
					: undefined,
				action === "feedback-required"
					? `re_memory feedback # maturation_close_feedback ${decision.sourceEventIds[0] ?? decision.id}`
					: undefined,
			],
			16,
		);
		const nextCommands = uniqueNonEmpty(
			[
				action === "promote" ? "re_memory playbooks" : undefined,
				action === "retain" ? "re_memory quality" : undefined,
				action === "demote" || action === "quarantine" ? "re_memory supervise" : undefined,
				action === "replay-required" ? "re_memory replay" : undefined,
				action === "feedback-required" ? "re_memory feedback" : undefined,
				...retention.retentionCommands,
				"re_memory mature",
				"re_context pack",
			],
			14,
		);
		addRow({
			id: `mmr:${sha256Text(`${decision.id}:${action}:${maturityScore}`).slice(0, 22)}`,
			ts: generatedAt,
			MemoryMaturationRuntimeV15: true,
			automatic_memory_maturation_pipeline: true,
			tool_result_to_strategy_loop: true,
			closed_loop_writeback: true,
			retention_decay_scheduler: true,
			stale_memory_rehearsal_queue: true,
			usefulness_backprop_to_maturation: true,
			action,
			retentionAction: retention.retentionAction,
			stagePath,
			route: decision.route,
			targetScope: decision.targetScope,
			sourceEventIds: decision.sourceEventIds,
			sourceStrategyCapsuleIds: decision.sourceStrategyCapsuleIds,
			sourceActiveDecisionIds: [decision.id],
			sourceQualityRowIds: decision.sourceQualityRowIds,
			sourceReplayRowIds: decision.sourceReplayRowIds,
			maturityScore,
			retentionScore: retention.retentionScore,
			stalenessDays: retention.stalenessDays,
			decayPenalty: retention.decayPenalty,
			lastUsefulAt: retention.lastUsefulAt,
			activeScore: decision.activeScore,
			qualityScore: decision.qualityScore,
			causalScore: decision.causalScore,
			confidence: decision.confidence,
			evidenceRefs: uniqueNonEmpty(
				[
					...decision.evidenceRefs,
					...sourceEvents.flatMap((event) => event.artifactHashes.map((artifact) => artifact.path)),
				],
				32,
			),
			commands: decision.commands,
			verifierCommands: decision.verifierCommands,
			fallbackCommands: decision.fallbackCommands,
			avoidCommands: decision.avoidCommands,
			feedbackCommands,
			retentionCommands: retention.retentionCommands,
			nextCommands,
			blockers: decision.blockers,
			rationale: uniqueNonEmpty(
				[
					`active_action=${decision.action}`,
					`maturity_score=${maturityScore}`,
					`stage_path=${stagePath.join("->")}`,
					hasRuntimeWriteback ? "runtime_writeback=true" : "runtime_writeback=false",
					...retention.rationale,
				],
				18,
			),
		});
	}
	for (const runtimeEvent of deposition.recentEvents.slice(0, 12)) {
		if (
			!runtimeEvent.memoryEventId ||
			rows.some((row) => row.sourceEventIds.includes(runtimeEvent.memoryEventId as string))
		)
			continue;
		const action: MemoryMaturationActionV15 =
			runtimeEvent.status === "blocked"
				? "quarantine"
				: runtimeEvent.status === "queued"
					? "feedback-required"
					: runtimeEvent.outcome === "failure"
						? "demote"
						: "retain";
		const maturityScore = Number(
			Math.max(
				0,
				Math.min(
					100,
					runtimeEvent.confidence * 100 +
						(runtimeEvent.artifactHashes.length ? 8 : 0) -
						(runtimeEvent.status === "blocked" ? 30 : 0),
				),
			).toFixed(2),
		);
		const retentionAction: MemoryMaturationRetentionActionV15 =
			action === "quarantine"
				? "quarantine"
				: action === "demote"
					? "decay"
					: action === "feedback-required"
						? "feedback"
						: "keep";
		const retentionCommands = uniqueNonEmpty(
			[
				retentionAction === "feedback"
					? `re_memory feedback # retention_feedback event=${runtimeEvent.memoryEventId}`
					: undefined,
				retentionAction === "decay" || retentionAction === "quarantine"
					? `re_memory supervise # retention_${retentionAction} event=${runtimeEvent.memoryEventId}`
					: undefined,
				retentionAction === "keep"
					? `re_memory quality # retention_keep event=${runtimeEvent.memoryEventId}`
					: undefined,
			],
			8,
		);
		addRow({
			id: `mmr:deposition:${sha256Text(`${runtimeEvent.id}:${action}`).slice(0, 18)}`,
			ts: generatedAt,
			MemoryMaturationRuntimeV15: true,
			automatic_memory_maturation_pipeline: true,
			tool_result_to_strategy_loop: true,
			closed_loop_writeback: true,
			retention_decay_scheduler: true,
			stale_memory_rehearsal_queue: true,
			usefulness_backprop_to_maturation: true,
			action,
			retentionAction,
			stagePath: uniqueNonEmpty(
				[
					"runtime-event",
					"memory-event",
					"episode",
					retentionAction !== "keep" ? "retention-decay" : undefined,
					"feedback-closure",
				],
				8,
			),
			route: runtimeEvent.route,
			targetScope: memoryTargetScope(runtimeEvent.target),
			sourceEventIds: [runtimeEvent.memoryEventId],
			sourceStrategyCapsuleIds: [],
			sourceActiveDecisionIds: [],
			sourceQualityRowIds: [],
			sourceReplayRowIds: [],
			maturityScore,
			retentionScore: maturityScore,
			stalenessDays: 0,
			decayPenalty: retentionAction === "keep" ? 0 : 6,
			lastUsefulAt: runtimeEvent.ts,
			activeScore: 0,
			qualityScore: 0,
			causalScore: 0,
			confidence: runtimeEvent.confidence,
			evidenceRefs: runtimeEvent.artifactHashes.map((artifact) => artifact.path),
			commands: runtimeEvent.commands,
			verifierCommands: runtimeEvent.claimIds.map((claimId) => `re_verifier matrix # claim=${claimId}`),
			fallbackCommands: ["re_memory quality", "re_memory active"],
			avoidCommands: runtimeEvent.outcome === "failure" ? runtimeEvent.commands : [],
			feedbackCommands: [
				`re_memory append # maturation_runtime_feedback event=${runtimeEvent.memoryEventId} status=${runtimeEvent.status}`,
			],
			retentionCommands,
			nextCommands: uniqueNonEmpty(
				["re_memory experience", "re_memory quality", ...retentionCommands, "re_memory mature"],
				10,
			),
			blockers: runtimeEvent.status === "blocked" ? [runtimeEvent.reason] : [],
			rationale: [
				`runtime_status=${runtimeEvent.status}`,
				`outcome=${runtimeEvent.outcome}`,
				`coverage=${deposition.autoWritebackCoverage}`,
				`retention_action=${retentionAction}`,
			],
		});
	}
	const byAction = (action: MemoryMaturationActionV15) => rows.filter((row) => row.action === action);
	const promotedEventIds = uniqueNonEmpty(
		byAction("promote").flatMap((row) => row.sourceEventIds),
		64,
	);
	const retainedEventIds = uniqueNonEmpty(
		byAction("retain").flatMap((row) => row.sourceEventIds),
		64,
	);
	const demotedEventIds = uniqueNonEmpty(
		byAction("demote").flatMap((row) => row.sourceEventIds),
		64,
	);
	const quarantinedEventIds = uniqueNonEmpty(
		byAction("quarantine").flatMap((row) => row.sourceEventIds),
		64,
	);
	const pendingFeedbackEventIds = uniqueNonEmpty(
		byAction("feedback-required").flatMap((row) => row.sourceEventIds),
		64,
	);
	const replayRequiredEventIds = uniqueNonEmpty(
		byAction("replay-required").flatMap((row) => row.sourceEventIds),
		64,
	);
	const operatorCommands = uniqueNonEmpty(
		rows.filter((row) => row.action === "promote" || row.action === "retain").flatMap((row) => row.commands),
		32,
	);
	const verifierCommands = uniqueNonEmpty(
		rows.flatMap((row) => row.verifierCommands),
		24,
	);
	const fallbackCommands = uniqueNonEmpty(
		rows.flatMap((row) => row.fallbackCommands),
		20,
	);
	const avoidCommands = uniqueNonEmpty(
		rows.flatMap((row) => row.avoidCommands),
		32,
	);
	const feedbackCommands = uniqueNonEmpty(
		rows.flatMap((row) => row.feedbackCommands),
		32,
	);
	const retentionCommands = uniqueNonEmpty(
		rows.flatMap((row) => row.retentionCommands),
		32,
	);
	const retentionQueueEventIds = uniqueNonEmpty(
		rows
			.filter(
				(row) =>
					row.retentionAction === "rehearse" ||
					row.retentionAction === "feedback" ||
					row.retentionAction === "decay" ||
					row.retentionAction === "expire",
			)
			.flatMap((row) => row.sourceEventIds),
		64,
	);
	const expiredEventIds = uniqueNonEmpty(
		rows.filter((row) => row.retentionAction === "expire").flatMap((row) => row.sourceEventIds),
		64,
	);
	const workerRoutingHints = uniqueNonEmpty(
		rows.map((row) => `maturation:${row.action}:${row.route}:${row.targetScope}`),
		24,
	);
	const compactResumeHints = uniqueNonEmpty(
		[
			"include maturation-runtime-report in ContextPackV2",
			"rerun re_memory mature after compact resume",
			...active.compactResumeHints,
		],
		24,
	);
	const maturationCoverage = Number(
		(
			rows.length /
			Math.max(1, active.decisionCount + deposition.pendingWritebackCount + deposition.blockedWritebackCount)
		).toFixed(4),
	);
	const status: MemoryMaturationRuntimeReportV15["status"] =
		rows.length === 0
			? "empty"
			: quarantinedEventIds.length && !operatorCommands.length
				? "blocked"
				: pendingFeedbackEventIds.length ||
						replayRequiredEventIds.length ||
						demotedEventIds.length ||
						quarantinedEventIds.length
					? "warn"
					: "pass";
	const report: MemoryMaturationRuntimeReportV15 = {
		kind: "repi-memory-maturation-runtime-report",
		schemaVersion: 1,
		generatedAt,
		MemoryMaturationRuntimeV15: true,
		automatic_memory_maturation_pipeline: true,
		tool_result_to_strategy_loop: true,
		closed_loop_writeback: true,
		retention_decay_scheduler: true,
		stale_memory_rehearsal_queue: true,
		usefulness_backprop_to_maturation: true,
		promotion_demotion_replay_backed: true,
		cross_session_maturation_ready: true,
		reportPath: memoryMaturationRuntimeReportPath(),
		ledgerPath: memoryMaturationRuntimeLedgerPath(),
		actionBoardPath: memoryMaturationActionBoardPath(),
		sourceDepositionReportPath: deposition.depositionReportPath,
		sourceExperienceReportPath: experience.reportPath,
		sourceSkillCapsuleReportPath: skillCapsules.reportPath,
		sourceDistillPromotionReportPath: distillPromotion.reportPath,
		sourceQualityReportPath: quality.reportPath,
		sourceReplayReportPath: replay.reportPath,
		sourceStrategyReportPath: strategy.reportPath,
		sourceActiveKernelReportPath: active.reportPath,
		rowCount: rows.length,
		promotedEventIds,
		retainedEventIds,
		demotedEventIds,
		quarantinedEventIds,
		pendingFeedbackEventIds,
		replayRequiredEventIds,
		retentionQueueEventIds,
		expiredEventIds,
		operatorCommands,
		verifierCommands,
		fallbackCommands,
		avoidCommands,
		feedbackCommands,
		retentionCommands,
		workerRoutingHints,
		compactResumeHints,
		maturationCoverage,
		status,
		rows,
		requiredChecks: [
			"MemoryMaturationRuntimeV15",
			"automatic_memory_maturation_pipeline",
			"tool_result_to_strategy_loop",
			"closed_loop_writeback",
			"retention_decay_scheduler",
			"stale_memory_rehearsal_queue",
			"usefulness_backprop_to_maturation",
			"promotion_demotion_replay_backed",
			"cross_session_maturation_ready",
		],
		policy: {
			MemoryMaturationRuntimeV15: true,
			automaticMemoryMaturationPipeline: true,
			toolResultToStrategyLoop: true,
			closedLoopWriteback: true,
			retentionDecayScheduler: true,
			staleMemoryRehearsalQueue: true,
			usefulnessBackpropToMaturation: true,
			promotionDemotionReplayBacked: true,
			crossSessionMaturationReady: true,
		},
		nextCommands: uniqueNonEmpty(
			[
				"re_memory mature",
				operatorCommands.length ? "re_operator plan # consume matured memory commands" : undefined,
				verifierCommands.length ? "re_verifier matrix # verify matured claims" : undefined,
				feedbackCommands.length ? "re_memory feedback # close maturation loop" : undefined,
				retentionCommands.length ? "re_memory replay # rehearse stale/decayed memory" : undefined,
				replayRequiredEventIds.length ? "re_memory replay # promote only replay-improving memory" : undefined,
				"re_context pack",
			],
			14,
		),
	};
	if (options.write !== false) {
		writeFileAtomic(memoryMaturationRuntimeReportPath(), `${JSON.stringify(report, null, 2)}\n`);
		writeFileAtomic(
			memoryMaturationRuntimeLedgerPath(),
			`${rows.map((row) => JSON.stringify(row)).join("\n")}${rows.length ? "\n" : ""}`,
		);
		writeFileAtomic(
			memoryMaturationActionBoardPath(),
			[
				"# REPI Memory Maturation Action Board",
				"",
				"MemoryMaturationRuntimeV15: true",
				"automatic_memory_maturation_pipeline: true",
				"tool_result_to_strategy_loop: true",
				"closed_loop_writeback: true",
				"retention_decay_scheduler: true",
				"stale_memory_rehearsal_queue: true",
				"usefulness_backprop_to_maturation: true",
				`generated_at: ${generatedAt}`,
				`status: ${status}`,
				`maturation_coverage: ${maturationCoverage}`,
				"",
				"## Rows",
				...(rows.length
					? rows
							.slice(0, 24)
							.map(
								(row) =>
									`- ${row.action}/${row.retentionAction} maturity=${row.maturityScore} retention=${row.retentionScore} stale=${row.stalenessDays}d route=${row.route} events=${row.sourceEventIds.join(",") || "none"} stages=${row.stagePath.join("->")}`,
							)
					: ["- none"]),
				"",
				"## Feedback commands",
				...(feedbackCommands.length ? feedbackCommands.slice(0, 20).map((command) => `- ${command}`) : ["- none"]),
				"",
				"## Retention commands",
				...(retentionCommands.length
					? retentionCommands.slice(0, 20).map((command) => `- ${command}`)
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

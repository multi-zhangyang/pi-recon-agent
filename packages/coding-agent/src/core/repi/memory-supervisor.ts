import { type CaseMemoryV1, latestCaseMemoryBySignature } from "./case-memory.ts";
import {
	buildMemorySemanticIndex,
	type MemoryContradictionLedgerEntryV1,
	type MemorySedimentationReportV1,
	type MemorySemanticIndexEntryV1,
} from "./memory-distillation.ts";
import type { MemoryArtifactHash, MemoryEventV1 } from "./memory-event.ts";
import {
	buildMemoryFeedbackClosureReport,
	type MemoryFeedbackClosureReportV1,
	type MemoryFeedbackClosureRowV1,
} from "./memory-feedback.ts";
import { memoryTargetScope } from "./memory-scope.ts";
import { readMemoryEvents } from "./memory-search.ts";
import { type MemoryStoreVerificationV1, verifyMemoryStore, writeFileAtomic } from "./memory-store.ts";
import { evaluateMemoryUsefulness } from "./memory-usefulness.ts";
import {
	ensureRepiStorage,
	memoryFeedbackClosureReportPath,
	memoryLifecycleBoardPath,
	memorySedimentationReportPath,
	memoryStoreReportPath,
	memorySupervisorReportPath,
	memoryUsefulnessEvalReportPath,
} from "./storage.ts";
import { truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type MemorySupervisorAction = "promote" | "retain" | "demote" | "quarantine" | "expire" | "merge";

export type MemorySupervisorDecisionV1 = {
	kind: "repi-memory-supervisor-decision";
	schemaVersion: 1;
	id: string;
	caseSignature: string;
	eventIds: string[];
	action: MemorySupervisorAction;
	reason: string;
	grade: number;
	confidence: number;
	targetScope: string;
	route: string;
	evidenceRefs: MemoryArtifactHash[];
	commands: string[];
	blockers: string[];
	lifecycle: {
		ttlDays: number;
		reviewAfterDays: number;
		archiveCandidate: boolean;
		requiresFeedback: boolean;
	};
};

export type MemorySupervisorReportV1 = {
	kind: "repi-memory-supervisor-report";
	schemaVersion: 1;
	generatedAt: string;
	MemorySupervisorV1: true;
	storeReportPath: string;
	sedimentationReportPath: string;
	usefulnessReportPath: string;
	feedbackClosureReportPath: string;
	supervisorReportPath: string;
	lifecycleBoardPath: string;
	eventCount: number;
	caseCount: number;
	storeGrade: "pass" | "repairable" | "blocked";
	hashChainOk: boolean;
	usefulnessStatus: "pass" | "warn" | "fail" | "empty";
	feedbackClosureStatus: "pass" | "warn" | "fail" | "empty";
	decisions: MemorySupervisorDecisionV1[];
	promotionQueue: MemorySupervisorDecisionV1[];
	demotionQueue: MemorySupervisorDecisionV1[];
	quarantineQueue: MemorySupervisorDecisionV1[];
	expireQueue: MemorySupervisorDecisionV1[];
	mergeQueue: MemorySupervisorDecisionV1[];
	retainQueue: MemorySupervisorDecisionV1[];
	injectionAllowedEventIds: string[];
	recommendedCommands: string[];
	requiredChecks: string[];
	policy: {
		MemorySupervisorV1: true;
		supervisorRunsAfterSedimentation: true;
		promotionRequiresArtifactSha256: true;
		promotionRequiresVerifierOrReplay: true;
		quarantineOverridesPromotion: true;
		failureFeedbackDemotes: true;
		mergeByCaseSignature: true;
	};
};

export function memorySupervisorTtlDays(action: MemorySupervisorAction): number {
	if (action === "promote") return 180;
	if (action === "retain" || action === "merge") return 90;
	if (action === "demote") return 30;
	if (action === "quarantine") return 14;
	return 0;
}

export function memorySupervisorDecisionFromEntry(params: {
	entry: MemorySemanticIndexEntryV1;
	event?: MemoryEventV1;
	caseRow?: CaseMemoryV1;
	feedback?: MemoryFeedbackClosureRowV1;
	action?: MemorySupervisorAction;
	reason?: string;
}): MemorySupervisorDecisionV1 {
	const sedimentationAction =
		params.action ??
		(params.entry.action === "inject"
			? "promote"
			: params.entry.action === "quarantine"
				? "quarantine"
				: params.entry.action === "expire"
					? "expire"
					: params.entry.action === "demote"
						? "demote"
						: "retain");
	const action =
		params.feedback?.feedbackStatus === "demoted" && sedimentationAction === "promote"
			? "demote"
			: sedimentationAction;
	const ttlDays = memorySupervisorTtlDays(action);
	const confidence =
		params.event?.quality.confidence ??
		params.caseRow?.quality.confidence ??
		Math.min(0.99, params.entry.grade / 100);
	const reason =
		params.reason ??
		(params.feedback?.feedbackStatus === "demoted"
			? `failure_feedback_demotes source_event=${params.entry.eventId} feedback=${params.feedback.feedbackEventIds.join(",")}`
			: params.entry.blockers.length
				? params.entry.blockers.join("; ")
				: action === "promote"
					? "artifact_sha256+verifier_or_replay+non_quarantine grade>=70"
					: `sedimentation_action=${params.entry.action} grade=${params.entry.grade.toFixed(1)}`);
	const blockers = uniqueNonEmpty(
		[
			...params.entry.blockers,
			params.feedback?.feedbackStatus === "pending" ? "pending_feedback_after_injection" : undefined,
			params.feedback?.feedbackStatus === "demoted" ? "failure_feedback_demotes" : undefined,
			...(params.feedback?.blockers ?? []),
		],
		24,
	);
	return {
		kind: "repi-memory-supervisor-decision",
		schemaVersion: 1,
		id: `memory-supervisor:${action}:${params.entry.eventId}`,
		caseSignature: params.entry.caseSignature,
		eventIds: [params.entry.eventId],
		action,
		reason: truncateMiddle(reason, 420),
		grade: params.entry.grade,
		confidence: Number(confidence.toFixed(3)),
		targetScope: params.entry.targetScope,
		route: params.entry.route,
		evidenceRefs: params.entry.artifactRefs,
		commands: uniqueNonEmpty(params.event?.commands ?? [], 16),
		blockers,
		lifecycle: {
			ttlDays,
			reviewAfterDays: action === "promote" ? 45 : action === "retain" || action === "merge" ? 21 : 7,
			archiveCandidate: action === "expire" || action === "quarantine",
			requiresFeedback:
				action === "promote" ||
				action === "retain" ||
				action === "merge" ||
				params.feedback?.feedbackStatus === "pending",
		},
	};
}

export function memorySupervisorMergeDecision(caseRow: CaseMemoryV1): MemorySupervisorDecisionV1 | undefined {
	if (caseRow.eventIds.length < 2) return undefined;
	const ttlDays = memorySupervisorTtlDays("merge");
	return {
		kind: "repi-memory-supervisor-decision",
		schemaVersion: 1,
		id: `memory-supervisor:merge:${caseRow.caseSignature}`,
		caseSignature: caseRow.caseSignature,
		eventIds: caseRow.eventIds.slice(0, 80),
		action: "merge",
		reason: `merge_by_case_signature events=${caseRow.eventIds.length} reuse=${caseRow.quality.reuseCount} failures=${caseRow.quality.failureCount}`,
		grade: Number(
			Math.min(100, caseRow.quality.confidence * 70 + Math.min(20, caseRow.quality.reuseCount * 3)).toFixed(2),
		),
		confidence: Number(caseRow.quality.confidence.toFixed(3)),
		targetScope: memoryTargetScope(caseRow.target),
		route: caseRow.route,
		evidenceRefs: [],
		commands: uniqueNonEmpty(caseRow.commands, 16),
		blockers:
			caseRow.quality.failureCount > caseRow.quality.reuseCount
				? ["failure_dominant_case_requires_demote_review"]
				: [],
		lifecycle: {
			ttlDays,
			reviewAfterDays: 21,
			archiveCandidate: false,
			requiresFeedback: true,
		},
	};
}

export function memorySupervisorQuarantineDecision(
	finding: MemoryContradictionLedgerEntryV1,
	caseRow?: CaseMemoryV1,
): MemorySupervisorDecisionV1 {
	const action: MemorySupervisorAction = finding.status === "stale" ? "expire" : "quarantine";
	const ttlDays = memorySupervisorTtlDays(action);
	return {
		kind: "repi-memory-supervisor-decision",
		schemaVersion: 1,
		id: `memory-supervisor:${action}:${finding.caseSignature}`,
		caseSignature: finding.caseSignature,
		eventIds: finding.eventIds.slice(0, 80),
		action,
		reason: truncateMiddle(`contradiction_ledger:${finding.status}:${finding.reasons.join("; ")}`, 420),
		grade: 0,
		confidence: Number((caseRow?.quality.confidence ?? 0.3).toFixed(3)),
		targetScope: memoryTargetScope(caseRow?.target ?? finding.targets[0]),
		route: caseRow?.route ?? finding.routes[0] ?? "unknown",
		evidenceRefs: [],
		commands: uniqueNonEmpty(caseRow?.commands ?? [], 16),
		blockers: finding.reasons,
		lifecycle: {
			ttlDays,
			reviewAfterDays: 7,
			archiveCandidate: true,
			requiresFeedback: false,
		},
	};
}

export function formatMemorySupervisorBoard(report: MemorySupervisorReportV1): string {
	const decisionLine = (decision: MemorySupervisorDecisionV1) =>
		`- id=${decision.id} case=${decision.caseSignature} action=${decision.action} grade=${decision.grade.toFixed(1)} confidence=${decision.confidence.toFixed(2)} route=${decision.route} ttl=${decision.lifecycle.ttlDays}d events=${decision.eventIds.length} reason=${truncateMiddle(decision.reason, 180)}`;
	return [
		"# REPI Memory Lifecycle Board",
		"",
		"memory_supervisor:",
		`MemorySupervisorV1: ${report.MemorySupervisorV1}`,
		`generated_at: ${report.generatedAt}`,
		`store_grade: ${report.storeGrade}`,
		`hash_chain_ok: ${report.hashChainOk}`,
		`usefulness_status: ${report.usefulnessStatus}`,
		`feedback_closure_status: ${report.feedbackClosureStatus}`,
		`events: ${report.eventCount}`,
		`cases: ${report.caseCount}`,
		`supervisor_report: ${report.supervisorReportPath}`,
		`sedimentation_report: ${report.sedimentationReportPath}`,
		`usefulness_report: ${report.usefulnessReportPath}`,
		`feedback_closure_report: ${report.feedbackClosureReportPath}`,
		"promotion_queue:",
		...(report.promotionQueue.length ? report.promotionQueue.map(decisionLine) : ["- none"]),
		"demotion_queue:",
		...(report.demotionQueue.length ? report.demotionQueue.map(decisionLine) : ["- none"]),
		"quarantine_queue:",
		...(report.quarantineQueue.length ? report.quarantineQueue.map(decisionLine) : ["- none"]),
		"expire_queue:",
		...(report.expireQueue.length ? report.expireQueue.map(decisionLine) : ["- none"]),
		"merge_queue:",
		...(report.mergeQueue.length ? report.mergeQueue.map(decisionLine) : ["- none"]),
		"injection_allowed_event_ids:",
		...(report.injectionAllowedEventIds.length ? report.injectionAllowedEventIds.map((id) => `- ${id}`) : ["- none"]),
		"recommended_commands:",
		...(report.recommendedCommands.length ? report.recommendedCommands.map((command) => `- ${command}`) : ["- none"]),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
		"",
	].join("\n");
}

export function formatMemorySupervisor(report: MemorySupervisorReportV1): string {
	return [
		"memory_supervisor:",
		`MemorySupervisorV1=${report.MemorySupervisorV1}`,
		`store_grade=${report.storeGrade}`,
		`hash_chain_ok=${report.hashChainOk}`,
		`usefulness_status=${report.usefulnessStatus}`,
		`feedback_closure_status=${report.feedbackClosureStatus}`,
		`events=${report.eventCount}`,
		`cases=${report.caseCount}`,
		`supervisor_report=${report.supervisorReportPath}`,
		`feedback_closure_report=${report.feedbackClosureReportPath}`,
		`lifecycle_board=${report.lifecycleBoardPath}`,
		`queues=promote:${report.promotionQueue.length},demote:${report.demotionQueue.length},quarantine:${report.quarantineQueue.length},expire:${report.expireQueue.length},merge:${report.mergeQueue.length},retain:${report.retainQueue.length}`,
		"promotion_queue:",
		...(report.promotionQueue.length
			? report.promotionQueue
					.slice(0, 8)
					.map(
						(decision) =>
							`- case=${decision.caseSignature} event=${decision.eventIds[0] ?? "none"} grade=${decision.grade.toFixed(1)} reason=${truncateMiddle(decision.reason, 180)}`,
					)
			: ["- none"]),
		"demotion_or_quarantine_queue:",
		...[...report.quarantineQueue, ...report.expireQueue, ...report.demotionQueue]
			.slice(0, 12)
			.map(
				(decision) =>
					`- action=${decision.action} case=${decision.caseSignature} grade=${decision.grade.toFixed(1)} blockers=${decision.blockers.join(",") || "none"}`,
			),
		...(report.quarantineQueue.length + report.expireQueue.length + report.demotionQueue.length === 0
			? ["- none"]
			: []),
		"merge_queue:",
		...(report.mergeQueue.length
			? report.mergeQueue
					.slice(0, 8)
					.map(
						(decision) =>
							`- case=${decision.caseSignature} events=${decision.eventIds.length} commands=${decision.commands.length}`,
					)
			: ["- none"]),
		"recommended_commands:",
		...report.recommendedCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}

export function superviseMemoryLifecycle(
	options: {
		// opt #99 PERF-1/PERF-2 — the orchestrator already holds the store verdict (verifyMemoryStore),
		// the sedimentation report (buildMemorySemanticIndex), and the feedback-closure report
		// (buildMemoryFeedbackClosureReport). Without these params superviseMemoryLifecycle re-runs
		// all three (a 2nd full hash-chain walk + 2nd sedimentation build + 2nd feedback build) per
		// orchestration. Thread them through so the supervisor reuses the in-hand reports (same
		// pattern buildMemoryActiveKernelReport uses for sedimentation/feedback/quality/replay).
		store?: MemoryStoreVerificationV1;
		sedimentation?: MemorySedimentationReportV1;
		feedback?: MemoryFeedbackClosureReportV1;
	} = {},
): MemorySupervisorReportV1 {
	ensureRepiStorage();
	const store = options.store ?? verifyMemoryStore();
	const usefulness = evaluateMemoryUsefulness();
	const sedimentation = options.sedimentation ?? buildMemorySemanticIndex();
	const feedbackClosure = options.feedback ?? buildMemoryFeedbackClosureReport({ sedimentation });
	const events = readMemoryEvents();
	const eventsById = new Map(events.map((event) => [event.id, event]));
	const casesBySignature = latestCaseMemoryBySignature();
	const feedbackByEvent = new Map(feedbackClosure.rows.map((row) => [row.eventId, row]));
	const decisions = sedimentation.entries.map((entry) =>
		memorySupervisorDecisionFromEntry({
			entry,
			event: eventsById.get(entry.eventId),
			caseRow: casesBySignature.get(entry.caseSignature),
			feedback: feedbackByEvent.get(entry.eventId),
		}),
	);
	const existingDecisionIds = new Set(decisions.map((decision) => decision.id));
	for (const finding of sedimentation.contradictions) {
		const decision = memorySupervisorQuarantineDecision(finding, casesBySignature.get(finding.caseSignature));
		if (!existingDecisionIds.has(decision.id)) {
			decisions.push(decision);
			existingDecisionIds.add(decision.id);
		}
	}
	for (const caseRow of casesBySignature.values()) {
		const decision = memorySupervisorMergeDecision(caseRow);
		if (decision && !existingDecisionIds.has(decision.id)) {
			decisions.push(decision);
			existingDecisionIds.add(decision.id);
		}
	}
	decisions.sort((left, right) => {
		const order: Record<MemorySupervisorAction, number> = {
			quarantine: 0,
			expire: 1,
			demote: 2,
			promote: 3,
			merge: 4,
			retain: 5,
		};
		return order[left.action] - order[right.action] || right.grade - left.grade || left.id.localeCompare(right.id);
	});
	const byAction = (action: MemorySupervisorAction) => decisions.filter((decision) => decision.action === action);
	const promotionQueue = byAction("promote");
	const demotionQueue = byAction("demote");
	const quarantineQueue = byAction("quarantine");
	const expireQueue = byAction("expire");
	const mergeQueue = byAction("merge");
	const retainQueue = byAction("retain");
	const recommendedCommands = uniqueNonEmpty(
		[
			store.storeGrade === "blocked"
				? "inspect memory/events.jsonl parse/hash-chain errors before new writes"
				: undefined,
			store.storeGrade === "repairable" ? "re_memory repair-index" : undefined,
			"re_memory verify",
			"re_memory sediment",
			"re_memory feedback",
			quarantineQueue.length || expireQueue.length ? "re_memory prune-playbooks" : undefined,
			mergeQueue.length ? "re_memory consolidate" : undefined,
			promotionQueue.length ? "re_memory playbooks" : undefined,
			"re_context pack",
		].filter(Boolean) as string[],
		12,
	);
	const report: MemorySupervisorReportV1 = {
		kind: "repi-memory-supervisor-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		MemorySupervisorV1: true,
		storeReportPath: memoryStoreReportPath(),
		sedimentationReportPath: memorySedimentationReportPath(),
		usefulnessReportPath: memoryUsefulnessEvalReportPath(),
		feedbackClosureReportPath: memoryFeedbackClosureReportPath(),
		supervisorReportPath: memorySupervisorReportPath(),
		lifecycleBoardPath: memoryLifecycleBoardPath(),
		eventCount: events.length,
		caseCount: casesBySignature.size,
		storeGrade: store.storeGrade,
		hashChainOk: store.hashChainOk && sedimentation.hashChainOk,
		usefulnessStatus: usefulness.aggregate.status,
		feedbackClosureStatus: feedbackClosure.closureStatus,
		decisions,
		promotionQueue,
		demotionQueue,
		quarantineQueue,
		expireQueue,
		mergeQueue,
		retainQueue,
		injectionAllowedEventIds: promotionQueue.flatMap((decision) => decision.eventIds).slice(0, 64),
		recommendedCommands,
		requiredChecks: [
			"MemorySupervisorV1",
			"store_verify_before_supervision",
			"sedimentation_before_promotion",
			"quarantine_overrides_promotion",
			"merge_by_case_signature",
			"ttl_review_after_days",
			"feedback_required_after_injection",
			"MemoryFeedbackClosureV1",
		],
		policy: {
			MemorySupervisorV1: true,
			supervisorRunsAfterSedimentation: true,
			promotionRequiresArtifactSha256: true,
			promotionRequiresVerifierOrReplay: true,
			quarantineOverridesPromotion: true,
			failureFeedbackDemotes: true,
			mergeByCaseSignature: true,
		},
	};
	writeFileAtomic(memorySupervisorReportPath(), `${JSON.stringify(report, null, 2)}\n`);
	writeFileAtomic(memoryLifecycleBoardPath(), formatMemorySupervisorBoard(report));
	return report;
}

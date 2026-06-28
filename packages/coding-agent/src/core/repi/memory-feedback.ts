import {
	buildMemorySemanticIndex,
	type MemorySedimentationAction,
	type MemorySedimentationReportV1,
} from "./memory-distillation.ts";
import type { MemoryEventV1 } from "./memory-event.ts";
import { memoryTargetScope } from "./memory-scope.ts";
import { memoryTextForSearch, readMemoryEvents } from "./memory-search.ts";
import { writeFileAtomic } from "./memory-store.ts";
import {
	ensureRepiStorage,
	memoryFeedbackClosureReportPath,
	memoryInjectionPacketPath,
	memorySedimentationReportPath,
} from "./storage.ts";
import { uniqueNonEmpty } from "./text.ts";

export type MemoryFeedbackClosureStatus = "promoted" | "demoted" | "pending" | "orphan_feedback";

export type MemoryFeedbackClosureRowV1 = {
	kind: "repi-memory-feedback-closure-row";
	schemaVersion: 1;
	eventId: string;
	caseSignature: string;
	route: string;
	targetScope: string;
	injectionAction: MemorySedimentationAction | "not_injected";
	injectionGrade: number;
	feedbackEventIds: string[];
	feedbackStatus: MemoryFeedbackClosureStatus;
	positiveFeedbackCount: number;
	negativeFeedbackCount: number;
	lastFeedbackAt?: string;
	blockers: string[];
	nextCommands: string[];
};

export type MemoryFeedbackClosureReportV1 = {
	kind: "repi-memory-feedback-closure-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryFeedbackClosureV1: true;
	sedimentationReportPath: string;
	injectionPacketPath: string;
	feedbackClosureReportPath: string;
	eventCount: number;
	injectedCount: number;
	feedbackLinkedCount: number;
	feedbackCoverage: number;
	closureStatus: "pass" | "warn" | "fail" | "empty";
	rows: MemoryFeedbackClosureRowV1[];
	promotionReadyEventIds: string[];
	demotionRequiredEventIds: string[];
	pendingFeedbackEventIds: string[];
	orphanFeedbackEventIds: string[];
	requiredChecks: string[];
};

export function memoryFeedbackSourceEventIds(event: MemoryEventV1): string[] {
	const text = memoryTextForSearch(event);
	return uniqueNonEmpty(
		[
			...Array.from(
				text.matchAll(/\b(?:event|source_event|memory_event|feedback_for|injected_event)=?(mem:[a-z0-9-]+)/gi),
			).map((match) => match[1]),
			...Array.from(text.matchAll(/\bhistorical memory event\s+(mem:[a-z0-9-]+)/gi)).map((match) => match[1]),
		].filter(Boolean) as string[],
		16,
	);
}

export function memoryFeedbackPolarity(event: MemoryEventV1): "positive" | "negative" | "neutral" {
	const text = memoryTextForSearch(event);
	if (
		event.outcome === "failure" ||
		event.outcome === "blocked" ||
		/memory_reuse_feedback_demote|feedback[_ -]?demote|failed/i.test(text)
	)
		return "negative";
	if (
		event.outcome === "success" ||
		/memory_reuse_feedback_promote|feedback[_ -]?promote|verified|strong evidence/i.test(text)
	)
		return "positive";
	return "neutral";
}

export function formatMemoryFeedbackClosure(report: MemoryFeedbackClosureReportV1): string {
	return [
		"memory_feedback_closure:",
		`MemoryFeedbackClosureV1=${report.MemoryFeedbackClosureV1}`,
		`status=${report.closureStatus}`,
		`injected=${report.injectedCount}`,
		`feedback_linked=${report.feedbackLinkedCount}`,
		`feedback_coverage=${report.feedbackCoverage}`,
		`report=${report.feedbackClosureReportPath}`,
		"promotion_ready_event_ids:",
		...(report.promotionReadyEventIds.length ? report.promotionReadyEventIds.map((id) => `- ${id}`) : ["- none"]),
		"demotion_required_event_ids:",
		...(report.demotionRequiredEventIds.length ? report.demotionRequiredEventIds.map((id) => `- ${id}`) : ["- none"]),
		"pending_feedback_event_ids:",
		...(report.pendingFeedbackEventIds.length ? report.pendingFeedbackEventIds.map((id) => `- ${id}`) : ["- none"]),
		"rows:",
		...(report.rows.length
			? report.rows
					.slice(0, 16)
					.map(
						(row) =>
							`- event=${row.eventId} status=${row.feedbackStatus} injection=${row.injectionAction} grade=${row.injectionGrade.toFixed(1)} feedback=${row.feedbackEventIds.length} blockers=${row.blockers.join(",") || "none"}`,
					)
			: ["- none"]),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}

export function buildMemoryFeedbackClosureReport(options?: {
	sedimentation?: MemorySedimentationReportV1;
	write?: boolean;
}): MemoryFeedbackClosureReportV1 {
	ensureRepiStorage();
	const events = readMemoryEvents();
	const eventsById = new Map(events.map((event) => [event.id, event]));
	const sedimentation = options?.sedimentation ?? buildMemorySemanticIndex();
	const injectedById = new Map(sedimentation.injectionPacket.entries.map((entry) => [entry.eventId, entry]));
	const feedbackBySource = new Map<string, MemoryEventV1[]>();
	for (const event of events) {
		for (const sourceId of memoryFeedbackSourceEventIds(event)) {
			const rows = feedbackBySource.get(sourceId) ?? [];
			rows.push(event);
			feedbackBySource.set(sourceId, rows);
		}
	}
	const sourceIds = uniqueNonEmpty([...injectedById.keys(), ...feedbackBySource.keys()], 240);
	const rows: MemoryFeedbackClosureRowV1[] = sourceIds.map((eventId) => {
		const source = eventsById.get(eventId);
		const injection = injectedById.get(eventId);
		const feedback = feedbackBySource.get(eventId) ?? [];
		const positiveFeedbackCount = feedback.filter((event) => memoryFeedbackPolarity(event) === "positive").length;
		const negativeFeedbackCount = feedback.filter((event) => memoryFeedbackPolarity(event) === "negative").length;
		const feedbackStatus: MemoryFeedbackClosureStatus = negativeFeedbackCount
			? "demoted"
			: positiveFeedbackCount
				? "promoted"
				: injection
					? "pending"
					: "orphan_feedback";
		const lastFeedbackAt = feedback
			.map((event) => event.ts)
			.sort()
			.at(-1);
		const blockers = uniqueNonEmpty(
			[
				feedbackStatus === "pending" ? "pending_feedback_after_injection" : undefined,
				feedbackStatus === "demoted" ? "failure_feedback_demotes" : undefined,
				feedbackStatus === "orphan_feedback" ? "feedback_without_current_injection_packet" : undefined,
				injection?.blockers ?? [],
			].flat(),
			16,
		);
		return {
			kind: "repi-memory-feedback-closure-row",
			schemaVersion: 1,
			eventId,
			caseSignature: source?.caseSignature ?? injection?.caseSignature ?? "unknown",
			route: source?.route ?? injection?.route ?? "unknown",
			targetScope: memoryTargetScope(source?.target) || injection?.targetScope || "global",
			injectionAction: injection?.action ?? "not_injected",
			injectionGrade: Number((injection?.grade ?? 0).toFixed(2)),
			feedbackEventIds: feedback.map((event) => event.id),
			feedbackStatus,
			positiveFeedbackCount,
			negativeFeedbackCount,
			lastFeedbackAt,
			blockers,
			nextCommands:
				feedbackStatus === "pending"
					? [
							`re_memory append # memory_reuse_feedback_promote event=${eventId} after verifier/replay success`,
							`re_memory append # memory_reuse_feedback_demote event=${eventId} after failed reuse`,
						]
					: feedbackStatus === "demoted"
						? ["re_memory supervise", "re_memory sediment", "re_memory eval"]
						: feedbackStatus === "promoted"
							? ["re_memory supervise", "re_context pack"]
							: ["re_memory sediment"],
		};
	});
	const injectedCount = injectedById.size;
	const closedInjected = rows.filter(
		(row) => row.injectionAction !== "not_injected" && row.feedbackStatus !== "pending",
	).length;
	const pendingFeedbackEventIds = rows.filter((row) => row.feedbackStatus === "pending").map((row) => row.eventId);
	const orphanFeedbackEventIds = rows
		.filter((row) => row.feedbackStatus === "orphan_feedback")
		.map((row) => row.eventId);
	const closureStatus =
		injectedCount === 0 && rows.length === 0
			? "empty"
			: orphanFeedbackEventIds.length
				? "fail"
				: pendingFeedbackEventIds.length
					? "warn"
					: "pass";
	const report: MemoryFeedbackClosureReportV1 = {
		kind: "repi-memory-feedback-closure-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		MemoryFeedbackClosureV1: true,
		sedimentationReportPath: memorySedimentationReportPath(),
		injectionPacketPath: memoryInjectionPacketPath(),
		feedbackClosureReportPath: memoryFeedbackClosureReportPath(),
		eventCount: events.length,
		injectedCount,
		feedbackLinkedCount: rows.reduce((sum, row) => sum + row.feedbackEventIds.length, 0),
		feedbackCoverage: injectedCount ? Number((closedInjected / injectedCount).toFixed(4)) : 0,
		closureStatus,
		rows,
		promotionReadyEventIds: rows.filter((row) => row.feedbackStatus === "promoted").map((row) => row.eventId),
		demotionRequiredEventIds: rows.filter((row) => row.feedbackStatus === "demoted").map((row) => row.eventId),
		pendingFeedbackEventIds,
		orphanFeedbackEventIds,
		requiredChecks: [
			"MemoryFeedbackClosureV1",
			"feedback_event_links_source_event",
			"success_feedback_promotes",
			"failure_feedback_demotes",
			"pending_injection_requires_feedback_writeback",
			"feedback_closure_report_in_context_pack",
		],
	};
	if (options?.write !== false)
		writeFileAtomic(memoryFeedbackClosureReportPath(), `${JSON.stringify(report, null, 2)}\n`);
	return report;
}

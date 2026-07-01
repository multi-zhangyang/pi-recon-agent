import { cachedJsonlDerived, jsonlRecords } from "./jsonl.ts";
import { isMemoryQuality, type MemoryEventV1, type MemoryQuality } from "./memory-event.ts";
import { caseMemoryPath, ensureRepiStorage } from "./storage.ts";
import { truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type CaseMemoryV1 = {
	kind: "repi-case-memory";
	schemaVersion: 1;
	id: string;
	ts: string;
	caseSignature: string;
	route: string;
	target?: string;
	domainTags: string[];
	summary: string;
	eventIds: string[];
	commands: string[];
	reuseRules: string[];
	failurePatterns: string[];
	quality: MemoryQuality;
	sourceEvents: string[];
	lastEventHash: string;
};

export function isCaseMemory(value: unknown): value is CaseMemoryV1 {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as CaseMemoryV1;
	return (
		row.kind === "repi-case-memory" &&
		row.schemaVersion === 1 &&
		typeof row.id === "string" &&
		typeof row.ts === "string" &&
		typeof row.caseSignature === "string" &&
		Array.isArray(row.eventIds) &&
		Array.isArray(row.commands) &&
		Array.isArray(row.reuseRules) &&
		Array.isArray(row.failurePatterns) &&
		isMemoryQuality(row.quality) &&
		typeof row.lastEventHash === "string"
	);
}

export function caseMemorySnapshotFromEvent(event: MemoryEventV1, previous?: CaseMemoryV1): CaseMemoryV1 {
	const eventIds = uniqueNonEmpty([...(previous?.eventIds ?? []), event.id], 80);
	const commands = uniqueNonEmpty([...(previous?.commands ?? []), ...event.commands], 40);
	const reuseRules = uniqueNonEmpty([...(previous?.reuseRules ?? []), ...event.reuseRules], 40);
	const failurePatterns = uniqueNonEmpty([...(previous?.failurePatterns ?? []), ...event.failurePatterns], 40);
	const sourceEvents = uniqueNonEmpty([...(previous?.sourceEvents ?? []), event.entryHash], 120);
	const quality: MemoryQuality = {
		confidence: Math.max(previous?.quality.confidence ?? 0, event.quality.confidence),
		replayVerified: Boolean(previous?.quality.replayVerified || event.quality.replayVerified),
		reuseCount: (previous?.quality.reuseCount ?? 0) + (event.outcome === "success" ? 1 : 0),
		failureCount:
			(previous?.quality.failureCount ?? 0) + (event.outcome === "failure" || event.outcome === "blocked" ? 1 : 0),
		lastUsefulAt: event.ts,
		decay: Math.max(0, (previous?.quality.decay ?? 0) * 0.9 + (event.outcome === "failure" ? 0.2 : 0)),
	};
	const summarySeed = uniqueNonEmpty(
		[event.lessons[0], event.reuseRules[0], event.failurePatterns[0], event.task],
		4,
	).join(" | ");
	const row: CaseMemoryV1 = {
		kind: "repi-case-memory",
		schemaVersion: 1,
		id: `case:${event.caseSignature}:${event.seq}`,
		ts: event.ts,
		caseSignature: event.caseSignature,
		route: event.route,
		target: event.target,
		domainTags: event.domainTags,
		summary: truncateMiddle(summarySeed || event.task, 600),
		eventIds,
		commands,
		reuseRules,
		failurePatterns,
		quality,
		sourceEvents,
		lastEventHash: event.entryHash,
	};
	return row;
}

export function rebuildCaseMemoryFromEvents(events: MemoryEventV1[]): CaseMemoryV1[] {
	const latest = new Map<string, CaseMemoryV1>();
	const rows: CaseMemoryV1[] = [];
	for (const event of events) {
		const row = caseMemorySnapshotFromEvent(event, latest.get(event.caseSignature));
		latest.set(event.caseSignature, row);
		rows.push(row);
	}
	return rows;
}

export function readCaseMemoryRows(): CaseMemoryV1[] {
	ensureRepiStorage();
	return jsonlRecords(caseMemoryPath(), isCaseMemory);
}

// opt #99 LEAK-1 REMOVED (2026-06-29): the standalone case-memory ledger rotation
// (rotateCaseMemoryLedgerIfNeeded + REPI_CASE_MEMORY_MAX_ROWS/_ROTATE_BATCH) was architecturally
// broken and has been deleted. case-memory is a DERIVED PROJECTION of events —
// rebuildCaseMemoryFromEvents pushes one row per event, and appendMemoryEventTransaction appends
// one case row per event, so case-memory count == event count ALWAYS. The storeGrade caseIndexOk
// check (memory-store.ts:236-251) requires every event's caseSignature to have a case-memory row
// with matching lastEventHash. A standalone case-memory rotation that drops head rows while their
// events remain → missing_latest_row → storeGrade="repairable" → the next deposit's
// repairable-rebuild (rebuildCaseMemoryFromEvents(ALL events)) RESURRECTS the dropped rows → the
// rotation is futile thrash: every post-cap deposit rebuilds-to-N then re-rotates to maxRows
// (probed: counts go 1..12 then stick at 10 via rebuild+rotate every deposit). case-memory is
// instead bounded TOGETHER with events by opt #113's rotateMemoryEventsLedgerIfNeeded, which
// co-rebuilds case-memory from the kept events tail (rebuildCaseMemoryFromEvents(keptRows)) →
// events and case-memory stay in sync → caseIndexOk stays true → no resurrection. Use
// REPI_MEMORY_EVENTS_MAX_ROWS (opt #113) to bound both ledgers.

export function latestCaseMemoryBySignature(): Map<string, CaseMemoryV1> {
	ensureRepiStorage();
	// opt #83 — the Map is a pure function of case-memory.jsonl rows (last row per caseSignature
	// wins), which only change on deposit. Cache it keyed by (path, mtime+size) so the per-
	// tool_result recall path skips the O(rows) Map rebuild on a hit. Shared rows from #74.
	return cachedJsonlDerived(caseMemoryPath(), () => {
		const rows = new Map<string, CaseMemoryV1>();
		for (const row of readCaseMemoryRows()) rows.set(row.caseSignature, row);
		return rows;
	});
}

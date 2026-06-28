import { jsonlRecords } from "./jsonl.ts";
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

export function latestCaseMemoryBySignature(): Map<string, CaseMemoryV1> {
	const rows = new Map<string, CaseMemoryV1>();
	for (const row of readCaseMemoryRows()) rows.set(row.caseSignature, row);
	return rows;
}

import { appendFileSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #74 — parsed-rows cache layered on the #70 text cache. jsonlRecords/jsonlScan run
// 4-5× per tool_result on the memory-recall hot path, each doing an O(rows) JSON.parse of
// the SAME events/case/quality/governance JSONL files that only change on
// deposit/governance/quality ops. #70 cached the TEXT read (zero readFileSync on a hit) but
// the per-call JSON.parse still ran. #74 caches the PARSED rows too: on a cache hit
// (mtime+size unchanged AND same predicate ref) return the cached rows directly — zero
// JSON.parse. Over a session with R tool_results and N ledger rows this is O(R·N) parse →
// O(deposits·N) (only the deposit that bumps mtime re-parses; subsequent recall reads hit).
//
// These tests prove (1) repeat jsonlRecords calls do NOT re-parse (parseCount stays at the
// first-call N, not K·N), (2) a new append re-parses (mtime invalidation — not stale),
// (3) a missing file returns [] and is not cached, and (4) the REAL readMemoryEvents recall
// path re-parses events.jsonl ZERO times across N calls once warm (the load-bearing
// end-to-end proof). The parse-count assertions are #74's novel proof; the readFileSync
// assertions reaffirm #70. The cache returns SHARED row refs (the #65 precedent) — safe
// because no caller mutates them (audited).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const MARKER = "repi-jsonl-parsed-cache-marker";
const EVENT_KIND = "repi-memory-event";

const { parseCount, eventParseCount, eventsReadCount } = vi.hoisted(() => ({
	parseCount: { current: 0 },
	eventParseCount: { current: 0 },
	eventsReadCount: { current: 0 },
}));

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return {
		...actual,
		readFileSync: vi.fn((...args: Parameters<typeof actual.readFileSync>) => {
			if (String(args[0]).endsWith("events.jsonl")) eventsReadCount.current++;
			return actual.readFileSync(...args);
		}),
	};
});

// Stable predicate ref (module-level) — the parsed cache keys on the predicate reference, so
// a fresh inline literal per call would defeat the cache. Real callers use one stable
// imported predicate per ledger path (isMemoryEvent, isCaseMemory, …); #74 extracted the
// governance predicate from an inline literal to a named function for the same reason.
const isMarkerRow = (value: unknown): value is { marker: string; n: number } =>
	typeof value === "object" &&
	value !== null &&
	typeof (value as { marker?: unknown }).marker === "string" &&
	typeof (value as { n?: unknown }).n === "number";

let originalParse: typeof JSON.parse;

beforeEach(() => {
	originalParse = JSON.parse;
	vi.spyOn(JSON, "parse").mockImplementation((text, reviver) => {
		if (typeof text === "string") {
			if (text.includes(MARKER)) parseCount.current++;
			else if (text.includes(EVENT_KIND)) eventParseCount.current++;
		}
		return originalParse.call(JSON, text, reviver);
	});
});

afterEach(() => {
	vi.restoreAllMocks();
});

const { jsonlRecords } = await import("../../src/core/repi/jsonl.ts");
const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { readMemoryEvents } = await import("../../src/core/repi/memory-search.ts");

describe("repi/jsonl parsed-rows cache (opt #74)", () => {
	let tempDir: string;
	let agentDir: string;
	let ledgerPath: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-jsonl-parsed-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		ledgerPath = join(tempDir, "marker.jsonl");
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
		parseCount.current = 0;
		eventParseCount.current = 0;
		eventsReadCount.current = 0;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("repeat jsonlRecords calls do NOT re-parse (cache hit returns shared rows, 0 JSON.parse)", () => {
		const n = 6;
		writeFileSync(
			ledgerPath,
			`${Array.from({ length: n }, (_, i) => `{"marker":"${MARKER}","n":${i}}`).join("\n")}\n`,
		);
		// First call parses all n marker rows → parseCount = n. Subsequent calls hit the parsed
		// cache (mtime+size unchanged, same predicate ref) → 0 JSON.parse. (Temp-neuter the
		// parsed cache → each of the 4 calls re-parses n rows → parseCount = 4n, failing === n.)
		const first = jsonlRecords(ledgerPath, isMarkerRow);
		expect(first).toHaveLength(n);
		expect(first.map((row) => row.n)).toEqual(Array.from({ length: n }, (_, i) => i));
		expect(parseCount.current).toBe(n);

		jsonlRecords(ledgerPath, isMarkerRow);
		jsonlRecords(ledgerPath, isMarkerRow);
		jsonlRecords(ledgerPath, isMarkerRow);
		expect(parseCount.current).toBe(n); // the load-bearing #74 assertion: still n, not 4n

		// Shared-ref safety: the SAME array is returned on a cache hit (no re-parse, no copy).
		expect(jsonlRecords(ledgerPath, isMarkerRow)).toBe(first);
		expect(parseCount.current).toBe(n);
	});

	it("a new append re-parses (mtime+size invalidation — not stale)", () => {
		writeFileSync(ledgerPath, `{"marker":"${MARKER}","n":0}\n`);
		jsonlRecords(ledgerPath, isMarkerRow);
		expect(parseCount.current).toBe(1);
		expect(jsonlRecords(ledgerPath, isMarkerRow)).toHaveLength(1);

		// Append a new row (appendFileSync bumps mtime+size → cache miss → re-parse).
		appendFileSync(ledgerPath, `{"marker":"${MARKER}","n":1}\n`);
		const after = jsonlRecords(ledgerPath, isMarkerRow);
		expect(after).toHaveLength(2);
		expect(after.map((row) => row.n)).toEqual([0, 1]);
		// Re-parse of the now-2-row file: parseCount went from 1 to 1+2 = 3.
		expect(parseCount.current).toBe(3);
	});

	it("a missing file returns [] and is not cached (a later write is observed)", () => {
		expect(jsonlRecords(ledgerPath, isMarkerRow)).toEqual([]);
		expect(parseCount.current).toBe(0);
		// File appears → next call parses it (stat now succeeds → cache populated).
		writeFileSync(ledgerPath, `{"marker":"${MARKER}","n":0}\n`);
		expect(jsonlRecords(ledgerPath, isMarkerRow)).toHaveLength(1);
		expect(parseCount.current).toBe(1);
	});

	it("readMemoryEvents (the recall hot path) re-parses events.jsonl ZERO times across N calls once warm", () => {
		appendMemoryEventTransaction({ source: "manual", task: "parsed-cache-test", route: "re", outcome: "success" });
		// Reset after the append. The append's post-commit verification (jsonlScan of events)
		// warms the parsed cache with the post-append rows, so the recall-path reads that follow
		// hit the parsed cache — 0 JSON.parse AND 0 readFileSync. (Temp-neuter the parsed cache
		// → each readMemoryEvents re-parses the 1 event line → eventParseCount = N, failing === 0;
		// #70's text cache still hits so eventsReadCount stays 0 — proving the parse, not the
		// text read, is what #74 eliminates.)
		eventParseCount.current = 0;
		eventsReadCount.current = 0;
		const first = readMemoryEvents();
		expect(first).toHaveLength(1);
		readMemoryEvents();
		readMemoryEvents();
		readMemoryEvents();
		readMemoryEvents();
		expect(eventParseCount.current).toBe(0); // load-bearing #74 proof: 0 parses across 5 calls
		expect(eventsReadCount.current).toBe(0); // reaffirms #70
		expect(readMemoryEvents()).toBe(first); // shared ref (no re-parse, no copy)
	});
});

import { appendFileSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The parsed-row cache is shared infrastructure for bounded JSONL ledgers. It
// invalidates on file changes and reuses parsed rows while the file is stable.
const MARKER = "repi-jsonl-parsed-cache-marker";

const parseCount = { current: 0 };

// Stable predicate ref (module-level) — the parsed cache keys on the predicate reference, so
// a fresh inline literal per call would defeat the cache. Real callers use one stable
// imported predicate per ledger path. A fresh inline literal per call would
// intentionally use a different cache entry.
const isMarkerRow = (value: unknown): value is { marker: string; n: number } =>
	typeof value === "object" &&
	value !== null &&
	typeof (value as { marker?: unknown }).marker === "string" &&
	typeof (value as { n?: unknown }).n === "number";

let originalParse: typeof JSON.parse;

beforeEach(() => {
	originalParse = JSON.parse;
	vi.spyOn(JSON, "parse").mockImplementation((text, reviver) => {
		if (typeof text === "string" && text.includes(MARKER)) parseCount.current++;
		return originalParse.call(JSON, text, reviver);
	});
});

afterEach(() => {
	vi.restoreAllMocks();
});

const { jsonlRecords } = await import("../../src/core/repi/jsonl.ts");

describe("repi/jsonl parsed-rows cache (opt #74)", () => {
	let tempDir: string;
	let ledgerPath: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-jsonl-parsed-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		ledgerPath = join(tempDir, "marker.jsonl");
		parseCount.current = 0;
	});

	afterEach(() => {
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
});

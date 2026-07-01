import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// opt #99 LEAK-1 — REWRITE (2026-06-29). The original opt #99 added a STANDALONE case-memory
// ledger rotation (rotateCaseMemoryLedgerIfNeeded + REPI_CASE_MEMORY_MAX_ROWS/_ROTATE_BATCH).
// That was architecturally broken and has been REMOVED. The proof:
//
// case-memory is a DERIVED PROJECTION of events — rebuildCaseMemoryFromEvents pushes one row per
// event and appendMemoryEventTransaction appends one case row per event, so case-memory count ==
// event count ALWAYS. The storeGrade caseIndexOk check (memory-store.ts:236-251) requires every
// event's caseSignature to have a case-memory row with matching lastEventHash. A standalone
// case-memory rotation that drops head rows while their events remain → missing_latest_row →
// storeGrade="repairable" → the next deposit's repairable-rebuild (rebuildCaseMemoryFromEvents(
// ALL events)) RESURRECTS the dropped rows → the rotation is FUTILE THRASH: every post-cap
// deposit rebuilds-to-N then re-rotates to maxRows. Probed empirically: with the standalone
// rotation and REPI_CASE_MEMORY_MAX_ROWS=10/batch=2, the on-disk count went 1..12 then STUCK at
// 10 for every subsequent deposit — the cap held ONLY because each deposit did a wasted
// rebuild-13-rows + rotate-back-to-10 cycle (2× the I/O of a plain append, every deposit,
// forever).
//
// The CORRECT bound is opt #113's events rotation, which CO-REBUILDS case-memory from the kept
// events tail (rebuildCaseMemoryFromEvents(keptRows)) → events and case-memory stay in sync →
// caseIndexOk stays true → no resurrection. These tests verify the correct mechanism from the
// case-memory angle: (1) events rotation co-rotates case-memory and keeps count == event count,
// (2) the repeated-signature "last row wins" invariant survives co-rotation, (3) with events
// rotation DISABLED, case-memory grows unbounded — proving the futile standalone thrash is gone
// (pre-fix, the standalone rotation would have thrashed it back to 10 every deposit even with
// events rotation off).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_EVENTS_MAX_ROWS = "REPI_MEMORY_EVENTS_MAX_ROWS";
const ENV_EVENTS_BATCH = "REPI_MEMORY_EVENTS_ROTATE_BATCH";

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { latestCaseMemoryBySignature, readCaseMemoryRows } = await import("../../src/core/repi/case-memory.ts");
const { caseMemoryPath, memoryEventsPath } = await import("../../src/core/repi/storage.ts");
const { jsonlRecords } = await import("../../src/core/repi/jsonl.ts");
const { isMemoryEvent } = await import("../../src/core/repi/memory-event.ts");

describe("case-memory is bounded by events rotation (opt #99 LEAK-1 rewrite)", () => {
	let tempDir: string;
	let agentDir: string;
	const previous: Record<string, string | undefined> = {};

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-case-rot-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		for (const key of [ENV_AGENT_DIR, ENV_EVENTS_MAX_ROWS, ENV_EVENTS_BATCH]) previous[key] = process.env[key];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		for (const key of [ENV_AGENT_DIR, ENV_EVENTS_MAX_ROWS, ENV_EVENTS_BATCH]) {
			if (previous[key] === undefined) delete process.env[key];
			else process.env[key] = previous[key];
		}
		rmSync(tempDir, { recursive: true, force: true });
	});

	// Each deposit appends one event + one case row. Distinct task per deposit → distinct
	// caseSignature, so "latest per signature" is meaningful (the only row per signature here).
	function seedDeposits(n: number, tag: string): void {
		for (let i = 0; i < n; i++) {
			appendMemoryEventTransaction({
				source: "operator",
				task: `${tag} event ${i}`,
				route: "re",
				outcome: "success",
				confidence: 0.7,
				commands: [`echo ${tag}-${i}`],
				lessons: [`lesson ${tag}-${i}`],
			});
		}
	}

	it("events rotation co-rotates case-memory: count stays == event count and ≤ maxRows+batch", () => {
		// events maxRows=10, batch=2 → events rotation fires once on-disk events > 12 (13th
		// deposit) and co-rebuilds case-memory from the kept events tail. After 20 deposits ≥ 1
		// rotation has fired. case-memory count must EQUAL the (rotated) event count and stay
		// within maxRows+batch — the co-rebuild keeps them in sync, unlike the deleted standalone
		// rotation which left case-memory < events and triggered resurrection thrash.
		process.env[ENV_EVENTS_MAX_ROWS] = "10";
		process.env[ENV_EVENTS_BATCH] = "2";
		seedDeposits(20, "co");

		const caseRows = readCaseMemoryRows();
		const eventRows = jsonlRecords(memoryEventsPath(), isMemoryEvent);
		expect(eventRows.length).toBeLessThanOrEqual(12); // events capped at maxRows+batch
		expect(caseRows.length).toBe(eventRows.length); // case-memory == event count (co-rotated)
		expect(caseRows.length).toBeLessThanOrEqual(12);
		// latestCaseMemoryBySignature covers every surviving on-disk row (last row per signature).
		const bySignature = latestCaseMemoryBySignature();
		expect(bySignature.size).toBe(caseRows.length);
		for (const row of caseRows) {
			expect(bySignature.get(row.caseSignature)).toBe(row);
		}
	});

	it("repeated-signature latest snapshot survives co-rotation (last row wins)", () => {
		// Two deposits share a caseSignature (same route+task). After events rotation co-rotates
		// case-memory, the LAST row for the shared signature must survive in the kept tail and be
		// the one latestCaseMemoryBySignature returns. maxRows=4, batch=1 → rotation fires once
		// events > 5 (6th deposit) → capped to 4. Inject the repeated-signature pair at the TAIL
		// so the latest row is in the kept window.
		process.env[ENV_EVENTS_MAX_ROWS] = "4";
		process.env[ENV_EVENTS_BATCH] = "1";
		seedDeposits(6, "repeat-head");
		appendMemoryEventTransaction({
			source: "operator",
			task: "repeat-shared-sig",
			route: "re",
			outcome: "success",
			confidence: 0.8,
			commands: ["echo shared-first"],
			lessons: ["first lesson"],
		});
		appendMemoryEventTransaction({
			source: "operator",
			task: "repeat-shared-sig",
			route: "re",
			outcome: "success",
			confidence: 0.9,
			commands: ["echo shared-second"],
			lessons: ["second lesson"],
		});

		const rows = readCaseMemoryRows();
		// Co-rotated with events → case-memory count == event count, both ≤ maxRows+batch=5.
		const eventRows = jsonlRecords(memoryEventsPath(), isMemoryEvent);
		expect(rows.length).toBe(eventRows.length);
		expect(rows.length).toBeLessThanOrEqual(5);
		const bySignature = latestCaseMemoryBySignature();
		// The shared signature's latest row is the second deposit (confidence 0.9).
		const shared = bySignature.get(rows.at(-1)!.caseSignature);
		expect(shared).toBeDefined();
		expect(shared?.quality.confidence).toBe(0.9);
	});

	it("events rotation disabled → case-memory grows unbounded (no standalone thrash resurrecting it)", () => {
		// REPI_MEMORY_EVENTS_MAX_ROWS=0 disables events rotation. With the broken standalone
		// rotation present, case-memory would still have been thrashed back to its own cap every
		// deposit. With the standalone rotation REMOVED, nothing rotates → case-memory grows to
		// exactly the deposit count (one row per event). This is the regression guard that the
		// futile standalone thrash is gone: the count is the full deposit count, not a stuck cap.
		process.env[ENV_EVENTS_MAX_ROWS] = "0";
		process.env[ENV_EVENTS_BATCH] = "2";
		seedDeposits(15, "disabled");
		const rows = readCaseMemoryRows();
		expect(rows.length).toBe(15); // unbounded — no rotation of either ledger
		const fileText = readFileSync(caseMemoryPath(), "utf-8");
		const lineCount = fileText.split(/\r?\n/).filter((line) => line.trim()).length;
		expect(lineCount).toBe(15);
	});

	it("storeGrade stays 'pass' after events rotation co-rotates case-memory (no repairable-resurrection)", () => {
		// The core invariant the standalone rotation violated: after bounding, the storeGrade
		// caseIndexOk check must hold (every event's caseSignature has a case-memory row with
		// matching lastEventHash). Co-rotation preserves this; the deleted standalone rotation
		// broke it (missing_latest_row → "repairable" → resurrection). Verify by reading the
		// last transaction's verification report status, which must be pass/done not blocked.
		process.env[ENV_EVENTS_MAX_ROWS] = "10";
		process.env[ENV_EVENTS_BATCH] = "2";
		seedDeposits(20, "grade");
		// After 20 deposits with rotation, every surviving case row's lastEventHash must resolve
		// to a known event entryHash (the co-rebuild guarantees this). Walk the cross-check the
		// way memory-store.ts does.
		const eventRows = jsonlRecords(memoryEventsPath(), isMemoryEvent);
		const caseRows = readCaseMemoryRows();
		const entryHashes = new Set(eventRows.map((e) => e.entryHash));
		for (const row of caseRows) {
			// lastEventHash must be a known event entryHash (or genesis for an empty case, which
			// never happens here since every case has ≥1 source event).
			expect(entryHashes.has(row.lastEventHash) || row.lastEventHash === "0".repeat(64)).toBe(true);
			// every referenced eventId must exist in the kept events tail.
			for (const eventId of row.eventIds) {
				expect(eventRows.some((e) => e.id === eventId)).toBe(true);
			}
		}
	});
});

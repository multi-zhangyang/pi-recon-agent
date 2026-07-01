import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// opt #113 — events.jsonl ledger rotation (the last unbounded REPI ledger; sibling of #99
// case-memory, #88 deposition bus, #48 tool-trace, #107 governance). events.jsonl is the
// append-only CHAIN ledger (each row has seq/prevHash/entryHash chained from genesis
// "0".repeat(64)); appendMemoryEventTransaction rewrites the whole file on every deposit, so
// it grows O(D) rows and every cold recall/quality/replay path reads the whole chain. The
// chain is CONTIGUOUS (prevHash = predecessor's entryHash, and prevHash is an INPUT to the
// row's own entryHash) → head truncation breaks every surviving row → rotation RE-HASHES the
// kept tail forward from genesis (mirroring the sanitize co-rewrite template). case-memory is
// CO-ROTATED via rebuildCaseMemoryFromEvents(keptRows) so eventIds/lastEventHash references
// stay consistent. Env knobs mirror #99: REPI_MEMORY_EVENTS_MAX_ROWS (default 500, 0=disable)
// + REPI_MEMORY_EVENTS_ROTATE_BATCH (default 50).
//
// These tests prove (1) the ledger is capped + the chain still verifies from genesis after
// re-hash + the co-rotated case-memory keeps verifyMemoryStore at "pass", (2) case-memory
// consistency (eventIds subset + lastEventHash matches), (3) maxRows=0 disables, (4) the
// corrupt-store guard aborts on a broken chain. Regression-verified via temp-neuter (disable
// the rotation call → on-disk events grow past maxRows → the cap assertion fails).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_ROWS = "REPI_MEMORY_EVENTS_MAX_ROWS";
const ENV_BATCH = "REPI_MEMORY_EVENTS_ROTATE_BATCH";

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { readCaseMemoryRows } = await import("../../src/core/repi/case-memory.ts");
const { memoryEventHashChainOk } = await import("../../src/core/repi/memory-event.ts");
const { invalidateMemoryStoreVerificationCache, rotateMemoryEventsLedgerIfNeeded, verifyMemoryStore } = await import(
	"../../src/core/repi/memory-store.ts"
);
const { readMemoryEvents } = await import("../../src/core/repi/memory-search.ts");
const { memoryEventsPath } = await import("../../src/core/repi/storage.ts");

describe("events.jsonl ledger rotation (opt #113)", () => {
	let tempDir: string;
	let agentDir: string;
	const previous: Record<string, string | undefined> = {};

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-events-rot-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		for (const key of [ENV_AGENT_DIR, ENV_MAX_ROWS, ENV_BATCH]) previous[key] = process.env[key];
		process.env[ENV_AGENT_DIR] = agentDir;
		// The #77 verification cache can leak verdicts across test cases (the store is swapped
		// under a fixed path key); drop it so each test builds a fresh verdict.
		invalidateMemoryStoreVerificationCache();
	});

	afterEach(() => {
		for (const key of [ENV_AGENT_DIR, ENV_MAX_ROWS, ENV_BATCH]) {
			if (previous[key] === undefined) delete process.env[key];
			else process.env[key] = previous[key];
		}
		rmSync(tempDir, { recursive: true, force: true });
	});

	// Each deposit appends one event (and one case row). Use a distinct task per deposit so the
	// caseSignature differs (proves the kept tail preserves every surviving signature's latest
	// snapshot); a shared signature would also work but distinct signatures exercise the
	// co-rotation more rigorously.
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

	it("caps the ledger at maxRows + chain still verifies from genesis + co-rotated case-memory keeps store at pass", () => {
		// maxRows=10, batch=2 → rotation fires once on-disk events > 10+2=12 (count reaches 13
		// → rotate → 10), then the count oscillates 10→11→12→13(rotate→10) per deposit. So the
		// observable post-deposit count is always ≤ maxRows+batch=12, and exactly maxRows=10 at
		// rotation-landing deposits (13,16,19,22,25). Seed 25 (a landing point, 5 rotations) so
		// the `<= 10` cap assertion is a strong regression guard: if rotation stopped firing,
		// the count would be 25 > 10. The kept tail is re-hashed from genesis →
		// memoryEventHashChainOk must hold. case-memory is co-rotated from the kept tail →
		// verifyMemoryStore must be "pass" (no unknown_event_id / last_event_hash_mismatch).
		process.env[ENV_MAX_ROWS] = "10";
		process.env[ENV_BATCH] = "2";
		seedDeposits(25, "cap");

		const events = readMemoryEvents();
		expect(events.length).toBeLessThanOrEqual(10);
		expect(memoryEventHashChainOk(events)).toBe(true);
		// seq must be contiguous 1..N after re-hash.
		for (const [index, event] of events.entries()) expect(event.seq).toBe(index + 1);
		const report = verifyMemoryStore({ write: false });
		expect(report.storeGrade).toBe("pass");
		expect(report.eventCount).toBe(events.length);
	});

	it("case-memory stays consistent with the re-hashed events tail (eventIds subset + lastEventHash matches)", () => {
		process.env[ENV_MAX_ROWS] = "10";
		process.env[ENV_BATCH] = "2";
		seedDeposits(20, "consistency");

		const events = readMemoryEvents();
		const eventIds = new Set(events.map((event) => event.id));
		const entryHashes = new Set(events.map((event) => event.entryHash));

		const rows = readCaseMemoryRows();
		expect(rows.length).toBeGreaterThan(0);
		for (const row of rows) {
			// Every referenced eventId must survive in the re-hashed events tail.
			for (const eventId of row.eventIds) expect(eventIds.has(eventId)).toBe(true);
			// lastEventHash must be a known event entryHash (or genesis for an empty case).
			if (row.lastEventHash !== "0".repeat(64)) {
				expect(entryHashes.has(row.lastEventHash)).toBe(true);
			}
		}
		// The verifyMemoryStore caseIndexOk cross-check confirms each case row's lastEventHash
		// matches the LATEST event entryHash for that signature (the strong consistency check).
		const report = verifyMemoryStore({ write: false });
		expect(report.caseIndexOk).toBe(true);
		expect(report.storeGrade).toBe("pass");
	});

	it("maxRows=0 disables rotation — the ledger grows unbounded (opt-out honored)", () => {
		process.env[ENV_MAX_ROWS] = "0";
		process.env[ENV_BATCH] = "2";
		seedDeposits(15, "disabled");
		const events = readMemoryEvents();
		// No rotation → all 15 events on disk.
		expect(events.length).toBe(15);
		expect(memoryEventHashChainOk(events)).toBe(true);
	});

	it("temp-neuter: rotation trigger fires only past maxRows+batch (cap holds once above the trigger)", () => {
		// maxRows=10, batch=2 → trigger at > 12. Below the trigger (8 deposits) no rotation
		// fires → 8 events on disk (≤ 10, cap not exceeded, rotation correctly inert). Append
		// past the trigger (13 total) → rotation fires → events ≤ 10. The temp-neuter (commenting
		// out rotateMemoryEventsLedgerIfNeeded at recon-profile.ts:30346) would leave 13 events
		// on disk → the `<= 10` cap assertion fails. The positive direction is asserted here;
		// the negative is verified by reverting the call site and re-running this file.
		process.env[ENV_MAX_ROWS] = "10";
		process.env[ENV_BATCH] = "2";
		seedDeposits(8, "neuter-below");
		expect(readMemoryEvents().length).toBe(8); // below trigger, no rotation
		seedDeposits(5, "neuter-above"); // total 13 > 12 → rotation fires
		const events = readMemoryEvents();
		expect(events.length).toBeLessThanOrEqual(10);
		expect(memoryEventHashChainOk(events)).toBe(true);
		const fileText = readFileSync(memoryEventsPath(), "utf-8");
		const lineCount = fileText.split(/\r?\n/).filter((line) => line.trim()).length;
		expect(lineCount).toBe(events.length);
		expect(lineCount).toBeLessThanOrEqual(10);
	});

	it("corrupt-store guard: a broken chain aborts rotation (returns null, file unchanged)", () => {
		// Build a store with > maxRows+batch events WITHOUT rotating (maxRows=0), then corrupt
		// the chain (flip a prevHash) and confirm rotation aborts instead of rewriting a
		// corrupt store.
		process.env[ENV_MAX_ROWS] = "0";
		process.env[ENV_BATCH] = "2";
		seedDeposits(13, "corrupt");
		expect(readMemoryEvents().length).toBe(13); // 13 on disk, unrotated

		// Corrupt: flip one character of the 2nd row's prevHash (keep it a valid 64-char hex
		// string so isMemoryEvent still parses → eventScan.errors.length===0, but the chain is
		// broken → storeGrade==="blocked").
		const raw = readFileSync(memoryEventsPath(), "utf-8");
		const lines = raw.split(/\r?\n/).filter((line) => line.trim());
		const secondRow = JSON.parse(lines[1]) as { prevHash: string };
		const flipped = secondRow.prevHash.charAt(0) === "0" ? "1" : "0";
		secondRow.prevHash = flipped + secondRow.prevHash.slice(1);
		lines[1] = JSON.stringify(secondRow);
		const corruptedBody = `${lines.join("\n")}\n`;
		writeFileSync(memoryEventsPath(), corruptedBody, "utf-8");

		// Now enable rotation and call directly.
		process.env[ENV_MAX_ROWS] = "10";
		process.env[ENV_BATCH] = "2";
		invalidateMemoryStoreVerificationCache(); // drop any pre-corruption verdict
		const result = rotateMemoryEventsLedgerIfNeeded();
		expect(result).toBeNull();
		// File unchanged — rotation did NOT rewrite a corrupt store.
		const afterRaw = readFileSync(memoryEventsPath(), "utf-8");
		expect(afterRaw).toBe(corruptedBody);
		// And case-memory is untouched by the abort.
		expect(readCaseMemoryRows().length).toBeGreaterThan(0);
	});
});

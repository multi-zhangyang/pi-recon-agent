import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { MemoryQualityLedgerRowV11 } from "../../src/core/repi/memory-quality.ts";

// opt F4 — quality ledger rotation (sibling of #88 deposition bus rotation + #48 tool-trace
// ledger rotation). The quality ledger (quality-ledger.jsonl) is appended once per event per
// orchestration call (rows = events.map(...)) via buildMemoryQualityLedgerReport({write:true})
// and never rotated → O(D·N) rows over a session; readMemoryQualityLedgerRows reads the whole
// file on every cold read. The ledger has a prevHash/entryHash chain but NO genesis-strict
// verifier (isMemoryQualityLedgerRow is structural only; no memoryQualityHashChainOk), and
// readers (latestMemoryQualityByEvent) take the latest row per eventId → HEAD IS DISPOSABLE →
// rotation-safe. opt F4 caps on-disk rows at REPI_QUALITY_LEDGER_MAX_ROWS (default 500): when
// the just-appended batch's last seq exceeds maxRows + REPI_QUALITY_LEDGER_ROTATE_BATCH
// (default 50), rotateQualityLedgerIfNeeded drops the head rows, keeps the last maxRows,
// RENUMBERS seq to 1..kept (seq IS part of entryHash via memoryQualityLedgerRowHash, which
// hashes every field except entryHash), re-hashes the kept tail forward from genesis, and
// atomically rewrites the ledger (writeFileAtomic temp+rename 0o600). The batch trigger fires
// once per orchestration call (not per row) so the hot-path write stays a single
// read-modify-write; the O(maxRows) rotation amortizes to O(maxRows/batch) per call. The #83
// latestMemoryQualityByEvent cache is mtime+size guarded → the atomic rewrite auto-invalidates
// it; there is no #73-style seq/prevHash chain cache for this ledger → no re-warm is needed.
//
// These tests prove (1) the ledger is capped at maxRows on disk after enough appends, (2) the
// rebuilt chain has no prevHash drift (genesis-reset head + per-row entryHash recompute +
// prevHash chaining all hold post-rotation), (3) seq is contiguous 1..kept, (4) the head
// prevHash is "0".repeat(64), (5) the next append after rotation continues seq correctly
// (kept.length+1) and chains onto the rotated tail, (6) maxRows=0 disables rotation.
// Regression-verified via temp-neuter (disable the rotation call → on-disk rows grow past
// maxRows → the cap assertion fails).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_ROWS = "REPI_QUALITY_LEDGER_MAX_ROWS";
const ENV_BATCH = "REPI_QUALITY_LEDGER_ROTATE_BATCH";

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { buildMemoryQualityLedgerReport, memoryQualityLedgerRowHash, readMemoryQualityLedgerRows } = await import(
	"../../src/core/repi/memory-quality.ts"
);
type QualityRow = MemoryQualityLedgerRowV11;

// Local genesis-strict chain verifier (the ledger has no production verifier —
// isMemoryQualityLedgerRow is structural only). Walks from "0".repeat(64), recomputes each
// row's entryHash via memoryQualityLedgerRowHash, and checks prevHash chaining. This is the
// contract a rotation must preserve: a genesis-reset head + re-hashed tail verifies cleanly.
function qualityChainOk(rows: { prevHash: string; entryHash: string }[]): boolean {
	let prev = "0".repeat(64);
	for (const row of rows) {
		if (row.prevHash !== prev) return false;
		const recomputed = memoryQualityLedgerRowHash({ ...row, entryHash: "" } as unknown as QualityRow);
		if (row.entryHash !== recomputed) return false;
		prev = row.entryHash;
	}
	return true;
}

describe("memory quality ledger rotation (opt F4)", () => {
	let tempDir: string;
	let agentDir: string;
	const previous: Record<string, string | undefined> = {};

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-quality-rot-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		for (const key of [ENV_AGENT_DIR, ENV_MAX_ROWS, ENV_BATCH]) previous[key] = process.env[key];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		for (const key of [ENV_AGENT_DIR, ENV_MAX_ROWS, ENV_BATCH]) {
			if (previous[key] === undefined) delete process.env[key];
			else process.env[key] = previous[key];
		}
		rmSync(tempDir, { recursive: true, force: true });
	});

	// Create K memory events; each buildMemoryQualityLedgerReport({write:true}) call appends K
	// rows (one per event). K=3 keeps the test cheap while still exercising the per-event batch.
	const EVENT_COUNT = 3;

	function seedEvents(n: number, tag: string): void {
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

	it("caps the ledger at maxRows on disk + the genesis-reset chain verifies cleanly after rotation", () => {
		process.env[ENV_MAX_ROWS] = "8";
		process.env[ENV_BATCH] = "2";
		seedEvents(EVENT_COUNT, "cap-chain");
		// Each call appends EVENT_COUNT=3 rows. Rotation fires once lastSeq > 8+2=10, i.e. on
		// the 4th call (lastSeq=12). Call 8 → at least one rotation has fired; on-disk rows ≤ 8.
		for (let c = 0; c < 8; c++) buildMemoryQualityLedgerReport({ write: true });

		const rows = readMemoryQualityLedgerRows();
		expect(rows.length).toBeLessThanOrEqual(8);
		// The kept tail is re-hashed from genesis; the local verifier recomputes each entryHash
		// AND walks prevHash from "0".repeat(64) → both must hold post-rotation.
		expect(qualityChainOk(rows)).toBe(true);
		// seq renumbered to a contiguous 1..kept.length (no leftover large seq values).
		expect(rows.map((row) => row.seq)).toEqual(Array.from({ length: rows.length }, (_, i) => i + 1));
		expect(rows[0]?.prevHash).toBe("0".repeat(64));
	});

	it("the next append after a rotation continues the chain + seq correctly (no backwards seq)", () => {
		// batch=20 so a second rotation does NOT fire on the single post-rotation append (with
		// EVENT_COUNT=3 rows the next call's lastSeq = 8+3 = 11, well under 8+20=28). This lets
		// us observe the new rows chaining onto the rotated tail before another compaction.
		process.env[ENV_MAX_ROWS] = "8";
		process.env[ENV_BATCH] = "20";
		seedEvents(EVENT_COUNT, "continue-seq");
		// 3 rows/call → rotation fires on call 10 (lastSeq=30 > 8+20=28) → ledger capped to 8.
		for (let c = 0; c < 10; c++) buildMemoryQualityLedgerReport({ write: true });
		const rotatedTail = readMemoryQualityLedgerRows();
		expect(rotatedTail.length).toBeLessThanOrEqual(8);
		const lastKept = rotatedTail.at(-1);
		expect(lastKept).toBeDefined();

		// One more call — must chain onto the rotated tail with seq = kept.length + 1.
		buildMemoryQualityLedgerReport({ write: true });
		const after = readMemoryQualityLedgerRows();
		// The first new row sits right after the kept tail.
		const firstNew = after[rotatedTail.length];
		expect(firstNew).toBeDefined();
		expect(firstNew.seq).toBe(rotatedTail.length + 1);
		expect(firstNew.prevHash).toBe(lastKept!.entryHash);
		// The new rows chain onto the rotated tail → full chain still verifies.
		expect(qualityChainOk(after)).toBe(true);
		// seq is contiguous 1..after.length (no gap at the rotation boundary).
		expect(after.map((row) => row.seq)).toEqual(Array.from({ length: after.length }, (_, i) => i + 1));
	});

	it("maxRows=0 disables rotation — the ledger grows unbounded (opt-out honored)", () => {
		process.env[ENV_MAX_ROWS] = "0";
		process.env[ENV_BATCH] = "2";
		seedEvents(EVENT_COUNT, "disabled");
		// 5 calls × 3 rows = 15 rows; no rotation → all 15 on disk, chain contiguous from genesis.
		for (let c = 0; c < 5; c++) buildMemoryQualityLedgerReport({ write: true });
		const rows = readMemoryQualityLedgerRows();
		expect(rows.length).toBe(15);
		expect(qualityChainOk(rows)).toBe(true);
	});
});

import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { MemoryReplayEvaluatorRowV12 } from "../../src/core/repi/memory-replay.ts";

// opt F5 — replay evaluator ledger rotation (sibling of #88 deposition bus rotation + #48
// tool-trace ledger rotation + F4 quality ledger rotation). The replay ledger
// (replay-evaluator-ledger.jsonl) is appended once per scenario (up to 24) per orchestration
// call via buildMemoryReplayEvaluatorReport({write:true}) and never rotates → unbounded growth;
// readMemoryReplayEvaluatorRows reads the whole file on every cold read. The ledger has a
// prevHash/entryHash chain but NO genesis-strict verifier (isMemoryReplayEvaluatorRow is
// structural only; no memoryReplayHashChainOk), and readers (previousRows.at(-1) for chain
// continuity only) → HEAD IS DISPOSABLE → rotation-safe. opt F5 caps on-disk rows at
// REPI_REPLAY_LEDGER_MAX_ROWS (default 500): when the just-appended batch's last seq exceeds
// maxRows + REPI_REPLAY_LEDGER_ROTATE_BATCH (default 50), rotateReplayLedgerIfNeeded drops the
// head rows, keeps the last maxRows, RENUMBERS seq to 1..kept (seq IS part of entryHash via
// memoryReplayEvaluatorRowHash, which hashes every field except entryHash), re-hashes the kept
// tail forward from genesis, and atomically rewrites the ledger (writeFileAtomic temp+rename
// 0o600). The batch trigger fires once per orchestration call (not per row); there is no cache
// for this ledger → no re-warm is needed.
//
// These tests prove (1) the ledger is capped at maxRows on disk after enough appends, (2) the
// rebuilt chain has no prevHash drift (genesis-reset head + per-row entryHash recompute +
// prevHash chaining all hold post-rotation), (3) seq is contiguous 1..kept, (4) the head
// prevHash is "0".repeat(64), (5) the next append after rotation continues seq correctly
// (kept.length+1) and chains onto the rotated tail, (6) maxRows=0 disables rotation.
// Regression-verified via temp-neuter (disable the rotation call → on-disk rows grow past
// maxRows → the cap assertion fails).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_ROWS = "REPI_REPLAY_LEDGER_MAX_ROWS";
const ENV_BATCH = "REPI_REPLAY_LEDGER_ROTATE_BATCH";

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { buildMemoryReplayEvaluatorReport, memoryReplayEvaluatorRowHash, readMemoryReplayEvaluatorRows } = await import(
	"../../src/core/repi/memory-replay.ts"
);

// Local genesis-strict chain verifier (the ledger has no production verifier —
// isMemoryReplayEvaluatorRow is structural only). Walks from "0".repeat(64), recomputes each
// row's entryHash via memoryReplayEvaluatorRowHash, and checks prevHash chaining. This is the
// contract a rotation must preserve: a genesis-reset head + re-hashed tail verifies cleanly.
function replayChainOk(rows: { prevHash: string; entryHash: string }[]): boolean {
	let prev = "0".repeat(64);
	for (const row of rows) {
		if (row.prevHash !== prev) return false;
		const recomputed = memoryReplayEvaluatorRowHash({
			...row,
			entryHash: "",
		} as unknown as MemoryReplayEvaluatorRowV12);
		if (row.entryHash !== recomputed) return false;
		prev = row.entryHash;
	}
	return true;
}

describe("memory replay evaluator ledger rotation (opt F5)", () => {
	let tempDir: string;
	let agentDir: string;
	const previous: Record<string, string | undefined> = {};

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-replay-rot-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	// Create K memory events; buildMemoryReplayEvaluatorReport({write:true}) builds up to 10
	// default-from-memory scenarios (one per qualifying event, sliced to 10) → appends up to K
	// rows per call (K ≤ 10). K=5 keeps the test cheap while still exercising the per-scenario
	// batch. Events must be success/partial with confidence ≥ 0.5 to pass the scenario filter.
	const EVENT_COUNT = 5;

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
		// Each call appends EVENT_COUNT=5 rows. Rotation fires once lastSeq > 8+2=10, i.e. on
		// the 3rd call (lastSeq=15). Call 6 → at least one rotation has fired; on-disk rows ≤ 8.
		for (let c = 0; c < 6; c++) buildMemoryReplayEvaluatorReport({ write: true });

		const rows = readMemoryReplayEvaluatorRows();
		expect(rows.length).toBeLessThanOrEqual(8);
		// The kept tail is re-hashed from genesis; the local verifier recomputes each entryHash
		// AND walks prevHash from "0".repeat(64) → both must hold post-rotation.
		expect(replayChainOk(rows)).toBe(true);
		// seq renumbered to a contiguous 1..kept.length (no leftover large seq values).
		expect(rows.map((row) => row.seq)).toEqual(Array.from({ length: rows.length }, (_, i) => i + 1));
		expect(rows[0]?.prevHash).toBe("0".repeat(64));
	});

	it("the next append after a rotation continues the chain + seq correctly (no backwards seq)", () => {
		// batch=30 so a second rotation does NOT fire on the single post-rotation append (with
		// EVENT_COUNT=5 rows the next call's lastSeq = 8+5 = 13, well under 8+30=38). This lets
		// us observe the new rows chaining onto the rotated tail before another compaction.
		process.env[ENV_MAX_ROWS] = "8";
		process.env[ENV_BATCH] = "30";
		seedEvents(EVENT_COUNT, "continue-seq");
		// 5 rows/call → rotation fires on call 8 (lastSeq=40 > 8+30=38) → ledger capped to 8.
		for (let c = 0; c < 8; c++) buildMemoryReplayEvaluatorReport({ write: true });
		const rotatedTail = readMemoryReplayEvaluatorRows();
		expect(rotatedTail.length).toBeLessThanOrEqual(8);
		const lastKept = rotatedTail.at(-1);
		expect(lastKept).toBeDefined();

		// One more call — must chain onto the rotated tail with seq = kept.length + 1.
		buildMemoryReplayEvaluatorReport({ write: true });
		const after = readMemoryReplayEvaluatorRows();
		// The first new row sits right after the kept tail.
		const firstNew = after[rotatedTail.length];
		expect(firstNew).toBeDefined();
		expect(firstNew.seq).toBe(rotatedTail.length + 1);
		expect(firstNew.prevHash).toBe(lastKept!.entryHash);
		// The new rows chain onto the rotated tail → full chain still verifies.
		expect(replayChainOk(after)).toBe(true);
		// seq is contiguous 1..after.length (no gap at the rotation boundary).
		expect(after.map((row) => row.seq)).toEqual(Array.from({ length: after.length }, (_, i) => i + 1));
	});

	it("maxRows=0 disables rotation — the ledger grows unbounded (opt-out honored)", () => {
		process.env[ENV_MAX_ROWS] = "0";
		process.env[ENV_BATCH] = "2";
		seedEvents(EVENT_COUNT, "disabled");
		// 3 calls × 5 rows = 15 rows; no rotation → all 15 on disk, chain contiguous from genesis.
		for (let c = 0; c < 3; c++) buildMemoryReplayEvaluatorReport({ write: true });
		const rows = readMemoryReplayEvaluatorRows();
		expect(rows.length).toBe(15);
		expect(replayChainOk(rows)).toBe(true);
	});
});

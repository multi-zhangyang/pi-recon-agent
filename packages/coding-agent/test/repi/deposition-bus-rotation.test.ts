import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// opt #88 — deposition bus rotation (sibling of #48 tool-trace ledger rotation). The
// deposition event bus (deposition-events.jsonl) is append-only with a contiguous prevHash
// chain that memoryDepositionHashChainOk walks FROM GENESIS ("0".repeat(64)). Without
// rotation the bus grows unbounded over a session → every cold read
// (buildMemoryDepositionReport, memoryDepositionHashChainOk, nextDepositionChain on a cache
// miss) pays O(file) → O(deposits). opt #88 caps on-disk rows at REPI_DEPOSITION_BUS_MAX_ROWS
// (default 500): when the just-appended row's seq exceeds maxRows + batch
// (REPI_DEPOSITION_BUS_ROTATE_BATCH, default 50), rotateDepositionBusIfNeeded drops the head
// rows, keeps the last maxRows, RENUMBERS seq to 1..maxRows, re-hashes the kept tail forward
// from genesis, and atomically rewrites the bus. The verifier walks from genesis → a
// genesis-reset head + re-hashed tail verifies CLEANLY. The batch trigger keeps the hot-path
// append O(chunk) via the #73 chain cache (rotation fires once per batch, not every append).
//
// These tests prove (1) the bus is capped at maxRows on disk after enough appends, (2) the
// hash chain + per-row entryHash verify cleanly after rotation (genesis-reset contract),
// (3) seq is contiguous 1..kept after rotation + the NEXT append's seq continues correctly
// (no backwards seq), (4) the #73 chain cache stays consistent across a rotation boundary.
// Regression-verified via temp-neuter (disable the rotation call → on-disk rows grow past
// maxRows → the cap assertion fails).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_ROWS = "REPI_DEPOSITION_BUS_MAX_ROWS";
const ENV_BATCH = "REPI_DEPOSITION_BUS_ROTATE_BATCH";

const { appendMemoryDepositionRuntimeEvent } = await import("../../src/core/recon-profile.ts");
const { memoryDepositionHashChainOk, readMemoryDepositionEvents } = await import(
	"../../src/core/repi/memory-deposition.ts"
);

function readBusRows(): ReturnType<typeof readMemoryDepositionEvents> {
	return readMemoryDepositionEvents();
}

describe("memory deposition bus rotation (opt #88)", () => {
	let tempDir: string;
	let agentDir: string;
	const previous: Record<string, string | undefined> = {};

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-deposition-rot-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	function appendN(n: number, baseTask: string): void {
		for (let i = 0; i < n; i++) {
			appendMemoryDepositionRuntimeEvent(
				{
					stage: "tool",
					source: `tool_result:bash`,
					status: "written",
					task: `${baseTask} ${i}`,
					route: "re",
					command: `echo ${i}`,
					stdout: `out ${i}`,
					outcome: "partial",
					lessons: [`lesson ${i}`],
					commands: [`echo ${i}`],
					reason: "rotation test deposition",
				},
				{ writeback: false },
			);
		}
	}

	it("caps the bus at maxRows on disk + the genesis-reset chain verifies cleanly after rotation", () => {
		// Small cap so rotation triggers quickly. maxRows=8, batch=2 → rotation fires once the
		// just-appended seq > 8+2=10, i.e. at seq=11 (the 11th append). Append 20 → at least one
		// rotation has fired; on-disk rows must be ≤ maxRows=8.
		process.env[ENV_MAX_ROWS] = "8";
		process.env[ENV_BATCH] = "2";
		appendN(20, "cap-chain");

		const rows = readBusRows();
		expect(rows.length).toBeLessThanOrEqual(8);
		// The kept tail is re-hashed from genesis; memoryDepositionHashChainOk walks from
		// "0".repeat(64) AND recomputes each row's entryHash → both must hold post-rotation.
		expect(memoryDepositionHashChainOk(rows)).toBe(true);
		// seq renumbered to a contiguous 1..kept.length (no leftover large seq values).
		expect(rows.map((row) => row.seq)).toEqual(Array.from({ length: rows.length }, (_, i) => i + 1));
		expect(rows[0]?.prevHash).toBe("0".repeat(64));
	});

	it("the next append after a rotation continues the chain + seq correctly (no backwards seq)", () => {
		process.env[ENV_MAX_ROWS] = "8";
		process.env[ENV_BATCH] = "2";
		// Append past the cap to force a rotation, then append one more and verify it chains
		// onto the rotated tail with seq = kept.length + 1 (monotonic, not reset-and-collide).
		appendN(14, "continue-seq"); // seq 1..14 → rotation fires at seq 11 (11 > 10) → bus capped to 8.
		const beforeTail = readBusRows();
		expect(beforeTail.length).toBeLessThanOrEqual(8);
		const lastKept = beforeTail.at(-1);
		expect(lastKept).toBeDefined();

		// One more append — must chain onto the rotated tail.
		const appended = appendMemoryDepositionRuntimeEvent(
			{
				stage: "tool",
				source: `tool_result:bash`,
				status: "written",
				task: `continue-seq tail`,
				route: "re",
				command: `echo tail`,
				stdout: `out tail`,
				outcome: "partial",
				lessons: [`lesson tail`],
				commands: [`echo tail`],
				reason: "post-rotation continuation",
			},
			{ writeback: false },
		);
		expect(appended.seq).toBe(beforeTail.length + 1);
		expect(appended.prevHash).toBe(lastKept!.entryHash);

		const after = readBusRows();
		// The new row chains onto the rotated tail → full chain still verifies.
		expect(memoryDepositionHashChainOk(after)).toBe(true);
		expect(after.at(-1)?.seq).toBe(beforeTail.length + 1);
	});

	it("maxRows=0 disables rotation — the bus grows unbounded (opt-out honored)", () => {
		process.env[ENV_MAX_ROWS] = "0";
		process.env[ENV_BATCH] = "2";
		appendN(15, "disabled");
		const rows = readBusRows();
		// No rotation → all 15 rows on disk, chain contiguous from genesis.
		expect(rows.length).toBe(15);
		expect(memoryDepositionHashChainOk(rows)).toBe(true);
	});
});

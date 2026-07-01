import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RepairQueueItemV1 } from "../src/core/recon-profile.ts";
import { appendFailureRepairLedger, readRuntimeRepairQueueRows } from "../src/core/recon-profile.ts";
import { runtimeRepairQueuePath } from "../src/core/repi/storage.ts";

// Companion to the failure-ledger rotation (opt #53). The repair queue
// (evidence/failures/repair-queue.jsonl) is an append-only audit log of repair
// actions, appended on every failure inside appendFailureRepairLedger. Before
// opt #56 it was NEVER drained or rotated → unbounded cross-session disk growth
// + an O(n) full-file scan on every failure-signature report (the same class
// opt #53 fixed for the failure ledger). The repair queue has NO per-row count
// semantics (readers dedup by signature, keeping the latest/best repair), so
// tail-rotation is safe WITHOUT a sidecar summary map. This test drives the real
// append path and verifies the queue is tail-capped while the latest repair
// survives.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_ROWS = "REPI_REPAIR_QUEUE_MAX_ROWS";

function makeRepair(signature: string, idx: number): RepairQueueItemV1 {
	return {
		repairId: `repair:${signature.slice(0, 8)}:${idx}`,
		fromFailureId: `fail:runtime:${signature.slice(0, 8)}:${idx}`,
		signature,
		scope: "test-scope",
		action: "rerun",
		repairAction: "rerun",
		commands: [`echo retry-${idx}`],
		expectedArtifacts: [],
		expectedChecks: ["check_a"],
		preconditions: { liveAllowed: false, providerAllowed: false, requiredSecrets: [] },
		paused: false,
		allowlist: [],
		rollbackCriteria: { baseline: "none", mustRestore: [], verificationCommand: "re_proof_loop run <target> 4 2" },
		blockedConditions: [],
		evidenceWriteback: {
			failureLedgerPath: "",
			repairQueuePath: runtimeRepairQueuePath(),
			appendOnly: true,
			mode: "runtime",
		},
		regressionChecks: ["check_a"],
	};
}

describe("runtime repair-queue rotation", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousMaxRows: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-repair-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		previousMaxRows = process.env[ENV_MAX_ROWS];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		if (previousMaxRows === undefined) delete process.env[ENV_MAX_ROWS];
		else process.env[ENV_MAX_ROWS] = previousMaxRows;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("does not rotate when under the cap (maxRows disabled = 0 keeps all)", async () => {
		process.env[ENV_MAX_ROWS] = "0"; // disable rotation
		const sig = "sig-norotate";
		for (let i = 1; i <= 5; i++) {
			appendFailureRepairLedger({ failures: [], repairs: [makeRepair(sig, i)] });
		}
		const rows = readRuntimeRepairQueueRows();
		expect(rows.length).toBe(5);
		// All survive: head and tail both present.
		expect(rows.some((r) => r.repairId.endsWith(":1"))).toBe(true);
		expect(rows.some((r) => r.repairId.endsWith(":5"))).toBe(true);
	});

	it("tail-rotates the repair queue, keeping the latest and dropping the oldest", async () => {
		process.env[ENV_MAX_ROWS] = "4"; // small cap
		const sig = "sig-rotate";
		// Append 10 same-signature repairs → queue caps to last 4 rows.
		for (let i = 1; i <= 10; i++) {
			appendFailureRepairLedger({ failures: [], repairs: [makeRepair(sig, i)] });
		}
		const rows = readRuntimeRepairQueueRows();
		expect(rows.length).toBeLessThanOrEqual(4);
		expect(rows.length).toBeGreaterThan(0);
		// Tail kept: the last appended repair survives.
		expect(rows.some((r) => r.repairId.endsWith(":10"))).toBe(true);
		// Head dropped: the first repair is gone from the queue.
		expect(rows.some((r) => r.repairId.endsWith(":1"))).toBe(false);
		// The on-disk file is capped (audit the raw line count too).
		const raw = readFileSync(runtimeRepairQueuePath(), "utf-8").split("\n").filter(Boolean);
		expect(raw.length).toBeLessThanOrEqual(4);
	});

	it("keeps the latest repair per signature available to readers after rotation", async () => {
		// Two signatures, each appended 6 times, cap 4. After rotation the queue
		// holds the last 4 rows total. The latest repair for the most-recently-
		// appended signature must survive; readers dedup by signature so the
		// report still finds a repair for any signature whose latest row is kept.
		process.env[ENV_MAX_ROWS] = "4";
		for (let i = 1; i <= 6; i++) {
			appendFailureRepairLedger({ failures: [], repairs: [makeRepair("sig-a", i)] });
		}
		for (let i = 1; i <= 6; i++) {
			appendFailureRepairLedger({ failures: [], repairs: [makeRepair("sig-b", i)] });
		}
		const rows = readRuntimeRepairQueueRows();
		expect(rows.length).toBeLessThanOrEqual(4);
		// The very last appended (sig-b:6) always survives.
		expect(rows.some((r) => r.repairId === "repair:sig-b:6")).toBe(true);
	});
});

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FailureLedgerEventV1 } from "../src/core/recon-profile.ts";
import {
	appendFailureRepairLedger,
	readRuntimeFailureLedgerRows,
	runtimeFailureAttempt,
} from "../src/core/recon-profile.ts";
import { runtimeFailureLedgerPath, runtimeFailureSummaryPath } from "../src/core/repi/storage.ts";

// The runtime-failure ledger is an append-only audit log that was previously
// scanned in full on EVERY failure to count same-signature rows for the
// "exhausted after maxAttempts" decision (O(n) per failure, O(n²) cumulative,
// unbounded on disk across sessions). opt #53 moved per-signature attempt
// counts into a compact {signature: count} summary map (the O(1) source of
// truth) so the ledger can be safely tail-rotated WITHOUT resetting attempt
// counts. This test drives the real append path and verifies: (1) counts come
// from the summary map; (2) rotation caps the ledger but does NOT reset counts
// (the load-bearing semantic); (3) migration rebuilds the summary from a
// pre-existing ledger that has no summary file yet.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_ROWS = "REPI_FAILURE_LEDGER_MAX_ROWS";

function makeFailure(signature: string, attempt: number): FailureLedgerEventV1 {
	return {
		id: `fail:runtime:${signature.slice(0, 8)}:${attempt}`,
		ts: `2026-06-29T00:00:0${attempt % 10}Z`,
		source: "re_autofix",
		scope: "test-scope",
		category: "runtime_failed",
		signature,
		attempt,
		maxAttempts: 3,
		status: "repair_queued",
		failedChecks: ["check_a"],
		artifacts: [],
		artifactHashes: [],
		repairId: `repair:runtime:${signature.slice(0, 8)}`,
		budget: { retryKey: signature, remainingAttempts: Math.max(0, 3 - attempt), exhaustedAction: "escalate" },
		retryBudget: { retryKey: signature, remainingAttempts: Math.max(0, 3 - attempt), exhaustedAction: "escalate" },
		evidenceWriteback: {
			failureLedgerPath: runtimeFailureLedgerPath(),
			repairQueuePath: "",
			appendOnly: true,
			mode: "runtime",
		},
		blockedConditions: [],
		rollback: { required: false, baseline: "none", allowlist: [], criteria: [], restored: false },
	};
}

describe("runtime-failure ledger summary map + rotation", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousMaxRows: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-fail-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("counts attempts from the summary map, incrementing per appended failure", async () => {
		process.env[ENV_MAX_ROWS] = "0"; // disable rotation for this scenario
		const sig = "sig-count-test";
		expect(runtimeFailureAttempt(sig)).toBe(1); // empty → attempt 1
		appendFailureRepairLedger({ failures: [makeFailure(sig, 1)], repairs: [] });
		expect(runtimeFailureAttempt(sig)).toBe(2);
		appendFailureRepairLedger({ failures: [makeFailure(sig, 2)], repairs: [] });
		appendFailureRepairLedger({ failures: [makeFailure(sig, 3)], repairs: [] });
		expect(runtimeFailureAttempt(sig)).toBe(4); // 3 prior → attempt 4
		// A different signature is counted independently.
		expect(runtimeFailureAttempt("sig-other")).toBe(1);
		// The summary file is persisted with the counts.
		const summary = JSON.parse(readFileSync(runtimeFailureSummaryPath(), "utf-8")) as Record<string, number>;
		expect(summary[sig]).toBe(3);
	});

	it("rotation caps the on-disk ledger WITHOUT resetting attempt counts (key semantic)", async () => {
		process.env[ENV_MAX_ROWS] = "4"; // small cap
		const sig = "sig-rotate-test";
		// Append 10 same-signature failures → ledger caps to last 4 rows, but
		// the summary map preserves the full count of 10, so the next attempt
		// is 11 (NOT reset to 5 by the rotation).
		for (let i = 1; i <= 10; i++) {
			appendFailureRepairLedger({ failures: [makeFailure(sig, i)], repairs: [] });
		}
		const rows = readRuntimeFailureLedgerRows();
		expect(rows.length).toBeLessThanOrEqual(4);
		expect(rows.length).toBeGreaterThan(0);
		// The tail is kept: the last appended attempt survives.
		expect(rows.some((row) => row.attempt === 10)).toBe(true);
		// The head is dropped: attempt 1 is gone from the ledger...
		expect(rows.some((row) => row.attempt === 1)).toBe(false);
		// ...but the attempt COUNT is preserved by the summary map → next attempt is 11.
		expect(runtimeFailureAttempt(sig)).toBe(11);
	});

	it("migrates a pre-summary ledger: builds counts from existing rows on first read", async () => {
		process.env[ENV_MAX_ROWS] = "0"; // disable rotation; we pre-seed the ledger
		const sig = "sig-migrate-test";
		// Pre-seed the ledger directly (no summary file yet) with 2 same-signature
		// rows, emulating a deployment that accumulated failures before opt #53.
		// ensureReconStorage() will create dirs; call it via a real append of an
		// unrelated signature, then overwrite the ledger with our pre-seed rows.
		appendFailureRepairLedger({ failures: [makeFailure("sig-bootstrap", 1)], repairs: [] });
		const seeded = `${[makeFailure(sig, 1), makeFailure(sig, 2)].map((row) => JSON.stringify(row)).join("\n")}\n`;
		writeFileSync(runtimeFailureLedgerPath(), seeded, { encoding: "utf-8", mode: 0o600 });
		// Remove the summary file so the next read must migrate from the ledger.
		// (The bootstrap append above created one; delete it to force migration.)
		const summaryPath = runtimeFailureSummaryPath();
		if (existsSync(summaryPath)) rmSync(summaryPath, { force: true });
		// First read migrates: 2 prior same-signature rows → next attempt is 3.
		expect(runtimeFailureAttempt(sig)).toBe(3);
		// Migration persists the summary so a second read does NOT rebuild.
		const summary = JSON.parse(readFileSync(summaryPath, "utf-8")) as Record<string, number>;
		expect(summary[sig]).toBe(2);
		// The unrelated bootstrap signature we appended is NOT in the migrated
		// summary (its row was overwritten by the pre-seed) — migration reflects
		// the current ledger contents only.
		expect(summary["sig-bootstrap"]).toBeUndefined();
	});
});

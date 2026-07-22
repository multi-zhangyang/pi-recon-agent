import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FailureLedgerEventV1, RepairQueueItemV1 } from "../src/core/recon-profile.ts";
import {
	failureSignaturePriorityReport,
	readRuntimeFailureLedgerRows,
	readRuntimeRepairQueueRows,
} from "../src/core/recon-profile.ts";
import {
	ensureRepiStorage,
	runtimeFailureLedgerPath,
	runtimeRepairQueuePath,
	writePrivateTextFile,
} from "../src/core/repi/storage.ts";

// Regression guard for opt #51: the runtime failure + repair ledger readers previously
// validated only `row?.signature && row?.id` / `row?.repairId && row?.signature`. The
// consumers call METHODS on fields those loose checks don't verify:
//   - failureSignaturePriorityReport sorts `right.ts.localeCompare(left.ts)`, reads
//     `left.budget.remainingAttempts`, maps `failure.failedChecks.join("|")` +
//     `failure.budget.exhaustedAction`.
//   - the repair-queue map reads `repair.commands.length` / `repair.commands.join` /
//     `repair.expectedChecks.join` / `repair.signature.slice`.
// A single JSONL line that PARSES (valid JSON) but is missing `ts`/`budget`/`failedChecks`/
// `commands`/`expectedChecks` (torn pre-#43 append, older schema, hand-edit) sailed past the
// loose check and threw `undefined.localeCompare is not a function` etc., crashing every
// per-turn recon caller. opt #51 tightens the readers with structural type guards so the
// corrupt row is dropped at the read boundary.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

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
			repairQueuePath: runtimeRepairQueuePath(),
			appendOnly: true,
			mode: "runtime",
		},
		blockedConditions: [],
		rollback: { required: false, baseline: "none", allowlist: [], criteria: [], restored: false },
	};
}

function makeRepair(signature: string): RepairQueueItemV1 {
	return {
		repairId: `repair:runtime:${signature.slice(0, 8)}`,
		fromFailureId: `fail:runtime:${signature.slice(0, 8)}:1`,
		signature,
		scope: "test-scope",
		action: "rerun",
		repairAction: "rerun",
		commands: ["re_proof_loop run test-target 4 2"],
		expectedArtifacts: [],
		expectedChecks: ["verifier_matrix_ready"],
		preconditions: { liveAllowed: false, providerAllowed: false, requiredSecrets: [] },
		paused: false,
		allowlist: [],
		rollbackCriteria: { baseline: "none", mustRestore: [], verificationCommand: "re_proof_loop run test-target 4 2" },
		blockedConditions: [],
		evidenceWriteback: {
			failureLedgerPath: runtimeFailureLedgerPath(),
			repairQueuePath: runtimeRepairQueuePath(),
			appendOnly: true,
			mode: "runtime",
		},
		regressionChecks: ["verifier_matrix_ready"],
	};
}

describe("runtime failure/repair ledger corrupt-row guards (opt #51)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-fail-guard-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
		// Runtime state is lazy; the shared writer creates each ledger's parent on first use.
		ensureRepiStorage();
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("drops failure rows that parse but miss structurally-required fields, keeping valid rows", () => {
		const valid = makeFailure("sig-valid", 1);
		// Each corrupt line below PARSES as JSON and would have passed the old
		// `row?.signature && row?.id` check, but is missing a field the consumer calls a
		// method on (ts / budget / failedChecks) — exactly the corrupt/old-schema shape.
		const corruptMissingTs = JSON.stringify({
			id: "fail:corrupt:1",
			signature: "sig-no-ts",
			attempt: 1,
			maxAttempts: 3,
			status: "repair_queued",
			budget: { retryKey: "k", remainingAttempts: 2, exhaustedAction: "x" },
			failedChecks: [],
		});
		const corruptMissingBudget = JSON.stringify({
			id: "fail:corrupt:2",
			signature: "sig-no-budget",
			ts: "2026-06-29T00:00:00Z",
			attempt: 1,
			maxAttempts: 3,
			status: "repair_queued",
			failedChecks: [],
		});
		const corruptMissingFailedChecks = JSON.stringify({
			id: "fail:corrupt:3",
			signature: "sig-no-checks",
			ts: "2026-06-29T00:00:00Z",
			attempt: 1,
			maxAttempts: 3,
			status: "repair_queued",
			budget: { retryKey: "k", remainingAttempts: 2, exhaustedAction: "x" },
		});
		// A line that doesn't even parse is still dropped (unchanged behavior).
		const unparseable = "{not json";

		writePrivateTextFile(
			runtimeFailureLedgerPath(),
			`${[corruptMissingTs, corruptMissingBudget, corruptMissingFailedChecks, JSON.stringify(valid), unparseable].join("\n")}\n`,
		);

		const rows = readRuntimeFailureLedgerRows();
		expect(rows).toHaveLength(1);
		expect(rows[0].id).toBe(valid.id);
	});

	it("drops repair rows that parse but miss commands/expectedChecks, keeping valid rows", () => {
		const valid = makeRepair("sig-valid");
		const corruptMissingCommands = JSON.stringify({
			repairId: "r1",
			signature: "sig-no-cmds",
			action: "retry",
			paused: false,
			expectedChecks: [],
		});
		const corruptMissingExpectedChecks = JSON.stringify({
			repairId: "r2",
			signature: "sig-no-checks",
			action: "retry",
			paused: false,
			commands: [],
		});
		const corruptMissingPaused = JSON.stringify({
			repairId: "r3",
			signature: "sig-no-paused",
			action: "retry",
			commands: [],
			expectedChecks: [],
		});

		writePrivateTextFile(
			runtimeRepairQueuePath(),
			`${[corruptMissingCommands, corruptMissingExpectedChecks, corruptMissingPaused, JSON.stringify(valid)].join("\n")}\n`,
		);

		const rows = readRuntimeRepairQueueRows();
		expect(rows).toHaveLength(1);
		expect(rows[0].repairId).toBe(valid.repairId);
	});

	it("failureSignaturePriorityReport does not throw when the ledger contains corrupt rows", () => {
		const valid = makeFailure("sig-valid", 2);
		const corruptMissingTs = JSON.stringify({
			id: "fail:corrupt:1",
			signature: "sig-no-ts",
			attempt: 1,
			maxAttempts: 3,
			status: "repair_queued",
			budget: { retryKey: "k", remainingAttempts: 2, exhaustedAction: "x" },
			failedChecks: [],
		});
		const corruptMissingBudget = JSON.stringify({
			id: "fail:corrupt:2",
			signature: "sig-no-budget",
			ts: "2026-06-29T00:00:00Z",
			attempt: 1,
			maxAttempts: 3,
			status: "repair_queued",
			failedChecks: [],
		});

		writePrivateTextFile(
			runtimeFailureLedgerPath(),
			`${[corruptMissingTs, corruptMissingBudget, JSON.stringify(valid)].join("\n")}\n`,
		);
		// A valid repair referencing the valid failure's signature so the repair-queue map
		// path is exercised too.
		writePrivateTextFile(runtimeRepairQueuePath(), `${JSON.stringify(makeRepair("sig-valid"))}\n`);

		// Must not throw — the corrupt rows are dropped at the read boundary, so the sort's
		// `right.ts.localeCompare(...)` and `left.budget.remainingAttempts` never see undefined.
		let report: ReturnType<typeof failureSignaturePriorityReport> | undefined;
		expect(() => {
			report = failureSignaturePriorityReport();
		}).not.toThrow();

		// The valid row surfaces in the priority report.
		expect(report?.rows.some((row) => row.includes(`signature=${valid.signature.slice(0, 16)}`))).toBe(true);
		expect(report?.repairQueue.some((row) => row.includes("failure_signature_repair_queue"))).toBe(true);
	});
});

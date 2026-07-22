import { describe, expect, it } from "vitest";
import {
	verifyRemoteProviderLongRunV1,
	verifyRepairRollbackPolicyV1,
} from "../src/core/repi/provider-worker-runtime.ts";
import { verifyRepairRollbackPolicyV1 as verifyCompat } from "../src/core/repi/worker-runtime.ts";

const validRollback = () => ({
	kind: "RepairRollbackPolicyV1" as const,
	schemaVersion: 1 as const,
	baseline: { treeSha256: "a".repeat(64), files: [{ path: "artifact.json" }] },
	allowlist: ["artifact.json"],
	repair: { changedFiles: ["artifact.json"] },
	rollback: { required: true, restored: true, restoredTreeSha256: "a".repeat(64) },
	regression: {
		after: "pass",
		restored: "pass",
		checkpoints: [{ checkId: "check", status: "pass" }],
	},
	failureLedgerEvents: [{ id: "failure" }],
	repairQueue: [{ action: "rollback", rollbackCriteria: { mustRestore: ["artifact.json"] } }],
	failureRepairValidation: { ok: true },
	assertions: {
		baselineCaptured: true,
		allowlistEnforced: true,
		rollbackRestored: true,
		regressionChecksPassed: true,
		noUnrelatedFileChanges: true,
		failureRepairLinked: true,
	},
});

describe("provider worker runtime boundary", () => {
	it("keeps rollback validation available through the compatibility worker module", () => {
		const report = validRollback();
		expect(verifyRepairRollbackPolicyV1(report).ok).toBe(true);
		expect(verifyCompat(report).ok).toBe(true);
		expect(verifyRepairRollbackPolicyV1({ ...report, repair: { changedFiles: ["unlisted.ts"] } }).errors).toContain(
			"repair_rollback_allowlist_violation:unlisted.ts",
		);
	});

	it("accepts an explicitly skipped remote probe without pretending it ran", () => {
		expect(
			verifyRemoteProviderLongRunV1({
				kind: "RemoteProviderLongRunV1",
				mode: "skipped",
				skipReason: "no provider credentials in offline CI",
				attemptsPlanned: 0,
				listModels: { status: "skipped" },
				cases: [],
				failureLedgerEvents: [],
				repairQueue: [],
				failureRepairValidation: { ok: true },
				writebackProbe: { status: "skipped", validation: { ok: true } },
			}).ok,
		).toBe(true);
	});
});

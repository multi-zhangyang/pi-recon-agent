import { basename } from "node:path";
import { describe, expect, it } from "vitest";
import {
	swarmArtifactPath,
	swarmClaimLedgerPath,
	swarmStructuredClaimMergePath,
	swarmSubagentRuntimeManifestIndexPath,
	swarmSubagentSessionRoot,
	swarmWorkerChildSessionRuntimePath,
	swarmWorkerLeaseSchedulerPath,
	swarmWorkerRetryHandoffClosurePath,
	swarmWorkerRetryHandoffMergeSummaryPath,
} from "../src/core/repi/swarm-artifact-paths.ts";

const swarm = {
	artifactId: "8f1c5e20-d5f0-4a10-9483-cb26c4a2e10c",
	timestamp: "2026-07-19T13:30:45.123Z",
	route: "web auth/z",
	mode: "run" as const,
};

describe("swarm artifact paths", () => {
	it("builds one stable canonical base name", () => {
		expect(basename(swarmArtifactPath(swarm))).toBe(
			"2026-07-19T13-30-45-123Z-web-auth-z-run-8f1c5e20d5f04a109483cb26.md",
		);
	});

	it("does not collide for runs created in the same millisecond", () => {
		const other = { ...swarm, artifactId: "a7f834f2-b1d3-49d5-ab88-8516f4949c7a" };
		expect(swarmArtifactPath(other)).not.toBe(swarmArtifactPath(swarm));
	});

	it.each([
		[swarmClaimLedgerPath, "-claim-ledger.jsonl"],
		[swarmStructuredClaimMergePath, "-structured-claim-merge.json"],
		[swarmSubagentRuntimeManifestIndexPath, "-subagent-runtime-manifests.json"],
		[swarmWorkerChildSessionRuntimePath, "-worker-child-session-runtime.json"],
		[swarmWorkerRetryHandoffClosurePath, "-worker-retry-handoff-closure.json"],
		[swarmWorkerRetryHandoffMergeSummaryPath, "-worker-retry-handoff-merge-summary.json"],
		[swarmWorkerLeaseSchedulerPath, "-worker-lease-scheduler.json"],
		[swarmSubagentSessionRoot, "-sessions"],
	] as const)("derives %s from the canonical path", (pathFor, suffix) => {
		expect(pathFor(swarm)).toBe(swarmArtifactPath(swarm).replace(/\.md$/, suffix));
	});
});

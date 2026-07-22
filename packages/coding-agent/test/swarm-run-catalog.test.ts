import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { discoverSwarmRuns } from "../../../scripts/reverse-agent/lib/swarm-run-catalog.mjs";

describe("swarm run catalog status derivation", () => {
	let root: string;
	let cliRoot: string;
	let tsRoot: string;

	beforeEach(() => {
		root = mkdtempSync(join(tmpdir(), "repi-swarm-catalog-"));
		cliRoot = join(root, "cli");
		tsRoot = join(root, "ts");
		mkdirSync(cliRoot, { recursive: true });
		mkdirSync(tsRoot, { recursive: true });
	});

	afterEach(() => {
		rmSync(root, { recursive: true, force: true });
	});

	function writeCliRun(runId: string, artifacts: { plan?: object; report?: object; merge?: object }): void {
		const runRoot = join(cliRoot, runId);
		mkdirSync(runRoot, { recursive: true });
		if (artifacts.plan) writeFileSync(join(runRoot, "plan.json"), JSON.stringify(artifacts.plan));
		if (artifacts.report) writeFileSync(join(runRoot, "report.json"), JSON.stringify(artifacts.report));
		if (artifacts.merge) writeFileSync(join(runRoot, "merge-report.json"), JSON.stringify(artifacts.merge));
	}

	function writeTsRun(runId: string, artifact: object): void {
		writeFileSync(
			join(tsRoot, `${runId}.md`),
			`# REPI Swarm Artifact\n\n\`\`\`json\n${JSON.stringify(artifact, null, 2)}\n\`\`\`\n`,
		);
	}

	it("treats a failed CLI merge as authoritative over a successful run report", () => {
		const runId = "2026-07-20T01-02-03-004Z-merge-failed";
		writeCliRun(runId, {
			plan: {
				kind: "repi-swarm-plan-report",
				generatedAt: "2026-07-20T01:02:03.004Z",
				runId,
				target: "catalog-target",
				workers: 1,
			},
			report: {
				kind: "repi-swarm-run-report",
				generatedAt: "2026-07-20T01:02:04.000Z",
				runId,
				target: "catalog-target",
				workers: 1,
				ok: true,
			},
			merge: {
				kind: "repi-swarm-merge-report",
				generatedAt: "2026-07-20T01:02:05.000Z",
				runId,
				target: "catalog-target",
				workerCount: 1,
				ok: false,
			},
		});

		expect(discoverSwarmRuns({ cliRoot, tsRoot })).toContainEqual(
			expect.objectContaining({ engine: "cli", runId, state: "failed", status: "failed", ok: false, mode: "run" }),
		);
	});

	it("fails closed when a TS run has no passing structured claim merge", () => {
		const runId = "2026-07-20T02-03-04-005Z-missing-merge";
		writeTsRun(runId, {
			timestamp: "2026-07-20T02:03:04.005Z",
			route: "web-api",
			target: "missing-merge-target",
			mode: "run",
			workers: [{ id: "worker-1", worker: "web-authz", status: "done" }],
			executions: [{ workerId: "worker-1", status: "done", exitCode: 0, elapsedMs: 3 }],
			blocked: [],
			structuredClaimMergeStatus: "missing",
		});

		const run = discoverSwarmRuns({ cliRoot, tsRoot })[0];
		expect(run).toMatchObject({ engine: "ts", runId, state: "failed", ok: false });
		expect(run.merge).toMatchObject({ ok: false, structuredClaimMergeStatus: "missing" });
	});

	it("rejects a claimed TS merge pass when its structured payload is absent", () => {
		const runId = "2026-07-20T02-03-04-006Z-invalid-merge-pass";
		writeTsRun(runId, {
			timestamp: "2026-07-20T02:03:04.006Z",
			route: "web-api",
			target: "invalid-merge-target",
			mode: "run",
			workers: [{ id: "worker-1", worker: "web-authz", status: "done" }],
			executions: [{ workerId: "worker-1", status: "done", exitCode: 0, elapsedMs: 3 }],
			blocked: [],
			structuredClaimMergeStatus: "pass",
		});

		const run = discoverSwarmRuns({ cliRoot, tsRoot })[0];
		expect(run).toMatchObject({ engine: "ts", runId, state: "failed", ok: false });
		expect(run.merge).toMatchObject({ ok: false, structuredClaimMergeStatus: "pass" });
	});

	it("uses the latest retry attempt instead of a stale historical block", () => {
		const runId = "2026-07-20T03-04-05-006Z-retry-recovered";
		writeTsRun(runId, {
			timestamp: "2026-07-20T03:04:05.006Z",
			route: "native-pwn",
			target: "retry-target",
			mode: "run",
			workers: [{ id: "worker-1", worker: "pwn-exploit", status: "blocked" }],
			executions: [
				{ workerId: "worker-1", status: "blocked", retryAttempt: 1, exitCode: 1, elapsedMs: 5 },
				{ workerId: "worker-1", status: "done", retryAttempt: 2, exitCode: 0, elapsedMs: 7 },
			],
			blocked: ["worker-1 stale attempt-1 failure"],
			structuredClaimMergeStatus: "pass",
			structuredClaimMerge: { promotionCheck: { finalClaims: [{ claimId: "proof-1" }] } },
		});

		const run = discoverSwarmRuns({ cliRoot, tsRoot })[0];
		expect(run).toMatchObject({ engine: "ts", runId, state: "complete", ok: true });
		expect(run.workers).toEqual([expect.objectContaining({ workerId: "worker-1", status: "pass", exit: 0, ms: 12 })]);
		expect(run.merge).toMatchObject({ ok: true, structuredClaimMergeStatus: "pass" });
	});
});

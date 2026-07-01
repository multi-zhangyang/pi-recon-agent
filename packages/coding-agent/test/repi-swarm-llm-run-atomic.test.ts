import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SWARM = fileURLToPath(new URL("../../../scripts/reverse-agent/repi-swarm-llm-run.mjs", import.meta.url));

const FAKE_REPI = `#!/usr/bin/env node
console.log(JSON.stringify({
	workerId: "worker-1",
	role: "mapper",
	claims: [{
		id: "claim-1",
		statement: "ret2win primitive is reachable",
		evidence: ["checksec: NX enabled, no PIE", "poc.py exits 0"],
		confidence: 0.9,
		blockers: []
	}],
	artifacts: ["poc.py"],
	blockers: [],
	nextCommands: ["python3 poc.py"]
}));
`;

function collectTmp(root: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		const path = join(root, entry.name);
		if (entry.name.endsWith(".tmp")) out.push(path);
		if (entry.isDirectory()) out.push(...collectTmp(path));
	}
	return out;
}

describe("repi-swarm-llm-run evidence artifact writes", () => {
	let tempRoot: string;
	let fakeRoot: string;
	let agentDir: string;
	let workspace: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-swarm-atomic-"));
		fakeRoot = join(tempRoot, "repo");
		agentDir = join(tempRoot, "agent");
		workspace = join(tempRoot, "workspace");
		mkdirSync(fakeRoot, { recursive: true });
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(workspace, { recursive: true });
		const fakeRepiPath = join(fakeRoot, "repi");
		writeFileSync(fakeRepiPath, FAKE_REPI);
		chmodSync(fakeRepiPath, 0o755);
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	it("writes plan/report/worker/merge artifacts atomically with private mode", () => {
		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"run",
				"./vuln",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--cwd",
				workspace,
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			evidenceRoot: string;
			merge: { promotedClaims: unknown[] };
		};
		expect(report.ok).toBe(true);
		expect(report.merge.promotedClaims.length).toBe(1);

		for (const name of [
			"plan.json",
			"report.json",
			"merge-report.json",
			"worker-1.stdout.txt",
			"worker-1.stderr.txt",
		]) {
			const path = join(report.evidenceRoot, name);
			expect(existsSync(path), `${name} exists`).toBe(true);
			expect(statSync(path).mode & 0o777, `${name} is private`).toBe(0o600);
		}
		expect(readFileSync(join(report.evidenceRoot, "worker-1.stdout.txt"), "utf8")).toContain("ret2win primitive");
		expect(JSON.parse(readFileSync(join(report.evidenceRoot, "merge-report.json"), "utf8")).finalPromotionReady).toBe(
			true,
		);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("honors --max-concurrency in llm-run mode instead of forcing workers-wide fanout", () => {
		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"llm-run",
				"local-selfcheck",
				"--workers",
				"3",
				"--max-concurrency",
				"1",
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			workers: number;
			maxConcurrency: number;
			workersReport: unknown[];
			plan: { maxConcurrency: number };
		};
		expect(report.ok).toBe(true);
		expect(report.workers).toBe(3);
		expect(report.workersReport).toHaveLength(3);
		expect(report.maxConcurrency).toBe(1);
		expect(report.plan.maxConcurrency).toBe(1);
	});

	it("does not mistake flag values for the swarm target", () => {
		const withTarget = spawnSync(
			process.execPath,
			[SWARM, fakeRoot, "plan", "--workers", "2", "--max-concurrency", "1", "./vuln", "--json"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(withTarget.status, `${withTarget.stderr}\n${withTarget.stdout}`).toBe(0);
		expect(
			(JSON.parse(withTarget.stdout) as { plan: { target: string; maxConcurrency: number } }).plan,
		).toMatchObject({
			target: "./vuln",
			maxConcurrency: 1,
		});

		const defaultTarget = spawnSync(process.execPath, [SWARM, fakeRoot, "plan", "--workers", "2", "--json"], {
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: agentDir,
			},
			timeout: 10_000,
		});
		expect(defaultTarget.status, `${defaultTarget.stderr}\n${defaultTarget.stdout}`).toBe(0);
		expect((JSON.parse(defaultTarget.stdout) as { plan: { target: string } }).plan.target).toBe("local-selfcheck");
	});

	it("reports worker profile preparation failures as structured worker failures", () => {
		mkdirSync(join(agentDir, "models.json"));

		const result = spawnSync(
			process.execPath,
			[
				SWARM,
				fakeRoot,
				"llm-run",
				"local-selfcheck",
				"--workers",
				"1",
				"--max-concurrency",
				"1",
				"--timeout-ms",
				"5000",
				"--json",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);

		expect(result.status).toBe(1);
		expect(result.stderr).not.toContain("Error:");
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			workersReport: Array<{ status: string; stderrTail: string }>;
		};
		expect(report.ok).toBe(false);
		expect(report.workersReport).toHaveLength(1);
		expect(report.workersReport[0].status).toBe("fail");
		expect(report.workersReport[0].stderrTail).toMatch(/EISDIR|illegal operation on a directory/i);
	});
});

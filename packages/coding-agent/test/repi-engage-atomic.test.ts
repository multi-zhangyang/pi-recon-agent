import { spawnSync } from "node:child_process";
import {
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

const ENGAGE = fileURLToPath(new URL("../../../scripts/reverse-agent/repi-engage.mjs", import.meta.url));

function collectTmp(root: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		const path = join(root, entry.name);
		if (entry.name.endsWith(".tmp")) out.push(path);
		if (entry.isDirectory()) out.push(...collectTmp(path));
	}
	return out;
}

describe("repi-engage artifact writes", () => {
	let tempRoot: string;
	let agentDir: string;
	let workspace: string;
	let target: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-engage-atomic-"));
		agentDir = join(tempRoot, "agent");
		workspace = join(tempRoot, "workspace");
		target = join(workspace, "sample.bin");
		mkdirSync(workspace, { recursive: true });
		writeFileSync(target, "REPI engage sample\n");
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	function runEngage() {
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, target, "--no-mission", "--json", "--timeout-ms", "5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		return JSON.parse(result.stdout) as { artifactDir: string; summary: { passed: number } };
	}

	it("rewrites latest.json by temp+rename and keeps engagement artifacts private", () => {
		const first = runEngage();
		expect(first.summary.passed).toBeGreaterThan(0);
		const latestPath = join(agentDir, "recon", "evidence", "engagements", "latest.json");
		const firstLatestInode = statSync(latestPath).ino;

		const second = runEngage();
		const secondLatestInode = statSync(latestPath).ino;
		if (firstLatestInode !== 0 && secondLatestInode !== 0) expect(secondLatestInode).not.toBe(firstLatestInode);

		for (const [name, mode] of [
			["commands.jsonl", 0o600],
			["report.json", 0o600],
			["summary.md", 0o600],
			["next-commands.sh", 0o700],
		] as const) {
			const path = join(second.artifactDir, name);
			expect(existsSync(path), `${name} exists`).toBe(true);
			expect(statSync(path).mode & 0o777, `${name} mode`).toBe(mode);
		}
		expect(JSON.parse(readFileSync(latestPath, "utf8")).artifactDir).toBe(second.artifactDir);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("does not consume the target after boolean flags", () => {
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, "--json", target, "--no-mission", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as { target: { redacted: string; kind: string; pathExists: boolean } };
		expect(report.target.redacted).toBe(target);
		expect(report.target.kind).toBe("file");
		expect(report.target.pathExists).toBe(true);
	});

	it("--no-write avoids persistent URL artifacts", () => {
		if (spawnSync("bash", ["-lc", "command -v curl >/dev/null 2>&1"]).status !== 0) return;
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, "http://127.0.0.1:9/", "--no-mission", "--no-write", "--json", "--timeout-ms=1000"],
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
		const report = JSON.parse(result.stdout) as { target: { kind: string }; commands: Array<{ id: string }> };
		expect(report.target.kind).toBe("url");
		expect(report.commands.map((row) => row.id)).toContain("http-get-sample");
		expect(existsSync(agentDir)).toBe(false);
	});
});

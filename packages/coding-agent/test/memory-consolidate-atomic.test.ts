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
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const CONSOLIDATE = fileURLToPath(new URL("../../../scripts/reverse-agent/memory-consolidate.mjs", import.meta.url));

function encodeCwdForScope(cwd: string): string {
	const resolvedCwd = resolve(cwd);
	return `--${resolvedCwd.replace(/^[/\\]/, "").replace(/[/\\:]/g, "-")}--`;
}

function collectTmp(root: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		const path = join(root, entry.name);
		if (entry.name.endsWith(".tmp")) out.push(path);
		if (entry.isDirectory()) out.push(...collectTmp(path));
	}
	return out;
}

describe("memory-consolidate.mjs atomic scoped writes", () => {
	let tempRoot: string;
	let agentDir: string;
	let workspace: string;
	let memoryDir: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-consolidate-"));
		agentDir = join(tempRoot, "agent");
		workspace = join(tempRoot, "workspace");
		memoryDir = join(agentDir, "recon", "memory", "projects", encodeCwdForScope(workspace));
		mkdirSync(memoryDir, { recursive: true });
		writeFileSync(
			join(memoryDir, "events.jsonl"),
			`${JSON.stringify({
				kind: "repi-memory-event",
				id: "evt-1",
				ts: "2026-07-01T00:00:00.000Z",
				route: "native-pwn",
				target: "./vuln",
				outcome: "success",
				commands: ["checksec --file ./vuln", "python3 exploit.py"],
				reuseRules: ["Probe mitigations before picking the exploit lane."],
				lessons: ["NX + no PIE should route to ret2win before ROP sprawl."],
				quality: { confidence: 0.8, replayVerified: true },
			})}\n`,
		);
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	function runConsolidate() {
		const result = spawnSync(process.execPath, [CONSOLIDATE, workspace, "--cwd", workspace, "--json"], {
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: agentDir,
			},
			timeout: 10_000,
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		return JSON.parse(result.stdout) as {
			selectedCount: number;
			projectMemoryPath: string;
			proceduralMemoryPath: string;
		};
	}

	it("writes scoped project/procedural/report files by temp+rename with private mode", () => {
		const first = runConsolidate();
		expect(first.selectedCount).toBe(1);
		expect(first.projectMemoryPath).toBe(join(memoryDir, "project-memory.md"));
		expect(first.proceduralMemoryPath).toBe(join(memoryDir, "procedural-memory.md"));
		const projectPath = join(memoryDir, "project-memory.md");
		const proceduralPath = join(memoryDir, "procedural-memory.md");
		const reportPath = join(memoryDir, "consolidation-report.json");
		chmodSync(projectPath, 0o600);
		chmodSync(proceduralPath, 0o600);
		chmodSync(reportPath, 0o600);
		const projectInode = statSync(projectPath).ino;
		const proceduralInode = statSync(proceduralPath).ino;
		const reportInode = statSync(reportPath).ino;

		runConsolidate();

		const nextProjectInode = statSync(projectPath).ino;
		const nextProceduralInode = statSync(proceduralPath).ino;
		const nextReportInode = statSync(reportPath).ino;
		if (projectInode !== 0 && nextProjectInode !== 0) expect(nextProjectInode).not.toBe(projectInode);
		if (proceduralInode !== 0 && nextProceduralInode !== 0) expect(nextProceduralInode).not.toBe(proceduralInode);
		if (reportInode !== 0 && nextReportInode !== 0) expect(nextReportInode).not.toBe(reportInode);
		expect(statSync(projectPath).mode & 0o777).toBe(0o600);
		expect(statSync(proceduralPath).mode & 0o777).toBe(0o600);
		expect(statSync(reportPath).mode & 0o777).toBe(0o600);
		expect(readFileSync(projectPath, "utf8")).toContain("checksec --file ./vuln");
		expect(readFileSync(proceduralPath, "utf8")).toContain("Probe mitigations before picking the exploit lane.");
		expect(JSON.parse(readFileSync(reportPath, "utf8")).selectedCount).toBe(1);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("dry-run does not create consolidation artifacts", () => {
		const result = spawnSync(process.execPath, [CONSOLIDATE, workspace, "--cwd", workspace, "--dry-run", "--json"], {
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: agentDir,
			},
			timeout: 10_000,
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(JSON.parse(result.stdout).dryRun).toBe(true);
		expect(existsSync(join(memoryDir, "project-memory.md"))).toBe(false);
		expect(existsSync(join(memoryDir, "procedural-memory.md"))).toBe(false);
		expect(existsSync(join(memoryDir, "consolidation-report.json"))).toBe(false);
	});

	it("accepts --cwd=<dir> and does not fall back to the global memory root", () => {
		const result = spawnSync(process.execPath, [CONSOLIDATE, workspace, `--cwd=${workspace}`, "--json"], {
			encoding: "utf8",
			env: {
				...process.env,
				REPI_CODING_AGENT_DIR: agentDir,
			},
			timeout: 10_000,
		});

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			selectedCount: number;
			projectMemoryPath: string;
			proceduralMemoryPath: string;
		};
		expect(report.selectedCount).toBe(1);
		expect(report.projectMemoryPath).toBe(join(memoryDir, "project-memory.md"));
		expect(report.proceduralMemoryPath).toBe(join(memoryDir, "procedural-memory.md"));
		expect(existsSync(join(agentDir, "recon", "memory", "project-memory.md"))).toBe(false);
	});
});

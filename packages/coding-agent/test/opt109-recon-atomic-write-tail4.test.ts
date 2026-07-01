import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import {
	evidenceContextsDir,
	evidenceKernelDir,
	evidenceSupervisorsDir,
	memoryPath,
} from "../src/core/repi/storage.ts";

// opt #109: fourth tail pass of the repi atomic-write audit. Prior opts
// (#43/#67/#103/#106/#107/#108) routed most bare-writeFileSync(..., "utf-8")
// REPI state writers through writePrivateTextFile (atomic temp+rename, 0o600).
// This pass converts 5 remaining sites in recon-profile.ts whose output is LATER
// read via readText (show action / JSON.parse(readText(path))) so a crash-torn
// write silently degrades state:
//   writeContextPackArtifact    → evidence/contexts/<ts>.md      (NEW file: mode 0o600)
//   writeKernelArtifact          → evidence/kernel/<ts>.md       (NEW file: mode 0o600)
//                              + memory/execution-kernel.md     (REWRITE-same-path: inode-change)
//   writeSupervisorArtifact      → evidence/supervisors/<ts>.md  (NEW file: mode 0o600)
//                              + memory/commander-merge-board.md (REWRITE-same-path: inode-change)
//   writeSwarmArtifact (run)     → memory/swarm-run-board.md     (REWRITE-same-path: inode-change)
//   writeSwarmArtifact (merge)   → memory/swarm-board.md         (REWRITE-same-path: inode-change)
// Drives re_context pack ×2, re_kernel build ×2, re_supervisor review ×2,
// re_swarm run ×2, re_swarm merge ×2 via the fakePi harness and probes:
// inode-change on the rewrite-same-path boards (atomic temp+rename swaps the
// inode; truncate-then-write keeps it) AND mode 0o600 on the new timestamped
// artifacts (bare writeFileSync yields 0o644 under default umask) AND no .tmp
// leftover in any involved directory.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const testTimeout = 30_000;

type RegisteredTool = {
	name: string;
	execute: (toolCallId: string, params: Record<string, unknown>) => Promise<unknown>;
};

function reconMemoryDir(): string {
	return dirname(memoryPath("x"));
}

function latestMarkdown(dir: string): string | undefined {
	const files = readdirSync(dir)
		.filter((f) => f.endsWith(".md"))
		.sort();
	return files.length ? files[files.length - 1] : undefined;
}

function noTmpLeftover(dir: string): void {
	expect(
		readdirSync(dir).filter((f) => f.endsWith(".tmp")),
		`no .tmp leftover in ${dir}`,
	).toEqual([]);
}

describe("recon-profile atomic writes tail4 (opt #109)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt109-recon-"));
		const agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		prevAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (prevAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = prevAgentDir;
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
	});

	function registerTools(): Map<string, RegisteredTool> {
		const tools = new Map<string, RegisteredTool>();
		const fakePi = {
			registerCommand() {},
			registerTool(tool: RegisteredTool) {
				tools.set(tool.name, tool);
			},
			on() {},
			appendEntry() {},
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage() {},
			exec: async () => ({ code: 0, stdout: "", stderr: "", killed: false }),
		} as unknown as ExtensionAPI;
		createReconExtensionFactory()(fakePi);
		return tools;
	}

	it(
		"re_context pack ×2 writes the context-pack artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_context");
			expect(tool, "re_context tool registered").toBeDefined();

			const contextsDir = evidenceContextsDir();
			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("ctx-1", { action: "pack" });

			const artifactAfter1 = latestMarkdown(contextsDir);
			expect(artifactAfter1, "context-pack artifact written (1st)").toBeDefined();
			expect(
				statSync(join(contextsDir, artifactAfter1!)).mode & 0o777,
				"context-pack artifact mode 0o600 (1st)",
			).toBe(0o600);

			// Distinct millisecond so the second artifact gets a fresh timestamp filename.
			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("ctx-2", { action: "pack" });

			const artifactAfter2 = latestMarkdown(contextsDir);
			expect(artifactAfter2, "context-pack artifact written (2nd)").toBeDefined();
			expect(
				statSync(join(contextsDir, artifactAfter2!)).mode & 0o777,
				"context-pack artifact mode 0o600 (2nd)",
			).toBe(0o600);

			noTmpLeftover(contextsDir);
			noTmpLeftover(memDir);
		},
		testTimeout,
	);

	it(
		"re_kernel build ×2 writes the kernel artifact (0o600) + rewrites execution-kernel.md atomically (inode-change, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_kernel");
			expect(tool, "re_kernel tool registered").toBeDefined();

			const kernelDir = evidenceKernelDir();
			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("k-1", { action: "build" });

			const boardAfter1 = statSync(memoryPath("execution-kernel.md")).ino;

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("k-2", { action: "build" });

			const boardAfter2 = statSync(memoryPath("execution-kernel.md")).ino;

			// execution-kernel.md rewritten via atomic temp+rename → inode changes.
			expect(boardAfter2, "execution-kernel.md inode changed between builds").not.toBe(boardAfter1);

			// kernel artifact: the latest kernel artifact .md is a NEW file written via
			// writePrivateTextFile → mode 0o600 (bare writeFileSync would be 0o644).
			const kernelArtifact = latestMarkdown(kernelDir);
			expect(kernelArtifact, "kernel artifact written").toBeDefined();
			expect(statSync(join(kernelDir, kernelArtifact!)).mode & 0o777, "kernel artifact mode 0o600").toBe(0o600);

			noTmpLeftover(kernelDir);
			noTmpLeftover(memDir);
		},
		testTimeout,
	);

	it(
		"re_supervisor review ×2 writes the supervisor artifact (0o600) + rewrites commander-merge-board.md atomically (inode-change, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_supervisor");
			expect(tool, "re_supervisor tool registered").toBeDefined();

			const supervisorsDir = evidenceSupervisorsDir();
			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("sv-1", { action: "review" });

			const boardAfter1 = statSync(memoryPath("commander-merge-board.md")).ino;

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("sv-2", { action: "review" });

			const boardAfter2 = statSync(memoryPath("commander-merge-board.md")).ino;

			// commander-merge-board.md rewritten via atomic temp+rename → inode changes.
			expect(boardAfter2, "commander-merge-board.md inode changed between reviews").not.toBe(boardAfter1);

			// supervisor artifact: the latest supervisor artifact .md is a NEW file
			// written via writePrivateTextFile → mode 0o600.
			const supervisorArtifact = latestMarkdown(supervisorsDir);
			expect(supervisorArtifact, "supervisor artifact written").toBeDefined();
			expect(
				statSync(join(supervisorsDir, supervisorArtifact!)).mode & 0o777,
				"supervisor artifact mode 0o600",
			).toBe(0o600);

			noTmpLeftover(supervisorsDir);
			noTmpLeftover(memDir);
		},
		testTimeout,
	);

	it(
		"re_swarm run ×2 rewrites swarm-run-board.md atomically (inode-change, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_swarm");
			expect(tool, "re_swarm tool registered").toBeDefined();

			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("sw-run-1", { action: "run", maxWorkers: 1, maxCommands: 1 });

			const boardAfter1 = statSync(memoryPath("swarm-run-board.md")).ino;

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("sw-run-2", { action: "run", maxWorkers: 1, maxCommands: 1 });

			const boardAfter2 = statSync(memoryPath("swarm-run-board.md")).ino;

			// swarm-run-board.md rewritten via atomic temp+rename → inode changes.
			expect(boardAfter2, "swarm-run-board.md inode changed between runs").not.toBe(boardAfter1);

			noTmpLeftover(memDir);
		},
		testTimeout,
	);

	it(
		"re_swarm merge ×2 rewrites swarm-board.md atomically (inode-change, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_swarm");
			expect(tool, "re_swarm tool registered").toBeDefined();

			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("sw-merge-1", { action: "merge" });

			const boardAfter1 = statSync(memoryPath("swarm-board.md")).ino;

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("sw-merge-2", { action: "merge" });

			const boardAfter2 = statSync(memoryPath("swarm-board.md")).ino;

			// swarm-board.md rewritten via atomic temp+rename → inode changes.
			expect(boardAfter2, "swarm-board.md inode changed between merges").not.toBe(boardAfter1);

			noTmpLeftover(memDir);
		},
		testTimeout,
	);
});

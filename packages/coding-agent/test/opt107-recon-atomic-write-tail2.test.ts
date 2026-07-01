import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import {
	evidenceKnowledgeDir,
	evidenceOperatorsDir,
	memoryPath,
	memoryPlaybooksDir,
} from "../src/core/repi/storage.ts";

// opt #107: the repi atomic-write audit found 5 bare-writeFileSync(..., "utf-8")
// sites in recon-profile.ts that were routed through writePrivateTextFile (atomic
// temp+rename, 0o600 — the #43/#103 primitive):
//   1A writeDispatcherFeedbackBoard  → memory/dispatcher-feedback-board.md   (REWRITE-same-path: inode-change)
//   1B writeDispatcherPromotionPlaybook → memory/dispatcher-promotion-playbook.md (REWRITE-same-path: inode-change)
//   1C writeKnowledgeGraphArtifact   → evidence/knowledge/<ts>.md (NEW file: mode 0o600)
//                                   + memory/knowledge-graph-index.md (REWRITE-same-path: inode-change)
//   operator writeOperatorArtifact   → evidence/operators/<ts>.md (NEW file: mode 0o600)
// This test drives re_knowledge_graph build ×2 and re_operator plan ×2 via the
// fakePi harness and probes: inode-change on the rewrite-same-path files (atomic
// temp+rename swaps the inode; truncate-then-write keeps it) AND mode 0o600 on the
// new timestamped artifacts (bare writeFileSync yields 0o644 under default umask)
// AND no .tmp leftover in any involved directory.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

vi.setConfig({ testTimeout: 30_000 });

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

describe("recon-profile atomic writes tail2 (opt #107)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt107-recon-"));
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

	it("re_knowledge_graph build ×2 writes the artifact (0o600) + rewrites the index and promotion playbook atomically (inode-change, no .tmp)", async () => {
		const tools = registerTools();
		const tool = tools.get("re_knowledge_graph");
		expect(tool, "re_knowledge_graph tool registered").toBeDefined();

		const kgDir = evidenceKnowledgeDir();
		const memDir = reconMemoryDir();
		const playbookDir = memoryPlaybooksDir();

		await (tool as RegisteredTool).execute("kg-1", { action: "build" });

		const indexAfter1 = statSync(memoryPath("knowledge-graph-index.md")).ino;
		const playbookAfter1 = statSync(memoryPath("dispatcher-promotion-playbook.md")).ino;

		// Distinct millisecond so the second artifact gets a fresh timestamp filename.
		await new Promise((resolve) => setTimeout(resolve, 5));

		await (tool as RegisteredTool).execute("kg-2", { action: "build" });

		const indexAfter2 = statSync(memoryPath("knowledge-graph-index.md")).ino;
		const playbookAfter2 = statSync(memoryPath("dispatcher-promotion-playbook.md")).ino;

		// 1C-index: knowledge-graph-index.md rewritten via atomic temp+rename → inode changes.
		expect(indexAfter2, "knowledge-graph-index.md inode changed between builds").not.toBe(indexAfter1);

		// 1B: dispatcher-promotion-playbook.md rewritten via atomic temp+rename → inode changes.
		expect(playbookAfter2, "dispatcher-promotion-playbook.md inode changed between builds").not.toBe(playbookAfter1);

		// 1C-artifact: the latest knowledge-graph artifact .md is a NEW file written via
		// writePrivateTextFile → mode 0o600 (bare writeFileSync would be 0o644).
		const kgArtifact = latestMarkdown(kgDir);
		expect(kgArtifact, "knowledge-graph artifact written").toBeDefined();
		expect(statSync(join(kgDir, kgArtifact!)).mode & 0o777, "knowledge-graph artifact mode 0o600").toBe(0o600);

		// No .tmp leftover in the knowledge evidence dir, the recon memory dir, or the playbooks dir.
		noTmpLeftover(kgDir);
		noTmpLeftover(memDir);
		noTmpLeftover(playbookDir);
	});

	it("re_operator plan ×2 writes the operator artifact (0o600) + rewrites the dispatcher feedback board atomically (inode-change, no .tmp)", async () => {
		const tools = registerTools();
		const tool = tools.get("re_operator");
		expect(tool, "re_operator tool registered").toBeDefined();

		const opsDir = evidenceOperatorsDir();
		const memDir = reconMemoryDir();
		const playbookDir = memoryPlaybooksDir();

		await (tool as RegisteredTool).execute("op-1", { action: "plan" });

		const boardAfter1 = statSync(memoryPath("dispatcher-feedback-board.md")).ino;

		await new Promise((resolve) => setTimeout(resolve, 5));

		await (tool as RegisteredTool).execute("op-2", { action: "plan" });

		const boardAfter2 = statSync(memoryPath("dispatcher-feedback-board.md")).ino;

		// 1A: dispatcher-feedback-board.md rewritten via atomic temp+rename → inode changes.
		expect(boardAfter2, "dispatcher-feedback-board.md inode changed between builds").not.toBe(boardAfter1);

		// operator-artifact @22454: the latest operator artifact .md is a NEW file written via
		// writePrivateTextFile → mode 0o600 (bare writeFileSync would be 0o644).
		const opArtifact = latestMarkdown(opsDir);
		expect(opArtifact, "operator artifact written").toBeDefined();
		expect(statSync(join(opsDir, opArtifact!)).mode & 0o777, "operator artifact mode 0o600").toBe(0o600);

		// No .tmp leftover in the operators evidence dir, the recon memory dir, or the playbooks dir.
		noTmpLeftover(opsDir);
		noTmpLeftover(memDir);
		noTmpLeftover(playbookDir);
	});
});

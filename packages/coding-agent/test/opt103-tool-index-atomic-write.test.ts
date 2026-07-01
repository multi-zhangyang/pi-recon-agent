import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import { memoryPlaybooksDir, toolIndexPath } from "../src/core/repi/storage.ts";

// opt #103: refreshToolIndex and the playbook memory index were written via a
// bare writeFileSync (truncate-then-write) on crash-critical REPI state that is
// read on recall/routing via readText() — which swallows parse failure → "" — so
// a crash mid-write silently degraded the tool posture / playbook recall to
// empty. Both sites now route through writePrivateTextFile (atomic temp+rename,
// 0o600). This test drives the real re_tool_index refresh handler with a mock
// pi.exec and asserts the on-disk write is atomic: the inode CHANGES on rewrite
// (temp+rename installs a new inode; the old truncate-then-write kept the same
// inode), mode 0o600, and no .tmp leftover. The inode-change assertion is the
// regression probe — it flips back if refreshToolIndex regresses to writeFileSync.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

vi.setConfig({ testTimeout: 30_000 });

type RegisteredTool = {
	name: string;
	execute: (toolCallId: string, params: Record<string, unknown>) => Promise<unknown>;
};

describe("re_tool_index refresh atomic write (opt #103)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt103-atomic-"));
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
			exec: async () => ({
				code: 0,
				stdout: "| gdb | yes | /usr/bin/gdb | 12.0 |",
				stderr: "",
				killed: false,
			}),
		} as unknown as ExtensionAPI;
		createReconExtensionFactory()(fakePi);
		return tools;
	}

	it("refresh writes the tool-index atomically (inode changes, 0o600, no .tmp leftover)", async () => {
		const tools = registerTools();
		const tool = tools.get("re_tool_index");
		expect(tool, "re_tool_index tool registered").toBeDefined();

		await (tool as RegisteredTool).execute("call-1", { action: "refresh" });

		const path = toolIndexPath();
		expect(existsSync(path), "tool-index written").toBe(true);
		expect(statSync(path).mode & 0o777).toBe(0o600);
		expect(readdirSync(dirname(path)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
		const inodeBefore = statSync(path).ino;

		// A second refresh rewrites via temp+rename → NEW inode. The old
		// truncate-then-write kept the SAME inode; this fails on regression.
		await (tool as RegisteredTool).execute("call-2", { action: "refresh" });
		const inodeAfter = statSync(path).ino;
		expect(inodeAfter).not.toBe(inodeBefore);
		expect(statSync(path).mode & 0o777).toBe(0o600);
		expect(readdirSync(dirname(path)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
	});
});

describe("re_memory playbooks reindex atomic write (opt #103)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt103-pb-"));
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

	it("playbook reindex writes index.md atomically (inode changes, 0o600, no .tmp leftover)", async () => {
		// Seed one active playbook so maintainPlaybooks() has something to rank
		// and rewrites the index. metadataValue reads `key: value` lines.
		const pbDir = memoryPlaybooksDir();
		mkdirSync(pbDir, { recursive: true });
		writeFileSync(
			join(pbDir, "2026-06-28T10-00-00-zig-zag-stack.md"),
			[
				"quality_score: 50",
				"route: recon",
				"requested_lane: native",
				"target: binary",
				"timestamp: 2026-06-28T10:00:00Z",
				"",
				"# Playbook: zig-zag stack",
				"body",
				"",
			].join("\n"),
			"utf-8",
		);

		const tools = registerTools();
		const tool = tools.get("re_memory");
		expect(tool, "re_memory tool registered").toBeDefined();

		await (tool as RegisteredTool).execute("call-1", { action: "playbooks" });

		const path = join(pbDir, "index.md");
		expect(existsSync(path), "playbook index written").toBe(true);
		expect(statSync(path).mode & 0o777).toBe(0o600);
		expect(readdirSync(pbDir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
		const inodeBefore = statSync(path).ino;

		// A second reindex rewrites via temp+rename → NEW inode. The old
		// truncate-then-write kept the SAME inode; this fails on regression.
		await (tool as RegisteredTool).execute("call-2", { action: "playbooks" });
		const inodeAfter = statSync(path).ino;
		expect(inodeAfter).not.toBe(inodeBefore);
		expect(statSync(path).mode & 0o777).toBe(0o600);
		expect(readdirSync(pbDir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
	});
});

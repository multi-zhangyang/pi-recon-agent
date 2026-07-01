import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import { evidenceReflectionsDir, memoryPlaybooksDir } from "../src/core/repi/storage.ts";

// opt #106: the repi audit found 8 bare-writeFileSync sites on REPI state read
// back via readText() (which swallows parse failure → "" so a torn write silently
// degrades). They were routed through writePrivateTextFile (atomic temp+rename,
// 0o600 — the #43/#103 primitive). This test drives re_reflect write, which
// triggers writeReflectionMemory (a playbook in memoryPlaybooksDir) AND
// writeReflectionArtifact (an artifact in evidenceReflectionsDir read back by
// buildReflectOutput "show"). The regression probe is mode 0o600 + no .tmp
// leftover: bare writeFileSync produces 0o644 (default umask) and these sites
// write NEW timestamped files per call (not rewrites), so the inode-change probe
// from #103 does not apply here — mode is the revert signal. Reverting either
// write to writeFileSync flips mode to 0o644 and fails the test.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

vi.setConfig({ testTimeout: 30_000 });

type RegisteredTool = {
	name: string;
	execute: (toolCallId: string, params: Record<string, unknown>) => Promise<unknown>;
};

describe("re_reflect write atomic artifacts (opt #106)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt106-reflect-"));
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

	it("re_reflect write writes the reflection playbook + artifact atomically (0o600, no .tmp leftover)", async () => {
		const tools = registerTools();
		const tool = tools.get("re_reflect");
		expect(tool, "re_reflect tool registered").toBeDefined();

		await (tool as RegisteredTool).execute("call-1", { action: "write", target: "binary" });

		const pbDir = memoryPlaybooksDir();
		const refDir = evidenceReflectionsDir();

		// A reflection playbook is written to memoryPlaybooksDir (supervisor-reflection).
		const playbook = readdirSync(pbDir).find((f) => f.endsWith(".md") && f !== "index.md");
		expect(playbook, "reflection playbook written").toBeDefined();
		const pbPath = join(pbDir, playbook!);
		expect(statSync(pbPath).mode & 0o777, "playbook mode 0o600").toBe(0o600);

		// A reflection artifact is written to evidenceReflectionsDir.
		const artifact = readdirSync(refDir).find((f) => f.endsWith(".md"));
		expect(artifact, "reflection artifact written").toBeDefined();
		const artPath = join(refDir, artifact!);
		expect(statSync(artPath).mode & 0o777, "artifact mode 0o600").toBe(0o600);

		// No .tmp leftover in either directory (atomic temp+rename cleans up).
		expect(readdirSync(pbDir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
		expect(readdirSync(refDir).filter((f) => f.endsWith(".tmp"))).toEqual([]);

		// Content survives and is parseable (readText round-trip).
		expect(existsSync(pbPath)).toBe(true);
		expect(existsSync(artPath)).toBe(true);
	});
});

import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import { evidenceCampaignsDir, evidenceGraphsDir, evidenceToolchainDir, memoryPath } from "../src/core/repi/storage.ts";

// opt #111: sixth tail pass of the repi atomic-write audit. Converts remaining
// bare-writeFileSync(..., "utf-8") REPI state writers in recon-profile.ts whose
// output is LATER read via readText (the "show" action of each tool reads its
// artifact via readText) so a crash-torn write silently degrades state:
//   writeAttackGraphArtifact              → evidence/graphs/<ts>.md (NEW: 0o600)
//   writeCampaignArtifact                 → evidence/campaigns/<ts>.md (NEW: 0o600)
//   writeProfessionalRuntimeBridgesArtifact → evidence/toolchain/<ts>.md (NEW: 0o600)
//   writeRuntimeAdapterExecutionArtifact    → evidence/toolchain/<ts>.md (NEW: 0o600)
//   writeToolchainDomainCapabilityArtifact  → evidence/toolchain/<ts>.md (NEW: 0o600)
//   writeDomainProofExitClosureArtifact     → evidence/toolchain/<ts>.md (NEW: 0o600)
// Drives re_graph build, re_campaign plan, re_runtime_bridge show,
// re_runtime_adapter show, re_toolchain_domain show, re_domain_proof_exit write
// ×2 each via the fakePi harness and probes mode 0o600 on the new timestamped
// artifacts (bare writeFileSync yields 0o644 under default umask) AND no .tmp
// leftover (atomic temp+rename cleans up the .tmp sibling).

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

describe("recon-profile atomic writes tail6 (opt #111)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt111-recon-"));
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
		"re_graph build ×2 writes the attack-graph artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_graph");
			expect(tool, "re_graph tool registered").toBeDefined();

			const graphsDir = evidenceGraphsDir();
			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("g-1", { action: "build" });

			const artifactAfter1 = latestMarkdown(graphsDir);
			expect(artifactAfter1, "attack-graph artifact written (1st)").toBeDefined();
			expect(statSync(join(graphsDir, artifactAfter1!)).mode & 0o777, "attack-graph artifact mode 0o600 (1st)").toBe(
				0o600,
			);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("g-2", { action: "build" });

			const artifactAfter2 = latestMarkdown(graphsDir);
			expect(artifactAfter2, "attack-graph artifact written (2nd)").toBeDefined();
			expect(statSync(join(graphsDir, artifactAfter2!)).mode & 0o777, "attack-graph artifact mode 0o600 (2nd)").toBe(
				0o600,
			);

			noTmpLeftover(graphsDir);
			noTmpLeftover(memDir);
		},
		testTimeout,
	);

	it(
		"re_campaign plan ×2 writes the campaign artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_campaign");
			expect(tool, "re_campaign tool registered").toBeDefined();

			const campaignsDir = evidenceCampaignsDir();
			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("c-1", { action: "plan" });

			const artifactAfter1 = latestMarkdown(campaignsDir);
			expect(artifactAfter1, "campaign artifact written (1st)").toBeDefined();
			expect(statSync(join(campaignsDir, artifactAfter1!)).mode & 0o777, "campaign artifact mode 0o600 (1st)").toBe(
				0o600,
			);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("c-2", { action: "plan" });

			const artifactAfter2 = latestMarkdown(campaignsDir);
			expect(artifactAfter2, "campaign artifact written (2nd)").toBeDefined();
			expect(statSync(join(campaignsDir, artifactAfter2!)).mode & 0o777, "campaign artifact mode 0o600 (2nd)").toBe(
				0o600,
			);

			noTmpLeftover(campaignsDir);
			noTmpLeftover(memDir);
		},
		testTimeout,
	);

	it(
		"re_runtime_bridge show ×2 writes the professional-runtime-bridges artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_runtime_bridge");
			expect(tool, "re_runtime_bridge tool registered").toBeDefined();

			const toolchainDir = evidenceToolchainDir();
			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("rb-1", { action: "show" });

			const artifactAfter1 = latestMarkdown(toolchainDir);
			expect(artifactAfter1, "runtime-bridges artifact written (1st)").toBeDefined();
			expect(
				statSync(join(toolchainDir, artifactAfter1!)).mode & 0o777,
				"runtime-bridges artifact mode 0o600 (1st)",
			).toBe(0o600);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("rb-2", { action: "show" });

			const artifactAfter2 = latestMarkdown(toolchainDir);
			expect(artifactAfter2, "runtime-bridges artifact written (2nd)").toBeDefined();
			expect(
				statSync(join(toolchainDir, artifactAfter2!)).mode & 0o777,
				"runtime-bridges artifact mode 0o600 (2nd)",
			).toBe(0o600);

			noTmpLeftover(toolchainDir);
			noTmpLeftover(memDir);
		},
		testTimeout,
	);

	it(
		"re_runtime_adapter show ×2 writes the runtime-adapter-execution artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_runtime_adapter");
			expect(tool, "re_runtime_adapter tool registered").toBeDefined();

			const toolchainDir = evidenceToolchainDir();
			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("ra-1", { action: "show" });

			const artifactAfter1 = latestMarkdown(toolchainDir);
			expect(artifactAfter1, "runtime-adapter artifact written (1st)").toBeDefined();
			expect(
				statSync(join(toolchainDir, artifactAfter1!)).mode & 0o777,
				"runtime-adapter artifact mode 0o600 (1st)",
			).toBe(0o600);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("ra-2", { action: "show" });

			const artifactAfter2 = latestMarkdown(toolchainDir);
			expect(artifactAfter2, "runtime-adapter artifact written (2nd)").toBeDefined();
			expect(
				statSync(join(toolchainDir, artifactAfter2!)).mode & 0o777,
				"runtime-adapter artifact mode 0o600 (2nd)",
			).toBe(0o600);

			noTmpLeftover(toolchainDir);
			noTmpLeftover(memDir);
		},
		testTimeout,
	);

	it(
		"re_toolchain_domain show ×2 writes the toolchain-domain-capability artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_toolchain_domain");
			expect(tool, "re_toolchain_domain tool registered").toBeDefined();

			const toolchainDir = evidenceToolchainDir();
			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("td-1", { action: "show" });

			const artifactAfter1 = latestMarkdown(toolchainDir);
			expect(artifactAfter1, "toolchain-domain artifact written (1st)").toBeDefined();
			expect(
				statSync(join(toolchainDir, artifactAfter1!)).mode & 0o777,
				"toolchain-domain artifact mode 0o600 (1st)",
			).toBe(0o600);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("td-2", { action: "show" });

			const artifactAfter2 = latestMarkdown(toolchainDir);
			expect(artifactAfter2, "toolchain-domain artifact written (2nd)").toBeDefined();
			expect(
				statSync(join(toolchainDir, artifactAfter2!)).mode & 0o777,
				"toolchain-domain artifact mode 0o600 (2nd)",
			).toBe(0o600);

			noTmpLeftover(toolchainDir);
			noTmpLeftover(memDir);
		},
		testTimeout,
	);

	it(
		"re_domain_proof_exit write ×2 writes the domain-proof-exit-closure artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_domain_proof_exit");
			expect(tool, "re_domain_proof_exit tool registered").toBeDefined();

			const toolchainDir = evidenceToolchainDir();
			const memDir = reconMemoryDir();

			await (tool as RegisteredTool).execute("dpe-1", { action: "write" });

			const artifactAfter1 = latestMarkdown(toolchainDir);
			expect(artifactAfter1, "domain-proof-exit artifact written (1st)").toBeDefined();
			expect(
				statSync(join(toolchainDir, artifactAfter1!)).mode & 0o777,
				"domain-proof-exit artifact mode 0o600 (1st)",
			).toBe(0o600);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("dpe-2", { action: "write" });

			const artifactAfter2 = latestMarkdown(toolchainDir);
			expect(artifactAfter2, "domain-proof-exit artifact written (2nd)").toBeDefined();
			expect(
				statSync(join(toolchainDir, artifactAfter2!)).mode & 0o777,
				"domain-proof-exit artifact mode 0o600 (2nd)",
			).toBe(0o600);

			noTmpLeftover(toolchainDir);
			noTmpLeftover(memDir);
		},
		testTimeout,
	);
});

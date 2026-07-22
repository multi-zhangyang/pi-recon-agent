import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import {
	evidenceCompilersDir,
	evidenceDecisionsDir,
	evidenceProfileCheckDir,
	evidenceVerifiersDir,
} from "../src/core/repi/storage.ts";

// opt #108: third tail pass of the repi atomic-write audit. Prior opts
// (#43/#67/#103/#106/#107) routed most bare-writeFileSync(..., "utf-8") REPI
// state writers through writePrivateTextFile (atomic temp+rename, 0o600). This
// pass converts 5 remaining sites in recon-profile.ts whose output is LATER read
// via readText (show action / JSON.parse(readText(path))) so a crash-torn write
// silently degrades state:
//   writeDecisionCoreArtifact  → evidence/decisions/<ts>.md  (NEW file: mode 0o600)
//   writeProfileCheckArtifact  → evidence/profile-check/<ts>.md (NEW file: mode 0o600)
//   writeVerifierArtifact      → evidence/verifiers/<ts>.md  (NEW file: mode 0o600)
//   writeCompilerArtifact      → evidence/compilers/<ts>.md  (NEW file: mode 0o600, JSON-parse read)
// Drives re_decision_core plan ×2, re_profile_check quick ×2, re_verifier check ×2,
// re_compiler draft ×2 via the fakePi harness and probes: inode-change on the
// mode 0o600 on the new timestamped artifacts (bare writeFileSync yields 0o644
// under default umask) and no .tmp leftovers in the artifact directories.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const testTimeout = 30_000;

type RegisteredTool = {
	name: string;
	execute: (toolCallId: string, params: Record<string, unknown>) => Promise<unknown>;
};

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

describe("recon-profile atomic writes tail3 (opt #108)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt108-recon-"));
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
		"re_decision_core plan ×2 writes private artifacts without temporary-file leftovers",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_decision_core");
			expect(tool, "re_decision_core tool registered").toBeDefined();

			const decisionsDir = evidenceDecisionsDir();
			await (tool as RegisteredTool).execute("dc-1", { action: "plan" });

			// Distinct millisecond so the second artifact gets a fresh timestamp filename.
			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("dc-2", { action: "plan" });

			// decision-core artifact: the latest decisions artifact .md is a NEW file
			// written via writePrivateTextFile → mode 0o600 (bare writeFileSync would be 0o644).
			const decisionArtifact = latestMarkdown(decisionsDir);
			expect(decisionArtifact, "decision-core artifact written").toBeDefined();
			expect(statSync(join(decisionsDir, decisionArtifact!)).mode & 0o777, "decision-core artifact mode 0o600").toBe(
				0o600,
			);

			noTmpLeftover(decisionsDir);
		},
		testTimeout,
	);

	it(
		"re_profile_check quick ×2 writes the profile-check artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_profile_check");
			expect(tool, "re_profile_check tool registered").toBeDefined();

			const profileCheckDir = evidenceProfileCheckDir();

			await (tool as RegisteredTool).execute("pc-1", { action: "quick" });

			const artifactAfter1 = latestMarkdown(profileCheckDir);
			expect(artifactAfter1, "profile-check artifact written (1st)").toBeDefined();
			expect(
				statSync(join(profileCheckDir, artifactAfter1!)).mode & 0o777,
				"profile-check artifact mode 0o600 (1st)",
			).toBe(0o600);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("pc-2", { action: "quick" });

			// Second call yields a new timestamped artifact file, also 0o600.
			const artifactAfter2 = latestMarkdown(profileCheckDir);
			expect(artifactAfter2, "profile-check artifact written (2nd)").toBeDefined();
			expect(
				statSync(join(profileCheckDir, artifactAfter2!)).mode & 0o777,
				"profile-check artifact mode 0o600 (2nd)",
			).toBe(0o600);

			noTmpLeftover(profileCheckDir);
		},
		testTimeout,
	);

	it(
		"re_verifier check ×2 writes the verifier artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_verifier");
			expect(tool, "re_verifier tool registered").toBeDefined();

			const verifiersDir = evidenceVerifiersDir();

			await (tool as RegisteredTool).execute("vr-1", { action: "check" });

			const artifactAfter1 = latestMarkdown(verifiersDir);
			expect(artifactAfter1, "verifier artifact written (1st)").toBeDefined();
			expect(statSync(join(verifiersDir, artifactAfter1!)).mode & 0o777, "verifier artifact mode 0o600 (1st)").toBe(
				0o600,
			);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("vr-2", { action: "check" });

			const artifactAfter2 = latestMarkdown(verifiersDir);
			expect(artifactAfter2, "verifier artifact written (2nd)").toBeDefined();
			expect(statSync(join(verifiersDir, artifactAfter2!)).mode & 0o777, "verifier artifact mode 0o600 (2nd)").toBe(
				0o600,
			);

			noTmpLeftover(verifiersDir);
		},
		testTimeout,
	);

	it(
		"re_compiler draft ×2 writes the compiler artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_compiler");
			expect(tool, "re_compiler tool registered").toBeDefined();

			const compilersDir = evidenceCompilersDir();

			await (tool as RegisteredTool).execute("cp-1", { action: "draft" });

			const artifactAfter1 = latestMarkdown(compilersDir);
			expect(artifactAfter1, "compiler artifact written (1st)").toBeDefined();
			expect(statSync(join(compilersDir, artifactAfter1!)).mode & 0o777, "compiler artifact mode 0o600 (1st)").toBe(
				0o600,
			);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("cp-2", { action: "draft" });

			const artifactAfter2 = latestMarkdown(compilersDir);
			expect(artifactAfter2, "compiler artifact written (2nd)").toBeDefined();
			expect(statSync(join(compilersDir, artifactAfter2!)).mode & 0o777, "compiler artifact mode 0o600 (2nd)").toBe(
				0o600,
			);

			noTmpLeftover(compilersDir);
		},
		testTimeout,
	);
});

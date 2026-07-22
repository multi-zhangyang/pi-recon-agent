import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import { evidenceAutofixDir, evidenceProofLoopsDir, evidenceReplayersDir } from "../src/core/repi/storage.ts";

// opt #110: fifth tail pass of the repi atomic-write audit. Converts remaining
// bare-writeFileSync(..., "utf-8") REPI state writers in recon-profile.ts whose
// output is later read via readText, so a crash-torn write silently degrades state:
//   writeReplayerArtifact             → evidence/replayers/<ts>.md (NEW: 0o600)
//   writeAutofixArtifact (1st + 2nd)  → evidence/autofix/<ts>.md  (NEW: 0o600;
//                                        2nd write rewrites same path in-call)
//   writeProofLoopArtifact            → evidence/proof-loops/<ts>.md (NEW: 0o600)
// Drives re_replayer plan ×2, re_autofix plan ×2, re_proof_loop plan ×2 via the
// fakePi harness and probes mode 0o600 on the new timestamped artifacts (bare
// writeFileSync yields 0o644 under default umask) and no .tmp leftovers.

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

describe("recon-profile atomic writes tail5 (opt #110)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt110-recon-"));
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
		"re_replayer plan ×2 writes the replayer artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_replayer");
			expect(tool, "re_replayer tool registered").toBeDefined();

			const replayersDir = evidenceReplayersDir();
			await (tool as RegisteredTool).execute("rep-1", { action: "plan" });

			const artifactAfter1 = latestMarkdown(replayersDir);
			expect(artifactAfter1, "replayer artifact written (1st)").toBeDefined();
			expect(statSync(join(replayersDir, artifactAfter1!)).mode & 0o777, "replayer artifact mode 0o600 (1st)").toBe(
				0o600,
			);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("rep-2", { action: "plan" });

			const artifactAfter2 = latestMarkdown(replayersDir);
			expect(artifactAfter2, "replayer artifact written (2nd)").toBeDefined();
			expect(statSync(join(replayersDir, artifactAfter2!)).mode & 0o777, "replayer artifact mode 0o600 (2nd)").toBe(
				0o600,
			);

			noTmpLeftover(replayersDir);
		},
		testTimeout,
	);

	it(
		"re_autofix plan ×2 writes the autofix artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_autofix");
			expect(tool, "re_autofix tool registered").toBeDefined();

			const autofixDir = evidenceAutofixDir();
			await (tool as RegisteredTool).execute("af-1", { action: "plan" });

			const artifactAfter1 = latestMarkdown(autofixDir);
			expect(artifactAfter1, "autofix artifact written (1st)").toBeDefined();
			expect(statSync(join(autofixDir, artifactAfter1!)).mode & 0o777, "autofix artifact mode 0o600 (1st)").toBe(
				0o600,
			);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("af-2", { action: "plan" });

			const artifactAfter2 = latestMarkdown(autofixDir);
			expect(artifactAfter2, "autofix artifact written (2nd)").toBeDefined();
			expect(statSync(join(autofixDir, artifactAfter2!)).mode & 0o777, "autofix artifact mode 0o600 (2nd)").toBe(
				0o600,
			);

			noTmpLeftover(autofixDir);
		},
		testTimeout,
	);

	it(
		"re_proof_loop plan ×2 writes the proof-loop artifact (0o600, no .tmp)",
		async () => {
			const tools = registerTools();
			const tool = tools.get("re_proof_loop");
			expect(tool, "re_proof_loop tool registered").toBeDefined();

			const proofLoopsDir = evidenceProofLoopsDir();
			await (tool as RegisteredTool).execute("pl-1", { action: "plan" });

			const artifactAfter1 = latestMarkdown(proofLoopsDir);
			expect(artifactAfter1, "proof-loop artifact written (1st)").toBeDefined();
			expect(
				statSync(join(proofLoopsDir, artifactAfter1!)).mode & 0o777,
				"proof-loop artifact mode 0o600 (1st)",
			).toBe(0o600);

			await new Promise((resolve) => setTimeout(resolve, 5));

			await (tool as RegisteredTool).execute("pl-2", { action: "plan" });

			const artifactAfter2 = latestMarkdown(proofLoopsDir);
			expect(artifactAfter2, "proof-loop artifact written (2nd)").toBeDefined();
			expect(
				statSync(join(proofLoopsDir, artifactAfter2!)).mode & 0o777,
				"proof-loop artifact mode 0o600 (2nd)",
			).toBe(0o600);

			noTmpLeftover(proofLoopsDir);
		},
		testTimeout,
	);
});

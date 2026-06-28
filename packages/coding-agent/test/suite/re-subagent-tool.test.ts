import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, fauxToolCall } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { BUILTIN_AGENT_THREAD_SPECS, createAgentThreadManager } from "../../src/core/agent-thread-manager.ts";
import { createReconExtensionFactory } from "../../src/core/recon-profile.ts";
import { createHarness, getMessageText, type Harness } from "./harness.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_AGENT_THREAD = "REPI_AGENT_THREAD";
const ENV_BIN_PATH = "REPI_BIN_PATH";

interface EnvSnapshot {
	agentDir: string | undefined;
	agentThread: string | undefined;
	binPath: string | undefined;
}

function snapshotEnv(): EnvSnapshot {
	return {
		agentDir: process.env[ENV_AGENT_DIR],
		agentThread: process.env[ENV_AGENT_THREAD],
		binPath: process.env[ENV_BIN_PATH],
	};
}

function restoreEnv(snapshot: EnvSnapshot): void {
	for (const [name, value] of Object.entries(snapshot) as Array<[keyof EnvSnapshot, string | undefined]>) {
		const envName = name === "agentDir" ? ENV_AGENT_DIR : name === "agentThread" ? ENV_AGENT_THREAD : ENV_BIN_PATH;
		if (value === undefined) {
			delete process.env[envName];
		} else {
			process.env[envName] = value;
		}
	}
}

function makeTempAgentDir(prefix: string): string {
	const dir = join(tmpdir(), `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	mkdirSync(dir, { recursive: true });
	return dir;
}

function writeStubBin(): string {
	const path = join(tmpdir(), `repi-stub-${Date.now()}-${Math.random().toString(36).slice(2)}.sh`);
	writeFileSync(
		path,
		"#!/bin/sh\n" +
			// Emulate a real reverser that writes its handoff to the file-based
			// handoff path (the reasoning-model-reliable path), then prints a short
			// stdout tail. mergeRun must surface the handoff file as ## Worker handoff.
			'if [ -n "$REPI_WORKER_HANDOFF_PATH" ]; then\n' +
			'  mkdir -p "$(dirname "$REPI_WORKER_HANDOFF_PATH")"\n' +
			"  cat > \"$REPI_WORKER_HANDOFF_PATH\" <<'HOEOF'\n" +
			"Outcome: claim verified\n" +
			"Key Evidence: readelf -lW shows PIE; offset 0x40 controlled\n" +
			"Verification: reproducible, 2 stable runs\n" +
			"Next Step: build ROP chain\n" +
			"Gaps: none\n" +
			"Artifacts: handoff.md\n" +
			"HOEOF\n" +
			"fi\n" +
			"printf 'VERIFIER_HANDOFF_PROOF: claim verified\\nfindings: ok\\n'\n" +
			"exit 0\n",
		"utf-8",
	);
	chmodSync(path, 0o755);
	return path;
}

function toolNames(harness: Harness): string[] {
	return harness.session.getAllTools().map((tool) => tool.name);
}

function getToolResultText(harness: Harness): string {
	for (const message of harness.session.messages) {
		if (message.role === "toolResult") {
			const text = getMessageText(message);
			if (text) return text;
		}
	}
	return "";
}

describe("re_subagent tool", () => {
	const harnesses: Harness[] = [];
	const tempDirs: string[] = [];
	let envSnapshot: EnvSnapshot;

	beforeEach(() => {
		envSnapshot = snapshotEnv();
	});

	afterEach(() => {
		while (harnesses.length > 0) {
			harnesses.pop()?.cleanup();
		}
		for (const dir of tempDirs) {
			if (dir && existsSync(dir)) {
				rmSync(dir, { recursive: true, force: true });
			}
		}
		restoreEnv(envSnapshot);
	});

	describe("AgentThreadManager primitives (no subprocess)", () => {
		it("exposes five builtin specialist specs", () => {
			expect(BUILTIN_AGENT_THREAD_SPECS).toHaveLength(5);
			expect(BUILTIN_AGENT_THREAD_SPECS.map((spec) => spec.name).sort()).toEqual([
				"explorer",
				"operator",
				"planner",
				"reverser",
				"verifier",
			]);
		});

		it("listSpecs/getSpec resolve known specs and reject unknown ones", () => {
			const agentDir = makeTempAgentDir("re-subagent-unit");
			tempDirs.push(agentDir);
			process.env[ENV_AGENT_DIR] = agentDir;
			const mgr = createAgentThreadManager({ cwd: agentDir });

			expect(mgr.listSpecs()).toHaveLength(5);
			expect(mgr.getSpec("reverser").name).toBe("reverser");
			expect(() => mgr.getSpec("bogus")).toThrow(/Unknown agent thread spec/);
		});

		it("reverser spec carries real RE doctrine, xhigh thinking, and script-authoring tools", () => {
			const reverser = BUILTIN_AGENT_THREAD_SPECS.find((spec) => spec.name === "reverser");
			expect(reverser).toBeDefined();
			expect(reverser?.thinkingLevel).toBe("xhigh");
			expect(reverser?.maxTurns).toBeGreaterThanOrEqual(10);
			expect(reverser?.tools).toContain("write");
			expect(reverser?.tools).toContain("edit");
			expect(reverser?.tools).toContain("bash");
			// Concrete RE methodology anchors (not a one-line placeholder).
			const prompt = reverser?.systemPrompt ?? "";
			expect(prompt.length).toBeGreaterThan(800);
			expect(prompt).toContain("checksec");
			expect(prompt).toContain("pdg");
			expect(prompt).toContain("ROPgadget");
			expect(prompt).toContain("pwntools");
			expect(prompt).toContain("angr");
			expect(prompt).toContain("binwalk");
			expect(prompt).toContain("volatility3");
			expect(prompt).toContain("falsifiable");
			// Phase 0 tool-availability doctrine + readelf fallback for tool-poor envs.
			expect(prompt).toContain("Phase 0");
			expect(prompt).toContain("Tool availability");
			expect(prompt).toContain("readelf");
			// Completion gate: forbid the "I can see it in disasm" shortcut and
			// require an executed PoC artifact + written handoff before stopping.
			expect(prompt).toContain("Completion gate");
			expect(prompt).toContain("Static analysis is triage");
		});

		it("every builtin spec has a non-trivial doctrine prompt and non-off thinking", () => {
			for (const spec of BUILTIN_AGENT_THREAD_SPECS) {
				expect(spec.systemPrompt.length).toBeGreaterThan(120);
				expect(spec.thinkingLevel).not.toBe("off");
			}
		});

		it("awaitRun rejects for an unknown run id", async () => {
			const agentDir = makeTempAgentDir("re-subagent-unit");
			tempDirs.push(agentDir);
			process.env[ENV_AGENT_DIR] = agentDir;
			const mgr = createAgentThreadManager({ cwd: agentDir });

			await expect(mgr.awaitRun("does-not-exist")).rejects.toThrow(/Unknown agent thread run/);
		});
	});

	describe("tool registration and recursion gate", () => {
		it("registers re_subagent in the main thread", async () => {
			const agentDir = makeTempAgentDir("re-subagent-register");
			tempDirs.push(agentDir);
			process.env[ENV_AGENT_DIR] = agentDir;
			delete process.env[ENV_AGENT_THREAD];

			const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
			harnesses.push(harness);
			await harness.session.bindExtensions({});

			expect(toolNames(harness)).toContain("re_subagent");
		});

		it("does not register re_subagent inside a worker thread (recursion gate)", async () => {
			const agentDir = makeTempAgentDir("re-subagent-worker");
			tempDirs.push(agentDir);
			process.env[ENV_AGENT_DIR] = agentDir;
			process.env[ENV_AGENT_THREAD] = "1";

			const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
			harnesses.push(harness);
			await harness.session.bindExtensions({});

			expect(toolNames(harness)).not.toContain("re_subagent");
		});
	});

	describe("end-to-end tool wiring via stub binary", () => {
		it("spawns, awaits, merges, and returns the worker handoff", async () => {
			const agentDir = makeTempAgentDir("re-subagent-e2e");
			tempDirs.push(agentDir);
			process.env[ENV_AGENT_DIR] = agentDir;
			delete process.env[ENV_AGENT_THREAD];
			const stubBin = writeStubBin();
			tempDirs.push(stubBin);
			process.env[ENV_BIN_PATH] = stubBin;

			const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
			harnesses.push(harness);
			harness.setResponses([
				fauxAssistantMessage(
					[
						fauxToolCall("re_subagent", {
							spec: "verifier",
							task: "verify the claim",
							inheritMcp: false,
							timeoutMs: 5000,
						}),
					],
					{ stopReason: "toolUse" },
				),
				fauxAssistantMessage("done"),
			]);

			await harness.session.prompt("verify it");

			const resultText = getToolResultText(harness);
			expect(resultText).toContain("VERIFIER_HANDOFF_PROOF");
			expect(resultText).toContain("status=complete");
			// File-based handoff: the stub wrote handoff.md to
			// $REPI_WORKER_HANDOFF_PATH; mergeRun must surface it as ## Worker handoff
			// so the parent recovers the work even when stdout text is thin.
			expect(resultText).toContain("## Worker handoff");
			expect(resultText).toContain("Outcome: claim verified");
			expect(resultText).toContain("Key Evidence: readelf -lW shows PIE");
			expect(resultText).toContain("handoff_path:");
		});
	});
});

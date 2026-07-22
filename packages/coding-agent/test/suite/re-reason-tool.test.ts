import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, fauxToolCall } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	createReconExtensionFactory,
	parsePlannerDecision,
	parseSupervisorCritique,
	swarmWorkerSpec,
} from "../../src/core/recon-profile.ts";
import { laneSpec, type MissionLane } from "../../src/core/repi/mission.ts";
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
	const path = join(tmpdir(), `repi-reason-stub-${Date.now()}-${Math.random().toString(36).slice(2)}.sh`);
	writeFileSync(
		path,
		"#!/bin/sh\n" +
			'if [ -n "$REPI_WORKER_HANDOFF_PATH" ]; then\n' +
			'  { printf \'run_id: %s\\nmission_id: %s\\nlineage_sha256: %s\\n\' "$REPI_WORKER_RUN_ID" "$REPI_WORKER_MISSION_ID" "$REPI_WORKER_LINEAGE_SHA256"; printf \'PLANNER_HANDOFF_PROOF: next_action=re_map; rationale=passive-first\\nfindings: ok\\n\'; } > "$REPI_WORKER_HANDOFF_PATH"\n' +
			"fi\n" +
			"printf 'PLANNER_HANDOFF_PROOF: next_action=re_map; rationale=passive-first\\nfindings: ok\\n'\nexit 0\n",
		"utf-8",
	);
	chmodSync(path, 0o755);
	return path;
}

function writeVerifierStubBin(): string {
	const path = join(tmpdir(), `repi-challenge-stub-${Date.now()}-${Math.random().toString(36).slice(2)}.sh`);
	writeFileSync(
		path,
		"#!/bin/sh\n" +
			'if [ -n "$REPI_WORKER_HANDOFF_PATH" ]; then\n' +
			'  { printf \'run_id: %s\\nmission_id: %s\\nlineage_sha256: %s\\n\' "$REPI_WORKER_RUN_ID" "$REPI_WORKER_MISSION_ID" "$REPI_WORKER_LINEAGE_SHA256"; printf \'verdict: proved\\nrepro: id; echo ok\\ncounter_evidence: none\\nnotes: stable repro\\n\'; } > "$REPI_WORKER_HANDOFF_PATH"\n' +
			"fi\n" +
			"printf 'verdict: proved\\nrepro: id; echo ok\\ncounter_evidence: none\\nnotes: stable repro\\n'\nexit 0\n",
		"utf-8",
	);
	chmodSync(path, 0o755);
	return path;
}

function writeSupervisorStubBin(): string {
	const path = join(tmpdir(), `repi-supervisor-stub-${Date.now()}-${Math.random().toString(36).slice(2)}.sh`);
	writeFileSync(
		path,
		"#!/bin/sh\n" +
			'if [ -n "$REPI_WORKER_HANDOFF_PATH" ]; then\n' +
			'  { printf \'run_id: %s\\nmission_id: %s\\nlineage_sha256: %s\\n\' "$REPI_WORKER_RUN_ID" "$REPI_WORKER_MISSION_ID" "$REPI_WORKER_LINEAGE_SHA256"; printf \'supervisor_verdict: repair\\ncritique: worker handoff attempted-as-proved without repro\\nrepair_queue: re_challenge claim, re_swarm run target 1 1\\nredispatch: spec=verifier; task=falsify flag leak claim\\nnotes: stable repro required before promotion\\n\'; } > "$REPI_WORKER_HANDOFF_PATH"\n' +
			"fi\n" +
			"printf 'supervisor_verdict: repair\\ncritique: worker handoff attempted-as-proved without repro\\nrepair_queue: re_challenge claim, re_swarm run target 1 1\\nredispatch: spec=verifier; task=falsify flag leak claim\\nnotes: stable repro required before promotion\\n'\nexit 0\n",
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

describe("parsePlannerDecision (llm step-planner parser)", () => {
	it("parses a well-formed planner verdict into a RunAutoDecision", () => {
		const decision = parsePlannerDecision(
			"action: continue_next\nnextLane: prove\nverdict: partial\nquality: 55\nreason: map done, advance to proof",
		);
		expect(decision.action).toBe("continue_next");
		expect(decision.nextLane).toBe("prove");
		expect(decision.verdict).toBe("partial");
		expect(decision.quality).toBe(55);
		expect(decision.reason).toBe("map done, advance to proof");
	});

	it("treats nextLane: none as undefined and tolerates missing optional fields", () => {
		const decision = parsePlannerDecision("action: stop\nnextLane: none");
		expect(decision.action).toBe("stop");
		expect(decision.nextLane).toBeUndefined();
		expect(decision.verdict).toBeUndefined();
		expect(decision.quality).toBeUndefined();
		expect(decision.reason).toContain("action=stop");
	});

	it("throws when the planner output has no action line", () => {
		expect(() => parsePlannerDecision("I think we should map more")).toThrow(/no action/);
	});
});

describe("swarmWorkerSpec (real swarm role→spec mapping)", () => {
	it("maps reverse/pwn/firmware/mobile/malware/dfir workers to reverser", () => {
		expect(swarmWorkerSpec("native-runtime")).toBe("reverser");
		expect(swarmWorkerSpec("pwn-exploit")).toBe("reverser");
		expect(swarmWorkerSpec("firmware-dfir")).toBe("reverser");
		expect(swarmWorkerSpec("mobile-runtime")).toBe("reverser");
		expect(swarmWorkerSpec("malware-triage")).toBe("reverser");
	});

	it("maps web/cloud/identity/mapping workers to explorer", () => {
		expect(swarmWorkerSpec("web-authz")).toBe("explorer");
		expect(swarmWorkerSpec("cloud-identity")).toBe("explorer");
		expect(swarmWorkerSpec("identity-ad-graph")).toBe("explorer");
		expect(swarmWorkerSpec("agentsec-boundary")).toBe("explorer");
	});

	it("maps audit/report workers to verifier and defaults to operator", () => {
		expect(swarmWorkerSpec("reporting-compile")).toBe("verifier");
		expect(swarmWorkerSpec("audit-verify")).toBe("verifier");
		expect(swarmWorkerSpec("general-operator")).toBe("operator");
	});
});

describe("laneSpec (lane→specialist mapping for opt-in specialist dispatch)", () => {
	const route = { domain: "Pwn / exploit", intent: "reverse", toolchain: "native", skillHint: "pwn", workflow: [] };
	const lane = (name: string, objective: string): MissionLane => ({ name, objective, next: [] });

	it("maps reverse/pwn/firmware/malware/native/mobile lanes to reverser", () => {
		expect(laneSpec(lane("mitigations", "确认保护与崩溃面"), route)).toBe("reverser");
		expect(laneSpec(lane("primitive", "prove controlled bytes"), route)).toBe("reverser");
		expect(laneSpec(lane("exploit", "build payload"), { ...route, domain: "Firmware / IoT" })).toBe("reverser");
		expect(laneSpec(lane("malware-triage", "decode config"), { ...route, domain: "Malware" })).toBe("reverser");
		expect(laneSpec(lane("native-disasm", "decompile handler"), { ...route, domain: "Native reverse" })).toBe(
			"reverser",
		);
	});

	it("maps verify/proof/report/audit lanes to verifier", () => {
		expect(laneSpec(lane("report", "沉淀证据"), route)).toBe("verifier");
		expect(laneSpec(lane("audit", "proof-exit audit"), route)).toBe("verifier");
		expect(laneSpec(lane("verify", "verify claim"), route)).toBe("verifier");
	});

	it("maps map/surface/recon/web/cloud lanes to explorer", () => {
		expect(laneSpec(lane("map", "passive surface"), { ...route, domain: "Web / API pentest" })).toBe("explorer");
		expect(laneSpec(lane("recon", "enumerate"), { ...route, domain: "Cloud" })).toBe("explorer");
	});

	it("returns undefined when no specialist owns the lane", () => {
		expect(laneSpec(lane("misc", "unrelated objective"), { ...route, domain: "General" })).toBeUndefined();
	});
});

describe("re_reason tool", () => {
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

	describe("tool registration and recursion gate", () => {
		it("registers re_reason in the main thread", async () => {
			const agentDir = makeTempAgentDir("re-reason-register");
			tempDirs.push(agentDir);
			process.env[ENV_AGENT_DIR] = agentDir;
			delete process.env[ENV_AGENT_THREAD];

			const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
			harnesses.push(harness);
			await harness.session.bindExtensions({});

			expect(toolNames(harness)).toContain("re_reason");
			expect(toolNames(harness)).toContain("re_challenge");
		});

		it("does not register re_reason inside a worker thread (recursion gate)", async () => {
			const agentDir = makeTempAgentDir("re-reason-worker");
			tempDirs.push(agentDir);
			process.env[ENV_AGENT_DIR] = agentDir;
			process.env[ENV_AGENT_THREAD] = "1";

			const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
			harnesses.push(harness);
			await harness.session.bindExtensions({});

			expect(toolNames(harness)).not.toContain("re_reason");
			expect(toolNames(harness)).not.toContain("re_challenge");
		});
	});

	describe("canvas mode (no subprocess)", () => {
		it("renders a Pentesting Task Tree snapshot and reasoning scaffold", async () => {
			const agentDir = makeTempAgentDir("re-reason-canvas");
			tempDirs.push(agentDir);
			process.env[ENV_AGENT_DIR] = agentDir;
			delete process.env[ENV_AGENT_THREAD];

			const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
			harnesses.push(harness);
			harness.setResponses([
				fauxAssistantMessage(
					[fauxToolCall("re_reason", { mode: "canvas", focus: "distinguish exploit vs benign crash" })],
					{ stopReason: "toolUse" },
				),
				fauxAssistantMessage("done"),
			]);

			await harness.session.prompt("pentest the target");

			const resultText = getToolResultText(harness);
			expect(resultText).toContain("Pentesting Task Tree (PTT) snapshot");
			expect(resultText).toContain("focus: distinguish exploit vs benign crash");
			expect(resultText).toContain("## root objective");
			expect(resultText).toContain("## attack graph");
			expect(resultText).toContain("## decision core");
			expect(resultText).toContain("## domain proof-exit closure");
			expect(resultText).toContain("## reasoning scaffold");
			expect(resultText).toContain("distinguishing_probe");
		});
	});

	describe("planner mode via stub binary", () => {
		it("dispatches a real planner subagent and returns its handoff", async () => {
			const agentDir = makeTempAgentDir("re-reason-planner");
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
					[fauxToolCall("re_reason", { mode: "planner", focus: "find initial access", timeoutMs: 5000 })],
					{ stopReason: "toolUse" },
				),
				fauxAssistantMessage("done"),
			]);

			await harness.session.prompt("plan the engagement");

			const resultText = getToolResultText(harness);
			expect(resultText).toContain("mode=planner");
			expect(resultText).toContain("PLANNER_HANDOFF_PROOF");
			expect(resultText).toContain("Pentesting Task Tree (PTT) snapshot");
		});
	});

	describe("re_challenge (adversarial verifier) via stub binary", () => {
		it("dispatches a real verifier subagent and normalizes the verdict", async () => {
			const agentDir = makeTempAgentDir("re-challenge-e2e");
			tempDirs.push(agentDir);
			process.env[ENV_AGENT_DIR] = agentDir;
			delete process.env[ENV_AGENT_THREAD];
			const stubBin = writeVerifierStubBin();
			tempDirs.push(stubBin);
			process.env[ENV_BIN_PATH] = stubBin;

			const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
			harnesses.push(harness);
			harness.setResponses([
				fauxAssistantMessage(
					[
						fauxToolCall("re_challenge", {
							claim: "the binary leaks the flag on a 40-byte overflow",
							reproCommand: "python3 exploit.py",
							timeoutMs: 5000,
						}),
					],
					{ stopReason: "toolUse" },
				),
				fauxAssistantMessage("done"),
			]);

			await harness.session.prompt("verify the exploit claim");

			const resultText = getToolResultText(harness);
			expect(resultText).toContain("spec=verifier");
			expect(resultText).toContain("verdict: proved");
			const ledger = readFileSync(join(agentDir, "recon", "evidence", "ledger.md"), "utf8");
			expect(ledger).toContain("challenge-proved");
			expect(ledger).toContain("Independent verifier verdict=proved");
			expect(ledger).toContain("domain runtime proof still required");
		});
	});

	describe("re_supervisor llm critique (adversarial supervisor) via stub binary", () => {
		it("parseSupervisorCritique extracts verdict and trims text", () => {
			const parsed = parseSupervisorCritique("supervisor_verdict: repair\ncritique: weak\ndesc: x".repeat(1));
			expect(parsed.verdict).toBe("repair");
			expect(parsed.text).toContain("critique: weak");
		});

		it("parseSupervisorCritique defaults to inconclusive when no verdict line", () => {
			const parsed = parseSupervisorCritique("just some notes with no verdict");
			expect(parsed.verdict).toBe("inconclusive");
		});

		it("dispatches a real verifier subagent and appends an llm_supervisor_critique section", async () => {
			const agentDir = makeTempAgentDir("re-supervisor-llm");
			tempDirs.push(agentDir);
			process.env[ENV_AGENT_DIR] = agentDir;
			delete process.env[ENV_AGENT_THREAD];
			const stubBin = writeSupervisorStubBin();
			tempDirs.push(stubBin);
			process.env[ENV_BIN_PATH] = stubBin;

			const harness = await createHarness({ extensionFactories: [createReconExtensionFactory()] });
			harnesses.push(harness);
			harness.setResponses([
				fauxAssistantMessage([fauxToolCall("re_supervisor", { action: "review", reasoning: "llm" })], {
					stopReason: "toolUse",
				}),
				fauxAssistantMessage("done"),
			]);

			await harness.session.prompt("supervise the workers");

			const resultText = getToolResultText(harness);
			expect(resultText).toContain("llm_supervisor_critique:");
			expect(resultText).toContain("spec=verifier");
			expect(resultText).toContain("supervisor_verdict: repair");
			expect(resultText).toContain("redispatch: spec=verifier");
		});
	});
});

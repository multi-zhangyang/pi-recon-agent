import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { readCurrentMission } from "../src/core/repi/mission.ts";
import { createRegisteredReconHarness } from "./recon-profile-harness.ts";

vi.setConfig({ testTimeout: 60_000 });

function readProofArtifactFromOutput(output: string): string {
	expect(output).toContain("proof_loop:");
	expect(output).toContain("next_proof_command:");
	expect(output).toContain("details: read ");
	expect(output).not.toContain("gap_classifier:");
	expect(output).not.toContain("specialist_queue:");
	expect(output.length).toBeLessThanOrEqual(4096);
	const path = /proof_loop_artifact: (.+)/.exec(output)?.[1]?.trim();
	expect(path).toBeDefined();
	return readFileSync(path!, "utf-8");
}

async function startMission(tools: Map<string, unknown>, task: string): Promise<void> {
	const missionTool = tools.get("re_mission") as {
		execute: (toolCallId: string, params: Record<string, unknown>) => Promise<unknown>;
	};
	await missionTool.execute("mission-new", { action: "new", task });
}

describe("REPI kernel profile proof-loop flow", () => {
	it("wires proof-loop gaps into a quick verifier/replayer/autofix path", async () => {
		const harness = createRegisteredReconHarness("repi-profile-proof-loop");
		try {
			await startMission(harness.tools, "audit https://target.local/app request order and runtime authorization");
			const proofLoopTool = harness.tools.get("re_proof_loop") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const runtimeAdapterTool = harness.tools.get("re_runtime_adapter") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const graphTool = harness.tools.get("re_graph") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			await runtimeAdapterTool.execute("tool-call-id", {
				action: "run",
				target: "https://target.local/app",
			});
			await graphTool.execute("tool-call-id", { action: "build" });
			const proof = await proofLoopTool.execute("tool-call-id", {
				action: "plan",
				target: "https://target.local/app",
			});
			const proofText = readProofArtifactFromOutput(proof.content[0]?.text ?? "");
			expect(proofText).toContain("gap_classifier:");
			expect(proofText).toContain("source=attack_graph");
			expect(proofText).toContain("class=runtime_adapter_gap");
			expect(proofText).toContain("class=missing_artifact");
			expect(proofText).toContain("quick_path:");
			expect(proofText).toContain("quick_plan_phases:");
			expect(proofText).toContain("runtime_adapter_before_replay=pass");
			expect(proofText).toContain("runtime_adapter_closure:");
			expect(proofText).toContain("re_runtime_adapter run web-cdp-network-adapter https://target.local/app");
			expect(proofText).toContain("re_verifier matrix https://target.local/app");
			expect(proofText).toContain("re_replayer run https://target.local/app 1");
			expect(proofText).toContain("re_autofix plan https://target.local/app");
			expect(proofText).toContain("source=attack_graph_gap");

			const proofRun = await proofLoopTool.execute("tool-call-id", {
				action: "run",
				target: "https://target.local/app",
				maxSteps: 1,
				replaySteps: 1,
			});
			const proofRunOutput = proofRun.content[0]?.text ?? "";
			expect(proofRunOutput).toContain("executed_steps: 1");
			const proofRunText = readProofArtifactFromOutput(proofRunOutput);
			expect(proofRunText).toContain("executed_steps: 1");
			expect(proofRunText).toContain(
				"quick_path_execution: index=1 phase=runtime-adapter command=re_runtime_adapter run web-cdp-network-adapter https://target.local/app",
			);
			const nextProofActions = /next_proof_actions:([\s\S]*?)source_artifacts:/m.exec(proofRunText)?.[1] ?? "";
			expect(nextProofActions).not.toContain(
				"re_runtime_adapter run web-cdp-network-adapter https://target.local/app",
			);

			const graph = await graphTool.execute("tool-call-id", { action: "build" });
			const graphPath = /graph_artifact: (.+)/.exec(graph.content[0]?.text ?? "")?.[1]?.trim();
			expect(graphPath).toBeDefined();
			const graphText = readFileSync(graphPath!, "utf-8");
			expect(graphText).toContain("proof_loop plan");
			expect(graphText).toContain("quick_path");
			expect(graphText).toContain("quick_plan_phases");
			expect(graphText).toContain("proof-loop-gap");
			expect(graphText).toContain("proof-loop-output-hash");
			expect(graphText).toContain("output_sha256");
			expect(graphText).toContain("re_runtime_adapter run web-cdp-network-adapter https://target.local/app");
			expect(graphText).toContain("runtime-adapter-lineage");
			expect(graphText).toContain("runtime-adapter-artifact");
			expect(graphText).toContain("runtime-adapter-closure");
		} finally {
			harness.restore();
		}
	});

	it("promotes attack-graph binary mitigation maps into the proof spine", async () => {
		const harness = createRegisteredReconHarness("repi-profile-proof-loop-mitigation");
		try {
			await startMission(harness.tools, "reverse native ELF ./vuln and prove its binary mitigations");
			const proofLoopTool = harness.tools.get("re_proof_loop") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const graphTool = harness.tools.get("re_graph") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const runtimeAdapterDir = join(
				harness.agentDir,
				"recon",
				"evidence",
				"toolchain",
				"runtime-adapters",
				"gdb-native-trace-adapter",
			);
			mkdirSync(runtimeAdapterDir, { recursive: true });
			writeFileSync(
				join(runtimeAdapterDir, "2026-01-01T00-00-00-000Z.json"),
				`${JSON.stringify(
					{
						kind: "RuntimeAdapterExecutionArtifactV1",
						schemaVersion: 1,
						missionId: readCurrentMission()?.id,
						adapterId: "gdb-native-trace-adapter",
						domainId: "rev-native",
						bridgeId: "tool-bridge-runtime",
						target: "./vuln",
						startedAt: new Date(0).toISOString(),
						finishedAt: new Date(0).toISOString(),
						selectedRunner: "fallback",
						command: "re_runtime_adapter run gdb-native-trace-adapter ./vuln",
						exitCode: 0,
						killed: false,
						stdoutSha256: "a".repeat(64),
						stderrSha256: "b".repeat(64),
						stdoutHead: "[native-mitigation] pie=yes nx=enabled relro=partial canary=no fortify=no type=DYN\n",
						stderrHead: "",
						parserSignals: [
							{
								ruleId: "parser-native-mitigation-map",
								evidenceRank: "runtime_artifact",
								proofExitSignal: "binary mitigation map",
								matches: ["[native-mitigation]", "PIE", "NX", "RELRO"],
							},
						],
						parserSignalSummary: {
							matchedRules: 1,
							totalRules: 1,
							matchCount: 4,
							evidenceRanks: ["runtime_artifact"],
							matchedProofExitSignals: ["binary mitigation map"],
							missingProofExitSignals: [],
						},
						artifactKinds: ["native-symbol-map", "binary-mitigation-map", "runtime-adapter-transcript"],
						ingestTargets: ["evidence-ledger"],
						proofExitSignals: ["binary mitigation map"],
					},
					null,
					2,
				)}\n`,
				"utf-8",
			);

			await graphTool.execute("tool-call-id", { action: "build" });
			const proof = await proofLoopTool.execute("tool-call-id", {
				action: "plan",
				target: "./vuln",
			});
			const text = readProofArtifactFromOutput(proof.content[0]?.text ?? "");
			expect(text).toContain("class=proof_spine_seed");
			expect(text).toContain("binary mitigation map matched");
			expect(text).toContain("phase=2:proof_spine");
			expect(text).toContain("re_verifier matrix ./vuln");
			expect(text).toContain("re_compiler draft ./vuln");
			expect(text).toContain("re_replayer run ./vuln 1");
		} finally {
			harness.restore();
		}
	});

	it("turns attack-graph parser summaries into exact runtime-adapter closure", async () => {
		const harness = createRegisteredReconHarness("repi-profile-proof-loop-parser-summary");
		try {
			await startMission(harness.tools, "audit opaque-web-target network request order");
			const proofLoopTool = harness.tools.get("re_proof_loop") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const graphTool = harness.tools.get("re_graph") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const runtimeAdapterDir = join(
				harness.agentDir,
				"recon",
				"evidence",
				"toolchain",
				"runtime-adapters",
				"web-cdp-network-adapter",
			);
			const runtimeArtifact = join(runtimeAdapterDir, "2026-01-01T00-00-00-000Z.json");
			mkdirSync(runtimeAdapterDir, { recursive: true });
			writeFileSync(
				runtimeArtifact,
				`${JSON.stringify(
					{
						kind: "RuntimeAdapterExecutionArtifactV1",
						schemaVersion: 1,
						missionId: readCurrentMission()?.id,
						adapterId: "web-cdp-network-adapter",
						domainId: "web-api",
						bridgeId: "tool-bridge-runtime",
						target: "opaque-web-target",
						startedAt: new Date(0).toISOString(),
						finishedAt: new Date(0).toISOString(),
						selectedRunner: "fallback",
						command: "re_runtime_adapter run web-cdp-network-adapter opaque-web-target",
						exitCode: 0,
						killed: false,
						stdoutSha256: "c".repeat(64),
						stderrSha256: "d".repeat(64),
						stdoutHead: "GET /api/me before GET /api/orders\n",
						stderrHead: "",
						parserSignals: [
							{
								ruleId: "parser-web-network-ledger",
								evidenceRank: "runtime_artifact",
								proofExitSignal: "network request ledger",
								matches: ["GET /api/me", "GET /api/orders"],
							},
							{
								ruleId: "parser-web-request-order",
								evidenceRank: "runtime_artifact",
								proofExitSignal: "request order proof",
								matches: [],
							},
						],
						parserSignalSummary: {
							matchedRules: 1,
							totalRules: 2,
							matchCount: 2,
							evidenceRanks: ["runtime_artifact"],
							matchedProofExitSignals: ["network request ledger"],
							missingProofExitSignals: ["request order proof"],
						},
						artifactKinds: ["web-network-ledger", "runtime-adapter-transcript"],
						ingestTargets: ["evidence-ledger"],
						proofExitSignals: ["network request ledger", "request order proof"],
					},
					null,
					2,
				)}\n`,
				"utf-8",
			);

			await graphTool.execute("tool-call-id", { action: "build" });
			const proof = await proofLoopTool.execute("tool-call-id", {
				action: "plan",
				target: "opaque-web-target",
			});
			const text = readProofArtifactFromOutput(proof.content[0]?.text ?? "");
			expect(text).toContain(
				"parser_signal_summary adapter=web-cdp-network-adapter matched=network request ledger missing=request order proof",
			);
			expect(text).toContain("runtime_adapter_closure:");
			expect(text).toContain("adapter=web-cdp-network-adapter status=needs_adapter_rerun");
			expect(text).toContain("missing=request order proof matched=network request ledger");
			expect(text).toContain("class=runtime_adapter_gap");
			expect(text).toContain("runtime adapter missing proof: web-cdp-network-adapter: request order proof");
			expect(text).toContain("re_runtime_adapter run web-cdp-network-adapter opaque-web-target");
			expect(text).toContain("runtime_adapter_before_replay=pass");
		} finally {
			harness.restore();
		}
	});

	it("uses complete parser summaries as proof-spine seeds instead of stale adapter gaps", async () => {
		const harness = createRegisteredReconHarness("repi-profile-proof-loop-parser-complete");
		try {
			await startMission(harness.tools, "audit opaque-web-target-complete network request order");
			const proofLoopTool = harness.tools.get("re_proof_loop") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const graphTool = harness.tools.get("re_graph") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const runtimeAdapterDir = join(
				harness.agentDir,
				"recon",
				"evidence",
				"toolchain",
				"runtime-adapters",
				"web-cdp-network-adapter",
			);
			mkdirSync(runtimeAdapterDir, { recursive: true });
			writeFileSync(
				join(runtimeAdapterDir, "2026-01-01T00-00-00-000Z.json"),
				`${JSON.stringify(
					{
						kind: "RuntimeAdapterExecutionArtifactV1",
						schemaVersion: 1,
						missionId: readCurrentMission()?.id,
						adapterId: "web-cdp-network-adapter",
						domainId: "web-api",
						bridgeId: "tool-bridge-runtime",
						target: "opaque-web-target-complete",
						startedAt: new Date(0).toISOString(),
						finishedAt: new Date(0).toISOString(),
						selectedRunner: "fallback",
						command: "re_runtime_adapter run web-cdp-network-adapter opaque-web-target-complete",
						exitCode: 0,
						killed: false,
						stdoutSha256: "e".repeat(64),
						stderrSha256: "f".repeat(64),
						stdoutHead: "GET /api/me before GET /api/orders\n",
						stderrHead: "",
						parserSignals: [
							{
								ruleId: "parser-web-network-ledger",
								evidenceRank: "runtime_artifact",
								proofExitSignal: "network request ledger",
								matches: ["GET /api/me", "GET /api/orders"],
							},
							{
								ruleId: "parser-web-request-order",
								evidenceRank: "runtime_artifact",
								proofExitSignal: "request order proof",
								matches: ["GET /api/me before GET /api/orders"],
							},
						],
						parserSignalSummary: {
							matchedRules: 2,
							totalRules: 2,
							matchCount: 3,
							evidenceRanks: ["runtime_artifact"],
							matchedProofExitSignals: ["network request ledger", "request order proof"],
							missingProofExitSignals: [],
						},
						artifactKinds: ["web-network-ledger", "runtime-adapter-transcript"],
						ingestTargets: ["evidence-ledger"],
						proofExitSignals: ["network request ledger", "request order proof"],
					},
					null,
					2,
				)}\n`,
				"utf-8",
			);

			await graphTool.execute("tool-call-id", { action: "build" });
			const proof = await proofLoopTool.execute("tool-call-id", {
				action: "plan",
				target: "opaque-web-target-complete",
			});
			const text = readProofArtifactFromOutput(proof.content[0]?.text ?? "");
			expect(text).toContain("class=proof_spine_seed");
			expect(text).toContain("runtime adapter proof-exit complete adapter=web-cdp-network-adapter");
			expect(text).toContain("adapter=web-cdp-network-adapter status=proof_spine_ready");
			expect(text).toContain("matched=network request ledger | request order proof");
			expect(text).toContain("re_verifier matrix opaque-web-target-complete");
			expect(text).toContain("re_compiler draft opaque-web-target-complete");
			expect(text).toContain("re_replayer run opaque-web-target-complete 1");
			expect(text).not.toContain(
				"parser_signal_summary adapter=web-cdp-network-adapter matched=network request ledger | request order proof missing=",
			);
		} finally {
			harness.restore();
		}
	});
});

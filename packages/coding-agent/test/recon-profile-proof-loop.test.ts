import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createRegisteredReconHarness } from "./recon-profile-harness.ts";

vi.setConfig({ testTimeout: 60_000 });

describe("REPI kernel profile proof-loop flow", () => {
	it("wires proof-loop gaps into a quick verifier/replayer/autofix path", async () => {
		const harness = createRegisteredReconHarness("repi-profile-proof-loop");
		try {
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
			expect(proof.content[0]?.text).toContain("gap_classifier:");
			expect(proof.content[0]?.text).toContain("source=attack_graph");
			expect(proof.content[0]?.text).toContain("class=runtime_adapter_gap");
			expect(proof.content[0]?.text).toContain("class=missing_artifact");
			expect(proof.content[0]?.text).toContain("quick_path:");
			expect(proof.content[0]?.text).toContain("quick_plan_phases:");
			expect(proof.content[0]?.text).toContain("runtime_adapter_before_replay=pass");
			expect(proof.content[0]?.text).toContain(
				"re_runtime_adapter run web-cdp-network-adapter https://target.local/app",
			);
			expect(proof.content[0]?.text).toContain("re_verifier matrix https://target.local/app");
			expect(proof.content[0]?.text).toContain("re_replayer run https://target.local/app 1");
			expect(proof.content[0]?.text).toContain("re_autofix plan https://target.local/app");
			expect(proof.content[0]?.text).toContain("source=attack_graph_gap");
			const caseMemoryPath = join(harness.agentDir, "recon", "memory", "case-memory.jsonl");
			expect(existsSync(caseMemoryPath) ? readFileSync(caseMemoryPath, "utf-8") : "").not.toContain(
				"proof_loop plan",
			);

			const proofRun = await proofLoopTool.execute("tool-call-id", {
				action: "run",
				target: "https://target.local/app",
				maxSteps: 1,
				replaySteps: 1,
			});
			const proofRunText = proofRun.content[0]?.text ?? "";
			expect(proofRunText).toContain("proof_loop:");
			expect(proofRunText).toContain("executed_steps: 1");
			expect(proofRunText).toContain(
				"quick_path_execution: index=1 phase=runtime-adapter command=re_runtime_adapter run web-cdp-network-adapter https://target.local/app",
			);
			expect(readFileSync(caseMemoryPath, "utf-8")).toContain("proof_loop run");
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
		} finally {
			harness.restore();
		}
	});

	it("promotes attack-graph binary mitigation maps into the proof spine", async () => {
		const harness = createRegisteredReconHarness("repi-profile-proof-loop-mitigation");
		try {
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
						ingestTargets: ["evidence-ledger", "knowledge-graph", "memory-event"],
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
			const text = proof.content[0]?.text ?? "";
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
});

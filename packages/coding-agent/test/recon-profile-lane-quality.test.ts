import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createRegisteredReconHarness } from "./recon-profile-harness.ts";

vi.setConfig({ testTimeout: 60_000 });

describe("REPI lane evidence quality", () => {
	it("scores weak lane evidence and queues self-healing follow-ups", async () => {
		const harness = createRegisteredReconHarness("repi-lane-quality", {
			exec: async () => ({ code: 0, stdout: "ok\n", stderr: "", killed: false }),
		});
		try {
			const missionTool = harness.tools.get("re_mission") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			await missionTool.execute("tool-call-id", { action: "new", task: "分析 ELF 许可证校验" });

			const laneTool = harness.tools.get("re_lane") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const weakRun = await laneTool.execute("tool-call-id", {
				action: "run",
				lane: "control-flow",
				target: "./license",
			});

			expect(harness.execCalls).toHaveLength(1);
			expect(weakRun.content[0]?.text).toContain("evidence_quality:");
			expect(weakRun.content[0]?.text).toContain("deficits:");
			expect(weakRun.content[0]?.text).toContain("self_heal_labels:");
			expect(weakRun.content[0]?.text).toContain("heal-native-baseline");
			const artifactPath = /evidence_artifact: (.+)/.exec(weakRun.content[0]?.text ?? "")?.[1]?.trim();
			expect(artifactPath).toBeDefined();
			expect(readFileSync(artifactPath!, "utf-8")).toContain("## Evidence critic");
			expect(readFileSync(artifactPath!, "utf-8")).toContain("## Self-heal commands");

			const missionAfterWeakRun = JSON.parse(
				readFileSync(join(harness.agentDir, "recon", "mission", "current.json"), "utf-8"),
			) as {
				lanes: Array<{ name: string; status?: string; next: string[] }>;
			};
			const controlFlowLane = missionAfterWeakRun.lanes.find((lane) => lane.name === "control-flow");
			expect(controlFlowLane?.status).toBe("in_progress");
			expect(controlFlowLane?.next.join("\n")).toContain("[auto:heal-native-baseline]");

			const adaptiveAuto = await laneTool.execute("tool-call-id", {
				action: "run-auto",
				lane: "control-flow",
				target: "./license",
				max: 1,
			});
			expect(harness.execCalls).toHaveLength(2);
			expect(harness.execCalls[1]?.args.join(" ")).toContain("license|serial|key");
			expect(adaptiveAuto.content[0]?.text).toContain("run_auto_summary:");
			expect(adaptiveAuto.content[0]?.text).toContain("adaptive_decisions: 1");
			expect(adaptiveAuto.content[0]?.text).toContain("adaptive_decision:");
			expect(adaptiveAuto.content[0]?.text).toContain("reason: partial_evidence_self_heal:control-flow");
			expect(adaptiveAuto.content[0]?.text).toContain(
				"stop_reason: max_steps_reached_after:partial_evidence_self_heal:control-flow",
			);
		} finally {
			harness.restore();
		}
	});

	it("does not treat source text containing error phrases as a runtime failure", async () => {
		const harness = createRegisteredReconHarness("repi-lane-error-text", {
			exec: async () => ({
				code: 0,
				stdout: 'packages/example.ts: const note = "command not found";\n',
				stderr: "",
				killed: false,
			}),
		});
		try {
			const missionTool = harness.tools.get("re_mission") as {
				execute: (toolCallId: string, params: Record<string, unknown>) => Promise<unknown>;
			};
			await missionTool.execute("tool-call-id", {
				action: "new",
				task: "audit prompt injection across an Agent/LLM tool boundary",
			});
			const laneTool = harness.tools.get("re_lane") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const run = await laneTool.execute("tool-call-id", {
				action: "run",
				lane: "surface",
				target: ".",
			});
			const text = run.content[0]?.text ?? "";
			expect(text).not.toContain("tool/target/runtime error surfaced");
			expect(text).not.toContain("tool-repair-matrix-scaffold");
		} finally {
			harness.restore();
		}
	});
});

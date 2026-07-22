import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import { readCurrentMission, writeCurrentMission } from "../src/core/repi/mission.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_BRANCH_ID = "REPI_BRANCH_ID";

describe("REPI kernel profile self-heal and specialist routing", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousBranchId: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-profile-specialist-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		previousBranchId = process.env[ENV_BRANCH_ID];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) {
			delete process.env[ENV_AGENT_DIR];
		} else {
			process.env[ENV_AGENT_DIR] = previousAgentDir;
		}
		if (previousBranchId === undefined) {
			delete process.env[ENV_BRANCH_ID];
		} else {
			process.env[ENV_BRANCH_ID] = previousBranchId;
		}
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("turns tool/runtime failures into repair matrix follow-ups", async () => {
		const tools = new Map<string, unknown>();
		const execCalls: Array<{ command: string; args: string[] }> = [];
		const fakePi = {
			registerCommand() {},
			registerTool(tool: { name: string }) {
				tools.set(tool.name, tool);
			},
			on() {},
			appendEntry() {},
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage() {},
			exec: async (command: string, args: string[]) => {
				execCalls.push({ command, args });
				return {
					code: 127,
					stdout: "",
					stderr: [
						"bash: line 2: r2: command not found",
						"ModuleNotFoundError: No module named 'pwn'",
						"./missing-target: No such file or directory",
					].join("\n"),
					killed: false,
				};
			},
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		await missionTool.execute("tool-call-id", { action: "new", task: "pwn ELF exploit primitive" });

		const laneTool = tools.get("re_lane") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const repairRun = await laneTool.execute("tool-call-id", {
			action: "run",
			lane: "primitive",
			target: "./vuln",
		});

		expect(execCalls).toHaveLength(1);
		const textOut = repairRun.content[0]?.text ?? "";
		expect(textOut).toContain("tool repair anchors");
		expect(textOut).toContain("tool repair missing dependency anchors");
		expect(textOut).toContain("tool-repair-matrix-scaffold");
		expect(textOut).toContain("tool-repair-rerun");
		expect(textOut).toContain("heal-tool-repair-matrix");
		expect(textOut).toContain("evidence_quality:");
		const artifactPath = /evidence_artifact: (.+)/.exec(textOut)?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		const artifact = readFileSync(artifactPath!, "utf-8");
		expect(artifact).toContain("tool repair anchors");
		expect(artifact).toContain("tool-repair-matrix-scaffold");

		const missionAfterRepair = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { lanes: Array<{ name: string; next: string[] }> };
		const primitiveLane = missionAfterRepair.lanes.find((lane) => lane.name === "primitive");
		expect(primitiveLane?.next.join("\n")).toContain("[auto:tool-repair-matrix-scaffold]");
	});

	it("escalates stalled adaptive self-heal into a multi-lane evidence repair plan", async () => {
		const tools = new Map<string, unknown>();
		const execCalls: Array<{ command: string; args: string[] }> = [];
		const fakePi = {
			registerCommand() {},
			registerTool(tool: { name: string }) {
				tools.set(tool.name, tool);
			},
			on() {},
			appendEntry() {},
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage() {},
			exec: async (command: string, args: string[]) => {
				execCalls.push({ command, args });
				return { code: 0, stdout: "ok\n", stderr: "", killed: false };
			},
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		await missionTool.execute("tool-call-id", { action: "new", task: "分析 ELF 许可证校验" });

		const laneTool = tools.get("re_lane") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		await laneTool.execute("tool-call-id", {
			action: "run",
			lane: "control-flow",
			target: "./license",
		});

		const adaptiveAuto = await laneTool.execute("tool-call-id", {
			action: "run-auto",
			lane: "control-flow",
			target: "./license",
			max: 2,
		});

		expect(execCalls).toHaveLength(3);
		expect(adaptiveAuto.content[0]?.text).toContain("run_auto_summary:");
		expect(adaptiveAuto.content[0]?.text).toContain("steps_executed: 2");
		expect(adaptiveAuto.content[0]?.text).toContain("adaptive_decisions: 2");
		expect(adaptiveAuto.content[0]?.text).toContain("multi_lane_plan:");
		expect(adaptiveAuto.content[0]?.text).toContain("lane: evidence-repair");
		expect(adaptiveAuto.content[0]?.text).toContain("reason: partial_evidence_self_heal:control-flow");
		expect(adaptiveAuto.content[0]?.text).toContain(
			"stop_reason: multi_lane_plan:evidence-repair:partial_evidence_self_heal:control-flow",
		);
		expect(adaptiveAuto.content[0]?.text).toContain("[auto:repair-target-baseline]");

		const missionAfterPlanner = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as {
			lanes: Array<{ name: string; status?: string; note?: string; next: string[] }>;
		};
		const controlFlowLane = missionAfterPlanner.lanes.find((lane) => lane.name === "control-flow");
		const repairLane = missionAfterPlanner.lanes.find((lane) => lane.name === "evidence-repair");
		expect(controlFlowLane?.status).toBe("pending");
		expect(controlFlowLane?.note).toContain("adaptive_handoff=evidence-repair");
		expect(repairLane?.status).toBe("in_progress");
		expect(repairLane?.note).toContain("adaptive_from=control-flow");
		expect(repairLane?.next.join("\n")).toContain("[auto:repair-target-baseline]");
		expect(repairLane?.next.join("\n")).toContain("[auto:repair-signal-sweep]");
	});

	it("closes tool-bootstrap lanes by refreshing tool-index and resuming the blocked source lane", async () => {
		const tools = new Map<string, unknown>();
		const execCalls: Array<{ command: string; args: string[] }> = [];
		const fakePi = {
			registerCommand() {},
			registerTool(tool: { name: string }) {
				tools.set(tool.name, tool);
			},
			on() {},
			appendEntry() {},
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage() {},
			exec: async (command: string, args: string[]) => {
				execCalls.push({ command, args });
				if (args.join("\n").includes("for t in")) {
					return {
						code: 0,
						stdout: [
							"| file | yes | /usr/bin/file | file |",
							"| sha256sum | yes | /usr/bin/sha256sum | sha256sum |",
							"| rg | yes | /usr/bin/rg | ripgrep |",
							"| python3 | yes | /usr/bin/python3 | Python |",
							"",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				return { code: 0, stdout: "strcmp\n", stderr: "", killed: false };
			},
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		await missionTool.execute("tool-call-id", { action: "new", task: "分析 ELF 许可证校验" });
		const mission = readCurrentMission();
		if (!mission) throw new Error("expected active mission");
		const updatedAt = new Date().toISOString();
		const lanes: typeof mission.lanes = mission.lanes.map((lane) => {
			if (lane.name === "control-flow") {
				return {
					...lane,
					status: "blocked" as const,
					note: "waiting for tool-bootstrap",
					next: ["[auto:post-bootstrap-signal] printf 'strcmp\\n' # evidence: resume after tool-index refresh"],
					updatedAt,
				};
			}
			return {
				...lane,
				status: lane.name === "triage" ? ("done" as const) : ("pending" as const),
				updatedAt,
			};
		});
		lanes.splice(2, 0, {
			name: "tool-bootstrap",
			objective: "补齐缺失工具或确认可用替代路径，再回到被阻塞 lane",
			status: "in_progress" as const,
			note: "adaptive_from=control-flow; reason=tool_strategy_tool-index-missing:control-flow",
			next: ["re_bootstrap plan file sha256sum rg python3"],
			updatedAt,
		});
		writeCurrentMission({ ...mission, lanes });

		const laneTool = tools.get("re_lane") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const auto = await laneTool.execute("tool-call-id", {
			action: "run-auto",
			lane: "tool-bootstrap",
			target: "./license",
			max: 2,
		});

		expect(execCalls, auto.content[0]?.text).toHaveLength(2);
		expect(auto.content[0]?.text).toContain("tool_bootstrap_closure:");
		expect(auto.content[0]?.text).toContain("missing_after_refresh: none");
		expect(auto.content[0]?.text).toContain("resumed_lane: control-flow");
		expect(auto.content[0]?.text).toContain("reason: tool_bootstrap_closed:control-flow");
		expect(auto.content[0]?.text).toContain("## run-auto step 2: control-flow");
		expect(auto.content[0]?.text).toContain("auto_lane_update: control-flow -> runtime-proof");

		const missionAfterClosure = readCurrentMission() as {
			lanes: Array<{ name: string; status?: string; note?: string }>;
			checkpoints: Array<{ name: string; status: string; note?: string }>;
		};
		expect(missionAfterClosure.lanes.find((lane) => lane.name === "tool-bootstrap")?.status).toBe("done");
		expect(missionAfterClosure.lanes.find((lane) => lane.name === "control-flow")?.status).toBe("done");
		expect(missionAfterClosure.lanes.find((lane) => lane.name === "runtime-proof")?.status).toBe("in_progress");
		expect(missionAfterClosure.checkpoints.find((gate) => gate.name === "tool_index_checked")?.status).toBe("done");
		expect(readFileSync(join(agentDir, "recon", "tools", "tool-index.md"), "utf-8")).toContain(
			"| file | yes | /usr/bin/file | file |",
		);
	});
});

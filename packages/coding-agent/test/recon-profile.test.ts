import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";
import { REPI_COMMAND_NAMES, REPI_TOOL_NAMES } from "../src/core/repi/profile.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_BRANCH_ID = "REPI_BRANCH_ID";

vi.setConfig({ testTimeout: 60_000 });

describe("REPI kernel profile", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousBranchId: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("blocks exact context resume negative fixtures and completion closure", async () => {
		const tools = new Map<string, unknown>();
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
			exec: async () => ({ code: 0, stdout: "", stderr: "", killed: false }),
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);
		process.env[ENV_BRANCH_ID] = "branch-a";
		const runtimeBridgeTool = tools.get("re_runtime_bridge") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const runtimeBridge = await runtimeBridgeTool.execute("tool-call-id", {
			action: "show",
			bridge: "web-cdp-replay",
		});
		expect(runtimeBridge.content[0]?.text).toContain("ProfessionalRuntimeBridgesCheckV1");
		expect(runtimeBridge.content[0]?.text).toContain("cdp-network-capture");

		const runtimeAdapterTool = tools.get("re_runtime_adapter") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const runtimeAdapter = await runtimeAdapterTool.execute("tool-call-id", {
			action: "plan",
			adapter: "r2-native-xref-adapter",
		});
		expect(runtimeAdapter.content[0]?.text).toContain("RuntimeAdapterExecutionCheckV1");
		expect(runtimeAdapter.content[0]?.text).toContain("adapter-r2-native-xref-runner");

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const mapTool = tools.get("re_map") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const contextTool = tools.get("re_context") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const completeTool = tools.get("re_complete") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};

		await missionTool.execute("tool-call-id", { action: "new", task: "exact resume negative fixture target-a" });
		await mapTool.execute("tool-call-id", { target: "target-a", depth: 1 });
		const contextPack = await contextTool.execute("tool-call-id", { action: "pack", target: "target-a" });
		const contextPath = /context_artifact: (.+)/.exec(contextPack.content[0]?.text ?? "")?.[1]?.trim();
		const mapPath = /- map: (.+?) exists=true sha256=/.exec(contextPack.content[0]?.text ?? "")?.[1]?.trim();
		expect(contextPath).toBeDefined();
		expect(mapPath).toBeDefined();
		expect(contextPack.content[0]?.text).toContain("closure:");
		expect(contextPack.content[0]?.text).toContain("- status=open");

		process.env[ENV_BRANCH_ID] = "branch-b";
		const branchResume = await contextTool.execute("tool-call-id", {
			action: "resume",
			target: "target-a",
			contextPath,
		});
		expect(branchResume.content[0]?.text).toContain("resume_queue_status: blocked");
		expect(branchResume.content[0]?.text).toContain("branch mismatch");
		const branchCompletion = await completeTool.execute("tool-call-id", { action: "audit" });
		expect(branchCompletion.content[0]?.text).toContain("context resume verification blocks completion");
		expect(branchCompletion.content[0]?.text).toContain("branch mismatch");

		process.env[ENV_BRANCH_ID] = "branch-a";
		const mismatchResume = await contextTool.execute("tool-call-id", {
			action: "resume",
			target: "target-b",
			contextPath,
		});
		expect(mismatchResume.content[0]?.text).toContain("resume_queue_status: blocked");
		expect(mismatchResume.content[0]?.text).toContain("- status=blocked");
		expect(mismatchResume.content[0]?.text).toContain("target mismatch");
		const mismatchCompletion = await completeTool.execute("tool-call-id", { action: "audit" });
		expect(mismatchCompletion.content[0]?.text).toContain("context resume closure blocks completion");
		expect(mismatchCompletion.content[0]?.text).toContain("context resume queue not done");

		writeFileSync(mapPath!, `${readFileSync(mapPath!, "utf-8")}\n# mutate map artifact for hash drift\n`, "utf-8");
		const driftResume = await contextTool.execute("tool-call-id", {
			action: "resume",
			target: "target-a",
			contextPath,
		});
		expect(driftResume.content[0]?.text).toContain("resume_queue_status: blocked");
		expect(driftResume.content[0]?.text).toContain("artifact hash drift");
		const driftCompletion = await completeTool.execute("tool-call-id", { action: "audit" });
		expect(driftCompletion.content[0]?.text).toContain("context resume verification blocks completion");
		expect(driftCompletion.content[0]?.text).toContain("artifact hash drift");

		const missingResume = await contextTool.execute("tool-call-id", {
			action: "resume",
			contextPath: join(agentDir, "recon", "evidence", "contexts", "missing-pack.md"),
		});
		expect(missingResume.content[0]?.text).toContain("resume_queue_status: blocked");
		expect(missingResume.content[0]?.text).toContain("context pack not found");
	});

	it("registers built-in commands, tools, and goal mode through an inline extension factory", async () => {
		const commands = new Map<string, unknown>();
		const tools = new Map<string, unknown>();
		const handlers = new Map<string, unknown[]>();
		const fakePi = {
			registerCommand(name: string, options: unknown) {
				commands.set(name, options);
			},
			registerTool(tool: { name: string }) {
				tools.set(tool.name, tool);
			},
			on(event: string, handler: unknown) {
				handlers.set(event, [...(handlers.get(event) ?? []), handler]);
			},
			appendEntry() {},
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage() {},
			exec: async () => ({ code: 0, stdout: "main\nstrcmp\n", stderr: "", killed: false }),
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		expect([...commands.keys()]).toEqual(expect.arrayContaining([...REPI_COMMAND_NAMES, "goal"]));
		expect([...tools.keys()]).toEqual(expect.arrayContaining([...REPI_TOOL_NAMES, "goal_complete"]));
		expect(handlers.has("before_agent_start")).toBe(true);
		expect(handlers.has("tool_call")).toBe(true);
		expect(handlers.has("session_before_compact")).toBe(true);

		const bootstrapTool = tools.get("re_bootstrap") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const bootstrapPlan = await bootstrapTool.execute("tool-call-id", { action: "plan", tools: ["gdb"] });
		expect(bootstrapPlan.content[0]?.text).toContain("sudo apt-get install -y gdb");

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const missionResult = await missionTool.execute("tool-call-id", {
			action: "new",
			task: "分析 ELF 许可证校验",
		});
		expect(missionResult.content[0]?.text).toContain("mission_id:");
		expect(readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8")).toContain("Native reverse");

		const kernelTool = tools.get("re_kernel") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const kernelResult = await kernelTool.execute("tool-call-id", { action: "build", target: "./license" });
		expect(kernelResult.content[0]?.text).toContain("execution_kernel:");
		expect(kernelResult.content[0]?.text).toContain("next_kernel_command:");
	});

	it("verifies and repairs MemoryStoreV5 transactional memory", async () => {
		const tools = new Map<string, unknown>();
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
			exec: async () => ({ code: 0, stdout: "", stderr: "", killed: false }),
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		const memoryTool = tools.get("re_memory") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }>; details?: Record<string, unknown> }>;
		};
		const appendResult = await memoryTool.execute("tool-call-id", {
			action: "append",
			scene: "native",
			title: "license runtime anchor",
			text: "runtime strcmp anchor verified; command: strings ./license | rg license",
		});
		expect(appendResult.content[0]?.text).toContain("memory_event:");
		const memoryDir = join(agentDir, "recon", "memory");
		const storeReportPath = join(memoryDir, "store-report.json");
		const transactionDir = join(memoryDir, "transactions");
		expect(readFileSync(storeReportPath, "utf-8")).toContain("MemoryStoreV5");
		expect(readFileSync(join(transactionDir, readdirSync(transactionDir)[0]!), "utf-8")).toContain(
			"repi-memory-append-transaction",
		);

		const verifyPass = await memoryTool.execute("tool-call-id", { action: "verify" });
		expect(verifyPass.content[0]?.text).toContain("memory_store_v5:");
		expect(verifyPass.content[0]?.text).toContain("status=pass");
		expect(verifyPass.content[0]?.text).toContain("hash_chain_ok=true");

		writeFileSync(join(memoryDir, "case-memory.jsonl"), "", "utf-8");
		const verifyRepairable = await memoryTool.execute("tool-call-id", { action: "verify" });
		expect(verifyRepairable.content[0]?.text).toContain("status=repairable");
		expect(verifyRepairable.content[0]?.text).toContain("re_memory repair-index");

		const repaired = await memoryTool.execute("tool-call-id", { action: "repair-index" });
		expect(repaired.content[0]?.text).toContain("status=pass");
		expect(readFileSync(join(memoryDir, "case-memory.jsonl"), "utf-8")).toContain("repi-case-memory");

		const snapshot = await memoryTool.execute("tool-call-id", { action: "snapshot" });
		expect(snapshot.content[0]?.text).toContain("snapshot=");
		expect(readFileSync(join(memoryDir, "store-snapshot.json"), "utf-8")).toContain("repi-memory-store-snapshot");

		const evalResult = await memoryTool.execute("tool-call-id", { action: "eval" });
		expect(evalResult.content[0]?.text).toContain("memory_usefulness_eval:");
		expect(evalResult.content[0]?.text).toContain("hit_at_k=");
		expect(readFileSync(join(memoryDir, "usefulness-eval.json"), "utf-8")).toContain("repi-memory-usefulness-eval");
	});

	it("scores weak lane evidence and queues self-healing follow-ups", async () => {
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
		const weakRun = await laneTool.execute("tool-call-id", {
			action: "run",
			lane: "control-flow",
			target: "./license",
		});

		expect(execCalls).toHaveLength(1);
		expect(weakRun.content[0]?.text).toContain("evidence_quality:");
		expect(weakRun.content[0]?.text).toContain("deficits:");
		expect(weakRun.content[0]?.text).toContain("self_heal_commands:");
		expect(weakRun.content[0]?.text).toContain("heal-native-baseline");
		const artifactPath = /evidence_artifact: (.+)/.exec(weakRun.content[0]?.text ?? "")?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(readFileSync(artifactPath!, "utf-8")).toContain("## Evidence critic");
		expect(readFileSync(artifactPath!, "utf-8")).toContain("## Self-heal commands");

		const missionAfterWeakRun = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
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
		expect(execCalls).toHaveLength(2);
		expect(execCalls[1]?.args.join(" ")).toContain("license|serial|key");
		expect(adaptiveAuto.content[0]?.text).toContain("run_auto_summary:");
		expect(adaptiveAuto.content[0]?.text).toContain("adaptive_decisions: 1");
		expect(adaptiveAuto.content[0]?.text).toContain("adaptive_decision:");
		expect(adaptiveAuto.content[0]?.text).toContain("reason: partial_evidence_self_heal:control-flow");
		expect(adaptiveAuto.content[0]?.text).toContain(
			"stop_reason: max_steps_reached_after:partial_evidence_self_heal:control-flow",
		);
	});
});

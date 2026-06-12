import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import {
	createReconExtensionFactory,
	createReconResourceLoaderOptions,
	RECON_APPEND_SYSTEM_PROMPT,
	RECON_SYSTEM_PROMPT,
	routeReconTask,
} from "../src/core/recon-profile.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_BRANCH_ID = "REPI_BRANCH_ID";

vi.setConfig({ testTimeout: 60_000 });

describe("REPI kernel profile", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousBranchId: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-recon-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("routes security tasks to a narrow workflow", () => {
		const route = routeReconTask("分析这个 ELF 的许可证校验逻辑");
		expect(route.domain).toBe("Native reverse");
		expect(route.workflow).toContain("headers/imports");
		expect(routeReconTask("LLM agent prompt injection MCP tool call 边界验证").domain).toBe("Agent / LLM security");
		expect(routeReconTask("autopwn exploit reliability poc replay matrix").domain).toBe("Exploit reliability");
		expect(routeReconTask("nuclei ffuf web 漏洞扫描和目录扫描").domain).toBe("Web vulnerability scanning");
		expect(routeReconTask("iOS IPA Keychain TLS pinning Frida 逆向").domain).toBe("Mobile / iOS");
		expect(routeReconTask("volatility vmem memory dump 内存取证").domain).toBe("Memory forensics");
	});

	it("injects built-in skills and prompts without project .repi files", () => {
		const options = createReconResourceLoaderOptions();
		const skillsResult = options.skillsOverride!({ skills: [], diagnostics: [] });
		const promptsResult = options.promptsOverride!({ prompts: [], diagnostics: [] });

		const skill = skillsResult.skills.find((candidate) => candidate.name === "reverse-pentest-orchestrator");
		expect(skill).toBeDefined();
		expect(skill?.sourceInfo.source).toBe("builtin:pi-recon");
		expect(skill?.filePath).toContain(join("recon", "builtin", "reverse-pentest-orchestrator", "SKILL.md"));
		expect(existsSync(skill!.filePath)).toBe(true);

		const promptNames = promptsResult.prompts.map((prompt) => prompt.name);
		expect(promptNames).toEqual(
			expect.arrayContaining([
				"reverse",
				"native",
				"websec",
				"webauthz",
				"jsre",
				"firmware",
				"agentsec",
				"pcap",
				"cloud",
				"identity",
				"malware",
				"pwn",
				"exploit",
				"chain",
				"decision",
				"mobile",
				"memory",
			]),
		);
		expect(promptsResult.prompts.every((prompt) => existsSync(prompt.filePath))).toBe(true);
		expect(readFileSync(skill!.filePath, "utf8")).toContain("refusal_to_execution");
		expect(readFileSync(skill!.filePath, "utf8")).toContain("operator_command_floor");
		expect(RECON_SYSTEM_PROMPT).toContain("execution-first mode");
		expect(RECON_SYSTEM_PROMPT).toContain("refusal_to_execution");
		expect(RECON_SYSTEM_PROMPT).toContain("operator_command_floor");
		expect(RECON_APPEND_SYSTEM_PROMPT).toContain("operator_next_command");
	});

	it("suppresses legacy profile extension conflicts when the built-in inline profile is active", () => {
		const reconTools = new Map([
			["re_route", {}],
			["re_kernel", {}],
			["re_decision_core", {}],
			["re_live_browser", {}],
			["re_web_authz_state", {}],
			["re_exploit_lab", {}],
			["re_mobile_runtime", {}],
			["re_native_runtime", {}],
			["re_memory", {}],
			["re_tool_index", {}],
			["re_toolchain_domain", {}],
			["re_lane_specialist_pack", {}],
			["re_domain_proof_exit", {}],
			["re_mission", {}],
			["re_evidence", {}],
			["re_graph", {}],
			["re_exploit_chain", {}],
			["re_campaign", {}],
			["re_operation", {}],
			["re_delegate", {}],
			["re_swarm", {}],
			["re_supervisor", {}],
			["re_reflect", {}],
			["re_context", {}],
			["re_operator", {}],
			["re_verifier", {}],
			["re_compiler", {}],
			["re_replayer", {}],
			["re_autofix", {}],
			["re_proof_loop", {}],
			["re_knowledge_graph", {}],
			["re_harness", {}],
			["re_lane", {}],
			["re_map", {}],
			["re_autopilot", {}],
			["re_bootstrap", {}],
			["re_complete", {}],
		]);
		const reconCommands = new Map([
			["re-route", {}],
			["re-kernel", {}],
			["re-decision", {}],
			["re-live-browser", {}],
			["re-web-authz-state", {}],
			["re-exploit-lab", {}],
			["re-mobile-runtime", {}],
			["re-native-runtime", {}],
			["re-tools", {}],
			["re-toolchain", {}],
			["re-lane-specialist-pack", {}],
			["re-domain-proof-exit", {}],
			["re-memory", {}],
			["re-mission", {}],
			["re-evidence", {}],
			["re-graph", {}],
			["re-chain", {}],
			["re-campaign", {}],
			["re-operation", {}],
			["re-delegate", {}],
			["re-swarm", {}],
			["re-supervisor", {}],
			["re-reflect", {}],
			["re-context", {}],
			["re-operator", {}],
			["re-verifier", {}],
			["re-compiler", {}],
			["re-replayer", {}],
			["re-autofix", {}],
			["re-proof-loop", {}],
			["re-knowledge-graph", {}],
			["re-harness", {}],
			["re-lane", {}],
			["re-map", {}],
			["re-auto", {}],
			["re-bootstrap", {}],
			["re-complete", {}],
			["re-self-review", {}],
		]);
		const options = createReconResourceLoaderOptions();
		const result = options.extensionsOverride!({
			extensions: [
				{
					path: "/root/.repi/agent/extensions/reverse-pentest-core.ts",
					tools: reconTools,
					commands: reconCommands,
				},
				{ path: "<inline:1>", tools: reconTools, commands: reconCommands },
			],
			errors: [
				{
					path: "<inline:1>",
					error: 'Tool "re_route" conflicts with /root/.repi/agent/extensions/reverse-pentest-core.ts',
				},
			],
			runtime: {},
		} as never);

		expect(result.extensions.map((extension) => extension.path)).toEqual(["<inline:1>"]);
		expect(result.errors).toEqual([]);
	});

	it("returns a REPI owned compaction result with a resume contract", async () => {
		const commands = new Map<string, unknown>();
		const tools = new Map<string, unknown>();
		const handlers = new Map<string, unknown[]>();
		const appended: Array<{ type: string; details: Record<string, unknown> }> = [];
		const sentMessages: Array<{
			message: { customType?: string; content?: string };
			options?: { triggerTurn?: boolean };
		}> = [];
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
			appendEntry(type: string, details: Record<string, unknown>) {
				appended.push({ type, details });
			},
			getSessionName: () => undefined,
			setSessionName() {},
			sendMessage(message: { customType?: string; content?: string }, options?: { triggerTurn?: boolean }) {
				sentMessages.push({ message, options });
			},
			exec: async () => ({ code: 0, stdout: "", stderr: "", killed: false }),
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);
		const compactHandler = handlers.get("session_before_compact")?.[0] as
			| ((event: unknown) => Promise<{
					compaction?: {
						summary: string;
						firstKeptEntryId: string;
						tokensBefore: number;
						details?: { kind?: string; contextPath?: string; resumeCommand?: string };
					};
			  }>)
			| undefined;
		expect(compactHandler).toBeDefined();

		const result = await compactHandler!({
			type: "session_before_compact",
			preparation: {
				firstKeptEntryId: "entry-keep",
				messagesToSummarize: [],
				turnPrefixMessages: [],
				isSplitTurn: false,
				tokensBefore: 4242,
				previousSummary: "previous Pi summary",
				fileOps: {},
				settings: {},
			},
			branchEntries: [{ id: "entry-old" }],
			customInstructions: "keep proof loop state",
			signal: new AbortController().signal,
		});

		const compaction = result.compaction;
		expect(compaction).toBeDefined();
		expect(compaction?.firstKeptEntryId).toBe("entry-keep");
		expect(compaction?.tokensBefore).toBe(4242);
		expect(compaction?.summary).toContain("# REPI Compaction Summary");
		expect(compaction?.summary).toContain("kind: pi-recon-compaction");
		expect(compaction?.summary).toContain("re_context resume");
		expect(compaction?.summary).toContain("re_operator plan");
		expect(compaction?.summary).toContain("re_operator dispatch");
		expect(compaction?.summary).toContain("re_proof_loop run <target> 4 2");
		expect(compaction?.summary).toContain("autonomous_execution_budget");
		expect(compaction?.details?.kind).toBe("pi-recon-compaction");
		expect(compaction?.details?.resumeCommand).toBe("re_context resume");
		expect(compaction?.details?.contextPath).toBeDefined();
		expect(existsSync(compaction!.details!.contextPath!)).toBe(true);
		const checkpoint = appended.find((entry) => entry.type === "pi-recon-compaction-checkpoint");
		expect(checkpoint).toBeDefined();
		expect(checkpoint?.details.compactionKind).toBe("pi-recon-compaction");
		expect(checkpoint?.details.firstKeptEntryId).toBe("entry-keep");

		const compactedHandler = handlers.get("session_compact")?.[0] as
			| ((event: unknown, ctx: { hasUI: false }) => Promise<void>)
			| undefined;
		expect(compactedHandler).toBeDefined();
		await compactedHandler!(
			{
				type: "session_compact",
				fromExtension: true,
				compactionEntry: {
					type: "compaction",
					id: "compact-entry",
					parentId: null,
					timestamp: new Date().toISOString(),
					summary: compaction!.summary,
					firstKeptEntryId: compaction!.firstKeptEntryId,
					tokensBefore: compaction!.tokensBefore,
					details: compaction!.details,
					fromHook: true,
				},
			},
			{ hasUI: false },
		);
		const resumeContract = appended.find((entry) => entry.type === "pi-recon-compaction-resume-contract");
		expect(resumeContract).toBeDefined();
		expect(resumeContract?.details.kind).toBe("pi-recon-compaction-resume-contract");
		expect(resumeContract?.details.verified).toBe(true);
		expect(resumeContract?.details.contextPath).toBe(compaction?.details?.contextPath);
		expect(String(resumeContract?.details.resumeContract)).toContain("re_context resume");
		const autoResume = appended.find((entry) => entry.type === "pi-recon-compaction-auto-resume");
		expect(autoResume?.details.kind).toBe("pi-recon-compaction-auto-resume");
		expect(autoResume?.details.triggered).toBe(true);
		const telemetry = appended.find((entry) => entry.type === "pi-recon-compaction-resume-telemetry");
		expect(telemetry?.details.kind).toBe("pi-recon-compaction-resume-telemetry");
		expect(String(telemetry?.details.path)).toContain("compaction-auto-resume-board.md");
		expect(sentMessages).toHaveLength(1);
		expect(sentMessages[0]?.message.customType).toBe("pi-recon-auto-resume");
		expect(sentMessages[0]?.message.content).toContain("REPI Auto Resume Trigger");
		expect(sentMessages[0]?.message.content).toContain("bounded_resume_commands");
		expect(sentMessages[0]?.options?.triggerTurn).toBe(true);

		const operatorTool = tools.get("re_operator") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const operatorPlan = await operatorTool.execute("tool-call-id", { action: "plan" });
		expect(operatorPlan.content[0]?.text).toContain("compact_resume_telemetry:");
		expect(operatorPlan.content[0]?.text).toContain("compact_resume_queue:");
		expect(operatorPlan.content[0]?.text).toContain("compact_resume_command");
		const proofLoopTool = tools.get("re_proof_loop") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const proofLoopPlan = await proofLoopTool.execute("tool-call-id", { action: "plan" });
		expect(proofLoopPlan.content[0]?.text).toContain("compact_resume_telemetry:");
		expect(proofLoopPlan.content[0]?.text).toContain("compact_resume_queue:");
		expect(proofLoopPlan.content[0]?.text).toContain("source=compact_resume");
		const completeTool = tools.get("re_complete") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const completeAudit = await completeTool.execute("tool-call-id", { action: "audit" });
		expect(completeAudit.content[0]?.text).toContain("compact resume command still queued");
		expect(completeAudit.content[0]?.text).toContain("compact_resume_telemetry:");
		const knowledgeTool = tools.get("re_knowledge_graph") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const knowledgeGraph = await knowledgeTool.execute("tool-call-id", { action: "build", target: "demo-target" });
		expect(knowledgeGraph.content[0]?.text).toContain("compact_resume_case_memory:");
		expect(knowledgeGraph.content[0]?.text).toContain("compact_resume_routing_hints:");
		expect(knowledgeGraph.content[0]?.text).toContain("compact_resume_status=queued");
		expect(knowledgeGraph.content[0]?.text).toContain("compact_resume_queue command=");
		expect(knowledgeGraph.content[0]?.text).toContain("compaction-auto-resume-board.md");
		const autopilotTool = tools.get("re_autopilot") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const queuedAutopilotPlan = await autopilotTool.execute("tool-call-id", {
			action: "plan",
			target: "demo-target",
		});
		expect(queuedAutopilotPlan.content[0]?.text).toContain("compact_resume_repair_from_case_memory");
		expect(queuedAutopilotPlan.content[0]?.text).toContain("target_lane: compact-resume-repair");
		expect(queuedAutopilotPlan.content[0]?.text).toContain("re_proof_loop run demo-target 4 2");
		const proofLoopRun = await proofLoopTool.execute("tool-call-id", {
			action: "run",
			target: "demo-target",
			maxSteps: 12,
			replaySteps: 1,
		});
		expect(proofLoopRun.content[0]?.text).toContain("compact resume proof loop entered by current re_proof_loop run");
		expect(proofLoopRun.content[0]?.text).toContain("proof_loop_entered=true");
		const postResumeAudit = await completeTool.execute("tool-call-id", { action: "audit" });
		expect(postResumeAudit.content[0]?.text).not.toContain("compact resume command still queued");
		expect(postResumeAudit.content[0]?.text).not.toContain("compact resume proof loop not entered");
		const resumedKnowledgeGraph = await knowledgeTool.execute("tool-call-id", {
			action: "build",
			target: "demo-target",
		});
		expect(resumedKnowledgeGraph.content[0]?.text).toContain("compact_resume_status=done");
		expect(resumedKnowledgeGraph.content[0]?.text).toContain("compact_resume_success");
		const resumedAutopilotPlan = await autopilotTool.execute("tool-call-id", {
			action: "plan",
			target: "demo-target",
		});
		expect(resumedAutopilotPlan.content[0]?.text).toContain("compact_resume_success_skip_low_value_lane");
		expect(resumedAutopilotPlan.content[0]?.text).toContain("skipped_lane: map");
		expect(resumedAutopilotPlan.content[0]?.text).toContain("target_lane: prove");
		const resumedAutopilotRun = await autopilotTool.execute("tool-call-id", {
			action: "run",
			target: "demo-target",
			runAuto: false,
		});
		expect(resumedAutopilotRun.content[0]?.text).toContain("compact_resume_success_skip_low_value_lane");
		const missionAfterCompactMemory = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { lanes: Array<{ name: string; status: string; note?: string }> };
		expect(missionAfterCompactMemory.lanes.find((lane) => lane.name === "prove")?.status).toBe("in_progress");
		expect(missionAfterCompactMemory.lanes.find((lane) => lane.name === "map")?.note).toContain(
			"case_memory_lane_plan=skipped",
		);
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

	it("registers built-in commands and tools through an inline extension factory", async () => {
		const commands = new Map<string, unknown>();
		const tools = new Map<string, unknown>();
		const handlers = new Map<string, unknown[]>();
		const execCalls: Array<{ command: string; args: string[] }> = [];
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
			exec: async (command: string, args: string[]) => {
				execCalls.push({ command, args });
				return {
					code: 0,
					stdout: "### lane-command 1: r2-xrefs\nmain\n### lane-command 2: objdump-control\nstrcmp\n",
					stderr: "",
					killed: false,
				};
			},
		} as unknown as ExtensionAPI;

		createReconExtensionFactory()(fakePi);

		expect(commands.has("re-route")).toBe(true);
		expect(commands.has("re-kernel")).toBe(true);
		expect(commands.has("re-decision")).toBe(true);
		expect(commands.has("re-live-browser")).toBe(true);
		expect(commands.has("re-web-authz-state")).toBe(true);
		expect(commands.has("re-exploit-lab")).toBe(true);
		expect(commands.has("re-mobile-runtime")).toBe(true);
		expect(commands.has("re-native-runtime")).toBe(true);
		expect(commands.has("re-tools")).toBe(true);
		expect(commands.has("re-memory")).toBe(true);
		expect(commands.has("re-mission")).toBe(true);
		expect(commands.has("re-evidence")).toBe(true);
		expect(commands.has("re-graph")).toBe(true);
		expect(commands.has("re-chain")).toBe(true);
		expect(commands.has("re-campaign")).toBe(true);
		expect(commands.has("re-operation")).toBe(true);
		expect(commands.has("re-delegate")).toBe(true);
		expect(commands.has("re-swarm")).toBe(true);
		expect(commands.has("re-supervisor")).toBe(true);
		expect(commands.has("re-reflect")).toBe(true);
		expect(commands.has("re-context")).toBe(true);
		expect(commands.has("re-operator")).toBe(true);
		expect(commands.has("re-verifier")).toBe(true);
		expect(commands.has("re-compiler")).toBe(true);
		expect(commands.has("re-replayer")).toBe(true);
		expect(commands.has("re-autofix")).toBe(true);
		expect(commands.has("re-proof-loop")).toBe(true);
		expect(commands.has("re-knowledge-graph")).toBe(true);
		expect(commands.has("re-harness")).toBe(true);
		expect(commands.has("re-lane")).toBe(true);
		expect(commands.has("re-map")).toBe(true);
		expect(commands.has("re-auto")).toBe(true);
		expect(commands.has("re-bootstrap")).toBe(true);
		expect(commands.has("re-complete")).toBe(true);
		expect(commands.has("re-self-review")).toBe(true);
		expect(tools.has("re_route")).toBe(true);
		expect(tools.has("re_kernel")).toBe(true);
		expect(tools.has("re_decision_core")).toBe(true);
		expect(tools.has("re_live_browser")).toBe(true);
		expect(tools.has("re_web_authz_state")).toBe(true);
		expect(tools.has("re_exploit_lab")).toBe(true);
		expect(tools.has("re_mobile_runtime")).toBe(true);
		expect(tools.has("re_native_runtime")).toBe(true);
		expect(tools.has("re_memory")).toBe(true);
		expect(tools.has("re_tool_index")).toBe(true);
		expect(tools.has("re_mission")).toBe(true);
		expect(tools.has("re_evidence")).toBe(true);
		expect(tools.has("re_graph")).toBe(true);
		expect(tools.has("re_exploit_chain")).toBe(true);
		expect(tools.has("re_campaign")).toBe(true);
		expect(tools.has("re_operation")).toBe(true);
		expect(tools.has("re_delegate")).toBe(true);
		expect(tools.has("re_swarm")).toBe(true);
		expect(tools.has("re_supervisor")).toBe(true);
		expect(tools.has("re_reflect")).toBe(true);
		expect(tools.has("re_context")).toBe(true);
		expect(tools.has("re_operator")).toBe(true);
		expect(tools.has("re_verifier")).toBe(true);
		expect(tools.has("re_compiler")).toBe(true);
		expect(tools.has("re_replayer")).toBe(true);
		expect(tools.has("re_autofix")).toBe(true);
		expect(tools.has("re_proof_loop")).toBe(true);
		expect(tools.has("re_knowledge_graph")).toBe(true);
		expect(tools.has("re_harness")).toBe(true);
		expect(tools.has("re_lane")).toBe(true);
		expect(tools.has("re_map")).toBe(true);
		expect(tools.has("re_autopilot")).toBe(true);
		expect(tools.has("re_bootstrap")).toBe(true);
		expect(tools.has("re_complete")).toBe(true);

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
		expect(kernelResult.content[0]?.text).toContain("kernel_artifact:");
		expect(kernelResult.content[0]?.text).toContain("directive_stack:");
		expect(kernelResult.content[0]?.text).toContain("operator-command-floor");
		expect(kernelResult.content[0]?.text).toContain("execution_invariants:");
		expect(kernelResult.content[0]?.text).toContain("operator_command_floor:");
		expect(kernelResult.content[0]?.text).toContain("specialist_capability_matrix:");
		expect(kernelResult.content[0]?.text).toContain("proof_exit_criteria:");
		expect(kernelResult.content[0]?.text).toContain("native-deep");
		expect(kernelResult.content[0]?.text).toContain("narrative_only_answer");
		expect(kernelResult.content[0]?.text).toContain("refusal_to_execution_rules:");
		expect(kernelResult.content[0]?.text).toContain("tool_call_policy:");
		expect(kernelResult.content[0]?.text).toContain("artifact_contract:");
		expect(kernelResult.content[0]?.text).toContain("stall_recovery:");
		expect(kernelResult.content[0]?.text).toContain("next_kernel_command:");
		const kernelPath = /kernel_artifact: (.+)/.exec(kernelResult.content[0]?.text ?? "")?.[1]?.trim();
		expect(kernelPath).toBeDefined();
		expect(existsSync(kernelPath!)).toBe(true);
		expect(readFileSync(kernelPath!, "utf-8")).toContain("REPI Execution Kernel Artifact");
		expect(readFileSync(join(agentDir, "recon", "memory", "execution-kernel.md"), "utf-8")).toContain(
			"Execution Kernel",
		);
		const missionAfterKernel = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterKernel.gates.find((gate) => gate.name === "execution_kernel_ready")?.status).toBe("done");

		const decisionTool = tools.get("re_decision_core") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const decisionResult = await decisionTool.execute("tool-call-id", { action: "tick", target: "./license" });
		expect(decisionResult.content[0]?.text).toContain("decision_core:");
		expect(decisionResult.content[0]?.text).toContain("decision_artifact:");
		expect(decisionResult.content[0]?.text).toContain("objective_stack:");
		expect(decisionResult.content[0]?.text).toContain("gate_pressure:");
		expect(decisionResult.content[0]?.text).toContain("evidence_priority:");
		expect(decisionResult.content[0]?.text).toContain("tool_posture:");
		expect(decisionResult.content[0]?.text).toContain("artifact_posture:");
		expect(decisionResult.content[0]?.text).toContain("decision_rules:");
		expect(decisionResult.content[0]?.text).toContain("operator_queue:");
		expect(decisionResult.content[0]?.text).toContain("operator_next_command:");
		expect(decisionResult.content[0]?.text).toContain("next_decision_command:");
		const decisionPath = /decision_artifact: (.+)/.exec(decisionResult.content[0]?.text ?? "")?.[1]?.trim();
		expect(decisionPath).toBeDefined();
		expect(existsSync(decisionPath!)).toBe(true);
		expect(readFileSync(decisionPath!, "utf-8")).toContain("REPI Decision Core Artifact");
		expect(readFileSync(join(agentDir, "recon", "memory", "decision-core.md"), "utf-8")).toContain("Decision Core");
		const missionAfterDecision = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterDecision.gates.find((gate) => gate.name === "decision_core_ready")?.status).toBe("done");

		const decisionRun = await decisionTool.execute("tool-call-id", {
			action: "run",
			target: "./license",
			maxSteps: 1,
		});
		expect(decisionRun.content[0]?.text).toContain("decision_core:");
		expect(decisionRun.content[0]?.text).toContain("mode: run");
		expect(decisionRun.content[0]?.text).toContain("executed_steps: 1");
		expect(decisionRun.content[0]?.text).toContain("next_decision_command: re_verifier matrix");
		const decisionRunPath = /decision_artifact: (.+)/.exec(decisionRun.content[0]?.text ?? "")?.[1]?.trim();
		expect(decisionRunPath).toBeDefined();
		expect(existsSync(decisionRunPath!)).toBe(true);
		expect(readFileSync(decisionRunPath!, "utf-8")).toContain("REPI Decision Core Artifact");
		expect(readFileSync(join(agentDir, "recon", "memory", "decision-core.md"), "utf-8")).toContain("## Executed");

		const liveBrowserTool = tools.get("re_live_browser") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const browserPlan = await liveBrowserTool.execute("tool-call-id", {
			action: "plan",
			target: "https://target.local/app",
		});
		expect(browserPlan.content[0]?.text).toContain("live_browser:");
		expect(browserPlan.content[0]?.text).toContain("browser_artifact:");
		expect(browserPlan.content[0]?.text).toContain("runtime_matrix:");
		expect(browserPlan.content[0]?.text).toContain("auth_matrix:");
		expect(browserPlan.content[0]?.text).toContain("idor_bola_probe_templates:");
		expect(browserPlan.content[0]?.text).toContain("websocket_probes:");
		expect(browserPlan.content[0]?.text).toContain("capture_script:");
		expect(browserPlan.content[0]?.text).toContain("next_browser_command:");
		const browserPath = /browser_artifact: (.+)/.exec(browserPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(browserPath).toBeDefined();
		expect(existsSync(browserPath!)).toBe(true);
		expect(readFileSync(browserPath!, "utf-8")).toContain("REPI Live Browser Artifact");
		const missionAfterBrowser = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterBrowser.gates.find((gate) => gate.name === "live_browser_ready")?.status).toBe("done");

		const webAuthzTool = tools.get("re_web_authz_state") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const webAuthzPlan = await webAuthzTool.execute("tool-call-id", {
			action: "plan",
			target: "https://target.local/api/users/123",
			timeoutMs: 9000,
		});
		expect(webAuthzPlan.content[0]?.text).toContain("web_authz_state:");
		expect(webAuthzPlan.content[0]?.text).toContain("web_authz_artifact:");
		expect(webAuthzPlan.content[0]?.text).toContain("route_inventory:");
		expect(webAuthzPlan.content[0]?.text).toContain("principal_matrix:");
		expect(webAuthzPlan.content[0]?.text).toContain("object_probes:");
		expect(webAuthzPlan.content[0]?.text).toContain("state_machine:");
		expect(webAuthzPlan.content[0]?.text).toContain("sequence_replay:");
		expect(webAuthzPlan.content[0]?.text).toContain("ownership_checks:");
		expect(webAuthzPlan.content[0]?.text).toContain("rollback_checks:");
		expect(webAuthzPlan.content[0]?.text).toContain("next_web_authz_command:");
		const webAuthzPath = /web_authz_artifact: (.+)/.exec(webAuthzPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(webAuthzPath).toBeDefined();
		expect(existsSync(webAuthzPath!)).toBe(true);
		expect(readFileSync(webAuthzPath!, "utf-8")).toContain("REPI Web Authz State Artifact");
		const missionAfterWebAuthz = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterWebAuthz.gates.find((gate) => gate.name === "web_authz_ready")?.status).toBe("done");

		const exploitLabTool = tools.get("re_exploit_lab") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const exploitLabPlan = await exploitLabTool.execute("tool-call-id", {
			action: "plan",
			target: "./exploit.py",
			runs: 3,
			timeoutMs: 7000,
		});
		expect(exploitLabPlan.content[0]?.text).toContain("exploit_lab:");
		expect(exploitLabPlan.content[0]?.text).toContain("exploit_lab_artifact:");
		expect(exploitLabPlan.content[0]?.text).toContain("lab_matrix:");
		expect(exploitLabPlan.content[0]?.text).toContain("poc_inventory:");
		expect(exploitLabPlan.content[0]?.text).toContain("environment_pins:");
		expect(exploitLabPlan.content[0]?.text).toContain("flake_triage:");
		expect(exploitLabPlan.content[0]?.text).toContain("bundle_manifest:");
		expect(exploitLabPlan.content[0]?.text).toContain("next_lab_command:");
		const exploitLabPath = /exploit_lab_artifact: (.+)/.exec(exploitLabPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(exploitLabPath).toBeDefined();
		expect(existsSync(exploitLabPath!)).toBe(true);
		expect(readFileSync(exploitLabPath!, "utf-8")).toContain("REPI Exploit Lab Artifact");
		const missionAfterExploitLab = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterExploitLab.gates.find((gate) => gate.name === "exploit_lab_ready")?.status).toBe("done");

		const mobileRuntimeTool = tools.get("re_mobile_runtime") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const mobilePlan = await mobileRuntimeTool.execute("tool-call-id", {
			action: "plan",
			target: "./app.apk",
			packageName: "com.demo.app",
			timeoutMs: 9000,
		});
		expect(mobilePlan.content[0]?.text).toContain("mobile_runtime:");
		expect(mobilePlan.content[0]?.text).toContain("mobile_runtime_artifact:");
		expect(mobilePlan.content[0]?.text).toContain("device_matrix:");
		expect(mobilePlan.content[0]?.text).toContain("apk_inventory:");
		expect(mobilePlan.content[0]?.text).toContain("process_map:");
		expect(mobilePlan.content[0]?.text).toContain("hook_plan:");
		expect(mobilePlan.content[0]?.text).toContain("frida_hooks:");
		expect(mobilePlan.content[0]?.text).toContain("native_trace:");
		expect(mobilePlan.content[0]?.text).toContain("anti_debug_checks:");
		expect(mobilePlan.content[0]?.text).toContain("next_mobile_command:");
		const mobilePath = /mobile_runtime_artifact: (.+)/.exec(mobilePlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(mobilePath).toBeDefined();
		expect(existsSync(mobilePath!)).toBe(true);
		expect(readFileSync(mobilePath!, "utf-8")).toContain("REPI Mobile Runtime Artifact");
		const missionAfterMobile = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterMobile.gates.find((gate) => gate.name === "mobile_runtime_ready")?.status).toBe("done");

		const nativeRuntimeTool = tools.get("re_native_runtime") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const nativePlan = await nativeRuntimeTool.execute("tool-call-id", {
			action: "plan",
			target: "./vuln",
			timeoutMs: 9000,
		});
		expect(nativePlan.content[0]?.text).toContain("native_runtime:");
		expect(nativePlan.content[0]?.text).toContain("native_runtime_artifact:");
		expect(nativePlan.content[0]?.text).toContain("binary_inventory:");
		expect(nativePlan.content[0]?.text).toContain("mitigation_matrix:");
		expect(nativePlan.content[0]?.text).toContain("loader_libc:");
		expect(nativePlan.content[0]?.text).toContain("symbol_map:");
		expect(nativePlan.content[0]?.text).toContain("crash_plan:");
		expect(nativePlan.content[0]?.text).toContain("gdb_trace:");
		expect(nativePlan.content[0]?.text).toContain("breakpoint_plan:");
		expect(nativePlan.content[0]?.text).toContain("exploit_scaffold:");
		expect(nativePlan.content[0]?.text).toContain("next_native_command:");
		const nativePath = /native_runtime_artifact: (.+)/.exec(nativePlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(nativePath).toBeDefined();
		expect(existsSync(nativePath!)).toBe(true);
		expect(readFileSync(nativePath!, "utf-8")).toContain("REPI Native Runtime Artifact");
		const missionAfterNative = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterNative.gates.find((gate) => gate.name === "native_runtime_ready")?.status).toBe("done");

		const laneTool = tools.get("re_lane") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const laneResult = await laneTool.execute("tool-call-id", {
			action: "done",
			lane: "triage",
			note: "headers mapped",
		});
		expect(laneResult.content[0]?.text).toContain("[done] triage");
		expect(laneResult.content[0]?.text).toContain("[in_progress] control-flow");
		expect(readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8")).toContain("passive_map_done");

		const lanePlan = await laneTool.execute("tool-call-id", {
			action: "plan",
			lane: "control-flow",
			target: "./license",
		});
		expect(lanePlan.content[0]?.text).toContain("lane: control-flow");
		expect(lanePlan.content[0]?.text).toContain("case_memory_migrations:");
		expect(lanePlan.content[0]?.text).toContain("r2 -A");
		expect(lanePlan.content[0]?.text).toContain("objdump");
		const missionAfterPlan = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as {
			gates: Array<{ name: string; status: string }>;
		};
		expect(missionAfterPlan.gates.find((gate) => gate.name === "repro_commands_ready")?.status).toBe("done");

		execCalls.length = 0;
		const laneRun = await laneTool.execute("tool-call-id", {
			action: "run",
			lane: "control-flow",
			target: "./license",
		});
		expect(execCalls).toHaveLength(1);
		expect(execCalls[0]?.command).toBe("bash");
		expect(execCalls[0]?.args.join(" ")).toContain("r2 -A");
		expect(execCalls[0]?.args.join(" ")).toContain("objdump");
		expect(laneRun.content[0]?.text).toContain("evidence_artifact:");
		expect(laneRun.content[0]?.text).toContain("evidence_ledger:");
		expect(laneRun.content[0]?.text).toContain("auto_lane_update: control-flow -> runtime-proof");
		expect(laneRun.content[0]?.text).toContain("analysis:");
		expect(laneRun.content[0]?.text).toContain("comparison/verification anchors");
		expect(laneRun.content[0]?.text).toContain("followup_commands:");
		expect(laneRun.content[0]?.text).toContain("runtime-compare-breakpoints");
		const artifactPath = /evidence_artifact: (.+)/.exec(laneRun.content[0]?.text ?? "")?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(existsSync(artifactPath!)).toBe(true);
		expect(readFileSync(artifactPath!, "utf-8")).toContain("REPI Lane Run Artifact");
		expect(readFileSync(artifactPath!, "utf-8")).toContain("## Auto analysis");
		expect(readFileSync(join(agentDir, "recon", "evidence", "ledger.md"), "utf-8")).toContain(
			"lane-run control-flow exit 0",
		);
		const missionAfterRun = JSON.parse(readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8")) as {
			lanes: Array<{ name: string; status?: string; note?: string; next: string[] }>;
		};
		const controlFlowLane = missionAfterRun.lanes.find((lane) => lane.name === "control-flow");
		const runtimeLane = missionAfterRun.lanes.find((lane) => lane.name === "runtime-proof");
		expect(controlFlowLane?.status).toBe("done");
		expect(controlFlowLane?.note).toContain("last_run exit=0");
		expect(runtimeLane?.status).toBe("in_progress");
		expect(runtimeLane?.next.join("\n")).toContain("[auto:runtime-compare-breakpoints]");
		expect(runtimeLane?.note).toContain("auto_from=control-flow");

		const laneRunAuto = await laneTool.execute("tool-call-id", {
			action: "run-auto",
			lane: "runtime-proof",
			target: "./license",
			max: 1,
		});
		expect(execCalls).toHaveLength(2);
		expect(laneRunAuto.content[0]?.text).toContain("run_auto_summary:");
		expect(laneRunAuto.content[0]?.text).toContain("adaptive_decisions:");
		expect(laneRunAuto.content[0]?.text).toContain("adaptive_decision:");
		expect(laneRunAuto.content[0]?.text).toContain("steps_executed: 1");
		expect(laneRunAuto.content[0]?.text).toContain("playbook_path:");
		expect(laneRunAuto.content[0]?.text).toContain("field_journal_anchor:");
		expect(laneRunAuto.content[0]?.text).toContain("evolution_anchor:");
		expect(laneRunAuto.content[0]?.text).toContain("## run-auto step 1: runtime-proof");
		expect(laneRunAuto.content[0]?.text).toContain("auto_lane_update: runtime-proof -> report");
		const playbookPath = /playbook_path: (.+)/.exec(laneRunAuto.content[0]?.text ?? "")?.[1]?.trim();
		expect(playbookPath).toBeDefined();
		expect(existsSync(playbookPath!)).toBe(true);
		expect(readFileSync(playbookPath!, "utf-8")).toContain("REPI Auto Playbook");
		expect(readFileSync(playbookPath!, "utf-8")).toContain("quality_score:");
		expect(readFileSync(playbookPath!, "utf-8")).toContain("auto_advance_count:");
		expect(readFileSync(join(agentDir, "recon", "memory", "field-journal.md"), "utf-8")).toContain(
			"run-auto-playbook",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "evolution-log.md"), "utf-8")).toContain(
			"run-auto playbook",
		);
		const missionAfterRunAuto = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as {
			lanes: Array<{ name: string; status?: string; note?: string; next: string[] }>;
			gates: Array<{ name: string; status: string }>;
		};
		expect(missionAfterRunAuto.lanes.find((lane) => lane.name === "runtime-proof")?.status).toBe("done");
		const reportLane = missionAfterRunAuto.lanes.find((lane) => lane.name === "report");
		expect(reportLane?.status).toBe("in_progress");
		expect(reportLane?.next.join("\n")).toContain("[auto:runtime-compare-breakpoints]");
		expect(missionAfterRunAuto.gates.find((gate) => gate.name === "memory_or_evolution_written")?.status).toBe(
			"done",
		);

		const memoryAugmentedPlan = await laneTool.execute("tool-call-id", {
			action: "plan",
			lane: "runtime-proof",
			target: "./fresh-license",
		});
		expect(memoryAugmentedPlan.content[0]?.text).toContain("memory_reuse:");
		expect(memoryAugmentedPlan.content[0]?.text).toContain("memory:");
		expect(memoryAugmentedPlan.content[0]?.text).toContain("quality=");
		expect(memoryAugmentedPlan.content[0]?.text).toContain("./fresh-license");
		expect(memoryAugmentedPlan.content[0]?.text).toContain("case_index_hits:");

		const mapTool = tools.get("re_map") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const passiveMap = await mapTool.execute("tool-call-id", {
			target: "./license",
			depth: 2,
		});
		expect(execCalls).toHaveLength(3);
		expect(execCalls[2]?.args.join(" ")).toContain("route-auth-search");
		expect(passiveMap.content[0]?.text).toContain("passive_map_result:");
		expect(passiveMap.content[0]?.text).toContain("map_artifact:");
		const mapArtifactPath = /map_artifact: (.+)/.exec(passiveMap.content[0]?.text ?? "")?.[1]?.trim();
		expect(mapArtifactPath).toBeDefined();
		expect(existsSync(mapArtifactPath!)).toBe(true);
		expect(readFileSync(mapArtifactPath!, "utf-8")).toContain("REPI Passive Map Artifact");
		expect(readFileSync(join(agentDir, "recon", "evidence", "ledger.md"), "utf-8")).toContain("passive-map");

		const mapInferredPlan = await laneTool.execute("tool-call-id", {
			action: "plan",
			lane: "control-flow",
		});
		expect(mapInferredPlan.content[0]?.text).toContain("target: ./license");
		expect(mapInferredPlan.content[0]?.text).toContain("map_reuse:");
		expect(mapInferredPlan.content[0]?.text).toContain("map_inferred_target: ./license");
		expect(mapInferredPlan.content[0]?.text).toContain("map-artifact-context");
		expect(mapInferredPlan.content[0]?.text).toContain("sed -n '1,180p'");

		const autopilotTool = tools.get("re_autopilot") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		writeFileSync(
			join(agentDir, "recon", "tools", "tool-index.md"),
			[
				"# REPI Tool Index",
				"",
				"| Tool | Present | Path | Version probe |",
				"|---|---:|---|---|",
				"| file | yes | /usr/bin/file | file |",
				"| sha256sum | yes | /usr/bin/sha256sum | sha256sum |",
				"| readelf | yes | /usr/bin/readelf | readelf |",
				"| strings | yes | /usr/bin/strings | strings |",
				"| objdump | yes | /usr/bin/objdump | objdump |",
				"| rabin2 | yes | /usr/bin/rabin2 | rabin2 |",
				"| r2 | yes | /usr/bin/r2 | r2 |",
				"| checksec | no |  |  |",
				"| python3 | yes | /usr/bin/python3 | Python |",
				"",
			].join("\n"),
		);
		const degradedLaneRun = await laneTool.execute("tool-call-id", {
			action: "run",
			lane: "triage",
			target: "./license",
		});
		expect(execCalls).toHaveLength(4);
		expect(degradedLaneRun.content[0]?.text).toContain("execution_strategy:");
		expect(degradedLaneRun.content[0]?.text).toContain("mode: degraded");
		expect(degradedLaneRun.content[0]?.text).toContain("fallback_commands:");
		expect(execCalls[3]?.args.join(" ")).toContain("rabin2 -I");
		expect(execCalls[3]?.args.join(" ")).not.toContain("checksec --file");

		const autopilotRun = await autopilotTool.execute("tool-call-id", {
			action: "run",
			task: "分析 ELF 许可证校验",
			target: "./license",
			maxAutoSteps: 1,
		});
		expect(execCalls).toHaveLength(7);
		expect(autopilotRun.content[0]?.text).toContain("autopilot_result:");
		expect(autopilotRun.content[0]?.text).toContain("bootstrap_plan:");
		expect(autopilotRun.content[0]?.text).toContain("recommended_tools:");
		expect(autopilotRun.content[0]?.text).toContain("next_bootstrap_command:");
		expect(autopilotRun.content[0]?.text).toContain("execution_strategy:");
		expect(autopilotRun.content[0]?.text).toContain("case_memory_migrations:");
		expect(autopilotRun.content[0]?.text).toContain("case_memory_lane_plan:");
		expect(autopilotRun.content[0]?.text).toContain("mode: degraded");
		expect(autopilotRun.content[0]?.text).toContain("fallback_commands:");
		expect(autopilotRun.content[0]?.text).toContain("checksec");
		expect(autopilotRun.content[0]?.text).toContain("r2");
		expect(execCalls[5]?.args.join(" ")).toContain("rabin2 -I");
		expect(execCalls[5]?.args.join(" ")).not.toContain("checksec --file");
		expect(autopilotRun.content[0]?.text).toContain("passive_map_result:");
		expect(autopilotRun.content[0]?.text).toContain("run_result:");
		expect(autopilotRun.content[0]?.text).toContain("run_auto_summary:");
		expect(autopilotRun.content[0]?.text).toContain("completion_status:");
		expect(autopilotRun.content[0]?.text).toContain("field_journal_anchor:");

		const evidenceTool = tools.get("re_evidence") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const evidenceResult = await evidenceTool.execute("tool-call-id", {
			action: "append",
			kind: "runtime",
			title: "strcmp hook",
			fact: "runtime compared candidate with expected license bytes",
		});
		expect(evidenceResult.content[0]?.text).toContain("P1 runtime");
		expect(readFileSync(join(agentDir, "recon", "evidence", "ledger.md"), "utf-8")).toContain(
			"expected license bytes",
		);

		const graphTool = tools.get("re_graph") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const graphResult = await graphTool.execute("tool-call-id", { action: "build" });
		expect(graphResult.content[0]?.text).toContain("attack_graph:");
		expect(graphResult.content[0]?.text).toContain("graph_artifact:");
		expect(graphResult.content[0]?.text).toContain("critical_path:");
		expect(graphResult.content[0]?.text).toContain("operator_next_actions:");
		const graphPath = /graph_artifact: (.+)/.exec(graphResult.content[0]?.text ?? "")?.[1]?.trim();
		expect(graphPath).toBeDefined();
		expect(existsSync(graphPath!)).toBe(true);
		expect(readFileSync(graphPath!, "utf-8")).toContain("REPI Attack Graph Artifact");
		expect(readFileSync(graphPath!, "utf-8")).toContain("## Nodes");
		expect(readFileSync(join(agentDir, "recon", "evidence", "ledger.md"), "utf-8")).toContain("attack-graph");
		const graphShow = await graphTool.execute("tool-call-id", { action: "show" });
		expect(graphShow.content[0]?.text).toContain("REPI Attack Graph Artifact");

		const chainTool = tools.get("re_exploit_chain") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const chainPlan = await chainTool.execute("tool-call-id", {
			action: "plan",
			target: "./license",
		});
		expect(chainPlan.content[0]?.text).toContain("exploit_chain:");
		expect(chainPlan.content[0]?.text).toContain("chain_artifact:");
		expect(chainPlan.content[0]?.text).toContain("chain_nodes:");
		expect(chainPlan.content[0]?.text).toContain("proof_path:");
		expect(chainPlan.content[0]?.text).toContain("exploit_path:");
		expect(chainPlan.content[0]?.text).toContain("evidence_gaps:");
		expect(chainPlan.content[0]?.text).toContain("operator_feedback:");
		expect(chainPlan.content[0]?.text).toContain("operator_feedback_queue:");
		expect(chainPlan.content[0]?.text).toContain("replay_commands:");
		expect(chainPlan.content[0]?.text).toContain("operator_queue:");
		expect(chainPlan.content[0]?.text).toContain("next_chain_command:");
		const chainPath = /chain_artifact: (.+)/.exec(chainPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(chainPath).toBeDefined();
		expect(existsSync(chainPath!)).toBe(true);
		expect(readFileSync(chainPath!, "utf-8")).toContain("REPI Exploit Chain Artifact");
		expect(readFileSync(chainPath!, "utf-8")).toContain("primitive_or_state_transition");
		const missionAfterChain = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterChain.gates.find((gate) => gate.name === "exploit_chain_ready")?.status).toBe("done");

		await missionTool.execute("tool-call-id", {
			action: "new",
			task: "Web API JWT auth websocket replay cloud identity",
		});
		const campaignTool = tools.get("re_campaign") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const campaignResult = await campaignTool.execute("tool-call-id", {
			action: "plan",
			target: "https://target.local/app",
		});
		expect(campaignResult.content[0]?.text).toContain("campaign_graph:");
		expect(campaignResult.content[0]?.text).toContain("campaign_artifact:");
		expect(campaignResult.content[0]?.text).toContain("phases:");
		expect(campaignResult.content[0]?.text).toContain("web-authz");
		expect(campaignResult.content[0]?.text).toContain("re_live_browser plan https://target.local/app");
		expect(campaignResult.content[0]?.text).toContain("re_web_authz_state plan https://target.local/app");
		expect(campaignResult.content[0]?.text).toContain("credential-identity");
		expect(campaignResult.content[0]?.text).toContain("cloud-container");
		expect(campaignResult.content[0]?.text).toContain("pivot_candidates:");
		expect(campaignResult.content[0]?.text).toContain("evidence_gaps:");
		expect(campaignResult.content[0]?.text).toContain("tool_gaps:");
		expect(campaignResult.content[0]?.text).toContain("operator_next_actions:");
		expect(campaignResult.content[0]?.text).toContain("next_bootstrap_command:");
		const campaignPath = /campaign_artifact: (.+)/.exec(campaignResult.content[0]?.text ?? "")?.[1]?.trim();
		expect(campaignPath).toBeDefined();
		expect(existsSync(campaignPath!)).toBe(true);
		expect(readFileSync(campaignPath!, "utf-8")).toContain("REPI Campaign Artifact");
		expect(readFileSync(campaignPath!, "utf-8")).toContain("campaign_graph:");
		expect(readFileSync(join(agentDir, "recon", "evidence", "ledger.md"), "utf-8")).toContain("campaign-plan");
		const campaignShow = await campaignTool.execute("tool-call-id", { action: "show" });
		expect(campaignShow.content[0]?.text).toContain("REPI Campaign Artifact");

		const operationTool = tools.get("re_operation") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const operationPlan = await operationTool.execute("tool-call-id", {
			action: "next",
			target: "https://target.local/app",
		});
		expect(operationPlan.content[0]?.text).toContain("operation_queue:");
		expect(operationPlan.content[0]?.text).toContain("operation_artifact:");
		expect(operationPlan.content[0]?.text).toContain("phase_runner:");
		expect(operationPlan.content[0]?.text).toContain("re_live_browser plan/run");
		expect(operationPlan.content[0]?.text).toContain("re_web_authz_state plan/run");
		expect(operationPlan.content[0]?.text).toContain(
			"re_verifier/re_compiler/re_replayer/re_autofix/re_proof_loop/re_knowledge_graph",
		);
		expect(operationPlan.content[0]?.text).toContain("steps:");
		expect(operationPlan.content[0]?.text).toContain("re_live_browser plan https://target.local/app");
		expect(operationPlan.content[0]?.text).toContain("re_web_authz_state plan https://target.local/app");
		expect(operationPlan.content[0]?.text).toContain("next_ready_step:");
		expect(operationPlan.content[0]?.text).toContain("next_operation_command:");
		const operationPlanPath = /operation_artifact: (.+)/.exec(operationPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(operationPlanPath).toBeDefined();
		expect(existsSync(operationPlanPath!)).toBe(true);
		expect(readFileSync(operationPlanPath!, "utf-8")).toContain("REPI Operation Artifact");

		const operationRun = await operationTool.execute("tool-call-id", {
			action: "run",
			target: "https://target.local/app",
			maxSteps: 2,
		});
		expect(operationRun.content[0]?.text).toContain("operation_queue:");
		expect(operationRun.content[0]?.text).toContain("phase_runner:");
		expect(operationRun.content[0]?.text).toContain("executed_steps: 2");
		expect(operationRun.content[0]?.text).toContain("live_browser:");
		expect(operationRun.content[0]?.text).toContain("web_authz_state:");
		expect(operationRun.content[0]?.text).toContain("next_operation_command:");
		const operationRunPath = /operation_artifact: (.+)/.exec(operationRun.content[0]?.text ?? "")?.[1]?.trim();
		expect(operationRunPath).toBeDefined();
		expect(existsSync(operationRunPath!)).toBe(true);
		expect(readFileSync(operationRunPath!, "utf-8")).toContain("REPI Operation Artifact");
		expect(readFileSync(join(agentDir, "recon", "evidence", "ledger.md"), "utf-8")).toContain("operation-run");
		const missionAfterOperation = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterOperation.gates.find((gate) => gate.name === "operation_queue_ready")?.status).toBe("done");

		const delegateTool = tools.get("re_delegate") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const delegatePlan = await delegateTool.execute("tool-call-id", {
			action: "plan",
			target: "https://target.local/app",
		});
		expect(delegatePlan.content[0]?.text).toContain("delegation_plan:");
		expect(delegatePlan.content[0]?.text).toContain("delegation_artifact:");
		expect(delegatePlan.content[0]?.text).toContain("worker_packets:");
		expect(delegatePlan.content[0]?.text).toContain("evidence_contract:");
		expect(delegatePlan.content[0]?.text).toContain("merge_queue:");
		expect(delegatePlan.content[0]?.text).toContain("specialist_coverage:");
		expect(delegatePlan.content[0]?.text).toContain("adaptive_routing_hints:");
		expect(delegatePlan.content[0]?.text).toContain("worker_promotion_queue:");
		expect(delegatePlan.content[0]?.text).toContain("next_delegate_command:");
		expect(delegatePlan.content[0]?.text).toContain("web-authz");
		const delegatePath = /delegation_artifact: (.+)/.exec(delegatePlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(delegatePath).toBeDefined();
		expect(existsSync(delegatePath!)).toBe(true);
		expect(readFileSync(delegatePath!, "utf-8")).toContain("REPI Delegation Artifact");
		expect(readFileSync(delegatePath!, "utf-8")).toContain("worker_packets:");
		const delegateMerge = await delegateTool.execute("tool-call-id", { action: "merge" });
		expect(delegateMerge.content[0]?.text).toContain("delegation_plan:");
		expect(delegateMerge.content[0]?.text).toContain("merge_summary:");
		expect(delegateMerge.content[0]?.text).toContain("next_delegate_command: re_complete audit");
		expect(readFileSync(join(agentDir, "recon", "evidence", "ledger.md"), "utf-8")).toContain("delegation-merge");
		const missionAfterDelegation = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterDelegation.gates.find((gate) => gate.name === "delegation_packets_ready")?.status).toBe(
			"done",
		);

		const swarmTool = tools.get("re_swarm") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const swarmPlan = await swarmTool.execute("tool-call-id", {
			action: "plan",
			target: "https://target.local/app",
		});
		expect(swarmPlan.content[0]?.text).toContain("swarm_plan:");
		expect(swarmPlan.content[0]?.text).toContain("swarm_artifact:");
		expect(swarmPlan.content[0]?.text).toContain("worker_runtime_packets:");
		expect(swarmPlan.content[0]?.text).toContain("parallel_groups:");
		expect(swarmPlan.content[0]?.text).toContain("merge_protocol:");
		expect(swarmPlan.content[0]?.text).toContain("collision_matrix:");
		expect(swarmPlan.content[0]?.text).toContain("execution_audit:");
		expect(swarmPlan.content[0]?.text).toContain("coverage_matrix:");
		expect(swarmPlan.content[0]?.text).toContain("retry_queue:");
		expect(swarmPlan.content[0]?.text).toContain("commander_next_actions:");
		expect(swarmPlan.content[0]?.text).toContain("next_swarm_command:");
		const swarmPath = /swarm_artifact: (.+)/.exec(swarmPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(swarmPath).toBeDefined();
		expect(existsSync(swarmPath!)).toBe(true);
		expect(readFileSync(swarmPath!, "utf-8")).toContain("REPI Swarm Artifact");
		const swarmRun = await swarmTool.execute("tool-call-id", {
			action: "run",
			target: "https://target.local/app",
			maxWorkers: 2,
			maxCommands: 1,
		});
		expect(swarmRun.content[0]?.text).toContain("swarm_plan:");
		expect(swarmRun.content[0]?.text).toContain("mode: run");
		expect(swarmRun.content[0]?.text).toContain("worker_executions:");
		expect(swarmRun.content[0]?.text).toContain("worker_results:");
		expect(swarmRun.content[0]?.text).toContain("merge_digest:");
		expect(swarmRun.content[0]?.text).toContain("execution_audit:");
		expect(swarmRun.content[0]?.text).toContain("coverage_matrix:");
		expect(swarmRun.content[0]?.text).toContain("retry_queue:");
		expect(swarmRun.content[0]?.text).toContain("memory_swarm_writeback:");
		expect(swarmRun.content[0]?.text).toContain("status=pass");
		expect(swarmRun.content[0]?.text).toContain("next_swarm_command: re_swarm merge");
		const swarmRunPath = /swarm_artifact: (.+)/.exec(swarmRun.content[0]?.text ?? "")?.[1]?.trim();
		expect(swarmRunPath).toBeDefined();
		expect(existsSync(swarmRunPath!)).toBe(true);
		expect(readFileSync(swarmRunPath!, "utf-8")).toContain("worker_executions:");
		expect(readFileSync(swarmRunPath!, "utf-8")).toContain("execution_audit:");
		expect(readFileSync(swarmRunPath!, "utf-8")).toContain("coverage_matrix:");
		expect(readFileSync(swarmRunPath!, "utf-8")).toContain("retry_queue:");
		expect(readFileSync(join(agentDir, "recon", "memory", "events.jsonl"), "utf-8")).toContain(
			"memory-swarm-writeback",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "store-report.json"), "utf-8")).toContain("MemoryStoreV5");
		expect(swarmRun.content[0]?.text).toContain("structured_claim_merge:");
		expect(swarmRun.content[0]?.text).toContain("status=blocked");
		const structuredClaimMergePath = swarmRunPath!.replace(/\.md$/i, "-structured-claim-merge.json");
		expect(existsSync(structuredClaimMergePath)).toBe(true);
		expect(readFileSync(structuredClaimMergePath, "utf-8")).toContain("StructuredClaimMergeV1");
		expect(readFileSync(structuredClaimMergePath, "utf-8")).toContain("strict_final_claim_promotion");
		expect(readFileSync(join(agentDir, "recon", "memory", "swarm-run-board.md"), "utf-8")).toContain(
			"Swarm Run Board",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "swarm-run-board.md"), "utf-8")).toContain(
			"Execution audit",
		);
		const swarmMerge = await swarmTool.execute("tool-call-id", { action: "merge" });
		expect(swarmMerge.content[0]?.text).toContain("swarm_plan:");
		expect(swarmMerge.content[0]?.text).toContain("coverage_matrix:");
		expect(swarmMerge.content[0]?.text).toContain("next_swarm_command: re_supervisor review");
		expect(readFileSync(join(agentDir, "recon", "memory", "swarm-board.md"), "utf-8")).toContain("Swarm Board");
		expect(readFileSync(join(agentDir, "recon", "memory", "swarm-board.md"), "utf-8")).toContain("Coverage matrix");
		const missionAfterSwarm = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterSwarm.gates.find((gate) => gate.name === "swarm_plan_ready")?.status).toBe("done");

		const supervisorTool = tools.get("re_supervisor") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const supervisorReview = await supervisorTool.execute("tool-call-id", {
			action: "review",
			target: "https://target.local/app",
		});
		expect(supervisorReview.content[0]?.text).toContain("supervisor_review:");
		expect(supervisorReview.content[0]?.text).toContain("supervisor_artifact:");
		expect(supervisorReview.content[0]?.text).toContain("supervisor_verdict:");
		expect(supervisorReview.content[0]?.text).toContain("swarm_artifact:");
		expect(supervisorReview.content[0]?.text).toContain("worker_reviews:");
		expect(supervisorReview.content[0]?.text).toContain("conflict_matrix:");
		expect(supervisorReview.content[0]?.text).toContain("repair_queue:");
		expect(supervisorReview.content[0]?.text).toContain("commander_merge_queue:");
		expect(supervisorReview.content[0]?.text).toContain("commander_merge_budget:");
		expect(supervisorReview.content[0]?.text).toContain("worker_scoreboard:");
		expect(supervisorReview.content[0]?.text).toContain("priority_queue:");
		expect(supervisorReview.content[0]?.text).toContain("release_gate_metadata:");
		expect(supervisorReview.content[0]?.text).toContain("strict_claim_gate:");
		expect(supervisorReview.content[0]?.text).toContain("claim_gate_result:");
		expect(supervisorReview.content[0]?.text).toContain("next_supervisor_command:");
		const supervisorPath = /supervisor_artifact: (.+)/.exec(supervisorReview.content[0]?.text ?? "")?.[1]?.trim();
		expect(supervisorPath).toBeDefined();
		expect(existsSync(supervisorPath!)).toBe(true);
		expect(readFileSync(supervisorPath!, "utf-8")).toContain("REPI Supervisor Artifact");
		expect(readFileSync(supervisorPath!, "utf-8")).toContain("worker_reviews:");
		expect(readFileSync(supervisorPath!, "utf-8")).toContain("commander_merge_queue:");
		expect(readFileSync(supervisorPath!, "utf-8")).toContain("commander_merge_budget:");
		expect(readFileSync(join(agentDir, "recon", "memory", "commander-merge-board.md"), "utf-8")).toContain(
			"Commander Merge Board",
		);
		const supervisorRepair = await supervisorTool.execute("tool-call-id", { action: "repair" });
		expect(supervisorRepair.content[0]?.text).toContain("supervisor_review:");
		expect(supervisorRepair.content[0]?.text).toContain("mode: repair");
		expect(supervisorRepair.content[0]?.text).toContain("repair_queue:");
		expect(readFileSync(join(agentDir, "recon", "evidence", "ledger.md"), "utf-8")).toContain("supervisor-repair");
		const missionAfterSupervisor = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterSupervisor.gates.find((gate) => gate.name === "supervisor_review_ready")?.status).toBe(
			"blocked",
		);

		const reflectTool = tools.get("re_reflect") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const reflectPlan = await reflectTool.execute("tool-call-id", { action: "plan" });
		expect(reflectPlan.content[0]?.text).toContain("reflection_cycle:");
		expect(reflectPlan.content[0]?.text).toContain("reflection_artifact:");
		expect(reflectPlan.content[0]?.text).toContain("lessons:");
		expect(reflectPlan.content[0]?.text).toContain("failure_patterns:");
		expect(reflectPlan.content[0]?.text).toContain("reuse_rules:");
		expect(reflectPlan.content[0]?.text).toContain("repair_playbook:");
		expect(reflectPlan.content[0]?.text).toContain("next_reflect_command:");
		const reflectPlanPath = /reflection_artifact: (.+)/.exec(reflectPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(reflectPlanPath).toBeDefined();
		expect(existsSync(reflectPlanPath!)).toBe(true);
		expect(readFileSync(reflectPlanPath!, "utf-8")).toContain("REPI Reflection Artifact");

		const reflectWrite = await reflectTool.execute("tool-call-id", { action: "write" });
		expect(reflectWrite.content[0]?.text).toContain("reflection_cycle:");
		expect(reflectWrite.content[0]?.text).toContain("playbook_path:");
		expect(reflectWrite.content[0]?.text).toContain("field_journal_anchor:");
		expect(reflectWrite.content[0]?.text).toContain("evolution_anchor:");
		const reflectWritePath = /reflection_artifact: (.+)/.exec(reflectWrite.content[0]?.text ?? "")?.[1]?.trim();
		expect(reflectWritePath).toBeDefined();
		expect(existsSync(reflectWritePath!)).toBe(true);
		const reflectPlaybookPath = /playbook_path: (.+)/.exec(reflectWrite.content[0]?.text ?? "")?.[1]?.trim();
		expect(reflectPlaybookPath).toBeDefined();
		expect(existsSync(reflectPlaybookPath!)).toBe(true);
		expect(readFileSync(reflectPlaybookPath!, "utf-8")).toContain("REPI Reflection Playbook");
		expect(readFileSync(reflectPlaybookPath!, "utf-8")).toContain("Worker routing / promotion");
		expect(readFileSync(join(agentDir, "recon", "memory", "field-journal.md"), "utf-8")).toContain(
			"supervisor-reflection",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "evolution-log.md"), "utf-8")).toContain(
			"supervisor reflection",
		);
		const missionAfterReflect = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterReflect.gates.find((gate) => gate.name === "reflection_memory_ready")?.status).toBe("done");

		const contextTool = tools.get("re_context") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const contextPack = await contextTool.execute("tool-call-id", {
			action: "pack",
			target: "https://target.local/app",
		});
		expect(contextPack.content[0]?.text).toContain("context_pack:");
		expect(contextPack.content[0]?.text).toContain("context_artifact:");
		expect(contextPack.content[0]?.text).toContain("resume_brief:");
		expect(contextPack.content[0]?.text).toContain("artifact_index:");
		expect(contextPack.content[0]?.text).toContain("repair_queue:");
		expect(contextPack.content[0]?.text).toContain("commander_merge_budget:");
		expect(contextPack.content[0]?.text).toContain("worker_scoreboard:");
		expect(contextPack.content[0]?.text).toContain("swarm_retry_queue:");
		expect(contextPack.content[0]?.text).toContain("swarm_retry_queue=");
		expect(contextPack.content[0]?.text).toContain("autonomous_execution_budget:");
		expect(contextPack.content[0]?.text).toContain("dispatcher_score_decay:");
		expect(contextPack.content[0]?.text).toContain("case_memory_lane_plan:");
		expect(contextPack.content[0]?.text).toContain("case_memory_next_commands:");
		expect(contextPack.content[0]?.text).toContain("reflection_reuse_rules:");
		expect(contextPack.content[0]?.text).toContain("next_operator_commands:");
		expect(contextPack.content[0]?.text).toContain("next_context_command:");
		const contextPackPath = /context_artifact: (.+)/.exec(contextPack.content[0]?.text ?? "")?.[1]?.trim();
		expect(contextPackPath).toBeDefined();
		expect(existsSync(contextPackPath!)).toBe(true);
		expect(readFileSync(contextPackPath!, "utf-8")).toContain("REPI Context Pack Artifact");
		expect(readFileSync(contextPackPath!, "utf-8")).toContain("## Mission snapshot");

		const contextResume = await contextTool.execute("tool-call-id", { action: "resume" });
		expect(contextResume.content[0]?.text).toContain("context_pack:");
		expect(contextResume.content[0]?.text).toContain("mode: resume");
		expect(contextResume.content[0]?.text).toContain("next_operator_commands:");
		const missionAfterContext = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterContext.gates.find((gate) => gate.name === "context_pack_ready")?.status).toBe("done");

		const operatorTool = tools.get("re_operator") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const operatorPlan = await operatorTool.execute("tool-call-id", { action: "plan" });
		expect(operatorPlan.content[0]?.text).toContain("operator_queue:");
		expect(operatorPlan.content[0]?.text).toContain("operator_artifact:");
		expect(operatorPlan.content[0]?.text).toContain("dispatcher_policy:");
		expect(operatorPlan.content[0]?.text).toContain("commander_runtime_policy:");
		expect(operatorPlan.content[0]?.text).toContain("operator_feedback:");
		expect(operatorPlan.content[0]?.text).toContain("operator_feedback_queue:");
		expect(operatorPlan.content[0]?.text).toContain("dispatcher_fallback_plan:");
		expect(operatorPlan.content[0]?.text).toContain("dispatcher_feedback_scoreboard:");
		expect(operatorPlan.content[0]?.text).toContain("dispatcher_learning_hints:");
		expect(operatorPlan.content[0]?.text).toContain("autonomous_execution_budget:");
		expect(operatorPlan.content[0]?.text).toContain("dispatcher_score_decay:");
		expect(operatorPlan.content[0]?.text).toContain("high_score_promotions:");
		expect(operatorPlan.content[0]?.text).toContain("swarm_retry_queue=");
		expect(operatorPlan.content[0]?.text).toContain("case_memory_lane_plan:");
		expect(operatorPlan.content[0]?.text).toContain("case_memory_dispatch_report:");
		expect(operatorPlan.content[0]?.text).toContain("verification_matrix:");
		expect(operatorPlan.content[0]?.text).toContain("escalation_queue:");
		expect(operatorPlan.content[0]?.text).toContain("next_operator_command:");
		const operatorPlanPath = /operator_artifact: (.+)/.exec(operatorPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(operatorPlanPath).toBeDefined();
		expect(existsSync(operatorPlanPath!)).toBe(true);
		expect(readFileSync(operatorPlanPath!, "utf-8")).toContain("REPI Operator Artifact");

		const operatorDispatch = await operatorTool.execute("tool-call-id", { action: "dispatch", maxSteps: 1 });
		expect(operatorDispatch.content[0]?.text).toContain("operator_queue:");
		expect(operatorDispatch.content[0]?.text).toContain("mode: dispatch");
		expect(operatorDispatch.content[0]?.text).toContain("executed_steps: 1");
		expect(operatorDispatch.content[0]?.text).toContain("commander_dispatch_report:");
		const operatorVerify = await operatorTool.execute("tool-call-id", { action: "verify" });
		expect(operatorVerify.content[0]?.text).toContain("mode: verify");
		expect(operatorVerify.content[0]?.text).toContain("verification_matrix:");
		const missionAfterOperator = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterOperator.gates.find((gate) => gate.name === "operator_queue_ready")?.status).toBe("done");

		const verifierTool = tools.get("re_verifier") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const verifierCheck = await verifierTool.execute("tool-call-id", { action: "check" });
		expect(verifierCheck.content[0]?.text).toContain("verifier_matrix:");
		expect(verifierCheck.content[0]?.text).toContain("verifier_artifact:");
		expect(verifierCheck.content[0]?.text).toContain("operator_feedback:");
		expect(verifierCheck.content[0]?.text).toContain("category=swarm_retry_queue");
		expect(verifierCheck.content[0]?.text).toContain("assertions:");
		expect(verifierCheck.content[0]?.text).toContain("evidence_bindings:");
		expect(verifierCheck.content[0]?.text).toContain("counter_evidence:");
		expect(verifierCheck.content[0]?.text).toContain("contradictions:");
		expect(verifierCheck.content[0]?.text).toContain("next_verifier_command:");
		const verifierPath = /verifier_artifact: (.+)/.exec(verifierCheck.content[0]?.text ?? "")?.[1]?.trim();
		expect(verifierPath).toBeDefined();
		expect(existsSync(verifierPath!)).toBe(true);
		expect(readFileSync(verifierPath!, "utf-8")).toContain("REPI Verifier Artifact");

		const verifierMatrix = await verifierTool.execute("tool-call-id", { action: "matrix" });
		expect(verifierMatrix.content[0]?.text).toContain("mode: matrix");
		expect(verifierMatrix.content[0]?.text).toContain("gaps:");
		const missionAfterVerifier = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterVerifier.gates.find((gate) => gate.name === "verifier_matrix_ready")?.status).toBe("done");

		const compilerTool = tools.get("re_compiler") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const compilerDraft = await compilerTool.execute("tool-call-id", { action: "draft" });
		expect(compilerDraft.content[0]?.text).toContain("compiler_report:");
		expect(compilerDraft.content[0]?.text).toContain("compiler_artifact:");
		expect(compilerDraft.content[0]?.text).toContain("operator_feedback:");
		expect(compilerDraft.content[0]?.text).toContain("category=swarm_retry_queue");
		expect(compilerDraft.content[0]?.text).toContain("supervisor_artifact:");
		expect(compilerDraft.content[0]?.text).toContain("release_gate_metadata:");
		expect(compilerDraft.content[0]?.text).toContain("strict_claim_gate:");
		expect(compilerDraft.content[0]?.text).toContain("claim_gate_result:");
		expect(compilerDraft.content[0]?.text).toContain("structured_claim_merge_gate:");
		expect(compilerDraft.content[0]?.text).toContain("status=blocked");
		expect(compilerDraft.content[0]?.text).toContain("structured claim merge error:");
		expect(compilerDraft.content[0]?.text).toContain("key_evidence_block:");
		expect(compilerDraft.content[0]?.text).toContain("repro_commands:");
		expect(compilerDraft.content[0]?.text).toContain("contradictions:");
		expect(compilerDraft.content[0]?.text).toContain("next_operator_queue:");
		expect(compilerDraft.content[0]?.text).toContain("next_compiler_command:");
		const compilerPath = /compiler_artifact: (.+)/.exec(compilerDraft.content[0]?.text ?? "")?.[1]?.trim();
		expect(compilerPath).toBeDefined();
		expect(existsSync(compilerPath!)).toBe(true);
		expect(readFileSync(compilerPath!, "utf-8")).toContain("REPI Compiler Artifact");
		const missionAfterCompiler = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterCompiler.gates.find((gate) => gate.name === "compiler_ready")?.status).toBe("done");

		const replayerTool = tools.get("re_replayer") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const replayPlan = await replayerTool.execute("tool-call-id", { action: "plan" });
		expect(replayPlan.content[0]?.text).toContain("replay_matrix:");
		expect(replayPlan.content[0]?.text).toContain("replay_artifact:");
		expect(replayPlan.content[0]?.text).toContain("compiler_artifact:");
		expect(replayPlan.content[0]?.text).toContain("operator_feedback:");
		expect(replayPlan.content[0]?.text).toContain("category=swarm_retry_queue");
		expect(replayPlan.content[0]?.text).toContain("steps:");
		expect(replayPlan.content[0]?.text).toContain("replay_matrix_rows:");
		expect(replayPlan.content[0]?.text).toContain("next_replay_command:");
		const replayPlanPath = /replay_artifact: (.+)/.exec(replayPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(replayPlanPath).toBeDefined();
		expect(existsSync(replayPlanPath!)).toBe(true);
		expect(readFileSync(replayPlanPath!, "utf-8")).toContain("REPI Replayer Artifact");

		const replayRun = await replayerTool.execute("tool-call-id", { action: "run", maxSteps: 2 });
		expect(replayRun.content[0]?.text).toContain("replay_matrix:");
		expect(replayRun.content[0]?.text).toContain("mode: run");
		expect(replayRun.content[0]?.text).toContain("executed_steps:");
		expect(replayRun.content[0]?.text).toContain("stdout_sha256=");
		expect(replayRun.content[0]?.text).toContain("next_replay_actions:");
		const replayRunPath = /replay_artifact: (.+)/.exec(replayRun.content[0]?.text ?? "")?.[1]?.trim();
		expect(replayRunPath).toBeDefined();
		expect(existsSync(replayRunPath!)).toBe(true);
		expect(readFileSync(replayRunPath!, "utf-8")).toContain("REPI Replayer Artifact");
		const missionAfterReplay = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterReplay.gates.find((gate) => gate.name === "replay_ready")?.status).toBe("done");

		const autofixTool = tools.get("re_autofix") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const autofixPlan = await autofixTool.execute("tool-call-id", { action: "plan" });
		expect(autofixPlan.content[0]?.text).toContain("autofix_plan:");
		expect(autofixPlan.content[0]?.text).toContain("autofix_artifact:");
		expect(autofixPlan.content[0]?.text).toContain("operator_feedback:");
		expect(autofixPlan.content[0]?.text).toContain("category=swarm_retry_queue");
		expect(autofixPlan.content[0]?.text).toContain("patch_queue:");
		expect(autofixPlan.content[0]?.text).toContain("command_substitutions:");
		expect(autofixPlan.content[0]?.text).toContain("bootstrap_queue:");
		expect(autofixPlan.content[0]?.text).toContain("evidence_recapture_queue:");
		expect(autofixPlan.content[0]?.text).toContain("next_operator_queue:");
		expect(autofixPlan.content[0]?.text).toContain("next_autofix_command:");
		const autofixPath = /autofix_artifact: (.+)/.exec(autofixPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(autofixPath).toBeDefined();
		expect(existsSync(autofixPath!)).toBe(true);
		expect(readFileSync(autofixPath!, "utf-8")).toContain("REPI Autofix Artifact");
		const missionAfterAutofix = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterAutofix.gates.find((gate) => gate.name === "autofix_ready")?.status).toBe("done");

		const feedbackChainCompose = await chainTool.execute("tool-call-id", {
			action: "compose",
			target: "https://target.local/app",
		});
		expect(feedbackChainCompose.content[0]?.text).toContain("operator_feedback:");
		expect(feedbackChainCompose.content[0]?.text).toContain("operator_feedback_queue:");
		expect(feedbackChainCompose.content[0]?.text).toContain("category=swarm_retry_queue");
		expect(feedbackChainCompose.content[0]?.text).toContain("re_swarm run");

		const feedbackOperatorPlan = await operatorTool.execute("tool-call-id", {
			action: "plan",
			target: "https://target.local/app",
		});
		expect(feedbackOperatorPlan.content[0]?.text).toContain("operator_feedback:");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("operator_feedback_queue:");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("dispatcher_fallback_plan:");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("dispatcher_feedback_scoreboard:");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("dispatcher_learning_hints:");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("autonomous_execution_budget:");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("dispatcher_score_decay:");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("score_decay dispatcher");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("dispatcher_feedback_priority");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("dispatcher_score");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("retry_dispatcher");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("category=swarm_retry_queue");
		expect(feedbackOperatorPlan.content[0]?.text).toContain("operator_feedback_queue=");
		expect(readFileSync(join(agentDir, "recon", "memory", "dispatcher-feedback-board.md"), "utf-8")).toContain(
			"Dispatcher Feedback Board",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "dispatcher-feedback-board.md"), "utf-8")).toContain(
			"Autonomous execution budget",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "dispatcher-promotion-playbook.md"), "utf-8")).toContain(
			"Dispatcher Promotion Playbook",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "dispatcher-promotion-playbook.md"), "utf-8")).toContain(
			"Historical score decay",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "dispatcher-promotion-playbook.md"), "utf-8")).toContain(
			"Ledger:",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "autonomous-budget-ledger.md"), "utf-8")).toContain(
			"Autonomous Budget Ledger",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "autonomous-budget-ledger.md"), "utf-8")).toContain(
			"budget=max_turns",
		);
		const dispatcherDelegatePlan = await delegateTool.execute("tool-call-id", {
			action: "plan",
			target: "https://target.local/app",
		});
		expect(dispatcherDelegatePlan.content[0]?.text).toContain("adaptive_routing_hints:");
		expect(dispatcherDelegatePlan.content[0]?.text).toContain("autonomous_execution_budget:");
		expect(dispatcherDelegatePlan.content[0]?.text).toContain("dispatcher");

		const proofLoopTool = tools.get("re_proof_loop") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const proofLoopPlan = await proofLoopTool.execute("tool-call-id", {
			action: "plan",
			target: "./license",
			maxSteps: 4,
			replaySteps: 1,
		});
		expect(proofLoopPlan.content[0]?.text).toContain("proof_loop:");
		expect(proofLoopPlan.content[0]?.text).toContain("proof_loop_artifact:");
		expect(proofLoopPlan.content[0]?.text).toContain("verdict:");
		expect(proofLoopPlan.content[0]?.text).toContain("case_memory_lane_plan:");
		expect(proofLoopPlan.content[0]?.text).toContain("case_memory_bridge:");
		expect(proofLoopPlan.content[0]?.text).toContain("operator_feedback:");
		expect(proofLoopPlan.content[0]?.text).toContain("operator_feedback_queue:");
		expect(proofLoopPlan.content[0]?.text).toContain("category=swarm_retry_queue");
		expect(proofLoopPlan.content[0]?.text).toContain("operator-feedback");
		expect(proofLoopPlan.content[0]?.text).toContain("swarm_retry_queue:");
		expect(proofLoopPlan.content[0]?.text).toContain("specialist_queue:");
		expect(proofLoopPlan.content[0]?.text).toContain("swarm_bridge:");
		expect(proofLoopPlan.content[0]?.text).toContain("autonomous_execution_budget:");
		expect(proofLoopPlan.content[0]?.text).toContain("dispatcher_score_decay:");
		expect(proofLoopPlan.content[0]?.text).toContain("re_delegate plan");
		expect(proofLoopPlan.content[0]?.text).toContain("next_proof_command:");
		const proofLoopPlanPath = /proof_loop_artifact: (.+)/.exec(proofLoopPlan.content[0]?.text ?? "")?.[1]?.trim();
		expect(proofLoopPlanPath).toBeDefined();
		expect(existsSync(proofLoopPlanPath!)).toBe(true);
		expect(readFileSync(proofLoopPlanPath!, "utf-8")).toContain("REPI Proof Loop Artifact");
		expect(readFileSync(proofLoopPlanPath!, "utf-8")).toContain("specialist_queue:");

		const proofLoopRun = await proofLoopTool.execute("tool-call-id", {
			action: "run",
			target: "./license",
			maxSteps: 6,
			replaySteps: 1,
		});
		expect(proofLoopRun.content[0]?.text).toContain("proof_loop:");
		expect(proofLoopRun.content[0]?.text).toContain("mode: run");
		expect(proofLoopRun.content[0]?.text).toContain("executed_steps:");
		expect(proofLoopRun.content[0]?.text).toContain("evidence_summary:");
		expect(proofLoopRun.content[0]?.text).toContain("case_memory_lane_plan:");
		expect(proofLoopRun.content[0]?.text).toContain("case_memory_bridge:");
		expect(proofLoopRun.content[0]?.text).toContain("operator_feedback:");
		expect(proofLoopRun.content[0]?.text).toContain("operator_feedback_queue:");
		expect(proofLoopRun.content[0]?.text).toContain("operator_feedback: rows=");
		expect(proofLoopRun.content[0]?.text).toContain("operator-feedback");
		expect(proofLoopRun.content[0]?.text).toContain("swarm_retry_queue:");
		expect(proofLoopRun.content[0]?.text).toContain("specialist_queue:");
		expect(proofLoopRun.content[0]?.text).toContain("swarm_bridge:");
		expect(proofLoopRun.content[0]?.text).toContain("autonomous_execution_budget:");
		expect(proofLoopRun.content[0]?.text).toContain("dispatcher_score_decay:");
		expect(proofLoopRun.content[0]?.text).toContain("proof:bridge:");
		expect(proofLoopRun.content[0]?.text).toContain("re_swarm run");
		expect(proofLoopRun.content[0]?.text).toContain("re_swarm merge");
		expect(proofLoopRun.content[0]?.text).toContain("next_proof_actions:");
		const proofLoopRunPath = /proof_loop_artifact: (.+)/.exec(proofLoopRun.content[0]?.text ?? "")?.[1]?.trim();
		expect(proofLoopRunPath).toBeDefined();
		expect(existsSync(proofLoopRunPath!)).toBe(true);
		expect(readFileSync(proofLoopRunPath!, "utf-8")).toContain("REPI Proof Loop Artifact");
		expect(readFileSync(proofLoopRunPath!, "utf-8")).toContain("swarm_bridge:");
		const missionAfterProofLoop = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterProofLoop.gates.find((gate) => gate.name === "proof_loop_ready")?.status).toBe("done");
		const runtimeFailureLedger = join(agentDir, "recon", "evidence", "failures", "ledger.jsonl");
		const runtimeRepairQueue = join(agentDir, "recon", "evidence", "repairs", "queue.jsonl");
		expect(existsSync(runtimeFailureLedger)).toBe(true);
		expect(existsSync(runtimeRepairQueue)).toBe(true);
		expect(readFileSync(runtimeFailureLedger, "utf-8")).toMatch(
			/"source":"re_(?:replayer|autofix|operator|proof_loop)"/,
		);
		expect(readFileSync(runtimeFailureLedger, "utf-8")).toContain('"retryBudget"');
		expect(readFileSync(runtimeRepairQueue, "utf-8")).toContain('"repairAction"');

		const knowledgeTool = tools.get("re_knowledge_graph") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const knowledgeGraph = await knowledgeTool.execute("tool-call-id", { action: "build" });
		expect(knowledgeGraph.content[0]?.text).toContain("knowledge_graph:");
		expect(knowledgeGraph.content[0]?.text).toContain("knowledge_artifact:");
		expect(knowledgeGraph.content[0]?.text).toContain("case_signatures:");
		expect(knowledgeGraph.content[0]?.text).toContain("artifact_nodes:");
		expect(knowledgeGraph.content[0]?.text).toContain("high_value_edges:");
		expect(knowledgeGraph.content[0]?.text).toContain("similarity_index:");
		expect(knowledgeGraph.content[0]?.text).toContain("worker_routing_hints:");
		expect(knowledgeGraph.content[0]?.text).toContain("worker_scoreboard:");
		expect(knowledgeGraph.content[0]?.text).toContain("adaptive_routing_hints:");
		expect(knowledgeGraph.content[0]?.text).toContain("worker_promotion_queue:");
		expect(knowledgeGraph.content[0]?.text).toContain("command_strategy_hints:");
		expect(knowledgeGraph.content[0]?.text).toContain("dispatcher_feedback_scoreboard:");
		expect(knowledgeGraph.content[0]?.text).toContain("dispatcher_routing_hints:");
		expect(knowledgeGraph.content[0]?.text).toContain("autonomous_execution_budget:");
		expect(knowledgeGraph.content[0]?.text).toContain("dispatcher_score_decay:");
		expect(knowledgeGraph.content[0]?.text).toContain("high_score_promotions:");
		expect(knowledgeGraph.content[0]?.text).toContain("dispatcher_score");
		expect(knowledgeGraph.content[0]?.text).toContain("next_knowledge_command:");
		const knowledgePath = /knowledge_artifact: (.+)/.exec(knowledgeGraph.content[0]?.text ?? "")?.[1]?.trim();
		expect(knowledgePath).toBeDefined();
		expect(existsSync(knowledgePath!)).toBe(true);
		expect(readFileSync(knowledgePath!, "utf-8")).toContain("REPI Knowledge Graph Artifact");
		expect(readFileSync(join(agentDir, "recon", "memory", "knowledge-graph-index.md"), "utf-8")).toContain(
			"Knowledge Graph Index",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "knowledge-graph-index.md"), "utf-8")).toContain(
			"Adaptive routing hints",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "knowledge-graph-index.md"), "utf-8")).toContain(
			"Dispatcher feedback scoreboard",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "knowledge-graph-index.md"), "utf-8")).toContain(
			"Autonomous execution budget",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "knowledge-graph-index.md"), "utf-8")).toContain(
			"Dispatcher score decay",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "knowledge-graph-index.md"), "utf-8")).toContain(
			"High-score promotions",
		);
		expect(readFileSync(join(agentDir, "recon", "memory", "dispatcher-promotion-playbook.md"), "utf-8")).toContain(
			"Score decay",
		);
		const harnessTool = tools.get("re_harness") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const harness = await harnessTool.execute("tool-call-id", { action: "full" });
		expect(harness.content[0]?.text).toContain("harness:");
		expect(harness.content[0]?.text).toContain("harness_artifact:");
		expect(harness.content[0]?.text).toContain("verdict:");
		expect(harness.content[0]?.text).toContain("install_readiness:");
		expect(harness.content[0]?.text).toContain("reverse_capability_guards:");
		expect(harness.content[0]?.text).toContain("regression_guards:");
		expect(harness.content[0]?.text).toContain("compact_resume_case_memory");
		expect(harness.content[0]?.text).toContain("re_native_runtime");
		const harnessPath = /harness_artifact: (.+)/.exec(harness.content[0]?.text ?? "")?.[1]?.trim();
		expect(harnessPath).toBeDefined();
		expect(existsSync(harnessPath!)).toBe(true);
		expect(readFileSync(harnessPath!, "utf-8")).toContain("REPI Harness Artifact");

		const migratedLanePlan = await laneTool.execute("tool-call-id", {
			action: "plan",
			lane: "control-flow",
			target: "./license",
		});
		expect(migratedLanePlan.content[0]?.text).toContain("case_memory_migrations:");
		expect(migratedLanePlan.content[0]?.text).toContain("case_memory_migration:");
		expect(migratedLanePlan.content[0]?.text).toContain("dispatcher-feedback");
		const migratedAutopilotPlan = await autopilotTool.execute("tool-call-id", {
			action: "plan",
			lane: "control-flow",
			target: "./license",
		});
		expect(migratedAutopilotPlan.content[0]?.text).toContain("case_memory_lane_plan:");
		expect(migratedAutopilotPlan.content[0]?.text).toMatch(/action: (reprioritized|added|skipped)/);
		const missionAfterKnowledge = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as { gates: Array<{ name: string; status: string }> };
		expect(missionAfterKnowledge.gates.find((gate) => gate.name === "knowledge_graph_ready")?.status).toBe("done");

		const completeTool = tools.get("re_complete") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const completionAudit = await completeTool.execute("tool-call-id", { action: "audit" });
		expect(completionAudit.content[0]?.text).toContain("completion_status:");
		expect(completionAudit.content[0]?.text).toContain("pending gate:");

		const memoryTool = tools.get("re_memory") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const playbookMaintenance = await memoryTool.execute("tool-call-id", { action: "playbooks" });
		const playbookIndexPath = join(agentDir, "recon", "memory", "playbooks", "index.md");
		expect(playbookMaintenance.content[0]?.text).toContain("Playbook Maintenance");
		expect(playbookMaintenance.content[0]?.text).toContain("active:");
		expect(existsSync(playbookIndexPath)).toBe(true);
		expect(readFileSync(playbookIndexPath, "utf-8")).toContain("Quality");
		expect(readFileSync(playbookIndexPath, "utf-8")).toContain("Policy:");
		expect(readFileSync(playbookIndexPath, "utf-8")).toContain("dispatcher-promotion");

		const playbookPrune = await memoryTool.execute("tool-call-id", { action: "prune-playbooks" });
		expect(playbookPrune.content[0]?.text).toContain("Playbook Maintenance");
		expect(readFileSync(playbookIndexPath, "utf-8")).toContain("archive=true");

		const evolutionResult = await memoryTool.execute("tool-call-id", {
			action: "evolve",
			title: "test evolution",
			text: "prefer runtime evidence over stale source",
		});
		expect(evolutionResult.content[0]?.text).toContain("Appended evolution entry");
		expect(readFileSync(join(agentDir, "recon", "memory", "evolution-log.md"), "utf-8")).toContain(
			"runtime evidence",
		);

		expect(handlers.has("before_agent_start")).toBe(true);
		expect(handlers.has("tool_call")).toBe(true);
		expect(handlers.has("session_before_compact")).toBe(true);

		const beforeAgentStart = handlers.get("before_agent_start")?.[0] as (
			event: Record<string, unknown>,
			ctx: Record<string, unknown>,
		) => Promise<{ systemPrompt?: string } | undefined>;
		const injected = await beforeAgentStart(
			{
				type: "before_agent_start",
				prompt: "分析这个 ELF 的许可证校验逻辑",
				systemPrompt: "base-system",
				systemPromptOptions: {},
			},
			{ hasUI: false },
		);
		expect(injected?.systemPrompt).toContain("Mission blackboard:");
		expect(injected?.systemPrompt).toContain("Execution kernel:");
		expect(injected?.systemPrompt).toContain("execution_kernel:");
		expect(injected?.systemPrompt).toContain("Decision core:");
		expect(injected?.systemPrompt).toContain("decision_core:");
		expect(injected?.systemPrompt).toContain("Evidence ledger tail:");
		expect(injected?.systemPrompt).toContain("Context/resume pack:");
		expect(injected?.systemPrompt).toContain("Completion gate audit:");
		expect(readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8")).toContain("Native reverse");
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

	it("runs the exploit lab and records stability anchors", async () => {
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
					code: 0,
					stdout: [
						"[exploit-lab-env] python=3.12 platform=Linux cwd=/tmp timeout_s=7 runs=3",
						"[exploit-lab-inventory] target=./exploit.py exists=true bytes=128 sha256=abc executable=true suffix=.py",
						"[exploit-lab-replay] run=1 exit=0 duration=0.11 stdout_sha256=aaa stderr_sha256=bbb stdout_len=20 stderr_len=0 ok=true",
						"[exploit-lab-replay] run=2 exit=0 duration=0.12 stdout_sha256=aaa stderr_sha256=bbb stdout_len=20 stderr_len=0 ok=true",
						"[exploit-lab-summary] runs=3 ok=3 success_rate=1.000 stable=true unique_exits=1 unique_stdout_hashes=1",
						"[exploit-lab-flake] failures=0 timeout_or_nonzero=0 stable=true retry_budget=0",
						"[exploit-lab-bundle] manifest=/tmp/pi-recon-exploit-lab-manifest.json artifacts=1 target=./exploit.py cmd_sha256=def",
					].join("\n"),
					stderr: "",
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
		await missionTool.execute("tool-call-id", { action: "new", task: "autopwn exploit reliability" });

		const exploitLabTool = tools.get("re_exploit_lab") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const result = await exploitLabTool.execute("tool-call-id", {
			action: "run",
			target: "./exploit.py",
			runs: 3,
			timeoutMs: 7000,
		});

		expect(execCalls).toHaveLength(1);
		expect(execCalls[0]?.args.join("\n")).toContain("pi-recon-exploit-lab-runner.py");
		expect(result.content[0]?.text).toContain("exploit_lab:");
		expect(result.content[0]?.text).toContain("mode: run");
		expect(result.content[0]?.text).toContain("executions:");
		expect(result.content[0]?.text).toContain("stdout_sha256=");
		expect(result.content[0]?.text).toContain("Exploit Lab PoC inventory anchors");
		expect(result.content[0]?.text).toContain("Exploit Lab replay matrix anchors");
		expect(result.content[0]?.text).toContain("Exploit Lab flake triage anchors");
		expect(result.content[0]?.text).toContain("Exploit Lab artifact bundle anchors");
		const artifactPath = /exploit_lab_artifact: (.+)/.exec(result.content[0]?.text ?? "")?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(existsSync(artifactPath!)).toBe(true);
		expect(readFileSync(artifactPath!, "utf-8")).toContain("REPI Exploit Lab Artifact");
		const missionAfterLab = JSON.parse(readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8")) as {
			gates: Array<{ name: string; status: string }>;
		};
		expect(missionAfterLab.gates.find((gate) => gate.name === "exploit_lab_ready")?.status).toBe("done");
	});

	it("runs the mobile runtime capture and records Frida/ADB anchors", async () => {
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
					code: 0,
					stdout: [
						"[mobile-env] adb=/usr/bin/adb frida=/usr/bin/frida frida_ps=/usr/bin/frida-ps jadx=/usr/bin/jadx apktool=/usr/bin/apktool gdb=/usr/bin/gdb",
						"[mobile-apk] target=./app.apk bytes=123 sha256=abc file=Android package",
						"[mobile-device] emulator-5554 device product=sdk",
						"[mobile-process] pidof com.demo.app 1234",
						"[mobile-frida-process] 1234 com.demo.app",
						"[mobile-frida-hook-template] /tmp/pi-recon-mobile-frida-hooks.js hooks=Java.crypto,String.equals,Debug.isDebuggerConnected,native.strcmp,memcmp",
						"[mobile-hook-line] Java.perform",
						"[mobile-crypto-hook] Cipher.doFinal in=aa",
						"[mobile-native-hook] strcmp ret=0x0",
						"[mobile-anti-debug-check] isDebuggerConnected",
					].join("\n"),
					stderr: "",
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
		await missionTool.execute("tool-call-id", { action: "new", task: "Android APK Frida anti-debug crypto" });

		const mobileRuntimeTool = tools.get("re_mobile_runtime") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const result = await mobileRuntimeTool.execute("tool-call-id", {
			action: "run",
			target: "./app.apk",
			packageName: "com.demo.app",
			timeoutMs: 9000,
		});

		expect(execCalls).toHaveLength(1);
		expect(execCalls[0]?.args.join("\n")).toContain("pi-recon-mobile-frida-hooks.js");
		expect(result.content[0]?.text).toContain("mobile_runtime:");
		expect(result.content[0]?.text).toContain("mode: run");
		expect(result.content[0]?.text).toContain("executions:");
		expect(result.content[0]?.text).toContain("stdout_sha256=");
		expect(result.content[0]?.text).toContain("mobile APK inventory anchors");
		expect(result.content[0]?.text).toContain("mobile device anchors");
		expect(result.content[0]?.text).toContain("mobile process map anchors");
		expect(result.content[0]?.text).toContain("mobile Frida hook template anchors");
		expect(result.content[0]?.text).toContain("mobile Java crypto/compare hook anchors");
		expect(result.content[0]?.text).toContain("mobile native compare hook anchors");
		expect(result.content[0]?.text).toContain("mobile anti-debug/root check anchors");
		const artifactPath = /mobile_runtime_artifact: (.+)/.exec(result.content[0]?.text ?? "")?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(existsSync(artifactPath!)).toBe(true);
		expect(readFileSync(artifactPath!, "utf-8")).toContain("REPI Mobile Runtime Artifact");
		const missionAfterMobile = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as {
			gates: Array<{ name: string; status: string }>;
		};
		expect(missionAfterMobile.gates.find((gate) => gate.name === "mobile_runtime_ready")?.status).toBe("done");
	});

	it("runs the web authz state capture and records principal/object anchors", async () => {
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
					code: 0,
					stdout: [
						"[web-authz-env] node=/usr/bin/node curl=/usr/bin/curl jq=/usr/bin/jq python3=/usr/bin/python3 timeout=9s",
						"[web-authz-script] /tmp/pi-recon-web-authz-state.mjs artifact=/tmp/pi-recon-web-authz-state.json principals=anon,A,B",
						"[web-authz-run] [web-authz-state] principal=anon route=/api/users/123 method=GET status=401 bytes=20 hash=aaa",
						"[web-authz-run] [web-authz-state] principal=A route=/api/users/123 method=GET status=200 bytes=120 hash=bbb",
						"[web-authz-run] [web-authz-state] principal=B route=/api/users/123 method=GET status=200 bytes=118 hash=ccc",
						"[web-authz-run] [web-authz-matrix] route=/api/users/123 principals=anon,A,B states=3 same_status=false unique_bodies=3 vector=anon:401:aaa,A:200:bbb,B:200:ccc",
						"[web-authz-run] [web-authz-object] route=/api/users/123 owner=A principal_a_status=200 principal_b_status=200 same_body_ab=false alt_status=200 potential_bola=true",
						"[web-authz-run] [web-authz-sequence] principal=A steps=2 statuses=200,200 hashes=bbb,ddd",
						"[web-authz-run] [web-authz-rollback] status=skipped reason=set_REPI_AUTHZ_MUTATE=1_and_REPI_MUTATION_URL",
						"[web-authz-run] [web-authz-artifact] /tmp/pi-recon-web-authz-state.json",
					].join("\n"),
					stderr: "",
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
		await missionTool.execute("tool-call-id", { action: "new", task: "Web API JWT IDOR BOLA authz state" });

		const webAuthzTool = tools.get("re_web_authz_state") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const result = await webAuthzTool.execute("tool-call-id", {
			action: "run",
			target: "https://target.local/api/users/123",
			timeoutMs: 9000,
		});

		expect(execCalls).toHaveLength(1);
		expect(execCalls[0]?.args.join("\n")).toContain("pi-recon-web-authz-state.mjs");
		expect(result.content[0]?.text).toContain("web_authz_state:");
		expect(result.content[0]?.text).toContain("mode: run");
		expect(result.content[0]?.text).toContain("executions:");
		expect(result.content[0]?.text).toContain("stdout_sha256=");
		expect(result.content[0]?.text).toContain("web authz principal state anchors");
		expect(result.content[0]?.text).toContain("web authz matrix anchors");
		expect(result.content[0]?.text).toContain("web authz object ownership anchors");
		expect(result.content[0]?.text).toContain("web authz sequence replay anchors");
		expect(result.content[0]?.text).toContain("web authz rollback anchors");
		expect(result.content[0]?.text).toContain("web authz artifact anchors");
		const artifactPath = /web_authz_artifact: (.+)/.exec(result.content[0]?.text ?? "")?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(existsSync(artifactPath!)).toBe(true);
		expect(readFileSync(artifactPath!, "utf-8")).toContain("REPI Web Authz State Artifact");
		const missionAfterWebAuthz = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as {
			gates: Array<{ name: string; status: string }>;
		};
		expect(missionAfterWebAuthz.gates.find((gate) => gate.name === "web_authz_ready")?.status).toBe("done");
	});

	it("runs the native runtime capture and records GDB/pwn anchors", async () => {
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
					code: 0,
					stdout: [
						"[native-env] file=/usr/bin/file readelf=/usr/bin/readelf objdump=/usr/bin/objdump gdb=/usr/bin/gdb checksec=/usr/bin/checksec ldd=/usr/bin/ldd strings=/usr/bin/strings ROPgadget=/usr/bin/ROPgadget ropper=/usr/bin/ropper patchelf=/usr/bin/patchelf",
						"[native-binary] target=./vuln bytes=123 sha256=abc mode=755 file=ELF 64-bit LSB executable",
						"[native-checksec] Canary found NX enabled PIE enabled",
						"[native-readelf-header] Type: EXEC (Executable file)",
						"[native-readelf-program] GNU_STACK RW",
						"[native-ldd] libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6",
						"[native-symbol] strcmp",
						"[native-string] license",
						"[native-gdb-script] /tmp/pi-recon-native-gdb.gdb breakpoints=main,strcmp,strncmp,memcmp,strstr",
						"[native-gdb] Program received signal SIGSEGV",
						"[native-gdb] RIP 0x6161616b RSP 0x7fffffffe000",
						"[native-pwn-scaffold] /tmp/pi-recon-native-pwn-scaffold.py target=./vuln cyclic=128 rop=leak-libc-verifier",
					].join("\n"),
					stderr: "",
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
		await missionTool.execute("tool-call-id", { action: "new", task: "pwn ELF ret2libc crash primitive" });

		const nativeRuntimeTool = tools.get("re_native_runtime") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const result = await nativeRuntimeTool.execute("tool-call-id", {
			action: "run",
			target: "./vuln",
			timeoutMs: 9000,
		});

		expect(execCalls).toHaveLength(1);
		expect(execCalls[0]?.args.join("\n")).toContain("pi-recon-native-gdb.gdb");
		expect(execCalls[0]?.args.join("\n")).toContain("pi-recon-native-pwn-scaffold.py");
		expect(result.content[0]?.text).toContain("native_runtime:");
		expect(result.content[0]?.text).toContain("mode: run");
		expect(result.content[0]?.text).toContain("executions:");
		expect(result.content[0]?.text).toContain("stdout_sha256=");
		expect(result.content[0]?.text).toContain("native binary inventory anchors");
		expect(result.content[0]?.text).toContain("native mitigation/header anchors");
		expect(result.content[0]?.text).toContain("native loader/libc anchors");
		expect(result.content[0]?.text).toContain("native symbol/string anchors");
		expect(result.content[0]?.text).toContain("native GDB trace anchors");
		expect(result.content[0]?.text).toContain("native crash/register anchors");
		expect(result.content[0]?.text).toContain("native exploit scaffold anchors");
		const artifactPath = /native_runtime_artifact: (.+)/.exec(result.content[0]?.text ?? "")?.[1]?.trim();
		expect(artifactPath).toBeDefined();
		expect(existsSync(artifactPath!)).toBe(true);
		expect(readFileSync(artifactPath!, "utf-8")).toContain("REPI Native Runtime Artifact");
		const missionAfterNative = JSON.parse(
			readFileSync(join(agentDir, "recon", "mission", "current.json"), "utf-8"),
		) as {
			gates: Array<{ name: string; status: string }>;
		};
		expect(missionAfterNative.gates.find((gate) => gate.name === "native_runtime_ready")?.status).toBe("done");
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
		const missionPath = join(agentDir, "recon", "mission", "current.json");
		const mission = JSON.parse(readFileSync(missionPath, "utf-8")) as {
			lanes: Array<{ name: string; objective: string; status?: string; note?: string; next: string[] }>;
		};
		const lanes = mission.lanes.map((lane) => {
			if (lane.name === "control-flow") {
				return {
					...lane,
					status: "blocked",
					note: "waiting for tool-bootstrap",
					next: ["[auto:post-bootstrap-signal] printf 'strcmp\\n' # evidence: resume after tool-index refresh"],
				};
			}
			return { ...lane, status: lane.name === "triage" ? "done" : "pending" };
		});
		lanes.splice(2, 0, {
			name: "tool-bootstrap",
			objective: "补齐缺失工具或确认可用替代路径，再回到被阻塞 lane",
			status: "in_progress",
			note: "adaptive_from=control-flow; reason=tool_strategy_tool-index-missing:control-flow",
			next: ["re_bootstrap plan file"],
		});
		writeFileSync(missionPath, `${JSON.stringify({ ...mission, lanes }, null, 2)}\n`, "utf-8");

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

		expect(execCalls).toHaveLength(2);
		expect(auto.content[0]?.text).toContain("tool_bootstrap_closure:");
		expect(auto.content[0]?.text).toContain("missing_after_refresh: none");
		expect(auto.content[0]?.text).toContain("resumed_lane: control-flow");
		expect(auto.content[0]?.text).toContain("reason: tool_bootstrap_closed:control-flow");
		expect(auto.content[0]?.text).toContain("## run-auto step 2: control-flow");
		expect(auto.content[0]?.text).toContain("auto_lane_update: control-flow -> runtime-proof");

		const missionAfterClosure = JSON.parse(readFileSync(missionPath, "utf-8")) as {
			lanes: Array<{ name: string; status?: string; note?: string }>;
			gates: Array<{ name: string; status: string; note?: string }>;
		};
		expect(missionAfterClosure.lanes.find((lane) => lane.name === "tool-bootstrap")?.status).toBe("done");
		expect(missionAfterClosure.lanes.find((lane) => lane.name === "control-flow")?.status).toBe("done");
		expect(missionAfterClosure.lanes.find((lane) => lane.name === "runtime-proof")?.status).toBe("in_progress");
		expect(missionAfterClosure.gates.find((gate) => gate.name === "tool_index_checked")?.status).toBe("done");
		expect(readFileSync(join(agentDir, "recon", "tools", "tool-index.md"), "utf-8")).toContain(
			"| file | yes | /usr/bin/file | file |",
		);
	});

	it("plans specialist runtime command packs for top reverse and pentest lanes", async () => {
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

		const missionTool = tools.get("re_mission") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const laneTool = tools.get("re_lane") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const planFor = async (task: string, lane: string, target: string) => {
			await missionTool.execute("tool-call-id", { action: "new", task });
			const result = await laneTool.execute("tool-call-id", { action: "plan", lane, target });
			return result.content[0]?.text ?? "";
		};

		const webPlan = await planFor("Web API JWT auth websocket replay", "surface", "https://target.local/app");
		expect(webPlan).toContain("route: Web / API security");
		expect(webPlan).toContain("specialist_runtime_planner: browser/XHR/WS");
		expect(webPlan).toContain("browser-xhr-ws-capture-scaffold");
		expect(webPlan).toContain("localStorage");
		expect(webPlan).toContain("websocket");
		expect(webPlan).toContain("browser-xhr-ws-auth-diff-scaffold");
		expect(webPlan).toContain("browser-cdp-artifact-scaffold");
		expect(webPlan).toContain("browser-replay-evaluator-scaffold");
		expect(webPlan).toContain("browser-route-graph-scaffold");
		expect(webPlan).toContain("browser-auth-matrix-scaffold");
		expect(webPlan).toContain("browser-idor-bola-probe-scaffold");
		expect(webPlan).toContain("browser-authz-state-machine-scaffold");
		expect(webPlan).toContain("browser-authz-sequence-replay-scaffold");
		expect(webPlan).toContain("browser-authz-object-ownership-scaffold");
		expect(webPlan).toContain("browser-authz-state-rollback-scaffold");
		expect(webPlan).toContain("web-api-authz-static-scaffold");
		expect(webPlan).toContain("web-api-schema-diff-scaffold");
		expect(webPlan).toContain("web-api-state-source-scaffold");
		expect(webPlan).toContain("/tmp/pi-recon-browser-artifact.json");

		const webScanPlan = await planFor("nuclei ffuf katana web 漏洞扫描", "scope", "https://target.local");
		expect(webScanPlan).toContain("route: Web vulnerability scanning");
		expect(webScanPlan).toContain("specialist_runtime_planner: web vulnerability scanner/triage");
		expect(webScanPlan).toContain("web-scan-scope-baseline");
		expect(webScanPlan).toContain("web-scan-crawl-corpus-scaffold");
		expect(webScanPlan).toContain("web-scan-content-discovery-scaffold");
		expect(webScanPlan).toContain("web-scan-template-scan-scaffold");
		expect(webScanPlan).toContain("web-scan-manual-replay-verifier");

		const jsPlan = await planFor("JS 签名 sign 参数 crypto.subtle fetch", "observe", "https://target.local/app.js");
		expect(jsPlan).toContain("route: Frontend JS reverse");
		expect(jsPlan).toContain("JS signing rebuild");
		expect(jsPlan).toContain("js-signing-rebuild-browser-hooks");
		expect(jsPlan).toContain("crypto.subtle");
		expect(jsPlan).toContain("XMLHttpRequest");
		expect(jsPlan).toContain("js-signing-rebuild-node-scaffold");
		expect(jsPlan).toContain("js-signing-observation-normalizer");
		expect(jsPlan).toContain("js-signing-first-divergence-scaffold");
		expect(jsPlan).toContain("js-signing-replay-harness-scaffold");

		const nativePlan = await planFor("ELF native reverse license patch symbolic fuzz", "control-flow", "./license");
		expect(nativePlan).toContain("route: Native reverse");
		expect(nativePlan).toContain("specialist_runtime_planner: native deep reverse/pwn");
		expect(nativePlan).toContain("native-deep-symbol-map-scaffold");
		expect(nativePlan).toContain("native-deep-decompiler-project-scaffold");
		expect(nativePlan).toContain("native-deep-compare-trace-scaffold");
		expect(nativePlan).toContain("native-deep-patch-hypothesis-scaffold");
		expect(nativePlan).toContain("native-deep-symbolic-fuzz-scaffold");
		expect(nativePlan).toContain("/tmp/pi-recon-native-symbolic-fuzz.py");

		const pwnPlan = await planFor("pwn ret2libc heap exploit", "primitive", "./vuln");
		expect(pwnPlan).toContain("route: Pwn / exploit");
		expect(pwnPlan).toContain("pwn primitive");
		expect(pwnPlan).toContain("native-deep-symbol-map-scaffold");
		expect(pwnPlan).toContain("pwn-primitive-cyclic-crash");
		expect(pwnPlan).toContain("pwn-primitive-offset-analyzer");
		expect(pwnPlan).toContain("pwn-primitive-rop-libc-scaffold");
		expect(pwnPlan).toContain("pwn-primitive-local-verifier");
		expect(pwnPlan).toContain("ROPgadget");
		expect(pwnPlan).toContain("pwntools");

		const exploitPlan = await planFor("autopwn exploit reliability poc replay matrix", "replay", "./exploit.py");
		expect(exploitPlan).toContain("route: Exploit reliability");
		expect(exploitPlan).toContain("specialist_runtime_planner: exploit reliability/autopwn");
		expect(exploitPlan).toContain("exploit-poc-normalizer-scaffold");
		expect(exploitPlan).toContain("exploit-replay-matrix-scaffold");
		expect(exploitPlan).toContain("exploit-environment-pin-scaffold");
		expect(exploitPlan).toContain("exploit-flake-triage-scaffold");
		expect(exploitPlan).toContain("exploit-artifact-bundle-scaffold");

		const pcapPlan = await planFor("分析 pcap 流量", "map", "capture.pcapng");
		expect(pcapPlan).toContain("PCAP/DFIR flow");
		expect(pcapPlan).toContain("pcap-flow-conversations");
		expect(pcapPlan).toContain("pcap-flow-stream-rank");
		expect(pcapPlan).toContain("pcap-flow-secret-timeline");
		expect(pcapPlan).toContain("tshark -r");
		expect(pcapPlan).toContain("conv,tcp");
		expect(pcapPlan).toContain("export-objects http");
		expect(pcapPlan).toContain("pcap-flow-transform-chain");

		const memoryPlan = await planFor("volatility vmem memory dump 内存取证", "image-info", "mem.vmem");
		expect(memoryPlan).toContain("route: Memory forensics");
		expect(memoryPlan).toContain("specialist_runtime_planner: memory forensics");
		expect(memoryPlan).toContain("memory-forensics-image-info-scaffold");
		expect(memoryPlan).toContain("memory-forensics-process-network-scaffold");
		expect(memoryPlan).toContain("memory-forensics-credential-artifact-scaffold");
		expect(memoryPlan).toContain("memory-forensics-timeline-carve-scaffold");

		const firmwarePlan = await planFor("OpenWrt firmware binwalk squashfs rootfs mips", "inventory", "router.bin");
		expect(firmwarePlan).toContain("route: Firmware / IoT");
		expect(firmwarePlan).toContain("specialist_runtime_planner: Firmware/IoT rootfs");
		expect(firmwarePlan).toContain("firmware-static-fingerprint-scaffold");
		expect(firmwarePlan).toContain("firmware-extract-rootfs-scaffold");
		expect(firmwarePlan).toContain("firmware-filesystem-config-secret-scaffold");
		expect(firmwarePlan).toContain("firmware-service-surface-scaffold");
		expect(firmwarePlan).toContain("firmware-emulation-scaffold");

		const agentSecPlan = await planFor("LLM agent prompt injection MCP tool call memory poisoning", "surface", ".");
		expect(agentSecPlan).toContain("route: Agent / LLM security");
		expect(agentSecPlan).toContain("specialist_runtime_planner: agent prompt/tool boundary");
		expect(agentSecPlan).toContain("agent-prompt-surface-map");
		expect(agentSecPlan).toContain("agent-tool-boundary-scaffold");
		expect(agentSecPlan).toContain("agent-memory-poisoning-scaffold");
		expect(agentSecPlan).toContain("agent-injection-replay-harness");
		expect(agentSecPlan).toContain("agent-delegation-trace-scaffold");

		const malwarePlan = await planFor("malware sample yara capa floss c2 ioc config", "triage", "./sample.bin");
		expect(malwarePlan).toContain("route: Malware analysis");
		expect(malwarePlan).toContain("specialist_runtime_planner: malware config/IOC");
		expect(malwarePlan).toContain("malware-static-triage-scaffold");
		expect(malwarePlan).toContain("malware-yara-capa-floss-scaffold");
		expect(malwarePlan).toContain("malware-ioc-config-scaffold");
		expect(malwarePlan).toContain("malware-behavior-trace-scaffold");

		const cloudPlan = await planFor("K8s cloud metadata serviceaccount privilege", "identity", ".");
		expect(cloudPlan).toContain("route: Cloud / container");
		expect(cloudPlan).toContain("specialist_runtime_planner: Cloud/K8s identity");
		expect(cloudPlan).toContain("cloud-identity-config-map");
		expect(cloudPlan).toContain("cloud-runtime-config-scaffold");
		expect(cloudPlan).toContain("cloud-metadata-probe-scaffold");
		expect(cloudPlan).toContain("cloud-privilege-edge-scaffold");

		const adPlan = await planFor("AD kerberos ldap certipy bloodhound credential graph", "principals", "10.0.0.5");
		expect(adPlan).toContain("route: Identity / Windows / AD");
		expect(adPlan).toContain("specialist_runtime_planner: Identity/AD graph");
		expect(adPlan).toContain("identity-ad-principal-enum-scaffold");
		expect(adPlan).toContain("identity-ad-credential-usability-scaffold");
		expect(adPlan).toContain("identity-ad-graph-scaffold");

		const iosPlan = await planFor("iOS IPA Keychain NSURLSession TLS pinning Frida", "ipa-inventory", "app.ipa");
		expect(iosPlan).toContain("route: Mobile / iOS");
		expect(iosPlan).toContain("specialist_runtime_planner: iOS IPA/mobile runtime");
		expect(iosPlan).toContain("ios-ipa-inventory-scaffold");
		expect(iosPlan).toContain("ios-macho-class-map-scaffold");
		expect(iosPlan).toContain("ios-frida-objection-hook-scaffold");
		expect(iosPlan).toContain("ios-network-replay-scaffold");

		const fridaPlan = await planFor("Android APK frida bypass", "runtime-proof", "./app.apk");
		expect(fridaPlan).toContain("Frida/GDB trace");
		expect(fridaPlan).toContain("frida-gdb-trace-hook-template");
		expect(fridaPlan).toContain("Java.perform");
		expect(fridaPlan).toContain("Module.findExportByName");
	});

	it("parses specialist runtime evidence and queues targeted follow-ups", async () => {
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
				const script = args.join("\n");
				execCalls.push({ command, args });
				if (script.includes("https://target.local/app.js") && script.includes("js-signing-rebuild")) {
					return {
						code: 0,
						stdout: [
							"[pi-recon-js-hook] fetch.args GET /api",
							"[pi-recon-js-hook] crypto.subtle.sign.args key body",
							"crypto.subtle.sign.ret 32",
							"[js-signing-normalized] artifact=/tmp/pi-recon-js-observed.json events=3 urls=1 crypto_ops=crypto.subtle.sign key_fields=signature,nonce body_hashes=abc123",
							"[js-first-divergence] expected=deadbeef candidate=feedface match=false suspect=body observed_keys=urls,cryptoOps,keyFields",
							"[js-first-divergence-candidate] name=body bytes=128 sha256=aaa hmacSha256=bbb",
							"[js-replay-harness] url=https://target.local/api method=POST status=200 bytes=88 body_hash=ccc signature_key=X-Signature",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (script.includes("browser-xhr-ws")) {
					return {
						code: 0,
						stdout: [
							'[request] GET https://target.local/api/me {"authorization":"Bearer x"}',
							"[response] 200 https://target.local/api/me",
							"[websocket] wss://target.local/ws",
							'[cookies] [{"name":"sid","value":"abc"}]',
							'[localStorage] {"access_token":"tok"}',
							"[cdp-request] GET https://target.local/api/me type=Fetch",
							"[cdp-response] 200 https://target.local/api/me",
							"[cdp-ws] wss://target.local/ws",
							"[browser-artifact] /tmp/pi-recon-browser-artifact.json",
							'[storage-snapshot] {"href":"https://target.local/app","localStorage":{"access_token":"tok"}}',
							"[replay-eval] artifact=/tmp/pi-recon-browser-artifact.json method=GET url=https://target.local/api/me status=200 expected=200 replay_match=true bytes=123 body_hash=abc123",
							"[route-graph] artifact=/tmp/pi-recon-browser-artifact.json routes=2 auth_routes=1 idor_params=1",
							"[route-node] GET /api/users/:id statuses=200 auth=true params=id idor=id sample=https://target.local/api/users/123?id=123",
							"[auth-matrix] route=/api/users/123 anon=401 a=200 b=200 same_ab=false diff_anon_a=true bytes_a=120 bytes_b=118 hash_a=aaa hash_b=bbb",
							"[idor-candidate] method=GET route=/api/users/:id param=id sample=https://target.local/api/users/123?id=123",
							"[idor-probe] route=/api/users/123 param=id base_status=200 alt_status=200 same_body=false potential_idor=true",
							"[authz-state] principal=anon route=/api/users/:id method=GET status=401 bytes=20 hash=anon sequence=direct",
							"[authz-state] principal=A route=/api/users/:id method=GET status=200 bytes=120 hash=aaa sequence=direct",
							"[authz-state] principal=B route=/api/users/:id method=GET status=200 bytes=118 hash=bbb sequence=direct",
							"[authz-state-machine] artifact=/tmp/pi-recon-authz-state-machine.json routes=1 states=3 principals=anon,A,B",
							"[authz-sequence] name=list-then-detail principal=A steps=2 statuses=200,200 stable=true drift=false",
							"[authz-sequence-artifact] /tmp/pi-recon-authz-sequence.json",
							"[authz-ownership] route=/api/users/:id object=123 owner=A principal=A status=200 principal_b_status=200 same_body=false potential_bola=true",
							"[authz-rollback] route=/api/users/123 mutation=PATCH before=aaa after=ccc rollback=aaa restored=true",
							"[web-authz-static] route_file=src/routes.ts line=10 code=app.get('/users/:id')",
							"[web-authz-risk] file=src/routes.ts line=12 reason=id_lookup_without_nearby_owner_check code=findUnique({id})",
							"[web-authz-static-summary] route_hits=2 auth_hits=1 risk_hits=1 files=10",
							"[web-schema] file=openapi.json bytes=1234",
							"[web-schema-route] method=GET path=/api/users/{id} security=no id_params=id",
							"[web-schema-risk] method=GET path=/api/users/{id} reason=id_param_without_security",
							"[web-state-source] file=src/routes.ts line=30 has_state=true has_auth_context=false code=router.patch('/users/:id')",
							"[web-state-risk] file=src/routes.ts line=30 reason=mutating_route_without_nearby_auth_context",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (
					script.includes("native-deep-symbol-map") &&
					!script.includes("pwn-primitive") &&
					!script.includes("frida-gdb-trace-mobile-environment")
				) {
					return {
						code: 0,
						stdout: [
							"[native-symbol-map] target=./license",
							"[native-header] ELF Header: Type EXEC Machine x86-64",
							"[native-section] .text PROGBITS",
							"[native-symbol] 0000000000401156 FUNC GLOBAL main",
							"[native-import] strcmp GLIBC_2.2.5",
							"[native-string] license invalid",
							"[native-decompiler] analyzeHeadless=missing script=/tmp/pi-recon-ghidra-export.java",
							"[native-decompiler-fallback] sym.main cmp eax,0",
							"[native-compare-trace] script=/tmp/pi-recon-native-compare-trace.gdb target=./license",
							"[native-compare] fn=strcmp a=user b=secret rip=0x401234",
							"[native-patch] candidates=3 artifact=/tmp/pi-recon-native-patch-candidates.json",
							"[native-patch-candidate] 401250: jne 401270",
							"[native-symbolic] angr=present arch=<Arch AMD64 (LE)> entry=0x401000",
							"[native-symbolic] cfg_functions=42",
							"[native-symbolic-fn] 0x401156 main",
							"[native-fuzz] seed=2 len=32 exit=-11 ms=3 stdout=b'' stderr=b''",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (script.includes("pwn-primitive")) {
					return {
						code: 0,
						stdout: [
							"Program received signal SIGSEGV",
							"RIP 0x6161616c",
							"RSP 0x7fffffffe000",
							"ROPgadget ... pop rdi ; ret",
							"[pwn-offset] crash_value=0x6161616c offset=120",
							"[pwn-libc-fingerprint] libc=/lib/x86_64-linux-gnu/libc.so.6",
							"[pwn-rop-chain] pop_rdi=0x40123b puts@plt=0x401030 puts@got=0x404018",
							"[pwn-local-verifier] target=./vuln offset=120 payload_len=128 exit=-11",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (script.includes("exploit-poc-normalizer") || script.includes("exploit-replay-matrix")) {
					return {
						code: 0,
						stdout: [
							"[exploit-candidate] file=./exploit.py",
							"[exploit-poc] file=exploit.py kind=pwn-pwntools bytes=2048 sha256=abc executable=true",
							"[exploit-poc-summary] candidates=1 artifact=/tmp/pi-recon-exploit-candidates.json",
							"[exploit-replay] cmd=python3 exploit.py runs=5 timeout=8",
							"[exploit-replay] run=1 exit=0 duration=0.120 hash=aaa ok=true stdout_len=40 stderr_len=0",
							"[exploit-replay-summary] runs=5 ok=5 success_rate=1.000 unique_hashes=1 unique_exits=1 stable=true artifact=/tmp/pi-recon-exploit-replay-matrix.json",
							"[exploit-env] python=3.12 platform=Linux target=exploit.py sha256=abc",
							"[exploit-flake] runs=5 failures=0 unique_exits=1 unique_hashes=1 stable=true",
							"[exploit-bundle] manifest=/tmp/pi-recon-exploit-bundle-manifest.json artifacts=3",
							"[exploit-bundle-artifact] path=/tmp/pi-recon-exploit-replay-matrix.json bytes=512 sha256=def",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (script.includes("pcap-flow")) {
					return {
						code: 0,
						stdout: [
							"TCP Conversations",
							"10.0.0.1:1234 <-> 10.0.0.2:80",
							"http.request GET /flag",
							"[pcap-stream-rank] stream=0 packets=42 bytes=4096 duration=1.337 hosts=10.0.0.1,10.0.0.2 protocols=HTTP,TCP",
							"[pcap-secret-timeline] frame=7 time=Jun 08 stream=0 src=10.0.0.1 dst=10.0.0.2 value=Authorization: Bearer token",
							"/tmp/pi-recon-pcap-objects/flag.txt",
							"[pcap-transform-chain] file=/tmp/pi-recon-pcap-objects/flag.txt bytes=64 hints=base64,secret-string decoded=base64:flag{demo}",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (script.includes("firmware-static-fingerprint") || script.includes("firmware-extract-rootfs")) {
					return {
						code: 0,
						stdout: [
							"[firmware-image] path=router.bin bytes=8388608 sha256=abc magic=27051956 entropy=7.812",
							"DECIMAL HEXADECIMAL DESCRIPTION Squashfs filesystem, little endian, version 4.0",
							"[firmware-extract] target=router.bin out=/tmp/pi-recon-firmware-extract",
							"[firmware-rootfs] /tmp/pi-recon-firmware-extract/squashfs-root",
							"[firmware-config] root=/tmp/pi-recon-firmware-extract/squashfs-root",
							"[firmware-secret] /etc/passwd:root:$1$hash:0:0:root:/root:/bin/sh",
							"[firmware-service] /etc/init.d/S50dropbear dropbear -p 22",
							"[firmware-surface] endpoint=/www/cgi-bin/login.cgi",
							"[firmware-emulation] root=/tmp/pi-recon-firmware-extract/squashfs-root busybox=/bin/busybox arch=ELF 32-bit MSB executable, MIPS",
							"[firmware-emulation] qemu=qemu-mips-static",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (script.includes("agent-prompt-surface") || script.includes("agent-tool-boundary")) {
					return {
						code: 0,
						stdout: [
							"[agent-prompt] file=prompts/system.md",
							"[agent-prompt-risk] prompts/system.md:3: prompt injection ignore previous",
							"[agent-tool] file=src/tools.ts hits=tool-reg,exec,schema",
							"[agent-tool-risk] file=src/unsafe.ts reason=exec_without_visible_schema_guard",
							"[agent-memory] file=recon/memory/field-journal.md bytes=120 sha256=abc",
							"[agent-memory-risk] file=recon/memory/field-journal.md line=4 text=ignore previous developer message",
							"[agent-injection-replay] corpus=/tmp/pi-recon-agent-injection-corpus.jsonl cases=4 target=.",
							"[agent-injection-case] name=tool-json-smuggle channel=tool_output bytes=66",
							"[agent-delegation] file=src/mcp.ts hits=2",
							"[agent-delegation-risk] file=src/mcp.ts line=tools/call delegates to sub-agent capability",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (script.includes("malware-static-triage") || script.includes("malware-ioc-config")) {
					return {
						code: 0,
						stdout: [
							"[malware-static] path=sample.bin bytes=4096 sha256=abc magic=4d5a entropy=7.221",
							"[malware-static] format_hint=PE",
							"[malware-yara] Pi_RECON_Suspicious_Strings sample.bin",
							"[malware-capa] ATT&CK T1055 Process Injection",
							"[malware-floss] decoded-string http://c2.example/panel",
							"[malware-ioc] type=url value=http://c2.example/panel",
							"[malware-ioc] type=ipv4 value=10.10.10.10",
							"[malware-config-hint] keyword=CreateRemoteThread",
							"[malware-config-summary] unique_iocs=3",
							'[malware-behavior] execve("./sample.bin", ["./sample.bin"], 0x7ffc)',
							'[malware-behavior] connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("10.10.10.10")}, 16)',
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (script.includes("cloud-identity-config-map") || script.includes("cloud-runtime-config")) {
					return {
						code: 0,
						stdout: [
							"[cloud-identity] env=AWS_PROFILE len=7 sha256=abc",
							"[k8s-serviceaccount] token_path=/var/run/secrets/kubernetes.io/serviceaccount/token namespace=default",
							"[cloud-runtime-config] manifest=deploy.yaml",
							"[k8s-rbac] create pods yes",
							"[cloud-metadata] provider=aws-imds-token status=200 token_len=56",
							"[cloud-privilege-edge] file=rbac.yaml kind=k8s-rbac",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (script.includes("identity-ad-principal-enum") || script.includes("identity-ad-graph")) {
					return {
						code: 0,
						stdout: [
							"[ad-principal] domain=LAB dc=10.0.0.5 user=alice target=10.0.0.5",
							"[kerberos-ticket] path=/tmp/krb5cc_0 bytes=1200",
							"[ldap-anchor] dn: CN=alice,CN=Users,DC=lab,DC=local",
							"[ad-credential-check] target=10.0.0.5 user=alice pass_set=true hash_set=false",
							"[ad-graph-edge] file=bh.json hints=GenericAll,MemberOf",
							"[ad-cert-edge] file=certipy.txt hint=adcs/certipy",
							"[ad-graph-summary] files=2 edge_files=2",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
				if (script.includes("frida-gdb-trace")) {
					return {
						code: 0,
						stdout: [
							"[pi-recon-frida] Java runtime ready",
							"[doFinal] javax.crypto.Cipher",
							"[doFinal.ret] hexdump ...",
							"[native] strcmp 0x1 0x2",
						].join("\n"),
						stderr: "",
						killed: false,
					};
				}
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
		const laneTool = tools.get("re_lane") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const runFor = async (task: string, lane: string, target: string) => {
			await missionTool.execute("tool-call-id", { action: "new", task });
			const result = await laneTool.execute("tool-call-id", { action: "run", lane, target });
			return result.content[0]?.text ?? "";
		};

		const webRun = await runFor("Web API JWT auth websocket replay", "surface", "https://target.local/app");
		expect(webRun).toContain("browser/XHR/WS runtime anchors");
		expect(webRun).toContain("websocket endpoint anchors");
		expect(webRun).toContain("cookie/storage anchors");
		expect(webRun).toContain("browser-xhr-ws-auth-diff-rerun");
		expect(webRun).toContain("browser-xhr-ws-capture-rerun");
		expect(webRun).toContain("browser CDP artifact anchors");
		expect(webRun).toContain("browser runtime artifact paths");
		expect(webRun).toContain("browser replay evaluator anchors");
		expect(webRun).toContain("browser route graph anchors");
		expect(webRun).toContain("browser auth matrix anchors");
		expect(webRun).toContain("browser IDOR/BOLA probe anchors");
		expect(webRun).toContain("browser authz state machine anchors");
		expect(webRun).toContain("browser authz sequence replay anchors");
		expect(webRun).toContain("browser authz object ownership anchors");
		expect(webRun).toContain("browser authz state rollback anchors");
		expect(webRun).toContain("web API static authz source anchors");
		expect(webRun).toContain("web API schema/auth parameter anchors");
		expect(webRun).toContain("web API state mutation source anchors");
		expect(webRun).toContain("browser-cdp-artifact-rerun");
		expect(webRun).toContain("browser-replay-eval-rerun");
		expect(webRun).toContain("browser-route-graph-rerun");
		expect(webRun).toContain("browser-auth-matrix-rerun");
		expect(webRun).toContain("browser-idor-bola-probe-rerun");
		expect(webRun).toContain("browser-authz-state-machine-rerun");
		expect(webRun).toContain("browser-authz-sequence-replay-rerun");
		expect(webRun).toContain("browser-authz-object-ownership-rerun");
		expect(webRun).toContain("browser-authz-state-rollback-rerun");
		expect(webRun).toContain("web-api-authz-static-rerun");
		expect(webRun).toContain("web-api-schema-diff-rerun");
		expect(webRun).toContain("web-api-state-source-rerun");
		expect(webRun).toContain("browser-cdp-artifact-review");
		expect(webRun).toContain("browser-replay-eval-artifact-rerun");
		expect(webRun).toContain("browser-authz-report-scaffold");
		expect(webRun).toContain("browser-authz-state-report-scaffold");
		expect(webRun).toContain("evidence_quality:");
		expect(webRun).toMatch(/verdict: (strong|partial)/);

		const jsRun = await runFor("JS 签名 sign 参数 crypto.subtle fetch", "observe", "https://target.local/app.js");
		expect(jsRun).toContain("JS signing rebuild anchors");
		expect(jsRun).toContain("crypto.subtle operation anchors");
		expect(jsRun).toContain("JS signing normalized artifact anchors");
		expect(jsRun).toContain("JS first-divergence anchors");
		expect(jsRun).toContain("JS signing replay harness anchors");
		expect(jsRun).toContain("js-signing-observed-rebuild");
		expect(jsRun).toContain("js-signing-normalizer-rerun");
		expect(jsRun).toContain("js-first-divergence-rerun");
		expect(jsRun).toContain("js-signing-replay-harness-rerun");

		const nativeRun = await runFor("ELF native reverse license patch symbolic fuzz", "control-flow", "./license");
		expect(nativeRun).toContain("Native deep symbol/import/string anchors");
		expect(nativeRun).toContain("Native decompiler/control-flow anchors");
		expect(nativeRun).toContain("Native compare trace anchors");
		expect(nativeRun).toContain("Native patch hypothesis anchors");
		expect(nativeRun).toContain("Native symbolic/CFG anchors");
		expect(nativeRun).toContain("Native fuzz/crash anchors");
		expect(nativeRun).toContain("native-deep-symbol-map-rerun");
		expect(nativeRun).toContain("native-deep-decompiler-rerun");
		expect(nativeRun).toContain("native-deep-compare-trace-rerun");
		expect(nativeRun).toContain("native-deep-symbolic-fuzz-rerun");
		expect(nativeRun).toContain("native-deep-patch-report-scaffold");

		const pwnRun = await runFor("pwn ret2libc heap exploit", "primitive", "./vuln");
		expect(pwnRun).toContain("pwn primitive crash/control anchors");
		expect(pwnRun).toContain("pwn crash register anchors");
		expect(pwnRun).toContain("pwn cyclic offset anchors");
		expect(pwnRun).toContain("pwn gadget anchors");
		expect(pwnRun).toContain("pwn ROP/libc chain anchors");
		expect(pwnRun).toContain("pwn local verifier anchors");
		expect(pwnRun).toContain("pwn-cyclic-offset-helper");
		expect(pwnRun).toContain("pwn-focused-gdb-rerun");
		expect(pwnRun).toContain("pwn-offset-analyzer-rerun");
		expect(pwnRun).toContain("pwn-rop-libc-scaffold-rerun");
		expect(pwnRun).toContain("pwn-local-verifier-rerun");
		expect(pwnRun).toContain("pwn-pwntools-exploit-template");

		const exploitRun = await runFor("autopwn exploit reliability poc replay matrix", "replay", "./exploit.py");
		expect(exploitRun).toContain("Exploit PoC inventory anchors");
		expect(exploitRun).toContain("PoC replay matrix anchors");
		expect(exploitRun).toContain("Exploit environment pin anchors");
		expect(exploitRun).toContain("Exploit flake triage anchors");
		expect(exploitRun).toContain("Exploit artifact bundle anchors");
		expect(exploitRun).toContain("exploit-poc-normalizer-rerun");
		expect(exploitRun).toContain("exploit-replay-matrix-rerun");
		expect(exploitRun).toContain("exploit-env-pin-rerun");
		expect(exploitRun).toContain("exploit-flake-triage-rerun");
		expect(exploitRun).toContain("exploit-artifact-bundle-rerun");
		expect(exploitRun).toContain("exploit-reliability-report-scaffold");

		const pcapRun = await runFor("分析 pcap 流量", "map", "capture.pcapng");
		expect(pcapRun).toContain("PCAP/DFIR traffic flow anchors");
		expect(pcapRun).toContain("PCAP stream ranking anchors");
		expect(pcapRun).toContain("PCAP secret timeline anchors");
		expect(pcapRun).toContain("PCAP extracted artifact anchors");
		expect(pcapRun).toContain("PCAP transform chain anchors");
		expect(pcapRun).toContain("pcap-follow-streams");
		expect(pcapRun).toContain("pcap-object-review");
		expect(pcapRun).toContain("pcap-stream-rank-rerun");
		expect(pcapRun).toContain("pcap-secret-timeline-rerun");
		expect(pcapRun).toContain("pcap-transform-chain-rerun");
		expect(pcapRun).toContain("pcap-dfir-report-scaffold");

		const firmwareRun = await runFor("OpenWrt firmware binwalk squashfs rootfs mips", "inventory", "router.bin");
		expect(firmwareRun).toContain("Firmware image metadata anchors");
		expect(firmwareRun).toContain("Firmware extraction/rootfs anchors");
		expect(firmwareRun).toContain("Firmware config/secret anchors");
		expect(firmwareRun).toContain("Firmware service/web surface anchors");
		expect(firmwareRun).toContain("Firmware emulation/runtime anchors");
		expect(firmwareRun).toContain("firmware-extract-rerun");
		expect(firmwareRun).toContain("firmware-config-secret-rerun");
		expect(firmwareRun).toContain("firmware-service-surface-rerun");
		expect(firmwareRun).toContain("firmware-emulation-scaffold-rerun");
		expect(firmwareRun).toContain("firmware-report-scaffold");

		const agentSecRun = await runFor("LLM agent prompt injection MCP tool call memory poisoning", "surface", ".");
		expect(agentSecRun).toContain("Agent prompt surface anchors");
		expect(agentSecRun).toContain("Agent tool boundary anchors");
		expect(agentSecRun).toContain("Agent memory poisoning anchors");
		expect(agentSecRun).toContain("Agent injection replay anchors");
		expect(agentSecRun).toContain("Agent delegation trace anchors");
		expect(agentSecRun).toContain("agent-prompt-surface-rerun");
		expect(agentSecRun).toContain("agent-tool-boundary-rerun");
		expect(agentSecRun).toContain("agent-memory-poisoning-rerun");
		expect(agentSecRun).toContain("agent-injection-replay-rerun");
		expect(agentSecRun).toContain("agent-delegation-trace-rerun");
		expect(agentSecRun).toContain("agent-security-report-scaffold");

		const malwareRun = await runFor("malware sample yara capa floss c2 ioc config", "triage", "./sample.bin");
		expect(malwareRun).toContain("Malware static triage anchors");
		expect(malwareRun).toContain("Malware rule/capability anchors");
		expect(malwareRun).toContain("Malware IOC/config anchors");
		expect(malwareRun).toContain("Malware behavior trace anchors");
		expect(malwareRun).toContain("malware-static-triage-rerun");
		expect(malwareRun).toContain("malware-ioc-config-rerun");
		expect(malwareRun).toContain("malware-behavior-trace-rerun");
		expect(malwareRun).toContain("malware-report-scaffold");

		const cloudRun = await runFor("K8s cloud metadata serviceaccount privilege", "identity", ".");
		expect(cloudRun).toContain("Cloud identity anchors");
		expect(cloudRun).toContain("Cloud/K8s runtime config anchors");
		expect(cloudRun).toContain("Cloud metadata probe anchors");
		expect(cloudRun).toContain("Cloud privilege edge anchors");
		expect(cloudRun).toContain("cloud-identity-rerun");
		expect(cloudRun).toContain("cloud-runtime-config-rerun");
		expect(cloudRun).toContain("cloud-metadata-probe-rerun");
		expect(cloudRun).toContain("cloud-privilege-report-scaffold");

		const adRun = await runFor("AD kerberos ldap certipy bloodhound credential graph", "principals", "10.0.0.5");
		expect(adRun).toContain("Identity/AD principal anchors");
		expect(adRun).toContain("Identity/AD credential usability anchors");
		expect(adRun).toContain("Identity/AD graph edge anchors");
		expect(adRun).toContain("identity-ad-enum-rerun");
		expect(adRun).toContain("identity-ad-credential-check-rerun");
		expect(adRun).toContain("identity-ad-graph-rerun");
		expect(adRun).toContain("identity-ad-report-scaffold");

		const fridaRun = await runFor("Android APK frida bypass", "runtime-proof", "./app.apk");
		expect(fridaRun).toContain("Frida/GDB trace anchors");
		expect(fridaRun).toContain("runtime hook return/value anchors captured");
		expect(fridaRun).toContain("frida-focused-trace-rerun");
		expect(execCalls).toHaveLength(12);
	});
});

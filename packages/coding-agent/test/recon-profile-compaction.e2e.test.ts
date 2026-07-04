import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_BRANCH_ID = "REPI_BRANCH_ID";
const RUN_RECON_E2E = process.env.REPI_RUN_RECON_E2E === "1";

vi.setConfig({ testTimeout: 60_000 });

describe("REPI compaction/resume e2e", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousBranchId: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-compaction-e2e-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	// This exercises the full compaction -> auto-resume -> proof-loop -> case-memory
	// chain and is intentionally kept out of the fast default suite.
	it.skipIf(!RUN_RECON_E2E)("returns a REPI owned compaction result with a resume contract", async () => {
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
				previousSummary: "previous REPI summary",
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
		expect(compaction?.summary).toContain("kind: repi-compaction");
		expect(compaction?.summary).toContain("re_context resume");
		expect(compaction?.summary).toContain("re_operator plan");
		expect(compaction?.summary).toContain("re_operator dispatch");
		expect(compaction?.summary).toContain("re_proof_loop run <target> 4 2");
		expect(compaction?.summary).toContain("autonomous_execution_budget");
		expect(compaction?.details?.kind).toBe("repi-compaction");
		expect(compaction?.details?.resumeCommand).toBe("re_context resume");
		expect(compaction?.details?.contextPath).toBeDefined();
		expect(existsSync(compaction!.details!.contextPath!)).toBe(true);
		const checkpoint = appended.find((entry) => entry.type === "repi-compaction-checkpoint");
		expect(checkpoint).toBeDefined();
		expect(checkpoint?.details.compactionKind).toBe("repi-compaction");
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
		const resumeContract = appended.find((entry) => entry.type === "repi-compaction-resume-contract");
		expect(resumeContract).toBeDefined();
		expect(resumeContract?.details.kind).toBe("repi-compaction-resume-contract");
		expect(resumeContract?.details.verified).toBe(true);
		expect(resumeContract?.details.contextPath).toBe(compaction?.details?.contextPath);
		expect(String(resumeContract?.details.resumeContract)).toContain("re_context resume");
		const autoResume = appended.find((entry) => entry.type === "repi-compaction-auto-resume");
		expect(autoResume?.details.kind).toBe("repi-compaction-auto-resume");
		expect(autoResume?.details.triggered).toBe(true);
		const telemetry = appended.find((entry) => entry.type === "repi-compaction-resume-telemetry");
		expect(telemetry?.details.kind).toBe("repi-compaction-resume-telemetry");
		expect(String(telemetry?.details.path)).toContain("compaction-auto-resume-board.md");
		expect(sentMessages).toHaveLength(1);
		expect(sentMessages[0]?.message.customType).toBe("repi-auto-resume");
		expect(sentMessages[0]?.message.content).toContain("REPI Auto Resume Trigger");
		expect(sentMessages[0]?.message.content).toContain("bounded_resume_commands");
		// The auto-resume is queued as a steer WITHOUT triggering a turn: the handler
		// runs inside _runAutoCompaction, so triggerTurn:true would start a concurrent
		// agent.continue() that races the session loop ("Agent is already processing").
		// The session's own post-compaction while-loop drains the steer queue instead.
		expect(sentMessages[0]?.options?.triggerTurn).toBe(false);

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
});

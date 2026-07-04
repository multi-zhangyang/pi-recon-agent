import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { createReconExtensionFactory } from "../src/core/recon-profile.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_BRANCH_ID = "REPI_BRANCH_ID";

vi.setConfig({ testTimeout: 60_000 });

describe("REPI kernel profile proof-loop and swarm flows", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousBranchId: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-profile-proof-swarm-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("wires proof-loop gaps into a quick verifier/replayer/autofix path", async () => {
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
		const proofLoopTool = tools.get("re_proof_loop") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const runtimeAdapterTool = tools.get("re_runtime_adapter") as {
			execute: (
				toolCallId: string,
				params: Record<string, unknown>,
			) => Promise<{ content: Array<{ text: string }> }>;
		};
		const graphTool = tools.get("re_graph") as {
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
		expect(proof.content[0]?.text).toContain(
			"re_runtime_adapter run web-cdp-network-adapter https://target.local/app",
		);
		expect(proof.content[0]?.text).toContain("re_verifier matrix https://target.local/app");
		expect(proof.content[0]?.text).toContain("re_replayer run https://target.local/app 1");
		expect(proof.content[0]?.text).toContain("re_autofix plan https://target.local/app");
		expect(proof.content[0]?.text).toContain("source=attack_graph_gap");

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
		const nextProofActions = /next_proof_actions:([\s\S]*?)source_artifacts:/m.exec(proofRunText)?.[1] ?? "";
		expect(nextProofActions).not.toContain("re_runtime_adapter run web-cdp-network-adapter https://target.local/app");

		const graph = await graphTool.execute("tool-call-id", { action: "build" });
		const graphPath = /graph_artifact: (.+)/.exec(graph.content[0]?.text ?? "")?.[1]?.trim();
		expect(graphPath).toBeDefined();
		const graphText = readFileSync(graphPath!, "utf-8");
		expect(graphText).toContain("proof_loop plan");
		expect(graphText).toContain("quick_path");
		expect(graphText).toContain("proof-loop-gap");
		expect(graphText).toContain("proof-loop-output-hash");
		expect(graphText).toContain("output_sha256");
		expect(graphText).toContain("re_runtime_adapter run web-cdp-network-adapter https://target.local/app");
		expect(graphText).toContain("runtime-adapter-lineage");
		expect(graphText).toContain("runtime-adapter-artifact");
	});

	it("propagates swarm worker timeout budgets into runtime manifests", async () => {
		const tools = new Map<string, unknown>();
		const previousTimeout = process.env.REPI_SWARM_WORKER_TIMEOUT_MS;
		process.env.REPI_SWARM_WORKER_TIMEOUT_MS = "12345";
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
			exec: async () => ({ code: 0, stdout: "ok\n", stderr: "", killed: false }),
		} as unknown as ExtensionAPI;

		try {
			createReconExtensionFactory()(fakePi);
			const swarmTool = tools.get("re_swarm") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const swarm = await swarmTool.execute("tool-call-id", {
				action: "run",
				target: "https://target.local/api/login",
				maxWorkers: 1,
				maxCommands: 1,
			});
			expect(swarm.content[0]?.text).toContain("subagent_runtime_manifests:");
			expect(swarm.content[0]?.text).toContain("timeoutMs=12345");
			expect(swarm.content[0]?.text).toContain("worker_child_session_runtime:");
			expect(swarm.content[0]?.text).toContain("pool_bridge=pass");
			expect(swarm.content[0]?.text).toContain("worker_retry_handoff_closure:");
			expect(swarm.content[0]?.text).toContain("- status=pass");
			expect(swarm.content[0]?.text).toContain("retry_attempts_bounded=pass");
			expect(swarm.content[0]?.text).toContain("worker_retry_handoff_merge_summary:");
			expect(swarm.content[0]?.text).toContain("retry_budget_visible=pass");
			expect(swarm.content[0]?.text).toContain("source_artifacts_preserved=pass");
		} finally {
			if (previousTimeout === undefined) delete process.env.REPI_SWARM_WORKER_TIMEOUT_MS;
			else process.env.REPI_SWARM_WORKER_TIMEOUT_MS = previousTimeout;
		}
	});

	it("retries blocked swarm workers with attempt metadata", async () => {
		const tools = new Map<string, unknown>();
		const previousRetryLimit = process.env.REPI_SWARM_RETRY_LIMIT;
		process.env.REPI_SWARM_RETRY_LIMIT = "1";
		const delegationDir = join(agentDir, "recon", "evidence", "delegations");
		mkdirSync(delegationDir, { recursive: true });
		const fixturePath = join(delegationDir, "9999-12-31T23-59-59-retry-fixture-plan.md");
		const fixtureDelegate = {
			timestamp: "9999-12-31T23:59:59.000Z",
			route: "Retry fixture",
			mode: "plan",
			packets: [
				{
					id: "worker:retry:general",
					worker: "general",
					objective: "exercise blocked-command retry metadata",
					status: "ready",
					phases: ["retry"],
					steps: [
						{
							id: "op:retry:1",
							phase: "retry",
							command: "definitely_missing_repi_retry_fixture_command",
							status: "ready",
							sourceArtifacts: [],
						},
						{
							id: "op:retry:2",
							phase: "retry",
							command: "printf retry-ok",
							status: "ready",
							sourceArtifacts: [],
						},
					],
					evidenceContract: ["command output"],
					recommendedTools: [],
					handoffPrompt: [],
					sourceArtifacts: [],
				},
			],
			mergeQueue: [],
			specialistCoverage: [],
			workerScoreboard: [],
			adaptiveRoutingHints: [],
			workerPromotionQueue: [],
			autonomousBudget: {
				maxTurns: 3,
				maxDispatch: 1,
				maxProofLoops: 1,
				maxWorkerRetries: 1,
				scoreDecay: [],
				historicalScoreDecay: [],
				demotionRules: [],
				laneDemotions: [],
				workerDemotions: [],
				dispatcherDemotions: [],
				promotionRules: [],
				playbookPromotions: [],
				ledgerRows: [],
				nextActions: [],
			},
			dispatcherScoreDecay: [],
			repeatedFailureDemotions: [],
			highScorePromotions: [],
			gaps: [],
			nextActions: [],
			sourceArtifacts: [],
		};
		writeFileSync(
			fixturePath,
			["# Retry fixture", "", "```json", JSON.stringify(fixtureDelegate, null, 2), "```", ""].join("\n"),
		);
		let execCalls = 0;
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
			exec: async () => {
				execCalls += 1;
				return execCalls === 1
					? { code: 127, stdout: "", stderr: "command not found\n", killed: false }
					: { code: 0, stdout: "retry-ok\n", stderr: "", killed: false };
			},
		} as unknown as ExtensionAPI;

		try {
			createReconExtensionFactory()(fakePi);
			const swarmTool = tools.get("re_swarm") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const swarm = await swarmTool.execute("tool-call-id", {
				action: "run",
				maxWorkers: 1,
				maxCommands: 1,
			});
			expect(swarm.content[0]?.text).toContain("retry_execution:");
			expect(swarm.content[0]?.text).toContain("attempt=2/");
			expect(swarm.content[0]?.text).toContain("retryRemaining=");
			expect(swarm.content[0]?.text).toContain("retries=1");
			expect(swarm.content[0]?.text).toContain("worker_retry_handoff_closure:");
			expect(swarm.content[0]?.text).toContain("attempt=2/3");
			expect(swarm.content[0]?.text).toContain("failed_workers_closed=pass");
			expect(swarm.content[0]?.text).toContain("worker_retry_handoff_merge_summary:");
			expect(swarm.content[0]?.text).toContain("next=re_swarm retry");
		} finally {
			if (previousRetryLimit === undefined) delete process.env.REPI_SWARM_RETRY_LIMIT;
			else process.env.REPI_SWARM_RETRY_LIMIT = previousRetryLimit;
		}
	});
});

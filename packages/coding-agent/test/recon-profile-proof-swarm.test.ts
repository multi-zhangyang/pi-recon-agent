import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createRegisteredReconHarness } from "./recon-profile-harness.ts";

vi.setConfig({ testTimeout: 60_000 });

describe("REPI kernel profile swarm flows", () => {
	it("propagates swarm worker timeout budgets into runtime manifests", async () => {
		const previousTimeout = process.env.REPI_SWARM_WORKER_TIMEOUT_MS;
		process.env.REPI_SWARM_WORKER_TIMEOUT_MS = "12345";
		const harness = createRegisteredReconHarness("repi-profile-swarm-timeout", {
			exec: async () => ({ code: 0, stdout: "ok\n", stderr: "", killed: false }),
		});

		try {
			const swarmTool = harness.tools.get("re_swarm") as {
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
			expect(swarm.content[0]?.text).toContain("worker_closures=3");
			expect(swarm.content[0]?.text).toContain("closure=worker=");
			expect(swarm.content[0]?.text).toContain("closure=passed");

			const graph = await graphTool.execute("tool-call-id", { action: "build" });
			const graphPath = /graph_artifact: (.+)/.exec(graph.content[0]?.text ?? "")?.[1]?.trim();
			expect(graphPath).toBeDefined();
			const graphText = readFileSync(graphPath!, "utf-8");
			expect(graphText).toContain("swarm-worker-closure");
			expect(graphText).toContain("worker_retry_handoff_closure");
			expect(graphText).toContain("worker-closure-next");
			expect(graphText).toContain("retry_budget_visible=pass");
		} finally {
			harness.restore();
			if (previousTimeout === undefined) delete process.env.REPI_SWARM_WORKER_TIMEOUT_MS;
			else process.env.REPI_SWARM_WORKER_TIMEOUT_MS = previousTimeout;
		}
	});

	it("retries blocked swarm workers with attempt metadata", async () => {
		const previousRetryLimit = process.env.REPI_SWARM_RETRY_LIMIT;
		process.env.REPI_SWARM_RETRY_LIMIT = "1";
		let execCalls = 0;
		const harness = createRegisteredReconHarness("repi-profile-swarm-retry", {
			exec: async () => {
				execCalls += 1;
				return execCalls === 1
					? { code: 127, stdout: "", stderr: "command not found\n", killed: false }
					: { code: 0, stdout: "retry-ok\n", stderr: "", killed: false };
			},
		});
		const delegationDir = join(harness.agentDir, "recon", "evidence", "delegations");
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

		try {
			const swarmTool = harness.tools.get("re_swarm") as {
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
			expect(swarm.content[0]?.text).toContain("worker_closures=1");
			expect(swarm.content[0]?.text).toContain("closure=retry_queued");
			expect(swarm.content[0]?.text).toContain("next=re_swarm retry");
		} finally {
			harness.restore();
			if (previousRetryLimit === undefined) delete process.env.REPI_SWARM_RETRY_LIMIT;
			else process.env.REPI_SWARM_RETRY_LIMIT = previousRetryLimit;
		}
	});
});

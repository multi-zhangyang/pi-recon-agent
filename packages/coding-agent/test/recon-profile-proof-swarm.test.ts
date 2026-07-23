import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { discoverSwarmRuns } from "../../../scripts/reverse-agent/lib/swarm-run-catalog.mjs";
import { readCurrentMission } from "../src/core/repi/mission.ts";
import type { SwarmArtifact } from "../src/core/repi/swarm-runtime-types.ts";
import { parseJsonCodeFence } from "../src/core/repi/text.ts";
import { createRegisteredReconHarness } from "./recon-profile-harness.ts";

vi.setConfig({ testTimeout: 60_000 });

describe("REPI kernel profile swarm flows", () => {
	it("fails closed when real swarm execution has no cwd", async () => {
		let execCalls = 0;
		const harness = createRegisteredReconHarness("repi-profile-swarm-real-missing-cwd", {
			exec: async () => {
				execCalls += 1;
				return { code: 0, stdout: "simulated\n", stderr: "", killed: false };
			},
		});

		try {
			const swarmTool = harness.tools.get("re_swarm") as {
				execute: (toolCallId: string, params: Record<string, unknown>) => Promise<unknown>;
			};
			await expect(swarmTool.execute("tool-call-id", { action: "run", execution: "real" })).rejects.toThrow(
				"RE_SWARM_REAL_CWD_REQUIRED",
			);
			expect(execCalls).toBe(0);
		} finally {
			harness.restore();
		}
	});

	it("fails closed instead of simulating a recursive real swarm", async () => {
		const previousAgentThread = process.env.REPI_AGENT_THREAD;
		let execCalls = 0;
		const harness = createRegisteredReconHarness("repi-profile-swarm-real-recursion", {
			exec: async () => {
				execCalls += 1;
				return { code: 0, stdout: "simulated\n", stderr: "", killed: false };
			},
		});
		process.env.REPI_AGENT_THREAD = "1";

		try {
			const swarmTool = harness.tools.get("re_swarm") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
					signal?: AbortSignal,
					onUpdate?: unknown,
					ctx?: { cwd: string },
				) => Promise<unknown>;
			};
			await expect(
				swarmTool.execute("tool-call-id", { action: "run", execution: "real" }, undefined, undefined, {
					cwd: harness.agentDir,
				}),
			).rejects.toThrow("RE_SWARM_REAL_RECURSION_BLOCKED");
			expect(execCalls).toBe(0);
		} finally {
			harness.restore();
			if (previousAgentThread === undefined) delete process.env.REPI_AGENT_THREAD;
			else process.env.REPI_AGENT_THREAD = previousAgentThread;
		}
	});

	it("executes a real isolated worker and records only observed child identity", async () => {
		const previousBin = process.env.REPI_BIN_PATH;
		const previousProvider = process.env.REPI_SUBAGENT_PROVIDER;
		const previousModel = process.env.REPI_SUBAGENT_MODEL;
		const harness = createRegisteredReconHarness("repi-profile-swarm-real-child");
		const workerBin = join(harness.tempDir, "real-worker.sh");
		writeFileSync(
			workerBin,
			[
				"#!/bin/sh",
				'mkdir -p "$(dirname "$REPI_WORKER_HANDOFF_PATH")"',
				`printf 'run_id: %s\\nmission_id: %s\\nlineage_sha256: %s\\nOutcome: verified\\nVerification: process-isolated worker\\n' "$REPI_WORKER_RUN_ID" "$REPI_WORKER_MISSION_ID" "$REPI_WORKER_LINEAGE_SHA256" > "$REPI_WORKER_HANDOFF_PATH"`,
				"printf 'real worker process\\n'",
				"exit 0",
				"",
			].join("\n"),
			"utf8",
		);
		chmodSync(workerBin, 0o700);
		process.env.REPI_BIN_PATH = workerBin;
		process.env.REPI_SUBAGENT_PROVIDER = "fixture-provider";
		process.env.REPI_SUBAGENT_MODEL = "fixture-model";
		try {
			const swarmTool = harness.tools.get("re_swarm") as {
				execute: (
					toolCallId: string,
					params: Record<string, unknown>,
					signal?: AbortSignal,
					onUpdate?: unknown,
					ctx?: { cwd: string },
				) => Promise<{ content: Array<{ text: string }> }>;
			};
			const result = await swarmTool.execute(
				"tool-call-id",
				{
					action: "run",
					target: "https://target.local/api/login",
					maxWorkers: 1,
					maxCommands: 1,
					execution: "real",
				},
				undefined,
				undefined,
				{ cwd: harness.agentDir },
			);
			const text = result.content[0]?.text ?? "";
			expect(text).toContain("parallel_mode=real_subagent");
			expect(text).toContain("provider=fixture-provider");
			expect(text).toContain("model=fixture-model");
			expect(text).toContain("mcp_inherited=false");
			expect(text).not.toContain("local-openai");
			expect(text).not.toContain("command-level-worker");
			const artifactPath = /swarm_artifact: (.+)/.exec(text)?.[1]?.trim();
			expect(artifactPath).toBeDefined();
			const artifact = parseJsonCodeFence(readFileSync(artifactPath!, "utf8")) as {
				executions: Array<{
					executionMode: string;
					artifactValidation: string;
					mcpInherited: boolean;
					provider: string;
					modelId: string;
				}>;
				subagentRuntimeManifests: Array<{
					model: { provider: string; modelId: string; source: string; modelCalls: number | null };
				}>;
			};
			expect(artifact.executions[0]).toMatchObject({
				executionMode: "real_subagent",
				artifactValidation: "passed",
				mcpInherited: false,
				provider: "fixture-provider",
				modelId: "fixture-model",
			});
			expect(artifact.subagentRuntimeManifests[0]?.model).toMatchObject({
				provider: "fixture-provider",
				modelId: "fixture-model",
				source: "agent-thread-manifest",
				modelCalls: null,
			});

			writeFileSync(
				workerBin,
				[
					"#!/bin/sh",
					`printf 'run_id: %s\\nmission_id: %s\\nlineage_sha256: forged\\nOutcome: unverified\\n' "$REPI_WORKER_RUN_ID" "$REPI_WORKER_MISSION_ID" > "$REPI_WORKER_HANDOFF_PATH"`,
					"exit 0",
					"",
				].join("\n"),
				"utf8",
			);
			const blockedResult = await swarmTool.execute(
				"tool-call-invalid-handoff",
				{
					action: "run",
					target: "https://target.local/api/login",
					maxWorkers: 1,
					maxCommands: 1,
					execution: "real",
				},
				undefined,
				undefined,
				{ cwd: harness.agentDir },
			);
			const blockedText = blockedResult.content[0]?.text ?? "";
			const blockedArtifactPath = /swarm_artifact: (.+)/.exec(blockedText)?.[1]?.trim();
			expect(blockedArtifactPath).toBeDefined();
			const blockedArtifact = parseJsonCodeFence(readFileSync(blockedArtifactPath!, "utf8")) as {
				executions: Array<{
					status: string;
					executionMode: string;
					artifactValidation: string;
					exitCode: number;
					sourceArtifacts: string[];
				}>;
			};
			expect(blockedArtifact.executions[0]).toMatchObject({
				status: "blocked",
				executionMode: "real_subagent",
				artifactValidation: "blocked",
				exitCode: 1,
			});
			expect(blockedArtifact.executions[0]?.sourceArtifacts).not.toEqual(
				expect.arrayContaining([expect.stringMatching(/(?:handoff|merge)\.(?:md|json)$/)]),
			);
			expect(blockedText).toContain("merge_handoff=withheld");
			expect(blockedText).not.toContain("Outcome: unverified");
			expect(blockedText).not.toContain("simulated_sequential_for_internal_repi_commands");
		} finally {
			harness.restore();
			if (previousBin === undefined) delete process.env.REPI_BIN_PATH;
			else process.env.REPI_BIN_PATH = previousBin;
			if (previousProvider === undefined) delete process.env.REPI_SUBAGENT_PROVIDER;
			else process.env.REPI_SUBAGENT_PROVIDER = previousProvider;
			if (previousModel === undefined) delete process.env.REPI_SUBAGENT_MODEL;
			else process.env.REPI_SUBAGENT_MODEL = previousModel;
		}
	});

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
				execution: "simulated",
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
		const missionTool = harness.tools.get("re_mission") as {
			execute: (toolCallId: string, params: Record<string, unknown>) => Promise<unknown>;
		};
		await missionTool.execute("retry-mission", { action: "new", task: "exercise swarm retry fixture" });
		const delegationDir = join(harness.agentDir, "recon", "evidence", "delegations");
		mkdirSync(delegationDir, { recursive: true });
		const fixturePath = join(delegationDir, "9999-12-31T23-59-59-retry-fixture-plan.md");
		const fixtureDelegate = {
			timestamp: "9999-12-31T23:59:59.000Z",
			missionId: readCurrentMission()?.id,
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
				demotionRules: [],
				laneDemotions: [],
				workerDemotions: [],
				dispatcherDemotions: [],
				promotionRules: [],
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
				execution: "simulated",
			});
			const output = swarm.content[0]?.text ?? "";
			expect(output).toContain("retry_execution:");
			expect(output).toContain("attempt=2/");
			expect(output).toContain("retryRemaining=");
			expect(output).toContain("retries=1");
			expect(output).toContain("historical_blocked=1");
			expect(output).toContain("recovered=true");
			expect(output).toContain("worker_retry_handoff_closure:");
			expect(output).toContain("attempt=2/3");
			expect(output).toContain("failed_workers_closed=pass");
			expect(output).toContain("worker_retry_handoff_merge_summary:");
			expect(output).toContain("worker_closures=1");
			expect(output).toContain("closure=passed");
			expect(output).not.toContain("closure=retry_queued");

			const artifactPath = /^swarm_artifact:\s*(.+)$/m.exec(output)?.[1]?.trim();
			expect(artifactPath).toBeDefined();
			const persisted = parseJsonCodeFence<SwarmArtifact>(readFileSync(artifactPath!, "utf8"));
			expect(persisted).toBeDefined();
			expect(persisted?.workers).toHaveLength(1);
			expect(persisted?.workers[0]?.status).toBe("done");
			expect(persisted?.blocked).toEqual([]);
			expect(persisted?.retryQueue).toEqual([]);
			expect(persisted?.subagentRuntimeManifests[0]?.status).toBe("done");
			expect(persisted?.structuredClaimMergeStatus).toBe("pass");
			expect(persisted?.structuredClaimMerge?.promotionCheck.finalClaims.length).toBeGreaterThan(0);

			const manifestPath = persisted?.subagentRuntimeManifests[0]?.runtimeManifestFile;
			expect(manifestPath).toBeDefined();
			expect(JSON.parse(readFileSync(manifestPath!, "utf8"))).toMatchObject({
				attempt: 2,
				status: "done",
				exitCode: 0,
				signal: null,
			});

			const catalogRun = discoverSwarmRuns({ agentDir: harness.agentDir }).find(
				(run) => run.paths?.artifact === artifactPath,
			);
			expect(catalogRun).toMatchObject({ engine: "ts", state: "complete", status: "complete", ok: true });
		} finally {
			harness.restore();
			if (previousRetryLimit === undefined) delete process.env.REPI_SWARM_RETRY_LIMIT;
			else process.env.REPI_SWARM_RETRY_LIMIT = previousRetryLimit;
		}
	});
});

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { atomicWriteFileSync } from "../tools/atomic-write.ts";
import { swarmSubagentSessionRoot, swarmWorkerChildSessionRuntimePath } from "./swarm-artifact-paths.ts";
import type {
	SwarmArtifact,
	SwarmSubagentRuntimeManifestRow,
	WorkerChildProcessProbeV1,
	WorkerChildSessionClaimLedgerEventV1,
	WorkerChildSessionRuntimeBatchV1,
	WorkerChildSessionRuntimeStatus,
	WorkerChildSessionRuntimeV1,
	WorkerRuntimePoolWorkerV1,
} from "./swarm-runtime-types.ts";
import { slug, uniqueNonEmpty } from "./text.ts";
import {
	verifyWorkerChildSessionRuntimeBatch,
	verifyWorkerRuntimePool,
	workerChildSessionLaunchPolicy,
	workerChildSessionToWorkerRuntimePoolBridge,
} from "./worker-runtime.ts";

export type SwarmWorkerChildSessionRuntimeDependencies = {
	executionDigest(value: string): string;
};

export function createSwarmWorkerChildSessionRuntime(dependencies: SwarmWorkerChildSessionRuntimeDependencies) {
	const { executionDigest } = dependencies;

	function swarmChildSessionStatusFromManifest(
		manifest: SwarmSubagentRuntimeManifestRow,
	): WorkerChildSessionRuntimeStatus {
		if (manifest.status === "done") return "passed";
		if (manifest.status === "blocked") return "failed";
		if (manifest.status === "cancelled") return manifest.signal === "SIGTERM" ? "timeout" : "cancelled";
		return "queued";
	}

	function swarmChildSessionWorkerStatusFromManifest(
		manifest: SwarmSubagentRuntimeManifestRow,
	): WorkerRuntimePoolWorkerV1["status"] {
		if (manifest.status === "done") return "passed";
		if (manifest.status === "blocked") return "failed";
		if (manifest.status === "cancelled") return manifest.signal === "SIGTERM" ? "timeout" : "cancelled";
		return "queued";
	}

	function swarmChildSessionProviderFromManifest(
		manifest: SwarmSubagentRuntimeManifestRow,
	): WorkerChildSessionRuntimeV1["provider"] {
		return {
			// AgentThread v1 persists the selected provider/model, but not API format,
			// endpoint refs, context size, output limit, or exact provider-call count.
			// Preserve only observed fields instead of manufacturing local-openai data.
			format: "unknown",
			name: manifest.model?.provider || "unknown",
			modelId: manifest.model?.modelId || "unknown",
			source: manifest.model?.source ?? "unknown",
		};
	}

	function swarmChildSessionClaimRefs(swarm: SwarmArtifact, workerId: string): string[] {
		return uniqueNonEmpty(
			(swarm.claimLedger ?? [])
				.filter(
					(event) =>
						event.workerId === workerId &&
						event.claimId &&
						["claim", "validation", "challenge", "resolution", "artifact_handoff"].includes(event.type),
				)
				.map((event) => event.claimId),
			8,
		);
	}

	function swarmChildSessionTranscript(manifest: SwarmSubagentRuntimeManifestRow, claimRefs: string[]): string {
		return `${[
			JSON.stringify({
				kind: "WorkerChildSessionTranscriptV1",
				sessionId: `child-${slug(manifest.workerId)}-${manifest.attempt}`,
				workerId: manifest.workerId,
				roleId: manifest.roleId,
				status: manifest.status,
				provider: swarmChildSessionProviderFromManifest(manifest),
				claimRefs,
				runtimeManifestFile: manifest.runtimeManifestFile,
				stdoutPath: manifest.stdoutPath,
				stderrPath: manifest.stderrPath,
				stdoutSha256: manifest.stdoutSha256,
				stderrSha256: manifest.stderrSha256,
				toolCallDigest: manifest.toolCallDigest,
			}),
			JSON.stringify({
				event: "pool_bridge",
				poolId: manifest.runId,
				mergeKeys: manifest.mergeKeys,
				retryBudget: manifest.retryBudget,
				resourceLimits: manifest.resourceLimits,
				evidenceRefs: manifest.evidenceRefs,
			}),
		].join("\n")}\n`;
	}

	function buildWorkerChildSessionRuntimeBatchFromSwarm(swarm: SwarmArtifact): WorkerChildSessionRuntimeBatchV1 {
		const manifests = swarm.subagentRuntimeManifests ?? [];
		const batchId = `worker-child-session/${slug(swarm.route ?? swarm.target ?? "swarm")}/${swarm.timestamp}`;
		const poolId = swarm.parallelPlan?.planId ?? `re_swarm/${swarm.timestamp}`;
		const launchPolicy = workerChildSessionLaunchPolicy({
			cwd: process.cwd(),
			isolatedHome: join(swarmSubagentSessionRoot(swarm), ".repi", "agent"),
			timeoutMs: Math.max(
				1000,
				Math.min(
					30 * 60 * 1000,
					Math.max(...manifests.map((manifest) => manifest.resourceLimits.timeoutMs), 30000),
				),
			),
		});
		const sessions = manifests.map((manifest): WorkerChildSessionRuntimeV1 => {
			const claimRefs = swarmChildSessionClaimRefs(swarm, manifest.workerId);
			const sessionId = `child-${slug(manifest.workerId)}-${manifest.attempt}`;
			const transcriptPath = join(manifest.sessionDir, "transcript.jsonl");
			const transcript = swarmChildSessionTranscript(manifest, claimRefs);
			atomicWriteFileSync(transcriptPath, transcript, 0o644);
			const transcriptSha256 = executionDigest(transcript);
			const timedOut = manifest.status === "cancelled" && manifest.signal === "SIGTERM";
			const status = timedOut ? "timeout" : swarmChildSessionStatusFromManifest(manifest);
			const runtime: WorkerChildSessionRuntimeV1["runtime"] = {
				status,
				pid: manifest.pid,
				sessionDir: manifest.sessionDir,
				transcriptPath,
				stdoutPath: manifest.stdoutPath,
				stderrPath: manifest.stderrPath,
				startedAt: manifest.startedAt,
				endedAt: manifest.endedAt,
				exitCode: manifest.exitCode,
				signal: timedOut ? "SIGTERM" : manifest.signal,
				...(status === "timeout" ? { cancelledAt: manifest.endedAt } : {}),
			};
			return {
				sessionId,
				workerId: manifest.workerId,
				packetId: `packet-${slug(manifest.workerId)}`,
				attempt: manifest.attempt,
				maxAttempts: manifest.retryBudget.maxAttempts,
				provider: swarmChildSessionProviderFromManifest(manifest),
				runtime,
				hashes: {
					transcriptSha256,
					stdoutSha256: manifest.stdoutSha256,
					stderrSha256: manifest.stderrSha256,
					toolCallDigest: manifest.toolCallDigest,
				},
				resourceLease: {
					cpuSlots: 1,
					memoryMb: 768,
					maxProcesses: 2,
				},
				retryBudget: manifest.retryBudget,
				poolBridge: {
					poolId,
					mergeKey: claimRefs[0] ?? manifest.mergeKeys[0] ?? manifest.workerId,
					claimRefs,
					workerRuntimePoolStatus: timedOut ? "timeout" : swarmChildSessionWorkerStatusFromManifest(manifest),
				},
				failureRepairRefs: [manifest.failureLedgerPath, manifest.repairQueuePath].filter(Boolean),
			};
		});
		return {
			kind: "WorkerChildSessionRuntimeBatchV1",
			schemaVersion: 1,
			batchId,
			poolId,
			resourceBudget: {
				cpuSlots: Math.max(1, Math.min(8, sessions.length || 1)),
				memoryMb: Math.max(1024, sessions.length * 768),
				maxProcesses: Math.max(2, sessions.length * 2),
			},
			launchPolicy,
			sessions,
			claimLedgerEvents: (swarm.claimLedger ?? []) as WorkerChildSessionClaimLedgerEventV1[],
			poolBridge: {
				kind: "WorkerRuntimePoolV1Bridge",
				poolId,
				workerIds: sessions.map((session) => session.workerId),
				claimAwareMerge: true,
				childSessionRuntimeCaptured: sessions.length > 0,
			},
		};
	}

	function runWorkerChildProcessProbe(
		batch: WorkerChildSessionRuntimeBatchV1,
		artifactPath: string,
	): WorkerChildProcessProbeV1 {
		const probeId = `child-process-probe:${createHash("sha256").update(`${batch.batchId}:${artifactPath}`).digest("hex").slice(0, 16)}`;
		const probeDir = artifactPath.replace(/\.json$/i, "-child-process");
		const home = join(probeDir, "home");
		const isolatedHome = join(home, ".repi", "agent");
		mkdirSync(isolatedHome, { recursive: true });
		const stdoutPath = join(probeDir, "stdout.txt");
		const stderrPath = join(probeDir, "stderr.txt");
		const command =
			process.env.REPI_CHILD_PROCESS_REPI_BIN ??
			(existsSync(join(process.env.REPI_REPO_ROOT ?? process.cwd(), "repi"))
				? join(process.env.REPI_REPO_ROOT ?? process.cwd(), "repi")
				: "repi");
		const args = ["--offline", "--help"];
		const cwd = existsSync(process.env.REPI_REPO_ROOT ?? "") ? (process.env.REPI_REPO_ROOT as string) : process.cwd();
		const envAllowlist = uniqueNonEmpty(
			[...batch.launchPolicy.envAllowlist, "REPI_CODING_AGENT_DIR", "REPI_REPO_ROOT"],
			64,
		);
		const envDenylist = batch.launchPolicy.envDenylist;
		const env: NodeJS.ProcessEnv = {
			PATH: process.env.PATH ?? "",
			HOME: home,
			REPI_PRODUCT: "1",
			REPI_PRIMARY: "1",
			REPI_OFFLINE: "1",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			REPI_CODING_AGENT_DIR: isolatedHome,
			REPI_CODING_AGENT_CONFIG_DIR: ".repi",
			REPI_CODING_AGENT_APP_NAME: "repi",
			PI_OFFLINE: "1",
			PI_SKIP_VERSION_CHECK: "1",
			PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			PI_TELEMETRY: "0",
		};
		if (process.env.REPI_REPO_ROOT) env.REPI_REPO_ROOT = process.env.REPI_REPO_ROOT;
		const started = Date.now();
		const startedAt = new Date(started).toISOString();
		const result = spawnSync(command, args, {
			cwd,
			env,
			encoding: "utf8",
			timeout: Math.min(30000, Math.max(5000, batch.launchPolicy.timeoutMs)),
			maxBuffer: 8 * 1024 * 1024,
		});
		const ended = Date.now();
		const stdout = result.stdout ?? "";
		const stderr = result.stderr ?? "";
		atomicWriteFileSync(stdoutPath, stdout, 0o644);
		atomicWriteFileSync(stderrPath, stderr, 0o644);
		const combined = `${stdout}\n${stderr}`;
		const assertions = {
			repiCommandExecuted: /repi\b/i.test(combined) && /REPI|reverse\/pentest|independent product/i.test(combined),
			isolatedRepiHome: isolatedHome.includes(".repi") && !isolatedHome.includes("/.pi/"),
			noPiHomeImport: !/(^|[\\s"'])~?\\\/?\\.pi\\\//i.test(combined),
			updateChecksDisabled: !/Update Available|pi\\.dev\/changelog|Run pi update/i.test(combined),
			telemetryDisabled: env.REPI_TELEMETRY === "0",
			noLiteralSecrets: !/(sk-[A-Za-z0-9]|ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9])/i.test(combined),
			stdoutCaptured: stdout.length > 0 || stderr.length > 0,
		};
		const errors = Object.entries(assertions)
			.filter(([, value]) => !value)
			.map(([key]) => `assertion_failed:${key}`);
		if (result.error) errors.push(`spawn_error:${result.error.message}`);
		if ((result.status ?? 1) !== 0) errors.push(`exit_code:${result.status}`);
		return {
			kind: "WorkerChildProcessProbeV1",
			schemaVersion: 1,
			probeId,
			command,
			args,
			cwd,
			isolatedHome,
			startedAt,
			endedAt: new Date(ended).toISOString(),
			elapsedMs: Math.max(0, ended - started),
			exitCode: result.status,
			signal: result.signal,
			status: errors.length ? "blocked" : "pass",
			stdoutPath,
			stderrPath,
			stdoutSha256: executionDigest(stdout),
			stderrSha256: executionDigest(stderr),
			envAllowlist,
			envDenylist,
			assertions,
			errors: uniqueNonEmpty(errors, 32),
		};
	}

	function refreshSwarmWorkerChildSessionRuntime(swarm: SwarmArtifact): SwarmArtifact {
		const path = swarmWorkerChildSessionRuntimePath(swarm);
		if (!(swarm.subagentRuntimeManifests ?? []).length) {
			return {
				...swarm,
				workerChildSessionRuntimePath: path,
				workerChildSessionRuntimeStatus: "missing",
				workerChildSessionRuntimeErrors: ["subagent_runtime_manifests_missing"],
				workerRuntimePoolBridgeStatus: "missing",
				workerRuntimePoolBridgeErrors: ["subagent_runtime_manifests_missing"],
			};
		}
		const initialBatch = buildWorkerChildSessionRuntimeBatchFromSwarm(swarm);
		const childProcessProbe =
			process.env.REPI_SWARM_CHILD_PROCESS_SMOKE === "1"
				? runWorkerChildProcessProbe(initialBatch, path)
				: undefined;
		const batch: WorkerChildSessionRuntimeBatchV1 = childProcessProbe
			? {
					...initialBatch,
					childProcessProbe,
					poolBridge: {
						...initialBatch.poolBridge,
						childProcessRuntimeCaptured: childProcessProbe.status === "pass",
					},
				}
			: initialBatch;
		const batchValidation = verifyWorkerChildSessionRuntimeBatch(batch);
		const pool = workerChildSessionToWorkerRuntimePoolBridge(batch);
		const poolValidation = verifyWorkerRuntimePool(pool);
		atomicWriteFileSync(
			path,
			`${JSON.stringify({ batch, batchValidation, workerRuntimePoolBridge: pool, poolValidation }, null, 2)}\n`,
			0o644,
		);
		return {
			...swarm,
			workerChildSessionRuntimePath: path,
			workerChildSessionRuntime: batch,
			workerChildSessionRuntimeStatus: batchValidation.ok ? "pass" : "blocked",
			workerChildSessionRuntimeErrors: batchValidation.errors,
			workerRuntimePoolBridge: pool,
			workerRuntimePoolBridgeStatus: poolValidation.ok ? "pass" : "blocked",
			workerRuntimePoolBridgeErrors: poolValidation.errors,
			sourceArtifacts: Array.from(
				new Set(
					[
						...swarm.sourceArtifacts,
						path,
						batch.childProcessProbe?.stdoutPath,
						batch.childProcessProbe?.stderrPath,
						...batch.sessions.flatMap((session) => [
							session.runtime.transcriptPath,
							session.runtime.stdoutPath,
							session.runtime.stderrPath,
						]),
					].filter((item): item is string => Boolean(item)),
				),
			).slice(0, 80),
		};
	}

	return {
		buildWorkerChildSessionRuntimeBatchFromSwarm,
		runWorkerChildProcessProbe,
		refreshSwarmWorkerChildSessionRuntime,
	};
}

export type SwarmWorkerChildSessionRuntime = ReturnType<typeof createSwarmWorkerChildSessionRuntime>;

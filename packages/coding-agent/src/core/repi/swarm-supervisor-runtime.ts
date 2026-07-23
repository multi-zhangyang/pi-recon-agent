import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createAgentThreadManager } from "../agent-thread-manager.ts";
import type { ExtensionAPI } from "../extensions/types.ts";
import { atomicWriteFileSync } from "../tools/atomic-write.ts";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import { ensureReconStorage } from "./resources.ts";
import {
	evidenceLedgerPath,
	evidenceSupervisorsDir,
	evidenceSwarmsDir,
	readTextFile as readText,
	runtimeFailureLedgerPath,
	runtimeRepairQueuePath,
	writePrivateTextFile,
} from "./storage.ts";
import {
	swarmArtifactPath,
	swarmClaimLedgerPath,
	swarmStructuredClaimMergePath,
	swarmSubagentRuntimeManifestIndexPath,
	swarmSubagentSessionRoot,
	swarmWorkerChildSessionRuntimePath,
	swarmWorkerLeaseSchedulerPath,
	swarmWorkerRetryHandoffClosurePath,
	swarmWorkerRetryHandoffMergeSummaryPath,
} from "./swarm-artifact-paths.ts";
import { createSwarmClaimRuntime } from "./swarm-claim-runtime.ts";
import { createSwarmCommanderRuntime } from "./swarm-commander-runtime.ts";
import type {
	DelegateArtifact,
	DelegatePacket,
	OperationStepStatus,
	ReconParallelPlanV1,
	SwarmArtifact,
	SwarmBuildOptions,
	SwarmOutputOptions,
	SwarmRunOptions,
	SwarmRuntimeModelSummary,
	SwarmRuntimeRetryBudget,
	SwarmRuntimeState,
	SwarmSubagentRuntimeManifestRow,
	SwarmSubagentRuntimeManifestV1,
	SwarmSupervisorRuntimeDependencies,
	SwarmWorkerExecution,
	SwarmWorkerRuntime,
} from "./swarm-runtime-types.ts";
import { createSwarmWorkerArtifactRuntime } from "./swarm-worker-artifact-runtime.ts";
import { shellQuote } from "./target.ts";
import { compactStoredArtifact, envBoolean, parseJsonCodeFence, slug, truncateMiddle } from "./text.ts";

export {
	claimPromotionEvidenceContract,
	verifyStructuredClaimMergePromotion,
} from "./swarm-claim-runtime.ts";
export type * from "./swarm-runtime-types.ts";

function swarmExecutionAttempt(execution: SwarmWorkerExecution): number {
	const attempt = execution.retryAttempt ?? 1;
	return Number.isInteger(attempt) && attempt > 0 ? attempt : 1;
}

/** Active execution rows for a worker; older attempts remain history/evidence only. */
export function terminalSwarmWorkerExecutions(executions: readonly SwarmWorkerExecution[]): SwarmWorkerExecution[] {
	if (executions.length === 0) return [];
	const terminalAttempt = Math.max(...executions.map(swarmExecutionAttempt));
	return executions.filter((execution) => swarmExecutionAttempt(execution) === terminalAttempt);
}

function swarmExecutionSucceeded(execution: SwarmWorkerExecution): boolean {
	return (
		execution.status === "done" &&
		!execution.timedOut &&
		execution.exitCode === 0 &&
		typeof execution.stdoutSha256 === "string" &&
		/^[a-f0-9]{64}$/i.test(execution.stdoutSha256) &&
		typeof execution.stderrSha256 === "string" &&
		/^[a-f0-9]{64}$/i.test(execution.stderrSha256)
	);
}

function swarmExecutionFailed(execution: SwarmWorkerExecution): boolean {
	return !swarmExecutionSucceeded(execution);
}

export function resolveSwarmExecutionMode(options: {
	execution: "simulated" | "real";
	cwd?: string;
	agentThread: boolean;
}): "simulated" | "real" {
	if (options.execution === "simulated") return "simulated";
	if (!options.cwd?.trim()) {
		throw new Error("RE_SWARM_REAL_CWD_REQUIRED: execution=real requires a non-empty cwd");
	}
	if (options.agentThread) {
		throw new Error("RE_SWARM_REAL_RECURSION_BLOCKED: execution=real is forbidden when REPI_AGENT_THREAD=1");
	}
	return "real";
}

export function createSwarmSupervisorRuntime(dependencies: SwarmSupervisorRuntimeDependencies) {
	const {
		appendEvidence,
		autoModeDefaults,
		buildClaimCheckResult,
		buildDelegate,
		executeOperatorStep,
		formatStrictClaimCheckSnapshot,
		latestDelegateArtifactPath,
		latestScopedMarkdownArtifact,
		operatorCommandConcrete,
		readCurrentMission,
		runtimeArtifactHashes,
		scopedMarkdownArtifacts,
		strictClaimCheckSnapshot,
		updateMissionCheckpoint,
		writeDelegateArtifact,
	} = dependencies;
	const {
		buildSwarmRuntimeClaimLedger,
		buildStructuredClaimMergeFromSwarm,
		structuredClaimMergeCheckFromSwarm,
		refreshSwarmRuntimeClaimLedger,
	} = createSwarmClaimRuntime({
		runtimeArtifactHashes,
		terminalExecutions: terminalSwarmWorkerExecutions,
		executionFailed: swarmExecutionFailed,
	});

	function latestSwarmArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("swarm", evidenceSwarmsDir(), options);
	}

	function latestSwarmRunArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		for (const path of scopedMarkdownArtifacts("swarm", evidenceSwarmsDir(), 24, {
			...options,
			requestedBy: options.requestedBy ?? "latest_swarm_run_for_supervisor",
			write: options.write ?? false,
		})) {
			const text = readText(path);
			if (/^mode:\s*run$/im.test(text)) return path;
		}
		return undefined;
	}

	function parseSwarmArtifact(path: string): SwarmArtifact | undefined {
		return parseJsonCodeFence<SwarmArtifact>(readText(path));
	}

	function recentSwarmArtifactsForGraph(
		limit = 4,
		options: ArtifactScopeFilterOptions = {},
	): Array<{ path: string; swarm: SwarmArtifact }> {
		return scopedMarkdownArtifacts("swarm", evidenceSwarmsDir(), limit, {
			...options,
			requestedBy: options.requestedBy ?? "recent_swarm_artifacts_for_graph",
		})
			.map((path) => {
				const swarm = parseSwarmArtifact(path);
				return swarm ? { path, swarm } : undefined;
			})
			.filter((item): item is { path: string; swarm: SwarmArtifact } => Boolean(item));
	}

	function splitRetryNextCommands(next: string): string[] {
		return next
			.split(/\s*(?:&&|;)\s*/g)
			.map((item) => item.trim().replace(/^\//, ""))
			.filter((item) => /^re[-_]/i.test(item));
	}

	function latestSwarmRetryQueue(target?: string): { path?: string; rows: string[]; commands: string[] } {
		const path = latestSwarmArtifactPath(
			target ? { target, requestedBy: "swarm_retry_queue_latest_artifact_consumer" } : {},
		);
		const swarm = path ? parseSwarmArtifact(path) : undefined;
		if (!swarm) return { path, rows: [], commands: [] };
		if (target && swarm.target && target !== swarm.target) return { path, rows: [], commands: [] };
		const concreteTarget = target ?? swarm.target;
		const rows = Array.from(new Set(swarm.retryQueue ?? [])).slice(0, 32);
		const commands = rows
			.flatMap((row) => /\bnext=(.+)$/i.exec(row)?.[1]?.trim() ?? "")
			.flatMap(splitRetryNextCommands)
			.map((command) => operatorCommandConcrete(command, concreteTarget).command)
			.filter((command) => /^re[-_]/i.test(command))
			.filter((command) => !/^re[-_]operator\s+dispatch\b/i.test(command));
		return { path, rows, commands: Array.from(new Set(commands)).slice(0, 12) };
	}

	function swarmMergeKeys(packet: DelegatePacket): string[] {
		return Array.from(
			new Set([
				`worker=${packet.worker}`,
				...packet.phases.map((phase) => `phase=${phase}`),
				...packet.evidenceContract.map((item) => `evidence=${slug(item).slice(0, 32)}`),
			]),
		).slice(0, 14);
	}

	function swarmDependencies(packet: DelegatePacket): string[] {
		const deps = new Set<string>();
		for (const step of packet.steps) {
			if (/re_map|passive map/i.test(step.command)) deps.add("passive_map_done");
			if (/re_lane plan|repro/i.test(step.command)) deps.add("repro_commands_ready");
			if (/re_lane run|run-auto|runtime|proof/i.test(step.command)) deps.add("minimal_path_proven");
			if (/re_verifier/i.test(step.command)) deps.add("verifier_matrix_ready");
			if (/re_compiler|report/i.test(step.command)) deps.add("compiler_ready");
			if (/re_replayer|replay/i.test(step.command)) deps.add("replay_ready");
			if (/re_autofix|repair/i.test(step.command)) deps.add("autofix_ready");
		}
		if (deps.size === 0) deps.add("delegation_packets_ready");
		return Array.from(deps).slice(0, 10);
	}

	function swarmSpawnPrompt(packet: DelegatePacket, target?: string): string[] {
		return [
			`role=${packet.worker}`,
			`target=${target ?? "<target>"}`,
			`objective=${packet.objective}`,
			`evidence_contract=${packet.evidenceContract.join(" | ")}`,
			`source_artifacts=${packet.sourceArtifacts.join(" | ") || "none"}`,
			`commands=${
				packet.steps
					.filter((step) => step.status === "ready")
					.slice(0, 5)
					.map((step) => step.command)
					.join(" || ") || "inspect source artifacts and return gap"
			}`,
			"return_format=Outcome -> Key Evidence -> Verification -> Next Step; include paths/hashes/commands only",
		];
	}

	const RECON_PARALLEL_EVIDENCE_ORDER = [
		"same_window_live",
		"runtime_artifact",
		"network",
		"served_asset",
		"process_config",
		"persisted_state",
	];

	function swarmArtifactGlobs(worker: SwarmWorkerRuntime, delegationArtifact?: string): string[] {
		return Array.from(
			new Set(
				[delegationArtifact, ...worker.sourceArtifacts, evidenceLedgerPath(), "recon/evidence/**"].filter(
					(item): item is string => Boolean(item),
				),
			),
		).slice(0, 16);
	}

	function buildSwarmParallelPlan(params: {
		delegate: DelegateArtifact;
		delegationArtifact?: string;
		workers: SwarmWorkerRuntime[];
		timestamp: string;
		target?: string;
		mode?: "plan" | "run" | "merge";
	}): ReconParallelPlanV1 {
		const { delegate, delegationArtifact, workers, timestamp } = params;
		const target = delegate.target ?? params.target;
		const planIdBase = delegate.missionId ?? delegate.route ?? target ?? "mission";
		return {
			kind: "ReconParallelPlanV1",
			schemaVersion: 1,
			planId: `re_swarm/${slug(planIdBase).slice(0, 64)}/${timestamp}`,
			target,
			source: "re_swarm",
			strategy: `${delegate.route ?? "operation"}:${params.mode ?? "plan"}`,
			workers: workers.map((worker) => ({
				id: worker.id,
				role: worker.worker,
				objective: worker.objective,
				commands: worker.commands,
				evidenceContract: worker.evidenceContract,
				mergeKeys: worker.mergeKeys,
				dependencies: worker.dependencies,
				artifactGlobs: swarmArtifactGlobs(worker, delegationArtifact),
				limits: {
					timeoutMs: 60000,
					maxCommands: Math.max(1, Math.min(5, worker.commands.length || 1)),
					recommendedTools: worker.recommendedTools.slice(0, 8),
				},
				prompt: worker.spawnPrompt,
				sourceWorkerId: worker.worker,
			})),
			merge: {
				strategy: "supervisor",
				evidenceOrder: RECON_PARALLEL_EVIDENCE_ORDER,
				expectedArtifacts: Array.from(
					new Set(
						[
							delegationArtifact,
							...workers.flatMap((worker) => worker.sourceArtifacts),
							evidenceLedgerPath(),
						].filter((item): item is string => Boolean(item)),
					),
				).slice(0, 40),
				command: "re_supervisor review",
				conflictPolicy:
					"supervisor coverage_matrix, execution_audit, and runtime artifacts overrule narrative-only worker summaries; unresolved conflicts block final claim promotion",
			},
		};
	}

	function swarmPlanCoverage(
		swarm: Pick<SwarmArtifact, "workers" | "parallelPlan" | "coverageMatrix" | "collisionMatrix">,
	): string[] {
		const plan = swarm.parallelPlan;
		if (!plan) return ["parallel_plan=missing status=fail next=re_swarm plan"];
		const workerIds = new Set(swarm.workers.map((worker) => worker.id));
		const planWorkerIds = new Set(plan.workers.map((worker) => worker.id));
		const missingFromPlan = [...workerIds].filter((id) => !planWorkerIds.has(id));
		const orphanPlanWorkers = [...planWorkerIds].filter((id) => !workerIds.has(id));
		const contractRows = plan.workers.map((worker) => {
			const coverageRows = swarm.coverageMatrix.filter((row) => row.includes(`worker=${worker.id}`));
			const missingRows = coverageRows.filter((row) => /status=missing/i.test(row));
			const missingCount =
				coverageRows.length === 0 ? Math.max(1, worker.evidenceContract.length) : missingRows.length;
			return `worker=${worker.id} contract=${worker.evidenceContract.length} coverage_rows=${coverageRows.length} missing=${missingCount}`;
		});
		return [
			`parallel_plan_id=${plan.planId}`,
			`parallel_plan_source=${plan.source}`,
			`parallel_plan_workers=${plan.workers.length} swarm_workers=${swarm.workers.length}`,
			`worker_binding=${missingFromPlan.length || orphanPlanWorkers.length ? "fail" : "pass"}`,
			`missing_from_plan=${missingFromPlan.join(",") || "none"}`,
			`orphan_plan_workers=${orphanPlanWorkers.join(",") || "none"}`,
			`merge_strategy=${plan.merge.strategy}`,
			`evidence_order=${plan.merge.evidenceOrder.join(">")}`,
			`collision_rows=${swarm.collisionMatrix.length}`,
			...contractRows,
		].slice(0, 48);
	}

	const {
		latestSupervisorArtifactPath,
		parseSupervisorArtifact,
		parseDelegateArtifact,
		latestOrBuildDelegate,
		supervisorClaimCheckPolicy,
		supervisorPlanCoverage,
		buildSupervisor,
		formatSupervisor,
		writeSupervisorArtifact,
		parseSupervisorCritique,
		buildSupervisorOutput,
	} = createSwarmCommanderRuntime({
		appendEvidence,
		buildClaimCheckResult,
		buildDelegate,
		ensureReconStorage,
		evidenceLedgerPath,
		evidenceSupervisorsDir,
		formatStrictClaimCheckSnapshot,
		latestDelegateArtifactPath,
		latestScopedMarkdownArtifact,
		latestSwarmArtifactPath,
		latestSwarmRunArtifactPath,
		nowIso: () => new Date().toISOString(),
		parseSwarmArtifact,
		readCurrentMission,
		readText,
		strictClaimCheckSnapshot,
		swarmExecutionFailed,
		swarmPlanCoverage,
		terminalSwarmWorkerExecutions,
		updateMissionCheckpoint,
		writeDelegateArtifact,
		writePrivateTextFile,
	});

	function swarmReleaseCheckMetadata(plan?: ReconParallelPlanV1): string[] {
		if (!plan) return ["release_check.parallel_plan_present=false", "release_check.next=re_swarm plan"];
		return [
			"release_check.parallel_plan_present=true",
			`release_check.parallel_plan_id=${plan.planId}`,
			`release_check.source=${plan.source}`,
			`release_check.worker_count=${plan.workers.length}`,
			`release_check.worker_required_fields=id,role,objective,commands,evidenceContract,mergeKeys,dependencies,artifactGlobs,limits`,
			`release_check.merge_strategy=${plan.merge.strategy}`,
			`release_check.evidence_order=${plan.merge.evidenceOrder.join(">")}`,
			"release_check.claim_promotion=blocked_until_supervisor_claim_check_passes",
		];
	}

	function buildSwarm(options: SwarmBuildOptions = {}): SwarmArtifact {
		ensureReconStorage();
		const { delegate, path: delegationArtifact } = latestOrBuildDelegate(options);
		const timestamp = new Date().toISOString();
		const workers: SwarmWorkerRuntime[] = delegate.packets.map((packet, index) => {
			const readyCommands = packet.steps
				.filter((step) => step.status === "ready")
				.map((step) => step.command)
				.slice(0, 8);
			const commands = readyCommands.length
				? readyCommands
				: [`re_delegate show # inspect ${packet.id}`, `re_evidence search ${packet.worker}`];
			return {
				id: `swarm:${index + 1}:${packet.worker}`,
				worker: packet.worker,
				status:
					options.mode === "merge" && packet.status === "done"
						? "merged"
						: packet.status === "blocked"
							? "blocked"
							: "ready",
				objective: packet.objective,
				spawnPrompt: swarmSpawnPrompt(packet, delegate.target ?? options.target),
				commands,
				evidenceContract: packet.evidenceContract,
				mergeKeys: swarmMergeKeys(packet),
				dependencies: swarmDependencies(packet),
				recommendedTools: packet.recommendedTools,
				sourceArtifacts: packet.sourceArtifacts,
			};
		});
		const parallelGroups = [
			workers.filter((worker) => /web-authz|agentsec|cloud|identity/.test(worker.worker)).map((worker) => worker.id),
			workers
				.filter((worker) => /mobile-runtime|native-runtime|pwn-exploit|firmware-dfir|malware/.test(worker.worker))
				.map((worker) => worker.id),
			workers.filter((worker) => /reporting|general/.test(worker.worker)).map((worker) => worker.id),
		]
			.filter((group) => group.length > 0)
			.map((group, index) => `group:${index + 1} ${group.join(" ")}`);
		const mergeProtocol = [
			"1. collect each worker's Outcome/Key Evidence/Verification/Next Step packet",
			"2. reject claims without command/path/hash/request/offset/state-transition evidence",
			"3. resolve conflicts by runtime/replay/verifier evidence order",
			"4. write merged evidence to ledger, then re_supervisor review and re_verifier matrix",
			"5. preserve unresolved gaps as re_operator escalation_queue or re_autofix evidence_recapture_queue",
		];
		const collisionMatrix = workers.flatMap((worker, index) =>
			workers.slice(index + 1).flatMap((other) => {
				const overlap = worker.mergeKeys.filter((key) => other.mergeKeys.includes(key));
				return overlap.length ? [`${worker.id} <-> ${other.id}: ${overlap.join(",")}`] : [];
			}),
		);
		if (workers.length > 1 && collisionMatrix.length === 0) {
			collisionMatrix.push(
				`structured_conflict_arbitration_live_wiring: ${workers[0].id} <-> ${workers[1].id}: shared target=${delegate.target ?? options.target ?? "unknown"} topic=final_claim_promotion`,
			);
		}
		const evidenceContract = Array.from(new Set(workers.flatMap((worker) => worker.evidenceContract))).slice(0, 24);
		const commanderNextActions = Array.from(
			new Set([
				...workers.filter((worker) => worker.status === "ready").flatMap((worker) => worker.commands.slice(0, 2)),
				"re_swarm merge",
				"re_supervisor review",
				"re_verifier matrix",
				"re_evidence show",
			]),
		).slice(0, 18);
		const handoffDigest = workers.map(
			(worker) =>
				`${worker.id} status=${worker.status} deps=${worker.dependencies.join(",")} tools=${worker.recommendedTools.slice(0, 5).join(",")}`,
		);
		const parallelPlan = buildSwarmParallelPlan({
			delegate,
			delegationArtifact,
			workers,
			timestamp,
			target: options.target,
			mode: options.mode ?? "plan",
		});
		const basePlanCoverage = swarmPlanCoverage({
			workers,
			parallelPlan,
			coverageMatrix: [],
			collisionMatrix: collisionMatrix.slice(0, 24),
		});
		const releaseCheckMetadata = swarmReleaseCheckMetadata(parallelPlan);
		const swarm: SwarmArtifact = {
			artifactId: randomUUID(),
			timestamp,
			missionId: delegate.missionId,
			route: delegate.route,
			target: delegate.target ?? options.target,
			mode: options.mode ?? "plan",
			delegationArtifact,
			workers,
			executions: [],
			workerResults: [],
			blocked: [],
			mergeDigest: [],
			executionAudit: [],
			coverageMatrix: [],
			retryQueue: [],
			parallelGroups,
			mergeProtocol,
			collisionMatrix: collisionMatrix.slice(0, 24),
			evidenceContract,
			commanderNextActions,
			handoffDigest,
			parallelPlan,
			planCoverage: basePlanCoverage,
			releaseCheckMetadata,
			claimLedger: [],
			claimLedgerEventCount: 0,
			runtimeClaimLedgerCaptured: false,
			structuredClaimMergeStatus: "missing",
			structuredClaimMergeErrors: [],
			subagentRuntimeManifests: [],
			subagentRuntimeManifestCount: 0,
			subagentRuntimeManifestsCaptured: false,
			workerChildSessionRuntimeStatus: "missing",
			workerChildSessionRuntimeErrors: [],
			workerLeaseSchedulerStatus: "missing",
			workerLeaseSchedulerErrors: [],
			workerRuntimePoolBridgeStatus: "missing",
			workerRuntimePoolBridgeErrors: [],
			workerRetryHandoffClosureStatus: "missing",
			workerRetryHandoffClosureErrors: [],
			workerRetryHandoffMergeSummaryStatus: "missing",
			workerRetryHandoffMergeSummaryErrors: [],
			sourceArtifacts: Array.from(
				new Set([
					delegationArtifact,
					...delegate.sourceArtifacts,
					...workers.flatMap((worker) => worker.sourceArtifacts),
				]),
			).slice(0, 40),
		};
		const auditFields = deriveSwarmAuditFields(swarm);
		const swarmWithAudit = { ...swarm, ...auditFields };
		return refreshSwarmRuntimeClaimLedger({
			...swarmWithAudit,
			planCoverage: swarmPlanCoverage(swarmWithAudit),
			releaseCheckMetadata: swarmReleaseCheckMetadata(swarmWithAudit.parallelPlan),
		});
	}

	function sanitizeSwarmCommand(command: string): string {
		return command.trim().replace(/\s+#.*$/g, "");
	}

	function swarmExecutionDigest(value: string): string {
		return createHash("sha256").update(value).digest("hex");
	}

	const {
		buildWorkerChildSessionRuntimeBatchFromSwarm,
		runWorkerChildProcessProbe,
		refreshSwarmWorkerChildSessionRuntime,
		buildSwarmWorkerRetryHandoffClosure,
		refreshSwarmWorkerRetryHandoffClosure,
		buildWorkerLeaseSchedulerFromSwarm,
		refreshSwarmWorkerLeaseScheduler,
	} = createSwarmWorkerArtifactRuntime({
		executionDigest: swarmExecutionDigest,
		executionFailed: swarmExecutionFailed,
		terminalExecutions: terminalSwarmWorkerExecutions,
	});

	function stripSwarmPidMarker(stderr: string): {
		stderr: string;
		pid: number | null;
		parentPid: number | null;
	} {
		const match = /^__repi_swarm_pid=(\d+)\s+ppid=(\d+)\s*\n?/m.exec(stderr);
		if (!match) return { stderr, pid: null, parentPid: null };
		return {
			stderr: stderr.replace(match[0], ""),
			pid: Number(match[1]),
			parentPid: Number(match[2]),
		};
	}

	function swarmWorkerSpec(workerName: string): "explorer" | "reverser" | "operator" | "verifier" {
		if (/native|pwn|firmware|mobile|malware|reverse|dfir|pcap|crypto/i.test(workerName)) return "reverser";
		if (/verif|challenge|audit|report/i.test(workerName)) return "verifier";
		if (/web-authz|cloud|identity|agentsec|map|surface|explore|recon/i.test(workerName)) return "explorer";
		return "operator";
	}

	function envBoundedInteger(name: string, fallback: number, min: number, max: number): number {
		const parsed = Number.parseInt(process.env[name] ?? "", 10);
		if (!Number.isFinite(parsed)) return fallback;
		return Math.max(min, Math.min(max, parsed));
	}

	function swarmWorkerTimeoutMs(worker: SwarmWorkerRuntime, execution: "simulated" | "real"): number {
		const global = envBoundedInteger(
			execution === "real" ? "REPI_SWARM_SUBAGENT_TIMEOUT_MS" : "REPI_SWARM_WORKER_TIMEOUT_MS",
			0,
			0,
			30 * 60 * 1000,
		);
		if (global > 0) return global;
		if (execution !== "real") return 60000;
		const spec = swarmWorkerSpec(worker.worker);
		if (spec === "reverser") return 360000;
		if (spec === "explorer") return 180000;
		return 240000;
	}

	function swarmWorkerRetryLimit(execution: "simulated" | "real"): number {
		return envBoundedInteger(
			execution === "real" ? "REPI_SWARM_REAL_RETRY_LIMIT" : "REPI_SWARM_RETRY_LIMIT",
			execution === "real" ? 0 : 1,
			0,
			3,
		);
	}

	async function executeSwarmWorkerSubagent(
		worker: SwarmWorkerRuntime,
		swarm: SwarmArtifact,
		cwd: string,
		timeoutMs: number,
		attempt = 1,
		signal?: AbortSignal,
	): Promise<SwarmWorkerExecution[]> {
		const spec = swarmWorkerSpec(worker.worker);
		const task = [
			`You are a REPI ${spec} subagent executing a swarm worker packet. Return ONLY a distilled handoff: Outcome, Key Evidence (command/path/hash/offset/request-response), Verification, Next Step, and unresolved gaps. No raw logs.`,
			`objective: ${worker.objective}`,
			`worker: ${worker.worker}`,
			swarm.target ? `target: ${swarm.target}` : "",
			`evidence_contract: ${worker.evidenceContract.join(" | ") || "(none)"}`,
			`merge_keys: ${worker.mergeKeys.join(" | ") || "(none)"}`,
			`suggested_commands: ${worker.commands.join(" || ") || "(none)"}`,
			...(worker.spawnPrompt.length ? ["", "## spawn_prompt", ...worker.spawnPrompt] : []),
		]
			.filter(Boolean)
			.join("\n");
		const mgr = createAgentThreadManager({ cwd });
		const startedAt = new Date().toISOString();
		const startMs = Date.now();
		try {
			const started = await mgr.spawnThread({
				specName: spec,
				task,
				timeoutMs,
				inheritMcp: true,
				signal,
				missionId: swarm.missionId,
			});
			const final = await mgr.awaitRun(started.runId);
			const merge = mgr.mergeRun(started.runId);
			const mergeText = merge?.text ?? "(no merge output)";
			const endedMs = Date.now();
			const elapsedMs = Math.max(0, endedMs - startMs);
			const timedOut =
				elapsedMs > timeoutMs || /timeout|timed out/i.test(final.error ?? "") || final.signal === "SIGTERM";
			const status: OperationStepStatus =
				final.status === "complete" && final.exitCode === 0 && merge?.manifest.handoffLineageValid === true
					? "done"
					: "blocked";
			const execution: SwarmWorkerExecution = {
				workerId: worker.id,
				worker: worker.worker,
				command: `re_subagent spec=${spec} task="${truncateMiddle(worker.objective, 80)}"`,
				status,
				output: [
					"parallel_mode=real_subagent",
					"isolation=process-agent-home",
					`spec=${spec}`,
					`timeout_ms=${timeoutMs} timed_out=${timedOut} retry_attempt=${attempt}`,
					`run_id=${final.runId}`,
					mergeText,
				].join("\n"),
				stdout: mergeText,
				stderr: final.error ?? "",
				stdoutSha256: swarmExecutionDigest(mergeText),
				stderrSha256: swarmExecutionDigest(final.error ?? ""),
				startedAt,
				endedAt: new Date(endedMs).toISOString(),
				elapsedMs,
				pid: final.pid ?? null,
				parentPid: null,
				exitCode: final.exitCode ?? (status === "done" ? 0 : 1),
				signal: timedOut ? "SIGTERM" : (final.signal ?? null),
				timeoutMs,
				timedOut,
				cancelledAt: timedOut ? new Date(endedMs).toISOString() : undefined,
				retryAttempt: attempt,
				sourceArtifacts: Array.from(
					new Set(
						[final.runRoot, final.manifestPath, final.mergePath].filter((item): item is string => Boolean(item)),
					),
				),
			};
			return [execution];
		} catch (error) {
			if (signal?.aborted) signal.throwIfAborted();
			const endedMs = Date.now();
			const message = String((error as Error).message ?? error);
			const elapsedMs = Math.max(0, endedMs - startMs);
			const timedOut = elapsedMs > timeoutMs || /timeout|timed out/i.test(message);
			return [
				{
					workerId: worker.id,
					worker: worker.worker,
					command: `re_subagent spec=${spec} (blocked)`,
					status: "blocked",
					output: `parallel_mode=real_subagent\nisolation=process-agent-home\ntimeout_ms=${timeoutMs} timed_out=${timedOut} retry_attempt=${attempt}\nblocked: ${truncateMiddle(message, 400)}`,
					stdout: "",
					stderr: message,
					stdoutSha256: swarmExecutionDigest(""),
					stderrSha256: swarmExecutionDigest(message),
					startedAt,
					endedAt: new Date(endedMs).toISOString(),
					elapsedMs,
					pid: null,
					parentPid: null,
					exitCode: 1,
					signal: timedOut ? "SIGTERM" : null,
					timeoutMs,
					timedOut,
					cancelledAt: timedOut ? new Date(endedMs).toISOString() : undefined,
					retryAttempt: attempt,
					sourceArtifacts: worker.sourceArtifacts,
				},
			];
		}
	}

	async function executeSwarmWorkerCommand(
		pi: ExtensionAPI,
		worker: SwarmWorkerRuntime,
		rawCommand: string,
		target?: string,
		timeoutMs = 60000,
		attempt = 1,
	): Promise<SwarmWorkerExecution> {
		const command = sanitizeSwarmCommand(rawCommand);
		const startedMs = Date.now();
		const startedAt = new Date(startedMs).toISOString();
		const finalize = (
			execution: Omit<SwarmWorkerExecution, "startedAt" | "endedAt" | "elapsedMs">,
		): SwarmWorkerExecution => {
			const endedMs = Date.now();
			const stdout = execution.stdout ?? execution.output;
			const stderr = execution.stderr ?? "";
			return {
				...execution,
				stdout,
				stderr,
				stdoutSha256: execution.stdoutSha256 ?? swarmExecutionDigest(stdout),
				stderrSha256: execution.stderrSha256 ?? swarmExecutionDigest(stderr),
				startedAt,
				endedAt: new Date(endedMs).toISOString(),
				elapsedMs: Math.max(0, endedMs - startedMs),
				exitCode: execution.exitCode ?? (execution.status === "done" ? 0 : 1),
				signal: execution.signal ?? null,
				timeoutMs: execution.timeoutMs ?? timeoutMs,
				timedOut: execution.timedOut ?? false,
				cancelledAt: execution.cancelledAt,
				retryAttempt: execution.retryAttempt ?? attempt,
			};
		};
		const blocked = (output: string): SwarmWorkerExecution =>
			finalize({
				workerId: worker.id,
				worker: worker.worker,
				command: command || rawCommand,
				status: "blocked",
				output,
				stdout: output,
				stderr: "",
				pid: process.pid,
				parentPid: process.ppid,
				exitCode: 1,
				signal: null,
				timeoutMs,
				timedOut: false,
				retryAttempt: attempt,
				sourceArtifacts: worker.sourceArtifacts,
			});
		if (!command) return blocked("empty swarm worker command");
		if (/^re[-_]swarm\s+run\b/i.test(command)) return blocked("recursive swarm run command is not allowed");
		if (/^re[-_]/i.test(command)) {
			const result = await executeOperatorStep(
				pi,
				{
					id: `${worker.id}:${slug(command).slice(0, 24)}`,
					command,
					status: "ready",
					priority: 1,
					sourceArtifacts: worker.sourceArtifacts,
				},
				target,
			);
			return finalize({
				workerId: worker.id,
				worker: worker.worker,
				command: result.command,
				status: result.status,
				output: [
					"parallel_mode=simulated_sequential",
					"isolation=shared-process-internal-dispatch",
					`timeout_ms=${timeoutMs} timed_out=false retry_attempt=${attempt}`,
					"note=internal REPI command executed through in-process operator dispatcher; shell workers still capture child pid",
					result.output,
				].join("\n"),
				stdout: [
					"parallel_mode=simulated_sequential",
					"isolation=shared-process-internal-dispatch",
					`timeout_ms=${timeoutMs} timed_out=false retry_attempt=${attempt}`,
					result.output,
				].join("\n"),
				stderr: "",
				pid: process.pid,
				parentPid: process.ppid,
				exitCode: result.status === "done" ? 0 : 1,
				signal: null,
				timeoutMs,
				timedOut: false,
				retryAttempt: attempt,
				sourceArtifacts: worker.sourceArtifacts,
			});
		}
		const result = await pi.exec(
			"bash",
			["-lc", `printf '__repi_swarm_pid=%s ppid=%s\\n' "$$" "$PPID" >&2\nset -o pipefail\n${command}`],
			{ timeout: timeoutMs },
		);
		const marker = stripSwarmPidMarker(result.stderr);
		const stdout = result.stdout;
		const stderr = marker.stderr;
		const timedOut = Boolean(result.killed);
		const endedAt = new Date().toISOString();
		const output = [
			`exit=${result.code}${result.killed ? " killed=true" : ""}`,
			`timeout_ms=${timeoutMs} timed_out=${timedOut}${timedOut ? ` cancelled_at=${endedAt}` : ""} retry_attempt=${attempt}`,
			`pid=${marker.pid ?? "unknown"} parent_pid=${marker.parentPid ?? "unknown"}`,
			`stdout_sha256=${swarmExecutionDigest(stdout)}`,
			`stderr_sha256=${swarmExecutionDigest(stderr)}`,
			`stdout=${truncateMiddle(stdout.trim(), 1200)}`,
			`stderr=${truncateMiddle(stderr.trim(), 1200)}`,
		].join("\n");
		return finalize({
			workerId: worker.id,
			worker: worker.worker,
			command,
			status: result.code === 0 && !result.killed ? "done" : "blocked",
			output,
			stdout,
			stderr,
			stdoutSha256: swarmExecutionDigest(stdout),
			stderrSha256: swarmExecutionDigest(stderr),
			pid: marker.pid,
			parentPid: marker.parentPid,
			exitCode: result.code,
			signal: timedOut ? "SIGTERM" : null,
			timeoutMs,
			timedOut,
			cancelledAt: timedOut ? endedAt : undefined,
			retryAttempt: attempt,
			sourceArtifacts: worker.sourceArtifacts,
		});
	}

	function swarmWorkerGroups(swarm: SwarmArtifact, selected: Set<string>): SwarmWorkerRuntime[][] {
		const byId = new Map(swarm.workers.map((worker) => [worker.id, worker]));
		const used = new Set<string>();
		const groups = swarm.parallelGroups
			.map((group) =>
				group
					.replace(/^group:\d+\s+/i, "")
					.split(/\s+/)
					.map((id) => byId.get(id))
					.filter((worker): worker is SwarmWorkerRuntime => Boolean(worker && selected.has(worker.id))),
			)
			.filter((group) => group.length > 0)
			.map((group) => {
				for (const worker of group) used.add(worker.id);
				return group;
			});
		const leftovers = swarm.workers.filter((worker) => selected.has(worker.id) && !used.has(worker.id));
		return leftovers.length ? [...groups, leftovers] : groups;
	}

	function swarmContractCovered(text: string, contract: string): boolean {
		const haystack = text.toLowerCase();
		if (!contract.trim()) return true;
		if (haystack.includes(contract.toLowerCase())) return true;
		const tokens = contract.toLowerCase().match(/[a-z0-9_./:-]{4,}/g);
		if (!tokens?.length) return false;
		return tokens.some((token) => haystack.includes(token));
	}

	function swarmWorkerEvidenceText(swarm: SwarmArtifact, worker: SwarmWorkerRuntime): string {
		const manifestRows = (swarm.subagentRuntimeManifests ?? []).filter((manifest) => manifest.workerId === worker.id);
		return [
			worker.worker,
			worker.objective,
			...worker.commands,
			...worker.mergeKeys,
			...swarm.executions
				.filter((execution) => execution.workerId === worker.id)
				.flatMap((execution) => [execution.command, execution.output]),
			...swarm.workerResults.filter(
				(result) => result.includes(worker.id) || result.includes(`worker=${worker.worker}`),
			),
			...swarm.mergeDigest.filter((item) => item.includes(worker.id) || item.includes(`worker=${worker.worker}`)),
			...manifestRows.flatMap((manifest) => [
				manifest.runtimeManifestFile,
				manifest.sessionDir,
				manifest.stdoutPath,
				manifest.stderrPath,
				manifest.stdoutSha256,
				manifest.stderrSha256,
				manifest.toolCallDigest,
			]),
		].join("\n");
	}

	function deriveSwarmAuditFields(
		swarm: SwarmArtifact,
	): Pick<SwarmArtifact, "executionAudit" | "coverageMatrix" | "retryQueue"> {
		const executionAudit: string[] = [];
		const coverageMatrix: string[] = [];
		const retryQueue: string[] = [];
		const target = swarm.target ?? "<target>";
		for (const worker of swarm.workers) {
			const executions = swarm.executions.filter((execution) => execution.workerId === worker.id);
			const terminalExecutions = terminalSwarmWorkerExecutions(executions);
			const done = terminalExecutions.filter(swarmExecutionSucceeded).length;
			const blocked = terminalExecutions.filter(swarmExecutionFailed).length;
			const historicalBlocked = executions.filter(swarmExecutionFailed).length;
			const retries = executions.filter((execution) => (execution.retryAttempt ?? 1) > 1).length;
			const text = swarmWorkerEvidenceText(swarm, worker);
			const hashes = new Set(text.match(/\b(?:stdout_sha256|stderr_sha256|sha256|hash)=[0-9a-f]{8,64}\b/gi) ?? []);
			const artifacts = new Set(
				text.match(/(?:^|\s)(?:\.\/|\.\.\/|\/tmp\/|\/root\/|\/home\/|[A-Za-z0-9_.-]+\/)[^\s`'"]{3,}/g) ?? [],
			);
			const anchors = new Set(
				text.match(/\[[A-Za-z0-9_.:/-]+\]|anchors?:|artifact=|status=|route=|offset=|RIP|EIP/gi) ?? [],
			);
			const coveredContracts = worker.evidenceContract.filter((contract) => swarmContractCovered(text, contract));
			const missingContracts = worker.evidenceContract.filter((contract) => !swarmContractCovered(text, contract));
			const auditStatus =
				blocked > 0
					? "needs_repair"
					: executions.length === 0
						? "pending_execution"
						: missingContracts.length
							? "needs_evidence"
							: "covered";
			executionAudit.push(
				[
					`worker=${worker.id}`,
					`role=${worker.worker}`,
					`status=${auditStatus}`,
					`commands=${executions.length}/${worker.commands.length}`,
					`passed=${done}`,
					`blocked=${blocked}`,
					`historical_blocked=${historicalBlocked}`,
					`recovered=${historicalBlocked > 0 && blocked === 0}`,
					`retries=${retries}`,
					`contract=${coveredContracts.length}/${worker.evidenceContract.length}`,
					`hashes=${hashes.size}`,
					`artifacts=${artifacts.size}`,
					`anchors=${anchors.size}`,
				].join(" "),
			);
			for (const contract of worker.evidenceContract) {
				const covered = swarmContractCovered(text, contract);
				coverageMatrix.push(
					`worker=${worker.id} role=${worker.worker} contract=${shellQuote(contract)} status=${covered ? "covered" : "missing"}`,
				);
			}
			if (executions.length === 0 && worker.status === "ready") {
				retryQueue.push(`worker=${worker.id} reason=no_execution next=re_swarm run ${target} 1 1`);
			}
			for (const execution of terminalExecutions.filter(swarmExecutionFailed)) {
				retryQueue.push(
					`worker=${worker.id} reason=blocked command=${shellQuote(execution.command)} next=re_swarm run ${target} 1 1`,
				);
			}
			if (executions.length > 0 && missingContracts.length > 0) {
				retryQueue.push(
					`worker=${worker.id} reason=contract_gap missing=${missingContracts
						.slice(0, 3)
						.map((item) => shellQuote(item))
						.join(",")} next=re_delegate plan ${target} && re_swarm run ${target} 1 1`,
				);
			}
		}
		return {
			executionAudit: executionAudit.slice(0, 48),
			coverageMatrix: coverageMatrix.slice(0, 96),
			retryQueue: Array.from(new Set(retryQueue)).slice(0, 32),
		};
	}

	function refreshSwarmRunDerivedFields(swarm: SwarmArtifact): SwarmArtifact {
		const executionsByWorker = new Map<string, SwarmWorkerExecution[]>();
		for (const execution of swarm.executions)
			executionsByWorker.set(execution.workerId, [...(executionsByWorker.get(execution.workerId) ?? []), execution]);
		const workers = swarm.workers.map((worker) => {
			const executions = executionsByWorker.get(worker.id) ?? [];
			const terminalExecutions = terminalSwarmWorkerExecutions(executions);
			if (terminalExecutions.length === 0) return worker;
			const status: SwarmWorkerRuntime["status"] = terminalExecutions.every(swarmExecutionSucceeded)
				? "done"
				: "blocked";
			return {
				...worker,
				status,
			};
		});
		const blocked = Array.from(executionsByWorker.values())
			.flatMap(terminalSwarmWorkerExecutions)
			.filter(swarmExecutionFailed)
			.map((execution) => `${execution.workerId} ${execution.command} — ${truncateMiddle(execution.output, 220)}`);
		const workerResults = workers.map((worker) => {
			const executions = executionsByWorker.get(worker.id) ?? [];
			const last = terminalSwarmWorkerExecutions(executions).at(-1);
			return `${worker.id} worker=${worker.worker} status=${worker.status} executed=${executions.length} evidence=${worker.evidenceContract.join(" | ")} last=${last ? truncateMiddle(last.output.replace(/\s+/g, " "), 220) : "none"}`;
		});
		const mergeDigest = Array.from(
			new Set([
				`mode=${swarm.mode} workers=${workers.length} executed=${swarm.executions.length} blocked=${blocked.length}`,
				...workerResults,
				...blocked.map((item) => `repair: ${item}`),
				...swarm.collisionMatrix.map((item) => `collision: ${item}`),
			]),
		).slice(0, 32);
		const auditFields = deriveSwarmAuditFields({
			...swarm,
			workers,
			blocked,
			workerResults,
			mergeDigest,
			executionAudit: [],
			coverageMatrix: [],
			retryQueue: [],
		});
		const target = swarm.target ?? "<target>";
		const refreshedForPlan = {
			...swarm,
			workers,
			blocked,
			workerResults,
			mergeDigest,
			executionAudit: auditFields.executionAudit,
			coverageMatrix: auditFields.coverageMatrix,
			retryQueue: auditFields.retryQueue,
		};
		const planCoverage = swarmPlanCoverage(refreshedForPlan);
		const releaseCheckMetadata = swarmReleaseCheckMetadata(swarm.parallelPlan);
		const commanderNextActions = Array.from(
			new Set([
				...auditFields.retryQueue
					.flatMap((item) => item.match(/next=([^&;]+)/i)?.[1]?.trim() ?? [])
					.filter((item) => /^re[-_]/i.test(item)),
				...(blocked.length ? [`re_supervisor repair ${target}`, "re_autofix plan", "re_operator escalate"] : []),
				"re_swarm merge",
				"re_supervisor review",
				"re_verifier matrix",
				`re_proof_loop run ${target} 4 2`,
				"re_evidence show",
			]),
		).slice(0, 18);
		return refreshSwarmRuntimeClaimLedger({
			...swarm,
			workers,
			blocked,
			workerResults,
			mergeDigest,
			...auditFields,
			planCoverage,
			releaseCheckMetadata,
			commanderNextActions,
			sourceArtifacts: Array.from(
				new Set(
					[
						...swarm.sourceArtifacts,
						...swarm.executions.flatMap((execution) => execution.sourceArtifacts),
						...(swarm.subagentRuntimeManifests ?? []).flatMap((manifest) => [
							manifest.runtimeManifestFile,
							manifest.stdoutPath,
							manifest.stderrPath,
						]),
						swarm.subagentRuntimeManifestPath,
					].filter((item): item is string => Boolean(item)),
				),
			).slice(0, 64),
		});
	}

	function swarmRuntimeStatus(executions: SwarmWorkerExecution[]): SwarmRuntimeState {
		const terminalExecutions = terminalSwarmWorkerExecutions(executions);
		if (terminalExecutions.length === 0) return "queued";
		if (terminalExecutions.some((execution) => execution.timedOut)) return "cancelled";
		if (terminalExecutions.some((execution) => execution.status === "skipped")) return "cancelled";
		return terminalExecutions.every(swarmExecutionSucceeded) ? "done" : "blocked";
	}

	function swarmRuntimeTimeWindow(
		executions: SwarmWorkerExecution[],
		fallback = new Date().toISOString(),
	): { startedAt: string; endedAt: string; elapsedMs: number } {
		const startedAt =
			executions
				.map((execution) => execution.startedAt)
				.filter((item): item is string => Boolean(item))
				.sort()[0] ?? fallback;
		const endedAt =
			executions
				.map((execution) => execution.endedAt)
				.filter((item): item is string => Boolean(item))
				.sort()
				.at(-1) ?? startedAt;
		const parsedStarted = Date.parse(startedAt);
		const parsedEnded = Date.parse(endedAt);
		const elapsedMs =
			Number.isFinite(parsedStarted) && Number.isFinite(parsedEnded)
				? Math.max(0, parsedEnded - parsedStarted)
				: executions.reduce((sum, execution) => sum + Math.max(0, execution.elapsedMs ?? 0), 0);
		return { startedAt, endedAt, elapsedMs };
	}

	function swarmRuntimeModel(executions: SwarmWorkerExecution[]): SwarmRuntimeModelSummary {
		return {
			provider: "re_swarm",
			modelId: "command-level-worker",
			modelCalls: 0,
			toolCalls: executions.length,
			toolResults: executions.length,
		};
	}

	function swarmRuntimeRetryBudget(worker: SwarmWorkerRuntime, attempt: number): SwarmRuntimeRetryBudget {
		return {
			signature: `re_swarm:${slug(worker.id)}:${createHash("sha256").update(worker.commands.join("\n")).digest("hex").slice(0, 16)}`,
			attempt,
			maxAttempts: 3,
			remaining: Math.max(0, 3 - attempt),
			exhausted: attempt >= 3,
		};
	}

	function writeSwarmSubagentRuntimeManifest(params: {
		swarm: SwarmArtifact;
		worker: SwarmWorkerRuntime;
		executions: SwarmWorkerExecution[];
		attempt: number;
		maxCommands: number;
		timeoutMs?: number;
	}): SwarmSubagentRuntimeManifestRow {
		const { swarm, worker, executions, attempt, maxCommands } = params;
		const timeoutMs =
			params.timeoutMs ??
			Math.max(
				1000,
				Math.min(30 * 60 * 1000, Math.max(...executions.map((execution) => execution.timeoutMs ?? 0), 60000)),
			);
		const sessionDir = join(swarmSubagentSessionRoot(swarm), slug(worker.id));
		mkdirSync(sessionDir, { recursive: true });
		const stdoutPath = join(sessionDir, "stdout.txt");
		const stderrPath = join(sessionDir, "stderr.txt");
		const runtimeManifestFile = join(sessionDir, "runtime-manifest.json");
		const stdout = executions.length
			? executions
					.map((execution, index) =>
						[`## command ${index + 1}: ${execution.command}`, execution.stdout ?? execution.output ?? ""].join(
							"\n",
						),
					)
					.join("\n\n")
			: `worker=${worker.id} status=queued no command selected for this bounded re_swarm run\n`;
		const stderr = executions.length
			? executions
					.map((execution, index) =>
						[`## command ${index + 1}: ${execution.command}`, execution.stderr ?? ""].join("\n"),
					)
					.join("\n\n")
			: "";
		// Atomic (opt #208): temp+rename 0o644 — a crash/ENOSPC mid-write cannot
		// leave a truncated stdout/stderr artifact that worker-result aggregation
		// later loads as partial output with no signal. Matches the nearby
		// runtime-manifest/transcript atomic writes (18053/18178/18366). The
		// previous bare writeFileSync truncated-then-wrote → a torn write lost the
		// worker's captured output.
		atomicWriteFileSync(stdoutPath, stdout, 0o644);
		atomicWriteFileSync(stderrPath, stderr, 0o644);
		const stdoutSha256 = swarmExecutionDigest(stdout);
		const stderrSha256 = swarmExecutionDigest(stderr);
		const status = swarmRuntimeStatus(executions);
		const terminalExecutions = terminalSwarmWorkerExecutions(executions);
		const timing = swarmRuntimeTimeWindow(executions, swarm.timestamp);
		const pid = terminalExecutions.find((execution) => Number.isInteger(execution.pid))?.pid ?? process.pid;
		const parentPid =
			terminalExecutions.find((execution) => Number.isInteger(execution.parentPid))?.parentPid ?? process.ppid;
		const exitCode =
			status === "queued"
				? null
				: status === "done"
					? 0
					: (terminalExecutions.find(swarmExecutionFailed)?.exitCode ?? 1);
		const signal = terminalExecutions.find((execution) => execution.signal)?.signal ?? null;
		const model = swarmRuntimeModel(executions);
		const evidenceRefs = Array.from(
			new Set(
				[
					swarm.delegationArtifact,
					...worker.sourceArtifacts,
					...executions.flatMap((execution) => execution.sourceArtifacts),
					stdoutPath,
					stderrPath,
				].filter((item): item is string => Boolean(item)),
			),
		).slice(0, 32);
		const toolCallDigest = createHash("sha256")
			.update(
				JSON.stringify({
					workerId: worker.id,
					attempt,
					commands: executions.map((execution) => execution.command),
					statuses: executions.map((execution) => execution.status),
					stdoutSha256,
					stderrSha256,
					model,
				}),
			)
			.digest("hex");
		const manifest: SwarmSubagentRuntimeManifestV1 = {
			kind: "SubagentRuntimeManifestV1",
			schemaVersion: 1,
			runId: swarm.parallelPlan?.planId ?? `re_swarm/${swarm.timestamp}`,
			roleId: worker.worker,
			workerId: worker.id,
			attempt,
			status,
			pid,
			parentPid,
			sessionDir,
			stdoutPath,
			stderrPath,
			stdoutSha256,
			stderrSha256,
			startedAt: timing.startedAt,
			endedAt: timing.endedAt,
			elapsedMs: timing.elapsedMs,
			exitCode,
			signal,
			model,
			toolCallDigest,
			claimLedgerPath: swarm.claimLedgerPath ?? swarmClaimLedgerPath(swarm),
			failureLedgerPath: runtimeFailureLedgerPath(),
			repairQueuePath: runtimeRepairQueuePath(),
			resourceLimits: {
				timeoutMs,
				maxCommands,
				maxOutputBytes: Buffer.byteLength(stdout) + Buffer.byteLength(stderr),
				cancelOnTimeout: true,
			},
			retryBudget: swarmRuntimeRetryBudget(worker, attempt),
			mergeKeys: worker.mergeKeys,
			evidenceRefs,
		};
		// opt #162: atomic temp+rename so a crash mid-write doesn't truncate the
		// swarm runtime manifest (a torn write → the verifier reads partial JSON
		// with no error → silent corruption).
		atomicWriteFileSync(runtimeManifestFile, `${JSON.stringify(manifest, null, 2)}\n`, 0o644);
		return {
			...manifest,
			runtimeManifestFile,
		};
	}

	function refreshSwarmSubagentRuntimeManifestCapture(swarm: SwarmArtifact): SwarmArtifact {
		const manifests = swarm.subagentRuntimeManifests ?? [];
		const subagentRuntimeManifestCount = manifests.length;
		const expectedWorkers = swarm.workers.length;
		const subagentRuntimeManifestsCaptured =
			expectedWorkers > 0 &&
			subagentRuntimeManifestCount >= expectedWorkers &&
			manifests.every(
				(manifest) =>
					manifest.kind === "SubagentRuntimeManifestV1" &&
					manifest.schemaVersion === 1 &&
					Boolean(manifest.runtimeManifestFile && existsSync(manifest.runtimeManifestFile)) &&
					Boolean(manifest.sessionDir && existsSync(manifest.sessionDir)) &&
					Boolean(manifest.stdoutPath && existsSync(manifest.stdoutPath)) &&
					Boolean(manifest.stderrPath && existsSync(manifest.stderrPath)) &&
					Boolean(manifest.stdoutSha256 && manifest.stderrSha256 && manifest.toolCallDigest) &&
					Number.isInteger(manifest.pid) &&
					Number.isInteger(manifest.parentPid) &&
					Boolean(manifest.model?.provider && manifest.model?.modelId),
			);
		return {
			...swarm,
			subagentRuntimeManifests: manifests,
			subagentRuntimeManifestCount,
			subagentRuntimeManifestsCaptured,
			sourceArtifacts: Array.from(
				new Set(
					[
						...swarm.sourceArtifacts,
						swarm.subagentRuntimeManifestPath,
						...manifests.flatMap((manifest) => [
							manifest.runtimeManifestFile,
							manifest.stdoutPath,
							manifest.stderrPath,
						]),
					].filter((item): item is string => Boolean(item)),
				),
			).slice(0, 64),
		};
	}

	async function runSwarm(pi: ExtensionAPI, options: SwarmRunOptions = {}): Promise<string> {
		options.signal?.throwIfAborted();
		const execution = resolveSwarmExecutionMode({
			execution: options.execution ?? autoModeDefaults().swarmExecution,
			cwd: options.cwd,
			agentThread: envBoolean("REPI_AGENT_THREAD") === true,
		});
		let swarm = buildSwarm({ target: options.target, task: options.task, mode: "run" });
		swarm.claimLedgerPath = swarmClaimLedgerPath(swarm);
		swarm.subagentRuntimeManifestPath = swarmSubagentRuntimeManifestIndexPath(swarm);
		const maxWorkers = Math.max(1, Math.min(8, Math.floor(options.maxWorkers ?? 3)));
		const maxCommands = Math.max(1, Math.min(5, Math.floor(options.maxCommands ?? 1)));
		const realMode = execution === "real";
		const retryLimit = swarmWorkerRetryLimit(execution);
		const selected = new Set(
			swarm.workers
				.filter((worker) => worker.status === "ready")
				.slice(0, maxWorkers)
				.map((worker) => worker.id),
		);
		for (const group of swarmWorkerGroups(swarm, selected)) {
			options.signal?.throwIfAborted();
			const groupRuns = await Promise.all(
				group.map(async (worker) => {
					const executions: SwarmWorkerExecution[] = [];
					const timeoutMs = swarmWorkerTimeoutMs(worker, realMode ? "real" : "simulated");
					if (realMode) {
						executions.push(
							...(await executeSwarmWorkerSubagent(
								worker,
								swarm,
								options.cwd as string,
								timeoutMs,
								1,
								options.signal,
							)),
						);
					} else {
						for (const command of worker.commands.slice(0, maxCommands))
							executions.push(await executeSwarmWorkerCommand(pi, worker, command, swarm.target, timeoutMs, 1));
					}
					for (
						let retry = 1;
						retry <= retryLimit &&
						!options.signal?.aborted &&
						terminalSwarmWorkerExecutions(executions).some(swarmExecutionFailed);
						retry++
					) {
						const attempt = retry + 1;
						const retryCommand = worker.commands[maxCommands + retry - 1] ?? worker.commands[0];
						if (!retryCommand) break;
						if (realMode) {
							const retryExecutions = await executeSwarmWorkerSubagent(
								worker,
								swarm,
								options.cwd as string,
								timeoutMs,
								attempt,
								options.signal,
							);
							for (const retryExecution of retryExecutions) {
								retryExecution.output = [
									`retry_execution: worker=${worker.id} attempt=${attempt}/${retryLimit + 1} previous_blocked=true`,
									retryExecution.output,
								].join("\n");
							}
							executions.push(...retryExecutions);
						} else {
							const retryExecution = await executeSwarmWorkerCommand(
								pi,
								worker,
								retryCommand,
								swarm.target,
								timeoutMs,
								attempt,
							);
							retryExecution.output = [
								`retry_execution: worker=${worker.id} attempt=${attempt}/${retryLimit + 1} previous_blocked=true`,
								retryExecution.output,
							].join("\n");
							executions.push(retryExecution);
						}
						if (terminalSwarmWorkerExecutions(executions).every(swarmExecutionSucceeded)) break;
					}
					const manifest = writeSwarmSubagentRuntimeManifest({
						swarm,
						worker,
						executions,
						attempt: Math.max(1, ...executions.map((item) => item.retryAttempt ?? 1)),
						maxCommands,
						timeoutMs,
					});
					return { executions, manifest };
				}),
			);
			options.signal?.throwIfAborted();
			swarm.executions.push(...groupRuns.flatMap((run) => run.executions));
			swarm.subagentRuntimeManifests.push(...groupRuns.map((run) => run.manifest));
			swarm = refreshSwarmSubagentRuntimeManifestCapture(swarm);
			swarm = refreshSwarmRunDerivedFields(swarm);
		}
		const manifestedWorkers = new Set(swarm.subagentRuntimeManifests.map((manifest) => manifest.workerId));
		const queuedManifests = swarm.workers
			.filter((worker) => !manifestedWorkers.has(worker.id))
			.map((worker) =>
				writeSwarmSubagentRuntimeManifest({
					swarm,
					worker,
					executions: [],
					attempt: 1,
					maxCommands,
					timeoutMs: swarmWorkerTimeoutMs(worker, realMode ? "real" : "simulated"),
				}),
			);
		if (queuedManifests.length) {
			swarm.subagentRuntimeManifests.push(...queuedManifests);
			swarm = refreshSwarmSubagentRuntimeManifestCapture(swarm);
		}
		swarm = refreshSwarmRunDerivedFields(swarm);
		writeSwarmArtifact(swarm);
		swarm = refreshSwarmRunDerivedFields(swarm);
		const path = writeSwarmArtifact(swarm);
		return formatSwarm(swarm, path);
	}

	function formatSwarm(swarm: SwarmArtifact, path?: string): string {
		return [
			"swarm_plan:",
			path ? `swarm_artifact: ${path}` : undefined,
			`timestamp: ${swarm.timestamp}`,
			`mode: ${swarm.mode}`,
			`mission_id: ${swarm.missionId ?? "none"}`,
			`route: ${swarm.route ?? "none"}`,
			`target: ${swarm.target ?? "<none>"}`,
			`delegation_artifact: ${swarm.delegationArtifact ?? "none"}`,
			"worker_runtime_packets:",
			...(swarm.workers.length
				? swarm.workers.flatMap((worker) => [
						`- ${worker.id} [${worker.status}] worker=${worker.worker}`,
						`  objective: ${worker.objective}`,
						`  dependencies: ${worker.dependencies.join(", ") || "none"}`,
						`  merge_keys: ${worker.mergeKeys.join(" | ")}`,
						`  evidence_contract: ${worker.evidenceContract.join(" | ")}`,
						`  spawn_prompt: ${worker.spawnPrompt.join(" ; ")}`,
						`  commands: ${worker.commands.join(" || ")}`,
					])
				: ["- none"]),
			`worker_executions: ${swarm.executions.length}`,
			...(swarm.executions.length
				? swarm.executions.map(
						(execution) =>
							`- ${execution.workerId} [${execution.status}] worker=${execution.worker} command=${execution.command} :: ${truncateMiddle(execution.output.replace(/\s+/g, " "), 260)}`,
					)
				: []),
			"worker_results:",
			...(swarm.workerResults.length ? swarm.workerResults.map((item) => `- ${item}`) : ["- none"]),
			"blocked:",
			...(swarm.blocked.length ? swarm.blocked.map((item) => `- ${item}`) : ["- none"]),
			"merge_digest:",
			...(swarm.mergeDigest.length ? swarm.mergeDigest.map((item) => `- ${item}`) : ["- none"]),
			"execution_audit:",
			...(swarm.executionAudit.length ? swarm.executionAudit.map((item) => `- ${item}`) : ["- none"]),
			"coverage_matrix:",
			...(swarm.coverageMatrix.length ? swarm.coverageMatrix.map((item) => `- ${item}`) : ["- none"]),
			"retry_queue:",
			...(swarm.retryQueue.length ? swarm.retryQueue.map((item) => `- ${item}`) : ["- none"]),
			"parallel_groups:",
			...(swarm.parallelGroups.length ? swarm.parallelGroups.map((item) => `- ${item}`) : ["- none"]),
			"merge_protocol:",
			...(swarm.mergeProtocol.length ? swarm.mergeProtocol.map((item) => `- ${item}`) : ["- none"]),
			"collision_matrix:",
			...(swarm.collisionMatrix.length ? swarm.collisionMatrix.map((item) => `- ${item}`) : ["- none"]),
			"evidence_contract:",
			...(swarm.evidenceContract.length ? swarm.evidenceContract.map((item) => `- ${item}`) : ["- none"]),
			"commander_next_actions:",
			...(swarm.commanderNextActions.length
				? swarm.commanderNextActions.map((item) => `- ${item}`)
				: ["- re_supervisor review"]),
			"handoff_digest:",
			...(swarm.handoffDigest.length ? swarm.handoffDigest.map((item) => `- ${item}`) : ["- none"]),
			"parallel_plan:",
			...(swarm.parallelPlan
				? [
						`- plan_id=${swarm.parallelPlan.planId}`,
						`- source=${swarm.parallelPlan.source}`,
						`- workers=${swarm.parallelPlan.workers.length}`,
						`- parallel_mode=${
							swarm.executions.some((execution) => /^re[-_]/i.test(execution.command))
								? "simulated_sequential_for_internal_repi_commands"
								: "child_process_for_shell_commands"
						}`,
						`- isolation=${
							swarm.executions.some((execution) =>
								/isolation=shared-process-internal-dispatch/i.test(execution.output),
							)
								? "shared-process-internal-dispatch"
								: "subprocess-shell"
						}`,
						`- merge=${swarm.parallelPlan.merge.strategy}`,
					]
				: ["- none"]),
			"plan_coverage:",
			...(swarm.planCoverage.length ? swarm.planCoverage.map((item) => `- ${item}`) : ["- none"]),
			"release_check_metadata:",
			...(swarm.releaseCheckMetadata.length ? swarm.releaseCheckMetadata.map((item) => `- ${item}`) : ["- none"]),
			"runtime_claim_ledger:",
			`- path=${swarm.claimLedgerPath ?? "pending"}`,
			`- events=${swarm.claimLedgerEventCount}`,
			`- tip_hash=${swarm.claimLedgerTipHash ?? "none"}`,
			`- hash_chain=${swarm.runtimeClaimLedgerCaptured ? "pass" : "fail"}`,
			...(swarm.claimLedger.length
				? swarm.claimLedger
						.slice(0, 10)
						.map(
							(event) =>
								`- seq=${event.seq} type=${event.type} claim=${event.claimId ?? "none"} status=${event.status ?? "n/a"} hash=${event.eventHash.slice(0, 16)}`,
						)
				: ["- none"]),
			"structured_claim_merge:",
			`- path=${swarm.structuredClaimMergePath ?? "pending"}`,
			`- status=${swarm.structuredClaimMergeStatus ?? "missing"}`,
			`- final_claims=${swarm.structuredClaimMerge?.promotionCheck?.finalClaims?.length ?? 0}`,
			`- blocked_claims=${swarm.structuredClaimMerge?.promotionCheck?.blockedClaims?.length ?? 0}`,
			...(swarm.structuredClaimMergeErrors?.length
				? swarm.structuredClaimMergeErrors.slice(0, 10).map((item) => `- error=${item}`)
				: ["- errors=none"]),
			"subagent_runtime_manifests:",
			`- path=${swarm.subagentRuntimeManifestPath ?? "pending"}`,
			`- count=${swarm.subagentRuntimeManifestCount ?? 0}`,
			`- captured=${swarm.subagentRuntimeManifestsCaptured ? "pass" : "fail"}`,
			...((swarm.subagentRuntimeManifests ?? []).length
				? (swarm.subagentRuntimeManifests ?? [])
						.slice(0, 12)
						.map(
							(manifest) =>
								`- worker=${manifest.workerId} role=${manifest.roleId} status=${manifest.status} attempt=${manifest.attempt}/${manifest.retryBudget.maxAttempts} retryRemaining=${manifest.retryBudget.remaining} timeoutMs=${manifest.resourceLimits.timeoutMs} pid=${manifest.pid ?? "null"} sessionDir=${manifest.sessionDir} runtimeManifestFile=${manifest.runtimeManifestFile} stdoutSha256=${manifest.stdoutSha256.slice(0, 16)} stderrSha256=${manifest.stderrSha256.slice(0, 16)} toolCallDigest=${manifest.toolCallDigest.slice(0, 16)}`,
						)
				: ["- none"]),
			"worker_child_session_runtime:",
			`- path=${swarm.workerChildSessionRuntimePath ?? "pending"}`,
			`- status=${swarm.workerChildSessionRuntimeStatus ?? "missing"}`,
			`- sessions=${swarm.workerChildSessionRuntime?.sessions.length ?? 0}`,
			`- pool_bridge=${swarm.workerRuntimePoolBridgeStatus ?? "missing"}`,
			`- childSessionRuntimeCaptured=${swarm.workerChildSessionRuntime?.poolBridge.childSessionRuntimeCaptured ?? false}`,
			...(swarm.workerChildSessionRuntimeErrors?.length
				? swarm.workerChildSessionRuntimeErrors.slice(0, 8).map((error) => `- child_error=${error}`)
				: ["- child_errors=none"]),
			...(swarm.workerRuntimePoolBridgeErrors?.length
				? swarm.workerRuntimePoolBridgeErrors.slice(0, 8).map((error) => `- pool_error=${error}`)
				: ["- pool_errors=none"]),
			"worker_retry_handoff_closure:",
			`- path=${swarm.workerRetryHandoffClosurePath ?? "pending"}`,
			`- status=${swarm.workerRetryHandoffClosureStatus ?? "missing"}`,
			`- workers=${swarm.workerRetryHandoffClosure?.workers.length ?? 0}`,
			`- recovered=${swarm.workerRetryHandoffClosure?.merge.recoveredWorkers.length ?? 0}`,
			`- unresolved=${swarm.workerRetryHandoffClosure?.merge.unresolvedWorkers.length ?? 0}`,
			`- retry_attempts_bounded=${swarm.workerRetryHandoffClosure?.assertions.retryAttemptsBounded ? "pass" : "fail"}`,
			`- failed_workers_closed=${swarm.workerRetryHandoffClosure?.assertions.failedWorkersHaveRetryOrHandoff ? "pass" : "fail"}`,
			`- timeout_cancel_recorded=${swarm.workerRetryHandoffClosure?.assertions.timeoutCancellationRecorded ? "pass" : "fail"}`,
			`- handoff_recovered=${(swarm.workerRetryHandoffClosure?.merge.recoveredWorkers.length ?? 0) > 0 ? "true" : "false"}`,
			...((swarm.workerRetryHandoffClosure?.workers ?? []).length
				? (swarm.workerRetryHandoffClosure?.workers ?? [])
						.slice(0, 12)
						.map(
							(worker) =>
								`- worker=${worker.workerId} status=${worker.status} retryState=${worker.retryState} attempt=${worker.attempt}/${worker.maxAttempts} retryRemaining=${worker.retryRemaining} timedOut=${worker.timedOut} handoffRefs=${worker.handoffRefs.length} retryQueueRefs=${worker.retryQueueRefs.length} claimRefs=${worker.claimRefs.length}`,
						)
				: ["- workers=none"]),
			...(swarm.workerRetryHandoffClosureErrors?.length
				? swarm.workerRetryHandoffClosureErrors.slice(0, 8).map((error) => `- retry_handoff_error=${error}`)
				: ["- retry_handoff_errors=none"]),
			"worker_retry_handoff_merge_summary:",
			`- path=${swarm.workerRetryHandoffMergeSummaryPath ?? "pending"}`,
			`- status=${swarm.workerRetryHandoffMergeSummaryStatus ?? "missing"}`,
			`- next_actions=${swarm.workerRetryHandoffMergeSummary?.nextActions.length ?? 0}`,
			`- retry_queued=${swarm.workerRetryHandoffMergeSummary?.retryQueuedWorkers.length ?? 0}`,
			`- handoff_recovered=${swarm.workerRetryHandoffMergeSummary?.handoffRecoveredWorkers.length ?? 0}`,
			`- exhausted_escalated=${swarm.workerRetryHandoffMergeSummary?.exhaustedEscalatedWorkers.length ?? 0}`,
			`- unresolved_workers=${swarm.workerRetryHandoffMergeSummary?.unresolvedWorkers.length ?? 0}`,
			`- unresolved_collisions=${swarm.workerRetryHandoffMergeSummary?.unresolvedCollisions.length ?? 0}`,
			`- retry_budget_visible=${swarm.workerRetryHandoffMergeSummary?.assertions.retryBudgetVisible ? "pass" : "fail"}`,
			`- source_artifacts_preserved=${swarm.workerRetryHandoffMergeSummary?.assertions.sourceArtifactsPreserved ? "pass" : "fail"}`,
			`- worker_closures=${swarm.workerRetryHandoffMergeSummary?.workerClosures.length ?? 0}`,
			...((swarm.workerRetryHandoffMergeSummary?.workerClosures ?? []).length
				? (swarm.workerRetryHandoffMergeSummary?.workerClosures ?? [])
						.slice(0, 12)
						.map(
							(worker) =>
								`- closure=${worker.summary} handoffRefs=${worker.handoffRefs.length} retryQueueRefs=${worker.retryQueueRefs.length} repairRefs=${worker.repairRefs.length} claimRefs=${worker.claimRefs.length}`,
						)
				: ["- closure=none"]),
			...((swarm.workerRetryHandoffMergeSummary?.nextActions ?? []).length
				? (swarm.workerRetryHandoffMergeSummary?.nextActions ?? []).slice(0, 8).map((action) => `- next=${action}`)
				: ["- next=none"]),
			...(swarm.workerRetryHandoffMergeSummaryErrors?.length
				? swarm.workerRetryHandoffMergeSummaryErrors.slice(0, 8).map((error) => `- merge_summary_error=${error}`)
				: ["- merge_summary_errors=none"]),
			"worker_lease_scheduler:",
			`- path=${swarm.workerLeaseSchedulerPath ?? "pending"}`,
			`- status=${swarm.workerLeaseSchedulerStatus ?? "missing"}`,
			`- tasks=${swarm.workerLeaseScheduler?.tasks.length ?? 0}`,
			`- events=${swarm.workerLeaseScheduler?.events.length ?? 0}`,
			`- stale_recovery=${swarm.workerLeaseScheduler?.assertions.staleLeaseRecovered ? "pass" : "fail"}`,
			`- work_stealing=${swarm.workerLeaseScheduler?.assertions.workStealingObserved ? "pass" : "fail"}`,
			`- duplicate_completion_rejected=${swarm.workerLeaseScheduler?.assertions.duplicateCompletionRejected ? "pass" : "fail"}`,
			...(swarm.workerLeaseSchedulerErrors?.length
				? swarm.workerLeaseSchedulerErrors.slice(0, 8).map((error) => `- scheduler_error=${error}`)
				: ["- scheduler_errors=none"]),
			`next_swarm_command: ${
				swarm.mode === "merge"
					? "re_supervisor review"
					: swarm.mode === "run"
						? "re_swarm merge"
						: `re_swarm run ${swarm.target ?? "<target>"} 3 1`
			}`,
			"source_artifacts:",
			...(swarm.sourceArtifacts.length ? swarm.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeSwarmArtifact(swarm: SwarmArtifact): string {
		ensureReconStorage();
		const path = swarmArtifactPath(swarm);
		swarm.claimLedgerPath = swarmClaimLedgerPath(swarm);
		swarm.structuredClaimMergePath = swarmStructuredClaimMergePath(swarm);
		swarm.subagentRuntimeManifestPath = swarmSubagentRuntimeManifestIndexPath(swarm);
		swarm.workerLeaseSchedulerPath = swarmWorkerLeaseSchedulerPath(swarm);
		swarm.workerRetryHandoffClosurePath = swarmWorkerRetryHandoffClosurePath(swarm);
		swarm.workerRetryHandoffMergeSummaryPath = swarmWorkerRetryHandoffMergeSummaryPath(swarm);
		Object.assign(swarm, refreshSwarmSubagentRuntimeManifestCapture(swarm));
		Object.assign(swarm, refreshSwarmWorkerChildSessionRuntime(swarm));
		Object.assign(swarm, refreshSwarmWorkerRetryHandoffClosure(swarm));
		Object.assign(swarm, refreshSwarmWorkerLeaseScheduler(swarm));
		// Derive integrity witnesses only after every persisted runtime field has settled.
		Object.assign(swarm, refreshSwarmRuntimeClaimLedger(swarm));
		// opt #162: atomic temp+rename for the swarm runtime state writes below —
		// a torn writeFileSync would leave truncated JSON/JSONL that the verifier
		// re-reads with no error (silent corruption). Same doctrine as #43/#103.
		atomicWriteFileSync(
			swarm.claimLedgerPath,
			`${swarm.claimLedger.map((event) => JSON.stringify(event)).join("\n")}${swarm.claimLedger.length ? "\n" : ""}`,
			0o644,
		);
		if (swarm.structuredClaimMergePath && swarm.structuredClaimMerge) {
			atomicWriteFileSync(
				swarm.structuredClaimMergePath,
				`${JSON.stringify(swarm.structuredClaimMerge, null, 2)}\n`,
				0o644,
			);
		}
		atomicWriteFileSync(
			swarm.subagentRuntimeManifestPath,
			`${JSON.stringify(
				{
					kind: "repi-swarm-subagent-runtime-manifest-index",
					schemaVersion: 1,
					planId: swarm.parallelPlan?.planId ?? "missing",
					swarmArtifact: path,
					manifestCount: swarm.subagentRuntimeManifestCount,
					captured: swarm.subagentRuntimeManifestsCaptured,
					manifests: swarm.subagentRuntimeManifests,
				},
				null,
				2,
			)}\n`,
			0o644,
		);
		atomicWriteFileSync(
			path,
			[
				"# REPI Swarm Artifact",
				"",
				formatSwarm(swarm, path),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(swarm, null, 2),
				"```",
				"",
			].join("\n"),
			0o644,
		);
		appendEvidence({
			kind: swarm.mode === "run" ? "runtime" : "artifact",
			title: `swarm-${swarm.mode} ${swarm.missionId ?? "no-mission"}`,
			fact: `Built swarm ${swarm.mode} with ${swarm.workers.length} worker runtime packet(s), ${swarm.executions.length} execution(s), ${swarm.parallelGroups.length} parallel group(s), ${swarm.collisionMatrix.length} collision(s), ${swarm.blocked.length} blocked, audit=${swarm.executionAudit.length}, retries=${swarm.retryQueue.length}, parallel_plan=${swarm.parallelPlan?.planId ?? "missing"}, plan_coverage=${swarm.planCoverage.length}, release_check_metadata=${swarm.releaseCheckMetadata.length}, subagent_runtime_manifests=${swarm.subagentRuntimeManifestCount} captured=${swarm.subagentRuntimeManifestsCaptured ? "pass" : "fail"}, runtime_claim_ledger=${swarm.claimLedgerEventCount} hash_chain=${swarm.runtimeClaimLedgerCaptured ? "pass" : "fail"}, structured_claim_merge=${swarm.structuredClaimMergeStatus ?? "missing"}, retry_handoff_closure=${swarm.workerRetryHandoffClosureStatus ?? "missing"}, retry_handoff_merge_summary=${swarm.workerRetryHandoffMergeSummaryStatus ?? "missing"}`,
			command: `re_swarm ${swarm.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "multi-specialist swarm orchestration",
		});
		updateMissionCheckpoint("swarm_plan_ready", "done", path);
		return path;
	}

	function buildSwarmOutput(action: "plan" | "show" | "merge" = "plan", options: SwarmOutputOptions = {}): string {
		if (action === "show") {
			const path = latestSwarmArtifactPath();
			if (!path) return "swarm_plan:\nstatus: missing\nnext: re_swarm plan";
			return compactStoredArtifact("swarm_plan", path, readText(path));
		}
		let swarm =
			action === "merge"
				? (() => {
						const latest = latestSwarmArtifactPath();
						const parsed = latest ? parseSwarmArtifact(latest) : undefined;
						const missionId = readCurrentMission()?.id;
						return parsed && missionId && parsed.missionId === missionId
							? refreshSwarmRunDerivedFields({
									...parsed,
									artifactId: randomUUID(),
									timestamp: new Date().toISOString(),
									mode: "merge",
								})
							: undefined;
					})()
				: undefined;
		swarm ??= buildSwarm({ ...options, mode: action === "merge" ? "merge" : "plan" });
		const path = writeSwarmArtifact(swarm);
		return formatSwarm(swarm, path);
	}

	return {
		latestSwarmArtifactPath,
		latestSwarmRunArtifactPath,
		swarmArtifactPath,
		swarmClaimLedgerPath,
		swarmStructuredClaimMergePath,
		swarmSubagentRuntimeManifestIndexPath,
		swarmWorkerChildSessionRuntimePath,
		swarmWorkerRetryHandoffClosurePath,
		swarmWorkerRetryHandoffMergeSummaryPath,
		swarmWorkerLeaseSchedulerPath,
		swarmSubagentSessionRoot,
		parseSwarmArtifact,
		recentSwarmArtifactsForGraph,
		splitRetryNextCommands,
		latestSwarmRetryQueue,
		buildSwarmParallelPlan,
		swarmPlanCoverage,
		swarmReleaseCheckMetadata,
		buildSwarmRuntimeClaimLedger,
		buildStructuredClaimMergeFromSwarm,
		structuredClaimMergeCheckFromSwarm,
		refreshSwarmRuntimeClaimLedger,
		buildSwarm,
		swarmWorkerSpec,
		executeSwarmWorkerSubagent,
		executeSwarmWorkerCommand,
		deriveSwarmAuditFields,
		refreshSwarmRunDerivedFields,
		writeSwarmSubagentRuntimeManifest,
		buildWorkerChildSessionRuntimeBatchFromSwarm,
		runWorkerChildProcessProbe,
		buildSwarmWorkerRetryHandoffClosure,
		buildWorkerLeaseSchedulerFromSwarm,
		runSwarm,
		formatSwarm,
		writeSwarmArtifact,
		buildSwarmOutput,
		latestSupervisorArtifactPath,
		parseSupervisorArtifact,
		parseDelegateArtifact,
		latestOrBuildDelegate,
		supervisorClaimCheckPolicy,
		supervisorPlanCoverage,
		buildSupervisor,
		formatSupervisor,
		writeSupervisorArtifact,
		parseSupervisorCritique,
		buildSupervisorOutput,
	};
}

export type SwarmSupervisorRuntime = ReturnType<typeof createSwarmSupervisorRuntime>;

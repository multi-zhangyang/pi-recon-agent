import { atomicWriteFileSync } from "../tools/atomic-write.ts";
import { runtimeFailureLedgerPath, runtimeRepairQueuePath } from "./storage.ts";
import { swarmWorkerRetryHandoffClosurePath, swarmWorkerRetryHandoffMergeSummaryPath } from "./swarm-artifact-paths.ts";
import type {
	SwarmArtifact,
	SwarmWorkerExecution,
	WorkerRuntimePoolV1,
	WorkerRuntimePoolWorkerV1,
} from "./swarm-runtime-types.ts";
import { slug, uniqueNonEmpty } from "./text.ts";
import {
	buildWorkerRetryHandoffMergeSummaryV1,
	type RepiWorkerRetryHandoffClosureV1,
	verifyWorkerRetryHandoffClosureV1,
	verifyWorkerRetryHandoffMergeSummaryV1,
} from "./worker-runtime.ts";

export type SwarmWorkerRetryHandoffRuntimeDependencies = {
	executionFailed(execution: SwarmWorkerExecution): boolean;
	terminalExecutions(executions: readonly SwarmWorkerExecution[]): SwarmWorkerExecution[];
};

export function createSwarmWorkerRetryHandoffRuntime(dependencies: SwarmWorkerRetryHandoffRuntimeDependencies) {
	const { executionFailed, terminalExecutions } = dependencies;

	function workerPoolStatusPassed(status: WorkerRuntimePoolWorkerV1["status"]): boolean {
		return status === "done" || status === "passed";
	}

	function workerPoolStatusFailed(status: WorkerRuntimePoolWorkerV1["status"]): boolean {
		return ["blocked", "failed", "timeout", "cancelled", "retry_queued", "exhausted"].includes(status);
	}

	function workerRetryQueueRefsForSwarmWorker(swarm: SwarmArtifact, workerId: string): string[] {
		const refs = swarm.retryQueue.filter((row) => row.includes(`worker=${workerId}`));
		return uniqueNonEmpty(refs, 12);
	}

	function workerHandoffRefsForSwarmWorker(swarm: SwarmArtifact, workerId: string): string[] {
		const manifests = (swarm.subagentRuntimeManifests ?? []).filter((manifest) => manifest.workerId === workerId);
		return uniqueNonEmpty(
			manifests.flatMap((manifest) => [
				manifest.runtimeManifestFile,
				manifest.stdoutPath,
				manifest.stderrPath,
				...manifest.evidenceRefs,
			]),
			24,
		);
	}

	function workerRepairRefsForSwarmWorker(swarm: SwarmArtifact, workerId: string): string[] {
		const manifests = (swarm.subagentRuntimeManifests ?? []).filter((manifest) => manifest.workerId === workerId);
		const failed = terminalExecutions(swarm.executions.filter((execution) => execution.workerId === workerId)).some(
			executionFailed,
		);
		return uniqueNonEmpty(
			[
				...manifests.flatMap((manifest) => [manifest.failureLedgerPath, manifest.repairQueuePath]),
				...(failed ? [runtimeFailureLedgerPath(), runtimeRepairQueuePath()] : []),
			],
			12,
		);
	}

	function workerRetryHandoffState(params: {
		worker: WorkerRuntimePoolWorkerV1;
		retryQueueRefs: string[];
		handoffRefs: string[];
		repairRefs: string[];
	}): RepiWorkerRetryHandoffClosureV1["workers"][number]["retryState"] {
		const { worker, retryQueueRefs, handoffRefs, repairRefs } = params;
		if (workerPoolStatusPassed(worker.status)) return "passed";
		if (!workerPoolStatusFailed(worker.status)) return "not_needed";
		if (worker.status === "exhausted") return repairRefs.length ? "exhausted_escalated" : "blocked_without_closure";
		if (retryQueueRefs.length && worker.retryBudget.remaining > 0) return "retry_queued";
		if (handoffRefs.length && worker.claimRefs.length) return "handoff_recovered";
		if (repairRefs.length) return worker.retryBudget.remaining > 0 ? "retry_queued" : "exhausted_escalated";
		return "blocked_without_closure";
	}

	function buildSwarmWorkerRetryHandoffClosure(
		swarm: SwarmArtifact,
		pool: WorkerRuntimePoolV1,
	): RepiWorkerRetryHandoffClosureV1 {
		const generatedAt = new Date().toISOString();
		const closureId = `worker-retry-handoff/${slug(swarm.route ?? swarm.target ?? "swarm")}/${swarm.timestamp}`;
		const workers = pool.workers.map((worker): RepiWorkerRetryHandoffClosureV1["workers"][number] => {
			const retryQueueRefs = workerRetryQueueRefsForSwarmWorker(swarm, worker.workerId);
			const handoffRefs = workerHandoffRefsForSwarmWorker(swarm, worker.workerId);
			const repairRefs = workerRepairRefsForSwarmWorker(swarm, worker.workerId);
			const mergeKeys = Array.isArray(worker.mergeKey) ? worker.mergeKey : [worker.mergeKey];
			const collisionEvidenceRefs = pool.mergeProtocol.conflicts
				.filter((conflict) => conflict.workers.includes(worker.workerId) || mergeKeys.includes(conflict.mergeKey))
				.flatMap((conflict) => conflict.evidenceRefs);
			const sourceArtifacts = uniqueNonEmpty(
				[
					...worker.claimRefs,
					...mergeKeys,
					...collisionEvidenceRefs,
					...retryQueueRefs,
					...handoffRefs,
					...repairRefs,
					worker.stdoutPath,
					worker.stderrPath,
					swarm.claimLedgerPath,
					swarm.workerChildSessionRuntimePath,
				],
				40,
			);
			const timedOut = worker.status === "timeout";
			const retryRemaining = Math.max(0, worker.maxAttempts - worker.attempt);
			const isFailure = workerPoolStatusFailed(worker.status);
			const exhausted =
				worker.status === "exhausted" || worker.retryBudget.exhausted || worker.attempt >= worker.maxAttempts;
			const retryState = workerRetryHandoffState({ worker, retryQueueRefs, handoffRefs, repairRefs });
			const assertions = {
				attemptBounded: worker.attempt <= worker.maxAttempts,
				retryBudgetConsistent:
					worker.retryBudget.attempt === worker.attempt &&
					worker.retryBudget.maxAttempts === worker.maxAttempts &&
					worker.retryBudget.remaining === retryRemaining &&
					worker.retryBudget.exhausted === exhausted,
				timeoutCancellationRecorded: !timedOut || Boolean(worker.cancelledAt),
				failureHasRetryOrHandoff:
					!isFailure || retryQueueRefs.length > 0 || handoffRefs.length > 0 || repairRefs.length > 0,
				exhaustionEscalated: !exhausted || workerPoolStatusPassed(worker.status) || repairRefs.length > 0,
				handoffBoundToClaim: handoffRefs.length === 0 || worker.claimRefs.length > 0,
				sourceArtifactsPreserved: sourceArtifacts.length > 0,
			};
			return {
				workerId: worker.workerId,
				role: worker.role,
				packetId: worker.packetId,
				status: worker.status,
				attempt: worker.attempt,
				maxAttempts: worker.maxAttempts,
				retryRemaining,
				retryState,
				timeoutMs: worker.timeoutMs,
				timedOut,
				cancelledAt: worker.cancelledAt,
				retryQueueRefs,
				handoffRefs,
				repairRefs,
				claimRefs: worker.claimRefs,
				sourceArtifacts,
				mergeKeys,
				assertions,
			};
		});
		const recoveredWorkers = workers
			.filter((worker) => worker.retryState === "handoff_recovered" || worker.retryState === "retry_queued")
			.map((worker) => worker.workerId);
		const unresolvedWorkers = workers
			.filter((worker) => worker.retryState === "blocked_without_closure")
			.map((worker) => worker.workerId);
		const collisions = pool.mergeProtocol.conflicts.map((conflict) => ({
			mergeKey: conflict.mergeKey,
			workers: conflict.workers,
			status: conflict.status,
			winner: conflict.winner,
			evidenceRefs: conflict.evidenceRefs,
			resolutionReason: conflict.resolutionReason,
		}));
		const reportWithoutAssertions = {
			kind: "WorkerRetryHandoffClosureV1" as const,
			schemaVersion: 1 as const,
			closureId,
			poolId: pool.poolId,
			generatedAt,
			strategy: "retry-budgeted claim-bound handoff closure" as const,
			workers,
			merge: {
				strategy: "claim-bound handoff merge" as const,
				recoveredWorkers,
				unresolvedWorkers,
				collisions,
			},
		};
		const assertions = {
			retryAttemptsBounded: workers.every((worker) => worker.assertions.attemptBounded),
			retryBudgetsConsistent: workers.every((worker) => worker.assertions.retryBudgetConsistent),
			timeoutCancellationRecorded: workers.every((worker) => worker.assertions.timeoutCancellationRecorded),
			failedWorkersHaveRetryOrHandoff: workers.every((worker) => worker.assertions.failureHasRetryOrHandoff),
			exhaustedWorkersEscalated: workers.every((worker) => worker.assertions.exhaustionEscalated),
			handoffRefsBoundToClaims: workers.every((worker) => worker.assertions.handoffBoundToClaim),
			mergeCollisionsResolved: collisions.every((collision) => collision.status === "resolved"),
			claimRefsPreserved: workers.every((worker) => worker.claimRefs.length > 0),
			sourceArtifactsPreserved: workers.every((worker) => worker.assertions.sourceArtifactsPreserved),
		};
		return {
			...reportWithoutAssertions,
			assertions,
			errors: [],
		};
	}

	function refreshSwarmWorkerRetryHandoffClosure(swarm: SwarmArtifact): SwarmArtifact {
		const path = swarmWorkerRetryHandoffClosurePath(swarm);
		const summaryPath = swarmWorkerRetryHandoffMergeSummaryPath(swarm);
		const pool = swarm.workerRuntimePoolBridge;
		if (!pool) {
			return {
				...swarm,
				workerRetryHandoffClosurePath: path,
				workerRetryHandoffClosureStatus: "missing",
				workerRetryHandoffClosureErrors: ["worker_runtime_pool_bridge_missing"],
				workerRetryHandoffMergeSummaryPath: summaryPath,
				workerRetryHandoffMergeSummaryStatus: "missing",
				workerRetryHandoffMergeSummaryErrors: ["worker_runtime_pool_bridge_missing"],
			};
		}
		const report = buildSwarmWorkerRetryHandoffClosure(swarm, pool);
		const validation = verifyWorkerRetryHandoffClosureV1(report);
		const mergeSummary = buildWorkerRetryHandoffMergeSummaryV1(report);
		const mergeSummaryValidation = verifyWorkerRetryHandoffMergeSummaryV1(mergeSummary);
		const artifact = { closure: report, validation };
		atomicWriteFileSync(path, `${JSON.stringify(artifact, null, 2)}\n`, 0o644);
		atomicWriteFileSync(
			summaryPath,
			`${JSON.stringify({ summary: mergeSummary, validation: mergeSummaryValidation }, null, 2)}\n`,
			0o644,
		);
		return {
			...swarm,
			workerRetryHandoffClosurePath: path,
			workerRetryHandoffClosure: report,
			workerRetryHandoffClosureStatus: validation.ok ? "pass" : "blocked",
			workerRetryHandoffClosureErrors: validation.errors,
			workerRetryHandoffMergeSummaryPath: summaryPath,
			workerRetryHandoffMergeSummary: mergeSummary,
			workerRetryHandoffMergeSummaryStatus: mergeSummaryValidation.ok ? "pass" : "blocked",
			workerRetryHandoffMergeSummaryErrors: mergeSummaryValidation.errors,
			sourceArtifacts: uniqueNonEmpty(
				[
					...swarm.sourceArtifacts,
					path,
					summaryPath,
					...report.workers.flatMap((worker) => [
						...worker.handoffRefs,
						...worker.retryQueueRefs,
						...worker.repairRefs,
					]),
				],
				120,
			),
		};
	}

	return {
		buildSwarmWorkerRetryHandoffClosure,
		refreshSwarmWorkerRetryHandoffClosure,
	};
}

export type SwarmWorkerRetryHandoffRuntime = ReturnType<typeof createSwarmWorkerRetryHandoffRuntime>;

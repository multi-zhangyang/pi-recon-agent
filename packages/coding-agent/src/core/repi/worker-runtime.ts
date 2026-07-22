import { createHash } from "node:crypto";
import { join } from "node:path";
import { REPI_MODEL_ENV_VARIABLES } from "../repi-env-provider.ts";
import {
	type RepiWorkerProviderChildProcessProbeV1,
	verifyWorkerProviderChildProcessProbe,
} from "./provider-worker-runtime.ts";
import { uniqueNonEmpty } from "./text.ts";

export type {
	RepiParallelProviderWorkerMatrixV1,
	RepiProviderFailureInjectionReportV1,
	RepiProviderRuntimeMatrixCaseV1,
	RepiProviderRuntimeMatrixV1,
	RepiRemoteProviderLongRunV1,
	RepiRepairRollbackPolicyV1,
	RepiWorkerProviderChildProcessProbeV1,
} from "./provider-worker-runtime.ts";
export {
	verifyParallelProviderWorkerMatrixV1,
	verifyProviderFailureInjectionReportV1,
	verifyProviderRuntimeMatrixV1,
	verifyRemoteProviderLongRunV1,
	verifyRepairRollbackPolicyV1,
	verifyWorkerProviderChildProcessProbe,
} from "./provider-worker-runtime.ts";

export type RepiSwarmRuntimeState = "queued" | "done" | "blocked" | "cancelled";

export type RepiSwarmRuntimeRetryBudget = {
	signature: string;
	attempt: number;
	maxAttempts: number;
	remaining: number;
	exhausted: boolean;
};

export type RepiFailureRepairArtifactHash = {
	path: string;
	sha256: string;
	tier: string;
};

export type RepiSwarmClaimLedgerEventV1 = {
	kind: "ClaimLedgerEventV1";
	seq: number;
	prevHash: string;
	eventHash: string;
	timestamp: string;
	source: "re_swarm";
	type: "artifact_handoff" | "claim" | "validation" | "challenge" | "resolution";
	claimId?: string;
	claimIds?: string[];
	workerId?: string;
	role?: string;
	scope?: string;
	status?: "proven" | "gap" | "pending" | "blocked" | "pass" | "fail" | "accepted" | "queued_repair";
	statement?: string;
	challenge?: string;
	resolution?: string;
	evidenceRefs: string[];
	artifactHashes?: RepiFailureRepairArtifactHash[];
	metadata?: Record<string, unknown>;
};

export type RepiWorkerRuntimePoolWorkerV1 = {
	workerId: string;
	role: string;
	route: string;
	packetId: string;
	attempt: number;
	maxAttempts: number;
	retryBudget: RepiSwarmRuntimeRetryBudget;
	resourceLease: {
		cpuSlots: number;
		memoryMb: number;
		maxProcesses: number;
	};
	timeoutMs: number;
	status: RepiSwarmRuntimeState | "passed" | "failed" | "timeout" | "retry_queued" | "exhausted";
	startedAt?: string;
	endedAt?: string;
	cancelledAt?: string;
	sessionDir: string;
	stdoutPath: string;
	stderrPath: string;
	stdoutSha256: string;
	stderrSha256: string;
	toolCallDigest: string;
	mergeKey: string | string[];
	claimRefs: string[];
};

export type RepiWorkerRuntimePoolV1 = {
	kind: "WorkerRuntimePoolV1";
	schemaVersion: 1;
	poolId: string;
	maxConcurrency: number;
	timeoutMs: number;
	cancelOnTimeout: boolean;
	resourceBudget: {
		cpuSlots: number;
		memoryMb: number;
		maxProcesses: number;
	};
	workers: RepiWorkerRuntimePoolWorkerV1[];
	parallelGroups: {
		groupId: string;
		workers: string[];
		dependsOn: string[];
		maxConcurrency: number;
	}[];
	mergeProtocol: {
		strategy: "claim-aware merge";
		evidenceContract: string[];
		conflicts: {
			mergeKey: string;
			workers: string[];
			status: "resolved" | "unresolved";
			winner?: string;
			evidenceRefs: string[];
			resolutionReason?: string;
		}[];
	};
	claimLedgerEvents: RepiSwarmClaimLedgerEventV1[];
};

export type RepiWorkerRetryHandoffClosureWorkerV1 = {
	workerId: string;
	role: string;
	packetId: string;
	status: RepiWorkerRuntimePoolWorkerV1["status"];
	attempt: number;
	maxAttempts: number;
	retryRemaining: number;
	retryState:
		| "passed"
		| "not_needed"
		| "retry_queued"
		| "handoff_recovered"
		| "exhausted_escalated"
		| "blocked_without_closure";
	timeoutMs: number;
	timedOut: boolean;
	cancelledAt?: string;
	retryQueueRefs: string[];
	handoffRefs: string[];
	repairRefs: string[];
	claimRefs: string[];
	sourceArtifacts: string[];
	mergeKeys: string[];
	assertions: {
		attemptBounded: boolean;
		retryBudgetConsistent: boolean;
		timeoutCancellationRecorded: boolean;
		failureHasRetryOrHandoff: boolean;
		exhaustionEscalated: boolean;
		handoffBoundToClaim: boolean;
		sourceArtifactsPreserved: boolean;
	};
};

export type RepiWorkerRetryHandoffClosureV1 = {
	kind: "WorkerRetryHandoffClosureV1";
	schemaVersion: 1;
	closureId: string;
	poolId: string;
	generatedAt: string;
	strategy: "retry-budgeted claim-bound handoff closure";
	workers: RepiWorkerRetryHandoffClosureWorkerV1[];
	merge: {
		strategy: "claim-bound handoff merge";
		recoveredWorkers: string[];
		unresolvedWorkers: string[];
		collisions: {
			mergeKey: string;
			workers: string[];
			status: "resolved" | "unresolved";
			winner?: string;
			evidenceRefs: string[];
			resolutionReason?: string;
		}[];
	};
	assertions: {
		retryAttemptsBounded: boolean;
		retryBudgetsConsistent: boolean;
		timeoutCancellationRecorded: boolean;
		failedWorkersHaveRetryOrHandoff: boolean;
		exhaustedWorkersEscalated: boolean;
		handoffRefsBoundToClaims: boolean;
		mergeCollisionsResolved: boolean;
		claimRefsPreserved: boolean;
		sourceArtifactsPreserved: boolean;
	};
	errors: string[];
};

export type RepiWorkerRetryHandoffMergeSummaryV1 = {
	kind: "WorkerRetryHandoffMergeSummaryV1";
	schemaVersion: 1;
	closureId: string;
	poolId: string;
	status: "pass" | "blocked";
	workerClosures: RepiWorkerRetryHandoffClosureRowV1[];
	retryQueuedWorkers: string[];
	handoffRecoveredWorkers: string[];
	exhaustedEscalatedWorkers: string[];
	unresolvedWorkers: string[];
	resolvedCollisions: string[];
	unresolvedCollisions: string[];
	nextActions: string[];
	claimRefs: string[];
	sourceArtifacts: string[];
	assertions: {
		noUnresolvedWorkers: boolean;
		collisionsResolved: boolean;
		allFailuresClosed: boolean;
		handoffEvidenceBound: boolean;
		retryBudgetVisible: boolean;
		sourceArtifactsPreserved: boolean;
	};
};

export type RepiWorkerRetryHandoffClosureRowV1 = {
	workerId: string;
	status: RepiWorkerRuntimePoolWorkerV1["status"];
	retryState: RepiWorkerRetryHandoffClosureWorkerV1["retryState"];
	attempt: number;
	maxAttempts: number;
	retryRemaining: number;
	timedOut: boolean;
	cancelledAt?: string;
	closure: "passed" | "retry_queued" | "handoff_recovered" | "exhausted_escalated" | "unresolved";
	retryQueueRefs: string[];
	handoffRefs: string[];
	repairRefs: string[];
	claimRefs: string[];
	mergeKeys: string[];
	evidenceRefs: string[];
	nextAction: string;
	summary: string;
};

export type RepiWorkerLeaseSchedulerTaskV1 = {
	taskId: string;
	shardKey: string;
	status: "queued" | "leased" | "running" | "completed" | "requeued" | "stale_recovered" | "failed";
	leaseId?: string;
	ownerWorkerId?: string;
	leaseExpiresAt?: string;
	attempt: number;
	maxAttempts: number;
	claimRefs: string[];
	artifactRefs: string[];
};

export type RepiWorkerLeaseSchedulerEventV1 = {
	kind: "WorkerLeaseSchedulerEventV1";
	schemaVersion: 1;
	eventId: string;
	ts: string;
	type:
		| "enqueue"
		| "lease_acquired"
		| "heartbeat"
		| "stale_detected"
		| "lease_released"
		| "work_stolen"
		| "completed"
		| "dedup_rejected"
		| "failed";
	taskId: string;
	workerId?: string;
	leaseId?: string;
	prevHash: string;
	eventHash: string;
};

export type RepiWorkerLeaseSchedulerV1 = {
	kind: "WorkerLeaseSchedulerV1";
	schemaVersion: 1;
	generatedAt: string;
	schedulerId: string;
	maxConcurrency: number;
	workerIds: string[];
	tasks: RepiWorkerLeaseSchedulerTaskV1[];
	events: RepiWorkerLeaseSchedulerEventV1[];
	assertions: {
		leaseExclusive: boolean;
		heartbeatRequired: boolean;
		staleLeaseRecovered: boolean;
		workStealingObserved: boolean;
		duplicateCompletionRejected: boolean;
		maxConcurrencyRespected: boolean;
		claimRefsPreserved: boolean;
		appendOnlyHashChain: boolean;
	};
};

export type RepiWorkerChildSessionProviderFormat = "openai-compatible" | "anthropic-compatible" | "local-openai";

export type RepiWorkerChildSessionRuntimeStatus =
	| "queued"
	| "running"
	| "passed"
	| "failed"
	| "timeout"
	| "cancelled"
	| "exhausted";

export type RepiWorkerChildSessionLaunchPolicyV1 = {
	command: "repi";
	args: string[];
	cwd: string;
	isolatedHome: string;
	profileDir: string;
	timeoutMs: number;
	cancelSignal: "SIGTERM";
	killAfterMs: number;
	importPiAuth: false;
	updateChecksDisabled: true;
	telemetryDisabled: true;
	envAllowlist: string[];
	envDenylist: string[];
};

export type RepiWorkerChildSessionRuntimeV1 = {
	sessionId: string;
	workerId: string;
	packetId: string;
	attempt: number;
	maxAttempts: number;
	provider: {
		format: RepiWorkerChildSessionProviderFormat;
		name: string;
		modelId: string;
		baseUrlRef: string;
		apiKeyRef: string;
		contextWindow: number;
		maxTokens: number;
	};
	runtime: {
		status: RepiWorkerChildSessionRuntimeStatus;
		pid?: number | null;
		sessionDir: string;
		transcriptPath: string;
		stdoutPath: string;
		stderrPath: string;
		startedAt: string;
		endedAt: string;
		exitCode?: number | null;
		signal?: string | null;
		cancelledAt?: string;
	};
	hashes: {
		transcriptSha256: string;
		stdoutSha256: string;
		stderrSha256: string;
		toolCallDigest: string;
	};
	resourceLease: RepiWorkerRuntimePoolWorkerV1["resourceLease"];
	retryBudget: RepiSwarmRuntimeRetryBudget;
	poolBridge: {
		poolId: string;
		mergeKey: string;
		claimRefs: string[];
		workerRuntimePoolStatus: RepiWorkerRuntimePoolWorkerV1["status"];
	};
	failureRepairRefs: string[];
};

export type RepiWorkerChildSessionClaimLedgerEventV1 = Omit<RepiSwarmClaimLedgerEventV1, "source"> & {
	source: "re_swarm" | "worker-child-session";
};

export type RepiWorkerChildProcessProbeV1 = {
	kind: "WorkerChildProcessProbeV1";
	schemaVersion: 1;
	probeId: string;
	command: string;
	args: string[];
	cwd: string;
	isolatedHome: string;
	startedAt: string;
	endedAt: string;
	elapsedMs: number;
	exitCode: number | null;
	signal: string | null;
	status: "pass" | "blocked";
	stdoutPath: string;
	stderrPath: string;
	stdoutSha256: string;
	stderrSha256: string;
	envAllowlist: string[];
	envDenylist: string[];
	assertions: {
		repiCommandExecuted: boolean;
		isolatedRepiHome: boolean;
		noPiHomeImport: boolean;
		updateChecksDisabled: boolean;
		telemetryDisabled: boolean;
		noLiteralSecrets: boolean;
		stdoutCaptured: boolean;
	};
	errors: string[];
};

export type RepiWorkerChildSessionRuntimeBatchV1 = {
	kind: "WorkerChildSessionRuntimeBatchV1";
	schemaVersion: 1;
	batchId: string;
	poolId: string;
	resourceBudget: RepiWorkerRuntimePoolV1["resourceBudget"];
	launchPolicy: RepiWorkerChildSessionLaunchPolicyV1;
	sessions: RepiWorkerChildSessionRuntimeV1[];
	claimLedgerEvents: RepiWorkerChildSessionClaimLedgerEventV1[];
	childProcessProbe?: RepiWorkerChildProcessProbeV1;
	providerChildProcessProbe?: RepiWorkerProviderChildProcessProbeV1;
	poolBridge: {
		kind: "WorkerRuntimePoolV1Bridge";
		poolId: string;
		workerIds: string[];
		claimAwareMerge: boolean;
		childSessionRuntimeCaptured: boolean;
		childProcessRuntimeCaptured?: boolean;
		providerChildProcessRuntimeCaptured?: boolean;
	};
};

function stableJson(value: unknown): string {
	return JSON.stringify(value, (_key, item) => {
		if (!item || typeof item !== "object" || Array.isArray(item)) return item;
		return Object.keys(item as Record<string, unknown>)
			.sort()
			.reduce<Record<string, unknown>>((out, key) => {
				out[key] = (item as Record<string, unknown>)[key];
				return out;
			}, {});
	});
}

function sameStringSet(left: readonly string[], right: readonly string[]): boolean {
	const leftSet = new Set(left);
	const rightSet = new Set(right);
	if (leftSet.size !== rightSet.size) return false;
	for (const item of leftSet) {
		if (!rightSet.has(item)) return false;
	}
	return true;
}

function envRefName(ref: string): string | undefined {
	const match = /^\$([A-Z_][A-Z0-9_]*)$/.exec(ref.trim());
	return match?.[1];
}

// WorkerRuntimePoolV1 split contract: runtime:worker-runtime-pool-validation runtime:claim-aware-worker-merge runtime:child-session-runtime-bridge.
export function workerRuntimePoolEvidenceContract(): string[] {
	return [
		"worker stdout/stderr sha256 must match captured artifacts",
		"timeout/cancel must be explicit when elapsedMs exceeds the cumulative per-attempt timeout budget",
		"retryBudget signature/attempt/remaining/exhausted must be consistent",
		"failed or timed-out workers must close through retry queue, handoff recovery, or exhausted escalation",
		"handoff artifacts must be claim-bound before supervisor merge",
		"resourceLease must fit the pool resourceBudget and group maxConcurrency",
		"claim-aware merge must resolve duplicate mergeKey conflicts before supervisor promotion",
		"resolved merge conflicts must name the real colliding workers, a winning worker, evidence refs, and a resolution reason",
		"each promoted worker claim must have artifact_handoff → claim → validation → challenge → resolution",
	];
}

export function claimAwareWorkerMergeProtocol(pool: RepiWorkerRuntimePoolV1): string[] {
	const resolved = new Set(
		pool.mergeProtocol.conflicts.filter((row) => row.status === "resolved").map((row) => row.mergeKey),
	);
	const collisions = new Map<string, string[]>();
	for (const worker of pool.workers) {
		for (const key of Array.isArray(worker.mergeKey) ? worker.mergeKey : [worker.mergeKey]) {
			const rows = collisions.get(key) ?? [];
			rows.push(worker.workerId);
			collisions.set(key, rows);
		}
	}
	return Array.from(collisions.entries()).flatMap(([mergeKey, workers]) => {
		if (workers.length <= 1) return [];
		if (resolved.has(mergeKey)) return [`mergeKey=${mergeKey} resolved workers=${workers.join(",")}`];
		return [`mergeKey=${mergeKey} unresolved workers=${workers.join(",")} -> supervisor block`];
	});
}

export function verifyWorkerRuntimePool(pool: RepiWorkerRuntimePoolV1): {
	ok: boolean;
	errors: string[];
	evidenceContract: string[];
} {
	const errors: string[] = [];
	const maxConcurrency = Math.max(1, Math.floor(pool.maxConcurrency));
	const runtimeIntervals: Array<{
		workerId: string;
		start: number;
		end: number;
		resourceLease: RepiWorkerRuntimePoolWorkerV1["resourceLease"];
	}> = [];
	const activePoints = pool.workers.flatMap((worker) => {
		const start = worker.startedAt ? Date.parse(worker.startedAt) : Number.NaN;
		const end = worker.endedAt ? Date.parse(worker.endedAt) : Number.NaN;
		if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return [];
		runtimeIntervals.push({
			workerId: worker.workerId,
			start,
			end,
			resourceLease: worker.resourceLease,
		});
		const cumulativeTimeoutMs = worker.timeoutMs * Math.max(1, worker.attempt);
		if (end - start > cumulativeTimeoutMs && worker.status !== "timeout" && worker.status !== "cancelled")
			errors.push(`timeout_not_marked:${worker.workerId}`);
		if (worker.status === "timeout" && pool.cancelOnTimeout && !worker.cancelledAt)
			errors.push(`timeout_without_cancel:${worker.workerId}`);
		if (worker.attempt > worker.maxAttempts) errors.push(`attempt_exceeds_maxAttempts:${worker.workerId}`);
		if (worker.retryBudget.remaining !== Math.max(0, worker.maxAttempts - worker.attempt))
			errors.push(`retryBudget_remaining_inconsistent:${worker.workerId}`);
		if (worker.retryBudget.exhausted !== worker.attempt >= worker.maxAttempts)
			errors.push(`retryBudget_exhausted_inconsistent:${worker.workerId}`);
		if (worker.status === "retry_queued" && worker.retryBudget.exhausted)
			errors.push(`exhausted_still_retrying:${worker.workerId}`);
		if (worker.resourceLease.cpuSlots > pool.resourceBudget.cpuSlots)
			errors.push(`resource_cpu_exceeds_budget:${worker.workerId}`);
		if (worker.resourceLease.memoryMb > pool.resourceBudget.memoryMb)
			errors.push(`resource_memory_exceeds_budget:${worker.workerId}`);
		if (worker.resourceLease.maxProcesses > pool.resourceBudget.maxProcesses)
			errors.push(`resource_process_exceeds_budget:${worker.workerId}`);
		return [
			{ t: start, delta: 1 },
			{ t: end, delta: -1 },
		];
	});
	let active = 0;
	for (const point of activePoints.sort((left, right) => left.t - right.t || left.delta - right.delta)) {
		active += point.delta;
		if (active > maxConcurrency) errors.push(`maxConcurrency_exceeded:${active}>${maxConcurrency}`);
	}
	for (const t of Array.from(new Set(runtimeIntervals.map((interval) => interval.start))).sort((a, b) => a - b)) {
		const activeAtTime = runtimeIntervals.filter((interval) => interval.start <= t && t < interval.end);
		const cpuSlots = activeAtTime.reduce((sum, interval) => sum + interval.resourceLease.cpuSlots, 0);
		const memoryMb = activeAtTime.reduce((sum, interval) => sum + interval.resourceLease.memoryMb, 0);
		const maxProcesses = activeAtTime.reduce((sum, interval) => sum + interval.resourceLease.maxProcesses, 0);
		if (cpuSlots > pool.resourceBudget.cpuSlots)
			errors.push(`resource_cpu_active_exceeds_budget:${cpuSlots}>${pool.resourceBudget.cpuSlots}`);
		if (memoryMb > pool.resourceBudget.memoryMb)
			errors.push(`resource_memory_active_exceeds_budget:${memoryMb}>${pool.resourceBudget.memoryMb}`);
		if (maxProcesses > pool.resourceBudget.maxProcesses)
			errors.push(`resource_process_active_exceeds_budget:${maxProcesses}>${pool.resourceBudget.maxProcesses}`);
	}
	for (const group of pool.parallelGroups) {
		const groupWorkerIds = new Set(group.workers);
		const groupIntervals = runtimeIntervals.filter((interval) => groupWorkerIds.has(interval.workerId));
		const groupLimit = Math.max(1, Math.floor(group.maxConcurrency));
		for (const t of Array.from(new Set(groupIntervals.map((interval) => interval.start))).sort((a, b) => a - b)) {
			const groupActive = groupIntervals.filter((interval) => interval.start <= t && t < interval.end).length;
			if (groupActive > groupLimit)
				errors.push(`parallelGroup_maxConcurrency_exceeded:${group.groupId}:${groupActive}>${groupLimit}`);
		}
	}
	if (claimAwareWorkerMergeProtocol(pool).some((row) => row.includes("unresolved")))
		errors.push("duplicate_mergeKey_unresolved");
	const mergeKeyWorkers = new Map<string, string[]>();
	for (const worker of pool.workers) {
		for (const key of Array.isArray(worker.mergeKey) ? worker.mergeKey : [worker.mergeKey]) {
			const rows = mergeKeyWorkers.get(key) ?? [];
			rows.push(worker.workerId);
			mergeKeyWorkers.set(key, rows);
		}
	}
	for (const [mergeKey, workers] of mergeKeyWorkers) {
		if (workers.length <= 1) continue;
		const conflicts = pool.mergeProtocol.conflicts.filter((conflict) => conflict.mergeKey === mergeKey);
		const resolvedConflicts = conflicts.filter((conflict) => conflict.status === "resolved");
		if (resolvedConflicts.length > 1) errors.push(`merge_conflict_multiple_resolutions:${mergeKey}`);
		for (const conflict of resolvedConflicts) {
			if (!sameStringSet(conflict.workers, workers)) errors.push(`merge_conflict_workers_mismatch:${mergeKey}`);
			if (!conflict.winner || !workers.includes(conflict.winner))
				errors.push(`merge_conflict_winner_invalid:${mergeKey}`);
			if (!conflict.evidenceRefs.length) errors.push(`merge_conflict_evidence_missing:${mergeKey}`);
			if (!conflict.resolutionReason?.trim()) errors.push(`merge_conflict_resolution_reason_missing:${mergeKey}`);
		}
	}
	for (const conflict of pool.mergeProtocol.conflicts) {
		const collidingWorkers = mergeKeyWorkers.get(conflict.mergeKey) ?? [];
		if (collidingWorkers.length < 2) errors.push(`merge_conflict_without_collision:${conflict.mergeKey}`);
	}
	const eventTypes = new Map<string, Set<string>>();
	for (const event of pool.claimLedgerEvents) {
		const id = event.claimId ?? event.claimIds?.[0];
		if (!id) continue;
		const types = eventTypes.get(id) ?? new Set<string>();
		types.add(event.type);
		eventTypes.set(id, types);
	}
	for (const claimId of pool.workers.flatMap((worker) => worker.claimRefs)) {
		const types = eventTypes.get(claimId);
		for (const required of ["artifact_handoff", "claim", "validation", "challenge", "resolution"]) {
			if (!types?.has(required)) errors.push(`claim_without_${required}:${claimId}`);
		}
	}
	return {
		ok: errors.length === 0,
		errors: uniqueNonEmpty(errors, 80),
		evidenceContract: workerRuntimePoolEvidenceContract(),
	};
}

export function workerLeaseSchedulerEventHash(event: Omit<RepiWorkerLeaseSchedulerEventV1, "eventHash">): string {
	return createHash("sha256").update(stableJson(event)).digest("hex");
}

export function verifyWorkerLeaseSchedulerV1(scheduler: RepiWorkerLeaseSchedulerV1): { ok: boolean; errors: string[] } {
	const errors: string[] = [];
	if (scheduler.kind !== "WorkerLeaseSchedulerV1") errors.push("worker_lease_scheduler_kind_invalid");
	if (scheduler.maxConcurrency < 1) errors.push("worker_lease_scheduler_max_concurrency_invalid");
	const activeLeases = new Map<string, string>();
	for (const task of scheduler.tasks) {
		if (task.status === "leased" || task.status === "running") {
			const existing = activeLeases.get(task.taskId);
			if (existing && existing !== task.leaseId)
				errors.push(`worker_lease_scheduler_duplicate_active_lease:${task.taskId}`);
			if (task.leaseId) activeLeases.set(task.taskId, task.leaseId);
		}
		if (task.attempt > task.maxAttempts) errors.push(`worker_lease_scheduler_attempt_exceeded:${task.taskId}`);
		if (!task.claimRefs.length) errors.push(`worker_lease_scheduler_claim_refs_missing:${task.taskId}`);
	}
	let prevHash = "0".repeat(64);
	const completed = new Set<string>();
	for (const event of scheduler.events) {
		if (event.kind !== "WorkerLeaseSchedulerEventV1")
			errors.push(`worker_lease_scheduler_event_kind_invalid:${event.eventId}`);
		if (event.prevHash !== prevHash) errors.push(`worker_lease_scheduler_prev_hash_mismatch:${event.eventId}`);
		const { eventHash: _eventHash, ...withoutHash } = event;
		if (event.eventHash !== workerLeaseSchedulerEventHash(withoutHash))
			errors.push(`worker_lease_scheduler_event_hash_mismatch:${event.eventId}`);
		prevHash = event.eventHash;
		if (event.type === "completed") {
			if (completed.has(event.taskId)) errors.push(`worker_lease_scheduler_duplicate_completion:${event.taskId}`);
			completed.add(event.taskId);
		}
	}
	if (!scheduler.assertions.leaseExclusive) errors.push("worker_lease_scheduler_lease_exclusive_missing");
	if (!scheduler.assertions.heartbeatRequired) errors.push("worker_lease_scheduler_heartbeat_missing");
	if (!scheduler.assertions.staleLeaseRecovered) errors.push("worker_lease_scheduler_stale_recovery_missing");
	if (!scheduler.assertions.workStealingObserved) errors.push("worker_lease_scheduler_work_steal_missing");
	if (!scheduler.assertions.duplicateCompletionRejected)
		errors.push("worker_lease_scheduler_duplicate_completion_rejection_missing");
	if (!scheduler.assertions.maxConcurrencyRespected)
		errors.push("worker_lease_scheduler_max_concurrency_not_respected");
	if (!scheduler.assertions.claimRefsPreserved) errors.push("worker_lease_scheduler_claim_refs_not_preserved");
	if (!scheduler.assertions.appendOnlyHashChain) errors.push("worker_lease_scheduler_hash_chain_not_append_only");
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 100) };
}

export function workerChildSessionLaunchPolicy(options?: {
	cwd?: string;
	isolatedHome?: string;
	timeoutMs?: number;
}): RepiWorkerChildSessionLaunchPolicyV1 {
	const isolatedHome =
		options?.isolatedHome ?? join(process.cwd(), ".repi", "runtime", "child-session-home", ".repi", "agent");
	return {
		command: "repi",
		args: ["--recon", "--offline", "--project-context", "--worker-runtime"],
		cwd: options?.cwd ?? process.cwd(),
		isolatedHome,
		profileDir: isolatedHome,
		timeoutMs: Math.max(1000, Math.min(30 * 60 * 1000, Math.floor(options?.timeoutMs ?? 30000))),
		cancelSignal: "SIGTERM",
		killAfterMs: 3000,
		importPiAuth: false,
		updateChecksDisabled: true,
		telemetryDisabled: true,
		envAllowlist: [
			"HOME",
			"PATH",
			"REPI_PRODUCT",
			"REPI_OFFLINE",
			"REPI_SKIP_VERSION_CHECK",
			"REPI_SKIP_PACKAGE_UPDATE_CHECK",
			"REPI_TELEMETRY",
			...REPI_MODEL_ENV_VARIABLES,
			"REPI_SUBAGENT_PROVIDER",
			"OPENAI_COMPAT_BASE_URL",
			"OPENAI_COMPAT_API_KEY",
			"ANTHROPIC_COMPAT_BASE_URL",
			"ANTHROPIC_COMPAT_API_KEY",
			"LOCAL_OPENAI_BASE_URL",
			"LOCAL_OPENAI_API_KEY",
		],
		envDenylist: ["GITHUB_TOKEN", "GITHUB_TOKEN_FOR_PUSH", "ANTHROPIC_AUTH_TOKEN", "NPM_TOKEN"],
	};
}

export function workerChildSessionToWorkerRuntimePoolBridge(
	batch: RepiWorkerChildSessionRuntimeBatchV1,
): RepiWorkerRuntimePoolV1 {
	const mergeKeyWorkers = new Map<string, string[]>();
	for (const session of batch.sessions) {
		const rows = mergeKeyWorkers.get(session.poolBridge.mergeKey) ?? [];
		rows.push(session.workerId);
		mergeKeyWorkers.set(session.poolBridge.mergeKey, rows);
	}
	const conflicts: RepiWorkerRuntimePoolV1["mergeProtocol"]["conflicts"] = Array.from(mergeKeyWorkers.entries())
		.filter(([, workers]) => workers.length > 1)
		.map(([mergeKey, workers]) => ({
			mergeKey,
			workers,
			status: "resolved" as const,
			winner: workers[0],
			evidenceRefs: uniqueNonEmpty(
				batch.claimLedgerEvents
					.filter((event) => event.claimId === mergeKey || event.claimIds?.includes(mergeKey))
					.flatMap((event) => event.evidenceRefs),
				16,
			),
			resolutionReason:
				"duplicate child-session merge key resolved by claim ledger validation and supervisor re-check before promotion",
		}));
	return {
		kind: "WorkerRuntimePoolV1",
		schemaVersion: 1,
		poolId: batch.poolId,
		maxConcurrency: Math.max(1, Math.min(8, batch.sessions.length || 1)),
		timeoutMs: batch.launchPolicy.timeoutMs,
		cancelOnTimeout: true,
		resourceBudget: batch.resourceBudget,
		workers: batch.sessions.map((session) => ({
			workerId: session.workerId,
			role: session.provider.format,
			route: session.provider.name,
			packetId: session.packetId,
			attempt: session.attempt,
			maxAttempts: session.maxAttempts,
			retryBudget: session.retryBudget,
			resourceLease: session.resourceLease,
			timeoutMs: batch.launchPolicy.timeoutMs,
			status: session.poolBridge.workerRuntimePoolStatus,
			startedAt: session.runtime.startedAt,
			endedAt: session.runtime.endedAt,
			cancelledAt: session.runtime.cancelledAt,
			sessionDir: session.runtime.sessionDir,
			stdoutPath: session.runtime.stdoutPath,
			stderrPath: session.runtime.stderrPath,
			stdoutSha256: session.hashes.stdoutSha256,
			stderrSha256: session.hashes.stderrSha256,
			toolCallDigest: session.hashes.toolCallDigest,
			mergeKey: session.poolBridge.mergeKey,
			claimRefs: session.poolBridge.claimRefs,
		})),
		parallelGroups: [
			{
				groupId: `${batch.batchId}:child-sessions`,
				workers: batch.sessions.map((session) => session.workerId),
				dependsOn: [],
				maxConcurrency: Math.max(1, Math.min(8, batch.sessions.length || 1)),
			},
		],
		mergeProtocol: {
			strategy: "claim-aware merge",
			evidenceContract: workerRuntimePoolEvidenceContract(),
			conflicts,
		},
		claimLedgerEvents: batch.claimLedgerEvents.filter(
			(event) => event.source === "re_swarm",
		) as RepiSwarmClaimLedgerEventV1[],
	};
}

export function workerChildSessionRuntimeBridgeEvidenceContract(): string[] {
	return [
		"runtime:child-session-pool-bridge-validation",
		"WorkerChildSessionRuntimeBatchV1 must capture childSessionRuntimeCaptured=true before supervisor promotion",
		"poolBridge.workerIds must exactly match child session worker ids",
		"child-session runtime status must be compatible with WorkerRuntimePoolV1 status",
		"child-session claim ledger must bridge into WorkerRuntimePoolV1 claim-aware merge validation",
		"child-session launch policy must keep REPI isolated, update checks disabled, telemetry disabled, and secrets denied",
	];
}

export function workerRetryHandoffClosureEvidenceContract(): string[] {
	return [
		"WorkerRetryHandoffClosureV1",
		"runtime:retry-handoff-closure-validation",
		"retry attempts must not exceed maxAttempts",
		"timeout/cancel closure must record cancelledAt",
		"failed workers must have retryQueueRefs, repairRefs, or handoffRefs",
		"exhausted workers must escalate with repairRefs and no hidden retry",
		"handoffRefs must bind to claimRefs before merge",
		"retry/handoff/repair refs must be preserved in sourceArtifacts",
		"merge collisions must be resolved or block promotion",
		"resolved merge collisions must name real workers, a valid winner, bound evidence refs, and a resolution reason",
	];
}

export function verifyWorkerRetryHandoffClosureV1(report: RepiWorkerRetryHandoffClosureV1): {
	ok: boolean;
	errors: string[];
	evidenceContract: string[];
} {
	const errors: string[] = [];
	if (report.kind !== "WorkerRetryHandoffClosureV1") errors.push("retry_handoff_closure_kind_invalid");
	if (report.schemaVersion !== 1) errors.push("retry_handoff_closure_schema_version_invalid");
	if (!report.poolId) errors.push("retry_handoff_closure_pool_missing");
	if (!report.workers.length) errors.push("retry_handoff_closure_workers_missing");
	const workerById = new Map(report.workers.map((worker) => [worker.workerId, worker]));
	const expectedRecovered = new Set<string>();
	const expectedUnresolved = new Set<string>();
	for (const worker of report.workers) {
		const closedByRetry = worker.retryQueueRefs.length > 0;
		const closedByHandoff = worker.handoffRefs.length > 0;
		const closedByRepair = worker.repairRefs.length > 0;
		const isPassing = worker.status === "done" || worker.status === "passed";
		const isFailure = ["failed", "timeout", "cancelled", "retry_queued", "exhausted", "blocked"].includes(
			worker.status,
		);
		if (worker.attempt > worker.maxAttempts) errors.push(`retry_handoff_attempt_exceeded:${worker.workerId}`);
		if (worker.retryRemaining !== Math.max(0, worker.maxAttempts - worker.attempt))
			errors.push(`retry_handoff_remaining_inconsistent:${worker.workerId}`);
		if (worker.timedOut && !worker.cancelledAt)
			errors.push(`retry_handoff_timeout_without_cancel:${worker.workerId}`);
		if (worker.status === "timeout" && !worker.cancelledAt)
			errors.push(`retry_handoff_timeout_status_without_cancel:${worker.workerId}`);
		if (isFailure && !closedByRetry && !closedByHandoff && !closedByRepair)
			errors.push(`retry_handoff_failed_without_closure:${worker.workerId}`);
		if (worker.status === "retry_queued" && worker.retryRemaining < 1)
			errors.push(`retry_handoff_retry_queued_without_budget:${worker.workerId}`);
		if (worker.status === "exhausted" && (worker.retryRemaining !== 0 || !closedByRepair))
			errors.push(`retry_handoff_exhausted_without_escalation:${worker.workerId}`);
		if (!isPassing && closedByHandoff && !worker.claimRefs.length)
			errors.push(`retry_handoff_handoff_without_claim:${worker.workerId}`);
		if (closedByHandoff && !worker.mergeKeys.some((key) => worker.claimRefs.includes(key)))
			errors.push(`retry_handoff_handoff_mergeKey_not_claim_bound:${worker.workerId}`);
		if (!worker.sourceArtifacts.length) errors.push(`retry_handoff_source_artifacts_missing:${worker.workerId}`);
		const sourceArtifactSet = new Set(worker.sourceArtifacts);
		for (const ref of [...worker.retryQueueRefs, ...worker.handoffRefs, ...worker.repairRefs]) {
			if (!sourceArtifactSet.has(ref)) errors.push(`retry_handoff_ref_not_preserved:${worker.workerId}:${ref}`);
		}
		if (!worker.assertions.attemptBounded)
			errors.push(`retry_handoff_assertion_attempt_unbounded:${worker.workerId}`);
		if (!worker.assertions.retryBudgetConsistent)
			errors.push(`retry_handoff_assertion_retry_budget_inconsistent:${worker.workerId}`);
		if (!worker.assertions.timeoutCancellationRecorded)
			errors.push(`retry_handoff_assertion_timeout_cancel_missing:${worker.workerId}`);
		if (!worker.assertions.failureHasRetryOrHandoff)
			errors.push(`retry_handoff_assertion_failure_unclosed:${worker.workerId}`);
		if (!worker.assertions.exhaustionEscalated)
			errors.push(`retry_handoff_assertion_exhaustion_not_escalated:${worker.workerId}`);
		if (!worker.assertions.handoffBoundToClaim)
			errors.push(`retry_handoff_assertion_handoff_unbound:${worker.workerId}`);
		if (!worker.assertions.sourceArtifactsPreserved)
			errors.push(`retry_handoff_assertion_artifacts_missing:${worker.workerId}`);
		if (worker.retryState === "blocked_without_closure")
			errors.push(`retry_handoff_worker_unclosed:${worker.workerId}`);
		if (worker.retryState === "retry_queued" || worker.retryState === "handoff_recovered")
			expectedRecovered.add(worker.workerId);
		if (worker.retryState === "blocked_without_closure") expectedUnresolved.add(worker.workerId);
	}
	for (const workerId of report.merge.recoveredWorkers) {
		if (!workerById.has(workerId)) errors.push(`retry_handoff_recovered_worker_unknown:${workerId}`);
		if (!expectedRecovered.has(workerId)) errors.push(`retry_handoff_recovered_worker_invalid:${workerId}`);
	}
	for (const workerId of expectedRecovered) {
		if (!report.merge.recoveredWorkers.includes(workerId))
			errors.push(`retry_handoff_recovered_worker_missing:${workerId}`);
	}
	for (const workerId of report.merge.unresolvedWorkers) {
		if (!workerById.has(workerId)) errors.push(`retry_handoff_unresolved_worker_unknown:${workerId}`);
		if (!expectedUnresolved.has(workerId)) errors.push(`retry_handoff_unresolved_worker_invalid:${workerId}`);
	}
	for (const workerId of expectedUnresolved) {
		if (!report.merge.unresolvedWorkers.includes(workerId))
			errors.push(`retry_handoff_unresolved_worker_missing:${workerId}`);
	}
	for (const conflict of report.merge.collisions) {
		if (conflict.status !== "resolved") errors.push(`retry_handoff_merge_collision_unresolved:${conflict.mergeKey}`);
		if (conflict.status === "resolved" && (!conflict.winner || !conflict.evidenceRefs.length))
			errors.push(`retry_handoff_merge_resolution_unproven:${conflict.mergeKey}`);
		if (conflict.workers.length < 2) errors.push(`retry_handoff_merge_collision_worker_count:${conflict.mergeKey}`);
		for (const workerId of conflict.workers) {
			if (!workerById.has(workerId))
				errors.push(`retry_handoff_merge_collision_worker_unknown:${conflict.mergeKey}:${workerId}`);
		}
		if (conflict.winner && !conflict.workers.includes(conflict.winner))
			errors.push(`retry_handoff_merge_winner_not_in_collision:${conflict.mergeKey}`);
		const winner = conflict.winner ? workerById.get(conflict.winner) : undefined;
		if (winner && ![...winner.mergeKeys, ...winner.claimRefs].includes(conflict.mergeKey))
			errors.push(`retry_handoff_merge_winner_not_bound_to_key:${conflict.mergeKey}`);
		if (conflict.status === "resolved" && !conflict.resolutionReason?.trim())
			errors.push(`retry_handoff_merge_resolution_reason_missing:${conflict.mergeKey}`);
		const collidingEvidence = new Set<string>();
		for (const workerId of conflict.workers) {
			const worker = workerById.get(workerId);
			if (!worker) continue;
			for (const ref of [
				...worker.sourceArtifacts,
				...worker.retryQueueRefs,
				...worker.handoffRefs,
				...worker.repairRefs,
				...worker.claimRefs,
				...worker.mergeKeys,
			]) {
				collidingEvidence.add(ref);
			}
		}
		if (conflict.evidenceRefs.length && !conflict.evidenceRefs.some((ref) => collidingEvidence.has(ref)))
			errors.push(`retry_handoff_merge_evidence_unbound:${conflict.mergeKey}`);
	}
	if (!report.assertions.retryAttemptsBounded) errors.push("retry_handoff_attempts_not_bounded");
	if (!report.assertions.retryBudgetsConsistent) errors.push("retry_handoff_budgets_inconsistent");
	if (!report.assertions.timeoutCancellationRecorded) errors.push("retry_handoff_timeout_cancel_not_recorded");
	if (!report.assertions.failedWorkersHaveRetryOrHandoff) errors.push("retry_handoff_failures_not_closed");
	if (!report.assertions.exhaustedWorkersEscalated) errors.push("retry_handoff_exhausted_not_escalated");
	if (!report.assertions.handoffRefsBoundToClaims) errors.push("retry_handoff_refs_not_claim_bound");
	if (!report.assertions.mergeCollisionsResolved) errors.push("retry_handoff_merge_collisions_unresolved");
	if (!report.assertions.claimRefsPreserved) errors.push("retry_handoff_claim_refs_missing");
	if (!report.assertions.sourceArtifactsPreserved) errors.push("retry_handoff_source_artifacts_missing");
	if (report.errors.length) errors.push(...report.errors.map((error) => `retry_handoff_report_error:${error}`));
	return {
		ok: errors.length === 0,
		errors: uniqueNonEmpty(errors, 120),
		evidenceContract: workerRetryHandoffClosureEvidenceContract(),
	};
}

export function workerRetryHandoffMergeSummaryEvidenceContract(): string[] {
	return [
		"WorkerRetryHandoffMergeSummaryV1",
		"runtime:retry-handoff-merge-summary-validation",
		"retry queued workers must remain retry-budget visible before supervisor merge",
		"handoff recovered workers must keep handoff refs claim-bound and source-artifact preserved",
		"exhausted workers must surface an explicit re_autofix/re_supervisor escalation next action",
		"every worker must emit a workerClosures row with timeout/cancel, retry budget, handoff refs, repair refs, claim refs, and next action",
		"unresolved workers or unresolved merge collisions must block promotion",
		"pass status requires no unresolved workers, resolved collisions, closed failures, and preserved artifacts",
	];
}

function workerRetryHandoffClosureState(
	worker: RepiWorkerRetryHandoffClosureWorkerV1,
): RepiWorkerRetryHandoffClosureRowV1["closure"] {
	if (worker.retryState === "retry_queued") return "retry_queued";
	if (worker.retryState === "handoff_recovered") return "handoff_recovered";
	if (worker.retryState === "exhausted_escalated") return "exhausted_escalated";
	if (worker.retryState === "blocked_without_closure") return "unresolved";
	return worker.status === "failed" || worker.status === "timeout" || worker.status === "cancelled"
		? "unresolved"
		: "passed";
}

function workerRetryHandoffClosureNextAction(row: {
	workerId: string;
	closure: RepiWorkerRetryHandoffClosureRowV1["closure"];
}): string {
	switch (row.closure) {
		case "retry_queued":
			return `re_swarm retry worker=${row.workerId}`;
		case "handoff_recovered":
			return `re_swarm merge worker=${row.workerId} && re_supervisor review`;
		case "exhausted_escalated":
			return `re_autofix plan worker=${row.workerId} && re_supervisor repair`;
		case "unresolved":
			return `re_supervisor repair worker=${row.workerId}`;
		default:
			return `re_swarm merge worker=${row.workerId}`;
	}
}

export function buildWorkerRetryHandoffClosureRowsV1(
	report: RepiWorkerRetryHandoffClosureV1,
): RepiWorkerRetryHandoffClosureRowV1[] {
	return report.workers.map((worker) => {
		const closure = workerRetryHandoffClosureState(worker);
		const evidenceRefs = uniqueNonEmpty(
			[
				...worker.sourceArtifacts,
				...worker.retryQueueRefs,
				...worker.handoffRefs,
				...worker.repairRefs,
				...worker.claimRefs,
				...worker.mergeKeys,
			],
			80,
		);
		const nextAction = workerRetryHandoffClosureNextAction({ workerId: worker.workerId, closure });
		return {
			workerId: worker.workerId,
			status: worker.status,
			retryState: worker.retryState,
			attempt: worker.attempt,
			maxAttempts: worker.maxAttempts,
			retryRemaining: worker.retryRemaining,
			timedOut: worker.timedOut,
			cancelledAt: worker.cancelledAt,
			closure,
			retryQueueRefs: worker.retryQueueRefs,
			handoffRefs: worker.handoffRefs,
			repairRefs: worker.repairRefs,
			claimRefs: worker.claimRefs,
			mergeKeys: worker.mergeKeys,
			evidenceRefs,
			nextAction,
			summary: [
				`worker=${worker.workerId}`,
				`status=${worker.status}`,
				`retry_state=${worker.retryState}`,
				`attempt=${worker.attempt}/${worker.maxAttempts}`,
				`remaining=${worker.retryRemaining}`,
				`timed_out=${worker.timedOut}`,
				`cancelled=${worker.cancelledAt ?? "none"}`,
				`closure=${closure}`,
				`evidence_refs=${evidenceRefs.length}`,
				`next=${nextAction}`,
			].join(" "),
		};
	});
}

export function buildWorkerRetryHandoffMergeSummaryV1(
	report: RepiWorkerRetryHandoffClosureV1,
): RepiWorkerRetryHandoffMergeSummaryV1 {
	const workerClosures = buildWorkerRetryHandoffClosureRowsV1(report);
	const retryQueuedWorkers = uniqueNonEmpty(
		report.workers.filter((worker) => worker.retryState === "retry_queued").map((worker) => worker.workerId),
		80,
	);
	const handoffRecoveredWorkers = uniqueNonEmpty(
		report.workers.filter((worker) => worker.retryState === "handoff_recovered").map((worker) => worker.workerId),
		80,
	);
	const exhaustedEscalatedWorkers = uniqueNonEmpty(
		report.workers.filter((worker) => worker.retryState === "exhausted_escalated").map((worker) => worker.workerId),
		80,
	);
	const unresolvedWorkers = uniqueNonEmpty(
		[
			...report.merge.unresolvedWorkers,
			...report.workers
				.filter((worker) => worker.retryState === "blocked_without_closure")
				.map((worker) => worker.workerId),
		],
		80,
	);
	const resolvedCollisions = uniqueNonEmpty(
		report.merge.collisions
			.filter((collision) => collision.status === "resolved")
			.map((collision) => collision.mergeKey),
		80,
	);
	const unresolvedCollisions = uniqueNonEmpty(
		report.merge.collisions
			.filter((collision) => collision.status !== "resolved")
			.map((collision) => collision.mergeKey),
		80,
	);
	const claimRefs = uniqueNonEmpty(
		report.workers.flatMap((worker) => worker.claimRefs),
		120,
	);
	const sourceArtifacts = uniqueNonEmpty(
		workerClosures.flatMap((worker) => worker.evidenceRefs),
		160,
	);
	const allWorkerRefsPreserved = report.workers.every((worker) => {
		const artifacts = new Set(worker.sourceArtifacts);
		return [...worker.retryQueueRefs, ...worker.handoffRefs, ...worker.repairRefs].every((ref) => artifacts.has(ref));
	});
	const handoffEvidenceBound =
		report.assertions.handoffRefsBoundToClaims &&
		report.workers.every((worker) => {
			if (!worker.handoffRefs.length) return true;
			return worker.claimRefs.length > 0 && worker.mergeKeys.some((key) => worker.claimRefs.includes(key));
		});
	const retryBudgetVisible =
		report.assertions.retryBudgetsConsistent &&
		report.workers.every(
			(worker) =>
				Number.isFinite(worker.attempt) &&
				Number.isFinite(worker.maxAttempts) &&
				Number.isFinite(worker.retryRemaining) &&
				worker.attempt <= worker.maxAttempts &&
				worker.retryRemaining === Math.max(0, worker.maxAttempts - worker.attempt),
		);
	const assertions = {
		noUnresolvedWorkers: unresolvedWorkers.length === 0,
		collisionsResolved: unresolvedCollisions.length === 0 && report.assertions.mergeCollisionsResolved,
		allFailuresClosed:
			report.errors.length === 0 &&
			report.assertions.failedWorkersHaveRetryOrHandoff &&
			report.workers.every((worker) => worker.retryState !== "blocked_without_closure"),
		handoffEvidenceBound,
		retryBudgetVisible,
		sourceArtifactsPreserved:
			report.assertions.sourceArtifactsPreserved &&
			sourceArtifacts.length > 0 &&
			report.workers.every((worker) => worker.sourceArtifacts.length > 0) &&
			allWorkerRefsPreserved,
	};
	const nextActions = uniqueNonEmpty(
		[
			...workerClosures.filter((worker) => worker.closure !== "passed").map((worker) => worker.nextAction),
			...unresolvedWorkers.flatMap((workerId) => [
				`re_supervisor repair worker=${workerId}`,
				`re_swarm retry worker=${workerId}`,
			]),
			...unresolvedCollisions.map((mergeKey) => `re_supervisor repair mergeKey=${mergeKey}`),
			...(report.errors.length ? ["re_supervisor review retry_handoff_errors"] : []),
			...(!assertions.retryBudgetVisible ? ["re_swarm inspect retry-budget"] : []),
			...(!assertions.handoffEvidenceBound ? ["re_evidence bind handoff-refs-to-claims"] : []),
			...(!assertions.sourceArtifactsPreserved ? ["re_evidence collect source-artifacts"] : []),
			...(Object.values(assertions).every(Boolean) ? ["re_swarm merge && re_supervisor review"] : []),
		],
		80,
	);
	return {
		kind: "WorkerRetryHandoffMergeSummaryV1",
		schemaVersion: 1,
		closureId: report.closureId,
		poolId: report.poolId,
		status: Object.values(assertions).every(Boolean) ? "pass" : "blocked",
		workerClosures,
		retryQueuedWorkers,
		handoffRecoveredWorkers,
		exhaustedEscalatedWorkers,
		unresolvedWorkers,
		resolvedCollisions,
		unresolvedCollisions,
		nextActions,
		claimRefs,
		sourceArtifacts,
		assertions,
	};
}

export function verifyWorkerRetryHandoffMergeSummaryV1(summary: RepiWorkerRetryHandoffMergeSummaryV1): {
	ok: boolean;
	errors: string[];
	evidenceContract: string[];
} {
	const errors: string[] = [];
	if (summary.kind !== "WorkerRetryHandoffMergeSummaryV1") errors.push("retry_handoff_merge_summary_kind_invalid");
	if (summary.schemaVersion !== 1) errors.push("retry_handoff_merge_summary_schema_version_invalid");
	if (!summary.closureId) errors.push("retry_handoff_merge_summary_closure_missing");
	if (!summary.poolId) errors.push("retry_handoff_merge_summary_pool_missing");
	if (!summary.nextActions.length) errors.push("retry_handoff_merge_summary_next_actions_missing");
	if (!summary.sourceArtifacts.length) errors.push("retry_handoff_merge_summary_source_artifacts_missing");
	if (!summary.workerClosures?.length) errors.push("retry_handoff_merge_summary_worker_closures_missing");
	const workerClosureIds = new Set<string>();
	const sourceArtifactSet = new Set(summary.sourceArtifacts);
	for (const row of summary.workerClosures ?? []) {
		if (!row.workerId) errors.push("retry_handoff_merge_summary_worker_closure_id_missing");
		if (workerClosureIds.has(row.workerId))
			errors.push(`retry_handoff_merge_summary_worker_closure_duplicate:${row.workerId}`);
		workerClosureIds.add(row.workerId);
		if (row.attempt > row.maxAttempts)
			errors.push(`retry_handoff_merge_summary_worker_closure_attempt_exceeded:${row.workerId}`);
		if (row.retryRemaining !== Math.max(0, row.maxAttempts - row.attempt))
			errors.push(`retry_handoff_merge_summary_worker_closure_budget_inconsistent:${row.workerId}`);
		if (row.timedOut && !row.cancelledAt)
			errors.push(`retry_handoff_merge_summary_timeout_without_cancel:${row.workerId}`);
		if (!row.evidenceRefs.length)
			errors.push(`retry_handoff_merge_summary_worker_closure_evidence_missing:${row.workerId}`);
		for (const ref of [...row.retryQueueRefs, ...row.handoffRefs, ...row.repairRefs]) {
			if (!row.evidenceRefs.includes(ref))
				errors.push(`retry_handoff_merge_summary_worker_closure_ref_unbound:${row.workerId}:${ref}`);
		}
		if (!row.evidenceRefs.every((ref) => sourceArtifactSet.has(ref)))
			errors.push(`retry_handoff_merge_summary_worker_closure_not_in_source_artifacts:${row.workerId}`);
		if (row.closure === "retry_queued" && !/re_swarm retry/.test(row.nextAction))
			errors.push(`retry_handoff_merge_summary_worker_closure_retry_action_missing:${row.workerId}`);
		if (row.closure === "handoff_recovered" && (!row.handoffRefs.length || !/re_swarm merge/.test(row.nextAction)))
			errors.push(`retry_handoff_merge_summary_worker_closure_handoff_action_missing:${row.workerId}`);
		if (
			row.closure === "exhausted_escalated" &&
			(!row.repairRefs.length || !/re_autofix|re_supervisor/.test(row.nextAction))
		)
			errors.push(`retry_handoff_merge_summary_worker_closure_escalation_action_missing:${row.workerId}`);
		if (row.closure === "unresolved" && !/re_supervisor repair/.test(row.nextAction))
			errors.push(`retry_handoff_merge_summary_worker_closure_unresolved_action_missing:${row.workerId}`);
		if (row.closure !== "passed" && !summary.nextActions.includes(row.nextAction))
			errors.push(`retry_handoff_merge_summary_worker_closure_next_action_missing:${row.workerId}`);
		if (!row.summary.includes(`worker=${row.workerId}`) || !row.summary.includes(`closure=${row.closure}`))
			errors.push(`retry_handoff_merge_summary_worker_closure_summary_incomplete:${row.workerId}`);
	}
	if (summary.unresolvedWorkers.length && summary.status === "pass")
		errors.push("retry_handoff_merge_summary_fake_pass_unresolved_workers");
	if (summary.unresolvedCollisions.length && summary.status === "pass")
		errors.push("retry_handoff_merge_summary_fake_pass_unresolved_collisions");
	if (!summary.assertions.noUnresolvedWorkers) errors.push("retry_handoff_merge_summary_unresolved_workers");
	if (!summary.assertions.collisionsResolved) errors.push("retry_handoff_merge_summary_collisions_unresolved");
	if (!summary.assertions.allFailuresClosed) errors.push("retry_handoff_merge_summary_failures_unclosed");
	if (!summary.assertions.handoffEvidenceBound) errors.push("retry_handoff_merge_summary_handoff_unbound");
	if (!summary.assertions.retryBudgetVisible) errors.push("retry_handoff_merge_summary_retry_budget_hidden");
	if (!summary.assertions.sourceArtifactsPreserved)
		errors.push("retry_handoff_merge_summary_source_artifacts_missing");
	if (summary.claimRefs.length && !summary.sourceArtifacts.length)
		errors.push("retry_handoff_merge_summary_claims_without_artifacts");
	for (const workerId of summary.retryQueuedWorkers) {
		if (!summary.nextActions.some((action) => action.includes(workerId) && /re_swarm retry/.test(action))) {
			errors.push(`retry_handoff_merge_summary_retry_action_missing:${workerId}`);
		}
	}
	for (const workerId of summary.exhaustedEscalatedWorkers) {
		if (!summary.nextActions.some((action) => action.includes(workerId) && /re_autofix|re_supervisor/.test(action))) {
			errors.push(`retry_handoff_merge_summary_escalation_action_missing:${workerId}`);
		}
	}
	for (const workerId of summary.unresolvedWorkers) {
		if (
			!summary.nextActions.some(
				(action) => action.includes(workerId) && /re_supervisor repair|re_swarm retry/.test(action),
			)
		) {
			errors.push(`retry_handoff_merge_summary_unresolved_action_missing:${workerId}`);
		}
	}
	for (const mergeKey of summary.unresolvedCollisions) {
		if (!summary.nextActions.some((action) => action.includes(`mergeKey=${mergeKey}`))) {
			errors.push(`retry_handoff_merge_summary_collision_action_missing:${mergeKey}`);
		}
	}
	const allAssertionsPass = Object.values(summary.assertions).every(Boolean);
	const hasBlockers =
		!allAssertionsPass || summary.unresolvedWorkers.length > 0 || summary.unresolvedCollisions.length > 0;
	if (summary.status === "pass" && (summary.workerClosures ?? []).some((row) => row.closure === "unresolved"))
		errors.push("retry_handoff_merge_summary_fake_pass_unresolved_worker_closure");
	if (summary.status === "pass" && hasBlockers) errors.push("retry_handoff_merge_summary_pass_with_blockers");
	if (summary.status === "blocked" && !hasBlockers) errors.push("retry_handoff_merge_summary_blocked_without_blocker");
	if (summary.status === "pass" && !summary.nextActions.some((action) => action.includes("re_swarm merge")))
		errors.push("retry_handoff_merge_summary_pass_without_merge_action");
	return {
		ok: errors.length === 0,
		errors: uniqueNonEmpty(errors, 120),
		evidenceContract: workerRetryHandoffMergeSummaryEvidenceContract(),
	};
}

export function verifyWorkerChildSessionRuntimeBatch(batch: RepiWorkerChildSessionRuntimeBatchV1): {
	ok: boolean;
	errors: string[];
} {
	const errors: string[] = [];
	if (batch.kind !== "WorkerChildSessionRuntimeBatchV1") errors.push("child_session_batch_kind_invalid");
	if (batch.schemaVersion !== 1) errors.push("child_session_batch_schema_version_invalid");
	if (!batch.sessions.length) errors.push("child_session_sessions_missing");
	if (batch.launchPolicy.command !== "repi") errors.push("child_session_command_not_repi");
	if (!batch.launchPolicy.args.includes("--recon")) errors.push("child_session_missing_recon_arg");
	if (!batch.launchPolicy.isolatedHome.includes(".repi") || batch.launchPolicy.isolatedHome.includes("/.pi/"))
		errors.push("child_session_isolated_home_invalid");
	if (batch.launchPolicy.importPiAuth !== false) errors.push("child_session_import_pi_auth_not_false");
	if (!batch.launchPolicy.updateChecksDisabled) errors.push("child_session_update_checks_not_disabled");
	if (!batch.launchPolicy.telemetryDisabled) errors.push("child_session_telemetry_not_disabled");
	if (batch.poolBridge?.kind !== "WorkerRuntimePoolV1Bridge") errors.push("child_session_pool_bridge_kind_invalid");
	if (batch.poolBridge?.poolId !== batch.poolId) errors.push("child_session_pool_bridge_pool_mismatch");
	if (!batch.poolBridge?.claimAwareMerge) errors.push("child_session_claim_aware_merge_missing");
	if (!batch.poolBridge?.childSessionRuntimeCaptured) errors.push("child_session_runtime_not_captured");
	const sessionWorkerIds = batch.sessions.map((session) => session.workerId);
	if (!sameStringSet(batch.poolBridge?.workerIds ?? [], sessionWorkerIds))
		errors.push("child_session_pool_bridge_workerIds_mismatch");
	if (batch.poolBridge?.childProcessRuntimeCaptured) {
		const probe = batch.childProcessProbe;
		if (!probe) errors.push("child_process_probe_missing");
		else {
			if (probe.kind !== "WorkerChildProcessProbeV1" || probe.status !== "pass")
				errors.push("child_process_probe_not_pass");
			if (!probe.assertions.repiCommandExecuted) errors.push("child_process_probe_command_not_repi");
			if (
				!probe.assertions.isolatedRepiHome ||
				!probe.isolatedHome.includes(".repi") ||
				probe.isolatedHome.includes("/.pi/")
			)
				errors.push("child_process_probe_isolated_home_invalid");
			if (!probe.assertions.noPiHomeImport) errors.push("child_process_probe_imported_pi_home");
			if (!probe.assertions.updateChecksDisabled) errors.push("child_process_probe_update_checks_not_disabled");
			if (!probe.assertions.telemetryDisabled) errors.push("child_process_probe_telemetry_not_disabled");
			if (!probe.assertions.noLiteralSecrets) errors.push("child_process_probe_literal_secret");
			if (!probe.assertions.stdoutCaptured || !probe.stdoutSha256) errors.push("child_process_probe_stdout_missing");
		}
	}
	if (batch.poolBridge?.providerChildProcessRuntimeCaptured || batch.providerChildProcessProbe) {
		const probe = batch.providerChildProcessProbe;
		if (!probe) errors.push("provider_child_process_probe_missing");
		else errors.push(...verifyWorkerProviderChildProcessProbe(probe));
	}
	for (const secret of ["GITHUB_TOKEN", "GITHUB_TOKEN_FOR_PUSH", "ANTHROPIC_AUTH_TOKEN"]) {
		if (batch.launchPolicy.envAllowlist.includes(secret)) errors.push(`child_session_secret_allowed:${secret}`);
		if (!batch.launchPolicy.envDenylist.includes(secret)) errors.push(`child_session_secret_not_denied:${secret}`);
	}
	const sessionDirs = new Set<string>();
	for (const session of batch.sessions) {
		if (!session.provider.apiKeyRef.startsWith("$"))
			errors.push(`child_session_literal_api_key:${session.sessionId}`);
		if (!session.provider.baseUrlRef.startsWith("$"))
			errors.push(`child_session_literal_base_url:${session.sessionId}`);
		for (const ref of [session.provider.apiKeyRef, session.provider.baseUrlRef]) {
			const name = envRefName(ref);
			if (!name) continue;
			if (!batch.launchPolicy.envAllowlist.includes(name))
				errors.push(`child_session_provider_env_not_allowlisted:${session.sessionId}:${name}`);
			if (batch.launchPolicy.envDenylist.includes(name))
				errors.push(`child_session_provider_env_denied:${session.sessionId}:${name}`);
		}
		if (sessionDirs.has(session.runtime.sessionDir))
			errors.push(`child_session_duplicate_session_dir:${session.sessionId}`);
		sessionDirs.add(session.runtime.sessionDir);
		if (!session.poolBridge?.poolId || session.poolBridge.poolId !== batch.poolId)
			errors.push(`child_session_missing_pool_bridge:${session.sessionId}`);
		if (session.retryBudget.remaining !== Math.max(0, session.maxAttempts - session.attempt))
			errors.push(`child_session_retry_remaining_inconsistent:${session.sessionId}`);
		if (session.retryBudget.exhausted && ["queued", "running"].includes(session.runtime.status))
			errors.push(`child_session_exhausted_still_running:${session.sessionId}`);
		if (session.runtime.status === "timeout" && !session.runtime.cancelledAt)
			errors.push(`child_session_timeout_without_cancel:${session.sessionId}`);
		if (
			!workerChildRuntimeStatusMatchesPoolStatus(session.runtime.status, session.poolBridge.workerRuntimePoolStatus)
		)
			errors.push(`child_session_pool_status_mismatch:${session.sessionId}`);
	}
	const bridgePool = workerChildSessionToWorkerRuntimePoolBridge(batch);
	const bridgeValidation = verifyWorkerRuntimePool(bridgePool);
	if (!bridgeValidation.ok)
		errors.push(...bridgeValidation.errors.map((error) => `child_session_pool_bridge:${error}`));
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 80) };
}

function workerChildRuntimeStatusMatchesPoolStatus(
	runtimeStatus: RepiWorkerChildSessionRuntimeStatus,
	poolStatus: RepiWorkerRuntimePoolWorkerV1["status"],
): boolean {
	switch (runtimeStatus) {
		case "queued":
			return poolStatus === "queued" || poolStatus === "retry_queued";
		case "running":
			return poolStatus === "queued" || poolStatus === "retry_queued";
		case "passed":
			return poolStatus === "done" || poolStatus === "passed";
		case "failed":
			return ["failed", "retry_queued", "exhausted", "blocked"].includes(poolStatus);
		case "timeout":
			return ["timeout", "cancelled", "retry_queued", "exhausted", "blocked"].includes(poolStatus);
		case "cancelled":
			return ["cancelled", "retry_queued", "exhausted", "blocked"].includes(poolStatus);
		case "exhausted":
			return poolStatus === "exhausted" || poolStatus === "blocked";
	}
}

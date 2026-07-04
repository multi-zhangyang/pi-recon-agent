import { createHash } from "node:crypto";
import { join } from "node:path";
import { uniqueNonEmpty } from "./text.ts";

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

export type RepiWorkerProviderChildProcessProbeV1 = {
	kind: "WorkerProviderChildProcessProbeV1";
	schemaVersion: 1;
	probeId: string;
	providerName: string;
	modelId: string;
	command: string;
	args: string[];
	cwd: string;
	isolatedHome: string;
	modelsJsonPath: string;
	requestLogPath: string;
	transcriptPath: string;
	stdoutPath: string;
	stderrPath: string;
	stdoutSha256: string;
	stderrSha256: string;
	requestLogSha256: string;
	transcriptSha256: string;
	startedAt: string;
	endedAt: string;
	elapsedMs: number;
	exitCode: number | null;
	signal: string | null;
	status: "pass" | "blocked";
	assertions: {
		openAICompatibleRequestSeen: boolean;
		modelMatched: boolean;
		stdoutMarkerObserved: boolean;
		apiKeyEnvRefOnly: boolean;
		authorizationFromEnv: boolean;
		transcriptCaptured: boolean;
		noPiHomeImport: boolean;
		noUpdateBanner: boolean;
		noLiteralSecrets: boolean;
	};
	request: {
		method?: string;
		path?: string;
		model?: string;
		stream?: boolean;
		authorizationHeaderSha256?: string;
		bodySha256?: string;
	};
	errors: string[];
};

export type RepiProviderRuntimeMatrixCaseV1 = {
	kind: "ProviderRuntimeMatrixCaseV1";
	schemaVersion: 1;
	caseId: string;
	providerName: string;
	api: "openai-completions" | "openai-responses" | "anthropic-messages";
	modelId: string;
	expectedPath: "/v1/chat/completions" | "/v1/responses" | "/v1/messages";
	diagnostic?: string;
	authHeader: "authorization" | "x-api-key";
	status: "pass" | "blocked";
	exitCode: number | null;
	signal: string | null;
	elapsedMs: number;
	stdoutPath: string;
	stderrPath: string;
	stdoutSha256: string;
	stderrSha256: string;
	request: {
		method?: string;
		path?: string;
		model?: string;
		stream?: boolean;
		authHeaderSha256?: string;
		bodySha256?: string;
	};
	assertions: {
		exitOk: boolean;
		requestSeen: boolean;
		modelMatched: boolean;
		streamingUsed: boolean;
		stdoutMarkerObserved: boolean;
		apiKeyEnvRefOnly: boolean;
		authorizationFromEnv: boolean;
		noPiHomeImport: boolean;
		noUpdateBanner: boolean;
		noLiteralSecrets: boolean;
		transcriptCaptured: boolean;
		requestLogCaptured: boolean;
	};
	errors: string[];
};

export type RepiProviderRuntimeMatrixV1 = {
	kind: "ProviderRuntimeMatrixV1";
	schemaVersion: 1;
	generatedAt: string;
	modelsJsonPath: string;
	requestLogPath: string;
	isolatedHome: string;
	workspace: string;
	listModels: {
		status: "pass" | "blocked";
		providers: string[];
		stdoutSha256: string;
		stderrSha256: string;
	};
	cases: RepiProviderRuntimeMatrixCaseV1[];
};

export type RepiProviderFailureInjectionReportV1 = {
	kind: "ProviderFailureInjectionReportV1";
	schemaVersion: 1;
	generatedAt: string;
	isolatedHome: string;
	workspace: string;
	cases: Array<{
		kind: "ProviderFailureInjectionCaseV1";
		schemaVersion: 1;
		caseId: string;
		providerName: string;
		api: "openai-completions" | "anthropic-messages";
		modelId: string;
		failureMode: "http_500" | "malformed_sse" | "anthropic_error_event" | "timeout" | "connection_reset";
		status: "pass" | "blocked";
		exitCode: number | null;
		signal: string | null;
		request: {
			method?: string;
			path?: string;
			model?: string;
			stream?: boolean;
			bodySha256?: string;
		};
		stdoutSha256: string;
		stderrSha256: string;
		requestLogSha256: string;
		transcriptSha256: string;
		failureId: string;
		repairId: string;
		assertions: {
			requestSeen: boolean;
			exitNonZero: boolean;
			failureTextCaptured: boolean;
			failureRepairLinked: boolean;
			noLiteralSecrets: boolean;
			noPiHomeImport: boolean;
			noUpdateBanner: boolean;
		};
	}>;
	failureLedgerEvents: Array<{
		id: string;
		status: string;
		retryBudget: { remainingAttempts: number };
	}>;
	repairQueue: Array<{
		repairId: string;
		fromFailureId: string;
		action: string;
		paused: boolean;
	}>;
	failureRepairValidation: {
		ok: boolean;
		failureCount: number;
		repairCount: number;
	};
	writebackProbe: {
		status: "pass" | "blocked";
		validation: { ok: boolean };
	};
};

export type RepiRepairRollbackPolicyV1 = {
	kind: "RepairRollbackPolicyV1";
	schemaVersion: 1;
	baseline: { treeSha256: string; files: unknown[] };
	allowlist: string[];
	repair: { changedFiles: string[] };
	rollback: { required: boolean; restored: boolean; restoredTreeSha256: string };
	regression: {
		after: string;
		restored: string;
		checkpoints: Array<{ checkId: string; status: string }>;
	};
	failureLedgerEvents: unknown[];
	repairQueue: Array<{ action: string; rollbackCriteria: { mustRestore: string[] } }>;
	failureRepairValidation: { ok: boolean };
	assertions: {
		baselineCaptured: boolean;
		allowlistEnforced: boolean;
		rollbackRestored: boolean;
		regressionChecksPassed: boolean;
		noUnrelatedFileChanges: boolean;
		failureRepairLinked: boolean;
	};
};

export type RepiParallelProviderWorkerMatrixV1 = {
	kind: "ParallelProviderWorkerMatrixV1";
	schemaVersion: 1;
	poolId: string;
	isolatedHome: string;
	maxConcurrency: number;
	peakConcurrency: number;
	listModels: { status: "pass" | "blocked" };
	workers: Array<{
		workerId: string;
		providerName: string;
		api: "openai-completions" | "anthropic-messages";
		modelId: string;
		mode: "pass" | "failure" | "timeout";
		status: "pass" | "repair_queued" | "cancelled" | "blocked";
		mergeKey: string;
		failureId?: string;
		repairId?: string;
		timedOut: boolean;
		cancelledAt?: string;
		assertions: {
			childProcessLaunched: boolean;
			requestSeen: boolean;
			endpointMatched: boolean;
			modelMatched: boolean;
			streamingUsed: boolean;
			successMarkerObserved: boolean;
			exitOkWhenExpected: boolean;
			exitFailedWhenExpected: boolean;
			timeoutCancelled: boolean;
			apiKeyEnvRefOnly: boolean;
			authorizationFromEnv: boolean;
			requestLogCaptured: boolean;
			transcriptCaptured: boolean;
			noLiteralSecrets: boolean;
			noPiHomeImport: boolean;
			noUpdateBanner: boolean;
			providerWorkerFailureRepairLinked?: boolean;
		};
	}>;
	claimMerge: {
		strategy: string;
		claimAwareProviderWorkerMerge: boolean;
		conflicts: Array<{ mergeKey: string; status: "resolved" | "open"; winner?: string; evidenceRefs: string[] }>;
	};
	failureLedgerEvents: Array<{ status: string; retryBudget: { remainingAttempts: number } }>;
	repairQueue: Array<{ action: string; paused: boolean }>;
	failureRepairValidation: { ok: boolean };
	writebackProbe: { status: "pass" | "blocked"; validation: { ok: boolean } };
};

export type RepiRemoteProviderLongRunV1 = {
	kind: "RemoteProviderLongRunV1";
	mode: "skipped" | "live";
	skipReason: string;
	providerName?: string;
	api?: "openai-completions" | "openai-responses" | "anthropic-messages";
	modelIdSha256?: string;
	baseUrlSha256?: string;
	apiKeyEnv?: string;
	attemptsPlanned: number;
	listModels: { status: "pass" | "blocked" | "skipped" };
	cases: Array<{
		caseId: string;
		status: "pass" | "blocked";
		assertions: {
			exitOk: boolean;
			stdoutNonEmpty: boolean;
			markerObserved: boolean;
			apiKeyEnvRefOnly: boolean;
			boundedTimeout: boolean;
			isolatedRepiHome: boolean;
			noLiteralSecrets: boolean;
			noPiHomeImport: boolean;
			noUpdateBanner: boolean;
			transcriptCaptured: boolean;
		};
	}>;
	failureLedgerEvents: unknown[];
	repairQueue: unknown[];
	failureRepairValidation: { ok: boolean };
	writebackProbe: { status: "pass" | "blocked" | "skipped"; validation: { ok: boolean } };
};

export type RepiCrossSessionResumeLiveV1 = {
	kind: "CrossSessionResumeLiveV1";
	isolatedHome: string;
	pack: { contextPath: string };
	resume: {
		resumedFromContextPath: string;
		resumeQueueStatus: string;
		closureStatus: string;
		exactResumeVerification: {
			loadedBy: string;
			contextSha256: string;
			artifactHashes: string;
			scope: string;
		};
	};
	compactResumeLedger: { currentState: string; invalidTransitions: unknown[]; statePath: string[] };
	providerContinuation: { status: "pass" | "blocked" };
	workerContinuation: { status: "pass" | "blocked" };
	assertions: {
		crossSessionDifferent: boolean;
		packQueued: boolean;
		exactResumeLoadedByContextPath: boolean;
		resumedFromOriginalPack: boolean;
		contextSha256Pass: boolean;
		artifactHashesPass: boolean;
		scopePass: boolean;
		closureClosed: boolean;
		ledgerDone: boolean;
		providerContinuedAfterResume: boolean;
		workerContinuedAfterResume: boolean;
		envRefOnly: boolean;
		noPiHomeImport: boolean;
		noUpdateBanner: boolean;
		noLiteralSecrets: boolean;
	};
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

// WorkerRuntimePoolV1 split contract: runtime:worker-runtime-pool-validation runtime:claim-aware-worker-merge runtime:child-session-runtime-bridge.
export function workerRuntimePoolEvidenceContract(): string[] {
	return [
		"worker stdout/stderr sha256 must match captured artifacts",
		"timeout/cancel must be explicit when elapsedMs exceeds timeoutMs",
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
		if (end - start > worker.timeoutMs && worker.status !== "timeout" && worker.status !== "cancelled")
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
		"unresolved workers or unresolved merge collisions must block promotion",
		"pass status requires no unresolved workers, resolved collisions, closed failures, and preserved artifacts",
	];
}

export function buildWorkerRetryHandoffMergeSummaryV1(
	report: RepiWorkerRetryHandoffClosureV1,
): RepiWorkerRetryHandoffMergeSummaryV1 {
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
		report.workers.flatMap((worker) => [
			...worker.sourceArtifacts,
			...worker.retryQueueRefs,
			...worker.handoffRefs,
			...worker.repairRefs,
			...worker.claimRefs,
			...worker.mergeKeys,
		]),
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
			...retryQueuedWorkers.map((workerId) => `re_swarm retry worker=${workerId}`),
			...handoffRecoveredWorkers.map((workerId) => `re_swarm merge worker=${workerId} && re_supervisor review`),
			...exhaustedEscalatedWorkers.map((workerId) => `re_autofix plan worker=${workerId} && re_supervisor repair`),
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

export function verifyWorkerProviderChildProcessProbe(probe: RepiWorkerProviderChildProcessProbeV1): string[] {
	const errors: string[] = [];
	if (probe.kind !== "WorkerProviderChildProcessProbeV1" || probe.status !== "pass")
		errors.push("provider_child_process_probe_not_pass");
	if (!probe.assertions.openAICompatibleRequestSeen) errors.push("provider_child_process_request_missing");
	if (!probe.assertions.modelMatched) errors.push("provider_child_process_model_mismatch");
	if (!probe.assertions.stdoutMarkerObserved) errors.push("provider_child_process_stdout_marker_missing");
	if (!probe.assertions.apiKeyEnvRefOnly) errors.push("provider_child_process_api_key_not_env_ref");
	if (!probe.assertions.authorizationFromEnv) errors.push("provider_child_process_authorization_not_env");
	if (!probe.assertions.transcriptCaptured || !probe.transcriptSha256)
		errors.push("provider_child_process_transcript_missing");
	if (!probe.assertions.noPiHomeImport) errors.push("provider_child_process_imported_pi_home");
	if (!probe.assertions.noUpdateBanner) errors.push("provider_child_process_update_banner");
	if (!probe.assertions.noLiteralSecrets) errors.push("provider_child_process_literal_secret");
	if (!probe.isolatedHome.includes(".repi") || probe.isolatedHome.includes("/.pi/"))
		errors.push("provider_child_process_isolated_home_invalid");
	if (probe.request.path !== "/v1/chat/completions") errors.push("provider_child_process_endpoint_invalid");
	if (probe.request.model !== probe.modelId) errors.push("provider_child_process_request_model_invalid");
	return errors;
}

export function verifyProviderRuntimeMatrixV1(matrix: RepiProviderRuntimeMatrixV1): { ok: boolean; errors: string[] } {
	const errors: string[] = [];
	if (matrix.kind !== "ProviderRuntimeMatrixV1") errors.push("provider_matrix_kind_invalid");
	if (!matrix.isolatedHome.includes(".repi") || matrix.isolatedHome.includes("/.pi/"))
		errors.push("provider_matrix_isolated_home_invalid");
	const requiredApis = new Set<RepiProviderRuntimeMatrixCaseV1["api"]>([
		"openai-completions",
		"openai-responses",
		"anthropic-messages",
	]);
	for (const row of matrix.cases) {
		requiredApis.delete(row.api);
		if (row.status !== "pass") errors.push(`provider_matrix_case_not_pass:${row.caseId}`);
		if (!row.assertions.exitOk) errors.push(`provider_matrix_exit_not_ok:${row.caseId}`);
		if (!row.assertions.requestSeen) errors.push(`provider_matrix_request_missing:${row.caseId}`);
		if (!row.assertions.modelMatched) errors.push(`provider_matrix_model_mismatch:${row.caseId}`);
		if (!row.assertions.streamingUsed) errors.push(`provider_matrix_stream_missing:${row.caseId}`);
		if (!row.assertions.stdoutMarkerObserved) errors.push(`provider_matrix_stdout_marker_missing:${row.caseId}`);
		if (!row.assertions.apiKeyEnvRefOnly) errors.push(`provider_matrix_api_key_not_env_ref:${row.caseId}`);
		if (!row.assertions.authorizationFromEnv) errors.push(`provider_matrix_authorization_not_env:${row.caseId}`);
		if (!row.assertions.noPiHomeImport) errors.push(`provider_matrix_pi_home_leak:${row.caseId}`);
		if (!row.assertions.noUpdateBanner) errors.push(`provider_matrix_update_banner_leak:${row.caseId}`);
		if (!row.assertions.noLiteralSecrets) errors.push(`provider_matrix_literal_secret:${row.caseId}`);
		if (!row.assertions.transcriptCaptured || !row.assertions.requestLogCaptured)
			errors.push(`provider_matrix_artifact_missing:${row.caseId}`);
		if (row.api === "openai-completions" && row.request.path !== "/v1/chat/completions")
			errors.push(`provider_matrix_openai_endpoint_invalid:${row.caseId}`);
		if (row.api === "openai-responses" && row.request.path !== "/v1/responses")
			errors.push(`provider_matrix_responses_endpoint_invalid:${row.caseId}`);
		if (row.api === "anthropic-messages" && row.request.path !== "/v1/messages")
			errors.push(`provider_matrix_anthropic_endpoint_invalid:${row.caseId}`);
	}
	for (const api of requiredApis) errors.push(`provider_matrix_missing_api:${api}`);
	if (matrix.listModels.status !== "pass") errors.push("provider_matrix_list_models_not_pass");
	for (const row of matrix.cases) {
		if (!matrix.listModels.providers.includes(row.providerName))
			errors.push(`provider_matrix_list_models_missing:${row.providerName}`);
	}
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 80) };
}

export function verifyProviderFailureInjectionReportV1(report: RepiProviderFailureInjectionReportV1): {
	ok: boolean;
	errors: string[];
} {
	const errors: string[] = [];
	if (report.kind !== "ProviderFailureInjectionReportV1") errors.push("provider_failure_report_kind_invalid");
	if (!report.isolatedHome.includes(".repi") || report.isolatedHome.includes("/.pi/"))
		errors.push("provider_failure_isolated_home_invalid");
	if (report.cases.length < 3) errors.push("provider_failure_case_count_lt_3");
	for (const row of report.cases) {
		if (row.status !== "pass") errors.push(`provider_failure_case_not_pass:${row.caseId}`);
		if (!row.assertions.requestSeen) errors.push(`provider_failure_request_missing:${row.caseId}`);
		if (!row.assertions.exitNonZero) errors.push(`provider_failure_exit_not_failed:${row.caseId}`);
		if (!row.assertions.failureTextCaptured) errors.push(`provider_failure_text_missing:${row.caseId}`);
		if (!row.assertions.failureRepairLinked) errors.push(`provider_failure_repair_not_linked:${row.caseId}`);
		if (!row.assertions.noLiteralSecrets) errors.push(`provider_failure_literal_secret:${row.caseId}`);
		if (!row.assertions.noPiHomeImport) errors.push(`provider_failure_pi_home_leak:${row.caseId}`);
		if (!row.assertions.noUpdateBanner) errors.push(`provider_failure_update_banner_leak:${row.caseId}`);
		if (!report.failureLedgerEvents.some((failure) => failure.id === row.failureId))
			errors.push(`provider_failure_missing_failure_row:${row.caseId}`);
		if (
			!report.repairQueue.some(
				(repair) => repair.repairId === row.repairId && repair.fromFailureId === row.failureId,
			)
		)
			errors.push(`provider_failure_missing_repair_row:${row.caseId}`);
	}
	if (!report.failureRepairValidation.ok) errors.push("provider_failure_repair_validation_not_ok");
	if (report.failureRepairValidation.failureCount !== report.cases.length)
		errors.push("provider_failure_failure_count_mismatch");
	if (report.failureRepairValidation.repairCount < report.failureRepairValidation.failureCount)
		errors.push("provider_failure_repair_count_lt_failure_count");
	if (report.writebackProbe.status !== "pass" || !report.writebackProbe.validation.ok)
		errors.push("provider_failure_writeback_probe_not_pass");
	if (
		!report.failureLedgerEvents.some(
			(failure) => failure.status === "exhausted" && failure.retryBudget.remainingAttempts === 0,
		)
	)
		errors.push("provider_failure_exhausted_budget_missing");
	if (!report.repairQueue.some((repair) => repair.action === "escalate" && repair.paused))
		errors.push("provider_failure_exhausted_escalation_missing");
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 80) };
}

export function verifyRepairRollbackPolicyV1(report: RepiRepairRollbackPolicyV1): { ok: boolean; errors: string[] } {
	const errors: string[] = [];
	if (report.kind !== "RepairRollbackPolicyV1") errors.push("repair_rollback_kind_invalid");
	if (report.schemaVersion !== 1) errors.push("repair_rollback_schema_version_invalid");
	if (!report.baseline.treeSha256 || report.baseline.files.length === 0)
		errors.push("repair_rollback_baseline_missing");
	if (report.allowlist.length === 0) errors.push("repair_rollback_allowlist_missing");
	const allowlist = new Set(report.allowlist);
	for (const path of report.repair.changedFiles) {
		if (!allowlist.has(path)) errors.push(`repair_rollback_allowlist_violation:${path}`);
	}
	if (report.rollback.required !== true) errors.push("repair_rollback_required_missing");
	if (!report.rollback.restored) errors.push("repair_rollback_not_restored");
	if (report.rollback.restoredTreeSha256 !== report.baseline.treeSha256)
		errors.push("repair_rollback_tree_hash_mismatch");
	if (report.regression.checkpoints.length === 0) errors.push("repair_rollback_regression_check_missing");
	for (const checkpoint of report.regression.checkpoints) {
		if (checkpoint.status !== "pass") errors.push(`repair_rollback_regression_check_failed:${checkpoint.checkId}`);
	}
	if (report.regression.after !== "pass") errors.push("repair_rollback_after_regression_not_pass");
	if (report.regression.restored !== "pass") errors.push("repair_rollback_restored_regression_not_pass");
	if (!report.failureRepairValidation.ok) errors.push("repair_rollback_failure_repair_validation_not_ok");
	if (report.failureLedgerEvents.length < 1) errors.push("repair_rollback_failure_ledger_missing");
	if (
		!report.repairQueue.some(
			(repair) => repair.action === "rollback" && repair.rollbackCriteria.mustRestore.length > 0,
		)
	)
		errors.push("repair_rollback_queue_missing");
	if (!report.assertions.baselineCaptured) errors.push("repair_rollback_assertion_baseline_not_captured");
	if (!report.assertions.allowlistEnforced) errors.push("repair_rollback_assertion_allowlist_not_enforced");
	if (!report.assertions.rollbackRestored) errors.push("repair_rollback_assertion_not_restored");
	if (!report.assertions.regressionChecksPassed) errors.push("repair_rollback_assertion_regression_not_passed");
	if (!report.assertions.noUnrelatedFileChanges) errors.push("repair_rollback_assertion_unrelated_file_changes");
	if (!report.assertions.failureRepairLinked) errors.push("repair_rollback_assertion_failure_repair_not_linked");
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 80) };
}

export function verifyParallelProviderWorkerMatrixV1(report: RepiParallelProviderWorkerMatrixV1): {
	ok: boolean;
	errors: string[];
} {
	const errors: string[] = [];
	if (report.kind !== "ParallelProviderWorkerMatrixV1") errors.push("parallel_provider_worker_matrix_kind_invalid");
	if (!report.isolatedHome.includes(".repi") || report.isolatedHome.includes("/.pi/"))
		errors.push("parallel_provider_worker_matrix_isolated_home_invalid");
	if (report.workers.length < 4) errors.push("parallel_provider_worker_matrix_worker_count_lt_4");
	if (report.peakConcurrency < 2) errors.push("parallel_provider_worker_matrix_peak_concurrency_lt_2");
	if (report.peakConcurrency > report.maxConcurrency)
		errors.push("parallel_provider_worker_matrix_max_concurrency_exceeded");
	if (report.listModels.status !== "pass") errors.push("parallel_provider_worker_matrix_list_models_not_pass");
	const passingApis = new Set(report.workers.filter((worker) => worker.status === "pass").map((worker) => worker.api));
	if (!passingApis.has("openai-completions")) errors.push("parallel_provider_worker_matrix_openai_pass_missing");
	if (!passingApis.has("anthropic-messages")) errors.push("parallel_provider_worker_matrix_anthropic_pass_missing");
	for (const worker of report.workers) {
		if (!worker.providerName.startsWith("parallel-"))
			errors.push(`parallel_provider_worker_fixture_invalid:${worker.workerId}`);
		if (!worker.modelId.startsWith("parallel/"))
			errors.push(`parallel_provider_worker_model_invalid:${worker.workerId}`);
		if (!worker.assertions.childProcessLaunched)
			errors.push(`parallel_provider_worker_not_launched:${worker.workerId}`);
		if (!worker.assertions.requestSeen) errors.push(`parallel_provider_worker_request_missing:${worker.workerId}`);
		if (!worker.assertions.endpointMatched)
			errors.push(`parallel_provider_worker_endpoint_mismatch:${worker.workerId}`);
		if (!worker.assertions.modelMatched) errors.push(`parallel_provider_worker_model_mismatch:${worker.workerId}`);
		if (!worker.assertions.streamingUsed) errors.push(`parallel_provider_worker_stream_missing:${worker.workerId}`);
		if (!worker.assertions.successMarkerObserved)
			errors.push(`parallel_provider_worker_success_marker_missing:${worker.workerId}`);
		if (!worker.assertions.exitOkWhenExpected) errors.push(`parallel_provider_worker_exit_not_ok:${worker.workerId}`);
		if (!worker.assertions.exitFailedWhenExpected)
			errors.push(`parallel_provider_worker_exit_not_failed:${worker.workerId}`);
		if (!worker.assertions.timeoutCancelled)
			errors.push(`parallel_provider_worker_timeout_without_cancel:${worker.workerId}`);
		if (!worker.assertions.apiKeyEnvRefOnly)
			errors.push(`parallel_provider_worker_api_key_not_env_ref:${worker.workerId}`);
		if (!worker.assertions.authorizationFromEnv)
			errors.push(`parallel_provider_worker_authorization_not_env:${worker.workerId}`);
		if (!worker.assertions.requestLogCaptured || !worker.assertions.transcriptCaptured)
			errors.push(`parallel_provider_worker_artifact_missing:${worker.workerId}`);
		if (!worker.assertions.noLiteralSecrets)
			errors.push(`parallel_provider_worker_literal_secret:${worker.workerId}`);
		if (!worker.assertions.noPiHomeImport) errors.push(`parallel_provider_worker_pi_home_leak:${worker.workerId}`);
		if (!worker.assertions.noUpdateBanner) errors.push(`parallel_provider_worker_update_banner:${worker.workerId}`);
		if (
			worker.mode === "failure" &&
			(worker.status !== "repair_queued" ||
				!worker.failureId ||
				!worker.repairId ||
				!worker.assertions.providerWorkerFailureRepairLinked)
		)
			errors.push(`parallel_provider_worker_failure_repair_not_linked:${worker.workerId}`);
		if (worker.mode === "timeout" && (worker.status !== "cancelled" || !worker.timedOut || !worker.cancelledAt))
			errors.push(`parallel_provider_worker_cancelledWorker_missing:${worker.workerId}`);
	}
	const mergeKeyCounts = new Map<string, number>();
	for (const worker of report.workers)
		mergeKeyCounts.set(worker.mergeKey, (mergeKeyCounts.get(worker.mergeKey) ?? 0) + 1);
	const resolvedMergeKeys = new Set(
		report.claimMerge.conflicts
			.filter(
				(conflict) =>
					conflict.status === "resolved" && Boolean(conflict.winner) && conflict.evidenceRefs.length > 0,
			)
			.map((conflict) => conflict.mergeKey),
	);
	for (const [mergeKey, count] of mergeKeyCounts) {
		if (count > 1 && !resolvedMergeKeys.has(mergeKey))
			errors.push(`parallel_provider_worker_duplicate_mergeKey_unresolved:${mergeKey}`);
	}
	if (
		report.claimMerge.strategy !== "claim-aware provider worker merge" ||
		!report.claimMerge.claimAwareProviderWorkerMerge
	)
		errors.push("parallel_provider_worker_claimAwareProviderWorkerMerge_missing");
	if (!report.failureRepairValidation.ok) errors.push("parallel_provider_worker_failure_repair_validation_not_ok");
	if (report.writebackProbe.status !== "pass" || !report.writebackProbe.validation.ok)
		errors.push("parallel_provider_worker_writeback_probe_not_pass");
	if (
		!report.failureLedgerEvents.some(
			(failure) => failure.status === "exhausted" && failure.retryBudget.remainingAttempts === 0,
		)
	)
		errors.push("parallel_provider_worker_timeout_exhausted_failure_missing");
	if (!report.repairQueue.some((repair) => repair.action === "escalate" && repair.paused))
		errors.push("parallel_provider_worker_timeout_escalation_missing");
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 100) };
}

export function verifyRemoteProviderLongRunV1(report: RepiRemoteProviderLongRunV1): { ok: boolean; errors: string[] } {
	const errors: string[] = [];
	if (report.kind !== "RemoteProviderLongRunV1") errors.push("remote_provider_longrun_kind_invalid");
	if (report.mode === "skipped") {
		if (!report.skipReason) errors.push("remote_provider_longrun_skipped_without_reason");
		if (report.cases.length > 0) errors.push("remote_provider_longrun_skipped_with_cases");
		// remote_provider_longrun_optional_live_skip: no env in CI is a pass, not a false failure.
		return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 40) };
	}
	if (report.mode !== "live") errors.push("remote_provider_longrun_mode_invalid");
	if (!report.providerName) errors.push("remote_provider_longrun_provider_missing");
	if (!report.api || !["openai-completions", "openai-responses", "anthropic-messages"].includes(report.api))
		errors.push("remote_provider_longrun_api_invalid");
	if (!report.modelIdSha256 || !/^[a-f0-9]{64}$/.test(report.modelIdSha256))
		errors.push("remote_provider_longrun_model_hash_missing");
	if (!report.baseUrlSha256 || !/^[a-f0-9]{64}$/.test(report.baseUrlSha256))
		errors.push("remote_provider_longrun_base_url_hash_missing");
	if (!report.apiKeyEnv || !/^[A-Z_][A-Z0-9_]*$/.test(report.apiKeyEnv))
		errors.push("remote_provider_longrun_api_key_env_invalid");
	if (report.listModels.status !== "pass") errors.push("remote_provider_longrun_list_models_not_pass");
	if (report.cases.length < Math.max(1, report.attemptsPlanned))
		errors.push("remote_provider_longrun_case_count_lt_attempts");
	for (const row of report.cases) {
		if (row.status !== "pass") errors.push(`remote_provider_longrun_case_not_pass:${row.caseId}`);
		if (!row.assertions.exitOk) errors.push(`remote_provider_longrun_exit_not_ok:${row.caseId}`);
		if (!row.assertions.stdoutNonEmpty) errors.push(`remote_provider_longrun_stdout_empty:${row.caseId}`);
		if (!row.assertions.markerObserved) errors.push(`remote_provider_longrun_marker_missing:${row.caseId}`);
		if (!row.assertions.apiKeyEnvRefOnly) errors.push(`remote_provider_longrun_api_key_not_env_ref:${row.caseId}`);
		if (!row.assertions.boundedTimeout) errors.push(`remote_provider_longrun_unbounded_timeout:${row.caseId}`);
		if (!row.assertions.isolatedRepiHome) errors.push(`remote_provider_longrun_home_not_isolated:${row.caseId}`);
		if (!row.assertions.noLiteralSecrets) errors.push(`remote_provider_longrun_literal_secret:${row.caseId}`);
		if (!row.assertions.noPiHomeImport) errors.push(`remote_provider_longrun_pi_home_leak:${row.caseId}`);
		if (!row.assertions.noUpdateBanner) errors.push(`remote_provider_longrun_update_banner:${row.caseId}`);
		if (!row.assertions.transcriptCaptured) errors.push(`remote_provider_longrun_transcript_missing:${row.caseId}`);
	}
	if (report.failureLedgerEvents.length > 0 || report.repairQueue.length > 0) {
		if (!report.failureRepairValidation.ok) errors.push("remote_provider_longrun_failure_repair_validation_not_ok");
		if (report.writebackProbe.status !== "pass" || !report.writebackProbe.validation.ok)
			errors.push("remote_provider_longrun_writeback_probe_not_pass");
	}
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 100) };
}

export function verifyCrossSessionResumeLiveV1(report: RepiCrossSessionResumeLiveV1): {
	ok: boolean;
	errors: string[];
} {
	const errors: string[] = [];
	if (report.kind !== "CrossSessionResumeLiveV1") errors.push("cross_session_resume_kind_invalid");
	if (!report.isolatedHome.includes(".repi") || report.isolatedHome.includes("/.pi/"))
		errors.push("cross_session_resume_isolated_home_invalid");
	if (!report.assertions.crossSessionDifferent) errors.push("cross_session_resume_same_session_not_cross_session");
	if (!report.assertions.packQueued) errors.push("cross_session_resume_pack_not_queued");
	// cross_session_resume_exact_context_path: never resume from latest when a pack path/hash was produced.
	if (
		!report.assertions.exactResumeLoadedByContextPath ||
		report.resume.exactResumeVerification.loadedBy !== "contextPath"
	)
		errors.push("cross_session_resume_exact_context_path_not_used");
	if (!report.assertions.resumedFromOriginalPack || report.resume.resumedFromContextPath !== report.pack.contextPath)
		errors.push("cross_session_resume_original_pack_not_loaded");
	if (!report.assertions.contextSha256Pass || report.resume.exactResumeVerification.contextSha256 !== "pass")
		errors.push("cross_session_resume_context_sha256_not_pass");
	if (!report.assertions.artifactHashesPass || report.resume.exactResumeVerification.artifactHashes !== "pass")
		errors.push("cross_session_resume_artifact_hashes_not_pass");
	if (!report.assertions.scopePass || report.resume.exactResumeVerification.scope !== "pass")
		errors.push("cross_session_resume_scope_not_pass");
	if (
		!report.assertions.closureClosed ||
		report.resume.resumeQueueStatus !== "done" ||
		report.resume.closureStatus !== "closed"
	)
		errors.push("cross_session_resume_closure_not_closed");
	if (
		!report.assertions.ledgerDone ||
		report.compactResumeLedger.currentState !== "done" ||
		report.compactResumeLedger.invalidTransitions.length > 0 ||
		!report.compactResumeLedger.statePath.includes("queued->running") ||
		!report.compactResumeLedger.statePath.includes("running->done")
	)
		errors.push("cross_session_resume_compact_resume_ledger_not_done");
	if (!report.assertions.providerContinuedAfterResume || report.providerContinuation.status !== "pass")
		errors.push("cross_session_resume_provider_continuation_missing");
	if (!report.assertions.workerContinuedAfterResume || report.workerContinuation.status !== "pass")
		errors.push("cross_session_resume_worker_continuation_missing");
	if (!report.assertions.envRefOnly) errors.push("cross_session_resume_provider_key_not_env_ref");
	if (!report.assertions.noPiHomeImport) errors.push("cross_session_resume_pi_home_leak");
	if (!report.assertions.noUpdateBanner) errors.push("cross_session_resume_update_banner_leak");
	if (!report.assertions.noLiteralSecrets) errors.push("cross_session_resume_literal_secret_leak");
	return { ok: errors.length === 0, errors: uniqueNonEmpty(errors, 100) };
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

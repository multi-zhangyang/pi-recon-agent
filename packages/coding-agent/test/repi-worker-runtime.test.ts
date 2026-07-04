import { describe, expect, it } from "vitest";
import {
	buildWorkerRetryHandoffMergeSummaryV1,
	type RepiSwarmClaimLedgerEventV1,
	type RepiWorkerChildSessionRuntimeBatchV1,
	type RepiWorkerLeaseSchedulerEventV1,
	type RepiWorkerLeaseSchedulerV1,
	type RepiWorkerRetryHandoffClosureV1,
	type RepiWorkerRuntimePoolV1,
	verifyWorkerChildSessionRuntimeBatch,
	verifyWorkerLeaseSchedulerV1,
	verifyWorkerRetryHandoffClosureV1,
	verifyWorkerRetryHandoffMergeSummaryV1,
	verifyWorkerRuntimePool,
	workerChildSessionLaunchPolicy,
	workerChildSessionRuntimeBridgeEvidenceContract,
	workerChildSessionToWorkerRuntimePoolBridge,
	workerLeaseSchedulerEventHash,
} from "../src/core/repi/worker-runtime.ts";

const ts = "2026-07-03T00:00:00.000Z";
const sha = "a".repeat(64);

function claimEvent(type: RepiSwarmClaimLedgerEventV1["type"], claimId = "claim-a"): RepiSwarmClaimLedgerEventV1 {
	return {
		kind: "ClaimLedgerEventV1",
		seq: 1,
		prevHash: "0".repeat(64),
		eventHash: sha,
		timestamp: ts,
		source: "re_swarm",
		type,
		claimId,
		evidenceRefs: [`artifact://${type}`],
	};
}

function validPool(overrides: Partial<RepiWorkerRuntimePoolV1> = {}): RepiWorkerRuntimePoolV1 {
	return {
		kind: "WorkerRuntimePoolV1",
		schemaVersion: 1,
		poolId: "pool-a",
		maxConcurrency: 2,
		timeoutMs: 10_000,
		cancelOnTimeout: true,
		resourceBudget: { cpuSlots: 4, memoryMb: 4096, maxProcesses: 8 },
		workers: [
			{
				workerId: "w1",
				role: "native-runtime",
				route: "native",
				packetId: "packet-a",
				attempt: 1,
				maxAttempts: 3,
				retryBudget: { signature: "sig", attempt: 1, maxAttempts: 3, remaining: 2, exhausted: false },
				resourceLease: { cpuSlots: 1, memoryMb: 512, maxProcesses: 2 },
				timeoutMs: 10_000,
				status: "done",
				startedAt: ts,
				endedAt: "2026-07-03T00:00:01.000Z",
				sessionDir: "/tmp/repi/w1",
				stdoutPath: "/tmp/repi/w1/stdout.log",
				stderrPath: "/tmp/repi/w1/stderr.log",
				stdoutSha256: sha,
				stderrSha256: sha,
				toolCallDigest: sha,
				mergeKey: "claim-a",
				claimRefs: ["claim-a"],
			},
		],
		parallelGroups: [{ groupId: "g1", workers: ["w1"], dependsOn: [], maxConcurrency: 2 }],
		mergeProtocol: { strategy: "claim-aware merge", evidenceContract: [], conflicts: [] },
		claimLedgerEvents: [
			claimEvent("artifact_handoff"),
			claimEvent("claim"),
			claimEvent("validation"),
			claimEvent("challenge"),
			claimEvent("resolution"),
		],
		...overrides,
	};
}

function schedulerEvent(
	type: RepiWorkerLeaseSchedulerEventV1["type"],
	eventId: string,
	prevHash: string,
): RepiWorkerLeaseSchedulerEventV1 {
	const withoutHash = {
		kind: "WorkerLeaseSchedulerEventV1" as const,
		schemaVersion: 1 as const,
		eventId,
		ts,
		type,
		taskId: "task-a",
		workerId: "w1",
		leaseId: "lease-a",
		prevHash,
	};
	return { ...withoutHash, eventHash: workerLeaseSchedulerEventHash(withoutHash) };
}

function validScheduler(overrides: Partial<RepiWorkerLeaseSchedulerV1> = {}): RepiWorkerLeaseSchedulerV1 {
	const first = schedulerEvent("enqueue", "e1", "0".repeat(64));
	const second = schedulerEvent("lease_acquired", "e2", first.eventHash);
	const third = schedulerEvent("completed", "e3", second.eventHash);
	return {
		kind: "WorkerLeaseSchedulerV1",
		schemaVersion: 1,
		generatedAt: ts,
		schedulerId: "sched-a",
		maxConcurrency: 2,
		workerIds: ["w1", "w2"],
		tasks: [
			{
				taskId: "task-a",
				shardKey: "shard-a",
				status: "completed",
				attempt: 1,
				maxAttempts: 3,
				claimRefs: ["claim-a"],
				artifactRefs: ["artifact://stdout"],
			},
		],
		events: [first, second, third],
		assertions: {
			leaseExclusive: true,
			heartbeatRequired: true,
			staleLeaseRecovered: true,
			workStealingObserved: true,
			duplicateCompletionRejected: true,
			maxConcurrencyRespected: true,
			claimRefsPreserved: true,
			appendOnlyHashChain: true,
		},
		...overrides,
	};
}

function validRetryHandoffClosure(
	overrides: Partial<RepiWorkerRetryHandoffClosureV1> = {},
): RepiWorkerRetryHandoffClosureV1 {
	return {
		kind: "WorkerRetryHandoffClosureV1",
		schemaVersion: 1,
		closureId: "closure-a",
		poolId: "pool-a",
		generatedAt: ts,
		strategy: "retry-budgeted claim-bound handoff closure",
		workers: [
			{
				workerId: "w1",
				role: "native-runtime",
				packetId: "packet-a",
				status: "passed",
				attempt: 1,
				maxAttempts: 3,
				retryRemaining: 2,
				retryState: "passed",
				timeoutMs: 10_000,
				timedOut: false,
				retryQueueRefs: [],
				handoffRefs: ["/tmp/repi/w1/runtime-manifest.json"],
				repairRefs: ["/tmp/repi/failure-ledger.jsonl"],
				claimRefs: ["claim-a"],
				sourceArtifacts: [
					"/tmp/repi/w1/runtime-manifest.json",
					"/tmp/repi/w1/stdout.log",
					"/tmp/repi/failure-ledger.jsonl",
				],
				mergeKeys: ["claim-a"],
				assertions: {
					attemptBounded: true,
					retryBudgetConsistent: true,
					timeoutCancellationRecorded: true,
					failureHasRetryOrHandoff: true,
					exhaustionEscalated: true,
					handoffBoundToClaim: true,
					sourceArtifactsPreserved: true,
				},
			},
		],
		merge: {
			strategy: "claim-bound handoff merge",
			recoveredWorkers: [],
			unresolvedWorkers: [],
			collisions: [],
		},
		assertions: {
			retryAttemptsBounded: true,
			retryBudgetsConsistent: true,
			timeoutCancellationRecorded: true,
			failedWorkersHaveRetryOrHandoff: true,
			exhaustedWorkersEscalated: true,
			handoffRefsBoundToClaims: true,
			mergeCollisionsResolved: true,
			claimRefsPreserved: true,
			sourceArtifactsPreserved: true,
		},
		errors: [],
		...overrides,
	};
}

describe("REPI worker runtime pure contracts", () => {
	it("accepts a complete worker runtime pool with claim-ledger proof chain", () => {
		const result = verifyWorkerRuntimePool(validPool());
		expect(result.ok).toBe(true);
		expect(result.evidenceContract.join("\n")).toContain(
			"artifact_handoff → claim → validation → challenge → resolution",
		);
	});

	it("rejects timeout without cancel, unresolved merge collisions, and incomplete claim refs", () => {
		const timeoutPool = validPool({
			workers: [{ ...validPool().workers[0], status: "timeout", cancelledAt: undefined }],
		});
		expect(verifyWorkerRuntimePool(timeoutPool).errors).toContain("timeout_without_cancel:w1");

		const duplicatePool = validPool({
			workers: [validPool().workers[0], { ...validPool().workers[0], workerId: "w2", sessionDir: "/tmp/repi/w2" }],
		});
		expect(verifyWorkerRuntimePool(duplicatePool).errors).toContain("duplicate_mergeKey_unresolved");

		const fakeResolvedDuplicatePool = validPool({
			workers: [validPool().workers[0], { ...validPool().workers[0], workerId: "w2", sessionDir: "/tmp/repi/w2" }],
			mergeProtocol: {
				strategy: "claim-aware merge",
				evidenceContract: [],
				conflicts: [
					{
						mergeKey: "claim-a",
						workers: ["w1"],
						status: "resolved",
						winner: "w9",
						evidenceRefs: [],
					},
				],
			},
		});
		expect(verifyWorkerRuntimePool(fakeResolvedDuplicatePool).errors).toEqual(
			expect.arrayContaining([
				"merge_conflict_workers_mismatch:claim-a",
				"merge_conflict_winner_invalid:claim-a",
				"merge_conflict_evidence_missing:claim-a",
				"merge_conflict_resolution_reason_missing:claim-a",
			]),
		);

		const incompleteClaimPool = validPool({
			claimLedgerEvents: [claimEvent("artifact_handoff"), claimEvent("claim")],
		});
		expect(verifyWorkerRuntimePool(incompleteClaimPool).errors).toEqual(
			expect.arrayContaining([
				"claim_without_validation:claim-a",
				"claim_without_challenge:claim-a",
				"claim_without_resolution:claim-a",
			]),
		);
	});

	it("rejects overlapping workers that exceed active resource or group budgets", () => {
		const secondWorker = {
			...validPool().workers[0],
			workerId: "w2",
			sessionDir: "/tmp/repi/w2",
			stdoutPath: "/tmp/repi/w2/stdout.log",
			stderrPath: "/tmp/repi/w2/stderr.log",
			mergeKey: "claim-b",
			claimRefs: ["claim-b"],
		};
		const overlappingPool = validPool({
			maxConcurrency: 2,
			resourceBudget: { cpuSlots: 1, memoryMb: 768, maxProcesses: 3 },
			workers: [validPool().workers[0], secondWorker],
			parallelGroups: [{ groupId: "g1", workers: ["w1", "w2"], dependsOn: [], maxConcurrency: 1 }],
			claimLedgerEvents: [
				...validPool().claimLedgerEvents,
				claimEvent("artifact_handoff", "claim-b"),
				claimEvent("claim", "claim-b"),
				claimEvent("validation", "claim-b"),
				claimEvent("challenge", "claim-b"),
				claimEvent("resolution", "claim-b"),
			],
		});

		expect(verifyWorkerRuntimePool(overlappingPool).errors).toEqual(
			expect.arrayContaining([
				"resource_cpu_active_exceeds_budget:2>1",
				"resource_memory_active_exceeds_budget:1024>768",
				"resource_process_active_exceeds_budget:4>3",
				"parallelGroup_maxConcurrency_exceeded:g1:2>1",
			]),
		);
	});

	it("validates worker lease scheduler hash-chain and rejection assertions", () => {
		expect(verifyWorkerLeaseSchedulerV1(validScheduler()).ok).toBe(true);

		const prevMismatch = validScheduler({
			events: validScheduler().events.map((event, index) =>
				index === 1 ? { ...event, prevHash: "b".repeat(64) } : event,
			),
		});
		expect(verifyWorkerLeaseSchedulerV1(prevMismatch).errors).toEqual(
			expect.arrayContaining([
				"worker_lease_scheduler_prev_hash_mismatch:e2",
				"worker_lease_scheduler_event_hash_mismatch:e2",
			]),
		);

		const duplicateCompletion = validScheduler({
			events: [
				...validScheduler().events,
				schedulerEvent("completed", "e4", validScheduler().events.at(-1)?.eventHash ?? ""),
			],
		});
		expect(verifyWorkerLeaseSchedulerV1(duplicateCompletion).errors).toContain(
			"worker_lease_scheduler_duplicate_completion:task-a",
		);

		const missingAssertions = validScheduler({
			assertions: { ...validScheduler().assertions, duplicateCompletionRejected: false },
		});
		expect(verifyWorkerLeaseSchedulerV1(missingAssertions).errors).toContain(
			"worker_lease_scheduler_duplicate_completion_rejection_missing",
		);
	});

	it("validates retry, timeout, and claim-bound handoff closure", () => {
		const result = verifyWorkerRetryHandoffClosureV1(validRetryHandoffClosure());
		expect(result.ok).toBe(true);
		expect(result.evidenceContract.join("\n")).toContain("runtime:retry-handoff-closure-validation");

		const overAttempt = validRetryHandoffClosure({
			workers: [{ ...validRetryHandoffClosure().workers[0], attempt: 4, retryRemaining: 0 }],
			assertions: { ...validRetryHandoffClosure().assertions, retryAttemptsBounded: false },
		});
		expect(verifyWorkerRetryHandoffClosureV1(overAttempt).errors).toEqual(
			expect.arrayContaining(["retry_handoff_attempt_exceeded:w1", "retry_handoff_attempts_not_bounded"]),
		);

		const timeoutNoCancel = validRetryHandoffClosure({
			workers: [
				{
					...validRetryHandoffClosure().workers[0],
					status: "timeout",
					timedOut: true,
					cancelledAt: undefined,
					retryState: "handoff_recovered",
					assertions: {
						...validRetryHandoffClosure().workers[0].assertions,
						timeoutCancellationRecorded: false,
					},
				},
			],
			assertions: {
				...validRetryHandoffClosure().assertions,
				timeoutCancellationRecorded: false,
			},
		});
		expect(verifyWorkerRetryHandoffClosureV1(timeoutNoCancel).errors).toContain(
			"retry_handoff_timeout_without_cancel:w1",
		);

		const failedWithoutClosure = validRetryHandoffClosure({
			workers: [
				{
					...validRetryHandoffClosure().workers[0],
					status: "failed",
					retryState: "blocked_without_closure",
					retryQueueRefs: [],
					handoffRefs: [],
					repairRefs: [],
					assertions: {
						...validRetryHandoffClosure().workers[0].assertions,
						failureHasRetryOrHandoff: false,
					},
				},
			],
			assertions: {
				...validRetryHandoffClosure().assertions,
				failedWorkersHaveRetryOrHandoff: false,
			},
		});
		expect(verifyWorkerRetryHandoffClosureV1(failedWithoutClosure).errors).toEqual(
			expect.arrayContaining([
				"retry_handoff_failed_without_closure:w1",
				"retry_handoff_worker_unclosed:w1",
				"retry_handoff_failures_not_closed",
			]),
		);

		const unresolvedCollision = validRetryHandoffClosure({
			merge: {
				...validRetryHandoffClosure().merge,
				collisions: [{ mergeKey: "claim-a", workers: ["w1", "w2"], status: "unresolved", evidenceRefs: [] }],
			},
			assertions: { ...validRetryHandoffClosure().assertions, mergeCollisionsResolved: false },
		});
		expect(verifyWorkerRetryHandoffClosureV1(unresolvedCollision).errors).toEqual(
			expect.arrayContaining([
				"retry_handoff_merge_collision_unresolved:claim-a",
				"retry_handoff_merge_collisions_unresolved",
			]),
		);

		const validCollision = validRetryHandoffClosure({
			workers: [
				validRetryHandoffClosure().workers[0],
				{
					...validRetryHandoffClosure().workers[0],
					workerId: "w2",
					claimRefs: ["claim-a"],
					handoffRefs: ["/tmp/repi/w2/runtime-manifest.json"],
					mergeKeys: ["claim-a"],
					sourceArtifacts: [
						"/tmp/repi/w2/runtime-manifest.json",
						"/tmp/repi/w2/stdout.log",
						"/tmp/repi/failure-ledger.jsonl",
						"artifact://validation",
					],
				},
			],
			merge: {
				strategy: "claim-bound handoff merge",
				recoveredWorkers: [],
				unresolvedWorkers: [],
				collisions: [
					{
						mergeKey: "claim-a",
						workers: ["w1", "w2"],
						status: "resolved",
						winner: "w1",
						evidenceRefs: ["artifact://validation"],
						resolutionReason:
							"w1 carries the verifier-accepted artifact hash and w2 is retained as corroboration",
					},
				],
			},
		});
		expect(verifyWorkerRetryHandoffClosureV1(validCollision).ok).toBe(true);

		const fakeResolvedCollision = validRetryHandoffClosure({
			merge: {
				...validRetryHandoffClosure().merge,
				collisions: [
					{
						mergeKey: "claim-a",
						workers: ["w1", "w2"],
						status: "resolved",
						winner: "w9",
						evidenceRefs: ["artifact://validation"],
					},
				],
			},
		});
		expect(verifyWorkerRetryHandoffClosureV1(fakeResolvedCollision).errors).toEqual(
			expect.arrayContaining([
				"retry_handoff_merge_collision_worker_unknown:claim-a:w2",
				"retry_handoff_merge_winner_not_in_collision:claim-a",
				"retry_handoff_merge_resolution_reason_missing:claim-a",
				"retry_handoff_merge_evidence_unbound:claim-a",
			]),
		);
	});

	it("summarizes retry handoff merge decisions without fake promotion", () => {
		const passSummary = buildWorkerRetryHandoffMergeSummaryV1(validRetryHandoffClosure());
		expect(passSummary.status).toBe("pass");
		expect(passSummary.nextActions).toContain("re_swarm merge && re_supervisor review");
		expect(verifyWorkerRetryHandoffMergeSummaryV1(passSummary)).toEqual({
			ok: true,
			errors: [],
			evidenceContract: expect.arrayContaining(["runtime:retry-handoff-merge-summary-validation"]),
		});

		const failedWithoutClosure = validRetryHandoffClosure({
			workers: [
				{
					...validRetryHandoffClosure().workers[0],
					status: "failed",
					retryState: "blocked_without_closure",
					retryQueueRefs: [],
					handoffRefs: [],
					repairRefs: [],
					assertions: {
						...validRetryHandoffClosure().workers[0].assertions,
						failureHasRetryOrHandoff: false,
					},
				},
			],
			merge: { ...validRetryHandoffClosure().merge, unresolvedWorkers: ["w1"] },
			assertions: {
				...validRetryHandoffClosure().assertions,
				failedWorkersHaveRetryOrHandoff: false,
			},
		});
		const blockedSummary = buildWorkerRetryHandoffMergeSummaryV1(failedWithoutClosure);
		expect(blockedSummary.status).toBe("blocked");
		expect(blockedSummary.unresolvedWorkers).toContain("w1");
		expect(blockedSummary.nextActions).toEqual(
			expect.arrayContaining(["re_supervisor repair worker=w1", "re_swarm retry worker=w1"]),
		);
		expect(verifyWorkerRetryHandoffMergeSummaryV1(blockedSummary).errors).toEqual(
			expect.arrayContaining([
				"retry_handoff_merge_summary_unresolved_workers",
				"retry_handoff_merge_summary_failures_unclosed",
			]),
		);

		const unresolvedCollision = validRetryHandoffClosure({
			merge: {
				...validRetryHandoffClosure().merge,
				collisions: [{ mergeKey: "claim-a", workers: ["w1", "w2"], status: "unresolved", evidenceRefs: [] }],
			},
			assertions: { ...validRetryHandoffClosure().assertions, mergeCollisionsResolved: false },
		});
		const collisionSummary = buildWorkerRetryHandoffMergeSummaryV1(unresolvedCollision);
		expect(collisionSummary.status).toBe("blocked");
		expect(collisionSummary.nextActions).toContain("re_supervisor repair mergeKey=claim-a");
		expect(verifyWorkerRetryHandoffMergeSummaryV1(collisionSummary).errors).toContain(
			"retry_handoff_merge_summary_collisions_unresolved",
		);

		const exhaustedClosure = validRetryHandoffClosure({
			workers: [
				{
					...validRetryHandoffClosure().workers[0],
					status: "exhausted",
					attempt: 3,
					retryRemaining: 0,
					retryState: "exhausted_escalated",
					repairRefs: ["/tmp/repi/failure-ledger.jsonl", "/tmp/repi/repair-queue.jsonl"],
					sourceArtifacts: [
						"/tmp/repi/w1/runtime-manifest.json",
						"/tmp/repi/w1/stdout.log",
						"/tmp/repi/failure-ledger.jsonl",
						"/tmp/repi/repair-queue.jsonl",
					],
				},
			],
		});
		const exhaustedSummary = buildWorkerRetryHandoffMergeSummaryV1(exhaustedClosure);
		expect(exhaustedSummary.status).toBe("pass");
		expect(exhaustedSummary.exhaustedEscalatedWorkers).toContain("w1");
		expect(exhaustedSummary.nextActions).toEqual(
			expect.arrayContaining(["re_autofix plan worker=w1 && re_supervisor repair"]),
		);

		const fakePass = {
			...blockedSummary,
			status: "pass" as const,
			assertions: { ...blockedSummary.assertions, noUnresolvedWorkers: true, allFailuresClosed: true },
		};
		expect(verifyWorkerRetryHandoffMergeSummaryV1(fakePass).errors).toEqual(
			expect.arrayContaining([
				"retry_handoff_merge_summary_fake_pass_unresolved_workers",
				"retry_handoff_merge_summary_pass_with_blockers",
			]),
		);
	});

	it("builds a safe child-session launch policy and verifies child runtime wiring", () => {
		const launchPolicy = workerChildSessionLaunchPolicy({
			cwd: "/work/project",
			isolatedHome: "/tmp/repi/.repi/agent",
			timeoutMs: 60_000,
		});
		expect(launchPolicy.command).toBe("repi");
		expect(launchPolicy.args).toEqual(expect.arrayContaining(["--recon", "--worker-runtime"]));
		expect(launchPolicy.isolatedHome).toContain(".repi");
		expect(launchPolicy.isolatedHome).not.toContain("/.pi/");
		expect(launchPolicy.importPiAuth).toBe(false);
		expect(launchPolicy.updateChecksDisabled).toBe(true);
		expect(launchPolicy.telemetryDisabled).toBe(true);
		expect(launchPolicy.envAllowlist).toEqual(
			expect.arrayContaining([
				"REPI_AUTH_TOKEN",
				"REPI_BASE_URL",
				"REPI_MODEL",
				"REPI_MODEL_API",
				"REPI_SUBAGENT_MODEL",
				"REPI_CONTEXT_WINDOW",
				"REPI_AUTO_COMPACT_WINDOW",
			]),
		);
		expect(launchPolicy.envDenylist).toEqual(
			expect.arrayContaining(["GITHUB_TOKEN", "ANTHROPIC_AUTH_TOKEN", "NPM_TOKEN"]),
		);

		const batch: RepiWorkerChildSessionRuntimeBatchV1 = {
			kind: "WorkerChildSessionRuntimeBatchV1",
			schemaVersion: 1,
			batchId: "batch-a",
			poolId: "pool-a",
			resourceBudget: { cpuSlots: 4, memoryMb: 4096, maxProcesses: 8 },
			launchPolicy,
			sessions: [
				{
					sessionId: "child-w1-1",
					workerId: "w1",
					packetId: "packet-a",
					attempt: 1,
					maxAttempts: 3,
					provider: {
						format: "openai-compatible",
						name: "env-provider",
						modelId: "env-model",
						baseUrlRef: "$REPI_BASE_URL",
						apiKeyRef: "$REPI_AUTH_TOKEN",
						contextWindow: 262_144,
						maxTokens: 8192,
					},
					runtime: {
						status: "passed",
						sessionDir: "/tmp/repi/w1",
						transcriptPath: "/tmp/repi/w1/transcript.jsonl",
						stdoutPath: "/tmp/repi/w1/stdout.log",
						stderrPath: "/tmp/repi/w1/stderr.log",
						startedAt: ts,
						endedAt: "2026-07-03T00:00:01.000Z",
					},
					hashes: { transcriptSha256: sha, stdoutSha256: sha, stderrSha256: sha, toolCallDigest: sha },
					resourceLease: { cpuSlots: 1, memoryMb: 512, maxProcesses: 2 },
					retryBudget: { signature: "sig", attempt: 1, maxAttempts: 3, remaining: 2, exhausted: false },
					poolBridge: {
						poolId: "pool-a",
						mergeKey: "claim-a",
						claimRefs: ["claim-a"],
						workerRuntimePoolStatus: "done",
					},
					failureRepairRefs: [],
				},
			],
			claimLedgerEvents: [
				claimEvent("artifact_handoff"),
				claimEvent("claim"),
				claimEvent("validation"),
				claimEvent("challenge"),
				claimEvent("resolution"),
			],
			poolBridge: {
				kind: "WorkerRuntimePoolV1Bridge",
				poolId: "pool-a",
				workerIds: ["w1"],
				claimAwareMerge: true,
				childSessionRuntimeCaptured: true,
			},
		};
		expect(workerChildSessionRuntimeBridgeEvidenceContract().join("\n")).toContain(
			"runtime:child-session-pool-bridge-validation",
		);
		expect(verifyWorkerChildSessionRuntimeBatch(batch)).toEqual({ ok: true, errors: [] });
		expect(verifyWorkerRuntimePool(workerChildSessionToWorkerRuntimePoolBridge(batch)).ok).toBe(true);
		expect(
			verifyWorkerChildSessionRuntimeBatch({
				...batch,
				sessions: [
					{ ...batch.sessions[0], provider: { ...batch.sessions[0].provider, apiKeyRef: "literal-secret" } },
				],
			}).errors,
		).toContain("child_session_literal_api_key:child-w1-1");
		expect(
			verifyWorkerChildSessionRuntimeBatch({
				...batch,
				launchPolicy: {
					...batch.launchPolicy,
					envAllowlist: batch.launchPolicy.envAllowlist.filter((name) => name !== "REPI_AUTH_TOKEN"),
				},
			}).errors,
		).toContain("child_session_provider_env_not_allowlisted:child-w1-1:REPI_AUTH_TOKEN");
		expect(
			verifyWorkerChildSessionRuntimeBatch({
				...batch,
				launchPolicy: {
					...batch.launchPolicy,
					envDenylist: [...batch.launchPolicy.envDenylist, "REPI_AUTH_TOKEN"],
				},
			}).errors,
		).toContain("child_session_provider_env_denied:child-w1-1:REPI_AUTH_TOKEN");
		expect(
			verifyWorkerChildSessionRuntimeBatch({
				...batch,
				poolBridge: {
					...batch.poolBridge,
					workerIds: ["w9"],
					claimAwareMerge: false,
					childSessionRuntimeCaptured: false,
				},
			}).errors,
		).toEqual(
			expect.arrayContaining([
				"child_session_claim_aware_merge_missing",
				"child_session_runtime_not_captured",
				"child_session_pool_bridge_workerIds_mismatch",
			]),
		);
		expect(
			verifyWorkerChildSessionRuntimeBatch({
				...batch,
				sessions: [
					{
						...batch.sessions[0],
						runtime: { ...batch.sessions[0].runtime, status: "failed" },
						poolBridge: { ...batch.sessions[0].poolBridge, workerRuntimePoolStatus: "done" },
					},
				],
			}).errors,
		).toContain("child_session_pool_status_mismatch:child-w1-1");
		expect(
			verifyWorkerChildSessionRuntimeBatch({
				...batch,
				claimLedgerEvents: batch.claimLedgerEvents.map((event) => ({
					...event,
					source: "worker-child-session" as const,
				})),
			}).errors,
		).toEqual(
			expect.arrayContaining([
				"child_session_pool_bridge:claim_without_artifact_handoff:claim-a",
				"child_session_pool_bridge:claim_without_validation:claim-a",
				"child_session_pool_bridge:claim_without_resolution:claim-a",
			]),
		);
	});
});

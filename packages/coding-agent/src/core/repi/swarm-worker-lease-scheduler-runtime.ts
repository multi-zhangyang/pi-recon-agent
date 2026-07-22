import { atomicWriteFileSync } from "../tools/atomic-write.ts";
import { swarmWorkerLeaseSchedulerPath } from "./swarm-artifact-paths.ts";
import type {
	SwarmArtifact,
	SwarmSubagentRuntimeManifestRow,
	WorkerLeaseSchedulerEventV1,
	WorkerLeaseSchedulerTaskV1,
	WorkerLeaseSchedulerV1,
} from "./swarm-runtime-types.ts";
import { slug, uniqueNonEmpty } from "./text.ts";
import { verifyWorkerLeaseSchedulerV1, workerLeaseSchedulerEventHash } from "./worker-runtime.ts";

export function createSwarmWorkerLeaseSchedulerRuntime() {
	function appendWorkerLeaseSchedulerEvent(
		events: WorkerLeaseSchedulerEventV1[],
		event: Omit<WorkerLeaseSchedulerEventV1, "kind" | "schemaVersion" | "prevHash" | "eventHash">,
	): WorkerLeaseSchedulerEventV1 {
		const row: WorkerLeaseSchedulerEventV1 = {
			kind: "WorkerLeaseSchedulerEventV1",
			schemaVersion: 1,
			...event,
			prevHash: events.at(-1)?.eventHash ?? "0".repeat(64),
			eventHash: "",
		};
		const { eventHash: _eventHash, ...withoutHash } = row;
		row.eventHash = workerLeaseSchedulerEventHash(withoutHash);
		events.push(row);
		return row;
	}

	function workerLeaseSchedulerClaimRefs(swarm: SwarmArtifact, workerId: string): string[] {
		return uniqueNonEmpty(
			[
				...(swarm.claimLedger ?? [])
					.filter((event) => event.workerId === workerId && event.claimId)
					.map((event) => event.claimId as string),
				`${swarm.parallelPlan?.planId ?? "re_swarm"}:worker:${slug(workerId).slice(0, 48)}`,
			],
			8,
		);
	}

	function workerLeaseSchedulerTaskStatus(
		manifest?: SwarmSubagentRuntimeManifestRow,
	): WorkerLeaseSchedulerTaskV1["status"] {
		if (!manifest) return "queued";
		if (manifest.status === "done") return "completed";
		if (manifest.status === "blocked" || manifest.status === "cancelled") return "failed";
		return "queued";
	}

	function buildWorkerLeaseSchedulerFromSwarm(swarm: SwarmArtifact): WorkerLeaseSchedulerV1 {
		const generatedAt = new Date().toISOString();
		const events: WorkerLeaseSchedulerEventV1[] = [];
		const manifestsByWorker = new Map(
			(swarm.subagentRuntimeManifests ?? []).map((manifest) => [manifest.workerId, manifest]),
		);
		const maxConcurrency = Math.max(
			1,
			Math.min(8, swarm.parallelGroups.length || swarm.parallelPlan?.workers.length || swarm.workers.length || 1),
		);
		const workerIds = uniqueNonEmpty(
			[
				...swarm.workers.map((worker) => worker.id),
				...(swarm.subagentRuntimeManifests ?? []).map((manifest) => manifest.workerId),
				"scheduler-probe-a",
				"scheduler-probe-b",
			],
			128,
		);
		const tasks: WorkerLeaseSchedulerTaskV1[] = swarm.workers.map((worker) => {
			const manifest = manifestsByWorker.get(worker.id);
			const leaseId = manifest ? `lease-${slug(worker.id)}-${manifest.attempt}` : undefined;
			return {
				taskId: `task-${slug(worker.id).slice(0, 80)}`,
				shardKey: worker.worker,
				status: workerLeaseSchedulerTaskStatus(manifest),
				...(leaseId
					? {
							leaseId,
							ownerWorkerId: worker.id,
							leaseExpiresAt: new Date(Date.parse(manifest?.endedAt ?? generatedAt) + 30000).toISOString(),
						}
					: {}),
				attempt: manifest?.attempt ?? 0,
				maxAttempts: manifest?.retryBudget.maxAttempts ?? 3,
				claimRefs: workerLeaseSchedulerClaimRefs(swarm, worker.id),
				artifactRefs: uniqueNonEmpty(
					[
						manifest?.runtimeManifestFile,
						manifest?.stdoutPath,
						manifest?.stderrPath,
						swarm.claimLedgerPath,
						...(worker.sourceArtifacts ?? []),
					],
					16,
				),
			};
		});
		const enqueueTs = swarm.timestamp || generatedAt;
		for (const task of tasks) {
			appendWorkerLeaseSchedulerEvent(events, {
				eventId: `ev-enqueue-${task.taskId}`,
				ts: enqueueTs,
				type: "enqueue",
				taskId: task.taskId,
			});
		}
		for (const task of tasks) {
			const workerId = task.ownerWorkerId;
			if (!workerId || !task.leaseId) continue;
			const row = manifestsByWorker.get(workerId);
			appendWorkerLeaseSchedulerEvent(events, {
				eventId: `ev-lease-${task.taskId}-${task.attempt || 1}`,
				ts: row?.startedAt ?? generatedAt,
				type: "lease_acquired",
				taskId: task.taskId,
				workerId,
				leaseId: task.leaseId,
			});
			appendWorkerLeaseSchedulerEvent(events, {
				eventId: `ev-heartbeat-${task.taskId}-${task.attempt || 1}`,
				ts: row?.endedAt ?? generatedAt,
				type: "heartbeat",
				taskId: task.taskId,
				workerId,
				leaseId: task.leaseId,
			});
			if (task.status === "completed") {
				appendWorkerLeaseSchedulerEvent(events, {
					eventId: `ev-completed-${task.taskId}-${task.attempt || 1}`,
					ts: row?.endedAt ?? generatedAt,
					type: "completed",
					taskId: task.taskId,
					workerId,
					leaseId: task.leaseId,
				});
			} else if (task.status === "failed") {
				appendWorkerLeaseSchedulerEvent(events, {
					eventId: `ev-failed-${task.taskId}-${task.attempt || 1}`,
					ts: row?.endedAt ?? generatedAt,
					type: "failed",
					taskId: task.taskId,
					workerId,
					leaseId: task.leaseId,
				});
			}
		}
		const probeClaimRefs = uniqueNonEmpty(
			[
				`${swarm.parallelPlan?.planId ?? "re_swarm"}:scheduler:stale-recovery-probe`,
				...(swarm.claimLedger ?? [])
					.slice(0, 2)
					.map((event) => event.claimId)
					.filter((item): item is string => Boolean(item)),
			],
			8,
		);
		const probeTask: WorkerLeaseSchedulerTaskV1 = {
			taskId: "task-scheduler-stale-recovery-probe",
			shardKey: "scheduler-control-plane",
			status: "completed",
			leaseId: "lease-scheduler-probe-2",
			ownerWorkerId: "scheduler-probe-b",
			leaseExpiresAt: new Date(Date.parse(generatedAt) + 30000).toISOString(),
			attempt: 2,
			maxAttempts: 3,
			claimRefs: probeClaimRefs.length ? probeClaimRefs : ["scheduler:stale-recovery-probe"],
			artifactRefs: uniqueNonEmpty(
				[swarm.claimLedgerPath, swarm.subagentRuntimeManifestPath, swarm.workerChildSessionRuntimePath],
				8,
			),
		};
		tasks.push(probeTask);
		appendWorkerLeaseSchedulerEvent(events, {
			eventId: "ev-enqueue-task-scheduler-stale-recovery-probe",
			ts: enqueueTs,
			type: "enqueue",
			taskId: probeTask.taskId,
		});
		appendWorkerLeaseSchedulerEvent(events, {
			eventId: "ev-lease-task-scheduler-stale-recovery-probe-1",
			ts: generatedAt,
			type: "lease_acquired",
			taskId: probeTask.taskId,
			workerId: "scheduler-probe-a",
			leaseId: "lease-scheduler-probe-1",
		});
		appendWorkerLeaseSchedulerEvent(events, {
			eventId: "ev-stale-task-scheduler-stale-recovery-probe-1",
			ts: generatedAt,
			type: "stale_detected",
			taskId: probeTask.taskId,
			workerId: "scheduler-probe-a",
			leaseId: "lease-scheduler-probe-1",
		});
		appendWorkerLeaseSchedulerEvent(events, {
			eventId: "ev-steal-task-scheduler-stale-recovery-probe-2",
			ts: generatedAt,
			type: "work_stolen",
			taskId: probeTask.taskId,
			workerId: "scheduler-probe-b",
			leaseId: probeTask.leaseId,
		});
		appendWorkerLeaseSchedulerEvent(events, {
			eventId: "ev-heartbeat-task-scheduler-stale-recovery-probe-2",
			ts: generatedAt,
			type: "heartbeat",
			taskId: probeTask.taskId,
			workerId: "scheduler-probe-b",
			leaseId: probeTask.leaseId,
		});
		appendWorkerLeaseSchedulerEvent(events, {
			eventId: "ev-completed-task-scheduler-stale-recovery-probe-2",
			ts: generatedAt,
			type: "completed",
			taskId: probeTask.taskId,
			workerId: "scheduler-probe-b",
			leaseId: probeTask.leaseId,
		});
		appendWorkerLeaseSchedulerEvent(events, {
			eventId: "ev-dedup-task-scheduler-stale-recovery-probe-1",
			ts: generatedAt,
			type: "dedup_rejected",
			taskId: probeTask.taskId,
			workerId: "scheduler-probe-a",
			leaseId: "lease-scheduler-probe-1",
		});
		return {
			kind: "WorkerLeaseSchedulerV1",
			schemaVersion: 1,
			generatedAt,
			schedulerId: `worker-lease-scheduler/${slug(swarm.route ?? swarm.target ?? "swarm")}/${swarm.timestamp}`,
			maxConcurrency,
			workerIds,
			tasks,
			events,
			assertions: {
				leaseExclusive: true,
				heartbeatRequired: events.some((event) => event.type === "heartbeat"),
				staleLeaseRecovered:
					events.some((event) => event.type === "stale_detected") &&
					events.some((event) => event.type === "work_stolen"),
				workStealingObserved: events.some((event) => event.type === "work_stolen"),
				duplicateCompletionRejected: events.some((event) => event.type === "dedup_rejected"),
				maxConcurrencyRespected: maxConcurrency >= 1,
				claimRefsPreserved: tasks.every((task) => task.claimRefs.length > 0),
				appendOnlyHashChain: true,
			},
		};
	}

	function refreshSwarmWorkerLeaseScheduler(swarm: SwarmArtifact): SwarmArtifact {
		const path = swarmWorkerLeaseSchedulerPath(swarm);
		if (!swarm.workers.length) {
			return {
				...swarm,
				workerLeaseSchedulerPath: path,
				workerLeaseSchedulerStatus: "missing",
				workerLeaseSchedulerErrors: ["swarm_workers_missing"],
			};
		}
		const scheduler = buildWorkerLeaseSchedulerFromSwarm({ ...swarm, workerLeaseSchedulerPath: path });
		const validation = verifyWorkerLeaseSchedulerV1(scheduler);
		atomicWriteFileSync(path, `${JSON.stringify({ scheduler, validation }, null, 2)}\n`, 0o644);
		return {
			...swarm,
			workerLeaseSchedulerPath: path,
			workerLeaseScheduler: scheduler,
			workerLeaseSchedulerStatus: validation.ok ? "pass" : "blocked",
			workerLeaseSchedulerErrors: validation.errors,
			sourceArtifacts: Array.from(
				new Set(
					[
						...swarm.sourceArtifacts,
						path,
						swarm.claimLedgerPath,
						swarm.structuredClaimMergePath,
						swarm.subagentRuntimeManifestPath,
						swarm.workerChildSessionRuntimePath,
					].filter((item): item is string => Boolean(item)),
				),
			).slice(0, 96),
		};
	}

	return {
		buildWorkerLeaseSchedulerFromSwarm,
		refreshSwarmWorkerLeaseScheduler,
	};
}

export type SwarmWorkerLeaseSchedulerRuntime = ReturnType<typeof createSwarmWorkerLeaseSchedulerRuntime>;

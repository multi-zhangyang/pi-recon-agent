import type { SwarmWorkerExecution } from "./swarm-runtime-types.ts";
import { createSwarmWorkerChildSessionRuntime } from "./swarm-worker-child-session-runtime.ts";
import { createSwarmWorkerLeaseSchedulerRuntime } from "./swarm-worker-lease-scheduler-runtime.ts";
import { createSwarmWorkerRetryHandoffRuntime } from "./swarm-worker-retry-handoff-runtime.ts";

export type SwarmWorkerArtifactRuntimeDependencies = {
	executionDigest(value: string): string;
	executionFailed(execution: SwarmWorkerExecution): boolean;
	terminalExecutions(executions: readonly SwarmWorkerExecution[]): SwarmWorkerExecution[];
};

export function createSwarmWorkerArtifactRuntime(dependencies: SwarmWorkerArtifactRuntimeDependencies) {
	const childSessions = createSwarmWorkerChildSessionRuntime({
		executionDigest: dependencies.executionDigest,
	});
	const retryHandoffs = createSwarmWorkerRetryHandoffRuntime({
		executionFailed: dependencies.executionFailed,
		terminalExecutions: dependencies.terminalExecutions,
	});
	const leaseScheduler = createSwarmWorkerLeaseSchedulerRuntime();

	return {
		...childSessions,
		...retryHandoffs,
		...leaseScheduler,
	};
}

export type SwarmWorkerArtifactRuntime = ReturnType<typeof createSwarmWorkerArtifactRuntime>;

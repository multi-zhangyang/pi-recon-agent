import type { AgentThreadRunManifest, AgentThreadStatus } from "../agent-thread-contract.ts";
import { sha256 } from "../agent-thread-runtime.ts";

/** Stable machine-readable result returned by the re_subagent tool. */
export interface RepiSubagentResultV1 {
	kind: "RepiSubagentResultV1";
	schemaVersion: 1;
	status: AgentThreadStatus;
	exitCode: number | null;
	runId: string | null;
	spec: string;
	task: string;
	taskSha256: string | null;
	missionId: string | null;
	runRoot: string | null;
	mergePath: string | null;
	handoffPath: string | null;
	handoffPresent: boolean;
	handoffRecovered: boolean;
	handoffBytes: number | null;
	handoffSha256: string | null;
	handoffRunId: string | null;
	handoffMissionId: string | null;
	handoffLineageSha256: string | null;
	handoffLineageValid: boolean;
	lineageSha256: string | null;
	error?: string;
}

function nullableString(value: string | undefined): string | null {
	return value?.trim() ? value : null;
}

/** Convert the persisted AgentThread manifest into the parent-verifiable result contract. */
export function repiSubagentResultFromManifest(manifest: AgentThreadRunManifest): RepiSubagentResultV1 {
	const result: RepiSubagentResultV1 = {
		kind: "RepiSubagentResultV1",
		schemaVersion: 1,
		status: manifest.status,
		exitCode: manifest.exitCode ?? null,
		runId: manifest.runId,
		spec: manifest.specName,
		task: manifest.task,
		taskSha256: nullableString(manifest.taskSha256),
		missionId: nullableString(manifest.missionId),
		runRoot: manifest.runRoot,
		mergePath: nullableString(manifest.mergePath),
		handoffPath: nullableString(manifest.handoffPath),
		handoffPresent: manifest.handoffPresent === true,
		handoffRecovered: manifest.handoffRecovered === true,
		handoffBytes: manifest.handoffBytes ?? null,
		handoffSha256: nullableString(manifest.handoffSha256),
		handoffRunId: nullableString(manifest.handoffRunId),
		handoffMissionId: nullableString(manifest.handoffMissionId),
		handoffLineageSha256: nullableString(manifest.handoffLineageSha256),
		handoffLineageValid: manifest.handoffLineageValid === true,
		lineageSha256: nullableString(manifest.lineageSha256),
	};
	if (manifest.status !== "complete" || manifest.exitCode !== 0) {
		result.error =
			manifest.error ?? `Agent thread ended with status=${manifest.status} exitCode=${manifest.exitCode ?? "null"}`;
	}
	return result;
}

/** Build a truthful result when no run manifest was created (for example admission/spawn failure). */
export async function repiSubagentFailureResult(options: {
	spec: string;
	task: string;
	missionId?: string;
	error: string;
}): Promise<RepiSubagentResultV1> {
	return {
		kind: "RepiSubagentResultV1",
		schemaVersion: 1,
		status: "failed",
		exitCode: null,
		runId: null,
		spec: options.spec,
		task: options.task,
		taskSha256: await sha256(options.task),
		missionId: options.missionId ?? null,
		runRoot: null,
		mergePath: null,
		handoffPath: null,
		handoffPresent: false,
		handoffRecovered: false,
		handoffBytes: null,
		handoffSha256: null,
		handoffRunId: null,
		handoffMissionId: null,
		handoffLineageSha256: null,
		handoffLineageValid: false,
		lineageSha256: null,
		error: options.error,
	};
}

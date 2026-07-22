export type AgentThreadStatus = "planned" | "running" | "complete" | "failed" | "timeout" | "stopped";

export interface AgentThreadRunManifest {
	kind: "repi-agent-thread-run";
	schemaVersion: 1;
	runId: string;
	specName: string;
	task: string;
	status: AgentThreadStatus;
	createdAt: string;
	startedAt?: string;
	endedAt?: string;
	pid?: number;
	exitCode?: number | null;
	signal?: string | null;
	cwd: string;
	runRoot: string;
	agentDir: string;
	stdoutPath: string;
	stderrPath: string;
	manifestPath: string;
	mergePath?: string;
	handoffPath?: string;
	handoffPresent?: boolean;
	handoffRecovered?: boolean;
	handoffBytes?: number;
	handoffSha256?: string;
	handoffRunId?: string;
	handoffMissionId?: string;
	handoffLineageSha256?: string;
	handoffLineageValid?: boolean;
	provider?: string;
	model?: string;
	taskSha256?: string;
	/** Stable parent cancellation/lineage metadata for control-plane consumers. */
	parentRunId?: string;
	missionId?: string;
	parentLineageSha256?: string;
	lineageSha256?: string;
	tools: string[];
	timeoutMs?: number;
	maxTurns?: number;
	cancelSignal?: "SIGTERM";
	cancelledAt?: string;
	mcpServers?: string[];
	mcpTools?: string[];
	mcpToolFilterActive?: boolean;
	mcpInherited?: boolean;
	promptSha256?: string;
	stdoutSha256?: string;
	stderrSha256?: string;
	error?: string;
}

export interface SpawnAgentThreadOptions {
	specName?: string;
	task: string;
	provider?: string;
	model?: string;
	cwd?: string;
	timeoutMs?: number;
	additionalPrompt?: string;
	mcpServers?: string[];
	mcpTools?: string[];
	inheritMcp?: boolean;
	/** Abort the child when the parent tool/run is cancelled. */
	signal?: AbortSignal;
	/** Optional lineage identifiers; never inferred from free-form task text. */
	parentRunId?: string;
	missionId?: string;
	parentLineageSha256?: string;
}

export interface AgentThreadManagerOptions {
	cwd: string;
	agentDir?: string;
	repiBinPath?: string;
}

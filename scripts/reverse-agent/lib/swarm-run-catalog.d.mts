export const SWARM_RUN_REF_KIND: "SwarmRunRefV1";
export const SWARM_CATALOG_SCHEMA_VERSION: 1;

export type SwarmRunEngine = "cli" | "ts";
export type SwarmRunState = "planned" | "complete" | "failed" | "unknown";
export type SwarmRunMode = "plan" | "run" | "merge";

export interface SwarmRunPaths {
	root: string;
	evidenceRoot: string;
	plan?: string;
	report?: string;
	mergeReport?: string;
	artifact?: string;
	claimLedger?: string;
	structuredClaimMerge?: string;
	subagentRuntimeManifests?: string;
}

export interface SwarmRunWorker {
	workerId: string;
	role?: string;
	status: "pass" | "fail" | "running" | "planned";
	exit: number | null;
	ms: number;
}

export interface SwarmRunMergeSummary {
	ok: boolean;
	promotedClaims: number;
	narrativeOnlyBlocked: boolean;
	structuredClaimMergeStatus: "pass" | "blocked" | "missing";
}

export interface SwarmRunRef {
	kind: typeof SWARM_RUN_REF_KIND;
	schemaVersion: typeof SWARM_CATALOG_SCHEMA_VERSION;
	engine: SwarmRunEngine;
	runId: string;
	path: string;
	evidenceRoot: string;
	paths: SwarmRunPaths;
	generatedAt?: string;
	createdAtMs: number;
	state: SwarmRunState;
	status: SwarmRunState;
	ok: boolean;
	target?: string;
	mode?: SwarmRunMode;
	workerCount?: number;
	workers?: SwarmRunWorker[];
	merge?: SwarmRunMergeSummary;
}

export interface SerializedSwarmRunRef {
	kind: typeof SWARM_RUN_REF_KIND;
	schemaVersion: typeof SWARM_CATALOG_SCHEMA_VERSION;
	engine: SwarmRunEngine;
	ref: string;
	runId: string;
	generatedAt?: string;
	createdAtMs: number;
	state: SwarmRunState;
	status: SwarmRunState;
	ok: boolean;
	target?: string;
	mode?: SwarmRunMode;
	workerCount?: number;
	evidenceRoot: string;
	artifactPath?: string;
	paths: SwarmRunPaths;
	workers?: SwarmRunWorker[];
	merge?: SwarmRunMergeSummary;
}

export interface DiscoverSwarmRunsOptions {
	agentDir?: string;
	cliRoot?: string;
	tsRoot?: string;
}

export interface SwarmRunResolutionSuccess {
	ok: true;
	ref: string;
	run: SwarmRunRef;
}

export interface SwarmRunResolutionFailure {
	ok: false;
	error: "run-not-found" | "run-ref-ambiguous";
	message: string;
	ref: string;
	matches: string[];
	candidateRefs: string[];
}

export type SwarmRunResolution = SwarmRunResolutionSuccess | SwarmRunResolutionFailure;

export interface SwarmRunCatalog {
	discover(): SwarmRunRef[];
	listRuns(): SwarmRunRef[];
	resolveRunRef(ref?: string): SwarmRunResolution;
}

export function discoverSwarmRuns(options?: DiscoverSwarmRunsOptions): SwarmRunRef[];
export function resolveSwarmRunRef(runs: readonly SwarmRunRef[], ref?: string): SwarmRunResolution;
export function createSwarmRunCatalog(options?: DiscoverSwarmRunsOptions): SwarmRunCatalog;
export function serializeSwarmRunRef(run: SwarmRunRef): SerializedSwarmRunRef;

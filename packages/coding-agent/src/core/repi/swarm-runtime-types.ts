import type { ExtensionAPI } from "../extensions/types.ts";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import type { EvidenceRecord } from "./evidence.ts";
import type { MissionCheckpointStatus, MissionState } from "./mission.ts";
import type {
	RepiFailureRepairArtifactHash,
	RepiSwarmClaimLedgerEventV1,
	RepiSwarmRuntimeRetryBudget,
	RepiSwarmRuntimeState,
	RepiWorkerChildProcessProbeV1,
	RepiWorkerChildSessionClaimLedgerEventV1,
	RepiWorkerChildSessionRuntimeBatchV1,
	RepiWorkerChildSessionRuntimeStatus,
	RepiWorkerChildSessionRuntimeV1,
	RepiWorkerLeaseSchedulerEventV1,
	RepiWorkerLeaseSchedulerTaskV1,
	RepiWorkerLeaseSchedulerV1,
	RepiWorkerRetryHandoffClosureV1,
	RepiWorkerRetryHandoffMergeSummaryV1,
	RepiWorkerRuntimePoolV1,
	RepiWorkerRuntimePoolWorkerV1,
} from "./worker-runtime.ts";

export type OperationStepStatus = "ready" | "done" | "blocked" | "skipped";

export type OperationStep = {
	id: string;
	phase: string;
	command: string;
	status: OperationStepStatus;
	reason?: string;
	sourceArtifacts: string[];
};

export type OperationExecution = {
	stepId: string;
	command: string;
	status: OperationStepStatus;
	output: string;
};

export type SwarmOperatorStep = {
	id: string;
	command: string;
	status: OperationStepStatus;
	priority: number;
	reason?: string;
	sourceArtifacts: string[];
};

export type AutonomousExecutionBudget = {
	maxTurns: number;
	maxDispatch: number;
	maxProofLoops: number;
	maxWorkerRetries: number;
	scoreDecay: string[];
	demotionRules: string[];
	laneDemotions: string[];
	workerDemotions: string[];
	dispatcherDemotions: string[];
	promotionRules: string[];
	nextActions: string[];
};

export type DelegateWorker =
	| "web-authz"
	| "identity"
	| "cloud"
	| "mobile-runtime"
	| "native-runtime"
	| "pwn-exploit"
	| "firmware-dfir"
	| "agentsec"
	| "malware"
	| "reporting"
	| "general";

export type DelegatePacket = {
	id: string;
	worker: DelegateWorker;
	objective: string;
	status: "ready" | "blocked" | "done";
	phases: string[];
	steps: OperationStep[];
	evidenceContract: string[];
	recommendedTools: string[];
	handoffPrompt: string[];
	sourceArtifacts: string[];
};

export type DelegateArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "merge";
	operationArtifact?: string;
	packets: DelegatePacket[];
	mergeQueue: string[];
	specialistCoverage: string[];
	workerScoreboard: string[];
	adaptiveRoutingHints: string[];
	workerPromotionQueue: string[];
	autonomousBudget: AutonomousExecutionBudget;
	dispatcherScoreDecay: string[];
	repeatedFailureDemotions: string[];
	highScorePromotions: string[];
	gaps: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

export type SwarmWorkerRuntime = {
	id: string;
	worker: DelegateWorker;
	status: "ready" | "blocked" | "done" | "merged";
	objective: string;
	spawnPrompt: string[];
	commands: string[];
	evidenceContract: string[];
	mergeKeys: string[];
	dependencies: string[];
	recommendedTools: string[];
	sourceArtifacts: string[];
};

export type SwarmWorkerExecution = {
	workerId: string;
	worker: DelegateWorker;
	command: string;
	status: OperationStepStatus;
	output: string;
	stdout?: string;
	stderr?: string;
	stdoutSha256?: string;
	stderrSha256?: string;
	startedAt?: string;
	endedAt?: string;
	elapsedMs?: number;
	pid?: number | null;
	parentPid?: number | null;
	exitCode?: number | null;
	signal?: string | null;
	timeoutMs?: number;
	timedOut?: boolean;
	cancelledAt?: string;
	retryAttempt?: number;
	sourceArtifacts: string[];
};

export type SwarmRuntimeState = RepiSwarmRuntimeState;

export type SwarmRuntimeModelSummary = {
	provider: string;
	modelId: string;
	modelCalls: number;
	toolCalls: number;
	toolResults: number;
};

export type SwarmRuntimeRetryBudget = RepiSwarmRuntimeRetryBudget;
export type FailureRepairArtifactHash = RepiFailureRepairArtifactHash;
export type SwarmClaimLedgerEventV1 = RepiSwarmClaimLedgerEventV1;
export type WorkerRuntimePoolWorkerV1 = RepiWorkerRuntimePoolWorkerV1;
export type WorkerRuntimePoolV1 = RepiWorkerRuntimePoolV1;
export type WorkerChildSessionRuntimeStatus = RepiWorkerChildSessionRuntimeStatus;
export type WorkerChildSessionRuntimeV1 = RepiWorkerChildSessionRuntimeV1;
export type WorkerChildSessionClaimLedgerEventV1 = RepiWorkerChildSessionClaimLedgerEventV1;
export type WorkerChildProcessProbeV1 = RepiWorkerChildProcessProbeV1;
export type WorkerChildSessionRuntimeBatchV1 = RepiWorkerChildSessionRuntimeBatchV1;
export type WorkerLeaseSchedulerTaskV1 = RepiWorkerLeaseSchedulerTaskV1;
export type WorkerLeaseSchedulerEventV1 = RepiWorkerLeaseSchedulerEventV1;
export type WorkerLeaseSchedulerV1 = RepiWorkerLeaseSchedulerV1;

export type SwarmSubagentRuntimeManifestV1 = {
	kind: "SubagentRuntimeManifestV1";
	schemaVersion: 1;
	runId: string;
	roleId: DelegateWorker;
	workerId: string;
	attempt: number;
	status: SwarmRuntimeState;
	pid: number | null;
	parentPid: number | null;
	sessionDir: string;
	stdoutPath: string;
	stderrPath: string;
	stdoutSha256: string;
	stderrSha256: string;
	startedAt: string;
	endedAt: string;
	elapsedMs: number;
	exitCode: number | null;
	signal: string | null;
	model: SwarmRuntimeModelSummary;
	toolCallDigest: string;
	claimLedgerPath: string;
	failureLedgerPath: string;
	repairQueuePath: string;
	resourceLimits: {
		timeoutMs: number;
		maxCommands: number;
		maxOutputBytes: number;
		cancelOnTimeout: boolean;
	};
	retryBudget: SwarmRuntimeRetryBudget;
	mergeKeys: string[];
	evidenceRefs: string[];
};

export type SwarmSubagentRuntimeManifestRow = SwarmSubagentRuntimeManifestV1 & {
	runtimeManifestFile: string;
};

export type StructuredClaimArtifactRefV1 = {
	artifactId: string;
	path: string;
	sha256: string;
	jsonQuery: string;
	op: "==" | "contains" | "includes_all";
	expected: unknown;
	verifierPass: boolean;
};

export type StructuredClaimRowV1 = {
	claimId: string;
	workerId: string;
	mergeKey: string;
	status: "proven" | "gap" | "contradicted" | "pending";
	statement: string;
	artifactRefs: StructuredClaimArtifactRefV1[];
	challenges: Array<{
		challengeId: string;
		status: "open" | "resolved";
		resolution?: string;
	}>;
};

export type StructuredClaimMergeV1 = {
	kind: "StructuredClaimMergeV1";
	schemaVersion: 1;
	mergeId: string;
	sourcePoolId: string;
	target?: string;
	claimRows: StructuredClaimRowV1[];
	conflictTable: Array<{
		conflictId: string;
		claimIds: string[];
		topic: string;
		status: "resolved" | "unresolved";
		winnerClaimId?: string;
		winningEvidenceRefs: string[];
		downgradeLosers: string[];
		resolutionReason?: string;
	}>;
	promotionCheck: {
		mode: "strict_final_claim_promotion";
		requiredStatuses: ["proven"];
		finalClaims: Array<{
			claimId: string;
			promotion: "final_pass";
			reportSection: string;
			verifierPass: boolean;
			artifactRefs: StructuredClaimArtifactRefV1[];
		}>;
		blockedClaims: Array<{
			claimId: string;
			reason: string;
		}>;
		policies: string[];
	};
};

export type StructuredClaimMergeCheckSnapshot = {
	status: "pass" | "blocked" | "missing";
	mergePath?: string;
	mergeId?: string;
	finalClaimCount: number;
	blockedClaimCount: number;
	errors: string[];
	policies: string[];
};

export type ReconParallelPlanWorkerV1 = {
	id: string;
	role: string;
	objective: string;
	commands: string[];
	evidenceContract: string[];
	mergeKeys: string[];
	dependencies: string[];
	artifactGlobs: string[];
	limits: Record<string, unknown>;
	prompt?: string[];
	sourceWorkerId?: string;
};

export type ReconParallelPlanV1 = {
	kind: "ReconParallelPlanV1";
	schemaVersion: 1;
	planId: string;
	target?: string;
	source: "re_swarm" | "frontier-orchestrator" | "agent-dogfood" | "hard-eval-control-plane" | "operator" | "manual";
	strategy?: string;
	workers: ReconParallelPlanWorkerV1[];
	merge: {
		strategy: "supervisor" | "synthesizer" | "frontier-summary" | "claim-ledger";
		evidenceOrder: string[];
		expectedArtifacts: string[];
		command?: string;
		conflictPolicy?: string;
	};
};

export type SwarmArtifact = {
	/** Per-artifact nonce used to prevent same-millisecond path collisions. */
	artifactId: string;
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "run" | "merge";
	delegationArtifact?: string;
	workers: SwarmWorkerRuntime[];
	executions: SwarmWorkerExecution[];
	workerResults: string[];
	blocked: string[];
	mergeDigest: string[];
	executionAudit: string[];
	coverageMatrix: string[];
	retryQueue: string[];
	parallelGroups: string[];
	mergeProtocol: string[];
	collisionMatrix: string[];
	evidenceContract: string[];
	commanderNextActions: string[];
	handoffDigest: string[];
	parallelPlan?: ReconParallelPlanV1;
	planCoverage: string[];
	releaseCheckMetadata: string[];
	claimLedger: SwarmClaimLedgerEventV1[];
	claimLedgerPath?: string;
	claimLedgerEventCount: number;
	claimLedgerTipHash?: string;
	runtimeClaimLedgerCaptured: boolean;
	structuredClaimMerge?: StructuredClaimMergeV1;
	structuredClaimMergePath?: string;
	structuredClaimMergeStatus?: "pass" | "blocked" | "missing";
	structuredClaimMergeErrors: string[];
	subagentRuntimeManifestPath?: string;
	subagentRuntimeManifests: SwarmSubagentRuntimeManifestRow[];
	subagentRuntimeManifestCount: number;
	subagentRuntimeManifestsCaptured: boolean;
	workerChildSessionRuntimePath?: string;
	workerChildSessionRuntime?: WorkerChildSessionRuntimeBatchV1;
	workerChildSessionRuntimeStatus?: "pass" | "blocked" | "missing";
	workerChildSessionRuntimeErrors: string[];
	workerLeaseSchedulerPath?: string;
	workerLeaseScheduler?: WorkerLeaseSchedulerV1;
	workerLeaseSchedulerStatus?: "pass" | "blocked" | "missing";
	workerLeaseSchedulerErrors: string[];
	workerRuntimePoolBridge?: WorkerRuntimePoolV1;
	workerRuntimePoolBridgeStatus?: "pass" | "blocked" | "missing";
	workerRuntimePoolBridgeErrors: string[];
	workerRetryHandoffClosurePath?: string;
	workerRetryHandoffClosure?: RepiWorkerRetryHandoffClosureV1;
	workerRetryHandoffClosureStatus?: "pass" | "blocked" | "missing";
	workerRetryHandoffClosureErrors: string[];
	workerRetryHandoffMergeSummaryPath?: string;
	workerRetryHandoffMergeSummary?: RepiWorkerRetryHandoffMergeSummaryV1;
	workerRetryHandoffMergeSummaryStatus?: "pass" | "blocked" | "missing";
	workerRetryHandoffMergeSummaryErrors: string[];
	sourceArtifacts: string[];
};

export type StrictClaimCheckSnapshot = {
	status: "pass" | "blocked" | "missing";
	markerPath?: string;
	generatedAt?: string;
	mode?: string;
	requiredGaps: string[];
	platformRequiredScore?: number;
	orchestrationScore?: number;
	claimCheckResult: string[];
};

export type SupervisorVerdict = "pass" | "watch" | "repair" | "blocked";

export type SupervisorWorkerReview = {
	packetId: string;
	worker: DelegateWorker;
	verdict: SupervisorVerdict;
	score: number;
	priority: number;
	rationale: string[];
	conflicts: string[];
	evidenceGaps: string[];
	repairActions: string[];
};

export type SupervisorArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "review" | "repair";
	delegationArtifact?: string;
	swarmArtifact?: string;
	supervisorVerdict: SupervisorVerdict;
	reviews: SupervisorWorkerReview[];
	conflicts: string[];
	repairQueue: string[];
	commanderMergeQueue: string[];
	commanderMergeBudget: string[];
	workerScoreboard: string[];
	priorityQueue: string[];
	checkpoints: string[];
	nextActions: string[];
	parallelPlan?: ReconParallelPlanV1;
	planCoverage: string[];
	releaseCheckMetadata: string[];
	claimCheckPolicy: string[];
	strictClaimCheck?: StrictClaimCheckSnapshot;
	claimCheckResult: string[];
	structuredClaimMergeCheck?: StructuredClaimMergeCheckSnapshot;
	llmCritique?: string;
	sourceArtifacts: string[];
};

export type SwarmRunOptions = {
	target?: string;
	task?: string;
	maxWorkers?: number;
	maxCommands?: number;
	execution?: "simulated" | "real";
	cwd?: string;
	signal?: AbortSignal;
};

export type SwarmBuildOptions = {
	target?: string;
	task?: string;
	mode?: "plan" | "run" | "merge";
};

export type SwarmOutputOptions = Pick<SwarmBuildOptions, "target" | "task">;

export type SupervisorBuildOptions = {
	target?: string;
	task?: string;
	mode?: "review" | "repair";
};

export type SupervisorOutputOptions = Pick<SupervisorBuildOptions, "target" | "task"> & {
	reasoning?: "rules" | "llm";
	cwd?: string;
	signal?: AbortSignal;
};

export type SwarmWorkerRetryHandoffClosureV1 = RepiWorkerRetryHandoffClosureV1;
export type SwarmWorkerRetryHandoffMergeSummaryV1 = RepiWorkerRetryHandoffMergeSummaryV1;

export type SwarmSupervisorRuntimeDependencies = {
	latestScopedMarkdownArtifact: (
		kind: string,
		dir: string,
		options?: ArtifactScopeFilterOptions,
	) => string | undefined;
	scopedMarkdownArtifacts: (
		kind: string,
		dir: string,
		limit: number,
		options?: ArtifactScopeFilterOptions,
	) => string[];
	latestDelegateArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	buildDelegate: (options?: { target?: string; task?: string; mode?: "plan" | "merge" }) => DelegateArtifact;
	writeDelegateArtifact: (delegate: DelegateArtifact) => string;
	operatorCommandConcrete: (command: string, target?: string) => { command: string; blocked?: string };
	executeOperatorStep: (pi: ExtensionAPI, step: SwarmOperatorStep, target?: string) => Promise<OperationExecution>;
	appendEvidence: (record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number }) => unknown;
	updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => unknown;
	runtimeArtifactHashes: (paths: Array<string | undefined>) => FailureRepairArtifactHash[];
	autoModeDefaults: () => { swarmExecution: "simulated" | "real" };
	strictClaimCheckSnapshot: () => StrictClaimCheckSnapshot;
	buildClaimCheckResult: (
		releaseCheckMetadata?: string[],
		claimCheckPolicy?: string[],
		strictCheck?: StrictClaimCheckSnapshot,
		additionalBlockers?: string[],
	) => string[];
	formatStrictClaimCheckSnapshot: (snapshot?: StrictClaimCheckSnapshot) => string[];
	readCurrentMission: () => MissionState | undefined;
};

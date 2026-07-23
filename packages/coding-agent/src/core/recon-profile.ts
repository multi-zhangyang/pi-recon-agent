import { existsSync } from "node:fs";
import type { ExtensionAPI } from "./extensions/types.ts";
import { createAdaptiveLaneRuntime } from "./repi/adaptive-lane-runtime.ts";
import { type ArtifactScopeFilterOptions, artifactTargetMatches } from "./repi/artifact-scope.ts";
import {
	contextArtifactIndex,
	contextEvidenceRank,
	latestScopedMarkdownArtifact,
	scopedMarkdownArtifacts,
	withScopedMarkdownArtifactSelectionCache,
} from "./repi/artifact-selection-runtime.ts";
import { createAttackGraphRuntime } from "./repi/attack-graph-runtime.ts";
import { createAutofixRuntime } from "./repi/autofix-runtime.ts";

export { parsePlannerDecision } from "./repi/adaptive-lane-runtime.ts";

import { createAutopilotRuntime } from "./repi/autopilot-runtime.ts";
import {
	autopilotBootstrapPlan,
	autopilotExecutionStrategy,
	bootstrapCatalogFor,
	buildToolDigest,
	commandKnownTools,
	createBootstrapPlan,
	formatAutopilotBootstrap,
	formatAutopilotExecutionStrategy,
	formatBootstrapPlan,
	installBootstrapTools,
	laneExecutionStrategy,
	parseToolIndex,
	recommendedToolsForRoute,
	refreshToolIndex,
} from "./repi/bootstrap-runtime.ts";
import { appendAgentThreadEvidence, appendEvidence, buildEvidenceDigest } from "./repi/evidence-runtime.ts";

export { appendEvidence } from "./repi/evidence-runtime.ts";

import { evidenceLedgerGraphNodes } from "./repi/evidence.ts";
import { createEvidenceGraphRuntime } from "./repi/evidence-graph-runtime.ts";
import { prioritizeAttackGraphTaskTree } from "./repi/graph.ts";
import { ensureReconStorage } from "./repi/resources.ts";

export {
	createReconResourceLoaderOptions,
	RECON_APPEND_SYSTEM_PROMPT,
	RECON_SYSTEM_PROMPT,
	REPI_REASONING_DOCTRINE,
} from "./repi/resources.ts";

import { createCampaignOperationRuntime } from "./repi/campaign-operation-runtime.ts";
import { createClaimReleaseRuntime, runtimeCheckpointStatus } from "./repi/claim-release-runtime.ts";
import { type CompletionAudit, createCompletionAuditRuntime } from "./repi/completion-audit-runtime.ts";
import { createDelegateOrchestrationRuntime } from "./repi/delegate-orchestration-runtime.ts";
import { createDomainProofExitRules, type DomainProofExitClosureV1 } from "./repi/domain-proof-exit-rules.ts";
import { createDomainProofExitRuntime } from "./repi/domain-proof-exit-runtime.ts";
import { createExploitChainRuntime } from "./repi/exploit-chain-runtime.ts";
import { createExploitMobileRuntime } from "./repi/exploit-mobile-runtime.ts";
import {
	recentProofLoopArtifacts,
	recentRuntimeAdapterExecutionArtifacts,
	runtimeAdapterMitigationEvidenceForGraph,
	runtimeAdapterParserSummaryForGraph,
} from "./repi/graph-artifacts.ts";
import { buildReLaneSpecialistCommandPackGate } from "./repi/lane-specialist-pack.ts";
import {
	createMission,
	type MissionState,
	missionOperatorDirective,
	readCurrentMission,
	updateMissionCheckpoint,
	writeCurrentMission,
} from "./repi/mission.ts";

export { updateMissionCheckpoint, writeCurrentMission } from "./repi/mission.ts";

import { createFailureRuntime } from "./repi/failure-runtime.ts";
import { createNativeRuntime } from "./repi/native-runtime.ts";
import { createOperatorOrchestrationRuntime, type OperatorArtifact } from "./repi/operator-orchestration-runtime.ts";
import { createPassiveMapRuntime } from "./repi/passive-map-runtime.ts";
import { REPI_SOURCE as RECON_SOURCE } from "./repi/profile.ts";
import { createProfileKernelReportRuntime } from "./repi/profile-kernel-report-runtime.ts";
import { createProofArtifactRuntime } from "./repi/proof-artifact-runtime.ts";
import { createProofLoopRuntime, replayClosureBlockers } from "./repi/proof-loop-runtime.ts";
import { createReconCommands } from "./repi/recon-commands.ts";
import { createReconLaneRuntime, type LaneCommandPack } from "./repi/recon-lane-runtime.ts";
import { createReconTools } from "./repi/recon-tools.ts";
import { formatRepiRoute, type RoutePlan, routeRepiTask } from "./repi/routes.ts";
import { createRuntimeAdapterExecutionRuntime } from "./repi/runtime-adapter-execution-runtime.ts";
import { assertRuntimeBindings, createRuntimeBinding } from "./repi/runtime-binding.ts";
import {
	installRepiSessionLifecycle,
	type ReconStats,
	type RepiSessionLifecycleOptions,
} from "./repi/session-lifecycle-runtime.ts";
import {
	artifactBasename,
	currentMissionPath,
	evidenceBrowserDir,
	evidenceCampaignsDir,
	evidenceCompilersDir,
	evidenceGraphsDir,
	evidenceLedgerPath,
	evidenceMapsDir,
	evidenceOperationsDir,
	evidenceReplayersDir,
	evidenceRunsDir,
	evidenceVerifiersDir,
	evidenceWebAuthzDir,
	readTextFile as readText,
	recentMarkdownArtifacts,
	reconArchiveDir,
	reconDir,
	reportDir,
	writePrivateTextFile,
} from "./repi/storage.ts";
import { createSwarmSupervisorRuntime } from "./repi/swarm-supervisor-runtime.ts";
import { commandContainsPoison, sanitizeTargetForCommand, shellQuote } from "./repi/target.ts";
import { type TechniqueDomain, techniquesForDomain } from "./repi/techniques.ts";
import {
	compactStoredArtifact,
	interestingLines,
	metadataValue,
	sha256Text,
	slug,
	truncateMiddle,
} from "./repi/text.ts";
import { createToolchainCapabilityRuntime } from "./repi/toolchain-capability-runtime.ts";
import {
	buildWebAuthzStateOutput as buildWebRuntimeAuthzStateOutput,
	buildLiveBrowserOutput as buildWebRuntimeLiveBrowserOutput,
	latestWebAuthzStateArtifactPath as latestWebRuntimeAuthzArtifactPath,
	latestLiveBrowserArtifactPath as latestWebRuntimeLiveBrowserArtifactPath,
	runWebAuthzState as runWebRuntimeAuthzState,
	runLiveBrowser as runWebRuntimeLiveBrowser,
	type WebRuntimeDependencies,
} from "./repi/web-runtime.ts";
import { atomicWriteFileSync } from "./tools/atomic-write.ts";

const operatorRuntimeBinding = createRuntimeBinding<ReturnType<typeof createOperatorOrchestrationRuntime>>("operator");
const campaignRuntimeBinding =
	createRuntimeBinding<ReturnType<typeof createCampaignOperationRuntime>>("campaign-operation");
const delegateRuntimeBinding = createRuntimeBinding<ReturnType<typeof createDelegateOrchestrationRuntime>>("delegate");
const swarmRuntimeBinding = createRuntimeBinding<ReturnType<typeof createSwarmSupervisorRuntime>>("swarm-supervisor");

const {
	buildKernelOutput,
	buildProfileCheckOutput,
	latestKernelArtifactPath,
	latestProfileCheckArtifactPath,
	writeReportScaffold,
} = createProfileKernelReportRuntime<DomainProofExitClosureV1>({
	readCurrentMission,
	updateMissionCheckpoint,
	formatStoredArtifactSummary,
	formatMission,
	latestSourceArtifactPaths: () => [
		operatorRuntimeBinding.get().latestDecisionCoreArtifactPath(),
		operatorRuntimeBinding.get().latestOperatorArtifactPath(),
		latestVerifierArtifactPath(),
		latestCompilerArtifactPath(),
		latestReplayerArtifactPath(),
		latestExploitChainArtifactPath(),
		latestExploitLabArtifactPath(),
		latestMobileRuntimeArtifactPath(),
		latestNativeRuntimeArtifactPath(),
		latestAutofixArtifactPath(),
		latestProofLoopArtifactPath(),
	],
	auditCompletion: () => auditCompletion(),
	formatCompletionAuditFromAudit: (audit) => formatCompletionAuditFromAudit(audit),
	strictClaimCheckSnapshot: () => strictClaimCheckSnapshot(),
});

const {
	buildProfessionalRuntimeBridgesGate,
	writeProfessionalRuntimeBridgesArtifact,
	buildToolchainDomainCapability,
	writeToolchainDomainCapabilityArtifact,
	buildToolchainDomainCapabilityOutput,
} = createToolchainCapabilityRuntime({ appendEvidence });

const { buildRuntimeAdapterExecutionGate, writeRuntimeAdapterExecutionArtifact, runRuntimeAdapterExecution } =
	createRuntimeAdapterExecutionRuntime({ appendEvidence });

const claimReleaseRuntime = createClaimReleaseRuntime({
	latestVerifierArtifactPath: () => latestVerifierArtifactPath(),
	parseVerifierArtifact: (path) => parseVerifierArtifact(path),
	latestSwarmArtifactPath: () => swarmRuntimeBinding.get().latestSwarmArtifactPath(),
	parseSwarmArtifact: (path) => swarmRuntimeBinding.get().parseSwarmArtifact(path),
	structuredClaimMergeCheckFromSwarm: (swarm) => swarmRuntimeBinding.get().structuredClaimMergeCheckFromSwarm(swarm),
});

const {
	artifactMatchesMission,
	buildClaimCheckResult,
	formatStrictClaimCheckSnapshot,
	safeStructuredClaimMergeCheck,
	strictClaimCheckSnapshot,
} = claimReleaseRuntime;

export function writeLocalClaimReleaseMarker(): string {
	return claimReleaseRuntime.writeLocalClaimReleaseMarker();
}

const failureRuntime = createFailureRuntime({
	artifactTier: (path) => contextEvidenceRank(/evidence\/([^/]+)/.exec(path)?.[1] ?? "runtime"),
	latestAutofixArtifactPath: () => latestAutofixArtifactPath(),
	latestProofLoopArtifactPath: () => latestProofLoopArtifactPath(),
	latestSupervisorArtifactPath: () => swarmRuntimeBinding.get().latestSupervisorArtifactPath(),
	operatorFeedbackCategory: (row) => operatorRuntimeBinding.get().operatorFeedbackCategory(row),
	operatorFeedbackFallbackCommands: (row, target) =>
		operatorRuntimeBinding.get().operatorFeedbackFallbackCommands(row, target),
});

const {
	appendRuntimeFailureRepairFromAutofix,
	appendRuntimeFailureRepairFromOperator,
	appendRuntimeFailureRepairFromProofLoop,
	appendRuntimeFailureRepairFromReplay,
	runtimeArtifactHashes,
	writeAutofixRepairRollbackPolicy,
} = failureRuntime;

export const appendFailureRepairLedger = failureRuntime.appendFailureRepairLedger;
export const failureSignaturePriorityReport = failureRuntime.failureSignaturePriorityReport;
export const readRuntimeFailureLedgerRows = failureRuntime.readRuntimeFailureLedgerRows;
export const readRuntimeRepairQueueRows = failureRuntime.readRuntimeRepairQueueRows;
export const runtimeFailureAttempt = failureRuntime.runtimeFailureAttempt;
export type { FailureLedgerEventV1, RepairQueueItemV1 } from "./repi/failure-runtime.ts";

const {
	latestVerifierArtifactPath,
	parseVerifierArtifact,
	buildVerifierOutput,
	latestCompilerArtifactPath,
	parseCompilerArtifact,
	buildCompilerOutput,
	latestReplayerArtifactPath,
	parseReplayArtifact,
	latestOrBuildReplay,
	replayHash,
	runReplayer,
	buildReplayerOutput,
} = createProofArtifactRuntime<OperatorArtifact>({
	ensureReconStorage,
	readText,
	writePrivateTextFile,
	evidenceVerifiersDir,
	evidenceCompilersDir,
	evidenceReplayersDir,
	evidenceLedgerPath,
	reportDir,
	latestScopedMarkdownArtifact,
	readCurrentMission,
	appendEvidence,
	updateMissionCheckpoint,
	latestOrBuildOperator: (options) => operatorRuntimeBinding.get().latestOrBuildOperator(options),
	classifyOperatorFeedback: (operator, operatorArtifact, target) =>
		operatorRuntimeBinding.get().classifyOperatorFeedback(operator, operatorArtifact, target),
	operatorFeedbackNextCommands: (feedback) => operatorRuntimeBinding.get().operatorFeedbackNextCommands(feedback),
	latestCompilerClaimCheckInputs: (options) => operatorRuntimeBinding.get().latestCompilerClaimCheckInputs(options),
	formatStrictClaimCheckSnapshot,
	prepareClaimReleaseMarker: writeLocalClaimReleaseMarker,
	artifactTargetMatches,
	commandContainsPoison,
	shellQuote,
	slug,
	truncateMiddle,
	exec: (pi, command, args, options) => pi.exec(command, args, options),
	appendRuntimeFailureRepairFromReplay,
});

const { buildAutofixOutput, latestAutofixArtifactPath } = createAutofixRuntime({
	latestScopedMarkdownArtifact,
	latestOrBuildReplay,
	latestCompilerArtifactPath,
	parseCompilerArtifact,
	operatorFeedbackNextCommands: (feedback) => operatorRuntimeBinding.get().operatorFeedbackNextCommands(feedback),
	writeAutofixRepairRollbackPolicy,
	appendRuntimeFailureRepairFromAutofix,
	appendEvidence,
	updateMissionCheckpoint,
	formatStoredArtifactSummary,
});

const webRuntimeDependencies: WebRuntimeDependencies = {
	ensureReconStorage,
	readCurrentMission,
	readText,
	recentMarkdownArtifacts,
	evidenceBrowserDir,
	evidenceWebAuthzDir,
	evidenceMapsDir,
	evidenceRunsDir,
	writePrivateTextFile,
	latestScopedMarkdownArtifact,
	latestKernelArtifactPath,
	latestVerifierArtifactPath,
	latestCompilerArtifactPath,
	latestReplayerArtifactPath,
	appendEvidence,
	updateMissionCheckpoint,
	runtimeCheckpointStatus,
	replayHash,
};

function latestLiveBrowserArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
	return latestWebRuntimeLiveBrowserArtifactPath(webRuntimeDependencies, options);
}

async function runLiveBrowser(
	pi: ExtensionAPI,
	options: { target?: string; url?: string; timeoutMs?: number } = {},
): Promise<string> {
	return runWebRuntimeLiveBrowser(pi, options, webRuntimeDependencies);
}

function buildLiveBrowserOutput(
	action: "plan" | "show" = "plan",
	options: { target?: string; url?: string; timeoutMs?: number } = {},
): string {
	return buildWebRuntimeLiveBrowserOutput(action, options, webRuntimeDependencies);
}

function latestWebAuthzStateArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
	return latestWebRuntimeAuthzArtifactPath(webRuntimeDependencies, options);
}

async function runWebAuthzState(
	pi: ExtensionAPI,
	options: { target?: string; url?: string; timeoutMs?: number } = {},
): Promise<string> {
	return runWebRuntimeAuthzState(pi, options, webRuntimeDependencies);
}

function buildWebAuthzStateOutput(
	action: "plan" | "show" = "plan",
	options: { target?: string; url?: string; timeoutMs?: number } = {},
): string {
	return buildWebRuntimeAuthzStateOutput(action, options, webRuntimeDependencies);
}

const { runPassiveMap } = createPassiveMapRuntime({
	ensureReconStorage,
	evidenceMapsDir,
	writePrivateTextFile,
	appendEvidence,
	currentMissionId: () => readCurrentMission()?.id,
	updateMissionCheckpoint,
	shellQuote,
	slug,
	truncateMiddle,
	interestingLines,
});

const {
	latestExploitLabArtifactPath,
	runExploitLab,
	buildExploitLabOutput,
	latestMobileRuntimeArtifactPath,
	runMobileRuntime,
	buildMobileRuntimeOutput,
} = createExploitMobileRuntime({
	latestScopedMarkdownArtifact,
	latestCompilerArtifactPath,
	latestReplayerArtifactPath,
	latestVerifierArtifactPath,
	latestOperatorArtifactPath: (options) => operatorRuntimeBinding.get().latestOperatorArtifactPath(options),
	latestLiveBrowserArtifactPath,
	appendEvidence,
	runtimeCheckpointStatus,
	updateMissionCheckpoint,
});

const { latestNativeRuntimeArtifactPath, runNativeRuntime, buildNativeRuntimeOutput } = createNativeRuntime({
	latestScopedMarkdownArtifact,
	latestVerifierArtifactPath,
	latestCompilerArtifactPath,
	latestReplayerArtifactPath,
	latestExploitLabArtifactPath,
	appendEvidence,
	runtimeCheckpointStatus,
	updateMissionCheckpoint,
});

const {
	updateMissionLane,
	autoCommandsForLane,
	autoLaneCommandPack,
	removeLaneNextItems,
	formatLaneQueue,
	activeLane,
	latestPassiveMapContext,
	inferTargetFromMap,
	laneCommandPack,
	formatLaneCommandPack,
	runLaneCommandPack,
	runLaneCommandPackWithStatus,
} = createReconLaneRuntime({
	writeCurrentMission,
	routeReconTask,
	appendEvidence,
	commandKnownTools,
	laneExecutionStrategy,
	formatAutopilotExecutionStrategy,
});

const evidenceGraphRuntime = createEvidenceGraphRuntime({
	readCurrentMission,
	formatRoute: formatRepiRoute,
	formatMission: (mission) => formatMission(mission),
	activeLane,
	inferTargetFromMap,
	parseLaneRunDecision: (text, laneName) => parseLaneRunDecision(text, laneName),
	recommendedToolsForRoute,
	createBootstrapPlan,
	buildAttackGraph: () => buildAttackGraph(),
	buildDecisionCore: (options) => buildDecisionCore(options),
	buildDomainProofExitClosure: (mission) => buildDomainProofExitClosure(mission),
	updateMissionCheckpoint,
	formatStoredArtifactSummary,
});

const {
	attackGraphNextActions,
	buildAttackGraphOutput,
	buildPentestingTaskTreeSnapshot,
	evidenceRecordHasCounterSignal,
	evidenceRecordHasHypothesisSignal,
	latestAttackGraphArtifactPath,
	parseEvidenceLedgerTaskRecords,
	writeAttackGraphArtifact,
} = evidenceGraphRuntime;

const { parseLaneRunDecision, runAutoLaneChain } = createAdaptiveLaneRuntime({
	readCurrentMission,
	writeCurrentMission,
	activeLane,
	autoCommandsForLane,
	autoLaneCommandPack,
	runLaneCommandPackWithStatus,
	removeLaneNextItems,
	buildTaskTreeSnapshot: buildPentestingTaskTreeSnapshot,
	createBootstrapPlan,
	formatBootstrapPlan,
	installBootstrapTools,
	refreshToolIndex,
});

const { domainProofExitNextCommands, proofExitExpectedEvidence, proofExitRegexes, toolchainDomainIdForRoute } =
	createDomainProofExitRules({ activeLane, readCurrentMission });

const {
	buildDomainProofExitClosure,
	buildDomainProofExitClosureOutput,
	formatDomainProofExitClosure,
	writeDomainProofExitClosureArtifact,
} = createDomainProofExitRuntime({
	readCurrentMission,
	buildToolchainDomainCapability,
	toolchainDomainIdForRoute,
	proofExitRegexes,
	proofExitExpectedEvidence,
	domainProofExitNextCommands,
	appendEvidence,
	updateMissionCheckpoint,
});

const { auditCompletion, formatCompletionAudit, formatCompletionAuditFromAudit, runCompletionAudit } =
	createCompletionAuditRuntime<DomainProofExitClosureV1>({
		latestSupervisorArtifactPath: () => swarmRuntimeBinding.get().latestSupervisorArtifactPath(),
		parseSupervisorArtifact: (path) => swarmRuntimeBinding.get().parseSupervisorArtifact(path),
		latestSwarmArtifactPath: () => swarmRuntimeBinding.get().latestSwarmArtifactPath(),
		parseSwarmArtifact: (path) => swarmRuntimeBinding.get().parseSwarmArtifact(path),
		latestVerifierArtifactPath: () => latestVerifierArtifactPath(),
		parseVerifierArtifact: (path) => parseVerifierArtifact(path),
		latestCompilerArtifactPath: () => latestCompilerArtifactPath(),
		parseCompilerArtifact: (path) => parseCompilerArtifact(path),
		latestReplayerArtifactPath: () => latestReplayerArtifactPath(),
		parseReplayArtifact: (path) => parseReplayArtifact(path),
		strictClaimCheckSnapshot: () => strictClaimCheckSnapshot(),
		safeStructuredClaimMergeCheck: (swarm) => safeStructuredClaimMergeCheck(swarm),
		replayClosureBlockers,
		buildDomainProofExitClosure,
		formatDomainProofExitClosure,
		formatMission,
	});

const { autoModeDefaults, runAutopilot } = createAutopilotRuntime({
	ensureReconStorage,
	currentMissionPath,
	reconArchiveDir,
	reconDir,
	artifactBasename,
	writePrivateJson: (path, value) => atomicWriteFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 0o644),
	sanitizeTargetForCommand,
	truncateMiddle,
	readCurrentMission,
	writeCurrentMission,
	createMission,
	routeReconTask,
	activeLane,
	laneCommandPack,
	latestPassiveMapContext,
	autopilotBootstrapPlan,
	autopilotExecutionStrategy,
	formatAutopilotBootstrap,
	formatAutopilotExecutionStrategy,
	formatLaneCommandPack,
	formatMission,
	runPassiveMap,
	updateMissionCheckpoint,
	runLaneCommandPack,
	runAutoLaneChain,
	formatCompletionAudit,
});

const { latestProofLoopArtifactPath, parseAutofixArtifact, runProofLoop, buildProofLoopOutput } =
	createProofLoopRuntime({
		latestScopedMarkdownArtifact,
		latestDecisionCoreArtifactPath: (options) => operatorRuntimeBinding.get().latestDecisionCoreArtifactPath(options),
		latestOperatorArtifactPath: (options) => operatorRuntimeBinding.get().latestOperatorArtifactPath(options),
		latestDelegateArtifactPath: (options) => delegateRuntimeBinding.get().latestDelegateArtifactPath(options),
		latestSwarmArtifactPath: (options) => swarmRuntimeBinding.get().latestSwarmArtifactPath(options),
		latestSupervisorArtifactPath: (options) => swarmRuntimeBinding.get().latestSupervisorArtifactPath(options),
		latestVerifierArtifactPath,
		latestCompilerArtifactPath,
		latestReplayerArtifactPath,
		latestAutofixArtifactPath,
		latestAttackGraphArtifactPath,
		contextArtifactIndex,
		parseVerifierArtifact,
		parseCompilerArtifact,
		parseReplayArtifact,
		latestOperatorFeedback: (target) => operatorRuntimeBinding.get().latestOperatorFeedback(target),
		latestCompilerClaimCheckInputs: (options) => operatorRuntimeBinding.get().latestCompilerClaimCheckInputs(options),
		failureSignaturePriorityReport,
		latestSwarmRetryQueue: (target) => swarmRuntimeBinding.get().latestSwarmRetryQueue(target),
		operatorFeedbackProofLoopCommands: (feedback, target) =>
			operatorRuntimeBinding.get().operatorFeedbackProofLoopCommands(feedback, target),
		delegateEvidenceContract: (worker) => delegateRuntimeBinding.get().delegateEvidenceContract(worker),
		autonomousExecutionBudget: (target, rows) => delegateRuntimeBinding.get().autonomousExecutionBudget(target, rows),
		autonomousBudgetLines: (budget) => delegateRuntimeBinding.get().autonomousBudgetLines(budget),
		withScopedMarkdownArtifactSelectionCache,
		appendEvidence,
		updateMissionCheckpoint,
		appendRuntimeFailureRepairFromProofLoop,
		executeOperatorStep: (pi, step, target) => operatorRuntimeBinding.get().executeOperatorStep(pi, step, target),
		operatorStepPriority: (command) => operatorRuntimeBinding.get().operatorStepPriority(command),
		buildAttackGraphOutput,
		runRuntimeAdapterExecution,
		buildVerifierOutput,
		buildCompilerOutput,
		runReplayer,
		buildAutofixOutput,
		formatCompletionAuditFromAudit,
		runCompletionAudit,
		buildDelegateOutput: (action, options) => delegateRuntimeBinding.get().buildDelegateOutput(action, options),
		buildSwarmOutput: (action, options) => swarmRuntimeBinding.get().buildSwarmOutput(action, options),
		buildSupervisorOutput: (action, options) => swarmRuntimeBinding.get().buildSupervisorOutput(action, options),
	});

const operatorRuntime = operatorRuntimeBinding.bind(
	createOperatorOrchestrationRuntime({
		latestScopedMarkdownArtifact,
		contextArtifactIndex,
		parseToolIndex,
		recommendedToolsForRoute,
		bootstrapCatalogFor,
		latestKernelArtifactPath,
		latestProofLoopArtifactPath,
		latestAutofixArtifactPath,
		latestVerifierArtifactPath,
		parseVerifierArtifact,
		buildVerifierOutput,
		latestCompilerArtifactPath,
		parseCompilerArtifact,
		buildCompilerOutput,
		latestReplayerArtifactPath,
		parseReplayArtifact,
		runReplayer,
		buildReplayerOutput,
		parseAutofixArtifact,
		buildAutofixOutput,
		buildDelegateOutput: (action, options) => delegateRuntimeBinding.get().buildDelegateOutput(action, options),
		runAutopilot,
		buildKernelOutput,
		runWebAuthzState,
		buildWebAuthzStateOutput,
		runMobileRuntime,
		buildMobileRuntimeOutput,
		runNativeRuntime,
		buildNativeRuntimeOutput,
		runExploitLab,
		buildExploitLabOutput,
		runProofLoop,
		buildProofLoopOutput,
		runOperationQueue: (pi, options) => campaignRuntimeBinding.get().runOperationQueue(pi, options),
		buildOperationOutput: (action, options) => campaignRuntimeBinding.get().buildOperationOutput(action, options),
		executeOperationStep: (pi, step, target) => campaignRuntimeBinding.get().executeOperationStep(pi, step, target),
		runSwarm: (pi, options) => swarmRuntimeBinding.get().runSwarm(pi, options),
		buildSwarmOutput: (action, options) => swarmRuntimeBinding.get().buildSwarmOutput(action, options),
		buildSupervisorOutput: (action, options) => swarmRuntimeBinding.get().buildSupervisorOutput(action, options),
		latestSwarmArtifactPath: (options) => swarmRuntimeBinding.get().latestSwarmArtifactPath(options),
		parseSwarmArtifact: (path) => swarmRuntimeBinding.get().parseSwarmArtifact(path),
		latestSwarmRetryQueue: (target) => swarmRuntimeBinding.get().latestSwarmRetryQueue(target),
		latestSupervisorArtifactPath: (options) => swarmRuntimeBinding.get().latestSupervisorArtifactPath(options),
		parseSupervisorArtifact: (path) => swarmRuntimeBinding.get().parseSupervisorArtifact(path),
		supervisorClaimCheckPolicy: (plan, coverage) =>
			swarmRuntimeBinding.get().supervisorClaimCheckPolicy(plan, coverage),
		supervisorPlanCoverage: (swarm) => swarmRuntimeBinding.get().supervisorPlanCoverage(swarm),
		splitRetryNextCommands: (next) => swarmRuntimeBinding.get().splitRetryNextCommands(next),
		artifactMatchesMission,
		safeStructuredClaimMergeCheck,
		strictClaimCheckSnapshot,
		buildClaimCheckResult,
		appendEvidence,
		updateMissionCheckpoint,
		appendRuntimeFailureRepairFromOperator,
		activeLane,
		autonomousExecutionBudget: (target, rows) => delegateRuntimeBinding.get().autonomousExecutionBudget(target, rows),
		autonomousBudgetLines: (budget) => delegateRuntimeBinding.get().autonomousBudgetLines(budget),
		createMission,
		writeCurrentMission,
		routeReconTask,
		formatMission,
		buildMissionDigest,
	}),
);

const {
	latestDecisionCoreArtifactPath,
	nextDecisionCommand,
	buildDecisionCore,
	runDecisionCore,
	buildDecisionCoreOutput,
	latestOperatorArtifactPath,
	operatorCommandConcrete,
	executeOperatorStep,
	dispatchOperatorQueue,
	buildOperatorOutput,
	latestOperatorFeedback,
} = operatorRuntime;

const { buildAttackGraph } = createAttackGraphRuntime({
	ensureReconStorage,
	nowIso: () => new Date().toISOString(),
	readCurrentMission,
	latestPassiveMapContext,
	recentRuntimeAdapterExecutionArtifacts,
	recentProofLoopArtifacts,
	recentSwarmArtifactsForGraph: (limit, options) => recentSwarmArtifactsForGraph(limit, options),
	artifactBasename,
	slug,
	recentMarkdownArtifacts,
	evidenceRunsDir,
	readText,
	metadataValue,
	runtimeAdapterParserSummaryForGraph,
	runtimeAdapterMitigationEvidenceForGraph,
	existsSync,
	truncateMiddle,
	sha256Text,
	evidenceLedgerGraphNodes,
	parseEvidenceLedgerTaskRecords,
	evidenceRecordHasHypothesisSignal,
	evidenceRecordHasCounterSignal,
	recommendedToolsForRoute,
	createBootstrapPlan,
	attackGraphNextActions,
	prioritizeAttackGraphTaskTree,
});

const {
	latestCampaignArtifactPath,
	buildCampaignOutput,
	latestOperationArtifactPath,
	latestOrBuildOperation,
	runOperationQueue,
	buildOperationOutput,
} = campaignRuntimeBinding.bind(
	createCampaignOperationRuntime({
		ensureReconStorage,
		readCurrentMission,
		writeCurrentMission,
		createMission,
		routeReconTask,
		latestPassiveMapContext,
		inferTargetFromMap,
		buildAttackGraph,
		writeAttackGraphArtifact,
		recommendedToolsForRoute,
		createBootstrapPlan,
		formatBootstrapPlan,
		recentMarkdownArtifacts,
		evidenceRunsDir,
		evidenceGraphsDir,
		evidenceCampaignsDir,
		evidenceOperationsDir,
		latestScopedMarkdownArtifact,
		readText,
		writePrivateTextFile,
		appendEvidence,
		updateMissionCheckpoint,
		slug,
		truncateMiddle,
		activeLane,
		laneCommandPack,
		formatLaneCommandPack,
		runLaneCommandPack,
		runAutoLaneChain,
		runPassiveMap,
		runDecisionCore,
		buildDecisionCoreOutput,
		buildKernelOutput,
		runLiveBrowser,
		buildLiveBrowserOutput,
		runWebAuthzState,
		buildWebAuthzStateOutput,
		runMobileRuntime,
		buildMobileRuntimeOutput,
		runNativeRuntime,
		buildNativeRuntimeOutput,
		runExploitLab,
		buildExploitLabOutput,
		refreshToolIndex,
		buildAttackGraphOutput,
		buildExploitChainOutput: (action, options) => buildExploitChainOutput(action, options),
		buildVerifierOutput,
		buildCompilerOutput,
		runReplayer,
		buildReplayerOutput,
		buildAutofixOutput,
		runProofLoop,
		buildProofLoopOutput,
		formatCompletionAudit,
		writeReportScaffold,
	}),
);

const { latestExploitChainArtifactPath, buildExploitChainOutput } = createExploitChainRuntime({
	latestScopedMarkdownArtifact,
	latestKernelArtifactPath,
	latestLiveBrowserArtifactPath,
	latestWebAuthzStateArtifactPath,
	latestNativeRuntimeArtifactPath,
	latestMobileRuntimeArtifactPath,
	latestAttackGraphArtifactPath,
	latestCampaignArtifactPath,
	latestOperationArtifactPath,
	latestExploitLabArtifactPath,
	latestVerifierArtifactPath,
	latestCompilerArtifactPath,
	latestReplayerArtifactPath,
	latestAutofixArtifactPath,
	latestProofLoopArtifactPath,
	latestOperatorFeedback,
	activeLane,
	appendEvidence,
	updateMissionCheckpoint,
});

const delegateRuntime = delegateRuntimeBinding.bind(
	createDelegateOrchestrationRuntime({
		latestScopedMarkdownArtifact,
		latestOrBuildOperation,
		latestSupervisorArtifactPath: (options) => swarmRuntimeBinding.get().latestSupervisorArtifactPath(options),
		parseSupervisorArtifact: (path) => swarmRuntimeBinding.get().parseSupervisorArtifact(path),
		operatorCommandConcrete,
		activeLane,
		appendEvidence,
		updateMissionCheckpoint,
	}),
);

const { latestDelegateArtifactPath, buildDelegate, writeDelegateArtifact, buildDelegateOutput } = delegateRuntime;

const {
	latestSwarmArtifactPath,
	recentSwarmArtifactsForGraph,
	swarmWorkerSpec,
	runSwarm,
	buildSwarmOutput,
	latestSupervisorArtifactPath,
	parseSupervisorCritique,
	buildSupervisorOutput,
} = swarmRuntimeBinding.bind(
	createSwarmSupervisorRuntime({
		latestScopedMarkdownArtifact,
		scopedMarkdownArtifacts,
		latestDelegateArtifactPath,
		buildDelegate,
		writeDelegateArtifact,
		operatorCommandConcrete,
		executeOperatorStep,
		appendEvidence,
		updateMissionCheckpoint,
		runtimeArtifactHashes,
		autoModeDefaults,
		strictClaimCheckSnapshot,
		buildClaimCheckResult,
		formatStrictClaimCheckSnapshot,
		readCurrentMission,
	}),
);

assertRuntimeBindings([operatorRuntimeBinding, campaignRuntimeBinding, delegateRuntimeBinding, swarmRuntimeBinding]);

export { parseSupervisorCritique, swarmWorkerSpec };

export { type RoutePlan, routeRepiTask } from "./repi/routes.ts";
export function routeReconTask(task: string): RoutePlan {
	return routeRepiTask(task);
}

// Map routeRepiTask domain labels (routes.ts) to repi/techniques.ts domains so
// re_route can surface the concrete advanced-technique ids for the routed domain.
const ROUTE_LABEL_TO_TECHNIQUE_DOMAIN: Record<string, TechniqueDomain> = {
	"Pwn / exploit": "pwn",
	"Web / API pentest": "web-api",
	"Web pentest scanning": "web-scan",
	"Frontend JS reverse": "js-reverse",
	"Crypto / stego": "crypto-stego",
	"Native reverse": "native-reverse",
	"Mobile / iOS": "mobile",
	"Mobile / Android": "mobile",
	"Firmware / IoT": "firmware-iot",
	"DFIR / PCAP / stego": "dfir-pcap",
	"Cloud / container": "cloud-container",
	"Identity / Windows / AD": "identity-ad",
	"Malware analysis": "malware",
	"Agent / LLM boundary": "agent-llm",
	"Memory forensics": "memory-forensics",
	"Exploit reliability": "exploit-reliability",
};

function techniqueIdsForRoute(route: RoutePlan): string[] {
	const domain = ROUTE_LABEL_TO_TECHNIQUE_DOMAIN[route.domain];
	if (!domain) return [];
	return techniquesForDomain(domain).map((entry) => entry.id);
}

const formatRoute = formatRepiRoute;

export type { ReconStats } from "./repi/session-lifecycle-runtime.ts";

function formatMission(mission: MissionState): string {
	return truncateMiddle(
		[
			`mission_id: ${mission.id}`,
			`task: ${truncateMiddle(mission.task, 320)}`,
			`operator_directive: ${truncateMiddle(missionOperatorDirective(mission) ?? mission.task, 320)}`,
			formatRoute(mission.route),
			formatLaneQueue(mission),
			"checkpoints:",
			...mission.checkpoints.map(
				(checkpoint) =>
					`- [${checkpoint.status}] ${checkpoint.name}${checkpoint.note ? `: ${truncateMiddle(checkpoint.note, 180)}` : ""}`,
			),
			`mission_artifact: ${currentMissionPath()}`,
		].join("\n"),
		4096,
	);
}

function buildMissionDigest(): string {
	const mission = readCurrentMission();
	return mission
		? truncateMiddle(formatMission(mission), 5000)
		: "无 active mission；调用 re_mission new 创建任务黑板。";
}

function missionCheckSummary(): string {
	const mission = readCurrentMission();
	if (!mission) return "no mission";
	return mission.checkpoints.map((checkpoint) => `${checkpoint.name}=${checkpoint.status}`).join(", ");
}

function formatStoredArtifactSummary(kind: string, path: string): string {
	const text = readText(path);
	return `${compactStoredArtifact(kind, path, text)}\nverify: cat ${shellQuote(path)}`;
}

function makeSelfReview(stats: ReconStats): string {
	return [
		"<self_review>",
		`目标推进证据：${stats.lastRoute ? formatRoute(stats.lastRoute) : "未记录路由"}; tool_calls=${stats.calls}; bash_calls=${stats.bashCalls}; failures=${stats.failures}`,
		`任务黑板：mission=${stats.currentMissionId ?? "none"}; checkpoints=${missionCheckSummary()}`,
		`重复/死循环检查：last_commands=${stats.lastCommands.slice(-3).join(" | ") || "none"}; repeated=${stats.repeatedCommandCount}`,
		"上个错误解释：如 failures 增长，先解释 stderr/exit code，再换路线。",
		"下一条路线：被动证据不足→补映射；静态卡住→动态/trace/hook；源码与运行时冲突→信运行时。",
		"</self_review>",
	].join("\n");
}

const installReconCommands = createReconCommands<
	ReconStats,
	CompletionAudit<DomainProofExitClosureV1>,
	LaneCommandPack
>({
	sendSource: RECON_SOURCE,
	buildKernelOutput,
	runDecisionCore,
	buildDecisionCoreOutput,
	runLiveBrowser,
	buildLiveBrowserOutput,
	runWebAuthzState,
	buildWebAuthzStateOutput,
	runExploitLab,
	buildExploitLabOutput,
	runMobileRuntime,
	buildMobileRuntimeOutput,
	runNativeRuntime,
	buildNativeRuntimeOutput,
	refreshToolIndex,
	buildToolDigest,
	buildToolchainDomainCapabilityOutput,
	buildProfessionalRuntimeBridgesGate,
	writeProfessionalRuntimeBridgesArtifact,
	buildRuntimeAdapterExecutionGate,
	writeRuntimeAdapterExecutionArtifact,
	runRuntimeAdapterExecution,
	buildReLaneSpecialistCommandPackGate,
	buildDomainProofExitClosureOutput,
	writeCurrentMission,
	updateMissionCheckpoint,
	formatMission,
	buildMissionDigest,
	formatLaneQueue,
	activeLane,
	updateMissionLane,
	laneCommandPack,
	formatLaneCommandPack,
	runLaneCommandPack,
	runAutoLaneChain,
	runPassiveMap,
	runAutopilot,
	appendEvidence,
	buildEvidenceDigest,
	buildAttackGraphOutput,
	buildExploitChainOutput,
	buildCampaignOutput,
	runOperationQueue,
	buildOperationOutput,
	buildDelegateOutput,
	runSwarm,
	buildSwarmOutput,
	buildSupervisorOutput,
	dispatchOperatorQueue,
	buildOperatorOutput,
	buildVerifierOutput,
	buildCompilerOutput,
	runReplayer,
	buildReplayerOutput,
	buildAutofixOutput,
	runProofLoop,
	buildProofLoopOutput,
	buildProfileCheckOutput,
	createBootstrapPlan,
	installBootstrapTools,
	formatBootstrapPlan,
	writeReportScaffold,
	formatCompletionAudit,
	runCompletionAudit,
	formatCompletionAuditFromAudit,
	makeSelfReview,
});

const installReconTools = createReconTools<CompletionAudit<DomainProofExitClosureV1>, LaneCommandPack>({
	routeReconTask,
	techniqueIdsForRoute,
	formatRoute,
	appendEvidence,
	appendAgentThreadEvidence,
	buildPentestingTaskTreeSnapshot,
	buildDomainProofExitClosure,
	formatDomainProofExitClosure,
	writeDomainProofExitClosureArtifact,
	buildToolchainDomainCapability,
	writeToolchainDomainCapabilityArtifact,
	buildProfessionalRuntimeBridgesGate,
	writeProfessionalRuntimeBridgesArtifact,
	buildRuntimeAdapterExecutionGate,
	writeRuntimeAdapterExecutionArtifact,
	runRuntimeAdapterExecution,
	buildReLaneSpecialistCommandPackGate,
	buildKernelOutput,
	latestKernelArtifactPath,
	runDecisionCore,
	buildDecisionCoreOutput,
	latestDecisionCoreArtifactPath,
	runLiveBrowser,
	buildLiveBrowserOutput,
	latestLiveBrowserArtifactPath,
	runWebAuthzState,
	buildWebAuthzStateOutput,
	latestWebAuthzStateArtifactPath,
	runExploitLab,
	buildExploitLabOutput,
	latestExploitLabArtifactPath,
	runMobileRuntime,
	buildMobileRuntimeOutput,
	latestMobileRuntimeArtifactPath,
	runNativeRuntime,
	buildNativeRuntimeOutput,
	latestNativeRuntimeArtifactPath,
	writeCurrentMission,
	updateMissionCheckpoint,
	formatMission,
	buildMissionDigest,
	formatLaneQueue,
	activeLane,
	updateMissionLane,
	laneCommandPack,
	formatLaneCommandPack,
	runLaneCommandPack,
	runAutoLaneChain,
	runPassiveMap,
	runAutopilot,
	buildEvidenceDigest,
	buildAttackGraphOutput,
	latestAttackGraphArtifactPath,
	buildExploitChainOutput,
	latestExploitChainArtifactPath,
	buildCampaignOutput,
	latestCampaignArtifactPath,
	runOperationQueue,
	buildOperationOutput,
	latestOperationArtifactPath,
	buildDelegateOutput,
	latestDelegateArtifactPath,
	runSwarm,
	buildSwarmOutput,
	latestSwarmArtifactPath,
	buildSupervisorOutput,
	latestSupervisorArtifactPath,
	dispatchOperatorQueue,
	buildOperatorOutput,
	latestOperatorArtifactPath,
	buildVerifierOutput,
	latestVerifierArtifactPath,
	buildCompilerOutput,
	latestCompilerArtifactPath,
	runReplayer,
	buildReplayerOutput,
	latestReplayerArtifactPath,
	buildAutofixOutput,
	latestAutofixArtifactPath,
	runProofLoop,
	buildProofLoopOutput,
	latestProofLoopArtifactPath,
	buildProfileCheckOutput,
	latestProfileCheckArtifactPath,
	createBootstrapPlan,
	installBootstrapTools,
	formatBootstrapPlan,
	writeReportScaffold,
	formatCompletionAudit,
	runCompletionAudit,
	formatCompletionAuditFromAudit,
	buildToolDigest,
	refreshToolIndex,
});

export type ReconExtensionOptions = RepiSessionLifecycleOptions;

export function createReconExtensionFactory(options: ReconExtensionOptions = {}) {
	return function reconExtension(pi: ExtensionAPI): void {
		installRepiSessionLifecycle(
			pi,
			{
				nextDecisionCommand,
				installCommands: installReconCommands,
				installTools: installReconTools,
			},
			options,
		);
	};
}

import { createHash } from "node:crypto";
import { Type } from "typebox";
import { type AgentThreadRunManifest, createAgentThreadManager } from "../agent-thread-manager.ts";
import { normalizeWorkerTask } from "../agent-thread-worker-runtime.ts";
import type { ExtensionAPI } from "../extensions/types.ts";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import type { EvidenceRecord } from "./evidence.ts";
import type { ReLaneSpecialistCommandPackCheckV1 } from "./lane-specialist-pack.ts";
import {
	createMission,
	type MissionCheckpointStatus,
	type MissionLane,
	type MissionLaneStatus,
	type MissionState,
	normalizeOperatorCheckpointUpdate,
	readCurrentMission,
} from "./mission.ts";
import type { ProfileCheckMode } from "./profile-check.ts";
import { repiSubagentFailureResult, repiSubagentResultFromManifest } from "./re-subagent-contract.ts";
import type { ReconCommandBootstrapPlan, ReconCommandLanePack } from "./recon-commands.ts";
import { validateRepiSubagentArtifact } from "./repi-subagent-artifact-validation.ts";
import { REPI_GENERIC_TASK, type RoutePlan } from "./routes.ts";
import type { RuntimeAdapterExecutionCheckV1 } from "./runtime-adapter.ts";
import { currentMissionPath, evidenceLedgerPath, evidenceMapsDir, toolIndexPath } from "./storage.ts";
import { formatCweTags, formatMitreTag } from "./taxonomy.ts";
import {
	ADVANCED_TECHNIQUES,
	formatTechniqueIndex,
	formatTechniquePlaybook,
	resolveTechniqueDomain,
	techniqueById,
	techniquesForDomain,
} from "./techniques.ts";
import { envBoolean, redactSensitiveText, truncateMiddle } from "./text.ts";
import { REPI_TOOL_BOOTSTRAP_CATALOG as TOOL_BOOTSTRAP_CATALOG } from "./toolchain.ts";
import type {
	ProfessionalRuntimeBridgesCheckV1,
	ToolchainDomainCapabilityV1,
	ToolchainDomainStatus,
} from "./toolchain-runtime.ts";

type TargetOptions = { target?: string };
type BrowserOptions = TargetOptions & { url?: string; timeoutMs?: number };
type ExploitOptions = TargetOptions & { runs?: number; timeoutMs?: number };
type MobileOptions = BrowserOptions & { packageName?: string };
type OperationOptions = TargetOptions & { task?: string };
type LaneRunOptions = TargetOptions & { lane?: string; maxSteps?: number; cwd?: string };
type AutopilotOptions = {
	action?: "plan" | "run";
	task?: string;
	target?: string;
	lane?: string;
	mapDepth?: number;
	maxAutoSteps?: number;
	runAuto?: boolean;
	cleanState?: boolean;
	reasoning?: "regex" | "llm";
	dispatch?: "inline" | "specialist";
	cwd?: string;
	signal?: AbortSignal;
};
type SwarmOptions = OperationOptions & {
	maxWorkers?: number;
	maxCommands?: number;
	execution?: "simulated" | "real";
	cwd?: string;
	signal?: AbortSignal;
};
type SupervisorOptions = OperationOptions & {
	reasoning?: "rules" | "llm";
	cwd?: string;
	signal?: AbortSignal;
};
type RuntimeAdapterOptions = { adapter?: string; target?: string; timeoutMs?: number };
type EvidenceInput = Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number };
type DomainProofExitRow = {
	proofExit: string;
	status: "matched" | "missing";
	matchedArtifacts: string[];
	matchedLines: string[];
	expectedEvidence: string[];
	nextCommands: string[];
};
type DomainProofExitClosure = {
	kind: "DomainProofExitClosureV1";
	schemaVersion: 1;
	generatedAt: string;
	missionId?: string;
	status: "passed" | "partial" | "blocked";
	domainId?: string;
	routeDomain?: string;
	toolchainStatus?: ToolchainDomainStatus;
	artifactCorpusHash: string;
	artifactSources: string[];
	rows: DomainProofExitRow[];
	matchedProofExits: string[];
	missingProofExits: string[];
	blockers: string[];
	nextRuntimeCommands: string[];
};
type PentestingTaskTreeSnapshot = {
	text: string;
	gapsCount: number;
	missingProofExits: number;
	lastRunVerdict?: string;
};

export type ReconToolDependencies<TCompletionAudit, TPack extends ReconCommandLanePack = ReconCommandLanePack> = {
	routeReconTask: (task: string) => RoutePlan;
	techniqueIdsForRoute: (route: RoutePlan) => string[];
	formatRoute: (route: RoutePlan) => string;
	appendEvidence: (record: EvidenceInput) => EvidenceRecord;
	appendAgentThreadEvidence: (
		manifest: AgentThreadRunManifest,
		options: {
			title: string;
			fact: string;
			command: string;
			confidence: string;
			checkpoint?: { name: string; status: MissionCheckpointStatus; note: string };
		},
	) => EvidenceRecord;
	buildPentestingTaskTreeSnapshot: (options: { target?: string; focus?: string }) => PentestingTaskTreeSnapshot;
	buildDomainProofExitClosure: (mission?: MissionState, domainFilter?: string) => DomainProofExitClosure;
	formatDomainProofExitClosure: (report: DomainProofExitClosure, path?: string) => string;
	writeDomainProofExitClosureArtifact: (report: DomainProofExitClosure) => string;
	buildToolchainDomainCapability: (domain?: string) => ToolchainDomainCapabilityV1;
	writeToolchainDomainCapabilityArtifact: (report: ToolchainDomainCapabilityV1) => string;
	buildProfessionalRuntimeBridgesGate: (filter?: string) => ProfessionalRuntimeBridgesCheckV1;
	writeProfessionalRuntimeBridgesArtifact: (report: ProfessionalRuntimeBridgesCheckV1) => string;
	buildRuntimeAdapterExecutionGate: (filter?: string) => RuntimeAdapterExecutionCheckV1;
	writeRuntimeAdapterExecutionArtifact: (report: RuntimeAdapterExecutionCheckV1) => string;
	runRuntimeAdapterExecution: (pi: ExtensionAPI, options: RuntimeAdapterOptions) => Promise<string>;
	buildReLaneSpecialistCommandPackGate: (domain?: string) => ReLaneSpecialistCommandPackCheckV1;
	buildKernelOutput: (action: "build" | "show" | "audit", options: TargetOptions) => string;
	latestKernelArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	runDecisionCore: (pi: ExtensionAPI, options: TargetOptions & { maxSteps?: number }) => Promise<string>;
	buildDecisionCoreOutput: (action: "plan" | "show" | "tick", options: TargetOptions) => string;
	latestDecisionCoreArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	runLiveBrowser: (pi: ExtensionAPI, options: BrowserOptions) => Promise<string>;
	buildLiveBrowserOutput: (action: "plan" | "show", options: BrowserOptions) => string;
	latestLiveBrowserArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	runWebAuthzState: (pi: ExtensionAPI, options: BrowserOptions) => Promise<string>;
	buildWebAuthzStateOutput: (action: "plan" | "show", options: BrowserOptions) => string;
	latestWebAuthzStateArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	runExploitLab: (pi: ExtensionAPI, options: ExploitOptions) => Promise<string>;
	buildExploitLabOutput: (action: "plan" | "show" | "bundle", options: ExploitOptions) => string;
	latestExploitLabArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	runMobileRuntime: (pi: ExtensionAPI, options: MobileOptions) => Promise<string>;
	buildMobileRuntimeOutput: (action: "plan" | "show", options: MobileOptions) => string;
	latestMobileRuntimeArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	runNativeRuntime: (pi: ExtensionAPI, options: BrowserOptions) => Promise<string>;
	buildNativeRuntimeOutput: (action: "plan" | "show", options: BrowserOptions) => string;
	latestNativeRuntimeArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	writeCurrentMission: (mission: MissionState) => MissionState;
	updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => MissionState;
	formatMission: (mission: MissionState) => string;
	buildMissionDigest: () => string;
	formatLaneQueue: (mission: MissionState) => string;
	activeLane: (mission: MissionState, name?: string) => MissionLane | undefined;
	updateMissionLane: (params: {
		action: "next" | "done" | "block" | "set" | "add";
		lane?: string;
		status?: MissionLaneStatus;
		objective?: string;
		next?: string[];
		note?: string;
	}) => MissionState;
	laneCommandPack: (mission: MissionState, lane: MissionLane, target?: string) => TPack;
	formatLaneCommandPack: (pack: TPack) => string;
	runLaneCommandPack: (pi: ExtensionAPI, pack: TPack) => Promise<string>;
	runAutoLaneChain: (pi: ExtensionAPI, options: LaneRunOptions) => Promise<string>;
	runPassiveMap: (pi: ExtensionAPI, options: { target?: string; depth?: number }) => Promise<string>;
	runAutopilot: (pi: ExtensionAPI, options: AutopilotOptions) => Promise<string>;
	buildEvidenceDigest: (query?: string) => string;
	buildAttackGraphOutput: (action: "build" | "show") => string;
	latestAttackGraphArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	buildExploitChainOutput: (action: "plan" | "show" | "compose", options: TargetOptions) => string;
	latestExploitChainArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	buildCampaignOutput: (action: "plan" | "show", options: OperationOptions) => string;
	latestCampaignArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	runOperationQueue: (pi: ExtensionAPI, options: OperationOptions & { maxSteps?: number }) => Promise<string>;
	buildOperationOutput: (action: "plan" | "show" | "next", options: OperationOptions) => string;
	latestOperationArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	buildDelegateOutput: (action: "plan" | "show" | "merge", options: OperationOptions) => string;
	latestDelegateArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	runSwarm: (pi: ExtensionAPI, options: SwarmOptions) => Promise<string>;
	buildSwarmOutput: (action: "plan" | "show" | "merge", options: OperationOptions) => string;
	latestSwarmArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	buildSupervisorOutput: (action: "review" | "show" | "repair", options: SupervisorOptions) => Promise<string>;
	latestSupervisorArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	dispatchOperatorQueue: (pi: ExtensionAPI, options: LaneRunOptions) => Promise<string>;
	buildOperatorOutput: (action: "plan" | "show" | "verify" | "escalate", options: TargetOptions) => string;
	latestOperatorArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	buildVerifierOutput: (
		action: "check" | "show" | "matrix",
		options: TargetOptions & { techniqueId?: string },
	) => string;
	latestVerifierArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	buildCompilerOutput: (action: "draft" | "show" | "final", options: TargetOptions) => string;
	latestCompilerArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	runReplayer: (
		pi: ExtensionAPI,
		options: TargetOptions & { maxSteps?: number; timeoutMs?: number },
	) => Promise<string>;
	buildReplayerOutput: (action: "plan" | "show", options: TargetOptions) => string;
	latestReplayerArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	buildAutofixOutput: (action: "plan" | "show" | "apply", options: TargetOptions) => string;
	latestAutofixArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	runProofLoop: (
		pi: ExtensionAPI,
		options: TargetOptions & { maxSteps?: number; replaySteps?: number },
	) => Promise<string>;
	buildProofLoopOutput: (
		action: "plan" | "show" | "run",
		options: TargetOptions & { maxSteps?: number; replaySteps?: number },
	) => string;
	latestProofLoopArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	buildProfileCheckOutput: (action: ProfileCheckMode | "show") => string;
	latestProfileCheckArtifactPath: () => string | undefined;
	createBootstrapPlan: (tools: string[]) => ReconCommandBootstrapPlan[];
	installBootstrapTools: (pi: ExtensionAPI, tools: string[]) => Promise<string>;
	formatBootstrapPlan: (plan: ReconCommandBootstrapPlan[]) => string;
	writeReportScaffold: (title?: string) => string;
	formatCompletionAudit: () => string;
	runCompletionAudit: () => TCompletionAudit;
	formatCompletionAuditFromAudit: (audit: TCompletionAudit) => string;
	buildToolDigest: () => string;
	refreshToolIndex: (pi: ExtensionAPI) => Promise<string>;
};

export function createReconTools<TCompletionAudit, TPack extends ReconCommandLanePack = ReconCommandLanePack>(
	dependencies: ReconToolDependencies<TCompletionAudit, TPack>,
) {
	const {
		routeReconTask,
		techniqueIdsForRoute,
		formatRoute,
		appendEvidence,
		appendAgentThreadEvidence,
		buildPentestingTaskTreeSnapshot,
		buildDomainProofExitClosure,
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
	} = dependencies;
	const artifactScope = (target: string | undefined, requestedBy: string): ArtifactScopeFilterOptions =>
		target ? { target, requestedBy } : { requestedBy };
	const ensureArtifactMission = (operation: string, target?: string): MissionState => {
		const current = readCurrentMission();
		if (current) return current;
		const task = target ? `${operation} ${target}` : operation;
		return writeCurrentMission(createMission(task, routeReconTask(task)));
	};
	const formatToolchainDomainSummary = (report: ToolchainDomainCapabilityV1, path: string): string =>
		[
			"toolchain_domain_capability:",
			"ToolchainDomainCapabilityV1: true",
			`artifact: ${path}`,
			`tool_index: ${report.toolIndexPath}`,
			`coverage: domains=${report.coverage.domainCount} ready=${report.coverage.readyCount} degraded=${report.coverage.degradedCount} blocked=${report.coverage.blockedCount}`,
			`closure: fallback=${report.toolchainClosure.allDomainsHaveFallback} playbook=${report.toolchainClosure.allDomainsHavePlaybookMarkers} commands=${report.toolchainClosure.allDomainsHaveCommandScaffolds} noCriticalGap=${report.toolchainClosure.noCriticalGap}`,
			"domain_status:",
			...report.domains
				.slice(0, 12)
				.map(
					(domain) =>
						`- ${domain.domainId} status=${domain.status} missing=${domain.missingRequired.slice(0, 5).join(",") || "none"} fallback=${domain.presentFallbacks.slice(0, 4).join(",") || "none"}`,
				),
			"next_actions:",
			...report.nextActions.slice(0, 5).map((item) => `- ${item}`),
		].join("\n");
	const formatRuntimeBridgeSummary = (report: ProfessionalRuntimeBridgesCheckV1, path: string): string =>
		[
			"professional_runtime_bridges:",
			"ProfessionalRuntimeBridgesCheckV1: true",
			`artifact: ${path}`,
			`closure: specs=${report.closure.allBridgeSpecsPresent} fallback=${report.closure.allFallbacksAvailable} executable=${report.closure.allHaveExecutableTemplates} artifact=${report.closure.allHaveArtifactPlans} proof=${report.closure.allHaveProofExitMappings} env_ref=${report.closure.allEnvRefsSecretFree}`,
			"bridge_status:",
			...report.bridges
				.slice(0, 10)
				.map(
					(bridge) =>
						`- ${bridge.bridgeId} status=${bridge.status} preferred=${bridge.presentPreferred.slice(0, 4).join(",") || "none"} fallback=${bridge.presentFallbacks.slice(0, 4).join(",") || "none"}`,
				),
			"next_runtime_commands:",
			...report.nextRuntimeCommands.slice(0, 5).map((item) => `- ${item}`),
		].join("\n");
	const formatRuntimeAdapterSummary = (report: RuntimeAdapterExecutionCheckV1, path: string): string =>
		[
			"runtime_adapter_execution:",
			"RuntimeAdapterExecutionCheckV1: true",
			`artifact: ${path}`,
			report.targetProfile
				? `target_profile: kinds=${report.targetProfile.targetKinds.join(",")} adapters=${report.targetProfile.adapterIds.join(",") || "none"} magic=${report.targetProfile.magic ?? "none"}`
				: undefined,
			`closure: specs=${report.closure.allAdapterSpecsPresent} runner=${report.closure.allHaveRunnerTemplates} parser=${report.closure.allHaveParserRules} artifact=${report.closure.allHaveArtifactKinds} ingest=${report.closure.allHaveIngestTargets} proof=${report.closure.allHaveProofExitSignals} fallback=${report.closure.allHaveNativeOrFallbackTool} env_ref=${report.closure.allEnvRefsSecretFree}`,
			"adapter_status:",
			...report.adapters
				.slice(0, 12)
				.map(
					(adapter) =>
						`- adapter:${adapter.adapterId} domain=${adapter.domainId} status=${adapter.status} tool=${adapter.tool} fallback=${adapter.fallbackTool}`,
				),
			"next_runtime_commands:",
			...report.nextRuntimeCommands.slice(0, 5).map((item) => `- ${item}`),
		]
			.filter(Boolean)
			.join("\n");
	const formatLaneSpecialistSummary = (report: ReLaneSpecialistCommandPackCheckV1): string =>
		[
			"relane_specialist_command_pack:",
			"ReLaneSpecialistCommandPackCheckV1: true",
			`coverage: domains=${report.domainCount} ready=${report.readyDomainCount}`,
			`closure: route=${report.closure.allDomainsHaveRouteMatchers} lanes=${report.closure.allDomainsHaveLaneSeeds} command_pack=${report.closure.allDomainsHaveCommandPacks} analyzer=${report.closure.allDomainsHaveAnalyzerAnchors} self_heal=${report.closure.allDomainsHaveSelfHeal} proof_exit=${report.closure.allDomainsHaveProofExitBridge}`,
			"domain_status:",
			...report.rows
				.slice(0, 14)
				.map(
					(row) =>
						`- domain:${row.domainId} status=${row.status} lanes=${row.laneSeeds.slice(0, 5).join(",") || "none"} gaps=${row.gaps.join(",") || "none"}`,
				),
			"next_runtime_commands:",
			...report.nextRuntimeCommands.slice(0, 5).map((item) => `- ${item}`),
		].join("\n");
	const formatDomainProofExitSummary = (report: DomainProofExitClosure, path?: string): string =>
		[
			"domain_proof_exit_closure:",
			"DomainProofExitClosureV1: true",
			path ? `artifact: ${path}` : undefined,
			`status: ${report.status}`,
			`domain: ${report.domainId ?? "unmapped"}`,
			`toolchain_status: ${report.toolchainStatus ?? "unknown"}`,
			`proof_exits: total=${report.rows.length} matched=${report.matchedProofExits.length} missing=${report.missingProofExits.length}`,
			`artifact_corpus_sha256: ${report.artifactCorpusHash}`,
			`artifact_sources: ${report.artifactSources.length}`,
			"missing:",
			...(report.missingProofExits.length
				? report.missingProofExits.slice(0, 6).map((item) => `- ${item}`)
				: ["- none"]),
			"blockers:",
			...(report.blockers.length
				? report.blockers.slice(0, 5).map((item) => `- ${truncateMiddle(item, 240)}`)
				: ["- none"]),
			"next_runtime_commands:",
			...report.nextRuntimeCommands.slice(0, 5).map((item) => `- ${item}`),
		]
			.filter(Boolean)
			.join("\n");
	const formatToolIndexSummary = (text: string): string => {
		const rows = text.split(/\r?\n/).filter((line) => /^\|\s*[^-].*\|$/.test(line) && !/^\|\s*Tool\s*\|/i.test(line));
		const present = rows.filter((line) => /\|\s*yes\s*\|/i.test(line));
		const missing = rows.filter((line) => /\|\s*no\s*\|/i.test(line));
		const toolName = (line: string) => line.split("|")[1]?.trim() ?? "unknown";
		return [
			"tool_index:",
			`path: ${toolIndexPath()}`,
			`coverage: total=${rows.length} present=${present.length} missing=${missing.length}`,
			`present_tools: ${present.slice(0, 16).map(toolName).join(", ") || "none"}`,
			`missing_tools: ${missing.slice(0, 16).map(toolName).join(", ") || "none"}`,
			`verify: cat ${toolIndexPath()}`,
		].join("\n");
	};
	const compactAgentThreadMerge = (text: string): string => {
		const handoff = /## (?:Validated worker handoff|Recovered worker output)\s+```text\s+([\s\S]*?)\s+```/i.exec(
			text,
		)?.[1];
		const source = handoff ?? text;
		const lines = source.split(/\r?\n/);
		const selected: string[] = [];
		for (let index = 0; index < lines.length; index++) {
			const line = lines[index]?.trim() ?? "";
			if (!line) continue;
			if (
				/^(?:#{1,4}\s*)?(?:Outcome|Status|Key Evidence|Verification|Next Step|Claims?|Blockers?|Artifacts?|verdict|repro|counter_evidence|notes)\b/i.test(
					line,
				) ||
				/\b(?:artifact|sha256|offset|run_id|mission_id|handoff_path|command|blocker|claim):/i.test(line)
			) {
				selected.push(truncateMiddle(line, 300));
				for (let lookahead = index + 1; lookahead < Math.min(lines.length, index + 3); lookahead++) {
					const detail = lines[lookahead]?.trim();
					if (!detail || /^#{1,4}\s/.test(detail)) break;
					selected.push(truncateMiddle(detail, 300));
				}
			}
		}
		return truncateMiddle(Array.from(new Set(selected)).slice(0, 20).join("\n") || source, 2400);
	};
	const compactAgentThreadError = (error: unknown): string =>
		redactSensitiveText(error instanceof Error ? error.message : String(error), 1200);
	return function installReconTools(pi: ExtensionAPI): void {
		pi.registerTool({
			name: "re_route",
			label: "RE Route",
			description:
				"Route a reverse engineering, CTF, pwn, web/API, mobile, cloud, identity, or DFIR task and return the minimal workflow.",
			promptSnippet: "Route reverse/pentest tasks before executing them.",
			promptGuidelines: [
				"For reverse or pentest tasks, call re_route or state equivalent routing before deep execution.",
			],
			parameters: Type.Object({ task: Type.String() }),
			async execute(_toolCallId, params) {
				const route = routeReconTask(params.task);
				const techniqueIds = techniqueIdsForRoute(route);
				return {
					content: [
						{
							type: "text" as const,
							text: [
								formatRoute(route),
								`skill: ${route.skillHint}`,
								...route.workflow.map((step) => `- ${step}`),
								...(techniqueIds.length > 0
									? [
											`techniques: ${techniqueIds.join(", ")} (call re_techniques(domain=...) for full playbooks)`,
										]
									: []),
							].join("\n"),
						},
					],
					details: { ...route, techniques: techniqueIds },
				};
			},
		});
		pi.registerTool({
			name: "re_techniques",
			label: "RE Advanced Techniques",
			description:
				"Pull concrete top-tier offensive-technique playbooks (pwn heap/web/crypto/reverse/mobile/identity-AD/cloud/malware/agent) with MITRE ATT&CK + CWE tags, triggers, ordered procedure, falsifiable proof-exit, pitfalls, and required tools. Use after re_route to ground execution in real high-skill methodology instead of tool-running.",
			promptSnippet:
				"Call re_techniques(domain=<domain>) for the playbook of advanced techniques in a routed domain, or re_techniques(id=<id>) for a single technique, before executing the technique.",
			promptGuidelines: [
				"After re_route resolves a domain, call re_techniques(domain=...) for a compact technique selection index with MITRE ATT&CK + CWE tags and falsifiable proof exits.",
				"Use re_techniques(id=<id>) to pull one technique's full procedure + proof-exit + pitfalls after the selection index identifies the next method.",
				"Every technique's proofExit is falsifiable — verify the stated observation before claiming the technique succeeded; record failures via re_evidence append.",
			],
			parameters: Type.Object({
				domain: Type.Optional(Type.String()),
				id: Type.Optional(Type.String()),
				intent: Type.Optional(Type.String()),
				format: Type.Optional(Type.Union([Type.Literal("index"), Type.Literal("playbook")])),
			}),
			async execute(_toolCallId, params) {
				const format = params.format ?? (params.id || params.domain ? "playbook" : "index");
				if (format === "index" && !params.id && !params.domain) {
					return {
						content: [{ type: "text" as const, text: truncateMiddle(formatTechniqueIndex(), 4096) }],
						details: { format: "index", count: ADVANCED_TECHNIQUES.length } as Record<string, unknown>,
					};
				}
				const entries: (typeof ADVANCED_TECHNIQUES)[number][] = [];
				if (params.id) {
					const entry = techniqueById(params.id);
					if (entry) entries.push(entry);
				} else if (params.domain) {
					const domain = resolveTechniqueDomain(params.domain);
					const domainEntries = domain ? techniquesForDomain(domain) : [];
					if (params.intent) {
						const needle = params.intent.toLowerCase();
						const filtered = domainEntries.filter(
							(entry) =>
								entry.name.toLowerCase().includes(needle) ||
								entry.triggers.toLowerCase().includes(needle) ||
								entry.procedure.some((step) => step.toLowerCase().includes(needle)),
						);
						entries.push(...(filtered.length > 0 ? filtered : domainEntries));
					} else {
						entries.push(...domainEntries);
					}
				}
				const text =
					!params.id && entries.length > 1
						? truncateMiddle(
								[
									"REPI technique selection index",
									"detail: call re_techniques(id=<id>) for the full ordered procedure and pitfalls",
									...entries.map((entry) => {
										const taxonomy = [
											entry.mitre?.length ? entry.mitre.map(formatMitreTag).join(", ") : undefined,
											entry.cwe?.length ? formatCweTags(entry.cwe) : undefined,
										]
											.filter(Boolean)
											.join(" | ");
										return [
											`- ${entry.id}: ${truncateMiddle(entry.name, 80)}`,
											taxonomy ? `taxonomy=${truncateMiddle(taxonomy, 120)}` : undefined,
											`trigger=${truncateMiddle(entry.triggers, 80)}`,
											`proof-exit=${truncateMiddle(entry.proofExit, 120)}`,
										]
											.filter((line): line is string => Boolean(line))
											.join(" | ");
									}),
								].join("\n"),
								4096,
							)
						: truncateMiddle(formatTechniquePlaybook(entries), 4096);
				return {
					content: [{ type: "text" as const, text }],
					details: {
						format: "playbook",
						domain: params.domain,
						id: params.id,
						intent: params.intent,
						resolvedDomain: params.domain ? resolveTechniqueDomain(params.domain) : undefined,
						matched: entries.length,
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_kernel",
			label: "RE Kernel",
			description:
				"Build, show, or audit the REPI execution kernel: directive stack, refusal-to-execution rewrites, tool policy, artifact contract, and stall recovery.",
			promptSnippet:
				"Use re_kernel at reverse/pentest task start or after compaction to convert intent into execution-first directives and next operator actions.",
			promptGuidelines: [
				"Call re_kernel build before re_map on new reverse/pentest tasks when execution policy or next actions are unclear.",
				"Use refusal_to_execution_rules to turn missing target/tool/context into concrete re_map, re_lane, bootstrap, verifier, or autofix actions.",
				"Persist execution-kernel artifacts before final completion when the task involves agent profile/runtime modification.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("build"), Type.Literal("show"), Type.Literal("audit")])),
				target: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "build";
				const text = buildKernelOutput(action, { target: params.target });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestKernelArtifactPath(artifactScope(params.target, "re_kernel_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_decision_core",
			label: "RE Decision Core",
			description:
				"Plan, show, tick, or run the REPI decision core: objective stack, checkpoint pressure, evidence priority, tool/artifact posture, decision rules, and operator queue.",
			promptSnippet:
				"Use re_decision_core when the next reverse/pentest action is unclear or after major evidence changes to select a concrete operator_next_command.",
			promptGuidelines: [
				"Call re_decision_core tick after re_kernel build, compaction resume, or any major artifact update.",
				"Use decision_rules and check_pressure to choose re_map, re_lane, re_chain, re_operator, verifier, compiler, replayer, or autofix actions.",
				"Do not continue with narrative-only output when decision_core has an operator_next_command.",
			],
			parameters: Type.Object({
				action: Type.Optional(
					Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("tick"), Type.Literal("run")]),
				),
				target: Type.Optional(Type.String()),
				maxSteps: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text =
					action === "run"
						? await runDecisionCore(pi, { target: params.target, maxSteps: params.maxSteps })
						: buildDecisionCoreOutput(action, { target: params.target });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestDecisionCoreArtifactPath(artifactScope(params.target, "re_decision_core_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_live_browser",
			label: "RE Live Browser",
			description:
				"Plan, show, or run browser/XHR/WebSocket runtime capture with Playwright-if-installed and node-fetch fallback, producing auth matrix, IDOR/BOLA probes, replay commands, and runtime anchors.",
			promptSnippet:
				"Use re_live_browser for Web/API/JS reverse/pentest tasks after re_map to capture rendered requests, responses, storage, WebSockets, and replay probes.",
			promptGuidelines: [
				"Call re_live_browser plan for HTTP(S) targets before claiming route/auth/session behavior.",
				"Call re_live_browser run with a concrete URL to capture request_response_log, runtime_anchors, storage, and WebSocket evidence.",
				"Feed browser_artifact into re_verifier, re_operator, and re_graph before final reporting.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("run")])),
				target: Type.Optional(Type.String()),
				url: Type.Optional(Type.String()),
				timeoutMs: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text =
					action === "run"
						? await runLiveBrowser(pi, { target: params.target, url: params.url, timeoutMs: params.timeoutMs })
						: buildLiveBrowserOutput(action, {
								target: params.target,
								url: params.url,
								timeoutMs: params.timeoutMs,
							});
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestLiveBrowserArtifactPath(
							artifactScope(params.url ?? params.target, "re_live_browser_tool_result"),
						),
						target: params.target,
						url: params.url,
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_web_authz_state",
			label: "RE Web Authz State",
			description:
				"Plan, show, or run Web/API authorization state capture with principal matrix, object ownership probes, sequence replay, rollback checks, and artifact JSON.",
			promptSnippet:
				"Use re_web_authz_state for Web/API authorization, IDOR, BOLA, JWT/session, object ownership, and state-machine claims after re_live_browser or re_map.",
			promptGuidelines: [
				"Call re_web_authz_state plan for Web/API targets to define principal, object, sequence, and rollback evidence contracts.",
				"Call re_web_authz_state run with COOKIE_A/COOKIE_B or AUTH_A/AUTH_B to capture principal status/body-hash matrix and object ownership anchors.",
				"Enable mutation rollback only with REPI_AUTHZ_MUTATE=1 and restore fixtures; default run is read-only and observability-first.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("run")])),
				target: Type.Optional(Type.String()),
				url: Type.Optional(Type.String()),
				timeoutMs: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text =
					action === "run"
						? await runWebAuthzState(pi, { target: params.target, url: params.url, timeoutMs: params.timeoutMs })
						: buildWebAuthzStateOutput(action, {
								target: params.target,
								url: params.url,
								timeoutMs: params.timeoutMs,
							});
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestWebAuthzStateArtifactPath(
							artifactScope(params.url ?? params.target, "re_web_authz_state_tool_result"),
						),
						target: params.target,
						url: params.url,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_exploit_lab",
			label: "RE Exploit Lab",
			description:
				"Plan, run, show, or bundle an exploit reliability lab with PoC inventory, environment pinning, replay matrix, flake triage, hashes, and bundle manifest.",
			promptSnippet:
				"Use re_exploit_lab for exploit/PoC/autopwn tasks before final claims to prove stability across bounded replay runs.",
			promptGuidelines: [
				"Call re_exploit_lab plan for exploit reliability tasks after re_lane or re_replayer has produced a PoC target.",
				"Call re_exploit_lab run with a concrete PoC path or REPI_EXPLOIT_CMD to capture success_rate, output hashes, and flake triage.",
				"Feed exploit_lab_artifact into re_verifier, re_compiler, re_replayer, and re_graph before final reporting.",
			],
			parameters: Type.Object({
				action: Type.Optional(
					Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("run"), Type.Literal("bundle")]),
				),
				target: Type.Optional(Type.String()),
				runs: Type.Optional(Type.Number()),
				timeoutMs: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text =
					action === "run"
						? await runExploitLab(pi, { target: params.target, runs: params.runs, timeoutMs: params.timeoutMs })
						: buildExploitLabOutput(action, {
								target: params.target,
								runs: params.runs,
								timeoutMs: params.timeoutMs,
							});
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestExploitLabArtifactPath(artifactScope(params.target, "re_exploit_lab_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_mobile_runtime",
			label: "RE Mobile Runtime",
			description:
				"Plan, show, or run Android/APK mobile runtime capture with ADB/Frida readiness, APK inventory, process map, Java crypto hooks, native compare hooks, anti-debug checks, and replay commands.",
			promptSnippet:
				"Use re_mobile_runtime for APK/Android/mobile reverse tasks after re_map or before claiming runtime hook, crypto, native compare, anti-debug, or package behavior.",
			promptGuidelines: [
				"Call re_mobile_runtime plan for APK/package targets to generate ADB/Frida hook strategy and artifact contract.",
				"Call re_mobile_runtime run with a concrete APK or packageName to capture tool readiness, device/process map, hook template, anti-debug strings, and runtime anchors.",
				"Set REPI_MOBILE_ATTACH=1 only when you want bounded live Frida attach; default run remains observability-first and non-attaching.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("run")])),
				target: Type.Optional(Type.String()),
				packageName: Type.Optional(Type.String()),
				timeoutMs: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text =
					action === "run"
						? await runMobileRuntime(pi, {
								target: params.target,
								packageName: params.packageName,
								timeoutMs: params.timeoutMs,
							})
						: buildMobileRuntimeOutput(action, {
								target: params.target,
								packageName: params.packageName,
								timeoutMs: params.timeoutMs,
							});
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestMobileRuntimeArtifactPath(
							artifactScope(params.target ?? params.packageName, "re_mobile_runtime_tool_result"),
						),
						target: params.target,
						packageName: params.packageName,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_native_runtime",
			label: "RE Native Runtime",
			description:
				"Plan, show, or run native ELF/SO runtime capture with binary inventory, mitigations, loader/libc map, symbols, GDB trace, crash/register anchors, and pwntools scaffold.",
			promptSnippet:
				"Use re_native_runtime for ELF/SO/Pwn/native reverse tasks after re_map or before claiming crash offsets, libc/loader behavior, GDB trace, or exploit primitive state.",
			promptGuidelines: [
				"Call re_native_runtime plan for native targets to generate binary inventory, mitigation matrix, breakpoint plan, and artifact contract.",
				"Call re_native_runtime run with a concrete ELF/SO to capture tool readiness, checksec/readelf/ldd/symbol anchors, GDB script, and pwn scaffold.",
				"Set REPI_NATIVE_RUN=1 only when you want bounded live GDB execution; default run remains observability-first and non-executing.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("run")])),
				target: Type.Optional(Type.String()),
				timeoutMs: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text =
					action === "run"
						? await runNativeRuntime(pi, { target: params.target, timeoutMs: params.timeoutMs })
						: buildNativeRuntimeOutput(action, { target: params.target, timeoutMs: params.timeoutMs });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestNativeRuntimeArtifactPath(artifactScope(params.target, "re_native_runtime_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_mission",
			label: "RE Mission",
			description: "Create, inspect, or update the REPI mission blackboard and completion checkpoints.",
			promptSnippet: "Track reverse/pentest mission lanes, checkpoints, and next actions.",
			promptGuidelines: [
				"Use re_mission to keep task state explicit: route, lanes, evidence checkpoints, replay, and report checkpoints.",
			],
			parameters: Type.Object({
				action: Type.Union([Type.Literal("show"), Type.Literal("new"), Type.Literal("checkpoint")]),
				task: Type.Optional(Type.String()),
				check: Type.Optional(Type.String()),
				status: Type.Optional(Type.Union([Type.Literal("pending"), Type.Literal("done"), Type.Literal("blocked")])),
				note: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				if (params.action === "new") {
					const task = params.task ?? REPI_GENERIC_TASK;
					const mission = writeCurrentMission(createMission(task, routeReconTask(task)));
					return {
						content: [{ type: "text" as const, text: formatMission(mission) }],
						details: mission as unknown as Record<string, unknown>,
					};
				}
				if (params.action === "checkpoint") {
					const checkpointUpdate = normalizeOperatorCheckpointUpdate(
						params.check ?? "manual_check",
						params.status ?? "done",
						params.note,
					);
					const mission = updateMissionCheckpoint(
						params.check ?? "manual_check",
						checkpointUpdate.status,
						checkpointUpdate.note,
					);
					return {
						content: [{ type: "text" as const, text: formatMission(mission) }],
						details: mission as unknown as Record<string, unknown>,
					};
				}
				return {
					content: [{ type: "text" as const, text: buildMissionDigest() }],
					details: { path: currentMissionPath() },
				};
			},
		});
		pi.registerTool({
			name: "re_lane",
			label: "RE Lane",
			description: "Show, advance, complete, block, set, add, plan, run, or run-auto REPI mission lanes.",
			promptSnippet:
				"Use mission lanes as an executable queue with generated command packs for reverse/pentest workflows.",
			promptGuidelines: [
				"Call re_lane next to focus the active lane.",
				"Call re_lane plan with a lane/target to generate the smallest command pack before broad scanning.",
				"Call re_lane run only for command packs with concrete targets and no placeholder values.",
				"Call re_lane run-auto to execute bounded [auto:*] follow-up commands already attached to the active lane.",
				"Call re_lane done when a lane has evidence; this advances the queue and updates related checkpoints.",
				"Call re_lane block with a reason when the lane is stuck, then change evidence surface or toolchain.",
			],
			parameters: Type.Object({
				action: Type.Union([
					Type.Literal("show"),
					Type.Literal("next"),
					Type.Literal("done"),
					Type.Literal("block"),
					Type.Literal("set"),
					Type.Literal("add"),
					Type.Literal("plan"),
					Type.Literal("run"),
					Type.Literal("run-auto"),
				]),
				lane: Type.Optional(Type.String()),
				target: Type.Optional(Type.String()),
				max: Type.Optional(Type.Number()),
				status: Type.Optional(
					Type.Union([
						Type.Literal("pending"),
						Type.Literal("in_progress"),
						Type.Literal("done"),
						Type.Literal("blocked"),
					]),
				),
				objective: Type.Optional(Type.String()),
				next: Type.Optional(Type.Array(Type.String())),
				note: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				if (params.action === "show") {
					const mission = readCurrentMission();
					return {
						content: [{ type: "text" as const, text: mission ? formatLaneQueue(mission) : "no active mission" }],
						details: { path: currentMissionPath() } as Record<string, unknown>,
					};
				}
				if (params.action === "run-auto") {
					const text = await runAutoLaneChain(pi, {
						lane: params.lane,
						target: params.target,
						maxSteps: params.max,
					});
					return {
						content: [{ type: "text" as const, text }],
						details: { path: currentMissionPath() } as Record<string, unknown>,
					};
				}
				if (params.action === "plan" || params.action === "run") {
					const mission =
						readCurrentMission() ??
						writeCurrentMission(createMission("manual mission", routeReconTask(REPI_GENERIC_TASK)));
					const lane = activeLane(mission, params.lane);
					if (!lane) {
						return {
							content: [{ type: "text" as const, text: "no active lane" }],
							details: { path: currentMissionPath() } as Record<string, unknown>,
						};
					}
					updateMissionCheckpoint("repro_commands_ready", "done", `lane-command-pack:${lane.name}`);
					const laneTarget = params.target ?? (mission.route.domain === "Agent / LLM boundary" ? "." : undefined);
					const pack = laneCommandPack(mission, lane, laneTarget);
					const text = params.action === "run" ? await runLaneCommandPack(pi, pack) : formatLaneCommandPack(pack);
					return {
						content: [{ type: "text" as const, text }],
						details: pack as unknown as Record<string, unknown>,
					};
				}
				const mission = updateMissionLane({
					action: params.action,
					lane: params.lane,
					status: params.status,
					objective: params.objective,
					next: params.next,
					note: params.note,
				});
				return {
					content: [{ type: "text" as const, text: formatLaneQueue(mission) }],
					details: mission as unknown as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_map",
			label: "RE Map",
			description:
				"Run a passive target/workspace mapper, write a map artifact, append evidence, and satisfy the passive_map_done checkpoint.",
			promptSnippet: "Use re_map before broad exploitation to anchor files/routes/configs/binaries in evidence.",
			promptGuidelines: [
				"Call re_map early for reverse/pentest tasks to capture target stat, manifests, routes/auth strings, binary candidates, and HTTP baseline when applicable.",
				"Use the generated map_artifact path as the source of truth for subsequent lane command packs.",
			],
			parameters: Type.Object({
				target: Type.Optional(Type.String()),
				depth: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				const text = await runPassiveMap(pi, { target: params.target, depth: params.depth });
				return {
					content: [{ type: "text" as const, text }],
					details: { path: evidenceMapsDir(), target: params.target ?? "." } as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_autopilot",
			label: "RE Autopilot",
			description:
				"Run a bounded REPI automation chain: mission routing, re_map, bootstrap_plan, lane command pack/run, run-auto follow-ups, and completion audit.",
			promptSnippet:
				"Use re_autopilot to execute the full map→bootstrap→prove→audit loop when the target is concrete.",
			promptGuidelines: [
				"Prefer action=plan when the target is still ambiguous.",
				"Review bootstrap_plan and run re_bootstrap plan/install only when missing tools are required.",
				"Follow execution_strategy first: use fallback_commands/degraded pack before installing tools.",
				"Use action=run with maxAutoSteps bounded to prove one path before expanding sideways.",
				"Inspect the returned map/run artifacts before final claims.",
				"Set reasoning=llm to let a real planner subagent reason over the PTT snapshot and last run transcript to pick each run-auto step's next action (regex remains an explicit deterministic option). reasoning=llm is the DEFAULT.",
				"Set dispatch=specialist to hand each run-auto lane to the real specialist subagent that owns it (reverser for pwn/firmware/malware/native/mobile lanes, explorer for mapping/web/cloud, operator for execution, verifier for proof/report). Specialist mode fails closed when dispatch or artifact validation fails; set dispatch=inline explicitly for the deterministic command-pack path.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("run")])),
				task: Type.Optional(Type.String()),
				target: Type.Optional(Type.String()),
				lane: Type.Optional(Type.String()),
				mapDepth: Type.Optional(Type.Number()),
				maxAutoSteps: Type.Optional(Type.Number()),
				runAuto: Type.Optional(Type.Boolean()),
				cleanState: Type.Optional(Type.Boolean()),
				reasoning: Type.Optional(Type.Union([Type.Literal("regex"), Type.Literal("llm")])),
				dispatch: Type.Optional(Type.Union([Type.Literal("inline"), Type.Literal("specialist")])),
			}),
			async execute(_toolCallId, params, signal, _onUpdate, ctx) {
				const text = await runAutopilot(pi, {
					action: params.action,
					task: params.task,
					target: params.target,
					lane: params.lane,
					mapDepth: params.mapDepth,
					maxAutoSteps: params.maxAutoSteps,
					runAuto: params.runAuto,
					cleanState: params.cleanState,
					reasoning: params.reasoning,
					dispatch: params.dispatch,
					cwd: ctx?.cwd,
					signal,
				});
				return {
					content: [{ type: "text" as const, text }],
					details: { path: currentMissionPath(), target: params.target ?? "<auto>" } as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_evidence",
			label: "RE Evidence",
			description: "Append, search, or show REPI evidence with runtime-first priority metadata.",
			promptSnippet: "Record decisive evidence and falsifiable hypothesis state before making claims.",
			promptGuidelines: [
				"Use re_evidence append for runtime behavior, traffic, served assets, process config, artifacts, source, and operator notes.",
				"Prefer P1/P2 evidence over source names or comments when evidence conflicts.",
				"For a claim, set claimId, hypothesis, prediction, observation, and verdict; use contradicted/inconclusive instead of narrating around a failed prediction.",
				"Set proved only when observation is bound to a reproducible command/request and a verifier or counterexample probe has passed.",
			],
			parameters: Type.Object({
				action: Type.Union([Type.Literal("show"), Type.Literal("append"), Type.Literal("search")]),
				kind: Type.Optional(
					Type.Union([
						Type.Literal("runtime"),
						Type.Literal("traffic"),
						Type.Literal("served_asset"),
						Type.Literal("process_config"),
						Type.Literal("artifact"),
						Type.Literal("source"),
						Type.Literal("note"),
					]),
				),
				title: Type.Optional(Type.String()),
				fact: Type.Optional(Type.String()),
				command: Type.Optional(Type.String()),
				path: Type.Optional(Type.String()),
				offset: Type.Optional(Type.String()),
				hash: Type.Optional(Type.String()),
				verify: Type.Optional(Type.String()),
				confidence: Type.Optional(Type.String()),
				claimId: Type.Optional(Type.String()),
				hypothesis: Type.Optional(Type.String()),
				prediction: Type.Optional(Type.String()),
				observation: Type.Optional(Type.String()),
				counterexample: Type.Optional(Type.String()),
				verdict: Type.Optional(
					Type.Union([
						Type.Literal("proposed"),
						Type.Literal("supported"),
						Type.Literal("contradicted"),
						Type.Literal("inconclusive"),
						Type.Literal("proved"),
					]),
				),
				query: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				if (params.action === "append") {
					const evidence = appendEvidence({
						kind: params.kind ?? "note",
						title: params.title ?? "agent evidence",
						fact: params.fact ?? "",
						command: params.command,
						path: params.path,
						offset: params.offset,
						hash: params.hash,
						verify: params.verify,
						confidence: params.confidence,
						claimId: params.claimId,
						hypothesis: params.hypothesis,
						prediction: params.prediction,
						observation: params.observation,
						counterexample: params.counterexample,
						verdict: params.verdict,
					});
					return {
						content: [
							{
								type: "text" as const,
								text: `Appended evidence: P${evidence.priority} ${evidence.kind} ${evidence.title}`,
							},
						],
						details: evidence as unknown as Record<string, unknown>,
					};
				}
				return {
					content: [
						{
							type: "text" as const,
							text: buildEvidenceDigest(params.action === "search" ? params.query : undefined),
						},
					],
					details: { path: evidenceLedgerPath(), action: params.action },
				};
			},
		});
		pi.registerTool({
			name: "re_graph",
			label: "RE Graph",
			description:
				"Build or show a REPI mission attack graph from mission lanes, checkpoints, passive maps, run artifacts, evidence ledger, and tool-index gaps.",
			promptSnippet:
				"Use re_graph to organize reverse/pentest work into a critical path, gaps, and next executable actions.",
			promptGuidelines: [
				"Call re_graph build after map/run/evidence updates to keep the operation graph current.",
				"Use graph gaps and operator_next_actions to choose the next lane or bootstrap step.",
			],
			parameters: Type.Object({
				action: Type.Union([Type.Literal("build"), Type.Literal("show")]),
			}),
			async execute(_toolCallId, params) {
				const text = buildAttackGraphOutput(params.action);
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action: params.action,
						path: latestAttackGraphArtifactPath({ requestedBy: "re_graph_tool_result" }),
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_exploit_chain",
			label: "RE Exploit Chain",
			description:
				"Plan, show, or compose a REPI exploit chain from map, runtime, authz, native/mobile, exploit-lab, verifier, compiler, replayer, and evidence artifacts.",
			promptSnippet:
				"Use re_exploit_chain before broad expansion or final exploitability claims to bind proof_path, exploit_path, evidence_gaps, replay_commands, and operator_queue.",
			promptGuidelines: [
				"Call re_exploit_chain plan after re_map/re_live_browser/re_native_runtime or when deciding the next operator command.",
				"Call re_exploit_chain compose before final claims to connect map/runtime/authz/primitive/lab/verifier artifacts into one chain artifact.",
				"Use evidence_gaps and operator_queue from exploit_chain to drive re_operator, re_verifier, re_compiler, and re_replayer.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("compose")])),
				target: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text = buildExploitChainOutput(action, { target: params.target });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestExploitChainArtifactPath(artifactScope(params.target, "re_chain_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_campaign",
			label: "RE Campaign",
			description:
				"Build or show a cross-domain REPI reverse/pentest campaign graph from mission, passive map, attack graph, lane runs, evidence, pivots, and tool gaps.",
			promptSnippet:
				"Use re_campaign to upgrade a single lane into a multi-phase campaign graph with pivots and operator actions.",
			promptGuidelines: [
				"Call re_campaign plan after re_map/re_graph or before expanding sideways across web, identity, cloud, pwn, firmware, DFIR, malware, or agent-security lanes.",
				"Use campaign_graph phases, pivot_candidates, evidence_gaps, tool_gaps, and operator_next_actions as the next execution queue.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("show")])),
				target: Type.Optional(Type.String()),
				task: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text = buildCampaignOutput(action, { target: params.target, task: params.task });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestCampaignArtifactPath(artifactScope(params.target, "re_campaign_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_operation",
			label: "RE Operation",
			description:
				"Build, inspect, or run a bounded REPI operation queue from the campaign graph and dispatch phase steps through internal runners.",
			promptSnippet:
				"Use re_operation after re_campaign to turn phases into a concrete execution queue and run one bounded step.",
			promptGuidelines: [
				"Call re_operation plan/next to inspect the queue before broad execution.",
				"Call re_operation run with maxSteps bounded to dispatch only concrete internal commands and write operation artifacts.",
				"Use operation_queue blocked entries to fix target/tool/lane gaps before continuing.",
			],
			parameters: Type.Object({
				action: Type.Optional(
					Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("next"), Type.Literal("run")]),
				),
				target: Type.Optional(Type.String()),
				task: Type.Optional(Type.String()),
				maxSteps: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text =
					action === "run"
						? await runOperationQueue(pi, { target: params.target, task: params.task, maxSteps: params.maxSteps })
						: buildOperationOutput(action, { target: params.target, task: params.task });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestOperationArtifactPath(artifactScope(params.target, "re_operation_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_delegate",
			label: "RE Delegate",
			description:
				"Build, show, or merge specialist worker packets from the REPI operation queue for multi-expert reverse/pentest orchestration.",
			promptSnippet:
				"Use re_delegate after re_operation to split work into specialist packets and merge evidence contracts.",
			promptGuidelines: [
				"Call re_delegate plan to create worker_packets before spreading across domains.",
				"Use each packet handoff/evidence_contract as the exact specialist subtask contract.",
				"Call re_delegate merge after packets or operation steps update to consolidate specialist coverage and gaps.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("merge")])),
				target: Type.Optional(Type.String()),
				task: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text = buildDelegateOutput(action, { target: params.target, task: params.task });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestDelegateArtifactPath(artifactScope(params.target, "re_delegate_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_swarm",
			label: "RE Swarm",
			description:
				"Build, show, run, or merge multi-specialist swarm runtime packets from delegation worker_packets, emitting ReconParallelPlanV1, planCoverage, releaseCheckMetadata, bounded worker executions, parallel groups, merge protocol, collision matrix, and commander next actions.",
			promptSnippet:
				"Use re_swarm after re_delegate to organize specialist work as ReconParallelPlanV1-backed worker runtime packets with merge contracts and release-check metadata.",
			promptGuidelines: [
				"Call re_swarm plan after re_delegate plan/merge before broad multi-lane expansion.",
				"Use worker_runtime_packets plus parallel_plan.workers as exact sub-agent handoff contracts with evidence requirements, artifactGlobs, limits, and merge keys.",
				"Call re_swarm run with bounded maxWorkers/maxCommands to execute ready worker commands and produce worker_results/merge_digest.",
				"Set execution=real to dispatch each ready worker as a real process-isolated re_subagent (spec mapped from worker role: reverser for native/pwn/firmware/mobile/malware, verifier for audit/report, explorer for web/cloud/identity/mapping, operator otherwise) in parallel within each group. execution=real is the DEFAULT; set execution=simulated explicitly for an in-process dispatcher. Real swarm fails closed when cwd is unavailable or recursive worker dispatch is forbidden; it never falls back to simulated execution.",
				"Call re_swarm merge before re_supervisor review so conflicts, planCoverage gaps, and missing evidence become explicit.",
			],
			parameters: Type.Object({
				action: Type.Optional(
					Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("run"), Type.Literal("merge")]),
				),
				target: Type.Optional(Type.String()),
				task: Type.Optional(Type.String()),
				maxWorkers: Type.Optional(Type.Number()),
				maxCommands: Type.Optional(Type.Number()),
				execution: Type.Optional(Type.Union([Type.Literal("simulated"), Type.Literal("real")])),
			}),
			async execute(_toolCallId, params, signal, _onUpdate, ctx) {
				const action = params.action ?? "plan";
				const text =
					action === "run"
						? await runSwarm(pi, {
								target: params.target,
								task: params.task,
								maxWorkers: params.maxWorkers,
								maxCommands: params.maxCommands,
								execution: params.execution,
								cwd: ctx?.cwd,
								signal,
							})
						: buildSwarmOutput(action, { target: params.target, task: params.task });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestSwarmArtifactPath(artifactScope(params.target, "re_swarm_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_supervisor",
			label: "RE Supervisor",
			description:
				"Review, show, or repair REPI specialist worker packets using a supervisor critic over ReconParallelPlanV1, planCoverage, claimCheckPolicy, evidence, conflicts, checkpoints, and priority queues.",
			promptSnippet:
				"Use re_supervisor after re_swarm/re_delegate to score worker evidence, enforce planCoverage/claimCheckPolicy, find conflicts, and produce repair queues.",
			promptGuidelines: [
				"Call re_supervisor review before final claims or when worker packets, planCoverage, or claim checkpoints conflict.",
				"Use supervisor planCoverage, claimCheckPolicy, repair_queue, and priority_queue to choose the next re_swarm/re_operation or lane action.",
				"Call re_supervisor repair after blocked/weak worker packets to generate a concrete recovery queue.",
				"Use reasoning=llm to dispatch an independent verifier subagent that adversarially critiques the rule-based score (finds attempted-as-proved handoffs and recommends re-dispatch); default rules is rule-based scoring only.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("review"), Type.Literal("show"), Type.Literal("repair")])),
				target: Type.Optional(Type.String()),
				task: Type.Optional(Type.String()),
				reasoning: Type.Optional(Type.Union([Type.Literal("rules"), Type.Literal("llm")])),
			}),
			async execute(_toolCallId, params, signal, _onUpdate, ctx) {
				const action = params.action ?? "review";
				const text = await buildSupervisorOutput(action, {
					target: params.target,
					task: params.task,
					reasoning: params.reasoning,
					cwd: ctx?.cwd,
					signal,
				});
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestSupervisorArtifactPath(artifactScope(params.target, "re_supervisor_tool_result")),
						target: params.target,
						reasoning: params.reasoning ?? "rules",
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_operator",
			label: "RE Operator",
			description:
				"Plan, dispatch, verify, or escalate the REPI operator queue derived from context next_operator_commands.",
			promptSnippet:
				"Use re_operator after evidence collection to turn the current mission into a bounded executable queue with verification and escalation.",
			promptGuidelines: [
				"Call re_operator plan before dispatching a resumed mission.",
				"Call re_operator dispatch with a small maxSteps value, then re_operator verify.",
				"Call re_operator escalate when checkpoints or artifacts remain blocked.",
			],
			parameters: Type.Object({
				action: Type.Optional(
					Type.Union([
						Type.Literal("plan"),
						Type.Literal("show"),
						Type.Literal("dispatch"),
						Type.Literal("verify"),
						Type.Literal("escalate"),
					]),
				),
				target: Type.Optional(Type.String()),
				maxSteps: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
				const action = params.action ?? "plan";
				const text =
					action === "dispatch"
						? await dispatchOperatorQueue(pi, {
								target: params.target,
								maxSteps: params.maxSteps,
								cwd: ctx?.cwd,
							})
						: buildOperatorOutput(action, { target: params.target });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestOperatorArtifactPath(artifactScope(params.target, "re_operator_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_verifier",
			label: "RE Verifier",
			description:
				"Build, show, or matrix-check REPI evidence assertions and counter-evidence from operator execution artifacts.",
			promptSnippet:
				"Use re_verifier after re_operator dispatch/verify to convert execution output into assertions, evidence bindings, counter-evidence, and next verifier actions.",
			promptGuidelines: [
				"Call re_verifier check after operator dispatch before claiming a result.",
				"Use contradictions and gaps to drive re_operator escalate or another bounded dispatch.",
				"Call re_verifier matrix before re_complete audit for a final evidence assertion pass.",
				"When the claim targets a named catalogued technique, pass technique=<id> (from re_techniques) to bind the assertion to that technique's falsifiable proofExit — the contract surfaces the exact done-when and counter-evidence probes to attempt.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("check"), Type.Literal("show"), Type.Literal("matrix")])),
				target: Type.Optional(Type.String()),
				technique: Type.Optional(
					Type.String({
						description:
							"Catalogued technique id (e.g. pwn-tcache-poisoning) to bind a falsifiable proof-contract from its proofExit.",
					}),
				),
			}),
			async execute(_toolCallId, params) {
				ensureArtifactMission("verify reverse/pentest evidence", params.target);
				const action = params.action ?? "check";
				const text = buildVerifierOutput(action, { target: params.target, techniqueId: params.technique });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestVerifierArtifactPath(artifactScope(params.target, "re_verifier_tool_result")),
						target: params.target,
						technique: params.technique,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_compiler",
			label: "RE Compiler",
			description:
				"Compile REPI verifier matrices into final report scaffolds, key evidence blocks, repro commands, contradictions, gaps, and next operator queues.",
			promptSnippet:
				"Use re_compiler after re_verifier matrix to turn proved/weak/contradicted/missing assertions into a final writeup skeleton.",
			promptGuidelines: [
				"Call re_compiler draft after re_verifier matrix and before re_complete audit.",
				"Use next_operator_queue when weak/missing/contradicted assertions remain.",
				"Call re_compiler final once the verifier matrix is clean enough for a report artifact.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("draft"), Type.Literal("show"), Type.Literal("final")])),
				target: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				ensureArtifactMission("compile reverse/pentest evidence", params.target);
				const action = params.action ?? "draft";
				const text = buildCompilerOutput(action, { target: params.target });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestCompilerArtifactPath(artifactScope(params.target, "re_compiler_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_replayer",
			label: "RE Replayer",
			description:
				"Plan, show, or execute a bounded replay matrix from REPI compiler repro_commands, recording exit codes, output hashes, blocked commands, and next actions.",
			promptSnippet:
				"Use re_replayer after re_compiler draft/final to prove report repro commands still execute and to capture stdout/stderr hashes.",
			promptGuidelines: [
				"Call re_replayer plan to inspect concrete replay commands before execution.",
				"Call re_replayer run with a small maxSteps value to produce replay_matrix evidence.",
				"Use blocked/failed replay rows to return to re_compiler or re_operator instead of claiming reproducibility.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("run")])),
				target: Type.Optional(Type.String()),
				maxSteps: Type.Optional(Type.Number()),
				timeoutMs: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				ensureArtifactMission("replay reverse/pentest evidence", params.target);
				const action = params.action ?? "plan";
				const text =
					action === "run"
						? await runReplayer(pi, {
								target: params.target,
								maxSteps: params.maxSteps,
								timeoutMs: params.timeoutMs,
							})
						: buildReplayerOutput(action, { target: params.target });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestReplayerArtifactPath(artifactScope(params.target, "re_replayer_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_autofix",
			label: "RE Autofix",
			description: "Plan, show, or queue REPI repair work from replay failed/blocked rows and compiler gaps.",
			promptSnippet: "Use re_autofix after re_replayer run when replay_matrix has blocked or failed rows.",
			promptGuidelines: [
				"Call re_autofix plan after replay failures to generate patch_queue, command_substitutions, bootstrap_queue, and evidence_recapture_queue.",
				"Call re_autofix apply only to mark the queue for dispatch; it does not execute commands. Run re_operator dispatch and inspect its runtime artifact before replay.",
				"Use next_operator_queue from autofix before re_complete audit when replay_ready is weak or failed.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("apply")])),
				target: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text = buildAutofixOutput(action, { target: params.target });
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestAutofixArtifactPath(artifactScope(params.target, "re_autofix_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_proof_loop",
			label: "RE Proof Loop",
			description:
				"Plan, show, or run a bounded REPI proof loop that chains verifier matrix, compiler draft/final, replay matrix, autofix repair, specialist delegate/swarm/supervisor bridge, and completion audit.",
			promptSnippet:
				"Use re_proof_loop after decision/operator execution to close verifier→compiler→replayer→autofix and route partial/repair gaps into specialist_queue/swarm_bridge instead of stopping at narrative-only evidence.",
			promptGuidelines: [
				"Call re_proof_loop plan to inspect the exact proof/repair phases before final claims.",
				"Call re_proof_loop run with bounded maxSteps after re_decision_core run or re_operator dispatch.",
				"Use proof_loop verdict, specialist_queue, swarm_bridge, and next_proof_actions to decide whether to delegate/swarm/supervise, replay, autofix, compile final, or complete audit.",
			],
			parameters: Type.Object({
				action: Type.Optional(Type.Union([Type.Literal("plan"), Type.Literal("show"), Type.Literal("run")])),
				target: Type.Optional(Type.String()),
				maxSteps: Type.Optional(Type.Number()),
				replaySteps: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "plan";
				const text =
					action === "run"
						? await runProofLoop(pi, {
								target: params.target,
								maxSteps: params.maxSteps,
								replaySteps: params.replaySteps,
							})
						: buildProofLoopOutput(action, {
								target: params.target,
								maxSteps: params.maxSteps,
								replaySteps: params.replaySteps,
							});
				return {
					content: [{ type: "text" as const, text }],
					details: {
						action,
						path: latestProofLoopArtifactPath(artifactScope(params.target, "re_proof_loop_tool_result")),
						target: params.target,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_profile_check",
			label: "RE Profile Check",
			description:
				"Run or show REPI profile checks for install readiness, regression guards, and reverse capability guards.",
			promptSnippet:
				"Use re_profile_check before installing/upgrading the profile or after major reverse/pentest capability changes.",
			promptGuidelines: [
				"Call re_profile_check full after profile edits and before claiming the agent is installable.",
				"Use install mode to verify install-repi/init wiring without touching global pi profile files.",
				"Treat reverse_capability_guards and regression_guards failures as blockers before final completion.",
			],
			parameters: Type.Object({
				action: Type.Optional(
					Type.Union([Type.Literal("quick"), Type.Literal("full"), Type.Literal("install"), Type.Literal("show")]),
				),
			}),
			async execute(_toolCallId, params) {
				const action = params.action ?? "quick";
				const text = buildProfileCheckOutput(action);
				return {
					content: [{ type: "text" as const, text }],
					details: { action, path: latestProfileCheckArtifactPath() } as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_bootstrap",
			label: "RE Bootstrap",
			description:
				"Plan or execute bootstrap commands for missing reverse/pentest tools and refresh the tool index.",
			promptSnippet: "Use tool-index driven bootstrap instead of guessing missing tool installation.",
			promptGuidelines: [
				"Call re_bootstrap plan before installing missing tools.",
				"Only call re_bootstrap install for tools required by the active mission lane.",
			],
			parameters: Type.Object({
				action: Type.Union([Type.Literal("show"), Type.Literal("plan"), Type.Literal("install")]),
				tools: Type.Optional(Type.Array(Type.String())),
			}),
			async execute(_toolCallId, params) {
				const tools = params.tools?.length
					? params.tools
					: params.action === "show"
						? TOOL_BOOTSTRAP_CATALOG.map((entry) => entry.tool)
						: ["checksec", "gdb", "radare2", "binwalk", "nmap", "ffuf"];
				const text =
					params.action === "install"
						? await installBootstrapTools(pi, tools)
						: formatBootstrapPlan(createBootstrapPlan(tools));
				return {
					content: [{ type: "text" as const, text }],
					details: { tools, action: params.action } as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_complete",
			label: "RE Complete",
			description: "Audit REPI completion checkpoints or write a report scaffold from mission/evidence state.",
			promptSnippet: "Audit completion checkpoints before claiming a reverse/pentest task is done.",
			promptGuidelines: [
				"Before final answers on reverse/pentest tasks, run re_complete audit or perform an equivalent checkpoint check.",
			],
			parameters: Type.Object({
				action: Type.Union([Type.Literal("audit"), Type.Literal("scaffold")]),
				title: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				if (params.action === "scaffold") {
					const path = writeReportScaffold(params.title);
					return {
						content: [
							{ type: "text" as const, text: `${path}\n\n${truncateMiddle(formatCompletionAudit(), 3800)}` },
						],
						details: { path } as Record<string, unknown>,
					};
				}
				const audit = runCompletionAudit();
				return {
					content: [{ type: "text" as const, text: truncateMiddle(formatCompletionAuditFromAudit(audit), 4096) }],
					details: audit as unknown as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_toolchain_domain",
			label: "RE Toolchain Domain Capability",
			description:
				"Inspect REPI professional reverse/pentest domain capability matrix with runtime tool-index evidence, fallbacks, proof exits, and next commands.",
			promptSnippet:
				"Use re_toolchain_domain to choose concrete domain tools and fallbacks before claiming a route is blocked.",
			promptGuidelines: [
				"Call re_toolchain_domain show when a reverse/pentest task feels under-tooled or too generic.",
				"Use domain nextRuntimeCommands and recommendedInstallHints to drive re_lane/re_bootstrap rather than narrative-only advice.",
			],
			parameters: Type.Object({
				action: Type.Union([Type.Literal("show"), Type.Literal("refresh")]),
				domain: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				if (params.action === "refresh") await refreshToolIndex(pi);
				const report = buildToolchainDomainCapability(params.domain);
				const path = writeToolchainDomainCapabilityArtifact(report);
				return {
					content: [
						{
							type: "text" as const,
							text: formatToolchainDomainSummary(report, path),
						},
					],
					details: { action: params.action, domain: params.domain, path, coverage: report.coverage } as Record<
						string,
						unknown
					>,
				};
			},
		});
		pi.registerTool({
			name: "re_runtime_bridge",
			label: "RE Professional Runtime Bridges",
			description:
				"Inspect ProfessionalRuntimeBridgesCheckV1: real toolchain bridge, exploit verifier runtime, Web/CDP replay harness, and Frida/Mobile dynamic bridge with artifact-backed command plans.",
			promptSnippet:
				"Use re_runtime_bridge when a reverse/pentest task needs concrete external tool bridging, replay verification, CDP capture, or Frida/mobile dynamic analysis.",
			promptGuidelines: [
				"Call re_runtime_bridge show before claiming a toolchain or dynamic bridge is missing.",
				"Use the bridge nextRuntimeCommands to drive re_live_browser, re_mobile_runtime, re_exploit_lab, re_replayer, and re_domain_proof_exit.",
				"Keep provider/API/device secrets as env refs such as REPI_BROWSER_CDP_URL or REPI_FRIDA_DEVICE; do not paste literal secrets into bridge artifacts.",
			],
			parameters: Type.Object({
				action: Type.Union([Type.Literal("show"), Type.Literal("refresh")]),
				bridge: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				if (params.action === "refresh") await refreshToolIndex(pi);
				const report = buildProfessionalRuntimeBridgesGate(params.bridge);
				const path = writeProfessionalRuntimeBridgesArtifact(report);
				return {
					content: [
						{
							type: "text" as const,
							text: formatRuntimeBridgeSummary(report, path),
						},
					],
					details: { action: params.action, bridge: params.bridge, path, closure: report.closure } as Record<
						string,
						unknown
					>,
				};
			},
		});

		pi.registerTool({
			name: "re_runtime_adapter",
			label: "RE Runtime Adapter Execution",
			description:
				"Plan or run RuntimeAdapterExecutionCheckV1 adapters that bind runner commands, parser rules, artifact kinds, ingest targets, and proof-exit signals for r2/Ghidra/Frida/CDP/pwntools/tshark/binwalk style workflows.",
			promptSnippet:
				"Use re_runtime_adapter to execute a bounded local adapter and parse output into evidence before claiming a reverse/pentest tool result.",
			promptGuidelines: [
				"Call re_runtime_adapter show or plan to choose an adapter with native/fallback status; if only a target is provided, REPI auto-detects URL/PCAP/APK/firmware/native/GDB-oriented adapters.",
				"Call re_runtime_adapter run only with an explicit target and bounded timeout; then feed the artifact to re_verifier and re_domain_proof_exit.",
				"Do not paste literal secrets; use env refs such as REPI_BROWSER_CDP_URL, REPI_FRIDA_DEVICE, or REPI_RUNTIME_ADAPTER_TIMEOUT_MS.",
			],
			parameters: Type.Object({
				action: Type.Union([
					Type.Literal("show"),
					Type.Literal("plan"),
					Type.Literal("run"),
					Type.Literal("refresh"),
				]),
				adapter: Type.Optional(Type.String()),
				target: Type.Optional(Type.String()),
				timeoutMs: Type.Optional(Type.Number()),
			}),
			async execute(_toolCallId, params) {
				if (params.action === "refresh") await refreshToolIndex(pi);
				if (params.action === "run") {
					const text = await runRuntimeAdapterExecution(pi, {
						adapter: params.adapter,
						target: params.target,
						timeoutMs: params.timeoutMs,
					});
					return {
						content: [{ type: "text" as const, text: truncateMiddle(text, 4096) }],
						details: { action: params.action, adapter: params.adapter, target: params.target } as Record<
							string,
							unknown
						>,
					};
				}
				const report = buildRuntimeAdapterExecutionGate(params.adapter ?? params.target);
				const path = writeRuntimeAdapterExecutionArtifact(report);
				return {
					content: [
						{
							type: "text" as const,
							text: formatRuntimeAdapterSummary(report, path),
						},
					],
					details: { action: params.action, adapter: params.adapter, path, closure: report.closure } as Record<
						string,
						unknown
					>,
				};
			},
		});

		pi.registerTool({
			name: "re_lane_specialist_pack",
			label: "RE Lane Specialist Command Pack",
			description:
				"Inspect ReLaneSpecialistCommandPackCheckV1: route → re_lane command pack → analyzer anchors → self-heal commands → proof-exit bridge for each professional domain.",
			promptSnippet:
				"Use re_lane_specialist_pack before broad execution when a reverse/pentest route feels generic or under-tooled.",
			promptGuidelines: [
				"Call re_lane_specialist_pack show to choose the right lane seeds, command pack markers, analyzer anchors, and self-heal commands.",
				"Follow with re_lane plan/run and re_domain_proof_exit so command-pack evidence closes the domain proof exit.",
			],
			parameters: Type.Object({ action: Type.Union([Type.Literal("show")]), domain: Type.Optional(Type.String()) }),
			async execute(_toolCallId, params) {
				const report = buildReLaneSpecialistCommandPackGate(params.domain);
				updateMissionCheckpoint(
					"repro_commands_ready",
					report.readyDomainCount === report.domainCount ? "done" : "blocked",
					"ReLaneSpecialistCommandPackCheckV1",
				);
				return {
					content: [{ type: "text" as const, text: formatLaneSpecialistSummary(report) }],
					details: {
						action: params.action,
						domain: params.domain,
						closure: report.closure,
						readyDomainCount: report.readyDomainCount,
					} as Record<string, unknown>,
				};
			},
		});

		pi.registerTool({
			name: "re_domain_proof_exit",
			label: "RE Domain Proof Exit Closure",
			description:
				"Check whether the active reverse/pentest domain has runtime evidence satisfying ToolchainDomainCapabilityV1 proof-exit criteria before final completion.",
			promptSnippet:
				"Use re_domain_proof_exit before final claims to convert missing domain proof exits into concrete next commands.",
			promptGuidelines: [
				"Call re_domain_proof_exit show after re_lane/re_native_runtime/re_live_browser/replayer/proof-loop artifacts exist.",
				"Treat domain_proof_exit_missing blockers as commands to run, not as narrative refusal.",
				"Use write mode to persist a DomainProofExitClosureV1 artifact for release/completion audit.",
			],
			parameters: Type.Object({
				action: Type.Union([Type.Literal("show"), Type.Literal("write")]),
				domain: Type.Optional(Type.String()),
			}),
			async execute(_toolCallId, params) {
				const report = buildDomainProofExitClosure(readCurrentMission(), params.domain);
				const path = params.action === "write" ? writeDomainProofExitClosureArtifact(report) : undefined;
				return {
					content: [{ type: "text" as const, text: formatDomainProofExitSummary(report, path) }],
					details: {
						action: params.action,
						domain: params.domain,
						path,
						status: report.status,
						missingProofExits: report.missingProofExits,
					} as Record<string, unknown>,
				};
			},
		});
		pi.registerTool({
			name: "re_tool_index",
			label: "RE Tools",
			description: "Show or refresh the REPI tool index so tool paths are evidence-based instead of guessed.",
			promptSnippet: "Show or refresh reverse/pentest tool availability.",
			promptGuidelines: ["Do not guess security tool paths; use re_tool_index or the current tool index."],
			parameters: Type.Object({ action: Type.Union([Type.Literal("show"), Type.Literal("refresh")]) }),
			async execute(_toolCallId, params) {
				const text = params.action === "refresh" ? await refreshToolIndex(pi) : buildToolDigest();
				updateMissionCheckpoint("tool_index_checked", "done", params.action);
				return {
					content: [{ type: "text" as const, text: formatToolIndexSummary(text) }],
					details: { path: toolIndexPath(), action: params.action },
				};
			},
		});
		if (!envBoolean("REPI_AGENT_THREAD")) {
			pi.registerTool({
				name: "re_subagent",
				label: "RE Subagent",
				description:
					"Spawn a process-isolated REPI specialist subagent (explorer/planner/operator/verifier/reverser) for a bounded sub-task and return its handoff as evidence candidates.",
				promptSnippet:
					"Delegate bounded sub-tasks to a process-isolated REPI specialist subagent instead of doing everything inline.",
				promptGuidelines: [
					"Spawn verifier to independently challenge a claim or rerun a minimal repro.",
					"Spawn reverser for binary/mobile/firmware/PCAP/DFIR reverse-engineering evidence.",
					"Spawn explorer for fast read-only surface mapping of files/routes/configs.",
					"Spawn planner to convert an ambiguous objective into a lane plan and worker split.",
					"Spawn operator to execute a bounded command pack and capture command/output/artifact evidence.",
					"Treat the returned handoff as evidence candidates; route unresolved gaps back to verifier/operator rather than pasting raw logs into the main context.",
				],
				parameters: Type.Object({
					spec: Type.Union([
						Type.Literal("explorer"),
						Type.Literal("planner"),
						Type.Literal("operator"),
						Type.Literal("verifier"),
						Type.Literal("reverser"),
					]),
					task: Type.String(),
					timeoutMs: Type.Optional(Type.Number()),
					additionalPrompt: Type.Optional(Type.String()),
				}),
				executionMode: "parallel",
				async execute(_toolCallId, params, signal, _onUpdate, ctx) {
					const timeoutMs = Math.min(600000, Math.max(1000, params.timeoutMs ?? 600000));
					const mgr = createAgentThreadManager({ cwd: ctx.cwd });
					const missionId = readCurrentMission()?.id;
					const task = normalizeWorkerTask(params.task);
					try {
						const started = await mgr.spawnThread({
							specName: params.spec,
							task,
							additionalPrompt: params.additionalPrompt,
							timeoutMs,
							inheritMcp: false,
							mcpServers: [],
							mcpTools: [],
							signal,
							missionId,
						});
						const final = await mgr.awaitRun(started.runId);
						const merge = mgr.mergeRun(started.runId);
						const mergedManifest = merge?.manifest ?? final;
						const resultDetails = repiSubagentResultFromManifest(mergedManifest);
						if (final.status !== "complete" || final.exitCode !== 0) {
							return {
								content: [
									{
										type: "text" as const,
										text: `re_subagent blocked: terminal status=${final.status} exitCode=${final.exitCode ?? "n/a"}; handoff was not accepted`,
									},
								],
								details: resultDetails,
							};
						}
						const validation = await validateRepiSubagentArtifact(resultDetails, {
							missionId,
							spec: params.spec,
							task,
							taskSha256: createHash("sha256").update(task).digest("hex"),
							requireMcpDisabled: true,
							timeoutMs,
						});
						if (!validation.ok) {
							return {
								content: [
									{
										type: "text" as const,
										text: `re_subagent blocked: artifact validation failed: ${validation.error}`,
									},
								],
								details: { ...resultDetails, error: `artifact validation failed: ${validation.error}` },
							};
						}
						const mergeText = merge?.text ?? "(no merge output)";
						appendAgentThreadEvidence(mergedManifest, {
							title: `subagent-handoff-${params.spec}-${final.status}`,
							fact: `AgentThread handoff run_id=${final.runId} spec=${final.specName} status=${final.status} exit_code=${final.exitCode ?? "n/a"} handoff_present=${mergedManifest.handoffPresent === true} handoff_recovered=${mergedManifest.handoffRecovered === true}`,
							command: `re_subagent spec=${params.spec} task=${task}`,
							confidence:
								final.status === "complete" && mergedManifest.handoffLineageValid === true
									? "candidate: process-isolated lineage-bound handoff; parent verifier must promote concrete claims"
									: final.status === "complete"
										? "candidate: process-isolated handoff; blocked from promotion because lineage metadata is invalid"
										: `blocked: process-isolated handoff status=${final.status}`,
							checkpoint: {
								name: "delegation_packets_ready",
								status:
									final.status === "complete" && mergedManifest.handoffLineageValid === true
										? "done"
										: "blocked",
								note: `re_subagent:${final.runId}:${final.status}:handoff_lineage=${mergedManifest.handoffLineageValid === true ? "valid" : "invalid"}`,
							},
						});
						const summary = [
							`re_subagent: spec=${final.specName} status=${final.status} exitCode=${final.exitCode ?? "n/a"}`,
							`run_id: ${final.runId}`,
							`run_root: ${final.runRoot}`,
						].join("\n");
						return {
							content: [
								{
									type: "text" as const,
									text: `${summary}\nmerge_artifact: ${mergedManifest.mergePath ?? final.runRoot}\nhandoff_artifact: ${mergedManifest.handoffPath ?? `${final.runRoot}/handoff.md`}\n\n${compactAgentThreadMerge(mergeText)}`,
								},
							],
							details: resultDetails,
						};
					} catch (error) {
						if (signal?.aborted) signal.throwIfAborted();
						const resultDetails = await repiSubagentFailureResult({
							spec: params.spec,
							task,
							missionId,
							error: compactAgentThreadError(error),
						});
						return {
							content: [
								{
									type: "text" as const,
									text: `re_subagent blocked: ${compactAgentThreadError(error)}`,
								},
							],
							details: resultDetails,
						};
					} finally {
						mgr.dispose("repi_subagent_complete");
					}
				},
			});
			pi.registerTool({
				name: "re_reason",
				label: "RE Reason",
				description:
					"Render a Pentesting Task Tree snapshot of the live mission (lanes/checkpoints, attack-graph gaps, decision-core rules, domain proof-exit closure, evidence tail, last lane-run decision) and either return it with a reasoning scaffold (mode=canvas) or dispatch a real process-isolated planner subagent to produce the next-step plan (mode=planner). Use this to reason like a pentester: form falsifiable hypotheses, pick the distinguishing probe, decide the next action with rationale.",
				promptSnippet:
					"Reason over a live Pentesting Task Tree snapshot before acting; dispatch a real planner subagent for the next-step plan when the objective is ambiguous.",
				promptGuidelines: [
					"Call re_reason(mode=canvas) to step back and reason over the whole task tree (lanes, gaps, proof-exit, last run).",
					"Call re_reason(mode=planner, focus=<question>) to hand the PTT snapshot to a real planner subagent and get a structured next-step plan.",
					"Use the scaffold to state a falsifiable hypothesis, the distinguishing probe, the next action with rationale, what to verify, and what to abandon.",
					"Do not paste raw logs back; merge distilled claims and unresolved gaps only.",
				],
				parameters: Type.Object({
					mode: Type.Optional(Type.Union([Type.Literal("canvas"), Type.Literal("planner")])),
					target: Type.Optional(Type.String()),
					focus: Type.Optional(Type.String()),
					timeoutMs: Type.Optional(Type.Number()),
				}),
				executionMode: "parallel",
				async execute(_toolCallId, params, signal, _onUpdate, ctx) {
					const mode = params.mode ?? "canvas";
					const snapshot = buildPentestingTaskTreeSnapshot({ target: params.target, focus: params.focus });
					if (mode === "planner") {
						const timeoutMs = Math.min(600000, Math.max(1000, params.timeoutMs ?? 300000));
						const task = normalizeWorkerTask(
							[
								"You are reasoning over a REPI Pentesting Task Tree snapshot. Produce the next-step plan.",
								params.focus ? `focus question: ${params.focus}` : "",
								"Return: assessment (one line), ranked hypotheses (each with a falsifying observation), distinguishing_probe, next_action (runnable command/tool + rationale), what_to_verify (falsification probe + who verifies), abandon_candidates, ptt_update (node status changes).",
								"",
								truncateMiddle(snapshot.text, 6000),
							]
								.filter(Boolean)
								.join("\n"),
						);
						const mgr = createAgentThreadManager({ cwd: ctx.cwd });
						const missionId = readCurrentMission()?.id;
						try {
							const started = await mgr.spawnThread({
								specName: "planner",
								task,
								timeoutMs,
								inheritMcp: false,
								mcpServers: [],
								mcpTools: [],
								signal,
								missionId,
							});
							const final = await mgr.awaitRun(started.runId);
							const merge = mgr.mergeRun(started.runId);
							const mergedManifest = merge?.manifest ?? final;
							const resultDetails = repiSubagentResultFromManifest(mergedManifest);
							const validation = await validateRepiSubagentArtifact(resultDetails, {
								missionId,
								spec: "planner",
								task,
								taskSha256: createHash("sha256").update(task).digest("hex"),
								requireMcpDisabled: true,
								timeoutMs,
							});
							if (!validation.ok) {
								return {
									content: [
										{
											type: "text" as const,
											text: `re_reason planner blocked: artifact validation failed: ${validation.error}`,
										},
									],
									details: {
										...resultDetails,
										mode,
										artifactValidation: "blocked",
										error: validation.error,
									} as unknown as Record<string, unknown>,
								};
							}
							const mergeText = merge?.text ?? "(no merge output)";
							const summary = [
								`re_reason: mode=planner status=${final.status} exitCode=${final.exitCode ?? "n/a"}`,
								`run_id: ${final.runId}`,
							].join("\n");
							return {
								content: [
									{
										type: "text" as const,
										text: `${summary}\nmerge_artifact: ${merge?.manifest.mergePath ?? final.runRoot}\nhandoff_artifact: ${merge?.manifest.handoffPath ?? `${final.runRoot}/handoff.md`}\n\n${compactAgentThreadMerge(mergeText)}`,
									},
								],
								details: {
									...validation.result,
									mode,
									artifactValidation: "passed",
								} as unknown as Record<string, unknown>,
							};
						} catch (error) {
							if (signal?.aborted) signal.throwIfAborted();
							return {
								content: [
									{
										type: "text" as const,
										text: `re_reason planner blocked: ${compactAgentThreadError(error)}`,
									},
								],
								details: { mode, error: true } as Record<string, unknown>,
							};
						} finally {
							mgr.dispose("repi_reason_planner_complete");
						}
					}
					const scaffold = [
						"",
						"## reasoning scaffold (fill before acting)",
						"- assessment: <progress vs root objective, one line>",
						"- hypotheses: <ranked, most-likely first; each with a falsifying observation>",
						"- distinguishing_probe: <the observation that separates the top hypotheses>",
						"- next_action: <command/tool + rationale; must be runnable now>",
						"- what_to_verify: <falsification probe + who verifies (re_subagent verifier?)>",
						"- abandon_candidates: <lanes/hypotheses to drop and why>",
						"- ptt_update: <which task-tree nodes change status and to what>",
					].join("\n");
					return {
						content: [{ type: "text" as const, text: `${truncateMiddle(snapshot.text, 3200)}${scaffold}` }],
						details: {
							mode,
							gapsCount: snapshot.gapsCount,
							missingProofExits: snapshot.missingProofExits,
							lastRunVerdict: snapshot.lastRunVerdict,
						} as Record<string, unknown>,
					};
				},
			});
			pi.registerTool({
				name: "re_challenge",
				label: "RE Challenge",
				description:
					"Independently challenge a claimed finding via a real process-isolated verifier subagent (Reflexion-style adversarial self-critique). The verifier treats the claim as a hypothesis, re-runs the minimal repro and actively searches for counter-evidence, then returns proved/refuted/inconclusive with the repro and contradicting observations. Call this before declaring a finding proved.",
				promptSnippet:
					"Try to falsify a claimed finding with an independent verifier subagent before accepting it.",
				promptGuidelines: [
					"Before declaring a finding proved, dispatch re_challenge with the claim and the minimal repro command.",
					"The verifier defaults to refuted/inconclusive if it cannot reproduce or finds counter-evidence; only proved survives a stable repro with no contradictions.",
					"Pass the exact reproCommand so the verifier re-runs it independently rather than trusting your summary.",
					"On refuted/inconclusive, downgrade the claim to a hypothesis and re-probe; do not override contradicting evidence with narrative.",
				],
				parameters: Type.Object({
					claim: Type.String(),
					evidence: Type.Optional(Type.String()),
					reproCommand: Type.Optional(Type.String()),
					target: Type.Optional(Type.String()),
					timeoutMs: Type.Optional(Type.Number()),
				}),
				executionMode: "parallel",
				async execute(_toolCallId, params, signal, _onUpdate, ctx) {
					const timeoutMs = Math.min(600000, Math.max(1000, params.timeoutMs ?? 300000));
					const task = normalizeWorkerTask(
						[
							"You are an independent REPI verifier. Your job is to FALSIFY the claim below. Treat it as a hypothesis, not a fact.",
							"- Re-run the minimal repro (if provided) and compare observations to the claim.",
							"- Actively search for counter-evidence: alternative explanations, contradictory observations, repro failure, flakiness, environment drift.",
							"- Default to refuted or inconclusive if you cannot reproduce or find supporting evidence; return proved only if the repro is stable and no counter-evidence exists.",
							"Return exactly one verdict line `verdict: proved | refuted | inconclusive`, then `repro: <command + result>`, `counter_evidence: <observations or none>`, `notes: <one line>`.",
							"",
							`claim: ${params.claim}`,
							params.evidence ? `evidence: ${params.evidence}` : "",
							params.reproCommand ? `repro_command: ${params.reproCommand}` : "",
							params.target ? `target: ${params.target}` : "",
						]
							.filter(Boolean)
							.join("\n"),
					);
					const mgr = createAgentThreadManager({ cwd: ctx.cwd });
					const missionId = readCurrentMission()?.id;
					try {
						const started = await mgr.spawnThread({
							specName: "verifier",
							task,
							timeoutMs,
							inheritMcp: false,
							mcpServers: [],
							mcpTools: [],
							signal,
							missionId,
						});
						const final = await mgr.awaitRun(started.runId);
						const merge = mgr.mergeRun(started.runId);
						const mergedManifest = merge?.manifest ?? final;
						const resultDetails = repiSubagentResultFromManifest(mergedManifest);
						const validation = await validateRepiSubagentArtifact(resultDetails, {
							missionId,
							spec: "verifier",
							task,
							taskSha256: createHash("sha256").update(task).digest("hex"),
							requireMcpDisabled: true,
							timeoutMs,
						});
						if (!validation.ok) {
							return {
								content: [
									{
										type: "text" as const,
										text: `re_challenge blocked: artifact validation failed: ${validation.error}\nverdict: inconclusive`,
									},
								],
								details: {
									...resultDetails,
									verdict: "inconclusive",
									artifactValidation: "blocked",
									error: validation.error,
								} as unknown as Record<string, unknown>,
							};
						}
						const mergeText = merge?.text ?? "(no merge output)";
						const verdictMatch = mergeText.match(/verdict:\s*(proved|refuted|inconclusive)/i);
						const parsedVerdict = verdictMatch ? verdictMatch[1].toLowerCase() : "inconclusive";
						const verdict = parsedVerdict;
						appendAgentThreadEvidence(mergedManifest, {
							title: `challenge-${verdict}`,
							fact: `Independent verifier verdict=${verdict} run_id=${final.runId} status=${final.status} exit_code=${final.exitCode ?? "n/a"} claim=${params.claim}`,
							command: `re_challenge claim=${params.claim}${params.reproCommand ? ` repro=${params.reproCommand}` : ""}`,
							confidence:
								verdict === "proved"
									? "candidate: independent verifier reproduced; domain runtime proof still required"
									: `counter-evidence: independent verifier verdict=${verdict}`,
							checkpoint: {
								name: "verifier_matrix_ready",
								status: verdict === "proved" ? "done" : "blocked",
								note: `re_challenge:${final.runId}:${verdict}`,
							},
						});
						const summary = [
							`re_challenge: spec=verifier status=${final.status} exitCode=${final.exitCode ?? "n/a"}`,
							`verdict: ${verdict}`,
							`run_id: ${final.runId}`,
						].join("\n");
						return {
							content: [
								{
									type: "text" as const,
									text: `${summary}\nmerge_artifact: ${mergedManifest.mergePath ?? final.runRoot}\nhandoff_artifact: ${mergedManifest.handoffPath ?? `${final.runRoot}/handoff.md`}\n\n${compactAgentThreadMerge(mergeText)}`,
								},
							],
							details: {
								...validation.result,
								verdict,
								artifactValidation: "passed",
							} as unknown as Record<string, unknown>,
						};
					} catch (error) {
						if (signal?.aborted) signal.throwIfAborted();
						return {
							content: [
								{
									type: "text" as const,
									text: `re_challenge blocked: ${compactAgentThreadError(error)}`,
								},
							],
							details: { verdict: "inconclusive", error: true } as Record<string, unknown>,
						};
					} finally {
						mgr.dispose("repi_challenge_complete");
					}
				},
			});
		}
	};
}

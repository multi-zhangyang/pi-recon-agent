import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import { type ArtifactScopeFilterOptions, artifactTargetMatches } from "./artifact-scope.ts";
import type { OperationExecution, OperationStepStatus } from "./campaign-operation-runtime.ts";
import {
	buildEvidenceClaimSummary,
	type EvidenceClaimSummary,
	type EvidenceKind,
	type EvidenceRecord,
	parseEvidenceRecords,
} from "./evidence.ts";
import {
	type MissionLane,
	type MissionState,
	missionOperatorDirective,
	missionRequiresParallel,
	readCurrentMission,
} from "./mission.ts";
import {
	createOperatorExecutionRuntime,
	type OperatorExecutionRuntimeDependencies,
	type OperatorExecutionStep,
} from "./operator-execution-runtime.ts";
import { createOperatorFeedbackRuntime } from "./operator-feedback-runtime.ts";
import { createOperatorPolicyRuntime } from "./operator-policy-runtime.ts";
import type {
	ProofArtifactRuntime,
	ProofCompilerClaimCheckInputs,
	StrictClaimCheckSnapshot,
	StructuredClaimMergeCheckSnapshot,
} from "./proof-artifact-runtime.ts";
import type { createProofLoopRuntime } from "./proof-loop-runtime.ts";
import type { createReconLaneRuntime } from "./recon-lane-runtime.ts";
import { ensureReconStorage } from "./resources.ts";
import type { RoutePlan } from "./routes.ts";
import {
	currentMissionPath,
	evidenceDecisionsDir,
	evidenceLedgerPath,
	evidenceOperatorsDir,
	readTextFile as readText,
	toolIndexPath,
	writePrivateTextFile,
} from "./storage.ts";
import type { AutonomousExecutionBudget, SupervisorArtifact, SwarmArtifact } from "./swarm-runtime-types.ts";
import type { SwarmSupervisorRuntime } from "./swarm-supervisor-runtime.ts";
import { commandTarget, looksLikeNaturalLanguageTarget, sanitizeTargetForCommand } from "./target.ts";
import { compactStoredArtifact, parseJsonCodeFence, slug, truncateMiddle, uniqueNonEmpty } from "./text.ts";
import type { RepiToolBootstrapCatalogEntry } from "./toolchain.ts";

export type DecisionCoreArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "tick" | "run";
	activeLane?: string;
	objectiveStack: string[];
	checkPressure: string[];
	evidencePriority: string[];
	claimPressure: string[];
	toolPosture: string[];
	artifactPosture: string[];
	decisionRules: string[];
	operatorQueue: string[];
	executed: OperationExecution[];
	blocked: string[];
	nextActions: string[];
	stopConditions: string[];
	sourceArtifacts: string[];
};

export type OperatorStep = {
	id: string;
	command: string;
	status: OperationStepStatus;
	priority: number;
	reason?: string;
	sourceArtifacts: string[];
};

export type OperatorArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "dispatch" | "verify" | "escalate";
	steps: OperatorStep[];
	executed: OperationExecution[];
	commanderPolicy: string[];
	commanderDispatchReport: string[];
	operatorFeedback: string[];
	operatorFeedbackQueue: string[];
	dispatcherFallbackPlan: string[];
	dispatcherFeedbackScoreboard: string[];
	dispatcherLearningHints: string[];
	autonomousBudget: AutonomousExecutionBudget;
	dispatcherScoreDecay: string[];
	repeatedFailureDemotions: string[];
	highScorePromotions: string[];
	verification: string[];
	escalationQueue: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

type OperatorFeedbackSnapshot = {
	rows: string[];
	commands: string[];
	sourceArtifacts: string[];
};

type ArtifactSelector = (options?: ArtifactScopeFilterOptions) => string | undefined;
type ProofLoopRuntime = ReturnType<typeof createProofLoopRuntime>;
type ReconLaneRuntime = ReturnType<typeof createReconLaneRuntime>;

type ProofArtifactBoundary = Pick<
	ProofArtifactRuntime,
	| "latestVerifierArtifactPath"
	| "parseVerifierArtifact"
	| "latestCompilerArtifactPath"
	| "parseCompilerArtifact"
	| "latestReplayerArtifactPath"
	| "parseReplayArtifact"
>;

type ProofLoopBoundary = Pick<ProofLoopRuntime, "latestProofLoopArtifactPath" | "parseAutofixArtifact">;

type SwarmSupervisorBoundary = Pick<
	SwarmSupervisorRuntime,
	| "latestSwarmArtifactPath"
	| "parseSwarmArtifact"
	| "latestSwarmRetryQueue"
	| "latestSupervisorArtifactPath"
	| "parseSupervisorArtifact"
	| "supervisorClaimCheckPolicy"
	| "supervisorPlanCoverage"
	| "splitRetryNextCommands"
>;

type LaneBoundary = Pick<ReconLaneRuntime, "activeLane">;

type AppendEvidence = (
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
) => EvidenceRecord;

/**
 * Dependencies are intentionally host-provided: this runtime owns decision/operator
 * policy while the profile owns cross-runtime wiring and initialization order.
 */
export type OperatorOrchestrationRuntimeDependencies = OperatorExecutionRuntimeDependencies &
	ProofArtifactBoundary &
	ProofLoopBoundary &
	SwarmSupervisorBoundary &
	LaneBoundary & {
		latestScopedMarkdownArtifact: (
			kind: string,
			dir: string,
			options?: ArtifactScopeFilterOptions,
		) => string | undefined;
		contextArtifactIndex: (options?: ArtifactScopeFilterOptions) => Array<{ kind: string; path: string }>;
		parseToolIndex: () => Map<string, { present: boolean; path?: string }>;
		recommendedToolsForRoute: (route: RoutePlan) => string[];
		bootstrapCatalogFor: (tool: string) => RepiToolBootstrapCatalogEntry | undefined;
		latestKernelArtifactPath: ArtifactSelector;
		latestAutofixArtifactPath: ArtifactSelector;
		artifactMatchesMission: (
			mission: MissionState | undefined,
			artifact: { missionId?: string } | undefined,
		) => boolean;
		safeStructuredClaimMergeCheck: (swarm?: SwarmArtifact) => StructuredClaimMergeCheckSnapshot;
		strictClaimCheckSnapshot: () => StrictClaimCheckSnapshot;
		buildClaimCheckResult: (
			releaseCheckMetadata?: string[],
			claimCheckPolicy?: string[],
			strictCheck?: StrictClaimCheckSnapshot,
			additionalBlockers?: string[],
		) => string[];
		appendEvidence: AppendEvidence;
		appendRuntimeFailureRepairFromOperator: (operator: OperatorArtifact, path: string) => void;
		autonomousExecutionBudget: (target?: string, rows?: string[]) => AutonomousExecutionBudget;
		autonomousBudgetLines: (budget?: AutonomousExecutionBudget) => string[];
	};

export function createOperatorOrchestrationRuntime(dependencies: OperatorOrchestrationRuntimeDependencies) {
	const {
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
		latestCompilerArtifactPath,
		parseCompilerArtifact,
		latestReplayerArtifactPath,
		parseReplayArtifact,
		parseAutofixArtifact,
		latestSwarmArtifactPath,
		parseSwarmArtifact,
		latestSwarmRetryQueue,
		latestSupervisorArtifactPath,
		parseSupervisorArtifact,
		supervisorClaimCheckPolicy,
		supervisorPlanCoverage,
		splitRetryNextCommands,
		artifactMatchesMission,
		safeStructuredClaimMergeCheck,
		strictClaimCheckSnapshot,
		buildClaimCheckResult,
		appendEvidence,
		updateMissionCheckpoint,
		appendRuntimeFailureRepairFromOperator,
		activeLane,
		autonomousExecutionBudget,
		autonomousBudgetLines,
	} = dependencies;
	const operatorExecutionRuntime = createOperatorExecutionRuntime(dependencies);
	const operatorFeedbackRuntime = createOperatorFeedbackRuntime({ latestSwarmRetryQueue });
	const operatorPolicyRuntime = createOperatorPolicyRuntime({
		operatorCommandConcrete: operatorExecutionRuntime.operatorCommandConcrete,
		splitRetryNextCommands,
	});
	const {
		isCommanderRuntimeCommand,
		commanderBudgetValue,
		operatorStepPriority,
		operatorFeedbackCategory,
		operatorFeedbackNextCommands,
		operatorFeedbackFallbackCommands,
		operatorFeedbackDispatchPlan,
		operatorFeedbackDispatcherCommands,
		dispatcherFeedbackScoreboard,
		dispatcherLearningHints,
		operatorVerificationLines,
		operatorEscalationQueue,
	} = operatorPolicyRuntime;
	const { classifyOperatorFeedback } = operatorFeedbackRuntime;

	function latestDecisionCoreArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("decision_core", evidenceDecisionsDir(), options);
	}

	function decisionEvidencePriority(claims: EvidenceClaimSummary, missionId?: string): string[] {
		const records = parseEvidenceRecords(readText(evidenceLedgerPath())).filter(
			(record) => !missionId || record.missionId === missionId,
		);
		const kinds: EvidenceKind[] = [
			"runtime",
			"traffic",
			"served_asset",
			"process_config",
			"artifact",
			"source",
			"note",
		];
		const counts = kinds.map((kind) => `${kind}: ${records.filter((record) => record.kind === kind).length}`);
		const decisive = records
			.filter((record) => record.priority <= 4)
			.slice(-8)
			.map((record) => `${record.timestamp} — P${record.priority} — ${record.kind} — ${record.title}`);
		return [
			"priority_order: runtime/memory > traffic > served_asset > process_config > artifact > source > note",
			`ledger_counts: ${counts.join(", ")}`,
			...claims.lines,
			...(decisive.length ? decisive.map((item) => `decisive: ${item}`) : ["decisive: none yet"]),
		];
	}

	function decisionToolPosture(mission: MissionState | undefined): string[] {
		const index = parseToolIndex();
		const recommended = mission
			? recommendedToolsForRoute(mission.route)
			: ["file", "sha256sum", "rg", "python3", "curl"].filter((tool) => bootstrapCatalogFor(tool));
		const missing = recommended.filter((tool) => !index.get(tool)?.present);
		const present = recommended.filter((tool) => index.get(tool)?.present);
		return [
			`tool_index: ${index.size ? `${index.size} indexed` : "empty; refresh required"}`,
			`recommended: ${recommended.join(", ") || "none"}`,
			`present: ${present.join(", ") || "none"}`,
			`missing: ${missing.join(", ") || "none"}`,
			missing.length
				? `tool_next: re_tool_index refresh -> re_bootstrap plan ${missing.slice(0, 8).join(" ")}`
				: "tool_next: use fallback/direct execution",
		];
	}

	function decisionArtifactPosture(scope: ArtifactScopeFilterOptions): string[] {
		const artifacts = contextArtifactIndex(scope);
		const byKind = new Map(artifacts.map((artifact) => [artifact.kind, artifact.path]));
		const required = [
			"map",
			"run",
			"attack_graph",
			"exploit_chain",
			"operator",
			"verifier",
			"compiler",
			"replayer",
			"autofix",
			"proof_loop",
		];
		return required.map((kind) => `${kind}: ${byKind.get(kind) ? `ok ${byKind.get(kind)}` : "missing"}`);
	}

	function decisionCheckPressure(mission: MissionState | undefined): string[] {
		if (!mission) return ["no mission: re_mission new <task>"];
		const ranks = new Map(
			[
				"execution_kernel_ready",
				"decision_core_ready",
				"tool_index_checked",
				"passive_map_done",
				"repro_commands_ready",
				"minimal_path_proven",
				"attack_graph_ready",
				"exploit_chain_ready",
				"operator_queue_ready",
				"verifier_matrix_ready",
				"compiler_ready",
				"replay_ready",
				"autofix_ready",
				"proof_loop_ready",
				"report_or_writeup_ready",
			].map((checkpoint, index) => [checkpoint, index + 1]),
		);
		return [...mission.checkpoints]
			.sort((a, b) => (ranks.get(a.name) ?? 99) - (ranks.get(b.name) ?? 99) || a.name.localeCompare(b.name))
			.map(
				(checkpoint) =>
					`${checkpoint.name}: ${checkpoint.status}${checkpoint.note ? ` — ${truncateMiddle(checkpoint.note, 160)}` : ""}`,
			);
	}

	function decisionObjectiveStack(
		mission: MissionState | undefined,
		active: MissionLane | undefined,
		target?: string,
	): string[] {
		const mappedTarget = commandTarget(target, missionOperatorDirective(mission) ?? mission?.task);
		if (!mission) {
			const mapped = mappedTarget === "<target>" ? "<task-or-target>" : mappedTarget;
			return [
				`bootstrap mission for ${mapped}`,
				`route task: re_route ${mapped}`,
				`create blackboard: re_mission new ${mapped}`,
				`build execution kernel: re_kernel build ${mapped}`,
			];
		}
		const pending = mission.checkpoints
			.filter((checkpoint) => checkpoint.status !== "done")
			.map((checkpoint) => checkpoint.name);
		return [
			`route=${mission.route.domain}`,
			`task=${truncateMiddle(missionOperatorDirective(mission) ?? mission.task, 180)}`,
			`active_lane=${active?.name ?? "none"}`,
			`active_objective=${active?.objective ?? "select next lane"}`,
			`target=${mappedTarget}`,
			`pending_checks=${pending.slice(0, 16).join(",") || "none"}`,
			"primary_invariant=prove one end-to-end evidence path before broad expansion",
		];
	}

	function decisionRulesFor(
		mission: MissionState | undefined,
		active: MissionLane | undefined,
		target?: string,
	): string[] {
		const mappedTarget = commandTarget(target, missionOperatorDirective(mission) ?? mission?.task);
		if (!mission)
			return [
				`no_mission -> re_mission new ${mappedTarget}`,
				`no_kernel -> re_kernel build ${mappedTarget}`,
				`no_map -> re_map ${mappedTarget} 2`,
			];
		const pending = new Set(
			mission.checkpoints.filter((checkpoint) => checkpoint.status !== "done").map((checkpoint) => checkpoint.name),
		);
		const lane = active?.name ?? "triage";
		const rules: string[] = [];
		if (pending.has("execution_kernel_ready")) rules.push(`execution_kernel_gap -> re_kernel build ${mappedTarget}`);
		if (pending.has("tool_index_checked")) rules.push("tool_posture_unknown -> re_tool_index refresh");
		if (pending.has("passive_map_done")) rules.push(`map_gap -> re_map ${mappedTarget} 2`);
		if (pending.has("live_browser_ready")) rules.push(`browser_gap -> re_live_browser run ${mappedTarget}`);
		if (pending.has("web_authz_ready")) rules.push(`web_authz_gap -> re_web_authz_state run ${mappedTarget}`);
		if (pending.has("mobile_runtime_ready"))
			rules.push(`mobile_runtime_gap -> re_mobile_runtime run ${mappedTarget}`);
		if (pending.has("native_runtime_ready"))
			rules.push(`native_runtime_gap -> re_native_runtime run ${mappedTarget}`);
		if (pending.has("exploit_lab_ready")) rules.push(`exploit_lab_gap -> re_exploit_lab run ${mappedTarget}`);
		if (pending.has("repro_commands_ready")) rules.push(`command_pack_gap -> re_lane plan ${lane} ${mappedTarget}`);
		if (pending.has("minimal_path_proven")) rules.push(`proof_gap -> re_lane run ${lane} ${mappedTarget}`);
		if (pending.has("attack_graph_ready")) rules.push("graph_gap -> re_graph build");
		if (pending.has("exploit_chain_ready")) rules.push(`chain_gap -> re_chain plan ${mappedTarget}`);
		if (pending.has("campaign_plan_ready")) rules.push(`campaign_gap -> re_campaign plan ${mappedTarget}`);
		if (pending.has("operation_queue_ready")) rules.push(`operation_gap -> re_operation plan ${mappedTarget}`);
		if (pending.has("delegation_packets_ready")) rules.push(`delegation_gap -> re_delegate plan ${mappedTarget}`);
		if (pending.has("swarm_plan_ready")) rules.push(`swarm_gap -> re_swarm plan ${mappedTarget}`);
		if (pending.has("supervisor_review_ready")) rules.push(`supervisor_gap -> re_supervisor review ${mappedTarget}`);
		if (pending.has("operator_queue_ready")) rules.push(`operator_gap -> re_operator plan ${mappedTarget}`);
		if (pending.has("verifier_matrix_ready")) rules.push(`verification_gap -> re_verifier matrix ${mappedTarget}`);
		if (pending.has("compiler_ready")) rules.push(`compiler_gap -> re_compiler draft ${mappedTarget}`);
		if (pending.has("replay_ready")) rules.push(`replay_gap -> re_replayer run ${mappedTarget} 1`);
		if (pending.has("autofix_ready")) rules.push(`repair_gap -> re_autofix plan ${mappedTarget}`);
		if (pending.has("proof_loop_ready")) rules.push(`proof_loop_gap -> re_proof_loop run ${mappedTarget} 4`);
		if (pending.has("report_or_writeup_ready")) rules.push("report_gap -> re_complete scaffold");
		if (rules.length === 0) rules.push("all_checks_green -> re_complete audit");
		return rules;
	}

	function decisionOperatorQueue(rules: string[]): string[] {
		const commands = rules
			.map((rule) => rule.split("->")[1]?.trim())
			.filter((command): command is string => Boolean(command));
		return Array.from(new Set(commands)).slice(0, 18);
	}

	function decisionRulesWithClaims(
		mission: MissionState | undefined,
		active: MissionLane | undefined,
		target: string,
		claims: EvidenceClaimSummary,
	): string[] {
		const claimRules = claims.open.flatMap((claim) => {
			const command =
				claim.verdict === "proposed"
					? (claim.command ?? claim.verify)
					: claim.verdict === "supported"
						? claim.verify
						: undefined;
			return command ? [`claim_${claim.verdict}:${claim.claimId} -> ${command}`] : [];
		});
		return Array.from(new Set([...claimRules, ...decisionRulesFor(mission, active, target)])).slice(0, 32);
	}

	function nextDecisionCommand(missionOverride?: MissionState): string {
		const mission = missionOverride ?? readCurrentMission();
		const active = mission ? activeLane(mission) : undefined;
		const target = sanitizeTargetForCommand(missionOperatorDirective(mission) ?? mission?.task) ?? ".";
		const claims = buildEvidenceClaimSummary({ missionId: mission?.id, readText });
		return (
			decisionOperatorQueue(decisionRulesWithClaims(mission, active, target, claims))[0] ??
			`re_decision_core tick ${target}`
		);
	}

	function buildDecisionCore(
		options: { target?: string; mode?: DecisionCoreArtifact["mode"] } = {},
	): DecisionCoreArtifact {
		ensureReconStorage();
		const mission = readCurrentMission();
		const active = mission ? activeLane(mission) : undefined;
		const target =
			sanitizeTargetForCommand(options.target) ??
			sanitizeTargetForCommand(missionOperatorDirective(mission) ?? mission?.task) ??
			".";
		const scope: ArtifactScopeFilterOptions = {
			missionId: mission?.id,
			route: mission?.route.domain,
			target,
			requestedBy: "decision_core",
		};
		const objectiveStack = decisionObjectiveStack(mission, active, target);
		const checkPressure = decisionCheckPressure(mission);
		const claims = buildEvidenceClaimSummary({ missionId: mission?.id, readText });
		const evidencePriority = decisionEvidencePriority(claims, mission?.id);
		const toolPosture = decisionToolPosture(mission);
		const artifactPosture = decisionArtifactPosture(scope);
		const decisionRules = decisionRulesWithClaims(mission, active, target, claims);
		const operatorQueue = decisionOperatorQueue(decisionRules);
		const nextActions = operatorQueue.slice(0, 10);
		const sourceArtifacts = Array.from(
			new Set(
				[
					currentMissionPath(),
					evidenceLedgerPath(),
					toolIndexPath(),
					latestKernelArtifactPath(scope),
					latestOperatorArtifactPath(scope),
					latestCompilerArtifactPath(scope),
					latestReplayerArtifactPath(scope),
					latestAutofixArtifactPath(scope),
					latestProofLoopArtifactPath(scope),
					...contextArtifactIndex(scope).map((artifact) => artifact.path),
				].filter((path): path is string => Boolean(path && existsSync(path))),
			),
		).slice(0, 48);
		return {
			timestamp: new Date().toISOString(),
			missionId: mission?.id,
			route: mission?.route.domain,
			target,
			mode: options.mode ?? "plan",
			activeLane: active?.name,
			objectiveStack,
			checkPressure,
			evidencePriority,
			claimPressure: claims.lines,
			toolPosture,
			artifactPosture,
			decisionRules,
			operatorQueue,
			executed: [],
			blocked: [],
			nextActions,
			stopConditions: [
				"stop_only_when: mission checkpoints done or each remaining checkpoint has evidence-backed blocker",
				"stop_only_when: structured open claims are proved, contradicted, or explicitly blocked by a recorded evidence gap",
				"stop_only_when: verifier/compiler/replayer outputs are bound to artifacts or explicit gaps",
				"never_stop_on: missing target/tool/context without emitting a concrete closure command",
				...(looksLikeNaturalLanguageTarget(options.target ?? missionOperatorDirective(mission) ?? mission?.task)
					? [
							"invalid_natural_language_target_sanitized: run re_map . 2 or pass an explicit URL/file/directory/package",
						]
					: []),
			],
			sourceArtifacts,
		};
	}

	function formatDecisionCore(decision: DecisionCoreArtifact, path?: string): string {
		return [
			"decision_core:",
			path ? `decision_artifact: ${path}` : undefined,
			`timestamp: ${decision.timestamp}`,
			`mode: ${decision.mode}`,
			`mission_id: ${decision.missionId ?? "none"}`,
			`route: ${decision.route ?? "none"}`,
			`target: ${decision.target ?? "<none>"}`,
			`active_lane: ${decision.activeLane ?? "none"}`,
			"objective_stack:",
			...(decision.objectiveStack.length ? decision.objectiveStack.map((item) => `- ${item}`) : ["- none"]),
			"check_pressure:",
			...(decision.checkPressure.length ? decision.checkPressure.map((item) => `- ${item}`) : ["- none"]),
			"evidence_priority:",
			...(decision.evidencePriority.length ? decision.evidencePriority.map((item) => `- ${item}`) : ["- none"]),
			"claim_pressure:",
			...(decision.claimPressure.length ? decision.claimPressure.map((item) => `- ${item}`) : ["- none"]),
			"tool_posture:",
			...(decision.toolPosture.length ? decision.toolPosture.map((item) => `- ${item}`) : ["- none"]),
			"artifact_posture:",
			...(decision.artifactPosture.length ? decision.artifactPosture.map((item) => `- ${item}`) : ["- none"]),
			"decision_rules:",
			...(decision.decisionRules.length ? decision.decisionRules.map((item) => `- ${item}`) : ["- none"]),
			"operator_queue:",
			...(decision.operatorQueue.length ? decision.operatorQueue.map((item) => `- ${item}`) : ["- re_mission show"]),
			`executed_steps: ${decision.executed.length}`,
			...(decision.executed.length
				? decision.executed.map(
						(item) =>
							`- ${item.stepId} [${item.status}] ${item.command} :: ${truncateMiddle(item.output.replace(/\s+/g, " "), 260)}`,
					)
				: []),
			"blocked:",
			...(decision.blocked.length ? decision.blocked.map((item) => `- ${item}`) : ["- none"]),
			"decision_next_actions:",
			...(decision.nextActions.length ? decision.nextActions.map((item) => `- ${item}`) : ["- re_mission show"]),
			"stop_conditions:",
			...(decision.stopConditions.length ? decision.stopConditions.map((item) => `- ${item}`) : ["- none"]),
			`operator_next_command: ${decision.operatorQueue[0] ?? "re_mission show"}`,
			`next_decision_command: ${
				decision.mode === "run"
					? (decision.nextActions[0] ?? `re_decision_core tick ${decision.target ?? "."}`)
					: decision.mode === "tick"
						? `re_decision_core run ${decision.target ?? "<target>"} 1`
						: `re_decision_core tick ${decision.target ?? "<target>"}`
			}`,
			"source_artifacts:",
			...(decision.sourceArtifacts.length ? decision.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeDecisionCoreArtifact(decision: DecisionCoreArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceDecisionsDir(),
			`${decision.timestamp.replace(/[:.]/g, "-")}-${slug(decision.route ?? "decision")}-${decision.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Decision Core Artifact",
				"",
				formatDecisionCore(decision, path),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(decision, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: "artifact",
			title: `decision-core-${decision.mode} ${decision.missionId ?? "no-mission"}`,
			fact: `Decision core ${decision.mode}: objectives=${decision.objectiveStack.length}, rules=${decision.decisionRules.length}, queue=${decision.operatorQueue.length}`,
			command: `re_decision_core ${decision.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "mission checkpoints/evidence/tool posture decision core",
		});
		updateMissionCheckpoint("decision_core_ready", "done", path);
		return path;
	}

	function decisionOperatorSteps(decision: DecisionCoreArtifact): OperatorStep[] {
		const seen = new Set<string>();
		const claimCommands = new Set(
			decision.decisionRules
				.filter((rule) => /^claim_/i.test(rule))
				.map((rule) => rule.split("->")[1]?.trim())
				.filter((command): command is string => Boolean(command)),
		);
		const steps: OperatorStep[] = [];
		for (const raw of decision.operatorQueue) {
			const concrete = operatorCommandConcrete(raw, decision.target);
			const command = concrete.command.trim();
			if (!command || seen.has(command)) continue;
			seen.add(command);
			steps.push({
				id: `decision:${steps.length + 1}:${slug(command).slice(0, 30)}`,
				command,
				status: concrete.blocked ? "blocked" : "ready",
				priority: claimCommands.has(command) ? 0 : operatorStepPriority(command),
				reason: concrete.blocked,
				sourceArtifacts: decision.sourceArtifacts,
			});
		}
		return steps.sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));
	}

	function claimForDecisionStep(decision: DecisionCoreArtifact, step: OperatorStep) {
		const rule = decision.decisionRules.find(
			(item) => /^claim_/i.test(item) && item.split("->")[1]?.trim() === step.command,
		);
		const claimId = /^claim_[^:]+:([^\s]+)\s*->/i.exec(rule ?? "")?.[1];
		if (!claimId) return undefined;
		return buildEvidenceClaimSummary({ missionId: decision.missionId, readText }).open.find(
			(claim) => claim.claimId === claimId,
		);
	}

	function recordDecisionClaimProbe(
		decision: DecisionCoreArtifact,
		step: OperatorStep,
		result: OperationExecution,
	): void {
		const claim = claimForDecisionStep(decision, step);
		if (!claim) return;
		const nextVerify =
			claim.verify?.trim() && claim.verify.trim() !== result.command.trim() ? claim.verify.trim() : undefined;
		appendEvidence({
			missionId: decision.missionId,
			kind: result.status === "done" ? "runtime" : "note",
			title: `claim-probe ${claim.claimId}`,
			fact: `Decision core executed claim probe ${result.command}; status=${result.status}`,
			claimId: claim.claimId,
			hypothesis: claim.hypothesis,
			prediction: claim.prediction,
			observation: truncateMiddle(result.output.replace(/\s+/g, " "), 1200),
			command: result.command,
			verify: result.status === "done" ? nextVerify : undefined,
			verdict: result.status === "done" ? "supported" : "inconclusive",
			confidence: "claim probe executed; final verdict still requires evidence adjudication",
		});
	}

	async function runDecisionCore(
		pi: ExtensionAPI,
		options: { target?: string; maxSteps?: number } = {},
	): Promise<string> {
		const decision = buildDecisionCore({ target: options.target, mode: "run" });
		const maxSteps = Math.max(1, Math.min(10, Math.floor(options.maxSteps ?? 1)));
		const steps = decisionOperatorSteps(decision);
		for (const step of steps.filter((item) => item.status === "ready").slice(0, maxSteps)) {
			const result = await executeOperatorStep(pi, step, decision.target);
			decision.executed.push(result);
			recordDecisionClaimProbe(decision, step, result);
			if (result.status === "blocked") decision.blocked.push(`${step.id}: ${result.output}`);
		}
		for (const step of steps.filter((item) => item.status === "blocked")) {
			decision.blocked.push(`${step.id}: ${step.reason ?? step.command}`);
		}
		decision.nextActions = steps
			.filter((step) => step.status === "ready")
			.slice(decision.executed.length, decision.executed.length + 8)
			.map((step) => `re_decision_core run ${decision.target ?? "<target>"} 1 # ${step.id}`);
		if (decision.nextActions.length === 0) {
			decision.nextActions = [`re_decision_core tick ${decision.target ?? "<target>"}`];
		}
		const path = writeDecisionCoreArtifact(decision);
		return formatDecisionCore(decision, path);
	}

	function buildDecisionCoreOutput(
		action: "plan" | "show" | "tick" = "plan",
		options: { target?: string } = {},
	): string {
		if (action === "show") {
			const path = latestDecisionCoreArtifactPath();
			if (!path) return "decision_core:\nstatus: missing\nnext: re_decision_core plan <target>";
			return compactStoredArtifact("decision_core", path, readText(path));
		}
		const decision = buildDecisionCore({ target: options.target, mode: action === "tick" ? "tick" : "plan" });
		const path = writeDecisionCoreArtifact(decision);
		return formatDecisionCore(decision, path);
	}

	function latestOperatorArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("operator", evidenceOperatorsDir(), options);
	}

	function operatorCommandConcrete(command: string, target?: string): { command: string; blocked?: string } {
		return operatorExecutionRuntime.operatorCommandConcrete(command, target);
	}

	function buildOperator(options: { target?: string; mode?: OperatorArtifact["mode"] } = {}): OperatorArtifact {
		ensureReconStorage();
		const mission = readCurrentMission();
		const target =
			sanitizeTargetForCommand(options.target) ??
			sanitizeTargetForCommand(missionOperatorDirective(mission) ?? mission?.task) ??
			".";
		const feedback = latestOperatorFeedback(target);
		const dispatcherCommands = operatorFeedbackDispatcherCommands(feedback.rows, target);
		const dispatcherFallbackPlan = operatorFeedbackDispatchPlan(feedback.rows, target);
		const decision = buildDecisionCore({ target, mode: "tick" });
		const claimCommands = new Set(
			decision.decisionRules
				.filter((rule) => /^claim_/i.test(rule))
				.map((rule) => rule.split("->")[1]?.trim())
				.filter((command): command is string => Boolean(command)),
		);
		const commanderPolicy = Array.from(
			new Set([
				`mission=${mission?.id ?? "none"}`,
				`route=${mission?.route.domain ?? "unknown"}`,
				`operator_feedback_queue=${dispatcherCommands.length}`,
				`operator_feedback_rows=${feedback.rows.length}`,
				`dispatcher_fallback_plan=${dispatcherFallbackPlan.length}`,
				"feedback_priority=missing_tool→target→runtime→budget→swarm→exploit→evidence",
			]),
		).slice(0, 28);
		const seen = new Set<string>();
		const steps: OperatorStep[] = [];
		const sourceArtifacts = uniqueNonEmpty(
			[currentMissionPath(), evidenceLedgerPath(), ...feedback.sourceArtifacts],
			24,
		);
		const addStep = (raw: string, stepArtifacts: string[] = sourceArtifacts, priority?: number) => {
			const concrete = operatorCommandConcrete(raw, target);
			const command = concrete.command.trim();
			if (!command) return;
			if (seen.has(command)) {
				const existing = steps.find((step) => step.command === command);
				if (existing) {
					existing.priority = Math.min(existing.priority, priority ?? operatorStepPriority(command));
					existing.sourceArtifacts = Array.from(new Set([...existing.sourceArtifacts, ...stepArtifacts])).slice(
						0,
						40,
					);
				}
				return;
			}
			seen.add(command);
			steps.push({
				id: `operator:${steps.length + 1}:${slug(command).slice(0, 30)}`,
				command,
				status: concrete.blocked ? "blocked" : "ready",
				priority: priority ?? operatorStepPriority(command),
				reason: concrete.blocked,
				sourceArtifacts: stepArtifacts,
			});
		};
		for (const command of dispatcherCommands) addStep(command, feedback.sourceArtifacts);
		for (const command of decision.operatorQueue) {
			if (/^re[-_]operator\b/i.test(command)) continue;
			addStep(command, decision.sourceArtifacts, claimCommands.has(command) ? 0 : undefined);
		}
		if (steps.length === 0) {
			addStep(mission ? `re_decision_core tick ${target ?? "<target>"}` : "re_mission show");
		}
		const sorted = [...steps].sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));
		const pendingGates =
			readCurrentMission()
				?.checkpoints.filter((checkpoint) => checkpoint.status !== "done")
				.map((checkpoint) => checkpoint.name) ?? [];
		const verification = operatorVerificationLines(steps, mission);
		const escalationQueue = operatorEscalationQueue(steps, pendingGates);
		const dispatcherFeedbackScoreboardRows = dispatcherFeedbackScoreboard({
			operatorFeedback: feedback.rows,
			executed: [],
			target,
		});
		const dispatcherLearning = dispatcherLearningHints(dispatcherFeedbackScoreboardRows, target);
		const autonomousBudget = autonomousExecutionBudget(target, dispatcherFeedbackScoreboardRows);
		return {
			timestamp: new Date().toISOString(),
			missionId: mission?.id,
			route: mission?.route.domain,
			target,
			mode: options.mode ?? "plan",
			steps: sorted,
			executed: [],
			commanderPolicy: Array.from(
				new Set([
					...commanderPolicy,
					`max_turns=${autonomousBudget.maxTurns}`,
					`max_dispatch=${autonomousBudget.maxDispatch}`,
					`max_proof_loops=${autonomousBudget.maxProofLoops}`,
					`retry_limit_per_worker=${autonomousBudget.maxWorkerRetries}`,
					`failure_budget=${Math.max(1, Math.min(autonomousBudget.maxDispatch, autonomousBudget.maxWorkerRetries))}`,
					`autonomous_budget=max_turns:${autonomousBudget.maxTurns},max_dispatch:${autonomousBudget.maxDispatch},max_proof_loops:${autonomousBudget.maxProofLoops},max_worker_retries:${autonomousBudget.maxWorkerRetries}`,
					`score_decay=${autonomousBudget.scoreDecay.length}; demotions=${autonomousBudget.demotionRules.length}; promotions=${autonomousBudget.promotionRules.length}`,
				]),
			).slice(0, 34),
			commanderDispatchReport: [],
			operatorFeedback: feedback.rows,
			operatorFeedbackQueue: dispatcherCommands,
			dispatcherFallbackPlan,
			dispatcherFeedbackScoreboard: dispatcherFeedbackScoreboardRows,
			dispatcherLearningHints: dispatcherLearning,
			autonomousBudget,
			dispatcherScoreDecay: autonomousBudget.scoreDecay,
			repeatedFailureDemotions: autonomousBudget.demotionRules,
			highScorePromotions: autonomousBudget.promotionRules,
			verification,
			escalationQueue,
			nextActions: Array.from(
				new Set([
					...autonomousBudget.nextActions,
					...sorted
						.filter((step) => step.status === "ready")
						.slice(0, 8)
						.map((step) => `re_operator dispatch ${target ?? "<target>"} 1 # ${step.id}`),
				]),
			).slice(0, 12),
			sourceArtifacts: Array.from(new Set([...feedback.sourceArtifacts, ...decision.sourceArtifacts])).slice(0, 40),
		};
	}

	function formatOperator(operator: OperatorArtifact, path?: string): string {
		return [
			"operator_queue:",
			path ? `operator_artifact: ${path}` : undefined,
			`timestamp: ${operator.timestamp}`,
			`mode: ${operator.mode}`,
			`mission_id: ${operator.missionId ?? "none"}`,
			`route: ${operator.route ?? "none"}`,
			`target: ${operator.target ?? "<none>"}`,
			"dispatcher_policy:",
			"- priority: bootstrap/tool-index → map/plan → runtime/graph → campaign/operation/delegate → supervisor → evidence/operator → verifier/compiler → replayer/autofix → completion",
			"- feedback_priority: operator_feedback_queue is promoted ahead of context commands; fallback plan reroutes missing tools, unresolved targets, runtime failure, swarm retry, and exploit/replay candidates",
			"- bounded_dispatch: default max=1, hard max=10, unsupported commands become escalation items",
			"commander_runtime_policy:",
			...(operator.commanderPolicy.length ? operator.commanderPolicy.map((item) => `- ${item}`) : ["- none"]),
			"operator_feedback:",
			...((operator.operatorFeedback ?? []).length
				? (operator.operatorFeedback ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"operator_feedback_queue:",
			...((operator.operatorFeedbackQueue ?? []).length
				? (operator.operatorFeedbackQueue ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"dispatcher_fallback_plan:",
			...((operator.dispatcherFallbackPlan ?? []).length
				? (operator.dispatcherFallbackPlan ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"dispatcher_feedback_scoreboard:",
			...((operator.dispatcherFeedbackScoreboard ?? []).length
				? (operator.dispatcherFeedbackScoreboard ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"dispatcher_learning_hints:",
			...((operator.dispatcherLearningHints ?? []).length
				? (operator.dispatcherLearningHints ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"autonomous_execution_budget:",
			...autonomousBudgetLines(operator.autonomousBudget).map((item) => `- ${item}`),
			"dispatcher_score_decay:",
			...((operator.dispatcherScoreDecay ?? []).length
				? (operator.dispatcherScoreDecay ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"repeated_failure_demotions:",
			...((operator.repeatedFailureDemotions ?? []).length
				? (operator.repeatedFailureDemotions ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"high_score_promotions:",
			...((operator.highScorePromotions ?? []).length
				? (operator.highScorePromotions ?? []).map((item) => `- ${item}`)
				: ["- none"]),
			"steps:",
			...(operator.steps.length
				? operator.steps.map(
						(step) =>
							`- ${step.id} [${step.status}] p=${step.priority} command=${step.command}${step.reason ? ` reason=${step.reason}` : ""}`,
					)
				: ["- none"]),
			`executed_steps: ${operator.executed.length}`,
			...(operator.executed.length
				? operator.executed.map(
						(item) =>
							`- ${item.stepId} [${item.status}] ${item.command} :: ${truncateMiddle(item.output.replace(/\s+/g, " "), 260)}`,
					)
				: []),
			"commander_dispatch_report:",
			...(operator.commanderDispatchReport.length
				? operator.commanderDispatchReport.map((item) => `- ${item}`)
				: ["- none"]),
			"verification_matrix:",
			...(operator.verification.length ? operator.verification.map((item) => `- ${item}`) : ["- none"]),
			"escalation_queue:",
			...(operator.escalationQueue.length ? operator.escalationQueue.map((item) => `- ${item}`) : ["- none"]),
			"operator_next_actions:",
			...(operator.nextActions.length
				? operator.nextActions.map((item) => `- ${item}`)
				: ["- re_decision_core tick"]),
			`next_operator_command: ${operator.mode === "dispatch" ? "re_operator verify" : `re_operator dispatch ${operator.target ?? "<target>"} 1`}`,
			"source_artifacts:",
			...(operator.sourceArtifacts.length ? operator.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeOperatorArtifact(operator: OperatorArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceOperatorsDir(),
			`${operator.timestamp.replace(/[:.]/g, "-")}-${slug(operator.route ?? "operator")}-${operator.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Operator Artifact",
				"",
				formatOperator(operator, path),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(operator, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: "artifact",
			title: `operator-${operator.mode} ${operator.missionId ?? "no-mission"}`,
			fact: `Operator queue ${operator.mode}: ${operator.steps.length} step(s), ${operator.executed.length} executed, ${operator.escalationQueue.length} escalation item(s), commander_policy=${operator.commanderPolicy.length}, commander_dispatch=${operator.commanderDispatchReport.length}, operator_feedback=${(operator.operatorFeedback ?? []).length}, operator_feedback_queue=${(operator.operatorFeedbackQueue ?? []).length}, dispatcher_fallback_plan=${(operator.dispatcherFallbackPlan ?? []).length}, dispatcher_feedback_scoreboard=${(operator.dispatcherFeedbackScoreboard ?? []).length}, dispatcher_learning_hints=${(operator.dispatcherLearningHints ?? []).length}, autonomous_budget=${operator.autonomousBudget?.maxTurns ?? "none"}/${operator.autonomousBudget?.maxDispatch ?? "none"}, score_decay=${(operator.dispatcherScoreDecay ?? []).length}, demotions=${(operator.repeatedFailureDemotions ?? []).length}, promotions=${(operator.highScorePromotions ?? []).length}`,
			command: `re_operator ${operator.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "bounded operator dispatcher",
		});
		updateMissionCheckpoint("operator_queue_ready", "done", path);
		appendRuntimeFailureRepairFromOperator(operator, path);
		return path;
	}

	async function executeOperatorStep(
		pi: ExtensionAPI,
		step: OperatorExecutionStep,
		target?: string,
	): Promise<OperationExecution> {
		return operatorExecutionRuntime.executeOperatorStep(pi, step, target, {
			dispatchOperatorQueue,
			buildOperatorOutput,
		});
	}

	async function dispatchOperatorQueue(
		pi: ExtensionAPI,
		options: { target?: string; maxSteps?: number } = {},
	): Promise<string> {
		const operator = buildOperator({ target: options.target, mode: "dispatch" });
		const decision = buildDecisionCore({ target: operator.target, mode: "tick" });
		const requestedMaxSteps = Math.max(1, Math.min(10, Math.floor(options.maxSteps ?? 1)));
		const policyMaxDispatch = commanderBudgetValue(operator.commanderPolicy, "max_dispatch", requestedMaxSteps);
		const maxSteps = Math.max(1, Math.min(10, requestedMaxSteps, policyMaxDispatch));
		const failureBudget = commanderBudgetValue(operator.commanderPolicy, "failure_budget", maxSteps);
		const retryLimit = commanderBudgetValue(operator.commanderPolicy, "retry_limit_per_worker", 1);
		let commanderFailures = 0;
		for (const step of operator.steps.filter((item) => item.status === "ready").slice(0, maxSteps)) {
			const result = await executeOperatorStep(pi, step, operator.target);
			operator.executed.push(result);
			recordDecisionClaimProbe(decision, step, result);
			step.status = result.status === "blocked" ? "blocked" : "done";
			step.reason = result.status === "blocked" ? result.output : step.reason;
			const commanderRuntime = isCommanderRuntimeCommand(step.command);
			if (commanderRuntime && result.status === "blocked") commanderFailures += 1;
			operator.commanderDispatchReport.push(
				`${step.id} commander=${commanderRuntime ? "yes" : "no"} status=${result.status} failures=${commanderFailures}/${failureBudget} retry_limit=${retryLimit} command=${step.command}`,
			);
			if (commanderRuntime && commanderFailures >= failureBudget) {
				operator.commanderDispatchReport.push(`failure_budget_exhausted=${failureBudget}; stop_dispatch=true`);
				break;
			}
		}
		const missionAfterDispatch = readCurrentMission();
		const pendingGates =
			missionAfterDispatch?.checkpoints
				.filter((checkpoint) => checkpoint.status !== "done")
				.map((checkpoint) => checkpoint.name) ?? [];
		const runtimeFeedback = classifyOperatorFeedback(operator, undefined, operator.target);
		operator.operatorFeedback = Array.from(new Set([...(operator.operatorFeedback ?? []), ...runtimeFeedback])).slice(
			0,
			64,
		);
		operator.operatorFeedbackQueue = operatorFeedbackDispatcherCommands(operator.operatorFeedback, operator.target);
		operator.dispatcherFallbackPlan = operatorFeedbackDispatchPlan(operator.operatorFeedback, operator.target);
		operator.dispatcherFeedbackScoreboard = dispatcherFeedbackScoreboard(operator);
		operator.dispatcherLearningHints = dispatcherLearningHints(
			operator.dispatcherFeedbackScoreboard,
			operator.target,
		);
		operator.autonomousBudget = autonomousExecutionBudget(operator.target, operator.dispatcherFeedbackScoreboard);
		operator.dispatcherScoreDecay = operator.autonomousBudget.scoreDecay;
		operator.repeatedFailureDemotions = operator.autonomousBudget.demotionRules;
		operator.highScorePromotions = operator.autonomousBudget.promotionRules;
		if (operator.operatorFeedback.length) {
			operator.commanderDispatchReport.push(
				`operator_feedback_runtime rows=${operator.operatorFeedback.length} queue=${operator.operatorFeedbackQueue.length} dispatcher_fallback_plan=${operator.dispatcherFallbackPlan.length} dispatcher_feedback_scoreboard=${operator.dispatcherFeedbackScoreboard.length} dispatcher_learning_hints=${operator.dispatcherLearningHints.length} autonomous_budget=${operator.autonomousBudget.maxTurns}/${operator.autonomousBudget.maxDispatch} score_decay=${operator.dispatcherScoreDecay.length} demotions=${operator.repeatedFailureDemotions.length} promotions=${operator.highScorePromotions.length}`,
			);
		}
		// Execution may have created or advanced the mission. Recompute this
		// snapshot after dispatch so the artifact describes the state just run.
		operator.verification = operatorVerificationLines(operator.steps, missionAfterDispatch);
		operator.escalationQueue = operatorEscalationQueue(operator.steps, pendingGates);
		const retryCommands = operator.steps
			.filter((step) => step.status === "blocked" && isCommanderRuntimeCommand(step.command))
			.slice(0, retryLimit)
			.map((step) => step.command);
		operator.nextActions = operator.steps
			.filter((step) => step.status === "ready")
			.slice(0, 8)
			.map((step) => `re_operator dispatch ${operator.target ?? "<target>"} 1 # ${step.id}`);
		operator.nextActions = Array.from(
			new Set([
				...operator.operatorFeedbackQueue,
				...retryCommands,
				...(operator.autonomousBudget?.nextActions ?? []),
				...operator.nextActions,
			]),
		).slice(0, 12);
		const path = writeOperatorArtifact(operator);
		return formatOperator(operator, path);
	}

	function buildOperatorOutput(
		action: "plan" | "show" | "verify" | "escalate" = "plan",
		options: { target?: string } = {},
	): string {
		if (action === "show") {
			const path = latestOperatorArtifactPath();
			if (!path) return "operator_queue:\nstatus: missing\nnext: re_operator plan";
			return compactStoredArtifact("operator_queue", path, readText(path));
		}
		const operator = buildOperator({
			target: options.target,
			mode: action === "verify" || action === "escalate" ? action : "plan",
		});
		if (action === "escalate") operator.nextActions = operator.escalationQueue;
		const path = writeOperatorArtifact(operator);
		return formatOperator(operator, path);
	}

	function parseOperatorArtifact(path: string): OperatorArtifact | undefined {
		return parseJsonCodeFence<OperatorArtifact>(readText(path));
	}

	function latestOrBuildOperator(options: { target?: string } = {}): { operator: OperatorArtifact; path: string } {
		const latest = latestOperatorArtifactPath(
			options.target ? { target: options.target, requestedBy: "latest_or_build_operator" } : {},
		);
		if (latest) {
			const operator = parseOperatorArtifact(latest);
			const missionId = readCurrentMission()?.id;
			const targetMatches =
				options.target === undefined ||
				Boolean(operator?.target?.trim() && artifactTargetMatches(options.target, operator.target));
			if (operator && missionId && operator.missionId === missionId && targetMatches)
				return { operator, path: latest };
		}
		const operator = buildOperator({ target: options.target, mode: "verify" });
		const path = writeOperatorArtifact(operator);
		return { operator, path };
	}

	function latestOperatorFeedback(target?: string): OperatorFeedbackSnapshot {
		const scope = target ? { target, requestedBy: "operator_feedback_latest_artifact_consumer" } : {};
		const specs: Array<
			[
				string | undefined,
				(path: string) => { target?: string; operatorFeedback?: string[] } | undefined,
				"scoped" | "fallback",
			]
		> = [
			[latestAutofixArtifactPath(scope), parseAutofixArtifact, "scoped"],
			[latestReplayerArtifactPath(scope), parseReplayArtifact, "scoped"],
			[latestCompilerArtifactPath(scope), parseCompilerArtifact, "scoped"],
			[latestVerifierArtifactPath(scope), parseVerifierArtifact, "scoped"],
			...(target
				? ([
						[latestAutofixArtifactPath(), parseAutofixArtifact, "fallback"],
						[latestReplayerArtifactPath(), parseReplayArtifact, "fallback"],
						[latestCompilerArtifactPath(), parseCompilerArtifact, "fallback"],
						[latestVerifierArtifactPath(), parseVerifierArtifact, "fallback"],
					] as Array<
						[
							string | undefined,
							(path: string) => { target?: string; operatorFeedback?: string[] } | undefined,
							"fallback",
						]
					>)
				: []),
		];
		const seenPaths = new Set<string>();
		const exactRows: string[] = [];
		const exactSources: string[] = [];
		const fallbackRows: string[] = [];
		const fallbackSources: string[] = [];
		for (const [path, parse, mode] of specs) {
			if (!path || !existsSync(path)) continue;
			if (seenPaths.has(path)) continue;
			seenPaths.add(path);
			const artifact = parse(path);
			if (!artifact) continue;
			const feedback = artifact.operatorFeedback ?? [];
			if (feedback.length) {
				const exact = mode === "scoped" && artifactTargetMatches(target, artifact.target);
				if (exact) {
					exactSources.push(path);
					exactRows.push(...feedback);
				} else {
					fallbackSources.push(path);
					fallbackRows.push(...feedback);
				}
			}
		}
		const rows = exactRows.length ? exactRows : fallbackRows;
		const sourceArtifacts = exactRows.length ? exactSources : fallbackSources;
		const dedupedRows = Array.from(new Set(rows)).slice(0, 48);
		const commands = operatorFeedbackNextCommands(dedupedRows)
			.map((command) => operatorCommandConcrete(command, target).command)
			.filter((command) => /^re[-_]/i.test(command))
			.filter((command) => !/^re[-_]proof[-_]loop\b/i.test(command));
		return {
			rows: dedupedRows,
			commands: Array.from(new Set(commands)).slice(0, 16),
			sourceArtifacts: Array.from(new Set(sourceArtifacts)).slice(0, 16),
		};
	}

	function operatorFeedbackProofLoopCommands(
		feedback: Pick<ReturnType<typeof latestOperatorFeedback>, "rows" | "commands">,
		target?: string,
	): string[] {
		const fallback = feedback.commands.length ? [] : operatorFeedbackDispatcherCommands(feedback.rows, target);
		return Array.from(new Set([...feedback.commands, ...fallback]).values())
			.map((command) => operatorCommandConcrete(command, target).command)
			.filter((command) => /^re[-_]/i.test(command))
			.filter((command) => !/^re[-_]proof[-_]loop\b/i.test(command))
			.slice(0, 16);
	}

	function latestCompilerClaimCheckInputs(options: { target?: string } = {}): ProofCompilerClaimCheckInputs & {
		supervisor?: SupervisorArtifact;
		swarm?: SwarmArtifact;
	} {
		const mission = readCurrentMission();
		const parallelRequired = missionRequiresParallel(mission);
		const scope = options.target ? { target: options.target, requestedBy: "compiler_claim_check" } : {};
		const candidateSupervisorPath = parallelRequired ? latestSupervisorArtifactPath(scope) : undefined;
		const parsedSupervisor = candidateSupervisorPath ? parseSupervisorArtifact(candidateSupervisorPath) : undefined;
		const candidateSupervisor =
			parsedSupervisor &&
			artifactMatchesMission(mission, parsedSupervisor) &&
			(options.target === undefined ||
				(typeof parsedSupervisor.target === "string" &&
					parsedSupervisor.target.trim().length > 0 &&
					artifactTargetMatches(options.target, parsedSupervisor.target))) &&
			Array.isArray(parsedSupervisor.releaseCheckMetadata) &&
			Array.isArray(parsedSupervisor.claimCheckPolicy) &&
			Array.isArray(parsedSupervisor.claimCheckResult)
				? parsedSupervisor
				: undefined;
		const supervisorPath = candidateSupervisor ? candidateSupervisorPath : undefined;
		const supervisor = supervisorPath ? candidateSupervisor : undefined;
		const candidateSwarmPath = parallelRequired ? latestSwarmArtifactPath(scope) : undefined;
		const parsedSwarm = candidateSwarmPath ? parseSwarmArtifact(candidateSwarmPath) : undefined;
		const candidateSwarm =
			parsedSwarm &&
			artifactMatchesMission(mission, parsedSwarm) &&
			(options.target === undefined ||
				(typeof parsedSwarm.target === "string" &&
					parsedSwarm.target.trim().length > 0 &&
					artifactTargetMatches(options.target, parsedSwarm.target))) &&
			Array.isArray(parsedSwarm.workers) &&
			Array.isArray(parsedSwarm.planCoverage) &&
			Array.isArray(parsedSwarm.releaseCheckMetadata) &&
			Array.isArray(parsedSwarm.claimLedger)
				? parsedSwarm
				: undefined;
		const swarmPath = candidateSwarm ? candidateSwarmPath : undefined;
		const swarm = swarmPath ? candidateSwarm : undefined;
		const releaseCheckMetadata = parallelRequired
			? (supervisor?.releaseCheckMetadata ?? swarm?.releaseCheckMetadata ?? [])
			: [];
		const claimCheckPolicy = parallelRequired
			? (supervisor?.claimCheckPolicy ??
				supervisorClaimCheckPolicy(swarm?.parallelPlan, supervisorPlanCoverage(swarm)))
			: ["claim_check_policy.parallel_required=false", "claim_check_policy.local_verifier_release=true"];
		// Re-evaluate the live marker for every compiler invocation. A persisted
		// supervisor artifact is an input, not an authority: otherwise a stale
		// `strictClaimCheck=pass` field could outlive the marker it describes.
		const strictClaimCheck = strictClaimCheckSnapshot();
		const supervisorLineageBlockers =
			parallelRequired && supervisor
				? supervisor.swarmArtifact !== swarmPath
					? [
							`supervisor_swarm_lineage_mismatch: supervisor=${supervisor.swarmArtifact ?? "missing"} swarm=${swarmPath ?? "missing"}`,
						]
					: []
				: [];
		const supervisorGateBlockers = parallelRequired
			? [
					...supervisorLineageBlockers,
					...(supervisor?.supervisorVerdict === "pass"
						? []
						: [supervisor ? `supervisor_verdict=${supervisor.supervisorVerdict}` : "supervisor_review_missing"]),
				]
			: [];
		const claimCheckResult = buildClaimCheckResult(
			releaseCheckMetadata,
			claimCheckPolicy,
			strictClaimCheck,
			supervisorGateBlockers,
		);
		const structuredClaimMergeCheck = parallelRequired
			? safeStructuredClaimMergeCheck(swarm)
			: {
					status: "pass" as const,
					finalClaimCount: 1,
					blockedClaimCount: 0,
					errors: [],
					policies: ["parallel merge not required by mission"],
				};
		return {
			parallelRequired,
			supervisor,
			supervisorPath,
			supervisorVerdict: parallelRequired ? supervisor?.supervisorVerdict : "pass",
			swarm,
			swarmPath,
			releaseCheckMetadata,
			claimCheckPolicy,
			strictClaimCheck,
			claimCheckResult,
			structuredClaimMergeCheck,
		};
	}

	return {
		latestDecisionCoreArtifactPath,
		nextDecisionCommand,
		buildDecisionCore,
		runDecisionCore,
		buildDecisionCoreOutput,
		latestOperatorArtifactPath,
		operatorCommandConcrete,
		operatorStepPriority,
		operatorFeedbackCategory,
		operatorFeedbackFallbackCommands,
		executeOperatorStep,
		dispatchOperatorQueue,
		buildOperatorOutput,
		latestOrBuildOperator,
		classifyOperatorFeedback,
		operatorFeedbackNextCommands,
		latestOperatorFeedback,
		operatorFeedbackProofLoopCommands,
		latestCompilerClaimCheckInputs,
		parseOperatorArtifact,
	} as const;
}

export type OperatorOrchestrationRuntime = ReturnType<typeof createOperatorOrchestrationRuntime>;

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import type { AutofixArtifact } from "./autofix-runtime.ts";

export type { AutofixArtifact, AutofixItem, AutofixItemKind, AutofixStatus } from "./autofix-runtime.ts";

import {
	type ArtifactScopeFilterOptions,
	artifactScopeDefaultOptions,
	artifactTargetMatches,
} from "./artifact-scope.ts";
import type { OperationExecution, OperationStepStatus } from "./campaign-operation-runtime.ts";
import { buildEvidenceClaimSummary, type EvidenceRecord } from "./evidence.ts";
import type { FailureSignaturePriorityReport } from "./failure-runtime.ts";
import type { AttackGraphArtifact } from "./graph.ts";
import { runtimeAdapterMitigationEvidenceForGraph, runtimeAdapterParserSummaryForGraph } from "./graph-artifacts.ts";
import { type MissionCheckpointStatus, missionRequiresParallel, readCurrentMission } from "./mission.ts";
import {
	type CompilerArtifact,
	type ProofCompilerClaimCheckInputs,
	type ReplayArtifact,
	replayExecutionHasProofSignal,
	type VerifierArtifact,
} from "./proof-artifact-runtime.ts";
import {
	formatRepiProofLoopGapClassifier as formatProofLoopGapClassifier,
	type RepiProofLoopGapItem as ProofLoopGapItem,
	type RepiProofLoopGapSource as ProofLoopGapSource,
	type RepiProofLoopRuntimeAdapterClosureRowV1 as ProofLoopRuntimeAdapterClosureRow,
	repiProofLoopCommandTarget as proofLoopCommandTarget,
	repiProofLoopQuickPathFromItems as proofLoopQuickPathFromItems,
	repiProofLoopQuickPlanFromItems as proofLoopQuickPlanFromItems,
	repiProofLoopRuntimeAdapterClosureRows as proofLoopRuntimeAdapterClosureRows,
	repiProofLoopRuntimeAdapterCommands as proofLoopRuntimeAdapterCommands,
	repiProofLoopSpecialistQueueFromItems as proofLoopSpecialistQueueFromItems,
	repiProofLoopWorkerForText as proofLoopWorkerForText,
} from "./proof-loop.ts";
import { ensureReconStorage } from "./resources.ts";
import { inspectRuntimeAdapterTarget, type RuntimeAdapterExecutionArtifactV1 } from "./runtime-adapter.ts";
import {
	currentMissionPath,
	evidenceLedgerPath,
	evidenceProofLoopsDir,
	readJsonObjectFile,
	readTextFile as readText,
	writePrivateTextFile,
} from "./storage.ts";
import type {
	AutonomousExecutionBudget,
	DelegateWorker,
	SupervisorOutputOptions,
	SwarmOutputOptions,
} from "./swarm-runtime-types.ts";
import { parseJsonCodeFence, slug, truncateMiddle } from "./text.ts";

type ProofLoopStatus = "ready" | "done" | "blocked";

type ProofLoopPhase =
	| "compact-resume"
	| "claim"
	| "failure-signature"
	| "operator-feedback"
	| "swarm-retry"
	| "attack-graph"
	| "runtime-adapter"
	| "verifier"
	| "compiler"
	| "replayer"
	| "autofix"
	| "completion";

type ProofLoopStep = {
	id: string;
	phase: ProofLoopPhase;
	command: string;
	status: ProofLoopStatus;
	reason?: string;
	sourceArtifacts: string[];
};

type ProofLoopVerdict = "ready" | "partial" | "needs_repair" | "blocked";

type ProofLoopArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "run";
	maxSteps: number;
	replaySteps: number;
	steps: ProofLoopStep[];
	executed: OperationExecution[];
	verdict: ProofLoopVerdict;
	checkStatus: string[];
	evidenceSummary: string[];
	claimPressure: string[];
	gapClassifier: string[];
	quickPath: string[];
	quickPlanPhases: string[];
	quickPlanAssertions: string[];
	runtimeAdapterClosure: string[];
	failureSignaturePriority: string[];
	failureSignatureRepairQueue: string[];
	operatorFeedback: string[];
	operatorFeedbackQueue: string[];
	swarmRetryQueue: string[];
	specialistQueue: string[];
	swarmBridge: string[];
	autonomousBudget: AutonomousExecutionBudget;
	dispatcherScoreDecay: string[];
	repeatedFailureDemotions: string[];
	highScorePromotions: string[];
	bridgeArtifacts: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

type OperatorFeedbackSnapshot = {
	rows: string[];
	commands: string[];
	sourceArtifacts: string[];
};

type SwarmRetryQueueSnapshot = {
	path?: string;
	rows: string[];
	commands: string[];
};

type CompletionAuditSnapshot = {
	ready: boolean;
	blockers: string[];
	warnings: string[];
};

function isReplaySha256(value: unknown): value is string {
	return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);
}

/**
 * Recompute replay closure from the bound compiler and individual executions.
 * Persisted summary counts and step statuses are reporting fields, not proof.
 */
export function replayClosureBlockers(
	replay: ReplayArtifact,
	compiler: CompilerArtifact,
	compilerPath: string | undefined,
): string[] {
	const blockers: string[] = [];
	if (replay.mode !== "run") blockers.push(`replay mode is ${replay.mode ?? "missing"}, expected run`);
	if (compiler.mode !== "final")
		blockers.push(`replay compiler mode is ${compiler.mode ?? "missing"}, expected final`);
	if (!compiler.missionId || replay.missionId !== compiler.missionId) {
		blockers.push(
			`replay/compiler mission lineage mismatch: replay.missionId=${replay.missionId ?? "missing"} compiler.missionId=${compiler.missionId ?? "missing"}`,
		);
	}
	if (!compilerPath || replay.compilerArtifact !== compilerPath) {
		blockers.push(
			`replay/compiler artifact lineage mismatch: replay.compilerArtifact=${replay.compilerArtifact ?? "missing"} expected compiler=${compilerPath ?? "missing"}`,
		);
	}
	if (!compilerPath || !existsSync(compilerPath)) {
		blockers.push(`replay compiler artifact is missing: ${compilerPath ?? "missing"}`);
	} else {
		const compilerSha256 = createHash("sha256").update(readText(compilerPath)).digest("hex");
		if (!isReplaySha256(replay.compilerSha256) || replay.compilerSha256 !== compilerSha256) {
			blockers.push(
				`replay/compiler SHA-256 mismatch: replay=${replay.compilerSha256 ?? "missing"} actual=${compilerSha256}`,
			);
		}
	}
	if (compiler.target !== replay.target && (compiler.target || replay.target)) {
		blockers.push(
			`replay/compiler target mismatch: replay.target=${replay.target ?? "missing"} compiler.target=${compiler.target ?? "missing"}`,
		);
	}
	if (!Array.isArray(compiler.reproCommands) || compiler.reproCommands.length === 0) {
		blockers.push("compiler has no replayable repro commands");
	}
	if (
		!Array.isArray(replay.steps) ||
		!Array.isArray(replay.executions) ||
		!Array.isArray(replay.blocked) ||
		!Array.isArray(replay.sourceArtifacts)
	) {
		blockers.push("replay artifact is missing steps, executions, blocked rows, or source artifacts");
		return blockers;
	}
	if (
		replay.steps.some(
			(step) =>
				!step || typeof step.id !== "string" || typeof step.command !== "string" || typeof step.status !== "string",
		) ||
		replay.executions.some(
			(execution) =>
				!execution ||
				typeof execution.stepId !== "string" ||
				typeof execution.command !== "string" ||
				typeof execution.status !== "string",
		)
	) {
		blockers.push("replay artifact contains malformed step or execution rows");
		return blockers;
	}
	if (Array.isArray(compiler.reproCommands) && compiler.reproCommands.some((command) => typeof command !== "string")) {
		blockers.push("compiler repro commands contain non-string rows");
	}

	const rawCommands = Array.isArray(compiler.reproCommands)
		? Array.from(
				new Set(
					compiler.reproCommands
						.slice(0, 40)
						.filter((command): command is string => typeof command === "string")
						.map((command) => command.trim())
						.filter(Boolean),
				),
			)
		: [];
	const expectedCommands = rawCommands.map((raw) => {
		let command = raw.replace(/^\//, "");
		if (replay.target) command = command.replace(/<target>|<TARGET>|<URL>|<none>/gi, replay.target);
		return command;
	});
	if (expectedCommands.length > 0 && replay.steps.length !== expectedCommands.length) {
		blockers.push(`replay step coverage mismatch: steps=${replay.steps.length} expected=${expectedCommands.length}`);
	}
	for (let index = 0; index < Math.min(expectedCommands.length, replay.steps.length); index += 1) {
		const step = replay.steps[index];
		const expected = expectedCommands[index];
		if (step && expected !== undefined && step.command !== expected) {
			blockers.push(`replay step command mismatch: step=${step.id} command=${step.command} expected=${expected}`);
		}
	}

	const stepsById = new Map<string, (typeof replay.steps)[number]>();
	for (const step of replay.steps) {
		if (!step?.id || stepsById.has(step.id)) {
			blockers.push(`replay step id is missing or duplicated: ${step?.id ?? "missing"}`);
			continue;
		}
		stepsById.set(step.id, step);
		if (step.status === "skipped") {
			if (!/^re[-_]/i.test(step.command)) blockers.push(`non-REPI replay step was skipped: ${step.id}`);
			continue;
		}
		if (step.status !== "passed") blockers.push(`replay step is not closed: ${step.id} status=${step.status}`);
	}

	const executionIds = new Set<string>();
	let actualPassed = 0;
	let actualFailed = 0;
	for (const execution of replay.executions) {
		if (!execution?.stepId || executionIds.has(execution.stepId)) {
			blockers.push(`replay execution step id is missing or duplicated: ${execution?.stepId ?? "missing"}`);
			continue;
		}
		executionIds.add(execution.stepId);
		const step = stepsById.get(execution.stepId);
		if (!step) {
			blockers.push(`replay execution has no bound step: ${execution.stepId}`);
			continue;
		}
		if (step.status === "skipped") blockers.push(`skipped replay step has an execution: ${execution.stepId}`);
		if (execution.command !== step.command) blockers.push(`replay execution command mismatch: ${execution.stepId}`);
		if (execution.status === "passed") actualPassed += 1;
		else actualFailed += 1;
		if (execution.status !== "passed" || execution.exit !== 0 || execution.killed) {
			blockers.push(
				`replay execution failed closure: ${execution.stepId} status=${execution.status} exit=${execution.exit}${execution.killed ? " killed=true" : ""}`,
			);
		}
		if (!isReplaySha256(execution.stdoutHash) || !isReplaySha256(execution.stderrHash)) {
			blockers.push(`replay execution has invalid SHA-256 binding: ${execution.stepId}`);
		}
		if (!replayExecutionHasProofSignal(execution, step)) {
			blockers.push(`replay execution lacks observation/artifact signal: ${execution.stepId}`);
		}
	}

	const executableSteps = replay.steps.filter((step) => step.status !== "skipped");
	if (executableSteps.length === 0) blockers.push("replay has no executable proof step");
	for (const step of executableSteps) {
		if (!executionIds.has(step.id)) blockers.push(`replay step has no execution: ${step.id}`);
	}
	if (replay.blocked.length > 0) blockers.push(`replay has ${replay.blocked.length} blocked row(s)`);
	if (replay.passed !== actualPassed || replay.failed !== actualFailed) {
		blockers.push(
			`replay summary mismatch: passed=${replay.passed}/${actualPassed} failed=${replay.failed}/${actualFailed}`,
		);
	}
	if (actualPassed === 0) blockers.push("replay has no passing execution");
	if (!replay.sourceArtifacts?.includes(compilerPath ?? "")) {
		blockers.push(`replay source artifacts do not bind compiler: ${compilerPath ?? "missing"}`);
	}
	const replayTime = Date.parse(replay.timestamp);
	const compilerTime = Date.parse(compiler.timestamp);
	if (!Number.isFinite(replayTime) || !Number.isFinite(compilerTime) || replayTime < compilerTime) {
		blockers.push(
			`replay is stale relative to compiler: replay=${replay.timestamp ?? "missing"} compiler=${compiler.timestamp ?? "missing"}`,
		);
	}
	return Array.from(new Set(blockers));
}

type ProofLoopOperatorStep = {
	id: string;
	command: string;
	status: OperationStepStatus;
	priority: number;
	reason?: string;
	sourceArtifacts: string[];
};

type ArtifactSelector = (options?: ArtifactScopeFilterOptions) => string | undefined;

type AppendEvidence = (
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
) => EvidenceRecord;

export type ProofLoopRuntimeDependencies = {
	latestScopedMarkdownArtifact: (
		kind: string,
		dir: string,
		options?: ArtifactScopeFilterOptions,
	) => string | undefined;
	latestDecisionCoreArtifactPath: ArtifactSelector;
	latestOperatorArtifactPath: ArtifactSelector;
	latestDelegateArtifactPath: ArtifactSelector;
	latestSwarmArtifactPath: ArtifactSelector;
	latestSupervisorArtifactPath: ArtifactSelector;
	latestVerifierArtifactPath: ArtifactSelector;
	latestCompilerArtifactPath: ArtifactSelector;
	latestReplayerArtifactPath: ArtifactSelector;
	latestAutofixArtifactPath: ArtifactSelector;
	latestAttackGraphArtifactPath: ArtifactSelector;
	contextArtifactIndex: (options?: ArtifactScopeFilterOptions) => Array<{ kind: string; path: string }>;
	parseVerifierArtifact: (path: string) => VerifierArtifact | undefined;
	parseCompilerArtifact: (path: string) => CompilerArtifact | undefined;
	parseReplayArtifact: (path: string) => ReplayArtifact | undefined;
	latestOperatorFeedback: (target?: string) => OperatorFeedbackSnapshot;
	latestCompilerClaimCheckInputs: (options?: { target?: string }) => ProofCompilerClaimCheckInputs;
	failureSignaturePriorityReport: (target?: string) => FailureSignaturePriorityReport;
	latestSwarmRetryQueue: (target?: string) => SwarmRetryQueueSnapshot;
	operatorFeedbackProofLoopCommands: (
		feedback: Pick<OperatorFeedbackSnapshot, "rows" | "commands">,
		target?: string,
	) => string[];
	delegateEvidenceContract: (worker: DelegateWorker) => string[];
	autonomousExecutionBudget: (target?: string, rows?: string[]) => AutonomousExecutionBudget;
	autonomousBudgetLines: (budget?: AutonomousExecutionBudget) => string[];
	withScopedMarkdownArtifactSelectionCache: <T>(fn: () => T) => T;
	appendEvidence: AppendEvidence;
	updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => unknown;
	appendRuntimeFailureRepairFromProofLoop: (proof: ProofLoopArtifact, path: string) => void;
	executeOperatorStep: (pi: ExtensionAPI, step: ProofLoopOperatorStep, target?: string) => Promise<OperationExecution>;
	operatorStepPriority: (command: string) => number;
	buildAttackGraphOutput: (action?: "build" | "show") => string;
	runRuntimeAdapterExecution: (
		pi: ExtensionAPI,
		options: { adapter?: string; target?: string; timeoutMs?: number },
	) => Promise<string>;
	buildVerifierOutput: (
		action?: "check" | "show" | "matrix",
		options?: { target?: string; techniqueId?: string },
	) => string;
	buildCompilerOutput: (action?: "draft" | "show" | "final", options?: { target?: string }) => string;
	runReplayer: (
		pi: ExtensionAPI,
		options?: { target?: string; maxSteps?: number; timeoutMs?: number },
	) => Promise<string>;
	buildAutofixOutput: (action?: "plan" | "show" | "apply", options?: { target?: string }) => string;
	formatCompletionAuditFromAudit: (audit: CompletionAuditSnapshot) => string;
	runCompletionAudit: () => CompletionAuditSnapshot;
	buildDelegateOutput: (action?: "plan" | "show" | "merge", options?: { target?: string; task?: string }) => string;
	buildSwarmOutput: (action?: "plan" | "show" | "merge", options?: SwarmOutputOptions) => string;
	buildSupervisorOutput: (action?: "review" | "show" | "repair", options?: SupervisorOutputOptions) => Promise<string>;
};

export function createProofLoopRuntime(dependencies: ProofLoopRuntimeDependencies) {
	const {
		latestScopedMarkdownArtifact,
		latestDecisionCoreArtifactPath,
		latestOperatorArtifactPath,
		latestDelegateArtifactPath,
		latestSwarmArtifactPath,
		latestSupervisorArtifactPath,
		latestVerifierArtifactPath,
		latestCompilerArtifactPath,
		latestReplayerArtifactPath,
		latestAutofixArtifactPath,
		latestAttackGraphArtifactPath,
		contextArtifactIndex,
		parseVerifierArtifact,
		parseCompilerArtifact,
		parseReplayArtifact,
		latestOperatorFeedback,
		latestCompilerClaimCheckInputs,
		failureSignaturePriorityReport,
		latestSwarmRetryQueue,
		operatorFeedbackProofLoopCommands,
		delegateEvidenceContract,
		autonomousExecutionBudget,
		autonomousBudgetLines,
		withScopedMarkdownArtifactSelectionCache,
		appendEvidence,
		updateMissionCheckpoint,
		appendRuntimeFailureRepairFromProofLoop,
		executeOperatorStep,
		operatorStepPriority,
		buildAttackGraphOutput,
		runRuntimeAdapterExecution,
		buildVerifierOutput,
		buildCompilerOutput,
		runReplayer,
		buildAutofixOutput,
		formatCompletionAuditFromAudit,
		runCompletionAudit,
		buildDelegateOutput,
		buildSwarmOutput,
		buildSupervisorOutput,
	} = dependencies;

	function latestProofLoopArtifactPath(options: ArtifactScopeFilterOptions = {}): string | undefined {
		return latestScopedMarkdownArtifact("proof_loop", evidenceProofLoopsDir(), options);
	}

	function parseAttackGraphArtifact(path: string): AttackGraphArtifact | undefined {
		const parsed = parseJsonCodeFence<Partial<AttackGraphArtifact>>(readText(path));
		return parsed &&
			Array.isArray(parsed.nodes) &&
			Array.isArray(parsed.edges) &&
			Array.isArray(parsed.taskTree) &&
			Array.isArray(parsed.gaps)
			? (parsed as AttackGraphArtifact)
			: undefined;
	}

	function proofLoopAttackGraphGapItems(target?: string): Array<Omit<ProofLoopGapItem, "worker">> {
		const scope = target ? { target, requestedBy: "proof_loop_attack_graph_gap_consumer" } : {};
		const path = latestAttackGraphArtifactPath(scope) ?? latestAttackGraphArtifactPath();
		if (!path) {
			return [
				{
					source: "attack_graph",
					text: "attack graph artifact missing: run re_graph build before proof-loop planning",
					sourceArtifacts: [],
				},
			];
		}
		const graph = parseAttackGraphArtifact(path);
		if (!graph) {
			return [
				{
					source: "attack_graph",
					text: `attack graph artifact unreadable: ${path}`,
					sourceArtifacts: [path],
				},
			];
		}
		if (target && graph.target && !artifactTargetMatches(target, graph.target)) return [];
		const sourceArtifacts = [path, ...(graph.sourceArtifacts ?? [])].filter((item) => existsSync(item)).slice(0, 16);
		const runtimeAdapterGapRows = sourceArtifacts.flatMap((artifactPath) => {
			if (!/\/runtime-adapters\/.+\.json$/i.test(artifactPath)) return [];
			try {
				const artifact = readJsonObjectFile<Partial<RuntimeAdapterExecutionArtifactV1>>(artifactPath);
				if (!artifact || artifact.kind !== "RuntimeAdapterExecutionArtifactV1" || !artifact.adapterId) return [];
				const canSummarize =
					Array.isArray(artifact.parserSignals) &&
					Array.isArray(artifact.artifactKinds) &&
					Array.isArray(artifact.ingestTargets) &&
					Array.isArray(artifact.proofExitSignals);
				const typedArtifact = canSummarize
					? (artifact as RuntimeAdapterExecutionArtifactV1 & { stdoutHead?: string; stderrHead?: string })
					: undefined;
				const summary = typedArtifact
					? runtimeAdapterParserSummaryForGraph(typedArtifact)
					: artifact.parserSignalSummary;
				const missing = summary?.missingProofExitSignals ?? [];
				const matched = summary?.matchedProofExitSignals ?? [];
				const rows: string[] = [];
				if (summary && missing.length > 0) {
					rows.push(
						`attack_graph runtime_adapter_gap: parser_signal_summary adapter=${artifact.adapterId} matched=${matched.join(" | ") || "<none>"} missing=${missing.join(" | ") || "<none>"} rules=${summary.matchedRules}/${summary.totalRules} artifact=${artifactPath}`,
					);
					rows.push(
						`attack_graph runtime_adapter_gap: runtime adapter missing proof: ${artifact.adapterId}: ${missing.join("; ")}`,
					);
				}
				if (summary && missing.length === 0 && matched.length > 0 && (artifact.proofExitSignals?.length ?? 0) > 0) {
					rows.push(
						`attack_graph proof_spine_seed: runtime adapter proof-exit complete adapter=${artifact.adapterId} matched=${matched.join(" | ")} rules=${summary.matchedRules}/${summary.totalRules} artifact=${artifactPath}`,
					);
				}
				if ((summary?.matchedRules ?? 0) === 0)
					rows.push(`attack_graph runtime_adapter_gap: runtime adapter parser no-match: ${artifact.adapterId}`);
				if (typedArtifact) {
					const mitigationEvidence = runtimeAdapterMitigationEvidenceForGraph(typedArtifact);
					if (mitigationEvidence?.matched) {
						rows.push(
							`attack_graph proof_spine_seed: binary mitigation map matched: ${artifact.adapterId}: ${mitigationEvidence.evidence.slice(0, 6).join(" | ")}`,
						);
					} else if (mitigationEvidence?.expected) {
						rows.push(
							`attack_graph runtime_adapter_gap: runtime adapter missing mitigation map proof: ${artifact.adapterId}`,
						);
					}
				}
				return rows;
			} catch {
				return [];
			}
		});
		const rows = [
			...runtimeAdapterGapRows,
			...(graph.gaps ?? []).map((gap) => `attack_graph gap: ${gap}`),
			...(graph.taskTree ?? [])
				.filter((node) => node.kind === "gap")
				.map(
					(node) =>
						`attack_graph task_tree_gap: ${node.label} status=${node.status ?? "gap"} evidence=${(node.evidence ?? []).join(" | ") || "none"}`,
				),
			...(graph.taskTree ?? [])
				.filter(
					(node) =>
						node.kind === "artifact" && /binary mitigation map/i.test(`${node.label} ${node.status ?? ""}`),
				)
				.map(
					(node) =>
						`attack_graph proof_spine_seed: ${node.label} status=${node.status ?? "unknown"} evidence=${(node.evidence ?? []).join(" | ") || "none"}`,
				),
			...(graph.taskTree ?? [])
				.filter((node) => node.kind === "parser_summary" && /missing=(?!0\b)/i.test(node.status ?? ""))
				.map(
					(node) =>
						`attack_graph parser_signal_summary: ${node.label} status=${node.status ?? "unknown"} evidence=${(node.evidence ?? []).join(" | ") || "none"}`,
				),
		];
		return Array.from(new Set(rows))
			.slice(0, 16)
			.map((text) => ({ source: "attack_graph" as const, text, sourceArtifacts }));
	}

	function proofLoopSourceArtifacts(target?: string): string[] {
		const scope = target ? { target, requestedBy: "proof_loop_source_latest_artifact_consumer" } : {};
		const parallelRequired = missionRequiresParallel(readCurrentMission());
		return Array.from(
			new Set(
				[
					currentMissionPath(),
					evidenceLedgerPath(),
					latestDecisionCoreArtifactPath(scope),
					latestOperatorArtifactPath(scope),
					...(parallelRequired
						? [
								latestDelegateArtifactPath(scope),
								latestSwarmArtifactPath(scope),
								latestSupervisorArtifactPath(scope),
							]
						: []),
					latestVerifierArtifactPath(scope),
					latestCompilerArtifactPath(scope),
					latestReplayerArtifactPath(scope),
					latestAutofixArtifactPath(scope),
					latestAttackGraphArtifactPath(scope),
					...contextArtifactIndex({ target, requestedBy: "proof_loop_source_artifact_index" }).map(
						(artifact) => artifact.path,
					),
				].filter((path): path is string => Boolean(path && existsSync(path))),
			),
		).slice(0, 64);
	}

	function proofLoopBridgeArtifacts(target?: string): string[] {
		if (!missionRequiresParallel(readCurrentMission())) return [];
		const scope = target ? { target, requestedBy: "proof_loop_bridge_latest_artifact_consumer" } : {};
		return [
			latestDelegateArtifactPath(scope),
			latestSwarmArtifactPath(scope),
			latestSupervisorArtifactPath(scope),
		].filter((path): path is string => Boolean(path && existsSync(path)));
	}

	function proofLoopCheckStatus(): string[] {
		const mission = readCurrentMission();
		return (
			mission?.checkpoints
				.filter((checkpoint) =>
					/decision_core_ready|operator_queue_ready|verifier_matrix_ready|compiler_ready|replay_ready|autofix_ready|proof_loop_ready|report_or_writeup_ready/i.test(
						checkpoint.name,
					),
				)
				.map(
					(checkpoint) =>
						`${checkpoint.name}: ${checkpoint.status}${checkpoint.note ? ` — ${truncateMiddle(checkpoint.note, 140)}` : ""}`,
				) ?? ["mission: missing"]
		);
	}

	function proofLoopArtifactMatchesCurrentMission(
		target: string | undefined,
		artifact: { missionId?: string; target?: string } | undefined,
	): boolean {
		const missionId = readCurrentMission()?.id;
		if (!missionId || artifact?.missionId !== missionId) return false;
		// A caller-supplied target is a hard scope boundary.  The generic artifact
		// selector intentionally tolerates target-less legacy artifacts for display,
		// but a final proof/replay gate must never promote one of those artifacts.
		if (target !== undefined && (!artifact.target || !artifact.target.trim())) return false;
		return artifactTargetMatches(target, artifact.target);
	}

	function proofLoopVerifierReady(target?: string): { verifier: VerifierArtifact; path: string } | undefined {
		const scope = target ? { target, requestedBy: "proof_loop_final_verifier" } : {};
		const path = latestVerifierArtifactPath(scope);
		const verifier = path ? parseVerifierArtifact(path) : undefined;
		if (
			!path ||
			!verifier ||
			!proofLoopArtifactMatchesCurrentMission(target, verifier) ||
			!Array.isArray(verifier.assertions) ||
			verifier.assertions.length === 0 ||
			verifier.assertions.some((assertion) => !assertion || assertion.status !== "proved") ||
			!Array.isArray(verifier.contradictions) ||
			verifier.contradictions.length > 0 ||
			!Array.isArray(verifier.gaps) ||
			verifier.gaps.length > 0
		) {
			return undefined;
		}
		return { verifier, path };
	}

	function proofLoopClaimInputsReady(target?: string): boolean {
		const claimInputs = latestCompilerClaimCheckInputs({ target });
		return (
			claimInputs.supervisorVerdict === "pass" &&
			claimInputs.strictClaimCheck.status === "pass" &&
			claimInputs.structuredClaimMergeCheck.status === "pass" &&
			claimInputs.structuredClaimMergeCheck.finalClaimCount > 0 &&
			Array.isArray(claimInputs.claimCheckResult) &&
			claimInputs.claimCheckResult.includes("claim_check.final_publish_ready=yes") &&
			!claimInputs.claimCheckResult.some((row) => /^claim_check\.blocker=/i.test(row))
		);
	}

	function proofLoopFinalCompiler(target?: string): { compiler: CompilerArtifact; path: string } | undefined {
		const verifier = proofLoopVerifierReady(target);
		if (!verifier || !proofLoopClaimInputsReady(target)) return undefined;
		const claimInputs = latestCompilerClaimCheckInputs({ target });
		const scope = target ? { target, requestedBy: "proof_loop_final_compiler" } : {};
		const path = latestCompilerArtifactPath(scope);
		const compiler = path ? parseCompilerArtifact(path) : undefined;
		if (
			!path ||
			!compiler ||
			!proofLoopArtifactMatchesCurrentMission(target, compiler) ||
			compiler.mode !== "final" ||
			compiler.verifierArtifact !== verifier.path ||
			compiler.supervisorArtifact !== claimInputs.supervisorPath ||
			!compiler.statusSummary ||
			typeof compiler.statusSummary !== "object" ||
			compiler.statusSummary?.proved !== verifier.verifier.assertions.length ||
			compiler.statusSummary.weak !== 0 ||
			compiler.statusSummary.contradicted !== 0 ||
			compiler.statusSummary.missing !== 0 ||
			!Array.isArray(compiler.contradictions) ||
			compiler.contradictions.length > 0 ||
			!Array.isArray(compiler.gaps) ||
			compiler.gaps.length > 0 ||
			compiler.supervisorVerdict !== "pass" ||
			compiler.strictClaimCheck?.status !== "pass" ||
			compiler.strictClaimCheck.markerPath !== claimInputs.strictClaimCheck.markerPath ||
			compiler.structuredClaimMergeCheck?.status !== "pass" ||
			compiler.structuredClaimMergeCheck.mergePath !== claimInputs.structuredClaimMergeCheck.mergePath ||
			(compiler.structuredClaimMergeCheck.finalClaimCount ?? 0) === 0 ||
			!Array.isArray(compiler.claimCheckResult) ||
			!compiler.claimCheckResult.includes("claim_check.final_publish_ready=yes") ||
			compiler.claimCheckResult.some((row) => /^claim_check\.blocker=/i.test(row)) ||
			!compiler.reportPath ||
			!existsSync(compiler.reportPath)
		) {
			return undefined;
		}
		return { compiler, path };
	}

	function proofLoopReplayForCompiler(
		target: string | undefined,
		compiler: { compiler: CompilerArtifact; path: string },
	): { replay?: ReplayArtifact; path?: string; blockers: string[] } {
		const scope = target ? { target, requestedBy: "proof_loop_final_replay" } : {};
		const path = latestReplayerArtifactPath(scope);
		const replay = path ? parseReplayArtifact(path) : undefined;
		if (!replay || !proofLoopArtifactMatchesCurrentMission(target, replay)) {
			return {
				path,
				blockers: [path ? `replayer artifact is stale or unreadable: ${path}` : "replayer artifact missing"],
			};
		}
		return { replay, path, blockers: replayClosureBlockers(replay, compiler.compiler, compiler.path) };
	}

	function proofLoopVerdict(target?: string): ProofLoopVerdict {
		const scope = target ? { target, requestedBy: "proof_loop_verdict_latest_artifact_consumer" } : {};
		const verifierPath = latestVerifierArtifactPath(scope);
		const candidateVerifier = verifierPath ? parseVerifierArtifact(verifierPath) : undefined;
		const verifier =
			proofLoopArtifactMatchesCurrentMission(target, candidateVerifier) &&
			candidateVerifier &&
			Array.isArray(candidateVerifier.assertions) &&
			Array.isArray(candidateVerifier.contradictions) &&
			Array.isArray(candidateVerifier.gaps)
				? candidateVerifier
				: undefined;
		const replayPath = latestReplayerArtifactPath(scope);
		const candidateReplay = replayPath ? parseReplayArtifact(replayPath) : undefined;
		const replay =
			proofLoopArtifactMatchesCurrentMission(target, candidateReplay) &&
			candidateReplay &&
			Array.isArray(candidateReplay.blocked) &&
			Array.isArray(candidateReplay.executions)
				? candidateReplay
				: undefined;
		const compilerPath = latestCompilerArtifactPath(scope);
		const candidateCompiler = compilerPath ? parseCompilerArtifact(compilerPath) : undefined;
		const compiler =
			proofLoopArtifactMatchesCurrentMission(target, candidateCompiler) &&
			candidateCompiler &&
			candidateCompiler.statusSummary &&
			typeof candidateCompiler.statusSummary === "object" &&
			Array.isArray(candidateCompiler.contradictions) &&
			Array.isArray(candidateCompiler.gaps) &&
			Array.isArray(candidateCompiler.claimCheckResult)
				? candidateCompiler
				: undefined;
		const feedbackRows = latestOperatorFeedback(target).rows.filter(
			(row) => !/category=(strong_evidence|worker_retry_progress)/i.test(row),
		);
		const graphPath = latestAttackGraphArtifactPath(scope);
		const graph = graphPath ? parseAttackGraphArtifact(graphPath) : undefined;
		if (replay?.failed || replay?.blocked.length) return "needs_repair";
		if (
			verifier &&
			(verifier.contradictions.length > 0 || verifier.assertions.some((row) => row.status === "contradicted"))
		)
			return "needs_repair";
		if (compiler && (compiler.statusSummary.contradicted > 0 || compiler.contradictions.length > 0))
			return "needs_repair";
		if (
			feedbackRows.some((row) =>
				/category=(unresolved_target|dispatcher_gap|missing_tool_or_dependency|worker_retry_blocked|runtime_failure|failure_budget_exhausted)/i.test(
					row,
				),
			)
		)
			return "needs_repair";
		if (
			graph?.gaps.some((gap) =>
				/runtime adapter missing (?:mitigation map )?proof|runtime adapter parser no-match|missing-proof-exit/i.test(
					gap,
				),
			)
		)
			return "needs_repair";
		if (feedbackRows.length) return "partial";
		if (!verifier || !compiler || !replay) return "partial";
		if (verifier.assertions.length === 0 || verifier.assertions.some((row) => row.status !== "proved"))
			return "partial";
		if (verifier.gaps.length > 0) return "partial";
		if (compiler.mode !== "final" || !compiler.reportPath || !existsSync(compiler.reportPath)) return "partial";
		if (compiler.verifierArtifact !== verifierPath) return "partial";
		if (
			["proved", "weak", "contradicted", "missing"].some(
				(key) => !Number.isFinite(compiler.statusSummary[key as keyof typeof compiler.statusSummary]),
			)
		)
			return "partial";
		if (compiler.statusSummary.missing > 0 || compiler.statusSummary.weak > 0 || compiler.gaps.length > 0)
			return "partial";
		const claimInputs = latestCompilerClaimCheckInputs({ target });
		if (
			claimInputs.supervisorVerdict !== "pass" ||
			claimInputs.strictClaimCheck.status !== "pass" ||
			claimInputs.structuredClaimMergeCheck.status !== "pass" ||
			claimInputs.structuredClaimMergeCheck.finalClaimCount === 0 ||
			!claimInputs.claimCheckResult.includes("claim_check.final_publish_ready=yes") ||
			claimInputs.claimCheckResult.some((row) => /^claim_check\.blocker=/i.test(row))
		)
			return "partial";
		if (
			compiler.supervisorArtifact !== claimInputs.supervisorPath ||
			compiler.supervisorVerdict !== "pass" ||
			compiler.strictClaimCheck?.status !== "pass" ||
			compiler.strictClaimCheck.markerPath !== claimInputs.strictClaimCheck.markerPath ||
			compiler.structuredClaimMergeCheck?.status !== "pass" ||
			compiler.structuredClaimMergeCheck.mergePath !== claimInputs.structuredClaimMergeCheck.mergePath ||
			(compiler.structuredClaimMergeCheck.finalClaimCount ?? 0) === 0 ||
			!compiler.claimCheckResult.includes("claim_check.final_publish_ready=yes") ||
			compiler.claimCheckResult.some((row) => /^claim_check\.blocker=/i.test(row))
		)
			return "partial";
		const replayBlockers = replayClosureBlockers(replay, compiler, compilerPath);
		if (replayBlockers.length > 0) {
			return replayBlockers.some((blocker) => /failed closure|blocked row|status=(?:failed|blocked)/i.test(blocker))
				? "needs_repair"
				: "partial";
		}
		return "ready";
	}

	function proofLoopEvidenceSummary(target?: string): string[] {
		const scope = target ? { target, requestedBy: "proof_loop_evidence_latest_artifact_consumer" } : {};
		const verifierPath = latestVerifierArtifactPath(scope);
		const candidateVerifier = verifierPath ? parseVerifierArtifact(verifierPath) : undefined;
		const verifier = artifactTargetMatches(target, candidateVerifier?.target) ? candidateVerifier : undefined;
		const compilerPath = latestCompilerArtifactPath(scope);
		const candidateCompiler = compilerPath ? parseCompilerArtifact(compilerPath) : undefined;
		const compiler = artifactTargetMatches(target, candidateCompiler?.target) ? candidateCompiler : undefined;
		const replayPath = latestReplayerArtifactPath(scope);
		const candidateReplay = replayPath ? parseReplayArtifact(replayPath) : undefined;
		const replay = artifactTargetMatches(target, candidateReplay?.target) ? candidateReplay : undefined;
		const autofixPath = latestAutofixArtifactPath(scope);
		const candidateAutofix = autofixPath ? parseAutofixArtifact(autofixPath) : undefined;
		const autofix = artifactTargetMatches(target, candidateAutofix?.target) ? candidateAutofix : undefined;
		const graphPath = latestAttackGraphArtifactPath(scope);
		const graph = graphPath ? parseAttackGraphArtifact(graphPath) : undefined;
		const feedback = latestOperatorFeedback(target);
		return [
			`verifier: ${verifierPath ?? "missing"} assertions=${verifier?.assertions.length ?? 0} contradictions=${verifier?.contradictions.length ?? 0} gaps=${verifier?.gaps.length ?? 0}`,
			`compiler: ${compilerPath ?? "missing"} proved=${compiler?.statusSummary.proved ?? 0} weak=${compiler?.statusSummary.weak ?? 0} contradicted=${compiler?.statusSummary.contradicted ?? 0} missing=${compiler?.statusSummary.missing ?? 0}`,
			`replayer: ${replayPath ?? "missing"} executed=${replay?.executions.length ?? 0} passed=${replay?.passed ?? 0} failed=${replay?.failed ?? 0} blocked=${replay?.blocked.length ?? 0}`,
			`autofix: ${autofixPath ?? "missing"} failures=${autofix?.failures.length ?? 0} applied=${autofix?.applied.length ?? 0}`,
			`attack_graph: ${graphPath ?? "missing"} gaps=${graph?.gaps.length ?? 0} task_tree=${graph?.taskTree.length ?? 0} runtime_adapter_gaps=${graph?.gaps.filter((gap) => /runtime adapter|missing proof|parser no-match/i.test(gap)).length ?? 0}`,
			`operator_feedback: rows=${feedback.rows.length} commands=${feedback.commands.length} sources=${feedback.sourceArtifacts.length}`,
		];
	}

	function parseAutofixArtifact(path: string): AutofixArtifact | undefined {
		return parseJsonCodeFence<AutofixArtifact>(readText(path));
	}

	function proofLoopGapItems(target?: string): ProofLoopGapItem[] {
		const mission = readCurrentMission();
		const targetRef = target ?? artifactScopeDefaultOptions().target ?? mission?.task;
		const items: Array<Omit<ProofLoopGapItem, "worker">> = [];
		const add = (source: ProofLoopGapSource, text: string | undefined, sourceArtifacts: string[]) => {
			const normalized = text?.replace(/\s+/g, " ").trim();
			if (!normalized) return;
			items.push({
				source,
				text: truncateMiddle(normalized, 520),
				sourceArtifacts: Array.from(new Set(sourceArtifacts.filter((path) => existsSync(path)))).slice(0, 16),
			});
		};
		const scope = targetRef ? { target: targetRef, requestedBy: "proof_loop_gap_latest_artifact_consumer" } : {};
		const verifierPath = latestVerifierArtifactPath(scope);
		const verifier = verifierPath ? parseVerifierArtifact(verifierPath) : undefined;
		if (verifierPath && verifier && artifactTargetMatches(targetRef, verifier.target)) {
			const sourceArtifacts = [verifierPath, ...verifier.sourceArtifacts];
			for (const gap of verifier.gaps.slice(0, 8)) add("verifier", `gap: ${gap}`, sourceArtifacts);
			for (const contradiction of verifier.contradictions.slice(0, 8))
				add("verifier", `contradiction: ${contradiction}`, sourceArtifacts);
			for (const assertion of verifier.assertions.filter((item) => item.status !== "proved").slice(0, 8)) {
				add(
					"verifier",
					`${assertion.status}: ${assertion.id} ${assertion.claim}; followups=${assertion.requiredFollowups.join(" | ") || "none"}`,
					sourceArtifacts,
				);
			}
		} else {
			add("artifact", "verifier artifact missing: run re_verifier matrix before final claim", []);
		}
		const compilerPath = latestCompilerArtifactPath(scope);
		const compiler = compilerPath ? parseCompilerArtifact(compilerPath) : undefined;
		if (compilerPath && compiler && artifactTargetMatches(targetRef, compiler.target)) {
			const sourceArtifacts = [compilerPath, ...compiler.sourceArtifacts];
			for (const gap of compiler.gaps.slice(0, 10)) add("compiler", `gap: ${gap}`, sourceArtifacts);
			for (const contradiction of compiler.contradictions.slice(0, 10))
				add("compiler", `contradiction: ${contradiction}`, sourceArtifacts);
			if (compiler.statusSummary.weak > 0 || compiler.statusSummary.missing > 0) {
				add(
					"compiler",
					`summary: weak=${compiler.statusSummary.weak} missing=${compiler.statusSummary.missing} next=${compiler.nextOperatorQueue.slice(0, 6).join(" | ")}`,
					sourceArtifacts,
				);
			}
		} else {
			add("artifact", "compiler artifact missing: run re_compiler draft before proof-loop completion", []);
		}
		const replayPath = latestReplayerArtifactPath(scope);
		const replay = replayPath ? parseReplayArtifact(replayPath) : undefined;
		if (replayPath && replay && artifactTargetMatches(targetRef, replay.target)) {
			const sourceArtifacts = [replayPath, ...replay.sourceArtifacts];
			for (const blocked of replay.blocked.slice(0, 10)) add("replayer", `blocked: ${blocked}`, sourceArtifacts);
			for (const execution of replay.executions.filter((item) => item.status === "failed").slice(0, 10)) {
				add(
					"replayer",
					`failed: ${execution.stepId} exit=${execution.exit} command=${execution.command} stderr=${truncateMiddle(execution.stderrHead, 220)}`,
					sourceArtifacts,
				);
			}
			if (replay.executions.length === 0)
				add("replayer", "no replay execution yet: run bounded replay", sourceArtifacts);
		} else {
			add("artifact", "replayer artifact missing: run re_replayer run <target> 1", []);
		}
		const autofixPath = latestAutofixArtifactPath(scope);
		const autofix = autofixPath ? parseAutofixArtifact(autofixPath) : undefined;
		if (autofixPath && autofix && artifactTargetMatches(targetRef, autofix.target)) {
			const sourceArtifacts = [autofixPath, ...autofix.sourceArtifacts];
			for (const failure of autofix.failures.slice(0, 8)) add("autofix", `failure: ${failure}`, sourceArtifacts);
			for (const item of [
				...autofix.patchQueue,
				...autofix.commandSubstitutions,
				...autofix.bootstrapQueue,
				...autofix.evidenceRecaptureQueue,
			]
				.filter((entry) => entry.status !== "applied")
				.slice(0, 12)) {
				add("autofix", `${item.kind}: ${item.reason}; command=${item.command}`, [
					autofixPath,
					...item.sourceArtifacts,
				]);
			}
		}
		for (const graphGap of proofLoopAttackGraphGapItems(targetRef)) {
			add("attack_graph", graphGap.text, graphGap.sourceArtifacts);
		}
		const feedback = latestOperatorFeedback(targetRef);
		for (const row of feedback.rows
			.filter((item) => !/category=(strong_evidence|worker_retry_progress)/i.test(item))
			.slice(0, 16)) {
			add("operator_feedback", row, feedback.sourceArtifacts);
		}
		const failurePriority = failureSignaturePriorityReport(targetRef);
		for (const row of failurePriority.rows.slice(0, 12)) {
			add("failure_signature", row, failurePriority.sourceArtifacts);
		}
		for (const checkpoint of proofLoopCheckStatus()
			.filter((item) => /pending|blocked|missing/i.test(item))
			.slice(0, 12))
			add("checkpoint", checkpoint, proofLoopSourceArtifacts(targetRef));
		const deduped = new Map<string, Omit<ProofLoopGapItem, "worker">>();
		for (const item of items) {
			const key = `${item.source}:${item.text}`;
			if (!deduped.has(key)) deduped.set(key, item);
		}
		return [...deduped.values()].slice(0, 32).map((item, index) => ({
			...item,
			text: item.text || `gap ${index + 1}`,
			worker: proofLoopWorkerForText(item.text, mission),
		}));
	}

	function proofLoopTargetRuntimeAdapterCommands(target?: string): string[] {
		const targetRef = target?.trim();
		if (!targetRef) return [];
		const profile = inspectRuntimeAdapterTarget(targetRef);
		const targetKinds = new Set(profile.targetKinds);
		const mobilePackageId =
			targetKinds.has("mobile-package") && /^([a-z][a-z0-9_]*\.){2,}[a-z][a-z0-9_]*$/i.test(targetRef);
		const strongRuntimeTarget =
			profile.exists || targetKinds.has("web-url") || targetKinds.has("cdp-endpoint") || mobilePackageId;
		if (!strongRuntimeTarget) return [];
		return proofLoopRuntimeAdapterCommands(profile.adapterIds, targetRef);
	}

	function proofLoopQuickPlanRows(
		items: ProofLoopGapItem[],
		target?: string,
	): {
		commands: string[];
		phases: string[];
		assertions: string[];
	} {
		const targetRuntimeCommands = proofLoopTargetRuntimeAdapterCommands(target);
		const targetRuntimeCommandSet = new Set(targetRuntimeCommands);
		const plan = proofLoopQuickPlanFromItems(items, target);
		const parallelRequired = missionRequiresParallel(readCurrentMission());
		const commandAllowed = (command: string) =>
			parallelRequired || !/^re[-_](?:delegate|swarm|supervisor)\b/i.test(command.trim());
		const commands = Array.from(new Set([...targetRuntimeCommands, ...plan.commands])).filter(commandAllowed);
		const phases = plan.phases
			.map((phase) => ({ ...phase, commands: phase.commands.filter(commandAllowed) }))
			.filter((phase) => phase.commands.length > 0);
		return {
			commands,
			phases: [
				...(targetRuntimeCommands.length
					? [
							`phase=0:target_runtime_frontload reason="auto-detected live target runtime adapters before stale artifact replay" classes=runtime_adapter_gap commands=${targetRuntimeCommands.join(" && ")} evidence=target_profile:auto-detect`,
						]
					: []),
				...phases.map(
					(phase, index) =>
						`phase=${index + 1}:${phase.phase} reason="${phase.reason}" classes=${phase.classes.join(",") || "any"} commands=${phase.commands.join(" && ")} evidence=${phase.evidenceRefs.join(" | ") || "none"}`,
				),
			].slice(0, 16),
			assertions: [
				`bounded=${commands.length <= 18 ? "pass" : "fail"} commands=${commands.length} omitted=${plan.omittedCommands.length}`,
				`deduplicated=${commands.length === new Set(commands).size ? "pass" : "fail"}`,
				`runtime_adapter_before_replay=${
					commands.some((command) => targetRuntimeCommandSet.has(command))
						? (
								() => {
									const adapterIndex = commands.findIndex((command) => targetRuntimeCommandSet.has(command));
									const replayIndex = commands.findIndex((command) => /^re_replayer run\b/i.test(command));
									return replayIndex < 0 || adapterIndex < replayIndex ? "pass" : "fail";
								}
							)()
						: plan.assertions.runtimeAdapterBeforeReplay
							? "pass"
							: "fail"
				}`,
				`autofix_apply_before_final_replay=${plan.assertions.autofixApplyBeforeFinalReplay ? "pass" : "fail"}`,
				`final_loop_last=${commands.at(-1) === plan.finalLoopCommand ? "pass" : "fail"} command=${plan.finalLoopCommand}`,
			],
		};
	}

	function proofLoopQuickPath(target?: string): string[] {
		return proofLoopQuickPlanRows(proofLoopGapItems(target), target).commands;
	}

	function formatProofLoopRuntimeAdapterClosureRow(row: ProofLoopRuntimeAdapterClosureRow): string {
		return [
			`adapter=${row.adapterId}`,
			`status=${row.status}`,
			`missing=${row.missingProofSignals.join(" | ") || "<none>"}`,
			`matched=${row.matchedProofSignals.join(" | ") || "<none>"}`,
			`commands=${row.commands.join(" && ") || "<none>"}`,
			`evidence=${row.sourceArtifacts.slice(0, 4).join(" | ") || "none"}`,
		].join(" ");
	}

	function proofLoopSwarmRetryQueue(target?: string): string[] {
		if (!missionRequiresParallel(readCurrentMission())) return [];
		const retry = latestSwarmRetryQueue(target);
		return retry.rows
			.map((row, index) => {
				const commands = /\bnext=(.+)$/i.exec(row)?.[1]?.trim() ?? "re_swarm run";
				return `swarm-retry:${index + 1}: ${row} :: commands=${commands}`;
			})
			.slice(0, 24);
	}

	function proofLoopSwarmBridgeFromItems(items: ProofLoopGapItem[], target?: string): string[] {
		if (!missionRequiresParallel(readCurrentMission())) return [];
		const suffix = proofLoopCommandTarget(target);
		const retry = latestSwarmRetryQueue(target);
		const feedback = latestOperatorFeedback(target);
		const feedbackRows = feedback.rows
			.filter((row) => !/category=(strong_evidence|worker_retry_progress)/i.test(row))
			.map(
				(row, index) =>
					`operator_feedback:${index + 1} next="${feedback.commands[index] ?? "re_operator dispatch"}" row=${row}`,
			);
		const retryRows = retry.rows.map(
			(row, index) =>
				`retry_queue:${index + 1} source=swarm next="${retry.commands[index] ?? "re_swarm run"}" row=${row}`,
		);
		const grouped = new Map<DelegateWorker, ProofLoopGapItem[]>();
		for (const item of items) grouped.set(item.worker, [...(grouped.get(item.worker) ?? []), item]);
		const rows = [...grouped.entries()].map(([worker, items]) => {
			const contracts = delegateEvidenceContract(worker).join(" | ");
			const sources = Array.from(new Set(items.flatMap((item) => item.sourceArtifacts))).slice(0, 5);
			return `${worker}: gaps=${items.length} delegate="re_delegate plan${suffix}" swarm="re_swarm run${suffix} 2 1" swarm_merge="re_swarm merge" supervisor="re_supervisor repair${suffix}" evidence_contract=${contracts} sources=${sources.join(" | ") || "none"}`;
		});
		if (rows.length || retryRows.length || feedbackRows.length)
			return [...feedbackRows, ...retryRows, ...rows].slice(0, 16);
		return [
			`general: no active proof gaps; bridge standby -> re_swarm run${suffix} 2 1 && re_swarm merge && re_supervisor review${suffix}`,
		];
	}

	function buildProofLoopSteps(target?: string): ProofLoopStep[] {
		const suffix = proofLoopCommandTarget(target);
		const replayTarget = target?.trim() || "<target>";
		const sourceArtifacts = proofLoopSourceArtifacts(target);
		const operatorFeedback = latestOperatorFeedback(target);
		const operatorFeedbackCommands = operatorFeedbackProofLoopCommands(operatorFeedback, target);
		const swarmRetryCommands = missionRequiresParallel(readCurrentMission())
			? latestSwarmRetryQueue(target).commands
			: [];
		const failureSignaturePriority = failureSignaturePriorityReport(target);
		const failureSignatureCommands = failureSignaturePriority.commands;
		const graphGapItems = proofLoopGapItems(target).filter((item) => item.source === "attack_graph");
		const graphGapCommands = proofLoopQuickPathFromItems(graphGapItems, target).filter((command) =>
			/^(?:re_graph build|re_runtime_adapter )/i.test(command),
		);
		const targetRuntimeCommands = proofLoopTargetRuntimeAdapterCommands(target);
		const targetRuntimeCommandSet = new Set(targetRuntimeCommands);
		const specs: Array<[ProofLoopPhase, string]> = [
			...targetRuntimeCommands.map((command): [ProofLoopPhase, string] => ["runtime-adapter", command]),
			["verifier", `re_verifier matrix${suffix}`],
			["compiler", `re_compiler draft${suffix}`],
			["replayer", `re_replayer run ${replayTarget} 2`],
			["autofix", `re_autofix plan${suffix}`],
			["autofix", `re_autofix apply${suffix}`],
			["replayer", `re_replayer run ${replayTarget} 1`],
			["compiler", `re_compiler final${suffix}`],
			["replayer", `re_replayer run ${replayTarget} 40`],
		];
		for (const command of failureSignatureCommands.slice(0, 4)) specs.push(["failure-signature", command]);
		for (const command of graphGapCommands.slice(0, 4))
			specs.push([/^re_runtime_adapter /i.test(command) ? "runtime-adapter" : "attack-graph", command]);
		for (const command of operatorFeedbackCommands.slice(0, 4)) specs.push(["operator-feedback", command]);
		for (const command of swarmRetryCommands.slice(0, 4)) specs.push(["swarm-retry", command]);
		return specs.map(([phase, command], index) => {
			const placeholderBlocked = /<target>/i.test(command) && !target;
			return {
				id: `proof:${index + 1}:${phase}`,
				phase,
				command,
				status: placeholderBlocked ? "blocked" : "ready",
				reason: placeholderBlocked
					? "target placeholder is unresolved"
					: phase === "failure-signature"
						? "source=failure_signature_priority"
						: phase === "attack-graph" || phase === "runtime-adapter"
							? targetRuntimeCommandSet.has(command)
								? "source=target_auto_detection"
								: "source=attack_graph_gap"
							: undefined,
				sourceArtifacts:
					phase === "failure-signature"
						? failureSignaturePriority.sourceArtifacts
						: phase === "attack-graph" || phase === "runtime-adapter"
							? targetRuntimeCommandSet.has(command)
								? sourceArtifacts
								: Array.from(new Set(graphGapItems.flatMap((item) => item.sourceArtifacts))).slice(0, 16)
							: sourceArtifacts,
			};
		});
	}

	function proofLoopNextActions(proof: ProofLoopArtifact): string[] {
		const ready = proof.steps.filter((step) => step.status === "ready");
		const target = proof.target ?? "<target>";
		const failureSignatureCommands = failureSignaturePriorityReport(proof.target).commands;
		const swarmRetryCommands = missionRequiresParallel(readCurrentMission())
			? latestSwarmRetryQueue(proof.target).commands
			: [];
		const autonomousBudgetActions =
			proof.autonomousBudget?.nextActions ?? autonomousExecutionBudget(proof.target).nextActions;
		const quickPath = proof.quickPath?.length ? proof.quickPath : proofLoopQuickPath(proof.target);
		const needsSpecialistBridge =
			missionRequiresParallel(readCurrentMission()) &&
			(proof.verdict === "partial" || proof.verdict === "needs_repair" || proof.specialistQueue.length > 0);
		const specialistBridge = needsSpecialistBridge
			? [
					`re_delegate plan ${target}`,
					`re_swarm run ${target} 2 1`,
					"re_swarm merge",
					`re_supervisor repair ${target}`,
				]
			: [];
		const base =
			proof.mode === "run"
				? [
						...specialistBridge,
						...(proof.verdict === "needs_repair" ? ["re_autofix apply", `re_replayer run ${target} 1`] : []),
						...(proof.verdict === "ready" ? ["re_complete audit"] : []),
						...(proof.verdict === "partial" ? [`re_proof_loop run ${target} 4 ${proof.replaySteps}`] : []),
					]
				: [...specialistBridge, `re_proof_loop run ${target} 4 ${proof.replaySteps}`];
		return Array.from(
			new Set([
				...failureSignatureCommands,
				...(proof.operatorFeedbackQueue ?? []),
				...quickPath,
				...autonomousBudgetActions,
				...swarmRetryCommands,
				...ready.slice(proof.executed.length, proof.executed.length + 6).map((step) => step.command),
				...base,
			]),
		).slice(0, 16);
	}

	function refreshProofLoop(proof: ProofLoopArtifact): ProofLoopArtifact {
		const retainedSteps = proof.steps.filter((step) => step.phase !== "claim");
		const computedVerdict = proofLoopVerdict(proof.target);
		const claims = buildEvidenceClaimSummary({ missionId: proof.missionId, readText });
		const verdict =
			computedVerdict === "ready" &&
			(proof.steps.some((step) => step.phase === "completion" && step.status === "blocked") ||
				claims.open.length > 0)
				? "partial"
				: computedVerdict;
		const operatorFeedback = latestOperatorFeedback(proof.target);
		const operatorFeedbackQueue = operatorFeedbackProofLoopCommands(operatorFeedback, proof.target);
		const existingCommands = new Set(retainedSteps.map((step) => step.command));
		const claimSteps: ProofLoopStep[] = claims.open.slice(0, 8).map((claim, index) => {
			const command =
				claim.verdict === "proposed" ? (claim.command ?? claim.verify) : (claim.verify ?? claim.command);
			return {
				id: `proof:${retainedSteps.length + index + 1}:claim`,
				phase: "claim",
				command: command ?? `re_evidence search ${claim.claimId}`,
				status: command ? "ready" : "blocked",
				reason: command
					? `claim=${claim.claimId} verdict=${claim.verdict}`
					: `claim=${claim.claimId} missing distinguishing command/verify probe`,
				sourceArtifacts: [evidenceLedgerPath()],
			};
		});
		const failureSignature = failureSignaturePriorityReport(proof.target);
		const graphGapItems = proofLoopGapItems(proof.target).filter((item) => item.source === "attack_graph");
		const graphGapCommands = proofLoopQuickPathFromItems(graphGapItems, proof.target).filter((command) =>
			/^(?:re_graph build|re_runtime_adapter )/i.test(command),
		);
		const targetRuntimeCommands = proofLoopTargetRuntimeAdapterCommands(proof.target);
		const targetRuntimeSteps: ProofLoopStep[] = targetRuntimeCommands
			.filter((command) => !existingCommands.has(command))
			.slice(0, 4)
			.map((command, index) => ({
				id: `proof:${retainedSteps.length + claimSteps.length + index + 1}:runtime-adapter`,
				phase: "runtime-adapter",
				command,
				status: /<target>/i.test(command) && !proof.target ? "blocked" : "ready",
				reason:
					/<target>/i.test(command) && !proof.target
						? "target placeholder is unresolved"
						: "source=target_auto_detection",
				sourceArtifacts: proofLoopSourceArtifacts(proof.target),
			}));
		const graphGapSteps: ProofLoopStep[] = graphGapCommands
			.filter((command) => !existingCommands.has(command))
			.slice(0, 4)
			.map((command, index) => ({
				id: `proof:${retainedSteps.length + claimSteps.length + targetRuntimeSteps.length + index + 1}:attack-graph`,
				phase: /^re_runtime_adapter /i.test(command) ? ("runtime-adapter" as const) : ("attack-graph" as const),
				command,
				status: /<target>/i.test(command) && !proof.target ? "blocked" : "ready",
				reason:
					/<target>/i.test(command) && !proof.target
						? "target placeholder is unresolved"
						: "source=attack_graph_gap",
				sourceArtifacts: Array.from(new Set(graphGapItems.flatMap((item) => item.sourceArtifacts))).slice(0, 16),
			}));
		const failureSignatureSteps: ProofLoopStep[] = failureSignature.commands
			.filter((command) => !existingCommands.has(command))
			.slice(0, 4)
			.map((command, index) => ({
				id: `proof:${retainedSteps.length + claimSteps.length + targetRuntimeSteps.length + graphGapSteps.length + index + 1}:failure-signature`,
				phase: "failure-signature",
				command,
				status: /<target>/i.test(command) && !proof.target ? "blocked" : "ready",
				reason:
					/<target>/i.test(command) && !proof.target
						? "target placeholder is unresolved"
						: "source=failure_signature_priority",
				sourceArtifacts: failureSignature.sourceArtifacts,
			}));
		const operatorFeedbackSteps: ProofLoopStep[] = operatorFeedbackQueue
			.filter((command) => !existingCommands.has(command))
			.slice(0, 4)
			.map((command, index) => ({
				id: `proof:${retainedSteps.length + claimSteps.length + targetRuntimeSteps.length + graphGapSteps.length + failureSignatureSteps.length + index + 1}:operator-feedback`,
				phase: "operator-feedback",
				command,
				status: /<target>/i.test(command) && !proof.target ? "blocked" : "ready",
				reason: /<target>/i.test(command) && !proof.target ? "target placeholder is unresolved" : undefined,
				sourceArtifacts: operatorFeedback.sourceArtifacts,
			}));
		const steps = [
			...retainedSteps,
			...claimSteps.filter((step) => !existingCommands.has(step.command)),
			...targetRuntimeSteps,
			...failureSignatureSteps,
			...graphGapSteps,
			...operatorFeedbackSteps,
		];
		const gapItems = proofLoopGapItems(proof.target);
		const swarmRetry = proofLoopSwarmRetryQueue(proof.target);
		const parallelRequired = missionRequiresParallel(readCurrentMission());
		const specialistQueue = parallelRequired ? proofLoopSpecialistQueueFromItems(gapItems, proof.target) : [];
		const swarmBridge = proofLoopSwarmBridgeFromItems(gapItems, proof.target);
		const bridgeArtifacts = proofLoopBridgeArtifacts(proof.target);
		const autonomousBudget = autonomousExecutionBudget(proof.target);
		const gapClassifier = [...claims.lines, ...formatProofLoopGapClassifier(gapItems, { parallelRequired })];
		const quickPlan = proofLoopQuickPlanRows(gapItems, proof.target);
		const quickPath = Array.from(new Set([...claims.nextCommands, ...quickPlan.commands])).slice(0, 24);
		const runtimeAdapterClosure = proofLoopRuntimeAdapterClosureRows(gapItems, proof.target)
			.map(formatProofLoopRuntimeAdapterClosureRow)
			.slice(0, 12);
		return {
			...proof,
			steps,
			verdict,
			checkStatus: proofLoopCheckStatus(),
			evidenceSummary: [...claims.lines, ...proofLoopEvidenceSummary(proof.target)],
			claimPressure: claims.lines,
			gapClassifier,
			quickPath,
			quickPlanPhases: quickPlan.phases,
			quickPlanAssertions: quickPlan.assertions,
			runtimeAdapterClosure,
			autonomousBudget,
			dispatcherScoreDecay: autonomousBudget.scoreDecay,
			repeatedFailureDemotions: autonomousBudget.demotionRules,
			highScorePromotions: autonomousBudget.promotionRules,
			failureSignaturePriority: failureSignature.rows,
			failureSignatureRepairQueue: failureSignature.repairQueue,
			operatorFeedback: operatorFeedback.rows,
			operatorFeedbackQueue,
			swarmRetryQueue: swarmRetry,
			specialistQueue,
			swarmBridge,
			bridgeArtifacts,
			nextActions: proofLoopNextActions({
				...proof,
				steps,
				verdict,
				gapClassifier,
				quickPath,
				quickPlanPhases: quickPlan.phases,
				quickPlanAssertions: quickPlan.assertions,
				runtimeAdapterClosure,
				autonomousBudget,
				dispatcherScoreDecay: autonomousBudget.scoreDecay,
				repeatedFailureDemotions: autonomousBudget.demotionRules,
				highScorePromotions: autonomousBudget.promotionRules,
				failureSignaturePriority: failureSignature.rows,
				failureSignatureRepairQueue: failureSignature.repairQueue,
				operatorFeedback: operatorFeedback.rows,
				operatorFeedbackQueue,
				swarmRetryQueue: swarmRetry,
				specialistQueue,
				swarmBridge,
				bridgeArtifacts,
			}),
			sourceArtifacts: Array.from(
				new Set(
					[
						...proofLoopSourceArtifacts(proof.target),
						...failureSignature.sourceArtifacts,
						...operatorFeedback.sourceArtifacts,
						...bridgeArtifacts,
					].filter(Boolean) as string[],
				),
			).slice(0, 72),
		};
	}

	function refreshProofLoopCached(proof: ProofLoopArtifact): ProofLoopArtifact {
		return withScopedMarkdownArtifactSelectionCache(() => refreshProofLoop(proof));
	}

	function buildProofLoop(
		options: { target?: string; mode?: "plan" | "run"; maxSteps?: number; replaySteps?: number } = {},
	): ProofLoopArtifact {
		ensureReconStorage();
		const mission = readCurrentMission();
		const maxSteps = Math.max(1, Math.min(12, Math.floor(options.maxSteps ?? 4)));
		const replaySteps = Math.max(1, Math.min(10, Math.floor(options.replaySteps ?? 2)));
		return refreshProofLoopCached({
			timestamp: new Date().toISOString(),
			missionId: mission?.id,
			route: mission?.route.domain,
			target: options.target ?? artifactScopeDefaultOptions().target ?? mission?.task,
			mode: options.mode ?? "plan",
			maxSteps,
			replaySteps,
			steps: buildProofLoopSteps(options.target ?? mission?.task),
			executed: [],
			verdict: "partial",
			checkStatus: [],
			evidenceSummary: [],
			claimPressure: [],
			gapClassifier: [],
			quickPath: [],
			quickPlanPhases: [],
			quickPlanAssertions: [],
			runtimeAdapterClosure: [],
			autonomousBudget: autonomousExecutionBudget(options.target ?? mission?.task),
			dispatcherScoreDecay: [],
			repeatedFailureDemotions: [],
			highScorePromotions: [],
			failureSignaturePriority: [],
			failureSignatureRepairQueue: [],
			operatorFeedback: [],
			operatorFeedbackQueue: [],
			swarmRetryQueue: [],
			specialistQueue: [],
			swarmBridge: [],
			bridgeArtifacts: [],
			nextActions: [],
			sourceArtifacts: proofLoopSourceArtifacts(options.target),
		});
	}

	function proofLoopNextCommand(proof: ProofLoopArtifact): string {
		if (proof.mode === "run" && proof.verdict === "ready") return "re_complete audit";
		if (proof.mode === "run") return `re_proof_loop run ${proof.target ?? "<target>"} 4 ${proof.replaySteps}`;
		return `re_proof_loop run ${proof.target ?? "<target>"} ${proof.maxSteps} ${proof.replaySteps}`;
	}

	function formatProofLoopCompact(proof: ProofLoopArtifact, path?: string): string {
		const keyBlockers = Array.from(
			new Set(
				[...proof.checkStatus, ...proof.claimPressure, ...proof.gapClassifier]
					.filter((row) => /block|missing|gap|fail|contradict|pending|unresolved|repair/i.test(row))
					.map((row) => truncateMiddle(row, 320)),
			),
		).slice(0, 6);
		const keyEvidence = proof.evidenceSummary.slice(0, 4).map((row) => truncateMiddle(row, 320));
		const recentExecutions = proof.executed
			.slice(-3)
			.map(
				(item) =>
					`- ${item.stepId} [${item.status}] ${item.command} :: ${truncateMiddle(item.output.replace(/\s+/g, " "), 180)}`,
			);
		return [
			"proof_loop:",
			path ? `proof_loop_artifact: ${path}` : undefined,
			`timestamp: ${proof.timestamp}`,
			`mode: ${proof.mode}`,
			`mission_id: ${proof.missionId ?? "none"}`,
			`route: ${proof.route ?? "none"}`,
			`target: ${proof.target ?? "<none>"}`,
			`verdict: ${proof.verdict}`,
			`claim_rows: ${proof.claimPressure.length}`,
			`gap_rows: ${proof.gapClassifier.length}`,
			`executed_steps: ${proof.executed.length}`,
			"key_blockers:",
			...(keyBlockers.length ? keyBlockers.map((row) => `- ${row}`) : ["- none"]),
			"key_evidence:",
			...(keyEvidence.length ? keyEvidence.map((row) => `- ${row}`) : ["- none"]),
			...(recentExecutions.length ? ["recent_executions:", ...recentExecutions] : []),
			`next_proof_command: ${proofLoopNextCommand(proof)}`,
			...(path ? [`details: read ${path}`] : []),
		]
			.filter(Boolean)
			.join("\n");
	}

	function formatProofLoop(
		proof: ProofLoopArtifact,
		path?: string,
		options: { includeDetails?: boolean } = {},
	): string {
		if (!options.includeDetails) return formatProofLoopCompact(proof, path);
		return [
			"proof_loop:",
			path ? `proof_loop_artifact: ${path}` : undefined,
			`timestamp: ${proof.timestamp}`,
			`mode: ${proof.mode}`,
			`mission_id: ${proof.missionId ?? "none"}`,
			`route: ${proof.route ?? "none"}`,
			`target: ${proof.target ?? "<none>"}`,
			`max_steps: ${proof.maxSteps}`,
			`replay_steps: ${proof.replaySteps}`,
			`verdict: ${proof.verdict}`,
			"check_status:",
			...(proof.checkStatus.length ? proof.checkStatus.map((item) => `- ${item}`) : ["- none"]),
			"evidence_summary:",
			...(proof.evidenceSummary.length ? proof.evidenceSummary.map((item) => `- ${item}`) : ["- none"]),
			"claim_pressure:",
			...(proof.claimPressure.length ? proof.claimPressure.map((item) => `- ${item}`) : ["- none"]),
			"gap_classifier:",
			...(proof.gapClassifier.length ? proof.gapClassifier.map((item) => `- ${item}`) : ["- none"]),
			"quick_path:",
			...(proof.quickPath.length ? proof.quickPath.map((item) => `- ${item}`) : ["- none"]),
			"quick_plan_phases:",
			...(proof.quickPlanPhases.length ? proof.quickPlanPhases.map((item) => `- ${item}`) : ["- none"]),
			"quick_plan_assertions:",
			...(proof.quickPlanAssertions.length ? proof.quickPlanAssertions.map((item) => `- ${item}`) : ["- none"]),
			"runtime_adapter_closure:",
			...(proof.runtimeAdapterClosure.length ? proof.runtimeAdapterClosure.map((item) => `- ${item}`) : ["- none"]),
			"failure_signature_priority:",
			...(proof.failureSignaturePriority.length
				? proof.failureSignaturePriority.map((item) => `- ${item}`)
				: ["- none"]),
			"failure_signature_repair_queue:",
			...(proof.failureSignatureRepairQueue.length
				? proof.failureSignatureRepairQueue.map((item) => `- ${item}`)
				: ["- none"]),
			"operator_feedback:",
			...(proof.operatorFeedback.length ? proof.operatorFeedback.map((item) => `- ${item}`) : ["- none"]),
			"operator_feedback_queue:",
			...(proof.operatorFeedbackQueue.length ? proof.operatorFeedbackQueue.map((item) => `- ${item}`) : ["- none"]),
			"swarm_retry_queue:",
			...(proof.swarmRetryQueue.length ? proof.swarmRetryQueue.map((item) => `- ${item}`) : ["- none"]),
			"specialist_queue:",
			...(proof.specialistQueue.length ? proof.specialistQueue.map((item) => `- ${item}`) : ["- none"]),
			"swarm_bridge:",
			...(proof.swarmBridge.length ? proof.swarmBridge.map((item) => `- ${item}`) : ["- none"]),
			"autonomous_execution_budget:",
			...autonomousBudgetLines(proof.autonomousBudget).map((item) => `- ${item}`),
			"dispatcher_score_decay:",
			...(proof.dispatcherScoreDecay?.length ? proof.dispatcherScoreDecay.map((item) => `- ${item}`) : ["- none"]),
			"repeated_failure_demotions:",
			...(proof.repeatedFailureDemotions?.length
				? proof.repeatedFailureDemotions.map((item) => `- ${item}`)
				: ["- none"]),
			"high_score_promotions:",
			...(proof.highScorePromotions?.length ? proof.highScorePromotions.map((item) => `- ${item}`) : ["- none"]),
			"bridge_artifacts:",
			...(proof.bridgeArtifacts.length ? proof.bridgeArtifacts.map((item) => `- ${item}`) : ["- none"]),
			"steps:",
			...(proof.steps.length
				? proof.steps.map(
						(step) => `- ${step.id} [${step.status}] ${step.command}${step.reason ? ` # ${step.reason}` : ""}`,
					)
				: ["- none"]),
			`executed_steps: ${proof.executed.length}`,
			...(proof.executed.length
				? proof.executed.map(
						(item) =>
							`- ${item.stepId} [${item.status}] ${item.command} :: ${truncateMiddle(item.output.replace(/\s+/g, " "), 260)}`,
					)
				: []),
			"next_proof_actions:",
			...(proof.nextActions.length
				? proof.nextActions.map((item) => `- ${item}`)
				: ["- re_proof_loop run <target> 4 2"]),
			`next_proof_command: ${proofLoopNextCommand(proof)}`,
			"source_artifacts:",
			...(proof.sourceArtifacts.length ? proof.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
		]
			.filter(Boolean)
			.join("\n");
	}

	function writeProofLoopArtifact(proof: ProofLoopArtifact): string {
		ensureReconStorage();
		const path = join(
			evidenceProofLoopsDir(),
			`${proof.timestamp.replace(/[:.]/g, "-")}-${slug(proof.route ?? "proof-loop")}-${proof.mode}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Proof Loop Artifact",
				"",
				formatProofLoop(proof, path, { includeDetails: true }),
				"",
				"## JSON",
				"",
				"```json",
				JSON.stringify(proof, null, 2),
				"```",
				"",
			].join("\n"),
		);
		appendEvidence({
			kind: proof.mode === "run" ? "runtime" : "artifact",
			title: `proof-loop-${proof.mode} ${proof.missionId ?? "no-mission"}`,
			fact: `Proof loop ${proof.mode}: verdict=${proof.verdict}, executed=${proof.executed.length}, replay_steps=${proof.replaySteps}, gaps=${proof.gapClassifier.length}, quick_path=${proof.quickPath.length}, runtime_adapter_closure=${proof.runtimeAdapterClosure.length}, operator_feedback=${proof.operatorFeedback.length}, specialist_queue=${proof.specialistQueue.length}`,
			command: `re_proof_loop ${proof.mode}`,
			path,
			verify: `cat ${path}`,
			confidence: "verifier/compiler/replayer/autofix bounded proof loop",
		});
		const proofCheckpointStatus =
			proof.verdict === "ready" ? "done" : proof.verdict === "partial" ? "pending" : "blocked";
		updateMissionCheckpoint("proof_loop_ready", proofCheckpointStatus, path);
		appendRuntimeFailureRepairFromProofLoop(proof, path);
		return path;
	}

	async function executeProofLoopStep(
		pi: ExtensionAPI,
		step: ProofLoopStep,
		target?: string,
		replaySteps = 2,
	): Promise<OperationExecution> {
		const done = (output: string): OperationExecution => ({
			stepId: step.id,
			command: step.command,
			status: "done",
			output,
		});
		const blocked = (output: string): OperationExecution => ({
			stepId: step.id,
			command: step.command,
			status: "blocked",
			output,
		});
		if (step.status === "blocked") return blocked(step.reason ?? "proof loop step blocked");
		switch (step.phase) {
			case "operator-feedback":
			case "failure-signature":
			case "swarm-retry":
				return executeOperatorStep(
					pi,
					{
						id: step.id,
						command: step.command,
						status: "ready",
						priority: operatorStepPriority(step.command),
						sourceArtifacts: step.sourceArtifacts,
					},
					target,
				);
			case "attack-graph":
				return done(buildAttackGraphOutput("build"));
			case "runtime-adapter": {
				const match = /^re[-_]runtime[-_]adapter\s+run\s+(\S+)(?:\s+(.+))?$/i.exec(step.command.trim());
				const adapter = match?.[1];
				const adapterTarget = match?.[2]?.trim() || target;
				if (!adapter) return blocked(`runtime adapter step missing adapter id: ${step.command}`);
				return done(await runRuntimeAdapterExecution(pi, { adapter, target: adapterTarget }));
			}
			case "verifier":
				return done(buildVerifierOutput("matrix", { target }));
			case "compiler": {
				const action = /\sfinal\b/i.test(step.command) ? "final" : "draft";
				return done(buildCompilerOutput(action, { target }));
			}
			case "replayer":
				return done(
					await runReplayer(pi, {
						target,
						maxSteps: Number.parseInt(/\s(\d+)\s*$/.exec(step.command)?.[1] ?? "", 10) || replaySteps,
					}),
				);
			case "autofix": {
				const action = /\sapply\b/i.test(step.command) ? "apply" : "plan";
				const output = buildAutofixOutput(action, { target });
				return action === "apply" && /^execution_status: deferred_to_operator$/m.test(output)
					? blocked(output)
					: done(output);
			}
			case "completion": {
				const audit = runCompletionAudit();
				const output = formatCompletionAuditFromAudit(audit);
				return audit.ready ? done(output) : blocked(output);
			}
		}
		return blocked(`unsupported proof-loop phase: ${step.phase}`);
	}

	async function executeProofLoopBridgeStep(
		kind: "delegate" | "swarm" | "supervisor",
		target?: string,
		repairMode = false,
	): Promise<OperationExecution> {
		const command =
			kind === "delegate"
				? `re_delegate plan${proofLoopCommandTarget(target)}`
				: kind === "swarm"
					? `re_swarm run${proofLoopCommandTarget(target)} 2 1 && re_swarm merge`
					: `re_supervisor ${repairMode ? "repair" : "review"}${proofLoopCommandTarget(target)}`;
		const output =
			kind === "delegate"
				? buildDelegateOutput("plan", { target })
				: kind === "swarm"
					? [
							buildSwarmOutput("plan", { target }),
							`proof_loop_bridge_command: re_swarm run${proofLoopCommandTarget(target)} 2 1`,
							"proof_loop_bridge_execution: deferred_to_re_swarm_run",
							buildSwarmOutput("merge", { target }),
						].join("\n\n")
					: await buildSupervisorOutput(repairMode ? "repair" : "review", { target });
		return {
			stepId: `proof:bridge:${kind}`,
			command,
			status: "done",
			output,
		};
	}

	function proofLoopPhaseForCommand(command: string): ProofLoopPhase | undefined {
		if (/^re[-_]verifier\b/i.test(command)) return "verifier";
		if (/^re[-_]compiler\b/i.test(command)) return "compiler";
		if (/^re[-_]replayer\b/i.test(command)) return "replayer";
		if (/^re[-_]autofix\b/i.test(command)) return "autofix";
		if (/^re[-_]graph\b/i.test(command)) return "attack-graph";
		if (/^re[-_]runtime[-_]adapter\b/i.test(command)) return "runtime-adapter";
		if (/^re[-_]complete\b/i.test(command)) return "completion";
		if (/^re[-_]context\s+resume\b/i.test(command)) return "compact-resume";
		if (/^re[-_](?:delegate|swarm|supervisor)\b/i.test(command)) return "operator-feedback";
		return undefined;
	}

	function markProofLoopStepForCommand(proof: ProofLoopArtifact, command: string, result: OperationExecution): void {
		const normalized = command.trim().replace(/\s+/g, " ");
		const phase = proofLoopPhaseForCommand(command);
		const step =
			proof.steps.find(
				(candidate) => candidate.status === "ready" && candidate.command.trim().replace(/\s+/g, " ") === normalized,
			) ??
			(phase
				? proof.steps.find((candidate) => candidate.status === "ready" && candidate.phase === phase)
				: undefined);
		if (!step) return;
		step.status = result.status === "blocked" ? "blocked" : "done";
		step.reason =
			result.status === "blocked"
				? result.output
				: step.reason
					? `${step.reason}; quick_path_executed`
					: "quick_path_executed";
	}

	async function executeProofLoopQuickPathCommand(
		pi: ExtensionAPI,
		proof: ProofLoopArtifact,
		command: string,
		index: number,
	): Promise<OperationExecution> {
		const phase = proofLoopPhaseForCommand(command);
		const stepId = `proof:quick:${index + 1}:${slug(command).slice(0, 32)}`;
		const result = phase
			? await executeProofLoopStep(
					pi,
					{
						id: stepId,
						phase,
						command,
						status: "ready",
						sourceArtifacts: proof.sourceArtifacts,
					},
					proof.target,
					proof.replaySteps,
				)
			: await executeOperatorStep(
					pi,
					{
						id: stepId,
						command,
						status: "ready",
						priority: 0,
						sourceArtifacts: proof.sourceArtifacts,
					},
					proof.target,
				);
		return {
			...result,
			output: [
				`quick_path_execution: index=${index + 1} phase=${phase ?? "operator"} command=${command}`,
				result.output,
			].join("\n"),
		};
	}

	async function runProofLoop(
		pi: ExtensionAPI,
		options: { target?: string; maxSteps?: number; replaySteps?: number } = {},
	): Promise<string> {
		let proof = buildProofLoop({ ...options, mode: "run" });
		let remaining = proof.maxSteps;
		let proofDirty = false;
		const executedCommands = new Set<string>();
		const normalizeExecutedCommand = (command: string) => command.trim().replace(/\s+/g, " ");
		const pruneExecutedQuickCommands = () => {
			proof.quickPath = proof.quickPath.filter(
				(command) => !executedCommands.has(normalizeExecutedCommand(command)),
			);
			proof.nextActions = proof.nextActions.filter(
				(command) => !executedCommands.has(normalizeExecutedCommand(command)),
			);
		};
		const runStep = async (step: ProofLoopStep, replaySteps = proof.replaySteps) => {
			if (remaining <= 0) return;
			const result = await executeProofLoopStep(pi, step, proof.target, replaySteps);
			proof.executed.push(result);
			executedCommands.add(normalizeExecutedCommand(result.command));
			step.status = result.status === "blocked" ? "blocked" : "done";
			step.reason = result.status === "blocked" ? result.output : step.reason;
			remaining -= 1;
			proof = refreshProofLoopCached(proof);
			proofDirty = false;
		};
		const runQuickPath = async () => {
			const quickCommands = proof.quickPath.filter((command) => !/^re[-_]proof[-_]loop\s+run\b/i.test(command));
			let touched = false;
			for (const [index, command] of quickCommands.entries()) {
				if (remaining <= 0) break;
				const normalized = normalizeExecutedCommand(command);
				if (!normalized || executedCommands.has(normalized)) continue;
				const result = await executeProofLoopQuickPathCommand(pi, proof, command, index);
				proof.executed.push(result);
				executedCommands.add(normalized);
				markProofLoopStepForCommand(proof, command, result);
				remaining -= 1;
				touched = true;
			}
			if (touched) pruneExecutedQuickCommands();
			if (touched && remaining > 0) {
				proof = refreshProofLoopCached(proof);
				proofDirty = false;
			} else if (touched) {
				proofDirty = true;
			}
		};
		const readyStep = (predicate: (step: ProofLoopStep) => boolean) =>
			proof.steps.find((step) => step.status === "ready" && predicate(step));
		const runFinalClosure = async (): Promise<boolean> => {
			if (!proofLoopVerifierReady(proof.target) || !proofLoopClaimInputsReady(proof.target)) return false;
			const finalCompilerStep = readyStep(
				(step) => step.phase === "compiler" && /^re[-_]compiler\s+final\b/i.test(step.command),
			);
			if (finalCompilerStep && remaining > 0) await runStep(finalCompilerStep, proof.replaySteps);
			const finalCompiler = proofLoopFinalCompiler(proof.target);
			if (!finalCompiler) return true;
			const finalReplay = proofLoopReplayForCompiler(proof.target, finalCompiler);
			if (finalReplay.blockers.length > 0 && remaining > 0) {
				const finalReplayStep = readyStep((step) => step.phase === "replayer" && /\s40\s*$/.test(step.command));
				if (finalReplayStep) await runStep(finalReplayStep, 40);
			}
			if (proof.verdict === "ready" && remaining > 0) {
				const completionStep = readyStep((step) => step.phase === "completion");
				if (completionStep) await runStep(completionStep, proof.replaySteps);
			}
			return true;
		};

		const existingFinal = proofLoopFinalCompiler(proof.target);
		if (existingFinal) {
			const replayState = proofLoopReplayForCompiler(proof.target, existingFinal);
			if (replayState.blockers.length > 0 && remaining > 0) {
				const finalReplayStep = readyStep((step) => step.phase === "replayer" && /\s40\s*$/.test(step.command));
				if (finalReplayStep) await runStep(finalReplayStep, 40);
			}
			if (proof.verdict === "ready" && remaining > 0) {
				const completionStep = readyStep((step) => step.phase === "completion");
				if (completionStep) await runStep(completionStep, proof.replaySteps);
			}
			const path = writeProofLoopArtifact(proof);
			return formatProofLoop(proof, path);
		}

		await runQuickPath();
		for (const matcher of [
			(step: ProofLoopStep) => step.phase === "verifier" && /^re[-_]verifier\s+matrix\b/i.test(step.command),
			(step: ProofLoopStep) => step.phase === "compiler" && /^re[-_]compiler\s+draft\b/i.test(step.command),
			(step: ProofLoopStep) => step.phase === "replayer" && /\s2\s*$/.test(step.command),
		]) {
			const step = readyStep(matcher);
			if (step) await runStep(step, proof.replaySteps);
		}
		if (await runFinalClosure()) {
			if (proofDirty) pruneExecutedQuickCommands();
			const path = writeProofLoopArtifact(proof);
			return formatProofLoop(proof, path);
		}
		if (
			(proof.verdict === "needs_repair" || proof.verdict === "partial") &&
			proof.operatorFeedbackQueue.length > 0 &&
			remaining > 0
		) {
			for (const step of proof.steps.filter(
				(item) => item.phase === "operator-feedback" && item.status === "ready",
			)) {
				if (remaining <= 0) break;
				await runStep(step, 1);
			}
		}
		if (
			missionRequiresParallel(readCurrentMission()) &&
			(proof.verdict === "needs_repair" || proof.verdict === "partial") &&
			proof.swarmRetryQueue.length > 0 &&
			remaining > 0
		) {
			for (const step of proof.steps.filter((item) => item.phase === "swarm-retry" && item.status === "ready")) {
				if (remaining <= 0) break;
				await runStep(step, 1);
			}
		}
		if (
			missionRequiresParallel(readCurrentMission()) &&
			(proof.verdict === "needs_repair" || proof.verdict === "partial") &&
			proof.specialistQueue.length > 0 &&
			remaining > 0
		) {
			for (const kind of ["delegate", "swarm", "supervisor"] as const) {
				if (remaining <= 0) break;
				const result = await executeProofLoopBridgeStep(kind, proof.target, proof.verdict === "needs_repair");
				proof.executed.push(result);
				remaining -= 1;
				proof = refreshProofLoopCached(proof);
				proofDirty = false;
			}
		}
		if (proof.verdict === "needs_repair") {
			for (const matcher of [
				(step: ProofLoopStep) => step.phase === "autofix" && /^re[-_]autofix\s+plan\b/i.test(step.command),
				(step: ProofLoopStep) => step.phase === "autofix" && /^re[-_]autofix\s+apply\b/i.test(step.command),
				(step: ProofLoopStep) => step.phase === "replayer" && /\s1\s*$/.test(step.command),
			]) {
				const step = readyStep(matcher);
				if (step) await runStep(step, /\s1\s*$/.test(step.command) ? 1 : proof.replaySteps);
			}
		}
		await runFinalClosure();
		if (proofDirty) pruneExecutedQuickCommands();
		const path = writeProofLoopArtifact(proof);
		return formatProofLoop(proof, path);
	}

	function buildProofLoopOutput(
		action: "plan" | "show" | "run" = "plan",
		options: { target?: string; maxSteps?: number; replaySteps?: number } = {},
	): string {
		if (action === "show") {
			const path = latestProofLoopArtifactPath();
			if (!path) return "proof_loop:\nstatus: missing\nnext: re_proof_loop plan <target>";
			const proof = parseJsonCodeFence<ProofLoopArtifact>(readText(path));
			return proof
				? formatProofLoop(proof, path)
				: `proof_loop:\nstatus: unreadable\nproof_loop_artifact: ${path}\nnext: read ${path}`;
		}
		const proof = buildProofLoop({ ...options, mode: "plan" });
		const path = writeProofLoopArtifact(proof);
		return formatProofLoop(proof, path);
	}

	return {
		latestProofLoopArtifactPath,
		parseAutofixArtifact,
		runProofLoop,
		buildProofLoopOutput,
	};
}

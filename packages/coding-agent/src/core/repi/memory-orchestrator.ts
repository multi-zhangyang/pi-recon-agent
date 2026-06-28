import type { ArtifactScopeFilterReportV1 } from "./artifact-scope.ts";
import type { CompactResumeStateV2 } from "./memory-compact-resume.ts";
import type { RepiMemoryScope } from "./memory-scope.ts";
import { truncateMiddle } from "./text.ts";

export type MemoryOrchestratorPhaseV6 =
	| "pre-task"
	| "pre-operator"
	| "post-tool"
	| "post-failure"
	| "post-success"
	| "pre-compact"
	| "post-compact"
	| "final"
	| "full";

export type MemoryOrchestratorStepStatusV6 = "pass" | "warn" | "blocked" | "pending";

export type MemoryOrchestratorStepV6 = {
	id: string;
	phase: MemoryOrchestratorPhaseV6;
	status: MemoryOrchestratorStepStatusV6;
	title: string;
	command: string;
	evidencePath?: string;
	reason: string;
	blocking: boolean;
};

export type MemoryOrchestratorReportV6 = {
	kind: "repi-memory-orchestrator-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryOrchestratorV6: true;
	mandatory_memory_control_loop: true;
	phase: MemoryOrchestratorPhaseV6;
	reportPath: string;
	currentScope: RepiMemoryScope;
	query: string;
	route?: string;
	target?: string;
	storeGrade: "pass" | "repairable" | "blocked";
	hashChainOk: boolean;
	retrievalReportPath: string;
	retrievalHitIds: string[];
	vectorSearchReportPath: string;
	vectorHitIds: string[];
	scopeIsolationReportPath: string;
	scopeBlockedEventIds: string[];
	scopeWarnEventIds: string[];
	artifactScopeFilterReportPath: string;
	artifactScopeBlockedArtifacts: string[];
	injectionPacketPath: string;
	injectionEventIds: string[];
	injectionCommands: string[];
	feedbackClosureReportPath: string;
	feedbackPendingEventIds: string[];
	supervisorReportPath: string;
	promotionEventIds: string[];
	demotionEventIds: string[];
	compactResumeLedgerPath: string;
	compactResumeStatus: "pass" | "missing" | "corrupt";
	compactResumeLedgerV2ReportPath: string;
	compactResumeLedgerV2Status: "pass" | "blocked";
	compactResumeLedgerV2State: CompactResumeStateV2;
	compactResumeLedgerV2InvalidTransitions: string[];
	memoryDepositionReportPath: string;
	memoryDepositionEventBusPath: string;
	memoryDepositionStatus: "pass" | "warn" | "blocked" | "empty";
	memoryDepositionRuntimeEventCount: number;
	memoryDepositionPendingWritebacks: number;
	memoryExperienceReportPath: string;
	memoryExperienceStatus: "pass" | "warn" | "blocked" | "empty";
	memoryExperienceEpisodeCount: number;
	memoryExperienceClaimCount: number;
	memoryExperienceLessonCount: number;
	memoryExperiencePromotedClaims: number;
	memoryExperienceConflictedClaims: number;
	memorySkillCapsuleReportPath: string;
	memorySkillCapsuleStatus: "pass" | "warn" | "blocked" | "empty";
	memorySkillCapsuleCount: number;
	memorySkillCapsulePromoted: number;
	memorySkillCapsuleCandidates: number;
	memoryDistillPromotionReportPath: string;
	memoryDistillPromotionStatus: "pass" | "warn" | "blocked" | "empty";
	memoryDistillPromotionCandidateCount: number;
	memoryDistillPromotionPromoted: number;
	memoryDistillPromotionRetained: number;
	memoryQualityReportPath: string;
	memoryQualityStatus: "pass" | "warn" | "blocked" | "empty";
	memoryQualityRowCount: number;
	memoryQualityPromoted: number;
	memoryQualityDemoted: number;
	memoryQualityRequiredFeedback: number;
	memoryReplayReportPath: string;
	memoryReplayStatus: "pass" | "warn" | "blocked" | "empty";
	memoryReplayScenarioCount: number;
	memoryReplayImproved: number;
	memoryReplayRegressed: number;
	memoryStrategyReportPath: string;
	memoryStrategyStatus: "pass" | "warn" | "blocked" | "empty";
	memoryStrategyCapsuleCount: number;
	memoryStrategyPromoted: number;
	memoryStrategyDemoted: number;
	memoryActiveKernelReportPath: string;
	memoryActiveKernelStatus: "pass" | "warn" | "blocked" | "empty";
	memoryActiveKernelDecisionCount: number;
	memoryActiveKernelInject: number;
	memoryActiveKernelAvoid: number;
	memoryMaturationReportPath: string;
	memoryMaturationStatus: "pass" | "warn" | "blocked" | "empty";
	memoryMaturationRowCount: number;
	memoryMaturationPromoted: number;
	memoryMaturationPending: number;
	steps: MemoryOrchestratorStepV6[];
	nextCommands: string[];
	requiredChecks: string[];
	policy: {
		MemoryOrchestratorV6: true;
		preTaskRetrieveBeforeOperator: true;
		scopeFilterBeforeMemoryInjection: true;
		postToolWritebackContract: true;
		memoryDepositionEngine: true;
		memoryExperienceEngine: true;
		memorySkillCapsuleEngine: true;
		memoryDistillPromotionEngine: true;
		memoryQualityLedger: true;
		memoryReplayEvaluator: true;
		memoryStrategyCapsules: true;
		memoryActiveKernel: true;
		memoryMaturationRuntime: true;
		failureSuccessFeedbackClosure: true;
		preCompactMemorySnapshot: true;
		postCompactResumeMemoryInjection: true;
		finalSuperviseBeforeClaim: true;
	};
};

export type MemoryOrchestratorOptions = {
	phase?: string;
	query?: string;
	route?: string;
	target?: string;
	artifactScopeFilter?: ArtifactScopeFilterReportV1;
	write?: boolean;
};

export function normalizeMemoryOrchestratorPhase(phase?: string): MemoryOrchestratorPhaseV6 {
	const normalized = String(phase ?? "full")
		.trim()
		.toLowerCase()
		.replaceAll("_", "-");
	if (
		normalized === "pre-task" ||
		normalized === "pre-operator" ||
		normalized === "post-tool" ||
		normalized === "post-failure" ||
		normalized === "post-success" ||
		normalized === "pre-compact" ||
		normalized === "post-compact" ||
		normalized === "final" ||
		normalized === "full"
	) {
		return normalized;
	}
	if (normalized === "orchestrate" || normalized === "orchestrator") return "full";
	if (normalized === "finalize" || normalized === "complete") return "final";
	return "full";
}

export function memoryOrchestratorStep(input: {
	id: string;
	phase: MemoryOrchestratorPhaseV6;
	status: MemoryOrchestratorStepStatusV6;
	title: string;
	command: string;
	evidencePath?: string;
	reason: string;
	blocking?: boolean;
}): MemoryOrchestratorStepV6 {
	return {
		id: input.id,
		phase: input.phase,
		status: input.status,
		title: input.title,
		command: input.command,
		evidencePath: input.evidencePath,
		reason: truncateMiddle(input.reason, 420),
		blocking: input.blocking ?? input.status === "blocked",
	};
}

export function memoryOrchestratorPhaseCommand(phase: MemoryOrchestratorPhaseV6, target?: string): string {
	const suffix = target?.trim() ? ` ${target.trim()}` : "";
	if (phase === "pre-task") return `re_memory orchestrate pre-task${suffix}`;
	if (phase === "pre-operator") return `re_memory orchestrate pre-operator${suffix}`;
	if (phase === "post-tool") return `re_memory orchestrate post-tool${suffix}`;
	if (phase === "post-failure") return `re_memory orchestrate post-failure${suffix}`;
	if (phase === "post-success") return `re_memory orchestrate post-success${suffix}`;
	if (phase === "pre-compact") return `re_memory orchestrate pre-compact${suffix}`;
	if (phase === "post-compact") return `re_memory orchestrate post-compact${suffix}`;
	if (phase === "final") return `re_memory orchestrate final${suffix}`;
	return `re_memory orchestrate full${suffix}`;
}

export function memoryOrchestratorNextCommands(
	report: Pick<
		MemoryOrchestratorReportV6,
		| "phase"
		| "target"
		| "injectionCommands"
		| "promotionEventIds"
		| "demotionEventIds"
		| "scopeBlockedEventIds"
		| "storeGrade"
		| "compactResumeStatus"
		| "compactResumeLedgerV2Status"
	>,
): string[] {
	const target = report.target;
	const suffix = target?.trim() ? ` ${target.trim()}` : "";
	const phase = report.phase;
	const commands = new Set<string>();
	if (report.storeGrade === "repairable") commands.add("re_memory repair-index");
	if (report.storeGrade === "blocked") commands.add("re_memory verify");
	if (report.scopeBlockedEventIds.length) commands.add(`re_memory scope${suffix}`);
	if (phase === "pre-task" || phase === "full") {
		commands.add(`re_memory search-events${suffix}`);
		commands.add(`re_memory quality${suffix}`);
		commands.add(`re_memory sediment${suffix}`);
		commands.add(`re_memory experience${suffix}`);
		commands.add(`re_memory skills${suffix}`);
		commands.add(`re_memory distill-promote${suffix}`);
		commands.add(`re_memory replay${suffix}`);
		commands.add(`re_memory strategy${suffix}`);
		commands.add(`re_memory active${suffix}`);
		commands.add(memoryOrchestratorPhaseCommand("pre-operator", target));
	}
	if (phase === "pre-operator" || phase === "full") {
		for (const command of report.injectionCommands.slice(0, 4)) commands.add(command);
		commands.add(`re_operator plan${suffix}`);
		commands.add(memoryOrchestratorPhaseCommand("post-tool", target));
	}
	if (phase === "post-tool" || phase === "full") {
		commands.add(
			're_memory deposit outcome=partial artifactPath=<artifact> "tool result + evidence hash + next reuse rule"',
		);
		commands.add(memoryOrchestratorPhaseCommand("post-success", target));
		commands.add(memoryOrchestratorPhaseCommand("post-failure", target));
	}
	if (phase === "post-failure" || phase === "full") {
		commands.add('re_memory append outcome=failure confidence=0.7 "failure signature + stderr + repair queue"');
		commands.add("re_memory quality");
		commands.add("re_autofix plan");
	}
	if (phase === "post-success" || phase === "full") {
		commands.add(
			're_memory append outcome=success replayVerified=true playbookCandidate=true "verified replay/proof evidence"',
		);
		commands.add("re_memory quality");
		if (report.promotionEventIds.length) commands.add("re_memory playbooks");
	}
	if (phase === "pre-compact" || phase === "full") {
		commands.add("re_memory snapshot");
		commands.add("re_context pack");
	}
	if (phase === "post-compact" || phase === "full") {
		if (report.compactResumeStatus !== "pass" || report.compactResumeLedgerV2Status !== "pass")
			commands.add("re_context resume");
		commands.add("re_memory compact-resume");
		commands.add(memoryOrchestratorPhaseCommand("pre-operator", target));
	}
	if (phase === "final" || phase === "full") {
		commands.add("re_memory experience");
		commands.add("re_memory skills");
		commands.add("re_memory distill-promote");
		commands.add("re_memory quality");
		commands.add("re_memory replay");
		commands.add("re_memory strategy");
		commands.add("re_memory active");
		commands.add("re_memory mature");
		commands.add("re_memory supervise");
		commands.add("re_memory feedback");
		if (report.demotionEventIds.length) commands.add("re_memory prune-playbooks");
		commands.add("re_complete audit");
	}
	return Array.from(commands).slice(0, 18);
}

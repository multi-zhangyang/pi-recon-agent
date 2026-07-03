#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const root = resolve(args[0] && !args[0].startsWith("--") ? args.shift() : process.cwd());
const json = args.includes("--json");

function read(rel) {
	return readFileSync(join(root, rel), "utf8");
}

function check(id, pass, evidence, fix) {
	return { id, status: pass ? "pass" : "fail", evidence, fix };
}

function includesAll(text, values) {
	return values.every((value) => text.includes(value));
}

function patternHits(rel, patterns, allow = () => false) {
	const text = read(rel);
	const hits = [];
	for (const [index, line] of text.split(/\r?\n/).entries()) {
		for (const pattern of patterns) {
			if (!pattern.re.test(line)) continue;
			if (allow({ rel, line, lineNumber: index + 1, id: pattern.id })) continue;
			hits.push({ rel, lineNumber: index + 1, id: pattern.id, line: line.trim().slice(0, 220) });
		}
	}
	return hits;
}

function firstMissing(text, values) {
	return values.filter((value) => !text.includes(value));
}

const requiredFiles = [
	"repi",
	"README.md",
	"AGENTS.md",
	"docs/reverse-agent/mainline-overhaul.md",
	"packages/coding-agent/src/core/recon-profile.ts",
	"packages/coding-agent/src/core/repi/artifact-scope.ts",
	"packages/coding-agent/src/core/repi/case-memory.ts",
	"packages/coding-agent/src/core/repi/evidence.ts",
	"packages/coding-agent/src/core/repi/graph.ts",
	"packages/coding-agent/src/core/repi/goal.ts",
	"packages/coding-agent/src/core/repi/jsonl.ts",
	"packages/coding-agent/src/core/repi/knowledge-scope.ts",
	"packages/coding-agent/src/core/repi/memory-active.ts",
	"packages/coding-agent/src/core/repi/memory-compact-resume.ts",
	"packages/coding-agent/src/core/repi/memory-deposition.ts",
	"packages/coding-agent/src/core/repi/memory-distillation.ts",
	"packages/coding-agent/src/core/repi/memory-distill.ts",
	"packages/coding-agent/src/core/repi/memory-event.ts",
	"packages/coding-agent/src/core/repi/memory-feedback.ts",
	"packages/coding-agent/src/core/repi/memory-experience.ts",
	"packages/coding-agent/src/core/repi/memory-maturation.ts",
	"packages/coding-agent/src/core/repi/memory-orchestrator.ts",
	"packages/coding-agent/src/core/repi/memory-quality.ts",
	"packages/coding-agent/src/core/repi/memory-replay.ts",
	"packages/coding-agent/src/core/repi/memory-search.ts",
	"packages/coding-agent/src/core/repi/memory-skill.ts",
	"packages/coding-agent/src/core/repi/memory-strategy.ts",
	"packages/coding-agent/src/core/repi/memory-supervisor.ts",
	"packages/coding-agent/src/core/repi/memory-usefulness.ts",
	"packages/coding-agent/src/core/repi/memory-ux.ts",
	"packages/coding-agent/src/core/repi/memory-vector.ts",
	"packages/coding-agent/src/core/repi/profile.ts",
	"packages/coding-agent/src/core/repi/routes.ts",
	"packages/coding-agent/src/core/repi/mission.ts",
	"packages/coding-agent/src/core/repi/memory-scope.ts",
	"packages/coding-agent/src/core/repi/memory-store.ts",
	"packages/coding-agent/src/core/repi/memory-runtime.ts",
	"packages/coding-agent/src/core/repi/storage.ts",
	"packages/coding-agent/src/core/repi/target.ts",
	"packages/coding-agent/src/core/repi/text.ts",
	"packages/coding-agent/src/core/repi/toolchain.ts",
	"scripts/reverse-agent/repi-smoke.mjs",
	"scripts/reverse-agent/repi-release-tarball-smoke.mjs",
	"scripts/reverse-agent/memory-inspect.mjs",
];

const rows = [];
const missingFiles = requiredFiles.filter((rel) => !existsSync(join(root, rel)));
rows.push(
	check(
		"files:repi-mainline-modules",
		missingFiles.length === 0,
		missingFiles.length ? `missing=${missingFiles.join(", ")}` : `files=${requiredFiles.length}`,
		"Restore the REPI module split and product scripts before adding new features.",
	),
);

const packageJson = JSON.parse(read("package.json"));
rows.push(
	check(
		"product:package-identity",
		packageJson.name === "repi-monorepo" &&
			/REPI reverse\/pentest/i.test(packageJson.description ?? "") &&
			(packageJson.keywords ?? []).includes("reverse-pentest") &&
			(packageJson.keywords ?? []).includes("web-pentest"),
		`name=${packageJson.name} description=${packageJson.description}`,
		"Keep package metadata centered on REPI reverse/pentest, not generic security or upstream Pi.",
	),
);

rows.push(
	check(
		"validation:release-tarball-smoke-script",
		packageJson.scripts?.["smoke:release"] === "node scripts/reverse-agent/repi-release-tarball-smoke.mjs" &&
			existsSync(join(root, "scripts/reverse-agent/repi-release-tarball-smoke.mjs")),
		`smoke:release=${packageJson.scripts?.["smoke:release"] ?? "<missing>"}`,
		"Keep a release tarball smoke that installs packed npm artifacts and validates repi + /goal + REPI_* env.",
	),
);

const launcher = read("repi");
rows.push(
	check(
		"launcher:independent-repi-entrypoint",
		includesAll(launcher, [
			"REPI_PRODUCT=1",
			"REPI_PRIMARY=1",
			"REPI_CODING_AGENT_DIR",
			"REPI does not manage upstream pi",
			"Active reverse/pentest execution entry",
		]) &&
			!/\bPI_CODING_AGENT_APP_NAME\b/.test(launcher) &&
			!/\bPI_CODING_AGENT_CONFIG_DIR\b/.test(launcher),
		"entrypoint=repi env=REPI_*",
		"Keep the launcher as the independent REPI product entrypoint. Do not reintroduce Pi app/config identity exports.",
	),
);

const profile = read("packages/coding-agent/src/core/repi/profile.ts");
rows.push(
	check(
		"profile:source-and-tool-surface",
		includesAll(profile, [
			'REPI_SOURCE = "builtin:repi"',
			'REPI_PROMPT_BASE = "<builtin:repi/prompts>"',
			"REPI_TOOL_INDEX_CANDIDATES",
			"REPI_TOOL_NAMES",
			"REPI_COMMAND_NAMES",
		]),
		"source=builtin:repi tool/command names externalized",
		"Add REPI profile constants in core/repi/profile.ts instead of growing recon-profile.ts.",
	),
);

const routes = read("packages/coding-agent/src/core/repi/routes.ts");
rows.push(
	check(
		"routes:reverse-pentest-domains",
		includesAll(routes, [
			"Native reverse",
			"Web / API pentest",
			"Web pentest scanning",
			"Agent / LLM boundary",
			"Reverse/Pentest general",
			"routeRepiTask",
			"isRepiTask",
		]),
		"domains=reverse/pentest routeRepiTask=yes",
		"Route new work through core/repi/routes.ts and keep labels reverse/pentest-specific.",
	),
);

const mission = read("packages/coding-agent/src/core/repi/mission.ts");
rows.push(
	check(
		"mission:lane-contract",
		includesAll(mission, [
			"missionLanesForRoute",
			"initializeMissionLanes",
			"defaultMissionCheckpoints",
			"createMission",
			"normalizeMission",
			"tool_index_checked",
			"minimal_path_proven",
		]),
		"mission factory and checkpoints externalized",
		"Put new lane/checkpoint defaults in core/repi/mission.ts, not inside the profile monolith.",
	),
);

const memoryRuntime = read("packages/coding-agent/src/core/repi/memory-runtime.ts");
rows.push(
	check(
		"memory:runtime-settings-contract",
		includesAll(memoryRuntime, [
			"RepiMemoryRuntimeSettings",
			"repiMemorySettings",
			"normalizeMemoryMode",
			"normalizeMemoryContextMode",
			"normalizeMemoryAutoDepositMode",
			"normalizeMemoryScopePolicy",
			"normalizeMemoryStartupDigest",
			"autoRecall",
			"autoInject",
			"rawAutoInject",
			"includeGlobalMemoryInContextPack",
		]),
		"memory runtime settings externalized",
		"Put REPI memory modes, scoped recall, and injection defaults in core/repi/memory-runtime.ts.",
	),
);

const memoryDeposition = read("packages/coding-agent/src/core/repi/memory-deposition.ts");
rows.push(
	check(
		"memory:deposition-engine-contract",
		includesAll(memoryDeposition, [
			"MemoryDepositionStageV7",
			"MemoryDepositionStatusV7",
			"MemoryDepositionRuntimeEventV7",
			"MemoryDepositionReportV7",
			"MemoryDepositionRuntimeInputV7",
			"isMemoryDepositionRuntimeEvent",
			"memoryDepositionEventHash",
			"memoryDepositionHashChainOk",
			"repi-memory-deposition-runtime-event",
			"MemoryDepositionEngineV7",
			"runtime_step_event_bus",
			"post_tool_writeback_autocapture",
			"appendOnlyDepositionLedger",
			"memoryEventHashBinding",
		]),
		"memory deposition event/report schemas, runtime input, validation, and hash-chain checks externalized",
		"Put REPI deposition event bus schemas and hash-chain validation in core/repi/memory-deposition.ts.",
	),
);

const memoryDistillation = read("packages/coding-agent/src/core/repi/memory-distillation.ts");
rows.push(
	check(
		"memory:distillation-pattern-contract",
		includesAll(memoryDistillation, [
			"MemoryDistilledPatternV1",
			"MemoryContaminationFindingV1",
			"MemoryDistillationReportV1",
			"MemorySedimentationAction",
			"MemorySemanticIndexEntryV1",
			"MemoryContradictionLedgerEntryV1",
			"MemoryInjectionPacketV1",
			"MemorySedimentationReportV1",
			"memoryPatternHash",
			"memoryPatternFrom",
			"repi-memory-distilled-pattern",
			"repi-memory-semantic-index-entry",
			"mandatory_memory_injection_packet",
			"MemorySedimentationV1",
			"promotionRequiresArtifactSha256",
			"quarantineBlocksInjection",
		]),
		"memory distillation pattern, sedimentation, injection packet schemas and pattern constructor externalized",
		"Put REPI distillation/sedimentation schemas and pattern construction in core/repi/memory-distillation.ts.",
	),
);

const memoryDistill = read("packages/coding-agent/src/core/repi/memory-distill.ts");
rows.push(
	check(
		"memory:distill-promotion-contract",
		includesAll(memoryDistill, [
			"MemoryDistillProviderBackendV10",
			"MemoryDistillPromotionDecisionV10",
			"MemoryDistillPromotionSourceV10",
			"MemoryDistillProviderV10",
			"MemoryDistillCandidateV10",
			"MemoryDistillPromotionReportV10",
			"memoryDistillProviderConfigV10",
			"memoryDistillCandidateHash",
			"memoryDistillCandidateFrom",
			"memoryDistillSnippetFromArtifacts",
			"memoryDistillDecision",
			"repi-memory-distill-provider",
			"MemoryDistillPromotionV10",
			"provider_distill_contract",
			"artifact_to_claim_distillation",
			"remote_distill_requires_explicit_allow",
			"local_distill_fallback",
		]),
		"memory distill provider, candidate/report schemas, artifact snippets, and promotion decision externalized",
		"Put REPI distill provider gates, candidate construction, and promotion decisions in core/repi/memory-distill.ts.",
	),
);

const memoryFeedback = read("packages/coding-agent/src/core/repi/memory-feedback.ts");
rows.push(
	check(
		"memory:feedback-closure-contract",
		includesAll(memoryFeedback, [
			"MemoryFeedbackClosureStatus",
			"MemoryFeedbackClosureRowV1",
			"MemoryFeedbackClosureReportV1",
			"memoryFeedbackSourceEventIds",
			"memoryFeedbackPolarity",
			"formatMemoryFeedbackClosure",
			"repi-memory-feedback-closure-row",
			"repi-memory-feedback-closure-report",
			"MemoryFeedbackClosureV1",
			"feedbackCoverage",
			"pendingFeedbackEventIds",
			"orphanFeedbackEventIds",
			"memory_reuse_feedback_promote",
			"memory_reuse_feedback_demote",
		]),
		"memory feedback closure schemas, source linking, polarity detection, and formatter externalized",
		"Put REPI feedback closure schemas, source/polarity helpers, and formatter in core/repi/memory-feedback.ts.",
	),
);

const memoryActive = read("packages/coding-agent/src/core/repi/memory-active.ts");
rows.push(
	check(
		"memory:active-kernel-contract",
		includesAll(memoryActive, [
			"MemoryActiveKernelActionV14",
			"MemoryActiveKernelSourceV14",
			"MemoryActiveKernelDecisionV14",
			"MemoryActiveInjectionPackV14",
			"MemoryActiveKernelReportV14",
			"MemoryActiveKernelActionInputV14",
			"memoryActiveKernelDecisionHash",
			"memoryActiveKernelDecisionFrom",
			"memoryActiveKernelActionFromScore",
			"formatMemoryActiveKernel",
			"repi-memory-active-kernel-decision",
			"repi-memory-active-injection-pack",
			"MemoryActiveKernelV14",
			"unified_memory_decision_engine",
			"active_recall_scheduler",
			"scope_safe_strategy_injection",
			"feedback_driven_promotion",
		]),
		"memory active kernel schema, decision constructor, action scoring, and formatter externalized",
		"Put REPI active memory decision/injection schemas, action scoring, and formatter in core/repi/memory-active.ts.",
	),
);

const memoryMaturation = read("packages/coding-agent/src/core/repi/memory-maturation.ts");
rows.push(
	check(
		"memory:maturation-runtime-contract",
		includesAll(memoryMaturation, [
			"MemoryMaturationActionV15",
			"MemoryMaturationRetentionActionV15",
			"MemoryMaturationRowV15",
			"MemoryMaturationRuntimeReportV15",
			"MemoryMaturationRetentionSignalV15",
			"memoryMaturationRowHash",
			"memoryMaturationActionFromDecision",
			"memoryMaturationRowFrom",
			"memoryMaturationDaysSince",
			"memoryMaturationRetentionSignal",
			"formatMemoryMaturationRuntime",
			"repi-memory-maturation-row",
			"MemoryMaturationRuntimeV15",
			"automatic_memory_maturation_pipeline",
			"retention_decay_scheduler",
			"stale_memory_rehearsal_queue",
			"usefulness_backprop_to_maturation",
		]),
		"memory maturation schema, row constructor, action decision, retention/decay signal, and formatter externalized",
		"Put REPI maturation runtime schema, retention/decay decisions, and formatter in core/repi/memory-maturation.ts.",
	),
);

const memoryOrchestrator = read("packages/coding-agent/src/core/repi/memory-orchestrator.ts");
rows.push(
	check(
		"memory:orchestrator-control-loop-contract",
		includesAll(memoryOrchestrator, [
			"MemoryOrchestratorPhaseV6",
			"MemoryOrchestratorStepStatusV6",
			"MemoryOrchestratorStepV6",
			"MemoryOrchestratorReportV6",
			"MemoryOrchestratorOptions",
			"normalizeMemoryOrchestratorPhase",
			"memoryOrchestratorStep",
			"memoryOrchestratorPhaseCommand",
			"memoryOrchestratorNextCommands",
			"repi-memory-orchestrator-report",
			"MemoryOrchestratorV6",
			"mandatory_memory_control_loop",
			"preTaskRetrieveBeforeOperator",
			"scopeFilterBeforeMemoryInjection",
			"postToolWritebackContract",
			"finalSuperviseBeforeClaim",
		]),
		"memory orchestrator schema, phase normalization, step constructor, and next-command planning externalized",
		"Put REPI memory orchestrator control-loop schema and command planning in core/repi/memory-orchestrator.ts.",
	),
);

const memoryCompactResume = read("packages/coding-agent/src/core/repi/memory-compact-resume.ts");
rows.push(
	check(
		"memory:compact-resume-ledger-contract",
		includesAll(memoryCompactResume, [
			"CompactResumeStateV2",
			"CompactResumeLedgerTransitionV2",
			"CompactResumeLedgerV2Report",
			"CompactResumeTransitionLedgerReadV2",
			"COMPACT_RESUME_ALLOWED_TRANSITIONS",
			"compactResumeStateForKey",
			"compactResumeAttemptForKey",
			"compactResumeTransitionEntryHash",
			"compactResumeTransitionAllowed",
			"compactResumeTransitionsFromText",
			"compactResumeLedgerV2ReportFromText",
			"formatCompactResumeLedgerV2",
			"repi-compact-resume-ledger-transition",
			"repi-compact-resume-ledger-v2-report",
			"CompactResumeLedgerV2",
			"append_only_transition_ledger",
			"idempotent_multi_compact_replay",
			"auto_resume_budget_enforced",
		]),
		"compact resume ledger schema, JSONL parser, report builder, transition table, idempotent replay counters, and formatter externalized",
		"Put REPI compact resume ledger schema, parser, report builder, state-machine helpers, and formatter in core/repi/memory-compact-resume.ts.",
	),
);

const memoryUsefulness = read("packages/coding-agent/src/core/repi/memory-usefulness.ts");
rows.push(
	check(
		"memory:usefulness-eval-contract",
		includesAll(memoryUsefulness, [
			"MemoryUsefulnessEvalScenarioV1",
			"MemoryUsefulnessEvalScenarioResultV1",
			"MemoryUsefulnessEvalReportV1",
			"memoryUsefulnessQueryForEvent",
			"defaultMemoryUsefulnessScenarios",
			"repi-memory-usefulness-eval",
			"MemoryUsefulnessEvalV1",
			"forbiddenLeakRate",
			"expectedEventIds",
			"forbiddenEventIds",
		]),
		"memory usefulness eval schemas and default scenario/query generation externalized",
		"Put REPI memory usefulness evaluation schemas and default scenario generation in core/repi/memory-usefulness.ts.",
	),
);

const memoryUx = read("packages/coding-agent/src/core/repi/memory-ux.ts");
rows.push(
	check(
		"memory:ux-dashboard-contract",
		includesAll(memoryUx, [
			"MemoryUxGovernanceActionV16",
			"MemoryUxWhyRowV16",
			"MemoryUxGovernanceDecisionV16",
			"MemoryUxDashboardV16",
			"memoryUxGovernanceCommandsForEvent",
			"memoryUxWhyRow",
			"formatMemoryStatusBoard",
			"formatMemoryUxDashboard",
			"formatMemoryUxGovernanceDecision",
			"repi-memory-ux-dashboard",
			"repi-memory-ux-governance-decision",
			"user_visible_memory_status",
			"recall_explainability",
			"append_only_memory_governance",
			"lifecycle_governance_commands",
			"re_memory promote",
			"re_memory demote",
			"re_memory forget",
		]),
		"memory UX dashboard/governance schemas, why-row helpers, and formatters externalized",
		"Put REPI user-visible memory dashboard, governance helper schemas, and formatters in core/repi/memory-ux.ts.",
	),
);

const memoryExperience = read("packages/coding-agent/src/core/repi/memory-experience.ts");
rows.push(
	check(
		"memory:experience-engine-contract",
		includesAll(memoryExperience, [
			"MemoryExperienceClaimTypeV8",
			"MemoryExperienceEpisodeV8",
			"MemoryExperienceClaimV8",
			"MemoryExperienceLessonV8",
			"MemoryExperiencePromotionRowV8",
			"MemoryExperienceReportV8",
			"memoryExperienceTargetScope",
			"memoryExperienceIntent",
			"memoryExperienceClaimBaseStatus",
			"isMemoryExperienceClaimRowV8",
			"repi-memory-experience-claim",
			"MemoryExperienceEngineV8",
			"episode_model_v8",
			"structured_claim_extraction",
			"lesson_promotion_check",
		]),
		"memory experience episode, claim, lesson, promotion schemas and extraction helpers externalized",
		"Put REPI memory experience schemas, hashes, claim status, and validation in core/repi/memory-experience.ts.",
	),
);

const memoryScope = read("packages/coding-agent/src/core/repi/memory-scope.ts");
rows.push(
	check(
		"memory:scope-isolation-contract",
		includesAll(memoryScope, [
			"RepiMemoryScope",
			"MemoryScopeIsolationEvent",
			"MemoryScopeIsolationRowV1",
			"MemoryScopeIsolationReportV1",
			"memoryTargetScope",
			"memoryRouteMatches",
			"contextSessionId",
			"contextBranchId",
			"buildCurrentMemoryScope",
			"memoryScopeIsolationRow",
			"buildMemoryScopeIsolationReport",
			"formatMemoryScopeIsolation",
			"scope_filter_by_mission_session_workspace_target",
			"cross_workspace_contamination_blocks_injection",
			"cross_target_contamination_blocks_injection",
			"legacy_memory_scope_requires_manual_review",
		]),
		"memory scope identity, target/route matching, isolation rows, report builder, and formatter externalized",
		"Put REPI memory scope identity, target/route normalization, isolation decisions, and report formatting in core/repi/memory-scope.ts.",
	),
);

const memoryEvent = read("packages/coding-agent/src/core/repi/memory-event.ts");
rows.push(
	check(
		"memory:event-contract",
		includesAll(memoryEvent, [
			"MemoryEventSource",
			"MemoryOutcome",
			"MemoryArtifactHash",
			"MemoryQuality",
			"MemoryEventV1",
			"MemoryEventInput",
			"isMemoryArtifactHash",
			"isMemoryQuality",
			"isMemoryEvent",
			"memoryArtifactTier",
			"memoryArtifactHashes",
			"memoryEventHash",
			"memoryEventHashChainOk",
			"memoryEventSignature",
			"repi-memory-event",
			"runtime_artifact",
			"persisted_memory",
		]),
		"memory event schema, type guards, artifact hashes, signatures, and hash-chain helpers externalized",
		"Put REPI memory event schema, validation, artifact hashing, event signatures, and hash-chain helpers in core/repi/memory-event.ts.",
	),
);

const memoryQuality = read("packages/coding-agent/src/core/repi/memory-quality.ts");
rows.push(
	check(
		"memory:quality-ledger-contract",
		includesAll(memoryQuality, [
			"MemoryQualityLifecycleDecisionV11",
			"MemoryQualitySignalV11",
			"MemoryQualityLedgerRowV11",
			"MemoryQualityLedgerReportV11",
			"MemoryQualityUsefulnessReportSource",
			"memoryQualityLedgerRowHash",
			"isMemoryQualityLedgerRow",
			"latestMemoryQualityRowsByEvent",
			"memoryQualityUsefulnessSignals",
			"memoryQualityDecision",
			"formatMemoryQualityLedger",
			"repi-memory-quality-ledger-row",
			"MemoryQualityLedgerV11",
			"quality_score_feedback_loop",
			"forbidden_leak",
			"scope_blocked",
			"ab_replay_improved",
		]),
		"memory quality ledger schema, validator, hash, usefulness signals, lifecycle decision, and formatter externalized",
		"Put REPI memory quality schema, row validation, feedback signals, lifecycle decision logic, and formatter in core/repi/memory-quality.ts.",
	),
);

const memoryReplay = read("packages/coding-agent/src/core/repi/memory-replay.ts");
rows.push(
	check(
		"memory:replay-evaluator-contract",
		includesAll(memoryReplay, [
			"MemoryReplayVerdictV12",
			"MemoryReplayScenarioV12",
			"MemoryReplayEvaluatorRowV12",
			"MemoryReplayEvaluatorReportV12",
			"memoryReplayEvaluatorRowHash",
			"isMemoryReplayEvaluatorRow",
			"memoryReplayCausalSignals",
			"formatMemoryReplayEvaluator",
			"repi-memory-replay-evaluator-row",
			"MemoryReplayEvaluatorV12",
			"memory_ab_replay",
			"causal_attribution_signal",
			"replay_delta_feedback_writeback",
			"attributionEventIds",
			"regressionEventIds",
		]),
		"memory replay evaluator schema, validator, row hash, causal signal aggregation, and formatter externalized",
		"Put REPI memory replay evaluator schema, validation, causal signal rollup, and formatter in core/repi/memory-replay.ts.",
	),
);

const memoryStrategy = read("packages/coding-agent/src/core/repi/memory-strategy.ts");
rows.push(
	check(
		"memory:strategy-capsule-contract",
		includesAll(memoryStrategy, [
			"MemoryStrategyCapsuleLifecycleV13",
			"MemoryStrategyCapsuleV13",
			"MemoryStrategyCapsuleReportV13",
			"memoryStrategyCapsuleHash",
			"memoryStrategyCapsuleFrom",
			"memoryStrategyLifecycleForReplay",
			"formatMemoryStrategyCapsules",
			"repi-memory-strategy-capsule",
			"MemoryStrategyCapsuleV13",
			"executable_strategy_capsule",
			"replay_backed_strategy_promotion",
			"strategy_quality_check",
			"operatorPromptSnippet",
			"verifierPromptSnippet",
		]),
		"memory strategy capsule schema, hash, constructor, replay lifecycle decision, and formatter externalized",
		"Put REPI strategy capsule schema, replay-to-capsule lifecycle logic, and formatter in core/repi/memory-strategy.ts.",
	),
);

const memorySkill = read("packages/coding-agent/src/core/repi/memory-skill.ts");
rows.push(
	check(
		"memory:skill-capsule-contract",
		includesAll(memorySkill, [
			"MemorySkillCapsuleTypeV9",
			"MemorySkillCapsuleLifecycleV9",
			"MemorySkillCapsulePromotionCheckV9",
			"MemorySkillCapsuleV9",
			"MemorySkillCapsuleReportV9",
			"memorySkillCapsuleHash",
			"memorySkillCapsuleTypeFromLesson",
			"memorySkillCapsuleTypeFromPattern",
			"memorySkillCapsuleLifecycleFromPattern",
			"memorySkillCapsuleLifecycleFromClaim",
			"memorySkillCapsulePromotionCheck",
			"memorySkillCapsuleFrom",
			"repi-memory-skill-capsule",
			"skill_capsule_assetization",
			"verified_skill_promotion_check",
			"operator_skill_injection",
		]),
		"memory skill capsule schemas, constructors, lifecycle mapping, and promotion checks externalized",
		"Put REPI skill capsule schema and pure promotion/lifecycle decisions in core/repi/memory-skill.ts.",
	),
);

const memorySupervisor = read("packages/coding-agent/src/core/repi/memory-supervisor.ts");
rows.push(
	check(
		"memory:supervisor-lifecycle-contract",
		includesAll(memorySupervisor, [
			"MemorySupervisorAction",
			"MemorySupervisorDecisionV1",
			"MemorySupervisorReportV1",
			"memorySupervisorTtlDays",
			"memorySupervisorDecisionFromEntry",
			"memorySupervisorMergeDecision",
			"memorySupervisorQuarantineDecision",
			"formatMemorySupervisorBoard",
			"formatMemorySupervisor",
			"repi-memory-supervisor-decision",
			"repi-memory-supervisor-report",
			"MemorySupervisorV1",
			"supervisorRunsAfterSedimentation",
			"promotionRequiresArtifactSha256",
			"promotionRequiresVerifierOrReplay",
			"quarantineOverridesPromotion",
			"failureFeedbackDemotes",
			"mergeByCaseSignature",
		]),
		"memory supervisor lifecycle schemas, decision builders, formatters, and TTL policy externalized",
		"Put REPI memory supervisor lifecycle schema, decision builders, formatters, and retention policy in core/repi/memory-supervisor.ts.",
	),
);

const caseMemory = read("packages/coding-agent/src/core/repi/case-memory.ts");
rows.push(
	check(
		"memory:case-index-contract",
		includesAll(caseMemory, [
			"CaseMemoryV1",
			"isCaseMemory",
			"caseMemorySnapshotFromEvent",
			"rebuildCaseMemoryFromEvents",
			"repi-case-memory",
			"lastEventHash",
			"sourceEvents",
			"reuseCount",
			"failureCount",
		]),
		"case memory schema, validation, snapshot, and rebuild logic externalized",
		"Put REPI case memory schema and event-to-case rebuild logic in core/repi/case-memory.ts.",
	),
);

const memorySearch = read("packages/coding-agent/src/core/repi/memory-search.ts");
rows.push(
	check(
		"memory:search-semantics-contract",
		includesAll(memorySearch, [
			"MemoryRetrievalHit",
			"memoryTextForSearch",
			"memorySearchTokens",
			"memorySemanticAliases",
			"memoryHybridQueryTokens",
			"memoryVectorTokens",
			"memoryVectorQualityWeight",
			"memoryCaseTextForSearch",
			"memoryArtifactTextForSearch",
			"memoryHybridOverlapScore",
			"memoryHybridSignalScore",
			"case-memory-hybrid",
			"artifact-hybrid",
			"memory_semantic_hybrid_reuse",
			"authz",
			"pwn",
			"firmware",
		]),
		"memory retrieval text, tokens, semantic aliases, vector quality weight, and hybrid scoring externalized",
		"Put REPI memory search semantics and domain alias expansion in core/repi/memory-search.ts.",
	),
);

const memoryVector = read("packages/coding-agent/src/core/repi/memory-vector.ts");
rows.push(
	check(
		"memory:vector-retrieval-contract",
		includesAll(memoryVector, [
			"MemoryEmbeddingProviderKind",
			"MemoryEmbeddingProviderV1",
			"MemoryVectorIndexEntryV1",
			"MemoryVectorIndexV1",
			"MemoryVectorSearchHitV1",
			"MemoryVectorSearchReportV1",
			"MEMORY_VECTOR_DIMENSIONS",
			"MEMORY_VECTOR_MODEL",
			"MEMORY_EMBEDDING_PROVIDER_GATE_MARKERS",
			"memoryVectorForTokens",
			"memoryVectorForText",
			"memoryEmbeddingProviderKind",
			"memoryEmbeddingProviderConfig",
			"normalizeMemoryEmbeddingVector",
			"memoryOpenAiCompatibleEmbeddings",
			"memoryEmbeddingVectorsForTexts",
			"memoryVectorCosine",
			"memoryVectorEntryFromEvent",
			"formatMemoryVectorSearch",
			"formatMemoryEmbeddingProvider",
			"remote_embedding_requires_explicit_allow",
			"local_hash_embedding_fallback",
			"embedding_api_key_env_ref_only",
		]),
		"memory vector provider gates, local hash vectors, cosine, vector index row construction, and formatters externalized",
		"Put REPI vector retrieval provider config, local embeddings, vector index row logic, and formatters in core/repi/memory-vector.ts.",
	),
);

const memoryStore = read("packages/coding-agent/src/core/repi/memory-store.ts");
rows.push(
	check(
		"memory:store-runtime-contract",
		includesAll(memoryStore, [
			"RepiMemoryStoreOperation",
			"MemoryTransactionFileDigestV1",
			"MemoryAppendTransactionV1",
			"MemoryStoreVerificationV1",
			"MemoryStoreJsonlScan",
			"MemoryStoreVerificationBuildInput",
			"withMemoryStoreLock",
			"memoryStoreSleep",
			"textWithJsonlLine",
			"writeFileAtomic",
			"writeMemoryTransaction",
			"buildMemoryStoreVerificationReport",
			"formatMemoryStoreVerification",
			"repi-memory-append-transaction",
			"repi-memory-store-verification",
			"MemoryStoreV5",
			"repi-memory-store-lock",
			"memory_store_lock_timeout",
			"0o600",
		]),
		"memory store transaction/verification schemas, report builder, lock, private write helpers, and formatter externalized",
		"Put REPI memory store schemas, verification report building, locking, JSONL append text, atomic writes, transaction manifest writes, and verification formatting in core/repi/memory-store.ts.",
	),
);

const evidence = read("packages/coding-agent/src/core/repi/evidence.ts");
rows.push(
	check(
		"evidence:ledger-contract",
		includesAll(evidence, [
			"EvidenceKind",
			"EvidenceRecord",
			"evidencePriority",
			"formatEvidenceRecord",
			"appendEvidenceRecord",
			"buildEvidenceDigest",
			"buildStartupEvidenceDigest",
			"buildContextEvidenceTail",
			"evidenceLedgerGraphNodes",
		]),
		"evidence ledger contract externalized",
		"Put evidence ledger types, formatting, digest, and graph parsing in core/repi/evidence.ts.",
	),
);

const graph = read("packages/coding-agent/src/core/repi/graph.ts");
rows.push(
	check(
		"graph:execution-artifact-contract",
		includesAll(graph, [
			"AttackGraphArtifact",
			"AttackGraphNode",
			"ExploitChainArtifact",
			"ExploitChainNode",
			"createExploitChainNode",
			"formatAttackGraph",
			"formatAttackGraphArtifactMarkdown",
			"formatExploitChain",
			"formatExploitChainArtifactMarkdown",
		]),
		"attack graph and exploit chain schema externalized",
		"Put execution graph/chain artifact schemas and formatters in core/repi/graph.ts.",
	),
);

const knowledgeScope = read("packages/coding-agent/src/core/repi/knowledge-scope.ts");
rows.push(
	check(
		"knowledge:scope-isolation-contract",
		includesAll(knowledgeScope, [
			"KnowledgeScopeSource",
			"KnowledgeScopeIsolationSourceV1",
			"KnowledgeScopeIsolationV1",
			"KnowledgeScopeIsolationBuildOptions",
			"knowledgeScopeRowForSource",
			"buildKnowledgeScopeIsolation",
			"artifactScopeMatchForSource",
			"artifactScopeVerdictPriority",
			"knowledge_graph_scope_filter_blocks_quarantined_artifacts",
			"knowledge_graph_command_hints_exclude_scope_blocked_sources",
			"knowledge_scope_isolation_report_in_artifact",
		]),
		"knowledge graph scope isolation types and builder externalized",
		"Put knowledge graph scope isolation source rows, artifact matching, and builder logic in core/repi/knowledge-scope.ts.",
	),
);

const jsonl = read("packages/coding-agent/src/core/repi/jsonl.ts");
rows.push(
	check(
		"jsonl:ledger-read-contract",
		includesAll(jsonl, ["jsonlRecords", "jsonlScan", "json_parse_error", "invalid_"]),
		"JSONL record readers externalized",
		"Put append-only ledger JSONL parsing and scan diagnostics in core/repi/jsonl.ts.",
	),
);

const storage = read("packages/coding-agent/src/core/repi/storage.ts");
rows.push(
	check(
		"storage:artifact-and-defaults-contract",
		includesAll(storage, [
			"reconDir",
			"memoryPath",
			"RepiStorageDefaultsOptions",
			"ensureRepiStorage",
			"currentMissionPath",
			"evidenceLedgerPath",
			"builtinSkillFilePath",
			"builtinPromptFilePath",
			"toolIndexPath",
			"memoryStoreReportPath",
			"memoryStoreSnapshotPath",
			"toolCallTraceLedgerPath",
			"chmodPrivate",
			"writePrivateTextFile",
			"readTextFile",
			"appendPrivateTextFile",
			"recentMarkdownArtifacts",
			"readJsonObjectFile",
			"0o700",
			"0o600",
		]),
		"storage paths, private permissions, and default artifact initialization externalized",
		"Add new REPI artifact paths and default file initialization to core/repi/storage.ts so future features share the same filesystem contract.",
	),
);

const artifactScope = read("packages/coding-agent/src/core/repi/artifact-scope.ts");
rows.push(
	check(
		"artifact-scope:scope-filter-contract",
		includesAll(artifactScope, [
			"ArtifactScopeFilterDecisionV1",
			"ArtifactScopeFilterReportV1",
			"ArtifactScopeFilterOptions",
			"ArtifactScopeArtifact",
			"ArtifactScopeEvent",
			"ArtifactScopeMemoryReport",
			"ArtifactScopeReportBuildOptions",
			"ScopedMarkdownArtifactSelectionOptions",
			"knowledgeScopePathKey",
			"artifactTargetMatches",
			"artifactScopeVerdictPriority",
			"artifactScopeInferTarget",
			"artifactScopeMatchForSource",
			"artifactExplicitTarget",
			"artifactScopeDecisionMap",
			"buildArtifactScopeFilterReport",
			"scopedMarkdownArtifacts",
			"latestScopedMarkdownArtifact",
			"formatArtifactScopeFilter",
			"latest_artifact_side_channel_scope_filter",
			"artifact_hash_path_matches_memory_scope",
			"context_artifact_index_excludes_scope_blocked_artifacts",
		]),
		"artifact scope types, report builder, and filter helpers externalized",
		"Put artifact scope/filter types, path keys, target matching, decision maps, report construction, and formatting in core/repi/artifact-scope.ts.",
	),
);

const target = read("packages/coding-agent/src/core/repi/target.ts");
rows.push(
	check(
		"target:intake-safety-contract",
		includesAll(target, [
			"RepiTargetKind",
			"REPI_POISON_PATTERNS",
			"classifyRepiTarget",
			"sanitizeTargetForCommand",
			"commandTarget",
			"commandContainsPoison",
			"looksLikeNaturalLanguageTarget",
			"shellQuote",
			"escapeRegExp",
			"isHttpUrlTarget",
			"isDirectoryTarget",
		]),
		"target intake and command quoting externalized",
		"Put target classification, natural-language rejection, poison guards, and command quoting in core/repi/target.ts.",
	),
);

const text = read("packages/coding-agent/src/core/repi/text.ts");
rows.push(
	check(
		"text:shared-formatting-contract",
		includesAll(text, [
			"truncateMiddle",
			"metadataValue",
			"numericMetadataValue",
			"slug",
			"uniqueMatches",
			"interestingLines",
			"sha256Text",
			"clamp01",
			"uniqueNonEmpty",
		]),
		"shared text and metadata helpers externalized",
		"Put shared text truncation, metadata parsing, slugging, hashing, and de-duplication helpers in core/repi/text.ts.",
	),
);

const toolchain = read("packages/coding-agent/src/core/repi/toolchain.ts");
const missingTools = firstMissing(toolchain, [
	"checksec",
	"gdb",
	"radare2",
	"ghidra",
	"binwalk",
	"nmap",
	"ffuf",
	"sqlmap",
	"burpsuite",
	"jadx",
	"frida",
	"tshark",
	"wireshark",
	"volatility3",
	"ROPgadget",
	"pwntools",
	"playwright",
]);
rows.push(
	check(
		"toolchain:bootstrap-catalog",
		toolchain.includes("REPI_TOOL_BOOTSTRAP_CATALOG") && missingTools.length === 0,
		missingTools.length ? `missingTools=${missingTools.join(", ")}` : "bootstrap catalog covers core REPI lanes",
		"Put install/verify metadata for new lane tools in core/repi/toolchain.ts.",
	),
);

const reconProfile = read("packages/coding-agent/src/core/recon-profile.ts");
rows.push(
	check(
		"architecture:profile-is-assembly-layer",
		includesAll(reconProfile, [
			"./repi/evidence.ts",
			"./repi/artifact-scope.ts",
			"./repi/case-memory.ts",
			"./repi/graph.ts",
			"./repi/goal.ts",
			"./repi/jsonl.ts",
			"./repi/knowledge-scope.ts",
			"./repi/profile.ts",
			"./repi/routes.ts",
			"./repi/mission.ts",
			"./repi/memory-active.ts",
			"./repi/memory-compact-resume.ts",
			"./repi/memory-deposition.ts",
			"./repi/memory-distillation.ts",
			"./repi/memory-distill.ts",
			"./repi/memory-event.ts",
			"./repi/memory-feedback.ts",
			"./repi/memory-experience.ts",
			"./repi/memory-maturation.ts",
			"./repi/memory-orchestrator.ts",
			"./repi/memory-quality.ts",
			"./repi/memory-replay.ts",
			"./repi/memory-search.ts",
			"./repi/memory-skill.ts",
			"./repi/memory-strategy.ts",
			"./repi/memory-supervisor.ts",
			"./repi/memory-usefulness.ts",
			"./repi/memory-ux.ts",
			"./repi/memory-vector.ts",
			"./repi/memory-scope.ts",
			"./repi/memory-store.ts",
			"./repi/memory-runtime.ts",
			"./repi/storage.ts",
			"./repi/target.ts",
			"./repi/text.ts",
			"./repi/toolchain.ts",
		]),
		"recon-profile imports REPI modules",
		"New REPI domains should land in core/repi/* modules first; recon-profile.ts should assemble and register.",
	),
);

const goalMode = read("packages/coding-agent/src/core/repi/goal.ts");
rows.push(
	check(
		"goal:built-in-mode-contract",
		includesAll(goalMode, [
			"installRepiGoalMode",
			"goal_complete",
			"REPI_GOAL_STATE_ENTRY_TYPE",
			"buildGoalSystemPrompt",
			"formatGoalFooterStatus",
			"repi-goal-continuation",
		]) &&
			includesAll(reconProfile, ["./repi/goal.ts", "installRepiGoalMode(pi)", "isExternalGoalModeExtension"]),
		"/goal command, goal_complete tool, footer status, continuation, and legacy conflict suppression are built in",
		"Keep REPI goal mode built into the inline profile and suppress external @narumitw/pi-goal conflicts.",
	),
);

rows.push(
	check(
		"runtime:adapter-auto-detect-contract",
		includesAll(reconProfile, [
			"detectRuntimeAdapterIds",
			"target_auto_detection_contract",
			"gdb-native-trace-adapter",
			"r2-native-xref-adapter",
			"frida-mobile-hook-adapter",
			"web-cdp-network-adapter",
			"tshark-pcap-flow-adapter",
			"binwalk-firmware-extract-adapter",
		]),
		"runtime adapter matrix covers GDB/r2/Frida/CDP/PCAP/firmware and target auto-detection",
		"Keep re_runtime_adapter able to infer the runner from URL, PCAP, APK/IPA/package, firmware/rootfs, pwn/crash, and native target shapes.",
	),
);

const graphSource = read("packages/coding-agent/src/core/repi/graph.ts");
rows.push(
	check(
		"evidence:task-tree-graph-contract",
		includesAll(graphSource, ["AttackGraphTaskTreeNode", "taskTree", "counter_evidence", "hypothesis"]) &&
			includesAll(reconProfile, [
				"parseEvidenceLedgerTaskRecords",
				"evidenceRecordHasCounterSignal",
				"evidenceRecordHasHypothesisSignal",
				"command",
				"produces",
				"refutes",
			]),
		"attack graph includes taskTree nodes linking commands, artifacts, hypotheses, verification, and counter-evidence",
		"Keep re_graph build as a traceable task tree, not just a flat mission/lane summary.",
	),
);

rows.push(
	check(
		"proof-loop:gap-classifier-contract",
		includesAll(reconProfile, [
			"ProofLoopGapClass",
			"proofLoopGapClassifier",
			"proofLoopQuickPath",
			"executeProofLoopQuickPathCommand",
			"quick_path_execution",
			"gap_classifier",
			"quick_path",
		]),
		"proof loop classifies gaps and executes a quick verifier/compiler/replayer/autofix path",
		"Keep re_proof_loop focused on fast executable gap classification and bounded proof repair, not only static queue dumps.",
	),
);

rows.push(
	check(
		"swarm:timeout-budget-contract",
		includesAll(reconProfile, [
			"swarmWorkerTimeoutMs",
			"REPI_SWARM_SUBAGENT_TIMEOUT_MS",
			"swarmWorkerRetryLimit",
			"REPI_SWARM_RETRY_LIMIT",
			"retry_execution",
			"retryAttempt",
			"timeoutMs",
			"timedOut",
			"cancelledAt",
			"WorkerRuntimePoolV1",
		]),
		"swarm workers carry explicit timeout/cancel metadata into manifests and pool bridge validation",
		"Keep subagent scheduling bounded, cancellable, and retry-budget visible across handoff manifests.",
	),
);

const scanFiles = [
	"README.md",
	"AGENTS.md",
	"docs/reverse-agent/README.md",
	"docs/reverse-agent/mainline-overhaul.md",
	"repi",
	"packages/coding-agent/src/core/recon-profile.ts",
	"packages/coding-agent/src/core/repi/artifact-scope.ts",
	"packages/coding-agent/src/core/repi/case-memory.ts",
	"packages/coding-agent/src/core/repi/evidence.ts",
	"packages/coding-agent/src/core/repi/graph.ts",
	"packages/coding-agent/src/core/repi/goal.ts",
	"packages/coding-agent/src/core/repi/jsonl.ts",
	"packages/coding-agent/src/core/repi/knowledge-scope.ts",
	"packages/coding-agent/src/core/repi/profile.ts",
	"packages/coding-agent/src/core/repi/routes.ts",
	"packages/coding-agent/src/core/repi/mission.ts",
	"packages/coding-agent/src/core/repi/memory-active.ts",
	"packages/coding-agent/src/core/repi/memory-compact-resume.ts",
	"packages/coding-agent/src/core/repi/memory-deposition.ts",
	"packages/coding-agent/src/core/repi/memory-distillation.ts",
	"packages/coding-agent/src/core/repi/memory-distill.ts",
	"packages/coding-agent/src/core/repi/memory-event.ts",
	"packages/coding-agent/src/core/repi/memory-feedback.ts",
	"packages/coding-agent/src/core/repi/memory-experience.ts",
	"packages/coding-agent/src/core/repi/memory-maturation.ts",
	"packages/coding-agent/src/core/repi/memory-orchestrator.ts",
	"packages/coding-agent/src/core/repi/memory-quality.ts",
	"packages/coding-agent/src/core/repi/memory-replay.ts",
	"packages/coding-agent/src/core/repi/memory-search.ts",
	"packages/coding-agent/src/core/repi/memory-skill.ts",
	"packages/coding-agent/src/core/repi/memory-strategy.ts",
	"packages/coding-agent/src/core/repi/memory-supervisor.ts",
	"packages/coding-agent/src/core/repi/memory-usefulness.ts",
	"packages/coding-agent/src/core/repi/memory-ux.ts",
	"packages/coding-agent/src/core/repi/memory-vector.ts",
	"packages/coding-agent/src/core/repi/memory-scope.ts",
	"packages/coding-agent/src/core/repi/memory-store.ts",
	"packages/coding-agent/src/core/repi/memory-runtime.ts",
	"packages/coding-agent/src/core/repi/storage.ts",
	"packages/coding-agent/src/core/repi/target.ts",
	"packages/coding-agent/src/core/repi/text.ts",
	"packages/coding-agent/src/core/repi/toolchain.ts",
	"scripts/reverse-agent/repi-smoke.mjs",
	"scripts/reverse-agent/repi-release-tarball-smoke.mjs",
	"scripts/reverse-agent/memory-inspect.mjs",
];
const forbiddenPatterns = [
	{ id: "old-source", re: /builtin:pi-recon/ },
	{ id: "old-env", re: /\bPI_RECON\b/ },
	{ id: "old-internal-marker", re: /__pi_/ },
	{ id: "old-route-agent-security", re: /Agent \/ LLM security/ },
	{ id: "old-route-web-security", re: /Web \/ API security/ },
	{ id: "old-route-security-general", re: /Security general/ },
	{ id: "red-team-theme", re: /\bred[- ]team\b/i },
];
const allowedLegacyCompatibility = ({ rel, line, id }) =>
	rel === "scripts/reverse-agent/memory-inspect.mjs" &&
	id.startsWith("old-route-") &&
	(/normalizeRouteLabel/.test(line) || /replace/.test(line) || /return "Reverse\/Pentest general"/.test(line));
const forbiddenHits = scanFiles.flatMap((rel) => patternHits(rel, forbiddenPatterns, allowedLegacyCompatibility));
rows.push(
	check(
		"theme:no-old-pi-or-generic-security-drift",
		forbiddenHits.length === 0,
		forbiddenHits.length ? JSON.stringify(forbiddenHits.slice(0, 12)) : `scanned=${scanFiles.length}`,
		"Do not reintroduce old Pi-recon markers, old generic security route labels, or red-team theme text in product surfaces.",
	),
);

const smoke = read("scripts/reverse-agent/repi-smoke.mjs");
rows.push(
	check(
		"validation:smoke-covers-usable-entrypoints",
		includesAll(smoke, [
			"product-contract",
			"doctor",
			"memory-status",
			"model-doctor",
			"model-status-env",
			"launcher-help",
			"launcher-list-models",
			"fresh-install-envless-models",
			"env-model-provider",
			"rpc-goal-command",
		]),
		"smoke covers product contract, doctor, memory, model parse, launcher help/list, fresh env-only models, and RPC /goal",
		"Keep smoke focused on fast user-facing REPI usability checks.",
	),
);

const ok = rows.every((row) => row.status === "pass");
const report = {
	kind: "repi-product-contract-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	root,
	ok,
	rows,
};

if (json) {
	console.log(JSON.stringify(report, null, 2));
} else {
	console.log("REPI Product Contract");
	console.log(`root: ${root}`);
	for (const row of rows) {
		console.log(`${row.status === "pass" ? "PASS" : "FAIL"} ${row.id} :: ${row.evidence}`);
		if (row.status !== "pass") console.log(`  fix: ${row.fix}`);
	}
	console.log(`verdict: ${ok ? "pass" : "fail"}`);
}

process.exit(ok ? 0 : 1);

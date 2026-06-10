#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const RUNTIME_MIRRORS = ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"];

const TEST_COMMANDS_PAUSED = [
	"npm run gate:same-window-live",
	"npm run gate:agent-parallel",
	"npm run gate:compound-frontier",
	"node bench/recon-remote/same-window-live/run.mjs --strict",
	"node bench/recon-remote/compound-frontier/run.mjs --live --strict",
	"node bench/recon-remote/agent-dogfood/parallel-run.mjs",
	"node bench/recon-remote/real-platform/run.mjs",
	"node bench/recon-remote/douyin-nowatermark/run.mjs",
];

const SELF_CHECK = {
	id: "audit_self",
	description: "审计脚本只做显式 root 的静态读取，默认不写文件，并在输出中保留 evidence integrity 与 maturity gaps。",
	files: ["scripts/reverse-agent/autonomy-control-plane.mjs"],
	markers: [
		"process.argv.slice(2)",
		"--json",
		"--write",
		"exists",
		"bytes",
		"sha256",
		"markerRows",
		"normalUseGuarantee",
		"currentLevel",
		"notYetTopAutonomousDefinition",
		"hardeningNeeded",
		"CONTROL_CONTRACTS",
		"controlPlaneContractAudit",
		"validateControlContractDefinitions",
	],
};

const CONTROL_CONTRACTS = [
	{
		id: "ContextPackV2",
		pillar: "long_context_compaction",
		title: "exact context pack + scoped artifact index",
		description: "长期上下文压缩必须能恢复同一个 context pack，而不是依赖 latest 重新生成。",
		requiredFields: [
			"contractId",
			"schemaVersion",
			"missionId",
			"sessionId",
			"cwd",
			"workspaceRoot",
			"target",
			"createdAt",
			"contextPath",
			"contextSha256",
			"scope",
			"artifactIndex",
			"resumeContract",
			"compactionLedger",
		],
		nestedRequired: {
			scope: ["missionId", "sessionId", "workspaceRoot", "target", "branchId"],
			artifactIndex: ["artifactId", "kind", "path", "exists", "size", "mtime", "sha256", "evidenceRank", "sourceCommand"],
			resumeContract: ["contractId", "contextPath", "contextSha256", "resumeQueueStatus", "idempotencyKey"],
			compactionLedger: ["path", "appendOnly", "prevHash", "entryHash"],
		},
		enumFields: {
			resumeQueueStatus: ["queued", "running", "done", "blocked", "exhausted"],
			evidenceRank: ["same_window_live", "runtime_artifact", "network", "served_asset", "process_config", "persisted_state"],
		},
		invariants: [
			"exact_context_load_by_contextPath_or_compactionEntryId",
			"reject_contextSha256_or_artifact_sha256_drift",
			"scope_filter_by_mission_session_workspace_target",
			"append_only_compaction_resume_ledger",
			"verified_resume_contract_must_close_or_block_completion",
		],
		schemaPath: "schemas/reverse-agent/context-resume-contract.schema.json",
		runtimeIntegration: "pending-runtime-wiring",
	},
	{
		id: "ResumeContractV2",
		pillar: "long_context_compaction",
		title: "bounded compact resume contract",
		description: "compact 之后的自动恢复必须携带不可变上下文指针、hash、预算和闭合状态。",
		requiredFields: [
			"contractId",
			"schemaVersion",
			"compactionEntryId",
			"contextPath",
			"contextSha256",
			"cwd",
			"missionId",
			"sessionId",
			"target",
			"artifactHashes",
			"resumeQueueStatus",
			"idempotencyKey",
			"ledgerPath",
			"budget",
			"closure",
		],
		nestedRequired: {
			artifactHashes: ["artifactId", "path", "sha256", "required"],
			budget: ["maxResumeTurns", "maxOperatorDispatch", "maxProofLoops"],
			closure: ["status", "closedAt", "reason", "verifiedBy"],
		},
		enumFields: {
			resumeQueueStatus: ["queued", "running", "done", "blocked", "exhausted"],
			"closure.status": ["open", "closed", "blocked", "exhausted"],
		},
		invariants: [
			"contextSha256_must_match_before_resume",
			"artifactHashes_required_items_must_exist",
			"idempotencyKey_prevents_double_auto_resume",
			"budget_exhaustion_sets_resumeQueueStatus_exhausted",
			"completion_audit_blocks_verified_open_contracts",
		],
		schemaPath: "schemas/reverse-agent/context-resume-contract.schema.json",
		runtimeIntegration: "pending-runtime-wiring",
	},
	{
		id: "FailureLedgerEventV1",
		pillar: "failure_self_repair",
		title: "failure signature + bounded repair ledger",
		description: "失败、重试和修复必须使用同一 signature 与预算，保留每次失败证据和 rollback 条件。",
		requiredFields: [
			"id",
			"ts",
			"source",
			"scope",
			"category",
			"signature",
			"attempt",
			"maxAttempts",
			"status",
			"failedGates",
			"artifacts",
			"artifactHashes",
			"repairId",
			"budget",
			"retryBudget",
			"evidenceWriteback",
			"blockedConditions",
			"rollback",
		],
		nestedRequired: {
			artifacts: ["path", "sha256", "tier"],
			artifactHashes: ["path", "sha256"],
			budget: ["retryKey", "remainingAttempts", "exhaustedAction"],
			retryBudget: ["retryKey", "remainingAttempts", "exhaustedAction"],
			evidenceWriteback: ["failureLedgerPath", "repairQueuePath", "appendOnly"],
			blockedConditions: ["reason", "unblock"],
			rollback: ["required", "baseline", "allowlist", "criteria", "restored"],
		},
		enumFields: {
			status: ["failed", "retrying", "repair_queued", "repaired", "exhausted", "rolled_back", "escalated", "blocked"],
			category: [
				"artifact_stale",
				"runtime_failed",
				"tool_missing",
				"contract_gap",
				"same_window_gap",
				"same_window_xhs_gap",
				"same_window_douyin_gap",
				"same_window_bilibili_gap",
				"platform_claim_gap",
			],
		},
		invariants: [
			"same_signature_shares_retry_budget",
			"exhausted_status_stops_blind_retry",
			"failedGates_map_to_repair_queue_item",
			"per_attempt_stdout_stderr_or_artifact_hashes_preserved",
			"autofix_requires_baseline_allowlist_regression_gate_and_rollback_criteria",
		],
		schemaPath: "schemas/reverse-agent/failure-repair-contract.schema.json",
		runtimeIntegration: "offline-hard-eval-source-wired",
	},
	{
		id: "RepairQueueItemV1",
		pillar: "failure_self_repair",
		title: "machine-actionable repair queue item",
		description: "repair queue 只能表达可执行/可暂停的修复动作，不能用自然语言遮蔽失败。",
		requiredFields: [
			"repairId",
			"fromFailureId",
			"signature",
			"scope",
			"action",
			"commands",
			"expectedArtifacts",
			"expectedGates",
			"preconditions",
			"paused",
			"allowlist",
			"rollbackCriteria",
			"repairAction",
			"blockedConditions",
			"evidenceWriteback",
			"regressionGates",
		],
		nestedRequired: {
			preconditions: ["liveAllowed", "providerAllowed", "requiredSecrets"],
			rollbackCriteria: ["baseline", "mustRestore", "verificationCommand"],
			blockedConditions: ["reason", "unblock"],
			evidenceWriteback: ["failureLedgerPath", "repairQueuePath", "appendOnly"],
		},
		enumFields: {
			action: ["rerun", "replace-command", "recapture-evidence", "refresh-context", "escalate", "rollback"],
		},
		invariants: [
			"paused_true_for_live_or_provider_dependent_repairs",
			"commands_are_not_executed_by_static_gate",
			"expectedGates_must_bind_to_failedGates",
			"repair_completion_requires_regressionGates_pass",
		],
		schemaPath: "schemas/reverse-agent/failure-repair-contract.schema.json",
		runtimeIntegration: "offline-hard-eval-source-wired",
	},
	{
		id: "DivisionValidationContractV1",
		pillar: "automatic_division_validation",
		title: "role contract + claim ledger + conflict table",
		description: "分工结果必须先落到 role contract、claim ledger、challenge/resolution 和 conflict table，再允许 synthesizer 汇总。",
		requiredFields: [
			"contractVersion",
			"runId",
			"evidenceOrder",
			"roles",
			"ledgerPolicy",
			"conflictPolicy",
			"claimGatePolicy",
		],
		nestedRequired: {
			roles: ["id", "mustEmit", "allowedClaimKinds", "forbiddenClaimKinds", "handoffTargets", "evidenceContract"],
			ledgerPolicy: ["appendOnly", "prevHash", "eventHash", "requiredEventTypes"],
			conflictPolicy: ["tableRequired", "evidenceOrder", "unresolvedBlocksFinal"],
			claimGatePolicy: ["provenRequiresArtifactSha256", "provenRequiresJsonQuery", "finalPassRequiresVerifier", "unresolvedChallengeBlocks"],
		},
		enumFields: {
			requiredEventTypes: ["artifact_handoff", "claim", "validation", "challenge", "resolution"],
		},
		invariants: [
			"proven_or_final_pass_claim_requires_artifact_sha256_and_json_query",
			"verifier_pass_required_before_final_pass",
			"unresolved_adversary_challenge_blocks_claim_promotion",
			"synthesizer_must_emit_conflict_table",
			"orchestration_score_must_not_imply_platform_claim_success",
		],
		schemaPath: "schemas/reverse-agent/division-validation-contract.schema.json",
		runtimeIntegration: "offline-hard-eval-source-wired",
	},
	{
		id: "AutonomousRuntimeBatchV1",
		pillar: "parallel_scheduling",
		title: "strict sub-agent runtime + shard/resume/repair/claim promotion state",
		description: "顶级 autonomous runtime 必须把子代理执行态、shard 状态、compact resume 状态机、repair budget 和 claim promotion gate 放入同一个 strict batch gate。",
		requiredFields: [
			"kind",
			"schemaVersion",
			"runId",
			"subagentRuntimeManifests",
			"parallelShardStates",
			"compactResumeStates",
			"repairBudgetStates",
			"claimPromotionGates",
		],
		nestedRequired: {
			subagentRuntimeManifests: ["pid", "sessionDir", "stdoutSha256", "stderrSha256", "model", "toolCallDigest", "retryBudget"],
			parallelShardStates: ["dependencies", "leaseId", "resourceLimits", "resultManifestPath", "mergeKeys"],
			compactResumeStates: ["transitionLog", "idempotencyKey", "resumeBudget", "operatorQueueRef", "proofLoopEntry"],
			repairBudgetStates: ["signature", "retryBudget", "allowlist", "rollbackCriteria", "regressionGates"],
			claimPromotionGates: ["ledgerPath", "hashChainOk", "eventTypes", "strictValidator", "finalPromotionBlocked"],
		},
		enumFields: {
			status: ["queued", "running", "done", "failed", "blocked", "exhausted", "cancelled", "rolled_back"],
			eventTypes: ["artifact_handoff", "claim", "validation", "challenge", "resolution"],
		},
		invariants: [
			"subagent_manifest_records_pid_session_stdout_stderr_model_tool_digest",
			"parallel_shard_state_records_dependencies_timeout_cancel_resource_limits_and_merge_keys",
			"compact_resume_state_is_idempotent_and_tracks_queued_running_done_blocked_exhausted",
			"repair_budget_state_shares_signature_budget_allowlist_rollback_and_regression_gates",
			"claim_promotion_gate_requires_strict_claim_ledger_validator_before_final_promotion",
		],
		schemaPath: "schemas/reverse-agent/autonomous-runtime-contract.schema.json",
		runtimeIntegration: "strict-fixture-gate-wired",
	},
];

const REQUIREMENTS = [
	{
		id: "parallel_scheduling",
		title: "并行调度 / 分片 / 专家分工",
		statusWhenPassing: "usable",
		normalChecks: [
			{
				id: "core_delegate_swarm_pipeline",
				description: "内核和文件型 profile 都保留 operation → delegate → swarm → supervisor 的 worker runtime packet 链路。",
				files: RUNTIME_MIRRORS,
				markers: ["re_operation", "re_delegate", "re_swarm", "parallel_groups", "worker_runtime_packets", "commander_next_actions"],
			},
			{
				id: "runtime_parallel_runner_evidence",
				description: "现有 dogfood runner 具备真实并发进程、角色结果、sub-agent runtime manifest 和 synthesizer 合并证据结构。",
				files: ["bench/recon-remote/agent-dogfood/parallel-run.mjs"],
				markers: [
					"Promise.all",
					"roleRuns",
					"synthesizerRun",
					"overlapStats",
					"sessionDigest",
					"writeSubagentRuntimeManifest",
					"pi-recon-subagent-runtime-manifest",
					"runtimeManifestFile",
					"subagentRuntimeManifestsCaptured",
					"toolResultCount",
					"modelProvider",
				],
			},
			{
				id: "frontier_shard_plan",
				description: "frontier orchestrator 已能输出 case catalog、agent lane 和 shard plan，供后续通用 parallel manifest 消费。",
				files: ["bench/recon-remote/frontier-orchestrator/run.mjs"],
				markers: ["agentLane", "function shardCases", "shards", "command", "makePlan"],
			},
			{
				id: "runtime_recon_parallel_plan",
				description: "re_swarm runtime 已输出 ReconParallelPlanV1、planCoverage 和 releaseGateMetadata，并把计划绑定到 worker runtime packets。",
				files: RUNTIME_MIRRORS,
				markers: [
					"type ReconParallelPlanV1",
					"function buildSwarmParallelPlan",
					"parallelPlan",
					"planCoverage",
					"releaseGateMetadata",
					"release_gate.claim_promotion=blocked_until_supervisor_claim_gate_passes",
				],
			},
			{
				id: "runtime_re_swarm_subagent_manifest",
				description: "re_swarm run 会为每个 worker 写 command-level SubagentRuntimeManifestV1、stdout/stderr、sessionDir、toolCallDigest 和 manifest index。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: [
					"SwarmSubagentRuntimeManifestV1",
					"writeSwarmSubagentRuntimeManifest",
					"subagentRuntimeManifestPath",
					"subagentRuntimeManifestsCaptured",
					"runtimeManifestFile",
					"stdoutPath",
					"stderrPath",
					"toolCallDigest",
				],
			},
			{
				id: "strict_autonomous_runtime_batch_gate",
				description: "AutonomousRuntimeBatchV1 strict gate 覆盖子代理 runtime manifest、parallel shard state、compact resume transition、repair budget 和 runtime claim promotion。",
				files: ["scripts/reverse-agent/autonomous-runtime-contracts.mjs"],
				markers: [
					"validateAutonomousRuntimeBatch",
					"SubagentRuntimeManifestV1",
					"ParallelShardStateV1",
					"CompactResumeStateV2",
					"RepairBudgetStateV1",
					"RuntimeClaimPromotionGateV1",
					"duplicate_subagent_runtime_attempt",
					"invalid_resume_transition",
				],
			},
			{
				id: "worker_runtime_pool_contract_gate",
				description: "WorkerRuntimePoolV1 hard-eval 覆盖真实调度应有的 maxConcurrency、timeout/cancel、resource lease、retryBudget 和 claim-aware merge 负例。",
				files: ["scripts/reverse-agent/worker-runtime-pool-gate.mjs", "fixtures/reverse-agent/worker-runtime-pool.fixture.json"],
				markers: [
					"WorkerRuntimePoolV1",
					"maxConcurrency_exceeded",
					"timeout_without_cancel",
					"duplicate_mergeKey_unresolved",
					"exhausted_still_retrying",
					"claim-aware merge",
				],
			},
		],
		hardeningNeeded: [
			"把 WorkerRuntimePoolV1 离线 hard-eval 接入真实 child session/provider runtime，形成 live timeout/cancel/resource lease 回归证据。",
			"把 worker merge 从文本摘要升级为 structured claim merge，并在 supervisor 前阻断缺证据或冲突 claim；离线 duplicate mergeKey 负例已由 gate:worker-runtime-pool 保护。",
			"把 re_swarm command-level SubagentRuntimeManifestV1 继续升级为可选独立 Pi child session/provider runtime。",
		],
		recommendedWork: [
			"保持 npm run audit:parallel-plan 作为 frontier --plan 与 dogfood --plan-only 的离线 smoke gate。",
			"保持 gate:claim-release --write-marker 作为 release gate marker，并让 supervisor/compiler/complete 消费最新 marker。",
			"让 agent-dogfood 与 re_swarm 的 sub-agent runtime manifest 继续和 planId/source/worker merge keys、failure signature 关联。",
		],
	},
	{
		id: "long_context_compaction",
		title: "长期上下文 / compact / resume",
		statusWhenPassing: "usable",
		normalChecks: [
			{
				id: "context_pack_runtime",
				description: "内核和文件型 profile 都由 REPI 自有 context pack/resume/compaction contract 接管。",
				files: RUNTIME_MIRRORS,
				markers: [
					"buildContextPack",
					"contextPackSha256",
					"contextArtifactHashes",
					"verifyContextPackResume",
					"buildExactResumeContextPack",
					"buildReconCompactionSummary",
					"buildReconCompactionResumeContract",
					"compaction-resume-ledger.jsonl",
					"exactResumeVerification",
					"pi-recon-compaction-auto-resume",
					"compact_resume_case_memory",
				],
			},
			{
				id: "context_compact_static_gate",
				description: "已有独立静态 harness 检查 context pack、owned compaction、resume contract、negative fixtures、evidence summarization 和 budget continuation。",
				files: ["scripts/reverse-agent/context-compact-audit.mjs"],
				markers: [
					"context_pack",
					"owned_compaction_provider",
					"resume_contract_continuation",
					"exact_resume_negative_fixtures",
					"evidence_summarization",
					"budget_continuation",
				],
			},
			{
				id: "context_docs_contract",
				description: "公开文档记录 context/resume pack、owned compaction 和 audit harness，不依赖 upstream compact 说明。",
				files: ["docs/reverse-agent/README.md"],
				markers: ["Context/resume pack 闭环", "REPI owned compaction kernel update", "context-compact-audit.mjs"],
			},
			{
				id: "memory_v3_distiller_quarantine",
				description: "Memory v3 不只保留事件，还把经验蒸馏为 pattern-book，并隔离跨 route/陈旧/矛盾/污染 case。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: [
					"MemoryDistilledPatternV1",
					"distillMemoryPatterns",
					"mandatory_memory_injection_chain",
					"memory_contamination_quarantine",
				],
			},
			{
				id: "memory_v3_distiller_gate",
				description: "Memory v3 distiller gate 覆盖 promote/quarantine/hash drift/低置信负例。",
				files: ["scripts/reverse-agent/memory-distiller-gate.mjs"],
				markers: ["repi-memory-distiller-gate", "mandatory_memory_injection_chain", "memory_contamination_quarantine"],
			},
			{
				id: "memory_v3_distiller_fixture",
				description: "Memory v3 fixture 包含跨 route 污染、陈旧失败和 mandatory injection chain 场景。",
				files: ["fixtures/reverse-agent/memory-distiller.fixture.json"],
				markers: ["repi-memory-distiller-fixture", "case-cross-route-pollution", "mustHaveInjectionStages"],
			},
		],
		hardeningNeeded: [
			"knowledge graph/latest artifact 查询继续按 mission/session/workspace/target 做更严格过滤，避免跨任务污染。",
			"compact resume ledger 继续扩展 queue 状态机：running/done/blocked/exhausted、auto-resume budget 和多次 compact 幂等回放。",
			"completion audit 继续扩展更多 closure 负例：多次 compact 交错、跨 session 恢复、预算 exhausted 后恢复。",
		],
		recommendedWork: [
			"保持 ContextPackV2 / ResumeContractV2 runtime markers 与 context-compact-audit.mjs 同步。",
			"把 memory/compaction-resume-ledger.jsonl 与 re_operator/re_proof_loop 的执行闭环做状态回写。",
			"继续补静态/单元级假 artifact 场景：multi compact、target unresolved、cross-session contamination。",
		],
	},
	{
		id: "failure_self_repair",
		title: "失败自修复 / retry / rollback",
		statusWhenPassing: "usable",
		normalChecks: [
			{
				id: "core_repair_loop",
				description: "内核和文件型 profile 都保留 verifier → compiler → replayer → autofix → proof-loop 的修复队列。",
				files: RUNTIME_MIRRORS,
				markers: ["re_autofix", "failure_budget_exhausted", "repair_queue", "dispatcherScoreDecayRows", "repeatedFailureDemotionRows", "evidence_recapture_queue"],
			},
			{
				id: "runtime_failure_repair_ledger",
				description: "re_replayer / re_autofix / re_operator / re_proof_loop failed|blocked rows 写入 canonical failure/repair JSONL。",
				files: RUNTIME_MIRRORS,
				markers: [
					"type FailureLedgerEventV1",
					"type RepairQueueItemV1",
					"runtimeFailureSignature",
					"failureToRepair",
					"appendFailureRepairLedger",
					"appendRuntimeFailureRepairFromReplay",
					"appendRuntimeFailureRepairFromAutofix",
					"appendRuntimeFailureRepairFromOperator",
					"appendRuntimeFailureRepairFromProofLoop",
				],
			},
			{
				id: "agent_session_retry_policy",
				description: "核心 agent session 具备 bounded retry、指数退避和 context overflow 排除逻辑。",
				files: ["packages/coding-agent/src/core/agent-session.ts"],
				markers: ["maxRetries", "baseDelayMs", "_prepareRetry", "context", "timeout"],
			},
			{
				id: "settings_retry_defaults",
				description: "settings manager 暴露默认 retry 开关、maxRetries 和 baseDelayMs。",
				files: ["packages/coding-agent/src/core/settings-manager.ts"],
				markers: ["retry", "enabled", "maxRetries", "baseDelayMs"],
			},
			{
				id: "dogfood_role_retry",
				description: "并行 runner 的 role/synthesizer 有 bounded retry、per-attempt artifact 和 failure/repair 输出。",
				files: ["bench/recon-remote/agent-dogfood/parallel-run.mjs"],
				markers: ["RECON_ROLE_RETRIES", "withRetries", "attempts", "attemptStdoutFile", "failureRepairFromGap", "failureLedgerEvents", "strictRunPassed"],
			},
			{
				id: "compound_frontier_failure_repair",
				description: "compound-frontier failed gates 输出 canonical failure/repair ledger rows。",
				files: ["bench/recon-remote/compound-frontier/run.mjs"],
				markers: ["failureRepairFromGaps", "failureLedgerEvents", "repairQueue", "failure-ledger.jsonl"],
			},
			{
				id: "plan_only_failure_repair",
				description: "plan-only invalid fixture 验证不启动 provider 且输出 failure/repair rows。",
				files: ["scripts/reverse-agent/audit-parallel-plan.mjs"],
				markers: ["validatePlanOnlyFailureRepair", "planOnlyFailureRepair", "tmp-invalid-plan.json"],
			},
			{
				id: "failure_repair_strict_schema",
				description: "FailureLedgerEventV1 / RepairQueueItemV1 schema 绑定 strict fixture、重复 signature 去重窗口和 strict additionalProperties。",
				files: ["schemas/reverse-agent/failure-repair-contract.schema.json"],
				markers: [
					"additionalProperties",
					"deterministic_duplicate_signature_attempt_rejected",
					"x-repiStrictFixture",
					"x-repiDedupWindow",
				],
			},
			{
				id: "failure_repair_strict_fixture",
				description: "Failure/repair strict fixture 覆盖 valid batch、duplicate signature/attempt 和 loose field 负例。",
				files: ["fixtures/reverse-agent/failure-repair-strict.fixture.json"],
				markers: [
					"invalidDuplicate",
					"invalidLoose",
					"strict_schema_fixture_gate",
					"unexpectedLooseField",
				],
			},
			{
				id: "failure_repair_strict_validator",
				description: "Autonomous contracts gate 调用本地 strict validator，验证 duplicate 和 loose field 负例。",
				files: ["scripts/reverse-agent/autonomous-contracts.mjs"],
				markers: [
					"validateFailureRepairStrictFixture",
					"failureRepairStrictFixture",
					"duplicateRejected",
					"looseRejected",
				],
			},
		],
		hardeningNeeded: [
			"把 strict failure/repair validator 接入独立 sub-agent/session runtime regression gates。",
			"所有 runtime retry 继续复用同一 signature 和 budget/retryBudget；达到 exhausted 后停止盲 retry，转 repair/escalate。",
			"为 autofix/operator/compound 类动作加入 baseline、allowlist、passed gate regression 和 rollback criteria。",
		],
		recommendedWork: [
			"保持 .repi-harness/evidence/failures/ledger.jsonl 和 .repi-harness/evidence/repairs/queue.jsonl schema，把 retryBudget/evidenceWriteback/blockedConditions 保持为必填。",
			"把 agent-dogfood 独立 sub-agent runtime manifest 继续接入 failure signature / retry budget 去重。",
			"让 proof-loop/knowledge graph 查询 failure signature，自动优先处理 exhausted 与重复失败。",
		],
	},
	{
		id: "automatic_division_validation",
		title: "自动分工验证 / claim 合同 / 冲突合成",
		statusWhenPassing: "usable",
		normalChecks: [
			{
				id: "core_validation_pipeline",
				description: "内核和文件型 profile 都保留 verifier/compiler/counter-evidence/conflict/supervisor 结构。",
				files: RUNTIME_MIRRORS,
				markers: ["re_verifier", "re_compiler", "counter_evidence", "conflict_matrix", "worker_scoreboard", "commander_merge_queue"],
			},
			{
				id: "parallel_role_gate_matrix",
				description: "并行 dogfood runner 已记录 roleGateMatrix、runtime claim ledger、toolResultsCaptured、synthesizerReconciled 等运行级分工验证信号。",
				files: ["bench/recon-remote/agent-dogfood/parallel-run.mjs"],
				markers: ["roleGateMatrix", "synthesizerReconciled", "toolResultsCaptured", "antiSelfDelusion", "ClaimLedgerEventV1", "claim-ledger.jsonl", "runtimeClaimLedgerCaptured"],
			},
			{
				id: "runtime_re_swarm_claim_ledger",
				description: "re_swarm runtime 已输出 ClaimLedgerEventV1 哈希链，绑定 worker handoff、claim、validation、challenge、resolution 与 repair queue。",
				files: RUNTIME_MIRRORS,
				markers: [
					"SwarmClaimLedgerEventV1",
					"appendSwarmClaimLedgerEvent",
					"buildSwarmRuntimeClaimLedger",
					"swarmClaimLedgerHashChainOk",
					"claimLedgerPath",
					"claimLedgerEventCount",
					"claimLedgerTipHash",
					"runtimeClaimLedgerCaptured",
					"claim-ledger.jsonl",
					"artifact_handoff",
					"claim",
					"validation",
					"challenge",
					"resolution",
				],
			},
			{
				id: "compound_frontier_runtime_claim_ledger",
				description: "compound-frontier 已写 runtime claim-ledger.jsonl，把 bound artifacts、gates、failure/repair 输出和最终降级原因串成 ClaimLedgerEventV1 风格哈希链。",
				files: ["bench/recon-remote/compound-frontier/run.mjs"],
				markers: [
					"ClaimLedgerEventV1",
					"appendCompoundClaimLedgerEvent",
					"buildCompoundClaimLedgerEvents",
					"claim-ledger.jsonl",
					"claimLedgerEvents",
					"claimLedgerPath",
					"claimLedgerEventCount",
					"claimLedgerTipHash",
					"runtimeClaimLedgerCaptured",
					"artifact_handoff",
					"claim",
					"validation",
					"challenge",
					"resolution",
				],
			},
			{
				id: "supervisor_claim_gate_policy",
				description: "re_supervisor 已消费 swarm parallelPlan/planCoverage/releaseGateMetadata，并输出 claimGatePolicy/claimGateResult 防止 narrative-only final pass。",
				files: RUNTIME_MIRRORS,
				markers: [
					"function supervisorClaimGatePolicy",
					"function supervisorPlanCoverage",
					"strictClaimGateSnapshot",
					"buildClaimGateResult",
					"releaseGateMetadata",
					"claimGatePolicy",
					"claimGateResult",
					"claim_gate_policy.final_pass_requires_verifier=true",
					"claim_gate_policy.orchestration_score_never_implies_platform_success=true",
				],
			},
			{
				id: "strict_claim_release_marker",
				description: "re_supervisor、re_compiler final、re_complete audit 读取同一 strict claim gate snapshot。",
				files: RUNTIME_MIRRORS,
				markers: [
					"claim-release",
					"strictClaimGateSnapshot",
					"buildClaimGateResult",
					"compilerClaimGateReady",
					"claimGateResult",
					"strict claim release marker blocks final claim",
				],
			},
			{
				id: "claim_release_marker_writer",
				description: "gate:claim-release 调用 strict validator 并写入 pi-recon-claim-release-marker。",
				files: ["scripts/reverse-agent/validate-claim-ledger.mjs"],
				markers: ["--write-marker", "pi-recon-claim-release-marker", "claim-release", "sourceSha256"],
			},
			{
				id: "claim_release_npm_gate",
				description: "package gate:claim-release 默认开启 --write-marker。",
				files: ["package.json"],
				markers: ["gate:claim-release", "--strict-claims --write-marker"],
			},
			{
				id: "runtime_claim_ledger_strict_gate",
				description: "runtime ClaimLedgerEventV1 会经 adapter 进入 validate-claim-ledger.mjs 的 allow-platform-gaps 与 strict-claims 双门禁，缺失 runtime artifact 明确标记 missing_runtime_artifact。",
				files: ["scripts/reverse-agent/gate-runtime-claim-ledger.mjs"],
				markers: [
					"normalizeRuntimeClaimLedgerToStrictInput",
					"validate-claim-ledger.mjs",
					"--allow-platform-gaps",
					"--strict-claims",
					"missing_runtime_artifact",
				],
			},
			{
				id: "runtime_claim_ledger_adapter",
				description: "adapter 把 runtime ledger 规范化成 strict input，并保留 missing_runtime_artifact 语义。",
				files: ["scripts/reverse-agent/runtime-claim-ledger-adapter.mjs"],
				markers: ["normalizeRuntimeClaimLedgerToStrictInput", "runtimeClaimLedgerCaptured", "missing_runtime_artifact", "artifact_handoff", "validation", "resolution"],
			},
			{
				id: "runtime_claim_ledger_npm_gate",
				description: "package 暴露 runtime claim ledger strict gate。",
				files: ["package.json"],
				markers: ["gate:runtime-claim-ledger", "gate-runtime-claim-ledger.mjs", "--strict"],
			},
			{
				id: "runtime_claim_ledger_autonomous_contract_wiring",
				description: "autonomous contracts 聚合 runtime claim ledger strict gate。",
				files: ["scripts/reverse-agent/autonomous-contracts.mjs"],
				markers: ["runtimeClaimLedgerStrictGate", "buildRuntimeClaimLedgerGate", "runtime_claim_ledger_strict"],
			},
		],
		hardeningNeeded: [
			"补齐 agent-dogfood/re_swarm live runtime artifact，让 gate:runtime-claim-ledger 从 partial coverage 变成 complete coverage。",
			"每个 proven/final_pass claim 继续强制绑定 artifact sha256、JSON query、verifier pass、无 unresolved adversary challenge。",
			"synthesizer 输出继续扩展 conflict table：claimIds、冲突主题、胜出证据、降级原因、未解决冲突。",
		],
		recommendedWork: [
			"保持 hard-eval claim ledger 与 gate:claim-release marker 作为 release 级门禁。",
			"继续把同一 ledger schema 接入通用 re_swarm 独立 sub-agent/session runtime 和 claim-aware merge。",
			"在 claim gap 修复后重新运行 gate:claim-release 生成 pass marker，再进入 re_compiler final。",
		],
	},
];

function sha256(text) {
	return createHash("sha256").update(text).digest("hex");
}

function safeJson(text, fallback = null) {
	try {
		return JSON.parse(text);
	} catch {
		return fallback;
	}
}

function readProjectFile(root, relativePath) {
	const path = join(root, relativePath);
	if (!existsSync(path)) return { relativePath, path, exists: false, text: "", bytes: 0, sha256: null };
	const text = readFileSync(path, "utf8");
	return { relativePath, path, exists: true, text, bytes: Buffer.byteLength(text), sha256: sha256(text) };
}

function markerRows(file, markers) {
	return markers.map((marker) => ({ marker, present: file.exists && file.text.includes(marker) }));
}

function schemaDefinition(schema, contractId) {
	return schema?.$defs?.[contractId] ?? schema?.definitions?.[contractId] ?? schema;
}

function validateControlContractDefinition(contract) {
	const missingTop = ["id", "pillar", "requiredFields", "nestedRequired", "enumFields", "invariants", "schemaPath"].filter(
		(field) => contract[field] === undefined || contract[field] === null,
	);
	const requiredOk = Array.isArray(contract.requiredFields) && contract.requiredFields.length >= 4;
	const nestedOk = contract.nestedRequired && Object.values(contract.nestedRequired).every((fields) => Array.isArray(fields) && fields.length > 0);
	const enumOk = contract.enumFields && Object.values(contract.enumFields).every((values) => Array.isArray(values) && values.length > 0);
	const invariantOk = Array.isArray(contract.invariants) && contract.invariants.length >= 3;
	const status = missingTop.length === 0 && requiredOk && nestedOk && enumOk && invariantOk ? "pass" : "fail";
	return {
		id: contract.id,
		pillar: contract.pillar,
		status,
		missingTop,
		requiredFields: contract.requiredFields?.length ?? 0,
		nestedContracts: Object.keys(contract.nestedRequired ?? {}).length,
		enumFields: Object.keys(contract.enumFields ?? {}).length,
		invariants: contract.invariants?.length ?? 0,
		schemaPath: contract.schemaPath,
		runtimeIntegration: contract.runtimeIntegration,
	};
}

function validateControlContractSchema(root, contract) {
	const file = readProjectFile(root, contract.schemaPath);
	const json = file.exists ? safeJson(file.text) : null;
	const definition = json ? schemaDefinition(json, contract.id) : null;
	const required = new Set(definition?.required ?? []);
	const properties = new Set(Object.keys(definition?.properties ?? {}));
	const schemaInvariants = new Set([
		...(json?.["x-repiInvariants"] ?? []),
		...(definition?.["x-repiInvariants"] ?? []),
	]);
	const missingRequired = (contract.requiredFields ?? []).filter((field) => !required.has(field));
	const missingProperties = (contract.requiredFields ?? []).filter((field) => !properties.has(field));
	const missingInvariants = (contract.invariants ?? []).filter((invariant) => !schemaInvariants.has(invariant));
	const schemaText = file.text ?? "";
	const missingEnumValues = Object.values(contract.enumFields ?? {})
		.flat()
		.filter((value) => !schemaText.includes(`"${value}"`));
	const status =
		file.exists &&
		Boolean(json) &&
		missingRequired.length === 0 &&
		missingProperties.length === 0 &&
		missingInvariants.length === 0 &&
		missingEnumValues.length === 0
			? "pass"
			: "fail";
	return {
		id: contract.id,
		pillar: contract.pillar,
		schemaPath: contract.schemaPath,
		status,
		exists: file.exists,
		parseOk: Boolean(json),
		bytes: file.bytes,
		sha256: file.sha256,
		missingRequired,
		missingProperties,
		missingInvariants,
		missingEnumValues,
	};
}

function validateControlContractDefinitions(root) {
	const definitions = CONTROL_CONTRACTS.map((contract) => validateControlContractDefinition(contract));
	const schemas = CONTROL_CONTRACTS.map((contract) => validateControlContractSchema(root, contract));
	const pillars = [...new Set(CONTROL_CONTRACTS.map((contract) => contract.pillar))].map((pillar) => {
		const definitionRows = definitions.filter((row) => row.pillar === pillar);
		const schemaRows = schemas.filter((row) => row.pillar === pillar);
		return {
			pillar,
			status: [...definitionRows, ...schemaRows].every((row) => row.status === "pass") ? "pass" : "fail",
			contracts: definitionRows.map((row) => row.id),
			runtimeIntegration: CONTROL_CONTRACTS.filter((contract) => contract.pillar === pillar).map((contract) => ({
				id: contract.id,
				status: contract.runtimeIntegration,
			})),
		};
	});
	const status = [...definitions, ...schemas].every((row) => row.status === "pass") ? "pass" : "fail";
	return {
		status,
		mode: "static-contract-field-and-schema-validator",
		description: "补齐长期上下文压缩、失败自修复、自动分工验证的控制面字段，并用 JSON schema + 本脚本 validator 静态校验。",
		definitions,
		schemas,
		pillars,
	};
}

function evaluateCheck(root, check) {
	const fileChecks = check.files.map((filePath) => {
		const file = readProjectFile(root, filePath);
		const markers = markerRows(file, check.markers);
		const missing = markers.filter((row) => !row.present).map((row) => row.marker);
		return {
			path: file.relativePath,
			exists: file.exists,
			bytes: file.bytes,
			sha256: file.sha256,
			status: file.exists && missing.length === 0 ? "pass" : "fail",
			markers,
			missing,
		};
	});
	return {
		id: check.id,
		description: check.description,
		status: fileChecks.every((file) => file.status === "pass") ? "pass" : "fail",
		files: fileChecks,
	};
}

function evaluatePillar(root, requirement) {
	const checks = requirement.normalChecks.map((check) => evaluateCheck(root, check));
	const normalUse = checks.every((check) => check.status === "pass");
	return {
		id: requirement.id,
		title: requirement.title,
		status: normalUse ? requirement.statusWhenPassing : "gap",
		normalUse,
		checks,
		hardeningNeeded: requirement.hardeningNeeded,
		recommendedWork: requirement.recommendedWork,
	};
}

function buildManifest(root) {
	const auditSelf = evaluateCheck(root, SELF_CHECK);
	const controlPlaneContractAudit = validateControlContractDefinitions(root);
	const pillars = REQUIREMENTS.map((requirement) => evaluatePillar(root, requirement));
	const normalUseGuarantee =
		auditSelf.status === "pass" && controlPlaneContractAudit.status === "pass" && pillars.every((pillar) => pillar.normalUse);
	const hardeningItems = pillars.flatMap((pillar) => pillar.hardeningNeeded.map((item) => `${pillar.id}: ${item}`));
	return {
		kind: "pi-recon-autonomy-control-plane",
		version: 2,
		generatedAt: new Date().toISOString(),
		root,
		auditMode: "static-source-and-harness-contract-only",
		normalUseGuarantee,
		currentLevel: normalUseGuarantee ? "professional reverse/pentest task organization agent" : "incomplete organization profile",
		auditSelf,
		controlPlaneContractAudit,
		topAutonomousDefinition: false,
		topAutonomousDefinitionReason: "核心组织链路、agent-dogfood subagent runtime manifest、AutonomousRuntimeBatchV1 strict fixture/gate，以及 agent-dogfood / re_swarm / compound runtime claim ledger、ContextPackV2 exact resume marker/negative fixtures/closure gate、strict failure/repair fixture、runtime failure/repair ledger hooks、compound/role retry failure-repair 输出、strict claim release marker 和 supervisor/compiler/complete final gate 已可用；通用 re_swarm live 独立子会话 runtime 与 cross-session resume live 回归仍可继续硬化。",
		pillars,
		notYetTopAutonomousDefinition: hardeningItems,
		recommendedNonTestWorkOrder: [
			"保持 ReconParallelPlanV1、releaseGateMetadata、claimGatePolicy、strict claim marker 在 re_swarm / re_supervisor / re_compiler / re_complete 间同源流转。",
			"保持 AutonomousRuntimeBatchV1 strict gate 覆盖 subagent manifest / shard state / compact resume / repair budget / runtime claim promotion，并继续把 role contract + claim ledger + conflict table 扩展到 live 独立子会话执行态。",
			"继续把 strict failure ledger + repair queue + bounded retry signature + rollback criteria 接入更多 live runtime 回归门禁。",
			"继续扩展 ContextPackV2 / ResumeContractV2 的 cross-session 和 multi-compact 负例 fixture。",
			"完成上述控制面后，再恢复真实平台/live benchmark。",
		],
		testCommandsPaused: TEST_COMMANDS_PAUSED,
	};
}

function formatMarkdown(manifest) {
	const lines = [
		"# REPI Autonomy Control Plane",
		"",
		`generated_at: ${manifest.generatedAt}`,
		`audit_mode: ${manifest.auditMode}`,
		`normal_use_guarantee: ${manifest.normalUseGuarantee}`,
		`current_level: ${manifest.currentLevel}`,
		`top_autonomous_definition: ${manifest.topAutonomousDefinition}`,
		`top_autonomous_reason: ${manifest.topAutonomousDefinitionReason}`,
		"",
		"## Outcome",
		"",
		manifest.normalUseGuarantee
			? "REPI 当前具备专业逆向/渗透任务组织能力：能把任务压入 map→operation→delegate→swarm→supervisor→context→operator→verifier→compiler→replayer→autofix→proof-loop 的控制面。"
			: "REPI 当前组织能力 marker 不完整，需要先修复 failed checks。",
		"",
		"它还不是完整 autonomous red-team agent；下面的 hardening_needed 是必须继续工程化的缺口，不作为本静态门槛的失败条件。",
		"",
		"## Audit self-check",
		"",
		`- ${manifest.auditSelf.id}: ${manifest.auditSelf.status} — ${manifest.auditSelf.description}`,
		...manifest.auditSelf.files.map((file) => `  - ${file.path}: ${file.status}${file.exists ? ` bytes=${file.bytes} sha256=${file.sha256.slice(0, 16)}` : " missing"}`),
		"",
		"## Control contract validators",
		"",
		`status: ${manifest.controlPlaneContractAudit.status}`,
		`mode: ${manifest.controlPlaneContractAudit.mode}`,
		"",
		"contracts:",
		...manifest.controlPlaneContractAudit.definitions.map(
			(row) =>
				`- ${row.id}: ${row.status} pillar=${row.pillar} fields=${row.requiredFields} nested=${row.nestedContracts} enums=${row.enumFields} invariants=${row.invariants} runtime=${row.runtimeIntegration}`,
		),
		"",
		"schemas:",
		...manifest.controlPlaneContractAudit.schemas.map(
			(row) =>
				`- ${row.id}: ${row.status} ${row.schemaPath}${row.exists ? ` bytes=${row.bytes} sha256=${row.sha256.slice(0, 16)}` : " missing"}`,
		),
		"",
		"## Pillars",
		"",
	];
	for (const pillar of manifest.pillars) {
		lines.push(`### ${pillar.id} — ${pillar.title}`, "", `status: ${pillar.status}`, "");
		lines.push("normal_checks:");
		for (const check of pillar.checks) {
			lines.push(`- ${check.id}: ${check.status} — ${check.description}`);
			for (const file of check.files) {
				lines.push(`  - ${file.path}: ${file.status}${file.exists ? ` bytes=${file.bytes} sha256=${file.sha256.slice(0, 16)}` : " missing"}`);
				if (file.status === "fail") {
					for (const marker of file.missing.slice(0, 12)) lines.push(`    - missing: ${marker}`);
					if (file.missing.length > 12) lines.push(`    - ... ${file.missing.length - 12} more`);
				}
			}
		}
		lines.push("", "hardening_needed:");
		for (const item of pillar.hardeningNeeded) lines.push(`- ${item}`);
		lines.push("", "recommended_non_test_work:");
		for (const item of pillar.recommendedWork) lines.push(`- ${item}`);
		lines.push("");
	}
	lines.push("## Paused test commands", "");
	for (const command of manifest.testCommandsPaused) lines.push(`- ${command}`);
	lines.push("", "## Recommended non-test work order", "");
	for (const item of manifest.recommendedNonTestWorkOrder) lines.push(`- ${item}`);
	return `${lines.join("\n")}\n`;
}

function writeManifest(root, manifest) {
	const stamp = manifest.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "autonomy-control-plane", stamp);
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, "result.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	writeFileSync(join(dir, "report.md"), formatMarkdown(manifest));
	return dir;
}

function printHelp() {
	console.log(`Usage: node scripts/reverse-agent/autonomy-control-plane.mjs [root] [--json] [--write] [--strict]\n\nStatic REPI organization-control audit. It does not run real-platform benchmarks, provider/model calls, or live network tests.`);
}

function main(argv) {
	if (argv.includes("--help") || argv.includes("-h")) {
		printHelp();
		return;
	}
	const json = argv.includes("--json");
	const write = argv.includes("--write");
	const strict = argv.includes("--strict");
	const rootArg = argv.find((arg) => !arg.startsWith("-"));
	const root = resolve(rootArg ?? process.cwd());
	const manifest = buildManifest(root);
	if (write) manifest.artifactDir = writeManifest(root, manifest);
	if (json) console.log(JSON.stringify(manifest, null, 2));
	else process.stdout.write(formatMarkdown(manifest));
	if (strict && !manifest.normalUseGuarantee) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	main(process.argv.slice(2));
}

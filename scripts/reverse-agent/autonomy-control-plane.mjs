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
		"hardeningGapLedger",
		"AutonomousHardeningGapLedgerV1",
		"AutonomousClosureReadinessGateV1",
		"autonomous_closure_readiness_gate",
		"gate:autonomous-closure-readiness",
		"CapabilityClaimReleaseBundleGateV1",
		"capability_claim_release_bundle_gate",
		"gate:capability-release-bundle",
		"ReleaseCiPipelineGateV1",
		"release_ci_pipeline_gate",
		"gate:release-ci-pipeline",
		"ReleaseEvidenceIndexGateV1",
		"release_evidence_index_gate",
		"gate:release-evidence-index",
		"closureGate",
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
		id: "MultiCompactPressureGateV1",
		pillar: "long_context_compaction",
		title: "multi-compact exact resume pressure gate",
		description: "多轮 compact/resume 压力必须证明 explicit contextPath 优先于 latest fallback，幂等 replay 不污染 ledger，scope/artifact drift 负例阻断，并把 operator/proof-loop 恢复反写 CompactResumeLedgerV2。",
		requiredFields: [
			"kind",
			"schemaVersion",
			"generatedAt",
			"MultiCompactPressureGateV1",
			"requiredGates",
			"runtimeCycles",
			"negativeCases",
			"operatorProofWriteback",
		],
		nestedRequired: {
			runtimeCycles: ["id", "packTarget", "resumeTarget", "expectedTransitions", "mustEmbedCompactResumeLedgerV2"],
			negativeCases: ["id", "expect", "mustNotPromote"],
			operatorProofWriteback: ["requiresSessionCompactHook", "requiresOperatorDispatch", "requiresProofLoopRun", "requiresCompactResumeTelemetryTransition"],
		},
		enumFields: {
			requiredGates: ["MultiCompactPressureGateV1", "multi_compact_append_only_pressure", "old_context_path_over_latest_fallback", "operator_proof_loop_compact_writeback"],
			"negativeCases.id": ["target-unresolved", "latest-fallback-without-explicit-ref", "scope-mismatch", "artifact-drift", "budget-exhausted"],
		},
		invariants: [
			"multi_compact_append_only_pressure",
			"old_context_path_over_latest_fallback",
			"duplicate_resume_idempotency_replay",
			"auto_resume_budget_exhaustion_pressure",
			"scope_artifact_drift_negative_cases",
			"operator_proof_loop_compact_writeback",
		],
		schemaPath: "schemas/reverse-agent/multi-compact-pressure.schema.json",
		runtimeIntegration: "bounded-offline-hard-eval",
	},
	{
		id: "CrossSessionMultiCompactMatrixGateV1",
		pillar: "long_context_compaction",
		title: "cross-session multi-compact provider continuation matrix",
		description: "同一个矩阵必须证明至少五轮 compact/resume 跨 session 精确恢复、旧 contextPath 优先 latest fallback、contextSha256/artifact hash 校验、multi-provider 与 remote provider continuation sample matrix、operator/proof-loop budget closure、CompactResumeLedgerV2 terminal row 不重开和 compact_resume_ledger_cycle_terminal_alignment 每周期 terminal 对齐。",
		requiredFields: [
			"kind",
			"schemaVersion",
			"generatedAt",
			"CrossSessionMultiCompactMatrixGateV1",
			"requiredGates",
			"matrix",
			"negativeCases",
			"invariants",
		],
		nestedRequired: {
			matrix: ["kind", "schemaVersion", "closureGate", "sessions", "compactCycles", "providerContinuations", "providerContinuationMatrix", "remoteProviderContinuationSampleMatrix", "operatorProofClosures", "compactResumeLedger"],
			compactCycles: ["cycleId", "sourceSessionId", "resumeSessionId", "contextPath", "contextSha256", "artifactHashes", "latestFallbackCandidate", "explicitContextPathUsed"],
			providerContinuations: ["cycleId", "resumeSessionId", "providerName", "modelId", "apiStyle", "apiKeyEnvRefOnly", "continuationAfterExactResume", "requestLogPath", "stdoutPath", "stderrPath"],
			providerContinuationMatrix: ["kind", "providerCount", "apiStyles", "modelIds", "cycleIds", "allAfterExactResume", "envRefOnly", "requestLogHashes"],
			remoteProviderContinuationSampleMatrix: ["kind", "sampleCount", "providerCount", "apiStyles", "samples", "allAfterExactResume", "envRefOnly", "secretFree", "noPiPollution"],
			operatorProofClosures: ["cycleId", "operatorStatus", "proofLoopStatus", "budget", "proofLoopEntered", "terminalReopened"],
			compactResumeLedger: ["kind", "transitionPath", "appendOnly", "hashChainOk", "terminalRowsNotReopened", "cycleTerminalAlignmentOk", "ledgerCycleAlignment", "transitions"],
			negativeCases: ["id", "mutates", "expect", "mustNotPromote"],
		},
		enumFields: {
			requiredGates: [
				"CrossSessionMultiCompactMatrixGateV1",
				"cross_session_multi_compact_same_run",
				"old_context_path_over_latest_after_multiple_compacts",
				"context_sha_artifact_hashes_verified_across_sessions",
				"provider_continuation_after_exact_resume",
				"provider_continuation_matrix_multi_provider",
				"longer_cross_session_compaction_chain",
				"five_cycle_cross_session_compaction_chain",
				"remote_provider_continuation_sample_matrix",
				"operator_proof_loop_budget_closure",
				"terminal_resume_rows_not_reopened",
				"compact_resume_ledger_cycle_terminal_alignment",
				"compact_resume_ledger_v2_hash_chain_quality",
			],
			"compactCycles.loadedBy": ["contextPath"],
			"operatorProofClosures.proofLoopStatus": ["done", "blocked", "exhausted"],
			"negativeCases.id": [
				"latest-fallback-without-explicit-context",
				"context-sha-drift",
				"artifact-hash-drift",
				"provider-continuation-missing",
				"budget-exhausted-open",
				"terminal-row-reopened",
				"same-session-only",
				"ledger-hash-chain-drift",
				"provider-continuation-single-provider",
				"compact-chain-too-short",
				"provider-continuation-before-exact-resume",
				"five-cycle-chain-too-short",
				"ledger-terminal-missing-after-rehash",
				"remote-provider-sample-missing",
				"remote-provider-secret-leak",
			],
		},
		invariants: [
			"cross_session_multi_compact_matrix_gate",
			"cross_session_multi_compact_same_run",
			"old_context_path_over_latest_after_multiple_compacts",
			"context_sha_artifact_hashes_verified_across_sessions",
			"provider_continuation_after_exact_resume",
			"provider_continuation_matrix_multi_provider",
			"longer_cross_session_compaction_chain",
			"five_cycle_cross_session_compaction_chain",
			"remote_provider_continuation_sample_matrix",
			"operator_proof_loop_budget_closure",
			"terminal_resume_rows_not_reopened",
			"compact_resume_ledger_cycle_terminal_alignment",
			"compact_resume_ledger_v2_hash_chain_quality",
		],
		schemaPath: "schemas/reverse-agent/cross-session-multi-compact-matrix.schema.json",
		runtimeIntegration: "bounded-cross-session-matrix-gate-wired",
	},
	{
		id: "LatestArtifactConsumerScopeGateV1",
		pillar: "memory_scope_isolation",
		title: "latest artifact consumer scope pressure gate",
		description: "latest_artifact_consumer_scope_gate 要证明 operator feedback、proof-loop gap/evidence/source、compiler claim gate 等 latest artifact consumer 都继承 target scope，不能把其它 target 的较新 artifact 当成当前任务证据。",
		requiredFields: [
			"kind",
			"schemaVersion",
			"generatedAt",
			"LatestArtifactConsumerScopeGateV1",
			"requiredGates",
			"scenarios",
		],
		nestedRequired: {
			scenarios: ["id", "consumer", "mustSelectSameTargetOlderArtifact", "mustBlockCrossTargetLatestArtifact"],
		},
		enumFields: {
			requiredGates: [
				"LatestArtifactConsumerScopeGateV1",
				"operator_feedback_latest_artifact_consumer",
				"proof_loop_gap_latest_artifact_consumer",
				"proof_loop_evidence_latest_artifact_consumer",
				"proof_loop_source_latest_artifact_consumer",
				"compiler_claim_gate_latest_artifact_consumer",
				"cross_target_latest_artifact_blocked",
				"same_target_older_artifact_selected",
			],
			"scenarios.consumer": ["operator-feedback", "proof-loop-gap", "proof-loop-evidence", "proof-loop-source", "compiler-claim-gate"],
		},
		invariants: [
			"latest_artifact_consumer_scope_gate",
			"operator_feedback_latest_artifact_consumer",
			"proof_loop_gap_latest_artifact_consumer",
			"proof_loop_evidence_latest_artifact_consumer",
			"proof_loop_source_latest_artifact_consumer",
			"compiler_claim_gate_latest_artifact_consumer",
			"cross_target_latest_artifact_blocked",
			"same_target_older_artifact_selected",
		],
		schemaPath: "schemas/reverse-agent/latest-artifact-consumer-scope.schema.json",
		runtimeIntegration: "bounded-offline-hard-eval",
	},
	{
		id: "FailureSignaturePriorityGateV1",
		pillar: "failure_self_repair",
		title: "failure signature priority proof-loop / knowledge consumer",
		description: "failure_signature_priority_gate 要证明 runtime failure ledger 与 repair queue 会优先进入 proof-loop 和 knowledge graph：exhausted/repeated signature 先于普通 feedback，缺少 concrete command 的 repair 不算 ready，且按 target scope 隔离。",
		requiredFields: [
			"kind",
			"schemaVersion",
			"FailureSignaturePriorityGateV1",
			"requiredGates",
			"scenarios",
			"invariants",
		],
		nestedRequired: {
			scenarios: ["id", "inputLedger", "expectedProofLoop", "expectedKnowledgeGraph", "mustNotContain"],
			inputLedger: ["target", "failureStatuses", "repairQueueCommands"],
		},
		enumFields: {
			requiredGates: [
				"FailureSignaturePriorityGateV1",
				"proof_loop_failure_signature_priority",
				"knowledge_graph_failure_signature_priority",
				"runtime_failure_ledger_preempts_blind_retry",
				"repair_queue_ready_command_required",
				"target_scoped_failure_signature_priority",
			],
			"scenarios.id": [
				"exhausted-failure-preempts-operator-feedback",
				"repeated-failure-promotes-repair-command",
				"unrelated-target-failure-does-not-leak",
				"missing-repair-command-is-not-ready",
			],
		},
		invariants: [
			"failure_signature_priority_gate",
			"proof_loop_failure_signature_priority",
			"knowledge_graph_failure_signature_priority",
			"runtime_failure_ledger_preempts_blind_retry",
			"repair_queue_ready_command_required",
			"target_scoped_failure_signature_priority",
		],
		schemaPath: "schemas/reverse-agent/failure-signature-priority.schema.json",
		runtimeIntegration: "bounded-offline-hard-eval",
	},
	{
		id: "AgentDogfoodFailureSignatureBindingGateV1",
		pillar: "failure_self_repair",
		title: "agent-dogfood runtime manifest failure signature binding",
		description: "agent-dogfood 子代理失败不能只落在 summary；每个失败 role/synthesizer 的 runtime manifest、failure ledger、repair queue、claim ledger event 和 retry/dedupe window 必须绑定同一 signature。",
		requiredFields: [
			"kind",
			"schemaVersion",
			"AgentDogfoodFailureSignatureBindingGateV1",
			"requiredGates",
			"binding",
			"negativeCases",
			"invariants",
		],
		nestedRequired: {
			binding: ["roleId", "runtimeManifestFile", "failureId", "repairId", "signature", "retryBudget", "dedupeWindow"],
			retryBudget: ["retryKey", "remainingAttempts", "exhaustedAction"],
			dedupeWindow: ["source", "roleId", "mergeKeys", "attemptCount", "retryKey"],
			negativeCases: ["id", "mutates", "expect", "mustNotPromote"],
		},
		enumFields: {
			requiredGates: [
				"AgentDogfoodFailureSignatureBindingGateV1",
				"subagent_runtime_manifest_failure_signature_binding",
				"failure_retry_budget_signature_consistency",
				"repair_queue_item_signature_consistency",
				"claim_ledger_events_carry_failure_signature_binding",
				"dedupe_window_role_scoped_retry_key",
				"runtime_manifest_index_lists_failure_signature_bindings",
				"exhausted_retry_budget_remaining_zero",
			],
			"negativeCases.id": [
				"missing-binding-in-runtime-manifest",
				"retry-budget-retry-key-mismatch",
				"failure-signature-mismatch",
				"missing-runtime-manifest-file",
				"duplicate-role-dedupe-window-mismatch",
			],
		},
		invariants: [
			"agent_dogfood_failure_signature_binding_gate",
			"subagent_runtime_manifest_failure_signature_binding",
			"failure_retry_budget_signature_consistency",
			"repair_queue_item_signature_consistency",
			"claim_ledger_events_carry_failure_signature_binding",
			"dedupe_window_role_scoped_retry_key",
			"runtime_manifest_index_lists_failure_signature_bindings",
			"exhausted_retry_budget_remaining_zero",
		],
		schemaPath: "schemas/reverse-agent/agent-dogfood-failure-signature-binding.schema.json",
		runtimeIntegration: "agent-dogfood-runtime-wired",
	},
	{
		id: "WorkerProviderRepairRollbackUnificationGateV1",
		pillar: "failure_self_repair",
		title: "provider/worker repair rollback unification",
		description: "provider-worker、re_swarm worker、compound-frontier 与 operator repair 必须共享 FailureLedgerEventV1/RepairQueueItemV1 signature、RepairRollbackPolicyV1、retry window closure、regression gate refs、provider-worker live repair matrix、state lineage snapshot matrix、RemoteProviderStateChangingRepairMatrixV1 与 DeepCompoundProviderRepairCompletionChainV1。",
		requiredFields: [
			"kind",
			"schemaVersion",
			"generatedAt",
			"WorkerProviderRepairRollbackUnificationGateV1",
			"requiredGates",
			"unificationReport",
			"negativeCases",
			"invariants",
		],
		nestedRequired: {
			unificationReport: ["kind", "schemaVersion", "closureGate", "scenarios", "liveRepairMatrix", "retryWindowCompletionChain", "stateLineageSnapshotMatrix", "longHorizonRepairCompletionChain", "remoteProviderStateChangingRepairMatrix", "deepCompoundProviderRepairCompletionChain", "signatureIndex", "promotionPolicy"],
			scenarios: ["id", "source", "workerId", "runtimeRefs", "failureLedgerEvent", "repairQueueItem", "rollbackPolicy", "retryWindow", "regressionGateRefs"],
			liveRepairMatrix: ["kind", "providerCount", "apiStyles", "stateChangingRepairCount", "rows", "allRollbackPolicyBound", "allRequestLogsBound", "allRegressionRefsMatched"],
			retryWindowCompletionChain: ["kind", "minAttemptCount", "chains", "allClosed", "allMonotonic", "allSameSignature", "allRegressionProofsPresent"],
			stateLineageSnapshotMatrix: ["kind", "rowCount", "providerCount", "apiStyles", "rows", "allBaselineCaptured", "allRollbackRestoredBaseline"],
			longHorizonRepairCompletionChain: ["kind", "minAttemptCount", "longestAttemptCount", "chains", "includesProviderWorker", "includesCompoundFrontier", "allSameSignature"],
			remoteProviderStateChangingRepairMatrix: ["kind", "matrixId", "rowCount", "providerCount", "apiStyles", "rows", "allRemoteProviderBacked", "allRuntimeRefsBound", "secretFree"],
			deepCompoundProviderRepairCompletionChain: ["kind", "chainId", "minAttemptCount", "longestAttemptCount", "totalAttemptCount", "chains", "allSameSignature", "allRuntimeRefsBound"],
			runtimeRefs: ["runtimeManifestFile", "requestLogFile", "rollbackPolicyFile", "regressionResultFile"],
			retryWindow: ["signature", "closed", "attempts"],
			negativeCases: ["id", "mutates", "expect", "mustNotPromote"],
		},
		enumFields: {
			requiredGates: [
				"WorkerProviderRepairRollbackUnificationGateV1",
				"same_signature_failure_repair_rollback_regression",
				"provider_worker_state_change_writes_rollback_policy",
				"exhausted_failure_blocks_unpaused_rerun",
				"provider_worker_refs_preserve_manifest_request_log_rollback",
				"compound_provider_retry_window_closes_same_signature",
				"regression_gate_refs_match_repair_queue",
				"provider_worker_live_state_change_repair_matrix",
				"multi_attempt_retry_window_completion_chain",
				"provider_worker_state_lineage_snapshot_matrix",
				"compound_provider_long_horizon_repair_completion_chain",
				"remote_provider_state_changing_repair_matrix",
				"deep_compound_provider_repair_completion_chain",
			],
			"scenarios.id": ["provider-worker-state-change", "swarm-worker-provider-repair", "provider-worker-cache-state-repair", "swarm-worker-tool-state-repair", "provider-worker-token-state-repair", "remote-provider-config-state-repair", "compound-frontier-retry-window", "compound-provider-long-horizon-repair", "compound-provider-deep-repair", "operator-exhausted-escalation"],
			"negativeCases.id": [
				"signature-mismatch",
				"missing-rollback-policy",
				"exhausted-unpaused-rerun",
				"missing-provider-request-log-ref",
				"regression-gate-mismatch",
				"policy-failure-repair-unlinked",
				"live-repair-matrix-missing-provider",
				"retry-window-not-monotonic",
				"completion-without-regression-proof",
				"state-lineage-missing-baseline",
				"long-horizon-chain-too-short",
				"long-horizon-signature-drift",
				"remote-state-repair-matrix-too-narrow",
				"deep-compound-chain-too-short",
				"remote-state-repair-secret-leak",
			],
		},
		invariants: [
			"worker_provider_repair_rollback_unification_gate",
			"same_signature_failure_repair_rollback_regression",
			"provider_worker_state_change_writes_rollback_policy",
			"exhausted_failure_blocks_unpaused_rerun",
			"provider_worker_refs_preserve_manifest_request_log_rollback",
			"compound_provider_retry_window_closes_same_signature",
			"regression_gate_refs_match_repair_queue",
			"provider_worker_live_state_change_repair_matrix",
			"multi_attempt_retry_window_completion_chain",
			"provider_worker_state_lineage_snapshot_matrix",
			"compound_provider_long_horizon_repair_completion_chain",
			"remote_provider_state_changing_repair_matrix",
			"deep_compound_provider_repair_completion_chain",
		],
		schemaPath: "schemas/reverse-agent/worker-provider-repair-rollback-unification.schema.json",
		runtimeIntegration: "bounded-offline-unification-gate-wired",
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
		id: "LiveConflictArbitrationMatrixGateV1",
		pillar: "automatic_division_validation",
		title: "cross-runtime live conflict arbitration matrix",
		description: "agent-dogfood、re_swarm、compound-frontier 和 provider-worker 的 claim 必须进入同一个 live conflict arbitration matrix：覆盖 source manifests、runtime claim ledger refs、winner evidence、loser downgrade、provider-backed same-window/long-window multi-worker conflict matrix、extended synthesizer topic parsing 和 orchestration/platform claim split。",
		requiredFields: [
			"kind",
			"schemaVersion",
			"generatedAt",
			"LiveConflictArbitrationMatrixGateV1",
			"requiredGates",
			"arbitrationMatrix",
			"negativeCases",
			"invariants",
		],
		nestedRequired: {
			arbitrationMatrix: ["kind", "schemaVersion", "closureGate", "sources", "claimRows", "conflictRows", "providerBackedConflictTable", "providerBackedLongWindowConflictMatrix", "promotionGate", "synthesizerRows", "synthesizerTopicParseMatrix", "extendedSynthesizerTopicParseMatrix"],
			sources: ["sourceKind", "runtimeManifestPath", "structuredClaimMergePath", "claimLedgerPath", "claimLedgerQuality"],
			claimRows: ["claimId", "workerId", "sourceKind", "mergeKey", "status", "artifactRefs", "orchestrationStatus", "platformClaimStatus"],
			conflictRows: ["conflictId", "topic", "claimIds", "winnerClaimId", "winningEvidenceRefs", "loserDowngrades", "resolutionReason", "runtimeLedgerRefs"],
			providerBackedConflictTable: ["kind", "tableId", "windowId", "sameWindow", "providerWorkerIds", "winnerClaimId", "loserClaimIds", "providerRuntimeManifestRefs", "requestLogRefs"],
			providerBackedLongWindowConflictMatrix: ["kind", "matrixId", "windowCount", "minProviderWorkersPerWindow", "providerBackedClaimCount", "secretHandling", "windows"],
			promotionGate: ["mode", "finalClaims", "blockedClaims", "policies"],
			synthesizerTopicParseMatrix: ["kind", "parseId", "longRunWindowIds", "topicRows", "narrativeOnlyBlockedRows"],
			extendedSynthesizerTopicParseMatrix: ["kind", "parseId", "baseParseId", "minTopicRows", "longRunWindowIds", "topicRows", "narrativeOnlyBlockedRows", "conflictsCovered", "parserCoverage"],
			negativeCases: ["id", "mutates", "expect", "mustNotPromote"],
		},
		enumFields: {
			requiredGates: [
				"LiveConflictArbitrationMatrixGateV1",
				"source_coverage_all_runtimes",
				"multi_claim_topic_conflict_matrix",
				"winner_evidence_json_query_verifier",
				"loser_downgrade_blocks_promotion",
				"orchestration_success_separate_from_platform_claim",
				"synthesizer_summary_parsed_to_structured_rows",
				"claim_ledger_refs_hash_chain_quality",
				"provider_backed_same_window_multi_worker_conflict_table",
				"long_run_synthesizer_topic_parse_matrix",
				"provider_backed_long_window_conflict_matrix",
				"synthesizer_extended_topic_parse_matrix",
			],
			"sources.sourceKind": ["agent-dogfood", "re_swarm", "compound-frontier", "provider-worker"],
			"negativeCases.id": [
				"missing-winner-evidence",
				"loser-promoted",
				"orchestration-implies-platform-pass",
				"missing-source-coverage",
				"narrative-only-synthesizer-promoted",
				"claim-ledger-ref-missing",
				"unresolved-conflict",
				"final-without-json-query",
				"provider-backed-conflict-single-worker",
				"synthesizer-topic-parse-missing",
				"same-window-conflict-without-provider-worker",
				"long-window-conflict-too-short",
				"extended-topic-parse-missing",
				"provider-window-secret-leak",
			],
		},
		invariants: [
			"live_conflict_arbitration_matrix_gate",
			"source_coverage_all_runtimes",
			"multi_claim_topic_conflict_matrix",
			"winner_evidence_json_query_verifier",
			"loser_downgrade_blocks_promotion",
			"orchestration_success_separate_from_platform_claim",
			"synthesizer_summary_parsed_to_structured_rows",
			"claim_ledger_refs_hash_chain_quality",
			"provider_backed_same_window_multi_worker_conflict_table",
			"long_run_synthesizer_topic_parse_matrix",
			"provider_backed_long_window_conflict_matrix",
			"synthesizer_extended_topic_parse_matrix",
		],
		schemaPath: "schemas/reverse-agent/live-conflict-arbitration-matrix.schema.json",
		runtimeIntegration: "bounded-cross-runtime-matrix-gate-wired",
	},
	{
		id: "AgentDogfoodStructuredClaimMergeGateV1",
		pillar: "automatic_division_validation",
		title: "agent-dogfood structured claim promotion boundary",
		description: "agent-dogfood worker/synthesizer 文本只能先进入 observation；只有绑定 runtime manifest artifact sha256、JSON query、verifier pass 且无 unresolved challenge 的 claim 才能进入 final promotion。",
		requiredFields: [
			"kind",
			"schemaVersion",
			"AgentDogfoodStructuredClaimMergeGateV1",
			"requiredGates",
			"structuredClaimMerge",
			"negativeCases",
			"invariants",
		],
		nestedRequired: {
			structuredClaimMerge: ["kind", "schemaVersion", "mergeId", "sourcePoolId", "claimRows", "conflictTable", "promotionGate"],
			claimRows: ["claimId", "workerId", "mergeKey", "status", "artifactRefs", "challenges", "promotionBoundary"],
			artifactRefs: ["artifactId", "path", "sha256", "jsonQuery", "op", "expected", "verifierPass"],
			promotionGate: ["mode", "requiredStatuses", "finalClaims", "blockedClaims", "policies"],
			negativeCases: ["id", "mutates", "expect", "mustNotPromote"],
		},
		enumFields: {
			requiredGates: [
				"AgentDogfoodStructuredClaimMergeGateV1",
				"agent_dogfood_structured_claim_merge",
				"narrative_only_observation_never_promotes",
				"final_pass_requires_json_query",
				"final_pass_requires_verifier",
				"unresolved_challenge_blocks_final",
				"claim_ledger_events_reference_structured_claims",
				"runtime_manifest_artifact_ref_required",
			],
			"negativeCases.id": [
				"narrative-only-final-pass",
				"missing-json-query",
				"verifier-false-final-pass",
				"unresolved-challenge-final-pass",
				"missing-runtime-manifest-artifact-ref",
			],
		},
		invariants: [
			"agent_dogfood_structured_claim_merge_gate",
			"agent_dogfood_structured_claim_merge",
			"narrative_only_observation_never_promotes",
			"final_pass_requires_json_query",
			"final_pass_requires_verifier",
			"unresolved_challenge_blocks_final",
			"claim_ledger_events_reference_structured_claims",
			"runtime_manifest_artifact_ref_required",
		],
		schemaPath: "schemas/reverse-agent/agent-dogfood-structured-claims.schema.json",
		runtimeIntegration: "agent-dogfood-runtime-wired",
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
		id: "SwarmProviderManifestParityGateV1",
		pillar: "parallel_scheduling",
		title: "re_swarm/provider worker manifest parity",
		description: "re_swarm command-level manifests、WorkerChildSessionRuntimeBatchV1 和 ParallelProviderWorkerMatrixV1 必须在 workerId、claimRefs、hash、provider env-ref、failure/repair refs 上保持同源；all_child_sessions_match_parity_rows 要求每个 child session 逐 worker 绑定 parityRows，并覆盖 live provider-backed shared ledger matrix、ProviderBackedLongWindowSharedMergeLedgerV1 与 ProviderWorkerExtendedRetryManifestChainV1。",
		requiredFields: [
			"kind",
			"schemaVersion",
			"SwarmProviderManifestParityGateV1",
			"requiredGates",
			"parityReport",
			"childSession",
			"negativeCases",
			"invariants",
		],
		nestedRequired: {
			parityReport: ["kind", "schemaVersion", "source", "parityRows", "promotionPolicy", "closureGate", "sharedMergeLedger", "retryRepairBindings", "liveProviderBackedSharedLedgerMatrix", "retryWindowManifestBindingChain", "providerBackedLongWindowSharedMergeLedger", "providerWorkerExtendedRetryManifestChain"],
			parityRows: ["workerId", "runtimeManifestFile", "sessionDir", "providerName", "modelId", "claimRefs", "mergeKey", "hashes", "failureRepairRefs", "parityChecks", "promotionAllowed"],
			hashes: ["stdoutSha256", "stderrSha256", "transcriptSha256"],
			parityChecks: ["workerIdMatch", "claimRefsPreserved", "hashesPresent", "providerEnvRefsOnly", "failureRepairLinked", "multiProviderSharedLedger", "retryRepairManifestBound"],
			liveProviderBackedSharedLedgerMatrix: ["kind", "windowId", "providerBacked", "providerNames", "workerIds", "claimRefs", "sharedClaimLedgerPath", "hashChain"],
			retryWindowManifestBindingChain: ["kind", "sharedRetryLedgerPath", "hashChain", "retryWindows"],
			providerBackedLongWindowSharedMergeLedger: ["kind", "ledgerId", "providerBacked", "windowCount", "providerNames", "windows", "envRefOnlySecrets", "literalSecretsPresent"],
			providerWorkerExtendedRetryManifestChain: ["kind", "chainId", "sharedRetryLedgerPath", "hashChain", "totalAttemptRows", "retryWindows", "envRefOnlySecrets", "literalSecretsPresent"],
			childSession: ["kind", "poolBridge", "sessions"],
			childSessionSessions: ["workerId", "provider", "runtime", "hashes", "poolBridge", "failureRepairRefs"],
			negativeCases: ["id", "mutates", "expect", "mustNotPromote"],
		},
		enumFields: {
			requiredGates: [
				"SwarmProviderManifestParityGateV1",
				"swarm_subagent_manifest_fields_match_provider_worker",
				"child_session_runtime_bridge_matches_provider_worker",
				"all_child_sessions_match_parity_rows",
				"claim_refs_preserved_across_manifest_provider_merge",
				"failure_repair_refs_preserved_across_provider_worker",
				"multi_provider_workers_share_claim_failure_merge_ledger",
				"provider_worker_retry_repair_rows_bound_to_worker_manifest",
				"live_provider_backed_multi_provider_shared_ledger_matrix",
				"provider_worker_retry_window_manifest_binding_chain",
				"provider_backed_long_window_shared_merge_ledger",
				"provider_worker_extended_retry_manifest_chain",
				"provider_env_refs_only",
				"runtime_artifacts_have_hashes",
				"narrative_only_provider_worker_not_promoted",
			],
			"negativeCases.id": ["worker-id-mismatch", "claim-ref-dropped", "missing-runtime-hash", "literal-provider-secret", "failure-repair-unlinked", "single-provider-matrix", "shared-ledger-worker-missing", "retry-repair-manifest-unbound", "shared-ledger-window-provider-missing", "retry-window-nonmonotonic", "retry-window-manifest-drift", "child-session-nonfirst-row-drift", "long-shared-ledger-window-too-short", "extended-retry-chain-too-short", "long-shared-ledger-secret-leak"],
		},
		invariants: [
			"swarm_provider_manifest_parity_gate",
			"swarm_subagent_manifest_fields_match_provider_worker",
			"child_session_runtime_bridge_matches_provider_worker",
			"all_child_sessions_match_parity_rows",
			"claim_refs_preserved_across_manifest_provider_merge",
			"failure_repair_refs_preserved_across_provider_worker",
			"multi_provider_workers_share_claim_failure_merge_ledger",
			"provider_worker_retry_repair_rows_bound_to_worker_manifest",
			"live_provider_backed_multi_provider_shared_ledger_matrix",
			"provider_worker_retry_window_manifest_binding_chain",
			"provider_backed_long_window_shared_merge_ledger",
			"provider_worker_extended_retry_manifest_chain",
			"provider_env_refs_only",
			"runtime_artifacts_have_hashes",
			"narrative_only_provider_worker_not_promoted",
		],
		schemaPath: "schemas/reverse-agent/swarm-provider-manifest-parity.schema.json",
		runtimeIntegration: "bounded-parity-gate-wired",
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
				id: "autonomous_closure_readiness_gate",
				description: "AutonomousClosureReadinessGateV1 汇总验证 AutonomousHardeningGapLedgerV1 中每个 closureGate 都具备 package script、gate script、top harness child gate、autonomy contract、docs 和 strict --no-write 通过证据。",
				files: ["scripts/reverse-agent/autonomous-closure-readiness-gate.mjs"],
				markers: [
					"AutonomousClosureReadinessGateV1",
					"autonomous_closure_readiness_gate",
					"runtime:closure-readiness-matrix",
					"runtime:all-closure-gates-strict-no-write",
					"closure_gate_strict_no_write_passes",
					"top_autonomous_false_until_closed",
					"fixture:negative-readiness",
				],
			},
			{
				id: "capability_claim_release_bundle_gate",
				description: "CapabilityClaimReleaseBundleGateV1 把 release-facing 能力声明绑定到 product boundary、autonomy control plane、closure readiness、source hashes 和 command evidence，阻断 narrative-only promotion。",
				files: ["scripts/reverse-agent/capability-release-bundle-gate.mjs"],
				markers: [
					"CapabilityClaimReleaseBundleGateV1",
					"capability_claim_release_bundle_gate",
					"runtime:capability-claim-release-bundle",
					"runtime:no-narrative-only-release-promotion",
					"release_claims_require_command_evidence",
					"no_narrative_only_release_promotion",
					"claim-without-command-evidence",
				],
			},
			{
				id: "release_ci_pipeline_gate",
				description: "ReleaseCiPipelineGateV1 校验 GitHub Actions release CI 与 docs 模板显式运行 product boundary、closure readiness、capability release bundle、top harness、repo check 和 no-diff，且不依赖 live provider secrets。",
				files: ["scripts/reverse-agent/release-ci-pipeline-gate.mjs"],
				markers: [
					"ReleaseCiPipelineGateV1",
					"release_ci_pipeline_gate",
					"runtime:release-ci-pipeline",
					"runtime:ci-no-live-secret-dependency",
					"product_boundary_before_capability_claim",
					"ci_no_live_provider_or_secret_dependency",
					"gate:capability-release-bundle",
				],
			},
			{
				id: "release_evidence_index_gate",
				description: "ReleaseEvidenceIndexGateV1 将 autonomy、closure readiness、capability bundle、release CI pipeline、source hashes 和 command outputs 汇总成 secret-free hash-chain release evidence index。",
				files: ["scripts/reverse-agent/release-evidence-index-gate.mjs"],
				markers: [
					"ReleaseEvidenceIndexGateV1",
					"release_evidence_index_gate",
					"runtime:release-evidence-index",
					"runtime:release-evidence-index-hash-chain",
					"release_evidence_index_links_capability_bundle",
					"release_evidence_index_hash_chain_valid",
					"missing-capability-bundle-ref",
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
			{
				id: "worker_lease_scheduler_gate",
				description: "WorkerLeaseSchedulerV1 从 hard-eval 推进到 re_swarm live artifact wiring，覆盖 workerLeaseSchedulerPath、lease exclusive、heartbeat、stale lease recovery、work stealing、duplicate completion rejection 和 claim ref preservation。",
				files: ["scripts/reverse-agent/worker-lease-scheduler-gate.mjs", "packages/coding-agent/src/core/recon-profile.ts"],
				markers: [
					"WorkerLeaseSchedulerV1",
					"WorkerLeaseSchedulerEventV1",
					"stale lease recovery",
					"runtime:worker-lease-scheduler-validation",
					"runtime:worker-lease-stale-recovery",
					"runtime:worker-lease-scheduler-live-wiring",
					"workerLeaseSchedulerPath",
					"workerLeaseSchedulerStatus",
					"duplicate_completion_rejected",
				],
			},
			{
				id: "worker_child_session_runtime_contract_gate",
				description: "WorkerChildSessionRuntimeBatchV1 hard-eval 把 worker pool 推进到独立 REPI child session/provider runtime 合同。",
				files: ["scripts/reverse-agent/worker-child-session-gate.mjs", "fixtures/reverse-agent/worker-child-session.fixture.json"],
				markers: [
					"WorkerChildSessionRuntimeBatchV1",
					"WorkerChildProcessProbeV1",
					"isolated_home_invalid",
					"secret_allowed",
					"apiKeyRef_not_env_ref",
					"timeout_without_cancel",
					"childSessionRuntimeCaptured",
				],
			},
			{
				id: "worker_provider_child_process_probe_gate",
				description: "WorkerProviderChildProcessProbeV1 通过本地 mock OpenAI-compatible provider 真实启动 repi print-mode 子进程，验证 env-ref-only API key、request capture 和脱敏 transcript。",
				files: ["scripts/reverse-agent/worker-child-session-gate.mjs"],
				markers: [
					"WorkerProviderChildProcessProbeV1",
					"runtime:worker-provider-child-process-smoke",
					"runtime:worker-provider-env-ref-only",
					"runtime:worker-provider-request-captured",
					"/v1/chat/completions",
					"apiKeyEnvRefOnly",
					"authorizationFromEnv",
				],
			},
			{
				id: "provider_runtime_matrix_core_contract",
				description: "ProviderRuntimeMatrixV1 / ProviderRuntimeMatrixCaseV1 在核心 profile 中有可机读合同和 verifier。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: ["type ProviderRuntimeMatrixV1", "type ProviderRuntimeMatrixCaseV1", "function verifyProviderRuntimeMatrixV1", "provider_matrix_api_key_not_env_ref"],
			},
			{
				id: "provider_runtime_matrix_gate",
				description: "ProviderRuntimeMatrixV1 hard-eval 覆盖 OpenAI Chat Completions-compatible、OpenAI Responses-compatible 与 Anthropic-compatible 三类主流自定义 provider，验证 list-models、env-ref-only、streaming request、transcript/request-log 和无 Pi 污染。",
				files: ["scripts/reverse-agent/provider-runtime-matrix-gate.mjs"],
				markers: [
					"ProviderRuntimeMatrixV1",
					"runtime:provider-matrix-openai-completions",
					"runtime:provider-matrix-openai-responses",
					"runtime:provider-matrix-anthropic-messages",
					"runtime:provider-matrix-env-ref-only",
					"negative:missing-env-ref",
					"negative:wrong-endpoint",
				],
			},
			{
				id: "provider_runtime_matrix_npm_gate",
				description: "package 暴露 gate:provider-runtime-matrix，供顶级 harness 与 CI 调用。",
				files: ["package.json"],
				markers: ["gate:provider-runtime-matrix", "provider-runtime-matrix-gate.mjs"],
			},
			{
				id: "provider_endpoint_doctor",
				description: "ProviderEndpointDoctorV1 把自定义网关接入诊断做成 REPI runtime 子命令和 hard-eval：自动探测 OpenAI Chat Completions、OpenAI Responses、Anthropic Messages endpoint，输出 env-ref-only models.json template，并诊断 Responses 404 不静默 fallback。",
				files: ["packages/coding-agent/src/cli/provider-doctor.ts", "scripts/reverse-agent/provider-endpoint-doctor-gate.mjs"],
				markers: [
					"ProviderEndpointDoctorV1",
					"provider-doctor",
					"openai-completions",
					"openai-responses",
					"anthropic-messages",
					"endpoint_not_found",
					"models.json template",
					"runtime:provider-endpoint-doctor-live",
				],
			},
			{
				id: "provider_endpoint_doctor_npm_gate",
				description: "package 暴露 gate:provider-endpoint-doctor，供顶级 harness 与 CI 验证 provider doctor 不泄漏密钥且能给出正确配置建议。",
				files: ["package.json"],
				markers: ["gate:provider-endpoint-doctor", "provider-endpoint-doctor-gate.mjs"],
			},
			{
				id: "toolchain_domain_capability_gate",
				description: "ToolchainDomainCapabilityV1 把专业逆向/渗透工具链能力做成 runtime:toolchain-doctor 与 domain_toolchain_matrix：按 web-api、rev-native、pwn、mobile、pcap-dfir、firmware-iot、crypto、cloud-identity、exploit-reliability 分类输出 present/missing/fallback/proof-exit/next commands，避免能力退化成泛化建议。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "scripts/reverse-agent/toolchain-domain-capability-gate.mjs", "schemas/reverse-agent/toolchain-domain-capability.schema.json"],
				markers: [
					"ToolchainDomainCapabilityV1",
					"runtime:toolchain-doctor",
					"domain_toolchain_matrix",
					"domain:web-api",
					"domain:rev-native",
					"domain:pwn",
					"domain:mobile",
					"domain:pcap-dfir",
					"domain:firmware-iot",
					"fallback_available",
					"critical_gap",
				],
			},
			{
				id: "toolchain_domain_capability_npm_gate",
				description: "package 暴露 gate:toolchain-domain-capability，供顶级 harness 和 CI 验证工具链/领域能力不是文档口号。",
				files: ["package.json"],
				markers: ["gate:toolchain-domain-capability", "toolchain-domain-capability-gate.mjs"],
			},
			{
				id: "toolchain_domain_capability_top_harness_gate",
				description: "top harness 把 ToolchainDomainCapabilityV1 接成 child gate，防止专业工具链层游离于 release harness 外。",
				files: ["scripts/reverse-agent/repi-top-harness.mjs"],
				markers: ["gate:toolchain-domain-capability", "toolchain:domain-capability-hard-eval", "ToolchainDomainCapabilityV1", "child:gate:toolchain-domain-capability"],
			},
			{
				id: "domain_proof_exit_closure_gate",
				description: "DomainProofExitClosureV1 把 ToolchainDomainCapabilityV1 的 proof-exit 接入 completion audit：final 前必须把 offset/leak/local verifier、principal matrix/object ownership/state rollback、crypto known-answer 等专业域退出条件绑定 runtime artifact，否则输出 domain_proof_exit_missing 并回到 operator/proof-loop。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "scripts/reverse-agent/domain-proof-exit-closure-gate.mjs", "schemas/reverse-agent/domain-proof-exit-closure.schema.json"],
				markers: ["DomainProofExitClosureV1", "domain_proof_exit_closure", "domain_proof_exit_missing", "buildDomainProofExitClosure", "re_domain_proof_exit"],
			},
			{
				id: "domain_proof_exit_closure_npm_gate",
				description: "package 暴露 gate:domain-proof-exit-closure，供顶级 harness 和 CI 验证专业 proof-exit 不游离于完成审计之外。",
				files: ["package.json"],
				markers: ["gate:domain-proof-exit-closure", "domain-proof-exit-closure-gate.mjs"],
			},
			{
				id: "domain_proof_exit_closure_top_harness_gate",
				description: "top harness 把 DomainProofExitClosureV1 接成 child gate，防止 completion 只看通用 gates 而忽略专业域 proof-exit。",
				files: ["scripts/reverse-agent/repi-top-harness.mjs"],
				markers: ["gate:domain-proof-exit-closure", "toolchain:domain-proof-exit-closure-hard-eval", "DomainProofExitClosureV1", "child:gate:domain-proof-exit-closure"],
			},
			{
				id: "relane_specialist_command_pack_gate",
				description: "ReLaneSpecialistCommandPackGateV1 把每个专业域的 route → lane seeds → command pack markers → analyzer anchors → self-heal commands → proof-exit bridge 做成可验证闭环，防止 re_lane plan 退化成泛化建议。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "scripts/reverse-agent/relane-specialist-command-pack-gate.mjs", "schemas/reverse-agent/relane-specialist-command-pack.schema.json"],
				markers: ["ReLaneSpecialistCommandPackGateV1", "runtime:re_lane-specialist-command-pack", "route_to_domain_lane_seed_matrix", "domain_lane_command_pack_markers", "specialist_evidence_analyzer_anchor_matrix", "self_heal_command_fallback_matrix", "proof_exit_bridge_matrix", "re_lane_specialist_pack"],
			},
			{
				id: "relane_specialist_command_pack_npm_gate",
				description: "package 暴露 gate:relane-specialist-command-pack，供 top harness/CI 验证专项 command pack 闭环。",
				files: ["package.json"],
				markers: ["gate:relane-specialist-command-pack", "relane-specialist-command-pack-gate.mjs"],
			},
			{
				id: "relane_specialist_command_pack_top_harness_gate",
				description: "top harness 把 ReLaneSpecialistCommandPackGateV1 接成 child gate，防止专业域 command pack/analyzer/self-heal 只存在于源码注释。",
				files: ["scripts/reverse-agent/repi-top-harness.mjs"],
				markers: ["gate:relane-specialist-command-pack", "toolchain:relane-specialist-command-pack-hard-eval", "ReLaneSpecialistCommandPackGateV1", "child:gate:relane-specialist-command-pack"],
			},
			{
				id: "parallel_provider_worker_matrix_core_contract",
				description: "ParallelProviderWorkerMatrixV1 把 provider matrix 提升为多 worker 并发 runtime 合同，绑定 claim-aware provider worker merge、timeout cancel 与 failure/repair。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: [
					"type ParallelProviderWorkerMatrixV1",
					"type ParallelProviderWorkerMatrixWorkerV1",
					"function verifyParallelProviderWorkerMatrixV1",
					"claimAwareProviderWorkerMerge",
					"parallel_provider_worker_matrix_peak_concurrency_lt_2",
				],
			},
			{
				id: "parallel_provider_worker_matrix_gate",
				description: "ParallelProviderWorkerMatrixV1 hard-eval 并发启动多个 repi provider worker，覆盖 OpenAI/Anthropic pass、provider failure repair、timeout cancel、claim-aware merge 和 secret redaction。",
				files: ["scripts/reverse-agent/parallel-provider-worker-matrix-gate.mjs"],
				markers: [
					"ParallelProviderWorkerMatrixV1",
					"runtime:parallel-provider-worker-concurrency",
					"runtime:parallel-provider-worker-openai-pass",
					"runtime:parallel-provider-worker-anthropic-pass",
					"runtime:parallel-provider-worker-failure-repair",
					"runtime:parallel-provider-worker-timeout-cancel",
					"negative:parallel-worker-missing-claim-merge",
				],
			},
			{
				id: "parallel_provider_worker_matrix_npm_gate",
				description: "package 暴露 gate:parallel-provider-worker-matrix，供顶级 harness 与 CI 调用。",
				files: ["package.json"],
				markers: ["gate:parallel-provider-worker-matrix", "parallel-provider-worker-matrix-gate.mjs"],
			},
			{
				id: "swarm_provider_manifest_parity_gate",
				description: "SwarmProviderManifestParityGateV1 将 re_swarm SubagentRuntimeManifestV1、WorkerChildSessionRuntimeBatchV1 与 ParallelProviderWorkerMatrixV1 的 workerId/claimRefs/hash/env-ref/failure-repair refs 做同源校验；all_child_sessions_match_parity_rows 会逐 worker 绑定所有 child sessions 与 parityRows，并覆盖 live provider-backed shared ledger matrix、ProviderBackedLongWindowSharedMergeLedgerV1 与 ProviderWorkerExtendedRetryManifestChainV1。",
				files: ["scripts/reverse-agent/swarm-provider-manifest-parity-gate.mjs", "fixtures/reverse-agent/swarm-provider-manifest-parity.fixture.json"],
				markers: ["SwarmProviderManifestParityGateV1", "fixture:positive-parity", "fixture:negative-parity", "all_child_sessions_match_parity_rows", "child-session-nonfirst-row-drift", "liveProviderBackedSharedLedgerMatrix", "retryWindowManifestBindingChain", "ProviderBackedLongWindowSharedMergeLedgerV1", "ProviderWorkerExtendedRetryManifestChainV1", "worker-id-mismatch", "literal-provider-secret", "failure-repair-unlinked", "multi_provider_workers_share_claim_failure_merge_ledger", "provider_worker_retry_repair_rows_bound_to_worker_manifest", "live_provider_backed_multi_provider_shared_ledger_matrix", "provider_worker_retry_window_manifest_binding_chain", "provider_backed_long_window_shared_merge_ledger", "provider_worker_extended_retry_manifest_chain", "single-provider-matrix", "retry-repair-manifest-unbound", "shared-ledger-window-provider-missing", "retry-window-manifest-drift", "child-session-nonfirst-row-drift", "long-shared-ledger-window-too-short", "extended-retry-chain-too-short", "long-shared-ledger-secret-leak"],
			},
			{
				id: "swarm_provider_manifest_parity_npm_gate",
				description: "package 暴露 gate:swarm-provider-manifest-parity，作为 AutonomousHardeningGapLedgerV1 的 parallel closure gate。",
				files: ["package.json"],
				markers: ["gate:swarm-provider-manifest-parity", "swarm-provider-manifest-parity-gate.mjs"],
			},

			{
				id: "remote_provider_longrun_core_contract",
				description: "RemoteProviderLongRunV1 把真实远程 provider 长跑做成 opt-in 合同：无密钥时可跳过，启用 live 时校验 OpenAI Chat Completions / OpenAI Responses / Anthropic provider 调用、超时、隔离和脱敏。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: [
					"type RemoteProviderLongRunV1",
					"type RemoteProviderLongRunCaseV1",
					"function verifyRemoteProviderLongRunV1",
					"remote_provider_longrun_optional_live_skip",
					"remote_provider_longrun_marker_missing",
					"openai-responses",
				],
			},
			{
				id: "remote_provider_longrun_gate",
				description: "RemoteProviderLongRunV1 hard-eval 默认 skip/pass；传 --live 或 REPI_REMOTE_PROVIDER_LIVE=1 时真实运行远程 provider 多轮长跑，覆盖 openai-completions、openai-responses、anthropic-messages 配置合同，并验证 session/profile 隔离、timeout、env-ref-only 和 failure/repair writeback。",
				files: ["scripts/reverse-agent/remote-provider-longrun-gate.mjs"],
				markers: [
					"RemoteProviderLongRunV1",
					"runtime:remote-provider-longrun-skipped",
					"runtime:remote-provider-longrun-attempts",
					"runtime:remote-provider-longrun-env-redaction",
					"contract:remote-provider-longrun-api-coverage",
					"openai-responses",
					"negative:remote-provider-live-missing-marker",
				],
			},
			{
				id: "remote_provider_longrun_npm_gate",
				description: "package 暴露 gate:remote-provider-longrun；CI 默认不需要真实 provider secret，live 长跑必须显式 opt-in。",
				files: ["package.json"],
				markers: ["gate:remote-provider-longrun", "remote-provider-longrun-gate.mjs"],
			},
			{
				id: "provider_backed_dogfood_gate",
				description: "ProviderBackedDogfoodReleaseGateV1 把 provider-backed agent-dogfood 多 worker 真执行做成 opt-in release quality gate，默认无密钥 skip/pass，live 时阻断 plan-only promoted、单 worker、缺模型调用、缺 synthesizer、缺 runtime claim ledger、non-mock false 和 secret leak。",
				files: ["scripts/reverse-agent/provider-backed-dogfood-gate.mjs"],
				markers: [
					"ProviderBackedDogfoodReleaseGateV1",
					"runtime:provider-backed-dogfood-skipped",
					"validateProviderBackedDogfood",
					"negative:dogfood-plan-only-promoted",
					"negative:dogfood-missing-model-calls",
					"negative:dogfood-nonmock-false",
				],
			},
			{
				id: "provider_backed_dogfood_schema",
				description: "ProviderBackedDogfoodReleaseGateV1 schema 固化非 plan-only、provider-backed、多 worker、synthesizer、model/tool、manifest、claim ledger、non-mock 和 overlap 字段。",
				files: ["schemas/reverse-agent/provider-backed-dogfood.schema.json"],
				markers: ["ProviderBackedDogfoodReleaseGateV1", "planOnlyNotPromoted", "providerBacked", "multiWorker", "runtimeClaimLedgerCaptured"],
			},
			{
				id: "provider_backed_dogfood_fixture",
				description: "Provider-backed dogfood fixture 覆盖 plan-only promoted、single worker、missing model calls、missing synthesizer、missing claim ledger、non-mock false 和 secret leak 负例。",
				files: ["fixtures/reverse-agent/provider-backed-dogfood.fixture.json"],
				markers: ["repi-provider-backed-dogfood-fixture", "negative:dogfood-plan-only-promoted", "negative:dogfood-missing-model-calls", "negative:dogfood-nonmock-false"],
			},
			{
				id: "provider_backed_dogfood_npm_gate",
				description: "package 暴露 gate:provider-backed-dogfood；CI 默认不需要真实 provider secret，live 多 worker dogfood 必须显式 opt-in。",
				files: ["package.json"],
				markers: ["gate:provider-backed-dogfood", "provider-backed-dogfood-gate.mjs"],
			},
			{
				id: "tool_call_trace_ledger_gate",
				description: "ToolCallTraceLedgerV1 给 tool_call/tool_result 建 append-only tool trace，保留输入/输出 hash、脱敏预览、replay hint 和 hash-chain。",
				files: ["scripts/reverse-agent/tool-call-trace-ledger-gate.mjs", "packages/coding-agent/src/core/recon-profile.ts"],
				markers: [
					"ToolCallTraceLedgerV1",
					"ToolCallTraceEventV1",
					"append-only tool trace",
					"runtime:tool-call-trace-ledger-written",
					"runtime:tool-call-trace-secret-redaction",
					"replayable_tool_result_hashes",
				],
			},
			{
				id: "runtime_re_swarm_child_session_bridge",
				description: "re_swarm run 会从 SubagentRuntimeManifestV1 生成 workerChildSessionRuntimePath，并把 WorkerChildSessionRuntimeBatchV1 桥接成 WorkerRuntimePoolV1。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "scripts/reverse-agent/worker-child-session-gate.mjs"],
				markers: [
					"buildWorkerChildSessionRuntimeBatchFromSwarm",
					"workerChildSessionRuntimePath",
					"runWorkerChildProcessProbe",
					"workerRuntimePoolBridgeStatus",
					"childSessionRuntimeCaptured",
					"childProcessRuntimeCaptured",
					"poolValidation",
				],
			},
		],
		hardeningNeeded: [
			"WorkerChildSessionRuntimeBatchV1 已由 re_swarm live bounded probe 生成 runtime artifact 并桥接 WorkerRuntimePoolV1；WorkerProviderChildProcessProbeV1 已覆盖本地 mock OpenAI-compatible provider 子进程回归；ProviderRuntimeMatrixV1 已覆盖 OpenAI Chat Completions-compatible / OpenAI Responses-compatible / Anthropic-compatible 自定义 provider 矩阵，ProviderFailureInjectionReportV1 已把 provider 失败路径接入 FailureLedgerEventV1 / RepairQueueItemV1；ParallelProviderWorkerMatrixV1 已覆盖多 worker 并发 provider pass/failure/timeout/merge；SwarmProviderManifestParityGateV1 已把 re_swarm manifest、child-session runtime 与 provider worker matrix 的 workerId/claimRefs/hash/env-ref/failure-repair refs、all_child_sessions_match_parity_rows 逐 worker child-session parity、live provider-backed shared ledger matrix、ProviderBackedLongWindowSharedMergeLedgerV1 和 ProviderWorkerExtendedRetryManifestChainV1 绑定成 closure gate；RemoteProviderLongRunV1 已接入可选远程 provider 长跑 gate（无 env 默认 skip/pass，live 显式 opt-in，支持 openai-completions / openai-responses / anthropic-messages）。",
			"把 worker merge 从文本摘要升级为 structured claim merge，并在 supervisor 前阻断缺证据或冲突 claim；离线 duplicate mergeKey 负例已由 gate:worker-runtime-pool 保护。",
			"继续让 SwarmProviderManifestParityGateV1 从 bounded parity 扩展到更多真实远程 worker/provider 长窗口场景。",
		],
		recommendedWork: [
			"保持 npm run audit:parallel-plan 作为 frontier --plan 与 dogfood --plan-only 的离线 smoke gate。",
			"保持 gate:claim-release --write-marker 作为 release gate marker，并让 supervisor/compiler/complete 消费最新 marker。",
			"让 agent-dogfood 与 re_swarm 的 sub-agent runtime manifest 继续和 planId/source/worker merge keys、failure signature、childSessionRuntimeCaptured 关联。",
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
						"memory_store_report",
						"memory_injection_packet",
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
				id: "context_runtime_schema_gate",
				description: "真实运行 re_context pack/resume，按 ContextPackV2 / ResumeContractV2 校验 contextSha256、artifactHashes、memory hash contract 和 exact resume closure。",
				files: ["scripts/reverse-agent/context-runtime-schema-gate.mjs"],
				markers: ["repi-context-runtime-schema-gate", "runtime:pack-schema", "runtime:resume-schema", "runtime:memory-hash-contract", "ContextPackV2", "ResumeContractV2"],
			},
			{
				id: "compact_resume_ledger_v2_runtime",
				description: "CompactResumeLedgerV2 把 compact/resume 从单条 ledger 升级为 append-only 状态机：queued/running/done/blocked/exhausted、幂等 replay 和 auto-resume budget。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["CompactResumeLedgerV2", "appendCompactResumeTransition", "buildCompactResumeLedgerV2Report", "append_only_transition_ledger", "idempotent_multi_compact_replay", "auto_resume_budget_enforced", "compact_resume_transition_report_in_context_pack"],
			},
			{
				id: "compact_resume_ledger_v2_gate",
				description: "CompactResumeLedgerV2 hard-eval 真实调用 re_context pack/resume 与 re_memory compact-resume，验证 queued→running→done、append-only hash、幂等与预算。",
				files: ["scripts/reverse-agent/compact-resume-ledger-v2-gate.mjs"],
				markers: ["repi-compact-resume-ledger-v2-gate", "runtime:queued-running-done", "runtime:idempotent-multi-compact-replay", "runtime:auto-resume-budget", "runtime:context-pack-embeds-v2"],
			},

			{
				id: "multi_compact_pressure_gate",
				description: "MultiCompactPressureGateV1 hard-eval 真实压测多轮 re_context pack/resume、old contextPath over latest fallback、duplicate resume 幂等、scope/artifact drift 负例以及 re_operator/re_proof_loop 对 CompactResumeLedgerV2 的反写。",
				files: ["scripts/reverse-agent/multi-compact-pressure-gate.mjs"],
				markers: ["repi-multi-compact-pressure-gate", "MultiCompactPressureGateV1", "runtime:multi-cycle-append-only", "runtime:old-context-path-beats-latest", "runtime:duplicate-resume-idempotent", "runtime:operator-proof-writeback", "negative:artifact-drift"],
			},
			{
				id: "multi_compact_pressure_schema",
				description: "MultiCompactPressureGateV1 schema 固化 runtimeCycles、negativeCases、operatorProofWriteback 和 required gate 名称。",
				files: ["schemas/reverse-agent/multi-compact-pressure.schema.json"],
				markers: ["MultiCompactPressureGateV1", "MultiCompactPressureRuntimeCycleV1", "MultiCompactPressureNegativeCaseV1", "operatorProofWriteback"],
			},
			{
				id: "multi_compact_pressure_fixture",
				description: "MultiCompactPressureGateV1 fixture 覆盖两轮 compact、old contextPath、duplicate replay、operator/proof writeback、target unresolved、latest fallback、scope mismatch、artifact drift 和 budget exhausted。",
				files: ["fixtures/reverse-agent/multi-compact-pressure.fixture.json"],
				markers: ["repi-multi-compact-pressure-fixture", "two-independent-compact-cycles", "old-context-path-beats-latest", "operator-proof-loop-writeback", "budget-exhausted"],
			},
			{
				id: "multi_compact_pressure_npm_gate",
				description: "package 暴露 gate:multi-compact-pressure，供顶级 harness 与 CI 调用。",
				files: ["package.json"],
				markers: ["gate:multi-compact-pressure", "multi-compact-pressure-gate.mjs"],
			},

			{
				id: "cross_session_resume_live_gate",
				description: "CrossSessionResumeLiveV1 hard-eval 用不同 REPI session 做 pack→exact resume，并在 resume 后启动 provider continuation 与 worker continuation，验证不退回 latest fallback。",
				files: ["scripts/reverse-agent/cross-session-resume-live-gate.mjs"],
				markers: [
					"CrossSessionResumeLiveV1",
					"runtime:cross-session-pack-resume",
					"runtime:cross-session-provider-continuation",
					"runtime:cross-session-ledger-done",
					"negative:cross-session-latest-fallback",
				],
			},
			{
				id: "cross_session_resume_live_core_contract",
				description: "核心 profile 中有 CrossSessionResumeLiveV1 / continuation verifier，要求 exact contextPath、ledger done、provider/worker continuation 和无 .pi 污染。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: ["type CrossSessionResumeLiveV1", "type CrossSessionResumeContinuationV1", "function verifyCrossSessionResumeLiveV1", "cross_session_resume_exact_context_path"],
			},
			{
				id: "cross_session_resume_live_npm_gate",
				description: "package 暴露 gate:cross-session-resume-live，供顶级 harness 与 CI 调用。",
				files: ["package.json"],
				markers: ["gate:cross-session-resume-live", "cross-session-resume-live-gate.mjs"],
			},
			{
				id: "cross_session_multi_compact_matrix_gate",
				description: "CrossSessionMultiCompactMatrixGateV1 把 CrossSessionResumeLiveV1 与 MultiCompactPressureGateV1 组合成同一矩阵，验证五轮 compact、跨 session exact contextPath、multi-provider 与 remote provider continuation sample matrix、operator/proof-loop closure 和 compact_resume_ledger_cycle_terminal_alignment。",
				files: ["scripts/reverse-agent/cross-session-multi-compact-matrix-gate.mjs"],
				markers: ["CrossSessionMultiCompactMatrixGateV1", "runtime:cross-session-same-run", "runtime:old-context-path-over-latest-after-multiple-compacts", "runtime:provider-continuation-after-exact-resume", "runtime:provider-continuation-matrix-multi-provider", "runtime:five-cycle-cross-session-compaction-chain", "runtime:remote-provider-continuation-sample-matrix", "runtime:longer-cross-session-compaction-chain", "runtime:compact-resume-ledger-cycle-terminal-alignment", "fixture:negative-rejections"],
			},
			{
				id: "cross_session_multi_compact_matrix_schema",
				description: "Cross-session multi-compact matrix schema 固化 exact contextPath、provider continuation、remote provider sample matrix、operator/proof closure 和 CompactResumeLedgerV2 terminal row 和 compact_resume_ledger_cycle_terminal_alignment 不变量。",
				files: ["schemas/reverse-agent/cross-session-multi-compact-matrix.schema.json"],
				markers: ["CrossSessionMultiCompactMatrixGateV1", "cross_session_multi_compact_same_run", "provider_continuation_after_exact_resume", "provider_continuation_matrix_multi_provider", "longer_cross_session_compaction_chain", "five_cycle_cross_session_compaction_chain", "remote_provider_continuation_sample_matrix", "ProviderContinuationMatrixV1", "RemoteProviderContinuationSampleMatrixV1", "terminal_resume_rows_not_reopened", "compact_resume_ledger_cycle_terminal_alignment", "CompactResumeLedgerCycleTerminalAlignmentV1"],
			},
			{
				id: "cross_session_multi_compact_matrix_fixture",
				description: "Cross-session multi-compact fixture 覆盖 latest fallback、context sha drift、artifact drift、provider missing、budget open、terminal reopen、same session、ledger drift、single provider、chain too short、remote provider sample missing、ledger-terminal-missing-after-rehash 和 secret leak 负例。",
				files: ["fixtures/reverse-agent/cross-session-multi-compact-matrix.fixture.json"],
				markers: ["repi-cross-session-multi-compact-matrix-fixture", "latest-fallback-without-explicit-context", "provider-continuation-missing", "terminal-row-reopened", "provider-continuation-single-provider", "compact-chain-too-short", "five-cycle-chain-too-short", "ledger-terminal-missing-after-rehash", "remote-provider-secret-leak"],
			},
			{
				id: "cross_session_multi_compact_matrix_npm_gate",
				description: "package 暴露 gate:cross-session-multi-compact-matrix，作为 AutonomousHardeningGapLedgerV1 的 context closure gate。",
				files: ["package.json"],
				markers: ["gate:cross-session-multi-compact-matrix", "cross-session-multi-compact-matrix-gate.mjs"],
			},
			{
				id: "compact_resume_ledger_v2_schema",
				description: "CompactResumeLedgerV2 schema 固化 report/transition row、状态枚举、hash 字段和预算字段。",
				files: ["schemas/reverse-agent/compact-resume-ledger-v2.schema.json"],
				markers: ["CompactResumeLedgerV2", "CompactResumeLedgerTransitionV2", "append_only_transition_ledger", "idempotent_multi_compact_replay", "auto_resume_budget_enforced"],
			},
			{
				id: "compact_resume_ledger_v2_fixture",
				description: "CompactResumeLedgerV2 fixture 覆盖 validScenarios、terminal reopen、duplicate replay 和 budget exhausted 负例。",
				files: ["fixtures/reverse-agent/compact-resume-ledger-v2.fixture.json"],
				markers: ["repi-compact-resume-ledger-v2-fixture", "validScenarios", "invalid-done-reopen", "duplicate-idempotent-replay", "budget-exhausted"],
			},
			{
				id: "context_docs_contract",
				description: "公开文档记录 context/resume pack、owned compaction 和 audit harness，不依赖 upstream compact 说明。",
				files: ["docs/reverse-agent/README.md"],
					markers: ["Context/resume pack 闭环", "REPI owned compaction kernel update", "context-compact-audit.mjs", "memory/injection-packet.json"],
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
			{
				id: "memory_v5_transactional_store",
				description: "Memory v5 把 append-only event chain 升级为有 lock、transaction manifest、verify、repair-index、snapshot 和 lane runtime auto writeback 的事务化记忆内核。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: [
					"MemoryAppendTransactionV1",
					"MemoryStoreVerificationV1",
					"withMemoryStoreLock",
					"appendMemoryEventTransaction",
					"verifyMemoryStore",
					"repairMemoryStoreIndex",
					"snapshotMemoryStore",
					"appendLaneRunMemoryEvent",
					"memory_auto_writeback",
				],
			},
				{
					id: "memory_v5_store_gate",
					description: "Memory v5 hard-eval 覆盖坏 prevHash 阻断、case-memory repair-index、transaction manifest 和 runtime auto writeback marker。",
					files: ["scripts/reverse-agent/memory-store-gate.mjs"],
					markers: ["repi-memory-store-gate", "hash-chain-negative", "repair-index-rebuild", "memory_store_v5"],
				},
				{
					id: "runtime_re_swarm_memory_writeback",
					description: "re_swarm run 的每个已执行 worker 会把 SubagentRuntimeManifestV1、stdout/stderr hash、worker status、命令和 claim/merge artifact 写回 MemoryStoreV5，避免并行 worker 经验只留在 swarm artifact 里。",
					files: ["packages/coding-agent/src/core/recon-profile.ts"],
					markers: [
						"function appendSwarmWorkerMemoryEvents",
						"appendSwarmWorkerMemoryEvents(swarm)",
						"memory-swarm-writeback",
						"memory_swarm_writeback:",
						"SubagentRuntimeManifestV1",
						"MemoryStoreV5",
					],
				},
				{
					id: "runtime_re_swarm_memory_writeback_gate",
					description: "re_swarm memory writeback gate 验证写回数量、artifact 捕获、非 run 模式跳过和文档/顶级 harness 接线。",
					files: ["scripts/reverse-agent/memory-swarm-writeback-gate.mjs"],
					markers: ["repi-memory-swarm-writeback-gate", "fixture:writeback-count", "fixture:artifact-capture", "gate:memory-swarm-writeback"],
				},
				{
					id: "memory_supervisor_lifecycle_runtime",
					description: "Memory Supervisor 在 sedimentation 后输出 promotion/demotion/quarantine/expire/merge 队列、lifecycle-board 和 required gates，避免长期记忆只会写不会治理。",
					files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
					markers: ["MemorySupervisorV1", "superviseMemoryLifecycle", "formatMemorySupervisor", "memorySupervisorReportPath", "memoryLifecycleBoardPath", "quarantineOverridesPromotion", "mergeByCaseSignature"],
				},
				{
					id: "memory_supervisor_gate",
					description: "Memory Supervisor hard-eval 真实调用 re_memory supervise 并验证 report schema、lifecycle-board、promotion/demotion/quarantine/merge fixture。",
					files: ["scripts/reverse-agent/memory-supervisor-gate.mjs"],
					markers: ["repi-memory-supervisor-gate", "runtime:report-schema", "runtime:lifecycle-board", "fixture:promotion-demotion-quarantine-merge"],
				},
				{
					id: "memory_supervisor_schema",
					description: "Memory Supervisor schema 固化 report/decision/lifecycle policy 的可机读合同。",
					files: ["schemas/reverse-agent/memory-supervisor.schema.json"],
					markers: ["MemorySupervisorReportV1", "MemorySupervisorDecisionV1", "quarantineOverridesPromotion", "mergeByCaseSignature"],
				},
				{
					id: "memory_supervisor_fixture",
					description: "Memory Supervisor fixture 覆盖 promote/demote/quarantine/merge 生命周期场景。",
					files: ["fixtures/reverse-agent/memory-supervisor.fixture.json"],
					markers: ["repi-memory-supervisor-fixture", "promote", "demote", "quarantine", "merge", "feedback_required_after_injection"],
				},
			{
				id: "memory_feedback_closure_runtime",
				description: "Memory Feedback Closure 把 injected memory 的执行反馈闭环固化为 report：成功反馈 promote、失败反馈 demote、未反馈保持 pending，避免沉淀只写不验证。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryFeedbackClosureV1", "buildMemoryFeedbackClosureReport", "formatMemoryFeedbackClosure", "memoryFeedbackClosureReportPath", "pending_feedback_after_injection", "failure_feedback_demotes"],
			},
			{
				id: "memory_feedback_closure_gate",
				description: "Memory Feedback Closure hard-eval 真实调用 re_memory feedback/supervise，验证 promote/demote/pending 三类反馈闭环和 supervisor demotion。",
				files: ["scripts/reverse-agent/memory-feedback-closure-gate.mjs"],
				markers: ["repi-memory-feedback-closure-gate", "runtime:success-feedback-promotes", "runtime:failure-feedback-demotes", "runtime:pending-feedback-tracked", "runtime:supervisor-demotes-failed-feedback"],
			},
			{
				id: "memory_feedback_closure_schema",
				description: "Memory Feedback Closure schema 固化 feedback report/row 的可机读合同。",
				files: ["schemas/reverse-agent/memory-feedback-closure.schema.json"],
				markers: ["MemoryFeedbackClosureReportV1", "MemoryFeedbackClosureRowV1", "pending_injection_requires_feedback_writeback"],
			},
			{
				id: "memory_feedback_closure_fixture",
				description: "Memory Feedback Closure fixture 覆盖成功反馈提升、失败反馈降权和 pending writeback。",
				files: ["fixtures/reverse-agent/memory-feedback-closure.fixture.json"],
				markers: ["repi-memory-feedback-closure-fixture", "success-feedback-promotes-injected-memory", "failure-feedback-demotes-injected-memory", "pending-injection-requires-writeback"],
			},
			{
				id: "memory_scope_isolation_runtime",
				description: "Memory Scope Isolation 给每条 MemoryEventV1 写入 mission/session/workspace/branch/route/target scope，并在沉淀前阻断跨 workspace/target/route 污染。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryScopeIsolationV1", "MemoryScopeV1", "buildMemoryScopeIsolationReport", "formatMemoryScopeIsolation", "scope_filter_by_mission_session_workspace_target", "cross_workspace_contamination_blocks_injection"],
			},
			{
				id: "memory_scope_isolation_gate",
				description: "Memory Scope Isolation hard-eval 真实调用 re_memory scope/sediment/context pack，验证同 scope allow、跨 session/workspace/target 阻断、legacy 手动复核和 context pack 接线。",
				files: ["scripts/reverse-agent/memory-scope-isolation-gate.mjs"],
				markers: ["repi-memory-scope-isolation-gate", "runtime:same-scope-allows-injection", "runtime:cross-workspace-blocks-injection", "runtime:cross-target-blocks-injection", "runtime:legacy-memory-scope-manual-review", "runtime:context-pack-has-scope-isolation"],
			},
			{
				id: "memory_scope_isolation_schema",
				description: "Memory Scope Isolation schema 固化 scope report/row 的可机读合同。",
				files: ["schemas/reverse-agent/memory-scope-isolation.schema.json"],
				markers: ["MemoryScopeIsolationReportV1", "MemoryScopeIsolationRowV1", "MemoryScopeV1", "scope_filter_by_mission_session_workspace_target"],
			},
			{
				id: "memory_scope_isolation_fixture",
				description: "Memory Scope Isolation fixture 覆盖同 scope、跨 scope 和 legacy scope 三类场景。",
				files: ["fixtures/reverse-agent/memory-scope-isolation.fixture.json"],
				markers: ["repi-memory-scope-isolation-fixture", "same-scope-allows-injection", "cross-session-workspace-blocks-injection", "legacy-scope-warns-manual-review"],
			},
			{
				id: "knowledge_scope_isolation_runtime",
				description: "Knowledge Graph 继续消费 MemoryScopeIsolationV1，把跨 workspace/target/route 污染 artifact 从 command_strategy_hints 和 similarity_index 中剔除，只保留 quarantine 证据节点。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["KnowledgeScopeIsolationV1", "buildKnowledgeScopeIsolation", "knowledge_graph_scope_filter_blocks_quarantined_artifacts", "knowledge_graph_command_hints_exclude_scope_blocked_sources", "knowledge_scope_isolation"],
			},
			{
				id: "knowledge_scope_isolation_gate",
				description: "Knowledge Scope Isolation hard-eval 真实构造跨目标 memory artifact，调用 re_knowledge_graph build，验证 blocked artifact 不进入 command hints/similarity，allowed artifact 仍可复用。",
				files: ["scripts/reverse-agent/knowledge-scope-isolation-gate.mjs"],
				markers: ["repi-knowledge-scope-isolation-gate", "runtime:blocked-artifact-quarantined", "runtime:command-hints-exclude-blocked", "runtime:similarity-excludes-blocked-artifact"],
			},
			{
				id: "knowledge_scope_isolation_schema",
				description: "Knowledge Scope Isolation schema 固化 knowledgeScopeIsolation/sourceRows 的可机读合同。",
				files: ["schemas/reverse-agent/knowledge-scope-isolation.schema.json"],
				markers: ["KnowledgeScopeIsolationV1", "KnowledgeScopeIsolationSourceV1", "knowledge_graph_scope_filter_blocks_quarantined_artifacts", "knowledge_graph_command_hints_exclude_scope_blocked_sources"],
			},
			{
				id: "knowledge_scope_isolation_fixture",
				description: "Knowledge Scope Isolation fixture 覆盖 blocked artifact、allowed artifact 和 embedded scope report 三类场景。",
				files: ["fixtures/reverse-agent/knowledge-scope-isolation.fixture.json"],
				markers: ["repi-knowledge-scope-isolation-fixture", "blocked-artifact-excluded-from-command-hints", "allowed-artifact-remains-queryable", "scope-report-embedded-in-knowledge-graph"],
			},
			{
				id: "artifact_scope_filter_runtime",
				description: "Artifact Scope Filter 把 MemoryScopeIsolationV1 verdict 继续传播到 latest artifact/context artifact index 旁路线，阻断非 knowledge graph 的污染 artifact 复用。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["ArtifactScopeFilterV1", "scopedContextArtifactIndex", "latest_artifact_side_channel_scope_filter", "context_artifact_index_excludes_scope_blocked_artifacts", "artifact_scope_filter_report_in_context_pack"],
			},
			{
				id: "artifact_scope_filter_gate",
				description: "Artifact Scope Filter hard-eval 构造 blocked latest artifact 与 older allowed artifact，调用 re_context pack 验证 context index 跳过污染 latest 并保留可复用 artifact。",
				files: ["scripts/reverse-agent/artifact-scope-filter-gate.mjs"],
				markers: ["repi-artifact-scope-filter-gate", "runtime:blocked-latest-artifact-quarantined", "runtime:context-index-excludes-blocked-latest", "runtime:context-index-selects-allowed-older"],
			},
			{
				id: "artifact_scope_filter_schema",
				description: "Artifact Scope Filter schema 固化 latest-artifact side-channel scope filter 的可机读合同。",
				files: ["schemas/reverse-agent/artifact-scope-filter.schema.json"],
				markers: ["ArtifactScopeFilterV1", "ArtifactScopeFilterDecisionV1", "latest_artifact_side_channel_scope_filter", "context_artifact_index_excludes_scope_blocked_artifacts"],
			},
			{
				id: "artifact_scope_filter_fixture",
				description: "Artifact Scope Filter fixture 覆盖 blocked latest、older allowed 和 context pack embedding 三类场景。",
				files: ["fixtures/reverse-agent/artifact-scope-filter.fixture.json"],
				markers: ["repi-artifact-scope-filter-fixture", "blocked-latest-artifact-skipped", "older-allowed-artifact-selected", "artifact-scope-report-embedded-in-context-pack"],
			},
			{
				id: "latest_artifact_consumer_scope_runtime",
				description: "LatestArtifactConsumerScopeGateV1 把 scope filter 从 context index 扩展到 operator/proof/compiler 的 latest artifact consumer，防止 proof-loop、claim gate 或 feedback 队列读取跨 target 的较新 artifact。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: ["artifactTargetMatches", "artifactScopeVerdictPriority", "operator_feedback_latest_artifact_consumer", "proof_loop_gap_latest_artifact_consumer", "proof_loop_evidence_latest_artifact_consumer", "proof_loop_source_latest_artifact_consumer", "compiler_claim_gate"],
			},
			{
				id: "latest_artifact_consumer_scope_gate",
				description: "LatestArtifactConsumerScopeGateV1 hard-eval 用 target A 的较新 verifier/compiler/replayer/autofix/supervisor/swarm artifact 与 target B 的较旧 artifact 做压力测试，要求所有 consumer 选择同 target 较旧 artifact 并隔离跨 target latest。",
				files: ["scripts/reverse-agent/latest-artifact-consumer-scope-gate.mjs"],
				markers: ["repi-latest-artifact-consumer-scope-gate", "LatestArtifactConsumerScopeGateV1", "runtime:no-cross-target-latest-leak", "runtime:operator-feedback-scope", "runtime:proof-loop-gap-scope", "runtime:compiler-claim-gate-scope"],
			},
			{
				id: "latest_artifact_consumer_scope_schema",
				description: "LatestArtifactConsumerScopeGateV1 schema 固化 operator-feedback、proof-loop gap/evidence/source 与 compiler-claim-gate 的 required gates 和 scenario enum。",
				files: ["schemas/reverse-agent/latest-artifact-consumer-scope.schema.json"],
				markers: ["LatestArtifactConsumerScopeGateV1", "LatestArtifactConsumerScopeScenarioV1", "proof_loop_source_latest_artifact_consumer", "compiler_claim_gate_latest_artifact_consumer", "cross_target_latest_artifact_blocked"],
			},
			{
				id: "latest_artifact_consumer_scope_fixture",
				description: "LatestArtifactConsumerScopeGateV1 fixture 覆盖同 target 旧 artifact 选择与跨 target 较新 artifact 阻断。",
				files: ["fixtures/reverse-agent/latest-artifact-consumer-scope.fixture.json"],
				markers: ["repi-latest-artifact-consumer-scope-fixture", "operator-feedback-cross-target-block", "proof-loop-source-cross-target-block", "compiler-claim-gate-cross-target-block"],
			},
			{
				id: "failure_signature_priority_runtime",
				description: "FailureSignaturePriorityGateV1 把 runtime failure ledger / repair queue 接成 proof-loop 与 knowledge graph 的优先消费者，exhausted/repeated signature 先进入 repair/escalate 路线。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: ["failureSignaturePriorityReport", "failureSignaturePriority", "failureSignatureRepairQueue", "failure_signature_priority", "knowledge_graph_failure_signature_priority", "runtimeRepairTargetMatches"],
			},
			{
				id: "failure_signature_priority_gate",
				description: "FailureSignaturePriorityGateV1 hard-eval 写入 exhausted、repeated、missing-command 和 unrelated-target runtime failure rows，验证 proof-loop/knowledge graph 优先级、sourceArtifacts 与 scope 隔离。",
				files: ["scripts/reverse-agent/failure-signature-priority-gate.mjs"],
				markers: ["repi-failure-signature-priority-gate", "FailureSignaturePriorityGateV1", "runtime:proof-loop-failure-priority", "runtime:knowledge-consumes-failure-signature", "runtime:no-unrelated-target-leak"],
			},
			{
				id: "failure_signature_priority_schema",
				description: "FailureSignaturePriorityGateV1 schema 固化 failure signature priority 的 required gates、scenario 输入和 proof-loop/knowledge 期望。",
				files: ["schemas/reverse-agent/failure-signature-priority.schema.json"],
				markers: ["FailureSignaturePriorityGateV1", "FailureSignaturePriorityScenarioV1", "runtime_failure_ledger_preempts_blind_retry", "repair_queue_ready_command_required"],
			},
			{
				id: "failure_signature_priority_fixture",
				description: "FailureSignaturePriorityGateV1 fixture 覆盖 exhausted 优先、repeated repair、缺命令非 ready、跨 target 不泄漏。",
				files: ["fixtures/reverse-agent/failure-signature-priority.fixture.json"],
				markers: ["repi-failure-signature-priority-fixture", "exhausted-failure-preempts-operator-feedback", "repeated-failure-promotes-repair-command", "missing-repair-command-is-not-ready"],
			},
			{
				id: "memory_orchestrator_v6_runtime",
				description: "Memory Orchestrator V6 把长期记忆从旁路工具提升为强制主循环：任务前召回、注入前 scope 过滤、tool 后写回、compact 前快照、compact 后恢复、最终 supervise。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: [
					"MemoryOrchestratorV6",
					"buildMemoryOrchestratorReport",
					"formatMemoryOrchestrator",
					"memoryOrchestratorReportPath",
					"mandatory_memory_control_loop",
					"pre_task_retrieve_before_operator",
					"scope_filter_before_memory_injection",
					"post_tool_writeback_contract",
					"pre_compact_memory_snapshot",
					"post_compact_resume_memory_injection",
					"final_supervise_before_claim",
				],
			},
			{
				id: "memory_orchestrator_v6_gate",
				description: "Memory Orchestrator hard-eval 真实调用 re_memory orchestrate 和 re_context pack，验证强制 control loop 与 context pack embedding。",
				files: ["scripts/reverse-agent/memory-orchestrator-gate.mjs"],
				markers: ["repi-memory-orchestrator-gate", "runtime:pre-task-retrieval-before-operator", "runtime:post-tool-writeback-contract", "runtime:compact-resume-memory-injection", "runtime:context-pack-embeds-orchestrator"],
			},
			{
				id: "memory_orchestrator_v6_schema",
				description: "Memory Orchestrator schema 固化 mandatory memory control loop 的可机读合同。",
				files: ["schemas/reverse-agent/memory-orchestrator.schema.json"],
				markers: ["MemoryOrchestratorV6", "mandatory_memory_control_loop", "pre_task_retrieve_before_operator", "post_compact_resume_memory_injection"],
			},
			{
				id: "memory_orchestrator_v6_fixture",
				description: "Memory Orchestrator fixture 覆盖 pre-task、post-tool、post-compact、final 四类关键主循环场景。",
				files: ["fixtures/reverse-agent/memory-orchestrator.fixture.json"],
				markers: ["repi-memory-orchestrator-fixture", "pre-task-retrieval-before-operator", "post-tool-writeback-contract", "compact-resume-memory-injection", "final-supervise-before-claim"],
			},
			{
				id: "memory_deposition_engine_v7_runtime",
				description: "MemoryDepositionEngineV7 把记忆沉淀从命令/报告提升为 runtime step event bus：tool/shell 结果自动写回、绑定 memory_event、claim/compact-resume，并进入 context pack。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryDepositionEngineV7", "appendMemoryDepositionRuntimeEvent", "buildMemoryDepositionReport", "runtime_step_event_bus", "post_tool_writeback_autocapture", "memoryDepositionEventBusPath"],
			},
			{
				id: "memory_deposition_engine_v7_gate",
				description: "MemoryDepositionEngineV7 hard-eval 模拟真实 tool_result 自动沉淀、手动 deposit、context pack embedding 与 orchestrator wiring。",
				files: ["scripts/reverse-agent/memory-deposition-gate.mjs"],
				markers: ["repi-memory-deposition-gate", "runtime:manual-deposit-memory-binding", "runtime:tool-result-autocapture", "runtime:context-pack-embeds-deposition", "runtime:orchestrator-wiring"],
			},
			{
				id: "memory_deposition_engine_v7_schema",
				description: "MemoryDepositionEngineV7 schema 固化 deposition runtime event、report、coverage 和 required gates。",
				files: ["schemas/reverse-agent/memory-deposition.schema.json"],
				markers: ["MemoryDepositionEngineV7", "MemoryDepositionRuntimeEventV7", "runtime_step_event_bus", "post_tool_writeback_autocapture", "claim_compact_resume_binding"],
			},
			{
				id: "memory_deposition_engine_v7_fixture",
				description: "MemoryDepositionEngineV7 fixture 覆盖手动沉淀、tool_result 自动沉淀、context pack embedding 与负例。",
				files: ["fixtures/reverse-agent/memory-deposition.fixture.json"],
				markers: ["MemoryDepositionEngineV7", "manual-runtime-deposit-writes-memory-event", "tool-result-autocapture-writes-deposition-row", "context-pack-embeds-deposition-report"],
			},
			{
				id: "memory_experience_engine_v8_runtime",
				description: "MemoryExperienceEngineV8 把日志型沉淀升级为经验型沉淀：Episode→Claim→Lesson→Promotion，带 contradiction_resolution 和 usefulness_backprop，并进入 context pack/operator 注入链。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryExperienceEngineV8", "buildMemoryExperienceReport", "formatMemoryExperienceReport", "episode_model_v8", "structured_claim_extraction", "lesson_promotion_gate", "contradiction_resolution", "usefulness_backprop"],
			},
			{
				id: "memory_experience_engine_v8_gate",
				description: "MemoryExperienceEngineV8 hard-eval 真实生成成功/失败/冲突 memory，验证 claim 提取、lesson promotion、operator injection、orchestrator wiring 和 context pack embedding。",
				files: ["scripts/reverse-agent/memory-experience-gate.mjs"],
				markers: ["repi-memory-experience-gate", "runtime:episode-model", "runtime:structured-claim-extraction", "runtime:lesson-promotion-gate", "runtime:contradiction-resolution", "runtime:context-pack-embeds-experience"],
			},
			{
				id: "memory_experience_engine_v8_schema",
				description: "MemoryExperienceEngineV8 schema 固化 Episode/Claim/Lesson/Promotion/report 的可机读合同。",
				files: ["schemas/reverse-agent/memory-experience.schema.json"],
				markers: ["MemoryExperienceEngineV8", "MemoryExperienceReportV8", "MemoryExperienceClaimV8", "episode_model_v8", "lesson_promotion_gate", "usefulness_backprop"],
			},
			{
				id: "memory_experience_engine_v8_fixture",
				description: "MemoryExperienceEngineV8 fixture 覆盖成功经验提升、失败经验降权、冲突隔离、context pack 嵌入和 orchestrator step。",
				files: ["fixtures/reverse-agent/memory-experience.fixture.json"],
				markers: ["repi-memory-experience-fixture", "success-event-promotes-command-strategy-lesson", "failure-event-demotes-avoid-lesson", "contradictory-command-enters-conflict-resolution", "context-pack-embeds-experience-report"],
			},
			{
				id: "memory_skill_capsule_v9_runtime",
				description: "MemorySkillCapsuleV9 把 Experience/Distiller 结果资产化为 operator/verifier/avoid/worker 技能胶囊，带 verified promotion gate 和 operator injection。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemorySkillCapsuleV9", "buildMemorySkillCapsuleReport", "formatMemorySkillCapsules", "skill_capsule_assetization", "verified_skill_promotion_gate", "operator_skill_injection"],
			},
			{
				id: "memory_skill_capsule_v9_gate",
				description: "MemorySkillCapsuleV9 hard-eval 真实生成 success/failure memory，验证 operator capsule、avoid capsule、context pack embedding 和 orchestrator step。",
				files: ["scripts/reverse-agent/memory-skill-capsule-gate.mjs"],
				markers: ["repi-memory-skill-capsule-gate", "runtime:experience-lesson-to-operator-capsule", "runtime:operator-skill-injection", "runtime:context-pack-embeds-skill-capsules", "runtime:orchestrator-wiring"],
			},
			{
				id: "memory_skill_capsule_v9_schema",
				description: "MemorySkillCapsuleV9 schema 固化 SkillCapsule/Report、promotion gate 和 operator injection 字段。",
				files: ["schemas/reverse-agent/memory-skill-capsule.schema.json"],
				markers: ["MemorySkillCapsuleV9", "MemorySkillCapsuleReportV9", "skill_capsule_assetization", "verified_skill_promotion_gate", "operator_skill_injection"],
			},
			{
				id: "memory_skill_capsule_v9_fixture",
				description: "MemorySkillCapsuleV9 fixture 覆盖 operator capsule、avoid capsule、context pack 和 orchestrator step。",
				files: ["fixtures/reverse-agent/memory-skill-capsule.fixture.json"],
				markers: ["repi-memory-skill-capsule-fixture", "experience-lesson-becomes-operator-skill-capsule", "context-pack-embeds-skill-capsule-report"],
			},
			{
				id: "memory_distill_promotion_v10_runtime",
				description: "MemoryDistillPromotionV10 增加 provider distill contract、本地确定性 fallback、artifact/claim 蒸馏和 verifier-backed promotion gate。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryDistillPromotionV10", "buildMemoryDistillPromotionReport", "formatMemoryDistillPromotion", "provider_distill_contract", "artifact_to_claim_distillation", "verifier_backed_promotion_gate"],
			},
			{
				id: "memory_distill_promotion_v10_gate",
				description: "MemoryDistillPromotionV10 hard-eval 真实生成 provider fallback、artifact-backed promotion、experience claim candidate、context pack embedding 和 orchestrator step。",
				files: ["scripts/reverse-agent/memory-distill-promotion-gate.mjs"],
				markers: ["repi-memory-distill-promotion-gate", "runtime:provider-contract-fallback", "runtime:artifact-backed-promotion", "runtime:context-pack-embeds-distill-promotion", "runtime:orchestrator-wiring"],
			},
			{
				id: "memory_distill_promotion_v10_schema",
				description: "MemoryDistillPromotionV10 schema 固化 provider、candidate、report 和 promotion gate。",
				files: ["schemas/reverse-agent/memory-distill-promotion.schema.json"],
				markers: ["MemoryDistillPromotionV10", "MemoryDistillPromotionReportV10", "MemoryDistillProviderV10", "provider_distill_contract"],
			},
			{
				id: "memory_distill_promotion_v10_fixture",
				description: "MemoryDistillPromotionV10 fixture 覆盖 provider fallback、artifact promotion、context pack 与 orchestrator step。",
				files: ["fixtures/reverse-agent/memory-distill-promotion.fixture.json"],
				markers: ["repi-memory-distill-promotion-fixture", "local-provider-contract-fallback-is-deterministic", "context-pack-embeds-distill-promotion-report"],
			},
			{
				id: "memory_quality_ledger_v11_runtime",
				description: "MemoryQualityLedgerV11 把长期记忆从能写/能召回推进到可度量学习闭环：召回、注入、反馈、usefulness、升降权和 sedimentation 策略同源。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryQualityLedgerV11", "buildMemoryQualityLedgerReport", "formatMemoryQualityLedger", "active_memory_policy", "quality_score_feedback_loop", "usefulness_feedback_writeback"],
			},
			{
				id: "memory_quality_ledger_v11_gate",
				description: "MemoryQualityLedgerV11 hard-eval 真实生成成功/失败/pending memory，验证正反馈提升、负反馈降权、append-only ledger、context pack embedding 和 orchestrator step。",
				files: ["scripts/reverse-agent/memory-quality-ledger-gate.mjs"],
				markers: ["repi-memory-quality-ledger-gate", "runtime:positive-feedback-promotes", "runtime:negative-feedback-demotes", "runtime:context-pack-embeds-quality", "runtime:orchestrator-wiring"],
			},
			{
				id: "memory_quality_ledger_v11_schema",
				description: "MemoryQualityLedgerV11 schema 固化 quality row/report、active memory policy 和 feedback/usefulness writeback 字段。",
				files: ["schemas/reverse-agent/memory-quality-ledger.schema.json"],
				markers: ["MemoryQualityLedgerV11", "MemoryQualityLedgerReportV11", "MemoryQualityLedgerRowV11", "active_memory_policy", "quality_score_feedback_loop"],
			},
			{
				id: "memory_quality_ledger_v11_fixture",
				description: "MemoryQualityLedgerV11 fixture 覆盖召回/注入提分、正反馈提升、负反馈降权、pending feedback、context pack 和 orchestrator step。",
				files: ["fixtures/reverse-agent/memory-quality-ledger.fixture.json"],
				markers: ["repi-memory-quality-ledger-fixture", "retrieval-and-injection-increase-quality-score", "negative-feedback-demotes-memory", "context-pack-embeds-quality-report"],
			},
			{
				id: "memory_replay_evaluator_v12_runtime",
				description: "MemoryReplayEvaluatorV12 用 A/B replay 和因果归因判断长期记忆是否真实减少步骤、提升成功率或引入污染回归，并把 replay signal 回写到 quality ledger。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryReplayEvaluatorV12", "buildMemoryReplayEvaluatorReport", "formatMemoryReplayEvaluator", "memory_ab_replay", "causal_attribution_signal", "replay_delta_feedback_writeback"],
			},
			{
				id: "memory_replay_evaluator_v12_gate",
				description: "MemoryReplayEvaluatorV12 hard-eval 真实生成成功 memory、跑 replay、验证 saved steps/causal score、quality signal、context pack 和 orchestrator step。",
				files: ["scripts/reverse-agent/memory-replay-evaluator-gate.mjs"],
				markers: ["repi-memory-replay-evaluator-gate", "runtime:ab-replay-improves-memory", "runtime:quality-ledger-consumes-replay", "runtime:context-pack-embeds-replay", "runtime:orchestrator-wiring"],
			},
			{
				id: "memory_replay_evaluator_v12_schema",
				description: "MemoryReplayEvaluatorV12 schema 固化 replay row/report、verdict、causal score、saved-step delta 和 writeback command 字段。",
				files: ["schemas/reverse-agent/memory-replay-evaluator.schema.json"],
				markers: ["MemoryReplayEvaluatorV12", "MemoryReplayEvaluatorReportV12", "MemoryReplayEvaluatorRowV12", "memory_ab_replay", "causal_attribution_signal"],
			},
			{
				id: "memory_replay_evaluator_v12_fixture",
				description: "MemoryReplayEvaluatorV12 fixture 覆盖 A/B replay promotion、因果 saved steps、quality 消费 replay signal、context pack 与 orchestrator step。",
				files: ["fixtures/reverse-agent/memory-replay-evaluator.fixture.json"],
				markers: ["repi-memory-replay-evaluator-fixture", "memory-ab-replay-promotes-useful-memory", "quality-ledger-consumes-replay-signal", "context-pack-embeds-replay-report"],
			},
			{
				id: "memory_strategy_capsule_v13_runtime",
				description: "MemoryStrategyCapsuleV13 把 replay/quality/skill 结果编译成带触发条件、目标、推荐命令、验证命令、fallback、适用边界的可执行战术胶囊。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryStrategyCapsuleV13", "buildMemoryStrategyCapsuleReport", "formatMemoryStrategyCapsules", "executable_strategy_capsule", "replay_backed_strategy_promotion", "strategy_quality_gate"],
			},
			{
				id: "memory_strategy_capsule_v13_gate",
				description: "MemoryStrategyCapsuleV13 hard-eval 真实生成 replay-backed strategy，验证可执行命令、verifier/fallback、context pack embedding 和 orchestrator step。",
				files: ["scripts/reverse-agent/memory-strategy-capsule-gate.mjs"],
				markers: ["repi-memory-strategy-capsule-gate", "runtime:replay-backed-strategy", "runtime:executable-command-contract", "runtime:context-pack-embeds-strategy", "runtime:orchestrator-wiring"],
			},
			{
				id: "memory_strategy_capsule_v13_schema",
				description: "MemoryStrategyCapsuleV13 schema 固化 strategy capsule/report、executionPolicy、injection 和 strategy quality gate 字段。",
				files: ["schemas/reverse-agent/memory-strategy-capsule.schema.json"],
				markers: ["MemoryStrategyCapsuleV13", "MemoryStrategyCapsuleReportV13", "executable_strategy_capsule", "strategy_quality_gate"],
			},
			{
				id: "memory_strategy_capsule_v13_fixture",
				description: "MemoryStrategyCapsuleV13 fixture 覆盖 replay 改善记忆转战术、命令/验证/fallback 合同、context pack 与 orchestrator step。",
				files: ["fixtures/reverse-agent/memory-strategy-capsule.fixture.json"],
				markers: ["repi-memory-strategy-capsule-fixture", "replay-improved-memory-becomes-executable-strategy", "strategy-capsule-in-context-pack"],
			},
			{
				id: "memory_active_kernel_v14_runtime",
				description: "MemoryActiveKernelV14 把 sedimentation/quality/replay/strategy 合并成主动记忆决策内核，输出 active injection pack、avoid/quarantine、feedback writeback 和 compact resume hints。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryActiveKernelV14", "buildMemoryActiveKernelReport", "formatMemoryActiveKernel", "unified_memory_decision_engine", "active_recall_scheduler", "scope_safe_strategy_injection"],
			},
			{
				id: "memory_active_kernel_v14_gate",
				description: "MemoryActiveKernelV14 hard-eval 验证 replay-proven strategy 注入、candidate reuse、失败记忆 avoid、pending feedback 和负例降级。",
				files: ["scripts/reverse-agent/memory-active-kernel-gate.mjs"],
				markers: ["repi-memory-active-kernel-gate", "fixture:active-kernel-policy", "quality_replay_strategy_fusion", "active_kernel_feedback"],
			},
			{
				id: "memory_active_kernel_v14_schema",
				description: "MemoryActiveKernelV14 schema 固化 report/decision/active injection pack、scope lock、feedback writeback 与 compact resume hints。",
				files: ["schemas/reverse-agent/memory-active-kernel.schema.json"],
				markers: ["MemoryActiveKernelV14", "repi-memory-active-kernel-report", "repi-memory-active-injection-pack", "unified_memory_decision_engine"],
			},
			{
				id: "memory_active_kernel_v14_fixture",
				description: "MemoryActiveKernelV14 fixture 覆盖 inject/reuse/avoid/wait-feedback 和 cross-session compact ready required gate。",
				files: ["fixtures/reverse-agent/memory-active-kernel.fixture.json"],
				markers: ["repi-memory-active-kernel-fixture", "mustInjectStrategyIds", "mustAvoidEventIds", "cross_session_compact_ready"],
			},
			{
				id: "memory_maturation_runtime_v15_runtime",
				description: "MemoryMaturationRuntimeV15 把 tool/runtime 结果持续成熟为经验、策略、主动注入、反馈闭环、retention_decay_scheduler、stale_memory_rehearsal_queue 和 replay-backed 升降权。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryMaturationRuntimeV15", "buildMemoryMaturationRuntimeReport", "formatMemoryMaturationRuntime", "automatic_memory_maturation_pipeline", "tool_result_to_strategy_loop", "closed_loop_writeback", "retention_decay_scheduler", "stale_memory_rehearsal_queue", "usefulness_backprop_to_maturation"],
			},
			{
				id: "memory_maturation_runtime_v15_gate",
				description: "MemoryMaturationRuntimeV15 hard-eval 真实调用 re_memory mature，验证 promote/feedback/replay/demote、retention/rehearsal 决策和 maturation hash chain。",
				files: ["scripts/reverse-agent/memory-maturation-runtime-gate.mjs"],
				markers: ["repi-memory-maturation-runtime-gate", "runtime:re-memory-mature-exit", "runtime:maturation-report", "maturation hash chain", "retention_decay_scheduler"],
			},
			{
				id: "memory_maturation_runtime_v15_schema",
				description: "MemoryMaturationRuntimeV15 schema 固化 report/row、stagePath、retention decay/rehearsal、hash chain 与 closed-loop writeback 字段。",
				files: ["schemas/reverse-agent/memory-maturation-runtime.schema.json"],
				markers: ["MemoryMaturationRuntimeV15", "repi-memory-maturation-runtime-report", "automatic_memory_maturation_pipeline", "tool_result_to_strategy_loop", "closed_loop_writeback", "retention_decay_scheduler"],
			},
			{
				id: "memory_maturation_runtime_v15_fixture",
				description: "MemoryMaturationRuntimeV15 fixture 覆盖成功 promote、pending feedback、replay-required、retention rehearse、demote 和 scope quarantine 负例。",
				files: ["fixtures/reverse-agent/memory-maturation-runtime.fixture.json"],
				markers: ["repi-memory-maturation-runtime-fixture", "mustPromoteEventIds", "mustReplayRequiredEventIds", "mustRehearseEventIds", "maturation-runtime-ledger.jsonl"],
			},
			{
				id: "memory_ux_dashboard_v16_runtime",
				description: "MemoryUxDashboardV16 把后台记忆闭环变成用户可见的 status/why/promote/demote/forget 控制面。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryUxDashboardV16", "buildMemoryUxDashboard", "formatMemoryUxDashboard", "memoryStatusReportPath", "user_visible_memory_status", "recall_explainability", "append_only_memory_governance"],
			},
			{
				id: "memory_ux_dashboard_v16_gate",
				description: "Memory UX hard-eval 真实调用 re_memory status/why/promote/forget，验证 status-board、why rows 和 append-only governance ledger。",
				files: ["scripts/reverse-agent/memory-ux-gate.mjs"],
				markers: ["repi-memory-ux-gate", "runtime:memory-ux-dashboard", "runtime:why-this-memory-visible", "runtime:append-only-governance", "runtime:memory-status-artifacts"],
			},
			{
				id: "memory_ux_dashboard_v16_schema",
				description: "Memory UX schema 固化 user_visible_memory_status、recall_explainability 和 lifecycle governance commands。",
				files: ["schemas/reverse-agent/memory-ux-dashboard.schema.json"],
				markers: ["MemoryUxDashboardV16", "user_visible_memory_status", "recall_explainability", "append_only_memory_governance", "lifecycle_governance_commands"],
			},
			{
				id: "memory_ux_dashboard_v16_fixture",
				description: "Memory UX fixture 覆盖 why rows、status board 和治理命令负例。",
				files: ["fixtures/reverse-agent/memory-ux-dashboard.fixture.json"],
				markers: ["repi-memory-ux-dashboard-fixture", "MemoryUxDashboardV16", "why_this_memory_rows", "memory_status_board_written"],
			},
			{
				id: "memory_vector_rerank_runtime",
				description: "Memory Vector Index 用本地 deterministic hash embedding 生成 vector-index/vector-search-report，并把 memory_vector_rerank 接入 search-events 排序。",
				files: ["packages/coding-agent/src/core/recon-profile.ts", "repi-profile/extensions/reverse-pentest-core.ts"],
				markers: ["MemoryVectorIndexV1", "MemoryVectorSearchV1", "MemoryEmbeddingProviderV1", "buildMemoryVectorIndex", "searchMemoryVectors", "memoryEmbeddingProviderConfig", "openai_compatible_embedding_contract", "memory_vector_rerank", "repi-local-hash-embedding-v1"],
			},
			{
				id: "memory_vector_gate",
				description: "Memory Vector hard-eval 真实调用 re_memory vector/search-events，验证 index/search schema、rerank reason 和跨 route 负例 fixture。",
				files: ["scripts/reverse-agent/memory-vector-gate.mjs"],
				markers: ["repi-memory-vector-gate", "runtime:index-schema", "runtime:search-schema", "runtime:vector-rerank-used", "runtime:embedding-provider-contract", "runtime:openai-compatible-fallback", "fixture:vector-rerank-negative"],
			},
			{
				id: "memory_vector_schema",
				description: "Memory Vector schema 固化 index/search/hit 的可机读合同。",
				files: ["schemas/reverse-agent/memory-vector.schema.json"],
				markers: ["MemoryVectorIndexV1", "MemoryVectorSearchReportV1", "MemoryVectorIndexEntryV1", "MemoryEmbeddingProviderV1", "openai_compatible_embedding_contract", "repi-local-hash-embedding-v1"],
			},
			{
				id: "memory_vector_fixture",
				description: "Memory Vector fixture 覆盖语义 rerank、跨 route forbidden leak 和 quality-weighted boost。",
				files: ["fixtures/reverse-agent/memory-vector.fixture.json"],
				markers: ["repi-memory-vector-fixture", "semantic-authz-rerank", "forbidden-cross-route-vector-leak", "quality-weighted-replay-boost", "provider-contract-env-fallback"],
			},
			{
				id: "memory_usefulness_eval_runtime",
				description: "Memory usefulness eval 把长期记忆从“能写”提升到“可度量地召回正确经验并阻断污染经验”，覆盖 hit@k、MRR、forbiddenHitIds、同进程并发写和 child-process 并发写压力。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: [
					"MemoryUsefulnessEvalV1",
					"MemoryUsefulnessEvalReportV1",
					"evaluateMemoryUsefulness",
					"formatMemoryUsefulnessEval",
					"forbiddenHitIds",
					"memory_usefulness_eval",
				],
			},
			{
				id: "memory_usefulness_gate",
				description: "Memory usefulness hard-eval 覆盖 authz/pwn 正召回、失败/跨 route forbidden memory 不进入 topK、同进程与 child-process 并发 append 保持 hash-chain。",
				files: ["scripts/reverse-agent/memory-usefulness-gate.mjs"],
				markers: ["repi-memory-usefulness-gate", "eval:hit-at-1", "eval:forbidden-leak", "concurrency:hash-chain", "concurrency:child-process-hash-chain"],
			},
		],
		hardeningNeeded: [
			"Memory v6 Orchestrator 已把 pre-task retrieve、scope-safe inject、post-tool writeback、compact hooks、final supervise 接入 gate；MemoryDepositionEngineV7 已补 runtime step event bus 与 tool_result 自动沉淀，MemoryExperienceEngineV8 已把沉淀推进到 Episode→Claim→Lesson→Promotion，MemorySkillCapsuleV9 已把经验/蒸馏结果资产化为 operator/verifier/avoid 技能胶囊，MemoryDistillPromotionV10 已补 provider 合同、本地 fallback 和 verifier-backed promotion gate，MemoryQualityLedgerV11 已补召回/注入/反馈/usefulness 质量闭环和主动升降权，MemoryReplayEvaluatorV12 已补 A/B replay、saved-step delta、因果归因和 quality writeback，MemoryStrategyCapsuleV13 已把高价值记忆转成可执行战术胶囊，MemoryActiveKernelV14 已把沉淀/质量/replay/strategy 融合成主动记忆决策与 active injection pack，MemoryMaturationRuntimeV15 已把 tool_result→Episode→Lesson→Strategy→ActiveDecision→Feedback→Retention/Rehearsal 的成熟闭环固化为 runtime report/ledger；后续继续补真实远程 embedding live 回归、更多 latest-artifact consumers 的 side-channel scope 压力回归、re_swarm 多进程 worker memory writeback 压力回归和 LLM 级蒸馏 promotion。",
		],
		recommendedWork: [
			"保持 ContextPackV2 / ResumeContractV2 / CompactResumeLedgerV2 runtime markers 与 context-compact-audit.mjs 同步。",
			"CrossSessionMultiCompactMatrixGateV1 已把 MultiCompactPressureGateV1 与 CrossSessionResumeLiveV1 合并成同一 closure gate，覆盖跨 session、五轮 compact、multi-provider 与 remote provider continuation sample matrix、operator/proof-loop closure；继续扩大更多 latest artifact consumer 的 scope verdict propagation。",
			"保持 cross-session multi-compact matrix 与 ContextPackV2 / ResumeContractV2 / CompactResumeLedgerV2 runtime markers 同步，并继续扩展真实远程 provider continuation live 样本。",
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
				id: "failure_signature_priority_npm_gate",
				description: "package 暴露 gate:failure-signature-priority，供顶级 harness 与 CI 验证 proof-loop/knowledge 对 runtime failure ledger 的优先消费。",
				files: ["package.json"],
				markers: ["gate:failure-signature-priority", "failure-signature-priority-gate.mjs"],
			},
			{
				id: "agent_dogfood_failure_signature_binding_runtime",
				description: "agent-dogfood 失败 role/synthesizer 会把 failure signature、retryBudget、repairId、failureId 和 dedupeWindow 写回 subagent runtime manifest、manifest index 与 runtime claim ledger event。",
				files: ["bench/recon-remote/agent-dogfood/parallel-run.mjs"],
				markers: ["AgentDogfoodFailureSignatureBindingV1", "failureSignatureManifestBindings", "failureSignatureBinding", "failureLedgerEventId", "repairQueueItemId", "retryBudget", "dedupeWindow", "failureSignatureManifestBindingsCaptured"],
			},
			{
				id: "agent_dogfood_failure_signature_binding_gate",
				description: "AgentDogfoodFailureSignatureBindingGateV1 用 schema/fixture 和负例验证 manifest/failure/repair/claim ledger 的 signature 一致性与 role-scoped dedupe window。",
				files: ["scripts/reverse-agent/agent-dogfood-failure-signature-binding-gate.mjs", "fixtures/reverse-agent/agent-dogfood-failure-signature-binding.fixture.json"],
				markers: ["AgentDogfoodFailureSignatureBindingGateV1", "fixture:positive-binding", "fixture:negative-rejections", "missing-binding-in-runtime-manifest", "duplicate-role-dedupe-window-mismatch"],
			},
			{
				id: "agent_dogfood_failure_signature_binding_npm_gate",
				description: "package 暴露 gate:agent-dogfood-failure-signature-binding，供顶级 harness 与 CI 验证 agent-dogfood runtime manifest 失败签名绑定。",
				files: ["package.json"],
				markers: ["gate:agent-dogfood-failure-signature-binding", "agent-dogfood-failure-signature-binding-gate.mjs"],
			},
			{
				id: "provider_failure_injection_core_contract",
				description: "ProviderFailureInjectionReportV1 / ProviderFailureInjectionCaseV1 在核心 profile 中有可机读合同和 verifier。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: ["type ProviderFailureInjectionReportV1", "type ProviderFailureInjectionCaseV1", "function verifyProviderFailureInjectionReportV1", "provider_failure_exhausted_escalation_missing"],
			},
			{
				id: "provider_failure_injection_gate",
				description: "ProviderFailureInjectionReportV1 hard-eval 用真实 repi provider 失败路径生成 FailureLedgerEventV1 / RepairQueueItemV1，并验证 exhausted 不继续盲 retry。",
				files: ["scripts/reverse-agent/provider-failure-injection-gate.mjs"],
				markers: [
					"ProviderFailureInjectionReportV1",
					"runtime:provider-failure-repair-ledger",
					"runtime:provider-failure-exhausted-escalates",
					"negative:provider-failure-exhausted-unpaused-rerun",
					"appendFailureRepairWriteback",
				],
			},
			{
				id: "provider_failure_injection_npm_gate",
				description: "package 暴露 gate:provider-failure-injection，供顶级 harness 与 CI 调用。",
				files: ["package.json"],
				markers: ["gate:provider-failure-injection", "provider-failure-injection-gate.mjs"],
			},
			{
				id: "repair_rollback_policy_core_contract",
				description: "RepairRollbackPolicyV1 把 state-changing repair 的 baseline/allowlist/regression/rollback 变成可机读合同，避免修复动作留下脏状态。",
				files: ["packages/coding-agent/src/core/recon-profile.ts"],
				markers: ["type RepairRollbackPolicyV1", "function verifyRepairRollbackPolicyV1", "repair_rollback_tree_hash_mismatch"],
			},
			{
				id: "repair_rollback_policy_gate",
				description: "RepairRollbackPolicyV1 已接入 re_autofix live artifact wiring：state-changing patch_queue 会写 repairRollbackPolicyPath，并验证 baseline/allowlist/regression/rollback。",
				files: ["scripts/reverse-agent/repair-rollback-policy-gate.mjs"],
				markers: [
					"RepairRollbackPolicyV1",
					"runtime:repair-baseline-snapshot",
					"runtime:repair-allowlist-enforced",
					"runtime:repair-rollback-restored",
					"runtime:repair-rollback-live-wiring",
					"repairRollbackPolicyPath",
					"negative:repair-allowlist-violation",
					"negative:repair-rollback-not-restored",
				],
			},
			{
				id: "repair_rollback_policy_schema_fixture",
				description: "Repair rollback schema/fixture 固化 baseline_required_before_repair、allowlist_violation_blocks_repair 和 rollback tree hash 不变量。",
				files: ["schemas/reverse-agent/repair-rollback-policy.schema.json", "fixtures/reverse-agent/repair-rollback-policy.fixture.json"],
				markers: ["RepairRollbackPolicyV1", "baseline_required_before_repair", "allowlist_violation_blocks_repair", "rollback_tree_hash_must_match_baseline"],
			},
			{
				id: "worker_provider_repair_rollback_unification_gate",
				description: "WorkerProviderRepairRollbackUnificationGateV1 把 provider-worker、re_swarm worker、compound-frontier 和 operator 的 repair rows 统一到同一 signature/rollback/regression 合同，补 provider-worker live repair matrix、state lineage snapshot matrix、RemoteProviderStateChangingRepairMatrixV1 与 DeepCompoundProviderRepairCompletionChainV1，阻断 exhausted 后 unpaused rerun。",
				files: ["scripts/reverse-agent/worker-provider-repair-rollback-unification-gate.mjs"],
				markers: ["WorkerProviderRepairRollbackUnificationGateV1", "runtime:provider-worker-state-change-rollback-policy", "runtime:provider-worker-live-state-change-repair-matrix", "runtime:multi-attempt-retry-window-completion-chain", "runtime:provider-worker-state-lineage-snapshot-matrix", "runtime:compound-provider-long-horizon-repair-completion-chain", "runtime:remote-provider-state-changing-repair-matrix", "runtime:deep-compound-provider-repair-completion-chain", "runtime:exhausted-blocks-unpaused-rerun", "provider_worker_refs_preserve_manifest_request_log_rollback", "provider_worker_state_lineage_snapshot_matrix", "compound_provider_long_horizon_repair_completion_chain", "remote_provider_state_changing_repair_matrix", "deep_compound_provider_repair_completion_chain", "policy-failure-repair-unlinked"],
			},
			{
				id: "worker_provider_repair_rollback_unification_fixture",
				description: "WorkerProviderRepairRollbackUnification fixture 覆盖 provider-worker、swarm-worker、compound-frontier、operator、live repair matrix、multi-attempt chain、state lineage、long-horizon chain、remote provider state matrix、deep compound chain 和 signature/rollback/repair 负例。",
				files: ["fixtures/reverse-agent/worker-provider-repair-rollback-unification.fixture.json"],
				markers: ["repi-worker-provider-repair-rollback-unification-fixture", "provider-worker-state-change", "swarm-worker-provider-repair", "provider-worker-cache-state-repair", "provider-worker-token-state-repair", "remote-provider-config-state-repair", "compound-provider-deep-repair", "compound-provider-long-horizon-repair", "signature-mismatch", "policy-failure-repair-unlinked", "live-repair-matrix-missing-provider", "retry-window-not-monotonic", "state-lineage-missing-baseline", "long-horizon-signature-drift", "remote-state-repair-matrix-too-narrow", "deep-compound-chain-too-short", "remote-state-repair-secret-leak"],
			},
			{
				id: "worker_provider_repair_rollback_unification_schema",
				description: "WorkerProviderRepairRollbackUnification schema 固化同 signature、rollback policy、provider worker refs、retry window、live repair matrix、multi-attempt completion chain、state lineage snapshot matrix、long-horizon completion chain、RemoteProviderStateChangingRepairMatrixV1、DeepCompoundProviderRepairCompletionChainV1 和 regression gate refs。",
				files: ["schemas/reverse-agent/worker-provider-repair-rollback-unification.schema.json"],
				markers: ["WorkerProviderRepairRollbackUnificationGateV1", "same_signature_failure_repair_rollback_regression", "provider_worker_state_change_writes_rollback_policy", "ProviderWorkerLiveRepairMatrixV1", "MultiAttemptRetryWindowCompletionChainV1", "ProviderWorkerStateLineageSnapshotMatrixV1", "CompoundProviderLongHorizonRepairCompletionChainV1", "RemoteProviderStateChangingRepairMatrixV1", "DeepCompoundProviderRepairCompletionChainV1", "regression_gate_refs_match_repair_queue"],
			},
			{
				id: "worker_provider_repair_rollback_unification_npm_gate",
				description: "package 暴露 gate:worker-provider-repair-rollback-unification，作为 AutonomousHardeningGapLedgerV1 的 repair closure gate。",
				files: ["package.json"],
				markers: ["gate:worker-provider-repair-rollback-unification", "worker-provider-repair-rollback-unification-gate.mjs"],
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
			"Provider failure injection 已接入 strict failure/repair validator；RepairRollbackPolicyV1 已把 baseline/allowlist/regression/rollback 接成独立 hard-eval；AgentDogfoodFailureSignatureBindingGateV1 已把 agent-dogfood subagent runtime manifest 与 failure signature / retryBudget / dedupeWindow 绑定；WorkerProviderRepairRollbackUnificationGateV1 已把 provider-worker、re_swarm worker、compound-frontier 和 operator repair rows 统一到同一 signature/rollback/regression 合同，并补 provider-worker live repair matrix、state lineage snapshot matrix、RemoteProviderStateChangingRepairMatrixV1 与 DeepCompoundProviderRepairCompletionChainV1；后续继续扩大真实 provider-worker state-changing repair 样本。",
			"所有 runtime retry 继续复用同一 signature 和 budget/retryBudget；达到 exhausted 后停止盲 retry，转 repair/escalate。",
			"保持 WorkerProviderRepairRollbackUnificationGateV1 作为 provider/worker repair closure gate，并继续把更多真实 state-changing repair 纳入 live regression、state lineage、RemoteProviderStateChangingRepairMatrixV1 和 DeepCompoundProviderRepairCompletionChainV1。",
		],
		recommendedWork: [
			"保持 .repi-harness/evidence/failures/ledger.jsonl 和 .repi-harness/evidence/repairs/queue.jsonl schema，把 retryBudget/evidenceWriteback/blockedConditions 保持为必填。",
			"保持 agent-dogfood failure signature binding 与 WorkerProviderRepairRollbackUnificationGateV1，并继续扩展到更多 re_swarm/provider worker live artifacts。",
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
				id: "agent_dogfood_structured_claim_merge_runtime",
				description: "agent-dogfood runner 会把 role/synthesizer strict run 转成 StructuredClaimMergeV1，finalClaims 只允许 manifest artifact sha256 + JSON query + verifierPass 的 claim，失败 role 保持 blocked/observation。",
				files: ["bench/recon-remote/agent-dogfood/parallel-run.mjs"],
				markers: ["StructuredClaimMergeV1", "structuredClaimMergePath", "structuredClaimRows", "structuredClaimRef", "narrative_only_observation_never_promotes", "structuredClaimMergeCaptured"],
			},
			{
				id: "agent_dogfood_structured_claim_merge_gate",
				description: "AgentDogfoodStructuredClaimMergeGateV1 用 fixture/负例阻断 narrative-only final pass、缺 JSON query、verifier=false、unresolved challenge 和缺 runtime manifest ref。",
				files: ["scripts/reverse-agent/agent-dogfood-structured-claims-gate.mjs", "fixtures/reverse-agent/agent-dogfood-structured-claims.fixture.json"],
				markers: ["AgentDogfoodStructuredClaimMergeGateV1", "fixture:positive-structured-claims", "fixture:negative-structured-claims", "narrative-only-final-pass", "missing-json-query", "unresolved-challenge-final-pass"],
			},
			{
				id: "agent_dogfood_structured_claim_merge_npm_gate",
				description: "package 暴露 gate:agent-dogfood-structured-claims，供顶级 harness 与 CI 验证 agent-dogfood structured claim promotion boundary。",
				files: ["package.json"],
				markers: ["gate:agent-dogfood-structured-claims", "agent-dogfood-structured-claims-gate.mjs"],
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
				description: "runtime ClaimLedgerEventV1 会经 adapter 进入 validate-claim-ledger.mjs 的 allow-platform-gaps 与 strict-claims 双门禁；缺少历史 source 时默认跑 bounded agent-dogfood plan-only native ledger、bounded reSwarmLiveProbe 和 compound-frontier use-latest native ledger，并输出 runtimeLedgerQuality 统一质量摘要。",
				files: ["scripts/reverse-agent/gate-runtime-claim-ledger.mjs"],
				markers: [
					"normalizeRuntimeClaimLedgerToStrictInput",
					"validate-claim-ledger.mjs",
					"--allow-platform-gaps",
					"--strict-claims",
					"missing_runtime_artifact",
					"runAgentDogfoodLiveProbe",
					"--write-plan-ledger",
					"loadedNativeRuntimeProbe",
					"runReSwarmLiveProbe",
					"reSwarmLiveProbeProvidesDefaultCoverage",
					"runCompoundFrontierLiveProbe",
					"runtimeLedgerQuality",
				],
			},
			{
				id: "runtime_claim_ledger_adapter",
				description: "adapter 把 runtime ledger 规范化成 strict input，并保留 missing_runtime_artifact、artifact sha256、event type count、tip hash 和 hash-chain 质量字段。",
				files: ["scripts/reverse-agent/runtime-claim-ledger-adapter.mjs"],
				markers: ["normalizeRuntimeClaimLedgerToStrictInput", "runtimeClaimLedgerCaptured", "missing_runtime_artifact", "artifact_handoff", "validation", "resolution", "eventTypeCounts", "artifactDigests", "tipHash"],
			},
			{
				id: "runtime_ledger_quality_gate",
				description: "RuntimeLedgerQualityGateV1 把 runtimeLedgerQuality 从报告字段升级为独立 hard gate，要求每个 source 都有 artifact sha256、event type count、tip hash、hash-chain 和 strict validator pass，并用负例阻断缺 event/digest/validator 的伪通过。",
				files: ["scripts/reverse-agent/runtime-ledger-quality-gate.mjs"],
				markers: ["RuntimeLedgerQualityGateV1", "validateSourceQuality", "runtimeLedgerQuality", "artifactDigests", "strictValidator", "negative:runtime-ledger-missing-event-type-count", "negative:runtime-ledger-strict-validator-failed"],
			},
			{
				id: "runtime_ledger_quality_schema",
				description: "RuntimeLedgerQualityGateV1 schema 固化 artifact sha256、event type count、tip hash、hash-chain 和 strict validator 必填字段。",
				files: ["schemas/reverse-agent/runtime-ledger-quality.schema.json"],
				markers: ["RuntimeLedgerQualityGateV1", "requireArtifactSha256", "requireStrictValidator", "eventTypeCounts", "artifactDigests"],
			},
			{
				id: "runtime_ledger_quality_fixture",
				description: "Runtime ledger quality fixture 覆盖缺 event type count、bad tip hash、缺 artifact digest、strict validator failed 和 hash-chain false 负例。",
				files: ["fixtures/reverse-agent/runtime-ledger-quality.fixture.json"],
				markers: ["repi-runtime-ledger-quality-fixture", "negative:runtime-ledger-missing-event-type-count", "negative:runtime-ledger-strict-validator-failed"],
			},
			{
				id: "runtime_claim_ledger_npm_gate",
				description: "package 暴露 runtime claim ledger strict gate。",
				files: ["package.json"],
				markers: ["gate:runtime-claim-ledger", "gate-runtime-claim-ledger.mjs", "gate:runtime-ledger-quality", "runtime-ledger-quality-gate.mjs", "--strict"],
			},
			{
				id: "runtime_claim_ledger_autonomous_contract_wiring",
				description: "autonomous contracts 聚合 runtime claim ledger strict gate。",
				files: ["scripts/reverse-agent/autonomous-contracts.mjs"],
				markers: ["runtimeClaimLedgerStrictGate", "buildRuntimeClaimLedgerGate", "runtime_claim_ledger_strict"],
			},
			{
				id: "structured_claim_merge_live_gate",
				description: "StructuredClaimMergeV1 hard-eval 通过 runtime:structured-claim-live-wiring 真实跑 bounded re_swarm，生成 claim ledger、structured merge artifact 和 live conflict arbitration winner/loser。",
				files: ["scripts/reverse-agent/structured-claim-merge-gate.mjs"],
				markers: [
					"StructuredClaimMergeV1",
					"final_pass_requires_json_query",
					"runtime:structured-claim-live-wiring",
					"structured_conflict_arbitration_live_wiring",
					"runtime:re-swarm-structured-merge-exit",
				],
			},
			{
				id: "structured_claim_merge_fixture",
				description: "StructuredClaimMergeV1 fixture 覆盖 pass、blocked、弱 authz、缺 winner evidence 等 promotion 分支。",
				files: ["fixtures/reverse-agent/structured-claim-merge.fixture.json"],
				markers: [
					"repi-structured-claim-merge-fixture",
					"StructuredClaimMergeV1",
					"final_pass_requires_json_query",
					"claim-authz-weak",
					"missing-winner-evidence",
				],
			},
			{
				id: "structured_claim_merge_schema",
				description: "StructuredClaimMergeV1 schema 固化 final promotion 的 JSON query、verifier、challenge resolution 与 strict final claim policy。",
				files: ["schemas/reverse-agent/structured-claim-merge.schema.json"],
				markers: [
					"StructuredClaimMergeV1",
					"strict_final_claim_promotion",
					"final_pass_requires_json_query",
					"unresolved_adversary_challenge_blocks_final",
				],
			},
			{
				id: "live_conflict_arbitration_matrix_gate",
				description: "LiveConflictArbitrationMatrixGateV1 把 agent-dogfood、re_swarm、compound-frontier 和 provider-worker claim 放入同一冲突矩阵，验证多 topic winner/loser、source coverage、runtime ledger refs、provider-backed same-window table、provider-backed long-window conflict matrix、extended synthesizer topic parsing 和 orchestration/platform split。",
				files: ["scripts/reverse-agent/live-conflict-arbitration-matrix-gate.mjs"],
				markers: ["LiveConflictArbitrationMatrixGateV1", "runtime:source-coverage-all-runtimes", "runtime:winner-evidence-json-query-verifier", "runtime:provider-backed-same-window-conflict-table", "runtime:provider-backed-long-window-conflict-matrix", "runtime:long-run-synthesizer-topic-parse-matrix", "runtime:extended-synthesizer-topic-parse-matrix", "runtime:orchestration-platform-split", "fixture:negative-rejections"],
			},
			{
				id: "live_conflict_arbitration_matrix_schema",
				description: "Live conflict arbitration schema 固化 source coverage、winner evidence、loser downgrade、provider-backed same-window multi-worker conflict table、provider-backed long-window conflict matrix、extended synthesizer topic parsing、orchestration/platform split 和 hash-chain quality。",
				files: ["schemas/reverse-agent/live-conflict-arbitration-matrix.schema.json"],
				markers: ["LiveConflictArbitrationMatrixGateV1", "source_coverage_all_runtimes", "winner_evidence_json_query_verifier", "provider_backed_same_window_multi_worker_conflict_table", "provider_backed_long_window_conflict_matrix", "long_run_synthesizer_topic_parse_matrix", "synthesizer_extended_topic_parse_matrix", "orchestration_success_separate_from_platform_claim"],
			},
			{
				id: "live_conflict_arbitration_matrix_fixture",
				description: "Live conflict arbitration fixture 覆盖四类 runtime source 与 missing winner、loser promoted、plan-only promoted、missing ledger、provider single-worker、missing topic parse、long-window too short、extended topic missing、literal secret leak 等负例。",
				files: ["fixtures/reverse-agent/live-conflict-arbitration-matrix.fixture.json"],
				markers: ["repi-live-conflict-arbitration-matrix-fixture", "agent-dogfood", "re_swarm", "compound-frontier", "provider-worker", "provider-backed-conflict-single-worker", "synthesizer-topic-parse-missing", "long-window-conflict-too-short", "extended-topic-parse-missing", "provider-window-secret-leak", "orchestration-implies-platform-pass"],
			},
			{
				id: "live_conflict_arbitration_matrix_npm_gate",
				description: "package 暴露 gate:live-conflict-arbitration-matrix，作为 AutonomousHardeningGapLedgerV1 的 claim closure gate。",
				files: ["package.json"],
				markers: ["gate:live-conflict-arbitration-matrix", "live-conflict-arbitration-matrix-gate.mjs"],
			},
		],
		hardeningNeeded: [
			"gate:runtime-claim-ledger 已补 agent-dogfood plan-only native ledger、bounded reSwarmLiveProbe、compound-frontier native/use-latest ledger 和 runtimeLedgerQuality；RuntimeLedgerQualityGateV1 已把 artifact sha256/event type count/tip hash/hash-chain/strict validator 提升为独立质量门禁；ProviderBackedDogfoodReleaseGateV1 已把 provider-backed agent-dogfood 多 worker 真执行做成 opt-in release quality gate，后续继续扩大 live provider 样本与更长链路回归。",
			"StructuredClaimMergeV1 已接入 bounded re_swarm live gate；AgentDogfoodStructuredClaimMergeGateV1 已把 agent-dogfood role/synthesizer summary 降为 structured claim rows；LiveConflictArbitrationMatrixGateV1 已把 agent-dogfood、re_swarm、compound-frontier 和 provider-worker 的多 topic conflict matrix、winner evidence、loser downgrade、provider-backed same-window multi-worker conflict table、provider-backed long-window conflict matrix、extended synthesizer topic parse matrix、orchestration/platform split 接成 closure gate；后续继续扩大真实 provider-backed 长窗口冲突样本。",
			"synthesizer 输出继续扩展更复杂 conflict table 样本：多 claimIds、冲突主题、胜出证据、降级原因和 loser downgrade。",
		],
		recommendedWork: [
			"保持 hard-eval claim ledger 与 gate:claim-release marker 作为 release 级门禁。",
			"继续把同一 ledger/schema 接入通用 re_swarm 独立 sub-agent/session runtime，并保持 LiveConflictArbitrationMatrixGateV1 / StructuredClaimMergeV1 claim-aware merge 的冲突仲裁样本。",
			"在 claim gap 修复后重新运行 gate:claim-release 生成 pass marker，再进入 re_compiler final。",
		],
	},
];

const HARDENING_GAP_CATALOG = [
	{
		gapId: "parallel.re_swarm_live_provider_manifest_parity",
		pillar: "parallel_scheduling",
		title: "re_swarm/provider worker manifest parity",
		targetCapability: "re_swarm/provider workers carry the same manifest, claim, repair, child session, and provider runtime proof as agent-dogfood.",
		status: "ready_for_live",
		priority: 1,
		ownerRuntime: "re_swarm + WorkerChildSessionRuntimeBatchV1 + ParallelProviderWorkerMatrixV1 + SwarmProviderManifestParityGateV1",
		currentEvidence: ["gate:swarm-provider-manifest-parity", "gate:worker-child-session", "gate:parallel-provider-worker-matrix", "gate:worker-lease-scheduler", "SwarmProviderSharedMergeLedgerV1", "SwarmProviderRetryRepairBindingV1", "all_child_sessions_match_parity_rows", "child-session-nonfirst-row-drift", "LiveProviderBackedSharedLedgerMatrixV1", "ProviderWorkerRetryWindowManifestBindingChainV1", "ProviderBackedLongWindowSharedMergeLedgerV1", "ProviderWorkerExtendedRetryManifestChainV1"],
		missingRuntimeProof: ["broader real remote provider-backed shared merge ledger windows beyond bounded four-window long-window ledger", "longer provider worker retry/repair manifest binding across real remote retry windows beyond bounded seven-attempt chain"],
		closureGate: "gate:swarm-provider-manifest-parity",
		regressionCommands: ["npm run gate:swarm-provider-manifest-parity", "npm run gate:worker-child-session", "npm run gate:parallel-provider-worker-matrix", "npm run gate:runtime-claim-ledger"],
		nextCommand: "node scripts/reverse-agent/swarm-provider-manifest-parity-gate.mjs . --strict",
		artifacts: [
			"~/.repi/agent/recon/evidence/swarms/*-subagent-runtime-manifests.json",
			"~/.repi/agent/recon/evidence/swarms/*-worker-child-session-runtime.json",
			"~/.repi/agent/recon/evidence/swarms/*-claim-ledger.jsonl",
		],
		acceptanceCriteria: [
			"all provider child workers have stdout/stderr/session/tool/model digests",
			"all_child_sessions_match_parity_rows binds every WorkerChildSessionRuntimeBatchV1 session to parityRows by workerId/model/sessionDir/hash/mergeKey/claimRefs/failureRepairRefs and rejects child-session-nonfirst-row-drift",
			"failure/repair rows reference the same worker manifest and retryBudget",
			"live provider-backed shared ledger windows cover at least two provider types and all worker/claim/failure refs",
			"ProviderBackedLongWindowSharedMergeLedgerV1 covers at least four provider-backed windows, all provider types, all workers, all claims, all failure/repair refs, runtime manifest refs, and env-ref-only secret handling",
			"provider retry window attempt rows are monotonic and stay bound to the same runtime manifest hash",
			"ProviderWorkerExtendedRetryManifestChainV1 covers at least seven retry attempts across at least two providers with same-signature manifest binding and terminal status proof",
			"claim-aware merge blocks narrative-only worker promotion",
		],
	},
	{
		gapId: "context.cross_session_multi_compact_live_matrix",
		pillar: "long_context_compaction",
		title: "cross-session multi-compact live matrix",
		targetCapability: "multiple compaction/resume cycles across sessions keep exact contextPath/hash priority and close operator/proof-loop ledgers.",
		status: "ready_for_live",
		priority: 2,
		ownerRuntime: "re_context + CompactResumeLedgerV2 + CrossSessionResumeLiveV1 + CrossSessionMultiCompactMatrixGateV1",
		currentEvidence: ["gate:cross-session-multi-compact-matrix", "gate:multi-compact-pressure", "gate:cross-session-resume-live", "gate:context-runtime-schema", "ProviderContinuationMatrixV1", "RemoteProviderContinuationSampleMatrixV1", "longer_cross_session_compaction_chain", "five_cycle_cross_session_compaction_chain", "compact_resume_ledger_cycle_terminal_alignment", "ledger-terminal-missing-after-rehash"],
		missingRuntimeProof: ["broader real remote provider continuation samples beyond bounded five-sample matrix", "longer cross-session compaction chains across live sessions beyond five-cycle bounded matrix"],
		closureGate: "gate:cross-session-multi-compact-matrix",
		regressionCommands: ["npm run gate:cross-session-multi-compact-matrix", "npm run gate:multi-compact-pressure", "npm run gate:cross-session-resume-live", "npm run gate:compact-resume-ledger-v2"],
		nextCommand: "node scripts/reverse-agent/cross-session-multi-compact-matrix-gate.mjs . --strict",
		artifacts: [
			"~/.repi/agent/recon/evidence/contexts/*.md",
			"~/.repi/agent/recon/memory/compaction-resume-transitions.jsonl",
			"~/.repi/agent/recon/memory/compaction-resume-ledger-v2-report.json",
		],
		acceptanceCriteria: [
			"old contextPath wins over latest fallback after multiple compactions",
			"cross-session resume validates contextSha256 and artifact hashes",
			"five compact/resume cycles produce fifteen CompactResumeLedgerV2 transitions without terminal reopen",
			"compact_resume_ledger_cycle_terminal_alignment proves every compact cycle has queued→running→terminal, terminal state matches resumeClosure/operatorProofClosure, context hash matches, and no orphan transitions",
			"remote provider continuation sample matrix stays env-ref-only, request-log hashed, secret-free, and after exact resume",
			"operator/proof-loop closure transitions to done|blocked|exhausted without reopening terminal rows",
		],
	},
	{
		gapId: "repair.provider_worker_rollback_unification",
		pillar: "failure_self_repair",
		title: "provider/worker repair rollback unification",
		targetCapability: "provider, operator, compound-frontier, and worker repairs share FailureLedgerEventV1/RepairQueueItemV1 signatures, rollback policy, and regression gates.",
		status: "ready_for_live",
		priority: 1,
		ownerRuntime: "provider failure injection + repair rollback + agent-dogfood failure binding + WorkerProviderRepairRollbackUnificationGateV1",
		currentEvidence: ["gate:worker-provider-repair-rollback-unification", "gate:provider-failure-injection", "gate:repair-rollback-policy", "gate:agent-dogfood-failure-signature-binding", "ProviderWorkerLiveRepairMatrixV1", "MultiAttemptRetryWindowCompletionChainV1", "ProviderWorkerStateLineageSnapshotMatrixV1", "CompoundProviderLongHorizonRepairCompletionChainV1", "RemoteProviderStateChangingRepairMatrixV1", "DeepCompoundProviderRepairCompletionChainV1"],
		missingRuntimeProof: ["broader real remote provider-worker state-changing repairs beyond bounded six-row remote provider state matrix", "longer compound/provider repair completion across real retry windows beyond bounded seven-attempt deep chain"],
		closureGate: "gate:worker-provider-repair-rollback-unification",
		regressionCommands: ["npm run gate:worker-provider-repair-rollback-unification", "npm run gate:provider-failure-injection", "npm run gate:repair-rollback-policy", "npm run gate:agent-dogfood-failure-signature-binding"],
		nextCommand: "node scripts/reverse-agent/worker-provider-repair-rollback-unification-gate.mjs . --strict",
		artifacts: [
			".repi-harness/evidence/failures/ledger.jsonl",
			".repi-harness/evidence/repairs/queue.jsonl",
			"~/.repi/agent/recon/evidence/autofix/*-repair-rollback-policy.json",
		],
		acceptanceCriteria: [
			"same signature maps failure -> repair -> rollback -> regression gate",
			"exhausted status cannot enqueue unpaused rerun",
			"provider/worker failures preserve manifest, request-log, and rollback evidence refs",
			"state-changing provider worker repairs preserve baseline snapshot, scoped mutation, restored tree hash, and regression proof",
			"RemoteProviderStateChangingRepairMatrixV1 covers at least six provider-worker state-changing repairs with manifest/request-log/rollback-policy refs, baseline restore lineage, regression proof, and secret-free env-ref handling",
			"compound/provider long-horizon repair chains keep monotonic same-signature attempt proof beyond three attempts",
			"DeepCompoundProviderRepairCompletionChainV1 covers at least seven same-signature attempts and twelve total attempt rows with per-attempt runtime refs and regression proof",
		],
	},
	{
		gapId: "claim.live_conflict_arbitration_matrix",
		pillar: "automatic_division_validation",
		title: "live conflict arbitration matrix",
		targetCapability: "agent-dogfood, re_swarm, compound-frontier, and provider workers all emit structured conflict tables with winner evidence and loser downgrade.",
		status: "ready_for_live",
		priority: 1,
		ownerRuntime: "StructuredClaimMergeV1 + AgentDogfoodStructuredClaimMergeGateV1 + runtime claim ledger + LiveConflictArbitrationMatrixGateV1",
		currentEvidence: ["gate:live-conflict-arbitration-matrix", "gate:structured-claim-merge", "gate:agent-dogfood-structured-claims", "gate:runtime-ledger-quality", "ProviderBackedLongWindowConflictMatrixV1", "ExtendedSynthesizerTopicParseMatrixV1"],
		missingRuntimeProof: ["broader real remote provider-backed conflict windows beyond the bounded three-window long-window matrix", "more synthesizer topics parsed from longer live runs beyond the bounded six-topic extended matrix"],
		closureGate: "gate:live-conflict-arbitration-matrix",
		regressionCommands: ["npm run gate:live-conflict-arbitration-matrix", "npm run gate:structured-claim-merge", "npm run gate:agent-dogfood-structured-claims", "npm run gate:runtime-ledger-quality"],
		nextCommand: "node scripts/reverse-agent/live-conflict-arbitration-matrix-gate.mjs . --strict",
		artifacts: [
			"~/.repi/agent/recon/evidence/swarms/*-structured-claim-merge.json",
			".repi-harness/evidence/remote/agent-parallel-dogfood/*/structured-claim-merge.json",
			".repi-harness/evidence/remote/compound-frontier/*/claim-ledger.jsonl",
		],
		acceptanceCriteria: [
			"every finalClaim has artifact sha256, JSON query, verifierPass, and no unresolved challenge",
			"conflicts name claimIds, topic, winner evidence, loser downgrade, and resolution reason",
			"provider-backed same-window conflict tables include at least two provider workers, runtime manifest refs, request-log refs, and loser blocked promotion",
			"provider-backed long-window conflict matrix covers at least two windows, at least two provider workers per window, at least five provider-backed claims, runtime manifest refs, request-log refs, and env-ref-only secret handling",
			"long-run and extended synthesizer topic parse matrices cover authz, JS replay, provider timeout, API rate-limit, session token scope, and API idempotency replay topics with final winners only",
			"orchestration success remains separate from platform claim success",
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

function hardeningGapEvidenceState(pillars, gap) {
	const pillar = pillars.find((row) => row.id === gap.pillar);
	const availableChecks = new Set(pillar?.checks.filter((check) => check.status === "pass").map((check) => check.id) ?? []);
	const failedChecks = new Set(pillar?.checks.filter((check) => check.status !== "pass").map((check) => check.id) ?? []);
	return {
		pillarStatus: pillar?.status ?? "missing",
		normalUse: Boolean(pillar?.normalUse),
		availableChecks: [...availableChecks].filter((id) => gap.currentEvidence.some((item) => id.includes(item.replace(/^gate:/, "").replace(/-/g, "_")) || item.includes(id))),
		failedChecks: [...failedChecks],
	};
}

function buildHardeningGapLedger(pillars) {
	const generatedAt = new Date().toISOString();
	const gaps = HARDENING_GAP_CATALOG.map((gap, index) => {
		const evidenceState = hardeningGapEvidenceState(pillars, gap);
		const closureReady = gap.regressionCommands.length > 0 && Boolean(gap.closureGate) && gap.acceptanceCriteria.length >= 3 && gap.missingRuntimeProof.length > 0;
		return {
			kind: "AutonomousHardeningGapV1",
			schemaVersion: 1,
			seq: index + 1,
			gapId: gap.gapId,
			pillar: gap.pillar,
			title: gap.title,
			targetCapability: gap.targetCapability,
			status: gap.status,
			priority: gap.priority,
			ownerRuntime: gap.ownerRuntime,
			currentEvidence: gap.currentEvidence,
			evidenceState,
			missingRuntimeProof: gap.missingRuntimeProof,
			closureGate: gap.closureGate,
			regressionCommands: gap.regressionCommands,
			nextCommand: gap.nextCommand,
			artifacts: gap.artifacts,
			acceptanceCriteria: gap.acceptanceCriteria,
			promotionPolicy: "do_not_mark_top_autonomous_until_closureGate_passes_and_acceptanceCriteria_are_artifact_backed",
			readyForImplementation: closureReady,
		};
	});
	const closureGateCount = new Set(gaps.map((gap) => gap.closureGate)).size;
	const gapHash = sha256(JSON.stringify(gaps.map(({ seq, gapId, pillar, closureGate, regressionCommands, acceptanceCriteria }) => ({ seq, gapId, pillar, closureGate, regressionCommands, acceptanceCriteria }))));
	return {
		kind: "AutonomousHardeningGapLedgerV1",
		schemaVersion: 1,
		generatedAt,
		appendOnlyTarget: ".repi-harness/evidence/autonomy-control-plane/*/hardening-gap-ledger.json",
		promotionPolicy: "topAutonomousDefinition remains false while any gap status is not closed",
		gapCount: gaps.length,
		closureGateCount,
		highestPriorityOpen: Math.min(...gaps.filter((gap) => gap.status !== "closed").map((gap) => gap.priority)),
		gapHash,
		gaps,
	};
}

function buildManifest(root) {
	const auditSelf = evaluateCheck(root, SELF_CHECK);
	const controlPlaneContractAudit = validateControlContractDefinitions(root);
	const pillars = REQUIREMENTS.map((requirement) => evaluatePillar(root, requirement));
	const hardeningGapLedger = buildHardeningGapLedger(pillars);
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
		topAutonomousDefinitionReason: "核心组织链路、MemoryOrchestratorV6 mandatory memory control loop、MemoryDepositionEngineV7 runtime step event bus、MemoryExperienceEngineV8 经验化沉淀、MemorySkillCapsuleV9 技能胶囊资产化、MemoryDistillPromotionV10 provider 蒸馏提升门、MemoryQualityLedgerV11 质量反馈学习闭环、MemoryReplayEvaluatorV12 A/B replay 因果归因、MemoryStrategyCapsuleV13 可执行战术胶囊、MemoryActiveKernelV14 主动记忆决策内核、MemoryMaturationRuntimeV15 记忆成熟/保鲜闭环、agent-dogfood subagent runtime manifest、AutonomousRuntimeBatchV1 strict fixture/gate、re_swarm → WorkerChildSessionRuntimeBatchV1 → WorkerRuntimePoolV1 live bounded bridge，以及 agent-dogfood structured claim merge / re_swarm / compound runtime claim ledger、ContextPackV2 exact resume marker/negative fixtures/closure gate、CrossSessionResumeLiveV1 跨 session resume/provider continuation gate、CompactResumeLedgerV2 状态机/runtime gate、strict failure/repair fixture、RepairRollbackPolicyV1 baseline/allowlist/regression/rollback gate、ToolCallTraceLedgerV1 append-only tool trace、runtime failure/repair ledger hooks、compound/role retry failure-repair 输出、strict claim release marker、ParallelProviderWorkerMatrixV1 多 worker provider 并发回归、RemoteProviderLongRunV1 可选远程长跑 gate 和 supervisor/compiler/complete final gate 已可用；MultiCompactPressureGateV1 多轮 compact 压力、old contextPath、幂等 replay、scope/artifact drift 负例和 operator/proof-loop writeback 已接入；FailureSignaturePriorityGateV1 已把 exhausted/repeated runtime failure signature 优先送入 proof-loop/knowledge graph 并验证 target scope；SwarmProviderManifestParityGateV1 已将 re_swarm/provider worker manifest parity 接成 closure gate；AutonomousClosureReadinessGateV1 / gate:autonomous-closure-readiness 已汇总验证每个 hardening gap closure gate 的 package、script、top harness child gate、autonomy contract、docs 和 strict --no-write 状态；CapabilityClaimReleaseBundleGateV1 / gate:capability-release-bundle 已把 release-facing 能力声明绑定到命令证据、source hash、product boundary、autonomy control plane 与 closure readiness bundle；ReleaseCiPipelineGateV1 / gate:release-ci-pipeline 已把这些 gates 显式接入 GitHub Actions release CI 与 docs 模板，并阻断 live secret 依赖；ReleaseEvidenceIndexGateV1 / gate:release-evidence-index 已把 autonomy、closure readiness、capability bundle、CI pipeline 与 source hashes 汇总成 secret-free hash-chain evidence index；ReLaneSpecialistCommandPackGateV1 / gate:relane-specialist-command-pack 已把 route、lane command pack、analyzer anchors、self-heal commands 与 proof-exit bridge 接成专项闭环；更深 runtime ledger wiring 仍可继续硬化。",
		pillars,
		notYetTopAutonomousDefinition: hardeningItems,
		hardeningGapLedger,
		hardeningGapLedgerSummary: {
			gapCount: hardeningGapLedger.gapCount,
			closureGateCount: hardeningGapLedger.closureGateCount,
			highestPriorityOpen: hardeningGapLedger.highestPriorityOpen,
			gapHash: hardeningGapLedger.gapHash,
		},
		recommendedNonTestWorkOrder: [
			"保持 ReconParallelPlanV1、releaseGateMetadata、claimGatePolicy、strict claim marker 在 re_swarm / re_supervisor / re_compiler / re_complete 间同源流转。",
			"保持 AutonomousClosureReadinessGateV1 / gate:autonomous-closure-readiness 作为 gap closure gate 总控，不允许 closureGate 只存在于文档或 package 而未进入 top harness child gate 与 strict --no-write 证据。",
			"保持 CapabilityClaimReleaseBundleGateV1 / gate:capability-release-bundle 作为 release 能力声明总控，不允许 README 或发布说明把 narrative-only 状态提升为已验证能力。",
			"保持 ReleaseCiPipelineGateV1 / gate:release-ci-pipeline 作为 release CI 总控，确保 product boundary 与 closure/capability gates 在 top harness 和 repo check 前显式执行，且 CI 不依赖 live provider secrets。",
			"保持 ReleaseEvidenceIndexGateV1 / gate:release-evidence-index 作为 release evidence 总索引，确保发布能力声明能追溯到 command outputs、source hashes、gap ledger、closure readiness、capability bundle 和 CI pipeline。",
			"保持 AutonomousRuntimeBatchV1 strict gate 覆盖 subagent manifest / shard state / compact resume / repair budget / runtime claim promotion，并继续把 role contract + claim ledger + conflict table 扩展到 live 独立子会话执行态。",
			"继续把 strict failure ledger + repair queue + bounded retry signature + rollback criteria 接入更多 live runtime 回归门禁。",
			"保持 MultiCompactPressureGateV1 与 ContextPackV2 / ResumeContractV2 / CompactResumeLedgerV2 的 live 回归口径同步，并继续扩展更深 runtime ledger wiring。",
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
		"## AutonomousHardeningGapLedgerV1",
		"",
		`gap_count: ${manifest.hardeningGapLedger.gapCount}`,
		`closure_gate_count: ${manifest.hardeningGapLedger.closureGateCount}`,
		`highest_priority_open: ${manifest.hardeningGapLedger.highestPriorityOpen}`,
		`gap_hash: ${manifest.hardeningGapLedger.gapHash}`,
		"",
		"gaps:",
		...manifest.hardeningGapLedger.gaps.map(
			(gap) =>
				`- ${gap.gapId}: status=${gap.status} priority=${gap.priority} pillar=${gap.pillar} closure=${gap.closureGate} next=${gap.nextCommand}`,
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
	writeFileSync(join(dir, "hardening-gap-ledger.json"), `${JSON.stringify(manifest.hardeningGapLedger, null, 2)}\n`);
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

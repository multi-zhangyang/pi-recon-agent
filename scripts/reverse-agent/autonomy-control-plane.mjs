#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const RUNTIME_MIRRORS = ["packages/coding-agent/src/core/recon-profile.ts", ".pi/extensions/reverse-pentest-core.ts"];

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
				description: "现有 dogfood runner 具备真实并发进程、角色结果和 synthesizer 合并证据结构。",
				files: ["bench/recon-remote/agent-dogfood/parallel-run.mjs"],
				markers: ["Promise.all", "roleRuns", "synthesizerRun", "overlapStats", "sessionDigest"],
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
		],
		hardeningNeeded: [
			"把 ReconParallelPlanV1 的 releaseGateMetadata 接进外层 release gate/CI 聚合，而不是只保留在 swarm/supervisor artifact。",
			"把 re_swarm 的 command-level worker packet 升级为可选独立 Pi agent/session runtime，并记录 PID、session dir、stdout/stderr hash、model/tool call digest。",
			"让 shard plan 支持真实并发执行、依赖检查、timeout/cancel、资源配额和多 shard result merge。",
			"把 worker merge 从文本摘要升级为 structured claim merge，并在 supervisor 前阻断缺证据或冲突 claim。",
		],
		recommendedWork: [
			"保持 npm run audit:parallel-plan 作为 frontier --plan 与 dogfood --plan-only 的离线 smoke gate。",
			"让 release gate 读取 swarm/supervisor 的 releaseGateMetadata、planCoverage 和 claimGatePolicy。",
			"让 agent-dogfood 执行态把 planId/source/worker merge keys 写入每个 worker runtime digest。",
		],
	},
	{
		id: "long_context_compaction",
		title: "长期上下文 / compact / resume",
		statusWhenPassing: "usable",
		normalChecks: [
			{
				id: "context_pack_runtime",
				description: "内核和文件型 profile 都由 Pi-RECON 自有 context pack/resume/compaction contract 接管。",
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
				description: "已有独立静态 harness 检查 context pack、owned compaction、resume contract、evidence summarization 和 budget continuation。",
				files: ["scripts/reverse-agent/context-compact-audit.mjs"],
				markers: ["context_pack", "owned_compaction_provider", "resume_contract_continuation", "evidence_summarization", "budget_continuation"],
			},
			{
				id: "context_docs_contract",
				description: "公开文档记录 context/resume pack、owned compaction 和 audit harness，不依赖 Pi 默认 compact 说明。",
				files: ["docs/reverse-agent/README.md"],
				markers: ["Context/resume pack 闭环", "Pi-RECON owned compaction kernel update", "context-compact-audit.mjs"],
			},
		],
		hardeningNeeded: [
			"把 exact resume 的 hash drift、target mismatch、missing artifact、cross-session contamination 负例补成单元/fixture gate。",
			"knowledge graph/latest artifact 查询继续按 mission/session/workspace/target 做更严格过滤，避免跨任务污染。",
			"compact resume ledger 继续扩展 queue 状态机：running/done/blocked/exhausted、auto-resume budget 和多次 compact 幂等回放。",
			"completion audit 继续深接 exact resume closure，阻断 verified 但未闭合或 drift-blocked 的 resume contract。",
		],
		recommendedWork: [
			"保持 ContextPackV2 / ResumeContractV2 runtime markers 与 context-compact-audit.mjs 同步。",
			"把 memory/compaction-resume-ledger.jsonl 与 re_operator/re_proof_loop 的执行闭环做状态回写。",
			"补静态/单元级假 artifact 场景：stale latest、hash drift、multi compact、target unresolved、cross-session contamination。",
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
				description: "并行 runner 的 role/synthesizer 有 bounded retry 和 attempt 记录。",
				files: ["bench/recon-remote/agent-dogfood/parallel-run.mjs"],
				markers: ["RECON_ROLE_RETRIES", "withRetries", "attempts", "strictRunPassed"],
			},
		],
		hardeningNeeded: [
			"把 canonical failure/repair ledger 写入继续扩展到 compound、agent role retry 和 plan-only runner 输出。",
			"为 runtime failure ledger 增加 strict schema fixture、重复 signature 去重窗口和回归 gate。",
			"所有 retry 继续复用同一 signature 和 budget/retryBudget；达到 exhausted 后停止盲 retry，转 repair/escalate。",
			"dogfood/parallel runner 保存 per-attempt stdout/stderr/session artifact，避免 retry 覆盖关键失败证据。",
			"为 autofix/operator/compound 类动作加入 baseline、allowlist、passed gate regression 和 rollback criteria。",
		],
		recommendedWork: [
			"保持 .pi/evidence/failures/ledger.jsonl 和 .pi/evidence/repairs/queue.jsonl schema，把 retryBudget/evidenceWriteback/blockedConditions 保持为必填。",
			"把 compound-frontier failedGates、agent-dogfood withRetries 写入同一 failure event。",
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
				description: "并行 dogfood runner 已记录 roleGateMatrix、toolResultsCaptured、synthesizerReconciled 等运行级分工验证信号。",
				files: ["bench/recon-remote/agent-dogfood/parallel-run.mjs"],
				markers: ["roleGateMatrix", "synthesizerReconciled", "toolResultsCaptured", "antiSelfDelusion"],
			},
			{
				id: "supervisor_claim_gate_policy",
				description: "re_supervisor 已消费 swarm parallelPlan/planCoverage，并输出 claimGatePolicy 防止 narrative-only final pass。",
				files: RUNTIME_MIRRORS,
				markers: [
					"function supervisorClaimGatePolicy",
					"function supervisorPlanCoverage",
					"claimGatePolicy",
					"claim_gate_policy.final_pass_requires_verifier=true",
					"claim_gate_policy.orchestration_score_never_implies_platform_success=true",
				],
			},
		],
		hardeningNeeded: [
			"把 role prompt 升级为 contract.json：每个角色声明 mustEmit、allowedClaimKinds、forbiddenClaimKinds、handoff target。",
			"新增 append-only claim ledger：artifact_handoff、claim、validation、challenge、resolution event，带 prevHash/eventHash。",
			"每个 proven/final_pass claim 必须绑定 artifact sha256 和 JSON query，并有 verifier pass 且无 unresolved adversary challenge。",
			"synthesizer 输出 conflict table：claimIds、冲突主题、胜出证据、降级原因、未解决冲突。",
			"hard-score/summary 拆分 orchestration_score 与 platform_claim_score，避免把 agent 编排成功误读成平台 claim 全绿。",
		],
		recommendedWork: [
			"先在 agent-dogfood 输出 contract.json、ledger.jsonl、gate.json，不改变模型调用流程。",
			"再让 hard-score 读取 ledger gate，把 orchestration 与 platform claims 分开计分。",
			"最后把同一 ledger schema 回流到 re_supervisor / re_compiler。",
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
	const schemaInvariants = new Set(json?.["x-piReconInvariants"] ?? definition?.["x-piReconInvariants"] ?? []);
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
		topAutonomousDefinitionReason: "核心组织链路、ContextPackV2 exact resume marker、runtime failure/repair ledger hooks 和控制面字段/validator 可用，但独立子会话 runtime、exact resume 负例/closure gate、compound/role retry ledger 和 claim-level runtime 合成仍需硬化。",
		pillars,
		notYetTopAutonomousDefinition: hardeningItems,
		recommendedNonTestWorkOrder: [
			"把已通过离线审计的 ReconParallelPlanV1 扩展到 re_swarm / re_supervisor / release gate。",
			"固化 role contract + claim ledger + conflict table，先拦截 narrative-only merge。",
			"固化 failure ledger + repair queue + bounded retry signature + rollback criteria。",
	"把 ContextPackV2 / ResumeContractV2 的 exact resume 负例 fixture 与 completion closure gate 补齐。",
			"完成上述控制面后，再恢复真实平台/live benchmark。",
		],
		testCommandsPaused: TEST_COMMANDS_PAUSED,
	};
}

function formatMarkdown(manifest) {
	const lines = [
		"# Pi-RECON Autonomy Control Plane",
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
			? "Pi-RECON 当前具备专业逆向/渗透任务组织能力：能把任务压入 map→operation→delegate→swarm→supervisor→context→operator→verifier→compiler→replayer→autofix→proof-loop 的控制面。"
			: "Pi-RECON 当前组织能力 marker 不完整，需要先修复 failed checks。",
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
	const dir = join(root, ".pi", "evidence", "autonomy-control-plane", stamp);
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, "result.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	writeFileSync(join(dir, "report.md"), formatMarkdown(manifest));
	return dir;
}

function printHelp() {
	console.log(`Usage: node scripts/reverse-agent/autonomy-control-plane.mjs [root] [--json] [--write] [--strict]\n\nStatic Pi-RECON organization-control audit. It does not run real-platform benchmarks, provider/model calls, or live network tests.`);
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

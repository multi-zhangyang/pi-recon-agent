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
	],
};

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
		],
		hardeningNeeded: [
			"定义统一 ReconParallelPlan / ReconWorkItem / ReconShard manifest，把 re_swarm、frontier shard 和 dogfood role 统一到同一调度合同。",
			"把 re_swarm 的 command-level worker packet 升级为可选独立 Pi agent/session runtime，并记录 PID、session dir、stdout/stderr hash、model/tool call digest。",
			"让 shard plan 支持真实并发执行、依赖检查、timeout/cancel、资源配额和多 shard result merge。",
			"把 worker merge 从文本摘要升级为 structured claim merge，并在 supervisor 前阻断缺证据或冲突 claim。",
		],
		recommendedWork: [
			"新增 parallel_plan 区块，字段包含 planId/source/workers/merge/evidenceOrder。",
			"先让 frontier-orchestrator --plan --json --shards=N 输出 machine-readable manifest，不立即恢复 live run。",
			"再让 agent-dogfood runner 支持 --plan-json/--plan-only，保留当前固定角色作为 fallback。",
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
					"buildReconCompactionSummary",
					"buildReconCompactionResumeContract",
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
			"re_context resume 支持按 compactionEntryId/contextPath 精确加载原 pack，并校验 contextSha256、missionId、sessionId、cwd、target。",
			"artifact index / latest context / knowledge graph 按 mission/session/workspace/target 过滤，避免跨任务污染。",
			"artifactIndex 增加 sha256、mtime、size、exists、evidence_rank、source_command，并在恢复时拒绝 hash drift 或缺失关键 artifact。",
			"compact resume telemetry 改为 append-only ledger，持久化 auto-resume budget、idempotency 和多次 compact 状态。",
			"completion audit 阻断所有 verified 但未闭合的 resume contract，而不仅仅是 autoResumeTriggered 的合同。",
		],
		recommendedWork: [
			"设计 ContextPackV2 / ResumeContractV2 字段，不改变当前 compact hook 行为。",
			"把 memory/compaction-auto-resume-board.md 扩展为 compaction-resume-ledger.jsonl。",
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
			"新增统一 failure ledger：source、scope、category、signature、attempt/maxAttempts、status、failedGates、artifact hashes。",
			"由 failureToRepair 生成 repair queue，把 artifact_stale、runtime_failed、tool_missing、contract_gap、same_window_gap 映射到机器可执行修复动作。",
			"所有 retry 使用同一失败签名和预算；达到 exhausted 后停止盲 retry，转 repair/escalate。",
			"dogfood/parallel runner 保存 per-attempt stdout/stderr/session artifact，避免 retry 覆盖关键失败证据。",
			"为 autofix/operator/compound 类动作加入 baseline、allowlist、passed gate regression 和 rollback criteria。",
		],
		recommendedWork: [
			"定义 .pi/evidence/failures/ledger.jsonl 和 .pi/evidence/repairs/queue.jsonl schema。",
			"先在 compound-frontier failedGates、agent-dogfood withRetries、replayer failed/blocked 三处写入 failure event。",
			"再让 proof-loop 按 failure signature 去重，并把 exhausted 状态交给 operator escalate。",
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

function readProjectFile(root, relativePath) {
	const path = join(root, relativePath);
	if (!existsSync(path)) return { relativePath, path, exists: false, text: "", bytes: 0, sha256: null };
	const text = readFileSync(path, "utf8");
	return { relativePath, path, exists: true, text, bytes: Buffer.byteLength(text), sha256: sha256(text) };
}

function markerRows(file, markers) {
	return markers.map((marker) => ({ marker, present: file.exists && file.text.includes(marker) }));
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
	const pillars = REQUIREMENTS.map((requirement) => evaluatePillar(root, requirement));
	const normalUseGuarantee = auditSelf.status === "pass" && pillars.every((pillar) => pillar.normalUse);
	const hardeningItems = pillars.flatMap((pillar) => pillar.hardeningNeeded.map((item) => `${pillar.id}: ${item}`));
	return {
		kind: "pi-recon-autonomy-control-plane",
		version: 1,
		generatedAt: new Date().toISOString(),
		root,
		auditMode: "static-source-and-harness-contract-only",
		normalUseGuarantee,
		currentLevel: normalUseGuarantee ? "professional reverse/pentest task organization agent" : "incomplete organization profile",
		auditSelf,
		topAutonomousDefinition: false,
		topAutonomousDefinitionReason: "核心组织链路可用，但独立子会话调度、精确 compact 恢复、统一失败账本、claim-level 验证仍需硬化。",
		pillars,
		notYetTopAutonomousDefinition: hardeningItems,
		recommendedNonTestWorkOrder: [
			"固化 ReconParallelPlan / ReconWorkItem manifest，统一 re_swarm、frontier shard、dogfood role。",
			"固化 role contract + claim ledger + conflict table，先拦截 narrative-only merge。",
			"固化 failure ledger + repair queue + bounded retry signature + rollback criteria。",
			"设计 ContextPackV2 / ResumeContractV2，实现按 contextPath/compactionEntryId 的精确恢复不变量。",
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

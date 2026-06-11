# REPI Agent

REPI Agent 是独立的逆向 / 渗透任务组织型 agent 产品。它把一次安全研究任务拆成可追踪的执行内核、证据账本、分工计划、上下文恢复包、验证矩阵、复现矩阵和 proof loop，目标是让 agent 不只是“会回复”，而是能把复杂逆向/渗透工程按阶段推进、留证、恢复和审计。

当前仓库包含三个层次，但默认只走独立 `repi`：

- `packages/coding-agent/src/cli/repi-bootstrap.ts`：REPI 产品级 bootstrap。无论是源码 wrapper 还是 npm/bin 直接启动，只要命令身份是 `repi`，都会默认启用 `--recon`、隔离资源、初始化 `~/.repi/agent`，不会依赖外层 shell hack。
- `packages/coding-agent/src/core/recon-profile.ts`：内置 REPI profile，实现 slash command、tool、prompt、storage、compaction hook 和控制面 gate。`repi` 默认直接启用这个内置 kernel。
- `repi-profile/extensions/reverse-pentest-core.ts`：保留给兼容/迁移的文件型 profile 镜像，不再默认写入或启用到普通 `pi` 的 `~/.pi/agent`。

> 当前收口状态：REPI 已能正常作为专业逆向/渗透任务组织 agent 使用；并行计划、agent-dogfood subagent runtime manifest、AgentDogfoodFailureSignatureBindingGateV1、AgentDogfoodStructuredClaimMergeGateV1、AutonomousHardeningGapLedgerV1、AutonomousClosureReadinessGateV1、CapabilityClaimReleaseBundleGateV1、ReleaseCiPipelineGateV1、SwarmProviderManifestParityGateV1、WorkerProviderRepairRollbackUnificationGateV1、LiveConflictArbitrationMatrixGateV1、AutonomousRuntimeBatchV1 strict gate、agent-dogfood / re_swarm / compound-frontier runtime ClaimLedgerEventV1、上下文 pack/resume、supervisor 分工验证、strict claim release gate、strict failure/repair schema fixture、`RepairRollbackPolicyV1` baseline/allowlist/regression/rollback gate、provider/worker repair rollback unification gate、`ToolCallTraceLedgerV1` append-only tool trace、runtime failure/repair ledger hooks、离线控制面 gates 已接入。最终输出不会只靠叙述放行：`re_supervisor`、`re_compiler final`、`re_complete audit` 都会读取 strict claim marker，并在 required claim gap 未闭合时阻断最终发布。

## 目录

- [能力概览](#能力概览)
- [环境要求](#环境要求)
- [快速安装](#快速安装)
- [启动 REPI](#启动-repi使用-repi)
- [独立 repi profile](#安装方式独立-profile不污染原-pi)
- [常用工作流](#常用工作流)
- [上下文压缩与精确恢复](#上下文压缩与精确恢复)
- [模型 / provider 配置](#模型--provider-配置)
- [离线验证与 gates](#离线验证与-gates)
- [关键文件结构](#关键文件结构)
- [排错](#排错)

## 能力概览

REPI 的核心不是单个 prompt，而是一套可落盘、可恢复、可审计的任务控制面。

### 1. 任务组织链路

推荐主链路：

```text
re_kernel → re_decision_core → re_map → re_operation → re_delegate
→ re_swarm → re_supervisor → re_reflect → re_context
→ re_operator → re_verifier → re_compiler → re_replayer
→ re_autofix → re_proof_loop → re_knowledge_graph → re_complete
```

对应能力：

- `re_kernel`：生成执行内核、能力矩阵、artifact contract、stall recovery 策略。
- `re_decision_core`：维护目标栈、gate pressure、operator next command。
- `re_map` / `re_lane` / `re_autopilot`：被动映射、专项 lane 规划、降级执行和自动续跑。
- `re_operation` / `re_delegate` / `re_swarm`：把大任务拆成 phase、worker packet、parallel plan。
- `re_supervisor`：审查 worker 输出，生成冲突表、claim gate policy 和修复队列。
- `re_reflect` / `re_knowledge_graph`：沉淀经验、case signature、playbook 和跨任务知识；`re_knowledge_graph` 会消费 `KnowledgeScopeIsolationV1`，阻断跨 workspace/target/route 污染 artifact 进入 similarity / command hints。
- `re_memory events/search-events/verify/repair-index/snapshot/compact-resume/eval/feedback/quality/replay/strategy/active/scope/artifact-scope/vector/consolidate/distill/sediment/supervise/deposit/deposition-report/experience/skills`：读取结构化长期记忆、检索可复用 case、校验/修复事务化 store、汇总高质量经验；`deposit` / runtime hook 通过 **MemoryDepositionEngineV7** 写 `deposition-events.jsonl` 与 `deposition-report.json`，把 tool/shell 结果自动绑定到 MemoryEventV1、artifact hash、claim/compact-resume 上；`active` 会运行 **MemoryActiveKernelV14**，把 sedimentation / quality / replay / strategy 融合成主动注入、复用、验证、回避和 compact-resume hints；`artifact-scope` 会输出 `ArtifactScopeFilterV1`，检查 latest artifact/context index 是否会绕过 scope 隔离。
- `re_context`：生成可恢复上下文包，支持 exact resume。
- `re_operator`：把 next commands 转成 bounded operator queue。
- `re_verifier` / `re_compiler` / `re_replayer` / `re_autofix` / `re_proof_loop`：验证、报告编译、复现、修复、闭环证明。
- `re_complete`：完成审计，阻断缺证据、未完成 compact resume、claim gate 缺口。

### 2. 已接入的控制面

- `ReconParallelPlanV1`：并行 worker plan、coverage、release gate metadata。
- `ContextPackV2` / `ResumeContractV2`：上下文 pack 带 `schemaVersion: 2`、`createdAt`、`sessionId`、`cwd`、`workspaceRoot`、`contextSha256`、artifact sha256、scope、closure、idempotency key 和可机读 `resumeContract`。
- exact context resume：`re_context resume <contextPath>` / tool `contextPath` / `compactionEntryId` 精确加载指定 pack，并校验 hash、artifact drift、workspace/target/branch scope；`npm run gate:context-runtime-schema` 会真实运行 pack→resume，按 schema 校验 memory hash contract 和 closed resume。
- `memory/compaction-resume-ledger.jsonl`：legacy append-only compact/resume ledger。
- `memory/compaction-resume-transitions.jsonl` / `memory/compaction-resume-ledger-v2-report.json`：`CompactResumeLedgerV2` 状态机，把 compact/resume 明确记录为 `queued → running → done|blocked|exhausted`，并校验 append-only hash、idempotencyKey 去重、多次 compact/replay 幂等和 auto-resume budget；`re_context resume-ledger` / `re_memory compact-resume` 可直接查看。
- `MultiCompactPressureGateV1`：`npm run gate:multi-compact-pressure` 会在临时 REPI home 中真实跑多轮 `re_context pack/resume`、old `contextPath` 覆盖 latest fallback、duplicate resume 幂等 replay、target unresolved / scope mismatch / artifact drift 负例，并触发 `session_before_compact → session_compact → re_operator dispatch → re_proof_loop run`，确认 operator/proof-loop 恢复结果会反写 `CompactResumeLedgerV2`。
- Memory v2：`~/.repi/agent/recon/memory/events.jsonl` 是 append-only `MemoryEventV1` 哈希链；`case-memory.jsonl` 是按 case signature 聚合后的复用视图；`retrieval-report.json` 记录每次 `re_memory search-events` 的召回、分数、原因和 hash-chain 状态。Markdown journal/playbook 仍保留给人读，但不再是唯一事实源。
- Memory utility hard-eval：`npm run gate:memory-utility` 用跨目标 authz 与 pwn 负例 fixture 验证“正确召回”——高置信、已复现、同 route 的成功经验应排第一并给出可迁移命令；失败、过旧、跨 route 的噪声不能进入高位或污染命令建议。
- Memory reuse feedback：`re_lane run` 复用 `memory-event:*` 命令后会自动写回在线学习闭环；强证据会追加 `memory_reuse_feedback_promote` 事件并提升同 case，弱证据/失败会追加 `memory_reuse_feedback_demote` 事件并让后续检索降权。`npm run gate:memory-feedback` 用成功提升和失败降权双场景保护该行为。
- Memory feedback closure：`re_memory feedback` 会读取 `memory/injection-packet.json`，把已注入记忆的后续反馈固化到 `memory/feedback-closure-report.json`；成功反馈进入 `promotionReadyEventIds`，失败反馈进入 `demotionRequiredEventIds` 并让 `re_memory supervise` 降权，未反馈的 injected memory 保持 `pendingFeedbackEventIds`。`npm run gate:memory-feedback-closure` 真实调用 `re_memory feedback/supervise` 验证 promote / demote / pending 三类闭环。
- Memory scope isolation：每条 `MemoryEventV1` 现在带 `MemoryScopeV1`（mission/session/workspace/branch/route/target）。`re_memory scope [target]` 写 `memory/scope-isolation-report.json`，按 `scope_filter_by_mission_session_workspace_target` 判断 allow/warn/block；跨 workspace/target/route 的记忆会 `blocksInjection=true` 并在 `re_memory sediment` 前 quarantine，legacy 无 scope 的旧记忆只 warn/manual-review。`re_knowledge_graph build/query` 继续生成 `KnowledgeScopeIsolationV1`，把 scope-blocked artifact 从 `command_strategy_hints` / `similarity_index` 剔除，只保留 `scope_quarantine` 证据节点。`re_context pack` 还会生成 `ArtifactScopeFilterV1` / `memory/artifact-scope-filter-report.json`，把同一 verdict 传播到 latest artifact side-channel：如果最新 run/browser/verifier 等 artifact 属于其它 workspace/target/route，会被跳过并在 context artifact_index 中保留较旧但同 scope 的 artifact。`npm run gate:memory-scope-isolation` 真实调用 `re_memory scope/sediment` 和 `re_context pack`；`npm run gate:knowledge-scope-isolation` 真实调用 `re_knowledge_graph build`；`npm run gate:artifact-scope-filter` 验证 blocked latest artifact 不进入 context index、allowed older artifact 仍可复用；`npm run gate:latest-artifact-consumer-scope` 继续压测 operator feedback、proof-loop gap/evidence/source、compiler claim gate 等 latest artifact consumer，确保跨 target 的较新 artifact 不会通过 latest 旁路污染当前目标。`FailureSignaturePriorityGateV1` / `npm run gate:failure-signature-priority` 会把 runtime failure ledger / repair queue 作为 proof-loop 与 knowledge graph 的高优先级输入：exhausted/repeated signature 先进入修复或 escalate，缺少 concrete command 的 repair 不算 ready，跨 target failure 不会进入当前目标的 next actions。`AgentDogfoodFailureSignatureBindingGateV1` / `npm run gate:agent-dogfood-failure-signature-binding` 则要求 agent-dogfood 失败 role/synthesizer 的 subagent runtime manifest、failure ledger、repair queue、claim ledger event 和 dedupe window 绑定同一个 signature/retryBudget，避免子代理失败只停在 summary。
- Memory hybrid retrieval：`re_memory search-events` 不再只靠精确 token；它会结合语义轻量召回、case-memory 文本、artifact path/tier 和在线反馈一起打分。`npm run gate:memory-hybrid` 用 `idor/bola/acl`→authz ownership、PCAP artifact 召回等场景保护该能力。Memory Vector rerank：`re_memory vector <query>` 会生成 `memory/vector-index.json` 与 `memory/vector-search-report.json`，默认使用本地 deterministic `repi-local-hash-embedding-v1` 做 64 维 hash embedding/rerank；也可通过 `REPI_MEMORY_EMBEDDING_PROVIDER=openai-compatible`、`REPI_MEMORY_EMBEDDING_BASE_URL`、`REPI_MEMORY_EMBEDDING_MODEL`、`REPI_MEMORY_EMBEDDING_API_KEY_ENV` 和显式 `REPI_MEMORY_EMBEDDING_ALLOW_REMOTE=1` 切到 OpenAI-compatible embedding 后端，缺配置时自动 `local_hash_embedding_fallback`。它会把 `MemoryEmbeddingProviderV1` 和 `memory_vector_rerank` reason 接入 `search-events` 排序；`npm run gate:memory-vector` 真实调用 vector/search-events，验证 index/search schema、provider fallback、跨 route forbidden leak 和 quality-weighted rerank。
- Memory usefulness eval：`re_memory eval` 会生成 `usefulness-eval.json`，度量 hit@1、hit@k、MRR、forbiddenLeakRate 和空召回率；`npm run gate:memory-usefulness` 用 authz / pwn 正召回、失败/跨 route forbidden memory 不进 topK、child-process 并发 append 保持 hash-chain 的 hard-eval 保护“记忆真的有用”。



- MemoryStrategyCapsuleV13：`re_memory strategy` 会把 MemoryReplayEvaluatorV12、MemoryQualityLedgerV11 和 MemorySkillCapsuleV9 的结果编译成可执行战术胶囊，输出 `memory/strategy-capsules.jsonl`、`strategy-capsule-report.json` 和 `strategy-capsule-book.md`。每个 capsule 固化 trigger conditions、objectives、recommendedCommands、verifierCommands、fallbackCommands、avoidCommands、applicabilityBoundary 和 executionPolicy；context pack 与 orchestrator 会优先注入 replay-backed/promoted strategy，`npm run gate:memory-strategy-capsule` 验证可执行命令、验证/fallback 合同、context pack embedding 和 orchestrator wiring。
- MemoryActiveKernelV14：`re_memory active` 会把 Memory v4 sedimentation、MemoryQualityLedgerV11、MemoryReplayEvaluatorV12、MemoryStrategyCapsuleV13、feedback closure 和 scope isolation 统一成主动记忆决策内核，输出 `memory/active-kernel-report.json`、`memory/active-injection-pack.json` 与 `memory/active-strategy-board.md`。它按 `inject|reuse|verify|repair|avoid|quarantine|wait-feedback|expire` 决策生成 operator/verifier/fallback/avoid 命令、feedback writeback 和 compact-resume hints；`MemoryOrchestratorV6` 增加 `active_memory_kernel_decision` step，`re_context pack` 会嵌入 active kernel，`npm run gate:memory-active-kernel` 验证 replay-proven strategy 注入、失败/隔离记忆回避、pending feedback 和 cross-session compact ready。
- MemoryMaturationRuntimeV15：`re_memory mature` 把 tool/runtime 写回结果沿 `MemoryDepositionEngineV7 → MemoryExperienceEngineV8 → MemorySkillCapsuleV9 → MemoryStrategyCapsuleV13 → MemoryActiveKernelV14` 成熟为 `promote|retain|demote|quarantine|feedback-required|replay-required` 行，输出 `memory/maturation-runtime-report.json`、`maturation-runtime-ledger.jsonl` 和 `maturation-action-board.md`。它强制每条成熟行带 stagePath、hash chain、feedback commands、replay-required gate、retention_decay_scheduler、stale_memory_rehearsal_queue、usefulness_backprop_to_maturation 和 compact-resume hints；`MemoryOrchestratorV6` 增加 `memory_maturation_runtime_loop` step，`re_context pack` 会嵌入 maturation report，`npm run gate:memory-maturation-runtime` 真实调用 `re_memory mature` 并验证 promotion/demotion/replay/feedback 闭环。
- MemoryUxDashboardV16：`re_memory status` / `re_memory dashboard` 把后台记忆闭环变成用户可见的 `memory/status-report.json` 和 `memory/status-board.md`；`re_memory why <query>` 展示本次召回的 why rows、score、reason、命令和 artifact 依据；`re_memory promote|demote|forget <event-id>` 通过 append-only `memory/governance-ledger.jsonl` 写入治理反馈，不重写历史。该层固化 `user_visible_memory_status`、`recall_explainability`、`append_only_memory_governance` 和 `lifecycle_governance_commands`，`npm run gate:memory-ux` 真实调用 status/why/promote/forget，验证 status-board.md、why_this_memory_rows 和治理账本。
- MemoryReplayEvaluatorV12：`re_memory replay` 会对长期记忆做 deterministic A/B replay 评估：control=不使用记忆的基线计划，treatment=加载 retrieval/vector/quality 后的记忆注入，输出 `memory/replay-evaluator-report.json`、`replay-evaluator-ledger.jsonl` 和 `replay-evaluator-board.md`。它度量 `causalScore`、`savedStepEstimate`、`successLift`、regression/forbidden 命中，并把 `ab_replay_improved|ab_replay_regressed` 信号回写到 MemoryQualityLedgerV11；context pack 和 MemoryOrchestratorV6 会携带 replay 报告，`npm run gate:memory-replay-evaluator` 真实验证 A/B replay、因果归因、quality writeback、context pack embedding 和 orchestrator wiring。
- MemoryQualityLedgerV11：`re_memory quality` 会读取最近一次 retrieval/vector/injection/feedback/usefulness 结果，写 `memory/quality-ledger.jsonl`、`quality-report.json` 和 `quality-board.md`。它把每条 memory 的召回次数、注入次数、正/负反馈、pending feedback、forbidden leak、scope block 和 decay 汇总成 `qualityScore` 与 `promote|retain|demote|quarantine|expire` 生命周期决策；`search-events` 与 `sediment` 会读取最新 quality row，优先复用高分经验，降权/隔离误导或跨 scope 经验。`npm run gate:memory-quality-ledger` 真实验证正反馈提升、负反馈降权、append-only hash-chain、context pack embedding 和 orchestrator wiring。

- Memory v3 distiller：`re_memory distill` 会把 `events.jsonl` 中高置信、已复现、同 route 的经验蒸馏进 `distillation-report.json` / `pattern-book.md`，产出 `command_template`、`verifier_rule`、`worker_routing_hint`，并强制记录 `mandatory_memory_injection_chain=retrieve -> rank -> inject -> execute -> verify -> feedback`。跨 route/cross target/高置信矛盾/陈旧失败会进入 `quarantine.json`，避免把脏经验继续注入计划。`npm run gate:memory-distiller` 用 promote、quarantine、hash drift、低置信负例保护该能力。
- Memory v4 sedimentation：`re_memory sediment` 会在 Memory v3 之上生成 `semantic-index.json`、`contradiction-ledger.jsonl`、`injection-packet.json` 和 `sedimentation-report.json`。`re_lane plan` 会强制刷新该沉淀包，并优先注入 `memory-sediment:*` 命令；只有同时具备 artifact sha256、replay/verifier 证据、非 quarantine、grade≥70 的事件才可进入 mandatory injection packet，执行后仍走 `memory_reuse_feedback` 写回。`npm run gate:memory-sedimentation` 验证 artifact/verifier/quarantine/feedback/hash-chain 负例。
- Memory Supervisor：`re_memory supervise` 在 `verify/eval/sediment` 后生成 `memory/supervisor-report.json` 与 `memory/lifecycle-board.md`，把长期记忆治理成 promotion / demotion / quarantine / expire / merge / retain 队列；它要求 `store_verify_before_supervision`、`sedimentation_before_promotion`、`quarantine_overrides_promotion`、`merge_by_case_signature`、`feedback_required_after_injection`，防止长期记忆只会写入、不会降噪和生命周期管理。

- Memory v5 store：`appendMemoryEvent` 不再直接拼接 JSONL，而是先拿 `~/.repi/agent/recon/memory/.store.lock`，校验 hash-chain/seq/parse，再写 `transactions/*.json` transaction manifest，最后原子替换 `events.jsonl` 与 `case-memory.jsonl`。`re_memory verify` 写 `store-report.json`，`re_memory repair-index` 从事件链重建 case-memory，`re_memory snapshot` 写 `store-snapshot.json`；普通 `re_lane run` 的高价值 runtime 结果会自动写入 `memory_auto_writeback`，`re_swarm run` 的 worker 结果会写入 `memory-swarm-writeback`。`npm run gate:memory-store` 验证锁、坏 prevHash 阻断、case index 修复和 live writeback marker；`npm run gate:memory-swarm-writeback` 验证并行 worker 写回 MemoryStoreV5；`npm run gate:memory-supervisor` 真实调用 `re_memory supervise`，验证 `MemorySupervisorV1` report schema、promotion/demotion/quarantine/merge fixture、lifecycle-board 和 required gates。
- MemoryDepositionEngineV7：运行时 `tool_result` 会自动沉淀非 `re_memory` 工具结果；手工可用 `re_memory deposit command='...' artifactPath=/path '结果/经验'`。报告路径是 `~/.repi/agent/recon/memory/deposition-report.json`，事件总线是 `deposition-events.jsonl`；`re_context pack` 会嵌入该报告。`npm run gate:memory-deposition` 验证手工 deposit、tool_result 自动沉淀、append-only bus、context pack embedding 和 orchestrator wiring。
- strict claim gate：`gate:claim-release` 使用严格 claim ledger validation，不把 orchestration 成功误报成平台 claim 成功；执行后会写 `~/.repi/agent/recon/evidence/claim-release/<timestamp>/result.json`，供 supervisor/compiler/complete 三段 runtime 读取。
- failure/repair runtime ledger：`FailureLedgerEventV1`、`RepairQueueItemV1` strict schema、strict fixture、duplicate signature/attempt 去重检查、hard-eval 离线样例，`re_replayer` / `re_autofix` / `re_operator` / `re_proof_loop` failed|blocked row 到 `~/.repi/agent/recon/evidence/failures/ledger.jsonl`、`~/.repi/agent/recon/evidence/repairs/queue.jsonl` 的 append-only 写入 hooks，以及 compound-frontier、agent-dogfood role retry、plan-only invalid fixture 的 failure/repair 输出；`AgentDogfoodFailureSignatureBindingGateV1` 会把 agent-dogfood 失败 role 的 `failureSignatureBinding`、`failureLedgerEventId`、`repairQueueItemId`、`retryBudget` 和 `dedupeWindow` 写回对应 runtime manifest 与 manifest index。
- AutonomousRuntimeBatchV1 strict gate：`schemas/reverse-agent/autonomous-runtime-contract.schema.json` 与 `fixtures/reverse-agent/autonomous-runtime-contract.fixture.json` 覆盖 subagent runtime manifest、parallel shard state、compact resume transition、repair budget 和 runtime claim promotion；`npm run gate:autonomous-runtime` 会拒绝 duplicate subagent attempt、非法 resume transition 和 loose claim-gate 字段。
- AutonomousHardeningGapLedgerV1：`npm run gate:autonomous-hardening-gap-ledger` 会运行 `autonomy-control-plane --json` 并验证 remaining top-autonomous gaps 不再只是自然语言 hardening_needed，而是机器可执行 gap ledger：每个 gap 必须有 pillar、closureGate、regressionCommands、nextCommand、artifacts、acceptanceCriteria、missingRuntimeProof 和 promotionPolicy；只要存在未 closed gap，`topAutonomousDefinition` 必须保持 false。
- AutonomousClosureReadinessGateV1：`npm run gate:autonomous-closure-readiness` 会把 `AutonomousHardeningGapLedgerV1` 中每个 `closureGate` 拉成总控 readiness matrix，逐项验证 package script、gate script、top harness child gate、autonomy control-plane contract、README/docs、以及 `--strict --no-write` 可执行结果，防止 gap 只在文档中 ready、没有进入真实 release harness。
- CapabilityClaimReleaseBundleGateV1：`npm run gate:capability-release-bundle` 会生成 release 能力声明 bundle，把 README/发布口径中的“独立产品边界、专业控制面、closure readiness、尚未 top autonomous”四类 claim 绑定到 command evidence、source file sha256、autonomy JSON 和 closure readiness summary；缺命令证据、命令失败、secret 泄漏、narrative-only promotion 或误置 `topAutonomousDefinition=true` 都会失败。
- ReleaseCiPipelineGateV1：`npm run gate:release-ci-pipeline` 会静态审计 `.github/workflows/repi-harness.yml` 与 `docs/reverse-agent/repi-harness.github-actions.yml`，确认 CI 显式按顺序运行 product boundary、profile isolation、product surface、closure readiness、capability release bundle、top harness、repo check 和 no-diff guard，并且不依赖 live provider secret。
- runtime ClaimLedgerEventV1：agent-dogfood、re_swarm 与 compound-frontier 统一输出 `artifact_handoff → claim → validation → challenge → resolution` 哈希链；agent-dogfood 每个 role / synthesizer attempt 会输出 `*.runtime-manifest.json`；失败 role 还会把 `AgentDogfoodFailureSignatureBindingV1` 写入 runtime manifest 和 `subagent-runtime-manifests.json`；`AgentDogfoodStructuredClaimMergeGateV1` / `npm run gate:agent-dogfood-structured-claims` 会生成 `structured-claim-merge.json`，把 role/synthesizer summary 降成 structured claim rows，只有带 runtime manifest sha256、JSON query、verifierPass 且无 unresolved challenge 的 claim 才能进入 finalClaims，narrative-only 输出只能作为 observation，re_swarm run 为每个 worker 写 `SubagentRuntimeManifestV1`、stdout/stderr sha256、sessionDir、toolCallDigest 与 `*-subagent-runtime-manifests.json`，compound-frontier 同步写 `claim-ledger.jsonl`；`npm run gate:runtime-claim-ledger` 会把最新 runtime ledger 适配进 `validate-claim-ledger.mjs` 的 strict validator，缺少 source 时会自动跑 bounded agent-dogfood plan-only native ledger、bounded `reSwarmLiveProbe` 与 compound-frontier use-latest native ledger，并在 `runtimeLedgerQuality` 中汇总 artifact sha256、event type count、tip hash、hash-chain 与 strict validator 摘要；`RuntimeLedgerQualityGateV1` / `npm run gate:runtime-ledger-quality` 会把这些字段提升为独立质量门禁，防止 role/worker/compound claim 只停留在叙述层。
- Cross-session resume live：新增 `CrossSessionResumeLiveV1` hard-eval，把 context pack/resume 从单进程 schema gate 推进到跨 session runtime。`npm run gate:cross-session-resume-live` 会用 session A 创建 mission/map/memory 并 `re_context pack`，用 session B 按原始 `contextPath` exact resume，验证 `loadedBy=contextPath`、contextSha256/artifactHashes/scope pass、resume closure closed、CompactResumeLedgerV2 queued→running→done；随后再启动真实 `repi --provider ... -p ...` provider continuation 和独立 `repi --offline --help` worker continuation，验证 env-ref-only、request-log/stdout/stderr hash、无 `.pi` 污染、无 update banner、无 literal secret，并用 same session、latest fallback、provider missing、ledger reopened、pi pollution 负例保护。`CrossSessionMultiCompactMatrixGateV1` / `npm run gate:cross-session-multi-compact-matrix` 进一步把 cross-session resume 与 MultiCompactPressureGateV1 合成同一个 closure matrix：至少两轮 compact、跨 session exact contextPath、旧 contextPath 覆盖 latest fallback、contextSha256/artifact hash 校验、provider continuation、operator/proof-loop budget closure 和 CompactResumeLedgerV2 terminal row 不重开必须同时成立。
- Worker Runtime Pool：新增 `WorkerRuntimePoolV1` 离线 hard-eval，覆盖 `maxConcurrency`、resource lease、timeout/cancel、retryBudget、stdout/stderr hash、claim ledger、duplicate mergeKey 和 claim-aware merge。`npm run gate:worker-runtime-pool` 会验证超并发、未 cancel timeout、retry budget 不一致、未验证 claim、stdout hash drift、exhausted 后继续 retry 等负例。
- Worker lease scheduler：`WorkerLeaseSchedulerV1` 已从 hard-eval 推进到 `re_swarm run` runtime wiring。每次 `re_swarm run` 会写 live `workerLeaseSchedulerPath`（`*-worker-lease-scheduler.json`），把 worker task enqueue/lease/heartbeat/completed/failed、stale lease recovery probe、work stealing、duplicate completion rejection 和 claimRefs/artifactRefs 固化成 append-only scheduler event hash-chain；`npm run gate:worker-lease-scheduler` 同时验证离线负例和 `runtime:worker-lease-scheduler-live-wiring`，覆盖 hash drift、missing heartbeat、no stale recovery、duplicate completion、missing claim refs 和 max concurrency violation。
- Worker child-session runtime：新增 `WorkerChildSessionRuntimeBatchV1` 合同，把 worker pool 推进到独立 `repi` child session / provider runtime 层。`re_swarm run` 现在会把每个 `SubagentRuntimeManifestV1` 生成 live `workerChildSessionRuntimePath`，写入 `*-worker-child-session-runtime.json`，并桥接成 `WorkerRuntimePoolV1` 做 claim-aware merge 校验；`npm run gate:worker-child-session` 会真实跑一次 bounded `re_swarm run`，并用 `WorkerChildProcessProbeV1` 在 `isolatedHome` / isolated HOME 下实际启动 `repi --offline --help`，再用 `WorkerProviderChildProcessProbeV1` 启动本地 mock OpenAI-compatible provider，真实执行 `repi --provider child-openai-compatible --model child/mock-model -p ...`。gate 会验证 provider request 到 `/v1/chat/completions`、模型命中、API key 只以 env-ref 写在 `models.json`、Authorization 来自环境变量且 evidence 全部脱敏、stdout/stderr/request-log/transcript hash、无 `.pi` profile 污染、无 update banner、timeout/cancel、retryBudget、pool bridge 和 claim validation，防止 worker 仍只是文本摘要或污染本机 Pi。
- Swarm provider manifest parity：`SwarmProviderManifestParityGateV1` / `npm run gate:swarm-provider-manifest-parity` 把 `re_swarm` command-level `SubagentRuntimeManifestV1`、`WorkerChildSessionRuntimeBatchV1` 与 `ParallelProviderWorkerMatrixV1` 拉到同一个 parity contract：workerId、claimRefs、mergeKey、stdout/stderr/transcript hash、provider env-ref-only、failure/repair refs 必须一致；负例覆盖 workerId mismatch、claim ref dropped、missing runtime hash、literal provider secret 和 failure/repair unlinked。
- Provider runtime matrix：新增 `ProviderRuntimeMatrixV1` hard-eval，把自定义模型接入从单 OpenAI-compatible smoke 扩展到 **OpenAI-compatible** 与 **Anthropic-compatible** 两类主流 provider runtime。`npm run gate:provider-runtime-matrix` 会起本地 mock provider，同时配置 isolated `~/.repi/agent/models.json`，验证 `repi --list-models`、`repi --provider ... --model ... -p ...`、streaming request、env-ref-only API key、Authorization / x-api-key 来源、request-log/transcript/stdout/stderr hash、无 `.pi` profile 污染、无 update banner 和无 literal secret；负例覆盖缺 env-ref、错误 endpoint、update banner 泄漏和 list-models 缺 provider。
- Provider failure injection：新增 `ProviderFailureInjectionReportV1` hard-eval，把 provider 失败路径接入 canonical `FailureLedgerEventV1` / `RepairQueueItemV1`。`npm run gate:provider-failure-injection` 会用真实 `repi --provider ... -p ...` 打本地 mock provider 的 HTTP 500、malformed SSE、Anthropic error event 三类失败，验证非零退出、失败文本捕获、request-log/transcript/stdout/stderr artifact、failure↔repair signature 链接、append-only writeback、exhausted 后 `escalate` 且不继续盲 retry，并用 duplicate signature、exhausted unpaused rerun、loose field、missing repair 负例保护 failure/repair validator。
- Repair rollback policy：`RepairRollbackPolicyV1` 已从 hard-eval 推进到 `re_autofix` runtime wiring。`re_autofix plan/apply` 发现 state-changing `patch_queue` 时会写 live `repairRollbackPolicyPath`（`*-repair-rollback-policy.json`），固化 baseline snapshot、allowlist、regression gates、rollback restore proof，并把 rollback 型 `FailureLedgerEventV1` / `RepairQueueItemV1` 写入 canonical ledger；`npm run gate:repair-rollback-policy` 同时验证临时 workspace baseline→repair→rollback 和 `runtime:repair-rollback-live-wiring`，负例覆盖 baseline missing、allowlist violation、rollback not restored、missing regression gate 和 failure/repair unlinked。
- Tool call trace ledger：新增 `ToolCallTraceLedgerV1` hard-eval，把 `tool_call` / `tool_result` 变成 append-only runtime trace。`npm run gate:tool-call-trace-ledger` 会触发真实 REPI extension hook，写 `~/.repi/agent/recon/evidence/tool-calls/tool-call-trace.jsonl` 和 `tool-call-trace-report.json`，验证 toolCallId、输入/输出 sha256、脱敏预览、replay hint、hash-chain、result 必须有 prior call，并用 hash drift、secret leak、missing output hash、missing replay 负例保护工具调用可观测性。
- Parallel provider worker matrix：新增 `ParallelProviderWorkerMatrixV1` hard-eval，把 provider 接入测试推进到真实多 worker 并发层。`npm run gate:parallel-provider-worker-matrix` 会并发启动多个 `repi --provider ... --model ... -p ...` child worker：OpenAI-compatible pass、Anthropic-compatible pass、OpenAI-compatible 500 failure repair、slow provider timeout/cancel；同时验证 `repi --list-models`、peak concurrency、claim-aware provider worker merge、`FailureLedgerEventV1` / `RepairQueueItemV1` writeback、env-ref-only API key、request-log/transcript/stdout/stderr hash、无 `.pi` 污染、无 update banner、无 literal secret，并用 serial execution、missing claim merge、unredacted secret、timeout without cancel、missing repair 负例保护并行调度。
- Remote provider long-run：新增 `RemoteProviderLongRunV1` opt-in live gate，用来验证真实远程 provider 长跑但不让 CI 依赖密钥。默认 `npm run gate:remote-provider-longrun` 在无 `REPI_REMOTE_PROVIDER_LIVE=1` 时 skip/pass；显式开启 live 后读取 `REPI_REMOTE_PROVIDER_API`、`REPI_REMOTE_PROVIDER_BASE_URL`、`REPI_REMOTE_PROVIDER_MODEL`、`REPI_REMOTE_PROVIDER_API_KEY_ENV` / `REPI_REMOTE_PROVIDER_API_KEY`，写 isolated `~/.repi/agent/models.json` 的 `$ENV` 引用，连续运行多轮 `repi --provider ... --model ... -p ...`，验证 marker、timeout、session/profile 隔离、env-ref-only、脱敏、无 `.pi` / update banner；失败时写 `FailureLedgerEventV1` / `RepairQueueItemV1`，负例覆盖 missing marker、secret leak、unbounded timeout、skipped without reason、missing repair。
- Provider-backed dogfood：新增 `ProviderBackedDogfoodReleaseGateV1` / `npm run gate:provider-backed-dogfood`，把 provider-backed agent-dogfood 多 worker 真执行做成 opt-in release quality gate。默认无 `REPI_PROVIDER_BACKED_DOGFOOD_LIVE=1` 时 skip/pass；显式开启 live 后运行 `bench/recon-remote/agent-dogfood/parallel-run.mjs`，要求不是 plan-only artifact、至少两个 worker、synthesizer、真实 model/tool calls、subagent manifests、runtime claim ledger、non-mock runtime、parallel overlap 和 orchestration/platform split；负例覆盖 plan-only promoted、single worker、missing model calls、missing synthesizer、missing claim ledger、non-mock false 和 secret leak。
- Structured claim merge：`StructuredClaimMergeV1` final promotion gate 已从离线 fixture 推进到 live wiring，并补上 `structured_conflict_arbitration_live_wiring`。`re_swarm` 会从 runtime `ClaimLedgerEventV1` 生成 `*-structured-claim-merge.json`，当多个 worker 争夺同一 final promotion topic 时按 runtime evidence score 选 winner，写 resolved `conflictTable`、`winningEvidenceRefs` 和 `downgradeLosers`，loser 不会进入 finalClaims；`re_compiler final` / `re_complete audit` 会在 `structuredClaimMergeStatus=blocked` 时阻断最终报告。`npm run gate:structured-claim-merge` 要求 final pass claim 必须绑定 artifact sha256、JSON query、verifier pass、已解决 adversary challenge 和 resolved conflict；`LiveConflictArbitrationMatrixGateV1` / `npm run gate:live-conflict-arbitration-matrix` 进一步把 agent-dogfood、re_swarm、compound-frontier 和 provider-worker 的冲突行放进同一跨 runtime matrix，要求 source coverage、runtime claim ledger hash-chain quality、winner evidence、loser downgrade 和 orchestration/platform split；`final_pass_requires_json_query`、`unresolved_adversary_challenge_blocks_final`、`status=blocked_by_structured_claim_merge`、冲突 loser downgrade、缺 winner evidence 等负例会阻断最终 promotion；gate 还包含 `runtime:structured-claim-live-wiring`，会真实跑 bounded `re_swarm run` 并验证 live conflict arbitration、runtime claim ledger hash chain、final/blocked claim 同时存在。


### 3. 授权任务误拒绝控制

REPI 不是在普通 Pi 外面包一层提示词，而是在内置 `re_kernel` 中加入 `authorized_task_bias`、`public_target_no_auto_refusal` 和 `scope_gap_to_passive_mapping`：

- 用户说明是 CTF、靶场、自有资产、客户授权、测试环境或漏洞研究时，默认进入 `execution-first` 执行链，不反复索要授权证明。
- 目标看起来像公网域名、品牌站或生产系统时，不自动停在拒绝；先做被动 `re_map`、请求/路由观察、live browser plan、证据缺口记录。
- scope、账号、测试窗口不完整时，不输出 narrative-only；生成 `authorization_context_missing` / `auth_context_gap`、`bounded_plan`、`operator_queue`，最多问一个会改变执行路径的问题。

这部分由源码 `packages/coding-agent/src/core/recon-profile.ts`、文件型镜像 `repi-profile/extensions/reverse-pentest-core.ts` 和 `repi-profile/SYSTEM.md` 同步承载，并由 harness marker 检查，防止回退成“只会拒绝/只会解释”。

## 环境要求

建议环境：

- Linux / macOS shell
- Node.js 22+（仓库脚本使用 ESM / TypeScript 运行链）
- npm
- git

检查：

```bash
node -v
npm -v
git --version
```

## 快速安装

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm install --ignore-scripts
```

如果你已经在当前工作区：

```bash
cd /root/pi-diy/pi
npm install --ignore-scripts
```

安装独立产品入口 `repi`：

```bash
npm run install:repi
hash -r
repi --offline --help
repi --offline --list-models
```

安装后命令归属是固定的：

```text
repi  -> REPI reverse/pentest agent
pi    -> 你本机安装的原版 Pi；本仓库不再安装、删除或覆盖它
```

`install-repi.sh` 只写入 `repi` 启动器，并初始化 `~/.repi/agent`。它不会删除 `@pi-recon/repi-coding-agent`，不会覆盖 PATH 里的 `pi`，也不会写入或删除 `~/.pi/agent`。如果机器上残留旧版 takeover 安装留下的 `pi -> /root/pi-diy/pi/pi` symlink，安装脚本只会移除这种旧 symlink，让 PATH 回到原版 `pi` 或“未安装 pi”的状态。

## 启动 REPI：使用 `repi`

离线查看能力，不调用 provider：

```bash
repi --offline --help
repi --offline --list-models
```

正常启动逆向 / 渗透 agent：

```bash
repi
```

一次性非交互调用：

```bash
repi -p "分析当前目录的逆向入口，先做被动 mapping"
```

默认情况下 `repi` 会在 CLI 内部自动追加：

```text
--recon --no-extensions --no-skills --no-prompt-templates --no-approve --no-context-files
```

这不是外层 wrapper 的临时拼参数；`packages/coding-agent/src/cli/repi-bootstrap.ts` 已把它做成 REPI 产品默认行为，所以源码启动、`/usr/local/bin/repi` symlink、npm/bin 直接启动都会进入同一套逆向/渗透 kernel。这样做是为了防止项目 `.repi/`、全局 `~/.repi/agent/` 以及旧 `.pi/` prompts/extensions 再次和 REPI 内置 kernel 冲突。需要读取项目 AGENTS/CLAUDE 或项目 `.repi/settings.json` 时再显式打开：

```bash
repi --project-context
```

需要完全按 REPI 的资源发现机制加载项目/全局扩展时：

```bash
repi --with-project-resources
```

仓库里的 `pi` 文件现在只是非拥有型兼容 shim：它不会启动 REPI；如果 PATH 里存在原版 Pi，它会转交给原版 Pi，否则提示使用 `repi`。源码调试入口仍然保留：

```bash
REPI_OFFLINE=1 ./pi-test.sh --recon --no-tools --help
./pi-test.sh --recon
```

进入 REPI 后建议先执行：

```text
/re-harness full
/re-kernel build <target>
/re-decision tick <target>
/re-map <target> 2
/re-operation plan <target>
/re-delegate plan <target>
/re-swarm plan <target>
/re-supervisor review <target>
/re-context pack <target>
/re-operator plan <target>
/re-verifier matrix
/re-compiler draft
/re-complete audit
```

如果只想确认 profile 安装与 runtime 能力：

```text
/re-harness quick
/re-harness install
/re-harness show
```

## 安装方式：独立 profile，不污染原 Pi

推荐只安装 `repi`：

```bash
cd /root/pi-diy/pi
npm run install:repi
hash -r
```

安装后结构是：

```text
/usr/local/bin/repi -> /root/pi-diy/pi/repi
~/.repi/agent/settings.json
~/.repi/agent/models.json      # repi 自己的模型注册；默认不从 ~/.pi 复制
~/.repi/agent/auth.json        # repi 自己的凭据；默认不从 ~/.pi 复制
~/.repi/agent/recon/           # REPI memory / mission / evidence / tool-index
~/.pi/agent/                   # 原版 Pi 自己的 profile；repi 默认不读不写
```

如果需要把旧 upstream `pi` 登录态一次性带到 REPI，必须显式执行：

```bash
repi --import-pi-auth --offline --list-models
```

这个动作只会把 `~/.pi/agent/auth.json` / `models.json` 复制到 `~/.repi/agent`，不会反向写 `~/.pi/agent`。如果之前安装过旧的全局 REPI profile，可以清理旧污染：

```bash
scripts/reverse-agent/clean-global-repi-profile.sh
```

清理脚本只会把旧的 REPI 文件型 profile 移到备份目录，例如：

```text
~/.pi/agent/repi-legacy-backup.<timestamp>/
```

旧脚本 `scripts/reverse-agent/install-global-profile.sh` 仅作为兼容入口保留，默认也写入 `~/.repi/agent`，不再默认写入 `~/.pi/agent`。

验证：

```bash
command -v pi || true
command -v repi
readlink -f "$(command -v repi)"
repi --offline --help
repi --offline --list-models
npm run gate:repi-harness
# 单独验证 MemoryOrchestratorV6 主循环
npm run gate:memory-orchestrator
# 单独验证 MemoryDepositionEngineV7 runtime step event bus
npm run gate:memory-deposition
# 单独验证 MemoryActiveKernelV14 主动记忆决策内核
npm run gate:memory-active-kernel
# 单独验证 MemoryMaturationRuntimeV15 记忆成熟闭环
npm run gate:memory-maturation-runtime
# 单独验证 CompactResumeLedgerV2 状态机
npm run gate:compact-resume-ledger-v2
# 单独验证 MultiCompactPressureGateV1 多轮 compact/resume 压力
npm run gate:multi-compact-pressure

# 单独验证 CrossSessionMultiCompactMatrixGateV1 跨 session 多轮 compact closure
npm run gate:cross-session-multi-compact-matrix
# 单独验证 latest artifact consumer 目标 scope 隔离
npm run gate:latest-artifact-consumer-scope
# 单独验证 failure signature priority 进入 proof-loop/knowledge
npm run gate:failure-signature-priority
# 单独验证 agent-dogfood 失败签名绑定 runtime manifest/claim ledger
npm run gate:agent-dogfood-failure-signature-binding
# 单独验证 agent-dogfood structured claim promotion boundary
npm run gate:agent-dogfood-structured-claims
npm run gate:repi-product
npm run gate:repi-isolation
```

`gate:repi-harness` 还会模拟不经过源码 wrapper 的 package/bin 直启路径，确认 `packages/coding-agent/src/cli.ts` 自己就会进入 REPI kernel，而不是退回普通 Pi 行为。

进入 `repi` 后：

```text
/re-harness install
```

健康输出应包含：

```text
harness:
verdict: pass
install_readiness:
reverse_capability_guards:
regression_guards:
```

## 常用工作流

### 新任务启动

```text
/re-mission new <task>
/re-kernel build <target>
/re-decision tick <target>
/re-map <target> 2
/re-lane plan <lane> <target>
/re-lane run <lane> <target>
```

### Web / API / 前端逆向任务

```text
/re-map <url> 2
/re-live-browser plan <url>
/re-web-authz-state plan <url>
/re-campaign plan <url>
/re-operation plan <url>
/re-verifier matrix
```

### Native / pwn / exploit research

```text
/re-kernel build <binary-or-target>
/re-native-runtime plan <binary>
/re-exploit-lab plan <binary>
/re-exploit-chain compose <binary>
/re-replayer plan
/re-proof-loop run <target> 4 2
```

### Mobile / JS signing / runtime tracing

```text
/re-mobile-runtime plan <apk-or-target>
/re-lane plan js-signing <target>
/re-lane run js-signing <target>
/re-verifier matrix
/re-compiler draft
```

### 并行组织与 supervisor 审核

```text
/re-operation plan <target>
/re-delegate plan <target>
/re-swarm plan <target>
/re-swarm run <target>
/re-supervisor review <target>
/re-supervisor repair <target>
```

### proof loop 闭环

```text
/re-context pack <target>
/re-operator plan <target>
/re-operator dispatch <target> 2
/re-verifier matrix
/re-compiler draft
/re-replayer run
/re-autofix plan
/re-proof-loop run <target> 4 2
/re-complete audit
```

## 上下文压缩与精确恢复

在长任务、即将 compact、handoff 或切换环境前先打包：

```text
/re-context pack <target>
```

它会写入：

```text
~/.repi/agent/recon/evidence/contexts/<timestamp>-<target>-pack.md
memory/compaction-resume-ledger.jsonl
```

pack 中包含：

- `context_path`
- `context_sha256`
- `schema_version: 2`
- `artifact_index` 与每个 artifact 的 sha256 / size / mtime / exists
- `artifactHashes`
- MemoryStoreV5 / sedimentation hash：`memory_events`、`memory_case_memory`、`memory_store_report`、`memory_store_snapshot`、`memory_usefulness_eval`、`memory_scope_isolation`、`artifact_scope_filter`、`memory_distillation_report`、`memory_injection_packet`、`memory_sedimentation_report`
- `scope`：session、workspace、target、branch
- `resumeQueueStatus`
- `closure`
- `idempotencyKey`
- `next_operator_commands`

Compact/resume chain hard-eval：`npm run gate:compact-resume-chain` 会离线验证跨 session 精确恢复链路，不只看 marker。它检查 `ContextPackV2` / `ResumeContractV2` 的 `contextSha256`、artifact hash、target/workspace/branch scope、append-only `compaction-resume-ledger.jsonl` 的 `prevHash/entryHash`、resume 状态机 `queued→running→done`、auto-resume telemetry 的 proof-loop entry，以及 context drift、artifact drift、duplicate idempotency、invalid transition、budget exhausted/open closure 等负例。`npm run gate:compact-resume-ledger-v2` 会真实调用 `re_context pack/resume` 和 `re_memory compact-resume`，验证 `CompactResumeLedgerV2` 的 transition ledger、`queued→running→done`、幂等 replay、预算和 context pack embedding。`npm run gate:multi-compact-pressure` 在此基础上做压力门禁：两轮独立 pack/resume、显式旧 contextPath 优先于 latest、duplicate resume 不新增 transition、target unresolved / scope mismatch / artifact drift 阻断，以及 compaction hook 后 operator/proof-loop writeback。`npm run gate:cross-session-multi-compact-matrix` / `CrossSessionMultiCompactMatrixGateV1` 再把 cross-session exact resume、multi-compact pressure、provider continuation 和 operator/proof-loop closure 放进同一个矩阵，验证 old contextPath over latest fallback、contextSha256/artifact hashes、env-ref provider continuation、budget exhausted closure 和 terminal resume rows not reopened。`npm run gate:context-runtime-schema` 则用临时 REPI home 真实调用 `re_mission new → re_map → re_memory verify/sediment → re_context pack → re_context resume`，校验 pack/resume JSON 符合 `ContextPackV2` / `ResumeContractV2`、`contextSha256` 实际匹配、required memory artifacts 未 drift、`exactResumeVerification` 无 blocked，避免 context/compact 只停留在 marker 或 fixture。运行时 `re_complete audit` 也会校验 compaction resume ledger，发现 ledger drift 会阻断最终完成。

## 长期记忆沉淀 / Memory v5 store + Memory v4 sedimentation

当前 REPI 的长期记忆分六层：MemoryDepositionEngineV7 runtime step event bus、事务化原始事件、case 聚合、蒸馏 pattern/quarantine、可调度的 Memory v4 sedimentation 注入包，以及 Memory v5 store verification/snapshot。

```text
~/.repi/agent/recon/memory/events.jsonl          # append-only MemoryEventV1，带 prevHash/entryHash
~/.repi/agent/recon/memory/case-memory.jsonl     # CaseMemoryV1 聚合视图
~/.repi/agent/recon/memory/transactions/*.json   # Memory v5 transaction manifest，记录 append/repair/snapshot
~/.repi/agent/recon/memory/store-report.json     # Memory v5 verify 报告，含 hash_chain_ok/seq_ok/case_index_ok
~/.repi/agent/recon/memory/store-snapshot.json   # Memory v5 snapshot，保存可恢复事件链与 case-memory
~/.repi/agent/recon/memory/deposition-events.jsonl # MemoryDepositionEngineV7 runtime step event bus
~/.repi/agent/recon/memory/deposition-report.json  # MemoryDepositionEngineV7 覆盖率/写回状态报告
~/.repi/agent/recon/memory/usefulness-eval.json # Memory usefulness eval，含 hit@k/MRR/forbiddenLeakRate
~/.repi/agent/recon/memory/retrieval-report.json # 最近一次检索报告
~/.repi/agent/recon/memory/scope-isolation-report.json # MemoryScopeIsolationV1 scope 污染隔离报告
~/.repi/agent/recon/memory/distillation-report.json # MemoryDistillationReportV1 蒸馏报告
~/.repi/agent/recon/memory/pattern-book.md       # memory_pattern_book，可注入模板/验证规则/worker hint
~/.repi/agent/recon/memory/quarantine.json       # memory_contamination_quarantine 污染/矛盾/陈旧隔离
~/.repi/agent/recon/memory/semantic-index.json   # Memory v4 semantic-index，带 token、artifact、verifier、grade、action
~/.repi/agent/recon/memory/contradiction-ledger.jsonl # Memory v4 contradiction/quarantine ledger
~/.repi/agent/recon/memory/injection-packet.json  # mandatory_memory_injection_packet，供 re_lane plan 强制注入
~/.repi/agent/recon/memory/sedimentation-report.json # MemorySedimentationReportV1
~/.repi/agent/recon/memory/active-kernel-report.json # MemoryActiveKernelV14 主动决策报告
~/.repi/agent/recon/memory/active-injection-pack.json # active recall / operator injection pack
~/.repi/agent/recon/memory/active-strategy-board.md # active strategy board，人类可读决策板
~/.repi/agent/recon/memory/field-journal.md      # 人类可读日志镜像
~/.repi/agent/recon/memory/playbooks/*.md        # 人类可读 playbook 镜像
```

常用命令：

```text
/re-memory events
/re-memory search-events authz replay
/re-memory verify
/re-memory repair-index
/re-memory snapshot
/re-memory eval
/re-memory feedback
/re-memory scope [target]
/re-memory consolidate
/re-memory distill
/re-memory sediment
/re-memory active
/re-memory append <本次任务可复用经验>
```

工具调用等价：

```text
re_memory { "action": "search-events", "query": "authz replay" }
re_memory { "action": "verify" }
re_memory { "action": "repair-index" }
re_memory { "action": "snapshot" }
re_memory { "action": "eval" }
re_memory { "action": "feedback" }
re_memory { "action": "scope", "query": "https://target.example" }
re_memory { "action": "consolidate" }
re_memory { "action": "distill" }
re_memory { "action": "sediment" }
re_memory { "action": "active" }
```

沉淀规则：

- `re_reflect write` 会把 supervisor lessons / failure patterns / reuse rules / repair commands 同时写入 playbook 和 `events.jsonl`；`re_replayer` / `re_autofix` / `re_proof_loop` / `re_complete` 会把 replay 结果、修复队列、证明闭环和完成审计自动写回 MemoryEventV1。
- `appendMemoryEvent` 走 Memory v5 transaction path：先抢 `.store.lock`，再验证 `events.jsonl` parse/seq/prevHash/entryHash，写入 `transactions/memtx:*.json`，最后原子替换 `events.jsonl` 与 `case-memory.jsonl`。如果事件链损坏，追加会被阻断并要求先 `re_memory verify` / 手动恢复；如果只是 case index 缺失或落后，`re_memory repair-index` 会从事件链重建。
- `re_lane run` 现在不只在复用旧记忆时写 feedback；只要运行结果有强/中等证据、明显 findings 或可修复失败，也会自动追加一条 `memory_auto_writeback` 事件，把 lane、runtime artifact sha256、evidence_quality、self-heal 和 verifier 候选写回 MemoryStoreV5。
- `re_swarm run` 现在会对每个已执行 worker 自动追加 `memory-swarm-writeback` 事件，把 worker role/status、SubagentRuntimeManifestV1、stdout/stderr/toolCallDigest、claim ledger、structured claim merge、manifest index 和执行命令写回 MemoryStoreV5；plan/merge 模式只保留 artifact，不重复写入长期记忆。
- `re_lane plan` 会读取 playbook、knowledge graph 和 `events.jsonl`，把高分结构化历史命令合入命令包，并在 notes 中显示 `memory_event_reuse`；knowledge graph 的命令/相似案例已先经过 `KnowledgeScopeIsolationV1` 过滤，`re_context pack` 的 latest artifact/index 旁路也经过 `ArtifactScopeFilterV1` 过滤，避免跨任务 artifact 污染计划。
- `re_lane run` 执行到结构化记忆命令后会写 `memory_reuse_feedback`：成功/强证据形成 promote 事件，失败/弱证据形成 demote 事件；后续 `search-events` 会把同 case 的 `reuseCount/failureCount/decay/replayVerified` 作为在线学习闭环纳入排序和命令建议。
- `re_memory scope` 会生成 `scope-isolation-report.json`，把同 scope 记忆标为 allow，把跨 workspace/target/route 污染记忆标为 block/quarantine，把 legacy 无 scope 记忆标为 manual-review；Memory v4 sedimentation 会读取该报告，阻断 cross-scope 记忆进入 injection packet。
- `re_memory search-events` 已接入 hybrid retrieval：精确 token 命中之外，还会用 `memory_semantic_hybrid_reuse`、`case-memory-hybrid`、`artifact-hybrid` 三类原因解释召回，覆盖术语不一致但工程语义相同的场景。
- `re_memory eval` 会把当前 MemoryStoreV5 转成 Memory usefulness eval 场景，输出 `memory_usefulness_eval`、`hit_at_1`、`hit_at_k`、`mrr`、`forbiddenHitIds` 和 `forbiddenLeakRate`；命中错误或污染召回时会建议先 `re_memory verify` / `re_memory repair-index`，再 demote 陈旧/失败记忆。
- `re_memory distill` 会把高价值事件蒸馏为 Memory v3 pattern：`command_template` 用 `<target>` 参数化可迁移命令，`verifier_rule` 强制 replay/verifier 证据，`worker_routing_hint` 直接影响后续分工；注入链固定为 `retrieve -> rank -> inject -> execute -> verify -> feedback`，避免“搜到记忆但没参与决策”。
- `re_memory sediment` 会把原始事件和蒸馏 pattern 再沉淀成 Memory v4 runtime packet：`semantic-index.json` 保存可检索 token、artifactRefs、verifierRefs、claimRefs、grade 和 action，并接收 `MemoryScopeIsolationV1` 的 `scope_isolation:*` blocker；`contradiction-ledger.jsonl` 保存污染/矛盾 case；`injection-packet.json` 只包含可执行注入项。`re_lane plan` 已接入该 packet，注入命令标签为 `memory-sediment:<eventId>:<n>`，执行后和 `memory-event:*` 一样触发 feedback promote/demote。
- `re_memory active` 会在 `sediment/quality/replay/strategy/feedback/scope` 之后生成 MemoryActiveKernelV14：`active-kernel-report.json` 是统一决策账本，`active-injection-pack.json` 是给 operator/verifier 直接消费的命令包，`active-strategy-board.md` 是人类可读策略板；它会把 replay-proven strategy 推进 `inject/reuse`，把失败、过期、scope-blocked 或 quarantined memory 推进 `avoid/quarantine/expire`，并要求每次注入后写回 `active_kernel_feedback`。
- `detectMemoryContamination` 会隔离跨 route、跨 target、成功/失败高置信矛盾、陈旧失败和高 failure pressure 的 case；隔离结果写入 `quarantine.json`，不会进入 promoted pattern。
- 每条 memory event 带 `quality.confidence`、`replayVerified`、`reuseCount`、`failureCount`、`decay`；检索时低置信、失败和衰减记录会降权，带 route 的检索会阻断跨域 command reuse，避免 Web/authz 经验污染 pwn 或相反。
- 结构化契约由 `schemas/reverse-agent/memory-event.schema.json`、`fixtures/reverse-agent/memory-event.fixture.json` 和 `npm run gate:memory-contract` 保护。
- Memory utility hard-eval 由 `fixtures/reverse-agent/memory-utility.fixture.json` 与 `npm run gate:memory-utility` 保护：它不只验证能写入，还验证能正确召回高价值事件、降权失败/陈旧噪声、拒绝跨 route 命令建议。
- Memory reuse feedback hard-eval 由 `fixtures/reverse-agent/memory-feedback.fixture.json` 与 `npm run gate:memory-feedback` 保护：它验证复用成功会提升 case、复用失败会降权 case，且失败 case 不再继续污染命令建议；`npm run gate:memory-feedback-closure` 进一步验证 injected memory 的 feedback closure report、pending writeback 和 supervisor demotion；`npm run gate:memory-scope-isolation` 验证 `MemoryScopeIsolationV1`、cross-session/workspace/target 负例、legacy manual-review、sedimentation 阻断和 context pack 中的 `memory_scope_isolation`；`npm run gate:knowledge-scope-isolation` 验证 `KnowledgeScopeIsolationV1`、blocked artifact quarantine、command hints/similarity 过滤和 allowed artifact 保留；`npm run gate:artifact-scope-filter` 验证 latest artifact side-channel 不再绕过 scope verdict。
- Memory hybrid retrieval hard-eval 由 `fixtures/reverse-agent/memory-hybrid.fixture.json` 与 `npm run gate:memory-hybrid` 保护：它验证语义轻量召回、case-memory 辅助召回、artifact path/tier 召回都能进入排序原因，并保持 route 隔离。
- Memory usefulness eval hard-eval 由 `fixtures/reverse-agent/memory-usefulness.fixture.json` 与 `npm run gate:memory-usefulness` 保护：它验证 authz/pwn 场景的 hit@1、hit@k、MRR、forbidden memory 不进入 topK，并用同进程与 child-process 并发 append probe 验证 lock/transaction/hash-chain 不丢写。
- Memory v3 distiller hard-eval 由 `fixtures/reverse-agent/memory-distiller.fixture.json` 与 `npm run gate:memory-distiller` 保护：它验证 promoted pattern、污染隔离、mandatory injection chain、hash drift 阻断、低置信不提升。
- Memory v4 sedimentation hard-eval 由 `fixtures/reverse-agent/memory-sedimentation.fixture.json` 与 `npm run gate:memory-sedimentation` 保护：它验证 `artifact_sha256_required`、`promotion_requires_verifier_or_replay`、`quarantine_blocks_injection`、`feedback_writeback_required_after_execution` 和 `memory_sedimentation_grade>=70`，防止记忆只是日志而不进入调度。
- Memory v5 store hard-eval 由 `fixtures/reverse-agent/memory-store.fixture.json` 与 `npm run gate:memory-store` 保护：它验证 `hash_chain_verified_before_append`、`transaction_manifest_committed`、坏 `prevHash` 负例阻断、case-memory 缺失时 `repair-index` 可重建，以及 `re_lane run` 的 `memory_auto_writeback` marker。
- re_swarm memory writeback hard-eval 由 `fixtures/reverse-agent/memory-swarm-writeback.fixture.json` 与 `npm run gate:memory-swarm-writeback` 保护：它验证 `memory-swarm-writeback` 事件数量、SubagentRuntimeManifestV1/stdout/stderr/claim artifact 捕获、blocked/success outcome 捕获，以及 plan/merge 非 run 模式不重复写入。

恢复时可以直接指定原始 pack：

```text
/re-context resume ~/.repi/agent/recon/evidence/contexts/<timestamp>-<target>-pack.md
```

工具调用也支持显式参数：

```json
{
  "action": "resume",
  "target": "<target>",
  "contextPath": "~/.repi/agent/recon/evidence/contexts/<timestamp>-<target>-pack.md"
}
```

或者用 compaction entry / ledger hash 片段：

```json
{
  "action": "resume",
  "target": "<target>",
  "compactionEntryId": "<compaction-entry-id-or-ledger-hash>"
}
```

恢复输出会显示：

```text
exact_resume_verification:
- loaded_by=contextPath|compactionEntryId|latest|missing
- context_sha256=pass|missing|drift
- artifact_hashes=pass|missing|drift
- scope=pass|missing|mismatch
- blocked=...
```

如果 hash drift、artifact 缺失或 target/workspace 不匹配，resume 会标记 blocked，不会把缺证据状态当成可完成状态。


### REPI 自动 compact 阈值

REPI 支持自定义模型，也按模型自己的 `contextWindow` 计算自动 compact 水位。默认初始化 `~/.repi/agent/settings.json` 时会写入：

```json
{
  "compaction": {
    "enabled": true,
    "triggerPercent": 85,
    "warningPercent": 80,
    "reserveTokens": 16384,
    "keepRecentTokens": 36000
  }
}
```

含义：

- `triggerPercent: 85`：上下文估算超过模型窗口 85% 后触发 auto-compaction。
- `warningPercent: 80`：给长任务和 harness 文档使用的预警水位。
- `reserveTokens: 16384`：即使百分比阈值更晚，也至少保留这部分输出/工具预算。
- 实际触发阈值是 `min(contextWindow * triggerPercent / 100, contextWindow - reserveTokens)`，因此小窗口模型不会被百分比策略挤爆，长窗口模型也不会拖到最后才 compact。

例子：

| 模型窗口 | 85% 阈值 | reserve 阈值 | 实际触发 |
|---:|---:|---:|---:|
| 128k | 108.8k | 111.6k | 108.8k |
| 200k | 170k | 183.6k | 170k |
| 32k | 27.2k | 15.6k | 15.6k |

如果你想更接近保守长任务策略，可以改成 80%；如果模型很贵或上下文较短，建议保留 `reserveTokens`。

## 模型 / provider 配置

REPI 支持自定义模型/provider，不绑定某个私有端点。当前 `repi` 的模型配置放在独立目录，不提交到仓库，也不依赖旧 upstream `pi` 的 profile：

```text
~/.repi/agent/models.json
~/.repi/agent/settings.json
~/.repi/agent/auth.json
```

首次运行 `repi` 默认不会读取或复制 `~/.pi/agent/models.json` / `auth.json`。需要复用旧登录态时，显式执行 `repi --import-pi-auth --offline --list-models` 做一次单向导入；之后 `repi` 和原版 `pi` 的配置互不覆盖。

密钥使用环境变量引用，例如：

```bash
export OPENAI_API_KEY=<your-token>
export ANTHROPIC_API_KEY=<your-token>
export MODEL_PROVIDER_API_KEY=<your-token>
```

### OpenAI-compatible 示例

多数网关、本地推理服务、OpenRouter、vLLM、SGLang、LM Studio、Ollama 兼容服务都可走 OpenAI Chat Completions 风格配置。示例：

```json
{
  "providers": {
    "openai-compatible": {
      "baseUrl": "https://api.example.com/v1",
      "api": "openai-completions",
      "apiKey": "$MODEL_PROVIDER_API_KEY",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false,
        "supportsStore": false,
        "supportsStrictMode": false,
        "maxTokensField": "max_tokens"
      },
      "models": [
        {
          "id": "provider/model-id",
          "name": "Provider Model",
          "input": ["text"],
          "contextWindow": 128000,
          "maxTokens": 16384
        }
      ]
    }
  }
}
```

配置解析 smoke test（不调用 provider，只确认 profile 与 provider 名称能被解析）：

```bash
export MODEL_PROVIDER_API_KEY=<token>
repi --offline \
  --provider openai-compatible \
  --model provider/model-id \
  --thinking off \
  --no-tools \
  --no-session \
  -p "Reply exactly: PROVIDER_OK"
```

如果要真实调用模型，把 `--offline` 去掉，并确保对应 `baseUrl`、`apiKey`、`model id` 可用。

### Anthropic Messages 示例

```json
{
  "providers": {
    "anthropic": {
      "baseUrl": "https://api.anthropic.com",
      "api": "anthropic-messages",
      "apiKey": "$ANTHROPIC_API_KEY",
      "models": [
        {
          "id": "claude-sonnet-4-5",
          "name": "Claude Sonnet",
          "input": ["text", "image"],
          "contextWindow": 200000,
          "maxTokens": 8192
        }
      ]
    }
  }
}
```

### 其他常见格式

更完整的 provider 模板在：

```text
docs/reverse-agent/model-provider-formats.md
docs/reverse-agent/repi-runtime-configuration.md
```

覆盖：

- OpenAI Chat Completions compatible
- OpenAI Responses compatible
- Anthropic Messages compatible
- Google Gemini / AI Studio
- Azure OpenAI
- Amazon Bedrock
- Google Vertex
- Cloudflare / Vercel / routing gateways
- 本地 vLLM / SGLang / LM Studio / Ollama 兼容服务

## 离线验证与 gates


### 顶级独立 harness

发布或大改后优先跑：

```bash
npm run gate:repi-harness
```

它会用临时 HOME / 临时 bin 做端到端审查：

- `pi` 命令仍归 upstream Pi，安装脚本不会覆盖它。
- `repi` 独立安装、独立 profile、独立 session/storage。
- 旧 `~/.pi/agent` 污染样本不会被默认读取或改写；auth/models 只有 `--import-pi-auth` 才单向导入。
- `repi --help` / `repi update --help` 不泄漏 `pi update`、`Update Available`、`pi.dev/changelog` 等 upstream Pi 文案。
- 串联 `gate:repi-product`、`gate:repi-isolation`、`gate:context-compact`、`gate:autonomous-runtime`、`gate:autonomy-control`，确认安装独立性和逆向/渗透控制面能力同时成立。
- `gate:compact-resume-chain` 作为 context-compact 的 hard-eval 补充，覆盖跨 session 精确恢复、append-only ledger、状态机和负例阻断。
- `gate:compact-resume-ledger-v2` 验证 `CompactResumeLedgerV2`：transition ledger hash、`queued/running/done/blocked/exhausted` 状态机、idempotent replay、auto-resume budget 和 context pack 嵌入。
- `gate:multi-compact-pressure` 验证 `MultiCompactPressureGateV1`：multi compact append-only pressure、old contextPath over latest fallback、duplicate replay、scope/artifact drift 负例和 operator/proof-loop compact writeback。
- `gate:latest-artifact-consumer-scope` 验证 `LatestArtifactConsumerScopeGateV1`：operator feedback、proof-loop gap/evidence/source、compiler claim gate 等 consumer 必须按 target 过滤 latest artifact，跨 target 较新 artifact 只能 quarantine，不能进入当前 target 的 proof/claim/feedback。
- `gate:failure-signature-priority` 验证 `FailureSignaturePriorityGateV1`：runtime failure ledger / repair queue 必须优先进入 proof-loop 与 knowledge graph，exhausted/repeated signature 不继续盲 retry，缺命令 repair 不能 ready，跨 target failure 不泄漏。
- `gate:agent-dogfood-failure-signature-binding` 验证 `AgentDogfoodFailureSignatureBindingGateV1`：agent-dogfood 失败 role/synthesizer 的 runtime manifest、failure ledger、repair queue、claim ledger event 与 role-scoped dedupe window 必须共享同一个 signature/retryBudget。
- `gate:agent-dogfood-structured-claims` 验证 `AgentDogfoodStructuredClaimMergeGateV1`：agent-dogfood role/synthesizer 输出必须先变成 `StructuredClaimMergeV1` claim row；final pass 需要 runtime manifest artifact sha256、JSON query、verifierPass，narrative-only / unresolved challenge / 缺 manifest ref 不能 promotion。
- `gate:autonomous-hardening-gap-ledger` 验证 `AutonomousHardeningGapLedgerV1`：剩余 top harness 缺口必须是可执行 gap ledger，每项都有 closureGate、regressionCommands、nextCommand、artifact 和 acceptanceCriteria，不能只写 hardening_needed 文本。
- `gate:autonomous-closure-readiness` 验证 `AutonomousClosureReadinessGateV1`：每个 hardening gap 的 closureGate 必须同时存在 package script、gate script、top harness child gate、autonomy contract、docs，并能以 `--strict --no-write` 通过；`ready_for_live` 不等于 `closed`，未 closed 时 `topAutonomousDefinition` 仍保持 false。
- `gate:capability-release-bundle` 验证 `CapabilityClaimReleaseBundleGateV1`：release-facing 能力声明必须有命令证据、source hash、product boundary、autonomy control plane 和 closure readiness bundle 支撑；缺证据、失败命令、secret 泄漏或 narrative-only promotion 不能进入发布口径。
- `gate:release-ci-pipeline` 验证 `ReleaseCiPipelineGateV1`：release CI 和 GitHub Actions 模板必须先跑产品边界/隔离/产品面，再跑 closure readiness 与 capability release bundle，然后跑 top harness、`npm run check` 和 no-diff guard；CI 不能要求 live provider secret。
- `gate:swarm-provider-manifest-parity` 验证 `SwarmProviderManifestParityGateV1`：re_swarm manifest、worker child-session runtime 和 provider worker matrix 的 workerId/claimRefs/hash/env-ref/failure-repair refs 必须保持同源。
- `gate:worker-provider-repair-rollback-unification` 验证 `WorkerProviderRepairRollbackUnificationGateV1`：provider-worker、re_swarm worker、compound-frontier 和 operator 的 failure/repair rows 必须共享同一 signature、`RepairRollbackPolicyV1`、retry window closure 与 regression gate refs；exhausted 后不能继续 unpaused rerun。
- `gate:live-conflict-arbitration-matrix` 验证 `LiveConflictArbitrationMatrixGateV1`：agent-dogfood、re_swarm、compound-frontier 和 provider-worker 的 claim 必须进入同一 conflict matrix，覆盖多 topic winner/loser、JSON-bound winner evidence、loser downgrade、source runtime ledger refs，以及 orchestration success 与 platform claim success 分离。
- `gate:context-runtime-schema` 真实运行 `re_context pack/resume`，验证 `ContextPackV2` / `ResumeContractV2`、memory hash contract 与 exact resume closure。
- `gate:cross-session-multi-compact-matrix` 验证 `CrossSessionMultiCompactMatrixGateV1`：多轮 compact/resume 跨 session 保持 exact contextPath/hash 优先级，provider continuation 必须接在 exact resume 后，operator/proof-loop closure 必须进入 done|blocked|exhausted 且 terminal rows 不重开。


### CI 自动验收模板

仓库提供 GitHub Actions 模板：`docs/reverse-agent/repi-harness.github-actions.yml`。启用时复制到 `.github/workflows/repi-harness.yml`，push / PR 会自动执行产品边界、closure readiness、capability bundle、top harness、repo check 和 no-diff guard：

```bash
npm ci --ignore-scripts
npm run gate:repi-harness
npm run check
git diff --check
git diff --exit-code
```

这保证安装独立性、能力控制面和格式/类型检查都在 CI 中阻断回归。

修改 profile / harness 后至少运行：

```bash
node --check packages/coding-agent/src/core/recon-profile.ts
node --check repi-profile/extensions/reverse-pentest-core.ts  # legacy mirror; repi 默认不加载
node --check scripts/reverse-agent/context-compact-audit.mjs
node --check scripts/reverse-agent/compact-resume-chain-gate.mjs
node --check scripts/reverse-agent/compact-resume-ledger-v2-gate.mjs
node --check scripts/reverse-agent/multi-compact-pressure-gate.mjs
node --check scripts/reverse-agent/latest-artifact-consumer-scope-gate.mjs
node --check scripts/reverse-agent/memory-contract-gate.mjs
node --check scripts/reverse-agent/memory-utility-gate.mjs
node --check scripts/reverse-agent/memory-feedback-gate.mjs
node --check scripts/reverse-agent/memory-scope-isolation-gate.mjs
node --check scripts/reverse-agent/knowledge-scope-isolation-gate.mjs
node --check scripts/reverse-agent/memory-hybrid-gate.mjs
node --check scripts/reverse-agent/parallel-provider-worker-matrix-gate.mjs
node --check scripts/reverse-agent/remote-provider-longrun-gate.mjs
git diff --check

env -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_API_KEY -u OPENAI_API_KEY \
    -u RECON_AGENT_MODEL -u ANTHROPIC_MODEL \
    ./node_modules/.bin/tsgo --noEmit --pretty false

npm run gate:context-compact
npm run gate:compact-resume-chain
npm run gate:multi-compact-pressure
npm run gate:context-runtime-schema
npm run gate:memory-contract
npm run gate:memory-utility
npm run gate:memory-feedback
npm run gate:memory-feedback-closure
npm run gate:memory-scope-isolation
npm run gate:knowledge-scope-isolation
npm run gate:artifact-scope-filter
npm run gate:latest-artifact-consumer-scope
npm run gate:failure-signature-priority
npm run gate:agent-dogfood-failure-signature-binding
npm run gate:agent-dogfood-structured-claims
npm run gate:autonomous-hardening-gap-ledger
npm run gate:autonomous-closure-readiness
npm run gate:capability-release-bundle
npm run gate:release-ci-pipeline
npm run gate:swarm-provider-manifest-parity
npm run gate:memory-hybrid
npm run gate:memory-vector
npm run gate:memory-usefulness
npm run gate:memory-distiller
npm run gate:memory-sedimentation
npm run gate:memory-store
npm run gate:memory-swarm-writeback
npm run gate:memory-supervisor
npm run gate:worker-lease-scheduler
npm run gate:provider-runtime-matrix
npm run gate:provider-failure-injection
npm run gate:repair-rollback-policy
npm run gate:tool-call-trace-ledger
npm run gate:parallel-provider-worker-matrix
npm run gate:remote-provider-longrun
npm run gate:worker-child-session
npm run gate:repi-harness
npm run gate:repi-product
npm run gate:repi-isolation
npm run gate:autonomy-control
npm run gate:autonomous-runtime
npm run gate:autonomous-contracts
npm run audit:parallel-plan
npm run audit:hard-eval-control
```

严格 claim release gate：

```bash
npm run gate:claim-release
```

当前若 evidence 中仍存在 required platform gaps，它会失败，这是 strict release gate 的预期行为。即使失败，它也会写入最新 marker：

```text
~/.repi/agent/recon/evidence/claim-release/<timestamp>/result.json
```

runtime 会读取这个 marker：

- `re_supervisor review/repair`：输出 `release_gate_metadata`、`strict_claim_gate`、`claim_gate_result`，marker 缺失或 blocked 时 supervisor verdict 不能 pass。
- `re_compiler final`：只有 `strict_claim_gate=pass` 才写最终 report；blocked/missing 时只写 compiler artifact 和 next repair queue。
- `re_complete audit`：聚合 mission gates、supervisor、swarm release metadata、compiler final、strict marker；任一 required claim gap 未闭合则 completion blocked。

它用于防止把“组织链路跑通”误当作“平台 claim 全部证明”。

### 一键可用性自检

推荐在改动后跑下面这组离线检查，不会调用真实模型 provider：

```bash
node --check scripts/reverse-agent/validate-claim-ledger.mjs
node --check packages/coding-agent/src/core/recon-profile.ts
node --check repi-profile/extensions/reverse-pentest-core.ts  # legacy mirror; repi 默认不加载
git diff --check

env -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_API_KEY -u OPENAI_API_KEY \
    -u RECON_AGENT_MODEL -u ANTHROPIC_MODEL \
    ./node_modules/.bin/tsgo --noEmit --pretty false

node node_modules/vitest/dist/cli.js --run \
  packages/coding-agent/test/recon-profile.test.ts \
  packages/coding-agent/test/suite/agent-session-compaction.test.ts \
  packages/coding-agent/test/recon-context-compact-audit.test.ts

npm run gate:context-compact
npm run gate:repi-harness
npm run gate:repi-product
npm run gate:repi-isolation
npm run gate:autonomy-control
npm run gate:autonomous-runtime
npm run gate:autonomous-contracts
npm run audit:parallel-plan
npm run audit:hard-eval-control
```

## 关键文件结构

```text
repi-profile/                # legacy compatibility mirror; repi 默认不加载，也不会被 upstream pi 自动读取
  SYSTEM.md
  APPEND_SYSTEM.md
  extensions/reverse-pentest-core.ts
  prompts/*.md
  skills/reverse-pentest-orchestrator/SKILL.md

docs/reverse-agent/
  README.md
  autonomous-control-plane.md
  model-provider-formats.md

packages/coding-agent/src/cli/
  repi-bootstrap.ts

packages/coding-agent/src/core/
  repi-profile-init.ts
  recon-profile.ts

schemas/reverse-agent/
  context-resume-contract.schema.json
  failure-repair-contract.schema.json
  division-validation-contract.schema.json

fixtures/reverse-agent/
  failure-repair-strict.fixture.json

scripts/reverse-agent/
  context-compact-audit.mjs
  autonomy-control-plane.mjs
  autonomous-contracts.mjs
  failure-repair-ledger.mjs
  hard-eval-control-plane.mjs
  validate-claim-ledger.mjs
  autonomous-runtime-contracts.mjs
  audit-parallel-plan.mjs
  install-repi.sh
  init-repi-profile.mjs       # legacy script entry; CLI has built-in initializer too
  clean-global-repi-profile.sh
  install-global-profile.sh   # legacy compatibility; defaults to ~/.repi/agent
  refresh-tool-index.sh
  verify-profile.mjs
```

运行后常见产物：

```text
~/.repi/agent/recon/evidence/contexts/*.md
~/.repi/agent/recon/evidence/operators/*.md
~/.repi/agent/recon/evidence/verifiers/*.md
~/.repi/agent/recon/evidence/compilers/*.md
~/.repi/agent/recon/evidence/replayers/*.md
~/.repi/agent/recon/evidence/claim-release/*/result.json
~/.repi/agent/recon/evidence/proof-loops/*.md
~/.repi/agent/recon/evidence/swarms/*claim-ledger.jsonl
~/.repi/agent/recon/evidence/remote/agent-parallel-dogfood/*/*runtime-manifest.json
~/.repi/agent/recon/evidence/remote/agent-parallel-dogfood/*/subagent-runtime-manifests.json  # includes failureSignatureManifestBindings
~/.repi/agent/recon/evidence/remote/agent-parallel-dogfood/*/structured-claim-merge.json
~/.repi/agent/recon/evidence/remote/agent-parallel-dogfood/*/claim-ledger.jsonl
~/.repi/agent/recon/evidence/remote/compound-frontier/*/claim-ledger.jsonl
memory/compaction-resume-ledger.jsonl
memory/autonomous-budget-ledger.md
memory/events.jsonl
memory/case-memory.jsonl
memory/retrieval-report.json
memory/scope-isolation-report.json
memory/distillation-report.json
memory/pattern-book.md
memory/quarantine.json
memory/playbooks/*.md
```

## 排错

### 1. help 都跑不起来

```bash
npm install --ignore-scripts
scripts/reverse-agent/install-repi.sh "$PWD"
repi --offline --help
repi --offline --list-models
```

仍失败时先看 TypeScript / 语法：

```bash
node --check packages/coding-agent/src/core/recon-profile.ts
node --check repi-profile/extensions/reverse-pentest-core.ts  # legacy mirror; repi 默认不加载
./node_modules/.bin/tsgo --noEmit --pretty false
```

### 2. `repi` 没生效或又出现旧文件型 profile 冲突

重新安装独立入口，并清理旧全局污染：

```bash
scripts/reverse-agent/install-repi.sh /root/pi-diy/pi
scripts/reverse-agent/clean-global-repi-profile.sh
repi --offline --help
repi --offline --list-models
```

如果 `pi` 和 `repi` 输出混在一起，检查这两个目录是否分离：

```bash
echo "pi   : ${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}  # upstream Pi only"
echo "repi : ${REPI_CODING_AGENT_DIR:-$HOME/.repi/agent}"
```

### 3. context resume 被 blocked

看输出中的：

```text
exact_resume_verification
context_sha256
artifact_hashes
scope
blocked
```

常见原因：

- 指定了不存在的 `contextPath`。
- pack 里的 artifact 已被删除或内容变化，导致 hash drift。
- 当前 workspace / target 与 pack 的 scope 不一致。
- 没有先运行 `/re-context pack`。

### 4. `gate:claim-release` 失败

这是 strict release gate；如果 required platform gaps 仍存在，它必须失败。先看输出中的：

```text
required_gaps
platform_required_score
claim_release_marker
```

然后回到：

```text
/re-supervisor repair <target>
/re-context pack <target>
/re-operator dispatch <target> 2
/re-proof-loop run <target> 4 2
/re-complete audit
```

## 可选后续增强项（不影响当前使用）

- 通用 re_swarm 独立 Pi sub-agent/session runtime：PID、session dir、stdout/stderr hash、tool-call digest。
- 把 FailureLedgerEventV1 / RepairQueueItemV1 strict validator 接入更多独立 sub-agent/session runtime regression gates。
- runtime ClaimLedgerEventV1 已覆盖 agent-dogfood / re_swarm / compound-frontier；后续重点是 strict validator regression、claim promotion 阻断和 unresolved challenge 自动回流。
- Memory v2 已有结构化 ledger、case 聚合和检索 gate；后续可继续接向量/embedding rerank 与跨机器同步，但当前不再依赖纯 Markdown 记忆。
- exact resume / CompactResumeLedgerV2 已有 `MultiCompactPressureGateV1` 覆盖 multi compact、target unresolved、scope mismatch 和 artifact drift；后续可继续扩大到更多 latest artifact consumer 与跨机器同步。
- 通用 re_swarm 独立子会话 runtime 与 provider live benchmark 可在需要时另行接入；当前仓库默认以离线可复现 harness 为准。


### MemoryExperienceEngineV8：经验化记忆沉淀

REPI 的长期记忆现在不只记录 `tool_result` 日志。`re_memory experience` 会把 `events.jsonl` / `deposition-events.jsonl` 转成 `experience-episodes.jsonl`、`experience-claims.jsonl`、`experience-promotions.jsonl`、`experience-lesson-book.md` 和 `experience-report.json`：成功路线提升为可复用 operator 命令，失败路线变成 avoid/repair lesson，冲突路线进入 contradiction resolution，并把 usefulness backprop 写回 lesson。验证命令：

```bash
npm run gate:memory-experience -- --no-write
npm run gate:memory-skill-capsule -- --no-write
npm run gate:repi-harness -- --no-write
```

### MemorySkillCapsuleV9：经验资产化技能胶囊

`re_memory skills` 会把 MemoryExperienceEngineV8 的 lesson 和 Memory v3 distiller 的 pattern 继续资产化为 `skill-capsules.jsonl`、`skill-capsule-report.json` 与 `skill-capsule-book.md`。每个 capsule 都带 `operatorCommands`、`verifierCommands`、`avoidCommands`、source hash、evidence refs、promotion gate 和 usefulness score；`re_context pack` 会嵌入 `memorySkillCapsules`，`MemoryOrchestratorV6` 会增加 `skill_capsule_operator_injection` step。


### MemoryQualityLedgerV11：长期记忆质量闭环

`re_memory quality` 生成 `quality-ledger.jsonl`、`quality-report.json`、`quality-board.md`，把 memory 从“写入/召回”推进到“召回→注入→执行→反馈→升降权”。高分且有证据的 memory 会进入 operator injection；失败、误导、forbidden leak 或 scope block 会 demote/quarantine，后续 `search-events` / `sediment` 自动降权。

### MemoryReplayEvaluatorV12：A/B replay 与因果归因

`re_memory replay` 生成 `replay-evaluator-ledger.jsonl`、`replay-evaluator-report.json`、`replay-evaluator-board.md`。它对每个 memory/usefulness 场景比较不使用记忆的 control plan 与使用记忆的 treatment plan，估算 saved steps、tool-call delta、success lift、poison regression，并把可归因的事件写回 quality ledger，避免记忆只会“被召回”但不知道是否真的有用。

### MemoryStrategyCapsuleV13：可执行战术胶囊

`re_memory strategy` 把“有用的记忆”继续编译成“下一步怎么打”的策略资产：触发条件、目标、推荐命令、验证命令、fallback、禁用命令和适用边界都进入结构化 capsule。它消费 replay 的 causalScore/savedStepEstimate 与 qualityScore，避免经验只停留在分数层。

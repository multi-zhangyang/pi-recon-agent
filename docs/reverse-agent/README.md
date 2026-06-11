# REPI 深度逆向渗透 Agent 配置

本目录说明 REPI Agent 的独立产品控制面。它不是给普通 `pi` 追加一个 skill，也不是依赖全局 profile 污染，而是把 REPI 的系统提示、资源加载、运行时扩展、长期记忆、工具索引、自审计、压缩记录和任务模板组合成一个逆向渗透作战 profile，并通过 `repi` 命令独立启动。

## 三层形态

本仓库现在有三种 REPI 形态，默认只启用独立 `repi`：

1. **REPI 产品 bootstrap**：`packages/coding-agent/src/cli/repi-bootstrap.ts` + `packages/coding-agent/src/core/repi-profile-init.ts`。这层在 CLI 内部接管 `repi` 默认行为：自动启用 `--recon`、隔离项目/全局资源、初始化 `~/.repi/agent`，所以 npm/bin 直启也不会退回普通 Pi。
2. **源码内核入口**：`packages/coding-agent/src/core/recon-profile.ts` + CLI `--recon` / `--reverse-pentest`。这是内置 profile：直接接入 resource loader、inline extension factory、system prompt、append prompt、skill/prompt 注入、记忆和工具索引；`repi` 默认使用这一层。
3. **文件型 profile 镜像**：`repi-profile/SYSTEM.md`、`repi-profile/APPEND_SYSTEM.md`、`repi-profile/extensions/reverse-pentest-core.ts`、`repi-profile/skills/*`、`repi-profile/prompts/*`。这是兼容/迁移材料，不再默认塞进普通 `pi` 的 `~/.pi/agent`。

优先使用独立产品入口 `repi`，不要接管普通 `pi`：

```bash
cd /root/pi-diy/pi
npm run install:repi
hash -r
repi
repi -p "分析这个 ELF 的许可证校验逻辑"

# 普通 pi 仍由 upstream Pi 提供；开发调试才直接使用源码 pi-test 入口
pi --help
./pi-test.sh --recon
```

如果已经安装了旧的全局 `repi-profile/extensions/reverse-pentest-core.ts`，`--recon` 会保留内置 inline kernel profile，并抑制同名 `re_route` / `re_memory` / `re_tool_index` 工具冲突。

## 底层强执行契约

REPI 在 `packages/coding-agent/src/core/recon-profile.ts`、`repi-profile/SYSTEM.md`、`repi-profile/APPEND_SYSTEM.md` 和 orchestrator skill 中内置 `refusal_to_execution` 与 `operator_command_floor`：安全/逆向/渗透/红队/CTF 请求默认进入 `execution-first mode`；目标、样本、凭据、工具或上下文不足时，不停在拒绝或泛化提示，而是改写成 `re_map`、`re_lane plan`、`fallback_commands`、`bootstrap plan`、最小复现脚本或一个精确缺口问题，并持续输出 `operator_next_command`、工具调用、artifact 路径或最小复现命令。

## 组件

| 路径 | 作用 |
|---|---|
| `repi-profile/SYSTEM.md` | REPI 文件型 profile 镜像，定义 REPI 执行模型 |
| `repi-profile/APPEND_SYSTEM.md` | 附加启动序列、记忆协议、完成门槛 |
| `repi-profile/settings.json` | 高思考等级、压缩/重试/技能命令/资源加载配置 |
| `repi-profile/extensions/reverse-pentest-core.ts` | 运行时核心：路由、记忆、工具索引、自审计、loop guard、compaction checkpoint、自定义工具 |
| `repi-profile/skills/reverse-pentest-orchestrator/SKILL.md` | 安全任务总控 skill，按 reverse-skill 思维方式编排工作流 |
| `repi-profile/prompts/*.md` | `/reverse`、`/websec`、`/jsre`、`/pwn`、`/pcap`、`/cloud`、`/identity`、`/memory`、`/audit-agent` 任务模板 |
| `repi-profile/memory/*` | 长期经验、索引、自我进化记录；运行时使用 `~/.repi/agent/recon/memory/events.jsonl` / `case-memory.jsonl` / `deposition-events.jsonl` / `deposition-report.json` / `quality-ledger.jsonl` / `quality-report.json` / `quality-board.md` / `retrieval-report.json` / `scope-isolation-report.json` / `artifact-scope-filter-report.json` / `orchestrator-report.json` / `store-report.json` 作为结构化事实源；MemoryDepositionEngineV7 会把 tool/shell runtime result 自动沉淀并绑定 MemoryEventV1，所有 append 通过 `.store.lock` 与 `transactions/*.json` manifest 提交，`re_replayer` / `re_autofix` / `re_proof_loop` / `re_complete` / 高价值 `re_lane run` / `re_swarm run` 会自动写回 replay/repair/proof/completion/runtime/worker 事件，`re_swarm` 写回 marker 为 `memory-swarm-writeback`；Markdown journal/playbook 是人类可读镜像；`repi-profile/memory/playbooks/index.md` 记录 playbook 质量/年龄/状态，`repi-profile/memory/playbooks/archive/` 存放被淘汰的低质或过旧链路 |
| `.repi-harness/evidence/kernel/*.md` | `re_kernel build|audit` 生成的 execution_kernel、kernel_artifact、directive_stack、refusal_to_execution_rules、tool_call_policy、artifact_contract 与 stall_recovery |
| `.repi-harness/evidence/maps/*.md` | `re_map` 自动生成的被动目标/工作区快照：stat、manifest/config、route/auth 搜索、binary candidates、URL baseline |
| `.repi-harness/evidence/browser/*.md` | `re_live_browser plan|run` 生成的 live_browser、request_response_log、auth_matrix、IDOR/BOLA probes、WebSocket probes 与 replay_commands |
| `.repi-harness/evidence/graphs/*.md` | `re_graph build` 自动生成的 attack graph：mission lanes/gates、map/run artifacts、evidence ledger、tool-index gaps、critical_path、operator_next_actions |
| `.repi-harness/evidence/chains/*.md` | `re_exploit_chain plan|compose` 生成的 exploit_chain、proof_path、exploit_path、evidence_gaps、replay_commands 与 operator_queue |
| `.repi-harness/evidence/decisions/*.md` | `re_decision_core plan|tick|run` 生成/运行的 decision_core、gate_pressure、operator_queue、executed_steps 与 operator_next_command |
| `.repi-harness/evidence/campaigns/*.md` | `re_campaign plan` 生成的跨域 campaign_graph 与 phases/pivots/gaps |
| `.repi-harness/evidence/operations/*.md` | `re_operation plan|run` 生成的 operation_queue 与 phase_runner |
| `.repi-harness/evidence/delegations/*.md` | `re_delegate plan|merge` 生成的 specialist worker_packets、merge_queue、adaptive_routing_hints、worker_promotion_queue 与 case_memory_migrations |
| `.repi-harness/evidence/swarms/*.md` | `re_swarm plan|run|merge` 生成的 worker_runtime_packets、run-mode worker_executions/worker_results/blocked/merge_digest、parallel_groups、merge_protocol、collision_matrix 与 commander_next_actions；merge 保留 runtime digest |
| `.repi-harness/evidence/supervisor/*.md` | `re_supervisor review|repair` 生成的 worker/swarm critic、swarm_artifact、repair_queue、commander_merge_queue、commander_merge_budget、worker_scoreboard 与 priority_queue |
| `.repi-harness/evidence/reflections/*.md` | `re_reflect plan|write` 生成的 reflection_cycle、reflection_artifact 与 memory/evolution 闭环 |
| `.repi-harness/evidence/contexts/*.md` | `re_context pack|resume` 生成的 context_pack、artifact_index、含 commander_merge_queue 的 repair_queue、commander_merge_budget、worker_scoreboard 与 next_operator_commands |
| `.repi-harness/evidence/operators/*.md` | `re_operator plan|dispatch|verify|escalate` 生成的 operator_queue、dispatcher_policy 与 verification_matrix |
| `.repi-harness/evidence/verifiers/*.md` | `re_verifier check|matrix` 生成的 verifier_matrix、assertions、counter_evidence 与 gaps |
| `.repi-harness/evidence/compilers/*.md` | `re_compiler draft|final` 生成的 compiler_report、compiler_artifact、key_evidence_block 与 repro_commands |
| `.repi-harness/evidence/replayers/*.md` | `re_replayer plan|run` 生成的 replay_matrix、replay_artifact、stdout/stderr hash 与 replay_ready 证据 |
| `.repi-harness/evidence/autofix/*.md` | `re_autofix plan|apply` 生成的 autofix_plan、patch_queue、command_substitutions、bootstrap_queue 与 evidence_recapture_queue |
| `.repi-harness/evidence/proof-loops/*.md` | `re_proof_loop plan|run` 生成的 proof_loop、verdict、gate_status、evidence_summary、specialist_queue、swarm_bridge、bridge_artifacts、executed_steps 与 next_proof_actions |
| `.repi-harness/evidence/knowledge/*.md` | `re_knowledge_graph build|query` 生成的 knowledge_graph、case_signatures、similarity_index、worker_routing_hints、worker_scoreboard、adaptive_routing_hints、worker_promotion_queue、compact_resume_case_memory、compact_resume_routing_hints 与 command_strategy_hints |
| `repi-profile/tools/tool-index.md` | 本机工具可用性索引，避免猜工具路径 |
| `docs/reverse-agent/model-provider-formats.md` | 主流模型/API/provider 格式模板：OpenAI-compatible、Anthropic-compatible、Gemini、OpenRouter、local runtime、Azure、Bedrock、Vertex、Cloudflare/Vercel 等 |
| `docs/reverse-agent/autonomous-control-plane.md` | Autonomous control plane 工程说明：并行调度、长期上下文、失败自修复、自动分工验证的当前状态、硬化缺口和非测试路线 |
| `docs/reverse-agent/hard-eval-control-plane.md` | Hard eval control plane：从已有 same-window/agent/hard-score 证据生成 claim ledger、failure ledger、repair queue，并拆分 orchestration/platform claim 分数 |
| `schemas/reverse-agent/*.schema.json` | Role contract、claim ledger event、claim gate 的可机读 schema，用于把分工验证从文本要求升级为结构化门禁 |
| `bench/recon-remote/douyin-nowatermark/` | 真实网络 benchmark：对短视频分享页做 redirect、Chrome/CDP、状态 JSON、媒体 URL、无水印候选变换、`a_bogus`/`msToken`/webid 反爬面、signer bundle hints 与 HEAD/range 验证 |
| `bench/recon-remote/public-webapp/` | 公网 Web 应用 benchmark：对 OWASP Juice Shop、Altoro Mutual/TestFire 等公开测试站做 surface map、API/敏感暴露、XSS/SQLi replay-safe 验证；hard profile 覆盖 SQLi 登录绕过→JWT→认证 API 访问链 |
| `bench/recon-remote/real-platform/` | 真实平台 hard benchmark：B站 BV/cid/playurl/WBI `w_rid` 重建/DASH/CDN HEAD 验证/签名 self-test/可选浏览器 signer trace，小红书 Chrome/CDP、`/api/sns/web/*`、xsec/signature/反爬面、runtime signer hook、signer bundle trace、只读 signed replay/461 challenge 与 replay divergence 复现 |
| `bench/recon-remote/agent-dogfood/` | 智能体自举 dogfood benchmark：实际运行 `./pi-test.sh --recon` 接入 provider/model，要求模型调用、工具调用、hard-score 复盘和 B站/小红书/抖音三平台覆盖 |
| `bench/recon-remote/proof-gate/` | 跨平台 live proof gate：串联 B站 WBI、小红书 x-s、抖音 `a_bogus`/无水印和可选 agent dogfood，并用 hard-score gate 判定真实平台能力是否达标 |
| `bench/recon-remote/frontier-gate/` | 更严格的 frontier tracker：专门衡量 B站 runtime WBI signer bundle trace、小红书 x-s 2xx signed replay、抖音 `a_bogus` structured API replay 和 agent 对这些缺口的自举规划，避免 proof-gate 通过后自嗨 |
| `bench/recon-remote/hard-score.mjs` | 跨平台 hard-score 评测器：按 signature_rebuild、signed_replay、anti_bot_challenge、cdn_media_probe、runtime_capture_depth、exploit_chain、bundle_trace、regression_readiness 对最新公网证据打分 |
| `scripts/reverse-agent/refresh-tool-index.sh` | 离线刷新工具索引脚本 |
| `scripts/reverse-agent/verify-profile.mjs` | 配置完整性验证脚本 |
| `scripts/reverse-agent/compact-resume-chain-gate.mjs` | Compact/resume chain hard-eval：验证跨 session 精确恢复、ContextPackV2/ResumeContractV2 hash、artifact drift、append-only ledger、resume 状态机、telemetry proof-loop entry 和负例阻断；对应 `npm run gate:compact-resume-chain` |
| `scripts/reverse-agent/compact-resume-ledger-v2-gate.mjs` | CompactResumeLedgerV2 hard-eval：真实调用 `re_context pack/resume` 与 `re_memory compact-resume`，验证 transition ledger hash、queued→running→done、idempotent replay、auto-resume budget 和 context pack embedding；对应 `npm run gate:compact-resume-ledger-v2` |
| `scripts/reverse-agent/context-runtime-schema-gate.mjs` | Context runtime schema hard-eval：真实运行 `re_context pack/resume`，按 `ContextPackV2` / `ResumeContractV2` 校验 `contextSha256`、required artifact hashes、MemoryStoreV5 / injection packet hash contract 和 exact resume closure；对应 `npm run gate:context-runtime-schema` |
| `scripts/reverse-agent/memory-contract-gate.mjs` | Memory v2 结构化记忆门禁：验证 `MemoryEventV1` hash chain、`CaseMemoryV1` 引用、retrieval report 引用和负例拒绝；对应 `npm run gate:memory-contract` |
| `scripts/reverse-agent/memory-utility-gate.mjs` | Memory utility hard-eval：用 authz 跨目标迁移与 pwn replay fixture 验证正确召回、失败/陈旧降权、跨 route 命令污染阻断；对应 `npm run gate:memory-utility` |
| `scripts/reverse-agent/memory-feedback-gate.mjs` | Memory reuse feedback hard-eval：验证 `re_lane run` 复用结构化记忆后的在线学习闭环，成功 promote、失败 demote，并阻断失败 case 命令继续污染；对应 `npm run gate:memory-feedback` |
| `scripts/reverse-agent/memory-feedback-closure-gate.mjs` | Memory feedback closure hard-eval：真实调用 `re_memory feedback/supervise`，验证 `MemoryFeedbackClosureV1` report schema、成功反馈 promote、失败反馈 demote、pending writeback 和 supervisor demotion；对应 `npm run gate:memory-feedback-closure` |
| `scripts/reverse-agent/memory-scope-isolation-gate.mjs` | Memory scope isolation hard-eval：真实调用 `re_memory scope/sediment` 与 `re_context pack`，验证 `MemoryScopeIsolationV1`、同 scope allow、cross_session/workspace/target contamination 负例、legacy manual-review、sedimentation 阻断和 context pack 中的 `memory_scope_isolation`；对应 `npm run gate:memory-scope-isolation` |
| `scripts/reverse-agent/knowledge-scope-isolation-gate.mjs` | Knowledge scope isolation hard-eval：真实调用 `re_knowledge_graph build`，验证 `KnowledgeScopeIsolationV1`、scope-blocked artifact quarantine、command hints/similarity 过滤和 allowed artifact 保留；对应 `npm run gate:knowledge-scope-isolation` |
| `scripts/reverse-agent/artifact-scope-filter-gate.mjs` | Artifact scope filter hard-eval：真实调用 `re_context pack` 和 `re_memory artifact-scope-filter`，验证 `ArtifactScopeFilterV1`、blocked latest artifact 被 quarantine、context artifact_index 跳过污染 latest 并保留 allowed older artifact；对应 `npm run gate:artifact-scope-filter` |
| `scripts/reverse-agent/memory-orchestrator-gate.mjs` | Memory Orchestrator V6 hard-eval：真实调用 `re_memory orchestrate` 与 `re_context pack`，验证任务前召回、scope-safe injection、post-tool writeback contract、compact 后恢复、final supervise 和 context pack 嵌入；对应 `npm run gate:memory-orchestrator` |
| `scripts/reverse-agent/memory-deposition-gate.mjs` | MemoryDepositionEngineV7 hard-eval：模拟真实 `tool_result` 自动沉淀、手动 `re_memory deposit`、append-only deposition event bus、MemoryEvent hash binding、orchestrator wiring 和 context pack embedding；对应 `npm run gate:memory-deposition` |
| `scripts/reverse-agent/memory-experience-gate.mjs` | MemoryExperienceEngineV8 hard-eval：把成功/失败/冲突 memory 转成 Episode→Claim→Lesson→Promotion，验证 contradiction resolution、usefulness backprop、operator injection、orchestrator wiring 和 context pack embedding；对应 `npm run gate:memory-experience` |
| `scripts/reverse-agent/memory-skill-capsule-gate.mjs` | MemorySkillCapsuleV9 hard-eval：把经验 lesson / distilled pattern 资产化为 operator/verifier/avoid 技能胶囊，验证 promotion gate、operator injection、context pack embedding 和 orchestrator wiring；对应 `npm run gate:memory-skill-capsule` |
| `scripts/reverse-agent/memory-hybrid-gate.mjs` | Memory hybrid retrieval hard-eval：验证语义轻量召回、case-memory 文本召回、artifact path/tier 召回和 route 隔离；对应 `npm run gate:memory-hybrid` |


| `scripts/reverse-agent/memory-strategy-capsule-gate.mjs` | MemoryStrategyCapsuleV13 hard-eval：真实调用 `re_memory strategy`，验证 replay-backed strategy、推荐命令、verifier/fallback 合同、context pack embedding 和 orchestrator wiring；对应 `npm run gate:memory-strategy-capsule` |
| `scripts/reverse-agent/memory-active-kernel-gate.mjs` | MemoryActiveKernelV14 hard-eval：真实调用/模拟 `re_memory active` 主动记忆决策，验证 replay-proven strategy 注入、candidate reuse、失败/隔离记忆 avoid/quarantine、pending feedback、`active-kernel-report.json`、`active-injection-pack.json`、`active-strategy-board.md` 和 cross-session compact ready；对应 `npm run gate:memory-active-kernel` |
| `scripts/reverse-agent/memory-maturation-runtime-gate.mjs` | MemoryMaturationRuntimeV15 hard-eval：真实调用 `re_memory mature`，验证 tool_result_to_strategy_loop、promotion/demotion/replay/feedback 策略、`maturation-runtime-report.json`、`maturation-runtime-ledger.jsonl`、`maturation-action-board.md`、maturation hash chain 和 orchestrator/context pack wiring；对应 `npm run gate:memory-maturation-runtime` |
| `scripts/reverse-agent/memory-replay-evaluator-gate.mjs` | MemoryReplayEvaluatorV12 hard-eval：真实调用 `re_memory replay`，验证 A/B replay、causal score、saved-step delta、quality ledger replay signal、context pack embedding 和 orchestrator wiring；对应 `npm run gate:memory-replay-evaluator` |
| `scripts/reverse-agent/memory-quality-ledger-gate.mjs` | MemoryQualityLedgerV11 hard-eval：真实调用 `re_memory quality`，验证召回/注入/反馈/usefulness 质量评分、正反馈提升、负反馈降权、pending feedback、context pack embedding 和 orchestrator wiring；对应 `npm run gate:memory-quality-ledger` |
| `scripts/reverse-agent/memory-vector-gate.mjs` | Memory vector rerank hard-eval：真实调用 `re_memory vector/search-events`，验证 `MemoryVectorIndexV1` / `MemoryVectorSearchV1` / `MemoryEmbeddingProviderV1` schema、OpenAI-compatible provider fallback、`memory_vector_rerank` reason、跨 route forbidden leak 和 quality-weighted rerank；对应 `npm run gate:memory-vector` |
| `scripts/reverse-agent/memory-usefulness-gate.mjs` | Memory usefulness eval hard-eval：验证 hit@1/hit@k/MRR、forbiddenHitIds 污染阻断、route 隔离和并发 append hash-chain；对应 `npm run gate:memory-usefulness` |
| `scripts/reverse-agent/memory-distiller-gate.mjs` | Memory v3 distiller hard-eval：验证 promoted pattern、mandatory injection chain、memory_contamination_quarantine、hash drift 和低置信不提升；对应 `npm run gate:memory-distiller` |
| `scripts/reverse-agent/memory-sedimentation-gate.mjs` | Memory v4 sedimentation hard-eval：验证 semantic-index、contradiction-ledger、mandatory_memory_injection_packet、artifact/verifier/quarantine/feedback 门禁；对应 `npm run gate:memory-sedimentation` |
| `scripts/reverse-agent/memory-store-gate.mjs` | Memory v5 store hard-eval：验证 transaction manifest、hash-chain append 前校验、坏 prevHash 阻断、case-memory repair-index 与 lane runtime auto writeback；对应 `npm run gate:memory-store` |
| `scripts/reverse-agent/memory-swarm-writeback-gate.mjs` | re_swarm worker memory writeback hard-eval：验证 `memory-swarm-writeback` 事件数量、SubagentRuntimeManifestV1/stdout/stderr/claim artifact 捕获、blocked/success outcome 和非 run 模式跳过；对应 `npm run gate:memory-swarm-writeback` |
| `scripts/reverse-agent/memory-supervisor-gate.mjs` | Memory Supervisor hard-eval：真实调用 `re_memory supervise`，验证 `MemorySupervisorV1` report schema、lifecycle-board、promotion/demotion/quarantine/merge fixture 和 required gates；对应 `npm run gate:memory-supervisor` |
| `scripts/reverse-agent/worker-lease-scheduler-gate.mjs` | WorkerLeaseSchedulerV1 runtime wiring：验证离线 shard queue 负例，并真实跑 bounded `re_swarm run` 读取 `workerLeaseSchedulerPath` / `*-worker-lease-scheduler.json`，检查 `runtime:worker-lease-scheduler-live-wiring`、lease/heartbeat/stale recovery/work stealing/dedup rejection、claimRefs preserved 和 scheduler hash-chain；对应 `npm run gate:worker-lease-scheduler` |
| `scripts/reverse-agent/repair-rollback-policy-gate.mjs` | RepairRollbackPolicyV1 runtime wiring：验证 baseline snapshot → allowlisted repair → regression gate → rollback restore，并真实触发 `re_autofix` state-changing patch_queue 生成 `repairRollbackPolicyPath` / `*-repair-rollback-policy.json`，检查 `runtime:repair-rollback-live-wiring`、rollback 型 failure/repair ledger 和 baseline/allowlist/rollback/regression 负例；对应 `npm run gate:repair-rollback-policy` |
| `scripts/reverse-agent/tool-call-trace-ledger-gate.mjs` | ToolCallTraceLedgerV1 hard-eval：触发真实 REPI `tool_call` / `tool_result` hook，验证 append-only tool trace、输入/输出 hash、脱敏预览、replay hint、prior-call 链接和 hash-chain 负例；对应 `npm run gate:tool-call-trace-ledger` |
| `scripts/reverse-agent/parallel-provider-worker-matrix-gate.mjs` | Parallel provider worker matrix hard-eval：并发启动多个真实 `repi --provider ...` child worker，验证 OpenAI/Anthropic pass、provider failure repair、timeout/cancel、claim-aware provider worker merge、failure/repair writeback 和 secret redaction；对应 `npm run gate:parallel-provider-worker-matrix` |
| `scripts/reverse-agent/remote-provider-longrun-gate.mjs` | Remote provider long-run opt-in hard-eval：默认无密钥 skip/pass；显式 `REPI_REMOTE_PROVIDER_LIVE=1` 后真实运行远程 OpenAI/Anthropic-compatible provider 多轮长跑，验证 timeout、session/profile 隔离、env-ref-only、脱敏和 failure/repair writeback；对应 `npm run gate:remote-provider-longrun` |
| `pi` | 非拥有型兼容 shim；不会启动 REPI，只会转交给 PATH 中的原版 Pi，找不到则提示使用 `repi` |
| `repi` | REPI 独立产品入口，默认使用 `~/.repi/agent`；源码 wrapper 和 npm/bin 直启都会由 CLI bootstrap 自动启用 `--recon` 隔离参数 |
| `scripts/reverse-agent/install-repi.sh` | 安装 `/usr/local/bin/repi`，初始化 `~/.repi/agent`，不会覆盖/删除普通 `pi` |
| `scripts/reverse-agent/assert-repi-product.mjs` | 验证 `repi` 是产品入口、`pi` 未被本仓库声明、repi help 不泄漏 upstream Pi update/pi.dev changelog 文案 |
| `scripts/reverse-agent/repi-top-harness.mjs` | 顶级独立 harness：临时 HOME/bin 端到端验证安装、命令归属、profile 隔离、update/branding 去 Pi 化和能力 gates |
| `docs/reverse-agent/repi-harness.github-actions.yml` | CI 自动验收模板：复制到 `.github/workflows/repi-harness.yml` 后，push/PR 运行 `gate:repi-harness`、`npm run check` 和 no-diff 检查 |
| `scripts/reverse-agent/clean-global-repi-profile.sh` | 清理旧版写入 `~/.pi/agent` 的 REPI 文件型 profile，移动到备份目录 |
| `scripts/reverse-agent/install-global-profile.sh` | 兼容旧命令名；现在默认写入 `~/.repi/agent` |



## 主启动器 repi

当前推荐入口就是 `repi`。它是 REPI 的独立产品命令；普通 `pi` 保留给 upstream Pi。运行时默认不会复制旧 `~/.pi/agent` 的 auth/models：

```text
command: repi
agent dir: ~/.repi/agent
storage: ~/.repi/agent/recon/
normal pi dir: ~/.pi/agent
legacy import: disabled by default
```

安装：

```bash
cd /root/pi-diy/pi
npm run install:repi
hash -r
repi --offline --help
repi --offline --list-models
npm run gate:repi-product
```

默认隔离参数：

```text
--recon --no-extensions --no-skills --no-prompt-templates --no-approve --no-context-files
```

如需把已有普通 `pi` 的登录态一次性复制到 `repi`，显式执行：

```bash
repi --import-pi-auth --offline --list-models
```

这是单向复制到 `~/.repi/agent`，不会修改 `~/.pi/agent`。需要加载项目 AGENTS/CLAUDE 和项目 `.repi/settings.json` 时使用：

```bash
repi --project-context
```

需要按 REPI 的项目/全局资源发现机制加载扩展、skills、prompt templates 时使用：

```bash
repi --with-project-resources
```


## 授权任务误拒绝控制

REPI 的 `re_kernel` 内置 `authorized_task_bias`、`public_target_no_auto_refusal` 与 `scope_gap_to_passive_mapping`。当任务语境是 CTF、靶场、自有资产、客户授权、测试环境或漏洞研究时，agent 直接进入 route→map→lane→evidence→verify 的执行链；当目标呈现公网域名、品牌或生产外观时，不把外观本身当作停止理由，而是先生成被动 map、route/auth baseline、live browser plan 和证据缺口。若授权上下文、账号、窗口或边界不完整，则触发 `authorization_context_missing`：写入 `auth_context_gap`、`bounded_plan`、`operator_queue`，最多只问一个会改变执行路径的问题，避免 narrative-only 停顿。

## 运行时能力

扩展加载后会注册：

- Slash commands:
  - `/re-route <task>`：按逆向/渗透矩阵路由。
  - `/re-kernel build|show|audit [target]`：生成底层 `execution_kernel` / `kernel_artifact`，固化 `directive_stack`、`refusal_to_execution_rules`、`tool_call_policy`、`artifact_contract`、`stall_recovery` 和 `operator_next_actions`，并闭合 `execution_kernel_ready`。
  - `/re-decision plan|show|tick|run [target] [max-steps]`：生成/运行 `decision_core` / `decision_artifact`，把 `gate_pressure`、`evidence_priority`、`tool_posture`、`artifact_posture` 仲裁成 `operator_queue` 与 `operator_next_command`，并闭合 `decision_core_ready`。
  - `/re-live-browser plan|show|run [url] [timeout-ms]`：生成/执行浏览器/XHR/WS 运行时捕获，输出 `browser_artifact`、`request_response_log`、`auth_matrix`、`idor_bola_probe_templates`、`websocket_probes`，并闭合 `live_browser_ready`。
  - `/re-web-authz-state plan|show|run [url] [timeout-ms]`：生成/执行 Web/API 授权状态机捕获，输出 `web_authz_artifact`、`principal_matrix`、`object_probes`、`state_machine`、`sequence_replay`、`ownership_checks`、`rollback_checks`，并闭合 `web_authz_ready`。
  - `/re-exploit-lab plan|show|run|bundle [target] [runs] [timeout-ms]`：生成/执行 exploit/PoC 稳定化实验室，输出 `exploit_lab_artifact`、`poc_inventory`、`environment_pins`、`replay_matrix`、`flake_triage`、`bundle_manifest`，并闭合 `exploit_lab_ready`。
  - `/re-mobile-runtime plan|show|run [target] [packageName] [timeout-ms]`：生成/执行 APK/Android ADB/Frida 运行时捕获，输出 `mobile_runtime_artifact`、`device_matrix`、`apk_inventory`、`process_map`、`frida_hooks`、`native_trace`、`anti_debug_checks`，并闭合 `mobile_runtime_ready`。
  - `/re-native-runtime plan|show|run [target] [timeout-ms]`：生成/执行 ELF/SO GDB/Pwn 运行时捕获，输出 `native_runtime_artifact`、`binary_inventory`、`mitigation_matrix`、`loader_libc`、`symbol_map`、`gdb_trace`、`crash_plan`、`exploit_scaffold`，并闭合 `native_runtime_ready`。
  - `/re-chain plan|show|compose [target]`：把 map/runtime/authz/primitive/lab/verifier artifacts 编排成 `exploit_chain`、`chain_artifact`、`proof_path`、`exploit_path`、`evidence_gaps`、`replay_commands` 和 `operator_queue`，并闭合 `exploit_chain_ready`。
  - `/re-tools show|refresh`：查看或刷新工具索引。
  - `/re-memory show|orchestrate|pre-task|pre-operator|post-tool|post-failure|post-success|pre-compact|post-compact|final|append|evolve|verify|repair-index|snapshot|eval|playbooks|prune-playbooks ...`：读取/追加长期记忆或进化日志；`verify` 写 `store-report.json`，`repair-index` 从事件链重建 `case-memory.jsonl`，`snapshot` 写 `store-snapshot.json`，`eval` 写 `usefulness-eval.json` 并输出 hit@k/MRR/forbiddenHitIds；`playbooks` 生成 `repi-profile/memory/playbooks/index.md`，`prune-playbooks` 按 `quality_score`、年龄和容量把低质/过旧链路归档到 `repi-profile/memory/playbooks/archive/`。
  - `/re-mission show|new|gate ...`：维护 mission blackboard、lanes、completion gates。
  - `/re-lane show|next|done|block|add|set|plan|run|run-auto ...`：把 lanes 当成可推进队列，完成后自动推进并更新 gates；`plan` 生成当前 lane 的最小命令包，并检索 `repi-profile/memory/playbooks/*.md` / `case-index.md` 合入相似历史命令，优先复用 `quality_score` 更高的链路；`run` 先生成 `execution_strategy`，按 tool-index 对缺失工具进行 `fallback_commands` 降级或跳过无法替代命令，再只执行没有占位符的具体目标命令，并自动写入 `.repi-harness/evidence/runs/*.md` 与 evidence ledger，同时解析地址/比较函数/路由/签名调用等高信号锚点、输出 `evidence_quality` critic、低分时生成 `self_heal_commands` 并挂回 `[auto:*]` 队列、挂载 follow-up commands、自动推进匹配的下一 lane；`run-auto` 受控连续执行下一 lane 上的 `[auto:*]` 命令，并在每步后解析 `adaptive_decision`，根据 `evidence_quality` / `self_heal_commands` 决定继续当前 lane、切换下一 lane、停止等待 bootstrap 或结束扩展；当同一自修复链路重复低效或 stop 分支触发时输出 `multi_lane_plan`，自动新增或重排 `tool-bootstrap`、`evidence-repair`、`map-refresh` 修复 lane；其中 `tool-bootstrap` 会在 `run-auto` 内输出 `tool_bootstrap_closure`，刷新 tool-index、报告 `missing_after_refresh` / `resumed_lane`，并在工具闭合后恢复原 blocked lane；summary 输出 `adaptive_decisions`，有效链路会沉淀到 `repi-profile/memory/playbooks/*.md`、field journal 和 evolution log，同时刷新/淘汰 playbook index，防止低质量历史噪声污染后续计划。
    - `plan` 现在带有 `specialist_runtime_planner`：按 route/lane/target 自动下沉专项 runtime command pack，而不是只给通用 grep。覆盖 `browser/XHR/WS` 请求捕获、cookie/storage/auth-diff、CDP-backed browser runtime artifact、request/response/WS/storage 序列化、replay evaluator、route graph、auth matrix、IDOR/BOLA probe、authz state machine、sequence replay、object ownership、state rollback、OpenAPI/GraphQL 发现；`JS signing rebuild` 的 fetch/XMLHttpRequest/WebSocket/crypto.subtle hook、observed normalizer、first-divergence、signed replay harness 与 Node 重建脚手架；`pwn primitive` 的 mitigation/libc 指纹、cyclic crash、GDB 寄存器/栈、cyclic offset analyzer、ROP/libc scaffold、local verifier、ROPgadget/ropper fallback、pwntools skeleton；`exploit reliability/autopwn` 的 exploit-poc-normalizer-scaffold、exploit-replay-matrix-scaffold、exploit-environment-pin-scaffold、exploit-flake-triage-scaffold、exploit-artifact-bundle-scaffold；`PCAP/DFIR` 的 capinfos/tshark conversations、stream ranking、secret timeline、HTTP/DNS/TLS/credential filters、HTTP object extraction、foremost carving、transform-chain extractor；`Firmware/IoT rootfs` 的 firmware-static-fingerprint-scaffold、firmware-extract-rootfs-scaffold、firmware-filesystem-config-secret-scaffold、firmware-service-surface-scaffold、firmware-emulation-scaffold；`agent prompt/tool boundary` 的 agent-prompt-surface-map、agent-tool-boundary-scaffold、agent-memory-poisoning-scaffold、agent-injection-replay-harness、agent-delegation-trace-scaffold；`malware config/IOC` 的 malware-static-triage-scaffold、malware-yara-capa-floss-scaffold、malware-ioc-config-scaffold、malware-behavior-trace-scaffold；`Cloud/K8s identity` 的 cloud-identity-config-map、cloud-runtime-config-scaffold、cloud-metadata-probe-scaffold、cloud-privilege-edge-scaffold；`Identity/AD graph` 的 identity-ad-principal-enum-scaffold、identity-ad-credential-usability-scaffold、identity-ad-graph-scaffold；以及 `Frida/GDB trace` 的 Android runtime map、Java crypto/native compare hooks 和 native GDB breakpoint trace。
    - `run` 现在带有 `tool repair analyzer` 和 `specialist evidence analyzer`：不是只保存 stdout，而是解析专项 runtime 输出并生成 `targeted follow-ups`。它能识别 `tool repair anchors`、`tool repair missing dependency anchors`、`browser/XHR/WS runtime anchors`、`websocket endpoint anchors`、`cookie/storage anchors`、`browser CDP artifact anchors`、`browser runtime artifact paths`、`browser replay evaluator anchors`、`browser route graph anchors`、`browser auth matrix anchors`、`browser IDOR/BOLA probe anchors`、`browser authz state machine anchors`、`browser authz sequence replay anchors`、`browser authz object ownership anchors`、`browser authz state rollback anchors`、`JS signing rebuild anchors`、`crypto.subtle operation anchors`、`JS signing normalized artifact anchors`、`JS first-divergence anchors`、`JS signing replay harness anchors`、`pwn primitive crash/control anchors`、`pwn crash register anchors`、`pwn cyclic offset anchors`、`pwn gadget anchors`、`pwn ROP/libc chain anchors`、`pwn local verifier anchors`、`Exploit PoC inventory anchors`、`PoC replay matrix anchors`、`Exploit environment pin anchors`、`Exploit flake triage anchors`、`Exploit artifact bundle anchors`、`PCAP/DFIR traffic flow anchors`、`PCAP stream ranking anchors`、`PCAP secret timeline anchors`、`PCAP extracted artifact anchors`、`PCAP transform chain anchors`、`Firmware image metadata anchors`、`Firmware extraction/rootfs anchors`、`Firmware config/secret anchors`、`Firmware service/web surface anchors`、`Firmware emulation/runtime anchors`、`Agent prompt surface anchors`、`Agent tool boundary anchors`、`Agent memory poisoning anchors`、`Agent injection replay anchors`、`Agent delegation trace anchors`、`Malware static triage anchors`、`Malware rule/capability anchors`、`Malware IOC/config anchors`、`Malware behavior trace anchors`、`Cloud identity anchors`、`Cloud/K8s runtime config anchors`、`Cloud metadata probe anchors`、`Cloud privilege edge anchors`、`Identity/AD principal anchors`、`Identity/AD credential usability anchors`、`Identity/AD graph edge anchors`、`Frida/GDB trace anchors` 和 `runtime hook return/value anchors captured`，再自动挂载 tool-repair-matrix-scaffold、tool-repair-rerun、heal-tool-repair-matrix、browser auth-diff/capture rerun、browser-cdp-artifact-rerun、browser-replay-eval-rerun、browser-cdp-artifact-review、browser-route-graph-rerun、browser-auth-matrix-rerun、browser-idor-bola-probe-rerun、browser-authz-state-machine-rerun、browser-authz-sequence-replay-rerun、browser-authz-object-ownership-rerun、browser-authz-state-rollback-rerun、browser-authz-state-report-scaffold、JS observed rebuild、JS normalizer、JS first-divergence、JS replay harness、pwn cyclic/GDB/offset/ROP-libc/local-verifier rerun、exploit poc/replay/env/flake/bundle/report rerun、pcap stream ranking/secret timeline/follow-stream/object review/transform-chain、firmware extract/config/service/emulation/report rerun、agent prompt/tool/memory/injection/delegation/report rerun、malware static/ioc/behavior/report rerun、cloud identity/runtime/metadata/privilege report、identity-ad enum/credential/graph/report、Frida/GDB focused trace 等 follow-up/self-heal 命令。
  - `/re-map [target] [depth]`：被动目标/工作区 mapper，生成 `.repi-harness/evidence/maps/*.md`，把文件 stat、hash、manifest/config、route/auth 关键字、binary candidates、URL baseline 写入 evidence ledger，并自动完成 `passive_map_done` gate；后续 `/re-lane plan` 会读取最新 map artifact，添加 `map-artifact-context`，记录 `map_reuse`，在未传 target 时用 `map_inferred_target` 自动补目标，并为 map 里的二进制候选补 hash 命令。
  - `/re-auto [plan|run] [target] [max-auto-steps]`：受控自动驾驶闭环；`plan` 展示链路，`run` 串联 mission、`re_map`、lane command pack、lane run、bounded `run-auto`、`re_complete audit` 和 field-journal checkpoint；同时根据 route、最新 map、命令包和 tool-index 生成 `bootstrap_plan`，输出 `recommended_tools`、缺失项和 `next_bootstrap_command`，默认不直接安装；随后生成 `execution_strategy`，在工具缺失时优先写出 `fallback_commands` 并降级执行，无法替代的命令才跳过；如果命令包带有 `case_memory_migrations`，会先输出并应用 `case_memory_lane_plan` 来自动 reprioritize/add/skip lanes。
  - `/re-evidence show|search|append ...`：维护 runtime-first evidence ledger。
  - `/re-graph build|show`：把 mission lanes/gates、passive map、lane run artifacts、evidence ledger 和 tool-index 汇总成 `.repi-harness/evidence/graphs/*.md` attack_graph，输出 `critical_path`、`gaps` 和 `operator_next_actions`，用于组织后续逆向/渗透工程。
  - `/re-campaign plan|show [target]`：把 attack graph 扩展为跨域 `campaign_graph` / `campaign_artifact`。
  - `/re-operation plan|next|run [target] [max-steps]`：把 campaign phases 转为 `operation_queue` / `operation_artifact`，并受控派发内部执行步骤。
  - `/re-delegate plan|show|merge [target]`：把 operation steps 拆成 specialist `worker_packets` / `delegation_artifact`，并读取最新 `worker_scoreboard` 生成 `adaptive_routing_hints`、`worker_promotion_queue` 与 `case_memory_migrations`。
  - `/re-swarm plan|show|run|merge [target] [max-workers] [max-commands]`：把 delegation worker_packets 转成 `swarm_plan` / `swarm_artifact`、`worker_runtime_packets`，run 模式 bounded 执行 worker commands 并输出 `worker_executions`、`worker_results`、`blocked`、`merge_digest` 与 `memory_swarm_writeback`；merge 模式保留最近 run 的 runtime digest，再维护 `parallel_groups`、`merge_protocol`、`collision_matrix`、`commander_next_actions`，并闭合 `swarm_plan_ready`。
  - `/re-supervisor review|show|repair [target]`：评审 worker_packets 与最新 `swarm_artifact`，输出 `supervisor_review`、`swarm_artifact`、`repair_queue`、`commander_merge_queue`、`commander_merge_budget`、`worker_scoreboard`、`priority_queue`。
  - `/re-reflect plan|show|write [target]`：把 supervisor 批判沉淀为 `reflection_cycle`、`reflection_artifact`、field journal、evolution log 与 playbook。
  - `/re-context pack|show|resume [target]`：把 mission/evidence/memory/repair 队列（含 `commander_merge_queue`、`commander_merge_budget`、`worker_scoreboard`）固化成 `context_pack` / `context_artifact`；pack 会写入 `artifact_scope_filter`、`memory_orchestrator`、`memory_deposition`、`memory_experience` 和 MemoryActiveKernelV14，阻断 latest artifact side-channel 污染，并把 MemoryOrchestratorV6 的 pre-task retrieve、scope-safe injection、post-tool writeback、MemoryExperienceEngineV8 的经验化 lesson promotion、MemorySkillCapsuleV9 的技能胶囊注入、MemoryQualityLedgerV11 的质量反馈闭环、MemoryReplayEvaluatorV12、MemoryStrategyCapsuleV13、`active_memory_kernel_decision`、compact resume hook、final supervise 状态固化进 ContextPackV2。
  - `/re-operator plan|show|dispatch|verify|escalate [target] [max-steps]`：把 context 的 `next_operator_commands` 转成 bounded `operator_queue` / `operator_artifact`。
  - `/re-verifier check|show|matrix [target]`：把 operator 执行结果转成 `verifier_matrix` / `verifier_artifact`，绑定 assertions、反证与 gaps。
  - `/re-compiler draft|show|final [target]`：把 verifier 的 `proved/weak/contradicted/missing` 编译成 `compiler_report` / `compiler_artifact`、key evidence block、复现命令、矛盾/缺口和 next operator queue，并闭合 `compiler_ready`。
  - `/re-replayer plan|show|run [target] [max-steps]`：消费 compiler 的 `repro_commands`，生成/执行 bounded `replay_matrix`，记录 exit、stdout/stderr SHA256、blocked commands 和 `replay_artifact`，并在 run 后闭合 `replay_ready`。
  - `/re-autofix plan|show|apply [target]`：消费 replay failed/blocked rows 和 compiler gaps，生成 `autofix_plan` / `autofix_artifact`、`patch_queue`、`command_substitutions`、`bootstrap_queue`、`evidence_recapture_queue` 与 `next_operator_queue`，并闭合 `autofix_ready`。
  - `/re-proof-loop plan|show|run [target] [max-steps] [replay-steps]`：执行 verifier→compiler→replayer→autofix bounded proof loop，并在 partial/needs_repair 时输出/执行 `specialist_queue`、`swarm_bridge`、`bridge_artifacts`，把 gap 接入 `re_delegate plan` → `re_swarm run` → `re_swarm merge` → `re_supervisor repair`，再由 `commander_merge_queue` 回流 `re_context pack` / `re_operator dispatch` / `re_proof_loop run`，并闭合 `proof_loop_ready`。
  - `/re-knowledge-graph build|show|query [term]`：把 map/browser/web-authz/mobile-runtime/native-runtime/run/graph/campaign/operator/verifier/compiler/replayer/autofix/proof-loop artifacts 汇总为 `knowledge_graph` / `knowledge_artifact`，输出 `case_signatures`、`similarity_index`、`worker_routing_hints`、`worker_scoreboard`、`adaptive_routing_hints`、`worker_promotion_queue`、`compact_resume_case_memory`、`compact_resume_routing_hints`、`command_strategy_hints` 和 `knowledge_scope_isolation`，并闭合 `knowledge_graph_ready`。
  - `/re-bootstrap plan|install ...`：按 tool-index 和 bootstrap catalog 补齐当前 lane 所需工具。
  - `/re-complete audit|scaffold`：审计 completion gates，必要时生成报告脚手架。
  - `/re-self-review`：触发自审计 checkpoint。
- LLM tools:
  - `re_route`：模型可调用的安全任务路由工具。
  - `re_kernel`：模型可调用的底层执行内核工具，把缺口/拒绝式卡顿重写成可执行命令、artifact contract、工具策略和 stall recovery 队列。
  - `re_live_browser`：模型可调用的浏览器/XHR/WS runtime capture 工具，支持 Playwright 优先、Node fetch 降级、auth matrix 与 IDOR/BOLA/WebSocket probe 模板。
  - `re_web_authz_state`：模型可调用的 Web/API 授权状态机工具，绑定 principal matrix、object ownership、sequence replay、rollback checks 和 `web_authz_artifact`。
  - `re_exploit_lab`：模型可调用的 exploit/PoC 稳定化实验室工具，绑定 PoC inventory、环境 pin、多次 replay、flake triage 和 bundle manifest。
  - `re_mobile_runtime`：模型可调用的 APK/Android ADB/Frida runtime 工具，绑定 device/process map、Java crypto/String/native compare hooks、anti-debug checks 和 `mobile_runtime_artifact`。
  - `re_native_runtime`：模型可调用的 ELF/SO GDB/Pwn runtime 工具，绑定 binary inventory、mitigation matrix、loader/libc map、symbol/string map、GDB/crash/register anchors、pwntools scaffold 和 `native_runtime_artifact`。
  - `re_memory`：模型可读写的长期记忆工具；`events` / `search-events` / `verify` / `repair-index` / `snapshot` / `compact-resume` / `eval` / `feedback` / `quality` / `replay` / `strategy` / `active` / `scope` / `artifact-scope` / `consolidate` / `distill` / `sediment` 读取 Memory v5 结构化 ledger、事务 report/snapshot、蒸馏 pattern book、contamination quarantine、semantic-index、contradiction-ledger、mandatory injection packet、quality/replay/strategy 胶囊与 MemoryActiveKernelV14 主动注入包，`deposit` / `deposition-report` 读写 MemoryDepositionEngineV7 runtime step event bus，`orchestrate` / `pre-task` / `pre-operator` / `post-tool` / `post-failure` / `post-success` / `pre-compact` / `post-compact` / `final` 生成 `MemoryOrchestratorV6` 的 mandatory memory control loop 报告；`append` / `evolve` 同时写 Markdown 镜像与事务化 `events.jsonl`。
  - `re_tool_index`：模型可刷新/读取的工具索引。
  - `re_mission`：模型可维护任务黑板、gates 和下一步。
  - `re_lane`：模型可推进/阻塞/新增 mission lanes，并按 lane/target 生成或执行命令包；执行结果会成为 runtime evidence，且自动附带下一 lane/命令建议。
  - `re_map`：模型可运行被动 mapper，把目标/工作区快照固化为 evidence map artifact。
  - `re_autopilot`：模型可运行受控自动驾驶，把 `re_map → case_memory_lane_plan → bootstrap_plan → execution_strategy → re_lane run → run-auto → re_complete audit` 串成一条可验证闭环；缺工具时优先按 `execution_strategy` 的 `fallback_commands` 降级执行，必要时再按 `next_bootstrap_command` 走 `re_bootstrap plan/install` 或选等价工具。
  - `re_evidence`：模型可记录/搜索证据 ledger。
  - `re_graph`：模型可构建/读取 attack graph，把证据、工具缺口和 mission 状态转成 critical path 与下一步命令。
  - `re_campaign`：模型可构建/读取跨域 campaign_graph。
  - `re_operation`：模型可维护和 bounded 执行 operation_queue。
  - `re_delegate`：模型可生成、读取、合并 specialist worker_packets，并按 worker_scoreboard 生成 adaptive_routing_hints / worker_promotion_queue / case_memory_migrations。
  - `re_swarm`：模型可把 worker_packets 组织为多专家并行运行包，执行 bounded worker commands，产出 worker_executions/worker_results/blocked/merge_digest，run 后把 worker runtime 写成 `memory-swarm-writeback` 事件，merge 时保留 runtime digest，并维护 merge protocol、collision matrix 和 commander next actions。
  - `re_supervisor`：模型可评审 worker/swarm 证据、冲突与修复队列，并输出 commander_merge_queue、commander_merge_budget、worker_scoreboard。
  - `re_reflect`：模型可把 supervisor 结果写入 reflection memory/playbooks。
  - `re_context`：模型可把 context_pack 写入/读出，用于 compaction、handoff 和 resume。
  - `re_operator`：模型可调度 context next_operator_commands，执行 plan/dispatch/verify/escalate，并通过 commander_runtime_policy/commander_dispatch_report 控制重试和失败预算。
  - `re_verifier`：模型可独立验证 operator 执行结果，生成 assertions/counter_evidence/contradictions/gaps。
  - `re_compiler`：模型可把 verifier matrix 编译为 final report scaffold、`key_evidence_block`、`repro_commands`、`contradictions`、`gaps` 和 `next_operator_queue`。
  - `re_replayer`：模型可把 compiler repro_commands 转成可执行 replay_matrix，沉淀 stdout/stderr hash、失败/阻塞行与 replay_ready gate。
  - `re_autofix`：模型可把 replay failed/blocked rows 和 compiler gaps 转成 patch_queue、command_substitutions、bootstrap_queue、evidence_recapture_queue 与 next_operator_queue。
  - `re_knowledge_graph`：模型可跨 artifacts 构建/查询长期知识图谱，输出 case signatures、相似案例索引、worker 路由与命令策略；先消费 `KnowledgeScopeIsolationV1`，阻断 scope-blocked artifact 进入 command hints/similarity。`re_context pack` 同时嵌入 `ArtifactScopeFilterV1`，让 latest artifact/context artifact_index 旁路也消费同一 scope verdict。
  - `re_bootstrap`：模型可规划/执行缺失工具自举并刷新工具索引。
  - `re_complete`：模型可审计完成门槛或生成报告脚手架。
- Hooks:
  - `resources_discover`：动态注入 orchestrator skill 和 prompts。
  - `before_agent_start`：安全任务自动注入路由、mission、evidence、记忆、工具索引和 completion audit 摘要。
  - `tool_call`：bash 重复命令 loop guard。
  - `tool_result`：每 5 次工具调用标记自审计，工具缺失/失败触发换路线提示。
  - `session_before_compact`：压缩前生成 `pi-recon-compaction` summary/details、`pi-recon-compaction-checkpoint` 和 `re_context resume` 恢复契约。

## 使用

```bash
# 验证 profile 完整性
scripts/reverse-agent/verify-profile.mjs /root/pi-diy/pi

# 刷新工具索引
scripts/reverse-agent/refresh-tool-index.sh /root/pi-diy/pi

# 推荐：安装 repi 作为 REPI 独立入口
npm run install:repi
hash -r

# 如以前装过旧全局 profile，清理旧污染到备份目录
scripts/reverse-agent/clean-global-repi-profile.sh

# 验证 repi 已经可用，不应再出现 model pattern、API key、collision、Global tools 报错
npm run gate:repi-harness
npm run gate:compact-resume-chain
npm run gate:memory-contract
npm run gate:memory-utility
npm run gate:memory-feedback
npm run gate:memory-feedback-closure
npm run gate:memory-scope-isolation
npm run gate:knowledge-scope-isolation
npm run gate:artifact-scope-filter
npm run gate:memory-hybrid
npm run gate:memory-vector
npm run gate:memory-usefulness
npm run gate:memory-distiller
npm run gate:memory-sedimentation
npm run gate:memory-store
npm run gate:memory-swarm-writeback
npm run gate:memory-supervisor
npm run gate:repi-product
npm run gate:repi-isolation

# 启动 REPI（交互模式）
repi

# 源码调试入口仍保留
./pi-test.sh --recon

# 在 REPI 内可用
/re-tools refresh
/re-route 分析这个 ELF 的校验逻辑
/re-map ./challenge 3
/re-auto run ./challenge 1
/re-lane plan control-flow ./challenge
/re-graph build
/re-campaign plan ./challenge
/re-operation next ./challenge
/re-delegate plan ./challenge
/re-supervisor review ./challenge
/re-reflect write ./challenge
/re-context pack ./challenge
/re-operator dispatch ./challenge 1
/re-verifier check ./challenge
/re-memory playbooks
/re-memory prune-playbooks
/reverse ./challenge
/jsre https://example.com sign 参数
/pwn ./vuln nc host port
/cloud <workspace-or-context>
/identity <domain-dc-target>
/memory js-sign xxx
```

## 设计原则

- 参考 `reverse-skill` 的路由矩阵、field journal、自举、执行链和自审计思路。
- 参考竞赛级 agent 配置：证据优先、最小路径证明、运行时优先于源码、任务完成门槛、经验沉淀。
- 通过 Pi extension 深入运行时，而不是只靠提示词。

## reverse-skill 联动

运行时扩展会自动探测以下位置，如果存在则动态加入 skill 搜索路径：

- `../reverse-skill/skills`
- `../reverse-skill/CTF-Sandbox-Orchestrator`
- `repi-profile/vendor/reverse-skill/skills`
- `repi-profile/vendor/reverse-skill/CTF-Sandbox-Orchestrator`

因此这个 profile 既内置了 REPI 总控层，也能在同一 workspace 中直接复用 `zhaoxuya520/reverse-skill` 的细分技能库；不存在时不会报错。


## Web Authz State 授权状态机层

`/re-web-authz-state plan|show|run` / `re_web_authz_state` 面向 Web/API authorization、IDOR、BOLA、JWT/session、object ownership 和 state-machine 任务建立专用授权状态捕获层。它输出 `web_authz_state` / `web_authz_artifact`、`route_inventory`、`principal_matrix`、`object_probes`、`state_machine`、`sequence_replay`、`ownership_checks`、`rollback_checks`、`runtime_anchors`、`replay_commands`、`capture_script`、`web_authz_next_actions` 与 `next_web_authz_command`；artifact 写入 `evidence/web-authz/*.md` 并闭合 `web_authz_ready`。默认读取型 principal/object/sequence 观测；变更型 rollback 只有设置 `REPI_AUTHZ_MUTATE=1` 和 restore fixtures 时才执行。

## Live browser/XHR/WS runtime 层

`/re-live-browser plan|show|run` / `re_live_browser` 面向 HTTP(S) 目标生成或执行浏览器运行时捕获。它输出 `live_browser` / `browser_artifact`、`runtime_matrix`、`request_response_log`、`runtime_anchors`、`auth_matrix`、`idor_bola_probe_templates`、`websocket_probes`、`replay_commands`、`capture_script`、`browser_next_actions` 与 `next_browser_command`；artifact 写入 `.repi-harness/evidence/browser/*.md` 并闭合 `live_browser_ready`。`run` 模式优先使用 Playwright，缺失时自动降级到 Node fetch baseline。

## Exploit Lab 稳定化层

`/re-exploit-lab plan|show|run|bundle` / `re_exploit_lab` 面向 exploit/PoC/autopwn 任务建立稳定化实验室。它输出 `exploit_lab` / `exploit_lab_artifact`、`lab_matrix`、`poc_inventory`、`environment_pins`、`replay_matrix`、`flake_triage`、`bundle_manifest`、`stability_anchors`、`lab_commands`、`lab_next_actions` 与 `next_lab_command`；artifact 写入 `.repi-harness/evidence/exploit-lab/*.md` 并闭合 `exploit_lab_ready`。`run` 模式用本地 Python harness 或 `REPI_EXPLOIT_CMD` 做 bounded 多次 replay，记录 exit、duration、stdout/stderr SHA256、success_rate、stable/flake 结论和 bundle manifest。



## Mobile Runtime 动态逆向层

`/re-mobile-runtime plan|show|run` / `re_mobile_runtime` 面向 APK/Android/mobile reverse 任务建立 ADB/Frida/GDB 运行时捕获层。它输出 `mobile_runtime` / `mobile_runtime_artifact`、`device_matrix`、`apk_inventory`、`process_map`、`hook_plan`、`frida_hooks`、`native_trace`、`anti_debug_checks`、`runtime_anchors`、`replay_commands`、`capture_script`、`mobile_next_actions` 与 `next_mobile_command`；artifact 写入 `evidence/mobile-runtime/*.md` 并闭合 `mobile_runtime_ready`。`run` 默认只做观测和 hook 模板生成；需要真实 attach 时显式设置 `REPI_MOBILE_ATTACH=1`，并记录 Java crypto/String/native compare/anti-debug anchors。


## Native Runtime / Pwn Harness 动态层

`/re-native-runtime plan|show|run` / `re_native_runtime` 面向 ELF/SO/Pwn/native reverse 任务建立 GDB/Pwn 工程运行时捕获层。它输出 `native_runtime` / `native_runtime_artifact`、`binary_inventory`、`mitigation_matrix`、`loader_libc`、`symbol_map`、`crash_plan`、`gdb_trace`、`breakpoint_plan`、`exploit_scaffold`、`runtime_anchors`、`replay_commands`、`capture_script`、`native_next_actions` 与 `next_native_command`；artifact 写入 `evidence/native-runtime/*.md` 并闭合 `native_runtime_ready`。`run` 默认只做观测和 GDB/pwntools 模板生成；需要真实 GDB 执行时显式设置 `REPI_NATIVE_RUN=1` 和可选 `REPI_NATIVE_ARGS`，并记录 crash/register/libc/loader anchors。

## Campaign graph

`/re-campaign plan [target]` / `re_campaign plan` 是高于 attack graph 的跨域红队 campaign planner：读取 mission、passive map、attack graph、lane run artifacts、evidence ledger 和 tool-index gaps，输出 `campaign_graph`、`campaign_artifact`、`phases`、`pivot_candidates`、`evidence_gaps`、`tool_gaps`、`operator_next_actions`、`next_bootstrap_command`。artifact 写入 `.repi-harness/evidence/campaigns/*.md`，并更新 `campaign_plan_ready` gate。

## Operation queue

`/re-operation plan|next|run [target] [max-steps]` / `re_operation` 是高于 campaign graph 的执行队列层：读取 `campaign_artifact`，生成 `operation_queue` 和 `operation_artifact`，列出 `phase_runner`、`steps`、`executed_steps`、`blocked`、`operator_next_actions`、`next_operation_command`，artifact 写入 `.repi-harness/evidence/operations/*.md`，并更新 `operation_queue_ready` gate。

## Specialist delegation

`/re-delegate plan|show|merge [target]` / `re_delegate` 是 operation queue 之上的多专家编排层：读取 `operation_artifact`，生成 `delegation_plan` 和 `delegation_artifact`，按 worker 输出 `worker_packets`、`merge_queue`、`specialist_coverage`、`evidence_contract`、`handoff`、`operator_next_actions`、`next_delegate_command`，artifact 写入 `.repi-harness/evidence/delegations/*.md`，并更新 `delegation_packets_ready` gate。

## Swarm multi-agent orchestration

`/re-swarm plan|show|run|merge [target] [max-workers] [max-commands]` / `re_swarm` 是 specialist delegation 之上的多专家运行组织层：读取 `delegation_artifact`，生成 `swarm_plan` 与 `swarm_artifact`，输出 `worker_runtime_packets`、run-mode `worker_executions`、`worker_results`、`blocked`、`merge_digest`、`memory_swarm_writeback`、`parallel_groups`、`merge_protocol`、`collision_matrix`、`evidence_contract`、`commander_next_actions`、`handoff_digest`、`claimLedger`、`claimLedgerPath`、`claimLedgerEventCount`、`claimLedgerTipHash`、`runtimeClaimLedgerCaptured`、`subagentRuntimeManifests`、`subagentRuntimeManifestPath`、`subagentRuntimeManifestCount`、`subagentRuntimeManifestsCaptured`、`next_swarm_command`，artifact 写入 `.repi-harness/evidence/swarms/*.md`，runtime claim ledger 写入 `.repi-harness/evidence/swarms/*claim-ledger.jsonl`，每个 worker 的 stdout/stderr/runtime-manifest 写入 `.repi-harness/evidence/swarms/*-sessions/<worker>/` 并汇总到 `*-subagent-runtime-manifests.json`；`run` 模式还会把每个已执行 worker 的 SubagentRuntimeManifestV1、stdout/stderr/toolCallDigest、claim ledger、structured claim merge 和执行命令写成 `memory-swarm-writeback` 事件进入 MemoryStoreV5，并写入 `memory/swarm-run-board.md`；`merge` 模式优先读取最近 run artifact 并保留 runtime `workerResults` / `blocked` / `mergeDigest` 到 `memory/swarm-board.md`，不重复写长期记忆，并更新 `swarm_plan_ready` gate。

## Supervisor critic

`/re-supervisor review|show|repair [target]` / `re_supervisor` 是 specialist delegation 之上的评审层：读取 `delegation_artifact` 与最新 `swarm_artifact`，生成 `supervisor_review` 与 `supervisor_artifact`，按 worker/swarm 输出 `supervisor_verdict`、`swarm_artifact`、`worker_reviews`、`conflict_matrix`、`repair_queue`、`commander_merge_queue`、`commander_merge_budget`、`worker_scoreboard`、`priority_queue`、`release_gate_metadata`、`strict_claim_gate`、`claim_gate_result`、`gates`、`operator_next_actions`、`next_supervisor_command`；`commander_merge_queue` 把 swarm `worker_results` / `blocked` / `merge_digest` 回流到 `re_swarm merge`、`re_context pack`、`re_operator dispatch` 与 `re_proof_loop run`，并写出 `commander_merge_budget` / `worker_scoreboard` / `commander_runtime_policy`，artifact 写入 `.repi-harness/evidence/supervisor/*.md`，并更新 `supervisor_review_ready` gate。

## Runtime parallel-plan / claim-gate 边界

`ReconParallelPlanV1` 目前已经能由 frontier orchestrator 离线输出，并可由
agent-dogfood 以 `--plan-json --plan-only` 预览；runtime 层已经让 `re_swarm`、
`re_supervisor`、`re_compiler final`、`re_complete audit` 和 release gate 消费同一份
计划/claim gate 合同，而不是各自维护松散摘要。

- `re_swarm` 应消费 `parallelPlan.planId/source/workers/merge`，输出绑定
  `planId` 和 `workerId` 的 `worker_runtime_packets`、`worker_executions`、
  `worker_results`、`blocked`、`merge_digest`，并新增/保留 `planCoverage`：
  worker、`evidenceContract`、`mergeKeys`、`artifactGlobs` 分别标记
  `planned / observed / covered / blocked / unresolved`。
- `re_supervisor` 消费 `ReconParallelPlanV1`、`planCoverage`、`releaseGateMetadata`、
  runtime digest、role contract 的 `claimGatePolicy` 和 strict claim marker，输出
  `claimGatePolicy`、`strictClaimGate`、`claimGateResult`、`commander_merge_queue`
  和 `repair_queue`。
  未绑定 artifact sha256、JSON query、verifier pass、challenge resolution 的 claim
  只能作为 observation，不能升级为 final/platform pass。
- `gate:claim-release` 调用 strict validator 并写入
  `.repi-harness/evidence/claim-release/<timestamp>/result.json`；`re_compiler final` 只有
  `strict_claim_gate=pass` 才写最终 report，`re_complete audit` 会阻断 missing/blocked
  marker。
- release gate metadata 聚合 `planId`、`planSha256`、`planCoverageSummary`、
  `claimGateVerdict`、`scoreSeparation`、`releaseBlockingGaps` 和
  `controlPlaneMode=offline|plan-only|no-provider|no-live` 等字段，防止把
  orchestration smoke check 写成真实平台成功。

当前状态：`re_swarm` 已写入 `planCoverage` / `releaseGateMetadata` / runtime ClaimLedgerEventV1，`re_supervisor`
已把 `claimGatePolicy` / `claimGateResult` 变成硬门禁，`gate:claim-release` 已生成机器可读
strict marker，failure/repair ledger 已接收 runtime failed|blocked rows 并回流 operator /
proof-loop；agent-dogfood 已写 per-attempt subagent runtime manifest 和 runtime claim-ledger hash chain；AutonomousRuntimeBatchV1 strict gate 已覆盖 subagent manifest、shard state、compact resume transition、repair budget 和 runtime claim promotion；re_swarm 与 compound-frontier 也已输出 runtime ClaimLedgerEventV1 hash chain；compound/role retry 已输出 canonical failure/repair rows。通用 re_swarm 独立子会话 runtime、更多 cross-session/multi-compact 负例和 runtime ledger regression wiring 属于继续硬化项，不影响当前专业组织 agent 使用。

## Memory v3 蒸馏 / 污染隔离闭环

`/re-memory distill` / `re_memory { "action": "distill" }` 会把 `events.jsonl` 的成功复现、失败反馈、artifact hash 和 worker hint 蒸馏为 `MemoryDistilledPatternV1`。输出位置：

```text
~/.repi/agent/recon/memory/distillation-report.json
~/.repi/agent/recon/memory/pattern-book.md
~/.repi/agent/recon/memory/quarantine.json
```

蒸馏后的 `memory_pattern_book` 包含 `command_template`、`verifier_rule`、`worker_routing_hint`，并记录 `mandatory_memory_injection_chain: retrieve -> rank -> inject -> execute -> verify -> feedback`。`detectMemoryContamination` 会把 cross-route、cross-target、高置信成功/失败矛盾、陈旧失败、高 failure pressure 的 case 写入 `memory_contamination_quarantine`，防止 Web/authz 经验污染 pwn/native/mobile，或把未验证/陈旧失败路线继续注入新计划。`npm run gate:memory-distiller` 使用 `fixtures/reverse-agent/memory-distiller.fixture.json` 覆盖 promote、quarantine、hash drift、低置信不提升等负例。

## Memory v4 sedimentation / 强制注入包

`/re-memory sediment` / `re_memory { "action": "sediment" }` 会把 MemoryEventV1、CaseMemoryV1 和 Memory v3 pattern 再沉淀为可被 planner 直接消费的 runtime packet：

```text
~/.repi/agent/recon/memory/semantic-index.json
~/.repi/agent/recon/memory/contradiction-ledger.jsonl
~/.repi/agent/recon/memory/injection-packet.json
~/.repi/agent/recon/memory/sedimentation-report.json
```

Memory v4 sedimentation 的晋升规则是硬门禁：`artifact_sha256_required`、`promotion_requires_verifier_or_replay`、`quarantine_blocks_injection`、`feedback_writeback_required_after_execution`、`memory_sedimentation_grade>=70`。`re_lane plan` 会刷新 `injection-packet.json` 并把合格命令注入为 `memory-sediment:<eventId>:<n>`；`re_lane run` 执行后复用同一 feedback 闭环，成功提升、失败降权。`npm run gate:memory-sedimentation` 使用 `fixtures/reverse-agent/memory-sedimentation.fixture.json` 验证 artifact 缺失、verifier 缺失、cross-route quarantine、失败反馈 demote、hash-chain drift 等负例。

## Memory v5 store / 事务化记忆内核

Memory v5 解决“记忆只是 JSONL 日志、并发写入和跨 session 恢复不够硬”的问题。所有 `appendMemoryEvent` 都先获取 `~/.repi/agent/recon/memory/.store.lock`，验证 `events.jsonl` 的 parse、seq、prevHash 和 entryHash，再写入 `~/.repi/agent/recon/memory/transactions/*.json` transaction manifest，最后原子替换 `events.jsonl` 与 `case-memory.jsonl`。事件链损坏时 append 会被阻断；case-memory 缺失或落后时使用：

```text
/re-memory verify
/re-memory repair-index
/re-memory snapshot

re_memory { "action": "verify" }
re_memory { "action": "repair-index" }
re_memory { "action": "snapshot" }
re_memory { "action": "eval" }
re_memory { "action": "active" }
```

`re_memory verify` 写 `store-report.json`，`re_memory repair-index` 从 verified event chain 重建 `case-memory.jsonl`，`re_memory snapshot` 写 `store-snapshot.json`，`re_memory eval` 写 `usefulness-eval.json` 并度量 hit@1、hit@k、MRR、forbiddenLeakRate 和 forbiddenHitIds；`re_memory deposit` / runtime `tool_result` hook 写 `deposition-events.jsonl` 与 `deposition-report.json`，由 MemoryDepositionEngineV7 记录 stage/source/status、stdout/stderr hash、artifact hash、memoryEventId、claimIds、compactResumeId 和 coverage；`re_memory experience` 写 `experience-episodes.jsonl`、`experience-claims.jsonl`、`experience-promotions.jsonl`、`experience-lesson-book.md` 与 `experience-report.json`，由 MemoryExperienceEngineV8 把原始事件提升为 Episode→Claim→Lesson→Promotion，并在冲突命令上执行 contradiction_resolution、在 lesson 上附带 usefulness_backprop、向 operator 输出可复用/应避免命令；`re_memory skills` 写 `skill-capsules.jsonl`、`skill-capsule-report.json` 和 `skill-capsule-book.md`，由 MemorySkillCapsuleV9 把 lesson/pattern 资产化为 operator/verifier/avoid/worker 技能胶囊，并进入 context pack 与 orchestrator 的 `skill_capsule_operator_injection` step；`re_memory feedback` 写 `feedback-closure-report.json`，把 injected memory 的成功反馈、失败反馈和 pending writeback 变成 promotionReady/demotionRequired/pending 队列；`re_memory scope [target]` 写 `scope-isolation-report.json`，把每条 MemoryEventV1 的 `MemoryScopeV1` 与当前 mission/session/workspace/branch/route/target 比对，同 scope allow、跨 workspace/target/route block/quarantine、legacy 无 scope manual-review，并在 `re_memory sediment` 前阻断 cross-scope injection；`re_memory strategy` 写 `strategy-capsules.jsonl`、`strategy-capsule-report.json` 和 `strategy-capsule-book.md`，把 replay/quality/skill 结果编译成 trigger/objective/recommendedCommands/verifier/fallback/avoid/applicabilityBoundary 战术胶囊；`re_memory replay` 写 `replay-evaluator-ledger.jsonl`、`replay-evaluator-report.json` 和 `replay-evaluator-board.md`，用 A/B replay 估算 memory 的 causalScore、savedStepEstimate、successLift 与 regression，并把 `ab_replay_improved|ab_replay_regressed` 回写到 quality；`re_memory quality` 写 `quality-ledger.jsonl`、`quality-report.json` 和 `quality-board.md`，把 retrieval/vector/injection/feedback/usefulness 汇总为 qualityScore 和 promote/retain/demote/quarantine/expire 决策并反馈给 search-events/sediment；`re_memory supervise` 写 `supervisor-report.json` 与 `lifecycle-board.md`，把沉淀结果治理成 promotion/demotion/quarantine/expire/merge/retain 队列。`re_lane run` 的高价值 runtime 结果会自动写 `memory_auto_writeback`，把 evidence artifact sha256、evidence_quality、self-heal 和 verifier candidate 一起沉淀；`re_swarm run` 的已执行 worker 会自动写 `memory-swarm-writeback`，把 SubagentRuntimeManifestV1、stdout/stderr hash、toolCallDigest、claim/merge artifact、命令和 blocked/success outcome 写回 MemoryStoreV5。`npm run gate:memory-deposition` 使用 `schemas/reverse-agent/memory-deposition.schema.json` 与 `fixtures/reverse-agent/memory-deposition.fixture.json` 验证手工 deposit、tool_result 自动沉淀、append-only event bus、context pack embedding 和 orchestrator wiring；`npm run gate:memory-experience` 使用 `schemas/reverse-agent/memory-experience.schema.json` 与 `fixtures/reverse-agent/memory-experience.fixture.json` 验证 Episode/Claim/Lesson/Promotion、冲突隔离、operator injection、context pack embedding 和 orchestrator wiring；`npm run gate:memory-skill-capsule` 使用 `schemas/reverse-agent/memory-skill-capsule.schema.json` 与 `fixtures/reverse-agent/memory-skill-capsule.fixture.json` 验证 SkillCapsule/report、promotion gate、operator injection、context pack embedding 和 orchestrator wiring；`npm run gate:memory-quality-ledger` 使用 `schemas/reverse-agent/memory-quality-ledger.schema.json` 与 `fixtures/reverse-agent/memory-quality-ledger.fixture.json` 验证 MemoryQualityLedgerV11 的正反馈提升、负反馈降权、pending feedback、append-only quality ledger、context pack embedding 和 orchestrator wiring；`npm run gate:memory-store` 使用 `fixtures/reverse-agent/memory-store.fixture.json` 验证坏 prevHash 阻断、case index 修复、transaction manifest 和 lane runtime auto writeback marker；`npm run gate:memory-swarm-writeback` 使用 `fixtures/reverse-agent/memory-swarm-writeback.fixture.json` 验证 worker 写回数量、artifact 捕获和 plan/merge 非 run 模式不重复写入。`npm run gate:memory-usefulness` 使用 `fixtures/reverse-agent/memory-usefulness.fixture.json` 验证 authz/pwn 正召回、失败/跨 route forbidden memory 不进 topK，以及 child-process 并发 append probe 保持 hash-chain。`npm run gate:memory-feedback-closure` 使用 `schemas/reverse-agent/memory-feedback-closure.schema.json` 与 `fixtures/reverse-agent/memory-feedback-closure.fixture.json` 验证 injected memory 的成功反馈提升、失败反馈降权、pending writeback 和 supervisor demotion。`npm run gate:memory-vector` 使用 `schemas/reverse-agent/memory-vector.schema.json` 与 `fixtures/reverse-agent/memory-vector.fixture.json` 验证本地 hash embedding、OpenAI-compatible embedding provider contract、env-ref API key、explicit remote allow、vector-index/vector-search-report、`memory_vector_rerank`、route-scoped rerank 和 forbidden cross-route vector leak。`npm run gate:memory-supervisor` 使用 `schemas/reverse-agent/memory-supervisor.schema.json` 与 `fixtures/reverse-agent/memory-supervisor.fixture.json` 验证 `MemorySupervisorV1` lifecycle 治理、promotion/demotion/quarantine/merge 和 runtime `re_memory supervise`。

### MemoryActiveKernelV14 / 主动记忆决策内核

`re_memory active` 会把 sedimentation、quality、replay、strategy、feedback closure 和 scope isolation 融合为 MemoryActiveKernelV14：`active-kernel-report.json` 是统一决策账本，`active-injection-pack.json` 是 operator/verifier/fallback/avoid 可直接消费的注入包，`active-strategy-board.md` 是人类可读 active strategy board。它将高质量、replay-proven strategy 变成 `inject/reuse/verify/repair`，将失败、过期、scope-blocked 或 quarantined memory 变成 `avoid/quarantine/expire/wait-feedback`，并要求注入后写回 `active_kernel_feedback`。`MemoryOrchestratorV6` 的 `active_memory_kernel_decision` step、`re_context pack`、compact-resume hints 与 `npm run gate:memory-active-kernel` 共同保护该链路，避免“记忆沉淀了但没有主动调度”。

### MemoryMaturationRuntimeV15 / 记忆成熟闭环

`re_memory mature` 会把 tool/runtime 写回结果沿 `tool_result_to_strategy_loop` 成熟为 MemoryMaturationRuntimeV15：`maturation-runtime-report.json` 是成熟决策报告，`maturation-runtime-ledger.jsonl` 是带 `prevHash/entryHash` 的成熟 hash chain，`maturation-action-board.md` 是人类可读行动板。它把 active decision 分为 `promote|retain|demote|quarantine|feedback-required|replay-required`，强制每条 row 带 stagePath、feedbackCommands、retentionCommands、retentionScore、stalenessDays、replay gate、retention_decay_scheduler、stale_memory_rehearsal_queue、usefulness_backprop_to_maturation、compact-resume hints 和 closed-loop writeback。`MemoryOrchestratorV6` 的 `memory_maturation_runtime_loop` step、`re_context pack` 与 `npm run gate:memory-maturation-runtime` 共同保护该链路，避免“记忆写进去了但没有继续升降权和复盘”。

## Reflection/evolution 闭环

`/re-reflect plan|show|write` / `re_reflect` 消费 `supervisor_review` / `supervisor_artifact`，输出 `reflection_cycle` 与 `reflection_artifact`。`write` 模式将 lessons、failure_patterns、reuse_rules、repair_playbook 写入 field journal、evolution log 和 `repi-profile/memory/playbooks/*.md`，并闭合 `reflection_memory_ready`。

## Context/resume pack 闭环

`/re-context pack|show|resume|resume-ledger` / `re_context` 消费 mission blackboard、evidence ledger、artifact_index、supervisor/reflect 结果、tool digest 与 memory tail，输出 `context_pack` 与 `context_artifact`。它把 `resume_brief`、`repair_queue`（含 supervisor 的 `commander_merge_queue`）、`commander_merge_budget`、`worker_scoreboard`、`reflection_reuse_rules`、`next_operator_commands` 和 `next_context_command` 固化到 `.repi-harness/evidence/contexts/*.md`，并闭合 `context_pack_ready`，用于压缩、重启、handoff 后恢复连续逆向渗透作战。

当前 runtime 已把 context pack 升级为 `ContextPackV2` / `ResumeContractV2`：pack 记录 `schemaVersion: 2`、`createdAt`、`sessionId`、`cwd`、`workspaceRoot`、`contextPath`、`contextSha256`、artifact sha256/mtime/size/exists、scope（mission/session/workspace/target/branch）、`resumeQueueStatus`、`idempotencyKey`、`closure`、可机读 `resumeContract` 和 append-only `memory/compaction-resume-ledger.jsonl`。artifact index 不只包含 evidence artifacts，也会把 MemoryStoreV5 / scope isolation / sedimentation 关键文件纳入 exact hash contract：`memory/events.jsonl`、`memory/case-memory.jsonl`、`memory/store-report.json`、`memory/store-snapshot.json`、`memory/usefulness-eval.json`、`memory/scope-isolation-report.json`、`memory/distillation-report.json`、`memory/injection-packet.json`、`memory/sedimentation-report.json` 等；这些文件存在时会作为 required artifact 校验，避免 compact 后用过期沉淀包继续规划。`re_context resume <contextPath>` 或 tool 参数 `contextPath` / `compactionEntryId` 会走 exact resume loader，按指定 pack 校验 `contextSha256`、artifact/memory hash drift、target/workspace/branch scope，并在输出中给出 `exactResumeVerification`；drift、缺失或 scope mismatch 会把 resume 标记为 blocked，避免用最新 pack 或污染 artifact 误恢复。`re_complete audit` 还会验证 `compaction-resume-ledger.jsonl` 的 `prevHash/entryHash`；`CompactResumeLedgerV2` 同步写入 `memory/compaction-resume-transitions.jsonl` 和 `memory/compaction-resume-ledger-v2-report.json`，由 `re_context resume-ledger` / `re_memory compact-resume` 查看，并把状态机报告嵌入 context pack；`npm run gate:compact-resume-chain` 用 fixture 覆盖 queued→running→done、proof-loop telemetry、duplicate idempotency、invalid transition、budget exhausted/open closure 和 memory store/injection packet hash 绑定等跨 session 精确恢复负例；`npm run gate:compact-resume-ledger-v2` 真实验证 V2 transition hash、幂等 replay、budget 和 pack embedding；`npm run gate:context-runtime-schema` 会用临时 REPI home 真实调用 `re_mission new → re_map → re_memory verify/sediment → re_context pack → re_context resume`，确认 pack/resume JSON schema、context hash、memory hash contract 和 exact resume closure 不是只存在于 marker。

## Operator queue 调度闭环

`/re-operator plan|show|dispatch|verify|escalate` / `re_operator` 消费 `context_pack` / `context_artifact` 中的 `next_operator_commands`，输出 `operator_queue` 与 `operator_artifact`。它按 `dispatcher_policy` 对 bootstrap/tool-index、map/plan、runtime/graph、campaign/operation/delegate/swarm、supervisor/reflect、context/memory、verifier/compiler、replayer/autofix、proof-loop、knowledge-graph、completion 分层排序，支持 bounded `dispatch`、`verification_matrix`、`escalation_queue`、`next_operator_command`，并闭合 `operator_queue_ready`。

## Verifier matrix 反证闭环

`/re-verifier check|show|matrix` / `re_verifier` 消费 `operator_queue` / `operator_artifact` 的 dispatch 结果，输出 `verifier_matrix` 与 `verifier_artifact`。它把每个执行结果转成 `assertions`、`evidence_bindings`、`counter_evidence`、`contradictions`、`gaps`、`operator_next_actions` 和 `next_verifier_command`，并闭合 `verifier_matrix_ready`，用于最终报告前的独立证据断言和反证检查。

## Compiler report 编译闭环

`/re-compiler draft|show|final` / `re_compiler` 消费最新 `verifier_matrix` / `verifier_artifact`，把 `proved`、`weak`、`contradicted`、`missing` 断言汇总为 `compiler_report` 与 `compiler_artifact`。输出包含 `supervisor_artifact`、`release_gate_metadata`、`strict_claim_gate`、`claim_gate_result`、`key_evidence_block`、`repro_commands`、`contradictions`、`gaps`、`next_operator_queue`、`final_report_scaffold` 和 `next_compiler_command`；`final` 模式只有 strict claim marker 为 pass 时才写入最终报告文件并闭合 `report_or_writeup_ready`，否则只写 compiler artifact 并把 gate 标记为 blocked。

## Replayer matrix 复现闭环

`/re-replayer plan|show|run` / `re_replayer` 消费最新 `compiler_report` / `compiler_artifact` 中的 `repro_commands`，把可直接执行的命令转成 bounded `replay_matrix`。`run` 模式逐条记录 `exit`、`stdout_sha256`、`stderr_sha256`、blocked/failed rows、`next_replay_actions` 与 `replay_artifact`，并闭合 `replay_ready`，用于证明报告里的复现命令仍可运行。

## Autofix repair 自动修复闭环

`/re-autofix plan|show|apply` / `re_autofix` 消费最新 `replay_matrix` / `replay_artifact` 的 failed/blocked rows，并合并 `compiler_report` 的 gaps/contradictions，生成 `autofix_plan` 与 `autofix_artifact`。输出包含 `patch_queue`、`command_substitutions`、`bootstrap_queue`、`evidence_recapture_queue`、`next_operator_queue` 和 `next_autofix_command`；`apply` 模式把修复队列写入 memory，并闭合 `autofix_ready`，之后应回到 `re_replayer run` 验证修复。

## Runtime failure/repair ledger 闭环

`re_replayer`、`re_autofix`、`re_operator` 和 `re_proof_loop` 的 runtime writer 会把 failed / blocked rows 归一化为 `FailureLedgerEventV1` 与 `RepairQueueItemV1`，append 到 `.repi-harness/evidence/failures/ledger.jsonl` 和 `.repi-harness/evidence/repairs/queue.jsonl`。每条 failure 复用 `runtimeFailureSignature`、`budget/retryBudget`、artifact sha256、`blockedConditions`、`rollback` 与 `evidenceWriteback` 字段；`failureToRepair` 把失败映射为 `rerun`、`replace-command`、`recapture-evidence`、`refresh-context`、`rollback` 或 `escalate` repair action。`RepairRollbackPolicyV1` / `npm run gate:repair-rollback-policy` 进一步要求 state-changing repair 先有 baseline snapshot，再按 allowlist 改动，repair 后跑 regression gate，最后 rollback restore 并验证 restored tree hash 与 baseline 一致；`re_autofix` 遇到 patch_queue 时会写 live `repairRollbackPolicyPath` 并输出 `runtime:repair-rollback-live-wiring` 可验证 artifact。该层让 proof-loop、operator、replayer 和 autofix 不再只在各自 artifact 中描述失败，而是写入同一 canonical failure/repair ledger；compound-frontier failed gates、agent-dogfood role retry 和 plan-only invalid fixture 也会生成同类 rows。schema 层通过 `fixtures/reverse-agent/failure-repair-strict.fixture.json` 与 `fixtures/reverse-agent/repair-rollback-policy.fixture.json` 验证 strict fixture、duplicate signature/attempt rejection、loose extra field rejection、baseline/allowlist/rollback/regression 负例，以及 `status=exhausted` 后 remaining budget 未闭合或 unpaused rerun/retry repair 的终态拒绝。

## Execution kernel 底层执行内核

`/re-kernel build|show|audit` / `re_kernel` 在任务启动或 profile/runtime 修改后生成 `execution_kernel` 与 `kernel_artifact`，输出 `directive_stack`、`refusal_to_execution_rules`、`domain_capabilities`、`tool_call_policy`、`artifact_contract`、`stall_recovery`、`operator_next_actions` 和 `next_kernel_command`。artifact 写入 evidence kernel 目录，同时写入 `memory/execution-kernel.md` 并闭合 `execution_kernel_ready`；后续 `re_map`、`re_lane`、`re_operator` 和 completion gates 按该底层执行内核推进。

## Proof loop 证明-复现-修复闭环

`/re-proof-loop plan|show|run` / `re_proof_loop` 把 `re_verifier matrix`、`re_compiler draft|final`、`re_replayer run`、`re_autofix plan|apply`、`re_knowledge_graph build` 和 `re_complete audit` 串成 bounded proof loop。输出 `proof_loop` / `proof_loop_artifact`、`verdict`、`gate_status`、`evidence_summary`、`specialist_queue`、`swarm_bridge`、`bridge_artifacts`、`steps`、`executed_steps`、`next_proof_actions` 与 `next_proof_command`；当 verdict 为 `partial`/`needs_repair` 时把 verifier/compiler/replayer/autofix/gate gap 分类为 web-authz、mobile-runtime、native-runtime、pwn-exploit、firmware-dfir、cloud、identity、agentsec、malware、reporting 或 general 专项 worker，并生成/执行 `re_delegate plan` → `re_swarm run` → `re_supervisor repair` 桥接；artifact 写入 `.repi-harness/evidence/proof-loops/*.md` 并闭合 `proof_loop_ready`。在 `re_decision_core run` 或 `re_operator dispatch` 后优先用 `re_proof_loop run <target> 4 2` 关闭 verifier→compiler→replayer→autofix 证据链。

## Knowledge graph 长期知识图谱闭环

`/re-knowledge-graph build|show|query` / `re_knowledge_graph` 汇总 `.repi-harness/evidence/*` 下的 map、browser、run、attack_graph、campaign、operation、delegation、supervisor、reflection、context、operator、verifier、compiler、replayer、autofix artifacts，生成 `knowledge_graph` 与 `knowledge_artifact`。输出包含 `case_signatures`、`artifact_nodes`、`high_value_edges`、`similarity_index`、`worker_routing_hints`、`worker_scoreboard`、`adaptive_routing_hints`、`worker_promotion_queue`、`compact_resume_telemetry`、`compact_resume_case_memory`、`compact_resume_routing_hints`、`command_strategy_hints`、`knowledge_scope_isolation` 和 `next_knowledge_command`，同时写入 `memory/knowledge-graph-index.md` 并闭合 `knowledge_graph_ready`，用于跨任务迁移和相似案例检索。`KnowledgeScopeIsolationV1` 会读取 `memory/scope-isolation-report.json`，把跨 workspace/target/route 污染 artifact 从 `command_strategy_hints` 与 `similarity_index` 剔除，只留下 `scope_quarantine` 节点供审计；`npm run gate:knowledge-scope-isolation` 保护该链路。


## Decision Core 决策内核层

`/re-decision plan|show|tick|run` / `re_decision_core` 读取 mission gates、active lane、tool posture、artifact posture、evidence priority、execution kernel 与 context/operator/verifier/compiler/replayer/autofix/proof-loop/knowledge artifacts，输出 `decision_core` / `decision_artifact`、`objective_stack`、`gate_pressure`、`evidence_priority`、`tool_posture`、`artifact_posture`、`decision_rules`、`operator_queue`、`decision_next_actions`、`operator_next_command` 与 `next_decision_command`；artifact 写入 `.repi-harness/evidence/decisions/*.md`，同时写入 `memory/decision-core.md` 并闭合 `decision_core_ready`。当下一步不清、上下文恢复、关键 artifact 更新或出现 narrative-only 倾向时，先 `re_decision_core tick <target>` 生成队列，再 `re_decision_core run <target> 1` bounded dispatch，最后进入 `re_proof_loop run <target> 4 2`。

## REPI native-deep execution kernel update

- `execution_invariants` / `operator_command_floor` / `specialist_capability_matrix` / `proof_exit_criteria` 是 `re_kernel build` 的底层执行约束：任何安全/逆向/渗透任务必须落到 route→map→lane plan/run→runtime artifact→verifier/replayer/proof-loop，而不是 narrative-only。
- `native deep reverse/pwn` 专项会在 Native/Pwn/Mobile/CTF lanes 注入 `native-deep-symbol-map-scaffold`、`native-deep-decompiler-project-scaffold`、`native-deep-compare-trace-scaffold`、`native-deep-patch-hypothesis-scaffold`、`native-deep-symbolic-fuzz-scaffold`。
- `analyzeNativeDeepEvidence` 解析 `Native deep symbol/import/string anchors`、`Native decompiler/control-flow anchors`、`Native compare trace anchors`、`Native patch hypothesis anchors`、`Native symbolic/CFG anchors`、`Native fuzz/crash anchors`，并生成 `native-deep-symbol-map-rerun`、`native-deep-decompiler-rerun`、`native-deep-compare-trace-rerun`、`native-deep-symbolic-fuzz-rerun`、`native-deep-patch-report-scaffold`。
- native patch 必须先绑定 compare/branch runtime trace，再用 replay/verifier 证明输入约束或字节补丁；禁止无 artifact 的口头 patch 结论。


## REPI web-api authz deep update
- operation dispatcher now routes `re_live_browser`, `re_web_authz_state`, verifier, compiler, replayer, autofix, proof-loop, and knowledge graph commands from `operation_queue`.
- Web/API planner adds `web-api-authz-static-scaffold`, `web-api-schema-diff-scaffold`, and `web-api-state-source-scaffold` for route/source/schema authorization evidence.
- Analyzer parses `web API static authz source anchors`, `web API schema/auth parameter anchors`, and `web API state mutation source anchors`, then emits `web-api-authz-static-rerun`, `web-api-schema-diff-rerun`, and `web-api-state-source-rerun`.

## REPI swarm execution audit update
- `re_swarm plan|run|merge` now outputs `execution_audit`, `coverage_matrix`, and `retry_queue` for worker-runtime proof, contract coverage, and bounded repair.
- `re_supervisor review|repair` consumes these rows so worker promotion depends on executed commands, hashes/artifacts/anchors, and covered evidence contracts.

## REPI swarm retry operator bridge update
- Swarm `retry_queue` rows are promoted into `context_pack` as `swarm_retry_queue`, parsed into `next_operator_commands`, and surfaced in `commander_runtime_policy`.
- `re_proof_loop` now exposes `swarm_retry_queue` and can execute `swarm-retry` bridge steps before broader specialist repair.

## REPI operator feedback loop update

- `operator_feedback` is now a first-class verifier→compiler→replayer→autofix field, not a note: operator dispatch results are classified into `unresolved_target`, `dispatcher_gap`, `missing_tool_or_dependency`, `worker_retry_blocked`, `worker_retry_progress`, `runtime_failure`, `replay_or_exploit_candidate`, `strong_evidence`, `failure_budget_exhausted`, and `swarm_retry_queue`.
- `classifyOperatorFeedback` and `operatorFeedbackNextCommands` turn dispatch output into next commands: missing tools go to `re_bootstrap plan`, worker gaps go to bounded `re_swarm run`, runtime failures go to `re_autofix plan`, replay/exploit candidates go to `re_replayer run` or `re_exploit_lab run`, and strong evidence goes back to `re_verifier matrix`.
- `re_verifier`, `re_compiler`, `re_replayer`, and `re_autofix` must preserve `operator_feedback` so proof-loop repairs are driven by execution evidence rather than narrative-only judgment.

## REPI operator feedback proof/chain bridge update

- `latestOperatorFeedback` now collects `operator_feedback` from verifier/compiler/replayer/autofix artifacts and promotes executable `operator_feedback_queue` commands into the proof and chain layers.
- `re_proof_loop` exposes `operator_feedback` and `operator_feedback_queue`, appends bounded `operator-feedback` steps, treats unresolved target/missing tool/runtime failure/failure budget feedback as `needs_repair`, and runs feedback commands before broader swarm/specialist repair.
- `re_exploit_chain plan|compose` carries `operator_feedback` into `evidence_gaps`, `replay_commands`, `operator_queue`, and `proof_path` so exploitability claims inherit dispatcher failure signals instead of bypassing them.

## REPI operator feedback dispatcher fallback update

- `re_operator plan|dispatch` now imports `latestOperatorFeedback` directly into `operator_feedback`, `operator_feedback_queue`, and `dispatcher_fallback_plan` before context commands are sorted.
- `operatorFeedbackDispatchPlan` assigns dispatcher feedback priority: missing tools, unresolved targets, runtime/dispatcher failures, failure-budget exhaustion, swarm retry, replay/exploit candidates, and strong evidence each get bounded primary/fallback commands.
- Dispatch runtime results are reclassified immediately after bounded execution; `operator_feedback_runtime` updates `nextActions` so bootstrap/tool-index refresh, replay/autofix, swarm repair, proof-loop, and exploit-lab fallbacks can run without waiting for narrative review.

## REPI dispatcher feedback learning update

- `dispatcher_feedback_scoreboard` scores every operator feedback fallback command as passed, failed, or queued, then writes `memory/dispatcher-feedback-board.md` for cross-turn reuse.
- `dispatcher_learning_hints` turns those scores into `promote_dispatcher`, `demote_dispatcher`, or `retry_dispatcher` actions so successful repair routes are promoted and failed routes are rerouted through autofix/context repair.
- `re_knowledge_graph build` imports the dispatcher feedback board as `dispatcher_feedback_scoreboard` and `dispatcher_routing_hints`, adding dispatcher-feedback nodes and command strategy hints so future operator queues can reuse the best fallback path.

## REPI dispatcher learning case-memory update

- Dispatcher feedback now feeds `case_memory_migrations`: `Dispatcher routing hints`, `Dispatcher feedback scoreboard`, and `memory/dispatcher-feedback-board.md` are parsed as migration sources with elevated priority.
- `case_memory_lane_plan` treats `promote_dispatcher` as a high-score promotion signal and `demote_dispatcher` / `retry_dispatcher` as repair signals, so autopilot can skip low-value lanes, add `case-memory-repair`, or reprioritize the active lane from dispatcher learning.
- `re_delegate plan` and `re_knowledge_graph build` merge `dispatcherAdaptiveRoutingHints` and `dispatcherPromotionQueue` into worker routing/promotion so dispatcher success/failure affects worker promotion, demotion, and future command strategy.

## REPI autonomous dispatcher budget update

- `AutonomousExecutionBudget` is now a first-class execution-control artifact across `context_pack`, `re_operator`, `re_delegate`, `re_proof_loop`, and `re_knowledge_graph`: it exposes `maxTurns`, `maxDispatch`, `maxProofLoops`, and `maxWorkerRetries` instead of letting the commander drift across unbounded retries.
- `dispatcherScoreDecayRows`, `repeatedFailureDemotionRows`, and `highScorePromotionRows` convert `dispatcher_score` rows into explicit `score_decay`, repeated-failure demotions, and high-score route promotions.
- `writeDispatcherPromotionPlaybook` writes `memory/dispatcher-promotion-playbook.md`, and the knowledge graph / case-memory migration path imports `Autonomous execution budget`, `Dispatcher score decay`, `Repeated failure demotions`, and `High-score promotions` so later lanes reuse the strongest route and demote weak fallback loops.

## REPI autonomous budget ledger update

- `memory/autonomous-budget-ledger.md` now persists `autonomous_budget`, `score_decay`, `historical_score_decay`, demotions, promotions, and `nextActions` across turns so dispatcher/worker/lane scoring is not reset by context compaction.
- `latestAutonomousBudgetLedger`, `cumulativeDispatcherScoreDecayRows`, `workerScoreDemotionRows`, `autonomousLaneDemotionRows`, and `applyAutonomousBudgetDemotions` convert repeated dispatcher/worker failure pressure into automatic `autonomous-dispatcher-repair` lane demotion when thresholds are crossed.
- `writeFormalDispatcherPromotionPlaybook` promotes high-score dispatcher/worker routes into `memory/playbooks/*dispatcher-promotion*.md`, then `maintainPlaybooks` indexes them so `case_memory_migrations` can reuse formal playbooks, the autonomous budget ledger, and `memory/dispatcher-promotion-playbook.md` together.

## REPI runtime configuration

模型/provider/API key、本地网关和 auto compact 的用户文档在 `docs/reverse-agent/repi-runtime-configuration.md`；运行中的 REPI 也必须按该文档直接回答配置问题。关键 marker：`model_provider_configuration_runtime`、`~/.repi/agent/models.json`、`triggerPercent=85`。

## REPI owned compaction kernel update

REPI auto-compact threshold policy is explicit and testable: `triggerPercent` defaults to `85`, `warningPercent` defaults to `80`, `reserveTokens` defaults to `16384`, and `keepRecentTokens` defaults to `36000` in `~/.repi/agent/settings.json`. Runtime compaction uses `compactionTriggerTokens = min(contextWindow * triggerPercent / 100, contextWindow - reserveTokens)`, so large-context models compact proactively while small-context models still keep a hard response/tool budget.

`session_before_compact` 已从“仅保存 checkpoint”升级为 REPI-owned compaction provider：hook 返回 `pi-recon-compaction` summary/details，写入 `pi-recon-compaction-checkpoint`，并把 `.repi-harness/evidence/contexts/*.md` 的 `context_path`、`contextSha256`、`artifactHashes`、`re_context resume`、`re_operator plan/dispatch`、`re_proof_loop run <target> 4 2`、`autonomous_execution_budget`、dispatcher ledger/playbook、repair queue、swarm retry queue、case memory 和 artifact index 固化为恢复契约。若 extension compaction 存在，upstream summarizer 不再主导该段摘要内容。`session_compact` 后追加 `pi-recon-compaction-resume-contract` entry，验证 `fromExtension`、`details.kind`、`context_path`、`re_context resume`、`re_operator plan/dispatch` 与 `re_proof_loop run`，并更新 `compaction_resume_contract_ready` gate；verified contract 会追加 `pi-recon-compaction-auto-resume` 并通过 `pi-recon-auto-resume` custom message 触发一次 bounded resume turn。`pi-recon-compaction-resume-telemetry` / `memory/compaction-auto-resume-board.md` tracks each `compact_resume_command` as queued/done/blocked, proof-loop entry, output hash, and gate status; `memory/compaction-resume-ledger.jsonl` 追加 `contextPath/contextSha256/idempotencyKey/prevHash/entryHash`，为 exact resume 提供 legacy 索引；`memory/compaction-resume-transitions.jsonl` 与 `memory/compaction-resume-ledger-v2-report.json` 是 `CompactResumeLedgerV2` 状态机，记录 `queued/running/done/blocked/exhausted` transition、append-only hash、idempotencyKey 幂等 replay 和 auto-resume budget；`re_context resume-ledger` / `re_memory compact-resume` 可直接查看；`re_operator` exposes this as `compact_resume_telemetry` and `compact_resume_queue`; `re_proof_loop` imports unresolved rows as `source=compact_resume` gaps and `re_complete audit` blocks completion while commands remain queued/blocked or proof_loop_entered is false. `re_knowledge_graph build` now turns the same telemetry into `compact_resume_case_memory`, `compact_resume_routing_hints`, and `compact_resume_status=*` case signatures so successful/failed compact recovery is reusable instead of a one-off resume event; `re_autopilot plan|run` consumes those sections via `compactResumeCaseMemoryCommands`, producing `compact_resume_repair_from_case_memory` repair lanes for queued/blocked recovery or `compact_resume_success_skip_low_value_lane` skips when compact recovery already survived proof-loop.

## Context compact harness 自检

`scripts/reverse-agent/context-compact-audit.mjs [root] [--json]` 是 context_compact_audit 静态门槛，用于在改动后快速确认源码内核与文件型 profile 都保留上下文恢复链路。它仍分组检查 `context_pack`、REPI-owned compaction provider、resume contract/auto-resume telemetry、`evidence_summarization`、`budget_continuation`、runtime tests 和 docs contract。`scripts/reverse-agent/compact-resume-chain-gate.mjs [root] --strict` 是 fixture hard-eval 门槛，用 fixture 证明 exact context load、append-only ledger、resume 状态机和 telemetry proof-loop entry 真能闭合，并拒绝 drift / scope mismatch / duplicate idempotency / invalid transition / exhausted-open closure。`scripts/reverse-agent/compact-resume-ledger-v2-gate.mjs [root] --strict` 是 runtime hard-eval 门槛，真实调用 `re_context pack/resume` 与 `re_memory compact-resume`，验证 transition hash、queued→running→done、幂等 replay、预算和 context pack embedding。`scripts/reverse-agent/context-runtime-schema-gate.mjs [root] --strict` 是 runtime schema 门槛，实际调用 `re_context pack/resume` 并验证 `ContextPackV2` / `ResumeContractV2`、`contextSha256`、required memory artifacts 和 `exactResumeVerification`。三者配合避免 context/compact 能力只存在于 upstream 默认逻辑、marker 或离线 fixture 里。

## Autonomous control plane 静态审计

`scripts/reverse-agent/autonomy-control-plane.mjs [root] [--json] [--write] [--strict]` 是非真实平台、非 provider、非 benchmark 的组织能力静态门槛。它只读取源码、文件型 profile、harness 源码和文档 marker，确认 REPI 当前具备专业逆向/渗透任务组织控制面，同时把尚未达到完整 autonomous red-team agent 的缺口保留为 `notYetTopAutonomousDefinition` / `hardeningNeeded`，避免把成熟度缺口误判成不可用，也避免把单次运行成功包装成完整自治能力。

常用入口：

```bash
npm run gate:autonomy-control
node scripts/reverse-agent/autonomy-control-plane.mjs . --json
```

详细工程路线见 `docs/reverse-agent/autonomous-control-plane.md`。

## Hard eval control plane 离线评测

`scripts/reverse-agent/hard-eval-control-plane.mjs [root] [--json] [--write] [--strict-claims]` 只读取已有 `.repi-harness/evidence/remote/*` 证据，不访问真实网站、不调用 provider、不重跑 benchmark。它把 latest same-window platform claim 与 agent orchestration runtime 分开打分，生成 role contract、append-only claim ledger、failure ledger、paused repair queue 和 anti-self-delusion gate。若 latest same-window 有 required gap，即使 agent 并行编排为 100 分，也会输出 `hard-eval-control-plane-platform-gaps`，防止把编排成功写成平台 claim 全绿。

常用入口：

```bash
npm run audit:hard-eval-control
node scripts/reverse-agent/hard-eval-control-plane.mjs . --json
```

详细说明见 `docs/reverse-agent/hard-eval-control-plane.md`。

## Claim ledger / autonomous contracts 静态门禁

`scripts/reverse-agent/validate-claim-ledger.mjs` 读取 hard-eval 输出，验证 role contract、append-only claim ledger hash chain、artifact handoff sha256、proven claim 的 evidenceRef、required gap 的 challenge/resolution，以及 orchestration/platform score split。当前允许真实平台 gap 的入口是：

```bash
npm run audit:claim-ledger
```

严格平台 claim 门禁可用：

```bash
npm run gate:claim-release
```

在当前 evidence 下 strict-claims 应失败，因为最新 same-window 仍有小红书/抖音 required gaps；这正是反自嗨边界。

该命令现在会同时写入 strict claim release marker：

```text
.repi-harness/evidence/claim-release/<timestamp>/result.json
```

marker 会被 `re_supervisor`、`re_compiler final` 和 `re_complete audit` 读取。只要
marker 缺失、blocked，或者存在 required platform gaps，最终报告 gate 必须 blocked。

runtime 分工验证还有专门 adapter/gate：

```bash
npm run gate:runtime-claim-ledger
```

它会发现最新 `agent-parallel-dogfood`、`re_swarm`、`compound-frontier` runtime claim ledger，把 runtime `ClaimLedgerEventV1` 适配成 `validate-claim-ledger.mjs` strict input，并同时跑 `--allow-platform-gaps` 与 `--strict-claims`。缺少 source 时，gate 默认执行 bounded agent-dogfood `--plan-only --write-plan-ledger` native ledger、bounded `reSwarmLiveProbe` 与 compound-frontier `--use-latest` native ledger，所以 `gate:runtime-claim-ledger --require-all-sources --require-promotion` 在干净工作树也能得到三类 source 覆盖；输出的 `runtimeLedgerQuality` 会保留 artifact sha256、event type count、tip hash、hash-chain 和 strict validator 摘要。`npm run gate:runtime-ledger-quality` / `RuntimeLedgerQualityGateV1` 会复用最新 runtime-claim-ledger result，并用 schema/fixture 负例阻断缺 event type count、缺 artifact digest、bad tip hash、hash-chain false 或 strict validator failed 的伪通过。已存在的 runtime ledger 必须通过 strict validator，缺失/失败仍会保留为 `missing_runtime_artifact` 或 promotion block。

Worker Runtime Pool hard-eval 用来把“并行 worker 是真的 runtime 组织”从叙述变成合同：

```bash
npm run gate:worker-runtime-pool
```

它验证 `WorkerRuntimePoolV1` 的 `maxConcurrency`、resource lease、timeout/cancel、retryBudget、stdout/stderr hash、claim refs、append-only claim ledger 与 claim-aware merge。负例包含超并发、timeout 未 cancel、duplicate mergeKey 未解决、retry budget 不一致、claim 缺 validation、stdout hash drift、exhausted 后继续 retry。`re_swarm run` 已把 command-level `SubagentRuntimeManifestV1` 默认桥接到 WorkerChildSessionRuntimeBatchV1 / WorkerRuntimePoolV1，不再只保留旁路 manifest。

Provider failure injection contract 约束“provider 失败不能只吐错误”：

```bash
npm run gate:provider-failure-injection
```

它验证 `ProviderFailureInjectionReportV1`：gate 会用真实 `repi --provider ... --model ... -p ...` 触发本地 mock provider 的 HTTP 500、OpenAI-compatible malformed SSE、Anthropic-compatible error event 三类失败；每个失败必须捕获 request-log、transcript、stdout/stderr hash，并生成 canonical `FailureLedgerEventV1` 与 `RepairQueueItemV1`，共享同一 signature / retryBudget / repairId。gate 还会把 rows 写入临时 append-only failure ledger / repair queue 并用 strict validator 复验；exhausted provider 失败必须转 `escalate` 且 repair `paused=true`，不能继续 unpaused rerun/retry。负例覆盖 duplicate signature、exhausted unpaused rerun、loose extra field 和 missing repair。

Provider runtime matrix contract 约束“主流模型/provider 接入不是只会列配置”：

```bash
npm run gate:provider-runtime-matrix
```

它验证 `ProviderRuntimeMatrixV1`：gate 会起本地 mock OpenAI-compatible 与 Anthropic-compatible provider，在 isolated `~/.repi/agent/models.json` 中只写 `$ENV` 引用，然后分别真实运行 `repi --provider child-openai-compatible --model child/openai-mock ...` 与 `repi --provider child-anthropic-compatible --model child/anthropic-mock ...`。通过条件包括 `repi --list-models` 能看到两个 provider、OpenAI-compatible 请求到 `/v1/chat/completions`、Anthropic-compatible 请求到 `/v1/messages`、streaming=true、Authorization/x-api-key 来自环境变量、request-log/transcript/stdout/stderr hash 可追踪、evidence 脱敏、无 `.pi` profile 污染和无 update banner。负例覆盖缺 env-ref、错误 endpoint、update banner 泄漏、Anthropic case 缺失和 list-models 缺 provider。

Parallel provider worker matrix contract 约束“多模型 worker 并行不是串行 smoke”：

```bash
npm run gate:parallel-provider-worker-matrix
```

它验证 `ParallelProviderWorkerMatrixV1`：gate 会在同一个 isolated `~/.repi/agent/models.json` 下并发启动多个真实 `repi --provider ... --model ... -p ...` child worker，覆盖 OpenAI-compatible pass、Anthropic-compatible pass、OpenAI-compatible 500 failure repair、slow provider timeout/cancel。通过条件包括 peak concurrency ≥ 2、`repi --list-models` 完整、claim-aware provider worker merge 解决 duplicate mergeKey、failure/timeout worker 生成 `FailureLedgerEventV1` / `RepairQueueItemV1` 并 append-only writeback、timeout worker 必须被 cancel、env-ref-only API key、request-log/transcript/stdout/stderr hash、evidence 脱敏、无 `.pi` profile 污染和无 update banner。负例覆盖 serial execution、missing claim merge、unredacted secret、timeout without cancel 和 missing repair。

Remote provider long-run contract 约束“真实远程 provider 回归必须可启用，但不能污染默认 CI”：

```bash
npm run gate:remote-provider-longrun
```

默认无 `REPI_REMOTE_PROVIDER_LIVE=1` 时该 gate 输出 skipped/pass，不需要任何远程密钥。显式开启 live 后，配置：

```bash
export REPI_REMOTE_PROVIDER_LIVE=1
export REPI_REMOTE_PROVIDER_API=openai-completions   # 或 anthropic-messages
export REPI_REMOTE_PROVIDER_BASE_URL=https://example.com/v1
export REPI_REMOTE_PROVIDER_MODEL=provider/model-id
export REPI_REMOTE_PROVIDER_API_KEY_ENV=REPI_REMOTE_PROVIDER_API_KEY
export REPI_REMOTE_PROVIDER_API_KEY=...
```

gate 会生成 isolated `~/.repi/agent/models.json`，只写 `$REPI_REMOTE_PROVIDER_API_KEY` 这种 env-ref，不写明文 key；随后运行 `repi --list-models` 和多轮 `repi --provider ... --model ... --no-tools --no-session -p ...`。`RemoteProviderLongRunV1` 要求 marker、stdout、bounded timeout、session/profile isolation、无 `.pi` profile 污染、无 update banner、无 literal secret；失败时生成 canonical `FailureLedgerEventV1` / `RepairQueueItemV1` writeback。负例覆盖 live missing marker、secret leak、unbounded timeout、skipped without reason 和 missing repair。

Worker child-session runtime contract 进一步约束“独立子代理/模型运行态”：

```bash
npm run gate:worker-child-session
```

它验证 `WorkerChildSessionRuntimeBatchV1`：child worker 必须通过 `repi --recon` 进入独立 `isolatedHome` / `.repi` profile，provider 配置只能引用环境变量，不能把真实 key 写入 artifact；默认不导入 `.pi` auth，不开启 update/telemetry；每个 child session 需要 transcript/stdout/stderr hash、toolCallDigest、timeout/cancel、retryBudget、pool bridge 和 `artifact_handoff → claim → validation → challenge → resolution` claim ledger。`re_swarm run` 会写 `workerChildSessionRuntimePath` / `*-worker-child-session-runtime.json`，其中包含 live batch、batchValidation、WorkerRuntimePoolV1 bridge 和 poolValidation；gate 会真实执行 bounded `re_swarm run`，并通过 `WorkerChildProcessProbeV1` 在 isolated HOME 下实际启动 `repi --offline --help`，确认 runtime artifact wiring、`childSessionRuntimeCaptured=true`、`childProcessRuntimeCaptured=true`、无 `.pi` auth 导入和 pool bridge pass。随后 gate 还会通过 `WorkerProviderChildProcessProbeV1` 起本地 mock OpenAI-compatible provider，写入 isolated `models.json`，真实运行 `repi --provider child-openai-compatible --model child/mock-model --no-tools --no-session --thinking off -p ...`；验证 `/v1/chat/completions` request、model、env-ref-only API key、Authorization 来源、stdout marker、request-log/transcript/stdout/stderr hash、脱敏 evidence、无 `.pi` 路径和无 update banner。负例覆盖 `pi` 命令污染、共享 `.pi` home、secret allowlist、literal api key、transcript hash drift、timeout 未 cancel、exhausted 还 running、缺 pool bridge 和 claim 缺 validation。

Structured claim merge contract 约束最终 claim promotion：

```bash
npm run gate:structured-claim-merge
```

它验证 `StructuredClaimMergeV1`：worker claim 不能靠文本摘要升级为 final pass，必须有 artifact sha256、JSON query、verifier pass、resolved adversary challenge、resolved conflict table、winner evidence 和 loser downgrade。运行时 `re_swarm` 现在会从 `ClaimLedgerEventV1` 生成 `*-structured-claim-merge.json` 和 `structuredClaimMergeStatus`，并在多个 worker 争夺同一 final promotion topic 时执行 `structured_conflict_arbitration_live_wiring`：按 runtime evidence score 选 winner，写 `winningEvidenceRefs`，把 loser 放入 `downgradeLosers` / blockedClaims，阻止 loser 进入 finalClaims；`re_compiler final` 与 `re_complete audit` 会读取该 gate，遇到 `status=blocked_by_structured_claim_merge`、unresolved challenge/conflict、weak/gap claim 被 promoted、JSON query mismatch、missing winner evidence 时阻断最终发布。`gate:structured-claim-merge` 的 `runtime:structured-claim-live-wiring` 会真实跑 bounded `re_swarm run`，校验 runtime claim ledger hash chain、`StructuredClaimMergeV1` artifact、live conflict arbitration、final pass claim 和 blocked claim 的同源生成。

`scripts/reverse-agent/autonomous-runtime-contracts.mjs . --strict` 验证 autonomous runtime strict fixture：subagent manifest、parallel shard state、compact resume transition、repair budget 与 runtime claim promotion gate。`scripts/reverse-agent/autonomous-contracts.mjs . --strict` 会把该 gate 纳入总控制合同，并继续聚合 `ReconParallelPlanV1`、`ResumeContractV2`、`FailureLedgerEventV1/RepairQueueItemV1`、`RoleContractV1/ClaimLedgerEventV1`。常用入口：

```bash
npm run gate:autonomous-runtime
npm run gate:autonomous-contracts
```

Failure/repair 合同现在同时保留机器字段和人类可读别名：

- failure event：`category/signature/attempt/maxAttempts/status/failedGates/artifactHashes/budget/retryBudget/rollback/evidenceWriteback/blockedConditions`。
- repair item：`action/repairAction/commands/expectedArtifacts/expectedGates/preconditions/paused/rollbackCriteria/regressionGates/blockedConditions/evidenceWriteback`。
- `--write` 仍写 per-run 目录，同时追加 canonical append-only 路径：
  `.repi-harness/evidence/failures/ledger.jsonl` 与 `.repi-harness/evidence/repairs/queue.jsonl`。
- `gate:repi-isolation` 会用临时 HOME 构造旧 `~/.pi/agent` 污染样本，验证 `repi` 默认只用 `~/.repi/agent`，不会触发 stale model scope、API key、collision 或 Global tools 报错，也不会改写普通 `pi` profile。
- `gate:memory-contract` 会验证 Memory v2 schema/fixture、`events.jsonl` hash chain、`case-memory.jsonl` 引用、`retrieval-report.json` 引用和负例拒绝，防止长期记忆退回纯 Markdown。
- `gate:autonomous-runtime` 会读取 autonomous runtime strict fixture，验证 valid batch 通过、duplicate subagent attempt、非法 resume transition、loose claim-gate field 都被拒绝。
- `gate:autonomous-contracts` 会读取 failure/repair strict fixture 与 autonomous runtime gate，验证 valid batch 通过、duplicate signature/attempt、loose extra field、exhausted 后继续 unpaused rerun/retry 都被拒绝。
- release 级 claim 不走 `audit:claim-ledger --allow-platform-gaps`，而走 `gate:claim-release`；当前 required platform gaps 存在时它应该阻断，并把 blocked marker 写给 runtime final path 使用。

## Harness 自检层

- `gate:repi-harness` 是外层顶级独立 harness：用临时 HOME/bin 模拟安装，证明 `pi` stub 不被覆盖、旧 repi stale shim 被清掉、`~/.pi/agent` 不被默认读取/改写、`repi` help/update help 去掉 upstream update/branding，并额外模拟不经源码 wrapper 的 package/bin 直启，确认 CLI 自身默认进入 REPI kernel；然后串联 product/isolation/context/memory（含 memory-orchestrator）/autonomous runtime/control gates。CI 模板 `docs/reverse-agent/repi-harness.github-actions.yml` 复制到 `.github/workflows/repi-harness.yml` 后，会在 push/PR 自动跑这套门禁。
- `re_harness` / `/re-harness quick|full|install|show` 生成 `harness_artifact`，聚合 `install_readiness`、`reverse_capability_guards`、`regression_guards`、注册工具/命令矩阵和 evidence/memory/tool-index 可写性。
- 开发或产品面整改后执行 `re_harness full`；运行 `npm run install:repi` 后，只安装/刷新 `repi`，普通 `pi` 仍归 upstream Pi；随后执行 `hash -r`、`repi --offline --help`、`npm run gate:repi-harness` 与 `/re-harness install`。
- `reverse_capability_guards` 会守住 re_native_runtime、re_web_authz_state、re_mobile_runtime、re_exploit_lab、re_proof_loop、re_autopilot、re_knowledge_graph、compact_resume_case_memory、compact_resume_repair_from_case_memory、compact_resume_success_skip_low_value_lane、operator_command_floor、proof_exit_criteria、specialist_runtime_planner，避免安装/自检优化削弱逆向渗透能力。

### MemoryUxDashboardV16 / 可观测记忆状态

`re_memory status` 生成 `status-report.json` 与 `status-board.md`，把 MemoryStore、召回、quality、replay、active kernel、maturation 和 supervisor 队列合成一张用户可读状态板；`re_memory why <query>` 展示 why rows，解释每条记忆的 score、reasons、commands 和 lessons；`re_memory promote|demote|forget <event-id>` 通过 append-only `governance-ledger.jsonl` 写治理反馈，不重写历史。`npm run gate:memory-ux` 覆盖 `MemoryUxDashboardV16`、`user_visible_memory_status`、`recall_explainability`、`append_only_memory_governance`、`lifecycle_governance_commands`、status-board 写入和 runtime governance flow。

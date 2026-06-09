# Pi-RECON 深度逆向渗透 Agent 配置

本目录说明本仓库对 Pi 的“魔改”配置。它不是单独添加一个 skill，而是把 Pi 的系统提示、资源加载、运行时扩展、长期记忆、工具索引、自审计、压缩记录和任务模板组合成一个逆向渗透作战 profile。

## 两层形态

本仓库现在有两种 Pi-RECON 形态：

1. **源码内核入口**：`packages/coding-agent/src/core/recon-profile.ts` + CLI `--recon` / `--reverse-pentest`。这是内置 profile：直接接入 resource loader、inline extension factory、system prompt、append prompt、skill/prompt 注入、记忆和工具索引。
2. **文件型 profile**：`.pi/SYSTEM.md`、`.pi/APPEND_SYSTEM.md`、`.pi/extensions/reverse-pentest-core.ts`、`.pi/skills/*`、`.pi/prompts/*`。这是项目/全局部署形态，方便迁移和外部分发。

优先使用源码入口：

```bash
./pi-test.sh --recon
./pi-test.sh --reverse-pentest -p "分析这个 ELF 的许可证校验逻辑"
```

如果已经安装了旧的全局 `.pi/extensions/reverse-pentest-core.ts`，`--recon` 会保留内置 inline kernel profile，并抑制同名 `re_route` / `re_memory` / `re_tool_index` 工具冲突。

## 底层强执行契约

Pi-RECON 在 `packages/coding-agent/src/core/recon-profile.ts`、`.pi/SYSTEM.md`、`.pi/APPEND_SYSTEM.md` 和 orchestrator skill 中内置 `refusal_to_execution` 与 `operator_command_floor`：安全/逆向/渗透/红队/CTF 请求默认进入 `execution-first mode`；目标、样本、凭据、工具或上下文不足时，不停在拒绝或泛化提示，而是改写成 `re_map`、`re_lane plan`、`fallback_commands`、`bootstrap plan`、最小复现脚本或一个精确缺口问题，并持续输出 `operator_next_command`、工具调用、artifact 路径或最小复现命令。

## 组件

| 路径 | 作用 |
|---|---|
| `.pi/SYSTEM.md` | 替换 Pi 默认系统提示，定义 Pi-RECON 执行模型 |
| `.pi/APPEND_SYSTEM.md` | 附加启动序列、记忆协议、完成门槛 |
| `.pi/settings.json` | 高思考等级、压缩/重试/技能命令/资源加载配置 |
| `.pi/extensions/reverse-pentest-core.ts` | 运行时核心：路由、记忆、工具索引、自审计、loop guard、compaction checkpoint、自定义工具 |
| `.pi/skills/reverse-pentest-orchestrator/SKILL.md` | 安全任务总控 skill，按 reverse-skill 思维方式编排工作流 |
| `.pi/prompts/*.md` | `/reverse`、`/websec`、`/jsre`、`/pwn`、`/pcap`、`/cloud`、`/identity`、`/memory`、`/audit-agent` 任务模板 |
| `.pi/memory/*` | 长期经验、索引、自我进化记录；`.pi/memory/playbooks/index.md` 记录 playbook 质量/年龄/状态，`.pi/memory/playbooks/archive/` 存放被淘汰的低质或过旧链路 |
| `.pi/evidence/kernel/*.md` | `re_kernel build|audit` 生成的 execution_kernel、kernel_artifact、directive_stack、refusal_to_execution_rules、tool_call_policy、artifact_contract 与 stall_recovery |
| `.pi/evidence/maps/*.md` | `re_map` 自动生成的被动目标/工作区快照：stat、manifest/config、route/auth 搜索、binary candidates、URL baseline |
| `.pi/evidence/browser/*.md` | `re_live_browser plan|run` 生成的 live_browser、request_response_log、auth_matrix、IDOR/BOLA probes、WebSocket probes 与 replay_commands |
| `.pi/evidence/graphs/*.md` | `re_graph build` 自动生成的 attack graph：mission lanes/gates、map/run artifacts、evidence ledger、tool-index gaps、critical_path、operator_next_actions |
| `.pi/evidence/chains/*.md` | `re_exploit_chain plan|compose` 生成的 exploit_chain、proof_path、exploit_path、evidence_gaps、replay_commands 与 operator_queue |
| `.pi/evidence/decisions/*.md` | `re_decision_core plan|tick|run` 生成/运行的 decision_core、gate_pressure、operator_queue、executed_steps 与 operator_next_command |
| `.pi/evidence/campaigns/*.md` | `re_campaign plan` 生成的跨域 campaign_graph 与 phases/pivots/gaps |
| `.pi/evidence/operations/*.md` | `re_operation plan|run` 生成的 operation_queue 与 phase_runner |
| `.pi/evidence/delegations/*.md` | `re_delegate plan|merge` 生成的 specialist worker_packets、merge_queue、adaptive_routing_hints、worker_promotion_queue 与 case_memory_migrations |
| `.pi/evidence/swarms/*.md` | `re_swarm plan|run|merge` 生成的 worker_runtime_packets、run-mode worker_executions/worker_results/blocked/merge_digest、parallel_groups、merge_protocol、collision_matrix 与 commander_next_actions；merge 保留 runtime digest |
| `.pi/evidence/supervisor/*.md` | `re_supervisor review|repair` 生成的 worker/swarm critic、swarm_artifact、repair_queue、commander_merge_queue、commander_merge_budget、worker_scoreboard 与 priority_queue |
| `.pi/evidence/reflections/*.md` | `re_reflect plan|write` 生成的 reflection_cycle、reflection_artifact 与 memory/evolution 闭环 |
| `.pi/evidence/contexts/*.md` | `re_context pack|resume` 生成的 context_pack、artifact_index、含 commander_merge_queue 的 repair_queue、commander_merge_budget、worker_scoreboard 与 next_operator_commands |
| `.pi/evidence/operators/*.md` | `re_operator plan|dispatch|verify|escalate` 生成的 operator_queue、dispatcher_policy 与 verification_matrix |
| `.pi/evidence/verifiers/*.md` | `re_verifier check|matrix` 生成的 verifier_matrix、assertions、counter_evidence 与 gaps |
| `.pi/evidence/compilers/*.md` | `re_compiler draft|final` 生成的 compiler_report、compiler_artifact、key_evidence_block 与 repro_commands |
| `.pi/evidence/replayers/*.md` | `re_replayer plan|run` 生成的 replay_matrix、replay_artifact、stdout/stderr hash 与 replay_ready 证据 |
| `.pi/evidence/autofix/*.md` | `re_autofix plan|apply` 生成的 autofix_plan、patch_queue、command_substitutions、bootstrap_queue 与 evidence_recapture_queue |
| `.pi/evidence/proof-loops/*.md` | `re_proof_loop plan|run` 生成的 proof_loop、verdict、gate_status、evidence_summary、specialist_queue、swarm_bridge、bridge_artifacts、executed_steps 与 next_proof_actions |
| `.pi/evidence/knowledge/*.md` | `re_knowledge_graph build|query` 生成的 knowledge_graph、case_signatures、similarity_index、worker_routing_hints、worker_scoreboard、adaptive_routing_hints、worker_promotion_queue、compact_resume_case_memory、compact_resume_routing_hints 与 command_strategy_hints |
| `.pi/tools/tool-index.md` | 本机工具可用性索引，避免猜工具路径 |
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
| `scripts/reverse-agent/install-global-profile.sh` | 安装到 `~/.pi/agent` 的全局 profile 脚本（会备份同名文件） |

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
  - `/re-memory show|append|evolve|playbooks|prune-playbooks ...`：读取/追加长期记忆或进化日志；`playbooks` 生成 `.pi/memory/playbooks/index.md`，`prune-playbooks` 按 `quality_score`、年龄和容量把低质/过旧链路归档到 `.pi/memory/playbooks/archive/`。
  - `/re-mission show|new|gate ...`：维护 mission blackboard、lanes、completion gates。
  - `/re-lane show|next|done|block|add|set|plan|run|run-auto ...`：把 lanes 当成可推进队列，完成后自动推进并更新 gates；`plan` 生成当前 lane 的最小命令包，并检索 `.pi/memory/playbooks/*.md` / `case-index.md` 合入相似历史命令，优先复用 `quality_score` 更高的链路；`run` 先生成 `execution_strategy`，按 tool-index 对缺失工具进行 `fallback_commands` 降级或跳过无法替代命令，再只执行没有占位符的具体目标命令，并自动写入 `.pi/evidence/runs/*.md` 与 evidence ledger，同时解析地址/比较函数/路由/签名调用等高信号锚点、输出 `evidence_quality` critic、低分时生成 `self_heal_commands` 并挂回 `[auto:*]` 队列、挂载 follow-up commands、自动推进匹配的下一 lane；`run-auto` 受控连续执行下一 lane 上的 `[auto:*]` 命令，并在每步后解析 `adaptive_decision`，根据 `evidence_quality` / `self_heal_commands` 决定继续当前 lane、切换下一 lane、停止等待 bootstrap 或结束扩展；当同一自修复链路重复低效或 stop 分支触发时输出 `multi_lane_plan`，自动新增或重排 `tool-bootstrap`、`evidence-repair`、`map-refresh` 修复 lane；其中 `tool-bootstrap` 会在 `run-auto` 内输出 `tool_bootstrap_closure`，刷新 tool-index、报告 `missing_after_refresh` / `resumed_lane`，并在工具闭合后恢复原 blocked lane；summary 输出 `adaptive_decisions`，有效链路会沉淀到 `.pi/memory/playbooks/*.md`、field journal 和 evolution log，同时刷新/淘汰 playbook index，防止低质量历史噪声污染后续计划。
    - `plan` 现在带有 `specialist_runtime_planner`：按 route/lane/target 自动下沉专项 runtime command pack，而不是只给通用 grep。覆盖 `browser/XHR/WS` 请求捕获、cookie/storage/auth-diff、CDP-backed browser runtime artifact、request/response/WS/storage 序列化、replay evaluator、route graph、auth matrix、IDOR/BOLA probe、authz state machine、sequence replay、object ownership、state rollback、OpenAPI/GraphQL 发现；`JS signing rebuild` 的 fetch/XMLHttpRequest/WebSocket/crypto.subtle hook、observed normalizer、first-divergence、signed replay harness 与 Node 重建脚手架；`pwn primitive` 的 mitigation/libc 指纹、cyclic crash、GDB 寄存器/栈、cyclic offset analyzer、ROP/libc scaffold、local verifier、ROPgadget/ropper fallback、pwntools skeleton；`exploit reliability/autopwn` 的 exploit-poc-normalizer-scaffold、exploit-replay-matrix-scaffold、exploit-environment-pin-scaffold、exploit-flake-triage-scaffold、exploit-artifact-bundle-scaffold；`PCAP/DFIR` 的 capinfos/tshark conversations、stream ranking、secret timeline、HTTP/DNS/TLS/credential filters、HTTP object extraction、foremost carving、transform-chain extractor；`Firmware/IoT rootfs` 的 firmware-static-fingerprint-scaffold、firmware-extract-rootfs-scaffold、firmware-filesystem-config-secret-scaffold、firmware-service-surface-scaffold、firmware-emulation-scaffold；`agent prompt/tool boundary` 的 agent-prompt-surface-map、agent-tool-boundary-scaffold、agent-memory-poisoning-scaffold、agent-injection-replay-harness、agent-delegation-trace-scaffold；`malware config/IOC` 的 malware-static-triage-scaffold、malware-yara-capa-floss-scaffold、malware-ioc-config-scaffold、malware-behavior-trace-scaffold；`Cloud/K8s identity` 的 cloud-identity-config-map、cloud-runtime-config-scaffold、cloud-metadata-probe-scaffold、cloud-privilege-edge-scaffold；`Identity/AD graph` 的 identity-ad-principal-enum-scaffold、identity-ad-credential-usability-scaffold、identity-ad-graph-scaffold；以及 `Frida/GDB trace` 的 Android runtime map、Java crypto/native compare hooks 和 native GDB breakpoint trace。
    - `run` 现在带有 `tool repair analyzer` 和 `specialist evidence analyzer`：不是只保存 stdout，而是解析专项 runtime 输出并生成 `targeted follow-ups`。它能识别 `tool repair anchors`、`tool repair missing dependency anchors`、`browser/XHR/WS runtime anchors`、`websocket endpoint anchors`、`cookie/storage anchors`、`browser CDP artifact anchors`、`browser runtime artifact paths`、`browser replay evaluator anchors`、`browser route graph anchors`、`browser auth matrix anchors`、`browser IDOR/BOLA probe anchors`、`browser authz state machine anchors`、`browser authz sequence replay anchors`、`browser authz object ownership anchors`、`browser authz state rollback anchors`、`JS signing rebuild anchors`、`crypto.subtle operation anchors`、`JS signing normalized artifact anchors`、`JS first-divergence anchors`、`JS signing replay harness anchors`、`pwn primitive crash/control anchors`、`pwn crash register anchors`、`pwn cyclic offset anchors`、`pwn gadget anchors`、`pwn ROP/libc chain anchors`、`pwn local verifier anchors`、`Exploit PoC inventory anchors`、`PoC replay matrix anchors`、`Exploit environment pin anchors`、`Exploit flake triage anchors`、`Exploit artifact bundle anchors`、`PCAP/DFIR traffic flow anchors`、`PCAP stream ranking anchors`、`PCAP secret timeline anchors`、`PCAP extracted artifact anchors`、`PCAP transform chain anchors`、`Firmware image metadata anchors`、`Firmware extraction/rootfs anchors`、`Firmware config/secret anchors`、`Firmware service/web surface anchors`、`Firmware emulation/runtime anchors`、`Agent prompt surface anchors`、`Agent tool boundary anchors`、`Agent memory poisoning anchors`、`Agent injection replay anchors`、`Agent delegation trace anchors`、`Malware static triage anchors`、`Malware rule/capability anchors`、`Malware IOC/config anchors`、`Malware behavior trace anchors`、`Cloud identity anchors`、`Cloud/K8s runtime config anchors`、`Cloud metadata probe anchors`、`Cloud privilege edge anchors`、`Identity/AD principal anchors`、`Identity/AD credential usability anchors`、`Identity/AD graph edge anchors`、`Frida/GDB trace anchors` 和 `runtime hook return/value anchors captured`，再自动挂载 tool-repair-matrix-scaffold、tool-repair-rerun、heal-tool-repair-matrix、browser auth-diff/capture rerun、browser-cdp-artifact-rerun、browser-replay-eval-rerun、browser-cdp-artifact-review、browser-route-graph-rerun、browser-auth-matrix-rerun、browser-idor-bola-probe-rerun、browser-authz-state-machine-rerun、browser-authz-sequence-replay-rerun、browser-authz-object-ownership-rerun、browser-authz-state-rollback-rerun、browser-authz-state-report-scaffold、JS observed rebuild、JS normalizer、JS first-divergence、JS replay harness、pwn cyclic/GDB/offset/ROP-libc/local-verifier rerun、exploit poc/replay/env/flake/bundle/report rerun、pcap stream ranking/secret timeline/follow-stream/object review/transform-chain、firmware extract/config/service/emulation/report rerun、agent prompt/tool/memory/injection/delegation/report rerun、malware static/ioc/behavior/report rerun、cloud identity/runtime/metadata/privilege report、identity-ad enum/credential/graph/report、Frida/GDB focused trace 等 follow-up/self-heal 命令。
  - `/re-map [target] [depth]`：被动目标/工作区 mapper，生成 `.pi/evidence/maps/*.md`，把文件 stat、hash、manifest/config、route/auth 关键字、binary candidates、URL baseline 写入 evidence ledger，并自动完成 `passive_map_done` gate；后续 `/re-lane plan` 会读取最新 map artifact，添加 `map-artifact-context`，记录 `map_reuse`，在未传 target 时用 `map_inferred_target` 自动补目标，并为 map 里的二进制候选补 hash 命令。
  - `/re-auto [plan|run] [target] [max-auto-steps]`：受控自动驾驶闭环；`plan` 展示链路，`run` 串联 mission、`re_map`、lane command pack、lane run、bounded `run-auto`、`re_complete audit` 和 field-journal checkpoint；同时根据 route、最新 map、命令包和 tool-index 生成 `bootstrap_plan`，输出 `recommended_tools`、缺失项和 `next_bootstrap_command`，默认不直接安装；随后生成 `execution_strategy`，在工具缺失时优先写出 `fallback_commands` 并降级执行，无法替代的命令才跳过；如果命令包带有 `case_memory_migrations`，会先输出并应用 `case_memory_lane_plan` 来自动 reprioritize/add/skip lanes。
  - `/re-evidence show|search|append ...`：维护 runtime-first evidence ledger。
  - `/re-graph build|show`：把 mission lanes/gates、passive map、lane run artifacts、evidence ledger 和 tool-index 汇总成 `.pi/evidence/graphs/*.md` attack_graph，输出 `critical_path`、`gaps` 和 `operator_next_actions`，用于组织后续逆向/渗透工程。
  - `/re-campaign plan|show [target]`：把 attack graph 扩展为跨域 `campaign_graph` / `campaign_artifact`。
  - `/re-operation plan|next|run [target] [max-steps]`：把 campaign phases 转为 `operation_queue` / `operation_artifact`，并受控派发内部执行步骤。
  - `/re-delegate plan|show|merge [target]`：把 operation steps 拆成 specialist `worker_packets` / `delegation_artifact`，并读取最新 `worker_scoreboard` 生成 `adaptive_routing_hints`、`worker_promotion_queue` 与 `case_memory_migrations`。
  - `/re-swarm plan|show|run|merge [target] [max-workers] [max-commands]`：把 delegation worker_packets 转成 `swarm_plan` / `swarm_artifact`、`worker_runtime_packets`，run 模式 bounded 执行 worker commands 并输出 `worker_executions`、`worker_results`、`blocked`、`merge_digest`；merge 模式保留最近 run 的 runtime digest，再维护 `parallel_groups`、`merge_protocol`、`collision_matrix`、`commander_next_actions`，并闭合 `swarm_plan_ready`。
  - `/re-supervisor review|show|repair [target]`：评审 worker_packets 与最新 `swarm_artifact`，输出 `supervisor_review`、`swarm_artifact`、`repair_queue`、`commander_merge_queue`、`commander_merge_budget`、`worker_scoreboard`、`priority_queue`。
  - `/re-reflect plan|show|write [target]`：把 supervisor 批判沉淀为 `reflection_cycle`、`reflection_artifact`、field journal、evolution log 与 playbook。
  - `/re-context pack|show|resume [target]`：把 mission/evidence/memory/repair 队列（含 `commander_merge_queue`、`commander_merge_budget`、`worker_scoreboard`）固化成 `context_pack` / `context_artifact`。
  - `/re-operator plan|show|dispatch|verify|escalate [target] [max-steps]`：把 context 的 `next_operator_commands` 转成 bounded `operator_queue` / `operator_artifact`。
  - `/re-verifier check|show|matrix [target]`：把 operator 执行结果转成 `verifier_matrix` / `verifier_artifact`，绑定 assertions、反证与 gaps。
  - `/re-compiler draft|show|final [target]`：把 verifier 的 `proved/weak/contradicted/missing` 编译成 `compiler_report` / `compiler_artifact`、key evidence block、复现命令、矛盾/缺口和 next operator queue，并闭合 `compiler_ready`。
  - `/re-replayer plan|show|run [target] [max-steps]`：消费 compiler 的 `repro_commands`，生成/执行 bounded `replay_matrix`，记录 exit、stdout/stderr SHA256、blocked commands 和 `replay_artifact`，并在 run 后闭合 `replay_ready`。
  - `/re-autofix plan|show|apply [target]`：消费 replay failed/blocked rows 和 compiler gaps，生成 `autofix_plan` / `autofix_artifact`、`patch_queue`、`command_substitutions`、`bootstrap_queue`、`evidence_recapture_queue` 与 `next_operator_queue`，并闭合 `autofix_ready`。
  - `/re-proof-loop plan|show|run [target] [max-steps] [replay-steps]`：执行 verifier→compiler→replayer→autofix bounded proof loop，并在 partial/needs_repair 时输出/执行 `specialist_queue`、`swarm_bridge`、`bridge_artifacts`，把 gap 接入 `re_delegate plan` → `re_swarm run` → `re_swarm merge` → `re_supervisor repair`，再由 `commander_merge_queue` 回流 `re_context pack` / `re_operator dispatch` / `re_proof_loop run`，并闭合 `proof_loop_ready`。
  - `/re-knowledge-graph build|show|query [term]`：把 map/browser/web-authz/mobile-runtime/native-runtime/run/graph/campaign/operator/verifier/compiler/replayer/autofix/proof-loop artifacts 汇总为 `knowledge_graph` / `knowledge_artifact`，输出 `case_signatures`、`similarity_index`、`worker_routing_hints`、`worker_scoreboard`、`adaptive_routing_hints`、`worker_promotion_queue`、`compact_resume_case_memory`、`compact_resume_routing_hints`、`command_strategy_hints`，并闭合 `knowledge_graph_ready`。
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
  - `re_memory`：模型可读写的长期记忆工具。
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
  - `re_swarm`：模型可把 worker_packets 组织为多专家并行运行包，执行 bounded worker commands，产出 worker_executions/worker_results/blocked/merge_digest，merge 时保留 runtime digest，并维护 merge protocol、collision matrix 和 commander next actions。
  - `re_supervisor`：模型可评审 worker/swarm 证据、冲突与修复队列，并输出 commander_merge_queue、commander_merge_budget、worker_scoreboard。
  - `re_reflect`：模型可把 supervisor 结果写入 reflection memory/playbooks。
  - `re_context`：模型可把 context_pack 写入/读出，用于 compaction、handoff 和 resume。
  - `re_operator`：模型可调度 context next_operator_commands，执行 plan/dispatch/verify/escalate，并通过 commander_runtime_policy/commander_dispatch_report 控制重试和失败预算。
  - `re_verifier`：模型可独立验证 operator 执行结果，生成 assertions/counter_evidence/contradictions/gaps。
  - `re_compiler`：模型可把 verifier matrix 编译为 final report scaffold、`key_evidence_block`、`repro_commands`、`contradictions`、`gaps` 和 `next_operator_queue`。
  - `re_replayer`：模型可把 compiler repro_commands 转成可执行 replay_matrix，沉淀 stdout/stderr hash、失败/阻塞行与 replay_ready gate。
  - `re_autofix`：模型可把 replay failed/blocked rows 和 compiler gaps 转成 patch_queue、command_substitutions、bootstrap_queue、evidence_recapture_queue 与 next_operator_queue。
  - `re_knowledge_graph`：模型可跨 artifacts 构建/查询长期知识图谱，输出 case signatures、相似案例索引、worker 路由与命令策略。
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

# 可选：安装为全局 Pi profile（会备份已有 SYSTEM/APPEND_SYSTEM/settings）
scripts/reverse-agent/install-global-profile.sh /root/pi-diy/pi

# 从源码启动 Pi（交互模式）
./pi-test.sh

# 在 Pi 内可用
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
- `.pi/vendor/reverse-skill/skills`
- `.pi/vendor/reverse-skill/CTF-Sandbox-Orchestrator`

因此这个 profile 既内置了 Pi-RECON 总控层，也能在同一 workspace 中直接复用 `zhaoxuya520/reverse-skill` 的细分技能库；不存在时不会报错。


## Web Authz State 授权状态机层

`/re-web-authz-state plan|show|run` / `re_web_authz_state` 面向 Web/API authorization、IDOR、BOLA、JWT/session、object ownership 和 state-machine 任务建立专用授权状态捕获层。它输出 `web_authz_state` / `web_authz_artifact`、`route_inventory`、`principal_matrix`、`object_probes`、`state_machine`、`sequence_replay`、`ownership_checks`、`rollback_checks`、`runtime_anchors`、`replay_commands`、`capture_script`、`web_authz_next_actions` 与 `next_web_authz_command`；artifact 写入 `evidence/web-authz/*.md` 并闭合 `web_authz_ready`。默认读取型 principal/object/sequence 观测；变更型 rollback 只有设置 `PI_RECON_AUTHZ_MUTATE=1` 和 restore fixtures 时才执行。

## Live browser/XHR/WS runtime 层

`/re-live-browser plan|show|run` / `re_live_browser` 面向 HTTP(S) 目标生成或执行浏览器运行时捕获。它输出 `live_browser` / `browser_artifact`、`runtime_matrix`、`request_response_log`、`runtime_anchors`、`auth_matrix`、`idor_bola_probe_templates`、`websocket_probes`、`replay_commands`、`capture_script`、`browser_next_actions` 与 `next_browser_command`；artifact 写入 `.pi/evidence/browser/*.md` 并闭合 `live_browser_ready`。`run` 模式优先使用 Playwright，缺失时自动降级到 Node fetch baseline。

## Exploit Lab 稳定化层

`/re-exploit-lab plan|show|run|bundle` / `re_exploit_lab` 面向 exploit/PoC/autopwn 任务建立稳定化实验室。它输出 `exploit_lab` / `exploit_lab_artifact`、`lab_matrix`、`poc_inventory`、`environment_pins`、`replay_matrix`、`flake_triage`、`bundle_manifest`、`stability_anchors`、`lab_commands`、`lab_next_actions` 与 `next_lab_command`；artifact 写入 `.pi/evidence/exploit-lab/*.md` 并闭合 `exploit_lab_ready`。`run` 模式用本地 Python harness 或 `PI_RECON_EXPLOIT_CMD` 做 bounded 多次 replay，记录 exit、duration、stdout/stderr SHA256、success_rate、stable/flake 结论和 bundle manifest。



## Mobile Runtime 动态逆向层

`/re-mobile-runtime plan|show|run` / `re_mobile_runtime` 面向 APK/Android/mobile reverse 任务建立 ADB/Frida/GDB 运行时捕获层。它输出 `mobile_runtime` / `mobile_runtime_artifact`、`device_matrix`、`apk_inventory`、`process_map`、`hook_plan`、`frida_hooks`、`native_trace`、`anti_debug_checks`、`runtime_anchors`、`replay_commands`、`capture_script`、`mobile_next_actions` 与 `next_mobile_command`；artifact 写入 `evidence/mobile-runtime/*.md` 并闭合 `mobile_runtime_ready`。`run` 默认只做观测和 hook 模板生成；需要真实 attach 时显式设置 `PI_RECON_MOBILE_ATTACH=1`，并记录 Java crypto/String/native compare/anti-debug anchors。


## Native Runtime / Pwn Harness 动态层

`/re-native-runtime plan|show|run` / `re_native_runtime` 面向 ELF/SO/Pwn/native reverse 任务建立 GDB/Pwn 工程运行时捕获层。它输出 `native_runtime` / `native_runtime_artifact`、`binary_inventory`、`mitigation_matrix`、`loader_libc`、`symbol_map`、`crash_plan`、`gdb_trace`、`breakpoint_plan`、`exploit_scaffold`、`runtime_anchors`、`replay_commands`、`capture_script`、`native_next_actions` 与 `next_native_command`；artifact 写入 `evidence/native-runtime/*.md` 并闭合 `native_runtime_ready`。`run` 默认只做观测和 GDB/pwntools 模板生成；需要真实 GDB 执行时显式设置 `PI_RECON_NATIVE_RUN=1` 和可选 `PI_RECON_NATIVE_ARGS`，并记录 crash/register/libc/loader anchors。

## Campaign graph

`/re-campaign plan [target]` / `re_campaign plan` 是高于 attack graph 的跨域红队 campaign planner：读取 mission、passive map、attack graph、lane run artifacts、evidence ledger 和 tool-index gaps，输出 `campaign_graph`、`campaign_artifact`、`phases`、`pivot_candidates`、`evidence_gaps`、`tool_gaps`、`operator_next_actions`、`next_bootstrap_command`。artifact 写入 `.pi/evidence/campaigns/*.md`，并更新 `campaign_plan_ready` gate。

## Operation queue

`/re-operation plan|next|run [target] [max-steps]` / `re_operation` 是高于 campaign graph 的执行队列层：读取 `campaign_artifact`，生成 `operation_queue` 和 `operation_artifact`，列出 `phase_runner`、`steps`、`executed_steps`、`blocked`、`operator_next_actions`、`next_operation_command`，artifact 写入 `.pi/evidence/operations/*.md`，并更新 `operation_queue_ready` gate。

## Specialist delegation

`/re-delegate plan|show|merge [target]` / `re_delegate` 是 operation queue 之上的多专家编排层：读取 `operation_artifact`，生成 `delegation_plan` 和 `delegation_artifact`，按 worker 输出 `worker_packets`、`merge_queue`、`specialist_coverage`、`evidence_contract`、`handoff`、`operator_next_actions`、`next_delegate_command`，artifact 写入 `.pi/evidence/delegations/*.md`，并更新 `delegation_packets_ready` gate。

## Swarm multi-agent orchestration

`/re-swarm plan|show|run|merge [target] [max-workers] [max-commands]` / `re_swarm` 是 specialist delegation 之上的多专家运行组织层：读取 `delegation_artifact`，生成 `swarm_plan` 与 `swarm_artifact`，输出 `worker_runtime_packets`、run-mode `worker_executions`、`worker_results`、`blocked`、`merge_digest`、`parallel_groups`、`merge_protocol`、`collision_matrix`、`evidence_contract`、`commander_next_actions`、`handoff_digest`、`next_swarm_command`，artifact 写入 `.pi/evidence/swarms/*.md`，`run` 模式写入 `memory/swarm-run-board.md`，`merge` 模式优先读取最近 run artifact 并保留 runtime `workerResults` / `blocked` / `mergeDigest` 到 `memory/swarm-board.md`，并更新 `swarm_plan_ready` gate。

## Supervisor critic

`/re-supervisor review|show|repair [target]` / `re_supervisor` 是 specialist delegation 之上的评审层：读取 `delegation_artifact` 与最新 `swarm_artifact`，生成 `supervisor_review` 与 `supervisor_artifact`，按 worker/swarm 输出 `supervisor_verdict`、`swarm_artifact`、`worker_reviews`、`conflict_matrix`、`repair_queue`、`commander_merge_queue`、`commander_merge_budget`、`worker_scoreboard`、`priority_queue`、`gates`、`operator_next_actions`、`next_supervisor_command`；`commander_merge_queue` 把 swarm `worker_results` / `blocked` / `merge_digest` 回流到 `re_swarm merge`、`re_context pack`、`re_operator dispatch` 与 `re_proof_loop run`，并写出 `commander_merge_budget` / `worker_scoreboard` / `commander_runtime_policy`，artifact 写入 `.pi/evidence/supervisor/*.md`，并更新 `supervisor_review_ready` gate。

## Reflection/evolution 闭环

`/re-reflect plan|show|write` / `re_reflect` 消费 `supervisor_review` / `supervisor_artifact`，输出 `reflection_cycle` 与 `reflection_artifact`。`write` 模式将 lessons、failure_patterns、reuse_rules、repair_playbook 写入 field journal、evolution log 和 `.pi/memory/playbooks/*.md`，并闭合 `reflection_memory_ready`。

## Context/resume pack 闭环

`/re-context pack|show|resume` / `re_context` 消费 mission blackboard、evidence ledger、artifact_index、supervisor/reflect 结果、tool digest 与 memory tail，输出 `context_pack` 与 `context_artifact`。它把 `resume_brief`、`repair_queue`（含 supervisor 的 `commander_merge_queue`）、`commander_merge_budget`、`worker_scoreboard`、`reflection_reuse_rules`、`next_operator_commands` 和 `next_context_command` 固化到 `.pi/evidence/contexts/*.md`，并闭合 `context_pack_ready`，用于压缩、重启、handoff 后恢复连续逆向渗透作战。

## Operator queue 调度闭环

`/re-operator plan|show|dispatch|verify|escalate` / `re_operator` 消费 `context_pack` / `context_artifact` 中的 `next_operator_commands`，输出 `operator_queue` 与 `operator_artifact`。它按 `dispatcher_policy` 对 bootstrap/tool-index、map/plan、runtime/graph、campaign/operation/delegate/swarm、supervisor/reflect、context/memory、verifier/compiler、replayer/autofix、proof-loop、knowledge-graph、completion 分层排序，支持 bounded `dispatch`、`verification_matrix`、`escalation_queue`、`next_operator_command`，并闭合 `operator_queue_ready`。

## Verifier matrix 反证闭环

`/re-verifier check|show|matrix` / `re_verifier` 消费 `operator_queue` / `operator_artifact` 的 dispatch 结果，输出 `verifier_matrix` 与 `verifier_artifact`。它把每个执行结果转成 `assertions`、`evidence_bindings`、`counter_evidence`、`contradictions`、`gaps`、`operator_next_actions` 和 `next_verifier_command`，并闭合 `verifier_matrix_ready`，用于最终报告前的独立证据断言和反证检查。

## Compiler report 编译闭环

`/re-compiler draft|show|final` / `re_compiler` 消费最新 `verifier_matrix` / `verifier_artifact`，把 `proved`、`weak`、`contradicted`、`missing` 断言汇总为 `compiler_report` 与 `compiler_artifact`。输出包含 `key_evidence_block`、`repro_commands`、`contradictions`、`gaps`、`next_operator_queue`、`final_report_scaffold` 和 `next_compiler_command`；`final` 模式同时写入报告文件，并闭合 `compiler_ready` 与 `report_or_writeup_ready`。

## Replayer matrix 复现闭环

`/re-replayer plan|show|run` / `re_replayer` 消费最新 `compiler_report` / `compiler_artifact` 中的 `repro_commands`，把可直接执行的命令转成 bounded `replay_matrix`。`run` 模式逐条记录 `exit`、`stdout_sha256`、`stderr_sha256`、blocked/failed rows、`next_replay_actions` 与 `replay_artifact`，并闭合 `replay_ready`，用于证明报告里的复现命令仍可运行。

## Autofix repair 自动修复闭环

`/re-autofix plan|show|apply` / `re_autofix` 消费最新 `replay_matrix` / `replay_artifact` 的 failed/blocked rows，并合并 `compiler_report` 的 gaps/contradictions，生成 `autofix_plan` 与 `autofix_artifact`。输出包含 `patch_queue`、`command_substitutions`、`bootstrap_queue`、`evidence_recapture_queue`、`next_operator_queue` 和 `next_autofix_command`；`apply` 模式把修复队列写入 memory，并闭合 `autofix_ready`，之后应回到 `re_replayer run` 验证修复。

## Execution kernel 底层执行内核

`/re-kernel build|show|audit` / `re_kernel` 在任务启动或 profile/runtime 修改后生成 `execution_kernel` 与 `kernel_artifact`，输出 `directive_stack`、`refusal_to_execution_rules`、`domain_capabilities`、`tool_call_policy`、`artifact_contract`、`stall_recovery`、`operator_next_actions` 和 `next_kernel_command`。artifact 写入 evidence kernel 目录，同时写入 `memory/execution-kernel.md` 并闭合 `execution_kernel_ready`；后续 `re_map`、`re_lane`、`re_operator` 和 completion gates 按该底层执行内核推进。

## Proof loop 证明-复现-修复闭环

`/re-proof-loop plan|show|run` / `re_proof_loop` 把 `re_verifier matrix`、`re_compiler draft|final`、`re_replayer run`、`re_autofix plan|apply`、`re_knowledge_graph build` 和 `re_complete audit` 串成 bounded proof loop。输出 `proof_loop` / `proof_loop_artifact`、`verdict`、`gate_status`、`evidence_summary`、`specialist_queue`、`swarm_bridge`、`bridge_artifacts`、`steps`、`executed_steps`、`next_proof_actions` 与 `next_proof_command`；当 verdict 为 `partial`/`needs_repair` 时把 verifier/compiler/replayer/autofix/gate gap 分类为 web-authz、mobile-runtime、native-runtime、pwn-exploit、firmware-dfir、cloud、identity、agentsec、malware、reporting 或 general 专项 worker，并生成/执行 `re_delegate plan` → `re_swarm run` → `re_supervisor repair` 桥接；artifact 写入 `.pi/evidence/proof-loops/*.md` 并闭合 `proof_loop_ready`。在 `re_decision_core run` 或 `re_operator dispatch` 后优先用 `re_proof_loop run <target> 4 2` 关闭 verifier→compiler→replayer→autofix 证据链。

## Knowledge graph 长期知识图谱闭环

`/re-knowledge-graph build|show|query` / `re_knowledge_graph` 汇总 `.pi/evidence/*` 下的 map、browser、run、attack_graph、campaign、operation、delegation、supervisor、reflection、context、operator、verifier、compiler、replayer、autofix artifacts，生成 `knowledge_graph` 与 `knowledge_artifact`。输出包含 `case_signatures`、`artifact_nodes`、`high_value_edges`、`similarity_index`、`worker_routing_hints`、`worker_scoreboard`、`adaptive_routing_hints`、`worker_promotion_queue`、`compact_resume_telemetry`、`compact_resume_case_memory`、`compact_resume_routing_hints`、`command_strategy_hints` 和 `next_knowledge_command`，同时写入 `memory/knowledge-graph-index.md` 并闭合 `knowledge_graph_ready`，用于跨任务迁移和相似案例检索。


## Decision Core 决策内核层

`/re-decision plan|show|tick|run` / `re_decision_core` 读取 mission gates、active lane、tool posture、artifact posture、evidence priority、execution kernel 与 context/operator/verifier/compiler/replayer/autofix/proof-loop/knowledge artifacts，输出 `decision_core` / `decision_artifact`、`objective_stack`、`gate_pressure`、`evidence_priority`、`tool_posture`、`artifact_posture`、`decision_rules`、`operator_queue`、`decision_next_actions`、`operator_next_command` 与 `next_decision_command`；artifact 写入 `.pi/evidence/decisions/*.md`，同时写入 `memory/decision-core.md` 并闭合 `decision_core_ready`。当下一步不清、上下文恢复、关键 artifact 更新或出现 narrative-only 倾向时，先 `re_decision_core tick <target>` 生成队列，再 `re_decision_core run <target> 1` bounded dispatch，最后进入 `re_proof_loop run <target> 4 2`。

## Pi-RECON native-deep execution kernel update

- `execution_invariants` / `operator_command_floor` / `specialist_capability_matrix` / `proof_exit_criteria` 是 `re_kernel build` 的底层执行约束：任何安全/逆向/渗透任务必须落到 route→map→lane plan/run→runtime artifact→verifier/replayer/proof-loop，而不是 narrative-only。
- `native deep reverse/pwn` 专项会在 Native/Pwn/Mobile/CTF lanes 注入 `native-deep-symbol-map-scaffold`、`native-deep-decompiler-project-scaffold`、`native-deep-compare-trace-scaffold`、`native-deep-patch-hypothesis-scaffold`、`native-deep-symbolic-fuzz-scaffold`。
- `analyzeNativeDeepEvidence` 解析 `Native deep symbol/import/string anchors`、`Native decompiler/control-flow anchors`、`Native compare trace anchors`、`Native patch hypothesis anchors`、`Native symbolic/CFG anchors`、`Native fuzz/crash anchors`，并生成 `native-deep-symbol-map-rerun`、`native-deep-decompiler-rerun`、`native-deep-compare-trace-rerun`、`native-deep-symbolic-fuzz-rerun`、`native-deep-patch-report-scaffold`。
- native patch 必须先绑定 compare/branch runtime trace，再用 replay/verifier 证明输入约束或字节补丁；禁止无 artifact 的口头 patch 结论。


## Pi-RECON web-api authz deep update
- operation dispatcher now routes `re_live_browser`, `re_web_authz_state`, verifier, compiler, replayer, autofix, proof-loop, and knowledge graph commands from `operation_queue`.
- Web/API planner adds `web-api-authz-static-scaffold`, `web-api-schema-diff-scaffold`, and `web-api-state-source-scaffold` for route/source/schema authorization evidence.
- Analyzer parses `web API static authz source anchors`, `web API schema/auth parameter anchors`, and `web API state mutation source anchors`, then emits `web-api-authz-static-rerun`, `web-api-schema-diff-rerun`, and `web-api-state-source-rerun`.

## Pi-RECON swarm execution audit update
- `re_swarm plan|run|merge` now outputs `execution_audit`, `coverage_matrix`, and `retry_queue` for worker-runtime proof, contract coverage, and bounded repair.
- `re_supervisor review|repair` consumes these rows so worker promotion depends on executed commands, hashes/artifacts/anchors, and covered evidence contracts.

## Pi-RECON swarm retry operator bridge update
- Swarm `retry_queue` rows are promoted into `context_pack` as `swarm_retry_queue`, parsed into `next_operator_commands`, and surfaced in `commander_runtime_policy`.
- `re_proof_loop` now exposes `swarm_retry_queue` and can execute `swarm-retry` bridge steps before broader specialist repair.

## Pi-RECON operator feedback loop update

- `operator_feedback` is now a first-class verifier→compiler→replayer→autofix field, not a note: operator dispatch results are classified into `unresolved_target`, `dispatcher_gap`, `missing_tool_or_dependency`, `worker_retry_blocked`, `worker_retry_progress`, `runtime_failure`, `replay_or_exploit_candidate`, `strong_evidence`, `failure_budget_exhausted`, and `swarm_retry_queue`.
- `classifyOperatorFeedback` and `operatorFeedbackNextCommands` turn dispatch output into next commands: missing tools go to `re_bootstrap plan`, worker gaps go to bounded `re_swarm run`, runtime failures go to `re_autofix plan`, replay/exploit candidates go to `re_replayer run` or `re_exploit_lab run`, and strong evidence goes back to `re_verifier matrix`.
- `re_verifier`, `re_compiler`, `re_replayer`, and `re_autofix` must preserve `operator_feedback` so proof-loop repairs are driven by execution evidence rather than narrative-only judgment.

## Pi-RECON operator feedback proof/chain bridge update

- `latestOperatorFeedback` now collects `operator_feedback` from verifier/compiler/replayer/autofix artifacts and promotes executable `operator_feedback_queue` commands into the proof and chain layers.
- `re_proof_loop` exposes `operator_feedback` and `operator_feedback_queue`, appends bounded `operator-feedback` steps, treats unresolved target/missing tool/runtime failure/failure budget feedback as `needs_repair`, and runs feedback commands before broader swarm/specialist repair.
- `re_exploit_chain plan|compose` carries `operator_feedback` into `evidence_gaps`, `replay_commands`, `operator_queue`, and `proof_path` so exploitability claims inherit dispatcher failure signals instead of bypassing them.

## Pi-RECON operator feedback dispatcher fallback update

- `re_operator plan|dispatch` now imports `latestOperatorFeedback` directly into `operator_feedback`, `operator_feedback_queue`, and `dispatcher_fallback_plan` before context commands are sorted.
- `operatorFeedbackDispatchPlan` assigns dispatcher feedback priority: missing tools, unresolved targets, runtime/dispatcher failures, failure-budget exhaustion, swarm retry, replay/exploit candidates, and strong evidence each get bounded primary/fallback commands.
- Dispatch runtime results are reclassified immediately after bounded execution; `operator_feedback_runtime` updates `nextActions` so bootstrap/tool-index refresh, replay/autofix, swarm repair, proof-loop, and exploit-lab fallbacks can run without waiting for narrative review.

## Pi-RECON dispatcher feedback learning update

- `dispatcher_feedback_scoreboard` scores every operator feedback fallback command as passed, failed, or queued, then writes `memory/dispatcher-feedback-board.md` for cross-turn reuse.
- `dispatcher_learning_hints` turns those scores into `promote_dispatcher`, `demote_dispatcher`, or `retry_dispatcher` actions so successful repair routes are promoted and failed routes are rerouted through autofix/context repair.
- `re_knowledge_graph build` imports the dispatcher feedback board as `dispatcher_feedback_scoreboard` and `dispatcher_routing_hints`, adding dispatcher-feedback nodes and command strategy hints so future operator queues can reuse the best fallback path.

## Pi-RECON dispatcher learning case-memory update

- Dispatcher feedback now feeds `case_memory_migrations`: `Dispatcher routing hints`, `Dispatcher feedback scoreboard`, and `memory/dispatcher-feedback-board.md` are parsed as migration sources with elevated priority.
- `case_memory_lane_plan` treats `promote_dispatcher` as a high-score promotion signal and `demote_dispatcher` / `retry_dispatcher` as repair signals, so autopilot can skip low-value lanes, add `case-memory-repair`, or reprioritize the active lane from dispatcher learning.
- `re_delegate plan` and `re_knowledge_graph build` merge `dispatcherAdaptiveRoutingHints` and `dispatcherPromotionQueue` into worker routing/promotion so dispatcher success/failure affects worker promotion, demotion, and future command strategy.

## Pi-RECON autonomous dispatcher budget update

- `AutonomousExecutionBudget` is now a first-class execution-control artifact across `context_pack`, `re_operator`, `re_delegate`, `re_proof_loop`, and `re_knowledge_graph`: it exposes `maxTurns`, `maxDispatch`, `maxProofLoops`, and `maxWorkerRetries` instead of letting the commander drift across unbounded retries.
- `dispatcherScoreDecayRows`, `repeatedFailureDemotionRows`, and `highScorePromotionRows` convert `dispatcher_score` rows into explicit `score_decay`, repeated-failure demotions, and high-score route promotions.
- `writeDispatcherPromotionPlaybook` writes `memory/dispatcher-promotion-playbook.md`, and the knowledge graph / case-memory migration path imports `Autonomous execution budget`, `Dispatcher score decay`, `Repeated failure demotions`, and `High-score promotions` so later lanes reuse the strongest route and demote weak fallback loops.

## Pi-RECON autonomous budget ledger update

- `memory/autonomous-budget-ledger.md` now persists `autonomous_budget`, `score_decay`, `historical_score_decay`, demotions, promotions, and `nextActions` across turns so dispatcher/worker/lane scoring is not reset by context compaction.
- `latestAutonomousBudgetLedger`, `cumulativeDispatcherScoreDecayRows`, `workerScoreDemotionRows`, `autonomousLaneDemotionRows`, and `applyAutonomousBudgetDemotions` convert repeated dispatcher/worker failure pressure into automatic `autonomous-dispatcher-repair` lane demotion when thresholds are crossed.
- `writeFormalDispatcherPromotionPlaybook` promotes high-score dispatcher/worker routes into `memory/playbooks/*dispatcher-promotion*.md`, then `maintainPlaybooks` indexes them so `case_memory_migrations` can reuse formal playbooks, the autonomous budget ledger, and `memory/dispatcher-promotion-playbook.md` together.

## Pi-RECON owned compaction kernel update

`session_before_compact` 已从“仅保存 checkpoint”升级为 RECON-owned compaction provider：hook 返回 `pi-recon-compaction` summary/details，写入 `pi-recon-compaction-checkpoint`，并把 `.pi/evidence/contexts/*.md` 的 `context_path`、`re_context resume`、`re_operator plan/dispatch`、`re_proof_loop run <target> 4 2`、`autonomous_execution_budget`、dispatcher ledger/playbook、repair queue、swarm retry queue、case memory 和 artifact index 固化为恢复契约。若 extension compaction 存在，Pi 原生 summarizer 不再主导该段摘要内容。`session_compact` 后追加 `pi-recon-compaction-resume-contract` entry，验证 `fromExtension`、`details.kind`、`context_path`、`re_context resume`、`re_operator plan/dispatch` 与 `re_proof_loop run`，并更新 `compaction_resume_contract_ready` gate；verified contract 会追加 `pi-recon-compaction-auto-resume` 并通过 `pi-recon-auto-resume` custom message 触发一次 bounded resume turn。`pi-recon-compaction-resume-telemetry` / `memory/compaction-auto-resume-board.md` tracks each `compact_resume_command` as queued/done/blocked, proof-loop entry, output hash, and gate status; `re_operator` exposes this as `compact_resume_telemetry` and `compact_resume_queue`; `re_proof_loop` imports unresolved rows as `source=compact_resume` gaps and `re_complete audit` blocks completion while commands remain queued/blocked or proof_loop_entered is false. `re_knowledge_graph build` now turns the same telemetry into `compact_resume_case_memory`, `compact_resume_routing_hints`, and `compact_resume_status=*` case signatures so successful/failed compact recovery is reusable instead of a one-off resume event; `re_autopilot plan|run` consumes those sections via `compactResumeCaseMemoryCommands`, producing `compact_resume_repair_from_case_memory` repair lanes for queued/blocked recovery or `compact_resume_success_skip_low_value_lane` skips when compact recovery already survived proof-loop.

## Context compact harness 自检

`scripts/reverse-agent/context-compact-audit.mjs [root] [--json]` 是 context_compact_audit 静态门槛，用于在改动后快速确认源码内核与文件型 profile 都保留上下文恢复链路。它分组检查 `context_pack`、RECON-owned compaction provider、resume contract/auto-resume telemetry、`evidence_summarization`、`budget_continuation`、runtime tests 和 docs contract；失败时列出缺失 marker，避免 context/compact 能力只存在于 Pi 原生默认逻辑或文档描述里。

## Autonomous control plane 静态审计

`scripts/reverse-agent/autonomy-control-plane.mjs [root] [--json] [--write] [--strict]` 是非真实平台、非 provider、非 benchmark 的组织能力静态门槛。它只读取源码、文件型 profile、harness 源码和文档 marker，确认 Pi-RECON 当前具备专业逆向/渗透任务组织控制面，同时把尚未达到完整 autonomous red-team agent 的缺口保留为 `notYetTopAutonomousDefinition` / `hardeningNeeded`，避免把成熟度缺口误判成不可用，也避免把单次运行成功包装成完整自治能力。

常用入口：

```bash
npm run gate:autonomy-control
node scripts/reverse-agent/autonomy-control-plane.mjs . --json
```

详细工程路线见 `docs/reverse-agent/autonomous-control-plane.md`。

## Hard eval control plane 离线评测

`scripts/reverse-agent/hard-eval-control-plane.mjs [root] [--json] [--write] [--strict-claims]` 只读取已有 `.pi/evidence/remote/*` 证据，不访问真实网站、不调用 provider、不重跑 benchmark。它把 latest same-window platform claim 与 agent orchestration runtime 分开打分，生成 role contract、append-only claim ledger、failure ledger、paused repair queue 和 anti-self-delusion gate。若 latest same-window 有 required gap，即使 agent 并行编排为 100 分，也会输出 `hard-eval-control-plane-platform-gaps`，防止把编排成功写成平台 claim 全绿。

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
node scripts/reverse-agent/hard-eval-control-plane.mjs . --json \
  | node scripts/reverse-agent/validate-claim-ledger.mjs --stdin --strict-claims
```

在当前 evidence 下 strict-claims 应失败，因为最新 same-window 仍有小红书/抖音 required gaps；这正是反自嗨边界。

`scripts/reverse-agent/autonomous-contracts.mjs . --strict` 聚合四类控制合同：`ReconParallelPlanV1`、`ResumeContractV2`、`FailureLedgerEventV1/RepairQueueItemV1`、`RoleContractV1/ClaimLedgerEventV1`，并确认 context compact audit 仍全绿。常用入口：

```bash
npm run gate:autonomous-contracts
```

## Harness 自检层

- `re_harness` / `/re-harness quick|full|install|show` 生成 `harness_artifact`，聚合 `install_readiness`、`reverse_capability_guards`、`regression_guards`、注册工具/命令矩阵和 evidence/memory/tool-index 可写性。
- 开发或魔改后执行 `re_harness full`；运行 `scripts/reverse-agent/install-global-profile.sh` 后执行 `/re-harness install`。
- `reverse_capability_guards` 会守住 re_native_runtime、re_web_authz_state、re_mobile_runtime、re_exploit_lab、re_proof_loop、re_autopilot、re_knowledge_graph、compact_resume_case_memory、compact_resume_repair_from_case_memory、compact_resume_success_skip_low_value_lane、operator_command_floor、proof_exit_criteria、specialist_runtime_planner，避免安装/自检优化削弱逆向渗透能力。

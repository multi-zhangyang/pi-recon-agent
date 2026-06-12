# REPI Agent

REPI Agent 是一个独立的逆向 / 渗透工程型 coding agent。它以 `repi` 作为唯一产品入口，把复杂安全研究任务拆成可恢复的上下文、可审计的证据、可执行的工具 adapter、可验证的 proof-exit 和可回放的修复闭环。

REPI 的目标不是替换单个工具，而是把 `r2 / Ghidra / Frida / CDP / pwntools / tshark / binwalk` 等工具、长期记忆、多 agent 分工、provider 调度和 release gates 组织成一套可运行的 harness。

```text
repi  -> REPI reverse/pentest agent
pi    -> 你本机安装的原版 Pi
```

REPI 不接管 `pi` 命令，不写入普通 Pi 的 `~/.pi/agent`，默认使用独立运行时目录：

```text
~/.repi/agent
```

---

## 目录

- [特性概览](#特性概览)
- [快速安装](#快速安装)
- [升级已有安装](#升级已有安装)
- [模型与 provider 配置](#模型与-provider-配置)
- [快速开始](#快速开始)
- [核心命令](#核心命令)
- [专业能力](#专业能力)
- [Runtime Adapter Execution](#runtime-adapter-execution)
- [Memory / Compact / Resume](#memory--compact--resume)
- [Harness 与测试](#harness-与测试)
- [目录结构](#目录结构)
- [故障排查](#故障排查)
- [Capability Gate Index](#capability-gate-index)
- [License](#license)

---

## 特性概览

### 独立产品边界

- `repi` 启动 REPI。
- `pi` 保持为上游 Pi。
- REPI 使用 `~/.repi/agent`，不污染 `~/.pi/agent`。
- REPI 默认关闭上游 Pi 更新提示和遥测类启动噪声。
- 安装脚本只创建 / 更新 `repi` 入口。

### 工程型任务组织

REPI 的默认工作链路：

```text
re_kernel → re_decision_core → re_map → re_lane → re_operation
→ re_delegate → re_swarm → re_supervisor → re_context
→ re_operator → re_verifier → re_compiler → re_replayer
→ re_autofix → re_proof_loop → re_knowledge_graph → re_complete
```

它会把任务状态写入 evidence、memory、context pack、claim ledger、repair queue、runtime adapter artifact，而不是只在对话里给建议。

### 专业逆向 / 渗透能力

REPI 内置专业域：

- Web/API auth、session、IDOR/BOLA、signed replay。
- Web/CDP replay、XHR/WS route extraction、request order proof。
- Frontend JS signing、crypto.subtle、first divergence。
- Native reverse、ELF/Mach-O/PE、imports、strings、xref、runtime trace。
- Pwn：crash、offset、leak、ROP/libc、heap/tcache、format-string、SROP/ret2dlresolve、one_gadget、seccomp/sandbox。
- Android/iOS：APK/IPA、JADX/APKTool、Frida、ObjC/Swift、Keychain/Keystore、cert pinning。
- PCAP/DFIR、memory forensics、firmware/IoT、crypto/stego、cloud/identity、agent security、malware analysis、exploit reliability。

### 可验收 harness

REPI 把能力声明绑定到 gate：

```bash
npm run check
npm run gate:repi-harness
npm run gate:runtime-adapter-execution
npm run gate:professional-runtime-bridges
```

关键 gates 会检查源码、schema、fixture、docs、top harness child gate 和 autonomy control-plane，不允许只靠文档描述通过。

---

## 快速安装

### 1. 获取源码

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm install
```

### 2. 安装独立 `repi`

```bash
npm run install:repi
```

或直接运行脚本：

```bash
scripts/reverse-agent/install-repi.sh "$PWD"
```

### 3. 验证启动

```bash
repi --offline --help
repi --offline --list-models
npm run gate:repi-harness
```

如果你本机也装了原版 Pi，命令边界应该是：

```text
repi  -> REPI reverse/pentest agent
pi    -> 你本机安装的原版 Pi
```

---

## 升级已有安装

在已安装过 REPI 的机器上：

```bash
cd pi-recon-agent
git pull
npm install
npm run install:repi
npm run check
npm run gate:repi-harness
```

如果曾经安装过旧的文件型全局 profile，可以先 dry-run 再清理：

```bash
npm run clean:repi-legacy-profile
npm run clean:repi-legacy-profile:apply
```

---

## 模型与 provider 配置

REPI 支持主流模型接入方式：

- OpenAI-compatible Chat Completions。
- OpenAI Responses-compatible。
- Anthropic-compatible Messages。
- OpenRouter / gateway / local inference server。
- 常规官方 provider 环境变量。

推荐把配置写入：

```text
~/.repi/agent/models.json
```

示例：OpenAI-compatible gateway。

```json
{
  "providers": [
    {
      "name": "openai-compatible",
      "type": "openai-completions",
      "baseURL": "https://gateway.example/v1",
      "apiKeyEnv": "OPENAI_COMPATIBLE_API_KEY",
      "models": [
        {
          "id": "provider/model-id",
          "contextWindow": 262144,
          "supportsThinking": true
        }
      ]
    }
  ]
}
```

启动：

```bash
export OPENAI_COMPATIBLE_API_KEY="..."
repi --provider openai-compatible --model provider/model-id
```

诊断自定义网关：

```bash
repi provider-doctor --base-url https://gateway.example/v1 --model provider/model-id --api auto
npm run gate:provider-endpoint-doctor
npm run gate:provider-runtime-matrix
```

相关能力：Provider Endpoint Doctor、provider-doctor、gate:provider-endpoint-doctor、Provider runtime matrix、gate:provider-runtime-matrix、ProviderRuntimeMatrixV1、OpenAI Responses-compatible、Anthropic-compatible。

---

## 快速开始

### 交互式启动

```bash
repi
```

### 一次性任务

```bash
repi -p "对当前目录做被动 mapping，找二进制入口、网络接口和证据缺口"
```

### 指定模型

```bash
repi --provider openai-compatible --model provider/model-id "分析 ./target 的校验逻辑"
```

### 只读 mapping

```bash
repi --tools read,grep,find,ls -p "只读分析 src/ 的路由、鉴权和入口"
```

---

## 核心命令

| 命令 | 作用 |
| --- | --- |
| `/re-kernel` / `re_kernel` | 建立 execution_kernel、kernel_artifact、execution_kernel_ready。 |
| `/re-decision` / `re_decision_core` | 生成 decision_core、adaptive_decision、executed_steps、decision_core_ready。 |
| `/re-map` / `re_map` | 被动 mapping，生成 map_inferred_target、map-artifact-context。 |
| `/re-lane plan` / `re_lane` | 领域 lane 规划，输出 specialist command pack。 |
| `/re-auto` / `re_autopilot` | 自动 bootstrap、fallback_commands、execution_strategy、self_heal_commands。 |
| `/re-campaign` / `re_campaign` | 生成 campaign_graph、campaign_artifact。 |
| `/re-operation` / `re_operation` | 生成 operation_queue、operation_artifact。 |
| `/re-delegate` / `re_delegate` | 生成 delegation_plan、delegation_artifact、specialist_queue。 |
| `/re-swarm` / `re_swarm` | 生成 swarm_plan、swarm_artifact、worker_results、swarm_bridge、swarm_plan_ready。 |
| `/re-supervisor` / `re_supervisor` | supervisor_review、supervisor_artifact、claim gate、repair queue。 |
| `/re-reflect` / `re_reflect` | reflection_cycle、reflection_artifact、经验沉淀。 |
| `/re-context` / `re_context` | context_pack、context_artifact、context_pack_ready、exact resume。 |
| `/re-operator` / `re_operator` | operator_queue、operator_artifact、operator_queue_ready。 |
| `/re-verifier` / `re_verifier` | verifier_matrix、verifier_artifact、verifier_matrix_ready。 |
| `/re-compiler` / `re_compiler` | compiler_report、compiler_artifact、compiler_ready。 |
| `/re-replayer` / `re_replayer` | replay_matrix、replay_artifact、replay_ready。 |
| `/re-autofix` / `re_autofix` | autofix_plan、autofix_artifact、autofix_ready。 |
| `/re-proof-loop` / `re_proof_loop` | proof_loop_ready、repair / replay / verification loop。 |
| `/re-knowledge-graph` / `re_knowledge_graph` | knowledge_graph、knowledge_artifact、knowledge_graph_ready。 |
| `/re-complete` / `re_complete` | 最终完成审计。 |

辅助命令：

```text
/re-graph build|show
/re-tools refresh
/re-toolchain show
/re-lane-specialist-pack show
/re-domain-proof-exit write <domain>
```

---

## 专业能力

### Toolchain Domain Capability

使用 `re_toolchain_domain` / `/re-toolchain` 查看领域工具链矩阵：

```bash
/re-tools refresh
/re-toolchain show
/re-toolchain show pwn
/re-toolchain show web-api
npm run gate:toolchain-domain-capability
```

输出包含 `ToolchainDomainCapabilityV1`、`runtime:toolchain-doctor`、fallback_available、critical_gap、proof-exit 和 nextRuntimeCommands。

### Domain Proof Exit Closure

`DomainProofExitClosureV1` 用于把专业域结果映射到最终完成条件：

```bash
/re-domain-proof-exit show
/re-domain-proof-exit write pwn
npm run gate:domain-proof-exit-closure
```

常见 proof-exit：principal matrix、object ownership、state rollback、signed replay divergence、offset、leak source、controllable bytes、local verifier、heap/tcache、format-string leak/write、SROP/ret2dlresolve、seccomp/sandbox。

### ReLane Specialist Command Pack

`ReLaneSpecialistCommandPackGateV1` 保证 route → lane seed → command pack → analyzer anchor → self-heal → proof-exit bridge 不退化为泛泛建议：

```bash
/re-lane-specialist-pack show
/re-lane-specialist-pack show web-scan
npm run gate:relane-specialist-command-pack
```

### Pwn Advanced Capability

`PwnAdvancedCapabilityGateV1` 覆盖：heap/tcache、format-string、SROP/ret2dlresolve、one_gadget constraint、seccomp/sandbox。

```bash
npm run gate:pwn-advanced-capability
```

### Professional Runtime Bridges

`ProfessionalRuntimeBridgesGateV1` 提供顶级执行桥：

```bash
re_runtime_bridge show
re_runtime_bridge show tool-bridge-runtime
re_runtime_bridge show exploit-verifier-runtime
re_runtime_bridge show web-cdp-replay
re_runtime_bridge show mobile-frida
npm run gate:professional-runtime-bridges
```

能力关键词：Web/CDP replay、Frida/Mobile、runtime_execution_bridge_matrix、real_toolchain_bridge_contract、exploit_verifier_runtime_contract、web_cdp_replay_contract、mobile_frida_dynamic_bridge_contract。

---

## Runtime Adapter Execution

`RuntimeAdapterExecutionGateV1` 是 REPI 的 runner → parser → artifact ingest 执行层。它把真实工具桥从“命令建议”推进到“可运行 adapter”。

每个 adapter 包含：

- adapter runner：native 工具命令。
- fallback runner：缺工具时的替代命令。
- parser：从 stdout/stderr 解析 proof-exit 信号。
- artifact ingest：写入 evidence-ledger、knowledge-graph、memory-event。
- proof-exit：把工具输出映射到 domain proof-exit。

常用命令：

```bash
re_runtime_adapter show
re_runtime_adapter plan r2-native-xref-adapter ./target
re_runtime_adapter run r2-native-xref-adapter ./target 60000
re_runtime_adapter run web-cdp-network-adapter https://example.test 60000
re_runtime_adapter run frida-mobile-hook-adapter com.example.app 60000
npm run gate:runtime-adapter-execution
```

内置 adapter：

| Adapter | 作用 |
| --- | --- |
| `r2-native-xref-adapter` | r2 native xref / symbol / strings，fallback 到 file/strings/objdump。 |
| `ghidra-headless-summary-adapter` | Ghidra headless summary，fallback 到 readelf/objdump。 |
| `frida-mobile-hook-adapter` | Frida hook output，fallback 到 adb package inspection。 |
| `web-cdp-network-adapter` | CDP/XHR/WS/replay-diff signals，fallback 到 curl capture。 |
| `pwntools-local-verifier-adapter` | pwn crash/primitive/multirun verifier scaffold，fallback 到 checksec/gdb。 |
| `tshark-pcap-flow-adapter` | PCAP conversation / HTTP object / credential timeline，fallback 到 strings。 |
| `binwalk-firmware-extract-adapter` | firmware signature / rootfs extraction / service map，fallback 到 file/strings。 |

Gate 关键词：runtime_adapter_execution_gate、adapter_runner_parser_ingest_contract、adapter runner、parser、artifact ingest。

---

## Memory / Compact / Resume

REPI 自动 compact 阈值默认围绕上下文窗口百分比工作：warningPercent=80，triggerPercent=85，并保留 reserve tokens。达到阈值时生成 context pack，后续通过 exact resume 继续任务。

核心文件：

```text
~/.repi/agent/recon/memory/events.jsonl
~/.repi/agent/recon/memory/case-memory.jsonl
~/.repi/agent/recon/memory/compaction-resume-transitions.jsonl
~/.repi/agent/recon/memory/compaction-resume-ledger-v2-report.json
```

相关能力：

- Memory v3：events.jsonl、case-memory.jsonl、gate:memory-contract。
- Memory v3 distiller：gate:memory-distiller、distillation-report.json、quarantine.json。
- Memory v4 sedimentation：gate:memory-sedimentation、semantic-index.json、injection-packet.json。
- Memory v5：gate:memory-store、store-report.json、transactions/、re_memory verify、re_memory repair-index。
- Memory reuse feedback：gate:memory-feedback、在线学习闭环。
- Memory utility hard-eval：gate:memory-utility、正确召回。
- Memory hybrid retrieval：gate:memory-hybrid、语义轻量召回。
- Memory usefulness eval：gate:memory-usefulness、hit@k、forbiddenHitIds、child-process、re_memory eval。
- MemoryActiveKernelV14：re_memory active、active-kernel-report.json。
- MemoryMaturationRuntimeV15：re_memory mature、maturation-runtime-report.json、retention_decay_scheduler。
- MemoryUxDashboardV16：re_memory status、re_memory why、re_memory promote、status-board.md。
- memory-swarm-writeback：gate:memory-swarm-writeback、re_swarm run。

Compact / resume gates：

- Compact/resume chain hard-eval、gate:compact-resume-chain、跨 session 精确恢复。
- Cross-session resume live、gate:cross-session-resume-live、CrossSessionResumeLiveV1、provider continuation。
- CrossSessionMultiCompactMatrixGateV1、gate:cross-session-multi-compact-matrix、multi-provider、八轮、remote provider、compact_resume_ledger_cycle_terminal_alignment。

---

## Harness 与测试

常用验证：

```bash
npm run check
npx vitest --run packages/coding-agent/test/recon-profile.test.ts
npm run gate:repi-harness
node scripts/reverse-agent/repi-top-harness.mjs . --strict --json
node scripts/reverse-agent/autonomy-control-plane.mjs . --strict --json
```

专业能力 gates：

```bash
npm run gate:toolchain-domain-capability
npm run gate:domain-proof-exit-closure
npm run gate:relane-specialist-command-pack
npm run gate:pwn-advanced-capability
npm run gate:professional-runtime-bridges
npm run gate:runtime-adapter-execution
```

Release / autonomy gates：

```bash
npm run gate:autonomous-hardening-gap-ledger
npm run gate:autonomous-closure-readiness
npm run gate:capability-release-bundle
npm run gate:release-ci-pipeline
npm run gate:release-evidence-index
```

运行时质量 gates：

```bash
npm run gate:provider-runtime-matrix
npm run gate:provider-endpoint-doctor
npm run gate:provider-failure-injection
npm run gate:parallel-provider-worker-matrix
npm run gate:remote-provider-longrun
npm run gate:structured-claim-merge
npm run gate:live-conflict-arbitration-matrix
npm run gate:runtime-ledger-quality
npm run gate:tool-call-trace-ledger
```

---

## 目录结构

```text
.
├── repi                                  # 源码运行入口
├── package.json                          # workspace scripts / gates
├── packages/coding-agent/src/core/
│   └── recon-profile.ts                  # REPI 内置 profile / tools / commands
├── repi-profile/                         # legacy mirror，不默认污染 Pi
├── scripts/reverse-agent/                # harness / gates / installer
├── schemas/reverse-agent/                # gate schemas
├── fixtures/reverse-agent/               # hard-eval fixtures
└── docs/reverse-agent/README.md          # 深度能力文档
```

---

## 故障排查

### `repi` 不是 REPI

```bash
which repi
repi --offline --help
npm run install:repi
```

确认输出包含：

```text
REPI: independent product; built-in reverse/pentest kernel is enabled.
```

### 原版 `pi` 与 REPI 混在一起

```bash
echo "pi   : ${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
echo "repi : ${REPI_CODING_AGENT_DIR:-$HOME/.repi/agent}"
```

REPI 不应要求你删除原版 Pi。

### 模型不可用

```bash
repi --offline --list-models
repi provider-doctor --base-url https://gateway.example/v1 --model provider/model-id --api auto
```

检查：

- `~/.repi/agent/models.json`
- provider name 是否匹配
- apiKeyEnv 是否指向真实环境变量
- baseURL 是否包含正确 `/v1` 路径

### Gate 失败

先跑：

```bash
npm run check
npm run gate:repi-harness
```

再针对失败项跑单独 gate。REPI 的 gate 失败通常表示 schema、fixture、runtime marker、docs 或 child harness 没有闭合。

---

## Capability Gate Index

本节是 release-facing capability contract index。它让 README 同时具备正式说明和可机读 harness anchor。

### Autonomy / Release

- AutonomousHardeningGapLedgerV1 / gate:autonomous-hardening-gap-ledger。
- AutonomousClosureReadinessGateV1 / gate:autonomous-closure-readiness。
- CapabilityClaimReleaseBundleGateV1 / gate:capability-release-bundle。
- ReleaseCiPipelineGateV1 / gate:release-ci-pipeline。
- ReleaseEvidenceIndexGateV1 / gate:release-evidence-index。
- RuntimeLedgerQualityGateV1 / gate:runtime-ledger-quality。

### Provider / Worker / Swarm

- Provider-backed dogfood / gate:provider-backed-dogfood / REPI_PROVIDER_BACKED_DOGFOOD_LIVE。
- Provider failure injection / gate:provider-failure-injection / ProviderFailureInjectionReportV1 / FailureLedgerEventV1 / RepairQueueItemV1。
- Worker Runtime Pool / gate:worker-runtime-pool / timeout/cancel / claim-aware merge。
- Worker child-session runtime / gate:worker-child-session / isolatedHome / provider runtime / workerChildSessionRuntimePath / WorkerChildProcessProbeV1 / WorkerProviderChildProcessProbeV1。
- WorkerLeaseSchedulerV1 / gate:worker-lease-scheduler / runtime:worker-lease-scheduler-live-wiring / workerLeaseSchedulerPath。
- WorkerProviderRepairRollbackUnificationGateV1 / gate:worker-provider-repair-rollback-unification / live repair matrix / multi-attempt / state lineage / long-horizon / RemoteProviderStateChangingRepairMatrixV1 / DeepCompoundProviderRepairCompletionChainV1。
- Parallel provider worker matrix / gate:parallel-provider-worker-matrix / ParallelProviderWorkerMatrixV1 / claim-aware provider worker merge。
- SwarmProviderManifestParityGateV1 / gate:swarm-provider-manifest-parity / multi-provider / retry/repair / ProviderBackedLongWindowSharedMergeLedgerV1 / ProviderWorkerExtendedRetryManifestChainV1 / all_child_sessions_match_parity_rows。
- Remote provider long-run / gate:remote-provider-longrun / RemoteProviderLongRunV1 / REPI_REMOTE_PROVIDER_LIVE。

### Claim / Conflict / Trace

- AgentDogfoodStructuredClaimMergeGateV1 / gate:agent-dogfood-structured-claims。
- AgentDogfoodFailureSignatureBindingGateV1 / gate:agent-dogfood-failure-signature-binding。
- Structured claim merge / gate:structured-claim-merge / final_pass_requires_json_query / unresolved_adversary_challenge_blocks_final / runtime:structured-claim-live-wiring / structured_conflict_arbitration_live_wiring。
- LiveConflictArbitrationMatrixGateV1 / gate:live-conflict-arbitration-matrix / ProviderBackedLongWindowConflictMatrixV1 / ExtendedSynthesizerTopicParseMatrixV1。
- ToolCallTraceLedgerV1 / gate:tool-call-trace-ledger。
- FailureSignaturePriorityGateV1 / gate:failure-signature-priority。
- RepairRollbackPolicyV1 / gate:repair-rollback-policy / runtime:repair-rollback-live-wiring / repairRollbackPolicyPath。

### Reverse / Pwn / Runtime Tools

- Toolchain Domain Capability / ToolchainDomainCapabilityV1 / re_toolchain_domain / gate:toolchain-domain-capability。
- DomainProofExitClosureV1 / re_domain_proof_exit / gate:domain-proof-exit-closure。
- ReLaneSpecialistCommandPackGateV1 / gate:relane-specialist-command-pack / re_lane_specialist_pack / /re-lane-specialist-pack。
- PwnAdvancedCapabilityGateV1 / gate:pwn-advanced-capability / heap/tcache / SROP/ret2dlresolve。
- ProfessionalRuntimeBridgesGateV1 / re_runtime_bridge / gate:professional-runtime-bridges / Web/CDP replay / Frida/Mobile。
- RuntimeAdapterExecutionGateV1 / re_runtime_adapter / gate:runtime-adapter-execution / adapter runner / parser / artifact ingest。

### Memory / Context

- Memory v3 / events.jsonl / case-memory.jsonl / gate:memory-contract。
- Memory v3 distiller / gate:memory-distiller / distillation-report.json / quarantine.json。
- Memory v4 sedimentation / gate:memory-sedimentation / semantic-index.json / injection-packet.json。
- Memory v5 / gate:memory-store / store-report.json / transactions/ / re_memory verify / re_memory repair-index。
- Memory reuse feedback / gate:memory-feedback / 在线学习闭环。
- Memory utility hard-eval / gate:memory-utility / 正确召回。
- Memory hybrid retrieval / gate:memory-hybrid / 语义轻量召回。
- Memory usefulness eval / gate:memory-usefulness / hit@k / forbiddenHitIds / child-process / re_memory eval。
- MemoryActiveKernelV14 / re_memory active / active-kernel-report.json。
- MemoryMaturationRuntimeV15 / re_memory mature / maturation-runtime-report.json / retention_decay_scheduler。
- MemoryUxDashboardV16 / re_memory status / re_memory why / re_memory promote / status-board.md。
- memory-swarm-writeback / gate:memory-swarm-writeback / re_swarm run。
- Compact/resume chain hard-eval / gate:compact-resume-chain / 跨 session 精确恢复。
- Cross-session resume live / gate:cross-session-resume-live / CrossSessionResumeLiveV1 / provider continuation。
- CrossSessionMultiCompactMatrixGateV1 / gate:cross-session-multi-compact-matrix / multi-provider / 八轮 / remote provider / compact_resume_ledger_cycle_terminal_alignment。

### Domain anchors

- Firmware/IoT rootfs / Firmware image metadata anchors。
- agent prompt/tool boundary / Agent prompt surface anchors。
- exploit reliability/autopwn / Exploit PoC inventory anchors。
- malware config/IOC / Malware IOC/config anchors。

---

## License

MIT. See [LICENSE](LICENSE).

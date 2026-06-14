# REPI Agent

REPI Agent 是面向逆向工程、渗透测试、漏洞利用链验证和红队任务组织的 autonomous coding agent。项目基于 Pi Coding Agent 底层深度改造，重构了运行时 profile、工具调度、证据账本、长期记忆、上下文恢复、runtime adapter 和 release harness。

REPI 的设计目标是把复杂逆向/渗透任务推进为可执行、可验证、可恢复的工程流程，而不是只输出建议。它会把 `r2 / Ghidra / Frida / CDP / pwntools / tshark / binwalk` 等工具、多 agent 分工、provider 调度和 release gates 组织成一套可运行的 harness。

默认命令是 `repi`，默认运行时目录是：

```text
~/.repi/agent
```

当前开源版本：

```text
v0.78.1-repi.1
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
- [开源治理](#开源治理)
- [Capability Gate Index](#capability-gate-index)
- [License](#license)

---

## 特性概览

### 运行时边界

- 默认入口：`repi`。
- 默认运行时目录：`~/.repi/agent`。
- 启动时加载内置 reverse/pentest kernel、profile、tools、commands 和 provider 配置。
- 安装脚本只创建 / 更新 REPI 入口，不需要额外的全局 profile。

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

面向普通用户只保留一条主路径：clone 后执行 `bash install.sh`。脚本会自动安装 npm 依赖、写入 `repi` 启动器、初始化 `~/.repi/agent`，并做离线启动检查。

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
bash install.sh
```

如果当前用户没有 `/usr/local/bin` 写权限，安装器会自动落到 `~/.local/bin`。也可以显式指定：

```bash
bash install.sh --user
bash install.sh --bin-dir "$HOME/bin"
```

如果 shell 找不到 `repi`，把安装目录加入 PATH 后重开终端：

```bash
export PATH="$HOME/.local/bin:$PATH"
```

安装后先跑这三个命令：

```bash
repi commands
repi doctor
repi model doctor
```

---

## 升级已有安装

日常更新直接用：

```bash
repi update
```

它会在当前安装源目录执行：

```text
git pull --ff-only --tags → npm install → 刷新 repi 启动器/profile → repi doctor --fix → repi smoke
```

常用变体：

```bash
repi update --fast       # 只更新和重装，跳过 smoke
repi update --full       # update + smoke + npm run check
repi update --no-pull    # 不拉远端，只修复当前 checkout 的安装
```

如果 `repi` 命令本身不可用，进入源码目录执行兜底更新：

```bash
cd pi-recon-agent
bash scripts/reverse-agent/update-repi.sh .
```

如果只是刷新启动器，不拉代码、不装依赖：

```bash
repi install
# 或
npm run install:repi
```

如果曾经安装过旧的文件型全局 profile，可以先 dry-run 再清理：

```bash
npm run clean:repi-legacy-profile
npm run clean:repi-legacy-profile:apply
```

---

## 模型与 provider 配置

REPI 的模型配置文件是：

```text
~/.repi/agent/models.json
```

配置格式与底层模型注册器兼容，核心结构是 **providers 对象**，不是数组。provider 名称就是启动时 `--provider` 使用的名字。

推荐先用 CLI 写入配置，再按需手动编辑 JSON：

```bash
# 1) 注册一个 OpenAI-compatible Chat Completions provider
repi model add \
  --provider openai-compatible \
  --api openai-completions \
  --base-url https://gateway.example/v1 \
  --model provider/model-id \
  --context-window 262144 \
  --max-tokens 16384 \
  --reasoning true \
  --set-default

# 2) 保存 API key 到本机 ~/.repi/agent/auth.json
repi model login --provider openai-compatible --api-key-stdin

# 3) 验证真实调用
repi model test --provider openai-compatible --model provider/model-id
```

`model add` 默认在 `models.json` 里只写 `$REPI_<PROVIDER>_API_KEY` 这种环境变量引用；如果使用 `model login`，真实 key 只写入本机 `auth.json`，不会进入仓库。

REPI 支持主流模型接入方式：

- OpenAI-compatible Chat Completions。
- OpenAI Responses-compatible。
- Anthropic-compatible Messages。
- OpenRouter / gateway / local inference server。
- 常规官方 provider 环境变量。

### 字段说明

| 字段 | 说明 |
| --- | --- |
| `providers.<name>` | provider id，例如 `openai-compatible`、`local-openai`、`anthropic-gateway`。 |
| `name` | UI 展示名，可选。 |
| `baseUrl` | API 地址。OpenAI-compatible 通常带 `/v1`；Anthropic-compatible 按网关要求填写。 |
| `api` | API 协议：`openai-completions`、`openai-responses`、`anthropic-messages`。 |
| `apiKey` | 推荐写 `$ENV_NAME`，运行时从环境变量读取；不要把真实 key 写进文件。 |
| `authHeader` | Anthropic-compatible 网关如果需要 `Authorization: Bearer`，设为 `true`。 |
| `models[].id` | 模型 ID，启动时 `--model` 使用。 |
| `models[].contextWindow` | 上下文窗口 token 数，用于上下文预算、compact 阈值等。 |
| `models[].maxTokens` | 单次最大输出 token。 |
| `models[].reasoning` | 是否支持 thinking/reasoning。 |
| `models[].input` | 输入模态，例如 `["text"]` 或 `["text", "image"]`。 |
| `models[].cost` | 价格配置，单位是 **美元 / 百万 tokens**。 |

`cost` 支持四个字段：

```json
{
  "input": 0.95,
  "output": 4,
  "cacheRead": 0.16,
  "cacheWrite": 0.95
}
```

运行时按如下方式估算成本：

```text
cost = input_tokens * input / 1_000_000
     + output_tokens * output / 1_000_000
     + cache_read_tokens * cacheRead / 1_000_000
     + cache_write_tokens * cacheWrite / 1_000_000
```

如果你的网关不收费、内网统一结算，或者不想显示费用，可以全部填 `0`。

### OpenAI-compatible Chat Completions

适用于大多数 `/v1/chat/completions` 网关、本地推理服务、New API、LiteLLM、vLLM、Ollama/LM Studio 的 OpenAI-compatible 代理等。

```json
{
  "providers": {
    "openai-compatible": {
      "name": "openai-compatible",
      "baseUrl": "https://gateway.example/v1",
      "api": "openai-completions",
      "apiKey": "$OPENAI_COMPATIBLE_API_KEY",
      "models": [
        {
          "id": "provider/model-id",
          "name": "Provider Model",
          "input": ["text", "image"],
          "cost": {
            "input": 0.95,
            "output": 4,
            "cacheRead": 0.16,
            "cacheWrite": 0.95
          },
          "contextWindow": 262144,
          "maxTokens": 16384,
          "reasoning": true
        }
      ]
    }
  }
}
```

启动：

```bash
export OPENAI_COMPATIBLE_API_KEY="..."
repi --provider openai-compatible --model provider/model-id
```

### OpenAI Responses-compatible

适用于 `/v1/responses` 协议的网关或官方兼容服务。

```json
{
  "providers": {
    "responses-gateway": {
      "name": "Responses Gateway",
      "baseUrl": "https://gateway.example/v1",
      "api": "openai-responses",
      "apiKey": "$RESPONSES_GATEWAY_API_KEY",
      "models": [
        {
          "id": "provider/responses-model",
          "input": ["text", "image"],
          "cost": {
            "input": 1,
            "output": 4,
            "cacheRead": 0.1,
            "cacheWrite": 1
          },
          "contextWindow": 262144,
          "maxTokens": 32768,
          "reasoning": true,
          "compat": {
            "supportsDeveloperRole": true,
            "supportsLongCacheRetention": false
          }
        }
      ]
    }
  }
}
```

### Anthropic-compatible Messages

适用于 `/v1/messages` 风格的 Anthropic-compatible 网关。

```json
{
  "providers": {
    "anthropic-gateway": {
      "name": "Anthropic Gateway",
      "baseUrl": "https://gateway.example",
      "api": "anthropic-messages",
      "apiKey": "$ANTHROPIC_GATEWAY_API_KEY",
      "authHeader": true,
      "compat": {
        "supportsEagerToolInputStreaming": false,
        "supportsCacheControlOnTools": false,
        "supportsLongCacheRetention": false
      },
      "models": [
        {
          "id": "provider/claude-compatible-model",
          "input": ["text"],
          "cost": {
            "input": 3,
            "output": 15,
            "cacheRead": 0.3,
            "cacheWrite": 3.75
          },
          "contextWindow": 200000,
          "maxTokens": 8192,
          "reasoning": false
        }
      ]
    }
  }
}
```

### 本地或免费网关

本地服务通常不需要真实计费，可以这样写：

```json
{
  "providers": {
    "local-openai": {
      "name": "Local OpenAI-compatible",
      "baseUrl": "http://127.0.0.1:11434/v1",
      "api": "openai-completions",
      "apiKey": "$LOCAL_LLM_API_KEY",
      "models": [
        {
          "id": "local/model",
          "input": ["text"],
          "cost": {
            "input": 0,
            "output": 0,
            "cacheRead": 0,
            "cacheWrite": 0
          },
          "contextWindow": 32768,
          "maxTokens": 4096,
          "reasoning": false
        }
      ]
    }
  }
}
```

如果本地服务不校验 key，也仍建议给一个占位环境变量，保持配置格式一致：

```bash
export LOCAL_LLM_API_KEY="local"
```

诊断自定义网关：

```bash
repi model add --provider openai-compatible --api openai-completions --base-url https://gateway.example/v1 --model provider/model-id
repi model login --provider openai-compatible --api-key-stdin
repi model default --provider openai-compatible --model provider/model-id
repi model list
repi model list --provider openai-compatible
repi model test --provider openai-compatible --model provider/model-id
repi model doctor
repi model cost --provider openai-compatible --model provider/model-id --input-tokens 100000 --output-tokens 10000
repi model export --output /tmp/repi-models.template.json
repi provider-doctor --base-url https://gateway.example/v1 --model provider/model-id --api auto
npm run gate:provider-endpoint-doctor
npm run gate:provider-runtime-matrix
```

`repi model doctor` 是离线检查：解析 `~/.repi/agent/models.json`、检查 provider/model 元数据、环境变量引用、context window、max tokens 和 cost/cache 字段，不会输出真实 key；provider `baseUrl` 默认也会脱敏，只有本机排障时显式加 `--show-urls` 才显示。

`repi model list/edit/remove/export/import` 用于本机 provider 配置维护；`list` 支持 `--provider <id>` / `--model <id>` 过滤，默认隐藏真实 `baseUrl`；`export` 不导出 `auth.json`，会把 literal key 归一化成 `$REPI_<PROVIDER>_API_KEY` 引用。

`repi model cost` 按 `cost.input/output/cacheRead/cacheWrite` 估算费用，单位是美元 / 百万 tokens。

相关能力：Model Doctor、Provider Endpoint Doctor、provider-doctor、gate:provider-endpoint-doctor、Provider runtime matrix、gate:provider-runtime-matrix、ProviderRuntimeMatrixV1、OpenAI Responses-compatible、Anthropic-compatible。

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

### 主动逆向 / 渗透入口

```bash
repi engage ./target
repi engage https://target.example --full
repi attack https://target.example --swarm --provider openai-compatible --model provider/model-id
```

`engage` 会立即识别目标类型，执行有界工具探测，写入证据 artifact 和下一步队列。

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

先看命令速查：

```bash
repi commands
```

常用 CLI：

| 命令 | 作用 |
| --- | --- |
| `repi` | 进入交互式任务。 |
| `repi -p "task"` | 执行一次性任务。 |
| `repi commands` | 查看安装、模型、记忆、swarm、诊断命令速查。 |
| `repi update` | 拉取最新代码、安装依赖、刷新启动器并跑 doctor/smoke。 |
| `repi update --fast` | 快速更新，跳过 smoke。 |
| `repi update --full` | 更新后追加 `npm run check`。 |
| `repi install` | 只刷新当前 checkout 的启动器和 runtime profile。 |
| `repi doctor --fix` | 修复 runtime profile、入口、memory 文件和常见配置问题。 |
| `repi smoke` | 本地快速可用性检查。 |
| `repi bugreport --output /tmp/repi-bugreport.json` | 导出严格脱敏诊断包。 |
| `repi trust status` | 查看当前目录是否已保存 trust。 |
| `repi trust yes` | 保存当前目录 trust，避免每次启动重复提示。 |
| `repi trust clear` | 清除当前目录 trust 决策。 |
| `repi mission new <task>` | 新建任务级 Mission Control，自动选择 lane、证据合同和下一步命令。 |
| `repi mission status/next/pack/close` | 查看任务状态、取下一步、生成恢复包、关闭任务。 |
| `repi engage <target>` | 主动执行入口：识别目标、跑工具、写证据、生成下一步队列。 |
| `repi attack/reverse/web <target>` | `engage` 的战术别名，适合红队、二进制逆向和 Web/API 任务。 |
| `repi model ...` | 维护 provider/model/auth/cost 配置。 |
| `repi memory ...` | 查看、解释、隔离、导出长期记忆。 |
| `repi mcp status/list/probe` | 查看和探测 MCP server 配置与工具列表。 |
| `repi swarm ...` | 多 worker 分工、运行、合并。 |

会话内 reverse/pentest workflow 命令：

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
| `/context` | 查看当前上下文预算、占用分类和 top consumers。 |
| `/agents` `/spawn` `/agent` `/merge` | 会话内一等子代理线程控制面。 |
| `/mcp` `/mcp list` `/mcp <server>` | 查看或探测 MCP server 和工具列表。 |
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

### Mission Control

`repi mission` 是任务级控制面。它不替代交互式 agent，而是把一次逆向/渗透工作先落成一个可恢复的 mission：目标、领域 lane、证据合同、下一步命令、context pack 都写到 `~/.repi/agent/recon/mission/` 和 `~/.repi/agent/recon/evidence/contexts/`。这样开新任务时不会把旧任务记忆直接混进来，也方便中断后恢复。

```bash
repi mission new "审计 JWT API 的 IDOR/BOLA 风险" --target https://target.example
repi mission status
repi mission next
repi mission pack
```

常见流程：

```bash
# 1) 建 mission，自动路由到 Web/API、Native/Pwn、Mobile、Firmware 等 lane
repi mission new "reverse ./crackme 的校验逻辑" --target ./crackme

# 2) 跑健康检查和 agent 任务
repi health
repi -p "按当前 mission 执行被动 mapping，证明一条最小路径，并给出复现命令"

# 3) 中断或切机器前生成恢复包
repi mission pack

# 4) 任务结束后显式关闭；长期记忆沉淀仍然需要显式执行，避免污染
repi mission close --summary "已定位校验函数和输入约束，复现命令见 evidence ledger"
```

### Active Engagement Engine

`repi engage` 是 REPI 的主动执行入口。它面向“给我一个目标，先动起来”的逆向/渗透场景：自动判断 URL、目录、二进制、APK、PCAP、固件、JS/WASM 等目标类型，立即运行一组有界工具探测，并把结果写成可恢复的 engagement artifact。

输出位置：

```text
~/.repi/agent/recon/evidence/engagements/<run-id>/report.json
~/.repi/agent/recon/evidence/engagements/<run-id>/summary.md
~/.repi/agent/recon/evidence/engagements/<run-id>/commands.jsonl
~/.repi/agent/recon/evidence/engagements/<run-id>/next-commands.sh
```

示例：

```bash
# 本地二进制 / SO / EXE / Mach-O
repi engage ./crackme --full

# Web/API 目标：抓 header、body sample、资产链接，并生成 auth/session/replay 下一步
repi engage https://target.example --full

# 目录目标：枚举 manifest、route/auth/signature/sink 搜索，生成 workspace 攻击面队列
repi engage ./src

# 需要多 worker 时再显式接 swarm
repi engage ./target --swarm --provider openai-compatible --model provider/model-id --workers 5
```

和 `mission` 的关系：

- `engage` 会默认创建/更新当前 mission；
- `mission` 管任务状态和恢复包；
- `engage` 管第一轮真实工具执行和证据落盘；
- `swarm` 负责把后续专项 worker 并行化。

### 多子代理控制面

`repi swarm` 提供 `plan → run → status → merge` 控制面。`run` 会真实拉起多个隔离 worker 进程；每个 worker 使用独立临时 `REPI_CODING_AGENT_DIR`，复制当前模型配置和本机凭据，默认 `--no-session`，并把 stdout/stderr hash、退出码、耗时、结构化 claim merge 和合并摘要写到：

```text
~/.repi/agent/recon/evidence/llm-swarms/<run-id>/report.json
~/.repi/agent/recon/evidence/llm-swarms/<run-id>/merge-report.json
```

规划分工，不调用模型：

```bash
repi swarm plan ./target --workers 5
```

真实并行执行：

```bash
repi swarm run ./target --workers 5 \
  --provider openai-compatible \
  --model provider/model-id \
  --tools bash,read,grep,ls \
  --prompt "重点检查签名逻辑、鉴权状态机和可复现证据。"
```

如果只想验证多 worker 调度和模型输出，不给 worker 工具：

```bash
repi swarm run local-selfcheck --workers 2 \
  --provider openai-compatible \
  --model provider/model-id \
  --no-tools
```

查看和合并：

```bash
repi swarm status latest
repi swarm merge latest
```

自检并发模型调用：

```bash
repi swarm llm-run local-selfcheck --workers 3 \
  --provider openai-compatible \
  --model provider/model-id \
  --prompt "Reply exactly: REPI_SWARM_WORKER_{id}_OK" \
  --expect "REPI_SWARM_WORKER_{id}_OK"
```

交互式会话内也有一等 child agent thread 控制面，适合把噪声探索放进独立上下文，只把摘要和证据引用合并回主线程：

```text
/agents                         # 查看 explorer/planner/operator/verifier/reverser
/spawn explorer ./target         # 启动只读 mapping worker
/spawn reverser 分析 ./license   # 启动逆向专项 worker
/agent latest                    # 查看最新 worker 状态、stdout/stderr/artifact 路径
/merge latest                    # 生成合并摘要，不把 raw logs 灌进主上下文
/agent stop latest               # 停止仍在运行的 worker
```

child agent thread 的运行记录写到：

```text
~/.repi/agent/recon/agent-threads/<run-id>/manifest.json
~/.repi/agent/recon/agent-threads/<run-id>/stdout.txt
~/.repi/agent/recon/agent-threads/<run-id>/stderr.txt
~/.repi/agent/recon/agent-threads/<run-id>/merge.md
```

---

## MCP Server 接入

REPI 支持读取 MCP server 配置、探测 stdio server，并把明确 opt-in 的 MCP tools 接入 agent tool registry。启动时只注册轻量 proxy tool，不主动拉起外部 server；执行 `/mcp list`、`/mcp <server>` 或 `repi mcp probe` 时才按 `tools/list` 探测并刷新具体 tool definition，坏掉的 MCP server 不会拖死启动。

配置文件：

```text
~/.repi/agent/mcp.json
<cwd>/.repi/mcp.json
```

示例：

```json
{
  "mcpServers": {
    "demo": {
      "transport": "stdio",
      "command": "node",
      "args": ["/absolute/path/to/mcp-server.js"],
      "env": {
        "DEMO_API_KEY": "$DEMO_API_KEY"
      },
      "autoRegisterTools": true,
      "allowedTools": ["search", "fetch"]
    }
  }
}
```

常用命令：

```bash
repi mcp status
repi mcp list
repi mcp probe demo
```

会话内：

```text
/mcp
/mcp list
/mcp demo
```

`autoRegisterTools: true` 后，REPI 会暴露两类运行时工具：

- `mcp__demo__call`：轻量 proxy，参数是 `{ "tool": "search", "arguments": { ... } }`。
- `mcp__demo__search` / `mcp__demo__fetch`：执行 `/mcp list` 或 `/mcp demo` 探测成功后，按 MCP `inputSchema` 生成的直连工具。

`allowedTools` / `blockedTools` 会同时作用于探测、直连工具和 proxy 调用。stdout/stderr 与返回文本会做默认脱敏；超过阈值的大文本不会整段塞回上下文，而是写入：

```text
~/.repi/agent/recon/mcp-artifacts/<server>/<timestamp>-<tool>-<sha>.txt
```

模型侧只收到 preview、artifact path、sha256 和 bytes，方便后续用 `read`/`bash` 精确取证。

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
| `frida-mobile-hook-adapter` | Frida hook output；无设备/无 Frida 时 fallback 到 portable mobile manifest runner，仍产出 hook/method/pinning 解析锚点。 |
| `web-cdp-network-adapter` | CDP/XHR/WS/replay-diff signals，fallback 到 curl capture。 |
| `pwntools-local-verifier-adapter` | pwn crash/primitive/multirun verifier scaffold，fallback 到 checksec/gdb。 |
| `tshark-pcap-flow-adapter` | PCAP conversation / HTTP object / credential timeline，fallback 到 strings。 |
| `binwalk-firmware-extract-adapter` | firmware signature / rootfs extraction / service map，fallback 到 file/strings。 |

Gate 关键词：runtime_adapter_execution_gate、adapter_runner_parser_ingest_contract、adapter runner、parser、artifact ingest。

---

## Memory / Compact / Resume

REPI 自动 compact 阈值默认围绕上下文窗口百分比工作：warningPercent=80，triggerPercent=85，并保留 reserve tokens。达到阈值时生成 context pack，后续通过 exact resume 继续任务。普通流式 provider 无法在模型正在输出 token 时由客户端改写同一次请求上下文；REPI 的本地 auto-compact 会在 assistant turn + tool results 结束后、下一次 LLM 请求前触发，长工具循环会先停在该安全边界 compact/resume 再继续。

### 默认记忆模式：scoped auto memory

REPI 默认启用“作用域自动记忆”：自动沉淀高价值经验；只有当前任务出现明确 URL、文件路径、目录或包名这类 concrete target 时，才召回同 workspace / target / route 的小卡片。没有明确 target 的新任务只显示记忆状态，不自动注入旧任务卡片，也不会把旧日志、旧对话、全量 events 原文塞进上下文。

默认策略：

- `memory.mode=scoped`：长期记忆可用，但必须经过 scope 过滤。
- `memory.autoRecall=true`：有 concrete target 时自动召回少量相关 memory cards；无 concrete target 时延迟召回，需要手动 `re_memory search/active`。
- `memory.autoDeposit=high-value`：只自动沉淀成功复现、关键失败修复、漏洞/逆向锚点、可复用命令等高价值事件；普通 stdout 不入库；`--no-session` 一次性任务默认不写入长期记忆。
- `memory.startupDigest=scoped`：启动包只放摘要卡片，不放原始 history。
- `memory.contextMemoryMode=scoped`：context pack 只带 scoped memory cards，不带全局 memory tail / active injection pack。
- `memory.rawTranscriptRetention=external-only`：原始 events/case-memory 保存在磁盘，默认不进 prompt。

记忆分层：

```text
core-memory.md       固定偏好、长期稳定事实，短小，在 scoped packet 中受预算加载
project-memory.md    当前 workspace 的构建/运行/测试/入口/常用命令
procedural-memory.md 可复用 workflow、checklist、verified command template
events.jsonl         事件级长期记忆，自动 high-value 沉淀
case-memory.jsonl    案例索引/摘要，召回时只转成 bounded cards
```

默认配置：

```json
{
  "memory": {
    "schemaVersion": 2,
    "mode": "scoped",
    "autoRecall": true,
    "autoInject": false,
    "rawAutoInject": false,
    "autoDeposit": "high-value",
    "startupDigest": "scoped",
    "scopePolicy": "mission+workspace+target",
    "contextMemoryMode": "scoped",
    "includeGlobalMemoryInContextPack": false,
    "activeRecall": false,
    "startupBudgetTokens": 800,
    "contextPackBudgetTokens": 1200,
    "maxStartupItems": 5,
    "minRecallScore": 0.35,
    "rawTranscriptRetention": "external-only"
  }
}
```

手动召回/维护：

```bash
repi memory status                  # 查看当前记忆姿态、污染保护、事件数量、文件状态
repi memory list --limit 20         # 列出脱敏 memory events，默认隐藏 forget/quarantine 行和长 lesson
repi memory list --verbose --limit 20 # 排障时显示命令、复用规则、lesson（仍会脱敏）
repi memory show <event-id>         # 查看单条脱敏 memory event
repi memory why <query-or-event-id> # 解释某条记忆为什么会被召回/可见
repi memory forget <event-id>       # 追加 tombstone，不重写历史
repi memory quarantine <event-id>   # 追加 quarantine，阻断后续召回/注入
repi memory doctor                  # 检查污染保护、raw/global 注入开关、JSONL/事件 hash-chain 健康
repi memory export --output /tmp/repi-memory.json  # 导出脱敏诊断包，不导出 auth/raw secret
repi memory purge --dry-run --governed             # 预览物理清理
repi memory purge --apply --yes --governed         # 确认后才会真正写入
repi memory sanitize --dry-run                  # 预览本机 memory secret/url 脱敏
repi memory sanitize --apply --yes              # 确认后重写本机 memory；默认不保留原始敏感备份
repi memory repair --dry-run                    # 预览损坏 JSONL 行隔离和 events hash-chain 重建
repi memory repair --apply --yes                # 隔离损坏 memory 行、重建 seq/hash 链并保留备份/quarantine
repi memory diff                    # 查看尚未 consolidation 的高价值事件
repi memory consolidate --dry-run   # 只看蒸馏计划
repi memory consolidate             # 写入 project/procedural memory
```

会话内命令：

```text
re_memory search <query>
re_memory scope <target>
re_memory active <target>
re_memory status
re_memory promote <event-id>
re_memory demote <event-id>
re_memory forget <event-id>
re_context show
re_context resume <ref>
re_evidence show <query>
```

如果确实要恢复旧式全局记忆注入，必须显式开启 raw/global 模式：

```json
{
  "memory": {
    "mode": "global",
    "rawAutoInject": true,
    "autoInject": true,
    "startupDigest": "full",
    "contextMemoryMode": "global",
    "includeGlobalMemoryInContextPack": true,
    "autoDeposit": "all"
  }
}
```

临时开关：

```bash
REPI_MEMORY_AUTO_RECALL=0 repi                    # 只关闭自动召回
REPI_MEMORY_AUTO_DEPOSIT_MODE=off repi            # 只关闭自动沉淀
REPI_MEMORY_AUTO_DEPOSIT_MODE=high-value repi     # 仅高价值沉淀
REPI_MEMORY_CONTEXT_MODE=scoped repi              # context pack 带 scoped cards
REPI_MEMORY_RAW_AUTO_INJECT=1 REPI_MEMORY_AUTO_INJECT=1 REPI_MEMORY_STARTUP_DIGEST=full repi
```

核心文件：

```text
~/.repi/agent/recon/memory/core-memory.md
~/.repi/agent/recon/memory/project-memory.md
~/.repi/agent/recon/memory/procedural-memory.md
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
npm run doctor:repi
npm run health:repi
npm run smoke:repi
npm run check
npx vitest --run packages/coding-agent/test/recon-profile.test.ts
npm run gate:repi-harness
npm run gate:memory-isolation-default
node scripts/reverse-agent/repi-top-harness.mjs . --strict --json
node scripts/reverse-agent/autonomy-control-plane.mjs . --strict --json
```

让 REPI 自己做真实使用自检：

```bash
repi selfcheck --provider <provider> --model <model>
repi selfcheck --deep --provider <provider> --model <model>
```

`selfcheck` 会实际跑模型最小调用、bash 工具调用、记忆可见性探针、3 个并发 worker、编排源码检查；`--deep` 额外在隔离 profile 里触发一次 `/re-swarm run`，避免污染当前长期记忆。

`health` 是面向用户的总控面板，不要求先理解内部 gate：它把 `doctor`、`model doctor`、`memory doctor`、memory secret hygiene、latest swarm、磁盘占用和可选 `selfcheck` 合成一个分数、状态和优先修复命令。日常更新后建议先跑：

```bash
repi health
repi health --fix
```

CLI 快速控制面：

```bash
repi commands                       # 用户命令速查
repi update                         # 拉取、安装、修复并 smoke
repi update --fast                  # 快速更新
repi update --full                  # 更新后追加 npm run check
repi install                        # 只刷新启动器/profile
repi health                         # operator dashboard：doctor/model/memory/mission/swarm/storage 汇总评分
repi health --fix                   # 执行安全修复：profile/init、memory repair、memory sanitize
repi health --deep                  # 追加 live selfcheck 和更深的本机 sanitize scope
repi mission new <task>             # 新建 scoped mission、lane plan、证据合同
repi mission next                   # 输出下一步 operator commands
repi mission pack                   # 写 context/resume pack
repi engage <target>                # 主动识别目标、跑工具、写 engagement artifact
repi attack|reverse|web <target>    # engage 战术别名
repi doctor                         # 安装、runtime、模型解析、memory scoped defaults
repi doctor --fix                   # 自动重建 runtime profile、memory repair/sanitize、重装 repi 入口
repi smoke                          # 快速 smoke：doctor + memory/model status + memory gate + shrinkwrap + imports
repi smoke --full                   # smoke 后追加 npm run check
repi selfcheck --deep               # 模型、工具、记忆、并发 worker、编排能力端到端自检
repi bugreport --output /tmp/repi-bugreport.json  # 生成严格脱敏诊断包
repi trust status                   # 查看当前目录 trust 状态
repi trust yes                      # 保存当前目录及其 git/context root 的 trust 决策
repi trust no                       # 保存不信任决策
repi trust clear                    # 清除当前目录及其 git/context root 的 trust 决策
repi memory status                  # scoped memory 状态与污染保护
repi memory list --limit 20          # 脱敏列出 memory events，默认短输出
repi memory list --verbose --limit 20 # 排障时显示命令/规则/lesson
repi memory show <event-id>          # 脱敏查看单条 memory event
repi memory why <query-or-event-id>  # 召回解释
repi memory forget <event-id>        # 记忆 tombstone
repi memory quarantine <event-id>    # 记忆隔离
repi memory doctor                  # 记忆污染保护、JSONL 与 hash-chain 健康检查
repi memory export --output /tmp/repi-memory.json  # 脱敏导出
repi memory purge --dry-run --governed             # 预览清理
repi memory purge --apply --yes --governed         # 确认后才会真正写入
repi memory sanitize --dry-run                  # 预览本机 memory secret/url 脱敏
repi memory sanitize --apply --yes              # 确认后重写本机 memory；默认不保留原始敏感备份
repi memory repair --dry-run                    # 预览损坏 JSONL 行隔离和 events hash-chain 重建
repi memory repair --apply --yes                # 隔离损坏 memory 行、重建 seq/hash 链并保留备份/quarantine
repi memory diff                    # 未蒸馏高价值事件差异
repi memory consolidate --dry-run   # 查看 memory 蒸馏计划
repi memory consolidate             # 把高价值 events 蒸馏到 project/procedural memory
repi swarm plan <target> --workers 5
repi swarm run <target> --workers 5 --provider <provider> --model <model>
repi swarm status latest
repi swarm merge latest
repi swarm llm-run <target> --workers 3 --provider <provider> --model <model>
repi model list                     # 列出本机 provider/model，默认隐藏 baseUrl
repi model list --provider <id>     # 只看一个 provider；本机排障可加 --show-urls
repi model doctor                   # 离线检查 provider/model 配置
repi model add --provider <id> --api openai-completions --base-url <url> --model <id>
repi model edit --provider <id> --model <id> --context-window 262144 --max-tokens 16384
repi model remove --provider <id> --model <id>
repi model login --provider <id> --api-key-stdin
repi model default --provider <id> --model <id>
repi model test --provider <id> --model <id>
repi model export --output /tmp/repi-models.template.json
repi model import --input /tmp/repi-models.template.json --merge
repi model cost --provider openai-compatible --model provider/model-id --input-tokens 100000 --output-tokens 10000
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
├── repi-profile/                         # 兼容 profile mirror / 发布锚点
├── scripts/reverse-agent/                # harness / gates / installer
├── schemas/reverse-agent/                # gate schemas
├── fixtures/reverse-agent/               # hard-eval fixtures
└── docs/reverse-agent/README.md          # 深度能力文档
```

---

## 故障排查

### 启动命令异常

```bash
which repi
repi --offline --help
repi doctor --fix
repi install
```

确认帮助信息包含：

```text
REPI: independent product; built-in reverse/pentest kernel is enabled.
```

如 PATH 指向旧入口，重新执行 `repi install`；如果 shell 找不到 `repi`，进入源码目录执行 `bash install.sh --user` 后打开一个新的 shell。

### 启动提示旧 tools/hooks 目录

旧版本可能在 `~/.repi/agent/tools/`、`~/.repi/agent/hooks/` 或旧的文件型 extension/skill 目录里留下资源。新版启动不会因此卡住；如需清理，执行：

```bash
repi doctor --fix
```

修复会把旧 hooks / 自定义 tools 归档到 `~/.repi/agent/extensions/legacy-*`，把旧文件型 profile 归档到 `~/.repi/agent/recon/archive/legacy-file-profile-*`，不会删除模型、密钥、session 或 memory。

### 已 trust 的目录仍反复提示

先在目标目录确认 trust 状态：

```bash
cd /path/to/project
repi trust status
```

如果显示 `decision: unset` 或 `effectiveTrusted: no`，直接保存：

```bash
repi trust yes
```

`repi trust yes` 会同时写入当前目录、真实路径、`$PWD`、最近的 git root 和最近的 context root，解决 symlink、子目录、git 根目录切换导致的重复 trust 提示。已经打开的会话里可以执行 `/trust` 或重启 `repi`。

trust 数据只保存在本机：

```text
~/.repi/agent/trust.json
```

### 模型不可用

```bash
repi model list
repi model doctor
repi model cost --provider openai-compatible --model provider/model-id --input-tokens 100000 --output-tokens 10000
repi --offline --list-models
repi provider-doctor --base-url https://gateway.example/v1 --model provider/model-id --api auto
```

检查：

- `~/.repi/agent/models.json`
- provider name 是否匹配
- apiKey 是否使用 `$ENV_NAME` 形式并指向真实环境变量
- baseUrl 是否包含正确 `/v1` 路径

### 诊断包

```bash
repi bugreport --output /tmp/repi-bugreport.json
```

`bugreport` 会汇总 `doctor`、`model doctor`、`memory doctor`、最新 swarm 状态、git/node/npm 基本信息，并严格脱敏 API key、GitHub token、Authorization header、baseUrl 和 URL；不会导出 `auth.json` 或原始 memory events。


### 非交互长任务 guardrails

`repi -p` 默认向 stderr 输出进度和 heartbeat，并启用 wall timeout、turn/tool-call 上限、bash 默认超时和 stdin 读取保护：

```bash
REPI_PRINT_TIMEOUT_MS=300000 repi -p "长任务"
REPI_PRINT_MAX_TOOL_CALLS=120 repi --tools bash,read,grep -p "工具密集任务"
REPI_BASH_DEFAULT_TIMEOUT_SECONDS=30 repi --tools bash -p "本地检查"
```

常用变量：`REPI_PRINT_PROGRESS`、`REPI_PRINT_TIMEOUT_MS`、`REPI_PRINT_MAX_TURNS`、`REPI_PRINT_MAX_TOOL_CALLS`、`REPI_BASH_DEFAULT_TIMEOUT_SECONDS`、`REPI_STDIN_READ_TIMEOUT_MS`、`REPI_READ_STDIN_WITH_PROMPT`。这些 guardrails 只影响稳定性，最终答案仍写 stdout。

### Gate 失败

先跑：

```bash
npm run check
npm run gate:repi-harness
```

再针对失败项跑单独 gate。REPI 的 gate 失败通常表示 schema、fixture、runtime marker、docs 或 child harness 没有闭合。

---

## 开源治理

REPI 按正式开源项目维护：

- 贡献指南：[CONTRIBUTING.md](CONTRIBUTING.md)
- 安全政策：[SECURITY.md](SECURITY.md)
- 行为准则：[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- 支持与反馈：[SUPPORT.md](SUPPORT.md)
- PR 模板：`.github/PULL_REQUEST_TEMPLATE.md`
- Issue 模板：`.github/ISSUE_TEMPLATE/`

发布前建议执行：

```bash
npm run gate:open-source-readiness
npm run check
npm run smoke:repi
npm run gate:repi-harness
```

`gate:open-source-readiness` 会检查项目元数据、公开文档、GitHub 模板、workflow、敏感信息模式和过期上游文案，避免开源前把私有配置或旧项目文本带出去。

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

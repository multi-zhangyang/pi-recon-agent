# REPI Agent

REPI Agent 是独立的逆向 / 渗透任务组织型 agent 产品。它把一次安全研究任务拆成可追踪的执行内核、证据账本、分工计划、上下文恢复包、验证矩阵、复现矩阵和 proof loop，目标是让 agent 不只是“会回复”，而是能把复杂逆向/渗透工程按阶段推进、留证、恢复和审计。

当前仓库包含三个层次，但默认只走独立 `repi`：

- `packages/coding-agent/src/cli/repi-bootstrap.ts`：REPI 产品级 bootstrap。无论是源码 wrapper 还是 npm/bin 直接启动，只要命令身份是 `repi`，都会默认启用 `--recon`、隔离资源、初始化 `~/.repi/agent`，不会依赖外层 shell hack。
- `packages/coding-agent/src/core/recon-profile.ts`：内置 REPI profile，实现 slash command、tool、prompt、storage、compaction hook 和控制面 gate。`repi` 默认直接启用这个内置 kernel。
- `repi-profile/extensions/reverse-pentest-core.ts`：保留给兼容/迁移的文件型 profile 镜像，不再默认写入或启用到普通 `pi` 的 `~/.pi/agent`。

> 当前收口状态：REPI 已能正常作为专业逆向/渗透任务组织 agent 使用；并行计划、agent-dogfood subagent runtime manifest、AutonomousRuntimeBatchV1 strict gate、agent-dogfood / re_swarm / compound-frontier runtime ClaimLedgerEventV1、上下文 pack/resume、supervisor 分工验证、strict claim release gate、strict failure/repair schema fixture、runtime failure/repair ledger hooks、离线控制面 gates 已接入。最终输出不会只靠叙述放行：`re_supervisor`、`re_compiler final`、`re_complete audit` 都会读取 strict claim marker，并在 required claim gap 未闭合时阻断最终发布。

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
- `re_reflect` / `re_knowledge_graph`：沉淀经验、case signature、playbook 和跨任务知识。
- `re_memory events/search-events/consolidate`：读取结构化长期记忆、检索可复用 case、汇总高质量经验。
- `re_context`：生成可恢复上下文包，支持 exact resume。
- `re_operator`：把 next commands 转成 bounded operator queue。
- `re_verifier` / `re_compiler` / `re_replayer` / `re_autofix` / `re_proof_loop`：验证、报告编译、复现、修复、闭环证明。
- `re_complete`：完成审计，阻断缺证据、未完成 compact resume、claim gate 缺口。

### 2. 已接入的控制面

- `ReconParallelPlanV1`：并行 worker plan、coverage、release gate metadata。
- `ContextPackV2`：上下文 pack 带 `schemaVersion: 2`、`contextSha256`、artifact sha256、scope、closure、idempotency key。
- exact context resume：`re_context resume <contextPath>` / tool `contextPath` / `compactionEntryId` 精确加载指定 pack，并校验 hash、artifact drift、workspace/target/branch scope。
- `memory/compaction-resume-ledger.jsonl`：append-only compact/resume ledger。
- Memory v2：`~/.repi/agent/recon/memory/events.jsonl` 是 append-only `MemoryEventV1` 哈希链；`case-memory.jsonl` 是按 case signature 聚合后的复用视图；`retrieval-report.json` 记录每次 `re_memory search-events` 的召回、分数、原因和 hash-chain 状态。Markdown journal/playbook 仍保留给人读，但不再是唯一事实源。
- strict claim gate：`gate:claim-release` 使用严格 claim ledger validation，不把 orchestration 成功误报成平台 claim 成功；执行后会写 `~/.repi/agent/recon/evidence/claim-release/<timestamp>/result.json`，供 supervisor/compiler/complete 三段 runtime 读取。
- failure/repair runtime ledger：`FailureLedgerEventV1`、`RepairQueueItemV1` strict schema、strict fixture、duplicate signature/attempt 去重检查、hard-eval 离线样例，`re_replayer` / `re_autofix` / `re_operator` / `re_proof_loop` failed|blocked row 到 `~/.repi/agent/recon/evidence/failures/ledger.jsonl`、`~/.repi/agent/recon/evidence/repairs/queue.jsonl` 的 append-only 写入 hooks，以及 compound-frontier、agent-dogfood role retry、plan-only invalid fixture 的 failure/repair 输出。
- AutonomousRuntimeBatchV1 strict gate：`schemas/reverse-agent/autonomous-runtime-contract.schema.json` 与 `fixtures/reverse-agent/autonomous-runtime-contract.fixture.json` 覆盖 subagent runtime manifest、parallel shard state、compact resume transition、repair budget 和 runtime claim promotion；`npm run gate:autonomous-runtime` 会拒绝 duplicate subagent attempt、非法 resume transition 和 loose claim-gate 字段。
- runtime ClaimLedgerEventV1：agent-dogfood、re_swarm 与 compound-frontier 统一输出 `artifact_handoff → claim → validation → challenge → resolution` 哈希链；agent-dogfood 每个 role / synthesizer attempt 会输出 `*.runtime-manifest.json`，re_swarm run 为每个 worker 写 `SubagentRuntimeManifestV1`、stdout/stderr sha256、sessionDir、toolCallDigest 与 `*-subagent-runtime-manifests.json`，compound-frontier 同步写 `claim-ledger.jsonl`；`npm run gate:runtime-claim-ledger` 会把最新 runtime ledger 适配进 `validate-claim-ledger.mjs` 的 strict validator，缺失 live runtime artifact 明确标为 `missing_runtime_artifact`，防止 role/worker/compound claim 只停留在叙述层。


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
- `scope`：session、workspace、target、branch
- `resumeQueueStatus`
- `closure`
- `idempotencyKey`
- `next_operator_commands`

## 长期记忆沉淀 / Memory v2

当前 REPI 的长期记忆分两层：

```text
~/.repi/agent/recon/memory/events.jsonl          # append-only MemoryEventV1，带 prevHash/entryHash
~/.repi/agent/recon/memory/case-memory.jsonl     # CaseMemoryV1 聚合视图
~/.repi/agent/recon/memory/retrieval-report.json # 最近一次检索报告
~/.repi/agent/recon/memory/field-journal.md      # 人类可读日志镜像
~/.repi/agent/recon/memory/playbooks/*.md        # 人类可读 playbook 镜像
```

常用命令：

```text
/re-memory events
/re-memory search-events authz replay
/re-memory consolidate
/re-memory append <本次任务可复用经验>
```

工具调用等价：

```text
re_memory { "action": "search-events", "query": "authz replay" }
re_memory { "action": "consolidate" }
```

沉淀规则：

- `re_reflect write` 会把 supervisor lessons / failure patterns / reuse rules / repair commands 同时写入 playbook 和 `events.jsonl`；`re_replayer` / `re_autofix` / `re_proof_loop` / `re_complete` 会把 replay 结果、修复队列、证明闭环和完成审计自动写回 MemoryEventV1。
- `re_lane plan` 会读取 playbook、knowledge graph 和 `events.jsonl`，把高分结构化历史命令合入命令包，并在 notes 中显示 `memory_event_reuse`。
- 每条 memory event 带 `quality.confidence`、`replayVerified`、`reuseCount`、`failureCount`、`decay`；检索时低置信、失败和衰减记录会降权。
- 结构化契约由 `schemas/reverse-agent/memory-event.schema.json`、`fixtures/reverse-agent/memory-event.fixture.json` 和 `npm run gate:memory-contract` 保护。

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


### CI 自动验收模板

仓库提供 GitHub Actions 模板：`docs/reverse-agent/repi-harness.github-actions.yml`。启用时复制到 `.github/workflows/repi-harness.yml`，push / PR 会自动执行：

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
node --check scripts/reverse-agent/memory-contract-gate.mjs
git diff --check

env -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_API_KEY -u OPENAI_API_KEY \
    -u RECON_AGENT_MODEL -u ANTHROPIC_MODEL \
    ./node_modules/.bin/tsgo --noEmit --pretty false

npm run gate:context-compact
npm run gate:memory-contract
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
~/.repi/agent/recon/evidence/remote/agent-parallel-dogfood/*/subagent-runtime-manifests.json
~/.repi/agent/recon/evidence/remote/agent-parallel-dogfood/*/claim-ledger.jsonl
~/.repi/agent/recon/evidence/remote/compound-frontier/*/claim-ledger.jsonl
memory/compaction-resume-ledger.jsonl
memory/autonomous-budget-ledger.md
memory/events.jsonl
memory/case-memory.jsonl
memory/retrieval-report.json
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
- exact resume 继续扩展负例 fixture：multi compact、target unresolved、cross-session contamination。
- 通用 re_swarm 独立子会话 runtime 与 provider live benchmark 可在需要时另行接入；当前仓库默认以离线可复现 harness 为准。

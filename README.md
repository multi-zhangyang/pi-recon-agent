# Pi-RECON Agent

Pi-RECON Agent 是基于 Pi agent harness 魔改的逆向 / 渗透任务组织型 agent profile。它把一次安全研究任务拆成可追踪的执行内核、证据账本、分工计划、上下文恢复包、验证矩阵、复现矩阵和 proof loop，目标是让 agent 不只是“会回复”，而是能把复杂逆向/渗透工程按阶段推进、留证、恢复和审计。

当前仓库包含两套同步实现：

- `packages/coding-agent/src/core/recon-profile.ts`：内置 Pi-RECON profile，实现 slash command、tool、prompt、storage、compaction hook 和控制面 gate。
- `.pi/extensions/reverse-pentest-core.ts`：可安装到全局 Pi profile 的扩展版 runtime，与内置 profile 保持同步。

> 当前状态：Pi-RECON 已能正常作为专业逆向/渗透任务组织 agent 使用；并行计划、上下文 pack/resume、claim gate、failure/repair schema、runtime failure/repair ledger hooks、离线控制面 gates 已接入。它还不宣称是完整顶级 autonomous red-team agent；独立子会话 runtime、compound/role retry ledger、claim ledger 全路径发布门禁仍属于后续增强项。

## 目录

- [能力概览](#能力概览)
- [环境要求](#环境要求)
- [快速安装](#快速安装)
- [从源码启动 Pi-RECON](#从源码启动-pi-recon)
- [安装为全局 Pi profile](#安装为全局-pi-profile)
- [常用工作流](#常用工作流)
- [上下文压缩与精确恢复](#上下文压缩与精确恢复)
- [模型 / provider 配置](#模型--provider-配置)
- [离线验证与 gates](#离线验证与-gates)
- [关键文件结构](#关键文件结构)
- [排错](#排错)

## 能力概览

Pi-RECON 的核心不是单个 prompt，而是一套可落盘、可恢复、可审计的任务控制面。

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
- `re_context`：生成可恢复上下文包，支持 exact resume。
- `re_operator`：把 next commands 转成 bounded operator queue。
- `re_verifier` / `re_compiler` / `re_replayer` / `re_autofix` / `re_proof_loop`：验证、报告编译、复现、修复、闭环证明。
- `re_complete`：完成审计，阻断缺证据、未完成 compact resume、claim gate 缺口。

### 2. 已接入的控制面

- `ReconParallelPlanV1`：并行 worker plan、coverage、release gate metadata。
- `ContextPackV2`：上下文 pack 带 `schemaVersion: 2`、`contextSha256`、artifact sha256、scope、closure、idempotency key。
- exact context resume：`re_context resume <contextPath>` / tool `contextPath` / `compactionEntryId` 精确加载指定 pack，并校验 hash、artifact drift、workspace/target scope。
- `memory/compaction-resume-ledger.jsonl`：append-only compact/resume ledger。
- strict claim gate：`gate:claim-release` 使用严格 claim ledger validation，不把 orchestration 成功误报成平台 claim 成功。
- failure/repair runtime ledger：`FailureLedgerEventV1`、`RepairQueueItemV1` schema、hard-eval 离线样例，以及 `re_replayer` / `re_autofix` / `re_operator` / `re_proof_loop` failed|blocked row 到 `.pi/evidence/failures/ledger.jsonl`、`.pi/evidence/repairs/queue.jsonl` 的 append-only 写入 hooks。

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

先跑一次离线 help，确认 profile 能加载：

```bash
PI_OFFLINE=1 ./pi-test.sh --recon --no-tools --help
```

## 从源码启动 Pi-RECON

离线查看能力，不调用 provider：

```bash
PI_OFFLINE=1 ./pi-test.sh --recon --no-tools --help
```

正常启动：

```bash
./pi-test.sh --recon
```

进入 Pi 后建议先执行：

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

## 安装为全局 Pi profile

把 `.pi` profile 安装到当前 Pi agent 目录。默认目标是 `~/.pi/agent`；如需自定义可设置 `PI_CODING_AGENT_DIR`。

```bash
scripts/reverse-agent/install-global-profile.sh /root/pi-diy/pi
scripts/reverse-agent/refresh-tool-index.sh /root/pi-diy/pi
scripts/reverse-agent/verify-profile.mjs /root/pi-diy/pi
```

安装后会同步 / 链接这些内容：

```text
~/.pi/agent/SYSTEM.md
~/.pi/agent/APPEND_SYSTEM.md
~/.pi/agent/extensions/reverse-pentest-core.ts
~/.pi/agent/skills/reverse-pentest-orchestrator/SKILL.md
~/.pi/agent/prompts/*.md
~/.pi/agent/node_modules -> <repo>/node_modules
```

验证：

```bash
PI_OFFLINE=1 ./pi-test.sh --recon --no-tools --help
```

进入 Pi 后：

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
.pi/evidence/contexts/<timestamp>-<target>-pack.md
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

恢复时可以直接指定原始 pack：

```text
/re-context resume .pi/evidence/contexts/<timestamp>-<target>-pack.md
```

工具调用也支持显式参数：

```json
{
  "action": "resume",
  "target": "<target>",
  "contextPath": ".pi/evidence/contexts/<timestamp>-<target>-pack.md"
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

## 模型 / provider 配置

Pi-RECON 不绑定某个私有端点。模型配置放在用户本地 Pi 配置目录，不提交到仓库：

```text
~/.pi/agent/models.json
~/.pi/agent/settings.json
```

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
PI_OFFLINE=1 ./pi-test.sh --recon \
  --provider openai-compatible \
  --model provider/model-id \
  --thinking off \
  --no-tools \
  --no-session \
  -p "Reply exactly: PROVIDER_OK"
```

如果要真实调用模型，把 `PI_OFFLINE=1` 去掉，并确保对应 `baseUrl`、`apiKey`、`model id` 可用。

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

修改 profile / harness 后至少运行：

```bash
node --check packages/coding-agent/src/core/recon-profile.ts
node --check .pi/extensions/reverse-pentest-core.ts
node --check scripts/reverse-agent/context-compact-audit.mjs
git diff --check

env -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_API_KEY -u OPENAI_API_KEY \
    -u RECON_AGENT_MODEL -u ANTHROPIC_MODEL \
    ./node_modules/.bin/tsgo --noEmit --pretty false

npm run gate:context-compact
npm run gate:autonomy-control
npm run gate:autonomous-contracts
npm run audit:parallel-plan
npm run audit:hard-eval-control
```

严格 claim release gate：

```bash
npm run gate:claim-release
```

当前若 evidence 中仍存在 required platform gaps，它会失败，这是 strict release gate 的预期行为。它用于防止把“组织链路跑通”误当作“平台 claim 全部证明”。

## 关键文件结构

```text
.pi/
  SYSTEM.md
  APPEND_SYSTEM.md
  extensions/reverse-pentest-core.ts
  prompts/*.md
  skills/reverse-pentest-orchestrator/SKILL.md

docs/reverse-agent/
  README.md
  autonomous-control-plane.md
  model-provider-formats.md

packages/coding-agent/src/core/
  recon-profile.ts

schemas/reverse-agent/
  context-resume-contract.schema.json
  failure-repair-contract.schema.json
  division-validation-contract.schema.json

scripts/reverse-agent/
  context-compact-audit.mjs
  autonomy-control-plane.mjs
  autonomous-contracts.mjs
  hard-eval-control-plane.mjs
  validate-claim-ledger.mjs
  audit-parallel-plan.mjs
  install-global-profile.sh
  refresh-tool-index.sh
  verify-profile.mjs
```

运行后常见产物：

```text
.pi/evidence/contexts/*.md
.pi/evidence/operators/*.md
.pi/evidence/verifiers/*.md
.pi/evidence/compilers/*.md
.pi/evidence/replayers/*.md
.pi/evidence/proof-loops/*.md
memory/compaction-resume-ledger.jsonl
memory/autonomous-budget-ledger.md
memory/playbooks/*.md
```

## 排错

### 1. help 都跑不起来

```bash
npm install --ignore-scripts
PI_OFFLINE=1 ./pi-test.sh --recon --no-tools --help
```

仍失败时先看 TypeScript / 语法：

```bash
node --check packages/coding-agent/src/core/recon-profile.ts
node --check .pi/extensions/reverse-pentest-core.ts
./node_modules/.bin/tsgo --noEmit --pretty false
```

### 2. 全局 profile 没生效

重新安装并刷新索引：

```bash
scripts/reverse-agent/install-global-profile.sh /root/pi-diy/pi
scripts/reverse-agent/refresh-tool-index.sh /root/pi-diy/pi
scripts/reverse-agent/verify-profile.mjs /root/pi-diy/pi
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
required_platform_gaps
release_blocking_gaps
unresolved_frontier_gaps
```

然后回到：

```text
/re-supervisor repair <target>
/re-context pack <target>
/re-operator dispatch <target> 2
/re-proof-loop run <target> 4 2
/re-complete audit
```

## 当前后续增强项

- 独立 Pi sub-agent/session runtime：PID、session dir、stdout/stderr hash、tool-call digest。
- FailureLedgerEventV1 / RepairQueueItemV1 继续扩展到 compound-frontier、agent role retry、plan-only runner，并补 strict schema fixtures。
- ClaimLedgerEventV1 深接 `re_supervisor`、`re_compiler` 和最终发布路径。
- exact resume 负例 fixture：stale latest、hash drift、multi compact、target unresolved、cross-session contamination。
- release gate 聚合 `releaseGateMetadata`、`planCoverage`、`claimGatePolicy`，形成完整 CI/release 门禁。

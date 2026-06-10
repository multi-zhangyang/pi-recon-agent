# REPI Hard Eval Control Plane

`hard-eval-control-plane.mjs` 是 REPI 的离线严苛评测控制面。它不访问真实网站、不调用模型 provider、不重跑 benchmark，而是读取当前 `.repi-harness/evidence/remote/*` 已有证据，把“agent 编排是否成功”和“平台 claim 是否被证明”拆开。

目的：避免把 agent 并行运行成功、hard-score 高分或旧证据成功，误写成当前 B站 / 小红书 / 抖音 same-window claim 全绿。

## 运行方式

```bash
npm run audit:hard-eval-control
node scripts/reverse-agent/hard-eval-control-plane.mjs . --json
node scripts/reverse-agent/hard-eval-control-plane.mjs . --write
```

默认只输出，不写文件。`--write` 会生成：

```text
.repi-harness/evidence/hard-eval-control-plane/<timestamp>/result.json
.repi-harness/evidence/hard-eval-control-plane/<timestamp>/contract.json
.repi-harness/evidence/hard-eval-control-plane/<timestamp>/ledger.jsonl
.repi-harness/evidence/hard-eval-control-plane/<timestamp>/gate.json
.repi-harness/evidence/hard-eval-control-plane/<timestamp>/failure-ledger.jsonl
.repi-harness/evidence/hard-eval-control-plane/<timestamp>/repair-queue.jsonl
.repi-harness/evidence/hard-eval-control-plane/<timestamp>/report.md
```

同时追加 canonical append-only ledger：

```text
.repi-harness/evidence/failures/ledger.jsonl
.repi-harness/evidence/repairs/queue.jsonl
```

`--strict-claims` 会在 required platform claim 存在 gap 时返回非零；这个开关用于恢复 live 评测后的硬门禁，不建议在控制面开发期间默认开启。

## 输入证据

脚本只读取最新已有 artifact：

```text
.repi-harness/evidence/remote/same-window-live/**/result.json
.repi-harness/evidence/remote/agent-parallel-dogfood/**/result.json
.repi-harness/evidence/remote/hard-score/**/scoreboard.json
```

证据优先级：

1. latest same-window live artifact
2. agent parallel runtime artifact
3. hard-score scoreboard

如果 hard-score 里旧证据高分，但 latest same-window 有 required gap，脚本会保留 gap，并阻断 platform success summary。

## 输出模型

### contract.json

定义 mapper、verifier、adversary、synthesizer 的最小 role contract：

- mapper 只能产出 artifact handoff 和 claim。
- verifier 必须逐 claim validation。
- adversary 必须 challenge same-window 和 orchestration-vs-platform 混淆。
- synthesizer 必须解析 required gaps、conflicts 和 score split。

### ledger.jsonl

append-only claim ledger，包含：

- `artifact_handoff`
- `claim`
- `validation`
- `challenge`
- `resolution`

每条 event 带 `prevHash/eventHash`，用于追踪 claim 是否从 artifact 推导而来。

### gate.json

硬规则：

- artifact path 存在。
- artifact sha256 已绑定。
- claim ledger 存在。
- required platform claims 已验证。
- orchestration claims 已验证。
- orchestration/platform 评分已分离。
- anti-self-delusion gate 生效。

### failure-ledger.jsonl / repair-queue.jsonl

每个未证明的 platform claim 会生成 failure 和 paused repair：

- 小红书 signed trace / target 2xx gap → xhs recapture repair。
- 抖音 structured replay gap → douyin recapture repair。
- B站 media/WBI gap → same-window recapture repair。

repair 默认 `paused=true`。恢复 live 测试前，只能作为计划，不自动执行。

failure/repair 合同字段包括：

- failure: `signature`、`artifactHashes`、`budget`、`retryBudget`、`rollback`、`evidenceWriteback`、`blockedConditions`。
- repair: `action`、`repairAction`、`expectedGates`、`preconditions`、`rollbackCriteria`、`regressionGates`、`evidenceWriteback`、`blockedConditions`。

## 评分拆分

脚本输出两个不同分数：

```text
orchestration.score
platformRequired.score
platformAll.score
```

含义：

- `orchestration.score`：多 agent 是否启动、调用模型/工具、并发、合并、记录 runtime digest。
- `platformRequired.score`：latest same-window required platform claims 是否被证明。
- `platformAll.score`：required + frontier/supporting platform claims 的整体证明度。

如果 orchestration 是 100，但 platform required 不是 100，结论必须是：

```text
orchestration success cannot be reported as platform success
```

## 当前用途

这个脚本是控制面硬化的第一步：先把既有真实平台 evidence 变成 claim ledger / failure ledger / repair queue。下一步再把同一 schema 接入：

- `agent-dogfood/parallel-run.mjs`
- `hard-score.mjs`
- `re_supervisor`
- `re_compiler`
- `re_proof_loop`

完成后，REPI 的评测结果才能从“文本复盘”升级为“artifact-backed claim verification”。

## Hard-score integration

`bench/recon-remote/hard-score.mjs` now carries the same split into the normal scoreboard:

```json
{
  "scoreSeparation": {
    "topScore": 100,
    "topOrchestrationScore": 100,
    "topPlatformClaimScore": 50,
    "orchestrationPlatformWarnings": []
  }
}
```

For `agent-parallel-dogfood` rows, `score` remains the orchestration score, but the row also includes:

- `scoreType: "orchestration"`
- `orchestrationScore`
- `platformClaimScore`
- `platformAllClaimScore`
- `platformClaimGaps[]`
- `scoreWarning`

For `same-window-live` rows, the row includes platform claim fields directly. This keeps historical scoring compatible while making the self-delusion boundary explicit in JSON and Markdown output.

## Parallel dogfood integration

`bench/recon-remote/agent-dogfood/parallel-run.mjs` now runs the hard eval control plane after hard-score and passes the score split into every worker's shared context. A confirmed orchestration run with required platform gaps becomes:

```text
agent-parallel-dogfood-confirmed-platform-gaps
```

That verdict means:

- multi-agent orchestration, model/tool calls, process proof and synthesizer reconciliation passed;
- latest same-window required platform claims still contain gaps;
- the result must not be reported as platform success;
- `hardEvalControl.repairQueue` is the next live-testing plan when testing resumes.

## Claim ledger validator

`validate-claim-ledger.mjs` is the hard gate for the automatic division-validation layer:

```bash
node scripts/reverse-agent/hard-eval-control-plane.mjs . --json \
  | node scripts/reverse-agent/validate-claim-ledger.mjs --stdin --allow-platform-gaps
```

It checks:

- role contract contains mapper / verifier / adversary / synthesizer;
- ledger `prevHash/eventHash` chain is intact;
- artifact handoff paths exist and sha256 matches;
- every `proven` / `final_pass` claim has evidence refs that evaluate against the artifact JSON;
- required gaps have challenge and resolution events;
- orchestration score and platform claim score are separated;
- strict platform success fails while required live same-window gaps remain.

The strict form is intentionally expected to fail on the current evidence until the repair queue closes XHS and Douyin required gaps:

```bash
node scripts/reverse-agent/hard-eval-control-plane.mjs . --json \
  | node scripts/reverse-agent/validate-claim-ledger.mjs --stdin --strict-claims
npm run gate:claim-release
```

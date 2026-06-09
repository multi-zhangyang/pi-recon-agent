# Pi-RECON Autonomous Control Plane

Pi-RECON 当前目标不是把一次 benchmark 分数包装成能力结论，而是把逆向/渗透任务组织成可恢复、可分工、可验证、可修复的控制面。

当前状态：Pi-RECON 已能正常使用，并具备专业逆向/渗透任务组织能力。它可以把任务推进到 `map → operation → delegate → swarm → supervisor → context → operator → verifier → compiler → replayer → autofix → proof-loop` 这条工程链路。

同时，它还没有达到完整 autonomous red-team agent 的定义。以下四个方向是继续硬化的工程任务，不应被静态审计、单次 live 通过或模型输出文本替代。

## 静态控制面审计

不跑真实平台、不调用模型 provider、不做 benchmark：

```bash
npm run gate:autonomy-control
npm run audit:parallel-plan
node scripts/reverse-agent/autonomy-control-plane.mjs . --json
node scripts/reverse-agent/autonomy-control-plane.mjs . --write
```

`autonomy-control-plane.mjs` 只检查源码、文件型 profile、文档和 harness marker，输出：

- `normalUseGuarantee`：四个组织能力是否具备可用控制面。
- `currentLevel`：当前工程定位。
- `topAutonomousDefinition=false`：仍需硬化的 autonomous 缺口。
- `pillars[]`：每个方向的 evidence marker、缺口和非测试工作顺序。
- `controlPlaneContractAudit`：离线校验长期上下文、失败修复、分工验证的字段合同和 JSON schema。

## ReconParallelPlanV1 离线集成流

`ReconParallelPlanV1` 是当前并行调度控制面的机读计划格式。它把“要让哪些
worker 做什么、允许看哪些 artifact、按什么字段合并、失败如何降级”写成显式
合同，而不是只靠 prompt 约定。

离线生成计划：

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs \
  --plan --json --strategy=balanced --shards=3 > /tmp/recon-parallel-plan.json
```

离线预览/校验下游 ingestion：

```bash
node bench/recon-remote/agent-dogfood/parallel-run.mjs \
  --plan-json /tmp/recon-parallel-plan.json --plan-only --json
npm run audit:parallel-plan
```

边界：

- `frontier-orchestrator --plan --json --shards=N` 输出 legacy plan 字段和
  `parallelPlan`，不启动浏览器、不调用 provider、不写新证据目录。
- `agent-dogfood/parallel-run.mjs --plan-json <path> --plan-only` 接受直接的
  `ReconParallelPlanV1`，也接受包含 `parallelPlan` 的 orchestrator JSON root。
- `--plan-only` 只输出 `pi-recon-parallel-plan-preview`，不要求
  `RECON_AGENT_MODEL`，不运行 hard-score/hard-eval/worker/synthesizer。
- 计划里的 `commands[]`、`evidenceContract[]`、`mergeKeys[]` 是后续执行和验证
  的合同，不是平台能力已通过的证据。
- `npm run audit:parallel-plan` 会把上游计划和下游 plan-only 预览串起来校验，
  并确认未设置模型/provider 时也不会创建 `agent-parallel-dogfood/<timestamp>`
  证据目录。

## Runtime 集成边界：re_swarm / re_supervisor / release gate

当前 runtime 接入边界是：`frontier-orchestrator` 和 `agent-dogfood`
已经证明 `ReconParallelPlanV1` 可以被离线生成、读取和预览；`re_swarm`、
`re_supervisor`、`re_compiler final`、`re_complete audit` 与 `gate:claim-release`
已经把同一份计划合同、release metadata 和 strict claim marker 贯穿到 runtime
artifact、claim gate 和最终发布路径里。

### re_swarm 应消费和输出的字段

`re_swarm plan|run|merge` 应消费 `ReconParallelPlanV1` 或包含
`parallelPlan` 的上游 artifact，并把其中字段归一化为 runtime worker 边界：

- `planId` / `source` / `target`：绑定本次 swarm 运行来源，避免跨计划合并。
- `workers[].id|role|objective|commands|dependencies|limits`：生成
  `worker_runtime_packets`、timeout/cancel/retry budget 和执行顺序。
- `workers[].evidenceContract` / `mergeKeys` / `artifactGlobs`：生成
  `planCoverage` 的覆盖项，而不是只作为文本提示。
- `merge.strategy` / `merge.evidenceOrder` / `merge.conflictPolicy`：决定
  `merge_digest` 如何处理冲突、过期 artifact 和 negative control。

`re_swarm` 输出应至少包含：

- `parallel_plan` 或 `reconParallelPlan`：原始计划摘要和 hash。
- `planCoverage`：每个 worker、evidenceContract、mergeKey、artifactGlob 的
  `planned / observed / covered / blocked / unresolved` 状态。
- `worker_runtime_packets`、`worker_executions`、`worker_results`、`blocked`：
  每行绑定 `planId`、`workerId`、stdout/stderr hash、artifact refs 和 failure refs。
- `merge_digest`：只汇总 runtime evidence 和 coverage，不把未验证 claim 升级为 pass。

边界：`planCoverage=covered` 只能证明计划项被 runtime artifact 覆盖，不能证明目标
平台 claim 成功；平台 claim 仍必须经过 claim ledger、verifier 和 release gate。

### re_supervisor 应消费和输出的字段

`re_supervisor review|repair` 应消费：

- `ReconParallelPlanV1` / `parallel_plan`
- `re_swarm` 的 `planCoverage`、`worker_results`、`blocked`、`merge_digest`
- role contract 的 `claimGatePolicy`
- claim ledger / validation / challenge / resolution event

`re_supervisor` 输出应包含：

- `planCoverageReview`：指出缺失 worker、未覆盖 evidenceContract、未解析 mergeKey、
  超时/取消/失败预算耗尽项。
- `claimGatePolicy`：明确哪些 claim kind 可升级、哪些只能作为 observation，
  以及 required artifact sha256、JSON query、verifier pass、adversary challenge
  resolution 条件。
- `claimGateResult`：按 claimId 给出 `passed / downgraded / blocked`，并列出
  unresolved challenge 和 platform required gaps。
- `commander_merge_queue` / `repair_queue`：把缺覆盖、冲突 claim、失败签名和
  release-blocking gaps 转回 operator、swarm retry、autofix 或 proof-loop。

边界：`re_supervisor` 可以阻止自嗨式结论，也可以产生修复队列；但在 runtime
repair、append-only failure ledger、rollback gate 未接完前，不能宣称它已经能自动修复
所有失败或自动完成所有平台验证。

### Release-gate metadata 应承载的字段

release gate 不应只看摘要文本，应消费 `planCoverage`、`claimGatePolicy`、
claim ledger、hard-eval score split 和 autonomous contracts gate，输出
`releaseGateMetadata`：

- `planId`、`source`、`planSha256`
- `planCoverageSummary`：workers/evidenceContracts/mergeKeys/artifactGlobs 覆盖率和
  unresolved rows。
- `claimGatePolicy` 与 `claimGateVerdict`：哪些 claim 被允许发布，哪些被降级或阻断。
- `scoreSeparation`：orchestration score 与 platform claim score 分开。
- `releaseBlockingGaps`：required platform gaps、unresolved challenges、missing artifact
  hashes、stale runtime evidence、failed gates。
- `controlPlaneMode`：标注是否为 offline/plan-only/no-provider/no-live，避免把控制面
  smoke check 写成真实平台证明。

仍未完成项：

1. `re_swarm` runtime artifact 统一写入 `ReconParallelPlanV1` hash 和
   `planCoverage` 明细。
2. `re_supervisor` 把 `claimGatePolicy` 和 claim ledger 作为硬门禁，而不是旁路说明。
3. release gate 聚合 `audit:parallel-plan`、`gate:autonomous-contracts`、
   `audit:claim-ledger`、hard-eval score split，并生成机器可读
   `releaseGateMetadata`。
4. 缺覆盖、claim 冲突、failure signature 应回流到 append-only repair/failure ledger，
   再由 operator/proof-loop 做 bounded 修复。

## 1. 并行调度 / 分片 / 专家分工

已有能力：

- `re_operation → re_delegate → re_swarm → re_supervisor` 已能把 operation queue 拆成 specialist worker packets，再组织 `worker_runtime_packets`、`parallel_groups`、`merge_protocol`、`collision_matrix` 和 `commander_next_actions`。
- `frontier-orchestrator` 已有 case catalog、`agentLane`、`--shards=N` 分片计划，并能在 `--plan --json` 输出 `ReconParallelPlanV1`。
- `agent-dogfood/parallel-run.mjs` 已有 mapper/verifier/adversary/planner/synthesizer 多角色并发 runner，并记录 PID、session digest、model/tool call digest、overlap/speedup 等运行证据。
- `agent-dogfood/parallel-run.mjs --plan-json <path> --plan-only` 已能离线读取 `ReconParallelPlanV1`，归一化 workers/merge/evidence contract，并在不调用模型的情况下预览调度边界。

仍需硬化：

- 将 `ReconParallelPlanV1` 扩展到 `re_swarm`、`re_supervisor` 和 release gate，避免只有 frontier/dogfood 两个入口懂这个结构。
- 把 `re_swarm` 的 command-level worker packet 升级为可选独立 Pi agent/session runtime。
- 为每个 worker 保存 PID、session dir、stdout/stderr hash、model/tool call digest、timeout/cancel、artifact globs。
- shard plan 支持真实并发执行、多 shard result merge、取消/超时/重排队。
- merge 前做 structured claim coverage，不再只靠文本摘要。

推荐非测试顺序：

1. 保持 `frontier-orchestrator --plan --json --shards=N | agent-dogfood --plan-json ... --plan-only` 作为静态合同 smoke check。
2. `re_swarm plan` 输出同一 `parallel_plan` 区块。
3. `agent-dogfood` 执行态把 planId/source/worker merge keys 写入每个 worker runtime digest。
4. `re_supervisor` 消费 worker runtime digest 和 structured merge keys。

## 2. 长期上下文 / compact / resume

已有能力：

- `re_context pack|resume` 生成 `context_pack`，包含 mission、evidence tail、memory tail、artifact index、repair queue、autonomous budget 和 next operator commands。
- `session_before_compact` 已由 Pi-RECON 接管，返回 `pi-recon-compaction` summary/details。
- `session_compact` 会验证 resume contract，写 auto-resume telemetry，并触发 bounded resume turn。
- `re_operator`、`re_proof_loop`、`re_knowledge_graph` 会消费 compact resume telemetry/queue。
- `scripts/reverse-agent/context-compact-audit.mjs` 已作为独立静态 gate 检查 context pack、owned compaction、resume contract、evidence summarization 和 budget continuation。
- `schemas/reverse-agent/context-resume-contract.schema.json` 已加固 V2 字段：`contextSha256`、artifact sha256、`idempotencyKey`、append-only ledger hash、`date-time` 与 `artifactHashes.minItems`；`gate:autonomous-contracts` 会读取真实 schema 文件确认这些不变量存在。

仍需硬化：

- `re_context resume` 按 `contextPath` 或 `compactionEntryId` 精确加载原 pack，而不是重新生成最新 pack。
- context/artifact index 按 mission、session、workspace、target 过滤，避免跨任务污染。
- artifact index 增加 sha256、mtime、size、exists、evidence rank、source command，并在恢复时校验漂移。
- compact resume telemetry 改为 append-only ledger，持久化 auto-resume budget 和 idempotency。
- completion audit 阻断所有 verified 但未闭合的 resume contract。

推荐非测试顺序：

1. 把 `ContextPackV2 / ResumeContractV2` schema 字段接入 runtime context pack。
2. 增加 `memory/compaction-resume-ledger.jsonl`，每条记录带 `prevHash/entryHash/idempotencyKey`。
3. 让 `re_context resume <contextPath|compactionEntryId>` 校验 `contextSha256`、mission、session、target 和 artifact hashes。
4. 补静态/单元级假 artifact 场景：stale latest、hash drift、multi compact、target unresolved、cross-session contamination。

## 3. 失败自修复 / retry / rollback

已有能力：

- provider/agent session 层已有 bounded retry 和指数退避。
- `re_replayer → re_autofix → re_proof_loop` 能把失败复现、compiler gaps、operator feedback 转为 repair queue。
- `re_operator`、`re_delegate`、`re_swarm`、`re_supervisor` 已有失败预算、score decay、demotion、retry queue、evidence recapture queue 等局部闭环。
- parallel dogfood runner 已有 role/synthesizer bounded retry。
- `hard-eval-control-plane --write` 同时写 per-run failure/repair artifact，并追加 canonical `.pi/evidence/failures/ledger.jsonl` 与 `.pi/evidence/repairs/queue.jsonl`；failure event 带 `retryBudget/evidenceWriteback/blockedConditions`，repair item 带 `repairAction/evidenceWriteback/blockedConditions`。

仍需硬化：

- 新增统一 failure ledger：source、scope、category、signature、attempt/maxAttempts、status、failedGates、artifact hashes。
- 由 `failureToRepair()` 生成 repair queue，把 stale artifact、runtime failed、tool missing、contract gap 等转成机器可执行动作。
- 所有 retry 使用同一失败签名和预算，达到 exhausted 后停止盲 retry。
- 保存 per-attempt stdout/stderr/session artifact，避免 retry 覆盖失败证据。
- 为 autofix/operator/compound 类动作加入 baseline、allowlist、passed gate regression 和 rollback criteria。

推荐非测试顺序：

1. 在 compound failed gates、agent role retry、replayer failed/blocked 三处复用同一 `FailureLedgerEventV1 / RepairQueueItemV1` 写 canonical ledger。
2. 字段必须包含 `signature`、`artifactHashes`、`budget/retryBudget`、`rollback`、`evidenceWriteback` 和 `blockedConditions`。
3. proof-loop 按 failure signature 去重，并把 exhausted 状态交给 operator escalate。
4. autofix/apply 前记录 git HEAD、git status、allowlist、source artifact hash 和上一轮 passed gates。

## 4. 自动分工验证 / claim 合同 / 冲突合成

已有能力：

- `re_verifier`、`re_compiler`、`re_supervisor` 已有 assertions、counter evidence、contradictions、conflict matrix、worker scoreboard 和 commander merge queue。
- parallel dogfood runner 已记录 `roleGateMatrix`、`toolResultsCaptured`、`synthesizerReconciled`、`antiSelfDelusion` 等运行级验证信号。
- `gate:claim-release` 使用 strict claim ledger validator，并写入 `.pi/evidence/claim-release/<timestamp>/result.json`；当前 required platform gap 存在时应失败，避免把 worker/orchestration 成功升级成 final platform pass。
- `re_supervisor` 输出 `strictClaimGate` / `claimGateResult`；`re_compiler final` 只有 strict marker pass 才写最终 report；`re_complete audit` 会阻断 marker missing/blocked、supervisor claim gate gap 和 compiler final claim gate gap。

仍需硬化：

- 把 role/compound runtime 的 claim ledger 写入从 hard-eval 离线链扩展到真实子会话执行态。
- 每个 `proven/final_pass` claim 继续强制绑定 artifact sha256 和 JSON query，并有 verifier pass 且无 unresolved adversary challenge。
- synthesizer 输出 conflict table：claim IDs、冲突主题、胜出证据、降级原因、未解决冲突。

推荐非测试顺序：

1. 在 parallel runner 输出 `contract.json + ledger.jsonl + gate.json`，角色字段必须包含 `handoffTargets` 和 `evidenceContract`。
2. role stdout 先解析结构化 claims；未结构化输出只能作为 observation，不能升级为 final pass。
3. hard-score/release gate 读取 claim gate，分离 orchestration 和 claim 结果。
4. `re_supervisor / re_compiler / re_complete` 保持复用同一 claim ledger schema 和 `gate:claim-release` marker。

## 当前边界：四个能力不是“顶级 autonomous”结论

| 方向 | 现在能保证 | 不能夸大的部分 |
|---|---|---|
| 并行调度 | 能生成 `ReconParallelPlanV1`，能用 `--plan-json --plan-only` 离线预览 worker/merge/evidence contract，已有 provider-backed parallel runner 的运行证据字段。 | 还不是动态 autonomous scheduler；尚未完成跨入口统一调度、自动取消、工作窃取、实时重分片和 claim-aware merge 执行闭环。 |
| 长期上下文压缩 | `re_context`、`session_before_compact`、`session_compact`、context audit 已覆盖 context pack、resume contract、evidence summarization 和 bounded resume。 | 还不能宣称无限长期记忆；仍需精确按 contextPath/entryId 恢复、artifact hash 漂移校验、append-only resume ledger 和跨任务污染阻断。 |
| 失败自修复 | 已有 bounded retry、repair queue、hard-eval gaps、autofix/proof-loop 方向和 failure/repair schema。 | 还不是自动修好所有失败；plan-only 不执行 repair，真实修复仍需 failure signature 去重、attempt ledger、rollback criteria 和 passed-gate regression。 |
| 自动分工验证 | 已有 role contract、claim ledger、synthesizer reconciliation、score split、strict claim marker 和 runtime final path 阻断，能防止把 orchestration 成功写成平台 claim 成功。 | 独立子会话/compound runtime 仍需把 claim ledger 写入扩展到真实执行态；每个 proven/final claim 仍需 artifact sha256、JSON query、verifier pass、无 unresolved adversary challenge。 |

## 当前不做的事

在控制面硬化期间暂停以下工作：

- 真实平台 live benchmark。
- provider/model 攻击能力 dogfood。
- 抖音/小红书/B站等线上平台专项重跑。
- 用单次 benchmark 分数证明 agent 已达到完整 autonomous。

控制面完成标准不是“某次测试通过”，而是：并行计划可机读、上下文恢复可校验、失败修复有账本、分工结论可追溯到 artifact 和 claim。

## Machine-readable contracts update

The control plane now has two static contract audits:

```bash
npm run gate:autonomy-control
npm run gate:autonomous-contracts
```

They validate these contract families without running live benchmarks or providers:

- `ReconParallelPlanV1`: worker IDs, roles, objectives, commands, evidence contracts, merge keys, dependencies, artifact globs, limits, merge strategy.
- `ContextPackV2` and `ResumeContractV2`: exact context path/hash fields, cwd/session/mission/target scope fields, artifact hash policy, append-only compaction ledger, resume queue status and closure values.
- `FailureLedgerEventV1` and `RepairQueueItemV1`: failure signature, bounded attempts, exhausted/repair status, artifact hashes, rollback criteria, linked paused repair action.
- `DivisionValidationContractV1`, `RoleContractV1` and `ClaimLedgerEventV1`: mapper/verifier/adversary/synthesizer contract, handoff targets, claim ledger hash chain, evidence refs, challenge/resolution for required gaps, conflict policy.

新增 schema：

- `schemas/reverse-agent/context-resume-contract.schema.json`
- `schemas/reverse-agent/failure-repair-contract.schema.json`
- `schemas/reverse-agent/division-validation-contract.schema.json`

`hard-eval-control-plane.mjs` 的离线 failure/repair 输出也已补齐 `signature`、`artifactHashes`、`budget`、`rollback`、`expectedGates`、`rollbackCriteria`；role contract 已补齐 `ledgerPolicy`、`conflictPolicy`、`claimGatePolicy`、`handoffTargets`、`evidenceContract`。

This means Pi-RECON now has a usable professional control plane with machine-readable schemas, validators, strict claim release markers, and runtime final-path gates. Remaining work is limited to optional hardening such as independent sub-agent runtime and negative fixtures.

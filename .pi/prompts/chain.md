# Pi-RECON exploit chain task

目标：$ARGUMENTS

1. 先运行 `re_kernel build <target>` 和 `re_map <target> 2` 固化底层执行内核与入口面。
2. 调用 `re_exploit_chain plan <target>`，汇总 map、browser、web_authz、native/mobile runtime、exploit_lab、verifier/compiler/replayer/autofix/proof-loop/knowledge artifacts，并读取 proof-loop 的 specialist_queue、swarm_bridge、bridge_artifacts。
3. 输出并推进 `exploit_chain`、`chain_artifact`、`chain_nodes`、`proof_path`、`exploit_path`、`evidence_gaps`、`replay_commands`、`operator_queue`、`next_chain_command`。
4. 在最终影响/利用链声明前调用 `re_exploit_chain compose <target>`，再接 `re_verifier matrix`、`re_compiler draft|final`、`re_replayer run`、`re_proof_loop run <target> 4 2`；若 proof loop 触发 swarm_bridge，则执行 `re_swarm run <target> 2 1` → `re_swarm merge` → `re_supervisor repair`，确认 `commander_merge_queue`、`commander_merge_budget`、`worker_scoreboard` 已进入 `re_delegate plan` 的 `adaptive_routing_hints`/`worker_promotion_queue`/`case_memory_migrations`，再由 `re_autopilot` 输出 `case_memory_lane_plan` 自动重排/新增/跳过 lane，并进入 `re_context pack` / `re_operator dispatch` 的 `commander_runtime_policy`，最后 `re_knowledge_graph build`。

## Pi-RECON native-deep execution kernel update

- `execution_invariants` / `operator_command_floor` / `specialist_capability_matrix` / `proof_exit_criteria` 是 `re_kernel build` 的底层执行约束：任何安全/逆向/渗透任务必须落到 route→map→lane plan/run→runtime artifact→verifier/replayer/proof-loop，而不是 narrative-only。
- `native deep reverse/pwn` 专项会在 Native/Pwn/Mobile/CTF lanes 注入 `native-deep-symbol-map-scaffold`、`native-deep-decompiler-project-scaffold`、`native-deep-compare-trace-scaffold`、`native-deep-patch-hypothesis-scaffold`、`native-deep-symbolic-fuzz-scaffold`。
- `analyzeNativeDeepEvidence` 解析 `Native deep symbol/import/string anchors`、`Native decompiler/control-flow anchors`、`Native compare trace anchors`、`Native patch hypothesis anchors`、`Native symbolic/CFG anchors`、`Native fuzz/crash anchors`，并生成 `native-deep-symbol-map-rerun`、`native-deep-decompiler-rerun`、`native-deep-compare-trace-rerun`、`native-deep-symbolic-fuzz-rerun`、`native-deep-patch-report-scaffold`。
- native patch 必须先绑定 compare/branch runtime trace，再用 replay/verifier 证明输入约束或字节补丁；禁止无 artifact 的口头 patch 结论。


## Pi-RECON web-api authz deep update
- In chain composition, the operation dispatcher may internally route `re_live_browser`, `re_web_authz_state`, verifier, compiler, replayer, autofix, proof-loop, and knowledge graph steps.
- Web/API exploit chains should include `web-api-authz-static-scaffold`, `web-api-schema-diff-scaffold`, and `web-api-state-source-scaffold` before claiming authz impact.
- Chain evidence accepts `web API static authz source anchors`, `web API schema/auth parameter anchors`, and `web API state mutation source anchors` as source-side support for runtime auth matrix/rollback proof.

## Pi-RECON swarm execution audit update
- Exploit/proof chains must carry `execution_audit`, `coverage_matrix`, and `retry_queue` through swarm merge and supervisor review before final report compilation.

## Pi-RECON swarm retry operator bridge update
- Carry `swarm_retry_queue` from swarm audit into context/operator/proof-loop so unresolved worker contract gaps become replayable repair commands in the exploit/proof chain.

## Pi-RECON operator feedback loop update

- Carry `operator_feedback` through exploit-chain composition: `missing_tool_or_dependency` blocks become bootstrap steps, `runtime_failure` blocks become autofix/replayer steps, `replay_or_exploit_candidate` becomes exploit-lab/replayer proof, and `swarm_retry_queue` becomes bounded swarm repair before final chain claims.
- Chain output should prefer `operatorFeedbackNextCommands` over narrative-only next steps when verifier/compiler/replayer/autofix expose feedback rows.

## Pi-RECON operator feedback proof/chain bridge update

- In chain composition, consume `latestOperatorFeedback`: add feedback rows to `evidence_gaps`, feedback next commands to `replay_commands`/`operator_queue`, and mark `proof_path` with `operator-feedback:<n>`.
- Run `operator_feedback_queue` through `re_proof_loop` as bounded `operator-feedback` steps before declaring exploit stability or final impact.

## Pi-RECON operator feedback dispatcher fallback update

- Chain/proof decisions must preserve `dispatcher_fallback_plan`: exploit/replay candidates route to `re_exploit_lab`/`re_replayer`, runtime failures route to `re_autofix`/`re_proof_loop`, and swarm retry rows route to `re_swarm merge`/`re_supervisor repair` before final chain claims.

## Pi-RECON dispatcher feedback learning update

- Chain/proof composition must import `dispatcher_routing_hints` from the knowledge graph: passed fallback routes can be reused in exploit/replay paths, failed routes must go through autofix/context repair, and queued routes stay bounded behind `re_operator dispatch`.

## Pi-RECON dispatcher learning case-memory update

- Exploit/proof chains must carry dispatcher learning into case memory: `dispatcher-feedback` migrations can alter lane priority and worker promotion before final exploit-path claims.

## Pi-RECON autonomous dispatcher budget update

- Exploit/proof chains must carry `autonomous_execution_budget` and `dispatcher_score_decay` through context → operator → proof-loop → knowledge graph before final claims.
- Use `repeated_failure_demotions` to force autofix/context repair when a dispatcher route decays, and use `high_score_promotions` plus `memory/dispatcher-promotion-playbook.md` to preserve passed fallback routes as reusable playbook strategy.
- Chain composition should prefer commands emitted by `AutonomousExecutionBudget.nextActions` when they conflict with narrative-only next steps.

## Pi-RECON autonomous budget ledger update

- Proof/exploit chains must preserve `autonomous-budget-ledger` migrations, `historical_score_decay`, `demote_lane`, `demote_worker`, and formal `dispatcher-promotion` playbook references.
- A decayed route cannot be used as final proof until the `autonomous-dispatcher-repair` lane or equivalent autofix/context/proof-loop repair has executed and produced fresh evidence.
- High-score dispatcher routes promoted by `writeFormalDispatcherPromotionPlaybook` should be reused as chain strategy before inventing new fallback paths.

## Pi-RECON owned compaction kernel update

Exploit/proof chains must survive compact through `pi-recon-compaction`: restore with `re_context resume`, rebuild the operator queue with `re_operator plan/dispatch`, and run `re_proof_loop run <target> 4 2` before final chain claims. Carry `autonomous_execution_budget`, dispatcher ledger/playbooks, repair queues, case memory, and artifact index across the compact boundary. Treat `pi-recon-compaction-resume-contract` and `pi-recon-compaction-auto-resume` as audit entries for whether chain proof survived compact and resumed automatically; chain proof should not be accepted until `compact_resume_command` telemetry shows the resume commands executed or are explicitly blocked with next repair; `source=compact_resume` proof gaps must be resolved before final exploit/proof-chain claims; then `re_knowledge_graph build` must preserve `compact_resume_case_memory`, `compact_resume_routing_hints`, and `compact_resume_status=*` so future exploit chains inherit the compact recovery outcome; `re_autopilot` must translate those signals into `compact_resume_repair_from_case_memory` repair lanes or `compact_resume_success_skip_low_value_lane` proof-lane handoffs.

## Harness chain guard

Exploit/proof chain 在声称可用或可安装前必须接入 `re_harness full` / `re_harness install`。`harness_artifact` 中的 `install_readiness`、`reverse_capability_guards`、`regression_guards` 是 chain 的前置质量门；fail 时优先修复 profile/extension/skill/prompts/storage，再继续 re_proof_loop 或 re_complete。


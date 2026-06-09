Pi-RECON decision core task: $ARGUMENTS

运行 re_decision_core plan/tick/run，把 mission gates、active lane、tool posture、artifact posture、evidence priority 和 kernel/context 状态仲裁成 objective_stack、gate_pressure、decision_rules、operator_queue、operator_next_command 和 decision_artifact / executed_steps。tick 后按 operator_next_command 进入 run 模式执行 bounded operator step，run 后进入 re_proof_loop run <target> 4 2，自动闭合 verifier→compiler→replayer→autofix 证据链；若 verdict 为 partial/needs_repair，先产出 specialist_queue/swarm_bridge 并执行 re_delegate plan → re_swarm run → re_swarm merge → re_supervisor repair；supervisor 必须读取 swarm_artifact，把 worker_results/blocked/merge_digest 转成 commander_merge_queue、commander_merge_budget、worker_scoreboard，并让 re_delegate plan 生成 adaptive_routing_hints/worker_promotion_queue/case_memory_migrations，再由 re_autopilot 生成 case_memory_lane_plan 完成 lane reprioritize/add/skip，随后 re_context pack → re_operator dispatch（commander_runtime_policy/failure_budget）→ re_proof_loop run 回流，不停在 narrative-only。

验证锚点：`re_verifier matrix` 是 proof loop 的第一阶段；若只需要单步反证矩阵，也可以直接调用。

## Pi-RECON native-deep execution kernel update

- `execution_invariants` / `operator_command_floor` / `specialist_capability_matrix` / `proof_exit_criteria` 是 `re_kernel build` 的底层执行约束：任何安全/逆向/渗透任务必须落到 route→map→lane plan/run→runtime artifact→verifier/replayer/proof-loop，而不是 narrative-only。
- `native deep reverse/pwn` 专项会在 Native/Pwn/Mobile/CTF lanes 注入 `native-deep-symbol-map-scaffold`、`native-deep-decompiler-project-scaffold`、`native-deep-compare-trace-scaffold`、`native-deep-patch-hypothesis-scaffold`、`native-deep-symbolic-fuzz-scaffold`。
- `analyzeNativeDeepEvidence` 解析 `Native deep symbol/import/string anchors`、`Native decompiler/control-flow anchors`、`Native compare trace anchors`、`Native patch hypothesis anchors`、`Native symbolic/CFG anchors`、`Native fuzz/crash anchors`，并生成 `native-deep-symbol-map-rerun`、`native-deep-decompiler-rerun`、`native-deep-compare-trace-rerun`、`native-deep-symbolic-fuzz-rerun`、`native-deep-patch-report-scaffold`。
- native patch 必须先绑定 compare/branch runtime trace，再用 replay/verifier 证明输入约束或字节补丁；禁止无 artifact 的口头 patch 结论。


## Pi-RECON web-api authz deep update
- Treat the operation dispatcher as an execution kernel lane: it must route `re_live_browser`, `re_web_authz_state`, verifier, compiler, replayer, autofix, proof-loop, and knowledge graph steps before declaring a queue blocked.
- For Web/API work, require `web-api-authz-static-scaffold`, `web-api-schema-diff-scaffold`, and `web-api-state-source-scaffold` when route/source/schema authorization proof is thin.
- Promote `web API static authz source anchors`, `web API schema/auth parameter anchors`, and `web API state mutation source anchors` into follow-up reruns and proof-loop gaps.

## Pi-RECON swarm execution audit update
- Before accepting delegated worker output, inspect `execution_audit`, `coverage_matrix`, and `retry_queue`; missing contracts or blocked executions become bounded repair commands.

## Pi-RECON swarm retry operator bridge update
- Treat `swarm_retry_queue` as executable repair intent: prefer parsed retry `next=` commands in `re_operator dispatch` and `re_proof_loop run` before final reporting.

## Pi-RECON operator feedback loop update

- After `re_operator dispatch`, read `operator_feedback` before final reporting. Categories include `unresolved_target`, `dispatcher_gap`, `missing_tool_or_dependency`, `worker_retry_blocked`, `worker_retry_progress`, `runtime_failure`, `replay_or_exploit_candidate`, `strong_evidence`, `failure_budget_exhausted`, and `swarm_retry_queue`.
- Let `operatorFeedbackNextCommands` drive the next bounded action: bootstrap missing tools, replay/exploit candidates, autofix runtime failures, and run swarm retry commands before accepting a proof-loop verdict.

## Pi-RECON operator feedback proof/chain bridge update

- When `operator_feedback_queue` exists, route it through `re_proof_loop run` before accepting completion; `operator-feedback` steps should execute before broad specialist repair.
- `re_exploit_chain compose` must preserve `operator_feedback` in evidence gaps and operator queue so exploit-path decisions inherit dispatch failures, bootstrap needs, replay candidates, and swarm retry rows.

## Pi-RECON operator feedback dispatcher fallback update

- Treat `dispatcher_fallback_plan` as the command scheduler's repair map: missing tools first, then target/context repair, runtime/autofix, failure-budget proof-loop, swarm repair, exploit/replay, and verifier/compiler evidence closure.
- After each `re_operator dispatch`, inspect `operator_feedback_runtime` and prefer `operator_feedback_queue` commands before ordinary context queue items.

## Pi-RECON dispatcher feedback learning update

- Read `dispatcher_feedback_scoreboard` and `dispatcher_learning_hints` before choosing the next queue item: promote high-score passed commands, demote failed fallback routes, and retry queued routes with bounded `re_operator dispatch`.
- Keep `memory/dispatcher-feedback-board.md` and `re_knowledge_graph build` in the loop so dispatcher scoring becomes reusable command strategy rather than one-off telemetry.

## Pi-RECON dispatcher learning case-memory update

- Before autopilot or worker routing, treat `dispatcher_routing_hints` and `dispatcher_feedback_scoreboard` as case-memory migration inputs; promote high-score dispatcher routes, demote failed routes, and retry queued routes through bounded operator dispatch.
- `case_memory_lane_plan` may skip low-value lanes or add `case-memory-repair` based on `promote_dispatcher`, `demote_dispatcher`, and `retry_dispatcher` signals.

## Pi-RECON autonomous dispatcher budget update

- Before selecting the next action, read `autonomous_execution_budget`, `dispatcher_score_decay`, `repeated_failure_demotions`, and `high_score_promotions` from context/operator/proof/knowledge output.
- Treat `dispatcherScoreDecayRows` as the retry governor: failed or low-effective dispatcher routes go through `re_autofix plan` + `re_context pack`, while high-score routes go to `writeDispatcherPromotionPlaybook` / `memory/dispatcher-promotion-playbook.md` and `re_knowledge_graph build`.
- When case memory shows `Autonomous execution budget`, `Dispatcher score decay`, `Repeated failure demotions`, or `High-score promotions`, let `case_memory_lane_plan` reprioritize lanes instead of continuing a stale low-score queue.

## Pi-RECON autonomous budget ledger update

- Treat `memory/autonomous-budget-ledger.md` as the cross-turn execution governor: repeated `historical_score_decay`, `demote_worker`, or `demote_lane` rows outrank fresh low-confidence plans.
- When `autonomousLaneDemotionRows` or `applyAutonomousBudgetDemotions` creates `autonomous-dispatcher-repair`, switch to that lane and run its bounded `re_context pack` / `re_operator dispatch` / `re_proof_loop run` sequence before retrying the demoted lane.
- Prefer formal `dispatcher-promotion` playbooks from `memory/playbooks/index.md` when `writeFormalDispatcherPromotionPlaybook` has promoted a high-score route.

## Pi-RECON owned compaction kernel update

When context pressure or compact occurs, treat `pi-recon-compaction` as authoritative. First run `re_context resume`, then `re_operator plan`, bounded `re_operator dispatch`, and `re_proof_loop run <target> 4 2`; preserve `autonomous_execution_budget`, dispatcher score decay, repair queues, case_memory_lane_plan, and ledger/playbook paths from the compaction summary. If `pi-recon-compaction-resume-contract` has `verified=false`, repair context with `re_context pack` before ordinary planning. If `pi-recon-auto-resume` is injected, follow its bounded_resume_commands before selecting any unrelated action, then inspect `compact_resume_telemetry` for queued/done/blocked commands and proof_loop_entered; never accept `completion_status: ready` until compact resume telemetry has no queued/blocked commands; after proof-loop repair, run `re_knowledge_graph build` so `compact_resume_case_memory`, `compact_resume_routing_hints`, and `compact_resume_status=*` become reusable case-memory signals; then let `re_autopilot plan|run` consume them as `compact_resume_repair_from_case_memory` or `compact_resume_success_skip_low_value_lane` before ordinary lane selection.

## Harness decision guard

在 profile 修改、安装验证或完成审计前调用 `re_harness full`；安装后调用 `re_harness install`。若 `harness_artifact` 的 `install_readiness`、`reverse_capability_guards`、`regression_guards` 出现 fail，则 decision_core 必须把下一步改成修复 harness，而不是继续报告 ready。守住 compact_resume_case_memory、compact_resume_repair_from_case_memory、compact_resume_success_skip_low_value_lane、operator_command_floor、proof_exit_criteria、specialist_runtime_planner。


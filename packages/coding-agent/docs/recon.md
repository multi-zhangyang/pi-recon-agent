# REPI Kernel Profile

REPI includes a built-in reverse-engineering and pentest-oriented kernel profile. In this repository the recommended clean-room launcher is `repi`, which enables the profile and stores state under `~/.repi/agent` so it can coexist with normal upstream `pi`:

```bash
repi
repi --offline --help
repi --offline --list-models
```

The lower-level REPI flags are still available:

```bash
repi --recon
# alias:
repi --reverse-pentest
```

`--recon` is not just a prompt preset. It changes the runtime session wiring and installs a bottom-level execution contract: `refusal_to_execution` converts missing target/sample/credential/tool/context cases into `re_map`, `re_lane plan`, `fallback_commands`, `bootstrap plan`, a minimal repro script, or one precise gap question, and `operator_next_command_required` plus `operator_command_floor` keep every non-status turn tied to a concrete next command, tool call, artifact path, or repro command.

- sets thinking to `high` unless you explicitly choose another level
- replaces the base system prompt with the REPI execution model
- appends the REPI runtime protocol
- injects an inline extension factory before the agent starts
- registers reverse/pentest commands and LLM tools
- injects built-in skills and prompt templates even when no project `.repi` files exist
- persists REPI memory, executable mission lanes, mission blackboard, evidence ledger, and tool indexes under the active agent dir (`repi`: `~/.repi/agent/recon/`; raw `repi --recon`: `~/.repi/agent/recon/`)


## Execution-first false-refusal control

The kernel carries `authorized_task_bias`, `public_target_no_auto_refusal`, and `scope_gap_to_passive_mapping` as runtime contract markers, not just documentation. CTF/lab/owned/client-authorized/security-test context enters the execution chain by default. A public-looking hostname, brand, or production-like surface does not stop the task by itself; REPI first creates passive `re_map` evidence, route/auth baseline, live browser plan, `auth_context_gap`, `bounded_plan`, and `operator_queue`. If authorization context, accounts, window, or scope are incomplete, `authorization_context_missing` asks at most one path-changing question while still producing executable next commands.


## REPI auto-compaction threshold

REPI initializes `~/.repi/agent/settings.json` with an explicit top-tier harness policy instead of relying only on a fixed reserve-token buffer:

```json
{ "compaction": { "enabled": true, "triggerPercent": 85, "warningPercent": 80, "reserveTokens": 16384, "keepRecentTokens": 36000 } }
```

The runtime threshold is `compactionTriggerTokens = min(contextWindow * triggerPercent / 100, contextWindow - reserveTokens)`. Default upstream behavior without `triggerPercent` remains backward compatible: `contextWindow - reserveTokens`.

## Runtime resources

The built-in profile creates these resources on demand:

| Resource | Location | Purpose |
|---|---|---|
| Field journal | `~/.repi/agent/recon/memory/field-journal.md` | Reusable reverse/pentest observations |
| Case index | `~/.repi/agent/recon/memory/case-index.md` | Searchable memory anchors |
| Evolution log | `~/.repi/agent/recon/memory/evolution-log.md` | Agent improvement notes |
| Memory v3 events | `~/.repi/agent/recon/memory/events.jsonl` | Append-only `MemoryEventV1` hash chain written by `re_reflect write`, `re_memory append/evolve`, `re_replayer`, `re_autofix`, `re_proof_loop`, `re_complete`, high-value `re_lane run`, and `re_swarm run` worker writebacks |
| Memory v3 case memory | `~/.repi/agent/recon/memory/case-memory.jsonl` | `CaseMemoryV1` aggregated view keyed by case signature for cross-task reuse |
| Memory v5 transaction manifests | `~/.repi/agent/recon/memory/transactions/*.json` | `MemoryAppendTransactionV1` records prepared/committed append, repair-index, and snapshot operations under `.store.lock` |
| Memory v5 store report | `~/.repi/agent/recon/memory/store-report.json` | `re_memory verify` output with `hash_chain_ok`, `seq_ok`, `case_index_ok`, parse status, and repair commands |
| Memory v5 store snapshot | `~/.repi/agent/recon/memory/store-snapshot.json` | `re_memory snapshot` durable copy of events/case-memory plus verification metadata |
| Memory usefulness eval | `~/.repi/agent/recon/memory/usefulness-eval.json` | `re_memory eval` report with hit@1, hit@k, MRR, forbiddenLeakRate, forbiddenHitIds, and scenario-level recall evidence |
| Memory v3 retrieval report | `~/.repi/agent/recon/memory/retrieval-report.json` | Last `re_memory search-events` report with hit scores, reasons, quality, and hash-chain status |
| Memory v3 distillation report | `~/.repi/agent/recon/memory/distillation-report.json` | `re_memory distill` output with `MemoryDistilledPatternV1`, promoted patterns, and mandatory injection chain |
| Memory v3 pattern book | `~/.repi/agent/recon/memory/pattern-book.md` | Machine/human-readable `memory_pattern_book` with command templates, verifier rules, and worker routing hints |
| Memory v3 quarantine | `~/.repi/agent/recon/memory/quarantine.json` | `memory_contamination_quarantine` for cross-route/cross-target/contradicted/stale/failure-dominant cases |
| Memory v4 semantic index | `~/.repi/agent/recon/memory/semantic-index.json` | `MemorySemanticIndexEntryV1` rows with normalized tokens, command fingerprints, artifact refs, verifier refs, grade, action, and blockers |
| Memory v4 contradiction ledger | `~/.repi/agent/recon/memory/contradiction-ledger.jsonl` | `MemoryContradictionLedgerEntryV1` quarantine/contradiction rows that block planner injection |
| Memory v4 injection packet | `~/.repi/agent/recon/memory/injection-packet.json` | `mandatory_memory_injection_packet` consumed by `re_lane plan`; only artifact+verifier+non-quarantine+grade>=70 rows are executable |
| Memory v4 sedimentation report | `~/.repi/agent/recon/memory/sedimentation-report.json` | `MemorySedimentationReportV1` summary of index, contradictions, injection packet, and hard gates |
| Auto playbooks | `~/.repi/agent/recon/memory/playbooks/*.md` | Scored reusable playbooks distilled from bounded `run-auto` chains |
| Playbook index | `~/.repi/agent/recon/memory/playbooks/index.md` | Generated quality/age/status index used by `re_memory playbooks` |
| Playbook archive | `~/.repi/agent/recon/memory/playbooks/archive/` | Low-quality, stale, or over-capacity playbooks pruned by `re_memory prune-playbooks` |
| Mission blackboard | `~/.repi/agent/recon/mission/current.json` | Active task lanes, gates, and next actions |
| Evidence ledger | `~/.repi/agent/recon/evidence/ledger.md` | Runtime-first facts and verification records |
| Execution kernel artifacts | `~/.repi/agent/recon/evidence/kernel/*.md` | `re_kernel build|audit` execution_kernel artifacts with directive_stack, refusal_to_execution_rules, tool_call_policy, artifact_contract, stall_recovery, and execution_kernel_ready gate |
| Passive map artifacts | `~/.repi/agent/recon/evidence/maps/*.md` | Auto-captured target/workspace map: stat, manifests, routes/auth strings, binary candidates, URL baseline |
| Live browser artifacts | `~/.repi/agent/recon/evidence/browser/*.md` | `re_live_browser plan|run` browser/XHR/WS runtime artifacts with request_response_log, auth_matrix, IDOR/BOLA probes, WebSocket probes, replay_commands, and live_browser_ready gate |
| Web authz artifacts | `~/.repi/agent/recon/evidence/web-authz/*.md` | `re_web_authz_state plan|run` web_authz_state artifacts with principal_matrix, object_probes, state_machine, sequence_replay, ownership_checks, rollback_checks, runtime anchors, and web_authz_ready gate |
| Exploit lab artifacts | `~/.repi/agent/recon/evidence/exploit-lab/*.md` | `re_exploit_lab plan|run|bundle` exploit_lab artifacts with PoC inventory, environment pins, replay_matrix, flake_triage, bundle_manifest, stability anchors, and exploit_lab_ready gate |
| Mobile runtime artifacts | `~/.repi/agent/recon/evidence/mobile-runtime/*.md` | `re_mobile_runtime plan|run` mobile_runtime artifacts with device_matrix, apk_inventory, process_map, frida_hooks, native_trace, anti_debug_checks, runtime anchors, and mobile_runtime_ready gate |
| Native runtime artifacts | `~/.repi/agent/recon/evidence/native-runtime/*.md` | `re_native_runtime plan|run` native_runtime artifacts with binary_inventory, mitigation_matrix, loader_libc, symbol_map, gdb_trace, crash_plan, exploit_scaffold, runtime anchors, and native_runtime_ready gate |
| Lane run artifacts | `~/.repi/agent/recon/evidence/runs/*.md` | Auto-captured `re_lane run` scripts, stdout, stderr, exit status, parsed anchors, and follow-up commands |
| Attack graph artifacts | `~/.repi/agent/recon/evidence/graphs/*.md` | `re_graph build` mission graph with lanes/gates, map/run artifacts, evidence ledger nodes, tool-index gaps, `critical_path`, `gaps`, and `operator_next_actions` |
| Exploit chain artifacts | `~/.repi/agent/recon/evidence/chains/*.md` | `re_exploit_chain plan|compose` chain artifacts with `proof_path`, `exploit_path`, `evidence_gaps`, `replay_commands`, `operator_queue`, and `exploit_chain_ready` gate |
| Campaign artifacts | `~/.repi/agent/recon/evidence/campaigns/*.md` | `re_campaign plan` campaign graph with phases, pivots, evidence/tool gaps, and next commands |
| Operation artifacts | `~/.repi/agent/recon/evidence/operations/*.md` | `re_operation plan|run` operation queue and phase runner |
| Delegation artifacts | `~/.repi/agent/recon/evidence/delegations/*.md` | `re_delegate plan|merge` specialist worker packets, evidence contracts, adaptive_routing_hints, worker_promotion_queue, case_memory_migrations, and merge queues |
| Swarm artifacts | `~/.repi/agent/recon/evidence/swarms/*.md` | `re_swarm plan|run|merge` multi-specialist worker_runtime_packets plus run-mode worker_executions, worker_results, blocked rows, merge_digest, memory_swarm_writeback, parallel_groups, merge_protocol, collision_matrix, commander_next_actions, and merge-mode runtime digest retention |
| Worker child sessions | `.repi-harness/evidence/child-sessions/*` | `WorkerChildSessionRuntimeBatchV1` hard-eval artifacts: isolated `repi --recon` child session transcript/stdout/stderr hashes, provider runtime env refs, timeout/cancel, retryBudget, pool bridge, and claim validation |
| Supervisor artifacts | `~/.repi/agent/recon/evidence/supervisor/*.md` | `re_supervisor review|repair` worker/swarm critic output, swarm_artifact, repair queue, commander_merge_queue, and priority queue |
| Reflection artifacts | `~/.repi/agent/recon/evidence/reflections/*.md` | `re_reflect plan|write` reflection_cycle artifacts tied to field journal, evolution log, and playbooks |
| Context pack artifacts | `~/.repi/agent/recon/evidence/contexts/*.md` | `re_context pack|resume` context_pack artifacts with resume_brief, artifact_index, repair queue including commander_merge_queue, commander_merge_budget, worker_scoreboard, and next_operator_commands |
| Operator artifacts | `~/.repi/agent/recon/evidence/operators/*.md` | `re_operator plan|dispatch|verify|escalate` operator_queue artifacts with dispatcher_policy, verification_matrix, escalation_queue, and next_operator_command |
| Verifier artifacts | `~/.repi/agent/recon/evidence/verifiers/*.md` | `re_verifier check|matrix` verifier_matrix artifacts with assertions, evidence_bindings, counter_evidence, contradictions, and gaps |
| Compiler artifacts | `~/.repi/agent/recon/evidence/compilers/*.md` | `re_compiler draft|final` compiler_report artifacts with key_evidence_block, repro_commands, contradictions, gaps, and next_operator_queue |
| Replayer artifacts | `~/.repi/agent/recon/evidence/replayers/*.md` | `re_replayer plan|run` replay_matrix artifacts with exit codes, stdout/stderr hashes, blocked commands, and next replay actions |
| Autofix artifacts | `~/.repi/agent/recon/evidence/autofix/*.md` | `re_autofix plan|apply` repair artifacts with patch_queue, command_substitutions, bootstrap_queue, evidence_recapture_queue, and next_operator_queue |
| Proof loop artifacts | `~/.repi/agent/recon/evidence/proof-loops/*.md` | `re_proof_loop plan|run` proof_loop artifacts with verdict, gate_status, evidence_summary, specialist_queue, swarm_bridge, bridge_artifacts, executed_steps, next_proof_actions, and proof_loop_ready gate |
| Knowledge graph artifacts | `~/.repi/agent/recon/evidence/knowledge/*.md` | `re_knowledge_graph build|query` knowledge_graph artifacts with case_signatures, similarity_index, worker_routing_hints, worker_scoreboard, adaptive_routing_hints, worker_promotion_queue, compact_resume_case_memory, compact_resume_routing_hints, and command_strategy_hints |
| Tool index | `~/.repi/agent/recon/tools/tool-index.md` | Evidence-based local tool inventory |
| Orchestrator skill | `~/.repi/agent/recon/builtin/reverse-pentest-orchestrator/SKILL.md` | Built-in security workflow router |
| Prompt templates | `~/.repi/agent/recon/builtin/prompts/*.md` | `/reverse`, `/websec`, `/webauthz`, `/chain`, `/decision`, `/jsre`, `/pcap`, `/pwn`, `/cloud`, `/identity`, `/memory` |

## Commands and tools

`--recon` registers these slash commands:

```text
/re-route <task>
/re-kernel build|show|audit [target]
/re-decision plan|show|tick|run [target] [max-steps]
/re-live-browser plan|show|run [url] [timeout-ms]
/re-web-authz-state plan|show|run [url] [timeout-ms]
/re-exploit-lab plan|show|run|bundle [target] [runs] [timeout-ms]
/re-mobile-runtime plan|show|run [target] [packageName] [timeout-ms]
/re-native-runtime plan|show|run [target] [timeout-ms]
/re-chain plan|show|compose [target]
/re-tools show|refresh
/re-memory show|events|search|search-events|append|evolve|consolidate|distill|sediment|playbooks|prune-playbooks ...
/re-mission show|new|gate ...
/re-lane show|next|done|block|add|set|plan|run|run-auto ...
/re-map [target] [depth]
/re-auto [plan|run] [target] [max-auto-steps]
/re-evidence show|search|append ...
/re-graph build|show
/re-campaign plan|show [target]
/re-operation plan|next|run [target] [max-steps]
/re-delegate plan|show|merge [target]
/re-swarm plan|show|run|merge [target] [max-workers] [max-commands]
/re-supervisor review|show|repair [target]
/re-reflect plan|show|write [target]
/re-context pack|show|resume [target]
/re-operator plan|show|dispatch|verify|escalate [target] [max-steps]
/re-verifier check|show|matrix [target]
/re-compiler draft|show|final [target]
/re-replayer plan|show|run [target] [max-steps]
/re-autofix plan|show|apply [target]
/re-proof-loop plan|show|run [target] [max-steps] [replay-steps]
/re-knowledge-graph build|show|query [term]
/re-bootstrap plan|install ...
/re-complete audit|scaffold
/re-self-review
```

It also registers LLM-callable tools:

```text
re_route
re_kernel
re_decision_core
re_live_browser
re_web_authz_state
re_exploit_lab
re_mobile_runtime
re_native_runtime
re_memory
re_tool_index
re_mission
re_lane
re_map
re_autopilot
re_evidence
re_graph
re_campaign
re_operation
re_delegate
re_swarm
re_supervisor
re_reflect
re_context
re_operator
re_verifier
re_compiler
re_replayer
re_autofix
re_proof_loop
re_knowledge_graph
re_bootstrap
re_complete
```

The profile automatically routes security tasks during `before_agent_start`, injects mission lane queue, evidence, memory, tool-index, and completion-audit digests, captures passive map artifacts through `re_map`, builds an attack graph through `re_graph`, tracks repeated bash commands, plans/executes tool bootstrap through `re_bootstrap`, marks self-review checkpoints every 5 tool results, and records a compaction checkpoint before session compaction.


## Bootstrap and completion gates


Memory v5 makes long-term memory transactional before it becomes planner-actionable. `appendMemoryEvent` acquires `~/.repi/agent/recon/memory/.store.lock`, verifies `events.jsonl` parse/seq/prevHash/entryHash, writes a `MemoryAppendTransactionV1` manifest under `transactions/`, then atomically replaces `events.jsonl` and `case-memory.jsonl`; broken event chains block append instead of silently poisoning future planning. `re_memory verify` writes `store-report.json`, `re_memory repair-index` rebuilds `case-memory.jsonl` from the verified event chain, `re_memory snapshot` writes `store-snapshot.json` for cross-session recovery, and `re_memory eval` writes `usefulness-eval.json` with Memory usefulness eval metrics (`hitAt1`, `hitAtK`, `mrr`, `forbiddenLeakRate`, `forbiddenHitIds`). Replay, autofix, proof-loop, completion, reflection, manual memory, high-value `re_lane run`, and now `re_swarm run` worker results automatically write structured memory events, so successful runtime anchors, repairable failures, self-heal commands, verifier candidates, SubagentRuntimeManifestV1 rows, stdout/stderr hashes, claim ledger paths, structured claim merge paths, and worker routing hints survive compaction and future task planning. Swarm writeback rows are tagged `memory-swarm-writeback` and summarized in the `memory_swarm_writeback` formatter block. `re_memory events` shows recent structured rows, `re_memory search-events` writes `retrieval-report.json` and ranks by exact token match, Memory hybrid retrieval signals (`memory_semantic_hybrid_reuse`, `case-memory-hybrid`, `artifact-hybrid`), route/target match, `quality.confidence`, replay verification, reuse count, failure count, and decay. Route-scoped searches block cross-route command reuse, so authz/browser memory cannot accidentally inject pwn commands or the reverse. `re_lane run` also closes a Memory reuse feedback online loop: when a `memory-event:*` or `memory-sediment:*` command is executed, strong evidence appends a `memory_reuse_feedback_promote` event, while weak/nonzero evidence appends `memory_reuse_feedback_demote`; later retrieval folds case-level `reuseCount/failureCount/decay/replayVerified` into ranking and suppresses commands from failure-dominant cases. `re_memory consolidate` summarizes latest `case-memory.jsonl` rows. `re_memory distill` writes `distillation-report.json`, `pattern-book.md`, and `quarantine.json`: high-confidence replayed events become `command_template`, `verifier_rule`, and `worker_routing_hint` patterns; the mandatory injection chain is `retrieve -> rank -> inject -> execute -> verify -> feedback`; cross-route/cross-target/contradicted/stale/failure-dominant cases enter `memory_contamination_quarantine` and cannot become promoted patterns. `re_memory sediment` writes `semantic-index.json`, `contradiction-ledger.jsonl`, `injection-packet.json`, and `sedimentation-report.json`; `re_memory supervise` writes `supervisor-report.json` and `lifecycle-board.md`, converting sedimentation into promotion/demotion/quarantine/expire/merge/retain queues with `quarantine_overrides_promotion`, `merge_by_case_signature`, and `feedback_required_after_injection`; `re_lane plan` refreshes that packet and injects only artifact-sha256-backed, replay/verifier-backed, non-quarantined rows with `memory_sedimentation_grade>=70`, emitting `memory-sediment:<eventId>:<n>` commands ahead of weaker recalls. The write/shape contract is guarded by `schemas/reverse-agent/memory-event.schema.json`, `fixtures/reverse-agent/memory-event.fixture.json`, and `npm run gate:memory-contract`; utility is guarded by `npm run gate:memory-utility`; feedback behavior is guarded by `npm run gate:memory-feedback`; hybrid retrieval is guarded by `npm run gate:memory-hybrid`; Memory usefulness eval is guarded by `fixtures/reverse-agent/memory-usefulness.fixture.json` and `npm run gate:memory-usefulness`, covering authz/pwn hit@k, forbidden memory leakage, route isolation, and same-process and child-process concurrent append hash-chain pressure; distillation/quarantine behavior is guarded by `npm run gate:memory-distiller`; Memory v4 sedimentation behavior is guarded by `fixtures/reverse-agent/memory-sedimentation.fixture.json` and `npm run gate:memory-sedimentation`; Memory v5 store behavior is guarded by `fixtures/reverse-agent/memory-store.fixture.json` and `npm run gate:memory-store`, covering `hash_chain_verified_before_append`, transaction commit, `re_memory verify`, `re_memory repair-index`, `store-snapshot.json`, bad prevHash blocking, case index rebuild, and `memory_auto_writeback`; swarm worker writeback is guarded by `fixtures/reverse-agent/memory-swarm-writeback.fixture.json` and `npm run gate:memory-swarm-writeback`, covering `memory-swarm-writeback` event count, artifact capture, success/blocked outcomes, and plan/merge skip behavior; Memory Supervisor lifecycle governance is guarded by `schemas/reverse-agent/memory-supervisor.schema.json`, `fixtures/reverse-agent/memory-supervisor.fixture.json`, and `npm run gate:memory-supervisor`, covering report schema, lifecycle-board, promotion/demotion/quarantine/merge fixture, and runtime `re_memory supervise`.

`re_memory playbooks` generates `memory/playbooks/index.md` without moving files. `re_memory prune-playbooks` applies the maintenance policy (`minQuality`, `maxActive`, `maxAgeDays`) and moves low-quality, stale, or over-capacity playbooks to `memory/playbooks/archive/`.

`re_map` is the passive mapper gate: it runs a bounded local/target inventory, writes `evidence/maps/*.md`, appends an evidence ledger entry, and marks `passive_map_done`. Use it before expanding sideways so route files, auth/session strings, binary candidates, manifests, hashes, and URL headers are anchored in a single artifact. `re_lane plan` now consumes the latest map artifact: it adds `map-artifact-context`, records `map_reuse`, infers `map_inferred_target` when the user omitted a target, and hashes binary candidates parsed from the map.

`re_autopilot` / `/re-auto` is the bounded execution loop: `plan` shows the chain, while `run` creates/uses a mission, runs `re_map`, builds a lane command pack from the latest map and memory, emits `case_memory_lane_plan` from `case_memory_migrations` to reprioritize/add/skip lanes, emits a route/map/command-pack/tool-index-driven `bootstrap_plan`, derives an `execution_strategy`, executes the lane, runs bounded `[auto:*]` follow-ups, audits completion gates, and writes an autopilot field-journal checkpoint. Autopilot does not install packages by default; when tools are missing it first emits `fallback_commands` / skipped commands in `execution_strategy`, then prints `next_bootstrap_command` so the agent can deliberately run `/re-bootstrap plan|install ...` or choose an equivalent available tool.

`re_graph` / `/re-graph` is the engineering organization layer: it reads mission lanes/gates, latest passive map, lane run artifacts, evidence ledger and tool-index-derived gaps, writes `evidence/graphs/*.md`, and returns an `attack_graph` with `critical_path`, `gaps`, `operator_next_actions`, and `source_artifacts`. Use it after map/run/evidence updates and before widening scope so the next action is evidence-driven instead of ad hoc.

`re_lane` turns the mission blackboard into an executable queue: `next` selects work, `done` advances to the next lane and updates related gates, `block` records stuck lanes, and `add` creates ad-hoc subtasks. `plan` emits a lane-specific command pack for the active route and target and now searches `memory/playbooks/` plus `case-index.md` to merge similar historical commands, prioritizing higher `quality_score` playbooks that produced artifacts, anchors, follow-ups, and lane advances. `run` derives an `execution_strategy` from tool-index before execution, applies `fallback_commands` or skips commands whose tools are missing, then executes only commands that have concrete targets and no placeholders, writes a lane-run artifact, appends runtime evidence to the ledger, parses `tool repair anchors` and high-signal anchors such as addresses/compare symbols/routes/signing calls, emits an `evidence_quality` critic, queues `self_heal_commands` back into `[auto:*]` lane items when quality is thin, emits follow-up commands, and automatically advances the matching next lane when the run produced usable signal. `run-auto` then executes a bounded chain of `[auto:*]` follow-up commands already attached to active lanes, parses an `adaptive_decision` after every step, uses `evidence_quality` / `self_heal_commands` to continue the same lane, advance to the next lane, stop for bootstrap, or stop expansion, emits `multi_lane_plan` when repeated weak self-heal or stop decisions require lane repair, automatically adds or reprioritizes `tool-bootstrap`, `evidence-repair`, or `map-refresh`; `tool-bootstrap` emits `tool_bootstrap_closure`, refreshes tool-index, reports `missing_after_refresh` / `resumed_lane`, and resumes the original blocked lane once tools are closed; reports `adaptive_decisions` in the summary, and writes the successful chain into field journal, evolution log, and `memory/playbooks/` with score metadata, then refreshes/prunes the playbook index so future plans reuse strong chains instead of stale noise.

`re_lane plan` also invokes `specialist_runtime_planner` for top-tier reverse/pentest lanes: `browser/XHR/WS` capture, auth-diff, CDP-backed browser runtime artifact, request/response/WS/storage serialization, replay evaluator, route graph, auth matrix, IDOR/BOLA probe, authz state-machine, sequence replay, object ownership, and state rollback scaffolds for Web/API, `JS signing rebuild` hooks, observed normalizer, first-divergence, signed replay harness, and Node rebuild scaffolds for frontend signing, `pwn primitive` crash/GDB/cyclic offset/ROP-libc/local verifier/pwntools packs for exploit engineering, `exploit reliability/autopwn` packs with `exploit-poc-normalizer-scaffold`, `exploit-replay-matrix-scaffold`, `exploit-environment-pin-scaffold`, `exploit-flake-triage-scaffold`, and `exploit-artifact-bundle-scaffold`, `PCAP/DFIR` stream ranking/secret timeline/flow/object/carving/transform-chain packs for traffic and forensic artifacts, `Firmware/IoT rootfs` packs with `firmware-static-fingerprint-scaffold`, `firmware-extract-rootfs-scaffold`, `firmware-filesystem-config-secret-scaffold`, `firmware-service-surface-scaffold`, and `firmware-emulation-scaffold`, `agent prompt/tool boundary` packs with `agent-prompt-surface-map`, `agent-tool-boundary-scaffold`, `agent-memory-poisoning-scaffold`, `agent-injection-replay-harness`, and `agent-delegation-trace-scaffold`, `malware config/IOC` packs with `malware-static-triage-scaffold`, `malware-yara-capa-floss-scaffold`, `malware-ioc-config-scaffold`, and `malware-behavior-trace-scaffold`, `Cloud/K8s identity` identity/config/metadata/privilege-edge packs for cloud/container/K8s work, `Identity/AD graph` principal/credential/graph-edge packs for Windows/AD work, and `Frida/GDB trace` hook scaffolds for mobile/native runtime proof. These commands are still filtered through tool-index and `execution_strategy`, so missing tools produce fallback or bootstrap plans instead of blind execution.

`re_lane run` now includes a `tool repair analyzer` plus a `specialist evidence analyzer`: it parses specialist runtime transcripts into high-signal anchors and `targeted follow-ups` instead of treating stdout as opaque text. It recognizes `tool repair anchors`, `tool repair missing dependency anchors`, `browser/XHR/WS runtime anchors`, websocket endpoints, cookie/storage anchors, `browser CDP artifact anchors`, browser runtime artifact paths, `browser replay evaluator anchors`, `browser route graph anchors`, `browser auth matrix anchors`, `browser IDOR/BOLA probe anchors`, `browser authz state machine anchors`, `browser authz sequence replay anchors`, `browser authz object ownership anchors`, `browser authz state rollback anchors`, `JS signing rebuild anchors`, `crypto.subtle operation anchors`, `JS signing normalized artifact anchors`, `JS first-divergence anchors`, `JS signing replay harness anchors`, `pwn primitive crash/control anchors`, `pwn crash register anchors`, `pwn cyclic offset anchors`, `pwn ROP/libc chain anchors`, `pwn local verifier anchors`, and `pwn gadget anchors`, `Exploit PoC inventory anchors`, `PoC replay matrix anchors`, `Exploit environment pin anchors`, `Exploit flake triage anchors`, `Exploit artifact bundle anchors`, `PCAP/DFIR traffic flow anchors`, `PCAP stream ranking anchors`, `PCAP secret timeline anchors`, extracted PCAP artifacts, `PCAP transform chain anchors`, `Firmware image metadata anchors`, `Firmware extraction/rootfs anchors`, `Firmware config/secret anchors`, `Firmware service/web surface anchors`, `Firmware emulation/runtime anchors`, `Agent prompt surface anchors`, `Agent tool boundary anchors`, `Agent memory poisoning anchors`, `Agent injection replay anchors`, `Agent delegation trace anchors`, `Malware static triage anchors`, `Malware rule/capability anchors`, `Malware IOC/config anchors`, `Malware behavior trace anchors`, `Cloud identity anchors`, `Cloud/K8s runtime config anchors`, `Cloud metadata probe anchors`, `Cloud privilege edge anchors`, `Identity/AD principal anchors`, `Identity/AD credential usability anchors`, `Identity/AD graph edge anchors`, `Frida/GDB trace anchors`, and runtime hook return/value anchors, then queues tool-repair-matrix-scaffold/tool-repair-rerun/heal-tool-repair-matrix, browser auth-diff/capture reruns, browser CDP artifact reruns/reviews, browser replay evaluator reruns, browser route graph/auth matrix/IDOR-BOLA/authz-state reruns, browser authz state report, JS observed rebuilds, JS normalizer/first-divergence/replay harness reruns, pwn cyclic/GDB/offset/ROP-libc/local-verifier reruns, exploit poc/replay/env/flake/bundle/report reruns, PCAP stream ranking/secret timeline/follow-stream/object review/transform-chain, firmware-extract-rerun/firmware-config-secret-rerun/firmware-service-surface-rerun/firmware-report-scaffold, agent-prompt-surface-rerun/agent-tool-boundary-rerun/agent-memory-poisoning-rerun/agent-injection-replay-rerun/agent-delegation-trace-rerun/agent-security-report-scaffold, malware-static-triage-rerun/malware-ioc-config-rerun/malware-behavior-trace-rerun/malware-report-scaffold, cloud identity/runtime/metadata/privilege report reruns, identity-ad enum/credential/graph/report reruns, and Frida/GDB focused trace self-heal commands.

Examples:

```text
/re-lane plan control-flow ./license
/re-map ./license 3
/re-auto run ./license 1
/re-lane run triage ./challenge
/re-lane run-auto runtime-proof 2
/re-campaign plan ./license
/re-operation next ./license
/re-delegate plan ./license
/re-supervisor review ./license
/re-reflect write ./license
/re-context pack ./license
/re-operator dispatch ./license 1
/re-verifier check ./license
/re-lane plan identity .
/re-lane plan principals 10.0.0.5
/re-memory playbooks
/re-memory prune-playbooks
```

`re_bootstrap` turns the reverse-skill “missing tools → bootstrap → refresh tool-index” rule into an in-kernel tool. Use `plan` first to see exact commands, then `install` only for tools required by the active mission lane. After installation, REPI refreshes the tool index and updates the mission gate.

`re_complete` audits mission gates before a final claim. It checks route/memory/tool/passive-map/minimal-proof/evidence/repro/report/memory gates, evidence metadata, and journal/evolution state. `scaffold` writes a report draft under `~/.repi/agent/recon/reports/`.

## Project profile coexistence

A project or global `.repi/extensions/reverse-pentest-core.ts` profile can still exist. `repi` avoids those collisions by default with `--no-extensions --no-skills --no-prompt-templates --no-approve --no-context-files`; raw `repi --recon` also keeps the built-in inline kernel profile and suppresses conflicts from the legacy file-based REPI extension where possible.

## Examples

```bash
repi "分析这个 ELF 的许可证校验逻辑"
repi /reverse ./challenge
repi /websec http://127.0.0.1:3000
repi /jsre "抓包里的 sign 参数"
repi /cloud "K8s serviceaccount metadata privilege"
repi /identity "AD kerberos ldap bloodhound"
```


## Web Authz State 授权状态机层

`/re-web-authz-state plan|show|run` / `re_web_authz_state` 面向 Web/API authorization、IDOR、BOLA、JWT/session、object ownership 和 state-machine 任务建立专用授权状态捕获层。它输出 `web_authz_state` / `web_authz_artifact`、`route_inventory`、`principal_matrix`、`object_probes`、`state_machine`、`sequence_replay`、`ownership_checks`、`rollback_checks`、`runtime_anchors`、`replay_commands`、`capture_script`、`web_authz_next_actions` 与 `next_web_authz_command`；artifact 写入 `evidence/web-authz/*.md` 并闭合 `web_authz_ready`。默认读取型 principal/object/sequence 观测；变更型 rollback 只有设置 `REPI_AUTHZ_MUTATE=1` 和 restore fixtures 时才执行。

## Live browser/XHR/WS runtime 层

`/re-live-browser plan|show|run` / `re_live_browser` 面向 HTTP(S) 目标生成或执行浏览器运行时捕获。它输出 `live_browser` / `browser_artifact`、`runtime_matrix`、`request_response_log`、`runtime_anchors`、`auth_matrix`、`idor_bola_probe_templates`、`websocket_probes`、`replay_commands`、`capture_script`、`browser_next_actions` 与 `next_browser_command`；artifact 写入 `.repi/evidence/browser/*.md` 并闭合 `live_browser_ready`。`run` 模式优先使用 Playwright，缺失时自动降级到 Node fetch baseline。

## Exploit Lab 稳定化层

`/re-exploit-lab plan|show|run|bundle` / `re_exploit_lab` 面向 exploit/PoC/autopwn 任务建立稳定化实验室。它输出 `exploit_lab` / `exploit_lab_artifact`、`lab_matrix`、`poc_inventory`、`environment_pins`、`replay_matrix`、`flake_triage`、`bundle_manifest`、`stability_anchors`、`lab_commands`、`lab_next_actions` 与 `next_lab_command`；artifact 写入 `.repi/evidence/exploit-lab/*.md` 并闭合 `exploit_lab_ready`。`run` 模式用本地 Python harness 或 `REPI_EXPLOIT_CMD` 做 bounded 多次 replay，记录 exit、duration、stdout/stderr SHA256、success_rate、stable/flake 结论和 bundle manifest。



## Mobile Runtime 动态逆向层

`/re-mobile-runtime plan|show|run` / `re_mobile_runtime` 面向 APK/Android/mobile reverse 任务建立 ADB/Frida/GDB 运行时捕获层。它输出 `mobile_runtime` / `mobile_runtime_artifact`、`device_matrix`、`apk_inventory`、`process_map`、`hook_plan`、`frida_hooks`、`native_trace`、`anti_debug_checks`、`runtime_anchors`、`replay_commands`、`capture_script`、`mobile_next_actions` 与 `next_mobile_command`；artifact 写入 `evidence/mobile-runtime/*.md` 并闭合 `mobile_runtime_ready`。`run` 默认只做观测和 hook 模板生成；需要真实 attach 时显式设置 `REPI_MOBILE_ATTACH=1`，并记录 Java crypto/String/native compare/anti-debug anchors。


## Native Runtime / Pwn Harness 动态层

`/re-native-runtime plan|show|run` / `re_native_runtime` 面向 ELF/SO/Pwn/native reverse 任务建立 GDB/Pwn 工程运行时捕获层。它输出 `native_runtime` / `native_runtime_artifact`、`binary_inventory`、`mitigation_matrix`、`loader_libc`、`symbol_map`、`crash_plan`、`gdb_trace`、`breakpoint_plan`、`exploit_scaffold`、`runtime_anchors`、`replay_commands`、`capture_script`、`native_next_actions` 与 `next_native_command`；artifact 写入 `evidence/native-runtime/*.md` 并闭合 `native_runtime_ready`。`run` 默认只做观测和 GDB/pwntools 模板生成；需要真实 GDB 执行时显式设置 `REPI_NATIVE_RUN=1` 和可选 `REPI_NATIVE_ARGS`，并记录 crash/register/libc/loader anchors。



## Decision Core 决策内核层

`/re-decision plan|show|tick|run` / `re_decision_core` 读取 mission gates、active lane、tool posture、artifact posture、evidence priority、execution kernel 与 context/operator/verifier/compiler/replayer/autofix/proof-loop/knowledge artifacts，输出 `decision_core` / `decision_artifact`、`objective_stack`、`gate_pressure`、`evidence_priority`、`tool_posture`、`artifact_posture`、`decision_rules`、`operator_queue`、`decision_next_actions`、`operator_next_command` 与 `next_decision_command`；artifact 写入 `.repi/evidence/decisions/*.md`，同时写入 `memory/decision-core.md` 并闭合 `decision_core_ready`。当下一步不清、上下文恢复、关键 artifact 更新或出现 narrative-only 倾向时，先 `re_decision_core tick <target>` 生成队列，再 `re_decision_core run <target> 1` bounded dispatch，最后进入 `re_proof_loop run <target> 4 2`。

## Exploit Chain 漏洞/利用链编排层

`/re-chain plan|show|compose` / `re_exploit_chain` 将 map、browser/XHR/WS、web_authz、native/mobile runtime、exploit_lab、verifier/compiler/replayer/autofix/proof-loop/knowledge artifacts 编排成 `exploit_chain` / `chain_artifact`，输出 `chain_nodes`、`chain_edges`、`proof_path`、`exploit_path`、`evidence_gaps`、`replay_commands`、`operator_queue`、`chain_next_actions` 与 `next_chain_command`；artifact 写入 `evidence/chains/*.md` 并闭合 `exploit_chain_ready`。

## Campaign graph

`/re-campaign plan [target]` / `re_campaign plan` 将单 lane 升级为跨域 campaign graph。它消费 mission、passive map、attack graph、lane run artifacts、evidence ledger、tool-index gaps，生成 `campaign_graph` 与 `campaign_artifact`，列出 `phases`、`pivot_candidates`、`evidence_gaps`、`tool_gaps`、`operator_next_actions`、`next_bootstrap_command`，并闭合 `campaign_plan_ready`。

## Operation queue

`/re-operation plan|next|run [target] [max-steps]` / `re_operation` 消费 `campaign_graph` / `campaign_artifact`，输出 `operation_queue` 与 `operation_artifact`。它把 phases 派生成 `phase_runner` steps，记录 `executed_steps`、`blocked`、`operator_next_actions`、`next_operation_command`，并闭合 `operation_queue_ready`。

## Specialist delegation

`/re-delegate plan|show|merge [target]` / `re_delegate` 消费 `operation_queue` / `operation_artifact` 与最新 `worker_scoreboard`，输出 `delegation_plan` 与 `delegation_artifact`。它把 operation steps 按 Web/Auth、Identity、Cloud、Pwn、Firmware/DFIR、AgentSec、Malware、Reporting 等 worker 拆分为 `worker_packets`，记录 `merge_queue`、`specialist_coverage`、`worker_scoreboard`、`adaptive_routing_hints`、`worker_promotion_queue`、`case_memory_migrations`、`evidence_contract`、`handoff`、`next_delegate_command`；低分 worker 自动补 evidence-repair/negative-control/replay 路由，高分 pass worker 推入 playbook promotion，并闭合 `delegation_packets_ready`。

## Swarm multi-agent orchestration

`/re-swarm plan|show|run|merge [target] [max-workers] [max-commands]` / `re_swarm` consumes `delegation_plan` / `delegation_artifact` and emits `swarm_plan`, `swarm_artifact`, `worker_runtime_packets`, run-mode `worker_executions`, `worker_results`, `blocked`, `merge_digest`, `memory_swarm_writeback`, plus `parallel_groups`, `merge_protocol`, `collision_matrix`, `evidence_contract`, `commander_next_actions`, and `next_swarm_command`; it closes `swarm_plan_ready`, writes each executed worker into MemoryStoreV5 as `memory-swarm-writeback` with SubagentRuntimeManifestV1/stdout/stderr/toolCallDigest/claim artifact refs, writes `memory/swarm-run-board.md` in run mode, and in merge mode reads the latest run artifact so runtime `workerResults` / `blocked` / `mergeDigest` survive into `memory/swarm-board.md` without duplicating long-term memory rows.

Worker runtime hard-eval now has two layers: `WorkerRuntimePoolV1` (`npm run gate:worker-runtime-pool`) validates concurrency/resource/timeout/retry/claim-aware merge semantics, while `WorkerChildSessionRuntimeBatchV1` (`npm run gate:worker-child-session`) validates the optional independent child-session/provider runtime contract. Child sessions must launch through `repi --recon` with an isolated `.repi` home, provider credentials as env refs, update/telemetry disabled, transcript/stdout/stderr hashes, timeout/cancel, retryBudget, pool bridge, and claim ledger validation.

Structured claim merge is the final-promotion layer: `StructuredClaimMergeV1` (`npm run gate:structured-claim-merge`) requires final pass claims to bind artifact sha256, JSON query, verifier pass, resolved adversary challenge, resolved conflict table, winner evidence, and loser downgrade. Runtime `re_swarm` now derives `*-structured-claim-merge.json` from `ClaimLedgerEventV1`; `re_compiler final` and `re_complete audit` block on `structuredClaimMergeStatus=blocked` / `status=blocked_by_structured_claim_merge`, so worker text summaries or orchestration success cannot become final claims without evidence.

## Supervisor critic

`/re-supervisor review|show|repair [target]` / `re_supervisor` 消费 `delegation_plan` / `delegation_artifact` 与最新 `swarm_artifact`，输出 `supervisor_review` 与 `supervisor_artifact`。它对 `worker_packets` 和 swarm runtime 做 score/verdict/conflicts/evidence_gaps/repair_actions 评估，生成 `swarm_artifact`、`conflict_matrix`、`repair_queue`、`commander_merge_queue`、`commander_merge_budget`、`worker_scoreboard`、`priority_queue`、`next_supervisor_command`；`commander_merge_queue` 将 `worker_results` / `blocked` / `merge_digest` 推入 `re_context pack`、`re_operator dispatch`、`re_proof_loop run`，并写出 operator 可消费的 `commander_runtime_policy`，闭合 `supervisor_review_ready`。

## Reflection/evolution 闭环

`/re-reflect plan|show|write` / `re_reflect` 消费 `supervisor_review` / `supervisor_artifact`，输出 `reflection_cycle` 与 `reflection_artifact`。`write` 模式将 lessons、failure_patterns、reuse_rules、repair_playbook 写入 field journal、evolution log 和 `.repi/memory/playbooks/*.md`，并闭合 `reflection_memory_ready`。

## Context/resume pack 闭环

`/re-context pack|show|resume` / `re_context` 消费 mission blackboard、evidence ledger、artifact_index、supervisor/reflect 结果、tool digest 与 memory tail，输出 `context_pack` 与 `context_artifact`。它把 `resume_brief`、`repair_queue`（含 supervisor 的 `commander_merge_queue`）、`commander_merge_budget`、`worker_scoreboard`、`reflection_reuse_rules`、`next_operator_commands` 和 `next_context_command` 固化到 `~/.repi/agent/recon/evidence/contexts/*.md`，并闭合 `context_pack_ready`，用于压缩、重启、handoff 后恢复连续逆向渗透作战。`ContextPackV2` / `ResumeContractV2` 现在包含 `createdAt`、`sessionId`、`cwd`、`workspaceRoot`、`resumeContract`、`contextSha256` 和 required artifact hash contract；MemoryStoreV5 / sedimentation 关键文件（`memory_events`、`memory_case_memory`、`memory_store_report`、`memory_store_snapshot`、`memory_usefulness_eval`、`memory_distillation_report`、`memory_injection_packet`、`memory_sedimentation_report`）存在时会作为 required artifact 检查，resume 时发生 drift 会 blocked。

Compact/resume chain hard-eval is covered by `npm run gate:compact-resume-chain`: it validates cross-session exact resume against `ContextPackV2` / `ResumeContractV2`, `contextSha256`, required artifact hashes, target/workspace/branch scope, append-only `compaction-resume-ledger.jsonl` `prevHash/entryHash`, queued→running→done resume transitions, proof-loop telemetry, and negative cases for drift, duplicate idempotency, invalid transitions, and exhausted/open closures. Runtime schema hard-eval is covered by `npm run gate:context-runtime-schema`: it creates a temporary REPI home, actually runs `re_mission new → re_map → re_memory verify/sediment → re_context pack → re_context resume`, parses the context artifact JSON, and verifies `contextSha256`, `resumeContract.contextSha256`, required memory artifact hashes, and closed `exactResumeVerification`. Runtime completion audit also verifies the compaction resume ledger before final completion.

## Operator queue 调度闭环

`/re-operator plan|show|dispatch|verify|escalate` / `re_operator` 消费 `context_pack` / `context_artifact` 中的 `next_operator_commands`，输出 `operator_queue` 与 `operator_artifact`。它按 `dispatcher_policy` 对 bootstrap/tool-index、map/plan、runtime/graph、campaign/operation/delegate/swarm、supervisor/reflect、context/memory、verifier/compiler、replayer/autofix、proof-loop、knowledge-graph、completion 分层排序，支持 bounded `dispatch`、`commander_runtime_policy`、`commander_dispatch_report`、`verification_matrix`、`escalation_queue`、`next_operator_command`，并在 commander failure_budget 耗尽时停止派发、保留 retry queue，闭合 `operator_queue_ready`。

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

`/re-proof-loop plan|show|run` / `re_proof_loop` 把 `re_verifier matrix`、`re_compiler draft|final`、`re_replayer run`、`re_autofix plan|apply`、`re_knowledge_graph build` 和 `re_complete audit` 串成 bounded proof loop。输出 `proof_loop` / `proof_loop_artifact`、`verdict`、`gate_status`、`evidence_summary`、`specialist_queue`、`swarm_bridge`、`bridge_artifacts`、`steps`、`executed_steps`、`next_proof_actions` 与 `next_proof_command`；当 verdict 为 `partial`/`needs_repair` 时把 verifier/compiler/replayer/autofix/gate gap 分类为 web-authz、mobile-runtime、native-runtime、pwn-exploit、firmware-dfir、cloud、identity、agentsec、malware、reporting 或 general 专项 worker，并生成/执行 `re_delegate plan` → `re_swarm run` → `re_swarm merge` → `re_supervisor repair` 桥接；supervisor 再把 `commander_merge_queue` 注入 context/operator/proof-loop；artifact 写入 `.repi/evidence/proof-loops/*.md` 并闭合 `proof_loop_ready`。在 `re_decision_core run` 或 `re_operator dispatch` 后优先用 `re_proof_loop run <target> 4 2` 关闭 verifier→compiler→replayer→autofix 证据链。

## Knowledge graph 长期知识图谱闭环

`/re-knowledge-graph build|show|query` / `re_knowledge_graph` 汇总 `.repi/evidence/*` 下的 map、browser、run、attack_graph、campaign、operation、delegation、supervisor、reflection、context、operator、verifier、compiler、replayer、autofix artifacts，生成 `knowledge_graph` 与 `knowledge_artifact`。输出包含 `case_signatures`、`artifact_nodes`、`high_value_edges`、`similarity_index`、`worker_routing_hints`、`worker_scoreboard`、`adaptive_routing_hints`、`worker_promotion_queue`、`compact_resume_telemetry`、`compact_resume_case_memory`、`compact_resume_routing_hints`、`command_strategy_hints` 和 `next_knowledge_command`，同时写入 `memory/knowledge-graph-index.md` 并闭合 `knowledge_graph_ready`，用于跨任务迁移和相似案例检索。

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

## REPI owned compaction kernel update

Built-in REPI handles `session_before_compact` as a first-class compaction provider. It returns a `repi-recon-compaction` summary/details object, writes a `repi-recon-compaction-checkpoint`, and embeds the `context_path`, `re_context resume`, bounded `re_operator plan/dispatch`, `re_proof_loop run <target> 4 2`, `autonomous_execution_budget`, dispatcher score decay, repair queues, ledger/playbook paths, case memory, and artifact index. Resume logic should consume this RECON contract before relying on generic REPI compact text. After `session_compact`, REPI appends `repi-recon-compaction-resume-contract`, verifies fromExtension/details/context_path/resume/operator/proof-loop coverage, and updates the `compaction_resume_contract_ready` gate. A verified contract appends `repi-recon-compaction-auto-resume` and injects a `repi-recon-auto-resume` custom message with `triggerTurn` to run one bounded resume turn. `repi-recon-compaction-resume-telemetry` persists `compact_resume_command` queued/done/blocked state, proof-loop entry, output hashes, and gate status in `memory/compaction-auto-resume-board.md`; `re_operator` imports it as `compact_resume_telemetry` / `compact_resume_queue`; `re_proof_loop` turns unresolved rows into `source=compact_resume` gaps, and `re_complete audit` treats queued/blocked resume commands, missing proof-loop entry, or compaction resume ledger hash drift as blockers. `re_knowledge_graph build` also promotes the telemetry into `compact_resume_case_memory`, `compact_resume_routing_hints`, and `compact_resume_status=*` signatures so compact recovery success/failure affects future case-memory routing; `re_autopilot plan|run` consumes those rows through `compactResumeCaseMemoryCommands`, creating `compact_resume_repair_from_case_memory` lanes for queued/blocked recovery or `compact_resume_success_skip_low_value_lane` handoffs after proof-loop success.

## Harness 自检与安装就绪

- `re_harness` / `/re-harness quick|full|install|show` 写入 `harness_artifact`，输出 `install_readiness`、`reverse_capability_guards`、`regression_guards`、registered tools/commands、存储可写性和 next_harness_command。
- `full` 用于每次 profile/extension/prompt/skill 修改后的回归；`install` 用于全局安装后的硬检查；`show` 读取最近 harness artifact。
- `reverse_capability_guards` 覆盖 native/web authz/mobile/exploit/proof loop/autopilot/compact/case-memory，明确守住 re_native_runtime、re_web_authz_state、re_proof_loop、compact_resume_case_memory、operator_command_floor、proof_exit_criteria、specialist_runtime_planner 等关键标记。

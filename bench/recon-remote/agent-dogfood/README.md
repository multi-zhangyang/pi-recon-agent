# Agent dogfood benchmark

Runs the actual REPI agent (`./pi-test.sh --recon`) against the latest remote benchmark evidence. This is the harness for proving the agent can call a real provider/model, use tools, read evidence, run hard-score, understand the current `same-window-live` frontier, and produce a platform-specific reverse/pentest roadmap instead of relying on external manual analysis.

## Usage

```bash
RECON_AGENT_PROVIDER=openai RECON_AGENT_MODEL=gpt-4.1 \
  node bench/recon-remote/agent-dogfood/run.mjs
```

or:

```bash
node bench/recon-remote/agent-dogfood/run.mjs openai gpt-4.1
```

For the harder multi-agent gate:

```bash
RECON_AGENT_PROVIDER=openai RECON_AGENT_MODEL=gpt-4.1 \
  node bench/recon-remote/agent-dogfood/parallel-run.mjs
```

`parallel-run.mjs` launches four real `./pi-test.sh --recon` workers at the same time, then runs a sequential synthesizer that must reconcile their disagreements:

| Role | Purpose |
|---|---|
| `mapper` | Map decisive Bilibili/Xiaohongshu/Douyin evidence and separate strong proof from weak inference. |
| `verifier` | Execute `node bench/recon-remote/hard-score.mjs` and verify concrete artifact fields. |
| `adversary` | Attack the benchmark for stale verdicts, indirect proof, and self-delusion. |
| `planner` | Design the next hardest benchmark with commands, gates, invariants, compact/context needs, and rollback criteria. |
| `synthesizer` | Read worker outputs, resolve mapper/verifier/adversary/planner conflicts, and downgrade unsupported claims. |

The parallel gate is intentionally stricter than the single-agent run: every role must call the model, use tools, cite `.repi-harness/evidence/remote/...` artifacts, cover `same-window-live`, Bilibili WBI, Xiaohongshu `x-s`, and Douyin `a_bogus`, emit the standard report sections, overlap in wall-clock time for the worker phase, and pass synthesizer conflict reconciliation.

## Offline plan ingestion: `--plan-json` and `--plan-only`

`parallel-run.mjs` can also consume a `ReconParallelPlanV1` manifest produced by
`frontier-orchestrator --plan --json --shards=N`. This mode is for static
control-plane integration checks, not for live/provider benchmarking.

Generate a plan:

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs \
  --plan --json --strategy=balanced --shards=3 > /tmp/recon-parallel-plan.json
```

Preview the normalized workers without launching anything:

```bash
node bench/recon-remote/agent-dogfood/parallel-run.mjs \
  --plan-json /tmp/recon-parallel-plan.json --plan-only --json
```

`--plan-json <path>` accepts either a direct `ReconParallelPlanV1` object or an
orchestrator JSON root containing `parallelPlan`. In plan-only mode the runner:

- reads and normalizes `workers[]`, `merge`, `evidenceContract`, `mergeKeys`,
  `artifactGlobs`, `dependencies`, and `limits`;
- does not require `RECON_AGENT_MODEL`, provider credentials, or provider base
  URLs;
- does not create `.repi-harness/evidence/remote/agent-parallel-dogfood/<timestamp>/`;
- does not run hard-score, hard-eval, worker agents, synthesizer agents, browser
  automation, or real-platform checks;
- prints a `pi-recon-parallel-plan-preview` object on stdout for CI/static review.

Supplying `--plan-json` without `--plan-only` is the provider-backed execution
path for later dogfood runs: workers are derived from the plan instead of the
built-in mapper/verifier/adversary/planner roles. Treat that as a separate live
or model-calling phase.

## Control-plane boundaries

The parallel dogfood harness now documents the control-plane surface, but it
does not by itself prove a complete autonomous red-team agent:

| Capability | Current offline boundary |
|---|---|
| Parallel scheduling | `ReconParallelPlanV1` can describe worker packets and plan-only can verify ingestion. It is not yet a full autonomous scheduler with dynamic work stealing, cancellation, or platform-aware replanning. |
| Long-context compaction | Prompts and summaries keep evidence paths, merge keys, and decisive lines compact. Durable `ContextPackV2` resume validation remains a separate control-plane track. |
| Failure self-repair | Role retries and hard-eval repair queues are represented, but plan-only does not execute repairs or prove rollback-safe autofix. |
| Automatic division validation | Worker contracts and synthesizer reconciliation separate orchestration success from platform claim success. Final claims still need artifact-backed claim-ledger validation before being reported as platform success. |

The parallel runner also executes `scripts/reverse-agent/hard-eval-control-plane.mjs . --json` after hard-score. This injects a claim-level score split into the shared worker context and final artifact:

- `hardEvalControl.scores.orchestration.score` for multi-agent runtime/coordination proof.
- `hardEvalControl.scores.platformRequired.score` for latest same-window required B站/小红书/抖音 claims.
- `hardEvalControl.platformGaps[]`, `failures[]`, and `repairQueue[]` for gaps that must not be hidden behind a successful orchestration run.

If orchestration passes but required platform claims still have gaps, the parallel verdict becomes `agent-parallel-dogfood-confirmed-platform-gaps`; this is a successful orchestration artifact, not a platform-success claim.

The parallel result also records a runtime audit so the dogfood proof is not just text:

- child PID and `/proc/<pid>` command-line digest per worker/synthesizer;
- wall-clock plus monotonic-clock timing and drift;
- session JSONL file digests;
- tool-call and tool-result counts, byte totals, error counts, and result digests;
- redacted provider/model environment presence;
- `--offline`, `--no-env`, mock/fake/stub environment detection.

## Environment

| Variable | Default | Purpose |
|---|---:|---|
| `RECON_AGENT_PROVIDER` | `aigateway` | Pi provider name passed to `--provider`. |
| `RECON_AGENT_MODEL` | unset / `ANTHROPIC_MODEL` | Model passed to `--model`. Required unless supplied as argv. |
| `RECON_AGENT_THINKING` | `low` | Thinking level passed to Pi. |
| `RECON_AGENT_TOOLS` | `read,grep,find,ls,bash` | Tool allowlist for the dogfood run. |
| `RECON_AGENT_TIMEOUT_MS` | `240000` | Overall agent timeout. |
| `RECON_AGENT_CMD` | `./pi-test.sh` | Agent command to execute. |
| `RECON_AGENT_EXTRA_ARGS` | unset | Extra Pi CLI args. |
| `RECON_AGENT_PROMPT` | built-in | Override dogfood prompt. |
| `RECON_PARALLEL_ROLES` | all roles | Optional comma-separated subset for `parallel-run.mjs`, e.g. `mapper,verifier`. |
| `RECON_PARALLEL_MAX_TOOL_CALLS` | `4` | Prompt-level per-worker cap to keep parallel roles bounded. |
| `RECON_PARALLEL_MAX_WORDS` | `500` | Prompt-level per-worker output cap. |
| `RECON_SYNTHESIZER` | `1` | Run the sequential conflict-synthesizer agent; set `0` only for debugging partial worker lanes. |
| `RECON_ROLE_RETRIES` | `1` | Retry flaky role/model runs before judging the strict gate. |
| `RECON_PARALLEL_PLAN_JSON` | unset | Same as `--plan-json <path>`; reads a `ReconParallelPlanV1` or an orchestrator JSON root containing `parallelPlan`. |
| `RECON_PARALLEL_PLAN_ONLY` | unset | Same as `--plan-only`; prints a normalized plan preview and exits without provider/model execution. |

## Output

```text
.repi-harness/evidence/remote/agent-dogfood/<timestamp>/
artifact.md
result.json
stdout.txt
stderr.txt
sessions/*.jsonl
```

Parallel artifacts are written to:

```text
.repi-harness/evidence/remote/agent-parallel-dogfood/<timestamp>/
artifact.md
result.json
mapper.stdout.txt / mapper.stderr.txt
verifier.stdout.txt / verifier.stderr.txt
adversary.stdout.txt / adversary.stderr.txt
planner.stdout.txt / planner.stderr.txt
synthesizer.stdout.txt / synthesizer.stderr.txt
worker-summary.json
sessions/<role>/*.jsonl
```

Plan-only output is stdout-only. It should not create an
`agent-parallel-dogfood/<timestamp>/` evidence directory.

Important `result.json` fields:

| Field | Meaning |
|---|---|
| `runtimeAudit` | Redacted process/provider/mock/offline audit for the harness. |
| `roleRuns[].pid` / `processAtSpawn` | Child process evidence captured at spawn. |
| `roleRuns[].monotonic` | Monotonic timing evidence independent of wall-clock formatting. |
| `roleRuns[].session.fileDigests` | JSONL evidence digests. |
| `roleRuns[].session.toolResultDigests` | Per-tool result byte/hash evidence. |
| `gates.childPidsCaptured` | Every role/synthesizer had process evidence. |
| `gates.toolResultsCaptured` | Tool calls have corresponding tool-result evidence. |
| `gates.nonMockRuntimeExpected` | No explicit offline/no-env/mock/fake/stub mode was detected. |
| `gates.orchestrationPlatformScoreSplit` | Hard eval control separated orchestration score from platform claim score. |
| `gates.platformClaimGapsCaptured` | Required platform claim gaps were either absent or captured as failure/repair rows. |
| `hardEvalControl` | Inline hard-eval verdict, score split, platform gaps, failure ledger summary, and paused repair queue. |
| `parallelPlan` | Present when a plan manifest was supplied; records plan source, plan id, worker count, and merge strategy. It is orchestration metadata, not target/platform proof. |

The result classifies the run as:

| Verdict | Meaning |
|---|---|
| `agent-dogfood-confirmed` | Agent exited successfully, model output was captured, hard-score was referenced, and all three real-platform tracks were covered with the required report sections. |
| `agent-dogfood-partial` | Agent produced model output but missed one or more gates. |
| `agent-dogfood-failed` | Agent/model run failed or produced no usable model evidence. |
| `agent-parallel-dogfood-confirmed` | All parallel workers plus synthesizer exited, called the model, used tools, overlapped in the worker phase, cited artifacts, covered same-window plus all three platforms, and passed role-specific/conflict-reconciliation/process/tool-result gates. |
| `agent-parallel-dogfood-confirmed-platform-gaps` | The parallel orchestration gate passed, but hard-eval found required latest same-window platform claim gaps; do not report this as platform success. |
| `agent-parallel-dogfood-partial` | At least one parallel role called the model and used tools, but one or more strict gates failed. |
| `agent-parallel-dogfood-failed` | The parallel run produced no usable model/tool evidence. |

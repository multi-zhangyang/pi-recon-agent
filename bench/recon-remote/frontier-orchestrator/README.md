# Frontier orchestrator

Lightweight dogfood orchestration for the real-platform frontier matrix. It does not change `frontier-matrix/run.mjs` and does not create a separate evidence tree; execution is delegated to `frontier-matrix`, then this runner compacts the resulting positive/negative evidence for agents.

## Usage

Plan only, no evidence writes:

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs --plan --shards=3
```

Run the hardest selected matrix cases and summarize:

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs --live --strict
```

Reject stale latest-evidence artifacts during a non-live merge:

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs --strict --fresh
```

Compact the latest matrix artifact without rerunning browsers:

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs --summarize-latest
```

JSON output for another agent or CI wrapper:

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs --summarize-latest --json
```

## ReconParallelPlanV1 integration

`--plan --json --shards=N` emits a machine-readable `ReconParallelPlanV1`
manifest alongside the legacy human plan. The manifest is intended for offline
control-plane review and for downstream runners that need explicit worker
contracts:

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs \
  --plan --json --strategy=balanced --shards=3 > /tmp/recon-parallel-plan.json
```

Important fields:

| Field | Meaning |
|---|---|
| `planId` / `source` | Stable identity for this generated plan and its producer. |
| `workers[]` | Parallel work packets. Each worker carries `id`, `role`, `objective`, `commands`, `evidenceContract`, `mergeKeys`, `dependencies`, `artifactGlobs`, and `limits`. |
| `merge` | Structured merge policy, expected artifacts, and evidence ordering for the final summary. |
| `parallelPlan` | The same manifest nested under a dedicated key for consumers that read an orchestrator JSON root. |
| legacy fields | `mode`, `strategy`, `selectedCases`, `matrixCommand`, `shardCount`, `shards`, and `contextPolicy` remain for existing wrappers. |

Downstream offline preview:

```bash
node bench/recon-remote/agent-dogfood/parallel-run.mjs \
  --plan-json /tmp/recon-parallel-plan.json --plan-only --json
```

Boundary of this mode:

- it plans case-to-worker assignment and evidence contracts; it does not launch
  Pi agents, browsers, live platform probes, or model providers;
- it does not create a new evidence tree in plan mode;
- worker `commands[]` are executable intent for later review/execution, not proof
  that the platform case has passed;
- merge policy compacts existing `frontier-matrix/result.json` artifacts and
  keeps positive cases separate from negative controls.

## Selection strategies

| Strategy | Behavior |
|---|---|
| `hardest` | Default. Sorts known matrix cases by difficulty and preserves negative-control coverage when truncating. |
| `failed-first` | Reads the latest matrix result, prioritizes failed cases, then fills with hardest cases. |
| `balanced` | Keeps Bilibili, Xiaohongshu, Douyin, and the XHS negative-control boundary represented. |
| `quick` | Runs the tight XHS pair: auto-discovery positive plus search negative-control. |

Explicit case override:

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs \
  --cases=xhs_auto_discovery,xhs_search_negative --live --strict
```

## Multi-agent and context management

Use `--shards=N` in plan mode to hand independent case groups to parallel agents:

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs --plan --live --strict --shards=3
```

Each shard command is a normal `frontier-matrix` invocation with `RECON_MATRIX_CASES=<ids>`. The final merge step can then run:

```bash
node bench/recon-remote/frontier-orchestrator/run.mjs --summarize-latest
```

Current catalog tracks Bilibili runtime WBI, Bilibili signed media/CDN boundary,
Bilibili multi-page WBI container, Bilibili per-page CID boundary, XHS
auto-discovery, XHS discovery hit-rate, XHS search negative-control, Douyin
structured API replay, and Douyin cookie-boundary replay divergence.

The summary intentionally keeps only compact context:

- one decisive evidence line per case;
- positive replay samples separated from negative controls;
- concrete `result.json` artifact paths;
- failed-case next actions with rerun commands.
- freshness status so stale latest-evidence runs do not look like current
  capability.

This makes compacting easier: agents do not need to carry full browser stdout/stderr, raw request bodies, or historical matrix logs in context.

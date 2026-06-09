# Frontier gate

Hard frontier tracker for Pi-RECON real-platform capability. This is intentionally stricter than `proof-gate/`: it measures the unsolved frontier instead of declaring victory after advanced evidence passes.

## Usage

Score latest evidence without rerunning live targets:

```bash
node bench/recon-remote/frontier-gate/run.mjs
```

Refresh live proof-gate first, then score the frontier:

```bash
node bench/recon-remote/frontier-gate/run.mjs --live
```

Fail the process unless every frontier gate passes:

```bash
node bench/recon-remote/frontier-gate/run.mjs --strict
```

## Gates

| Gate | Frontier requirement |
|---|---|
| `bilibili_runtime_wbi_bundle_trace` | WBI self-test + signed endpoint + runtime signer/bundle trace + signed request observed |
| `xiaohongshu_xs_2xx_signed_replay` | `x-s`/`x-t`/`x-s-common` captured + signed replay returns structured 2xx note data + signer events >= 20 |
| `douyin_abogus_rebuild_structured_api` | `a_bogus`/`msToken` observed + runtime signed fetch anchored + independently replayed structured 2xx aweme API |
| `agent_frontier_gap_reasoning` | Dogfood agent made real model/tool calls and named frontier gaps/next commands across Bili/XHS/Douyin |
| `cross_platform_live_binding` | Latest live proof-gate passed with rows bound to artifacts from the same invocation |

`frontier-incomplete` is a useful result: it means the harness found real high-difficulty gaps instead of inflating the score. Use `--strict` only when this is promoted to a release-blocking target.

## Output

```text
.pi/evidence/remote/frontier-gate/<timestamp>/
artifact.md
result.json
```

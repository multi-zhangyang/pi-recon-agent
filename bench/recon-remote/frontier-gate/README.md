# Frontier gate

Hard frontier tracker for REPI real-platform capability. This is intentionally stricter than `proof-gate/`: it measures the unsolved frontier instead of declaring victory after advanced evidence passes.

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

Strict mode also enforces evidence freshness by default. Use `--fresh` to make
that explicit and tune the window with `RECON_FRONTIER_MAX_ARTIFACT_AGE_HOURS`
or `RECON_FRONTIER_MAX_ARTIFACT_AGE_MS`:

```bash
node bench/recon-remote/frontier-gate/run.mjs --strict --fresh
```

## Gates

| Gate | Frontier requirement |
|---|---|
| `bilibili_runtime_wbi_bundle_trace` | WBI self-test + signed endpoint + runtime signer/bundle trace + signed request observed |
| `xiaohongshu_xs_2xx_signed_replay` | `x-s`/`x-t`/`x-s-common` captured + eligible target note/feed replay returns structured 2xx note data + signer events >= 20; generic 2xx does not pass |
| `douyin_abogus_rebuild_structured_api` | `a_bogus`/`msToken` observed + runtime signed fetch anchored + independently replayed browser-captured aweme API returns structured 2xx JSON |
| `agent_frontier_gap_reasoning` | Dogfood agent made real model/tool calls and named frontier gaps/next commands across Bili/XHS/Douyin |
| `cross_platform_live_binding` | Latest live proof-gate passed with rows bound to artifacts from the same invocation |
| `freshness` | All referenced Bili/XHS/Douyin/dogfood/proof artifacts are inside the configured age window |

`frontier-incomplete` is a useful result: it means the harness found real high-difficulty gaps instead of inflating the score. Use `--strict` only when this is promoted to a release-blocking target.

## Output

```text
.repi-harness/evidence/remote/frontier-gate/<timestamp>/
artifact.md
result.json
```


## Current frontier interpretation

A passing Bilibili gate means runtime WBI request/bundle evidence exists. Xiaohongshu can earn partial frontier credit for signed structured 2xx web API replay, but it does not pass until an eligible target endpoint (`h5-note-info`, `web-feed`, `web-api-note`, `web-note-or-feed`, or `web-search-notes`) returns structured note/feed 2xx. Search recommendation, `user/me`, system config, board, and other generic 2xx endpoints are explicitly excluded from the note/feed pass condition. Douyin can earn partial credit when the browser observes a signed 2xx aweme API body, but it does not pass until `runtimeApiReplay.bestReplayedStructuredApi` proves an independent structured 2xx replay. `frontier-incomplete` means the latest evidence is missing one or more gates; inspect each gate's evidence fields instead of assuming a fixed unresolved platform set.

For Xiaohongshu regression, prefer an auto-discovery seed over a hand-maintained note URL:

```bash
RECON_BROWSER=1 RECON_XHS_AUTO_DISCOVER=1 RECON_XHS_DISCOVERY_LIMIT=2 \
  RECON_TIMEOUT_MS=45000 RECON_QUIET_MS=5000 RECON_XHS_PROBE_WAIT_MS=15000 \
  node bench/recon-remote/real-platform/run.mjs https://www.xhs-download.org/zh xiaohongshu-note
```

The gate accepts the resulting `xhs-auto-discovery-target-note-replay-confirmed` evidence only when the chained XHS child run still produces eligible target note/feed structured 2xx replay.

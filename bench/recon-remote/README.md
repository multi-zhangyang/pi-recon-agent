# Remote live benchmarks

Reproducible public-network benchmark harnesses for REPI. Runtime evidence is written under `.repi-harness/evidence/remote/` and is git-ignored.

| Benchmark | Purpose |
|---|---|
| `douyin-nowatermark/` | Short-video media URL reverse analysis: redirect/CDP/state extraction, `playwm -> play` no-watermark candidate transform, `a_bogus`/`msToken`/webid anti-bot surface inventory, signer-bundle hints, HEAD/range verification. |
| `public-webapp/` | Public webapp surface mapping and replay-safe vulnerability confirmation for profiles such as OWASP Juice Shop and Altoro Mutual/TestFire. |
| `real-platform/` | Hard-mode real-platform reverse benchmark for Bilibili WBI/media APIs/CDN probes/self-test/browser signer trace and Xiaohongshu CDP anti-bot/API signed replay, runtime signer hooks, signer-bundle trace, replay-divergence capture. |
| `agent-dogfood/` | Runs the REPI agent itself through `./pi-test.sh --recon` against latest remote evidence, requiring a real provider/model call, tool execution, platform coverage, and reproducible dogfood artifacts. |
| `same-window-live/` | Same freshness-window live gate for Bilibili, Xiaohongshu, and Douyin; blocks stale best-artifact self-delusion by requiring all platform proofs inside one time span. |
| `compound-frontier/` | Hardest release-frontier binder/runner: same-window real platforms + parallel multi-agent dogfood + context/compact audit + hard-score recognition. |
| `proof-gate/` | Cross-platform live proof gate: reruns Bilibili WBI, Xiaohongshu x-s, Douyin `a_bogus`/no-watermark, optional agent dogfood, then enforces hard-score gates. |
| `frontier-gate/` | Stricter frontier tracker for Bili runtime WBI bundle trace, XHS 2xx signed replay, Douyin `a_bogus` structured API replay, and dogfood frontier reasoning. |
| `frontier-matrix/` | Multi-scenario hardest frontier matrix: Bili runtime WBI/media/CDN/per-page-CID positives, XHS auto-discovery positive, XHS search permission negative control, Douyin structured API positive, Douyin cookie-boundary negative control, freshness, and aggregate frontier strict gate. |
| `frontier-orchestrator/` | Lightweight dogfood dispatcher over `frontier-matrix`: selects hardest cases, emits shard commands for parallel agents, and compacts positive/negative evidence summaries. |

Run each benchmark with `node <benchmark>/run.mjs --help` for usage.

## Hard-score evaluator

After running any remote benchmark, generate a cross-platform scoreboard:

```bash
node bench/recon-remote/hard-score.mjs
```

The evaluator scores latest artifacts across `signature_rebuild`, `signed_replay`, `anti_bot_challenge`, `cdn_media_probe`, `runtime_capture_depth`, `exploit_chain`, `bundle_trace`, and `regression_readiness`, writing:

```text
.repi-harness/evidence/remote/hard-score/<timestamp>/scoreboard.{json,md}
```

## Agent dogfood

Run the actual REPI agent against the latest remote evidence:

```bash
RECON_AGENT_PROVIDER=openai RECON_AGENT_MODEL=gpt-4.1 \
  node bench/recon-remote/agent-dogfood/run.mjs
```

The dogfood harness records stdout/stderr, session metadata, model/tool evidence, hard-score linkage, and whether the agent covered Bilibili WBI, Xiaohongshu x-s, and Douyin `a_bogus`.

## Proof gate

Run the live cross-platform release gate:

```bash
node bench/recon-remote/proof-gate/run.mjs
```

Use `--use-latest` for a fast gate over existing evidence.

## Frontier gate

Track the next unsolved real-platform frontier without pretending it already passes:

```bash
node bench/recon-remote/frontier-gate/run.mjs
```

Use `--live` to refresh proof-gate first and `--strict` when frontier completion should block release.

## Frontier matrix

Run the multi-scenario live matrix when a single latest artifact is not enough:

```bash
node bench/recon-remote/frontier-matrix/run.mjs --live --strict
```

Release/script gate entry over existing evidence:

```bash
npm run gate:frontier-matrix
npm run gate:context-compact
```

Use `RECON_MATRIX_CASES=xhs_auto_discovery,xhs_search_negative` to iterate on a subset. The matrix intentionally includes negative controls and a strict freshness gate so generic 2xx, permission/login boundaries, and stale artifacts cannot be mistaken for current target success.

## Compound frontier

Bind latest elite evidence quickly:

```bash
node bench/recon-remote/compound-frontier/run.mjs --use-latest --strict
```

Full live release gate:

```bash
npm run gate:compound-frontier
```

This gate requires same-window real-platform success, agent-parallel model/tool/process proof, context/compact audit pass, and hard-score recognition before it reports `compound-frontier-passed`.

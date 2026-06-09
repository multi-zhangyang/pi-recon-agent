# Remote proof gate

Cross-platform live gate for Pi-RECON remote capability. It reruns Bilibili, Xiaohongshu, Douyin, and optionally agent-dogfood, then generates a hard-score scoreboard and checks concrete gates.

## Usage

```bash
node bench/recon-remote/proof-gate/run.mjs
```

Use latest existing evidence without rerunning live targets:

```bash
node bench/recon-remote/proof-gate/run.mjs --use-latest
```

## Gates

| Gate | Requirement |
|---|---|
| `bilibili_wbi_signed_media` | score >= 75, confirmed verdict, WBI self-test ok |
| `xiaohongshu_xs_runtime_challenge` | score >= 80, signed replay attempted, 461 reproduced, signer events >= 10 |
| `douyin_abogus_nowatermark` | score >= 80, strong candidate, signature signals >= 5, bundle hints >= 5 |
| `agent_dogfood_recon_model_tools` | score >= 70, confirmed dogfood, model call and tool use |

The agent dogfood run starts automatically when `RECON_AGENT_MODEL` or `ANTHROPIC_MODEL` is configured. `RECON_GATE_AGENT=0` disables rerunning the agent; if latest dogfood evidence already exists, proof-gate still scores it as a regression gate.

In live mode, Bilibili/Xiaohongshu/Douyin gates are bound to the artifact paths produced by the current invocation; stale or higher-scoring artifacts from another target cannot satisfy those gates. `--use-latest` intentionally switches to latest-evidence scoring.

## Environment

| Variable | Default | Purpose |
|---|---:|---|
| `RECON_GATE_AGENT` | auto | `1` force dogfood rerun; `0` skip dogfood rerun but still score latest dogfood evidence if present; auto when a model env exists. |
| `RECON_GATE_TIMEOUT_MS` | `600000` | Overall gate timeout. |
| `RECON_GATE_LATEST` | unset | Set `1` to score latest artifacts only. |
| `RECON_GATE_BILI_URL` | sample BV URL | Bilibili target. |
| `RECON_GATE_XHS_URL` | sample note URL | Xiaohongshu target. |
| `RECON_GATE_XHS_TIMEOUT_MS` | `45000` | Xiaohongshu CDP wait budget; higher default reduces shallow captures. |
| `RECON_GATE_XHS_QUIET_MS` | `5000` | Xiaohongshu network quiet window before stopping capture. |
| `RECON_GATE_DOUYIN_URL` | sample video URL | Douyin target. |

## Output

```text
.pi/evidence/remote/proof-gate/<timestamp>/
artifact.md
result.json
*.stdout.txt
*.stderr.txt
```

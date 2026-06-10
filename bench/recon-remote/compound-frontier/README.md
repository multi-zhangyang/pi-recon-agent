# Compound frontier live-swarm gate

Binds or reruns the two hardest REPI release-frontier proofs:

1. `same-window-live`: Bilibili + Xiaohongshu + Douyin real-platform runtime proof.
2. `agent-parallel-dogfood`: real REPI multi-agent worker/synthesizer proof with process/tool-result evidence.

It also runs the context/compact audit and hard-score recognition check, then fails if the result depends on stale gaps or text-only self-assessment.

## Usage

Fast bind to latest artifacts:

```bash
node bench/recon-remote/compound-frontier/run.mjs --use-latest --strict
```

Full live release gate:

```bash
RECON_COMPOUND_LIVE=1 \
RECON_AGENT_TIMEOUT_MS=600000 \
node bench/recon-remote/compound-frontier/run.mjs --live --strict
```

## Required gates

- `same-window-live` artifact exists, is fresh, passed, and has no frontier gaps.
- Same-window negative boundaries are present: XHS challenge boundary, Douyin cookie divergence, Bilibili page boundary.
- Bilibili CDN and Douyin no-watermark byte/range proofs are present.
- `agent-parallel-dogfood` is confirmed with model calls, tool calls, matching tool results, child PID proof, monotonic timing, session digests, and non-mock runtime audit.
- The agent dogfood artifact explicitly binds the same same-window-live artifact.
- Context/compact/resume audit passes.
- `hard-score` recognizes same-window and agent-parallel artifacts as elite.

## Output

```text
.repi-harness/evidence/remote/compound-frontier/<timestamp>/
artifact.md
result.json
context-compact.stdout.txt / context-compact.stderr.txt
hard-score.stdout.txt / hard-score.stderr.txt
sameWindow.stdout.txt / sameWindow.stderr.txt       # only in --live mode
agentParallel.stdout.txt / agentParallel.stderr.txt # only in --live mode
```

Verdicts:

| Verdict | Meaning |
|---|---|
| `compound-frontier-passed` | Same-window platform proof, agent swarm proof, compact audit, and hard-score recognition all passed. |
| `compound-frontier-gaps` | Some proof exists but one or more compound frontier gates failed. |
| `compound-frontier-failed` | No useful required proof exists. |

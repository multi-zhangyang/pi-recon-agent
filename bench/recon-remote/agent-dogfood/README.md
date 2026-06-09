# Agent dogfood benchmark

Runs the actual Pi-RECON agent (`./pi-test.sh --recon`) against the latest remote benchmark evidence. This is the harness for proving the agent can call a real provider/model, use tools, read evidence, run hard-score, and produce a platform-specific reverse/pentest roadmap instead of relying on external manual analysis.

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

The parallel gate is intentionally stricter than the single-agent run: every role must call the model, use tools, cite `.pi/evidence/remote/...` artifacts, cover Bilibili WBI, Xiaohongshu `x-s`, and Douyin `a_bogus`, emit the standard report sections, overlap in wall-clock time for the worker phase, and pass synthesizer conflict reconciliation.

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

## Output

```text
.pi/evidence/remote/agent-dogfood/<timestamp>/
artifact.md
result.json
stdout.txt
stderr.txt
sessions/*.jsonl
```

Parallel artifacts are written to:

```text
.pi/evidence/remote/agent-parallel-dogfood/<timestamp>/
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

The result classifies the run as:

| Verdict | Meaning |
|---|---|
| `agent-dogfood-confirmed` | Agent exited successfully, model output was captured, hard-score was referenced, and all three real-platform tracks were covered with the required report sections. |
| `agent-dogfood-partial` | Agent produced model output but missed one or more gates. |
| `agent-dogfood-failed` | Agent/model run failed or produced no usable model evidence. |
| `agent-parallel-dogfood-confirmed` | All parallel workers plus synthesizer exited, called the model, used tools, overlapped in the worker phase, cited artifacts, covered all three platforms, and passed role-specific/conflict-reconciliation gates. |
| `agent-parallel-dogfood-partial` | At least one parallel role called the model and used tools, but one or more strict gates failed. |
| `agent-parallel-dogfood-failed` | The parallel run produced no usable model/tool evidence. |

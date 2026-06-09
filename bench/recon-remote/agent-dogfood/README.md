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

## Output

```text
.pi/evidence/remote/agent-dogfood/<timestamp>/
artifact.md
result.json
stdout.txt
stderr.txt
sessions/*.jsonl
```

The result classifies the run as:

| Verdict | Meaning |
|---|---|
| `agent-dogfood-confirmed` | Agent exited successfully, model output was captured, hard-score was referenced, and all three real-platform tracks were covered with the required report sections. |
| `agent-dogfood-partial` | Agent produced model output but missed one or more gates. |
| `agent-dogfood-failed` | Agent/model run failed or produced no usable model evidence. |

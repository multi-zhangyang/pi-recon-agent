# Pi-RECON Agent

Pi-RECON Agent is a customized Pi harness profile for reverse engineering, CTF, exploit research, web/API authorization testing, mobile/runtime tracing, DFIR, firmware, cloud/identity, malware triage, and agent-security workflows.

This repository is based on the Pi agent harness monorepo and adds a built-in reverse/pentest orchestration layer with persistent mission state, evidence artifacts, compact/resume recovery, proof loops, knowledge graph memory, and a top-level harness self-check.

## What is included

### Core profile

- `packages/coding-agent/src/core/recon-profile.ts` — built-in Pi-RECON profile, commands, tools, prompts, storage, compaction hooks, and harness checks.
- `.pi/extensions/reverse-pentest-core.ts` — installable extension version of the same reverse/pentest runtime.
- `.pi/SYSTEM.md` and `.pi/APPEND_SYSTEM.md` — runtime steering contract for the customized agent.
- `.pi/skills/reverse-pentest-orchestrator/SKILL.md` — skill workflow for reverse/pentest orchestration.
- `.pi/prompts/*.md` — domain prompts for native, web, web authz, JS reverse, pwn, exploit reliability, mobile, firmware, PCAP/DFIR, cloud, identity/AD, malware, memory, decision, and chain workflows.

### Pi-RECON capabilities

- Mission blackboard: `re_mission`, lanes, gates, and evidence ledger.
- Passive mapping and lane execution: `re_map`, `re_lane`, `re_autopilot`.
- Runtime analyzers: `re_native_runtime`, `re_mobile_runtime`, `re_live_browser`, `re_web_authz_state`, `re_exploit_lab`.
- Campaign orchestration: `re_campaign`, `re_operation`, `re_delegate`, `re_swarm`, `re_supervisor`, `re_reflect`.
- Context recovery: `re_context`, Pi-owned compact summaries, auto-resume telemetry, and compact resume case memory.
- Proof chain: `re_verifier`, `re_compiler`, `re_replayer`, `re_autofix`, `re_proof_loop`, `re_knowledge_graph`, `re_complete`.
- Harness gate: `re_harness` / `/re-harness` with `install_readiness`, `reverse_capability_guards`, and `regression_guards`.

## Quick start

```bash
# from repo root
npm install --ignore-scripts
npm run check

# run from source with the built-in Pi-RECON profile
PI_OFFLINE=1 ./pi-test.sh --recon --no-tools --help
```

Start Pi normally with the recon profile:

```bash
./pi-test.sh --recon
```

Useful first commands inside Pi:

```text
/re-harness full
/re-kernel build <target>
/re-decision tick <target>
/re-map <target> 2
/re-auto run <target>
/re-complete audit
```

## Install as global Pi profile

Install the `.pi` profile into the active Pi agent directory. By default this is `~/.pi/agent`; override with `PI_CODING_AGENT_DIR` if needed.

```bash
scripts/reverse-agent/install-global-profile.sh /root/pi-diy/pi
scripts/reverse-agent/refresh-tool-index.sh /root/pi-diy/pi
```

The installer copies profile files and links runtime dependencies:

```text
~/.pi/agent/SYSTEM.md
~/.pi/agent/APPEND_SYSTEM.md
~/.pi/agent/extensions/reverse-pentest-core.ts
~/.pi/agent/skills/reverse-pentest-orchestrator/SKILL.md
~/.pi/agent/prompts/*.md
~/.pi/agent/node_modules -> <repo>/node_modules
```

After install, validate the installed profile:

```bash
scripts/reverse-agent/verify-profile.mjs /root/pi-diy/pi
PI_OFFLINE=1 ./pi-test.sh --recon --no-tools --help
```

Inside Pi, run:

```text
/re-harness install
```

A healthy install returns a harness artifact with:

```text
harness:
verdict: pass
install_readiness:
reverse_capability_guards:
regression_guards:
```

## Model provider formats

Pi-RECON is not tied to one vendor. The full provider-format guide is in:

```text
docs/reverse-agent/model-provider-formats.md
```

It covers the mainstream formats used by reverse/pentest agents:

| Format | Pi `api` / provider path | Typical use |
|---|---|---|
| OpenAI Chat Completions compatible | `openai-completions` | OpenAI-compatible gateways, OpenRouter, provider-compatible endpoints, vLLM, SGLang, LM Studio, Ollama. |
| OpenAI Responses compatible | `openai-responses` | Responses API endpoints and proxies. |
| Anthropic Messages compatible | `anthropic-messages` | Claude/Anthropic-compatible `/v1/messages` gateways and bearer-token proxies. |
| Google Gemini / AI Studio | `google-generative-ai` | Gemini-compatible direct endpoints. |
| Azure OpenAI | built-in `azure-openai-responses` | Azure deployment mapping through env vars. |
| Amazon Bedrock | built-in `amazon-bedrock` | AWS SDK / Bedrock ConverseStream. |
| Google Vertex | built-in `google-vertex` | ADC/service-account based Vertex models. |
| Cloudflare / Vercel / routing gateways | built-in or `openai-completions` | Gateway-specific routing and BYOK setups. |

Provider configs live in:

```text
~/.pi/agent/models.json
~/.pi/agent/settings.json
```

Secrets must stay outside the repo. Use env references such as `$OPENAI_API_KEY`, `$ANTHROPIC_API_KEY`, `$OPENROUTER_API_KEY`, `$GEMINI_API_KEY`, or a command-backed secret loader.

## Generic OpenAI-compatible provider example

Most routers and local inference servers expose an OpenAI Chat Completions-compatible endpoint. Add an entry like this to `~/.pi/agent/models.json`:

```json
{
  "providers": {
    "openai-compatible": {
      "baseUrl": "https://api.example.com/v1",
      "api": "openai-completions",
      "apiKey": "$MODEL_PROVIDER_API_KEY",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false,
        "supportsStore": false,
        "supportsStrictMode": false,
        "maxTokensField": "max_tokens"
      },
      "models": [
        {
          "id": "provider/model-id",
          "name": "Provider Model",
          "input": ["text"],
          "contextWindow": 128000,
          "maxTokens": 16384
        }
      ]
    }
  }
}
```

Smoke test:

```bash
export MODEL_PROVIDER_API_KEY=<token>
PI_OFFLINE=1 ./pi-test.sh --recon \
  --provider openai-compatible \
  --model provider/model-id \
  --thinking off \
  --no-tools \
  --no-session \
  -p "Reply exactly: PROVIDER_OK"
```

## Validation commands

Run these before pushing or after profile changes:

```bash
node - <<'NODE'
const ts=require('typescript');
for(const file of [
  'packages/coding-agent/src/core/recon-profile.ts',
  '.pi/extensions/reverse-pentest-core.ts',
  'packages/coding-agent/test/recon-profile.test.ts',
  'packages/coding-agent/test/suite/agent-session-compaction.test.ts'
]){
  const source=require('fs').readFileSync(file,'utf8');
  const result=ts.transpileModule(source,{compilerOptions:{module:99,target:99},reportDiagnostics:true});
  console.log(file,result.diagnostics?.length||0);
  if(result.diagnostics?.length) for(const d of result.diagnostics) console.log(d.code,ts.flattenDiagnosticMessageText(d.messageText,'\n'));
}
NODE

node node_modules/vitest/dist/cli.js --run \
  packages/coding-agent/test/recon-profile.test.ts \
  packages/coding-agent/test/args.test.ts

npm run check
scripts/reverse-agent/verify-profile.mjs /root/pi-diy/pi
```

## Harness commands

```text
/re-harness quick    # fast source/profile/storage check
/re-harness full     # full profile regression and reverse-capability guard check
/re-harness install  # installed global profile readiness check
/re-harness show     # show latest harness artifact
```

The harness writes artifacts under:

```text
.pi/evidence/harness/
~/.pi/agent/evidence/harness/
~/.pi/agent/recon/evidence/harness/  # when using built-in core storage
```

## Important directories

```text
.pi/                              Installable Pi-RECON profile
.pi/extensions/                   Reverse/pentest extension
.pi/prompts/                      Domain prompts
.pi/skills/reverse-pentest-orchestrator/
.pi/tools/tool-index.md           Tool availability index
docs/reverse-agent/README.md      Detailed reverse-agent docs
docs/reverse-agent/model-provider-formats.md
packages/coding-agent/docs/recon.md
scripts/reverse-agent/            Install, verify, and tool-index scripts
packages/coding-agent/src/core/    Built-in profile source
```

## Reverse capability guards

The harness intentionally checks for markers that should not disappear during refactors:

```text
re_native_runtime
re_web_authz_state
re_mobile_runtime
re_exploit_lab
re_proof_loop
re_autopilot
re_knowledge_graph
compact_resume_case_memory
compact_resume_repair_from_case_memory
compact_resume_success_skip_low_value_lane
operator_command_floor
proof_exit_criteria
specialist_runtime_planner
```

If any guard fails, repair the profile before treating the agent as ready.

## Notes

- Do not commit real API keys, OAuth tokens, target credentials, customer data, or live engagement artifacts.
- `.env`, `node_modules/`, build outputs, logs, and local session exports are ignored by `.gitignore`.
- Keep commands, protocol fields, and evidence artifact names stable because tests and `verify-profile.mjs` use them as regression markers.

## License

MIT, inherited from the upstream Pi project.

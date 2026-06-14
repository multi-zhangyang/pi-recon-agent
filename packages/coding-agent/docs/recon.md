# REPI Kernel Profile

REPI includes a built-in reverse-engineering and penetration-testing kernel profile. The `repi` launcher enables the profile and stores state under `~/.repi/agent`.

```bash
repi
repi --offline --help
repi --offline --list-models
repi doctor
```

## Execution-first runtime

`--recon` / `--reverse-pentest` is not just a prompt preset. It changes runtime session wiring and installs an execution contract:

- map first: files, configs, routes, logs, manifests, storage, endpoints;
- trace the live path before making broad claims;
- keep every non-status turn tied to a concrete next command, tool call, artifact path, request, or repro step;
- convert missing target/sample/credential/tool/context into `re_map`, `re_lane plan`, fallback commands, bootstrap plan, or one precise gap question.

## Runtime resources

| Resource | Location | Purpose |
|---|---|---|
| Evidence | `~/.repi/agent/recon/evidence/` | Runtime artifacts, maps, browser captures, replay output, reports. |
| Mission | `~/.repi/agent/recon/mission/` | Mission state, lane plan, checkpoints, next actions. |
| Memory | `~/.repi/agent/recon/memory/` | Scoped memories, playbooks, quality/recall metadata. |
| Tool index | `~/.repi/agent/recon/tools/tool-index.md` | Available reverse/pentest tools and bootstrap hints. |

## Core operator commands

```text
/re-route                 route task to a lane
/re-map                   passive target/workspace map
/re-lane plan|run         specialist command pack and bounded execution
/re-live-browser          browser/XHR/WS capture plan
/re-web-authz-state       auth/session/IDOR/BOLA state machine
/re-native-runtime        native reverse/pwn runtime plan
/re-mobile-runtime        APK/IPA/Frida runtime plan
/re-exploit-lab           exploit/PoC stability lab
/re-delegate              split work into specialist packets
/re-swarm                 parallel worker plan/run/merge
/re-supervisor            review worker evidence and repair queue
/re-context               context pack/resume
/re-operator              bounded operator queue
/re-verifier              evidence assertions and contradictions
/re-compiler              report compiler
/re-replayer              replay matrix
/re-autofix               repair queue
/re-proof-loop            verifier→compiler→replayer→autofix loop
/re-knowledge-graph       reusable case knowledge
/re-memory                scoped memory inspection/governance
/re-profile-check         local profile/install sanity check
/re-complete              completion audit/report scaffold
```

## Compact/resume

Default config in `~/.repi/agent/settings.json`:

```json
{ "compaction": { "enabled": true, "triggerPercent": 85, "warningPercent": 80, "reserveTokens": 16384, "keepRecentTokens": 36000 } }
```

Runtime threshold:

```text
min(contextWindow * triggerPercent / 100, contextWindow - reserveTokens)
```

普通 OpenAI-compatible / Anthropic-compatible 流式接口不能在模型已经开始输出 token 后由客户端强行改写本次请求上下文；REPI 会在安全 turn boundary 生成 context pack、执行 compact/resume，再继续后续任务链。

## Model/provider validation

```bash
repi model add --provider openai-compatible --api openai-completions --base-url https://api.example.com/v1 --model provider/model-id --context-window 128000 --max-tokens 16384 --set-default
printf '%s' "$API_KEY" | repi model login --provider openai-compatible --api-key-stdin
repi model doctor
repi model test --provider openai-compatible --model provider/model-id
```

## MCP validation

```bash
repi mcp status
repi mcp list
repi mcp probe <server-id>
repi mcp search <server-id> browser
repi mcp call <server-id> call_tool '{"name":"browser_status","args":{}}'
```

Search/router-style MCP servers should expose a small real tool list first; REPI calls the real listed tool, and dynamic target tool names go inside the proxy arguments.

## Development validation

REPI no longer ships per-provider/per-MCP/per-feature release scripts. Use normal repository and runtime checks:

```bash
npm run check
node scripts/reverse-agent/repi-smoke.mjs . --json
```

For real providers, MCP servers, or targets, validate through the normal user-facing commands above rather than adding a special-purpose release script.

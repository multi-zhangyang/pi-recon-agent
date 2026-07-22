# REPI Mainline Overhaul

REPI 的主线目标是独立逆向渗透 agent。后续大改以功能扩张为目标，但扩张必须服务 reverse / pentest execution，不能回到泛安全助手、通用 coding agent 或纯自研 agent 控制平面。

## Product Boundary

- Default product: `repi` is a reverse/pentest execution agent.
- Core domains: reverse engineering, web/API pentest, pwn/exploit proof, JS signing, mobile runtime, firmware/IoT, PCAP/DFIR, malware triage, cloud/container/identity attack surface, and Agent/LLM boundary testing when it supports offensive testing or evidence work.
- Supporting surfaces: model/provider config, MCP, doctor, smoke, bugreport, and session management exist to support the reverse/pentest workflow. They do not define the product by themselves.
- Non-goals: generic security chatbot, generic coding assistant, broad AI safety assistant, private research control-plane framework, and compatibility-preserving rewrite of old drift.

## Engineering Direction

Prefer mature runtime mechanisms:

- Pi-style tool/runtime/session/resource loading.
- Claude Code-style direct tool use, concise project context, artifact references, and bounded execution.
- Plugins and MCP for external capability.
- Subagents for specialist parallel work when a lane can be isolated and merged with evidence.

Avoid adding another abstract orchestration layer unless it removes real complexity or unlocks a concrete reverse/pentest capability.

## Migration Order

1. **Freeze the theme**
   Keep README, AGENTS, help text, package metadata, and system prompts aligned on independent reverse/pentest agent.

2. **Unify runtime profile ownership**
   Choose the built-in `--recon` kernel as the product path. Remove stale source-profile assumptions or make them explicit fixtures. Runtime initialization should not silently disagree with repository profile files.

3. **Split the giant kernel**
   Break `packages/coding-agent/src/core/recon-profile.ts` into route, mission, evidence, runtime planners, operator commands, and tool registration modules. New capabilities should not be added to the monolith.

4. **Replace narrative contracts with executable capabilities**
   Keep operator commands only when they create artifacts, run tools, route lanes, verify claims, replay evidence, or dispatch bounded subagents. Remove process-only layers that mostly restate policy.

5. **Expand specialist lanes**
   Add deeper lane packs for native/pwn, web/API authz, JS signing, mobile/Frida, firmware/rootfs, PCAP/DFIR, malware config, cloud/identity, and Agent/LLM boundary testing. Each lane must define triage commands, runtime commands, evidence anchors, replay/verifier expectations, and fallback/bootstrap commands.

6. **Make subagents practical**
   Subagents should inherit only the provider, model, MCP allowlist, mission packet, and artifact contract they need. Merge should promote only claims with evidence references, hashes, logs, or reproducible commands.

7. **Restore lean validation**
   Do not resurrect every old custom gate. Add a small hard check suite that proves product claims: launcher isolation, reverse/pentest default prompt, profile install, model config, MCP listing/call, mission/engage artifact writing, and one representative specialist lane.

8. **Then expand**
   After the runtime is modular and validated, expand functionality aggressively by adding lanes, tools, MCP bridges, and worker strategies.

## Enhancement Contract

New REPI capability should enter through the modular product surface:

- Route and label: add or refine task routing in `packages/coding-agent/src/core/repi/routes.ts`.
- Target intake: add target classification, command quoting, and natural-language/poison rejection in `packages/coding-agent/src/core/repi/target.ts`.
- Text utilities: add shared truncation, metadata parsing, hashing, slugging, and de-duplication helpers in `packages/coding-agent/src/core/repi/text.ts`.
- JSONL ledgers: add append-only ledger readers and scan diagnostics in `packages/coding-agent/src/core/repi/jsonl.ts`.
- Mission shape: add lanes/checkpoints in `packages/coding-agent/src/core/repi/mission.ts`.
- Evidence: add ledger record shape, formatting, digest, and graph parsing in `packages/coding-agent/src/core/repi/evidence.ts`.
- Execution graph: add attack graph / exploit chain artifact schemas and formatters in `packages/coding-agent/src/core/repi/graph.ts`.
- Artifacts and storage defaults: add filesystem paths, private read/write/append helpers, default artifact initialization, built-in prompt/skill files, and private permission handling in `packages/coding-agent/src/core/repi/storage.ts`.
- Tool bootstrap: add install/verify metadata in `packages/coding-agent/src/core/repi/toolchain.ts`.
- Profile assembly: wire commands/tools in `recon-profile.ts` only after the domain module exists.
- Validation: keep `npm run contract:repi`, `npm run check`, and `npm run smoke:repi -- --json` passing.

Every added lane should ship with target intake, concrete commands, artifact writeback, verifier/replay expectations, fallback/bootstrap commands, and a clear operator next step. A feature that only adds narrative policy is not a REPI capability.

Cross-task recall, automatic learning stores, embedding retrieval, and hidden
context injection are non-goals. Session transcripts and generic compaction
provide continuity without maintaining a second state system.

## Default Decision Rule

When a change conflicts with old compatibility or current reverse/pentest clarity, choose reverse/pentest clarity. Breaking changes are acceptable when they remove generic-agent baggage or make REPI more useful for real reverse/pentest work.

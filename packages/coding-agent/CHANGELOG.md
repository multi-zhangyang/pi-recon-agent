# REPI Changelog

REPI is a reverse-engineering / penetration-testing autonomous agent built on
the [pi coding agent](https://github.com/earendil-works/pi) runtime. This
changelog covers REPI-specific releases. The upstream pi changelog is preserved
in `CHANGELOG.upstream.md` for reference.


## [Unreleased]

### Changed

- Source installs now build and validate all production workspace entrypoints; the checkout launcher prefers the current compiled Node runtime and falls back to `tsx` only when the build is missing, stale, or explicitly disabled for development.
- Removed REPI's cross-session memory CLI, store, recall, and prompt-injection paths. Session transcripts and generic compaction now provide continuity without a second persistence system.
- Removed the implicit provider/model catalog completely. Models now come only from `REPI_*`, explicit `models.json` providers, or extension registration; the environment path supports headers, compat overrides, thinking maps, input/reasoning metadata, context/output limits, four-way pricing, and pricing tiers.

### Fixed

- Prompt templates now support default values for positional and all-argument placeholders (`${N:-default}`, `${@:-default}`, and `${ARGUMENTS:-default}`).
- System prompts no longer embed the wall-clock date, keeping otherwise identical provider cache prefixes stable across days.
- OpenAI Responses streams that end before a terminal event now fail explicitly and enter the existing transient retry path.

### Tests

- Added installer/launcher smoke coverage for compiled runtime selection, stale or incomplete build fallback, package-command dispatch, and shell-routed product commands.

## [0.1.3] - 2026-07-07

Patch release focused on env-provider correctness, runtime reliability, and release install safety.

### Changed

- Tightened the package README into a product-first launch page: source installer first, GitHub Release tarball install spelled out as four same-version packages, `REPI_*` env model block, `/goal` footer/progress behavior, and the verified installer PATH prompt.
- `/goal status` now surfaces a compact token-budget progress bar in help/status notifications so print/RPC/non-TUI operators can see budget burn without relying on the TUI footer.
- Default model discovery is env-first and explicit-config-first: no bundled provider catalog is loaded unless the operator opts in, while extension-registered providers remain supported.
- OpenAI-compatible and Responses requests now omit unsupported optional controls by default, avoiding provider-side `store=false` and empty-tool payload failures.

### Fixed

- Fresh/release smoke tests now scrub outer `REPI_*` model env vars for envless checks, preventing false positives from a developer shell.
- Print mode now reports a guard-abort summary when max-turn/max-tool limits stop a run before assistant text is produced.
- Self-check/doctor flows now repair fresh scoped profiles before retrying readiness checks.
- Runtime self-review notifications are de-duplicated to avoid repeated checkpoint noise.

### Tests

- Added provider payload regression coverage for OpenAI-compatible tool-choice/tool-list edge cases and Responses optional control handling.
- Added release/selfcheck smoke coverage for env isolation, scoped doctor initialization, print guard output, and atomic engage artifact behavior.

## [0.1.2] - 2026-07-03

Release focused on install reliability, env-first model selection, and upstream pi extension compatibility.

### Added

- **Env-only model switching**: `REPI_AUTH_TOKEN`, `REPI_BASE_URL`, `REPI_MODEL`, `REPI_MODEL_API`, `REPI_CONTEXT_WINDOW` / `REPI_AUTO_COMPACT_WINDOW`, `REPI_MAX_TOKENS`, and `REPI_SUBAGENT_MODEL` provide a Claude Code-style setup while keeping OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages wire formats.
- **Built-in goal mode**: `/goal [--tokens 100k] <objective>` now ships with REPI, persists goal state, shows `🎯 active/paused/budget/complete` in the footer, auto-continues unfinished work, and terminates only through the verified `goal_complete` tool.
- **Runtime adapter auto-detection**: `re_runtime_adapter plan/run <target>` now infers GDB/radare2, Frida mobile, CDP web, PCAP/tshark, firmware/rootfs/binwalk, and pwn verifier adapters from target shape when no adapter is specified.
- **Evidence task tree graph**: `re_graph build` now links ledger commands, output facts, artifacts, hypotheses, verification commands, and counter-evidence into a traceable task tree.
- **Proof-loop gap classifier**: `re_proof_loop` now labels missing artifacts, contradictions, replay failures, dependency gaps, target/state problems, weak evidence, and timeout/flake signals, then emits a short quick path for verifier → compiler → replayer → autofix closure.
- **Model status check**: `repi model status` reports the effective `REPI_*` env provider/model/API/context/token settings offline, redacts base URLs, and warns about missing auth or shell-quote mistakes.
- **Upstream pi package compatibility**: loader aliases for `@earendil-works/pi-*` imports and `@earendil-works/pi-ai/compat` let REPI install/use packages such as `pi-web-access` while keeping state in `~/.repi/agent`; an older external `@narumitw/pi-goal` is suppressed in favor of the built-in mode.
- **RPC tool introspection**: headless/RPC clients can call `get_tools` to inspect registered tool metadata and active tool names, which makes extension smoke checks prove actual tool registration rather than only slash-command presence.
- **Extension compatibility smoke**: `npm run smoke:extensions -- --json` performs a real npm install of `pi-web-access` and `@narumitw/pi-goal`, then verifies `web_search`/`fetch_content`/`get_search_content`, `skill:librarian`, and built-in `/goal` conflict suppression through RPC.

### Changed

- REPI no longer loads the upstream generated provider/model catalog; the runtime surface is environment providers, explicit `models.json` providers, and dynamic extension providers.
- Swarm/subagent runtime manifests now carry explicit timeout, cancellation, and retry-attempt metadata into child-session and worker-pool validation.
- Swarm/subagent timeout handling now terminates the worker process group, records `timeoutMs`/`maxTurns`/`cancelledAt`, and recovers partial stdout/stderr into merge output when a model fails to write `handoff.md`.
- `re_swarm` output now surfaces worker closure rows (`passed`, `retry_queued`, timeout/cancel state, and evidence ref counts) so handoff/retry evidence is visible without opening the JSON artifact.
- Runtime-adapter execution JSON artifacts now enter the evidence graph as adapter, command, artifact, and parser-verification nodes instead of staying as disconnected files.
- REPI prompt, built-in skill, resource-loader, and legacy extension suppression contracts now live in `core/repi/resources.ts`, keeping `recon-profile.ts` closer to an assembly layer and cutting the core routing/resource test collection path from the full profile import to a lightweight module import.
- Documentation now leads with env-only model configuration and verified upstream pi extension installation examples.
- `re_proof_loop run` reuses target-scoped verifier/compiler/operator artifacts and refreshes the gap model only when execution changed it, cutting the slow proof-loop flow test from roughly 35s to roughly 13s while keeping verifier → compiler → replayer → autofix closure semantics.
- Runtime adapter target sniffing now reads bounded file headers instead of whole artifacts and recognizes ELF/MZ/Mach-O, PCAP/PCAPNG, APK/IPA ZIP markers, firmware/rootfs magic, and rootfs directory markers without loading large PCAP/firmware blobs into memory.
- Extension loader aliases now map upstream coding-agent imports to the lightweight extension SDK surface and force jiti resolution for extension imports, avoiding hangs when packages import `defineTool` from `@earendil-works/pi-coding-agent`.

### Fixed

- **Installer PATH reliability**: source installs now prefer a PATH-visible launcher directory, use sudo for `/usr/local/bin` when available, and create/update shell startup files when falling back to `~/.local/bin`, preventing post-install `repi: command not found` in new shells.
- Hardened runtime reliability/evidence flows from real-run self-checks, including route/memory noise reduction and realistic smoke/doctor probe budgets.
- `repi doctor` now checks goal mode, goal-extension conflict suppression, and the env-only model contract. `repi doctor --fix` also initializes a fresh `REPI_CODING_AGENT_DIR` profile before re-running readiness checks, including from release tarball/package-bin installs.
- Incomplete `REPI_*` env model configs now fail before falling back to saved/default models, with a concrete quoted export block and unmatched-quote hint.
- Installing `@narumitw/pi-goal` no longer hangs extension loading; REPI loads the package, suppresses the external `/goal`/`goal_complete`, and keeps the built-in goal footer/tool contract active.

### Tests

- Added installer regression coverage for `~/.local/bin/repi` symlink creation, idempotent PATH rc updates, no-op rc behavior when the launcher directory is already on PATH, and `repi doctor --fix` fresh-profile initialization.
- Added `/goal` unit coverage for print/RPC/no-UI behavior, token-budget stop/resume semantics, edit-with-token-budget footer preservation, and a JSON-clean release tarball smoke that builds, packs, installs the four `.tgz` artifacts, and verifies PATH-resolved `repi`, fresh envless models, redacted `repi model status` for `REPI_*`, RPC `/goal` + `goal_complete` tool introspection, and `/goal status` under an active `REPI_*` env model.
- Added pure runtime-adapter contract tests for file magic detection, rootfs-over-PCAP path priority, command materialization, and parser signal extraction.
- Added upstream extension alias coverage for pi-goal-style `defineTool` + `@earendil-works/pi-ai` imports and a real npm extension smoke for `pi-web-access` plus `@narumitw/pi-goal`.

## [0.1.1] - 2026-06-28

Patch release: bug fixes from real-run verification and a full
test-suite reconciliation. No feature or contract changes.

### Fixed

- **Subagent delegation auth**: `auth.json` was not copied into a subagent's
  agent-home, so delegation via the model-login flow failed to authenticate.
  The launcher now provisions the child agent-home with the parent's auth.
- **model-test error output**: a model-test run that errored printed
  `undefined` instead of the error; the error path now surfaces the message.
- **Non-interactive `--help` stdout leak**: a regression let `--help` and
  startup package-install chatter reach real stdout in print/json/rpc modes,
  breaking the "stdout is machine-readable" contract. The stdout takeover is
  now gated only on appMode; interactive `--help` (TTY) still goes to stdout.
- **Installer**: create `/usr/local/bin` when it is on `PATH` but missing, so
  the launcher symlink target directory exists.

### Tests

- Reconciled **17 stale assertions** with the current implementation contract
  (full vitest suite: 1428 passed, 44 skipped, 0 failed; was 17 failed). The
  tests had drifted from two intentional refactors: the `gates` field was
  removed from `MissionState` in favor of `checkpoints`, and `re_harness` /
  `re-harness` were renamed to `re_profile_check` / `re-profile-check` (plus
  `GateV1` → `CheckV1` and `gate:` → `check:` markers). Also fixed a misshapen
  `prepareCompaction` mock and a `process.cwd()`-relative `dark.json` test
  path.

### Docs

- Rewrote the README install section around the verified 0.1.0 paths and led
  with the basic `repi` start command.

## [0.1.0] - 2026-06-28

First public REPI release: a standalone reverse/pentest agent with an isolated
runtime, a reverse/pentest tool kernel, specialist subagents, and mature
operator infrastructure.

### Added — reverse/pentest kernel

- **5 specialist subagents** dispatched by lane → spec: `explorer`, `planner`,
  `operator`, `verifier`, `reverser`. Each runs in a process-isolated child
  (`repi --no-session -p`) under a recursion gate (`REPI_AGENT_THREAD=1`).
- **File-based handoff**: child workers write an authoritative handoff to
  `$REPI_WORKER_HANDOFF_PATH`; the parent surfaces `## Worker handoff`. This
  sidesteps empty-final-content from reasoning models without any
  reasoning-content adapter or per-provider special-casing.
- **Completion gate (reverser)**: a pwn/exploit/decode/emulate task is not done
  because the answer is visible in disassembly. The reverser must build and run
  the PoC and write its handoff file before stopping. Static analysis is
  triage.
- **Phase 0 tool-availability with generic fallbacks**: `checksec` → `readelf`,
  `gdb` → `strace`/`objdump`, `binwalk` → `dd`+`strings`, etc. The agent
  degrades gracefully when a tool is missing instead of failing.
- **Route-aware defaults**: `autoModeDefaults()` returns
  `reasoning=llm / dispatch=specialist / swarmExecution=real` unless
  `REPI_AUTOMODE_LEGACY=1`; cwd-gated and recursion-bound.
- **18 route domains**, **43 `re_*` tools**, lane → spec dispatch table.

### Added — operator infrastructure

- **One-line install**: `curl -fsSL .../install.sh | bash` clones, installs
  deps, wires the `repi` launcher, and provisions the runtime profile.
  Idempotent (re-run to upgrade). Supports `--prefix`, `--user`/`--system`,
  `--branch`, `--skip-npm`.
- **`repi bootstrap`**: self-contained RE/pentest toolchain installer
  (gdb, pwntools, binwalk, radare2, ROPgadget, ropper, angr, z3, volatility3,
  qemu-user, yara, capa, floss, nmap, sqlmap, tshark, frida, …) with
  `--dry-run`, `--only`, `--list`. Best-effort; failures are non-fatal.
- **`repi uninstall`**: removes the REPI launcher (dry-run by default,
  `--apply` to execute, `--purge` for runtime, `--source <dir>` for a
  checkout). Never touches upstream `pi` or `~/.pi`.
- **`repi update`**: pull latest code, reinstall, run doctor/smoke.
- **Diagnostics**: `repi doctor`, `repi smoke`, `repi selfcheck`,
  `repi bugreport`, `repi health`, `repi trust`, `repi mission`,
  `repi engage`.
- **Model + MCP management**: `repi model add|login|default|list|doctor|test`,
  `repi mcp status|list|probe|search|resources`.

### Added — distribution

- All four workspace packages (`@pi-recon/repi-agent-core`, `@pi-recon/repi-ai`,
  `@pi-recon/repi-tui`, `@pi-recon/repi-coding-agent`) configured with
  `publishConfig.access: public` for public scoped npm publishing.
- `scripts/publish.mjs` publishes the four packages in dependency order with
  `--access public --provenance`, idempotent (skips already-published), and
  tags prerelease versions with `--tag next`.
- GitHub Actions release workflow (`.github/workflows/release.yml`): on `v*`
  tag, build → check → provision → smoke → publish → GitHub Release. A
  `REPI_RELEASE_DRY_RUN=1` switch validates the pipeline without publishing.
- REPI CI (`.github/workflows/repi-ci.yml`): hermetic runtime provisioning
  (`REPI_CODING_AGENT_DIR`) + offline smoke on every push/PR to `main`.

### Documentation

- Rewritten `README.md` covering subagents, file-based handoff, completion
  gate, Phase 0 fallbacks, route-aware defaults, install/bootstrap/uninstall,
  and the ret2win validation (5/5 `uid=0` shells on a real pwn target).
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue/PR templates.

### Notes

- REPI does **not** introduce a reasoning-content adapter or any per-provider
  special-casing; it stays generic like Claude Code / Codex. The file-based
  handoff + completion gate are the mechanism that handles reasoning models.
- The completion gate is a prompt-level (probabilistic) doctrine, validated
  against 1 model × 1 pwn target; it is not a hard code guarantee.
- Upstream `pi` and `~/.pi` are never managed or modified by REPI.

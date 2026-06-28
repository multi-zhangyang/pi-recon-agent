# REPI Changelog

REPI is a reverse-engineering / penetration-testing autonomous agent built on
the [pi coding agent](https://github.com/earendil-works/pi) runtime. This
changelog covers REPI-specific releases. The upstream pi changelog is preserved
in `CHANGELOG.upstream.md` for reference.

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
- **Memory**: `repi memory status|list|show|why|forget|quarantine|doctor|export|purge|consolidate`.

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

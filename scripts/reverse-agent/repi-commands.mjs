#!/usr/bin/env node
// Shared REPI command reference for the source launcher and packaged bin.

const args = process.argv.slice(2);
if (args[0] && !args[0].startsWith("-")) args.shift();

process.stdout.write(`REPI command quick reference

Install / update:
  repi install [--user|--system|--bin-dir <dir>]     Refresh launcher/profile from this checkout
  repi update [--fast|--full|--no-pull]              Pull latest code, reinstall, run doctor/smoke
  repi bootstrap [--dry-run|--only a,b|--list]      Install the RE/pentest toolchain (gdb/pwntools/binwalk/...)
  repi uninstall [--apply] [--purge] [--source <dir>]  Remove the repi launcher (dry-run by default; never touches pi)

Health:
  repi health [--fix] [--selfcheck|--deep]          Operator health dashboard and safe repair plan
  repi doctor [--fix]                                Runtime, profile and model diagnostics
  repi smoke [--full]                                Fast local smoke test
  repi selfcheck [--deep] --provider <id> --model <id>
  repi bugreport --output /tmp/repi-bugreport.json   Redacted diagnostic bundle
  repi trust status                                  Show project trust decision for current folder
  repi trust yes|no|clear [path]                     Save or clear project trust
  repi mission new <task> [--target <target>]        Start a scoped mission/control-plane
  repi mission status|plan|next|pack|close           Mission state, lane plan, resume pack
  repi engage <target> [--full] [--swarm]            Active reverse/pentest execution entry
  repi attack|reverse|web <target>                   Aliases for repi engage

Models:
  export REPI_AUTH_TOKEN=sk-... REPI_BASE_URL=https://... REPI_PROVIDER=gateway REPI_MODEL=vendor/model
  export REPI_MODEL_API=openai-compatible   # also: openai-responses, anthropic
  repi --list-models                        # REPI env-only model appears as repi-env by default
  repi model add --provider <id> --api openai-completions --base-url <url> --model <model>
  repi model login --provider <id> --api-key-stdin
  repi model default --provider <id> --model <model>  # legacy; REPI_* env is preferred
  repi model list [--provider <id>] [--model <id>] [--show-urls]
  repi model doctor|test|cost|export|import

MCP:
  repi mcp status
  repi mcp list
  repi mcp probe <server-id>
  repi mcp search <server-id> [query]
  repi mcp resources <server-id>

Swarm:
  repi swarm plan <target> --workers 5
  repi swarm run <target> --workers 5 --provider <id> --model <model>
  repi swarm list
  repi swarm resolve latest
  repi swarm status latest
  repi swarm merge latest

Run:
  repi                                             Interactive
  repi -p "task"                                  One-shot task
  repi --provider <id> --model <model> -p "task"  One-shot with a specific model
`);

# REPI Documentation

REPI is an autonomous reverse-engineering and penetration-testing CLI agent. It combines a terminal coding agent with REPI's reverse/pentest kernel, isolated runtime profile, evidence ledger, scoped memory, compact/resume flow, runtime adapters, MCP support, and model/provider management.

## Quick start

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm install
npm run install:repi
repi --offline --help
repi --offline --list-models
repi doctor
```

Development validation uses normal commands only:

```bash
npm run check
node scripts/reverse-agent/repi-smoke.mjs . --json
```

Configure providers in `~/.repi/agent/models.json`, store local credentials with `repi model login --provider <id> --api-key-stdin`, and inspect configuration with `repi model doctor`.

## Start here

- [Quickstart](quickstart.md) - install, authenticate, and run a first session.
- [Using REPI](usage.md) - interactive mode, slash commands, context files, and CLI reference.
- [Models](models.md) - provider/model configuration.
- [Providers](providers.md) - provider authentication and API compatibility.
- [MCP](mcp.md) - MCP server configuration.
- [REPI Kernel](recon.md) - reverse/pentest runtime profile details.

# REPI Documentation

REPI is an autonomous reverse-engineering and security-research agent harness. It combines a terminal coding agent with REPI's reverse/pentest kernel, isolated runtime profile, evidence ledger, memory/compact/resume flow, runtime adapters, and release gates.

## Quick start

### Source install

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm install
npm run install:repi
```

Validate the installation:

```bash
repi --offline --help
repi --offline --list-models
npm run gate:repi-harness
```

### npm package install

After the package is published, the CLI package can also be installed with npm:

```bash
npm install -g @pi-recon/repi-coding-agent
```

Then run it in a project directory:

```bash
repi
```

Configure providers in `~/.repi/agent/models.json`, use `/login` for supported built-in providers, or set the relevant API-key environment variable before starting REPI.

For the full first-run flow, see [Quickstart](quickstart.md).

## Start here

- [Quickstart](quickstart.md) - install, authenticate, and run a first session.
- [Using REPI](usage.md) - interactive mode, slash commands, context files, and CLI reference.
- [Providers](providers.md) - subscription and API-key setup for built-in providers.
- [Custom models](models.md) - add model entries for supported provider APIs.
- [Containerization](containerization.md) - sandbox repi with OpenShell, Gondolin, or Docker.
- [Settings](settings.md) - global and project settings.
- [Keybindings](keybindings.md) - default shortcuts and custom keybindings.
- [Sessions](sessions.md) - session management, branching, and tree navigation.
- [Compaction](compaction.md) - context compaction and branch summarization.

## Customization

- [Extensions](extensions.md) - TypeScript modules for tools, commands, events, and custom UI.
- [Skills](skills.md) - Agent Skills for reusable on-demand capabilities.
- [Prompt templates](prompt-templates.md) - reusable prompts that expand from slash commands.
- [Themes](themes.md) - built-in and custom terminal themes.
- [REPI packages](packages.md) - bundle and share extensions, skills, prompts, and themes.
- [Custom providers](custom-provider.md) - implement custom APIs and OAuth flows.

## Programmatic usage

- [SDK](sdk.md) - embed repi in Node.js applications.
- [RPC mode](rpc.md) - integrate over stdin/stdout JSONL.
- [JSON event stream mode](json.md) - print mode with structured events.
- [TUI components](tui.md) - build custom terminal UI for extensions.

## Reference

- [Session format](session-format.md) - JSONL session file format, entry types, and SessionManager API.

## Platform setup

- [Windows](windows.md)
- [Termux on Android](termux.md)
- [tmux](tmux.md)
- [Terminal setup](terminal-setup.md)
- [Shell aliases](shell-aliases.md)

## Development

- [Development](development.md) - local setup, project structure, and debugging.

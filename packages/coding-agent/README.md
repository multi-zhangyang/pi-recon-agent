<p align="center">
  <a href="https://github.com/multi-zhangyang/pi-recon-agent">
    <img alt="repi logo" src="docs/images/repi-logo.svg" width="128">
  </a>
</p>
<p align="center">
  <a href="https://www.npmjs.com/package/@pi-recon/repi-coding-agent"><img alt="npm" src="https://img.shields.io/npm/v/@pi-recon/repi-coding-agent?style=flat-square" /></a>
</p>

---

REPI Agent is an independent reverse-engineering and penetration-testing task harness. It is not a `pi` profile skin: the product command is `repi`, runtime state lives in `~/.repi/agent`, and normal upstream `pi` stays separate.

The npm/bin entry itself defaults into the REPI kernel: `--recon`, clean-room resource isolation, context compaction/resume support, evidence ledgers, verifier/compiler/replayer/autofix/proof-loop commands, and the REPI profile initializer are applied inside the CLI. A shell wrapper is only a convenience for source checkouts.

REPI still supports the extension, skill, prompt-template, theme, RPC and SDK surfaces inherited from the harness, but the default product path is the reverse/pentest control plane documented in the repository root README.

## Table of Contents

- [Quick Start](#quick-start)
- [Providers & Models](#providers--models)
- [Interactive Mode](#interactive-mode)
  - [Editor](#editor)
  - [Commands](#commands)
  - [Keyboard Shortcuts](#keyboard-shortcuts)
  - [Message Queue](#message-queue)
- [Sessions](#sessions)
  - [Branching](#branching)
  - [Compaction](#compaction)
- [Settings](#settings)
- [Context Files](#context-files)
- [Customization](#customization)
  - [Prompt Templates](#prompt-templates)
  - [Skills](#skills)
  - [Extensions](#extensions)
  - [Themes](#themes)
  - [REPI Packages](#repi-packages)
- [Programmatic Usage](#programmatic-usage)
- [Philosophy](#philosophy)
- [CLI Reference](#cli-reference)

---

## Quick Start

```bash
npm install -g --ignore-scripts @pi-recon/repi-coding-agent
```

`--ignore-scripts` disables dependency lifecycle scripts during install. REPI does not require install scripts for normal npm installs.

Source checkout alternative:

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm install --ignore-scripts
npm run install:repi
```

Authenticate with an API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
repi
```

Or use your existing subscription:

```bash
repi
/login  # Then select provider
```

Then start with `/re-profile-check quick`, `/re-kernel build <target>`, `/re-map <target> 2`, `/re-operator plan <target>`, `/re-verifier matrix`, and `/re-complete audit`. REPI still exposes the standard `read`, `write`, `edit`, and `bash` tools, but its default system prompt and commands are the REPI reverse/pentest control plane.

**Platform notes:** [Windows](docs/windows.md) | [Termux (Android)](docs/termux.md) | [tmux](docs/tmux.md) | [Terminal setup](docs/terminal-setup.md) | [Shell aliases](docs/shell-aliases.md)

---

## Providers & Models

For each built-in provider, repi maintains a list of tool-capable models, updated with every release. Authenticate via subscription (`/login`) or API key, then select any model from that provider via `/model` (or Ctrl+L).

**Subscriptions:**
- Anthropic Claude Pro/Max
- OpenAI ChatGPT Plus/Pro (Codex)
- GitHub Copilot

**API keys:**
- Anthropic
- Ant Ling
- OpenAI
- Azure OpenAI
- DeepSeek
- NVIDIA NIM
- Google Gemini
- Google Vertex
- Amazon Bedrock
- Mistral
- Groq
- Cerebras
- Cloudflare AI Gateway
- Cloudflare Workers AI
- xAI
- OpenRouter
- Vercel AI Gateway
- ZAI
- ZAI Coding Plan (China)
- OpenCode Zen
- OpenCode Go
- Hugging Face
- Fireworks
- Together AI
- Kimi For Coding
- MiniMax
- Xiaomi MiMo
- Xiaomi MiMo Token Plan (China)
- Xiaomi MiMo Token Plan (Amsterdam)
- Xiaomi MiMo Token Plan (Singapore)

See [docs/providers.md](docs/providers.md) for detailed setup instructions.

**Custom providers & models:** Add providers via `~/.repi/agent/models.json` if they speak a supported API (OpenAI, Anthropic, Google). For custom APIs or OAuth, use extensions. See [docs/models.md](docs/models.md) and [docs/custom-provider.md](docs/custom-provider.md).

---

## Interactive Mode

<p align="center"><img src="docs/images/interactive-mode.png" alt="Interactive Mode" width="600"></p>

The interface from top to bottom:

- **Startup header** - Shows shortcuts (`/hotkeys` for all), loaded AGENTS.md files, prompt templates, skills, and extensions
- **Messages** - Your messages, assistant responses, tool calls and results, notifications, errors, and extension UI
- **Editor** - Where you type; border color indicates thinking level
- **Footer** - Working directory, session name, total token/cache usage (`↑` input, `↓` output, `R` cache read, `W` cache write, `CH` latest cache hit rate), cost, context usage, current model

The editor can be temporarily replaced by other UI, like built-in `/settings` or custom UI from extensions (e.g., a Q&A tool that lets the user answer model questions in a structured format). [Extensions](#extensions) can also replace the editor, add widgets above/below it, a status line, custom footer, or overlays.

### Editor

| Feature | How |
|---------|-----|
| File reference | Type `@` to fuzzy-search project files |
| Path completion | Tab to complete paths |
| Multi-line | Shift+Enter (or Ctrl+Enter on Windows Terminal) |
| Images | Ctrl+V to paste (Alt+V on Windows), or drag onto terminal |
| Bash commands | `!command` runs and sends output to LLM, `!!command` runs without sending |

Standard editing keybindings for delete word, undo, etc. See [docs/keybindings.md](docs/keybindings.md).

### Commands

Type `/` in the editor to trigger commands. [Extensions](#extensions) can register custom commands, [skills](#skills) are available as `/skill:name`, and [prompt templates](#prompt-templates) expand via `/templatename`.

| Command | Description |
|---------|-------------|
| `/login`, `/logout` | OAuth authentication |
| `/model` | Switch models |
| `/scoped-models` | Enable/disable models for Ctrl+P cycling |
| `/settings` | Thinking level, theme, message delivery, transport |
| `/resume` | Pick from previous sessions |
| `/new` | Start a new session |
| `/name <name>` | Set session display name |
| `/session` | Show session info (file, ID, messages, tokens, cost) |
| `/tree` | Jump to any point in the session and continue from there |
| `/trust` | Save project trust decision for future sessions (restart required) |
| `/fork` | Create a new session from a previous user message |
| `/clone` | Duplicate the current active branch into a new session |
| `/compact [prompt]` | Manually compact context, optional custom instructions |
| `/copy` | Copy last assistant message to clipboard |
| `/export [file]` | Export session to HTML file |
| `/share` | Upload as private GitHub gist with shareable HTML link |
| `/reload` | Reload keybindings, extensions, skills, prompts, and context files (themes hot-reload automatically) |
| `/hotkeys` | Show all keyboard shortcuts |
| `/changelog` | Display version history |
| `/quit` | Quit repi |

### Keyboard Shortcuts

See `/hotkeys` for the full list. Customize via `~/.repi/agent/keybindings.json`. See [docs/keybindings.md](docs/keybindings.md).

**Commonly used:**

| Key | Action |
|-----|--------|
| Ctrl+C | Clear editor |
| Ctrl+C twice | Quit |
| Escape | Cancel/abort |
| Escape twice | Open `/tree` |
| Ctrl+L | Open model selector |
| Ctrl+P / Shift+Ctrl+P | Cycle scoped models forward/backward |
| Shift+Tab | Cycle thinking level |
| Ctrl+O | Collapse/expand tool output |
| Ctrl+T | Collapse/expand thinking blocks |

### Message Queue

Submit messages while the agent is working:

- **Enter** queues a *steering* message, delivered after the current assistant turn finishes executing its tool calls
- **Alt+Enter** queues a *follow-up* message, delivered only after the agent finishes all work
- **Escape** aborts and restores queued messages to editor
- **Alt+Up** retrieves queued messages back to editor

On Windows Terminal, `Alt+Enter` is fullscreen by default. Remap it in [docs/terminal-setup.md](docs/terminal-setup.md) so repi can receive the follow-up shortcut.

Configure delivery in [settings](docs/settings.md): `steeringMode` and `followUpMode` can be `"one-at-a-time"` (default, waits for response) or `"all"` (delivers all queued at once). `transport` selects provider transport preference (`"sse"`, `"websocket"`, or `"auto"`) for providers that support multiple transports.

---

## Sessions

Sessions are stored as JSONL files with a tree structure. Each entry has an `id` and `parentId`, enabling in-place branching without creating new files. See [docs/session-format.md](docs/session-format.md) for file format.

### Management

Sessions auto-save to `~/.repi/agent/sessions/` organized by working directory.

```bash
repi -c                  # Continue most recent session
repi -r                  # Browse and select from past sessions
repi --no-session        # Ephemeral mode (don't save)
repi --name "my task"    # Set session display name at startup
repi --session <path|id> # Use specific session file or ID
repi --fork <path|id>    # Fork specific session file or ID into a new session
```

Use `/session` in interactive mode to see the current session ID before reusing it with `--session <id>` or `--fork <id>`.

### Branching

**`/tree`** - Navigate the session tree in-place. Select any previous point, continue from there, and switch between branches. All history preserved in a single file.

<p align="center"><img src="docs/images/tree-view.png" alt="Tree View" width="600"></p>

- Search by typing, fold/unfold and jump between branches with Ctrl+←/Ctrl+→ or Alt+←/Alt+→, page with ←/→
- Filter modes (Ctrl+O): default → no-tools → user-only → labeled-only → all
- Press Shift+L to label entries as bookmarks and Shift+T to toggle label timestamps

**`/fork`** - Create a new session file from a previous user message on the active branch. Opens a selector, copies the active path up to that point, and places the selected prompt in the editor for modification.

**`/clone`** - Duplicate the current active branch into a new session file at the current position. The new session keeps the full active-path history and opens with an empty editor.

**`--fork <path|id>`** - Fork an existing session file or partial session UUID directly from the CLI. This copies the full source session into a new session file in the current project.

### Compaction

Long sessions can exhaust context windows. Compaction summarizes older messages while keeping recent ones.

**Manual:** `/compact` or `/compact <custom instructions>`

**Automatic:** Enabled by default. Triggers on context overflow (recovers and retries) or when approaching the limit (proactive). Configure via `/settings` or `settings.json`.

Compaction is lossy. The full history remains in the JSONL file; use `/tree` to revisit. Customize compaction behavior via [extensions](#extensions). See [docs/compaction.md](docs/compaction.md) for internals.

---

## Settings

Use `/settings` to modify common options, or edit JSON files directly:

| Location | Scope |
|----------|-------|
| `~/.repi/agent/settings.json` | Global (all projects) |
| `.repi/settings.json` | Project (overrides global) |

See [docs/settings.md](docs/settings.md) for all options.

### Project Trust

On interactive startup, repi asks before trusting a project folder that contains project-local inputs and has no saved decision in `~/.repi/agent/trust.json`. Trusting a project allows repi to read project instructions (`AGENTS.md`/`CLAUDE.md`), load `.repi/settings.json` and `.repi` resources, install missing project packages, and execute project extensions.

Non-interactive modes (`-p`, `--mode json`, and `--mode rpc`) do not show a trust prompt. Without a saved trust decision, they ignore project-local inputs unless `--approve`/`-a` is passed. Use `--no-approve`/`-na` to ignore project-local inputs for one run even when the project is trusted.

`repi config` assumes project trust for that command so you can view and change project resource settings before starting a session. It does not save a trust decision; starting a session in that folder still prompts. Pass `--no-approve` to hide project-local inputs in `repi config`.

Use `/trust` in interactive mode to save a project trust decision for future sessions. It writes `~/.repi/agent/trust.json` only; the current session is not reloaded, so restart repi for changes to take effect.

### Telemetry and update checks

REPI product mode disables upstream update checks and install telemetry by default. The inherited compatibility code has two startup features only when the CLI is not running as REPI:

- **Update check:** disabled in REPI product mode. For non-REPI compatibility runs, disable it with the legacy skip-version-check environment flag.
- **Install/update telemetry:** disabled in REPI product mode. Provider attribution headers remain controlled by provider-specific settings and do not require upstream update telemetry.

Use `--offline` or `REPI_OFFLINE=1` to disable startup network operations such as package update checks and install/update telemetry.

---

## Context Files

REPI loads `AGENTS.md` (or `CLAUDE.md`) at startup from:
- `~/.repi/agent/AGENTS.md` (global)
- Parent directories (walking up from cwd, only when the project is trusted)
- Current directory (only when the project is trusted)

Use for project instructions (`AGENTS.md`/`CLAUDE.md`), conventions, common commands. All matching files are concatenated.

Disable context file loading with `--no-context-files` (or `-nc`).

### System Prompt

Replace the default system prompt with `.repi/SYSTEM.md` (project) or `~/.repi/agent/SYSTEM.md` (global). Append without replacing via `APPEND_SYSTEM.md`.

---

## Customization

### Prompt Templates

Reusable prompts as Markdown files. Type `/name` to expand.

```markdown
<!-- ~/.repi/agent/prompts/review.md -->
Review this code for bugs, security issues, and performance problems.
Focus on: {{focus}}
```

Place in `~/.repi/agent/prompts/`, `.repi/prompts/`, or a [repi package](#repi-packages) to share with others. See [docs/prompt-templates.md](docs/prompt-templates.md).

### Skills

On-demand capability packages following the [Agent Skills standard](https://agentskills.io). Invoke via `/skill:name` or let the agent load them automatically.

```markdown
<!-- ~/.repi/agent/skills/my-skill/SKILL.md -->
# My Skill
Use this skill when the user asks about X.

## Steps
1. Do this
2. Then that
```

Place in `~/.repi/agent/skills/`, `~/.agents/skills/`, `.repi/skills/`, or `.agents/skills/` (from `cwd` up through parent directories) or a [repi package](#repi-packages) to share with others. See [docs/skills.md](docs/skills.md).

### Extensions

<p align="center"><img src="docs/images/doom-extension.png" alt="Doom Extension" width="600"></p>

TypeScript modules that extend repi with custom tools, commands, keyboard shortcuts, event handlers, and UI components.

```typescript
export default function (repi: ExtensionAPI) {
  repi.registerTool({ name: "deploy", ... });
  repi.registerCommand("stats", { ... });
  repi.on("tool_call", async (event, ctx) => { ... });
}
```

The default export can also be `async`. repi waits for async extension factories before startup continues, which is useful for one-time initialization such as fetching remote model lists before calling `repi.registerProvider()`.

**What's possible:**
- Custom tools (or replace built-in tools entirely)
- Sub-agents and plan mode
- Custom compaction and summarization
- Permission gates and path protection
- Custom editors and UI components
- Status lines, headers, footers
- Git checkpointing and auto-commit
- SSH and sandbox execution
- MCP server integration
- Make repi look like Claude Code
- Games while waiting (yes, Doom runs)
- ...anything you can dream up

Place in `~/.repi/agent/extensions/`, `.repi/extensions/`, or a [repi package](#repi-packages) to share with others. See [docs/extensions.md](docs/extensions.md) and [examples/extensions/](examples/extensions/).

### Themes

Built-in: `dark`, `light`. Themes hot-reload: modify the active theme file and repi immediately applies changes.

Place in `~/.repi/agent/themes/`, `.repi/themes/`, or a [repi package](#repi-packages) to share with others. See [docs/themes.md](docs/themes.md).

### REPI Packages

Bundle and share extensions, skills, prompts, and themes via npm or git. Find packages on [npmjs.com](https://www.npmjs.com/search?q=keywords%3Api-package) or [Discord](https://discord.com/channels/1456806362351669492/1457744485428629628).

> **Security:** REPI packages run with full system access. Extensions execute arbitrary code, and skills can instruct the model to perform any action including running executables. Review source code before installing third-party packages.

```bash
repi install npm:@foo/repi-tools
repi install npm:@foo/repi-tools@1.2.3      # pinned version
repi install git:github.com/user/repo
repi install git:github.com/user/repo@v1      # tag or commit
repi install git:git@github.com:user/repo
repi install git:git@github.com:user/repo@v1  # tag or commit
repi install https://github.com/user/repo
repi install https://github.com/user/repo@v1  # tag or commit
repi install ssh://git@github.com/user/repo
repi install ssh://git@github.com/user/repo@v1 # tag or commit
repi remove npm:@foo/repi-tools
repi uninstall npm:@foo/repi-tools            # alias for remove
repi list
repi update                                   # update installed packages (skips pinned packages)
repi update --extensions                      # update installed packages only
repi update npm:@foo/repi-tools               # update one package
repi update --extension npm:@foo/repi-tools   # update one package
repi config                                   # enable/disable extensions, skills, prompts, themes
```

Packages install to `~/.repi/agent/git/` (git) or `~/.repi/agent/npm/` (npm). Use `-l` for project-local installs (`.repi/git/`, `.repi/npm/`). Git `@ref` values are pinned tags or commits; pinned packages are skipped by `repi update`, so use `repi install git:host/user/repo@new-ref` to move an existing package to a new ref. Git packages install dependencies with `npm install --omit=dev` by default, so runtime deps must be listed under `dependencies`; when `npmCommand` is configured, git packages use plain `install` for compatibility with wrappers. If you use a Node version manager and want package installs to reuse a stable npm context, set `npmCommand` in `settings.json`, for example `["mise", "exec", "node@20", "--", "npm"]`.
REPI does not manage the upstream `pi` command: `repi update pi` is rejected, and `repi update` only updates REPI packages.

Create a package by adding a `repi` key to `package.json`:

```json
{
  "name": "my-repi-package",
  "keywords": ["repi-package"],
  "repi": {
    "extensions": ["./extensions"],
    "skills": ["./skills"],
    "prompts": ["./prompts"],
    "themes": ["./themes"]
  }
}
```

Without a `repi` manifest, repi auto-discovers from conventional directories (`extensions/`, `skills/`, `prompts/`, `themes/`).

See [docs/packages.md](docs/packages.md).

---

## Programmatic Usage

### SDK

```typescript
import { AuthStorage, createAgentSession, ModelRegistry, SessionManager } from "@pi-recon/repi-coding-agent";

const authStorage = AuthStorage.create();
const modelRegistry = ModelRegistry.create(authStorage);
const { session } = await createAgentSession({
  sessionManager: SessionManager.inMemory(),
  authStorage,
  modelRegistry,
});

await session.prompt("What files are in the current directory?");
```

For advanced multi-session runtime replacement, use `createAgentSessionRuntime()` and `AgentSessionRuntime`.

See [docs/sdk.md](docs/sdk.md) and [examples/sdk/](examples/sdk/).

### RPC Mode

For non-Node.js integrations, use RPC mode over stdin/stdout:

```bash
repi --mode rpc
```

RPC mode uses strict LF-delimited JSONL framing. Clients must split records on `\n` only. Do not use generic line readers like Node `readline`, which also split on Unicode separators inside JSON payloads.

See [docs/rpc.md](docs/rpc.md) for the protocol.

---

## Philosophy

REPI is aggressively extensible so it doesn't have to dictate your workflow. Features that other tools bake in can be built with [extensions](#extensions), [skills](#skills), or installed from third-party [repi packages](#repi-packages). This keeps the core minimal while letting you shape repi to fit how you work.

**No MCP.** Build CLI tools with READMEs (see [Skills](#skills)), or build an extension that adds MCP support. [Why?](https://mariozechner.at/posts/2025-11-02-what-if-you-dont-need-mcp/)

**No sub-agents.** There's many ways to do this. Spawn repi instances via tmux, or build your own with [extensions](#extensions), or install a package that does it your way.

**No permission popups.** Run in a container, or build your own confirmation flow with [extensions](#extensions) inline with your environment and security requirements.

**No plan mode.** Write plans to files, or build it with [extensions](#extensions), or install a package.

**No built-in to-dos.** They confuse models. Use a TODO.md file, or build your own with [extensions](#extensions).

**No background bash.** Use tmux. Full observability, direct interaction.

Read the [blog post](https://mariozechner.at/posts/2025-11-30-repi-coding-agent/) for the full rationale.

---

## CLI Reference

```bash
repi [options] [@files...] [messages...]
```

### Package Commands

```bash
repi install <source> [-l]     # Install package, -l for project-local
repi remove <source> [-l]      # Remove package
repi uninstall <source> [-l]   # Alias for remove
repi update [source]          # Update installed packages (skips pinned packages)
repi update --extensions       # Update packages only
repi update --extension <src>  # Update one package
repi list                      # List installed packages
repi config                    # Enable/disable package resources
```

Project package commands accept `--approve`/`--no-approve` to trust or ignore project-local package settings for one command.

### Modes

| Flag | Description |
|------|-------------|
| (default) | Interactive mode |
| `-p`, `--print` | Print response and exit |
| `--mode json` | Output all events as JSON lines (see [docs/json.md](docs/json.md)) |
| `--mode rpc` | RPC mode for process integration (see [docs/rpc.md](docs/rpc.md)) |
| `--export <in> [out]` | Export session to HTML |

In print mode, repi also reads piped stdin and merges it into the initial prompt:

```bash
cat traffic.har | repi -p "提取 API、签名参数、状态机和 replay 命令"
```

### Model Options

| Option | Description |
|--------|-------------|
| `--provider <name>` | Provider (anthropic, openai, google, etc.) |
| `--model <pattern>` | Model pattern or ID (supports `provider/id` and optional `:<thinking>`) |
| `--api-key <key>` | API key (overrides env vars) |
| `--thinking <level>` | `off`, `minimal`, `low`, `medium`, `high`, `xhigh` |
| `--models <patterns>` | Comma-separated patterns for Ctrl+P cycling |
| `--list-models [search]` | List available models |

### Session Options

| Option | Description |
|--------|-------------|
| `-c`, `--continue` | Continue most recent session |
| `-r`, `--resume` | Browse and select session |
| `--session <path\|id>` | Use specific session file or partial UUID |
| `--fork <path\|id>` | Fork specific session file or partial UUID into a new session |
| `--session-dir <dir>` | Custom session storage directory |
| `--no-session` | Ephemeral mode (don't save) |
| `--name <name>`, `-n <name>` | Set session display name at startup |

### Tool Options

| Option | Description |
|--------|-------------|
| `--tools <list>`, `-t <list>` | Allowlist specific tool names across built-in, extension, and custom tools |
| `--exclude-tools <list>`, `-xt <list>` | Disable specific tool names across built-in, extension, and custom tools |
| `--no-builtin-tools`, `-nbt` | Disable built-in tools by default but keep extension/custom tools enabled |
| `--no-tools`, `-nt` | Disable all tools by default |

Available built-in tools: `read`, `bash`, `edit`, `write`, `grep`, `find`, `ls`

### Resource Options

| Option | Description |
|--------|-------------|
| `-e`, `--extension <source>` | Load extension from path, npm, or git (repeatable) |
| `--no-extensions` | Disable extension discovery |
| `--skill <path>` | Load skill (repeatable) |
| `--no-skills` | Disable skill discovery |
| `--prompt-template <path>` | Load prompt template (repeatable) |
| `--no-prompt-templates` | Disable prompt template discovery |
| `--theme <path>` | Load theme (repeatable) |
| `--no-themes` | Disable theme discovery |
| `--no-context-files`, `-nc` | Disable AGENTS.md and CLAUDE.md context file discovery |

Combine `--no-*` with explicit flags to load exactly what you need, ignoring settings.json (e.g., `--no-extensions -e ./my-ext.ts`).

### Other Options

| Option | Description |
|--------|-------------|
| `--system-prompt <text>` | Replace default prompt (context files and skills still appended) |
| `--append-system-prompt <text>` | Append to system prompt |
| `--verbose` | Force verbose startup |
| `-a`, `--approve` | Trust project-local files for this run |
| `-na`, `--no-approve` | Ignore project-local files for this run |
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show version |

### File Arguments

Prefix files with `@` to include in the message:

```bash
repi @notes.md "提取目标、入口、证据缺口和下一步命令"
repi -p @screenshot.png "分析页面状态、接口线索和可复现证据"
repi @sample.c @trace.log "定位校验路径并生成 verifier matrix"
```

### Examples

```bash
# Interactive with initial REPI task
repi "先对当前目录做被动 mapping，列出入口、鉴权点和证据缺口"

# Non-interactive bounded plan
repi -p "对 ./challenge 生成 re_map、re_operator、re_verifier 执行计划"

# Non-interactive with piped stdin
cat traffic.har | repi -p "提取 API、签名参数、状态机和 replay 命令"

# Named one-shot session
repi --name "firmware-auth-analysis" -p "审计固件认证链路并输出 proof loop"

# Different configured provider/model
repi --provider openai-compatible --model provider/model-id "分析 Web/API 授权状态机"

# Model with provider prefix (no --provider needed)
repi --model openai-compatible/provider-model "生成 exploit-lab 复现矩阵"

# Model with thinking level shorthand
repi --model sonnet:high "构建 pwn 目标的 leak→primitive→proof 路线"

# Limit model cycling
repi --models "claude-*,gpt-4o,provider/model-id"

# Passive/read-only mapping mode
repi --tools read,grep,find,ls -p "只读分析 src/ 的路由、鉴权和入口"

# Disable one extension or built-in tool while keeping the rest available
repi --exclude-tools ask_question

```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `REPI_CODING_AGENT_DIR` | Override config directory (default: `~/.repi/agent`) |
| `REPI_CODING_AGENT_SESSION_DIR` | Override session storage directory (overridden by `--session-dir`) |
| `REPI_PACKAGE_DIR` | Override package directory (useful for Nix/Guix where store paths tokenize poorly; `PI_PACKAGE_DIR` remains a compatibility fallback) |
| `PI_OFFLINE` | Disable startup network operations, including update checks, package update checks, and install/update telemetry |
| `PI_SKIP_VERSION_CHECK` | Compatibility flag; REPI launcher sets it by default to suppress upstream Pi version checks |
| `PI_TELEMETRY` | Override install/update telemetry and provider attribution headers. Use `1`/`true`/`yes` to enable or `0`/`false`/`no` to disable. This does not disable update checks |
| `PI_CACHE_RETENTION` | Set to `long` for extended prompt cache (Anthropic: 1h, OpenAI: 24h) |
| `VISUAL`, `EDITOR` | External editor for Ctrl+G |

---

## Contributing & Development

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines and [docs/development.md](docs/development.md) for setup, forking, and debugging.

---

## License

MIT

## See Also

- [@pi-recon/repi-ai](https://www.npmjs.com/package/@pi-recon/repi-ai): Core LLM toolkit
- [@pi-recon/repi-agent-core](https://www.npmjs.com/package/@pi-recon/repi-agent-core): Agent framework
- [@pi-recon/repi-tui](https://www.npmjs.com/package/@pi-recon/repi-tui): Terminal UI components

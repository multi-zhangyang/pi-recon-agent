# Using REPI

This page collects day-to-day usage details that do not fit on the quickstart page.

## Interactive Mode

<p align="center"><img src="images/interactive-mode.png" alt="Interactive Mode" width="600"></p>

The interface has four main areas:

- **Startup header** - shortcuts, loaded context files, prompt templates, skills, and extensions
- **Messages** - user messages, assistant responses, tool calls, tool results, notifications, errors, and extension UI
- **Editor** - where you type; border color indicates the current thinking level
- **Footer** - working directory, session name, token/cache usage, cost, context usage, and current model

The editor can be replaced temporarily by built-in UI such as `/settings` or by custom extension UI.

### Editor Features

| Feature | How |
|---------|-----|
| File reference | Type `@` to fuzzy-search project files |
| Path completion | Press Tab to complete paths |
| Multi-line input | Shift+Enter, or Ctrl+Enter on Windows Terminal |
| Images | Paste with Ctrl+V, Alt+V on Windows, or drag into the terminal |
| Shell command | `!command` runs and sends output to the model |
| Hidden shell command | `!!command` runs without sending output to the model |
| External editor | Ctrl+G opens `$VISUAL` or `$EDITOR` |

See [Keybindings](keybindings.md) for all shortcuts and customization.

## Slash Commands

Type `/` in the editor to open command completion. Extensions can register custom commands, skills are available as `/skill:name`, and prompt templates expand via `/templatename`.

| Command | Description |
|---------|-------------|
| `/login`, `/logout` | Manage OAuth or API-key credentials |
| `/model` | Switch models |
| `/scoped-models` | Enable/disable models for Ctrl+P cycling |
| `/settings` | Thinking level, theme, message delivery, transport |
| `/resume` | Pick from previous sessions |
| `/new` | Start a new session |
| `/name <name>` | Set session display name |
| `/session` | Show session file, ID, messages, tokens, and cost |
| `/tree` | Jump to any point in the session and continue from there |
| `/fork` | Create a new session from a previous user message |
| `/clone` | Duplicate the current active branch into a new session |
| `/compact [prompt]` | Manually compact context, optionally with custom instructions |
| `/copy` | Copy last assistant message to clipboard |
| `/export [file]` | Export session to HTML |
| `/share` | Upload as private GitHub gist with shareable HTML link |
| `/reload` | Reload keybindings, extensions, skills, prompts, and context files |
| `/hotkeys` | Show all keyboard shortcuts |
| `/changelog` | Display version history |
| `/quit` | Quit repi |

## Message Queue

You can submit messages while the agent is still working:

- **Enter** queues a steering message, delivered after the current assistant turn finishes executing its tool calls.
- **Alt+Enter** queues a follow-up message, delivered after the agent finishes all work.
- **Escape** aborts and restores queued messages to the editor.
- **Alt+Up** retrieves queued messages back to the editor.

On Windows Terminal, Alt+Enter is fullscreen by default. Remap it as described in [Terminal setup](terminal-setup.md) if you want repi to receive the shortcut.

Configure delivery in [Settings](settings.md) with `steeringMode` and `followUpMode`.

## Sessions

Sessions are saved automatically to `~/.repi/agent/sessions/`, organized by working directory.

```bash
repi -c                  # Continue most recent session
repi -r                  # Browse and select a session
repi --no-session        # Ephemeral mode; do not save
repi --name "my task"    # Set session display name at startup
repi --session <path|id> # Use a specific session file or session ID
repi --fork <path|id>    # Fork a session into a new session file
```

Useful session commands:

- `/session` shows the current session file and ID.
- `/tree` navigates the in-file session tree and can summarize abandoned branches.
- `/fork` creates a new session from an earlier user message.
- `/clone` duplicates the current active branch into a new session file.
- `/compact` summarizes older messages to free context.

See [Sessions](sessions.md) and [Compaction](compaction.md) for details.

## Context Files

REPI loads `AGENTS.md` or `CLAUDE.md` at startup from:

- `~/.repi/agent/AGENTS.md` for global instructions
- parent directories, walking up from the current working directory when the project is trusted
- the current directory when the project is trusted

Use context files for project conventions, commands, safety rules, and preferences. Disable loading with `--no-context-files` or `-nc`.

### System Prompt Files

Replace the default system prompt with:

- `.repi/SYSTEM.md` for a project
- `~/.repi/agent/SYSTEM.md` globally

Append to the default prompt without replacing it with `APPEND_SYSTEM.md` in either location.

### Project Trust

On interactive startup, repi asks before trusting a project folder that contains project-local inputs and has no saved decision in `~/.repi/agent/trust.json`. Trust decisions inherit from parent directories, so trusting a repository root covers sessions started in its subdirectories unless a child path has its own decision. Trusting a project allows repi to read project instructions (`AGENTS.md`/`CLAUDE.md`), load `.repi/settings.json` and `.repi` resources, install missing project packages, and execute project extensions.

Non-interactive modes (`-p`, `--mode json`, and `--mode rpc`) do not show a trust prompt. Without a saved trust decision, they ignore project-local inputs unless `--approve`/`-a` is passed. Use `--no-approve`/`-na` to ignore project-local inputs for one run even when the project is trusted.

`repi config` assumes project trust for that command so you can view and change project resource settings before starting a session. It does not save a trust decision; starting a session in that folder still prompts. Pass `--no-approve` to hide project-local inputs in `repi config`.

Use `/trust` in interactive mode to save a project trust decision. The current session reloads resources after the decision is saved, and future sessions inherit the saved decision for that path and its subdirectories.

## Exporting and Sharing Sessions

Use `/export [file]` to write a session to HTML.

Use `/share` to upload a private GitHub gist with a shareable HTML link.

If you use repi for open source work and want to publish sessions for model, prompt, tool, and evaluation research, see [`badlogic/repi-share-hf`](https://github.com/badlogic/repi-share-hf). It publishes sessions to Hugging Face datasets.

## CLI Reference

```bash
repi [options] [@files...] [messages...]
```

### Package Commands

```bash
repi install <source> [-l]     # Install package, -l for project-local
repi remove <source> [-l]      # Remove package
repi uninstall <source> [-l]   # Alias for remove
repi update [source]          # Update installed packages; reconcile pinned git refs
repi update --extensions       # Update packages only; reconcile pinned git refs
repi update --extension <src>  # Update one package
repi list                      # List installed packages
repi config                    # Enable/disable package resources
```

These commands manage repi packages, not the repi CLI installation. `repi update pi` is intentionally rejected because REPI keeps the upstream `pi` command separate; `repi update` only updates REPI packages. To uninstall repi itself, see [Quickstart](quickstart.md#uninstall). Project package commands accept `--approve`/`--no-approve` to trust or ignore project-local package settings for one command.

See [REPI Packages](packages.md) for package sources and security notes.

### Modes

| Flag | Description |
|------|-------------|
| default | Interactive mode |
| `-p`, `--print` | Print response and exit |
| `--mode json` | Output all events as JSON lines; see [JSON mode](json.md) |
| `--mode rpc` | RPC mode over stdin/stdout; see [RPC mode](rpc.md) |
| `--export <in> [out]` | Export a session to HTML |

In print mode, repi also reads piped stdin and merges it into the initial prompt:

```bash
cat README.md | repi -p "从这份材料提取接口、鉴权和复现命令"
```

### Model Options

| Option | Description |
|--------|-------------|
| `--provider <name>` | Provider, such as `anthropic`, `openai`, or `google` |
| `--model <pattern>` | Model pattern or ID; supports `provider/id` and optional `:<thinking>` |
| `--api-key <key>` | API key, overriding environment variables |
| `--thinking <level>` | `off`, `minimal`, `low`, `medium`, `high`, `xhigh` |
| `--models <patterns>` | Comma-separated patterns for Ctrl+P cycling |
| `--list-models [search]` | List available models |

### Session Options

| Option | Description |
|--------|-------------|
| `-c`, `--continue` | Continue the most recent session |
| `-r`, `--resume` | Browse and select a session |
| `--session <path\|id>` | Use a specific session file or partial UUID |
| `--fork <path\|id>` | Fork a session file or partial UUID into a new session |
| `--session-dir <dir>` | Custom session storage directory |
| `--no-session` | Ephemeral mode; do not save |
| `--name <name>`, `-n <name>` | Set session display name at startup |

### Tool Options

| Option | Description |
|--------|-------------|
| `--tools <list>`, `-t <list>` | Allowlist specific built-in, extension, and custom tools |
| `--exclude-tools <list>`, `-xt <list>` | Disable specific built-in, extension, and custom tools |
| `--no-builtin-tools`, `-nbt` | Disable built-in tools but keep extension/custom tools enabled |
| `--no-tools`, `-nt` | Disable all tools |

Built-in tools: `read`, `bash`, `edit`, `write`, `grep`, `find`, `ls`.

### Resource Options

| Option | Description |
|--------|-------------|
| `-e`, `--extension <source>` | Load an extension from path, npm, or git; repeatable |
| `--no-extensions` | Disable extension discovery |
| `--skill <path>` | Load a skill; repeatable |
| `--no-skills` | Disable skill discovery |
| `--prompt-template <path>` | Load a prompt template; repeatable |
| `--no-prompt-templates` | Disable prompt template discovery |
| `--theme <path>` | Load a theme; repeatable |
| `--no-themes` | Disable theme discovery |
| `--no-context-files`, `-nc` | Disable `AGENTS.md` and `CLAUDE.md` discovery |

Combine `--no-*` with explicit flags to load exactly what you need, ignoring settings. Example:

```bash
repi --no-extensions -e ./my-extension.ts
```

### Other Options

| Option | Description |
|--------|-------------|
| `--system-prompt <text>` | Replace default prompt; context files and skills are still appended |
| `--append-system-prompt <text>` | Append to system prompt |
| `--verbose` | Force verbose startup |
| `-a`, `--approve` | Trust project-local files for this run |
| `-na`, `--no-approve` | Ignore project-local files for this run |
| `--clean-room` | REPI one-run isolation: ignore project context/resources |
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show version |

### File Arguments

Prefix files with `@` to include them in the message:

```bash
repi @prompt.md "Answer this"
repi -p @screenshot.png "What's in this image?"
repi @code.ts @test.ts "提取入口、验证路径和证据缺口"
```

### Examples

```bash
# Interactive with initial prompt
repi "对 ./challenge 做入口、路由、鉴权被动 mapping"

# Non-interactive
repi -p "提取当前仓库的攻击面、验证路径和证据缺口"

# Non-interactive with piped stdin
cat README.md | repi -p "从这份材料提取接口、鉴权和复现命令"

# Named one-shot session
repi --name "release audit" -p "Audit this repository"

# Different model
repi --provider openai --model gpt-4o "生成 Web/API 授权状态机审计计划"

# Model with provider prefix
repi --model openai/gpt-4o "生成 exploit-lab 复现矩阵"

# Model with thinking level shorthand
repi --model sonnet:high "Solve this complex problem"

# Limit model cycling
repi --models "claude-*,gpt-4o"

# Read-only mode
repi --tools read,grep,find,ls -p "只读审计 src/ 的路由、鉴权和危险 sink"

# Disable one extension or built-in tool while keeping the rest available
repi --exclude-tools ask_question
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `REPI_CODING_AGENT_DIR` | Override config directory; default is `~/.repi/agent` |
| `REPI_CODING_AGENT_SESSION_DIR` | Override session storage directory; overridden by `--session-dir` |
| `REPI_PACKAGE_DIR` | Override package directory, useful for Nix/Guix store paths (`PI_PACKAGE_DIR` remains a compatibility fallback) |
| `PI_OFFLINE` | Disable startup network operations, including update checks, package update checks, and install/update telemetry |
| `PI_SKIP_VERSION_CHECK` | Compatibility flag; REPI launcher sets it by default to suppress upstream Pi version checks |
| `PI_TELEMETRY` | Override install/update telemetry and provider attribution headers: `1`/`true`/`yes` or `0`/`false`/`no`. This does not disable update checks |
| `PI_CACHE_RETENTION` | Set to `long` for extended prompt cache where supported |
| `VISUAL`, `EDITOR` | External editor for Ctrl+G |

## Design Principles

REPI is organized around executable security-research workflows: passive mapping first, runtime proof before broad claims, evidence-ledger writeback, memory feedback, compact/resume continuity, and gate-backed capability claims.

The core remains extensible through extensions, skills, prompt templates, packages, runtime adapters, and external sandboxes. Built-in reverse/pentest commands provide the default operating system; project-specific policy and tool routing can still be layered on top.

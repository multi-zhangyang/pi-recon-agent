# Quickstart

This page gets you from install to a useful first repi session.

## Install

### Source install

Use this path when working from the open-source repository:

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm install --ignore-scripts
npm run install:repi
```

`install:repi` builds the four workspace runtime entrypoints before linking the launcher, so normal source installs run compiled JavaScript through Node instead of transpiling TypeScript on every startup.

Validate that the installed launcher is usable:

```bash
repi --offline --help
repi --offline --list-models
```

### Release tarball install

The `@pi-recon/*` packages are not published to the npm registry. Download the four files listed by `repi-release-manifest.json` from one GitHub Release and install them in one command:

```bash
npm install -g \
  ./pi-recon-repi-ai-0.1.3.tgz \
  ./pi-recon-repi-agent-core-0.1.3.tgz \
  ./pi-recon-repi-tui-0.1.3.tgz \
  ./pi-recon-repi-coding-agent-0.1.3.tgz
```

### Uninstall

If you installed from source with `npm run install:repi`, remove the global launcher symlink and keep or delete `~/.repi/agent` as needed:

```bash
sudo rm -f /usr/local/bin/repi
# optional: rm -rf ~/.repi/agent
```

If you installed the release tarballs globally, remove all four packages together:

```bash
npm uninstall -g \
  @pi-recon/repi-ai \
  @pi-recon/repi-agent-core \
  @pi-recon/repi-tui \
  @pi-recon/repi-coding-agent
```

Uninstalling the CLI does not automatically remove settings, credentials, sessions, and installed repi packages in `~/.repi/agent/`.

Then start repi in the project directory you want it to work on:

```bash
cd /path/to/project
repi
```

## Authenticate

REPI can use subscription providers through `/login`, or API-key providers through environment variables or the auth file.

### Option 1: subscription login

Start repi and run:

```text
/login
```

Then select a provider. Built-in subscription logins include Claude Pro/Max, ChatGPT Plus/Pro (Codex), and GitHub Copilot.

### Option 2: API key

Set an API key before launching repi:

```bash
export ANTHROPIC_API_KEY=<anthropic-api-key>
repi
```

You can also run `/login` and select an API-key provider to store the key in `~/.repi/agent/auth.json`.

See [Providers](providers.md) for all supported providers, environment variables, and cloud-provider setup.

## First session

Once repi starts, type a request and press Enter:

```text
Summarize this repository and tell me how to run its checks.
```

By default, repi gives the model four tools:

- `read` - read files
- `write` - create or overwrite files
- `edit` - patch files
- `bash` - run shell commands

Additional built-in read-only tools (`grep`, `find`, `ls`) are available through tool options. REPI runs in your current working directory and can modify files there. Use git or another checkpointing workflow if you want easy rollback.

## Give repi project instructions

REPI loads context files at startup. Add an `AGENTS.md` file to tell it how to work in a project:

```markdown
# Project Instructions

- Run `npm run check` after code changes.
- Do not run production migrations locally.
- Keep responses concise.
```

REPI loads:

- `~/.repi/agent/AGENTS.md` for global instructions
- `AGENTS.md` or `CLAUDE.md` from parent directories and the current directory

Restart repi, or run `/reload`, after changing context files.

## Common things to try

### Reference files

Type `@` in the editor to fuzzy-search files, or pass files on the command line:

```bash
repi @README.md "Summarize this"
repi @src/app.ts @src/app.test.ts "Review these together"
```

Images can be pasted with Ctrl+V (Alt+V on Windows) or dragged into supported terminals.

### Run shell commands

In interactive mode:

```text
!npm run lint
```

The command output is sent to the model. Use `!!command` to run a command without adding its output to the model context.

### Switch models

Use `/model` or Ctrl+L to choose a model. Use Shift+Tab to cycle thinking level. Use Ctrl+P / Shift+Ctrl+P to cycle through scoped models.

### Continue later

Sessions are saved automatically:

```bash
repi -c                  # Continue most recent session
repi -r                  # Browse previous sessions
repi --name "my task"    # Set session display name at startup
repi --session <path|id> # Open a specific session
```

Inside repi, use `/resume`, `/new`, `/tree`, `/fork`, and `/clone` to manage sessions.

### Non-interactive mode

For one-shot prompts:

```bash
repi -p "Summarize this codebase"
cat README.md | repi -p "Summarize this text"
repi -p @screenshot.png "What's in this image?"
```

Use `--mode json` for JSON event output or `--mode rpc` for process integration.

## Next steps

- [Using REPI](usage.md) - interactive mode, slash commands, sessions, context files, and CLI reference.
- [Providers](providers.md) - authentication and model setup.
- [Settings](settings.md) - global and project configuration.
- [Keybindings](keybindings.md) - shortcuts and customization.
- [REPI Packages](packages.md) - install shared extensions, skills, prompts, and themes.

Platform notes: [Windows](windows.md), [Termux](termux.md), [tmux](tmux.md), [Terminal setup](terminal-setup.md), [Shell aliases](shell-aliases.md).

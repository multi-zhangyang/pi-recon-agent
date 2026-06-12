# Development

See [AGENTS.md](https://github.com/multi-zhangyang/pi-recon-agent/blob/main/AGENTS.md) for additional guidelines.

## Setup

```bash
git clone https://github.com/multi-zhangyang/pi-recon-agent.git
cd pi-recon-agent
npm install
npm run build
```

Run from source:

```bash
/path/to/pi-recon-agent/repi
```

The source launcher can be run from any directory. REPI keeps the caller's current working directory.

## Product metadata

Core CLI metadata is configured via `package.json`:

```json
{
  "piConfig": {
    "name": "repi",
    "configDir": ".repi"
  }
}
```

For REPI releases, keep `name: "repi"`, `configDir: ".repi"`, and the `bin.repi` entry aligned. These fields affect the CLI banner, config paths, runtime profile directory, and environment variable names.

## Path Resolution

Three execution modes: npm install, standalone binary, tsx from source.

**Always use `src/config.ts`** for package assets:

```typescript
import { getPackageDir, getThemeDir } from "./config.js";
```

Never use `__dirname` directly for package assets.

## Debug Command

`/debug` (hidden) writes to `~/.repi/agent/repi-debug.log`:
- Rendered TUI lines with ANSI codes
- Last messages sent to the LLM

## Testing

```bash
./test.sh                         # Run non-LLM tests (no API keys needed)
npm test                          # Run all tests
npm test -- test/specific.test.ts # Run specific test
```

## Project Structure

```
packages/
  ai/           # LLM provider abstraction
  agent/        # Agent loop and message types  
  tui/          # Terminal UI components
  coding-agent/ # CLI and interactive mode
```

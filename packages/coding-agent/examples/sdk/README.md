# SDK Examples

Programmatic usage of repi-coding-agent via `createAgentSession()` and `createAgentSessionRuntime()`.

The runtime example shows how to build a recreate function that closes over process-global fixed inputs and recreates cwd-bound services and sessions as the active session cwd changes.

## Examples

| File | Description |
|------|-------------|
| `01-minimal.ts` | Simplest usage with models.json/REPI_* runtime configuration |
| `02-custom-model.ts` | Select model and thinking level |
| `03-custom-prompt.ts` | Replace or modify system prompt |
| `04-skills.ts` | Discover, filter, or replace skills |
| `05-tools.ts` | Built-in tool allowlists |
| `06-extensions.ts` | Logging, blocking, result modification |
| `07-context-files.ts` | AGENTS.md context files |
| `08-slash-commands.ts` | File-based slash commands |
| `09-api-keys-and-oauth.ts` | API key resolution, OAuth config |
| `10-settings.ts` | Override compaction, retry, terminal settings |
| `11-sessions.ts` | In-memory, persistent, continue, list sessions |
| `12-full-control.ts` | Replace everything, no discovery |
| `13-session-runtime.ts` | Manage runtime-backed session replacement |

## Running

```bash
cd packages/coding-agent
npx tsx examples/sdk/01-minimal.ts
```

## Quick Reference

```typescript
import type { Model } from "@pi-recon/repi-ai";
import {
  AuthStorage,
  createAgentSession,
  DefaultResourceLoader,
  ModelRegistry,
  ModelRuntime,
  SessionManager,
  SettingsManager,
} from "@pi-recon/repi-coding-agent";

// Auth and models setup. The runtime model set contains only entries supplied by
// ~/.repi/agent/models.json, a complete REPI_* config, or extensions.
const authStorage = AuthStorage.create();
const modelRuntime = await ModelRuntime.create({ credentials: authStorage.asCredentialStore() });

// Minimal
const { session } = await createAgentSession({ authStorage, modelRuntime });

// Select an explicitly configured model
const configuredModel = modelRuntime.getModel("my-provider", "my-model");
if (!configuredModel) throw new Error("Configure my-provider/my-model first");
const { session } = await createAgentSession({
  model: configuredModel,
  thinkingLevel: "high",
  authStorage,
  modelRuntime,
});

// Modify prompt
const loader = new DefaultResourceLoader({
  systemPromptOverride: (base) => `${base}\n\nBe concise.`,
});
await loader.reload();
const { session } = await createAgentSession({ resourceLoader: loader, authStorage, modelRuntime });

// Read-only
const { session } = await createAgentSession({
  tools: ["read", "grep", "find", "ls"],
  authStorage,
  modelRuntime,
});

// In-memory
const { session } = await createAgentSession({
  sessionManager: SessionManager.inMemory(),
  authStorage,
  modelRuntime,
});

// Full control
const customAuth = AuthStorage.create("/my/app/auth.json");
customAuth.setRuntimeApiKey("anthropic", process.env.MY_KEY!);
const customRegistry = ModelRegistry.inMemory(customAuth);
const model: Model<"anthropic-messages"> = {
  id: "claude-sonnet-4-5",
  name: "Claude Sonnet 4.5",
  api: "anthropic-messages",
  provider: "anthropic",
  baseUrl: "https://api.anthropic.com",
  reasoning: true,
  input: ["text", "image"],
  cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  contextWindow: 200000,
  maxTokens: 64000,
};

const resourceLoader = new DefaultResourceLoader({
  systemPromptOverride: () => "You are helpful.",
  extensionFactories: [myExtension],
  skillsOverride: () => ({ skills: [], diagnostics: [] }),
  agentsFilesOverride: () => ({ agentsFiles: [] }),
  promptsOverride: () => ({ prompts: [], diagnostics: [] }),
});
await resourceLoader.reload();

const { session } = await createAgentSession({
  model,
  authStorage: customAuth,
  modelRegistry: customRegistry,
  resourceLoader,
  tools: ["read", "bash", "my_tool"],
  customTools: [myTool],
  sessionManager: SessionManager.inMemory(),
  settingsManager: SettingsManager.inMemory(),
});

// Run prompts
session.subscribe((event) => {
  if (event.type === "message_update" && event.assistantMessageEvent.type === "text_delta") {
    process.stdout.write(event.assistantMessageEvent.delta);
  }
});
await session.prompt("Hello");
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `authStorage` | `AuthStorage.create()` | Credential storage |
| `modelRuntime` | `ModelRuntime.create(...)` | Canonical provider/auth/stream runtime; loads explicit models.json and REPI_* configuration |
| `modelRegistry` | Facade over `modelRuntime` | Compatibility model registry; pass one only for legacy/custom dispatch |
| `cwd` | `process.cwd()` | Working directory |
| `agentDir` | `~/.repi/agent` | Config directory |
| `model` | From settings/first explicitly configured available model | Model to use |
| `thinkingLevel` | From settings/"off" | off, low, medium, high |
| `tools` | `["read", "bash", "edit", "write"]` built-ins | Allowlist tool names across built-in, extension, and custom tools |
| `customTools` | `[]` | Additional tool definitions |
| `resourceLoader` | DefaultResourceLoader | Resource loader for extensions, skills, prompts, themes |
| `sessionManager` | `SessionManager.create(cwd)` | Persistence |
| `settingsManager` | `SettingsManager.create(cwd, agentDir)` | Settings overrides |

## Events

```typescript
session.subscribe((event) => {
  switch (event.type) {
    case "message_update":
      if (event.assistantMessageEvent.type === "text_delta") {
        process.stdout.write(event.assistantMessageEvent.delta);
      }
      break;
    case "tool_execution_start":
      console.log(`Tool: ${event.toolName}`);
      break;
    case "tool_execution_end":
      console.log(`Result: ${event.result}`);
      break;
    case "agent_end":
      console.log("Done");
      break;
  }
});
```

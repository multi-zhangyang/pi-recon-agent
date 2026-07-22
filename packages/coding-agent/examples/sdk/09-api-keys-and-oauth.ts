/**
 * API Keys and OAuth
 *
 * Configure credentials and explicit model sources via AuthStorage and ModelRuntime.
 */

import { AuthStorage, createAgentSession, ModelRuntime, SessionManager } from "@pi-recon/repi-coding-agent";

// AuthStorage uses ~/.repi/agent/auth.json. ModelRuntime loads only models
// declared in ~/.repi/agent/models.json or by a complete REPI_* environment config.
const authStorage = AuthStorage.create();
const modelRuntime = await ModelRuntime.create({ credentials: authStorage.asCredentialStore() });

const { session: defaultAuthSession } = await createAgentSession({
	sessionManager: SessionManager.inMemory(),
	authStorage,
	modelRuntime,
});
console.log("Session with the default credential store and explicit model runtime");
defaultAuthSession.dispose();

// Custom auth and models.json locations
const customAuthStorage = AuthStorage.create("/tmp/my-app/auth.json");
const customModelRuntime = await ModelRuntime.create({
	credentials: customAuthStorage.asCredentialStore(),
	modelsPath: "/tmp/my-app/models.json",
});

const { session: customAuthSession } = await createAgentSession({
	sessionManager: SessionManager.inMemory(),
	authStorage: customAuthStorage,
	modelRuntime: customModelRuntime,
});
console.log("Session with custom credential and model configuration locations");
customAuthSession.dispose();

// Runtime API key override for an explicitly declared provider (not persisted to disk)
await modelRuntime.setRuntimeApiKey("my-provider", process.env.MY_PROVIDER_API_KEY ?? "test-key");
const { session: runtimeKeySession } = await createAgentSession({
	sessionManager: SessionManager.inMemory(),
	authStorage,
	modelRuntime,
});
console.log("Session with runtime API key override");
runtimeKeySession.dispose();

// Disable models.json while still allowing a complete REPI_* environment model.
const envOnlyRuntime = await ModelRuntime.create({
	credentials: authStorage.asCredentialStore(),
	modelsPath: null,
});
const { session: envOnlySession } = await createAgentSession({
	sessionManager: SessionManager.inMemory(),
	authStorage,
	modelRuntime: envOnlyRuntime,
});
console.log("Session with models.json disabled; only REPI_* or extensions can add models");
envOnlySession.dispose();

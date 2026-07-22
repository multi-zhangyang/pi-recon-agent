import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AssistantMessage,
	type AssistantMessageEventStream,
	createAssistantMessageEventStream,
	type Model,
	type Provider,
	type ProviderHeaders,
	type RefreshModelsContext,
	type SimpleStreamOptions,
} from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { ModelRuntime } from "../src/core/model-runtime.ts";
import { InMemoryCodingAgentModelsStore } from "../src/core/models-store.ts";

const tempDirs: string[] = [];
const repiEnvNames = [
	"REPI_BASE_URL",
	"REPI_MODEL_BASE_URL",
	"REPI_MODEL",
	"REPI_MODEL_ID",
	"REPI_MODEL_API",
	"REPI_API",
	"REPI_AUTH_TOKEN",
	"REPI_API_KEY",
	"REPI_MODEL_API_KEY",
	"REPI_PROVIDER",
	"REPI_MODEL_PROVIDER",
	"REPI_PROVIDER_ID",
	"REPI_PROVIDER_NAME",
	"REPI_MODEL_NAME",
	"REPI_MODEL_INPUT",
	"REPI_MODEL_REASONING",
	"REPI_MODEL_COST_INPUT",
	"REPI_MODEL_COST_OUTPUT",
	"REPI_MODEL_COST_CACHE_READ",
	"REPI_MODEL_COST_CACHE_WRITE",
] as const;
let repiEnvSnapshot = new Map<string, string | undefined>();

beforeEach(() => {
	repiEnvSnapshot = new Map(repiEnvNames.map((name) => [name, process.env[name]]));
	for (const name of repiEnvNames) delete process.env[name];
});

afterEach(() => {
	for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
	for (const [name, value] of repiEnvSnapshot) {
		if (value === undefined) delete process.env[name];
		else process.env[name] = value;
	}
});

function testModel(provider: string, id = "model-a"): Model<"openai-completions"> {
	return {
		id,
		name: id,
		api: "openai-completions",
		provider,
		baseUrl: "https://base.example/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 10_000,
		maxTokens: 1_000,
	};
}

function doneMessage(model: Model<string>): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text: "ok" }],
		api: model.api,
		provider: model.provider,
		model: model.id,
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
		timestamp: Date.now(),
	};
}

function completedStream(model: Model<string>): AssistantMessageEventStream {
	const stream = createAssistantMessageEventStream();
	const message = doneMessage(model);
	stream.push({ type: "done", reason: "stop", message });
	stream.end(message);
	return stream;
}

function testProvider(
	providerId: string,
	onRequest?: (model: Model<string>, options: SimpleStreamOptions | undefined) => void,
): Provider {
	const model = testModel(providerId);
	return {
		id: providerId,
		name: providerId,
		auth: {
			apiKey: {
				name: "Test key",
				resolve: async ({ ctx, credential }) => {
					const key = credential?.key ?? (await ctx.env("TEST_PROVIDER_KEY"));
					return key ? { auth: { apiKey: key }, source: credential ? "stored" : "environment" } : undefined;
				},
			},
		},
		getModels: () => [model],
		stream: (requestModel, _context, options) => {
			onRequest?.(requestModel, options);
			return completedStream(requestModel);
		},
		streamSimple: (requestModel, _context, options) => {
			onRequest?.(requestModel, options);
			return completedStream(requestModel);
		},
	};
}

function refreshableProvider(
	providerId: string,
	getModels: () => readonly Model<"openai-completions">[],
	refreshModels: (context: RefreshModelsContext) => Promise<void>,
): Provider {
	return {
		...testProvider(providerId),
		auth: {
			apiKey: {
				name: "Ambient test auth",
				check: async () => ({ type: "api_key", source: "test" }),
				resolve: async () => ({ auth: { apiKey: "test-key" }, source: "test" }),
			},
		},
		getModels,
		refreshModels,
	};
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
	let resolve = () => {};
	const promise = new Promise<void>((resolvePromise) => {
		resolve = resolvePromise;
	});
	return { promise, resolve };
}

function writeModelsConfig(config: unknown): string {
	const dir = mkdtempSync(join(tmpdir(), "repi-model-runtime-core-"));
	tempDirs.push(dir);
	const path = join(dir, "models.json");
	writeFileSync(path, JSON.stringify(config));
	return path;
}

describe("ModelRuntime core", () => {
	it("rejects malformed extension models before they poison the runtime catalog", async () => {
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath: null,
			allowModelNetwork: false,
		});
		const validModel = testModel("valid-provider", "valid-model");
		const providerConfig = {
			baseUrl: "https://valid.example/v1",
			apiKey: "test-key",
			api: "openai-completions" as const,
			models: [validModel],
		};

		try {
			runtime.registerProvider("valid-provider", providerConfig);
			expect(runtime.getModel("valid-provider", "valid-model")).toBeDefined();

			for (const [providerId, model, message] of [
				["invalid-id", { ...validModel, id: undefined }, '"id" must be a non-empty string'],
				["invalid-context", { ...validModel, contextWindow: Number.NaN }, "invalid contextWindow"],
				["invalid-output", { ...validModel, maxTokens: Number.POSITIVE_INFINITY }, "invalid maxTokens"],
			] as const) {
				expect(() =>
					runtime.registerProvider(providerId, {
						...providerConfig,
						models: [model as typeof validModel],
					}),
				).toThrow(message);
				expect(runtime.getProvider(providerId)).toBeUndefined();
			}

			expect(runtime.getModel("valid-provider", "valid-model")).toBeDefined();
		} finally {
			runtime.dispose();
		}
	});

	it("starts without the legacy built-in provider catalog by default", async () => {
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath: null,
			allowModelNetwork: false,
		});

		expect(runtime.getProviders()).toEqual([]);
		expect(runtime.getModels()).toEqual([]);
	});

	it("does not load a generated provider catalog", async () => {
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath: null,
			allowModelNetwork: false,
		});

		expect(runtime.getProviders()).toEqual([]);
		expect(runtime.getModels()).toEqual([]);
	});

	it("loads the explicit REPI environment provider without a generated catalog", async () => {
		const names = [
			"REPI_AUTH_TOKEN",
			"REPI_BASE_URL",
			"REPI_MODEL",
			"REPI_MODEL_API",
			"REPI_CONTEXT_WINDOW",
			"REPI_MAX_TOKENS",
			"REPI_PROVIDER_NAME",
			"REPI_MODEL_NAME",
			"REPI_MODEL_INPUT",
			"REPI_MODEL_REASONING",
			"REPI_MODEL_COST_INPUT",
			"REPI_MODEL_COST_OUTPUT",
			"REPI_MODEL_COST_CACHE_READ",
			"REPI_MODEL_COST_CACHE_WRITE",
		] as const;
		const original = new Map(names.map((name) => [name, process.env[name]]));
		Object.assign(process.env, {
			REPI_AUTH_TOKEN: "runtime-env-key",
			REPI_BASE_URL: "https://runtime-env.example/v1",
			REPI_MODEL: "runtime-env-model",
			REPI_MODEL_API: "openai-compatible",
			REPI_CONTEXT_WINDOW: "196608",
			REPI_MAX_TOKENS: "32768",
			REPI_PROVIDER_NAME: "Runtime Gateway",
			REPI_MODEL_NAME: "Runtime Environment Model",
			REPI_MODEL_INPUT: "text,image",
			REPI_MODEL_REASONING: "true",
			REPI_MODEL_COST_INPUT: "0.25",
			REPI_MODEL_COST_OUTPUT: "1.5",
			REPI_MODEL_COST_CACHE_READ: "0.025",
			REPI_MODEL_COST_CACHE_WRITE: "0.3",
		});

		try {
			const runtime = await ModelRuntime.create({
				credentials: AuthStorage.inMemory().asCredentialStore(),
				modelsPath: null,
				providers: [],
				allowModelNetwork: false,
			});

			expect(runtime.getProviders().map((provider) => [provider.id, provider.name])).toEqual([
				["repi-env", "Runtime Gateway"],
			]);
			expect(runtime.getModel("repi-env", "runtime-env-model")).toMatchObject({
				name: "Runtime Environment Model",
				api: "openai-completions",
				baseUrl: "https://runtime-env.example/v1",
				reasoning: true,
				input: ["text", "image"],
				cost: { input: 0.25, output: 1.5, cacheRead: 0.025, cacheWrite: 0.3 },
				contextWindow: 196608,
				maxTokens: 32768,
			});
			expect((await runtime.getAuth("repi-env"))?.auth.apiKey).toBe("runtime-env-key");
		} finally {
			for (const [name, value] of original) {
				if (value === undefined) delete process.env[name];
				else process.env[name] = value;
			}
		}
	});

	it("loads complete model metadata from models.json without a built-in catalog", async () => {
		const modelsPath = writeModelsConfig({
			providers: {
				explicit: {
					baseUrl: "https://explicit.example/v1",
					apiKey: "literal-key",
					api: "openai-completions",
					models: [
						{
							id: "explicit-model",
							name: "Explicit Model",
							reasoning: true,
							input: ["text", "image"],
							cost: { input: 0.2, output: 0.8, cacheRead: 0.02, cacheWrite: 0.24 },
							contextWindow: 262_144,
							maxTokens: 32_768,
						},
					],
				},
			},
		});
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath,
			providers: [],
			allowModelNetwork: false,
		});

		expect(runtime.getProviders().map((provider) => provider.id)).toEqual(["explicit"]);
		expect(runtime.getModel("explicit", "explicit-model")).toMatchObject({
			name: "Explicit Model",
			reasoning: true,
			input: ["text", "image"],
			cost: { input: 0.2, output: 0.8, cacheRead: 0.02, cacheWrite: 0.24 },
			contextWindow: 262_144,
			maxTokens: 32_768,
		});
		expect((await runtime.getAuth("explicit"))?.auth.apiKey).toBe("literal-key");
	});

	it("reloads models.json while preserving and then revealing extension overlays", async () => {
		const modelsPath = writeModelsConfig({
			providers: {
				explicit: {
					baseUrl: "https://saved-old.example/v1",
					apiKey: "literal-key",
					api: "openai-completions",
					models: [
						{ ...testModel("explicit", "old-model"), baseUrl: undefined, provider: undefined, api: undefined },
					],
				},
			},
		});
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath,
			allowModelNetwork: false,
		});
		runtime.registerProvider("explicit", { baseUrl: "https://extension.example/v1" });
		expect(runtime.getModel("explicit", "old-model")?.baseUrl).toBe("https://extension.example/v1");

		writeFileSync(
			modelsPath,
			JSON.stringify({
				providers: {
					explicit: {
						baseUrl: "https://saved-new.example/v1",
						apiKey: "literal-key",
						api: "openai-completions",
						models: [
							{ ...testModel("explicit", "new-model"), baseUrl: undefined, provider: undefined, api: undefined },
						],
					},
				},
			}),
		);
		await runtime.reloadConfig();

		expect(runtime.getModel("explicit", "old-model")).toBeUndefined();
		expect(runtime.getModel("explicit", "new-model")?.baseUrl).toBe("https://extension.example/v1");

		runtime.unregisterProvider("explicit");
		expect(runtime.getModel("explicit", "new-model")?.baseUrl).toBe("https://saved-new.example/v1");
	});

	it("publishes runtime extension OAuth to the interactive login registry", async () => {
		const providerId = "runtime-oauth-extension";
		const authStorage = AuthStorage.inMemory();
		const runtime = await ModelRuntime.create({
			credentials: authStorage.asCredentialStore(),
			modelsPath: null,
			allowModelNetwork: false,
		});

		runtime.registerProvider(providerId, {
			name: "Runtime OAuth Extension",
			baseUrl: "https://runtime-oauth.example/v1",
			api: "openai-completions",
			oauth: {
				name: "Runtime OAuth Extension",
				login: async () => ({
					access: "runtime-access",
					refresh: "runtime-refresh",
					expires: Date.now() + 60_000,
				}),
				refreshToken: async (credentials) => credentials,
				getApiKey: (credentials) => credentials.access,
			},
			models: [
				{
					id: "runtime-oauth-model",
					name: "Runtime OAuth Model",
					reasoning: false,
					input: ["text"],
					cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 10_000,
					maxTokens: 1_000,
				},
			],
		});

		try {
			ModelRegistry.inMemory(AuthStorage.inMemory()).refresh();
			expect(authStorage.getOAuthProviders()).toContainEqual(
				expect.objectContaining({ id: providerId, name: "Runtime OAuth Extension" }),
			);
			await authStorage.login(providerId, {
				onAuth: () => {},
				onDeviceCode: () => {},
				onPrompt: async () => "",
				onSelect: async () => undefined,
			});
			expect(authStorage.get(providerId)).toMatchObject({ type: "oauth", access: "runtime-access" });
			expect(runtime.isUsingOAuth(providerId)).toBe(true);
		} finally {
			runtime.dispose();
			runtime.dispose();
		}

		expect(authStorage.getOAuthProviders().some((provider) => provider.id === providerId)).toBe(false);
	});

	it("aborts a background provider refresh without restoring OAuth after dispose", async () => {
		const providerId = "runtime-oauth-dispose-refresh";
		const authStorage = AuthStorage.inMemory();
		const runtime = await ModelRuntime.create({
			credentials: authStorage.asCredentialStore(),
			modelsPath: null,
			allowModelNetwork: false,
		});
		const refreshStarted = deferred();
		const releaseRefresh = deferred();
		let refreshFinished = false;
		let refreshWasAborted = false;

		runtime.registerProvider(providerId, {
			name: "Disposable OAuth Extension",
			baseUrl: "https://runtime-oauth-dispose.example/v1",
			api: "openai-completions",
			oauth: {
				name: "Disposable OAuth Extension",
				login: async () => ({ access: "access", refresh: "refresh", expires: Date.now() + 60_000 }),
				refreshToken: async (credentials) => credentials,
				getApiKey: (credentials) => credentials.access,
			},
			models: [testModel(providerId, "initial")],
			refreshModels: async ({ signal }) => {
				refreshStarted.resolve();
				await releaseRefresh.promise;
				refreshWasAborted = signal?.aborted === true;
				refreshFinished = true;
				return [testModel(providerId, "late")];
			},
		});

		await refreshStarted.promise;
		expect(authStorage.getOAuthProviders().some((provider) => provider.id === providerId)).toBe(true);
		runtime.dispose();
		releaseRefresh.resolve();
		await vi.waitFor(() => expect(refreshFinished).toBe(true));

		expect(refreshWasAborted).toBe(true);
		expect(authStorage.getOAuthProviders().some((provider) => provider.id === providerId)).toBe(false);
		expect(await runtime.refresh({ allowNetwork: true })).toEqual({ aborted: true, errors: new Map() });
	});

	it("does not dispatch a provider stream or accept mutations after dispose", async () => {
		let requestCount = 0;
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory({
				explicit: { type: "api_key", key: "stored-key" },
			}).asCredentialStore(),
			modelsPath: null,
			providers: [testProvider("explicit", () => requestCount++)],
			allowModelNetwork: false,
		});
		const model = runtime.getModel("explicit", "model-a")!;

		runtime.dispose();
		const result = await runtime.completeSimple(model, { messages: [] });

		expect(result).toMatchObject({
			stopReason: "error",
			errorMessage: "Model runtime has been disposed",
		});
		expect(requestCount).toBe(0);
		await expect(runtime.getAuth("explicit")).rejects.toThrow("Model runtime has been disposed");
		await expect(runtime.setRuntimeApiKey("explicit", "late-key")).rejects.toThrow("Model runtime has been disposed");
		expect(() => runtime.unregisterProvider("explicit")).toThrow("Model runtime has been disposed");
	});

	it("releases shared AuthStorage subscriptions across repeated runtime lifecycles", async () => {
		const authStorage = AuthStorage.inMemory();
		const subscribe = authStorage.subscribe.bind(authStorage);
		let activeSubscriptions = 0;
		vi.spyOn(authStorage, "subscribe").mockImplementation((listener) => {
			activeSubscriptions++;
			const unsubscribe = subscribe(listener);
			let active = true;
			return () => {
				if (!active) return;
				active = false;
				activeSubscriptions--;
				unsubscribe();
			};
		});

		for (let index = 0; index < 5; index++) {
			const runtime = await ModelRuntime.create({
				credentials: authStorage.asCredentialStore(),
				modelsPath: null,
				allowModelNetwork: false,
			});
			expect(activeSubscriptions).toBe(1);
			runtime.dispose();
			runtime.dispose();
			expect(activeSubscriptions).toBe(0);
		}
	});

	it("releases its credential subscription when startup initialization rejects", async () => {
		const authStorage = AuthStorage.inMemory();
		const subscribe = authStorage.subscribe.bind(authStorage);
		let activeSubscriptions = 0;
		const subscribeSpy = vi.spyOn(authStorage, "subscribe").mockImplementation((listener) => {
			activeSubscriptions++;
			const unsubscribe = subscribe(listener);
			return () => {
				activeSubscriptions--;
				unsubscribe();
			};
		});
		const refresh = vi
			.spyOn(ModelRuntime.prototype, "refresh")
			.mockRejectedValueOnce(new Error("startup refresh failed"));

		try {
			await expect(
				ModelRuntime.create({
					credentials: authStorage.asCredentialStore(),
					modelsPath: null,
					allowModelNetwork: false,
				}),
			).rejects.toThrow("startup refresh failed");
		} finally {
			refresh.mockRestore();
			subscribeSpy.mockRestore();
		}

		expect(activeSubscriptions).toBe(0);
	});

	it("replaces and removes the REPI environment provider during config reload", async () => {
		Object.assign(process.env, {
			REPI_AUTH_TOKEN: "old-token",
			REPI_BASE_URL: "https://env-old.example/v1",
			REPI_PROVIDER: "env-old",
			REPI_MODEL: "old-model",
		});
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath: null,
			providers: [],
			allowModelNetwork: false,
		});
		expect(runtime.getModel("env-old", "old-model")).toBeDefined();

		Object.assign(process.env, {
			REPI_AUTH_TOKEN: "new-token",
			REPI_BASE_URL: "https://env-new.example/v1",
			REPI_PROVIDER: "env-new",
			REPI_MODEL: "new-model",
		});
		await runtime.reloadConfig();

		expect(runtime.getProvider("env-old")).toBeUndefined();
		expect(runtime.getModel("env-new", "new-model")?.baseUrl).toBe("https://env-new.example/v1");
		expect((await runtime.getAuth("env-new"))?.auth.apiKey).toBe("new-token");

		for (const name of ["REPI_AUTH_TOKEN", "REPI_BASE_URL", "REPI_PROVIDER", "REPI_MODEL"] as const) {
			delete process.env[name];
		}
		await runtime.reloadConfig();
		expect(runtime.getProviders()).toEqual([]);
	});

	it("keeps facade auth status aligned with provider credential support", async () => {
		const authStorage = AuthStorage.inMemory({
			explicit: { type: "oauth", refresh: "refresh", access: "access", expires: Date.now() + 60_000 },
		});
		const modelsPath = writeModelsConfig({
			providers: {
				explicit: {
					baseUrl: "https://explicit.example/v1",
					apiKey: "literal-key",
					api: "openai-completions",
					models: [
						{
							...testModel("explicit", "explicit-model"),
							baseUrl: undefined,
							provider: undefined,
							api: undefined,
						},
					],
				},
			},
		});
		const runtime = await ModelRuntime.create({
			credentials: authStorage.asCredentialStore(),
			modelsPath,
			allowModelNetwork: false,
		});
		const registry = ModelRegistry.fromRuntime(authStorage, runtime);
		const model = registry.find("explicit", "explicit-model")!;

		expect(runtime.hasConfiguredAuth("explicit")).toBe(false);
		expect(registry.hasConfiguredAuth(model)).toBe(false);
		expect(registry.getProviderAuthStatus("explicit")).toEqual({ configured: false });

		authStorage.set("explicit", { type: "api_key", key: "saved-key" });
		expect(registry.hasConfiguredAuth(model)).toBe(true);
		expect(registry.getProviderAuthStatus("explicit")).toMatchObject({ configured: true, source: "stored" });
		await registry.refresh();
		expect(runtime.hasConfiguredAuth("explicit")).toBe(true);

		authStorage.set("explicit", {
			type: "oauth",
			refresh: "refresh-again",
			access: "access-again",
			expires: Date.now() + 60_000,
		});
		expect(registry.hasConfiguredAuth(model)).toBe(false);
		expect(registry.getProviderAuthStatus("explicit")).toEqual({ configured: false });
		await registry.refresh();
		expect(runtime.hasConfiguredAuth("explicit")).toBe(false);
	});

	it("invalidates runtime and registry auth snapshots after external AuthStorage mutations", async () => {
		const authStorage = AuthStorage.inMemory({
			explicit: { type: "api_key", key: "initial-key" },
		});
		const runtime = await ModelRuntime.create({
			credentials: authStorage.asCredentialStore(),
			modelsPath: null,
			providers: [testProvider("explicit")],
			authContext: {
				env: async () => undefined,
				fileExists: async () => false,
			},
			allowModelNetwork: false,
		});
		const registry = ModelRegistry.fromRuntime(authStorage, runtime);
		const model = runtime.getModel("explicit", "model-a")!;

		expect(runtime.hasConfiguredAuth("explicit")).toBe(true);
		expect(registry.hasConfiguredAuth(model)).toBe(true);
		expect((await runtime.getAuth("explicit"))?.auth.apiKey).toBe("initial-key");

		authStorage.remove("explicit");

		expect(runtime.hasConfiguredAuth("explicit")).toBe(false);
		expect(runtime.getProviderAuthStatus("explicit")).toEqual({ configured: false });
		expect(registry.hasConfiguredAuth(model)).toBe(false);
		expect(registry.getProviderAuthStatus("explicit")).toEqual({ configured: false });
		expect(runtime.getAvailableSnapshot()).toEqual([]);
		expect(await runtime.getAuth("explicit")).toBeUndefined();

		authStorage.set("explicit", {
			type: "oauth",
			access: "unsupported-access",
			refresh: "unsupported-refresh",
			expires: Date.now() + 60_000,
		});
		expect(runtime.hasConfiguredAuth("explicit")).toBe(false);
		expect(registry.getProviderAuthStatus("explicit")).toEqual({ configured: false });
		expect(await runtime.getAuth("explicit")).toBeUndefined();

		authStorage.set("explicit", { type: "api_key", key: "replacement-key" });
		expect(runtime.hasConfiguredAuth("explicit")).toBe(true);
		expect(runtime.getProviderAuthStatus("explicit")).toEqual({ configured: true, source: "stored" });
		expect(registry.hasConfiguredAuth(model)).toBe(true);
		expect(registry.getProviderAuthStatus("explicit")).toEqual({ configured: true, source: "stored" });
		expect(runtime.getAvailableSnapshot()).toEqual([model]);
		expect((await runtime.getAuth("explicit"))?.auth.apiKey).toBe("replacement-key");
	});

	it("tracks AuthStorage runtime overrides without a manual runtime refresh", async () => {
		const authStorage = AuthStorage.inMemory();
		const runtime = await ModelRuntime.create({
			credentials: authStorage.asCredentialStore(),
			modelsPath: null,
			providers: [testProvider("explicit")],
			authContext: {
				env: async () => undefined,
				fileExists: async () => false,
			},
			allowModelNetwork: false,
		});
		const registry = ModelRegistry.fromRuntime(authStorage, runtime);
		const model = runtime.getModel("explicit", "model-a")!;

		authStorage.setRuntimeApiKey("explicit", "runtime-key");
		expect(runtime.hasConfiguredAuth("explicit")).toBe(true);
		expect(runtime.getProviderAuthStatus("explicit")).toEqual({ configured: true, source: "runtime" });
		expect(registry.getProviderAuthStatus("explicit")).toMatchObject({ configured: true, source: "runtime" });
		expect((await runtime.getAuth("explicit"))?.auth.apiKey).toBe("runtime-key");

		authStorage.removeRuntimeApiKey("explicit");
		expect(runtime.hasConfiguredAuth("explicit")).toBe(false);
		expect(registry.hasConfiguredAuth(model)).toBe(false);
		expect(runtime.getProviderAuthStatus("explicit")).toEqual({ configured: false });
		expect(await runtime.getAuth("explicit")).toBeUndefined();
	});

	it("uses explicit AuthStorage credentials for models outside the runtime catalog", async () => {
		const authStorage = AuthStorage.inMemory();
		const runtime = await ModelRuntime.create({
			credentials: authStorage.asCredentialStore(),
			modelsPath: null,
			allowModelNetwork: false,
		});
		const registry = ModelRegistry.fromRuntime(authStorage, runtime);
		const model = testModel("sdk-explicit", "sdk-model");

		expect(runtime.getProvider(model.provider)).toBeUndefined();
		expect(registry.hasConfiguredAuth(model)).toBe(false);
		expect(registry.getProviderAuthStatus(model.provider)).toEqual({ configured: false });

		authStorage.setRuntimeApiKey(model.provider, "runtime-key");

		expect(registry.hasConfiguredAuth(model)).toBe(true);
		expect(registry.getProviderAuthStatus(model.provider)).toMatchObject({ configured: true, source: "runtime" });
		expect(await registry.getApiKeyAndHeaders(model)).toEqual({
			ok: true,
			apiKey: "runtime-key",
			headers: undefined,
		});
	});

	it("keeps runtime API-key overrides out of the atomic persistent store", async () => {
		const authStorage = AuthStorage.inMemory({
			native: { type: "api_key", key: "stored-key" },
		});
		const runtime = await ModelRuntime.create({
			credentials: authStorage.asCredentialStore(),
			modelsPath: null,
			providers: [testProvider("native")],
			allowModelNetwork: false,
		});

		expect((await runtime.getAuth("native"))?.auth.apiKey).toBe("stored-key");
		await runtime.setRuntimeApiKey("native", "runtime-key");
		expect((await runtime.getAuth("native"))?.auth.apiKey).toBe("runtime-key");
		expect(authStorage.get("native")).toEqual({ type: "api_key", key: "stored-key" });
		expect(runtime.getProviderAuthStatus("native")).toMatchObject({ configured: true, source: "runtime" });

		await runtime.removeRuntimeApiKey("native");
		expect((await runtime.getAuth("native"))?.auth.apiKey).toBe("stored-key");
		expect(authStorage.get("native")).toEqual({ type: "api_key", key: "stored-key" });
	});

	it("registers the REPI environment provider before the initial refresh", async () => {
		process.env.REPI_BASE_URL = "https://env.example/v1";
		process.env.REPI_MODEL = "env-model";
		process.env.REPI_AUTH_TOKEN = "env-token";
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath: null,
			providers: [],
			allowModelNetwork: false,
		});

		expect(runtime.getModel("repi-env", "env-model")).toMatchObject({
			baseUrl: "https://env.example/v1",
			api: "openai-completions",
		});
		expect(runtime.hasConfiguredAuth("repi-env")).toBe(true);
	});

	it("reports an invalid REPI environment API through the runtime error surface", async () => {
		process.env.REPI_BASE_URL = "https://env.example/v1";
		process.env.REPI_MODEL = "env-model";
		process.env.REPI_MODEL_API = "invalid-api";
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath: null,
			providers: [],
			allowModelNetwork: false,
		});

		expect(runtime.getProviders()).toEqual([]);
		expect(runtime.getError()).toContain("invalid REPI_MODEL_API");
	});

	it("keeps the latest refresh state when an older refresh finishes last", async () => {
		const firstGate = deferred();
		const secondGate = deferred();
		let armed = false;
		let networkCalls = 0;
		const provider = refreshableProvider(
			"ordered",
			() => [testModel("ordered")],
			async ({ allowNetwork }) => {
				if (!allowNetwork || !armed) return;
				const call = networkCalls++;
				await (call === 0 ? firstGate.promise : secondGate.promise);
				if (call === 0) throw new Error("stale refresh failure");
			},
		);
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath: null,
			providers: [provider],
			allowModelNetwork: false,
		});
		armed = true;

		const first = runtime.refresh({ allowNetwork: true });
		await vi.waitFor(() => expect(networkCalls).toBe(1));
		const second = runtime.refresh({ allowNetwork: true });
		await vi.waitFor(() => expect(networkCalls).toBe(2));
		secondGate.resolve();
		await second;
		expect(runtime.getError()).toBeUndefined();

		firstGate.resolve();
		expect((await first).errors.get("ordered")?.message).toBe("stale refresh failure");
		expect(runtime.getError()).toBeUndefined();
	});

	it("does not clear a recorded refresh failure when a later refresh is aborted", async () => {
		let fail = false;
		const provider = refreshableProvider(
			"stateful",
			() => [testModel("stateful")],
			async ({ allowNetwork }) => {
				if (allowNetwork && fail) throw new Error("historical refresh failure");
			},
		);
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath: null,
			providers: [provider],
			allowModelNetwork: false,
		});
		fail = true;
		await runtime.refresh({ allowNetwork: true });
		expect(runtime.getError()).toContain("historical refresh failure");

		const controller = new AbortController();
		controller.abort();
		const aborted = await runtime.refresh({ allowNetwork: true, signal: controller.signal });
		expect(aborted.aborted).toBe(true);
		expect(runtime.getError()).toContain("historical refresh failure");
	});

	it("enforces a hard startup deadline and quarantines late catalog writes", async () => {
		const gate = deferred();
		const modelsStore = new InMemoryCodingAgentModelsStore();
		let finished = false;
		let networkCalls = 0;
		let catalog: readonly Model<"openai-completions">[] = [testModel("slow", "baseline")];
		const provider = refreshableProvider(
			"slow",
			() => catalog,
			async ({ allowNetwork, store }) => {
				if (!allowNetwork) return;
				networkCalls++;
				await gate.promise;
				catalog = [testModel("slow", "late")];
				await store.write({ models: catalog, checkedAt: Date.now() });
				finished = true;
			},
		);
		const startedAt = Date.now();
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath: null,
			modelsStore,
			providers: [provider],
			allowModelNetwork: true,
			modelRefreshTimeoutMs: 40,
		});

		expect(Date.now() - startedAt).toBeLessThan(1_000);
		expect(networkCalls).toBe(1);
		expect(runtime.getModel("slow", "baseline")).toBeDefined();
		expect(runtime.getError()).toContain("timed out after 40ms");

		gate.resolve();
		await vi.waitFor(() => expect(finished).toBe(true));
		expect(runtime.getModel("slow", "late")).toBeUndefined();
		expect(await modelsStore.read("slow")).toBeUndefined();
	});

	it("does not erase a full availability error after one provider succeeds", async () => {
		const good = refreshableProvider(
			"good",
			() => [testModel("good")],
			async () => {},
		);
		const bad: Provider = {
			...testProvider("bad"),
			auth: {
				apiKey: {
					name: "Broken check",
					check: async () => {
						throw new Error("bad availability check");
					},
					resolve: async () => ({ auth: { apiKey: "bad-key" } }),
				},
			},
		};
		const runtime = await ModelRuntime.create({
			credentials: AuthStorage.inMemory().asCredentialStore(),
			modelsPath: null,
			providers: [good, bad],
			allowModelNetwork: false,
		});
		expect(runtime.getError()).toContain("API key auth check failed for provider bad");

		expect((await runtime.getAvailable("good")).map((model) => model.provider)).toEqual(["good"]);
		expect(runtime.getError()).toContain("API key auth check failed for provider bad");
	});

	it("assembles auth, headers, env, and stream dispatch exactly once with request env first", async () => {
		const originalKey = process.env.REPI_RUNTIME_KEY;
		const originalProviderHeader = process.env.REPI_RUNTIME_PROVIDER_HEADER;
		const originalModelHeader = process.env.REPI_RUNTIME_MODEL_HEADER;
		process.env.REPI_RUNTIME_KEY = "process-key";
		process.env.REPI_RUNTIME_PROVIDER_HEADER = "process-provider";
		process.env.REPI_RUNTIME_MODEL_HEADER = "process-model";

		let capturedModel: Model<string> | undefined;
		let capturedOptions: SimpleStreamOptions | undefined;
		let transforms = 0;
		try {
			const runtime = await ModelRuntime.create({
				credentials: AuthStorage.inMemory().asCredentialStore(),
				modelsPath: null,
				allowModelNetwork: false,
			});
			runtime.registerProvider("scoped", {
				name: "Scoped",
				baseUrl: "https://scoped.example/v1",
				apiKey: "$REPI_RUNTIME_KEY",
				authHeader: true,
				headers: {
					"X-Layer": "provider",
					"X-Remove": "provider",
					"X-Provider-Env": "$REPI_RUNTIME_PROVIDER_HEADER",
				},
				api: "openai-completions",
				streamSimple: (model, _context, options) => {
					capturedModel = model;
					capturedOptions = options;
					expect(options).not.toHaveProperty("transformHeaders");
					return completedStream(model);
				},
				models: [
					{
						...testModel("scoped", "scoped-model"),
						headers: {
							"x-layer": "model",
							"x-remove": null,
							"X-Model-Env": "$REPI_RUNTIME_MODEL_HEADER",
						},
					},
				],
			});
			const model = runtime.getModel("scoped", "scoped-model");
			expect(model).toBeDefined();

			const result = await runtime.completeSimple(
				model!,
				{ messages: [] },
				{
					env: {
						REPI_RUNTIME_KEY: "request-key",
						REPI_RUNTIME_PROVIDER_HEADER: "request-provider",
						REPI_RUNTIME_MODEL_HEADER: "request-model",
						REPI_STREAM_ONLY: "stream-value",
					},
					headers: {
						"X-LAYER": "request",
						authorization: "Explicit token",
						"x-request": "request",
					},
					transformHeaders: async (headers) => {
						transforms++;
						expect(headers).toEqual({
							"X-Provider-Env": "request-provider",
							"x-remove": null,
							"X-Model-Env": "request-model",
							"X-LAYER": "request",
							authorization: "Explicit token",
							"x-request": "request",
						});
						return { ...headers, "x-transformed": "yes" };
					},
				},
			);

			expect(result.stopReason).toBe("stop");
			expect(transforms).toBe(1);
			expect(capturedModel).toMatchObject({
				provider: "scoped",
				id: "scoped-model",
				baseUrl: "https://scoped.example/v1",
			});
			expect(capturedModel).not.toHaveProperty("headers");
			expect(capturedOptions?.apiKey).toBe("request-key");
			expect(capturedOptions?.env).toMatchObject({
				REPI_RUNTIME_KEY: "request-key",
				REPI_STREAM_ONLY: "stream-value",
			});
			expect(capturedOptions?.headers).toEqual({
				"X-Provider-Env": "request-provider",
				"x-remove": null,
				"X-Model-Env": "request-model",
				"X-LAYER": "request",
				authorization: "Explicit token",
				"x-request": "request",
				"x-transformed": "yes",
			} satisfies ProviderHeaders);
		} finally {
			if (originalKey === undefined) delete process.env.REPI_RUNTIME_KEY;
			else process.env.REPI_RUNTIME_KEY = originalKey;
			if (originalProviderHeader === undefined) delete process.env.REPI_RUNTIME_PROVIDER_HEADER;
			else process.env.REPI_RUNTIME_PROVIDER_HEADER = originalProviderHeader;
			if (originalModelHeader === undefined) delete process.env.REPI_RUNTIME_MODEL_HEADER;
			else process.env.REPI_RUNTIME_MODEL_HEADER = originalModelHeader;
		}
	});
});

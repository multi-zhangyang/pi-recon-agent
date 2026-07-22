import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
	AnthropicMessagesCompat,
	Api,
	Context,
	Model,
	OpenAICompletionsCompat,
	OpenAIResponsesCompat,
} from "@pi-recon/repi-ai";
import { getApiProvider } from "@pi-recon/repi-ai";
import { getOAuthProvider } from "@pi-recon/repi-ai/oauth";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { clearApiKeyCache, ModelRegistry, type ProviderConfigInput } from "../src/core/model-registry.ts";
import { clearDeprecationWarningsForTests } from "../src/utils/deprecation.ts";

describe("ModelRegistry", () => {
	let tempDir: string;
	let modelsJsonPath: string;
	let authStorage: AuthStorage;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-test-model-registry-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		modelsJsonPath = join(tempDir, "models.json");
		authStorage = AuthStorage.create(join(tempDir, "auth.json"));
		clearDeprecationWarningsForTests();
	});

	afterEach(() => {
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true });
		}
		clearApiKeyCache();
		clearDeprecationWarningsForTests();
		vi.restoreAllMocks();
	});

	/** Create minimal provider config  */
	function providerConfig(
		baseUrl: string,
		models: Array<{ id: string; name?: string }>,
		api: string = "anthropic-messages",
	): ProviderConfigInput {
		return {
			baseUrl,
			apiKey: "test-key",
			api: api as Api,
			models: models.map((m) => ({
				id: m.id,
				name: m.name ?? m.id,
				reasoning: false,
				input: ["text"],
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
				contextWindow: 100000,
				maxTokens: 8000,
			})),
		};
	}

	function writeModelsJson(providers: Record<string, ReturnType<typeof providerConfig>>) {
		writeFileSync(modelsJsonPath, JSON.stringify({ providers }));
	}

	function getModelsForProvider(registry: ModelRegistry, provider: string) {
		return registry.getAll().filter((m) => m.provider === provider);
	}

	function toShPath(value: string): string {
		return value.replace(/\\/g, "/").replace(/"/g, '\\"');
	}

	/** Create a baseUrl-only override (no custom models) */
	function overrideConfig(baseUrl: string, headers?: Record<string, string>) {
		return { baseUrl, ...(headers && { headers }) };
	}

	/** Write raw providers config (for mixed override/replacement scenarios) */
	function writeRawModelsJson(providers: Record<string, unknown>) {
		writeFileSync(modelsJsonPath, JSON.stringify({ providers }));
	}

	const openAiModel: Model<Api> = {
		id: "test-openai-model",
		name: "Test OpenAI Model",
		api: "openai-completions",
		provider: "openai",
		baseUrl: "https://api.openai.com/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 128000,
		maxTokens: 4096,
	};

	const emptyContext: Context = {
		messages: [],
	};

	async function withRepiModelEnv<T>(values: Record<string, string>, fn: () => T | Promise<T>): Promise<T> {
		const names = new Set([
			...Object.keys(process.env).filter((name) => name.startsWith("REPI_")),
			...Object.keys(values),
			"OPENAI_API_KEY",
			"ANTHROPIC_API_KEY",
		]);
		const originals = new Map([...names].map((name) => [name, process.env[name]]));
		for (const name of names) delete process.env[name];
		for (const [name, value] of Object.entries(values)) process.env[name] = value;
		try {
			return await fn();
		} finally {
			for (const name of names) {
				const original = originals.get(name);
				if (original === undefined) delete process.env[name];
				else process.env[name] = original;
			}
		}
	}

	describe("REPI environment model provider", () => {
		test("registers an env-only OpenAI-compatible model with configured auth", async () => {
			await withRepiModelEnv(
				{
					REPI_AUTH_TOKEN: "env-runtime-key",
					REPI_BASE_URL: "https://gateway.example.invalid/v1",
					REPI_MODEL: "moonshotai/Kimi-K2.7-Code",
					REPI_MODEL_API: "openai-compatible",
					REPI_CONTEXT_WINDOW: "262144",
					REPI_MAX_TOKENS: "32768",
					REPI_SUBAGENT_MODEL: "moonshotai/Kimi-K2.7-Code-Worker",
				},
				async () => {
					const registry = ModelRegistry.create(authStorage, modelsJsonPath);
					const model = registry.find("repi-env", "moonshotai/Kimi-K2.7-Code");
					expect(model).toMatchObject({
						provider: "repi-env",
						api: "openai-completions",
						baseUrl: "https://gateway.example.invalid/v1",
						contextWindow: 262144,
						maxTokens: 32768,
					});
					expect(registry.find("repi-env", "moonshotai/Kimi-K2.7-Code-Worker")).toBeDefined();
					expect(registry.getAvailable().some((m) => m.provider === "repi-env" && m.id === model?.id)).toBe(true);

					const auth = await registry.getApiKeyAndHeaders(model!);
					expect(auth).toEqual({ ok: true, apiKey: "env-runtime-key", headers: undefined });
				},
			);
		});

		test.each([
			["response", "openai-responses"],
			["openai-responses", "openai-responses"],
			["anthropic", "anthropic-messages"],
			["anthropic-messages", "anthropic-messages"],
		] as const)("normalizes REPI_MODEL_API=%s", async (alias, api) => {
			await withRepiModelEnv(
				{
					REPI_AUTH_TOKEN: "env-runtime-key",
					REPI_BASE_URL: "https://gateway.example.invalid/v1",
					REPI_MODEL: `env-model-${alias}`,
					REPI_MODEL_API: alias,
				},
				() => {
					const registry = ModelRegistry.create(authStorage, modelsJsonPath);
					expect(registry.find("repi-env", `env-model-${alias}`)?.api).toBe(api);
				},
			);
		});

		test("rejects invalid REPI_MODEL_API at registry load time so env-only setup cannot silently hit the wrong endpoint", async () => {
			await withRepiModelEnv(
				{
					REPI_AUTH_TOKEN: "env-runtime-key",
					REPI_BASE_URL: "https://gateway.example.invalid/v1",
					REPI_MODEL: "env-invalid-api-model",
					REPI_MODEL_API: "totally-custom-json",
				},
				() => {
					const registry = ModelRegistry.create(authStorage, modelsJsonPath);
					expect(registry.find("repi-env", "env-invalid-api-model")).toBeUndefined();
					expect(registry.getError()).toContain("invalid REPI_MODEL_API");
				},
			);
		});

		test("accepts REPI_AUTO_COMPACT_WINDOW as a Claude Code-style context-window alias", async () => {
			await withRepiModelEnv(
				{
					REPI_AUTH_TOKEN: "env-runtime-key",
					REPI_BASE_URL: "https://gateway.example.invalid/v1",
					REPI_MODEL: "env-auto-window-model",
					REPI_AUTO_COMPACT_WINDOW: "524288",
				},
				() => {
					const registry = ModelRegistry.create(authStorage, modelsJsonPath);
					expect(registry.find("repi-env", "env-auto-window-model")?.contextWindow).toBe(524288);
				},
			);
		});

		test("accepts endpoint, protocol, token, context, and output aliases", async () => {
			await withRepiModelEnv(
				{
					REPI_TOKEN: "alias-runtime-key",
					REPI_ENDPOINT: "https://alias-gateway.example.invalid/v1",
					REPI_MODEL_ID: "alias-model",
					REPI_PROTOCOL: "openai-responses",
					REPI_CONTEXT_LENGTH: "200000",
					REPI_OUTPUT_TOKEN_LIMIT: "24000",
				},
				async () => {
					const registry = ModelRegistry.create(authStorage, modelsJsonPath);
					const model = registry.find("repi-env", "alias-model");
					expect(model).toMatchObject({
						api: "openai-responses",
						baseUrl: "https://alias-gateway.example.invalid/v1",
						contextWindow: 200000,
						maxTokens: 24000,
					});
					expect(await registry.getApiKeyAndHeaders(model!)).toMatchObject({
						ok: true,
						apiKey: "alias-runtime-key",
					});
				},
			);
		});

		test("loads rich env-only metadata, request headers, and tiered pricing", async () => {
			await withRepiModelEnv(
				{
					REPI_AUTH_TOKEN: "env-runtime-key",
					REPI_BASE_URL: "https://gateway.example.invalid/v1",
					REPI_MODEL: "env-rich-model",
					REPI_MODEL_API: "openai-compatible",
					REPI_MODEL_INPUT: '["text", "image"]',
					REPI_MODEL_REASONING: "true",
					REPI_CONTEXT_WINDOW: "262144",
					REPI_MAX_TOKENS: "32768",
					REPI_TENANT_ID: "tenant-header",
					REPI_HEADERS: '{"X-Provider":"$REPI_TENANT_ID"}',
					REPI_MODEL_HEADERS: '{"X-Model":"model-header"}',
					REPI_COMPAT: '{"supportsDeveloperRole":false,"maxTokensField":"max_tokens"}',
					REPI_MODEL_COMPAT: '{"supportsUsageInStreaming":false}',
					REPI_MODEL_THINKING_LEVEL_MAP: '{"high":"max","xhigh":null}',
					REPI_AUTH_HEADER: "1",
					REPI_MODEL_COST_INPUT: "0.25",
					REPI_MODEL_COST_OUTPUT: "1.5",
					REPI_MODEL_COST_CACHE_READ: "0.05",
					REPI_MODEL_COST_CACHE_WRITE: "0.4",
					REPI_MODEL_COST_TIERS:
						'[{"inputTokensAbove":100000,"input":0.2,"output":1.2,"cacheRead":0.04,"cacheWrite":0.3}]',
				},
				async () => {
					const registry = ModelRegistry.create(authStorage, modelsJsonPath);
					const model = registry.find("repi-env", "env-rich-model");
					expect(registry.getError()).toBeUndefined();
					expect(model).toMatchObject({
						input: ["text", "image"],
						reasoning: true,
						contextWindow: 262144,
						maxTokens: 32768,
						thinkingLevelMap: { high: "max", xhigh: null },
						compat: {
							supportsDeveloperRole: false,
							supportsUsageInStreaming: false,
							maxTokensField: "max_tokens",
						},
						cost: {
							input: 0.25,
							output: 1.5,
							cacheRead: 0.05,
							cacheWrite: 0.4,
							tiers: [
								{
									inputTokensAbove: 100000,
									input: 0.2,
									output: 1.2,
									cacheRead: 0.04,
									cacheWrite: 0.3,
								},
							],
						},
					});
					const auth = await registry.getApiKeyAndHeaders(model!);
					expect(auth).toEqual({
						ok: true,
						apiKey: "env-runtime-key",
						headers: {
							"X-Provider": "tenant-header",
							"X-Model": "model-header",
							Authorization: "Bearer env-runtime-key",
						},
					});
				},
			);
		});

		test("can disable the upstream built-in catalog while keeping the REPI env-only provider", async () => {
			await withRepiModelEnv(
				{
					OPENAI_API_KEY: "ambient-openai-key-should-not-enable-builtins",
					REPI_AUTH_TOKEN: "env-runtime-key",
					REPI_BASE_URL: "https://gateway.example.invalid/v1",
					REPI_MODEL: "env-only-model",
					REPI_MODEL_API: "openai-compatible",
				},
				() => {
					const registry = ModelRegistry.create(authStorage, modelsJsonPath);
					expect(getModelsForProvider(registry, "openai")).toHaveLength(0);
					expect(registry.find("repi-env", "env-only-model")).toBeDefined();
					expect(registry.getAvailable().map((model) => model.provider)).toEqual(["repi-env"]);
				},
			);
		});

		test("does not load upstream built-in catalog even if legacy opt-in env is set", async () => {
			await withRepiModelEnv(
				{
					REPI_PRODUCT: "1",
					OPENAI_API_KEY: "ambient-openai-key-should-not-enable-builtins",
					REPI_AUTH_TOKEN: "env-runtime-key",
					REPI_BASE_URL: "https://gateway.example.invalid/v1",
					REPI_MODEL: "product-env-only-model",
				},
				() => {
					const registry = ModelRegistry.create(authStorage, modelsJsonPath);
					expect(getModelsForProvider(registry, "openai")).toHaveLength(0);
					expect(registry.find("repi-env", "product-env-only-model")).toBeDefined();
					expect(registry.getAvailable().map((model) => model.provider)).toEqual(["repi-env"]);
				},
			);
		});
	});

	describe("models.json requires explicit providers", () => {
		test("rejects override-only provider config because no built-in catalog is loaded", () => {
			writeRawModelsJson({
				anthropic: overrideConfig("https://my-proxy.example.com/v1"),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);

			expect(getModelsForProvider(registry, "anthropic")).toHaveLength(0);
			expect(registry.getError()).toContain('must define explicit "models"');
		});

		test("loads a provider only when models, api, baseUrl, and apiKey are explicit", async () => {
			writeModelsJson({
				anthropic: providerConfig("https://my-proxy.example.com/v1", [{ id: "claude-custom" }]),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const anthropicModels = getModelsForProvider(registry, "anthropic");

			expect(registry.getError()).toBeUndefined();
			expect(anthropicModels.map((model) => model.id)).toEqual(["claude-custom"]);
			expect(anthropicModels[0].baseUrl).toBe("https://my-proxy.example.com/v1");
			expect(await registry.getApiKeyForProvider("anthropic")).toBe("test-key");
		});
	});

	describe("custom models merge behavior", () => {
		test("custom providers require baseUrl and apiKey", () => {
			writeRawModelsJson({
				"my-custom-provider": {
					models: [
						{
							id: "my-model",
							api: "openai-completions",
							reasoning: false,
							input: ["text"],
						},
					],
				},
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			expect(registry.getError()).toContain("baseUrl");
		});

		test("provider names that match old built-ins are still explicit-only", () => {
			writeModelsJson({
				anthropic: providerConfig("https://my-proxy.example.com/v1", [{ id: "claude-custom" }]),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const anthropicModels = getModelsForProvider(registry, "anthropic");

			expect(anthropicModels.map((m) => m.id)).toEqual(["claude-custom"]);
			expect(getModelsForProvider(registry, "google")).toHaveLength(0);
			expect(getModelsForProvider(registry, "openai")).toHaveLength(0);
		});

		test("custom model with same id is just the explicit model", () => {
			writeModelsJson({
				openrouter: providerConfig(
					"https://my-proxy.example.com/v1",
					[{ id: "anthropic/claude-sonnet-4" }],
					"openai-completions",
				),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const models = getModelsForProvider(registry, "openrouter");

			expect(models).toHaveLength(1);
			expect(models[0].id).toBe("anthropic/claude-sonnet-4");
			expect(models[0].baseUrl).toBe("https://my-proxy.example.com/v1");
		});

		test("provider-level compat applies to custom models", () => {
			writeRawModelsJson({
				demo: {
					baseUrl: "https://example.com/v1",
					apiKey: "DEMO_KEY",
					api: "openai-completions",
					compat: {
						supportsUsageInStreaming: false,
						maxTokensField: "max_tokens",
					},
					models: [
						{
							id: "demo-model",
							reasoning: false,
							input: ["text"],
							cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
							contextWindow: 1000,
							maxTokens: 100,
						},
					],
				},
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const compat = registry.find("demo", "demo-model")?.compat as OpenAICompletionsCompat | undefined;

			expect(compat?.supportsUsageInStreaming).toBe(false);
			expect(compat?.maxTokensField).toBe("max_tokens");
		});

		test("model-level compat overrides provider-level compat for custom models", () => {
			writeRawModelsJson({
				demo: {
					baseUrl: "https://example.com/v1",
					apiKey: "DEMO_KEY",
					api: "openai-completions",
					compat: {
						supportsUsageInStreaming: false,
						maxTokensField: "max_tokens",
					},
					models: [
						{
							id: "demo-model",
							reasoning: false,
							input: ["text"],
							cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
							contextWindow: 1000,
							maxTokens: 100,
							compat: {
								supportsUsageInStreaming: true,
								maxTokensField: "max_completion_tokens",
							},
						},
					],
				},
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const compat = registry.find("demo", "demo-model")?.compat as OpenAICompletionsCompat | undefined;

			expect(compat?.supportsUsageInStreaming).toBe(true);
			expect(compat?.maxTokensField).toBe("max_completion_tokens");
		});

		test("model schema accepts thinkingLevelMap and compat schema accepts supportsStrictMode and cacheControlFormat", () => {
			writeRawModelsJson({
				demo: {
					baseUrl: "https://example.com/v1",
					apiKey: "DEMO_KEY",
					api: "openai-completions",
					models: [
						{
							id: "demo-model",
							reasoning: true,
							input: ["text"],
							cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
							contextWindow: 1000,
							maxTokens: 100,
							thinkingLevelMap: {
								minimal: null,
								high: "max",
							},
							compat: {
								supportsStrictMode: false,
								cacheControlFormat: "anthropic",
							},
						},
					],
				},
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const model = registry.find("demo", "demo-model");
			const compat = model?.compat as OpenAICompletionsCompat | undefined;

			expect(registry.getError()).toBeUndefined();
			expect(model?.thinkingLevelMap).toEqual({ minimal: null, high: "max" });
			expect(compat?.supportsStrictMode).toBe(false);
			expect(compat?.cacheControlFormat).toBe("anthropic");
		});

		test("compat schema accepts Anthropic eager input and tool reference flags", () => {
			writeRawModelsJson({
				demo: {
					baseUrl: "https://example.com",
					apiKey: "DEMO_KEY",
					api: "anthropic-messages",
					compat: {
						supportsEagerToolInputStreaming: false,
						supportsToolReferences: true,
					},
					models: [
						{
							id: "demo-model",
							reasoning: true,
							input: ["text"],
							cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
							contextWindow: 1000,
							maxTokens: 100,
						},
					],
				},
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const compat = registry.find("demo", "demo-model")?.compat as AnthropicMessagesCompat | undefined;

			expect(registry.getError()).toBeUndefined();
			expect(compat?.supportsEagerToolInputStreaming).toBe(false);
			expect(compat?.supportsToolReferences).toBe(true);
		});

		test("compat schema accepts OpenAI Responses tool search flag", () => {
			writeRawModelsJson({
				demo: {
					baseUrl: "https://example.com/v1",
					apiKey: "DEMO_KEY",
					api: "openai-responses",
					compat: {
						supportsToolSearch: true,
					},
					models: [
						{
							id: "demo-model",
							reasoning: false,
							input: ["text"],
							cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
							contextWindow: 1000,
							maxTokens: 100,
						},
					],
				},
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const compat = registry.find("demo", "demo-model")?.compat as OpenAIResponsesCompat | undefined;

			expect(registry.getError()).toBeUndefined();
			expect(compat?.supportsToolSearch).toBe(true);
		});

		test("model-level baseUrl overrides provider-level baseUrl for custom models", () => {
			writeRawModelsJson({
				"opencode-go": {
					baseUrl: "https://opencode.ai/zen/go/v1",
					apiKey: "TEST_KEY",
					models: [
						{
							id: "minimax-m2.5",
							api: "anthropic-messages",
							baseUrl: "https://opencode.ai/zen/go",
							reasoning: true,
							input: ["text"],
							cost: { input: 0.3, output: 1.2, cacheRead: 0.03, cacheWrite: 0 },
							contextWindow: 204800,
							maxTokens: 131072,
						},
						{
							id: "glm-5",
							api: "openai-completions",
							reasoning: true,
							input: ["text"],
							cost: { input: 1, output: 3.2, cacheRead: 0.2, cacheWrite: 0 },
							contextWindow: 204800,
							maxTokens: 131072,
						},
					],
				},
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const m25 = registry.find("opencode-go", "minimax-m2.5");
			const glm5 = registry.find("opencode-go", "glm-5");

			expect(m25?.baseUrl).toBe("https://opencode.ai/zen/go");
			expect(glm5?.baseUrl).toBe("https://opencode.ai/zen/go/v1");
		});

		test("refresh() reloads explicit custom models from disk", () => {
			writeModelsJson({
				anthropic: providerConfig("https://first-proxy.example.com/v1", [{ id: "claude-custom" }]),
			});
			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			expect(getModelsForProvider(registry, "anthropic").map((m) => m.id)).toEqual(["claude-custom"]);

			writeModelsJson({
				anthropic: providerConfig("https://second-proxy.example.com/v1", [{ id: "claude-custom-2" }]),
			});
			registry.refresh();

			expect(getModelsForProvider(registry, "anthropic").map((m) => m.id)).toEqual(["claude-custom-2"]);
		});

		test("removing custom models from models.json leaves no provider models", () => {
			writeModelsJson({
				anthropic: providerConfig("https://proxy.example.com/v1", [{ id: "claude-custom" }]),
			});
			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			expect(getModelsForProvider(registry, "anthropic")).toHaveLength(1);

			writeModelsJson({});
			registry.refresh();

			expect(getModelsForProvider(registry, "anthropic")).toHaveLength(0);
		});
	});

	describe("dynamic provider lifecycle", () => {
		test("getProviderDisplayName resolves registered, OAuth, and fallback names", () => {
			const registry = ModelRegistry.create(authStorage, modelsJsonPath);

			expect(registry.getProviderDisplayName("openai")).toBe("openai");
			expect(registry.getProviderDisplayName("github-copilot")).toBe("GitHub Copilot");
			expect(registry.getProviderDisplayName("unknown-provider")).toBe("unknown-provider");

			registry.registerProvider("named-provider", {
				name: "Named Provider",
				baseUrl: "https://provider.test/v1",
				apiKey: "test-key",
				api: "openai-completions",
				models: [
					{
						id: "demo-model",
						name: "Demo Model",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 128000,
						maxTokens: 4096,
					},
				],
			});
			expect(registry.getProviderDisplayName("named-provider")).toBe("Named Provider");

			registry.registerProvider("oauth-provider", {
				baseUrl: "https://provider.test/v1",
				api: "openai-completions",
				oauth: {
					name: "OAuth Provider",
					login: async () => ({ access: "access", refresh: "refresh", expires: Date.now() + 60_000 }),
					refreshToken: async (credentials) => credentials,
					getApiKey: (credentials) => credentials.access,
				},
				models: [
					{
						id: "demo-model",
						name: "Demo Model",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 128000,
						maxTokens: 4096,
					},
				],
			});
			expect(registry.getProviderDisplayName("oauth-provider")).toBe("OAuth Provider");
		});

		test("registerProvider warns and temporarily treats uppercase apiKey as an env reference", async () => {
			const originalEnv = process.env.CUSTOM_NAME;
			process.env.CUSTOM_NAME = "legacy-env-key";
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

			try {
				const registry = ModelRegistry.create(authStorage, modelsJsonPath);

				registry.registerProvider("legacy-provider", {
					...providerConfig("https://provider.test/v1", [{ id: "demo-model" }], "openai-completions"),
					apiKey: "CUSTOM_NAME",
				});

				expect(await registry.getApiKeyForProvider("legacy-provider")).toBe("legacy-env-key");
				expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('Pass "$CUSTOM_NAME" instead'));
			} finally {
				if (originalEnv === undefined) {
					delete process.env.CUSTOM_NAME;
				} else {
					process.env.CUSTOM_NAME = originalEnv;
				}
			}
		});

		test("failed registerProvider does not persist invalid streamSimple config", () => {
			const registry = ModelRegistry.create(authStorage, modelsJsonPath);

			expect(() =>
				registry.registerProvider("broken-provider", {
					streamSimple: (() => {
						throw new Error("should not run");
					}) as any,
				}),
			).toThrow('Provider broken-provider: "api" is required when registering streamSimple.');

			expect(() => registry.refresh()).not.toThrow();
		});

		test("failed registerProvider does not remove existing provider models", () => {
			const registry = ModelRegistry.create(authStorage, modelsJsonPath);

			registry.registerProvider("demo-provider", {
				baseUrl: "https://provider.test/v1",
				apiKey: "test-key",
				api: "openai-completions",
				models: [
					{
						id: "demo-model",
						name: "Demo Model",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 128000,
						maxTokens: 4096,
					},
				],
			});

			expect(registry.find("demo-provider", "demo-model")).toBeDefined();

			expect(() =>
				registry.registerProvider("demo-provider", {
					baseUrl: "https://provider.test/v2",
					apiKey: "test-key",
					models: [
						{
							id: "broken-model",
							name: "Broken Model",
							reasoning: false,
							input: ["text"],
							cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
							contextWindow: 128000,
							maxTokens: 4096,
						},
					],
				}),
			).toThrow('Provider demo-provider, model broken-model: no "api" specified.');

			expect(registry.find("demo-provider", "demo-model")).toBeDefined();
			expect(() => registry.refresh()).not.toThrow();
			expect(registry.find("demo-provider", "demo-model")).toBeDefined();
		});

		test("unregisterProvider removes custom OAuth provider and restores built-in OAuth provider", () => {
			const registry = ModelRegistry.create(authStorage, modelsJsonPath);

			registry.registerProvider("anthropic", {
				oauth: {
					name: "Custom Anthropic OAuth",
					login: async () => ({
						access: "custom-access-token",
						refresh: "custom-refresh-token",
						expires: Date.now() + 60_000,
					}),
					refreshToken: async (credentials) => credentials,
					getApiKey: (credentials) => credentials.access,
				},
			});

			expect(getOAuthProvider("anthropic")?.name).toBe("Custom Anthropic OAuth");

			registry.unregisterProvider("anthropic");

			expect(getOAuthProvider("anthropic")?.name).not.toBe("Custom Anthropic OAuth");
		});

		test("unregisterProvider removes custom streamSimple override and restores built-in API stream handler", () => {
			const registry = ModelRegistry.create(authStorage, modelsJsonPath);

			registry.registerProvider("stream-override-provider", {
				api: "openai-completions",
				streamSimple: () => {
					throw new Error("custom streamSimple override");
				},
			});

			let threwCustomOverride = false;
			try {
				getApiProvider("openai-completions")?.streamSimple(openAiModel, emptyContext);
			} catch (error) {
				threwCustomOverride = error instanceof Error && error.message === "custom streamSimple override";
			}
			expect(threwCustomOverride).toBe(true);

			registry.unregisterProvider("stream-override-provider");

			let threwCustomOverrideAfterUnregister = false;
			try {
				getApiProvider("openai-completions")?.streamSimple(openAiModel, emptyContext);
			} catch (error) {
				threwCustomOverrideAfterUnregister =
					error instanceof Error && error.message === "custom streamSimple override";
			}
			expect(threwCustomOverrideAfterUnregister).toBe(false);
		});

		test("refresh only rebuilds this registry's global provider layers", () => {
			const first = ModelRegistry.inMemory(AuthStorage.inMemory());
			const second = ModelRegistry.inMemory(AuthStorage.inMemory());
			const api = "openai-completions";
			const model = { ...openAiModel, api };
			const register = (registry: ModelRegistry, providerId: string, marker: string) => {
				registry.registerProvider(providerId, {
					api,
					streamSimple: () => {
						throw new Error(marker);
					},
					oauth: {
						name: marker,
						login: async () => ({ access: marker, refresh: marker, expires: Date.now() + 60_000 }),
						refreshToken: async (credentials) => credentials,
						getApiKey: (credentials) => credentials.access,
					},
				});
			};
			const invokeActiveApi = () => getApiProvider(api)?.streamSimple(model, emptyContext);

			register(first, "first-layered-provider", "first-layer");
			register(second, "second-layered-provider", "second-layer");
			try {
				expect(invokeActiveApi).toThrow("second-layer");

				first.refresh();
				expect(getOAuthProvider("first-layered-provider")?.name).toBe("first-layer");
				expect(getOAuthProvider("second-layered-provider")?.name).toBe("second-layer");
				expect(invokeActiveApi).toThrow("first-layer");

				first.unregisterProvider("first-layered-provider");
				expect(getOAuthProvider("first-layered-provider")).toBeUndefined();
				expect(getOAuthProvider("second-layered-provider")?.name).toBe("second-layer");
				expect(invokeActiveApi).toThrow("second-layer");

				second.refresh();
				expect(getOAuthProvider("second-layered-provider")?.name).toBe("second-layer");
				expect(invokeActiveApi).toThrow("second-layer");
			} finally {
				first.unregisterProvider("first-layered-provider");
				second.unregisterProvider("second-layered-provider");
			}
		});

		describe("dynamic provider override persistence", () => {
			test("baseUrl-only override is harmless when no explicit provider models exist", () => {
				const registry = ModelRegistry.create(authStorage, modelsJsonPath);

				registry.registerProvider("anthropic", { baseUrl: "https://proxy.test/anthropic" });
				registry.refresh();

				expect(getModelsForProvider(registry, "anthropic")).toHaveLength(0);
			});

			test("models-only override replaces built-in provider models after refresh", () => {
				const registry = ModelRegistry.create(authStorage, modelsJsonPath);

				registry.registerProvider("anthropic", {
					...providerConfig("https://custom.test/anthropic", [{ id: "custom-claude" }], "anthropic-messages"),
					baseUrl: "https://custom.test/anthropic",
				});
				registry.refresh();

				expect(getModelsForProvider(registry, "anthropic").map((m) => m.id)).toEqual(["custom-claude"]);
				expect(registry.find("anthropic", "custom-claude")?.baseUrl).toBe("https://custom.test/anthropic");
			});

			test("models plus baseUrl override replaces built-in provider models after refresh", () => {
				const registry = ModelRegistry.create(authStorage, modelsJsonPath);

				registry.registerProvider("anthropic", {
					...providerConfig("https://custom.test/anthropic", [{ id: "custom-claude" }], "anthropic-messages"),
					baseUrl: "https://custom.test/anthropic",
				});
				registry.registerProvider("anthropic", { baseUrl: "https://proxy.test/anthropic" });
				registry.refresh();

				expect(getModelsForProvider(registry, "anthropic").map((m) => m.id)).toEqual(["custom-claude"]);
				expect(registry.find("anthropic", "custom-claude")?.baseUrl).toBe("https://proxy.test/anthropic");
			});

			test("models-only custom provider registration survives refresh", () => {
				const registry = ModelRegistry.create(authStorage, modelsJsonPath);

				registry.registerProvider(
					"custom-provider",
					providerConfig("https://custom.test/v1", [{ id: "custom-a" }, { id: "custom-b" }], "openai-completions"),
				);
				registry.refresh();

				expect(getModelsForProvider(registry, "custom-provider").map((m) => m.id)).toEqual([
					"custom-a",
					"custom-b",
				]);
			});

			test("baseUrl-only override keeps custom provider models after refresh", () => {
				const registry = ModelRegistry.create(authStorage, modelsJsonPath);

				registry.registerProvider(
					"custom-provider",
					providerConfig("https://custom.test/v1", [{ id: "custom-a" }, { id: "custom-b" }], "openai-completions"),
				);
				registry.registerProvider("custom-provider", { baseUrl: "https://proxy.test/custom" });
				registry.refresh();

				expect(getModelsForProvider(registry, "custom-provider").map((m) => m.id)).toEqual([
					"custom-a",
					"custom-b",
				]);
				expect(
					getModelsForProvider(registry, "custom-provider").every(
						(m) => m.baseUrl === "https://proxy.test/custom",
					),
				).toBe(true);
			});

			test("headers-only override keeps custom provider models after refresh", async () => {
				const registry = ModelRegistry.create(authStorage, modelsJsonPath);

				registry.registerProvider(
					"custom-provider",
					providerConfig("https://custom.test/v1", [{ id: "custom-a" }, { id: "custom-b" }], "openai-completions"),
				);
				registry.registerProvider("custom-provider", { headers: { "x-proxy": "enabled" } });
				registry.refresh();

				const models = getModelsForProvider(registry, "custom-provider");
				expect(models.map((m) => m.id)).toEqual(["custom-a", "custom-b"]);
				expect(models.every((m) => m.baseUrl === "https://custom.test/v1")).toBe(true);
				expect(await registry.getApiKeyAndHeaders(models[0])).toMatchObject({
					ok: true,
					headers: { "x-proxy": "enabled" },
				});
			});
		});
	});

	describe("API key resolution", () => {
		/** Create provider config with custom apiKey */
		function providerWithApiKey(apiKey: string) {
			return {
				baseUrl: "https://example.com/v1",
				apiKey,
				api: "anthropic-messages",
				models: [
					{
						id: "test-model",
						name: "Test Model",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 100000,
						maxTokens: 8000,
					},
				],
			};
		}

		test("apiKey with ! prefix executes command and uses stdout", async () => {
			writeRawModelsJson({
				"custom-provider": providerWithApiKey("!echo test-api-key-from-command"),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const apiKey = await registry.getApiKeyForProvider("custom-provider");

			expect(apiKey).toBe("test-api-key-from-command");
		});

		test("apiKey with ! prefix trims whitespace from command output", async () => {
			writeRawModelsJson({
				"custom-provider": providerWithApiKey("!echo '  spaced-key  '"),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const apiKey = await registry.getApiKeyForProvider("custom-provider");

			expect(apiKey).toBe("spaced-key");
		});

		test("apiKey with ! prefix handles multiline output (uses trimmed result)", async () => {
			writeRawModelsJson({
				"custom-provider": providerWithApiKey("!printf 'line1\\nline2'"),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const apiKey = await registry.getApiKeyForProvider("custom-provider");

			expect(apiKey).toBe("line1\nline2");
		});

		test("apiKey with ! prefix returns undefined on command failure", async () => {
			writeRawModelsJson({
				"custom-provider": providerWithApiKey("!exit 1"),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const apiKey = await registry.getApiKeyForProvider("custom-provider");

			expect(apiKey).toBeUndefined();
		});

		test("apiKey with ! prefix returns undefined on nonexistent command", async () => {
			writeRawModelsJson({
				"custom-provider": providerWithApiKey("!nonexistent-command-12345"),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const apiKey = await registry.getApiKeyForProvider("custom-provider");

			expect(apiKey).toBeUndefined();
		});

		test("apiKey with ! prefix returns undefined on empty output", async () => {
			writeRawModelsJson({
				"custom-provider": providerWithApiKey("!printf ''"),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const apiKey = await registry.getApiKeyForProvider("custom-provider");

			expect(apiKey).toBeUndefined();
		});

		test("apiKey with $ prefix resolves to env value", async () => {
			const originalEnv = process.env.TEST_API_KEY_12345;
			process.env.TEST_API_KEY_12345 = "env-api-key-value";

			try {
				writeRawModelsJson({
					"custom-provider": providerWithApiKey("$TEST_API_KEY_12345"),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				const apiKey = await registry.getApiKeyForProvider("custom-provider");

				expect(apiKey).toBe("env-api-key-value");
			} finally {
				if (originalEnv === undefined) {
					delete process.env.TEST_API_KEY_12345;
				} else {
					process.env.TEST_API_KEY_12345 = originalEnv;
				}
			}
		});

		test("apiKey with braced env syntax resolves to env value", async () => {
			const originalEnv = process.env.TEST_BRACED_API_KEY_12345;
			process.env.TEST_BRACED_API_KEY_12345 = "braced-env-api-key-value";
			const bracedKey = "$" + "{TEST_BRACED_API_KEY_12345}";

			try {
				writeRawModelsJson({
					"custom-provider": providerWithApiKey(bracedKey),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				const apiKey = await registry.getApiKeyForProvider("custom-provider");

				expect(apiKey).toBe("braced-env-api-key-value");
			} finally {
				if (originalEnv === undefined) {
					delete process.env.TEST_BRACED_API_KEY_12345;
				} else {
					process.env.TEST_BRACED_API_KEY_12345 = originalEnv;
				}
			}
		});

		test("apiKey interpolates braced env references inside literals", async () => {
			const originalPartA = process.env.TEST_INTERPOLATED_PART_A_12345;
			const originalPartB = process.env.TEST_INTERPOLATED_PART_B_12345;
			process.env.TEST_INTERPOLATED_PART_A_12345 = "left";
			process.env.TEST_INTERPOLATED_PART_B_12345 = "right";
			const interpolatedKey = ["$", "{TEST_INTERPOLATED_PART_A_12345}_$", "{TEST_INTERPOLATED_PART_B_12345}"].join(
				"",
			);

			try {
				writeRawModelsJson({
					"custom-provider": providerWithApiKey(interpolatedKey),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				const apiKey = await registry.getApiKeyForProvider("custom-provider");

				expect(apiKey).toBe("left_right");
			} finally {
				if (originalPartA === undefined) {
					delete process.env.TEST_INTERPOLATED_PART_A_12345;
				} else {
					process.env.TEST_INTERPOLATED_PART_A_12345 = originalPartA;
				}
				if (originalPartB === undefined) {
					delete process.env.TEST_INTERPOLATED_PART_B_12345;
				} else {
					process.env.TEST_INTERPOLATED_PART_B_12345 = originalPartB;
				}
			}
		});

		test("apiKey with $$ prefix escapes a leading dollar", async () => {
			writeRawModelsJson({
				"custom-provider": providerWithApiKey("$$TEST_API_KEY_12345"),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const apiKey = await registry.getApiKeyForProvider("custom-provider");

			expect(apiKey).toBe("$TEST_API_KEY_12345");
		});

		test("apiKey with $! escapes a literal bang and still interpolates later env refs", async () => {
			const originalEnv = process.env.TEST_API_KEY_12345;
			process.env.TEST_API_KEY_12345 = "env-api-key-value";

			try {
				writeRawModelsJson({
					"custom-provider": providerWithApiKey("$!literal-$TEST_API_KEY_12345"),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				const apiKey = await registry.getApiKeyForProvider("custom-provider");

				expect(apiKey).toBe("!literal-env-api-key-value");
			} finally {
				if (originalEnv === undefined) {
					delete process.env.TEST_API_KEY_12345;
				} else {
					process.env.TEST_API_KEY_12345 = originalEnv;
				}
			}
		});

		test("plain apiKey is used directly even when it matches an env var", async () => {
			const originalEnv = process.env.TEST_API_KEY_12345;
			process.env.TEST_API_KEY_12345 = "env-api-key-value";

			try {
				writeRawModelsJson({
					"custom-provider": providerWithApiKey("TEST_API_KEY_12345"),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				const apiKey = await registry.getApiKeyForProvider("custom-provider");

				expect(apiKey).toBe("TEST_API_KEY_12345");
			} finally {
				if (originalEnv === undefined) {
					delete process.env.TEST_API_KEY_12345;
				} else {
					process.env.TEST_API_KEY_12345 = originalEnv;
				}
			}
		});

		test("apiKey as literal value is used directly when not an env var", async () => {
			// Make sure this isn't an env var
			delete process.env.literal_api_key_value;

			writeRawModelsJson({
				"custom-provider": providerWithApiKey("literal_api_key_value"),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const apiKey = await registry.getApiKeyForProvider("custom-provider");

			expect(apiKey).toBe("literal_api_key_value");
		});

		test("apiKey command can use shell features like pipes", async () => {
			writeRawModelsJson({
				"custom-provider": providerWithApiKey("!echo 'hello world' | tr ' ' '-'"),
			});

			const registry = ModelRegistry.create(authStorage, modelsJsonPath);
			const apiKey = await registry.getApiKeyForProvider("custom-provider");

			expect(apiKey).toBe("hello-world");
		});

		describe("request-time resolution", () => {
			test("preserves null header suppression with case-insensitive precedence", async () => {
				const baseProvider = providerWithApiKey("test-key");
				writeRawModelsJson({
					"custom-provider": {
						...baseProvider,
						headers: { "X-Default": "provider", "X-Provider": "kept" },
						models: [
							{
								...baseProvider.models[0],
								headers: { "x-default": null, "X-Model": "kept" },
							},
						],
					},
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				const model = registry.find("custom-provider", "test-model");
				expect(model).toBeDefined();
				expect(await registry.getApiKeyAndHeaders(model!)).toEqual({
					ok: true,
					apiKey: "test-key",
					headers: { "X-Provider": "kept", "x-default": null, "X-Model": "kept" },
				});
			});

			test("command is executed on every provider lookup", async () => {
				const counterFile = join(tempDir, "counter");
				writeFileSync(counterFile, "0");

				const counterPath = toShPath(counterFile);
				const command = `!sh -c 'count=$(cat "${counterPath}"); echo $((count + 1)) > "${counterPath}"; echo "key-value"'`;
				writeRawModelsJson({
					"custom-provider": providerWithApiKey(command),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				await registry.getApiKeyForProvider("custom-provider");
				await registry.getApiKeyForProvider("custom-provider");
				await registry.getApiKeyForProvider("custom-provider");

				const count = parseInt(readFileSync(counterFile, "utf-8").trim(), 10);
				expect(count).toBe(3);
			});

			test("commands are re-executed across registry instances", async () => {
				const counterFile = join(tempDir, "counter");
				writeFileSync(counterFile, "0");

				const counterPath = toShPath(counterFile);
				const command = `!sh -c 'count=$(cat "${counterPath}"); echo $((count + 1)) > "${counterPath}"; echo "key-value"'`;
				writeRawModelsJson({
					"custom-provider": providerWithApiKey(command),
				});

				const registry1 = ModelRegistry.create(authStorage, modelsJsonPath);
				await registry1.getApiKeyForProvider("custom-provider");

				const registry2 = ModelRegistry.create(authStorage, modelsJsonPath);
				await registry2.getApiKeyForProvider("custom-provider");

				const count = parseInt(readFileSync(counterFile, "utf-8").trim(), 10);
				expect(count).toBe(2);
			});

			test("different commands resolve independently", async () => {
				writeRawModelsJson({
					"provider-a": providerWithApiKey("!echo key-a"),
					"provider-b": providerWithApiKey("!echo key-b"),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);

				const keyA = await registry.getApiKeyForProvider("provider-a");
				const keyB = await registry.getApiKeyForProvider("provider-b");

				expect(keyA).toBe("key-a");
				expect(keyB).toBe("key-b");
			});

			test("failed commands are retried", async () => {
				const counterFile = join(tempDir, "counter");
				writeFileSync(counterFile, "0");

				const counterPath = toShPath(counterFile);
				const command = `!sh -c 'count=$(cat "${counterPath}"); echo $((count + 1)) > "${counterPath}"; exit 1'`;
				writeRawModelsJson({
					"custom-provider": providerWithApiKey(command),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				const key1 = await registry.getApiKeyForProvider("custom-provider");
				const key2 = await registry.getApiKeyForProvider("custom-provider");

				expect(key1).toBeUndefined();
				expect(key2).toBeUndefined();

				const count = parseInt(readFileSync(counterFile, "utf-8").trim(), 10);
				expect(count).toBe(2);
			});

			test("provider auth status reports apiKey environment variables from models.json", () => {
				const envVarName = "TEST_API_KEY_STATUS_TEST_98765";
				const originalEnv = process.env[envVarName];

				try {
					process.env[envVarName] = "status-test-key";

					writeRawModelsJson({
						"custom-provider": providerWithApiKey(`$${envVarName}`),
					});

					const registry = ModelRegistry.create(authStorage, modelsJsonPath);

					expect(registry.getProviderAuthStatus("custom-provider")).toEqual({
						configured: true,
						source: "environment",
						label: envVarName,
					});
				} finally {
					if (originalEnv === undefined) {
						delete process.env[envVarName];
					} else {
						process.env[envVarName] = originalEnv;
					}
				}
			});

			test("provider auth status reports interpolated apiKey environment variables", () => {
				const envVarNameA = "TEST_API_KEY_STATUS_PART_A_98765";
				const envVarNameB = "TEST_API_KEY_STATUS_PART_B_98765";
				const originalEnvA = process.env[envVarNameA];
				const originalEnvB = process.env[envVarNameB];
				process.env[envVarNameA] = "left";
				process.env[envVarNameB] = "right";
				const interpolatedKey = ["$", "{", envVarNameA, "}_$", "{", envVarNameB, "}"].join("");

				try {
					writeRawModelsJson({
						"custom-provider": providerWithApiKey(interpolatedKey),
					});

					const registry = ModelRegistry.create(authStorage, modelsJsonPath);

					expect(registry.getProviderAuthStatus("custom-provider")).toEqual({
						configured: true,
						source: "environment",
						label: `${envVarNameA}, ${envVarNameB}`,
					});
				} finally {
					if (originalEnvA === undefined) {
						delete process.env[envVarNameA];
					} else {
						process.env[envVarNameA] = originalEnvA;
					}
					if (originalEnvB === undefined) {
						delete process.env[envVarNameB];
					} else {
						process.env[envVarNameB] = originalEnvB;
					}
				}
			});

			test("provider auth status reports non-env apiKey values from models.json as a config key", () => {
				writeRawModelsJson({
					"custom-provider": providerWithApiKey("literal_api_key_value"),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);

				expect(registry.getProviderAuthStatus("custom-provider")).toEqual({
					configured: true,
					source: "models_json_key",
				});
			});

			test("missing explicit env apiKey keeps provider unavailable", () => {
				const envVarName = "TEST_API_KEY_MISSING_TEST_98765";
				const originalEnv = process.env[envVarName];
				delete process.env[envVarName];

				try {
					writeRawModelsJson({
						"custom-provider": providerWithApiKey(`$${envVarName}`),
					});

					const registry = ModelRegistry.create(authStorage, modelsJsonPath);

					expect(registry.getProviderAuthStatus("custom-provider")).toEqual({ configured: false });
					expect(registry.getAvailable().some((model) => model.provider === "custom-provider")).toBe(false);
				} finally {
					if (originalEnv === undefined) {
						delete process.env[envVarName];
					} else {
						process.env[envVarName] = originalEnv;
					}
				}
			});

			test("provider auth status reports command apiKey values from models.json without executing them", () => {
				const counterFile = join(tempDir, "status-counter");
				writeFileSync(counterFile, "0");
				const counterPath = toShPath(counterFile);
				const command = `!sh -c 'echo 1 > "${counterPath}"; echo key-value'`;
				writeRawModelsJson({
					"custom-provider": providerWithApiKey(command),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);

				expect(registry.getProviderAuthStatus("custom-provider")).toEqual({
					configured: true,
					source: "models_json_command",
				});
				expect(readFileSync(counterFile, "utf-8")).toBe("0");
			});

			test("environment variables are not cached (changes are picked up)", async () => {
				const envVarName = "TEST_API_KEY_CACHE_TEST_98765";
				const originalEnv = process.env[envVarName];

				try {
					process.env[envVarName] = "first-value";

					writeRawModelsJson({
						"custom-provider": providerWithApiKey(`$${envVarName}`),
					});

					const registry = ModelRegistry.create(authStorage, modelsJsonPath);

					const key1 = await registry.getApiKeyForProvider("custom-provider");
					expect(key1).toBe("first-value");

					process.env[envVarName] = "second-value";

					const key2 = await registry.getApiKeyForProvider("custom-provider");
					expect(key2).toBe("second-value");
				} finally {
					if (originalEnv === undefined) {
						delete process.env[envVarName];
					} else {
						process.env[envVarName] = originalEnv;
					}
				}
			});

			test("getAvailable does not execute command-backed apiKey resolution", async () => {
				const counterFile = join(tempDir, "counter");
				writeFileSync(counterFile, "0");

				const counterPath = toShPath(counterFile);
				const command = `!sh -c 'count=$(cat "${counterPath}"); echo $((count + 1)) > "${counterPath}"; echo "key-value"'`;
				writeRawModelsJson({
					"custom-provider": providerWithApiKey(command),
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				const available = registry.getAvailable();

				expect(available.some((m) => m.provider === "custom-provider")).toBe(true);
				const count = parseInt(readFileSync(counterFile, "utf-8").trim(), 10);
				expect(count).toBe(0);
			});

			test("getApiKeyAndHeaders resolves authHeader on every request", async () => {
				const tokenFile = join(tempDir, "token");
				writeFileSync(tokenFile, "token-1");
				const tokenPath = toShPath(tokenFile);

				writeRawModelsJson({
					"custom-provider": {
						...providerWithApiKey(`!sh -c 'cat "${tokenPath}"'`),
						authHeader: true,
					},
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				const model = registry.find("custom-provider", "test-model");
				expect(model).toBeDefined();

				const auth1 = await registry.getApiKeyAndHeaders(model!);
				expect(auth1).toEqual({
					ok: true,
					apiKey: "token-1",
					headers: { Authorization: "Bearer token-1" },
				});

				writeFileSync(tokenFile, "token-2");

				const auth2 = await registry.getApiKeyAndHeaders(model!);
				expect(auth2).toEqual({
					ok: true,
					apiKey: "token-2",
					headers: { Authorization: "Bearer token-2" },
				});
			});

			test("getApiKeyAndHeaders returns an error for failed authHeader resolution", async () => {
				writeRawModelsJson({
					"custom-provider": {
						...providerWithApiKey("!exit 1"),
						authHeader: true,
					},
				});

				const registry = ModelRegistry.create(authStorage, modelsJsonPath);
				const model = registry.find("custom-provider", "test-model");
				expect(model).toBeDefined();

				const auth = await registry.getApiKeyAndHeaders(model!);
				expect(auth.ok).toBe(false);
				if (!auth.ok) {
					expect(auth.error).toContain('Failed to resolve API key for provider "custom-provider"');
				}
			});
		});
	});
});

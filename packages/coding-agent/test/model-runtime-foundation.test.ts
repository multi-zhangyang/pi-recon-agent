import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InMemoryCredentialStore, type Model, mergeProviderHeaders } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { ModelConfig } from "../src/core/model-config.ts";
import {
	composeModelProvider,
	type ProviderConfigInput,
	resolveCompatibilityRequestConfig,
	resolveConfiguredModelHeaders,
} from "../src/core/provider-composer.ts";
import { RuntimeCredentials } from "../src/core/runtime-credentials.ts";

const tempDirs: string[] = [];

afterEach(() => {
	for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function writeModelsConfig(config: unknown): string {
	const dir = mkdtempSync(join(tmpdir(), "repi-model-runtime-foundation-"));
	tempDirs.push(dir);
	const path = join(dir, "models.json");
	writeFileSync(path, JSON.stringify(config));
	return path;
}

function explicitModel(id = "explicit-model") {
	return {
		id,
		name: id,
		reasoning: false,
		input: ["text"] as ("text" | "image")[],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 128_000,
		maxTokens: 8_192,
	};
}

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((resolvePromise) => {
		resolve = resolvePromise;
	});
	return { promise, resolve };
}

const refreshContext = {
	store: {
		read: async () => undefined,
		write: async () => {},
		delete: async () => {},
	},
	allowNetwork: true,
};

describe("ModelRuntime foundation", () => {
	it("loads an immutable credential-blind config and preserves null header suppression", async () => {
		const config = await ModelConfig.load(
			writeModelsConfig({
				providers: {
					explicit: {
						baseUrl: "https://example.test/v1",
						apiKey: "$EXPLICIT_KEY",
						api: "openai-completions",
						headers: { "x-enabled": "yes", "x-suppressed": null },
						models: [
							{
								...explicitModel(),
								cost: {
									input: 1,
									output: 2,
									cacheRead: 0.5,
									cacheWrite: 3,
									tiers: [{ inputTokensAbove: 200_000, input: 2, output: 3, cacheRead: 1, cacheWrite: 4 }],
								},
							},
						],
					},
				},
			}),
		);

		const provider = config.getProvider("explicit");
		expect(config.getError()).toBeUndefined();
		expect(provider?.headers).toEqual({ "x-enabled": "yes", "x-suppressed": null });
		expect(provider?.models?.[0]?.cost?.tiers?.[0]).toEqual({
			inputTokensAbove: 200_000,
			input: 2,
			output: 3,
			cacheRead: 1,
			cacheWrite: 4,
		});
		expect(Object.isFrozen(provider)).toBe(true);
		expect(Object.isFrozen(provider?.headers)).toBe(true);
	});

	it("composes an explicit provider without loading any built-in model catalog", async () => {
		const config = await ModelConfig.load(
			writeModelsConfig({
				providers: {
					explicit: {
						name: "Explicit Provider",
						baseUrl: "https://example.test/v1",
						apiKey: "literal-key",
						api: "openai-completions",
						models: [explicitModel()],
					},
				},
			}),
		);

		const provider = composeModelProvider("explicit", undefined, config, undefined);

		expect(provider.name).toBe("Explicit Provider");
		expect(provider.getModels().map((model) => `${model.provider}/${model.id}`)).toEqual(["explicit/explicit-model"]);
	});

	it("resolves configured auth and model headers from request-scoped env before process.env", async () => {
		const originalKey = process.env.REPI_SCOPED_KEY;
		const originalProviderHeader = process.env.REPI_SCOPED_PROVIDER_HEADER;
		const originalModelHeader = process.env.REPI_SCOPED_MODEL_HEADER;
		process.env.REPI_SCOPED_KEY = "process-key";
		process.env.REPI_SCOPED_PROVIDER_HEADER = "process-provider";
		process.env.REPI_SCOPED_MODEL_HEADER = "process-model";
		try {
			const config = await ModelConfig.load(
				writeModelsConfig({
					providers: {
						scoped: {
							baseUrl: "https://example.test/v1",
							apiKey: "$REPI_SCOPED_KEY",
							api: "openai-completions",
							headers: { "x-provider": "$REPI_SCOPED_PROVIDER_HEADER" },
							models: [
								{
									...explicitModel("scoped-model"),
									headers: { "x-model": "$REPI_SCOPED_MODEL_HEADER" },
								},
							],
						},
					},
				}),
			);
			const provider = composeModelProvider("scoped", undefined, config, undefined);
			const auth = await provider.auth.apiKey?.resolve({
				ctx: {
					env: async (name) =>
						({
							REPI_SCOPED_KEY: "scoped-key",
							REPI_SCOPED_PROVIDER_HEADER: "scoped-provider",
						})[name],
					fileExists: async () => false,
				},
			});
			const model = provider.getModels()[0] as Model<"openai-completions">;
			const modelHeaders = resolveConfiguredModelHeaders(model, config.getProvider("scoped"), undefined, {
				REPI_SCOPED_MODEL_HEADER: "scoped-model",
			});

			expect(auth?.auth).toEqual({ apiKey: "scoped-key", headers: { "x-provider": "scoped-provider" } });
			expect(modelHeaders).toEqual({ "x-model": "scoped-model" });
		} finally {
			if (originalKey === undefined) delete process.env.REPI_SCOPED_KEY;
			else process.env.REPI_SCOPED_KEY = originalKey;
			if (originalProviderHeader === undefined) delete process.env.REPI_SCOPED_PROVIDER_HEADER;
			else process.env.REPI_SCOPED_PROVIDER_HEADER = originalProviderHeader;
			if (originalModelHeader === undefined) delete process.env.REPI_SCOPED_MODEL_HEADER;
			else process.env.REPI_SCOPED_MODEL_HEADER = originalModelHeader;
		}
	});

	it("merges provider and model headers case-insensitively while retaining null suppression", async () => {
		const config = await ModelConfig.load(
			writeModelsConfig({
				providers: {
					explicit: {
						baseUrl: "https://example.test/v1",
						apiKey: "key",
						api: "openai-completions",
						headers: { "X-Trace": "provider", "X-Remove": "provider" },
						models: [
							{
								...explicitModel(),
								headers: { "x-trace": "model", "x-remove": null },
							},
						],
					},
				},
			}),
		);
		const extension: ProviderConfigInput = { headers: { "x-extension": "yes" } };
		const provider = composeModelProvider("explicit", undefined, config, extension);
		const model = provider.getModels()[0]!;
		const compatibility = resolveCompatibilityRequestConfig(model, config.getProvider("explicit"), extension);

		expect(compatibility.headers).toEqual({
			"x-extension": "yes",
			"x-trace": "model",
			"x-remove": null,
		});
		expect(mergeProviderHeaders({ "X-Trace": "request" }, compatibility.headers)).toEqual({
			"x-extension": "yes",
			"x-trace": "model",
			"x-remove": null,
		});
	});

	it("keeps explicit model metadata above extension provider defaults and preserves cost tiers", async () => {
		const tiers = [{ inputTokensAbove: 200_000, input: 2, output: 3, cacheRead: 1, cacheWrite: 4 }];
		const config = await ModelConfig.load(
			writeModelsConfig({
				providers: {
					explicit: {
						baseUrl: "https://example.test/v1",
						apiKey: "key",
						api: "openai-completions",
						models: [
							{
								...explicitModel(),
								headers: { "x-layer": "models-json", "x-remove": null },
								cost: { input: 7, output: 2, cacheRead: 0.5, cacheWrite: 3, tiers },
							},
						],
					},
				},
			}),
		);
		const extension: ProviderConfigInput = {
			headers: { "X-LAYER": "extension", "X-REMOVE": "extension" },
		};
		const provider = composeModelProvider("explicit", undefined, config, extension);
		const model = provider.getModels()[0]!;

		expect(resolveCompatibilityRequestConfig(model, config.getProvider("explicit"), extension).headers).toEqual({
			"x-layer": "models-json",
			"x-remove": null,
		});
		expect(model.cost).toEqual({ input: 7, output: 2, cacheRead: 0.5, cacheWrite: 3, tiers });
	});

	it("publishes dynamic model headers into request-time resolution", async () => {
		const config = await ModelConfig.load(undefined);
		const extension: ProviderConfigInput = {
			baseUrl: "https://dynamic.test/v1",
			apiKey: "key",
			api: "openai-completions",
			models: [{ ...explicitModel("initial"), headers: { "x-catalog": "initial" } }],
			refreshModels: async () => [
				{ ...explicitModel("dynamic"), headers: { "x-catalog": "refreshed", "x-dynamic": "yes" } },
			],
		};
		const provider = composeModelProvider("dynamic", undefined, config, extension);

		await provider.refreshModels?.(refreshContext);
		const model = provider.getModels()[0]!;

		expect(model.id).toBe("dynamic");
		expect(resolveConfiguredModelHeaders(model, undefined, extension)).toEqual({
			"x-catalog": "refreshed",
			"x-dynamic": "yes",
		});
	});

	it("does not let an older dynamic refresh overwrite a newer successful result", async () => {
		const config = await ModelConfig.load(undefined);
		const first = deferred<NonNullable<ProviderConfigInput["models"]>>();
		const second = deferred<NonNullable<ProviderConfigInput["models"]>>();
		let call = 0;
		const extension: ProviderConfigInput = {
			baseUrl: "https://dynamic.test/v1",
			apiKey: "key",
			api: "openai-completions",
			models: [explicitModel("initial")],
			refreshModels: async () => (call++ === 0 ? first.promise : second.promise),
		};
		const provider = composeModelProvider("dynamic", undefined, config, extension);
		const older = provider.refreshModels!(refreshContext);
		const newer = provider.refreshModels!(refreshContext);
		await Promise.resolve();
		await Promise.resolve();

		second.resolve([{ ...explicitModel("newer"), headers: { "x-generation": "newer" } }]);
		await newer;
		first.resolve([{ ...explicitModel("older"), headers: { "x-generation": "older" } }]);
		await older;

		const model = provider.getModels()[0]!;
		expect(model.id).toBe("newer");
		expect(resolveConfiguredModelHeaders(model, undefined, extension)).toEqual({ "x-generation": "newer" });
	});

	it("does not publish dynamic models or OAuth projection after abort", async () => {
		const config = await ModelConfig.load(undefined);
		const pending = deferred<NonNullable<ProviderConfigInput["models"]>>();
		const extension: ProviderConfigInput = {
			baseUrl: "https://dynamic.test/v1",
			apiKey: "key",
			api: "openai-completions",
			models: [explicitModel("initial")],
			refreshModels: async () => pending.promise,
		};
		const provider = composeModelProvider("dynamic", undefined, config, extension);
		const controller = new AbortController();
		const refresh = provider.refreshModels!({ ...refreshContext, signal: controller.signal });
		await Promise.resolve();
		controller.abort();
		pending.resolve([explicitModel("aborted")]);
		await refresh;

		expect(provider.getModels().map((model) => model.id)).toEqual(["initial"]);
	});

	it("keeps the previous dynamic catalog when a refresh returns invalid metadata", async () => {
		const config = await ModelConfig.load(undefined);
		const extension: ProviderConfigInput = {
			baseUrl: "https://dynamic.test/v1",
			apiKey: "key",
			api: "openai-completions",
			models: [explicitModel("initial")],
			refreshModels: async () => [{ ...explicitModel("invalid"), contextWindow: 0 }],
		};
		const provider = composeModelProvider("dynamic", undefined, config, extension);

		await expect(provider.refreshModels?.(refreshContext)).rejects.toThrow("invalid contextWindow");
		expect(provider.getModels().map((model) => model.id)).toEqual(["initial"]);
	});

	it("keeps runtime API keys out of the persistent credential store", async () => {
		const stored = new InMemoryCredentialStore();
		await stored.modify("explicit", async () => ({ type: "api_key", key: "stored-key" }));
		const credentials = new RuntimeCredentials(stored);

		credentials.setRuntimeApiKey("explicit", "runtime-key");
		expect(await credentials.read("explicit")).toEqual({ type: "api_key", key: "runtime-key" });
		expect(await stored.read("explicit")).toEqual({ type: "api_key", key: "stored-key" });
		expect(await credentials.list()).toEqual([{ providerId: "explicit", type: "api_key" }]);

		credentials.removeRuntimeApiKey("explicit");
		expect(await credentials.read("explicit")).toEqual({ type: "api_key", key: "stored-key" });
	});
});

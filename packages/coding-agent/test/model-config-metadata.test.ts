import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Model, Provider } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { ModelConfig } from "../src/core/model-config.ts";
import { composeModelProvider, resolveConfiguredModelHeaders } from "../src/core/provider-composer.ts";

const tempDirs: string[] = [];

afterEach(() => {
	for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function writeModelsConfig(config: unknown): string {
	const dir = mkdtempSync(join(tmpdir(), "repi-model-config-metadata-"));
	tempDirs.push(dir);
	const path = join(dir, "models.json");
	writeFileSync(path, JSON.stringify(config));
	return path;
}

function baseModel(): Model<"openai-completions"> {
	return {
		id: "base-model",
		name: "Base Model",
		api: "openai-completions",
		provider: "native",
		baseUrl: "https://native.example/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 1, output: 2, cacheRead: 0.1, cacheWrite: 0.2 },
		contextWindow: 128_000,
		maxTokens: 8_192,
		headers: { "x-native": "base", "x-layer": "base" },
	};
}

function baseProvider(model = baseModel()): Provider {
	return {
		id: "native",
		name: "Native",
		baseUrl: model.baseUrl,
		auth: {
			apiKey: {
				name: "API key",
				resolve: async () => ({ auth: { apiKey: "key" }, source: "test" }),
			},
		},
		getModels: () => [model],
		stream: () => {
			throw new Error("not used");
		},
		streamSimple: () => {
			throw new Error("not used");
		},
	};
}

describe("models.json metadata", () => {
	it("preserves complete model metadata and the current compatibility surface", async () => {
		const config = await ModelConfig.load(
			writeModelsConfig({
				providers: {
					complete: {
						baseUrl: "https://provider.example/v1",
						apiKey: "$COMPLETE_KEY",
						api: "openai-completions",
						compat: { thinkingFormat: "zai", zaiToolStream: true },
						models: [
							{
								id: "vendor/model",
								name: "Vendor Model",
								baseUrl: "https://model.example/v1",
								reasoning: true,
								thinkingLevelMap: { off: null, high: "high", max: "max" },
								input: ["text", "image"],
								cost: {
									input: 0.25,
									output: 1.5,
									cacheRead: 0.025,
									cacheWrite: 0.3,
									tiers: [
										{
											inputTokensAbove: 200_000,
											input: 0.5,
											output: 2,
											cacheRead: 0.05,
											cacheWrite: 0.6,
										},
									],
								},
								contextWindow: 262_144,
								maxTokens: 32_768,
								headers: { "x-model-route": "$MODEL_ROUTE" },
							},
						],
					},
					responses: {
						compat: { supportsStore: true, sendSessionIdHeader: false, supportsToolSearch: true },
					},
					anthropic: {
						compat: { supportsTemperature: false, allowEmptySignature: true },
					},
				},
			}),
		);

		expect(config.getError()).toBeUndefined();
		expect(config.getProvider("responses")?.compat).toEqual({
			supportsStore: true,
			sendSessionIdHeader: false,
			supportsToolSearch: true,
		});
		expect(config.getProvider("anthropic")?.compat).toEqual({
			supportsTemperature: false,
			allowEmptySignature: true,
		});

		const provider = composeModelProvider("complete", undefined, config, undefined);
		const model = provider.getModels()[0]!;
		expect(model).toMatchObject({
			id: "vendor/model",
			name: "Vendor Model",
			api: "openai-completions",
			provider: "complete",
			baseUrl: "https://model.example/v1",
			reasoning: true,
			thinkingLevelMap: { off: null, high: "high", max: "max" },
			input: ["text", "image"],
			cost: {
				input: 0.25,
				output: 1.5,
				cacheRead: 0.025,
				cacheWrite: 0.3,
			},
			contextWindow: 262_144,
			maxTokens: 32_768,
			compat: { thinkingFormat: "zai", zaiToolStream: true },
		});
		expect(
			resolveConfiguredModelHeaders(model, config.getProvider("complete"), undefined, { MODEL_ROUTE: "gpu" }),
		).toEqual({
			"x-model-route": "gpu",
		});
	});

	it.each([
		["empty input modalities", { input: [] }],
		["duplicate input modalities", { input: ["text", "text"] }],
		["zero context window", { contextWindow: 0 }],
		["fractional max output", { maxTokens: 1024.5 }],
		["negative input price", { cost: { input: -1, output: 1, cacheRead: 0, cacheWrite: 0 } }],
		[
			"negative pricing tier threshold",
			{
				cost: {
					input: 1,
					output: 1,
					cacheRead: 0,
					cacheWrite: 0,
					tiers: [{ inputTokensAbove: -1, input: 1, output: 1, cacheRead: 0, cacheWrite: 0 }],
				},
			},
		],
	])("rejects %s", async (_name, invalidFields) => {
		const config = await ModelConfig.load(
			writeModelsConfig({
				providers: {
					invalid: {
						baseUrl: "https://invalid.example/v1",
						apiKey: "key",
						api: "openai-completions",
						models: [{ id: "invalid-model", ...invalidFields }],
					},
				},
			}),
		);

		expect(config.getError()).toContain("Invalid models.json schema");
		expect(config.getProviderIds()).toEqual([]);
	});

	it("applies provider API configuration and explicit model headers", async () => {
		const config = await ModelConfig.load(
			writeModelsConfig({
				providers: {
					native: {
						name: "Configured Native",
						api: "openai-responses",
						models: [
							{
								id: "base-model",
								name: "Base Model",
								reasoning: false,
								input: ["text"],
								cost: { input: 1, output: 2, cacheRead: 0.1, cacheWrite: 0.2 },
								contextWindow: 128_000,
								maxTokens: 8_192,
								headers: { "x-native": "base", "x-layer": "config", "x-disabled": null },
							},
						],
					},
				},
			}),
		);
		const provider = composeModelProvider("native", baseProvider(), config, undefined);
		const model = provider.getModels()[0]!;

		expect(provider.name).toBe("Configured Native");
		expect(model.api).toBe("openai-responses");
		expect(resolveConfiguredModelHeaders(model, config.getProvider("native"), undefined)).toEqual({
			"x-native": "base",
			"x-layer": "config",
			"x-disabled": null,
		});
	});
});

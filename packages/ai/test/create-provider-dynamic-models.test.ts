import { describe, expect, it, vi } from "vitest";
import type { ApiKeyAuth } from "../src/auth/types.ts";
import { createModels, createProvider, type RefreshModelsContext } from "../src/models.ts";
import { InMemoryModelsStore, type ProviderModelsStore } from "../src/models-store.ts";
import type { Api, Model, ProviderStreams } from "../src/types.ts";
import { AssistantMessageEventStream } from "../src/utils/event-stream.ts";

function testModel(provider: string, id: string, name = id): Model<Api> {
	return {
		id,
		name,
		api: "test-api",
		provider,
		baseUrl: "https://example.test/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 10_000,
		maxTokens: 1_000,
	};
}

const ambientAuth: ApiKeyAuth = {
	name: "Ambient",
	resolve: async () => ({ auth: {} }),
};

const streams: ProviderStreams = {
	stream: () => new AssistantMessageEventStream(),
	streamSimple: () => new AssistantMessageEventStream(),
};

function scopedStore(store: InMemoryModelsStore, providerId: string): ProviderModelsStore {
	return {
		read: () => store.read(providerId),
		write: (entry) => store.write(providerId, entry),
		delete: () => store.delete(providerId),
	};
}

function refreshContext(
	store: InMemoryModelsStore,
	providerId: string,
	overrides: Partial<RefreshModelsContext> = {},
): RefreshModelsContext {
	return {
		store: scopedStore(store, providerId),
		allowNetwork: true,
		...overrides,
	};
}

describe("createProvider dynamic model catalogs", () => {
	it("merges a dynamic overlay over the current baseline by model id", async () => {
		let baseline = [testModel("dynamic", "baseline", "baseline-v1"), testModel("dynamic", "shared", "static")];
		const provider = createProvider({
			id: "dynamic",
			auth: { apiKey: ambientAuth },
			models: () => baseline,
			fetchModels: async () => [testModel("dynamic", "shared", "dynamic"), testModel("dynamic", "discovered")],
			api: streams,
		});

		await provider.refreshModels?.(refreshContext(new InMemoryModelsStore(), "dynamic"));
		expect(provider.getModels().map(({ id, name }) => [id, name])).toEqual([
			["baseline", "baseline-v1"],
			["shared", "dynamic"],
			["discovered", "discovered"],
		]);

		baseline = [testModel("dynamic", "baseline", "baseline-v2"), testModel("dynamic", "shared", "static-v2")];
		expect(provider.getModels().map(({ id, name }) => [id, name])).toEqual([
			["baseline", "baseline-v2"],
			["shared", "dynamic"],
			["discovered", "discovered"],
		]);
	});

	it("persists a network overlay and restores only its provider models offline", async () => {
		const modelsStore = new InMemoryModelsStore();
		const online = createModels({ modelsStore });
		online.setProvider(
			createProvider({
				id: "dynamic",
				auth: { apiKey: ambientAuth },
				models: [testModel("dynamic", "baseline")],
				fetchModels: async () => [testModel("dynamic", "remote")],
				api: streams,
			}),
		);

		expect((await online.refresh()).errors.size).toBe(0);
		expect(online.getModels("dynamic").map((model) => model.id)).toEqual(["baseline", "remote"]);
		expect(await modelsStore.read("dynamic")).toMatchObject({
			models: [expect.objectContaining({ id: "remote", provider: "dynamic" })],
		});

		const stored = await modelsStore.read("dynamic");
		if (!stored) throw new Error("Expected persisted model catalog");
		await modelsStore.write("dynamic", {
			...stored,
			models: [...stored.models, testModel("other", "foreign")],
		});
		const offlineFetch = vi.fn(async () => [testModel("dynamic", "must-not-fetch")]);
		const offline = createModels({ modelsStore });
		offline.setProvider(
			createProvider({
				id: "dynamic",
				auth: { apiKey: ambientAuth },
				models: [testModel("dynamic", "baseline")],
				fetchModels: offlineFetch,
				api: streams,
			}),
		);

		expect((await offline.refresh({ allowNetwork: false })).errors.size).toBe(0);
		expect(offlineFetch).not.toHaveBeenCalled();
		expect(offline.getModels("dynamic").map((model) => model.id)).toEqual(["baseline", "remote"]);
	});

	it("deduplicates overlapping refreshes and permits a later refresh", async () => {
		let release: (() => void) | undefined;
		const blocked = new Promise<void>((resolve) => {
			release = resolve;
		});
		const fetchModels = vi.fn(async () => {
			await blocked;
			return [testModel("dynamic", "remote")];
		});
		const provider = createProvider({
			id: "dynamic",
			auth: { apiKey: ambientAuth },
			models: [],
			fetchModels,
			api: streams,
		});
		const context = refreshContext(new InMemoryModelsStore(), "dynamic");

		const first = provider.refreshModels?.(context);
		const second = provider.refreshModels?.(context);
		expect(first).toBe(second);
		await vi.waitFor(() => expect(fetchModels).toHaveBeenCalledTimes(1));
		release?.();
		await Promise.all([first, second]);

		await provider.refreshModels?.(context);
		expect(fetchModels).toHaveBeenCalledTimes(2);
	});

	it("does not publish or persist a fetched overlay after cancellation", async () => {
		const controller = new AbortController();
		const modelsStore = new InMemoryModelsStore();
		const providerStore = scopedStore(modelsStore, "dynamic");
		const write = vi.spyOn(providerStore, "write");
		const provider = createProvider({
			id: "dynamic",
			auth: { apiKey: ambientAuth },
			models: [testModel("dynamic", "baseline")],
			fetchModels: async () => {
				controller.abort();
				return [testModel("dynamic", "cancelled")];
			},
			api: streams,
		});

		await provider.refreshModels?.({
			store: providerStore,
			allowNetwork: true,
			signal: controller.signal,
		});
		expect(provider.getModels().map((model) => model.id)).toEqual(["baseline"]);
		expect(write).not.toHaveBeenCalled();
		expect(await modelsStore.read("dynamic")).toBeUndefined();
	});

	it("keeps custom refreshModels as a passthrough and rejects dual lifecycle ownership", async () => {
		const refreshModels = vi.fn(async () => {});
		const provider = createProvider({
			id: "managed",
			auth: { apiKey: ambientAuth },
			models: [],
			refreshModels,
			api: streams,
		});
		const context = refreshContext(new InMemoryModelsStore(), "managed");

		await provider.refreshModels?.(context);
		expect(refreshModels).toHaveBeenCalledWith(context);
		expect(provider.refreshModels).toBe(refreshModels);
		expect(() =>
			createProvider({
				id: "conflicting",
				auth: { apiKey: ambientAuth },
				models: [],
				fetchModels: async () => [],
				refreshModels: async () => {},
				api: streams,
			}),
		).toThrow("cannot configure both fetchModels and refreshModels");
	});
});

import { describe, expect, it } from "vitest";
import { lazyStream } from "../src/api/lazy.ts";
import { registerApiProvider, unregisterApiProviders } from "../src/api-registry.ts";
import { InMemoryCredentialStore } from "../src/auth/credential-store.ts";
import { lazyOAuth } from "../src/auth/helpers.ts";
import type { ApiKeyAuth, CredentialStore, OAuthAuth, ProviderAuth } from "../src/auth/types.ts";
import {
	clearModelCatalog,
	createModels,
	createProvider,
	getModel as getLegacyModel,
	getModels as getLegacyModels,
	hasApi,
	type Provider,
	registerModelCatalog,
} from "../src/models.ts";
import { InMemoryModelsStore } from "../src/models-store.ts";
import { streamSimple as legacyStreamSimple } from "../src/stream.ts";
import type { Api, AssistantMessage, Context, Model, SimpleStreamOptions, StreamOptions } from "../src/types.ts";
import { AssistantMessageEventStream } from "../src/utils/event-stream.ts";
import { mergeProviderHeaders, providerHeadersToRecord } from "../src/utils/headers.ts";

function testModel(provider: string, id = "model-a"): Model<Api> {
	return {
		id,
		name: id,
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

function doneMessage(model: Model<Api>, text = "ok"): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
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

function completedStream(model: Model<Api>, text = "ok"): AssistantMessageEventStream {
	const stream = new AssistantMessageEventStream();
	const message = doneMessage(model, text);
	stream.push({ type: "start", partial: message });
	stream.push({ type: "done", reason: "stop", message });
	stream.end(message);
	return stream;
}

interface ProviderCall {
	model: Model<Api>;
	options: StreamOptions | undefined;
}

const ambientAuth: ApiKeyAuth = {
	name: "Ambient",
	resolve: async () => ({ auth: {} }),
};

function testProvider(input: {
	id: string;
	baseUrl?: string;
	headers?: Model<Api>["headers"];
	models?: readonly Model<Api>[];
	auth?: ProviderAuth;
	getModels?: () => readonly Model<Api>[];
	refreshModels?: Provider["refreshModels"];
	filterModels?: Provider["filterModels"];
	calls?: ProviderCall[];
}): Provider {
	const models = input.models ?? [testModel(input.id)];
	const respond = (model: Model<Api>, options: StreamOptions | undefined) => {
		input.calls?.push({ model, options });
		return completedStream(model);
	};
	return {
		id: input.id,
		name: input.id,
		baseUrl: input.baseUrl,
		headers: input.headers,
		auth: input.auth ?? { apiKey: ambientAuth },
		getModels: input.getModels ?? (() => models),
		refreshModels: input.refreshModels,
		filterModels: input.filterModels,
		stream: (model, _context, options) => respond(model, options as StreamOptions | undefined),
		streamSimple: (model, _context, options) => respond(model, options as SimpleStreamOptions | undefined),
	};
}

function envKeyAuth(key: string | undefined): ApiKeyAuth {
	return {
		name: "Test API key",
		resolve: async ({ credential }) => {
			const resolved = credential?.key ?? key;
			return resolved ? { auth: { apiKey: resolved }, source: credential ? "stored" : "environment" } : undefined;
		},
	};
}

function testOAuth(overrides?: Partial<OAuthAuth>): OAuthAuth {
	return {
		name: "Test OAuth",
		login: async () => {
			throw new Error("not used");
		},
		refresh: async (credential) => credential,
		toAuth: async (credential) => ({ apiKey: credential.access }),
		...overrides,
	};
}

const context: Context = {
	messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
};

describe("Models runtime", () => {
	it("registers providers and performs synchronous best-effort model lookup", () => {
		const models = createModels();
		models.setProvider(testProvider({ id: "p1", models: [testModel("p1", "m1"), testModel("p1", "m2")] }));
		models.setProvider(testProvider({ id: "p2", models: [testModel("p2", "m3")] }));

		expect(models.getProviders().map((provider) => provider.id)).toEqual(["p1", "p2"]);
		expect(models.getModels().map((model) => model.id)).toEqual(["m1", "m2", "m3"]);
		expect(models.getModel("p2", "m3")?.id).toBe("m3");
		const found = models.getModel("p2", "m3");
		expect(found && hasApi(found, "test-api")).toBe(true);

		models.setProvider(
			testProvider({
				id: "broken",
				getModels: () => {
					throw new Error("catalog failed");
				},
			}),
		);
		expect(models.getModels("broken")).toEqual([]);
		expect(models.getModels().map((model) => model.id)).toEqual(["m1", "m2", "m3"]);

		models.deleteProvider("p1");
		expect(models.getProvider("p1")).toBeUndefined();
		models.clearProviders();
		expect(models.getProviders()).toEqual([]);
	});

	it("isolates stored catalogs by provider and clones both storage boundaries", async () => {
		const store = new InMemoryModelsStore();
		const source = { models: [testModel("p1", "stored")], checkedAt: 123 };
		await store.write("p1", source);
		source.models[0].name = "mutated-after-write";

		const firstRead = await store.read("p1");
		expect(firstRead).toEqual({ models: [testModel("p1", "stored")], checkedAt: 123 });
		expect(await store.read("p2")).toBeUndefined();

		if (!firstRead) throw new Error("Expected stored catalog");
		(firstRead.models[0] as Model<Api>).name = "mutated-after-read";
		expect((await store.read("p1"))?.models[0].name).toBe("stored");

		await store.delete("p1");
		expect(await store.read("p1")).toBeUndefined();
	});

	it("persists a network catalog and restores it offline with force and scoped store context", async () => {
		const credentials = new InMemoryCredentialStore();
		const modelsStore = new InMemoryModelsStore();
		await credentials.modify("dynamic", async () => ({ type: "api_key", key: "stored-key" }));
		let onlineCatalog: readonly Model<Api>[] = [];
		let onlineCalls = 0;
		let seenForce: boolean | undefined;
		let seenCredential: unknown;
		const online = createModels({ credentials, modelsStore });
		online.setProvider(
			testProvider({
				id: "dynamic",
				auth: { apiKey: envKeyAuth(undefined) },
				getModels: () => onlineCatalog,
				refreshModels: async (refreshContext) => {
					onlineCalls++;
					seenForce = refreshContext.force;
					seenCredential = refreshContext.credential;
					expect(refreshContext.allowNetwork).toBe(true);
					const fetched = [testModel("dynamic", "fetched")];
					onlineCatalog = fetched;
					await refreshContext.store.write({ models: fetched, checkedAt: 456 });
				},
			}),
		);

		const onlineResult = await online.refresh({ force: true });
		expect(onlineResult).toMatchObject({ aborted: false });
		expect(onlineResult.errors.size).toBe(0);
		expect(onlineCalls).toBe(1);
		expect(seenForce).toBe(true);
		expect(seenCredential).toEqual({ type: "api_key", key: "stored-key", env: undefined });
		expect(online.getModel("dynamic", "fetched")).toBeDefined();
		expect(await modelsStore.read("dynamic")).toMatchObject({ checkedAt: 456 });

		let offlineCatalog: readonly Model<Api>[] = [];
		let networkCalls = 0;
		const offline = createModels({ credentials, modelsStore });
		offline.setProvider(
			testProvider({
				id: "dynamic",
				auth: { apiKey: envKeyAuth(undefined) },
				getModels: () => offlineCatalog,
				refreshModels: async (refreshContext) => {
					if (refreshContext.allowNetwork) networkCalls++;
					const stored = await refreshContext.store.read();
					offlineCatalog = stored?.models ?? offlineCatalog;
				},
			}),
		);

		const offlineResult = await offline.refresh({ allowNetwork: false });
		expect(offlineResult.errors.size).toBe(0);
		expect(networkCalls).toBe(0);
		expect(offline.getModel("dynamic", "fetched")).toBeDefined();
	});

	it("restores an offline catalog even when provider auth is no longer configured", async () => {
		const modelsStore = new InMemoryModelsStore();
		await modelsStore.write("dynamic", { models: [testModel("dynamic", "cached")], checkedAt: 456 });
		let catalog: readonly Model<Api>[] = [];
		let restores = 0;
		const models = createModels({ modelsStore });
		models.setProvider(
			testProvider({
				id: "dynamic",
				auth: { apiKey: envKeyAuth(undefined) },
				getModels: () => catalog,
				refreshModels: async ({ allowNetwork, credential, store }) => {
					expect(allowNetwork).toBe(false);
					expect(credential).toBeUndefined();
					restores++;
					catalog = (await store.read())?.models ?? [];
				},
			}),
		);

		const result = await models.refresh({ allowNetwork: false });
		expect(result.errors.size).toBe(0);
		expect(restores).toBe(1);
		expect(models.getModel("dynamic", "cached")).toBeDefined();
	});

	it("restores cached models in online mode when provider auth is unavailable", async () => {
		const modelsStore = new InMemoryModelsStore();
		await modelsStore.write("dynamic", { models: [testModel("dynamic", "cached-online")] });
		let networkCalls = 0;
		const models = createModels({ modelsStore });
		models.setProvider(
			createProvider({
				id: "dynamic",
				auth: { apiKey: envKeyAuth(undefined) },
				models: [],
				fetchModels: async () => {
					networkCalls++;
					return [testModel("dynamic", "network")];
				},
				api: {
					stream: (model) => completedStream(model),
					streamSimple: (model) => completedStream(model),
				},
			}),
		);

		const result = await models.refresh({ allowNetwork: true });

		expect(result.errors.size).toBe(0);
		expect(networkCalls).toBe(0);
		expect(models.getModel("dynamic", "cached-online")).toBeDefined();
	});

	it("refreshes dynamic providers concurrently and retains last-known models on failure", async () => {
		let active = 0;
		let maxActive = 0;
		const failure = new Error("network failed");
		const stableCatalog: readonly Model<Api>[] = [testModel("flaky", "last-known")];
		let offlineFallbacks = 0;
		let unconfiguredCacheRestores = 0;
		let unconfiguredNetworkCalls = 0;
		const models = createModels();
		for (const id of ["fast-a", "fast-b"]) {
			models.setProvider(
				testProvider({
					id,
					auth: { apiKey: envKeyAuth("ambient") },
					refreshModels: async () => {
						active++;
						maxActive = Math.max(maxActive, active);
						await new Promise((resolve) => setTimeout(resolve, 10));
						active--;
					},
				}),
			);
		}
		models.setProvider(
			testProvider({
				id: "flaky",
				auth: { apiKey: envKeyAuth("ambient") },
				getModels: () => stableCatalog,
				refreshModels: async ({ allowNetwork }) => {
					if (!allowNetwork) {
						offlineFallbacks++;
						return;
					}
					throw failure;
				},
			}),
		);
		models.setProvider(
			testProvider({
				id: "non-error",
				auth: { apiKey: envKeyAuth("ambient") },
				refreshModels: async ({ allowNetwork }) => {
					if (allowNetwork) throw "string failure";
				},
			}),
		);
		models.setProvider(testProvider({ id: "static" }));
		models.setProvider(
			testProvider({
				id: "unconfigured",
				auth: { apiKey: envKeyAuth(undefined) },
				refreshModels: async ({ allowNetwork }) => {
					if (allowNetwork) unconfiguredNetworkCalls++;
					else unconfiguredCacheRestores++;
				},
			}),
		);

		const result = await models.refresh();
		expect(maxActive).toBeGreaterThan(1);
		expect(result.aborted).toBe(false);
		expect(result.errors.get("flaky")).toBe(failure);
		expect(result.errors.get("non-error")).toMatchObject({ code: "model_source" });
		expect(result.errors.has("unconfigured")).toBe(false);
		expect(offlineFallbacks).toBe(1);
		expect(unconfiguredCacheRestores).toBe(1);
		expect(unconfiguredNetworkCalls).toBe(0);
		expect(stableCatalog.map((model) => model.id)).toEqual(["last-known"]);
		expect(models.getModel("flaky", "last-known")).toBeDefined();
	});

	it("does not let an in-flight offline restore absorb a later online refresh", async () => {
		let releaseFirstRead!: () => void;
		let markFirstReadStarted!: () => void;
		const firstReadGate = new Promise<void>((resolve) => {
			releaseFirstRead = resolve;
		});
		const firstReadStarted = new Promise<void>((resolve) => {
			markFirstReadStarted = resolve;
		});
		let reads = 0;
		let networkCalls = 0;
		let storedModels: readonly Model<Api>[] = [testModel("mixed", "cached")];
		const store = {
			read: async () => {
				reads++;
				if (reads === 1) {
					markFirstReadStarted();
					await firstReadGate;
				}
				return { models: storedModels };
			},
			write: async (entry: { models: readonly Model<Api>[] }) => {
				storedModels = entry.models;
			},
			delete: async () => {},
		};
		const credential = { type: "api_key" as const, key: "key" };
		const provider = createProvider({
			id: "mixed",
			auth: { apiKey: envKeyAuth(undefined) },
			models: [],
			fetchModels: async () => {
				networkCalls++;
				return [testModel("mixed", "network")];
			},
			api: {
				stream: (model) => completedStream(model),
				streamSimple: (model) => completedStream(model),
			},
		});

		const offline = provider.refreshModels?.({ credential, store, allowNetwork: false });
		await firstReadStarted;
		const online = provider.refreshModels?.({ credential, store, allowNetwork: true });
		releaseFirstRead();
		await Promise.all([offline, online]);

		expect(networkCalls).toBe(1);
		expect(provider.getModels().map((model) => model.id)).toEqual(["network"]);
	});

	it("does not let an aborted refresh absorb a later healthy refresh", async () => {
		let releaseFirstRead!: () => void;
		let markFirstReadStarted!: () => void;
		const firstReadGate = new Promise<void>((resolve) => {
			releaseFirstRead = resolve;
		});
		const firstReadStarted = new Promise<void>((resolve) => {
			markFirstReadStarted = resolve;
		});
		let reads = 0;
		let networkCalls = 0;
		const store = {
			read: async () => {
				reads++;
				if (reads === 1) {
					markFirstReadStarted();
					await firstReadGate;
				}
				return { models: [testModel("abort-mixed", "cached")] };
			},
			write: async () => {},
			delete: async () => {},
		};
		const credential = { type: "api_key" as const, key: "key" };
		const provider = createProvider({
			id: "abort-mixed",
			auth: { apiKey: envKeyAuth(undefined) },
			models: [],
			fetchModels: async () => {
				networkCalls++;
				return [testModel("abort-mixed", "healthy")];
			},
			api: {
				stream: (model) => completedStream(model),
				streamSimple: (model) => completedStream(model),
			},
		});
		const controller = new AbortController();

		const aborted = provider.refreshModels?.({
			credential,
			store,
			allowNetwork: true,
			signal: controller.signal,
		});
		await firstReadStarted;
		controller.abort();
		const healthy = provider.refreshModels?.({ credential, store, allowNetwork: true });
		releaseFirstRead();
		await Promise.all([aborted, healthy]);

		expect(networkCalls).toBe(1);
		expect(provider.getModels().map((model) => model.id)).toEqual(["healthy"]);
	});

	it("refreshes expired OAuth for network access and forwards cancellation", async () => {
		const credentials = new InMemoryCredentialStore();
		await credentials.modify("oauth-dynamic", async () => ({
			type: "oauth",
			access: "expired",
			refresh: "refresh",
			expires: 0,
		}));
		const controller = new AbortController();
		let oauthSignal: AbortSignal | undefined;
		let refreshCredential: unknown;
		const models = createModels({ credentials });
		models.setProvider(
			testProvider({
				id: "oauth-dynamic",
				auth: {
					oauth: testOAuth({
						refresh: async (_credential, signal) => {
							oauthSignal = signal;
							return {
								type: "oauth",
								access: "fresh",
								refresh: "rotated",
								expires: Date.now() + 60_000,
							};
						},
					}),
				},
				refreshModels: async (refreshContext) => {
					refreshCredential = refreshContext.credential;
				},
			}),
		);

		const result = await models.refresh({ signal: controller.signal });
		expect(result.errors.size).toBe(0);
		expect(oauthSignal).toBe(controller.signal);
		expect(refreshCredential).toMatchObject({ type: "oauth", access: "fresh", refresh: "rotated" });
		expect(await credentials.read("oauth-dynamic")).toMatchObject({ access: "fresh", refresh: "rotated" });

		let offlineFallbacks = 0;
		models.setProvider(
			testProvider({
				id: "aborted",
				auth: { apiKey: envKeyAuth("ambient") },
				refreshModels: async ({ allowNetwork }) => {
					if (!allowNetwork) {
						offlineFallbacks++;
						return;
					}
					controller.abort();
					throw new Error("cancelled request");
				},
			}),
		);

		const aborted = await models.refresh({ signal: controller.signal });
		expect(aborted.aborted).toBe(true);
		expect(aborted.errors.size).toBe(0);
		expect(offlineFallbacks).toBe(1);
	});

	it("lists only credential metadata and serializes concurrent writes", async () => {
		const credentials = new InMemoryCredentialStore();
		await Promise.all([
			credentials.modify("p1", async () => ({ type: "api_key", key: "secret" })),
			credentials.modify("p1", async (current) => ({
				type: "api_key",
				key: `${current?.type === "api_key" ? current.key : "missing"}-rotated`,
			})),
		]);
		await credentials.modify("p2", async () => ({
			type: "oauth",
			access: "access",
			refresh: "refresh",
			expires: Date.now() + 60_000,
		}));

		expect(await credentials.read("p1")).toEqual({ type: "api_key", key: "secret-rotated" });
		expect(await credentials.list()).toEqual([
			{ providerId: "p1", type: "api_key" },
			{ providerId: "p2", type: "oauth" },
		]);
	});

	it("gives stored credentials ownership and lets explicit request auth override them", async () => {
		const credentials = new InMemoryCredentialStore();
		const models = createModels({ credentials });
		models.setProvider(testProvider({ id: "p1", auth: { apiKey: envKeyAuth("ambient"), oauth: testOAuth() } }));

		expect((await models.getAuth("p1"))?.auth.apiKey).toBe("ambient");
		await credentials.modify("p1", async () => ({
			type: "oauth",
			access: "oauth-token",
			refresh: "refresh",
			expires: Date.now() + 60_000,
		}));
		expect((await models.getAuth("p1"))?.auth.apiKey).toBe("oauth-token");
		expect((await models.getAuth("p1", { apiKey: "request-key" }))?.auth.apiKey).toBe("request-key");

		models.setProvider(testProvider({ id: "mismatch", auth: { apiKey: envKeyAuth("ambient") } }));
		await credentials.modify("mismatch", async () => ({
			type: "oauth",
			access: "stale",
			refresh: "refresh",
			expires: 0,
		}));
		expect(await models.getAuth("mismatch")).toBeUndefined();
	});

	it("checks availability without refreshing OAuth and applies provider filters", async () => {
		const credentials = new InMemoryCredentialStore();
		let refreshes = 0;
		let resolves = 0;
		const checkedAuth: ApiKeyAuth = {
			name: "Checked",
			check: async () => ({ type: "api_key", source: "checked" }),
			resolve: async () => {
				resolves++;
				return { auth: { apiKey: "key" } };
			},
		};
		const models = createModels({ credentials });
		models.setProvider(
			testProvider({
				id: "checked",
				auth: { apiKey: checkedAuth },
				models: [testModel("checked", "visible"), testModel("checked", "hidden")],
				filterModels: (catalog) => catalog.filter((model) => model.id === "visible"),
			}),
		);
		models.setProvider(testProvider({ id: "missing", auth: { apiKey: envKeyAuth(undefined) } }));
		models.setProvider(
			testProvider({
				id: "oauth",
				auth: {
					oauth: testOAuth({
						refresh: async (credential) => {
							refreshes++;
							return credential;
						},
					}),
				},
			}),
		);
		await credentials.modify("oauth", async () => ({
			type: "oauth",
			access: "expired",
			refresh: "refresh",
			expires: 0,
		}));

		expect(await models.checkAuth("checked")).toEqual({ type: "api_key", source: "checked" });
		expect(await models.checkAuth("oauth")).toEqual({ type: "oauth", source: "OAuth" });
		expect((await models.getAvailable()).map((model) => `${model.provider}:${model.id}`)).toEqual([
			"checked:visible",
			"oauth:model-a",
		]);
		expect(refreshes).toBe(0);
		expect(resolves).toBe(0);
	});

	it("runs provider-owned login and logout through the credential store", async () => {
		const credentials = new InMemoryCredentialStore();
		const auth = envKeyAuth(undefined);
		auth.login = async (interaction) => ({
			type: "api_key",
			key: await interaction.prompt({ type: "secret", message: "Key" }),
		});
		const models = createModels({ credentials });
		models.setProvider(testProvider({ id: "p1", auth: { apiKey: auth } }));

		const credential = await models.login("p1", "api_key", {
			prompt: async () => "logged-in",
			notify: () => {},
		});
		expect(credential).toEqual({ type: "api_key", key: "logged-in" });
		expect(await credentials.read("p1")).toEqual(credential);
		await models.logout("p1");
		expect(await credentials.read("p1")).toBeUndefined();
		await expect(
			models.login("unknown", "api_key", { prompt: async () => "", notify: () => {} }),
		).rejects.toMatchObject({ code: "provider" });
	});

	it("refreshes an expired OAuth token exactly once across concurrent requests", async () => {
		const credentials = new InMemoryCredentialStore();
		await credentials.modify("p1", async () => ({
			type: "oauth",
			access: "expired",
			refresh: "refresh",
			expires: 0,
		}));
		let refreshes = 0;
		const models = createModels({ credentials });
		models.setProvider(
			testProvider({
				id: "p1",
				auth: {
					oauth: testOAuth({
						refresh: async () => {
							refreshes++;
							await new Promise((resolve) => setTimeout(resolve, 10));
							return {
								type: "oauth",
								access: "fresh",
								refresh: "rotated",
								expires: Date.now() + 60_000,
							};
						},
					}),
				},
			}),
		);

		const [first, second] = await Promise.all([models.getAuth("p1"), models.getAuth("p1")]);
		expect(refreshes).toBe(1);
		expect(first?.auth.apiKey).toBe("fresh");
		expect(second?.auth.apiKey).toBe("fresh");
		expect(await credentials.read("p1")).toMatchObject({ access: "fresh", refresh: "rotated" });
	});

	it("preserves an expired credential when OAuth refresh fails", async () => {
		const credentials = new InMemoryCredentialStore();
		await credentials.modify("p1", async () => ({
			type: "oauth",
			access: "expired",
			refresh: "refresh",
			expires: 0,
		}));
		const models = createModels({ credentials });
		models.setProvider(
			testProvider({
				id: "p1",
				auth: {
					oauth: testOAuth({
						refresh: async () => {
							throw new Error("invalid_grant");
						},
					}),
				},
			}),
		);

		await expect(models.getAuth("p1")).rejects.toMatchObject({ code: "oauth" });
		expect(await credentials.read("p1")).toMatchObject({ access: "expired", refresh: "refresh" });
	});

	it("assembles and transforms null-suppressed headers case-insensitively", async () => {
		const calls: ProviderCall[] = [];
		const auth: ApiKeyAuth = {
			name: "Scoped",
			resolve: async ({ credential, ctx }) => {
				const account = credential?.env?.ACCOUNT_ID ?? (await ctx.env("ACCOUNT_ID"));
				if (!credential?.key || !account) return undefined;
				return {
					auth: {
						apiKey: credential.key,
						baseUrl: `https://example.test/${account}`,
						headers: { Authorization: "Bearer resolved", "x-auth": "yes", "x-shared": "auth" },
					},
					env: { ACCOUNT_ID: account },
				};
			},
		};
		const models = createModels();
		models.setProvider(
			testProvider({
				id: "p1",
				baseUrl: "https://provider.test/v1",
				headers: { "x-provider": "yes", "x-shared": "provider" },
				auth: { apiKey: auth },
				calls,
			}),
		);
		const model = testModel("p1");
		model.headers = { "x-model": "yes", "X-Shared": "model" };
		let transforms = 0;

		const result = await models.completeSimple(model, context, {
			apiKey: "request-key",
			env: { ACCOUNT_ID: "acct" },
			headers: { authorization: null, "X-MODEL": null, "x-explicit": "yes" },
			transformHeaders: (headers) => {
				transforms++;
				expect(headers).toEqual({
					"x-provider": "yes",
					"x-auth": "yes",
					"X-Shared": "model",
					authorization: null,
					"X-MODEL": null,
					"x-explicit": "yes",
				});
				return mergeProviderHeaders(headers, { "x-shared": null, "x-transformed": "yes" }) ?? {};
			},
		});

		expect(result.stopReason).toBe("stop");
		expect(transforms).toBe(1);
		expect(calls[0].model.baseUrl).toBe("https://example.test/acct");
		expect(calls[0].model.headers).toBeUndefined();
		expect(calls[0].options).toMatchObject({
			apiKey: "request-key",
			env: { ACCOUNT_ID: "acct" },
			headers: {
				"x-provider": "yes",
				"x-auth": "yes",
				authorization: null,
				"X-MODEL": null,
				"x-explicit": "yes",
				"x-shared": null,
				"x-transformed": "yes",
			},
		});
		expect(calls[0].options).not.toHaveProperty("transformHeaders");
		expect(providerHeadersToRecord(calls[0].options?.headers)).toEqual({
			"x-provider": "yes",
			"x-auth": "yes",
			"x-explicit": "yes",
			"x-transformed": "yes",
		});
	});

	it("does not forward a raw request API key after provider auth consumes it", async () => {
		const calls: ProviderCall[] = [];
		const models = createModels();
		models.setProvider(
			testProvider({
				id: "consumed-key",
				auth: {
					apiKey: {
						name: "Consumed key",
						resolve: async ({ credential }) =>
							credential?.key
								? {
										auth: {},
										env: { CONSUMED_API_KEY: credential.key },
										source: "request",
									}
								: undefined,
					},
				},
				calls,
			}),
		);

		await models.completeSimple(testModel("consumed-key"), context, { apiKey: "raw-secret" });

		expect(calls[0].options).not.toHaveProperty("apiKey");
		expect(calls[0].options?.env).toEqual({ CONSUMED_API_KEY: "raw-secret" });
	});

	it("applies a provider base URL when auth does not supply a dynamic override", async () => {
		const calls: ProviderCall[] = [];
		const models = createModels();
		models.setProvider(
			testProvider({
				id: "p1",
				baseUrl: "https://provider.test/v1",
				auth: { apiKey: envKeyAuth("ambient") },
				calls,
			}),
		);

		await models.completeSimple(testModel("p1"), context);
		expect(calls[0].model.baseUrl).toBe("https://provider.test/v1");
	});

	it("turns unknown and unconfigured provider failures into terminal stream errors", async () => {
		const models = createModels();
		const unknown = await models.completeSimple(testModel("unknown"), context);
		expect(unknown).toMatchObject({ stopReason: "error" });
		expect(unknown.errorMessage).toContain("Unknown provider: unknown");

		models.setProvider(testProvider({ id: "missing", auth: { apiKey: envKeyAuth(undefined) } }));
		const unconfigured = await models.completeSimple(testModel("missing"), context);
		expect(unconfigured).toMatchObject({ stopReason: "error" });
		expect(unconfigured.errorMessage).toContain("Provider is not configured: missing");
	});

	it("preserves an inner lazy stream result even when it emits no terminal event", async () => {
		const model = testModel("p1");
		const inner = new AssistantMessageEventStream();
		const message = doneMessage(model, "result-only");
		inner.end(message);

		const result = await lazyStream(model, async () => inner).result();
		expect(result.content).toEqual([{ type: "text", text: "result-only" }]);
	});

	it("turns lazy inner-iterator failures into terminal error results", async () => {
		const model = testModel("p1");
		const source: AsyncIterable<never> = {
			[Symbol.asyncIterator]() {
				return {
					next: async () => {
						throw new Error("iterator failed");
					},
				};
			},
		};

		const result = await lazyStream(model, async () => source).result();
		expect(result).toMatchObject({ stopReason: "error", errorMessage: "iterator failed" });
	});

	it("forwards cancellation through a lazy OAuth wrapper", async () => {
		const controller = new AbortController();
		let receivedSignal: AbortSignal | undefined;
		const oauth = lazyOAuth({
			name: "Lazy OAuth",
			load: async () =>
				testOAuth({
					refresh: async (credential, signal) => {
						receivedSignal = signal;
						return credential;
					},
				}),
		});
		const credential = { type: "oauth" as const, access: "a", refresh: "r", expires: 0 };

		await oauth.refresh(credential, controller.signal);
		expect(receivedSignal).toBe(controller.signal);
	});

	it("keeps explicit legacy catalogs and the global API registry operational", async () => {
		clearModelCatalog();
		expect(getLegacyModels("anthropic")).toEqual([]);
		expect(getLegacyModel("anthropic", "explicit-model")).toBeUndefined();

		const explicitModel = { ...testModel("anthropic", "explicit-model"), api: "anthropic-messages" } as Model<Api>;
		registerModelCatalog({ anthropic: { "explicit-model": explicitModel } });
		expect(getLegacyModels("anthropic")).toEqual([explicitModel]);
		expect(getLegacyModel("anthropic", "explicit-model")?.provider).toBe("anthropic");

		const sourceId = "models-runtime-legacy-compat";
		registerApiProvider(
			{
				api: "runtime-legacy-test",
				stream: (model) => completedStream(model),
				streamSimple: (model) => completedStream(model, "legacy-ok"),
			},
			sourceId,
		);
		try {
			const model: Model<Api> = { ...testModel("legacy"), api: "runtime-legacy-test" };
			const result = await legacyStreamSimple(model, context, { apiKey: "explicit" }).result();
			expect(result.content).toEqual([{ type: "text", text: "legacy-ok" }]);
		} finally {
			unregisterApiProviders(sourceId);
			clearModelCatalog();
		}
	});

	it("wraps credential-store failures with stable auth error codes", async () => {
		const failingStore: CredentialStore = {
			read: async () => {
				throw new Error("storage unavailable");
			},
			list: async () => [],
			modify: async () => undefined,
			delete: async () => {},
		};
		const models = createModels({ credentials: failingStore });
		models.setProvider(testProvider({ id: "p1", auth: { apiKey: envKeyAuth("ambient") } }));

		await expect(models.getAuth("p1")).rejects.toMatchObject({ code: "auth" });
	});
});

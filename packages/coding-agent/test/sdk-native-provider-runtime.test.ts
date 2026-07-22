import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type AssistantMessage, createAssistantMessageEventStream, type Model, type Provider } from "@pi-recon/repi-ai";
import { describe, expect, it, vi } from "vitest";
import { createAgentSessionFromServices, createAgentSessionServices } from "../src/core/agent-session-services.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import type { ExtensionFactory } from "../src/core/extensions/types.ts";
import { ModelRuntime } from "../src/core/model-runtime.ts";
import { DefaultResourceLoader } from "../src/core/resource-loader.ts";
import { createAgentSession } from "../src/core/sdk.ts";
import { SessionManager } from "../src/core/session-manager.ts";

function nativeProvider(onStream: () => void): Provider<"openai-completions"> {
	const model: Model<"openai-completions"> = {
		id: "native-model",
		name: "Native Model",
		api: "openai-completions",
		provider: "native-extension",
		baseUrl: "https://native.invalid/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 10_000,
		maxTokens: 1_000,
	};
	const stream = (requestModel: Model<"openai-completions">) => {
		onStream();
		const events = createAssistantMessageEventStream();
		const message: AssistantMessage = {
			role: "assistant",
			content: [{ type: "text", text: "native-ok" }],
			api: requestModel.api,
			provider: requestModel.provider,
			model: requestModel.id,
			usage: {
				input: 1,
				output: 1,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 2,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: Date.now(),
		};
		events.push({ type: "done", reason: "stop", message });
		events.end(message);
		return events;
	};
	return {
		id: "native-extension",
		name: "Native Extension",
		auth: {
			apiKey: {
				name: "Native key",
				resolve: async () => ({ auth: { apiKey: "native-key" }, source: "native test" }),
			},
		},
		getModels: () => [model],
		stream: (requestModel) => stream(requestModel),
		streamSimple: (requestModel) => stream(requestModel),
	};
}

describe("SDK native Provider runtime", () => {
	it("disposes a service-owned runtime when service initialization fails", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "repi-failed-services-runtime-sdk-"));
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
		const reload = vi
			.spyOn(DefaultResourceLoader.prototype, "reload")
			.mockRejectedValueOnce(new Error("resource reload failed"));

		try {
			await expect(
				createAgentSessionServices({
					cwd,
					agentDir: cwd,
					authStorage,
				}),
			).rejects.toThrow("resource reload failed");
		} finally {
			reload.mockRestore();
			subscribeSpy.mockRestore();
			rmSync(cwd, { recursive: true, force: true });
		}

		expect(activeSubscriptions).toBe(0);
	});

	it("disposes an owned runtime when direct session initialization fails", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "repi-failed-session-runtime-sdk-"));
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
		const reload = vi
			.spyOn(DefaultResourceLoader.prototype, "reload")
			.mockRejectedValueOnce(new Error("session resource reload failed"));

		try {
			await expect(
				createAgentSession({
					cwd,
					agentDir: cwd,
					authStorage,
					sessionManager: SessionManager.inMemory(cwd),
				}),
			).rejects.toThrow("session resource reload failed");
		} finally {
			reload.mockRestore();
			subscribeSpy.mockRestore();
			rmSync(cwd, { recursive: true, force: true });
		}

		expect(activeSubscriptions).toBe(0);
	});

	it("disposes a service-owned model runtime with its session", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "repi-owned-runtime-dispose-sdk-"));
		const providerId = "owned-runtime-dispose-oauth";
		let services: Awaited<ReturnType<typeof createAgentSessionServices>> | undefined;
		try {
			services = await createAgentSessionServices({
				cwd,
				agentDir: cwd,
				resourceLoaderOptions: { noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true },
			});
			const runtime = services.modelRuntime!;
			runtime.registerProvider(providerId, {
				name: "Owned runtime OAuth",
				baseUrl: "https://owned-runtime-dispose.invalid/v1",
				api: "openai-completions",
				oauth: {
					name: "Owned runtime OAuth",
					login: async () => ({ access: "access", refresh: "refresh", expires: Date.now() + 60_000 }),
					refreshToken: async (credentials) => credentials,
					getApiKey: (credentials) => credentials.access,
				},
				models: [
					{
						id: "owned-model",
						name: "Owned model",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 10_000,
						maxTokens: 1_000,
					},
				],
			});
			expect(services.authStorage.getOAuthProviders().some((provider) => provider.id === providerId)).toBe(true);

			const { session } = await createAgentSessionFromServices({
				services,
				sessionManager: SessionManager.inMemory(cwd),
			});
			session.dispose();
			expect(services.authStorage.getOAuthProviders().some((provider) => provider.id === providerId)).toBe(false);
			expect((await runtime.refresh()).aborted).toBe(true);
		} finally {
			services?.modelRuntime?.dispose();
			rmSync(cwd, { recursive: true, force: true });
		}
	});

	it("does not dispose an injected model runtime until its owner does", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "repi-injected-runtime-dispose-sdk-"));
		const authStorage = AuthStorage.inMemory();
		const runtime = await ModelRuntime.create({
			credentials: authStorage.asCredentialStore(),
			modelsPath: null,
			allowModelNetwork: false,
		});
		const providerId = "injected-runtime-dispose-oauth";
		runtime.registerProvider(providerId, {
			name: "Injected runtime OAuth",
			baseUrl: "https://injected-runtime-dispose.invalid/v1",
			api: "openai-completions",
			oauth: {
				name: "Injected runtime OAuth",
				login: async () => ({ access: "access", refresh: "refresh", expires: Date.now() + 60_000 }),
				refreshToken: async (credentials) => credentials,
				getApiKey: (credentials) => credentials.access,
			},
			models: [
				{
					id: "injected-model",
					name: "Injected model",
					reasoning: false,
					input: ["text"],
					cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 10_000,
					maxTokens: 1_000,
				},
			],
		});
		const dispose = vi.spyOn(runtime, "dispose");

		try {
			const services = await createAgentSessionServices({
				cwd,
				agentDir: cwd,
				authStorage,
				modelRuntime: runtime,
				resourceLoaderOptions: { noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true },
			});
			const { session } = await createAgentSessionFromServices({
				services,
				sessionManager: SessionManager.inMemory(cwd),
			});
			session.dispose();

			expect(dispose).not.toHaveBeenCalled();
			expect(authStorage.getOAuthProviders().some((provider) => provider.id === providerId)).toBe(true);
		} finally {
			runtime.dispose();
			rmSync(cwd, { recursive: true, force: true });
		}

		expect(dispose).toHaveBeenCalledTimes(1);
		expect(authStorage.getOAuthProviders().some((provider) => provider.id === providerId)).toBe(false);
	});

	it("honors explicit runtime ownership in the direct SDK", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "repi-explicit-runtime-ownership-sdk-"));
		const authStorage = AuthStorage.inMemory();
		const runtime = await ModelRuntime.create({
			credentials: authStorage.asCredentialStore(),
			modelsPath: null,
			allowModelNetwork: false,
		});
		const providerId = "explicit-owned-runtime-oauth";
		runtime.registerProvider(providerId, {
			name: "Explicitly owned runtime OAuth",
			baseUrl: "https://explicit-owned-runtime.invalid/v1",
			api: "openai-completions",
			oauth: {
				name: "Explicitly owned runtime OAuth",
				login: async () => ({ access: "access", refresh: "refresh", expires: Date.now() + 60_000 }),
				refreshToken: async (credentials) => credentials,
				getApiKey: (credentials) => credentials.access,
			},
			models: [
				{
					id: "explicit-owned-model",
					name: "Explicit owned model",
					reasoning: false,
					input: ["text"],
					cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 10_000,
					maxTokens: 1_000,
				},
			],
		});
		const dispose = vi.spyOn(runtime, "dispose");

		try {
			const { session } = await createAgentSession({
				cwd,
				agentDir: cwd,
				authStorage,
				modelRuntime: runtime,
				disposeModelRuntime: true,
				sessionManager: SessionManager.inMemory(cwd),
			});
			session.dispose();

			expect(dispose).toHaveBeenCalledTimes(1);
			expect(authStorage.getOAuthProviders().some((provider) => provider.id === providerId)).toBe(false);
		} finally {
			runtime.dispose();
			rmSync(cwd, { recursive: true, force: true });
		}
	});

	it("pre-applies native providers for model selection and preserves hot unregister ownership", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "repi-native-provider-sdk-"));
		let streamCalls = 0;
		const provider = nativeProvider(() => streamCalls++);
		const extension: ExtensionFactory = (pi) => {
			pi.registerProvider(provider);
			pi.registerCommand("remove-native", {
				description: "Remove the native provider",
				handler: async () => pi.unregisterProvider(provider.id),
			});
		};

		try {
			const services = await createAgentSessionServices({
				cwd,
				agentDir: cwd,
				resourceLoaderOptions: {
					extensionFactories: [extension],
					noSkills: true,
					noPromptTemplates: true,
					noThemes: true,
				},
			});
			expect(services.modelRuntime).toBeDefined();
			expect(services.modelRegistry.isBackedBy(services.modelRuntime!)).toBe(true);
			const model = services.modelRegistry.find(provider.id, "native-model");
			expect(model).toBeDefined();

			const { session } = await createAgentSessionFromServices({
				services,
				sessionManager: SessionManager.inMemory(cwd),
				model,
			});
			try {
				await session.bindExtensions({});
				await session.prompt("hello");
				expect(streamCalls).toBe(1);
				expect(session.messages.at(-1)).toMatchObject({ role: "assistant" });

				await session.prompt("/remove-native");
				expect(services.modelRuntime?.getProvider(provider.id)).toBeUndefined();
			} finally {
				session.dispose();
			}
		} finally {
			rmSync(cwd, { recursive: true, force: true });
		}
	});

	it("routes an explicit non-catalog model through its native runtime provider", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "repi-native-explicit-model-sdk-"));
		let streamCalls = 0;
		const provider = nativeProvider(() => streamCalls++);
		const extension: ExtensionFactory = (pi) => pi.registerProvider(provider);

		try {
			const services = await createAgentSessionServices({
				cwd,
				agentDir: cwd,
				resourceLoaderOptions: {
					extensionFactories: [extension],
					noSkills: true,
					noPromptTemplates: true,
					noThemes: true,
				},
			});
			const catalogModel = services.modelRegistry.find(provider.id, "native-model");
			expect(catalogModel).toBeDefined();
			const explicitModel: Model<"native-uncatalogued-api"> = {
				...catalogModel!,
				id: "explicit-native-model",
				name: "Explicit Native Model",
				api: "native-uncatalogued-api",
				compat: undefined,
			};
			expect(services.modelRuntime?.getModel(provider.id, explicitModel.id)).toBeUndefined();

			const { session } = await createAgentSessionFromServices({
				services,
				sessionManager: SessionManager.inMemory(cwd),
				model: explicitModel,
			});
			try {
				await session.bindExtensions({});
				await session.prompt("hello explicit model");

				expect(streamCalls).toBe(1);
				expect(session.messages.at(-1)).toMatchObject({
					role: "assistant",
					model: explicitModel.id,
				});
			} finally {
				session.dispose();
			}
		} finally {
			rmSync(cwd, { recursive: true, force: true });
		}
	});

	it("reloads models.json through the session's canonical runtime facade", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "repi-model-config-reload-sdk-"));
		const modelsPath = join(cwd, "models.json");
		const writeModels = (baseUrl: string, includeSecond: boolean) => {
			const model = (id: string) => ({
				id,
				name: id,
				reasoning: false,
				input: ["text"],
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
				contextWindow: 10_000,
				maxTokens: 1_000,
			});
			writeFileSync(
				modelsPath,
				JSON.stringify({
					providers: {
						saved: {
							baseUrl,
							apiKey: "saved-key",
							api: "openai-completions",
							models: [model("stable-model"), ...(includeSecond ? [model("second-model")] : [])],
						},
					},
				}),
			);
		};
		writeModels("https://saved-old.invalid/v1", false);

		try {
			const services = await createAgentSessionServices({
				cwd,
				agentDir: cwd,
				resourceLoaderOptions: { noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true },
			});
			const { session } = await createAgentSessionFromServices({
				services,
				sessionManager: SessionManager.inMemory(cwd),
				model: services.modelRegistry.find("saved", "stable-model"),
			});
			try {
				expect(session.model?.baseUrl).toBe("https://saved-old.invalid/v1");
				writeModels("https://saved-new.invalid/v1", true);

				await session.reload();

				expect(session.model?.baseUrl).toBe("https://saved-new.invalid/v1");
				expect(session.modelRegistry.find("saved", "second-model")?.baseUrl).toBe("https://saved-new.invalid/v1");
			} finally {
				session.dispose();
			}
		} finally {
			rmSync(cwd, { recursive: true, force: true });
		}
	});

	it("replaces legacy and native extension providers across reload and dispose", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "repi-provider-reload-sdk-"));
		const provider = nativeProvider(() => {});
		let enabled = true;
		const extension: ExtensionFactory = (pi) => {
			if (!enabled) return;
			pi.registerProvider(provider);
			pi.registerProvider("legacy-extension", {
				baseUrl: "https://legacy.invalid/v1",
				apiKey: "legacy-key",
				api: "openai-completions",
				models: [
					{
						id: "legacy-model",
						name: "Legacy Model",
						reasoning: false,
						input: ["text"],
						cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 10_000,
						maxTokens: 1_000,
					},
				],
			});
		};

		try {
			const services = await createAgentSessionServices({
				cwd,
				agentDir: cwd,
				resourceLoaderOptions: {
					extensionFactories: [extension],
					noSkills: true,
					noPromptTemplates: true,
					noThemes: true,
				},
			});
			const { session } = await createAgentSessionFromServices({
				services,
				sessionManager: SessionManager.inMemory(cwd),
				model: services.modelRegistry.find(provider.id, "native-model"),
			});
			try {
				expect(session.modelRuntime).toBe(services.modelRuntime);
				expect(session.modelRegistry.isBackedBy(session.modelRuntime!)).toBe(true);
				expect(session.modelRuntime?.getProvider(provider.id)).toBeDefined();
				expect(session.modelRuntime?.getProvider("legacy-extension")).toBeDefined();

				enabled = false;
				await session.reload();
				expect(session.modelRuntime?.getProvider(provider.id)).toBeUndefined();
				expect(session.modelRuntime?.getProvider("legacy-extension")).toBeUndefined();

				enabled = true;
				await session.reload();
				expect(session.modelRuntime?.getProvider(provider.id)).toBeDefined();
				expect(session.modelRuntime?.getProvider("legacy-extension")).toBeDefined();

				session.dispose();
				expect(services.modelRuntime?.getProvider(provider.id)).toBeUndefined();
				expect(services.modelRuntime?.getProvider("legacy-extension")).toBeUndefined();
			} finally {
				session.dispose();
			}
		} finally {
			rmSync(cwd, { recursive: true, force: true });
		}
	});
});

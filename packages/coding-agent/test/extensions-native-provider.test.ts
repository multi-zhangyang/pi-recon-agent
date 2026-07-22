import { createAssistantMessageEventStream, type Model, type Provider } from "@pi-recon/repi-ai";
import { describe, expect, it, vi } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { createEventBus } from "../src/core/event-bus.ts";
import { createExtensionRuntime, loadExtensionFromFactory } from "../src/core/extensions/loader.ts";
import { ExtensionRunner } from "../src/core/extensions/runner.ts";
import type {
	ExtensionActions,
	ExtensionAPI,
	ExtensionContextActions,
	ProviderConfig,
} from "../src/core/extensions/types.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";

const legacyConfig: ProviderConfig = {
	baseUrl: "https://legacy.example/v1",
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
};

const extensionActions: ExtensionActions = {
	sendMessage: () => {},
	sendUserMessage: () => {},
	appendEntry: () => {},
	setSessionName: () => {},
	getSessionName: () => undefined,
	setLabel: () => {},
	getActiveTools: () => [],
	getAllTools: () => [],
	setActiveTools: () => {},
	refreshTools: () => {},
	getCommands: () => [],
	setModel: async () => false,
	getThinkingLevel: () => "off",
	setThinkingLevel: () => {},
};

const contextActions: ExtensionContextActions = {
	getModel: () => undefined,
	isIdle: () => true,
	getSignal: () => undefined,
	abort: () => {},
	hasPendingMessages: () => false,
	shutdown: () => {},
	getContextUsage: () => undefined,
	compact: () => {},
	getSystemPrompt: () => "",
};

function nativeProvider(id: string, modelId = `${id}-model`): Provider {
	const model: Model<"native-test-api"> = {
		id: modelId,
		name: modelId,
		api: "native-test-api",
		provider: id,
		baseUrl: "https://native.example/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 10_000,
		maxTokens: 1_000,
	};
	return {
		id,
		name: id,
		auth: {
			apiKey: {
				name: "Native test key",
				resolve: async () => ({ auth: { apiKey: "native-key" } }),
			},
		},
		getModels: () => [model],
		stream: () => createAssistantMessageEventStream(),
		streamSimple: () => createAssistantMessageEventStream(),
	};
}

function createRunner(runtime = createExtensionRuntime()) {
	return {
		runtime,
		runner: new ExtensionRunner(
			[],
			runtime,
			process.cwd(),
			SessionManager.inMemory(),
			ModelRegistry.inMemory(AuthStorage.inMemory()),
		),
	};
}

describe("native extension providers", () => {
	it("queues native providers and pre-bind unregister only removes the calling extension's registration", async () => {
		const runtime = createExtensionRuntime();
		const eventBus = createEventBus();
		const providerA = nativeProvider("shared", "model-a");
		const providerB = nativeProvider("shared", "model-b");

		await loadExtensionFromFactory(
			(pi) => {
				pi.registerProvider(providerA);
			},
			process.cwd(),
			eventBus,
			runtime,
			"/extensions/a.ts",
		);
		await loadExtensionFromFactory(
			(pi) => {
				pi.registerProvider(providerB);
				pi.unregisterProvider("shared");
			},
			process.cwd(),
			eventBus,
			runtime,
			"/extensions/b.ts",
		);

		expect(runtime.pendingNativeProviderRegistrations).toEqual([
			expect.objectContaining({ provider: providerA, extensionPath: "/extensions/a.ts" }),
		]);
	});

	it("flushes native and legacy registrations in source order through injected actions", async () => {
		const runtime = createExtensionRuntime();
		const provider = nativeProvider("ordered");
		runtime.registerNativeProvider(provider, "/extensions/ordered.ts");
		runtime.registerProvider("ordered", legacyConfig, "/extensions/ordered.ts");
		const { runner } = createRunner(runtime);
		const calls: string[] = [];

		runner.bindCore(extensionActions, contextActions, {
			registerNativeProvider: (registered) => calls.push(`native:${registered.id}`),
			registerProvider: (name) => calls.push(`legacy:${name}`),
			unregisterProvider: () => {},
		});

		expect(calls).toEqual(["native:ordered", "legacy:ordered"]);
		expect(runtime.pendingNativeProviderRegistrations).toEqual([]);
		expect(runtime.pendingProviderRegistrations).toEqual([]);
	});

	it("enforces ownership when providers are replaced and hot-unregistered", async () => {
		const runtime = createExtensionRuntime();
		const eventBus = createEventBus();
		let apiA!: ExtensionAPI;
		let apiB!: ExtensionAPI;
		await loadExtensionFromFactory(
			(pi) => {
				apiA = pi;
			},
			process.cwd(),
			eventBus,
			runtime,
			"/extensions/a.ts",
		);
		await loadExtensionFromFactory(
			(pi) => {
				apiB = pi;
			},
			process.cwd(),
			eventBus,
			runtime,
			"/extensions/b.ts",
		);
		const { runner } = createRunner(runtime);
		const registerNativeProvider = vi.fn();
		const unregisterProvider = vi.fn();
		runner.bindCore(extensionActions, contextActions, {
			registerNativeProvider,
			registerProvider: vi.fn(),
			unregisterProvider,
		});

		apiA.registerProvider(nativeProvider("shared", "a"));
		apiB.registerProvider(nativeProvider("shared", "b"));
		apiA.unregisterProvider("shared");
		expect(unregisterProvider).not.toHaveBeenCalled();

		apiB.unregisterProvider("shared");
		expect(registerNativeProvider).toHaveBeenCalledTimes(2);
		expect(unregisterProvider).toHaveBeenCalledOnce();
		expect(unregisterProvider).toHaveBeenCalledWith("shared");

		apiA.registerProvider("legacy", legacyConfig);
		apiA.unregisterProvider("legacy");
		expect(unregisterProvider).toHaveBeenLastCalledWith("legacy");
	});

	it("reports queued native registration when runtime actions are not wired", async () => {
		const runtime = createExtensionRuntime();
		const eventBus = createEventBus();
		let api!: ExtensionAPI;
		const provider = nativeProvider("requires-runtime");
		const extension = await loadExtensionFromFactory(
			(pi) => {
				api = pi;
				pi.registerProvider(provider);
			},
			process.cwd(),
			eventBus,
			runtime,
			"/extensions/native.ts",
		);
		const modelRegistry = ModelRegistry.inMemory(AuthStorage.inMemory());
		const runner = new ExtensionRunner([extension], runtime, process.cwd(), SessionManager.inMemory(), modelRegistry);
		const errors: string[] = [];
		runner.onError((error) => errors.push(error.error));

		expect(() => runner.bindCore(extensionActions, contextActions)).not.toThrow();
		expect(errors).toEqual([
			"Native provider registration requires registerNativeProvider and unregisterProvider runtime actions",
		]);
		expect(modelRegistry.find("requires-runtime", "requires-runtime-model")).toBeUndefined();
		expect(() => api.registerProvider(nativeProvider("hot-native"))).toThrow(
			"Native provider registration requires registerNativeProvider and unregisterProvider runtime actions",
		);
	});
});

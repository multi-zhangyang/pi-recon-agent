import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type Api,
	type AssistantMessage,
	createAssistantMessageEventStream,
	type Model,
	type ProviderHeaders,
	type SimpleStreamOptions,
} from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { ModelRuntime } from "../src/core/model-runtime.ts";
import { createAgentSession } from "../src/core/sdk.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";

describe("createAgentSession stream options", () => {
	let tempDir: string;
	let cwd: string;
	let agentDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "pi-sdk-stream-options-"));
		cwd = join(tempDir, "project");
		agentDir = join(tempDir, "agent");
		mkdirSync(cwd, { recursive: true });
		mkdirSync(agentDir, { recursive: true });
	});

	afterEach(() => {
		if (tempDir) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	function createModel(api: Api): Model<Api> {
		return {
			id: "capture-model",
			name: "Capture Model",
			api,
			provider: "capture-provider",
			baseUrl: "https://capture.invalid/v1",
			reasoning: false,
			input: ["text"],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 128000,
			maxTokens: 4096,
		};
	}

	function createDoneStream(api: Api) {
		const stream = createAssistantMessageEventStream();
		const message: AssistantMessage = {
			role: "assistant",
			content: [{ type: "text", text: "ok" }],
			api,
			provider: "capture-provider",
			model: "capture-model",
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
		stream.end(message);
		return stream;
	}

	async function captureStreamOptions(
		api: Api,
		settings: { httpIdleTimeoutMs?: number; websocketConnectTimeoutMs?: number },
		requestOptions: SimpleStreamOptions = {},
	): Promise<SimpleStreamOptions | undefined> {
		const model = createModel(api);
		const settingsManager = SettingsManager.inMemory(settings);

		const authStorage = AuthStorage.create(join(agentDir, "auth.json"));
		authStorage.setRuntimeApiKey(model.provider, "test-api-key");
		const modelRegistry = ModelRegistry.create(authStorage, join(agentDir, "models.json"));
		let capturedOptions: SimpleStreamOptions | undefined;

		modelRegistry.registerProvider(model.provider, {
			api,
			streamSimple: (_model, _context, providerOptions) => {
				capturedOptions = providerOptions;
				return createDoneStream(api);
			},
		});

		const sessionManager = SessionManager.inMemory(cwd);
		const { session } = await createAgentSession({
			cwd,
			agentDir,
			model,
			authStorage,
			modelRegistry,
			settingsManager,
			sessionManager,
		});

		try {
			await session.agent.streamFn(model, { messages: [] }, requestOptions);
			return capturedOptions;
		} finally {
			session.dispose();
			modelRegistry.unregisterProvider(model.provider);
		}
	}

	it("forwards httpIdleTimeoutMs as timeoutMs for OpenAI Codex", async () => {
		const options = await captureStreamOptions("openai-codex-responses", { httpIdleTimeoutMs: 1234 });

		expect(options?.timeoutMs).toBe(1234);
	});

	it("defaults timeoutMs from httpIdleTimeoutMs for all providers", async () => {
		const options = await captureStreamOptions("openai-completions", { httpIdleTimeoutMs: 1234 });

		expect(options?.timeoutMs).toBe(1234);
	});

	it("lets request timeoutMs override httpIdleTimeoutMs for OpenAI Codex", async () => {
		const options = await captureStreamOptions(
			"openai-codex-responses",
			{ httpIdleTimeoutMs: 1234 },
			{ timeoutMs: 0 },
		);

		expect(options?.timeoutMs).toBe(0);
	});

	it("forwards websocketConnectTimeoutMs from settings", async () => {
		const options = await captureStreamOptions("openai-codex-responses", { websocketConnectTimeoutMs: 1234 });

		expect(options?.websocketConnectTimeoutMs).toBe(1234);
	});

	it("lets request websocketConnectTimeoutMs override settings", async () => {
		const options = await captureStreamOptions(
			"openai-codex-responses",
			{ websocketConnectTimeoutMs: 1234 },
			{ websocketConnectTimeoutMs: 0 },
		);

		expect(options?.websocketConnectTimeoutMs).toBe(0);
	});

	it("routes runtime auth, scoped env, configured headers, and attribution through one stream assembly", async () => {
		const authStorage = AuthStorage.create(join(agentDir, "auth.json"));
		const modelRegistry = ModelRegistry.create(authStorage, join(agentDir, "models.json"));
		const modelRuntime = await ModelRuntime.create({
			credentials: authStorage.asCredentialStore(),
			modelsPath: null,
			allowModelNetwork: false,
		});
		let capturedOptions: SimpleStreamOptions | undefined;
		modelRuntime.registerProvider("openrouter", {
			name: "Runtime OpenRouter",
			baseUrl: "https://openrouter.ai/api/v1",
			apiKey: "$CAPTURE_RUNTIME_KEY",
			api: "openai-completions",
			headers: { "X-Provider-Env": "$CAPTURE_PROVIDER_HEADER" },
			streamSimple: (model, _context, options) => {
				capturedOptions = options;
				expect(options).not.toHaveProperty("transformHeaders");
				return createDoneStream(model.api);
			},
			models: [
				{
					...createModel("openai-completions"),
					id: "runtime-model",
					name: "Runtime Model",
					headers: { "X-Model-Env": "$CAPTURE_MODEL_HEADER" },
				},
			],
		});
		const model = modelRuntime.getModel("openrouter", "runtime-model")!;
		const { session } = await createAgentSession({
			cwd,
			agentDir,
			model,
			authStorage,
			modelRegistry,
			modelRuntime,
			settingsManager: SettingsManager.create(cwd, agentDir),
			sessionManager: SessionManager.inMemory(cwd),
		});

		try {
			const stream = await session.agent.streamFn(
				model,
				{ messages: [] },
				{
					env: {
						CAPTURE_RUNTIME_KEY: "request-key",
						CAPTURE_PROVIDER_HEADER: "provider-env",
						CAPTURE_MODEL_HEADER: "model-env",
					},
					headers: { "X-Request": "request" },
				},
			);
			await stream.result();

			expect(capturedOptions?.apiKey).toBe("request-key");
			expect(capturedOptions?.env).toMatchObject({ CAPTURE_RUNTIME_KEY: "request-key" });
			expect(capturedOptions?.headers).toEqual({
				"X-Provider-Env": "provider-env",
				"X-Model-Env": "model-env",
				"X-Request": "request",
				"X-OpenRouter-Title": "repi",
				"X-OpenRouter-Categories": "cli-agent",
			} satisfies ProviderHeaders);
		} finally {
			session.dispose();
			modelRuntime.unregisterProvider("openrouter");
		}
	});
});

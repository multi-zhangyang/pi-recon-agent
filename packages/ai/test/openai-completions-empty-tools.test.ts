import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createModels, createProvider } from "../src/models.ts";
import { streamOpenAICompletions, streamSimpleOpenAICompletions } from "../src/providers/openai-completions.ts";
import { streamSimple } from "../src/stream.ts";
import type { Model } from "../src/types.ts";

// Empty tools arrays must NOT be serialized as `tools: []` — some OpenAI-compatible
// backends (e.g. DashScope / Aliyun Qwen via compatible-mode) reject the request with
// `"[] is too short - 'tools'"` (HTTP 400) when `--no-tools` produces an empty array.
// Regression for https://github.com/earendil-works/pi-mono/issues/<issue-number>

const mockState = vi.hoisted(() => ({
	lastParams: undefined as unknown,
	lastClientOptions: undefined as unknown,
}));

const openAICompletionsModel: Model<"openai-completions"> = {
	id: "gpt-4o-mini",
	name: "GPT-4o Mini",
	api: "openai-completions",
	provider: "openai",
	baseUrl: "https://api.openai.com/v1",
	reasoning: false,
	input: ["text", "image"],
	cost: { input: 0.15, output: 0.6, cacheRead: 0.075, cacheWrite: 0 },
	contextWindow: 128_000,
	maxTokens: 16_384,
};

const cloudflareGatewayModel: Model<"openai-completions"> = {
	id: "workers-ai/@cf/moonshotai/kimi-k2.6",
	name: "Kimi K2.6",
	api: "openai-completions",
	provider: "cloudflare-ai-gateway",
	baseUrl: "https://gateway.ai.cloudflare.com/v1/{CLOUDFLARE_ACCOUNT_ID}/{CLOUDFLARE_GATEWAY_ID}/compat",
	reasoning: true,
	input: ["text", "image"],
	cost: { input: 0.95, output: 4, cacheRead: 0.16, cacheWrite: 0 },
	contextWindow: 256_000,
	maxTokens: 256_000,
	compat: { sendSessionAffinityHeaders: true },
};

const cloudflareEnv = {
	CLOUDFLARE_ACCOUNT_ID: "account-id",
	CLOUDFLARE_GATEWAY_ID: "gateway-id",
};

vi.mock("openai", () => {
	class FakeOpenAI {
		constructor(options: unknown) {
			mockState.lastClientOptions = options;
		}

		chat = {
			completions: {
				create: (params: unknown) => {
					mockState.lastParams = params;
					const stream = {
						async *[Symbol.asyncIterator]() {
							yield {
								choices: [{ delta: {}, finish_reason: "stop" }],
								usage: {
									prompt_tokens: 1,
									completion_tokens: 1,
									prompt_tokens_details: { cached_tokens: 0 },
									completion_tokens_details: { reasoning_tokens: 0 },
								},
							};
						},
					};
					const promise = Promise.resolve(stream) as Promise<typeof stream> & {
						withResponse: () => Promise<{
							data: typeof stream;
							response: { status: number; headers: Headers };
						}>;
					};
					promise.withResponse = async () => ({
						data: stream,
						response: { status: 200, headers: new Headers() },
					});
					return promise;
				},
			},
		};
	}

	return { default: FakeOpenAI };
});

describe("openai-completions empty tools handling", () => {
	beforeEach(() => {
		mockState.lastParams = undefined;
		mockState.lastClientOptions = undefined;
	});

	afterEach(() => vi.unstubAllEnvs());

	it("omits tools field when context.tools is an empty array", async () => {
		await streamSimple(
			openAICompletionsModel,
			{
				messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
				tools: [],
			},
			{ apiKey: "test" },
		).result();

		const params = mockState.lastParams as { tools?: unknown };
		expect("tools" in (params as object)).toBe(false);
	});

	it("omits tools field when context.tools is undefined", async () => {
		await streamSimple(
			openAICompletionsModel,
			{
				messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
			},
			{ apiKey: "test" },
		).result();

		const params = mockState.lastParams as { tools?: unknown };
		expect("tools" in (params as object)).toBe(false);
	});

	it("does not send default max token fields", async () => {
		await streamSimple(
			openAICompletionsModel,
			{
				messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
			},
			{ apiKey: "test" },
		).result();

		const params = mockState.lastParams as { max_tokens?: number; max_completion_tokens?: number };
		expect(params.max_tokens).toBeUndefined();
		expect(params.max_completion_tokens).toBeUndefined();
	});

	it("sends explicit maxTokens with the standard-compatible max_tokens field", async () => {
		await streamSimple(
			openAICompletionsModel,
			{
				messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
			},
			{ apiKey: "test", maxTokens: 1234 },
		).result();

		const params = mockState.lastParams as { max_tokens?: number; max_completion_tokens?: number };
		expect(params.max_tokens).toBe(1234);
		expect(params.max_completion_tokens).toBeUndefined();
	});

	it("resolves a legacy stream API key from request-scoped env", async () => {
		await streamSimple(
			openAICompletionsModel,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{ env: { OPENAI_API_KEY: "scoped-openai-key" } },
		).result();

		expect(mockState.lastClientOptions).toMatchObject({ apiKey: "scoped-openai-key" });
	});

	it("materializes Cloudflare provider credentials and endpoint from its auth context", async () => {
		const scopedEnv: Record<string, string> = {
			CLOUDFLARE_API_KEY: "scoped-cloudflare-key",
			CLOUDFLARE_ACCOUNT_ID: "scoped-account",
			CLOUDFLARE_GATEWAY_ID: "scoped-gateway",
		};
		const models = createModels({
			authContext: {
				env: async (name) => scopedEnv[name],
				fileExists: async () => false,
			},
		});
		models.setProvider(
			createProvider({
				id: "cloudflare-ai-gateway",
				auth: {
					apiKey: {
						name: "Cloudflare API key",
						resolve: async ({ ctx }) => {
							const apiKey = await ctx.env("CLOUDFLARE_API_KEY");
							const accountId = await ctx.env("CLOUDFLARE_ACCOUNT_ID");
							const gatewayId = await ctx.env("CLOUDFLARE_GATEWAY_ID");
							if (!apiKey || !accountId || !gatewayId) return undefined;
							return {
								auth: { apiKey },
								env: {
									CLOUDFLARE_ACCOUNT_ID: accountId,
									CLOUDFLARE_GATEWAY_ID: gatewayId,
								},
								source: "CLOUDFLARE_API_KEY",
							};
						},
					},
				},
				models: [cloudflareGatewayModel],
				api: {
					stream: streamOpenAICompletions,
					streamSimple: streamSimpleOpenAICompletions,
				},
			}),
		);
		const model = models.getModel("cloudflare-ai-gateway", cloudflareGatewayModel.id);
		if (!model) throw new Error("Expected Cloudflare model");

		const result = await models.completeSimple(model, {
			messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
		});

		expect(result.stopReason).toBe("stop");
		const clientOptions = mockState.lastClientOptions as {
			apiKey?: string;
			baseURL?: string;
			defaultHeaders?: Record<string, unknown>;
		};
		expect(clientOptions.apiKey).toBe("scoped-cloudflare-key");
		expect(clientOptions.baseURL).toBe("https://gateway.ai.cloudflare.com/v1/scoped-account/scoped-gateway/compat");
		expect(clientOptions.defaultHeaders?.Authorization).toBeNull();
		expect(clientOptions.defaultHeaders?.["cf-aig-authorization"]).toBe("Bearer scoped-cloudflare-key");
	});

	it("prefers request-scoped Cloudflare endpoint values over process env", async () => {
		vi.stubEnv("CLOUDFLARE_ACCOUNT_ID", "process-account");
		vi.stubEnv("CLOUDFLARE_GATEWAY_ID", "process-gateway");

		await streamSimple(
			cloudflareGatewayModel,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{
				apiKey: "test",
				env: {
					CLOUDFLARE_ACCOUNT_ID: "provider-account",
					CLOUDFLARE_GATEWAY_ID: "provider-gateway",
				},
			},
		).result();

		expect(mockState.lastClientOptions).toMatchObject({
			baseURL: "https://gateway.ai.cloudflare.com/v1/provider-account/provider-gateway/compat",
		});
	});

	it("uses conservative OpenAI-compatible fields for Cloudflare AI Gateway /compat models", async () => {
		await streamSimple(
			cloudflareGatewayModel,
			{
				systemPrompt: "You are helpful.",
				messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
			},
			{ apiKey: "test", maxTokens: 1234, reasoning: "high", env: cloudflareEnv },
		).result();

		const params = mockState.lastParams as {
			messages: Array<{ role: string }>;
			max_tokens?: number;
			max_completion_tokens?: number;
			reasoning_effort?: string;
			store?: boolean;
		};
		expect(params.messages[0].role).toBe("system");
		expect(params.max_tokens).toBe(1234);
		expect(params.max_completion_tokens).toBeUndefined();
		expect(params.reasoning_effort).toBeUndefined();
		expect(params.store).toBeUndefined();

		const clientOptions = mockState.lastClientOptions as {
			baseURL?: string;
			defaultHeaders?: Record<string, unknown>;
		};
		expect(clientOptions.baseURL).toBe("https://gateway.ai.cloudflare.com/v1/account-id/gateway-id/compat");
		expect(clientOptions.defaultHeaders?.Authorization).toBeNull();
		expect(clientOptions.defaultHeaders?.["cf-aig-authorization"]).toBe("Bearer test");
	});

	it("preserves inline upstream Authorization for Cloudflare AI Gateway BYOK requests", async () => {
		const model = { ...cloudflareGatewayModel, id: "gpt-5.1", name: "GPT-5.1" };

		await streamSimple(
			model,
			{
				messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
			},
			{
				apiKey: "cf-token",
				headers: { Authorization: "Bearer upstream-token" },
				env: cloudflareEnv,
			},
		).result();

		const clientOptions = mockState.lastClientOptions as { defaultHeaders?: Record<string, unknown> };
		expect(clientOptions.defaultHeaders?.Authorization).toBe("Bearer upstream-token");
		expect(clientOptions.defaultHeaders?.["cf-aig-authorization"]).toBe("Bearer cf-token");
	});

	it("sends session affinity headers for Workers AI through Cloudflare AI Gateway", async () => {
		await streamSimple(
			cloudflareGatewayModel,
			{
				messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
			},
			{ apiKey: "test", sessionId: "session-1", env: cloudflareEnv },
		).result();

		const clientOptions = mockState.lastClientOptions as { defaultHeaders?: Record<string, string> };
		expect(clientOptions.defaultHeaders?.session_id).toBe("session-1");
		expect(clientOptions.defaultHeaders?.["x-client-request-id"]).toBe("session-1");
		expect(clientOptions.defaultHeaders?.["x-session-affinity"]).toBe("session-1");
	});

	it("still emits tools: [] for Anthropic/LiteLLM proxy when conversation has tool history", async () => {
		await streamSimple(
			openAICompletionsModel,
			{
				messages: [
					{ role: "user", content: "use the tool", timestamp: Date.now() },
					{
						role: "assistant",
						content: [
							{
								type: "toolCall",
								id: "t1",
								name: "noop",
								arguments: {},
							},
						],
						stopReason: "toolUse",
						usage: {
							input: 0,
							output: 0,
							cacheRead: 0,
							cacheWrite: 0,
							totalTokens: 0,
							cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
						},
						api: "openai-completions",
						provider: "openai",
						model: "gpt-4o-mini",
						timestamp: Date.now(),
					},
					{
						role: "toolResult",
						toolCallId: "t1",
						toolName: "noop",
						content: [{ type: "text", text: "done" }],
						isError: false,
						timestamp: Date.now(),
					},
				],
				tools: [],
			},
			{ apiKey: "test" },
		).result();

		const params = mockState.lastParams as { tools?: unknown[] };
		expect(Array.isArray(params.tools)).toBe(true);
		expect(params.tools).toEqual([]);
	});
});

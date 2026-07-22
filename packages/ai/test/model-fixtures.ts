import { registerModelCatalog } from "../src/models.ts";
import type { Api, Model } from "../src/types.ts";

/**
 * Small, explicit catalog for protocol regression tests.
 *
 * The runtime intentionally has no built-in model directory. These fixtures
 * keep metadata-only tests independent from user configuration while leaving
 * production model discovery opt-in.
 */
type Fixture = {
	provider: string;
	id: string;
	api: Api;
	name?: string;
	baseUrl?: string;
	headers?: Model<Api>["headers"];
	reasoning?: boolean;
	input?: ("text" | "image")[];
	compat?: Record<string, unknown>;
	thinkingLevelMap?: Record<string, string | null>;
	cost?: Model<Api>["cost"];
	contextWindow?: number;
	maxTokens?: number;
};

function model(fixture: Fixture): Model<Api> {
	return {
		id: fixture.id,
		name: fixture.name ?? fixture.id,
		api: fixture.api,
		provider: fixture.provider,
		baseUrl: fixture.baseUrl ?? "http://127.0.0.1:9",
		...(fixture.headers ? { headers: fixture.headers } : {}),
		reasoning: fixture.reasoning ?? false,
		input: fixture.input ?? ["text"],
		cost: fixture.cost ?? { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: fixture.contextWindow ?? 200_000,
		maxTokens: fixture.maxTokens ?? 32_000,
		...(fixture.compat ? { compat: fixture.compat as Model<Api>["compat"] } : {}),
		...(fixture.thinkingLevelMap ? { thinkingLevelMap: fixture.thinkingLevelMap } : {}),
	};
}

/** Register fixtures additively so unrelated test files can provide their own. */
export function registerModelFixtures(fixtures: readonly Fixture[]): void {
	const catalog: Record<string, Record<string, Model<Api>>> = {};
	for (const fixture of fixtures) {
		const providerCatalog = catalog[fixture.provider] ?? {};
		providerCatalog[fixture.id] = model(fixture);
		catalog[fixture.provider] = providerCatalog;
	}
	registerModelCatalog(catalog, { replace: false });
}

export function registerAnthropicFixtures(): void {
	registerModelFixtures([
		{
			provider: "anthropic",
			id: "claude-sonnet-4-5",
			api: "anthropic-messages",
			reasoning: true,
			name: "Claude Sonnet 4.5",
		},
		{
			provider: "anthropic",
			id: "claude-haiku-4-5",
			api: "anthropic-messages",
			reasoning: true,
			name: "Claude Haiku 4.5",
			input: ["text", "image"],
		},
		{
			provider: "anthropic",
			id: "claude-opus-4-6",
			api: "anthropic-messages",
			reasoning: true,
			name: "Claude Opus 4.6",
			compat: { forceAdaptiveThinking: true },
			thinkingLevelMap: { xhigh: "max" },
		},
		{
			provider: "anthropic",
			id: "claude-opus-4-7",
			api: "anthropic-messages",
			reasoning: true,
			name: "Claude Opus 4.7",
			compat: { forceAdaptiveThinking: true, supportsTemperature: false },
			thinkingLevelMap: { xhigh: "xhigh" },
		},
		{
			provider: "anthropic",
			id: "claude-opus-4-8",
			api: "anthropic-messages",
			reasoning: true,
			name: "Claude Opus 4.8",
			compat: { forceAdaptiveThinking: true, supportsTemperature: false },
			thinkingLevelMap: { xhigh: "xhigh" },
		},
		{
			provider: "anthropic",
			id: "claude-sonnet-4-6",
			api: "anthropic-messages",
			reasoning: true,
			name: "Claude Sonnet 4.6",
			compat: { forceAdaptiveThinking: true },
		},
	]);
}

export function registerMistralFixtures(): void {
	registerModelFixtures([
		{
			provider: "mistral",
			id: "codestral-latest",
			api: "mistral-conversations",
			name: "Codestral",
		},
		{
			provider: "mistral",
			id: "devstral-medium-latest",
			api: "mistral-conversations",
			name: "Devstral Medium",
		},
		{
			provider: "mistral",
			id: "mistral-small-2603",
			api: "mistral-conversations",
			name: "Mistral Small 4",
			reasoning: true,
		},
		{
			provider: "mistral",
			id: "magistral-medium-latest",
			api: "mistral-conversations",
			name: "Magistral Medium",
			reasoning: true,
		},
		{
			provider: "mistral",
			id: "mistral-medium-3.5",
			api: "mistral-conversations",
			name: "Mistral Medium 3.5",
			reasoning: true,
		},
	]);
}

export function registerBedrockFixtures(): void {
	registerModelFixtures([
		{
			provider: "amazon-bedrock",
			id: "global.anthropic.claude-opus-4-6-v1",
			api: "bedrock-converse-stream",
			name: "Claude Opus 4.6 (Global)",
			reasoning: true,
			baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
			thinkingLevelMap: { xhigh: "max" },
			input: ["text", "image"],
		},
		{
			provider: "amazon-bedrock",
			id: "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
			api: "bedrock-converse-stream",
			name: "Claude Sonnet 4.5 (US)",
			reasoning: true,
			baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
			input: ["text", "image"],
		},
		{
			provider: "amazon-bedrock",
			id: "global.anthropic.claude-sonnet-4-6",
			api: "bedrock-converse-stream",
			name: "Claude Sonnet 4.6 (Global)",
			reasoning: true,
			baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
			input: ["text", "image"],
		},
		{
			provider: "amazon-bedrock",
			id: "us.anthropic.claude-opus-4-8",
			api: "bedrock-converse-stream",
			name: "Claude Opus 4.8 (US)",
			reasoning: true,
			baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
			thinkingLevelMap: { xhigh: "xhigh" },
			input: ["text", "image"],
		},
		{
			provider: "amazon-bedrock",
			id: "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
			api: "bedrock-converse-stream",
			name: "Claude Sonnet 4.5 (EU)",
			reasoning: true,
			baseUrl: "https://bedrock-runtime.eu-central-1.amazonaws.com",
			input: ["text", "image"],
		},
	]);
}

export function registerFireworksFixtures(): void {
	const compat = {
		sendSessionAffinityHeaders: true,
		supportsEagerToolInputStreaming: false,
		supportsCacheControlOnTools: false,
		supportsLongCacheRetention: false,
	};
	registerModelFixtures([
		{
			provider: "fireworks",
			id: "accounts/fireworks/models/kimi-k2p6",
			api: "anthropic-messages",
			name: "Kimi K2.6",
			baseUrl: "https://api.fireworks.ai/inference",
			reasoning: true,
			input: ["text", "image"],
			cost: { input: 0.95, output: 4, cacheRead: 0.16, cacheWrite: 0 },
			contextWindow: 262_000,
			maxTokens: 262_000,
			compat,
		},
		{
			provider: "fireworks",
			id: "accounts/fireworks/routers/kimi-k2p6-turbo",
			api: "anthropic-messages",
			name: "Kimi K2.6 Turbo",
			baseUrl: "https://api.fireworks.ai/inference",
			reasoning: true,
			input: ["text", "image"],
			cost: { input: 2, output: 8, cacheRead: 0.3, cacheWrite: 0 },
			contextWindow: 262_000,
			maxTokens: 262_000,
			compat,
		},
	]);
}

export function registerTogetherFixtures(): void {
	const standardCompat = {
		supportsStore: false,
		supportsDeveloperRole: false,
		supportsReasoningEffort: false,
		maxTokensField: "max_tokens",
		supportsStrictMode: false,
		supportsLongCacheRetention: false,
	};
	registerModelFixtures([
		{
			provider: "together",
			id: "moonshotai/Kimi-K2.6",
			api: "openai-completions",
			name: "Kimi K2.6",
			baseUrl: "https://api.together.ai/v1",
			reasoning: true,
			input: ["text", "image"],
			cost: { input: 1.2, output: 4.5, cacheRead: 0.2, cacheWrite: 0 },
			contextWindow: 262_144,
			maxTokens: 131_000,
			thinkingLevelMap: { minimal: null, low: null, medium: null },
			compat: { ...standardCompat, thinkingFormat: "together" },
		},
		{
			provider: "together",
			id: "openai/gpt-oss-120b",
			api: "openai-completions",
			reasoning: true,
			thinkingLevelMap: { off: null, minimal: null },
			compat: { ...standardCompat, supportsReasoningEffort: true, thinkingFormat: "openai" },
		},
		{
			provider: "together",
			id: "deepseek-ai/DeepSeek-V4-Pro",
			api: "openai-completions",
			reasoning: true,
			thinkingLevelMap: { minimal: null, low: null, medium: null, high: "high", xhigh: null },
			compat: { ...standardCompat, supportsReasoningEffort: true, thinkingFormat: "together" },
		},
		{
			provider: "together",
			id: "MiniMaxAI/MiniMax-M2.7",
			api: "openai-completions",
			reasoning: true,
			thinkingLevelMap: { off: null, minimal: null, low: null, medium: null },
			compat: standardCompat,
		},
	]);
}

export function registerXiaomiFixtures(): void {
	registerModelFixtures([
		{
			provider: "xiaomi",
			id: "mimo-v2-flash",
			api: "openai-completions",
			name: "MiMo-V2-Flash",
			baseUrl: "https://api.xiaomimimo.com/v1",
			reasoning: true,
			compat: { requiresReasoningContentOnAssistantMessages: true, thinkingFormat: "deepseek" },
		},
	]);
}

export function registerThinkingLevelFixtures(): void {
	registerAnthropicFixtures();
	registerModelFixtures([
		{
			provider: "openai-codex",
			id: "gpt-5.4",
			api: "openai-codex-responses",
			reasoning: true,
			thinkingLevelMap: { minimal: "low", xhigh: "xhigh" },
		},
		{
			provider: "openai-codex",
			id: "gpt-5.5",
			api: "openai-codex-responses",
			reasoning: true,
			thinkingLevelMap: { minimal: "low", xhigh: "xhigh" },
		},
		{
			provider: "openai",
			id: "gpt-5.5-pro",
			api: "openai-responses",
			reasoning: true,
			thinkingLevelMap: { off: null, minimal: null, low: null, xhigh: "xhigh" },
		},
		{
			provider: "openrouter",
			id: "openai/gpt-5.5-pro",
			api: "openai-completions",
			reasoning: true,
			thinkingLevelMap: { off: null, minimal: null, low: null, xhigh: "xhigh" },
		},
		{
			provider: "deepseek",
			id: "deepseek-v4-flash",
			api: "openai-completions",
			reasoning: true,
			thinkingLevelMap: { minimal: null, low: null, medium: null, high: "high", xhigh: "max" },
		},
		{
			provider: "opencode-go",
			id: "deepseek-v4-flash",
			api: "openai-completions",
			reasoning: true,
			thinkingLevelMap: { minimal: null, low: null, medium: null, high: "high", xhigh: "max" },
		},
		{
			provider: "opencode-go",
			id: "kimi-k2.6",
			api: "openai-completions",
			reasoning: true,
			thinkingLevelMap: { minimal: null, low: null, medium: null },
		},
		{
			provider: "opencode",
			id: "grok-build-0.1",
			api: "openai-completions",
			reasoning: true,
			thinkingLevelMap: { off: null, minimal: null, low: null, medium: null },
		},
		{
			provider: "openrouter",
			id: "deepseek/deepseek-v4-flash",
			api: "openai-completions",
			reasoning: true,
			thinkingLevelMap: { minimal: null, low: null, medium: null, high: "high", xhigh: "max" },
		},
		{
			provider: "openrouter",
			id: "anthropic/claude-opus-4.6",
			api: "openai-completions",
			reasoning: true,
			thinkingLevelMap: { xhigh: "max" },
		},
	]);
}

export function registerOpenAIFixtures(): void {
	registerModelFixtures([
		{
			provider: "openai",
			id: "gpt-4o-mini",
			api: "openai-responses",
			name: "GPT-4o mini",
			baseUrl: "https://api.openai.com/v1",
			input: ["text", "image"],
		},
		{
			provider: "openai-codex",
			id: "gpt-5.5",
			api: "openai-codex-responses",
			name: "GPT-5.5",
			baseUrl: "https://chatgpt.com/backend-api",
			reasoning: true,
			input: ["text", "image"],
			thinkingLevelMap: { minimal: "low", xhigh: "xhigh" },
		},
	]);
}

export function registerAzureOpenAIFixtures(): void {
	registerModelFixtures([
		{
			provider: "azure-openai-responses",
			id: "gpt-4o-mini",
			api: "azure-openai-responses",
			name: "GPT-4o mini",
			baseUrl: "",
			input: ["text", "image"],
			cost: { input: 0.15, output: 0.6, cacheRead: 0.075, cacheWrite: 0 },
			contextWindow: 128_000,
			maxTokens: 16_384,
		},
	]);
}

export function registerGoogleVertexFixtures(): void {
	registerModelFixtures([
		{
			provider: "google-vertex",
			id: "gemini-3-flash-preview",
			api: "google-vertex",
			name: "Gemini 3 Flash Preview (Vertex)",
			baseUrl: "https://{location}-aiplatform.googleapis.com",
			reasoning: true,
			thinkingLevelMap: { off: null },
			input: ["text", "image"],
			cost: { input: 0.5, output: 3, cacheRead: 0.05, cacheWrite: 0 },
			contextWindow: 1_048_576,
			maxTokens: 65_536,
		},
	]);
}

export function registerGitHubCopilotFixtures(): void {
	const headers = {
		"User-Agent": "GitHubCopilotChat/0.35.0",
		"Editor-Version": "vscode/1.107.0",
		"Editor-Plugin-Version": "copilot-chat/0.35.0",
		"Copilot-Integration-Id": "vscode-chat",
	};
	registerModelFixtures([
		{
			provider: "github-copilot",
			id: "claude-sonnet-4.6",
			api: "anthropic-messages",
			name: "Claude Sonnet 4.6",
			baseUrl: "https://api.individual.githubcopilot.com",
			headers,
			compat: { forceAdaptiveThinking: true },
			reasoning: true,
			input: ["text", "image"],
			cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
			contextWindow: 1_000_000,
			maxTokens: 32_000,
		},
		{
			provider: "github-copilot",
			id: "gpt-5-mini",
			api: "openai-responses",
			name: "GPT-5 Mini",
			baseUrl: "https://api.individual.githubcopilot.com",
			headers,
			reasoning: true,
			thinkingLevelMap: { off: null, minimal: "low" },
			input: ["text", "image"],
			cost: { input: 0.25, output: 2, cacheRead: 0.025, cacheWrite: 0 },
			contextWindow: 264_000,
			maxTokens: 64_000,
		},
	]);
}

export function registerOpenRouterFixtures(): void {
	registerModelFixtures([
		{
			provider: "openrouter",
			id: "anthropic/claude-sonnet-4",
			api: "openai-completions",
			name: "Anthropic: Claude Sonnet 4",
			baseUrl: "https://openrouter.ai/api/v1",
			reasoning: true,
			input: ["text", "image"],
			cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
			contextWindow: 1_000_000,
			maxTokens: 64_000,
		},
	]);
}

export function registerOpenAIResponsesRegressionFixtures(): void {
	const openAiModels = [
		{ id: "gpt-5.1", off: "none" },
		{ id: "gpt-5.2", off: "none" },
		{ id: "gpt-5.3-codex", off: "none" },
		{ id: "gpt-5.4", off: "none" },
		{ id: "gpt-5.4-mini", off: "none" },
		{ id: "gpt-5.4-nano", off: "none" },
		{ id: "gpt-5.5", off: "none" },
		{ id: "gpt-5", off: null },
		{ id: "gpt-5-mini", off: null },
		{ id: "gpt-5-nano", off: null },
		{ id: "gpt-5-pro", off: null },
		{ id: "gpt-5.2-pro", off: null },
		{ id: "gpt-5.4-pro", off: null },
		{ id: "gpt-5.5-pro", off: null },
	] as const;
	registerModelFixtures([
		...openAiModels.map((entry) => ({
			provider: "openai",
			id: entry.id,
			api: "openai-responses" as const,
			name: entry.id,
			reasoning: true,
			thinkingLevelMap: { off: entry.off },
			input: ["text", "image"] as ("text" | "image")[],
			cost: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 400_000,
			maxTokens: 128_000,
		})),
	]);
}

export function registerOpenAICompletionsRegressionFixtures(): void {
	const standard = {
		provider: "openrouter",
		baseUrl: "https://openrouter.ai/api/v1",
		api: "openai-completions" as const,
		reasoning: true,
		input: ["text", "image"] as ("text" | "image")[],
		cost: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 400_000,
		maxTokens: 128_000,
	};
	registerModelFixtures([
		{
			provider: "groq",
			id: "qwen/qwen3-32b",
			api: "openai-completions",
			name: "Qwen3 32B",
			reasoning: true,
			thinkingLevelMap: { minimal: null, low: null, medium: null, high: "default" },
			compat: { supportsReasoningEffort: true },
		},
		{
			provider: "groq",
			id: "openai/gpt-oss-20b",
			api: "openai-completions",
			name: "GPT OSS 20B",
			reasoning: true,
			compat: { supportsReasoningEffort: true },
		},
		...(["glm-5.1", "glm-4.7", "glm-5-turbo"] as const).map((id) => ({
			provider: "zai",
			id,
			api: "openai-completions" as const,
			name: id,
			reasoning: true,
			compat: { supportsDeveloperRole: false, thinkingFormat: "zai", zaiToolStream: true },
		})),
		{
			provider: "zai",
			id: "glm-4.5-air",
			api: "openai-completions",
			name: "GLM-4.5-Air",
			reasoning: true,
			compat: { supportsDeveloperRole: false, thinkingFormat: "zai" },
		},
		{
			...standard,
			id: "deepseek/deepseek-v4-pro",
			name: "DeepSeek V4 Pro",
			compat: { requiresReasoningContentOnAssistantMessages: true },
		},
		{
			...standard,
			id: "openai/gpt-5.2-codex",
			name: "GPT-5.2 Codex",
		},
		{
			...standard,
			id: "anthropic/claude-sonnet-4.5",
			name: "Claude Sonnet 4.5",
		},
		{
			...standard,
			id: "moonshotai/kimi-k2.6",
			name: "Kimi K2.6",
			compat: { supportsDeveloperRole: false, requiresReasoningContentOnAssistantMessages: true },
		},
		{
			...standard,
			id: "moonshotai/kimi-k2.6:free",
			name: "Kimi K2.6 (free)",
			compat: { supportsDeveloperRole: false, requiresReasoningContentOnAssistantMessages: true },
		},
		{
			...standard,
			id: "deepseek/deepseek-r1",
			name: "DeepSeek R1",
		},
		...(["xiaomi", "xiaomi-token-plan-cn", "xiaomi-token-plan-ams", "xiaomi-token-plan-sgp"] as const).map(
			(provider) => ({
				provider,
				id: "mimo-v2.5-pro",
				api: "openai-completions" as const,
				name: "MiMo V2.5 Pro",
				reasoning: true,
				compat: { requiresReasoningContentOnAssistantMessages: true, thinkingFormat: "deepseek" },
			}),
		),
		{
			provider: "opencode-go",
			id: "kimi-k2.6",
			api: "openai-completions",
			name: "Kimi K2.6",
			reasoning: true,
			thinkingLevelMap: { minimal: null, low: null, medium: null },
			compat: { thinkingFormat: "deepseek", supportsReasoningEffort: false },
		},
		{
			provider: "opencode",
			id: "grok-build-0.1",
			api: "openai-completions",
			name: "Grok Build 0.1",
			reasoning: true,
			thinkingLevelMap: { off: null, minimal: null, low: null, medium: null },
			compat: { supportsReasoningEffort: false },
		},
		{
			provider: "openai",
			id: "gpt-5.5",
			api: "openai-responses",
			name: "GPT-5.5",
			reasoning: true,
			thinkingLevelMap: { off: null, xhigh: "xhigh" },
		},
		{
			provider: "ant-ling",
			id: "Ring-2.6-1T",
			api: "openai-completions",
			name: "Ring 2.6 1T",
			reasoning: true,
			thinkingLevelMap: { off: null, minimal: null, low: null, medium: null, high: "high", xhigh: "xhigh" },
			compat: {
				supportsStore: false,
				supportsDeveloperRole: false,
				supportsReasoningEffort: false,
				maxTokensField: "max_tokens",
				supportsLongCacheRetention: false,
				thinkingFormat: "ant-ling",
			},
		},
		{
			provider: "ant-ling",
			id: "Ling-2.6-flash",
			api: "openai-completions",
			name: "Ling 2.6 Flash",
			reasoning: false,
			compat: {
				supportsStore: false,
				supportsDeveloperRole: false,
				supportsReasoningEffort: false,
				maxTokensField: "max_tokens",
				supportsLongCacheRetention: false,
			},
		},
	]);
}

/**
 * Catalog used by the provider-matrix protocol suites. Production deliberately
 * has no implicit model directory; these suites exercise transport behavior and
 * therefore need an explicit, deterministic set of model metadata.
 */
export function registerProviderIntegrationFixtures(): void {
	registerAnthropicFixtures();
	registerMistralFixtures();
	registerBedrockFixtures();
	registerTogetherFixtures();
	registerOpenAIFixtures();
	registerAzureOpenAIFixtures();
	registerGoogleVertexFixtures();
	registerGitHubCopilotFixtures();
	registerOpenAIResponsesRegressionFixtures();
	registerOpenAICompletionsRegressionFixtures();

	const missingModels: readonly [provider: string, id: string, api: Api][] = [
		["google", "gemini-2.5-flash", "google-generative-ai"],
		["anthropic", "claude-opus-4-1-20250805", "anthropic-messages"],
		["mistral", "pixtral-12b", "mistral-conversations"],
		["amazon-bedrock", "global.anthropic.claude-sonnet-4-5-20250929-v1:0", "bedrock-converse-stream"],
		["azure-openai-responses", "gpt-4o-mini", "azure-openai-responses"],
		["github-copilot", "claude-haiku-4.5", "anthropic-messages"],
		["github-copilot", "gpt-5.3-codex", "openai-responses"],
		["openai-codex", "gpt-5.4", "openai-codex-responses"],
		["xai", "grok-3", "openai-completions"],
		["xai", "grok-3-fast", "openai-completions"],
		["xai", "grok-code-fast-1", "openai-completions"],
		["cerebras", "gpt-oss-120b", "openai-completions"],
		["cloudflare-workers-ai", "@cf/moonshotai/kimi-k2.6", "openai-completions"],
		["cloudflare-ai-gateway", "workers-ai/@cf/moonshotai/kimi-k2.6", "openai-completions"],
		["cloudflare-ai-gateway", "gpt-5.1", "openai-responses"],
		["cloudflare-ai-gateway", "claude-sonnet-4-5", "anthropic-messages"],
		["huggingface", "moonshotai/Kimi-K2.5", "openai-completions"],
		["kimi-coding", "k2p7", "anthropic-messages"],
		["minimax", "MiniMax-M2.7", "anthropic-messages"],
		["nvidia", "nvidia/nemotron-3-super-120b-a12b", "openai-completions"],
		["openrouter", "z-ai/glm-4.5v", "openai-completions"],
		["vercel-ai-gateway", "anthropic/claude-opus-4.5", "openai-completions"],
		["vercel-ai-gateway", "google/gemini-2.5-flash", "openai-completions"],
		["vercel-ai-gateway", "openai/gpt-5.1-codex-max", "openai-completions"],
		["deepseek", "deepseek-v4-flash", "openai-completions"],
	];
	registerModelFixtures(
		missingModels.map(([provider, id, api]) => ({
			provider,
			id,
			api,
			name: id,
			input: ["text", "image"] as ("text" | "image")[],
			reasoning: true,
		})),
	);
}

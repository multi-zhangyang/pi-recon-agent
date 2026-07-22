import { type ExternalModelCatalog, registerModelCatalog } from "../../ai/src/models.ts";

/**
 * Legacy `getModel()` callers in coding-agent tests need explicit metadata now
 * that production no longer ships a generated catalog. Keep this list narrow:
 * unknown provider/model pairs must remain absent in resolver tests.
 */
export const codingAgentTestModelCatalog = {
	anthropic: {
		"claude-sonnet-4-5": {
			id: "claude-sonnet-4-5",
			name: "Claude Sonnet 4.5 (latest)",
			api: "anthropic-messages",
			provider: "anthropic",
			baseUrl: "https://api.anthropic.com",
			reasoning: true,
			input: ["text", "image"],
			cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
			contextWindow: 200_000,
			maxTokens: 64_000,
		},
	},
	"openai-codex": {
		"gpt-5.5": {
			id: "gpt-5.5",
			name: "GPT-5.5",
			api: "openai-codex-responses",
			provider: "openai-codex",
			baseUrl: "https://chatgpt.com/backend-api",
			reasoning: true,
			thinkingLevelMap: { xhigh: "xhigh", minimal: "low" },
			input: ["text", "image"],
			cost: { input: 5, output: 30, cacheRead: 0.5, cacheWrite: 0 },
			contextWindow: 272_000,
			maxTokens: 128_000,
		},
	},
} satisfies ExternalModelCatalog;

registerModelCatalog(codingAgentTestModelCatalog, { replace: false });

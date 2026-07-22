import { describe, expect, it } from "vitest";
import { convertMessages } from "../src/providers/openai-completions.ts";
import type { AssistantMessage, Context, Model, OpenAICompletionsCompat } from "../src/types.ts";

// opt #213: an assistant turn that produced ONLY reasoning (a thinking block
// with non-empty thinking + a reasoning signature, no text, no tool_calls)
// used to be DROPPED by the convertMessages skip guard (content===null + no
// tool_calls → continue), silently losing the reasoning_content replay →
// degraded multi-turn reasoning for providers that rely on it (gpt-oss /
// DeepSeek / OpenRouter reasoning models). The fix tracks that a reasoning
// field was populated and preserves the turn.

const compat = {
	supportsStore: true,
	supportsDeveloperRole: true,
	supportsReasoningEffort: true,
	supportsUsageInStreaming: true,
	maxTokensField: "max_completion_tokens",
	requiresToolResultName: false,
	requiresAssistantAfterToolResult: false,
	requiresThinkingAsText: false,
	requiresReasoningContentOnAssistantMessages: false,
	thinkingFormat: "openai",
	openRouterRouting: {},
	vercelGatewayRouting: {},
	zaiToolStream: false,
	supportsStrictMode: true,
	cacheControlFormat: undefined,
	sendSessionAffinityHeaders: false,
	supportsLongCacheRetention: true,
} satisfies Omit<Required<OpenAICompletionsCompat>, "cacheControlFormat" | "deferredToolsMode"> & {
	cacheControlFormat?: OpenAICompletionsCompat["cacheControlFormat"];
	deferredToolsMode?: OpenAICompletionsCompat["deferredToolsMode"];
};

function buildModel(): Model<"openai-completions"> {
	return {
		id: "repro-reasoning",
		name: "Repro Reasoning",
		api: "openai-completions",
		provider: "repro-provider",
		baseUrl: "http://127.0.0.1:1",
		reasoning: true,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 128000,
		maxTokens: 4096,
		compat,
	};
}

function buildAssistant(content: AssistantMessage["content"]): AssistantMessage {
	return {
		role: "assistant",
		content,
		api: "openai-completions",
		provider: "repro-provider",
		model: "repro-reasoning",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
		timestamp: 2,
	};
}

function buildContext(assistant: AssistantMessage): Context {
	return {
		messages: [
			{ role: "user", content: "hello", timestamp: 1 },
			assistant,
			{ role: "user", content: "continue", timestamp: 3 },
		],
	};
}

describe("opt #213: reasoning-only assistant turn preserved on replay", () => {
	it("keeps a reasoning-only turn and replays reasoning_content", () => {
		// A turn with ONLY a thinking block (non-empty thinking, signature
		// "reasoning_content"), no text, no tool_calls. Pre-fix: dropped by the
		// skip guard → reasoning_content lost. Post-fix: the turn is preserved
		// and reasoning_content carries the thinking text.
		const messages = convertMessages(
			buildModel(),
			buildContext(
				buildAssistant([
					{ type: "thinking", thinking: "internal reasoning step", thinkingSignature: "reasoning_content" },
				]),
			),
			compat,
		);

		const assistant = messages.find((m) => m.role === "assistant");
		expect(assistant).toBeDefined();
		expect((assistant as { content?: unknown }).content).toBe(
			"[Assistant reasoning ended before a final response was produced.]",
		);
		expect((assistant as { reasoning_content?: string }).reasoning_content).toBe("internal reasoning step");
	});

	it("keeps generic reasoning-field replay valid when no final content exists", () => {
		const messages = convertMessages(
			buildModel(),
			buildContext(
				buildAssistant([{ type: "thinking", thinking: "internal reasoning step", thinkingSignature: "reasoning" }]),
			),
			compat,
		);

		const assistant = messages.find((m) => m.role === "assistant");
		expect(assistant).toMatchObject({
			role: "assistant",
			content: "[Assistant reasoning ended before a final response was produced.]",
			reasoning: "internal reasoning step",
		});
	});

	it("still drops a genuinely-empty assistant turn (no text, no reasoning, no tool_calls)", () => {
		// Regression guard: an aborted turn with no content at all is still
		// skipped (the skip guard's original purpose).
		const messages = convertMessages(buildModel(), buildContext(buildAssistant([])), compat);
		expect(messages.find((m) => m.role === "assistant")).toBeUndefined();
	});

	it("replays a turn with both reasoning and text unchanged", () => {
		// The reasoning field is populated AND the text content is present.
		const messages = convertMessages(
			buildModel(),
			buildContext(
				buildAssistant([
					{ type: "thinking", thinking: "reasoning here", thinkingSignature: "reasoning_content" },
					{ type: "text", text: "visible answer" },
				]),
			),
			compat,
		);
		const assistant = messages.find((m) => m.role === "assistant");
		expect(assistant).toBeDefined();
		expect((assistant as { reasoning_content?: string }).reasoning_content).toBe("reasoning here");
		expect((assistant as { content?: unknown }).content).toBe("visible answer");
	});
});

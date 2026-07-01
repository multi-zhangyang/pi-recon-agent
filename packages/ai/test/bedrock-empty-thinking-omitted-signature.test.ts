import { describe, expect, it, vi } from "vitest";

vi.mock("@aws-sdk/client-bedrock-runtime", () => {
	class BedrockRuntimeServiceException extends Error {}
	class BedrockRuntimeClient {
		send(): Promise<never> {
			return Promise.reject(new Error("mock send"));
		}
	}
	class ConverseStreamCommand {
		readonly input: unknown;
		constructor(input: unknown) {
			this.input = input;
		}
	}
	return {
		BedrockRuntimeClient,
		BedrockRuntimeServiceException,
		ConverseStreamCommand,
		StopReason: {
			END_TURN: "end_turn",
			STOP_SEQUENCE: "stop_sequence",
			MAX_TOKENS: "max_tokens",
			MODEL_CONTEXT_WINDOW_EXCEEDED: "model_context_window_exceeded",
			TOOL_USE: "tool_use",
		},
		CachePointType: { DEFAULT: "default" },
		CacheTTL: { ONE_HOUR: "ONE_HOUR" },
		ConversationRole: { ASSISTANT: "assistant", USER: "user" },
		ImageFormat: { JPEG: "jpeg", PNG: "png", GIF: "gif", WEBP: "webp" },
		ToolResultStatus: { ERROR: "error", SUCCESS: "success" },
	};
});

import { getModel } from "../src/models.ts";
import { convertMessages } from "../src/providers/amazon-bedrock.ts";
import type { AssistantMessage, Context, Message } from "../src/types.ts";

// opt #212 (bedrock twin): thinkingDisplay:"omitted" streams an EMPTY thinking
// string BUT a real signature. The replay path used to drop the whole block on
// `thinking.trim().length === 0`, discarding the signature → silent multi-turn
// reasoning degradation. The fix preserves the signature-bearing block for
// Anthropic-Claude models (which support reasoningText.signature).

const baseModel = getModel("amazon-bedrock", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")!;

function makeAssistant(thinking: string, thinkingSignature: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "thinking", thinking, thinkingSignature }],
		provider: "amazon-bedrock",
		api: "bedrock-converse-stream",
		model: baseModel.id,
		timestamp: 1,
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
	};
}

function buildContext(thinking: string, thinkingSignature: string): Context {
	const messages: Message[] = [
		{ role: "user", content: "first", timestamp: 0 },
		makeAssistant(thinking, thinkingSignature),
		{ role: "user", content: "second", timestamp: 2 },
	];
	return { messages };
}

// convertMessages returns AWS-SDK Message[] (a different type than REPI's
// Message); access via a structural shape to avoid the type collision.
function assistantBlocks(params: Array<{ role?: string; content?: unknown }>): unknown[] | undefined {
	const assistant = params.find((m) => m.role === "assistant");
	return assistant?.content as unknown[] | undefined;
}

describe("opt #212: empty-thinking + signature preserved on Bedrock replay", () => {
	it("preserves an empty-thinking block that carries a signature (Anthropic Claude model)", () => {
		const params = convertMessages(buildContext("", "opaque-sig-omitted"), baseModel, "none");
		const blocks = assistantBlocks(params);
		expect(blocks).toBeDefined();
		expect(blocks).toContainEqual({
			reasoningContent: { reasoningText: { text: "", signature: "opaque-sig-omitted" } },
		});
	});

	it("drops an empty-thinking block when there is no signature", () => {
		const params = convertMessages(buildContext("", ""), baseModel, "none");
		// No signature → nothing to replay → the assistant turn has no content and
		// is skipped entirely.
		expect(params.find((m) => m.role === "assistant")).toBeUndefined();
	});

	it("replays a non-empty thinking block with its signature unchanged", () => {
		const params = convertMessages(buildContext("internal reasoning", "opaque-sig"), baseModel, "none");
		const blocks = assistantBlocks(params);
		expect(blocks).toBeDefined();
		expect(blocks).toContainEqual({
			reasoningContent: { reasoningText: { text: "internal reasoning", signature: "opaque-sig" } },
		});
	});
});

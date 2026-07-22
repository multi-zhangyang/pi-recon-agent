/**
 * Foundational opt #260 — usage `input` subtraction must be floored at 0.
 *
 * Both google.ts and openai-responses-shared.ts compute non-cached `input` by
 * subtracting cached tokens from the total input tokens. A proxy/misreporting
 * endpoint can emit cached > input (double-counted cache), producing a NEGATIVE
 * input token count, negative input cost, and a totalTokens that no longer
 * matches the component sum. Sibling openai-completions.ts:1090 already guards
 * with Math.max(0, ...); these two sites did not. Fix: floor the subtraction.
 */
import type { ResponseStreamEvent } from "openai/resources/responses/responses.js";
import { describe, expect, it, vi } from "vitest";
import { processResponsesStream } from "../src/providers/openai-responses-shared.ts";
import type { AssistantMessage, Context, Model } from "../src/types.ts";
import { AssistantMessageEventStream } from "../src/utils/event-stream.ts";
import { registerGoogleVertexFixtures } from "./model-fixtures.ts";

registerGoogleVertexFixtures();

// ---------------------------------------------------------------------------
// openai-responses: processResponsesStream response.completed usage
// ---------------------------------------------------------------------------

function createOutput(model: Model<"openai-responses">): AssistantMessage {
	return {
		role: "assistant",
		content: [],
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

async function* completedWithCachedExceedingInput(): AsyncIterable<ResponseStreamEvent> {
	yield {
		type: "response.completed",
		response: {
			id: "resp_1",
			status: "completed",
			// cached_tokens (300) > input_tokens (100): pre-fix input = -200.
			usage: {
				input_tokens: 100,
				output_tokens: 3,
				total_tokens: 303,
				input_tokens_details: { cached_tokens: 300 },
			},
		},
	} as ResponseStreamEvent;
}

describe("openai-responses usage input floored at 0 (opt #260)", () => {
	it("does not go negative when cached_tokens exceeds input_tokens", async () => {
		const model: Model<"openai-responses"> = {
			id: "gpt-5-mini",
			name: "GPT-5 Mini",
			api: "openai-responses",
			provider: "openai",
			baseUrl: "https://api.openai.com/v1",
			reasoning: true,
			input: ["text"],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 400000,
			maxTokens: 128000,
		};
		const output = createOutput(model);
		const stream = new AssistantMessageEventStream();
		await processResponsesStream(completedWithCachedExceedingInput(), output, stream, model);

		expect(output.usage.input).toBe(0); // pre-fix: -200
		expect(output.usage.cacheRead).toBe(300);
	});
});

// ---------------------------------------------------------------------------
// google: streamGoogleVertex usageMetadata with cached > prompt
// ---------------------------------------------------------------------------

vi.mock("@google/genai", () => {
	const FinishReason = {
		STOP: "STOP",
		MAX_TOKENS: "MAX_TOKENS",
		SAFETY: "SAFETY",
		RECITATION: "RECITATION",
		OTHER: "OTHER",
		FINISH_REASON_UNSPECIFIED: "FINISH_REASON_UNSPECIFIED",
	} as const;
	class GoogleGenAI {
		models = {
			generateContentStream: async function* () {
				yield {
					responseId: "resp-g",
					candidates: [{ content: { parts: [{ text: "ok" }] }, finishReason: FinishReason.STOP }],
					// cachedContentTokenCount (1200) > promptTokenCount (1000):
					// pre-fix input = -200.
					usageMetadata: {
						promptTokenCount: 1000,
						candidatesTokenCount: 5,
						cachedContentTokenCount: 1200,
						totalTokenCount: 1205,
					},
				};
			},
		};
	}
	return {
		GoogleGenAI,
		ResourceScope: { COLLECTION: "COLLECTION" },
		ThinkingLevel: {
			THINKING_LEVEL_UNSPECIFIED: "THINKING_LEVEL_UNSPECIFIED",
			MINIMAL: "MINIMAL",
			LOW: "LOW",
			MEDIUM: "MEDIUM",
			HIGH: "HIGH",
		},
		FinishReason,
	};
});

import { getModel } from "../src/models.ts";
import { streamGoogleVertex } from "../src/providers/google-vertex.ts";

describe("google usage input floored at 0 (opt #260)", () => {
	it("does not go negative when cachedContentTokenCount exceeds promptTokenCount", async () => {
		const model = getModel("google-vertex", "gemini-3-flash-preview");
		const context: Context = {
			messages: [{ role: "user", content: "hello", timestamp: Date.now() }],
		};
		const stream = streamGoogleVertex(model, context, {
			project: "test-project",
			location: "us-central1",
		});
		const result = await stream.result();

		expect(result.stopReason).toBe("stop");
		expect(result.errorMessage).toBeUndefined();
		expect(result.usage.input).toBe(0); // pre-fix: -200
		expect(result.usage.cacheRead).toBe(1200);
	});
});

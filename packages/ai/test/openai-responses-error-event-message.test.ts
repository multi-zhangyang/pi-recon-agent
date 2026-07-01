import type { ResponseStreamEvent } from "openai/resources/responses/responses.js";
import { describe, expect, it } from "vitest";
import { processResponsesStream } from "../src/providers/openai-responses-shared.ts";
import type { AssistantMessage, Model } from "../src/types.ts";
import { AssistantMessageEventStream } from "../src/utils/event-stream.ts";

// opt #274: the Responses API `event.type === "error"` handler threw
// `new Error(`Error Code ${event.code}: ${event.message}` || "Unknown error")`.
// The template literal is always a truthy string, so `|| "Unknown error"` was
// DEAD — a provider/proxy that emits an error event with undefined code/message
// rendered as the garbled "Error Code undefined: undefined" instead of the
// intended "Unknown error". The fix mirrors the sibling response.failed
// handler: only format `Error Code <code>: <msg>` when at least one field is
// present, else "Unknown error".

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

async function* errorEventStream(code: unknown, message: unknown): AsyncIterable<ResponseStreamEvent> {
	yield { type: "error", code, message } as ResponseStreamEvent;
}

describe("openai-responses error event message fidelity (opt #274)", () => {
	it("throws 'Unknown error' when code and message are both undefined (not 'Error Code undefined: undefined')", async () => {
		const output = createOutput(model);
		const stream = new AssistantMessageEventStream();
		// Pre-fix: threw "Error Code undefined: undefined" (the `|| "Unknown error"`
		// fallback was dead because the template literal is always truthy).
		await expect(
			processResponsesStream(errorEventStream(undefined, undefined), output, stream, model),
		).rejects.toThrow("Unknown error");
	});

	it("formats 'Error Code <code>: <message>' when both fields are present", async () => {
		const output = createOutput(model);
		const stream = new AssistantMessageEventStream();
		await expect(
			processResponsesStream(errorEventStream("rate_limit_exceeded", "slow down"), output, stream, model),
		).rejects.toThrow("Error Code rate_limit_exceeded: slow down");
	});

	it("formats the template when only code is present", async () => {
		const output = createOutput(model);
		const stream = new AssistantMessageEventStream();
		await expect(
			processResponsesStream(errorEventStream("server_error", undefined), output, stream, model),
		).rejects.toThrow("Error Code server_error: undefined");
	});
});

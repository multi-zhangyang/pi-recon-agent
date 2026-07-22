import type { ResponseStreamEvent } from "openai/resources/responses/responses.js";
import { describe, expect, it, vi } from "vitest";
import { streamOpenAIResponses } from "../src/providers/openai-responses.ts";
import { processResponsesStream } from "../src/providers/openai-responses-shared.ts";
import type { AssistantMessage, AssistantMessageEvent, Context, Model } from "../src/types.ts";
import { AssistantMessageEventStream } from "../src/utils/event-stream.ts";

vi.mock("openai", () => {
	async function* createEarlyEofStream(): AsyncIterable<ResponseStreamEvent> {
		yield {
			type: "response.created",
			response: { id: "resp_wrapper_early_eof" },
			sequence_number: 0,
		} as ResponseStreamEvent;
		yield {
			type: "response.output_item.added",
			item: { type: "reasoning", id: "rs_wrapper_early_eof", summary: [] },
			output_index: 0,
			sequence_number: 1,
		} as ResponseStreamEvent;
		yield {
			type: "response.reasoning_text.delta",
			delta: "partial reasoning before EOF",
			item_id: "rs_wrapper_early_eof",
			output_index: 0,
			content_index: 0,
			sequence_number: 2,
		} as ResponseStreamEvent;
	}

	class FakeOpenAI {
		responses = {
			create: () => {
				const responseStream = createEarlyEofStream();
				const request = Promise.resolve(responseStream) as Promise<AsyncIterable<ResponseStreamEvent>> & {
					withResponse(): Promise<{
						data: AsyncIterable<ResponseStreamEvent>;
						response: { status: number; headers: Headers; body: null };
					}>;
				};
				request.withResponse = async () => ({
					data: responseStream,
					response: { status: 200, headers: new Headers(), body: null },
				});
				return request;
			},
		};
	}

	return { default: FakeOpenAI };
});

function createModel(): Model<"openai-responses"> {
	return {
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
}

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

async function* earlyEofEvents(): AsyncIterable<ResponseStreamEvent> {
	yield { type: "response.created", response: { id: "resp_early_eof" } } as ResponseStreamEvent;
}

async function* terminalEvent(type: "response.completed" | "response.incomplete"): AsyncIterable<ResponseStreamEvent> {
	yield {
		type,
		response: {
			id: type === "response.completed" ? "resp_completed" : "resp_incomplete",
			status: type === "response.completed" ? "completed" : "incomplete",
			usage: {
				input_tokens: 20,
				output_tokens: 7,
				total_tokens: 27,
				input_tokens_details: { cached_tokens: 2 },
			},
		},
	} as ResponseStreamEvent;
}

describe("OpenAI Responses terminal event handling", () => {
	it("rejects streams that end before a terminal response event", async () => {
		const model = createModel();
		await expect(
			processResponsesStream(earlyEofEvents(), createOutput(model), new AssistantMessageEventStream(), model),
		).rejects.toThrow("OpenAI Responses stream ended before a terminal response event");
	});

	it.each([
		["response.completed" as const, "stop", "resp_completed"],
		["response.incomplete" as const, "length", "resp_incomplete"],
	])("finalizes %s as %s", async (type, expectedStopReason, expectedId) => {
		const model = createModel();
		const output = createOutput(model);
		await processResponsesStream(terminalEvent(type), output, new AssistantMessageEventStream(), model);
		expect(output.responseId).toBe(expectedId);
		expect(output.stopReason).toBe(expectedStopReason);
		expect(output.usage).toMatchObject({ input: 18, output: 7, cacheRead: 2, totalTokens: 27 });
	});

	it("surfaces early EOF as the wrapper stream's terminal error result", async () => {
		const model = createModel();
		const context: Context = {
			systemPrompt: "",
			messages: [{ role: "user", content: [{ type: "text", text: "hi" }], timestamp: 0 }],
			tools: [],
		};
		const stream = streamOpenAIResponses(model, context, { apiKey: "test" });
		const events: AssistantMessageEvent[] = [];
		for await (const event of stream) events.push(event);

		const result = await stream.result();
		expect(events.at(-1)?.type).toBe("error");
		expect(result.stopReason).toBe("error");
		expect(result.errorMessage).toBe("OpenAI Responses stream ended before a terminal response event");
	});
});

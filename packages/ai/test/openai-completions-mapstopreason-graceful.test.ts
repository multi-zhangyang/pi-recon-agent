import { describe, expect, it, vi } from "vitest";
import type { Context, Model } from "../src/types.ts";

// opt #187 — openai-completions mapStopReason's `default` branch returned
// `{ stopReason: "error", errorMessage: "Provider finish_reason: <reason>" }`,
// and the streaming loop threw `if (!hasFinishReason)`. For an OpenAI-compatible
// provider (OpenRouter/vLLM/local gateways — REPI's default kimchi/kimi runs this
// path via the GLM proxy) that emits a finish_reason outside the known set (e.g.
// "insufficient_information", "sensitive", "model_length"), the successfully-
// streamed content was reclassified as a failure (error event instead of done);
// if no content, the retry layer re-sent up to maxRetries wasting tokens then
// false-errored. This diverged from the round-8 graceful fixes (anthropic #179,
// mistral #178, openai-responses #180). Fix: default to "stop" for unknown
// non-error finish_reasons; only KNOWN error sentinels (content_filter/
// network_error) map to "error"; a missing finish_reason defaults to "stop"
// instead of throwing. Mirrors openai-responses-shared.ts:552-572.

const mockState = vi.hoisted(() => ({
	finishReason: "stop" as string | null,
	content: "ok" as string | null,
}));

vi.mock("openai", () => {
	class FakeOpenAI {
		chat = {
			completions: {
				create: () => {
					const stream = {
						async *[Symbol.asyncIterator]() {
							if (mockState.content !== null) {
								yield {
									id: "chatcmpl-test",
									choices: [{ index: 0, delta: { content: mockState.content } }],
								};
							}
							yield {
								id: "chatcmpl-test",
								choices: [{ index: 0, delta: {}, finish_reason: mockState.finishReason }],
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

const model: Model<"openai-completions"> = {
	id: "test-model",
	name: "Test Model",
	api: "openai-completions",
	provider: "opencode-go",
	baseUrl: "https://opencode.ai/zen/go/v1",
	reasoning: false,
	input: ["text"],
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
	contextWindow: 1000,
	maxTokens: 100,
};

const context: Context = {
	systemPrompt: "",
	messages: [{ role: "user", content: [{ type: "text", text: "hi" }], timestamp: 0 }],
	tools: [],
};

async function consume() {
	const { streamOpenAICompletions } = await import("../src/providers/openai-completions.ts");
	const stream = streamOpenAICompletions(model, context, { apiKey: "test" });
	const events: { type: string; reason?: string; message?: { content: unknown[] } }[] = [];
	for await (const event of stream) {
		events.push(event as { type: string; reason?: string; message?: { content: unknown[] } });
	}
	const result = await stream.result();
	return { events, result };
}

describe("openai-completions mapStopReason graceful unknown default (opt #187)", () => {
	it("mapStopReason returns 'stop' for an unknown finish_reason (no error)", async () => {
		const { mapStopReason } = await import("../src/providers/openai-completions.ts");
		expect(mapStopReason("insufficient_information")).toEqual({ stopReason: "stop" });
		expect(mapStopReason("sensitive")).toEqual({ stopReason: "stop" });
		expect(mapStopReason("model_length")).toEqual({ stopReason: "stop" });
	});

	it("mapStopReason still maps known finish_reasons correctly (no regression)", async () => {
		const { mapStopReason } = await import("../src/providers/openai-completions.ts");
		expect(mapStopReason(null)).toEqual({ stopReason: "stop" });
		expect(mapStopReason("stop")).toEqual({ stopReason: "stop" });
		expect(mapStopReason("end")).toEqual({ stopReason: "stop" });
		expect(mapStopReason("length")).toEqual({ stopReason: "length" });
		expect(mapStopReason("function_call")).toEqual({ stopReason: "toolUse" });
		expect(mapStopReason("tool_calls")).toEqual({ stopReason: "toolUse" });
		// Known error sentinels MUST remain "error".
		expect(mapStopReason("content_filter")).toEqual({
			stopReason: "error",
			errorMessage: "Provider finish_reason: content_filter",
		});
		expect(mapStopReason("network_error")).toEqual({
			stopReason: "error",
			errorMessage: "Provider finish_reason: network_error",
		});
	});

	it("streams an unknown finish_reason as a done event with stopReason 'stop' and preserves content", async () => {
		mockState.content = "partial answer";
		mockState.finishReason = "insufficient_information";
		const { events, result } = await consume();

		const done = events.find((e) => e.type === "done");
		expect(done).toBeDefined();
		expect(done?.reason).toBe("stop");
		expect(result.stopReason).toBe("stop");
		// No error event emitted (pre-fix this was an error event + stopReason "error").
		expect(events.some((e) => e.type === "error")).toBe(false);
		// Content preserved on the final message.
		const text = (done?.message?.content ?? [])
			.filter((b): b is { type: string; text: string } => (b as { type?: string }).type === "text")
			.map((b) => b.text)
			.join("");
		expect(text).toContain("partial answer");
	});

	it("defaults to stop when the stream ends with no finish_reason (no throw, no error event)", async () => {
		mockState.content = "orphan answer";
		mockState.finishReason = null; // no finish_reason chunk emitted
		// Override the fake iterator to omit finish_reason entirely.
		const { streamOpenAICompletions } = await import("../src/providers/openai-completions.ts");
		const stream = streamOpenAICompletions(model, context, { apiKey: "test" });
		const events: { type: string; reason?: string; message?: { content: unknown[] } }[] = [];
		for await (const event of stream) {
			events.push(event as { type: string; reason?: string; message?: { content: unknown[] } });
		}
		const result = await stream.result();

		const done = events.find((e) => e.type === "done");
		expect(done).toBeDefined();
		expect(done?.reason).toBe("stop");
		expect(result.stopReason).toBe("stop");
		expect(events.some((e) => e.type === "error")).toBe(false);
	});
});

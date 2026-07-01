/**
 * opt #254 — proxy SSE trailing buffer flush (LOW-MED data-loss).
 *
 * streamProxy split the SSE buffer on "\n" and kept the trailing partial via
 * `lines.pop()`. When the body ended, that trailing buffer was NEVER flushed —
 * so a terminal done/error event sent WITHOUT a trailing newline (legal SSE;
 * the spec only requires a blank-line event terminator, and some upstream
 * proxies omit the final "\n") sat in `buffer` and was dropped. `terminated`
 * stayed false → a spurious "Proxy stream ended without a done event" error was
 * synthesized, discarding the real terminal event + its stopReason/usage.
 *
 * Fix: after the read loop, flush the decoder's trailing bytes and process the
 * remaining line(s) via the same per-line handler.
 */
import type { AssistantMessage, Model } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { streamProxy } from "../src/proxy.ts";

function createModel(): Model<"openai-responses"> {
	return {
		id: "mock",
		name: "mock",
		api: "openai-responses",
		provider: "openai",
		baseUrl: "https://example.invalid",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 8192,
		maxTokens: 2048,
	};
}

const originalFetch = globalThis.fetch;

afterEach(() => {
	globalThis.fetch = originalFetch;
});

function sseLine(payload: string): Uint8Array {
	return new TextEncoder().encode(`data: ${payload}\n`);
}

describe("streamProxy trailing SSE buffer flush (opt #254)", () => {
	it("processes a terminal done event sent without a trailing newline", async () => {
		// The final done event is enqueued with NO trailing "\n" — it sits in the
		// trailing buffer. Pre-fix it was dropped and a spurious "ended without a
		// done event" error was synthesized instead.
		const finalDoneNoNewline = new TextEncoder().encode(`data: ${JSON.stringify({ type: "done", reason: "stop" })}`);
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(sseLine(JSON.stringify({ type: "start" })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_start", contentIndex: 0 })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_delta", contentIndex: 0, delta: "final text" })));
				controller.enqueue(finalDoneNoNewline);
				controller.close();
			},
		});

		globalThis.fetch = (() =>
			Promise.resolve({
				ok: true,
				status: 200,
				statusText: "OK",
				body,
			})) as unknown as typeof globalThis.fetch;

		const stream = streamProxy(
			createModel(),
			{ systemPrompt: "", messages: [], tools: [] },
			{ authToken: "tok", proxyUrl: "https://proxy.invalid" },
		);

		const events: AssistantMessage[] = [];
		for await (const event of stream) {
			if (event.type === "done" || event.type === "error") {
				events.push(event.type === "done" ? event.message : event.error);
			}
		}

		const result = await Promise.race([
			stream.result(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("stream.result() hung")), 2000)),
		]);

		// The real done event from the trailing buffer was processed: stopReason
		// is "stop" (the done reason), NOT the synthesized "error"/"Proxy stream
		// ended without a done event".
		expect(result.stopReason).toBe("stop");
		expect(result.errorMessage).toBeUndefined();
		// Exactly one terminal event, and it was the done (not a synthesized error).
		expect(events).toHaveLength(1);
		expect(events[0].stopReason).toBe("stop");
		// The partial text streamed before the terminal event is preserved.
		const textBlock = result.content[0];
		expect(textBlock).toBeDefined();
		if (textBlock && textBlock.type === "text") {
			expect(textBlock.text).toBe("final text");
		}
	}, 10000);
});

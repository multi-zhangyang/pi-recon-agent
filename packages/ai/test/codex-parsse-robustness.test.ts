import { describe, expect, it } from "vitest";
import { parseSSE } from "../src/providers/openai-codex-responses.ts";

// opt #186 — codex `parseSSE` robustness.
// (A) One malformed `data:` frame (proxy HTML injection, bare-string error
// frame, truncated chunk) used to throw CodexProtocolError →
// isCodexNonTransportError → no SSE retry → the WHOLE turn died, discarding
// everything already streamed. Sibling providers use parseJsonWithRepair and
// SKIP unrecoverable frames. parseSSE now does the same.
// (B) parseSSE broke on `done` with no final `decoder.decode()` flush and no
// trailing-buffer drain (anthropic.ts:411-432 does BOTH). A final
// `response.completed` frame whose trailing `\n\n` never arrives (truncated
// connection) was dropped → zero usage/cost, a tool-use turn mislabeled as
// `stop`. parseSSE now does a final flush + trailing-buffer drain.

function encode(text: string): Uint8Array {
	return new TextEncoder().encode(text);
}

function sseResponse(chunks: string[]): Response {
	const body = new ReadableStream<Uint8Array>({
		start(controller) {
			for (const chunk of chunks) controller.enqueue(encode(chunk));
			controller.close();
		},
	});
	return new Response(body, {
		status: 200,
		headers: { "content-type": "text/event-stream" },
	});
}

function completedFrame(usage: { input_tokens: number; output_tokens: number }): string {
	return `data: ${JSON.stringify({
		type: "response.completed",
		response: { status: "completed", usage },
	})}`;
}

describe("codex parseSSE robustness (opt #186)", () => {
	it("(A) skips a malformed data frame and keeps parsing subsequent valid frames", async () => {
		const frames = [
			`data: ${JSON.stringify({ type: "response.output_text.delta", delta: "Hello" })}`,
			"data: <html>proxy error</html>",
			completedFrame({ input_tokens: 5, output_tokens: 3 }),
		];
		const response = sseResponse([`${frames.join("\n\n")}\n\n`]);

		const events: Record<string, unknown>[] = [];
		for await (const ev of parseSSE(response)) {
			events.push(ev);
		}

		expect(events.map((e) => e.type)).toEqual(["response.output_text.delta", "response.completed"]);
		const completed = events.find((e) => e.type === "response.completed") as {
			response: { usage: { input_tokens: number; output_tokens: number } };
		};
		expect(completed.response.usage.input_tokens).toBe(5);
		expect(completed.response.usage.output_tokens).toBe(3);
	});

	it("(B) parses a final frame with no trailing separator (truncated connection)", async () => {
		// First frame has its trailing `\n\n`; the final `response.completed`
		// frame has NO trailing separator and the stream closes — mirroring a
		// truncated connection. Without the final flush + trailing-buffer drain
		// the completed frame (and its usage) would be dropped.
		const first = `data: ${JSON.stringify({ type: "response.output_text.delta", delta: "Hi" })}\n\n`;
		const finalFrame = completedFrame({ input_tokens: 7, output_tokens: 4 });
		const response = sseResponse([`${first}${finalFrame}`]);

		const events: Record<string, unknown>[] = [];
		for await (const ev of parseSSE(response)) {
			events.push(ev);
		}

		expect(events.map((e) => e.type)).toEqual(["response.output_text.delta", "response.completed"]);
		const completed = events.find((e) => e.type === "response.completed") as {
			response: { usage: { input_tokens: number; output_tokens: number } };
		};
		expect(completed.response.usage.input_tokens).toBe(7);
		expect(completed.response.usage.output_tokens).toBe(4);
	});
});

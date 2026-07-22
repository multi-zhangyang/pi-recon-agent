import type Anthropic from "@anthropic-ai/sdk";
import { describe, expect, it } from "vitest";
import { getModel } from "../src/models.ts";
import { streamAnthropic } from "../src/providers/anthropic.ts";
import type { Context } from "../src/types.ts";
import { registerAnthropicFixtures } from "./model-fixtures.ts";

registerAnthropicFixtures();

// opt #117 — iterateSseMessages (anthropic.ts) read the response body via a
// reader whose `finally` only called reader.releaseLock(). On a mid-stream
// throw — a server-side `error` SSE event, an unparseable event, or an abort
// — the body was partially consumed and NEVER cancelled. undici does NOT
// release the keep-alive socket until the body is consumed OR cancelled, and
// releaseLock() alone doesn't cancel → the socket was stranded against the
// per-host connection cap until GC (same class as opt #49). Fix: await
// reader.cancel().catch(() => {}) in the finally before releaseLock().
//
// This test builds a ReadableStream whose underlying source records cancel(),
// sends a server-side `error` event mid-stream (so iterateAnthropicEvents
// throws at the `if (sse.event === "error")` guard), and leaves the stream
// OPEN (more data would follow in a real partial-error stream) so cancel is
// observable. Pre-fix cancel stays false; post-fix it is called.

function encode(text: string): Uint8Array {
	return new TextEncoder().encode(text);
}

function sseChunk(event: string, data: string): Uint8Array {
	return encode(`event: ${event}\ndata: ${data}\n\n`);
}

function createFakeAnthropicClient(response: Response): Anthropic {
	return {
		messages: {
			create: () => ({
				asResponse: async () => response,
			}),
		},
	} as unknown as Anthropic;
}

describe("streamAnthropic cancels the SSE body on a mid-stream error event (opt #117)", () => {
	it("cancels the response body when a server-side error event arrives mid-stream", async () => {
		let cancelCalled = false;
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(
					sseChunk(
						"message_start",
						JSON.stringify({
							type: "message_start",
							message: {
								id: "msg_test",
								usage: {
									input_tokens: 12,
									output_tokens: 0,
									cache_read_input_tokens: 0,
									cache_creation_input_tokens: 0,
								},
							},
						}),
					),
				);
				// Server-side error event mid-stream. iterateAnthropicEvents throws
				// at `if (sse.event === "error") throw new Error(sse.data)` BEFORE the
				// body is done → iterateSseMessages finally must cancel.
				controller.enqueue(sseChunk("error", "upstream exploded"));
				// Intentionally do NOT close — the stream is partially read. A real
				// partial-error stream would have more chunks pending; leaving it open
				// makes cancel() observable (a closed stream may not invoke source.cancel).
			},
			cancel() {
				cancelCalled = true;
			},
		});

		const response = new Response(body, {
			status: 200,
			headers: { "content-type": "text/event-stream" },
		});

		const model = getModel<"anthropic-messages">("anthropic", "claude-haiku-4-5")!;
		const context: Context = {
			messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
		};

		const stream = streamAnthropic(model, context, {
			client: createFakeAnthropicClient(response),
		});
		const result = await stream.result();

		// The error event surfaces as an error stop reason (the IIFE catch maps it).
		expect(result.stopReason).toBe("error");
		// The KEY invariant: the body was cancelled so undici releases the socket.
		// Pre-fix the finally only released the lock → cancelCalled stays false.
		expect(cancelCalled).toBe(true);
	});
});

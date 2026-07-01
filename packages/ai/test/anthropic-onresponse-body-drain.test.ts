import type Anthropic from "@anthropic-ai/sdk";
import { describe, expect, it } from "vitest";
import { getModel } from "../src/models.ts";
import { streamAnthropic } from "../src/providers/anthropic.ts";
import type { Context } from "../src/types.ts";

// opt #122 — every streaming provider awaits `options?.onResponse?.(...)` BEFORE
// iterating/cancelling the response body. A throwing onResponse (e.g. a throwing
// `after_provider_response` extension handler) skipped the iteration entirely →
// the body's `finally` cancel (opt #117) never ran → undici did not release the
// keep-alive socket (stranded against the per-host cap until GC; one leak per
// request if the handler throws consistently). Fix: callOnResponseWithDrain
// wraps the call and cancels the body on throw before rethrowing.
//
// This test feeds a fake client whose Response body records cancel(), makes
// onResponse throw, and asserts the body is cancelled (and the error surfaces).

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

describe("streamAnthropic cancels the body when onResponse throws (opt #122)", () => {
	it("cancels the response body so the keep-alive socket is released", async () => {
		let cancelCalled = false;
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				// A valid message_start is enqueued but never read (onResponse
				// throws before iteration begins). Leave the stream open so
				// cancel() is observable.
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
			},
			cancel() {
				cancelCalled = true;
			},
		});

		const response = new Response(body, {
			status: 200,
			headers: { "content-type": "text/event-stream" },
		});

		const model = getModel("anthropic", "claude-haiku-4-5");
		const context: Context = {
			messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
		};

		const stream = streamAnthropic(model, context, {
			client: createFakeAnthropicClient(response),
			onResponse: async () => {
				throw new Error("onResponse boom");
			},
		});
		const result = await stream.result();

		// The onResponse throw surfaces as an error stop reason (the IIFE catch).
		expect(result.stopReason).toBe("error");
		// The KEY invariant: the body was cancelled so undici releases the socket.
		// Pre-fix onResponse threw before iteration → body never cancelled.
		expect(cancelCalled).toBe(true);
	});
});

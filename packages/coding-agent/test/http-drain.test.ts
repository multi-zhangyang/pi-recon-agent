import { describe, expect, it } from "vitest";
import { drainResponseBody } from "../src/utils/http-drain.ts";

// A fetch Response (undici/WHATWG) does not release its keep-alive socket until
// the body is consumed or cancelled. drainResponseBody must call
// response.body.cancel() so an unread body does not hold the socket until GC.

function makeResponse(body: ReadableStream<Uint8Array> | null): Response {
	return { body } as unknown as Response;
}

describe("drainResponseBody", () => {
	it("cancels a readable body so the socket is released", async () => {
		let cancelled = false;
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode("unread body"));
				// Do NOT close — emulate a response whose body was never read to end.
			},
			cancel() {
				cancelled = true;
			},
		});
		await drainResponseBody(makeResponse(body));
		expect(cancelled).toBe(true);
	});

	it("is a no-op when the response has no body (null)", async () => {
		// Must not throw — a 204/HEAD response has body === null.
		await expect(drainResponseBody(makeResponse(null))).resolves.toBeUndefined();
	});

	it("swallows a cancel rejection so the caller's result is not masked", async () => {
		// A locked/errored stream's cancel() may reject; drain must not propagate.
		const body = new ReadableStream<Uint8Array>({
			start() {
				// intentionally leave the stream unlocked-but-errored below
			},
			cancel() {
				return Promise.reject(new Error("cancel refused"));
			},
		});
		await expect(drainResponseBody(makeResponse(body))).resolves.toBeUndefined();
	});
});

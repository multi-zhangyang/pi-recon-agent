import { describe, expect, it, vi } from "vitest";

// opt #185 — both codex `parseSSE` (openai-codex-responses.ts) and anthropic
// `iterateSseMessages` do `buffer += decoder.decode(...)` and slice on the SSE
// frame separator (`\n\n` / `\n`) with NO length check. A misbehaving proxy/gateway/
// CDN that strips the separator (Cloudflare AI Gateway + custom baseUrls in the
// user's env) → buffer grows unbounded → OOM mid-stream. The idle timeout bounds
// wall-clock, not bytes. Fix: REPI_SSE_BUFFER_MAX_BYTES cap (default 16MB, 0
// disables). On overflow, throw a framing error so agent-loop retry engages; the
// existing finally block cancels/drains the reader (drainResponseBody doctrine).
// The cap resolver is a module-level IIFE, so the env must be stubbed BEFORE the
// dynamic import (resetModules clears the cached evaluation).

function encode(text: string): Uint8Array {
	return new TextEncoder().encode(text);
}

describe("SSE buffer cap (opt #185)", () => {
	it("codex parseSSE throws a framing error and cancels the reader when the buffer exceeds the cap", async () => {
		vi.resetModules();
		vi.stubEnv("REPI_SSE_BUFFER_MAX_BYTES", String(1024 * 1024)); // 1 MB
		const { parseSSE } = await import("../src/providers/openai-codex-responses.ts");

		let cancelCalled = false;
		// 2 MB blob with NO `\n\n` frame separator — over the 1 MB cap, would OOM.
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(encode("x".repeat(2 * 1024 * 1024)));
				// Intentionally do NOT close — leaves cancel() observable.
			},
			cancel() {
				cancelCalled = true;
			},
		});
		const response = new Response(body, {
			status: 200,
			headers: { "content-type": "text/event-stream" },
		});

		await expect(async () => {
			for await (const _ of parseSSE(response)) {
				void _;
			}
		}).rejects.toThrow(/framing error/i);

		// The finally block cancels/drains the reader so undici releases the socket.
		expect(cancelCalled).toBe(true);
		vi.unstubAllEnvs();
	});

	it("anthropic iterateSseMessages throws a framing error and cancels the reader when the buffer exceeds the cap", async () => {
		vi.resetModules();
		vi.stubEnv("REPI_SSE_BUFFER_MAX_BYTES", String(1024 * 1024)); // 1 MB
		const { iterateSseMessages } = await import("../src/providers/anthropic.ts");

		let cancelCalled = false;
		// 2 MB blob with NO `\n`/`\r\n` line separator — over the 1 MB cap.
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(encode("x".repeat(2 * 1024 * 1024)));
			},
			cancel() {
				cancelCalled = true;
			},
		});

		await expect(async () => {
			for await (const _ of iterateSseMessages(body)) {
				void _;
			}
		}).rejects.toThrow(/framing error/i);

		expect(cancelCalled).toBe(true);
		vi.unstubAllEnvs();
	});

	it("0 disables the cap (legacy unbounded, no framing error)", async () => {
		vi.resetModules();
		vi.stubEnv("REPI_SSE_BUFFER_MAX_BYTES", "0");
		const { SSE_BUFFER_MAX_BYTES, parseSSE } = await import("../src/providers/openai-codex-responses.ts");
		expect(SSE_BUFFER_MAX_BYTES).toBe(Number.POSITIVE_INFINITY);

		// 32 KB blob with no separator — under the disabled cap it stays buffered
		// until the stream closes (no throw).
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(encode("x".repeat(32 * 1024)));
				controller.close();
			},
		});
		const response = new Response(body, {
			status: 200,
			headers: { "content-type": "text/event-stream" },
		});

		const events: unknown[] = [];
		for await (const ev of parseSSE(response)) {
			events.push(ev);
		}
		// No framing error thrown; stream completed normally (no SSE events parsed).
		expect(events).toHaveLength(0);
		vi.unstubAllEnvs();
	});
});

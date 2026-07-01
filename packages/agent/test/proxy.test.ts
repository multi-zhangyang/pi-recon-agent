import type { AssistantMessage, Model } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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

beforeEach(() => {
	// Ensure a clean fetch mock between tests; restored in afterEach.
});

afterEach(() => {
	globalThis.fetch = originalFetch;
});

/** Encode an SSE `data:` line (newline-terminated). */
function sseLine(payload: string): Uint8Array {
	return new TextEncoder().encode(`data: ${payload}\n`);
}

describe("streamProxy terminal-event synthesis (FIX 1a)", () => {
	it("synthesizes an error event when the SSE body ends without a done event", async () => {
		// Server streams start + text deltas, then closes the body WITHOUT ever
		// sending a done/error terminal event. Without the fix, stream.end() is
		// called with no result → finalResultPromise never resolves → a consumer
		// awaiting stream.result() hangs forever.
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(sseLine(JSON.stringify({ type: "start" })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_start", contentIndex: 0 })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_delta", contentIndex: 0, delta: "partial text" })));
				controller.close(); // no done event
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
			{
				authToken: "tok",
				proxyUrl: "https://proxy.invalid",
			},
		);

		// Consume events (must terminate, not hang).
		const events: AssistantMessage[] = [];
		for await (const event of stream) {
			if (event.type === "done" || event.type === "error") {
				events.push(event.type === "done" ? event.message : event.error);
			}
		}

		// result() must resolve within the timeout (would hang without the fix).
		const result = await Promise.race([
			stream.result(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("stream.result() hung")), 2000)),
		]);

		// A terminal error event was synthesized.
		expect(result.stopReason).toBe("error");
		expect(result.errorMessage).toBe("Proxy stream ended without a done event");
		// The partial text streamed before the body closed is preserved on the
		// synthesized error message (and would be committed by the agent-loop).
		const textBlock = result.content[0];
		expect(textBlock).toBeDefined();
		if (textBlock && textBlock.type === "text") {
			expect(textBlock.text).toBe("partial text");
		}
		expect(events.length).toBe(1);
		expect(events[0].stopReason).toBe("error");
	});
});

describe("streamProxy reader release on mid-stream throw (FIX 2)", () => {
	it("cancels the response body reader when processProxyEvent throws", async () => {
		// A structural SSE error (text_delta for a content index that was never text_start'd)
		// makes processProxyEvent throw "Received text_delta for non-text content" mid-stream.
		// The throw path used to skip reader.cancel() (only the abort path cancelled), leaving
		// the ReadableStreamDefaultReader holding the response body → undici kept the keep-alive
		// socket until GC. The finally must cancel the reader. (opt #55 changed malformed-JSON
		// lines to be SKIPPED instead of thrown, so this test now uses a genuine processProxyEvent
		// structural throw — the reader-cancel-on-throw guard still applies to that path.)
		let cancelCalled = false;
		const chunks: Uint8Array[] = [sseLine(JSON.stringify({ type: "text_delta", contentIndex: 0, delta: "x" }))];
		let chunkIndex = 0;
		const fakeReader = {
			read: async (): Promise<{ done: boolean; value: Uint8Array | undefined }> => {
				if (chunkIndex < chunks.length) {
					return { done: false, value: chunks[chunkIndex++] };
				}
				return { done: true, value: undefined };
			},
			cancel: async (): Promise<void> => {
				cancelCalled = true;
			},
			releaseLock: (): void => {},
		};
		const fakeBody = { getReader: () => fakeReader };
		const fakeResponse = { ok: true, status: 200, statusText: "OK", body: fakeBody };

		globalThis.fetch = (() => Promise.resolve(fakeResponse)) as unknown as typeof globalThis.fetch;

		const stream = streamProxy(
			createModel(),
			{ systemPrompt: "", messages: [], tools: [] },
			{
				authToken: "tok",
				proxyUrl: "https://proxy.invalid",
			},
		);

		// The structural error triggers processProxyEvent → catch pushes an error event.
		// Await result() (resolves via the error event), then flush the macrotask queue so
		// the finally's `await reader.cancel()` completes before we assert.
		const result = await Promise.race([
			stream.result(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("stream.result() hung")), 2000)),
		]);
		expect(result.stopReason).toBe("error");
		await new Promise((resolve) => setTimeout(resolve, 0));

		expect(cancelCalled).toBe(true);
	});
});

describe("streamProxy malformed-SSE-line resilience (opt #55)", () => {
	it("skips a malformed data line mid-stream and preserves the rest of the response", async () => {
		// A single malformed `data:` line (truncated JSON / non-JSON heartbeat) in the MIDDLE of
		// an otherwise-valid SSE response. Pre-fix: JSON.parse threw SyntaxError → outer catch
		// synthesized an error event → stream.end() → the ENTIRE response was lost, including the
		// valid text_delta AFTER the bad line (never read) and the done event (never reached).
		// Post-fix: the bad line is skipped (try/catch + continue, matching mcp-manager's
		// parseSseJsonMessages); the subsequent text_delta is emitted and the stream completes
		// normally with a done event (stopReason "stop", NOT "error").
		const usage = {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		};
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(sseLine(JSON.stringify({ type: "start" })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_start", contentIndex: 0 })));
				// Malformed line in the middle — must be skipped, not fatal.
				controller.enqueue(sseLine("{ this is not valid json"));
				controller.enqueue(
					sseLine(JSON.stringify({ type: "text_delta", contentIndex: 0, delta: "after bad line" })),
				);
				controller.enqueue(sseLine(JSON.stringify({ type: "text_end", contentIndex: 0 })));
				controller.enqueue(sseLine(JSON.stringify({ type: "done", reason: "stop", usage })));
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
			{
				authToken: "tok",
				proxyUrl: "https://proxy.invalid",
			},
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

		// The stream completed via the done event (NOT a synthesized error).
		expect(result.stopReason).toBe("stop");
		expect(result.errorMessage).toBeUndefined();
		// The text_delta AFTER the malformed line was preserved (skipping the bad line didn't
		// kill the stream). Pre-fix this assertion fails — the response was lost to an error.
		const textBlock = result.content[0];
		expect(textBlock).toBeDefined();
		if (textBlock && textBlock.type === "text") {
			expect(textBlock.text).toBe("after bad line");
		}
		// Exactly one terminal message (the done), no error event.
		expect(events).toHaveLength(1);
	});
});

describe("streamProxy usage normalization (opt #58)", () => {
	// The proxy assigns the server's `done`/`error` usage verbatim into the AssistantMessage, but
	// that usage arrives from JSON.parse of an external proxy server's SSE — the `Usage` type is not
	// enforced at the boundary. A server that omits usage, sends a partial object, or wrong-typed
	// fields would propagate undefined/NaN downstream: calculateContextTokens(undefined) crashes
	// every turn (agent-session.ts:2140), and `input + undefined` = NaN silently disables compaction
	// (Number.isFinite guard → never fires → lost turn) and the overflow detector. Every direct
	// provider rebuilds Usage with ?? 0; the proxy was the lone outlier. normalizeProxyUsage mirrors
	// the direct-provider contract: ?? 0 on every field, recompute totalTokens when missing/falsy.

	it("synthesizes a zero Usage when the done event omits usage entirely", async () => {
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(sseLine(JSON.stringify({ type: "start" })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_start", contentIndex: 0 })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_delta", contentIndex: 0, delta: "hi" })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_end", contentIndex: 0 })));
				// done with NO usage field — pre-fix: partial.usage became undefined.
				controller.enqueue(sseLine(JSON.stringify({ type: "done", reason: "stop" })));
				controller.close();
			},
		});

		globalThis.fetch = (() =>
			Promise.resolve({ ok: true, status: 200, statusText: "OK", body })) as unknown as typeof globalThis.fetch;

		const stream = streamProxy(
			createModel(),
			{ systemPrompt: "", messages: [], tools: [] },
			{ authToken: "tok", proxyUrl: "https://proxy.invalid" },
		);
		for await (const _event of stream) {
			/* drain */
		}

		const result = await Promise.race([
			stream.result(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("hung")), 2000)),
		]);

		// Pre-fix: result.usage was undefined (the server omitted it) → downstream
		// calculateContextTokens(undefined) would TypeError-crash. Post-fix: well-shaped zeros.
		expect(result.usage).toBeDefined();
		expect(result.usage.input).toBe(0);
		expect(result.usage.output).toBe(0);
		expect(result.usage.cacheRead).toBe(0);
		expect(result.usage.cacheWrite).toBe(0);
		expect(result.usage.totalTokens).toBe(0);
		expect(result.usage.cost.total).toBe(0);
	});

	it("recomputes totalTokens from components when the server sends partial usage", async () => {
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(sseLine(JSON.stringify({ type: "start" })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_start", contentIndex: 0 })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_delta", contentIndex: 0, delta: "hi" })));
				controller.enqueue(sseLine(JSON.stringify({ type: "text_end", contentIndex: 0 })));
				// Partial usage: no totalTokens, no cacheRead/cacheWrite, no cost. Pre-fix:
				// partial.usage = {input:100, output:50} → calculateContextTokens did
				// `undefined || 100 + 50 + undefined + undefined` = NaN → compaction never fired.
				controller.enqueue(
					sseLine(JSON.stringify({ type: "done", reason: "stop", usage: { input: 100, output: 50 } })),
				);
				controller.close();
			},
		});

		globalThis.fetch = (() =>
			Promise.resolve({ ok: true, status: 200, statusText: "OK", body })) as unknown as typeof globalThis.fetch;

		const stream = streamProxy(
			createModel(),
			{ systemPrompt: "", messages: [], tools: [] },
			{ authToken: "tok", proxyUrl: "https://proxy.invalid" },
		);
		for await (const _event of stream) {
			/* drain */
		}

		const result = await Promise.race([
			stream.result(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("hung")), 2000)),
		]);

		// Post-fix: totalTokens recomputed = 100 + 50 + 0 + 0 = 150; missing fields zeroed; cost
		// synthesized as zeros (server sent none). Pre-fix: totalTokens was undefined → NaN
		// downstream → silent overflow / lost turn.
		expect(result.usage.input).toBe(100);
		expect(result.usage.output).toBe(50);
		expect(result.usage.cacheRead).toBe(0);
		expect(result.usage.cacheWrite).toBe(0);
		expect(result.usage.totalTokens).toBe(150);
		expect(result.usage.cost).toEqual({ input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 });
	});

	it("preserves a complete, well-shaped server usage", async () => {
		const usage = {
			input: 200,
			output: 80,
			cacheRead: 1000,
			cacheWrite: 300,
			totalTokens: 1580,
			cost: { input: 1, output: 2, cacheRead: 3, cacheWrite: 4, total: 10 },
		};
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(sseLine(JSON.stringify({ type: "start" })));
				controller.enqueue(sseLine(JSON.stringify({ type: "done", reason: "stop", usage })));
				controller.close();
			},
		});

		globalThis.fetch = (() =>
			Promise.resolve({ ok: true, status: 200, statusText: "OK", body })) as unknown as typeof globalThis.fetch;

		const stream = streamProxy(
			createModel(),
			{ systemPrompt: "", messages: [], tools: [] },
			{ authToken: "tok", proxyUrl: "https://proxy.invalid" },
		);
		for await (const _event of stream) {
			/* drain */
		}

		const result = await Promise.race([
			stream.result(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("hung")), 2000)),
		]);

		expect(result.usage).toEqual(usage);
	});
});

import { afterEach, describe, expect, it, vi } from "vitest";

// Regression guard for opt #170 — StreamableHttpJsonRpcClient.post did `await response.text()` on the
// ENTIRE MCP HTTP success-path body then `text.split(/\r?\n\r?\n/)` over it (parseSseJsonMessages) —
// unbounded, so a misbehaving/hostile (user-configured) MCP server returning a huge text/event-stream
// or JSON body loaded it all before the message was located → OOM. opt #49 only DRAINED the body on
// the error/non-ok path; the success path was the lone unbounded read (stdio MCP stdout is capped via
// MCP_STDIO_BUFFER_MAX_CHARS, opt #59). Fix: readBoundedResponseBody streams via
// response.body.getReader() and accumulates into a Buffer up to MCP_HTTP_BODY_MAX_BYTES (default 16MB,
// REPI_MCP_HTTP_BODY_MAX_BYTES env, 0 disables); Content-Length > cap aborts WITHOUT reading; exceeding
// mid-stream cancels the reader and throws. A normal response under the cap is byte-for-byte identical
// to `await response.text()`. The natural seam is a FAKE Response (no fs mock): a plain object with
// `body: { getReader() }` emitting chunks, `text()`, and `headers.get("content-length")`.

/** Build a fake fetch Response whose body streams `bodyBytes` in fixed-size chunks. Tracks read calls,
 * bytes delivered, and whether the reader/stream was cancelled so tests can assert the body was NOT
 * consumed whole on the cap-exceeded path. */
function fakeResponse(opts: {
	body: string | Uint8Array;
	contentType?: string;
	/** Explicit Content-Length header. `undefined` = derive from body length; `null` = omit header. */
	contentLength?: string | null;
	chunkSize?: number;
	ok?: boolean;
	status?: number;
}): { response: Response; state: { readCalls: number; bytesDelivered: number; cancelled: boolean } } {
	const fullBytes = typeof opts.body === "string" ? Buffer.from(opts.body, "utf8") : Buffer.from(opts.body);
	const chunkSize = opts.chunkSize ?? 10;
	const state = { readCalls: 0, bytesDelivered: 0, cancelled: false };
	const reader = {
		async read(): Promise<{ done: boolean; value?: Uint8Array }> {
			if (state.cancelled) return { done: true };
			if (state.bytesDelivered >= fullBytes.length) return { done: true };
			const slice = fullBytes.subarray(state.bytesDelivered, state.bytesDelivered + chunkSize);
			state.bytesDelivered += slice.length;
			state.readCalls += 1;
			return { done: false, value: slice };
		},
		async cancel(): Promise<void> {
			state.cancelled = true;
		},
		releaseLock(): void {},
	};
	const stream = {
		getReader: () => reader,
		cancel: async (): Promise<void> => {
			state.cancelled = true;
		},
	};
	const headers = new Map<string, string>();
	if (opts.contentType) headers.set("content-type", opts.contentType);
	if (opts.contentLength === null) {
		// omit
	} else if (opts.contentLength !== undefined) {
		headers.set("content-length", opts.contentLength);
	} else {
		headers.set("content-length", String(fullBytes.length));
	}
	const response = {
		body: stream,
		headers: { get: (k: string): string | null => headers.get(k.toLowerCase()) ?? null },
		text: async (): Promise<string> => fullBytes.toString("utf8"),
		ok: opts.ok ?? true,
		status: opts.status ?? 200,
	} as unknown as Response;
	return { response, state };
}

/** Re-import the module fresh so the MCP_HTTP_BODY_MAX_BYTES constant picks up the given env override
 * (it is captured at module-evaluation time). */
async function importWithEnv(envValue: string | undefined): Promise<typeof import("../src/core/mcp-manager.ts")> {
	vi.resetModules();
	if (envValue === undefined) delete process.env.REPI_MCP_HTTP_BODY_MAX_BYTES;
	else process.env.REPI_MCP_HTTP_BODY_MAX_BYTES = envValue;
	return await import("../src/core/mcp-manager.ts");
}

describe("MCP HTTP response body bound (opt #170)", () => {
	const savedEnv = process.env.REPI_MCP_HTTP_BODY_MAX_BYTES;

	afterEach(() => {
		vi.resetModules();
		if (savedEnv === undefined) delete process.env.REPI_MCP_HTTP_BODY_MAX_BYTES;
		else process.env.REPI_MCP_HTTP_BODY_MAX_BYTES = savedEnv;
	});

	it("parses a small SSE body byte-identically to the unbounded path (parity)", async () => {
		const mod = await importWithEnv(undefined);
		const sseBody = ['data: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}]}}', ""].join(
			"\n\n",
		);
		const { response } = fakeResponse({ body: sseBody, contentType: "text/event-stream" });
		const bodyText = await mod.readBoundedResponseBody(response);
		// Byte-identical to response.text().
		expect(bodyText).toBe(sseBody);
		const messages = mod.parseHttpResponseMessages("text/event-stream", bodyText);
		expect(messages).toEqual([{ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "hi" }] } }]);
	});

	it("parses a small JSON body byte-identically (parity, non-SSE content type)", async () => {
		const mod = await importWithEnv(undefined);
		const jsonBody = JSON.stringify({ jsonrpc: "2.0", id: 7, result: { ok: true } });
		const { response } = fakeResponse({ body: jsonBody, contentType: "application/json" });
		const bodyText = await mod.readBoundedResponseBody(response);
		expect(bodyText).toBe(jsonBody);
		expect(mod.parseHttpResponseMessages("application/json", bodyText)).toEqual([
			{ jsonrpc: "2.0", id: 7, result: { ok: true } },
		]);
	});

	it("aborts an oversized streaming body WITHOUT consuming it whole (cap exceeded mid-stream)", async () => {
		// 64-byte cap so the oversized body (1000 bytes) trips it quickly.
		const mod = await importWithEnv("64");
		const bigBody = "x".repeat(1000);
		const { response, state } = fakeResponse({
			body: bigBody,
			contentType: "text/event-stream",
			contentLength: null,
		});
		await expect(mod.readBoundedResponseBody(response)).rejects.toThrow(
			/MCP HTTP response body exceeded REPI_MCP_HTTP_BODY_MAX_BYTES/,
		);
		// The reader was cancelled (stream torn down), NOT left reading.
		expect(state.cancelled).toBe(true);
		// The whole body was NOT consumed — only a bounded prefix was read from the stream.
		expect(state.bytesDelivered).toBeLessThan(bigBody.length);
		// And the number of read calls is bounded (well under the 100 calls a full 10-byte-chunked
		// read of 1000 bytes would require) — proving early abort, not drain-to-end.
		expect(state.readCalls).toBeLessThan(20);
	});

	it("aborts WITHOUT reading the body when Content-Length exceeds the cap", async () => {
		const mod = await importWithEnv("64");
		const bigBody = "x".repeat(1000);
		const { response, state } = fakeResponse({
			body: bigBody,
			contentType: "application/json",
			contentLength: "10000",
		});
		await expect(mod.readBoundedResponseBody(response)).rejects.toThrow(
			/MCP HTTP response body exceeded REPI_MCP_HTTP_BODY_MAX_BYTES.*Content-Length: 10000/,
		);
		// The reader was NEVER acquired for streaming — zero read calls (Content-Length early-abort
		// fires before any chunk is pulled). drainResponseBody cancels the stream (cancelled=true).
		expect(state.readCalls).toBe(0);
		expect(state.bytesDelivered).toBe(0);
		expect(state.cancelled).toBe(true);
	});

	it("cap=0 disables the bound (a body larger than the default cap reads fully, no throw)", async () => {
		const mod = await importWithEnv("0");
		// 5000 bytes would far exceed the 64-byte cap used above; under cap=0 it must read fully.
		const bigBody = `data: ${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } })}\n\n${"x".repeat(4900)}`;
		const { response, state } = fakeResponse({
			body: bigBody,
			contentType: "text/event-stream",
			contentLength: null,
		});
		const bodyText = await mod.readBoundedResponseBody(response);
		expect(bodyText).toBe(bigBody);
		// cap=0 takes the POSITIVE_INFINITY fast-path (`await response.text()`), bypassing the reader.
		expect(state.readCalls).toBe(0);
	});
});

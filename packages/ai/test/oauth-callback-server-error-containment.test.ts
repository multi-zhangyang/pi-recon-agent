import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { startCallbackServer } from "../src/utils/oauth/anthropic.ts";
import { startLocalOAuthServer } from "../src/utils/oauth/openai-codex.ts";

// opt #146: the OAuth callback HTTP servers registered server.on("error")
// (listen-time EADDRINUSE) but attached NO 'error' listener on the req/res
// streams inside the request handler (listenerCount("error") === 0). A
// write-failure on the response (proxy reset mid-stream on a large response,
// or a req parse error) surfaces an 'error' on the unguarded stream with no
// listener → `Unhandled 'error' event` crashes `pi auth login` mid-flow.
// Modern Node handles the connection-SOCKET 'error' internally, so the
// meaningful guard is the req/res noop listeners added at the top of the
// handler (plus a belt-and-suspenders `connection` listener for older Node).
//
// Test strategy: the createServer handler IS the 'request' listener, so a
// SECOND `server.on("request", ...)` listener receives the same (req, res)
// and fires right after the handler — by which point the handler has attached
// its noop 'error' listeners. The test then deterministically emits 'error'
// on the captured req/res: with the guard the emit is swallowed; without it,
// EventEmitter throws synchronously on an unhandled 'error' event.

type Captured = { req: IncomingMessage; res: ServerResponse };

async function captureReqRes(server: Server, url: string, state: string): Promise<Captured> {
	return new Promise((resolve) => {
		server.on("request", (req: IncomingMessage, res: ServerResponse) => {
			resolve({ req, res });
		});
		fetch(`${url}?code=test-code&state=${state}`).catch(() => {
			// The handler may have ended res before fetch reads it; a fetch rejection
			// here is fine — we already captured req/res synchronously on the event.
		});
	});
}

describe("OAuth callback server req/res error containment (opt #146)", () => {
	const servers: Server[] = [];

	afterEach(() => {
		for (const s of servers) {
			try {
				s.close();
			} catch {
				// ignore
			}
		}
		servers.length = 0;
	});

	it("Anthropic callback handler swallows req/res 'error' (no unhandled event)", async () => {
		const state = "test-state-146-anthropic";
		const info = await startCallbackServer(state);
		servers.push(info.server);

		const uncaught: unknown[] = [];
		const onUncaught = (err: unknown) => {
			uncaught.push(err);
		};
		process.on("uncaughtException", onUncaught);
		try {
			const { req, res } = await captureReqRes(info.server, `http://127.0.0.1:53692/callback`, state);
			// Guard attached a noop 'error' listener on each stream.
			expect(req.listenerCount("error")).toBeGreaterThanOrEqual(1);
			expect(res.listenerCount("error")).toBeGreaterThanOrEqual(1);
			// Deterministic: emitting 'error' on a guarded stream is swallowed.
			expect(() => req.emit("error", new Error("req boom"))).not.toThrow();
			expect(() => res.emit("error", new Error("res boom"))).not.toThrow();
			await new Promise<void>((r) => setImmediate(r));
			expect(uncaught).toEqual([]);
		} finally {
			process.off("uncaughtException", onUncaught);
		}
	});

	it("OpenAI Codex callback handler swallows req/res 'error' (no unhandled event)", async () => {
		const state = "test-state-146-openai";
		const info = await startLocalOAuthServer(state);
		servers.push(info.server);

		const uncaught: unknown[] = [];
		const onUncaught = (err: unknown) => {
			uncaught.push(err);
		};
		process.on("uncaughtException", onUncaught);
		try {
			const { req, res } = await captureReqRes(info.server, `http://127.0.0.1:1455/auth/callback`, state);
			expect(req.listenerCount("error")).toBeGreaterThanOrEqual(1);
			expect(res.listenerCount("error")).toBeGreaterThanOrEqual(1);
			expect(() => req.emit("error", new Error("req boom"))).not.toThrow();
			expect(() => res.emit("error", new Error("res boom"))).not.toThrow();
			await new Promise<void>((r) => setImmediate(r));
			expect(uncaught).toEqual([]);
		} finally {
			process.off("uncaughtException", onUncaught);
		}
	});
});

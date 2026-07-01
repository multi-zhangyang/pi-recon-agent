import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

// opt #276: withInitializedMcpClient's catch closed the pooled MCP client on
// EVERY callback error — including a per-request `message.error` (a tools/call
// returning "invalid params" / "not found") where the stdio connection is
// still HEALTHY (client.isClosed === false, error not retryable). That killed
// the shared stdio child and forced a spawn+initialize handshake on the next
// call to the same pooled server — a perf/cost regression on every erroring
// tool call. Fix: finalizePooledClientOnError only closes when the connection
// is actually dead (isClosed OR retryable transport error); otherwise it
// re-pools the healthy client (mirrors the success path).

interface FakeClient {
	isClosed: boolean;
	stderrTail: string;
	childPid?: number;
	request: () => Promise<unknown>;
	notify: () => void;
	close: () => Promise<void>;
}

interface Internals {
	clientPool: Map<
		string,
		{ key: string; fingerprint: string; client: FakeClient; init: unknown; idleTimer?: NodeJS.Timeout }
	>;
	poolKey: (entry: unknown) => string;
	serverFingerprint: (entry: unknown) => string;
	withInitializedMcpClient: <T>(
		entry: unknown,
		callback: (client: FakeClient, init: unknown) => Promise<T>,
		signal?: AbortSignal,
	) => Promise<T>;
	finalizePooledClientOnError: (
		entry: unknown,
		pooled: { key: string; fingerprint: string; client: FakeClient; init: unknown; idleTimer?: NodeJS.Timeout },
		error: unknown,
		signal?: AbortSignal,
	) => Promise<void>;
}

describe("withInitializedMcpClient per-request error does NOT close a healthy pooled client (opt #276)", () => {
	let tempRoot: string | undefined;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-pooled-perreq-"));
	});

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	function makeManager(): Internals {
		const root = tempRoot!;
		const manager = createMcpManager({ cwd: root, agentDir: join(root, "agent") });
		return manager as unknown as Internals;
	}

	function makeEntry(id: string) {
		return {
			id,
			sourcePath: "test",
			config: { transport: "stdio", command: "fake", pool: true, poolIdleMs: 1_000_000_000 },
		};
	}

	it("end-to-end: per-request protocol error re-pools the healthy client (close NOT called, remains in pool)", async () => {
		const internals = makeManager();
		const entry = makeEntry("srv");
		const key = internals.poolKey(entry);
		const fingerprint = internals.serverFingerprint(entry);

		let closeCalls = 0;
		// A per-request tools/call error: the message is the JSON-stringified
		// MCP error object (handleMessageLine rejects with this). It contains
		// no "timeout"/"ECONN"/"server exited" → isRetryableMcpError is FALSE.
		const client: FakeClient = {
			isClosed: false,
			stderrTail: "",
			childPid: undefined,
			request: async () => {
				throw new Error('{"code":-32602,"message":"Invalid params"}');
			},
			notify: () => {},
			close: () => {
				closeCalls++;
				return Promise.resolve();
			},
		};
		const pooled = { key, fingerprint, client, init: {}, idleTimer: undefined };
		internals.clientPool.set(key, pooled);

		const callback = async (c: FakeClient) => c.request();

		await expect(internals.withInitializedMcpClient(entry, callback)).rejects.toThrow("Invalid params");
		// FIX: the healthy pooled client was NOT closed (re-pooled instead).
		expect(closeCalls).toBe(0);
		// It remains in the pool for reuse by the next call.
		expect(internals.clientPool.has(key)).toBe(true);
		expect(internals.clientPool.get(key)).toBe(pooled);
		if (pooled.idleTimer) clearTimeout(pooled.idleTimer);
	});

	it("finalizePooledClientOnError: healthy client + per-request error → re-pool (close NOT called, idle timer armed)", async () => {
		const internals = makeManager();
		const entry = makeEntry("srvA");
		const key = internals.poolKey(entry);

		let closeCalls = 0;
		const client: FakeClient = {
			isClosed: false,
			stderrTail: "",
			childPid: undefined,
			request: async () => {
				throw new Error('{"code":-32601,"message":"Method not found"}');
			},
			notify: () => {},
			close: () => {
				closeCalls++;
				return Promise.resolve();
			},
		};
		const pooled = { key, fingerprint: "f", client, init: {}, idleTimer: undefined };
		internals.clientPool.set(key, pooled);

		await internals.finalizePooledClientOnError(
			entry,
			pooled,
			new Error('{"code":-32601,"message":"Method not found"}'),
		);

		expect(closeCalls).toBe(0);
		expect(internals.clientPool.has(key)).toBe(true);
		// schedulePooledClientClose armed the idle timer (re-pool for reuse).
		expect(pooled.idleTimer).toBeDefined();
		if (pooled.idleTimer) clearTimeout(pooled.idleTimer);
	});

	it("finalizePooledClientOnError: already-closed client + per-request error → close + evict (fatal path retained)", async () => {
		const internals = makeManager();
		const entry = makeEntry("srvB");
		const key = internals.poolKey(entry);

		let closeCalls = 0;
		// The framing/exit path already marked the client closed. A subsequent
		// per-request error must still close (no-op on a dead child) + evict.
		const client: FakeClient = {
			isClosed: true,
			stderrTail: "",
			childPid: undefined,
			request: async () => {
				throw new Error('{"code":-32602,"message":"Invalid params"}');
			},
			notify: () => {},
			close: () => {
				closeCalls++;
				return Promise.resolve();
			},
		};
		const pooled = { key, fingerprint: "f", client, init: {}, idleTimer: undefined };
		internals.clientPool.set(key, pooled);

		await internals.finalizePooledClientOnError(
			entry,
			pooled,
			new Error('{"code":-32602,"message":"Invalid params"}'),
		);

		expect(closeCalls).toBe(1);
		expect(internals.clientPool.has(key)).toBe(false);
		if (pooled.idleTimer) clearTimeout(pooled.idleTimer);
	});

	it("finalizePooledClientOnError: healthy client + retryable transport error → close + evict (respawn warranted)", async () => {
		const internals = makeManager();
		const entry = makeEntry("srvC");
		const key = internals.poolKey(entry);

		let closeCalls = 0;
		const client: FakeClient = {
			isClosed: false,
			stderrTail: "",
			childPid: undefined,
			request: async () => {
				throw new Error("MCP request timeout");
			},
			notify: () => {},
			close: () => {
				closeCalls++;
				return Promise.resolve();
			},
		};
		const pooled = { key, fingerprint: "f", client, init: {}, idleTimer: undefined };
		internals.clientPool.set(key, pooled);

		// "MCP request timeout" matches isRetryableMcpError → connectionFatal.
		await internals.finalizePooledClientOnError(entry, pooled, new Error("MCP request timeout"));

		expect(closeCalls).toBe(1);
		expect(internals.clientPool.has(key)).toBe(false);
		if (pooled.idleTimer) clearTimeout(pooled.idleTimer);
	});
});

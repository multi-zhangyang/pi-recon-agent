/**
 * opt #248 — StdioJsonRpcClient.request on a closed client rejected slowly
 * (LOW-MED latency/hang).
 *
 * request() did NOT check `this.closed` before registering the pending entry
 * and calling write(). write() no-ops on a dead stdin (the :837 guard), so a
 * request issued against a client whose child already exited (the narrow race
 * between getPooledClient's !isClosed pool check at :1980 and the request()
 * call) sat in `this.pending` with no response coming and ONLY the timeout
 * timer (full timeoutMs, default 10s) to settle it — a fast "closed" failure
 * became a slow timeout. close() already rejects in-flight requests with
 * "MCP client closed"; a new request on an already-closed client should fail
 * the same way immediately.
 *
 * Fix: reject immediately with "MCP client closed" at the top of the Promise
 * executor when this.closed is already true.
 */
import { afterEach, describe, expect, it } from "vitest";
import type { McpServerEntry } from "../src/core/mcp-manager.ts";
import { StdioJsonRpcClient } from "../src/core/mcp-manager.ts";

describe("StdioJsonRpcClient.request closed guard (opt #248)", () => {
	let client: StdioJsonRpcClient | undefined;

	afterEach(() => {
		try {
			client?.close();
		} catch {}
		client = undefined;
	});

	it("rejects immediately with 'MCP client closed' when the client is already closed", async () => {
		// Long-lived child so the client starts healthy; we close it explicitly.
		const entry: McpServerEntry = {
			id: "fake",
			sourcePath: "",
			config: {
				command: process.execPath,
				args: ["-e", "setInterval(() => {}, 1000)"],
			},
		};
		client = new StdioJsonRpcClient(entry);
		expect(client.isClosed).toBe(false);

		client.close();
		expect(client.isClosed).toBe(true);

		const start = Date.now();
		// Short timeoutMs so the neuter (no closed guard) still settles quickly
		// via the timeout path rather than hanging the suite.
		await expect(client.request("ping", {}, 500)).rejects.toThrow("MCP client closed");
		const elapsed = Date.now() - start;

		// Post-fix the rejection is immediate, well under the 500ms timeout.
		// Pre-fix (neutered) this would wait ~500ms and reject with
		// "MCP request timeout: ping" instead — the message assertion above is
		// the deterministic lock; the timing check is a secondary signal.
		expect(elapsed).toBeLessThan(400);
	}, 10000);
});

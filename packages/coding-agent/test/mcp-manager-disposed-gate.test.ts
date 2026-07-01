import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

// opt #141: closeAll() is terminal (called fire-and-forget from
// agent-session dispose). Pre-fix only the abort `signal` guarded
// withInitializedMcpClient's retry (`!signal?.aborted && isRetryableMcpError`),
// so a closeAll triggered by a DIFFERENT signal than an in-flight call's left
// the retry guard true on a retryable error → a racing retry (or any NEW call
// after dispose) spawned a fresh detached stdio child AFTER closeAll had killed
// the pool — a spawn-after-dispose leak. Fix: a `_disposed` flag set
// synchronously at the start of closeAll, checked in getPooledClient (refuses to
// spawn/resolve any client — a warm-pool hit would be a stale killed client) and
// in the retry guard. This test proves a NEW call after closeAll refuses to
// spawn (returns a disposed error, not ok:true with a freshly-spawned child).
// Pre-fix (neuter the _disposed gate) the post-closeAll call spawns a fresh
// child and succeeds → the ok:false assertion fails.

describe("McpManager disposed gate (opt #141)", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("refuses to spawn a fresh child for a new call after closeAll()", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-disposed-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		const fakeServer = join(tempRoot, "fake-mcp-disposed.mjs");
		writeFileSync(
			fakeServer,
			`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { resources: {} } } }));
 if (msg.method === "resources/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { resources: [{ uri: "file:///demo.txt", name: "demo" }] } }));
});
`,
		);
		chmodSync(fakeServer, 0o700);
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: { fake: { transport: "stdio", command: process.execPath, args: [fakeServer] } },
			}),
		);

		const manager = createMcpManager({ cwd: tempRoot, agentDir });

		// Sanity: the server is functional and a call succeeds (spawns the child).
		const ok = await manager.listResources("fake");
		expect(ok.ok).toBe(true);
		expect(ok.resources.map((r) => r.uri)).toEqual(["file:///demo.txt"]);

		// Tear down.
		await manager.closeAll();

		// A NEW call after closeAll must NOT spawn a fresh child. listResources
		// catches the getPooledClient throw and returns ok:false with a disposed
		// error. Pre-fix (neuter the _disposed gate) this spawns a new child and
		// resolves ok:true like the sanity call → the ok:false assertion fails.
		const after = await manager.listResources("fake");
		expect(after.ok).toBe(false);
		expect(String(after.error)).toMatch(/dispos/i);

		// callTool does NOT catch — it propagates the disposed error as a throw.
		await expect(manager.callTool("fake", "echo", {})).rejects.toThrow(/dispos/i);
	});
});

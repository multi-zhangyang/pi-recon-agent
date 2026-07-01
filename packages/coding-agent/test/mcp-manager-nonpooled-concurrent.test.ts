/**
 * opt #234 — McpManager `pool:false` concurrent same-server calls must NOT share
 * one in-flight client. Pre-fix, getPooledClient's inflight-create sharing was
 * NOT gated on `poolingEnabled`, so a second concurrent `pool:false` caller on
 * the same server reused the first's in-flight create (no warm pool exists for
 * pool:false → `existing` was always undefined → the inflight branch fired).
 * Both callers then operated on the SAME StdioJsonRpcClient. The first finisher
 * resolved its tools/call, ran schedulePooledClientClose → `client.close()`
 * (pool:false closes immediately), killing the shared child + closing stdin
 * while the second's tools/call was still in flight → the second rejected
 * "MCP client closed" (non-retryable data loss on a perfectly healthy server).
 *
 * Fix: gate inflight sharing on `poolingEnabled` so each `pool:false` caller
 * spawns its OWN child; track per-spawn pids in `Map<string, Set<number>>` so
 * closeAll + the exit-reap hook still reach every concurrent child.
 *
 * The fake server responds to the FIRST tools/call on a given connection after
 * 80ms and to the SECOND after 800ms (per-connection counter). Post-fix each
 * callTool is its own connection so both are "first" → both return ~80ms → both
 * succeed. Pre-fix (shared connection) call A is first (80ms) and call B is
 * second (800ms); A finishes, closes the shared client, B rejects.
 */
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

function writeFakeMcpServer(tempRoot: string): string {
	const fakeServer = join(tempRoot, "fake-mcp-concurrent.mjs");
	writeFileSync(
		fakeServer,
		`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
// Per-connection counter: the first tools/call responds fast, the second slow.
// With opt #234 each pool:false callTool is its own connection so each is first.
let callCount = 0;
rl.on("line", (line) => {
  const msg = JSON.parse(line);
  if (msg.method === "initialize") {
    console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { tools: {} } } }));
    return;
  }
  if (msg.method === "tools/list") {
    console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", inputSchema: { type: "object" } }] } }));
    return;
  }
  if (msg.method === "tools/call") {
    callCount += 1;
    const delay = callCount === 1 ? 80 : 800;
    const text = msg.params?.arguments?.text ?? "?";
    setTimeout(() => {
      console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "echo:" + text }], isError: false } }));
    }, delay);
  }
});
`,
	);
	chmodSync(fakeServer, 0o700);
	return fakeServer;
}

describe("McpManager pool:false concurrent same-server calls (opt #234)", () => {
	let tempRoot: string | undefined;
	let manager: ReturnType<typeof createMcpManager> | undefined;

	afterEach(async () => {
		if (manager) {
			await manager.closeAll();
			manager = undefined;
		}
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("two concurrent callTool on the same pool:false server both succeed (no shared-client close)", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-conc-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		const fakeServer = writeFakeMcpServer(tempRoot);
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				// pool:false = "fresh client per call". Pre-fix this was the trigger:
				// concurrent callers shared one inflight client and the first finisher
				// closed it under the second.
				mcpServers: { fake: { transport: "stdio", command: process.execPath, args: [fakeServer], pool: false } },
			}),
		);

		manager = createMcpManager({ cwd: tempRoot, agentDir });

		// Fire BOTH callTool concurrently without awaiting the first.
		const [a, b] = await Promise.all([
			manager.callTool("fake", "echo", { text: "a" }),
			manager.callTool("fake", "echo", { text: "b" }),
		]);

		// Post-fix: each call got its own client; both returned their own echo.
		// Pre-fix: the shared client was closed after the fast (first) call, so the
		// slow (second) call rejected "MCP client closed" and Promise.all threw.
		const aText = String(a.content[0]?.type === "text" ? a.content[0].text : "");
		const bText = String(b.content[0]?.type === "text" ? b.content[0].text : "");
		expect(aText).toBe("echo:a");
		expect(bText).toBe("echo:b");
		expect(a.isError).toBe(false);
		expect(b.isError).toBe(false);
	}, 15000);
});

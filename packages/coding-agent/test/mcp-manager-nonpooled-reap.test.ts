import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

// opt #139: for `pool:false` servers, getPooledClient's createPromise `.finally`
// cleared `_inflightChildPids` and the `if (!poolingEnabled) return created` path
// never added the client to `clientPool` — so for the ENTIRE duration of the
// in-flight tool callback (resources/list, tools/call, … up to the 10s timeout)
// the non-pooled stdio child's pid was in NEITHER structure. A process exit (or
// closeAll) in that window missed it → the detached+unref'd child was reparented
// to init and kept running (cost/quota leak — same class opt #46 fixed for pooled
// clients). Fix: withInitializedMcpClient registers the non-pooled pid in
// `_inflightNonPooledPids` for the duration of the callback (cleared in finally),
// and the exit-reap hook + closeAll reap it. This test drives a non-pooled
// listResources against a server that DELAYS its resources/list response, and
// asserts the pid is tracked (and the exit-reap hook installed) mid-call, then
// cleared after the call settles. Pre-fix (neuter the registration) the map
// stays empty mid-call → the size>0 assertion fails.

describe("McpManager non-pooled in-flight child reap tracking (opt #139)", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("tracks a pool:false stdio child's pid for the duration of the in-flight call", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-np-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		const fakeServer = join(tempRoot, "fake-mcp-np.mjs");
		writeFileSync(
			fakeServer,
			`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { resources: {} } } }));
 if (msg.method === "resources/list") {
  // Delay the response so the parent's callback is still in flight when we
  // inspect the tracking map below.
  setTimeout(() => console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { resources: [{ uri: "file:///demo.txt", name: "demo" }] } })), 1200);
 }
});
`,
		);
		chmodSync(fakeServer, 0o700);
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				// pool:false forces the non-pooled path: the child is NOT retained in
				// clientPool during the call, so without opt #139 it would be
				// unreachable by the exit-reap hook + closeAll.
				mcpServers: { fake: { transport: "stdio", command: process.execPath, args: [fakeServer], pool: false } },
			}),
		);

		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const tracked = (manager as unknown as { _inflightNonPooledPids: Map<string, Set<number>> })
			._inflightNonPooledPids;
		const hook = () => (manager as unknown as { _exitReapHook: (() => void) | undefined })._exitReapHook;
		// opt #234: tracked is Map<string, Set<number>> (per-spawn) — pull a pid
		// out of any key's set for the type check below.
		const firstTrackedPid = () => {
			for (const set of tracked.values()) for (const pid of set) return pid;
			return undefined;
		};

		// Sanity: nothing tracked yet, no exit-reap hook installed.
		expect(tracked.size).toBe(0);
		expect(hook()).toBeUndefined();

		// Start the call WITHOUT awaiting — the server delays resources/list by
		// 1.2s so the callback stays in flight.
		const callP = manager.listResources("fake");

		// Poll until the in-flight pid is registered (initialize handshake +
		// resources/list send). Bounds at 5s so a regression fails fast.
		const deadline = Date.now() + 5000;
		while (tracked.size === 0 && Date.now() < deadline) {
			await new Promise<void>((resolve) => setTimeout(resolve, 20));
		}

		// Mid-call: the non-pooled child's pid IS tracked, and the exit-reap hook
		// is installed (so a process exit during the call would SIGKILL it). Pre-fix
		// (neuter the registration) tracked.size stays 0 here.
		expect(tracked.size).toBe(1);
		const trackedPid = firstTrackedPid();
		expect(typeof trackedPid).toBe("number");
		expect(trackedPid).toBeGreaterThan(0);
		expect(hook()).toBeDefined();

		// Let the delayed response settle the call; runTracked's finally clears
		// the registration + refreshes the hook (pool empty + no inflight → removed).
		const result = await callP;
		expect(result.ok).toBe(true);
		expect(result.resources.map((r) => r.uri)).toEqual(["file:///demo.txt"]);
		expect(tracked.size).toBe(0);
		expect(hook()).toBeUndefined();

		await manager.closeAll();
	});

	it("closeAll reaps a pool:false stdio child mid in-flight call", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-np2-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		const fakeServer = join(tempRoot, "fake-mcp-np2.mjs");
		writeFileSync(
			fakeServer,
			`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { resources: {} } } }));
 if (msg.method === "resources/list") {
  // Never respond — keeps the callback in flight until we closeAll.
 }
});
`,
		);
		chmodSync(fakeServer, 0o700);
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: { fake: { transport: "stdio", command: process.execPath, args: [fakeServer], pool: false } },
			}),
		);

		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const tracked = (manager as unknown as { _inflightNonPooledPids: Map<string, Set<number>> })
			._inflightNonPooledPids;
		// Spy on killProcessGroup via the manager's own hook firing is awkward; we
		// instead assert closeAll clears the tracked pid (it must have reaped it).
		const callP = manager.listResources("fake");

		const deadline = Date.now() + 5000;
		while (tracked.size === 0 && Date.now() < deadline) {
			await new Promise<void>((resolve) => setTimeout(resolve, 20));
		}
		expect(tracked.size).toBe(1);

		// closeAll during the in-flight non-pooled call must reap the tracked child
		// (opt #139 added the _inflightNonPooledPids reap loop) and clear the map.
		// Pre-fix closeAll only reaped _inflightChildPids + clientPool, both empty
		// here, so the child was orphaned and tracked stayed populated until the
		// 10s timeout — neuter makes this assertion fail (tracked.size stays 1).
		await manager.closeAll();
		expect(tracked.size).toBe(0);

		// The orphaned call resolves (not ok) after closeAll killed the child; race
		// it with a short timeout so a regression fails fast instead of waiting the
		// full 10s MCP request timeout. Swallow either way — the assertion above is
		// the real check.
		await Promise.race([callP.catch(() => undefined), new Promise<void>((resolve) => setTimeout(resolve, 1500))]);
	});
});

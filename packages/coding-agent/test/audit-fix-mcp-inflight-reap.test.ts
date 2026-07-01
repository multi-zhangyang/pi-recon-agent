import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

const tempRoots: string[] = [];

afterEach(() => {
	for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

// opt #234: _inflightChildPids is now Map<string, Set<number>> (per-spawn, so
// concurrent pool:false creates don't overwrite each other's pid). Pull the
// first in-flight pid out of any key's set.
function firstInflightPid(map: Map<string, Set<number>>): number | undefined {
	for (const set of map.values()) {
		for (const pid of set) return pid;
	}
	return undefined;
}

// A stdio MCP server that delays its `initialize` response by 5s. This keeps the
// client in the inflight (handshake-not-complete) window long enough for the
// test to enter inflight, invoke a teardown path, and assert the spawned child
// was reaped. The child stays alive (readline) until killed.
function writeSlowMcpServer(tempRoot: string): string {
	const path = join(tempRoot, "slow-mcp.mjs");
	writeFileSync(
		path,
		`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") {
   setTimeout(() => {
     console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "slow" }, capabilities: { tools: {} } } }));
   }, 5000);
 }
});
`,
	);
	chmodSync(path, 0o700);
	return path;
}

function writeMcpConfig(agentDir: string, serverPath: string): void {
	mkdirSync(agentDir, { recursive: true });
	writeFileSync(
		join(agentDir, "mcp.json"),
		JSON.stringify({
			mcpServers: { slow: { transport: "stdio", command: process.execPath, args: [serverPath] } },
		}),
	);
}

/** Poll whether a pid is still alive (process.kill(pid, 0) throws when dead). */
async function waitForPidDead(pid: number, timeoutMs = 4000): Promise<boolean> {
	for (let i = 0; i < Math.max(1, Math.ceil(timeoutMs / 20)); i++) {
		try {
			process.kill(pid, 0);
		} catch {
			return true;
		}
		await new Promise<void>((r) => setTimeout(r, 20));
	}
	return false;
}

type ManagerInternals = {
	_inflightChildPids: Map<string, Set<number>>;
	_exitReapHook: (() => void) | undefined;
	clientPool: Map<string, unknown>;
	getPooledClient: (entry: unknown, signal?: AbortSignal, forceNew?: boolean) => Promise<unknown>;
};

describe("mcp-manager inflight stdio child reap (Finding F3)", () => {
	it("closeAll reaps an inflight stdio child whose initialize handshake is still pending", async () => {
		const tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-f3-"));
		tempRoots.push(tempRoot);
		const agentDir = join(tempRoot, "agent");
		writeMcpConfig(agentDir, writeSlowMcpServer(tempRoot));

		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const internals = manager as unknown as ManagerInternals;

		const entry = manager.getServer("slow");
		expect(entry).toBeDefined();

		// Enter the inflight window: getPooledClient spawns the stdio child and
		// awaits the (5s-delayed) initialize response. Don't await it; we want to
		// tear down while the handshake is still pending.
		const inflightPromise = internals.getPooledClient(entry!).catch(() => {
			// closeAll killing the child rejects the inflight creation; expected.
		});

		// Wait until the child has spawned and its pid is recorded in the inflight
		// map (the exit-reap hook is also installed at this point).
		let pid: number | undefined;
		for (let i = 0; i < 200; i++) {
			if (internals._inflightChildPids.size > 0) {
				pid = firstInflightPid(internals._inflightChildPids);
				break;
			}
			await new Promise<void>((r) => setTimeout(r, 10));
		}
		expect(pid).toBeDefined();
		expect(internals._exitReapHook).toBeDefined();

		// Teardown: closeAll must reach the inflight child (not just clientPool,
		// which is still empty because the create hasn't resolved).
		expect(internals.clientPool.size).toBe(0);
		await manager.closeAll();

		// The spawned child must be dead.
		const dead = await waitForPidDead(pid!, 4000);
		expect(dead).toBe(true);

		// Allow the rejected inflight promise to settle.
		await inflightPromise;
	}, 15000);

	it("the process exit reap hook reaps an inflight stdio child", async () => {
		const tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-f3-hook-"));
		tempRoots.push(tempRoot);
		const agentDir = join(tempRoot, "agent");
		writeMcpConfig(agentDir, writeSlowMcpServer(tempRoot));

		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const internals = manager as unknown as ManagerInternals;

		const entry = manager.getServer("slow");
		expect(entry).toBeDefined();

		const inflightPromise = internals.getPooledClient(entry!).catch(() => {});

		let pid: number | undefined;
		for (let i = 0; i < 200; i++) {
			if (internals._inflightChildPids.size > 0) {
				pid = firstInflightPid(internals._inflightChildPids);
				break;
			}
			await new Promise<void>((r) => setTimeout(r, 10));
		}
		expect(pid).toBeDefined();
		expect(internals._exitReapHook).toBeDefined();

		// Invoke the registered exit reap hook directly (simulates process exit
		// while a stdio MCP handshake is in flight).
		internals._exitReapHook!();

		const dead = await waitForPidDead(pid!, 4000);
		expect(dead).toBe(true);

		await inflightPromise;
		// Clean up the hook so it doesn't outlive the test.
		await manager.closeAll();
	}, 15000);
});

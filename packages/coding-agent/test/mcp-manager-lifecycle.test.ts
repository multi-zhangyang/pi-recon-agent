import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";
import * as atomicWrite from "../src/core/tools/atomic-write.ts";
import { createTestSession } from "./utilities.ts";

/** Build a long-lived stdio MCP fake server that stays alive until killed. */
function writeFakeMcpServer(tempRoot: string): string {
	const fakeServer = join(tempRoot, "fake-mcp-life.mjs");
	writeFileSync(
		fakeServer,
		`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { tools: {} } } }));
 if (msg.method === "tools/call") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "echo:" + (msg.params.arguments?.text ?? "") }], isError: false } }));
});
`,
	);
	chmodSync(fakeServer, 0o700);
	return fakeServer;
}

function writeMcpConfig(agentDir: string, fakeServer: string): void {
	mkdirSync(agentDir, { recursive: true });
	writeFileSync(
		join(agentDir, "mcp.json"),
		JSON.stringify({
			mcpServers: { fake: { transport: "stdio", command: process.execPath, args: [fakeServer] } },
		}),
	);
}

/** Poll until process.kill(pid, 0) throws (ESRCH) or timeout. Returns true if dead.
 * Must yield to the event loop between checks: Node reaps the spawned child
 * asynchronously (via the stdio pipe close), and a busy-spin would block that
 * reap, leaving a zombie that still answers signal 0. */
async function isDeadWithin(pid: number | undefined, ms: number): Promise<boolean> {
	if (!pid) return true;
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		try {
			process.kill(pid, 0);
		} catch {
			return true;
		}
		await new Promise((r) => setTimeout(r, 10));
	}
	try {
		process.kill(pid, 0);
		return false;
	} catch {
		return true;
	}
}

describe("McpManager lifecycle (FIX 1/2/3)", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	describe("FIX 1 — stdio child reap on closeAll", () => {
		it("closeAll kills pooled stdio MCP children", async () => {
			tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-life-"));
			const agentDir = join(tempRoot, "agent");
			const fakeServer = writeFakeMcpServer(tempRoot);
			writeMcpConfig(agentDir, fakeServer);

			const manager = createMcpManager({ cwd: tempRoot, agentDir });
			await manager.callTool("fake", "echo", { text: "hi" });

			const pool = (manager as any).clientPool as Map<string, { client: { childPid?: number } }>;
			const pid = pool.values().next().value?.client?.childPid;
			expect(pid).toBeTypeOf("number");
			// Child is alive before closeAll.
			expect(() => process.kill(pid as number, 0)).not.toThrow();

			await manager.closeAll();

			// Child killed within ~2s.
			expect(await isDeadWithin(pid, 2000)).toBe(true);
			// Pool drained.
			expect(pool.size).toBe(0);
		});
	});

	describe("FIX 1 — exit reap hook", () => {
		it("installs a process.on('exit') hook that SIGKILLs pooled stdio children", async () => {
			tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-exit-"));
			const agentDir = join(tempRoot, "agent");
			const fakeServer = writeFakeMcpServer(tempRoot);
			writeMcpConfig(agentDir, fakeServer);

			const manager = createMcpManager({ cwd: tempRoot, agentDir });
			expect((manager as any)._exitReapHook).toBeUndefined();

			await manager.callTool("fake", "echo", { text: "hi" });

			const pool = (manager as any).clientPool as Map<string, { client: { childPid?: number } }>;
			const pid = pool.values().next().value?.client?.childPid;
			expect(pid).toBeTypeOf("number");

			// Hook installed while pool is non-empty.
			const hook = (manager as any)._exitReapHook as (() => void) | undefined;
			expect(hook).toBeTypeOf("function");

			// Simulate process exit: the hook SIGKILLs every pooled stdio child.
			hook!();

			expect(await isDeadWithin(pid, 2000)).toBe(true);

			// closeAll drains the pool and removes the hook.
			await manager.closeAll();
			expect((manager as any)._exitReapHook).toBeUndefined();
		});

		it("AgentSession.dispose() calls closeAll on a lazily-created mcp manager", () => {
			const ctx = createTestSession();
			try {
				let closeAllCalled = false;
				// Force the lazy manager to exist, then replace it with a stub that
				// records the closeAll call. This verifies the dispose() wiring guards
				// on the private field and invokes closeAll — without spawning a real
				// server in the shared test home agent dir.
				const realManager = (ctx.session as any).mcpManager;
				expect(realManager).toBeDefined();
				(ctx.session as any)._mcpManager = {
					closeAll: () => {
						closeAllCalled = true;
						return Promise.resolve();
					},
				};

				ctx.session.dispose();

				expect(closeAllCalled).toBe(true);
			} finally {
				// createTestSession cleanup calls dispose; ensure no double-free error
			}
		});
	});

	describe("FIX 2 — loadServers mtime/size cache", () => {
		it("returns the same cached array when config mtime+size unchanged", () => {
			tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-cache-"));
			const agentDir = join(tempRoot, "agent");
			mkdirSync(agentDir, { recursive: true });
			writeFileSync(
				join(agentDir, "mcp.json"),
				JSON.stringify({ mcpServers: { a: { transport: "stdio", command: "node" } } }),
			);

			const manager = createMcpManager({ cwd: tempRoot, agentDir });
			const first = manager.loadServers();
			const second = manager.loadServers();
			expect(second).toBe(first); // same reference — cached
		});

		it("re-reads and returns a fresh array when config content changes", async () => {
			tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-cache2-"));
			const agentDir = join(tempRoot, "agent");
			mkdirSync(agentDir, { recursive: true });
			const configPath = join(agentDir, "mcp.json");
			writeFileSync(configPath, JSON.stringify({ mcpServers: { a: { transport: "stdio", command: "node" } } }));

			const manager = createMcpManager({ cwd: tempRoot, agentDir });
			const first = manager.loadServers();
			expect(first.map((s) => s.id)).toEqual(["a"]);

			// Wait so mtime definitely advances; change content (size changes).
			await new Promise((r) => setTimeout(r, 20));
			writeFileSync(
				configPath,
				JSON.stringify({
					mcpServers: {
						a: { transport: "stdio", command: "node" },
						b: { transport: "stdio", command: "node" },
					},
				}),
			);

			const second = manager.loadServers();
			expect(second).not.toBe(first); // new reference — cache invalidated
			expect(second.map((s) => s.id)).toEqual(["a", "b"]);
		});
	});

	describe("FIX 3 — writeTextArtifact atomic write", () => {
		it("writes the artifact via atomicWriteFileSync with 0o600 mode", () => {
			tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-atomic-"));
			const agentDir = join(tempRoot, "agent");
			mkdirSync(agentDir, { recursive: true });

			const manager = createMcpManager({ cwd: tempRoot, agentDir });
			const text = `artifact-body-${"x".repeat(100)}`;
			const spy = vi.spyOn(atomicWrite, "atomicWriteFileSync");

			const artifact = (manager as any).writeTextArtifact("srv", "tool", 0, text) as {
				path: string;
				sha256: string;
				bytes: number;
			};

			expect(spy).toHaveBeenCalledTimes(1);
			expect(spy.mock.calls[0][0]).toBe(artifact.path);
			expect(spy.mock.calls[0][1]).toBe(text);
			// 0o600 mode preserved.
			expect(statSync(artifact.path).mode & 0o777).toBe(0o600);
			expect(artifact.bytes).toBe(Buffer.byteLength(text, "utf8"));
			spy.mockRestore();
		});
	});
});

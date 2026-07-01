import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, test } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";
import { RpcClient } from "../src/modes/rpc/rpc-client.ts";

const tempDirs: string[] = [];
const tempRoots: string[] = [];

afterEach(() => {
	for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
	for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

// ===========================================================================
// Fix 1 — RpcClient awaiting methods must reject on process exit (opt #105)
// ===========================================================================

function writeChildScript(contents: string): string {
	const dir = mkdtempSync(join(tmpdir(), "pi-rpc-opt105-"));
	tempDirs.push(dir);
	const path = join(dir, "child.mjs");
	writeFileSync(path, contents);
	return path;
}

describe("opt #105 fix 1 — RpcClient waiter rejection on process exit", () => {
	test("waitForIdle rejects promptly when the agent process is killed (not after 60s)", async () => {
		// Child stays alive (resumed stdin, no agent_end emitted) so the only way
		// waitForIdle resolves/rejects is via the exit path. Pre-fix the exit
		// handler only rejected pendingRequests (send() waiters); onEvent-based
		// waiters hung for the full 60s timeout.
		const client = new RpcClient({
			cliPath: writeChildScript(`
process.stdin.resume();
`),
		});

		await client.start();

		const idle = client.waitForIdle(60000);

		// Kill the underlying child process; the 'exit' handler must reject the
		// active waiter within ~2s, NOT 60s.
		const child = (client as unknown as { process: { kill: (sig: NodeJS.Signals) => void } }).process;
		child.kill("SIGKILL");

		await expect(idle).rejects.toThrow(/Agent process exited/);
	}, 10000);

	test("collectEvents rejects promptly when the agent process is killed", async () => {
		const client = new RpcClient({
			cliPath: writeChildScript(`
process.stdin.resume();
`),
		});

		await client.start();

		const events = client.collectEvents(60000);
		const child = (client as unknown as { process: { kill: (sig: NodeJS.Signals) => void } }).process;
		child.kill("SIGKILL");

		await expect(events).rejects.toThrow(/Agent process exited/);
	}, 10000);
});

// ===========================================================================
// Fix 2 — StdioJsonRpcClient.close() tracks/clears the SIGKILL grace timer
// ===========================================================================

function writeFakeMcpServer(tempRoot: string): string {
	const fakeServer = join(tempRoot, "fake-mcp-opt105.mjs");
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

describe("opt #105 fix 2 — StdioJsonRpcClient SIGKILL grace timer cleared on child exit", () => {
	it("clears killGraceTimer when the child exits promptly on SIGTERM", async () => {
		const tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-opt105-"));
		tempRoots.push(tempRoot);
		const agentDir = join(tempRoot, "agent");
		const fakeServer = writeFakeMcpServer(tempRoot);
		writeMcpConfig(agentDir, fakeServer);

		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		// Instantiate the stdio client by calling a tool.
		await manager.callTool("fake", "echo", { text: "hi" });

		const pool = (
			manager as unknown as {
				clientPool: Map<
					string,
					{ client: { close: () => void; child: { on: (ev: string, cb: () => void) => void }; isClosed: boolean } }
				>;
			}
		).clientPool;
		const entry = pool.values().next().value;
		expect(entry).toBeDefined();
		const client = entry!.client;
		expect(client).toBeDefined();

		// close() sends SIGTERM and arms the 1s SIGKILL escalation timer.
		client.close();

		// Wait for the child 'close' event (the handler clears the timer).
		await new Promise<void>((resolve) => {
			client.child.on("close", () => resolve());
			// Safety timeout in case 'close' never fires.
			setTimeout(resolve, 3000);
		});
		// Yield once more so the close handler's synchronous clear runs before we
		// inspect the field.
		await new Promise<void>((r) => setTimeout(r, 10));

		const killGraceTimer = (client as unknown as { killGraceTimer: unknown }).killGraceTimer;
		expect(killGraceTimer).toBeUndefined();
	}, 15000);
});

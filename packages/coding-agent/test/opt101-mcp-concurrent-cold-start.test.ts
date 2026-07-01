import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

/** Stdio MCP fake server: initialize + tools/list + tools/call. Stays alive until killed. */
function writeFakeMcpServer(tempRoot: string): string {
	const fakeServer = join(tempRoot, "fake-mcp-concurrent.mjs");
	writeFileSync(
		fakeServer,
		`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { tools: {} } } }));
 if (msg.method === "tools/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [] } }));
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

describe("McpManager concurrent cold-start (opt #101 F1)", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("serializes pooled-client creation per key — two concurrent cold-start calls spawn ONE child, not two (no orphan)", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-conc-"));
		const agentDir = join(tempRoot, "agent");
		const fakeServer = writeFakeMcpServer(tempRoot);
		writeMcpConfig(agentDir, fakeServer);

		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const managerAny = manager as unknown as {
			createInitializedClient: (entry: unknown, signal?: unknown) => Promise<unknown>;
			clientPool: Map<string, unknown>;
		};
		// Capture the real create before spying, then wrap it with a small delay so
		// the second concurrent caller enters getPooledClient before the first's
		// create resolves — the exact race that orphaned the first child pre-fix.
		const originalCreate = managerAny.createInitializedClient.bind(manager);
		const createSpy = vi
			.spyOn(managerAny, "createInitializedClient")
			.mockImplementation(async (entry: unknown, signal?: unknown) => {
				await new Promise((r) => setTimeout(r, 5));
				return originalCreate(entry, signal);
			});

		const [a, b] = await Promise.all([
			manager.callTool("fake", "echo", { text: "a" }),
			manager.callTool("fake", "echo", { text: "b" }),
		]);

		// Both calls succeed.
		expect(a).toBeDefined();
		expect(b).toBeDefined();
		// createInitializedClient called exactly once — the second concurrent
		// waiter reused the first's in-flight creation. Pre-fix this was 2 (and
		// the first child was orphaned: overwritten in clientPool, never reaped).
		expect(createSpy).toHaveBeenCalledTimes(1);
		// Exactly one pooled entry — no orphan child overwriting it.
		expect(managerAny.clientPool.size).toBeLessThanOrEqual(1);

		await manager.closeAll();
	});
});

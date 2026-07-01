import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

/**
 * Stdio MCP fake server: initialize succeeds, but tools/list returns a JSON-RPC
 * error (tools is an optional MCP capability — a server can legitimately reject
 * tools/list). Pre-fix probeEntry swallowed this and reported ok:true / tools:[]
 * with NO error field, hiding the broken server as "healthy, no tools".
 */
function writeFakeMcpServer(tempRoot: string): string {
	const fakeServer = join(tempRoot, "fake-mcp-probe.mjs");
	writeFileSync(
		fakeServer,
		`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: {} } }));
 if (msg.method === "tools/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "tools not supported" } }));
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

describe("McpManager probeEntry surfaces tools/list errors (opt #101 F2)", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("reports ok:true (initialize-reachable) with the tools/list failure in error, instead of hiding it", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-probe-"));
		const agentDir = join(tempRoot, "agent");
		const fakeServer = writeFakeMcpServer(tempRoot);
		writeMcpConfig(agentDir, fakeServer);

		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const probe = await manager.probeServer("fake");

		// initialize succeeded → ok stays true (probe.ok-gated callers behave
		// identically). tools is empty because tools/list failed.
		expect(probe.ok).toBe(true);
		expect(probe.tools).toEqual([]);
		// The tools/list failure is now surfaced (pre-fix: error was undefined).
		expect(probe.error).toBeTruthy();
		expect(probe.error).toContain("tools not supported");

		await manager.closeAll();
	});
});

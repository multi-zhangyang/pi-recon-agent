import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

describe("McpManager", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("loads configs from REPI home and redacts config display", () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: { demo: { transport: "stdio", command: "node", env: { DEMO_TOKEN: "plain-token" } } },
			}),
		);
		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		expect(manager.loadServers()).toHaveLength(1);
		const text = manager.formatConfig();
		expect(text).toContain("demo");
		expect(text).not.toContain("plain-token");
	});

	it("probes a stdio MCP server and lists tools", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		const fakeServer = join(tempRoot, "fake-mcp.mjs");
		writeFileSync(
			fakeServer,
			`import readline from "node:readline";\nconst rl = readline.createInterface({ input: process.stdin });\nrl.on("line", (line) => {\n const msg = JSON.parse(line);\n if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { tools: {} } } }));\n if (msg.method === "tools/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", description: "Echo text", inputSchema: { type: "object" } }] } }));\n});\n`,
		);
		chmodSync(fakeServer, 0o700);
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: { fake: { transport: "stdio", command: process.execPath, args: [fakeServer] } },
			}),
		);

		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const result = await manager.probeServer("fake");
		expect(result.ok).toBe(true);
		expect(result.tools.map((tool) => tool.name)).toEqual(["echo"]);
		expect(manager.formatProbeResults([result])).toContain("tool: echo");
	});
});

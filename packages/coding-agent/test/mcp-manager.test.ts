import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

	it("calls MCP tools and generates runtime tool definitions", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		const fakeServer = join(tempRoot, "fake-mcp-call.mjs");
		writeFileSync(
			fakeServer,
			`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { tools: {} } } }));
 if (msg.method === "tools/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", description: "Echo text", inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } }, { name: "blocked", description: "Blocked", inputSchema: { type: "object" } }] } }));
 if (msg.method === "tools/call") {
  const text = msg.params.arguments.text === "large" ? "x".repeat(21050) + " token=sk-secret-1234567890" : "echo:" + msg.params.arguments.text;
  console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text }], isError: false } }));
 }
});
`,
		);
		chmodSync(fakeServer, 0o700);
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: {
					fake: {
						transport: "stdio",
						command: process.execPath,
						args: [fakeServer],
						autoRegisterTools: true,
						allowedTools: ["echo"],
					},
				},
			}),
		);

		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const callResult = await manager.callTool("fake", "echo", { text: "hi" });
		expect(callResult.isError).toBe(false);
		expect(callResult.content).toEqual([{ type: "text", text: "echo:hi" }]);

		const proxies = manager.createProxyToolDefinitions();
		expect(proxies.map((tool) => tool.name)).toEqual(["mcp__fake__call"]);
		const proxyResult = await proxies[0].execute(
			"tool-call-1",
			{ tool: "echo", arguments: { text: "proxy" } },
			undefined,
			undefined,
			{} as any,
		);
		expect(proxyResult.content).toEqual([{ type: "text", text: "echo:proxy" }]);

		const definitions = await manager.createToolDefinitions();
		expect(definitions.map((tool) => tool.name)).toEqual(["mcp__fake__echo"]);
		const directResult = await definitions[0].execute(
			"tool-call-2",
			{ text: "direct" },
			undefined,
			undefined,
			{} as any,
		);
		expect(directResult.content).toEqual([{ type: "text", text: "echo:direct" }]);

		const largeResult = await manager.callTool("fake", "echo", { text: "large" });
		expect(largeResult.details.artifacts).toHaveLength(1);
		const artifact = largeResult.details.artifacts?.[0];
		expect(artifact?.bytes).toBeGreaterThan(20000);
		expect(String(largeResult.content[0].type === "text" ? largeResult.content[0].text : "")).toContain(
			"MCP output stored as artifact",
		);
		const artifactText = readFileSync(String(artifact?.path), "utf8");
		expect(artifactText).toContain("<redacted>");
		expect(artifactText).not.toContain("sk-secret-1234567890");
		await expect(manager.callTool("fake", "blocked", {})).rejects.toThrow("not allowed");
	});
});

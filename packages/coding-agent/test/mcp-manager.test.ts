import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
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
  const text = msg.params.arguments.text === "large" ? "x".repeat(21050) + " token=synthetic-redaction-value" : "echo:" + msg.params.arguments.text;
  console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text }], isError: false } }));
 }
 if (msg.method === "resources/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { resources: [{ uri: "file:///demo.txt", name: "demo", mimeType: "text/plain", description: "Demo resource" }] } }));
 if (msg.method === "resources/read") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { contents: [{ uri: msg.params.uri, mimeType: "text/plain", text: "resource-body token=synthetic-redaction-value" }] } }));
 if (msg.method === "prompts/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { prompts: [{ name: "triage", description: "Triage target", arguments: [{ name: "target", required: true }] }] } }));
 if (msg.method === "prompts/get") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { description: "Triage target", messages: [{ role: "user", content: { type: "text", text: "triage " + msg.params.arguments.target + " token=synthetic-redaction-value" } }] } }));
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
		expect(proxies.map((tool) => tool.name)).toEqual([
			"mcp__fake__call",
			"mcp__fake__search_tools",
			"mcp__fake__list_resources",
			"mcp__fake__read_resource",
			"mcp__fake__list_prompts",
			"mcp__fake__get_prompt",
		]);
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

		const searchResult = await proxies[1].execute(
			"tool-call-s1",
			{ query: "echo", limit: 5, includeSchema: true },
			undefined,
			undefined,
			{} as any,
		);
		expect(String(searchResult.content[0].type === "text" ? searchResult.content[0].text : "")).toContain(
			"MCP tool search: fake",
		);
		expect(String(searchResult.content[0].type === "text" ? searchResult.content[0].text : "")).toContain(
			"inputSchema=",
		);

		const resources = await manager.listResources("fake");
		expect(resources.ok).toBe(true);
		expect(resources.resources.map((resource) => resource.uri)).toEqual(["file:///demo.txt"]);
		const listResourceResult = await proxies[2].execute("tool-call-r1", {}, undefined, undefined, {} as any);
		expect(String(listResourceResult.content[0].type === "text" ? listResourceResult.content[0].text : "")).toContain(
			"file:///demo.txt",
		);
		const readResourceResult = await proxies[3].execute(
			"tool-call-r2",
			{ uri: "file:///demo.txt" },
			undefined,
			undefined,
			{} as any,
		);
		expect(String(readResourceResult.content[0].type === "text" ? readResourceResult.content[0].text : "")).toContain(
			"resource-body token=<redacted>",
		);

		const prompts = await manager.listPrompts("fake");
		expect(prompts.ok).toBe(true);
		expect(prompts.prompts.map((prompt) => prompt.name)).toEqual(["triage"]);
		const listPromptResult = await proxies[4].execute("tool-call-p1", {}, undefined, undefined, {} as any);
		expect(String(listPromptResult.content[0].type === "text" ? listPromptResult.content[0].text : "")).toContain(
			"name=triage",
		);
		const getPromptResult = await proxies[5].execute(
			"tool-call-p2",
			{ name: "triage", arguments: { target: "example.test" } },
			undefined,
			undefined,
			{} as any,
		);
		expect(String(getPromptResult.content[0].type === "text" ? getPromptResult.content[0].text : "")).toContain(
			"triage example.test token=<redacted>",
		);

		const largeResult = await manager.callTool("fake", "echo", { text: "large" });
		expect(largeResult.details.artifacts).toHaveLength(1);
		const artifact = largeResult.details.artifacts?.[0];
		expect(artifact?.bytes).toBeGreaterThan(20000);
		expect(String(largeResult.content[0].type === "text" ? largeResult.content[0].text : "")).toContain(
			"MCP output stored as artifact",
		);
		const artifactText = readFileSync(String(artifact?.path), "utf8");
		expect(artifactText).toContain("<redacted>");
		expect(artifactText).not.toContain("synthetic-redaction-value");
		await expect(manager.callTool("fake", "blocked", {})).rejects.toThrow("not allowed");
	});

	it("probes and calls streamable HTTP MCP servers with env-backed headers", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-http-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		const requests: Array<{ method?: string; headers: Record<string, string | string[] | undefined>; body: any }> =
			[];
		const server = createServer((req, res) => {
			if (req.method === "GET" && req.url === "/.well-known/oauth-protected-resource") {
				res.writeHead(200, { "content-type": "application/json" }).end(
					JSON.stringify({
						resource: `http://${req.headers.host}/mcp`,
						authorization_servers: [`http://${req.headers.host}/.well-known/oauth-authorization-server`],
					}),
				);
				return;
			}
			let body = "";
			req.setEncoding("utf8");
			req.on("data", (chunk) => {
				body += chunk;
			});
			req.on("end", () => {
				const parsed = body ? JSON.parse(body) : {};
				requests.push({ method: req.method, headers: req.headers, body: parsed });
				if (req.method === "DELETE") {
					res.writeHead(202).end();
					return;
				}
				if (req.headers.authorization !== "Bearer http-test-token") {
					res.writeHead(401, {
						"www-authenticate": `Bearer resource_metadata="http://${req.headers.host}/.well-known/oauth-protected-resource"`,
					}).end("bad auth");
					return;
				}
				if (parsed.method !== "initialize" && req.headers["mcp-session-id"] !== "session-1") {
					res.writeHead(404).end("missing session");
					return;
				}
				if (parsed.method === "initialize") {
					res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "session-1" }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: {
								protocolVersion: "2025-11-25",
								serverInfo: { name: "httpfake" },
								capabilities: { tools: {}, prompts: {} },
							},
						}),
					);
					return;
				}
				if (parsed.method === "notifications/initialized") {
					res.writeHead(202).end();
					return;
				}
				if (parsed.method === "tools/list") {
					res.writeHead(200, { "content-type": "text/event-stream" }).end(
						`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: parsed.id, result: { tools: [{ name: "echo", description: "HTTP echo", inputSchema: { type: "object" } }] } })}\n\n`,
					);
					return;
				}
				if (parsed.method === "tools/call") {
					res.writeHead(200, { "content-type": "application/json" }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: {
								content: [{ type: "text", text: `http:${parsed.params.arguments.text}` }],
								isError: false,
							},
						}),
					);
					return;
				}
				if (parsed.method === "prompts/list") {
					res.writeHead(200, { "content-type": "application/json" }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: { prompts: [{ name: "triage", description: "HTTP triage" }] },
						}),
					);
					return;
				}
				if (parsed.method === "prompts/get") {
					res.writeHead(200, { "content-type": "application/json" }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: {
								description: "HTTP triage",
								messages: [
									{
										role: "user",
										content: { type: "text", text: `triage ${parsed.params.arguments.target}` },
									},
								],
							},
						}),
					);
					return;
				}
				res.writeHead(404).end("unknown method");
			});
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		process.env.MCP_TEST_TOKEN = "http-test-token";
		try {
			const address = server.address();
			if (!address || typeof address === "string") throw new Error("missing test server address");
			writeFileSync(
				join(agentDir, "mcp.json"),
				JSON.stringify({
					mcpServers: {
						httpfake: {
							transport: "http",
							url: `http://127.0.0.1:${address.port}/mcp`,
							headers: { Authorization: "Bearer $MCP_TEST_TOKEN" },
							autoRegisterTools: true,
						},
					},
				}),
			);
			const manager = createMcpManager({ cwd: tempRoot, agentDir });
			const authInfo = await manager.inspectAuth("httpfake");
			expect(authInfo.ok).toBe(true);
			expect(authInfo.wwwAuthenticate).toContain("resource_metadata=");
			expect(JSON.stringify(authInfo.resourceMetadata)).toContain("authorization_servers");
			const probe = await manager.probeServer("httpfake");
			expect(probe.ok).toBe(true);
			expect(probe.transport).toBe("http");
			expect(probe.tools.map((tool) => tool.name)).toEqual(["echo"]);
			const callResult = await manager.callTool("httpfake", "echo", { text: "live" });
			expect(callResult.content).toEqual([{ type: "text", text: "http:live" }]);
			const prompts = await manager.listPrompts("httpfake");
			expect(prompts.prompts.map((prompt) => prompt.name)).toEqual(["triage"]);
			const prompt = await manager.getPrompt("httpfake", "triage", { target: "example.test" });
			expect(String(prompt.content[0].type === "text" ? prompt.content[0].text : "")).toContain(
				"triage example.test",
			);
			expect(requests.some((request) => request.body.method === "tools/list")).toBe(true);
			expect(
				requests
					.filter((request) => request.body.method && request.body.method !== "initialize")
					.every((request) => request.headers["mcp-session-id"] === "session-1"),
			).toBe(true);
			expect(
				requests
					.filter((request) => request.body.method && request.body.method !== "initialize")
					.every((request) => request.headers.authorization === "Bearer http-test-token"),
			).toBe(true);
			expect(manager.formatConfig()).not.toContain("http-test-token");
		} finally {
			delete process.env.MCP_TEST_TOKEN;
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	});

	it("reuses pooled HTTP MCP sessions and reconnects once on stale session errors", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-pool-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		let initCount = 0;
		let currentSession = "";
		let staleFailureInjected = false;
		const server = createServer((req, res) => {
			let body = "";
			req.setEncoding("utf8");
			req.on("data", (chunk) => {
				body += chunk;
			});
			req.on("end", () => {
				const parsed = body ? JSON.parse(body) : {};
				if (req.method === "DELETE") {
					res.writeHead(202).end();
					return;
				}
				if (parsed.method === "initialize") {
					currentSession = `session-${++initCount}`;
					res.writeHead(200, { "content-type": "application/json", "mcp-session-id": currentSession }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: { protocolVersion: "2025-11-25", capabilities: { tools: {} } },
						}),
					);
					return;
				}
				if (req.headers["mcp-session-id"] !== currentSession) {
					res.writeHead(404).end("stale session");
					return;
				}
				if (parsed.method === "notifications/initialized") {
					res.writeHead(202).end();
					return;
				}
				if (parsed.method === "tools/list") {
					res.writeHead(200, { "content-type": "application/json" }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: { tools: [{ name: "echo", description: "Echo", inputSchema: { type: "object" } }] },
						}),
					);
					return;
				}
				if (
					parsed.method === "tools/call" &&
					parsed.params.arguments.text === "reconnect" &&
					!staleFailureInjected
				) {
					staleFailureInjected = true;
					res.writeHead(503).end("temporary stale session");
					return;
				}
				if (parsed.method === "tools/call") {
					res.writeHead(200, { "content-type": "application/json" }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: {
								content: [{ type: "text", text: `pool:${parsed.params.arguments.text}` }],
								isError: false,
							},
						}),
					);
					return;
				}
				res.writeHead(404).end("unknown method");
			});
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		try {
			const address = server.address();
			if (!address || typeof address === "string") throw new Error("missing test server address");
			writeFileSync(
				join(agentDir, "mcp.json"),
				JSON.stringify({
					mcpServers: {
						pooled: {
							transport: "http",
							url: `http://127.0.0.1:${address.port}/mcp`,
							autoRegisterTools: true,
							poolIdleMs: 5000,
						},
					},
				}),
			);
			const manager = createMcpManager({ cwd: tempRoot, agentDir });
			const probe = await manager.probeServer("pooled");
			expect(probe.ok).toBe(true);
			expect(initCount).toBe(1);
			const pooledCall = await manager.callTool("pooled", "echo", { text: "reuse" });
			expect(pooledCall.content).toEqual([{ type: "text", text: "pool:reuse" }]);
			expect(initCount).toBe(1);
			const reconnectCall = await manager.callTool("pooled", "echo", { text: "reconnect" });
			expect(reconnectCall.content).toEqual([{ type: "text", text: "pool:reconnect" }]);
			expect(initCount).toBe(2);
			await manager.closeAll();
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	});

	it("rejects in-flight requests immediately when the stdio client is closed", async () => {
		// A server that answers initialize/tools/list but silently ignores
		// tools/call → the request stays pending. Closing the client must reject
		// it with "MCP client closed" (the explicit close() rejectAll) rather than
		// waiting for the per-request 10s timeout or the child 'close' event
		// (which would surface as "MCP server exited ..." and trigger a retry).
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		const fakeServer = join(tempRoot, "fake-mcp-pending.mjs");
		writeFileSync(
			fakeServer,
			`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { tools: {} } } }));
 if (msg.method === "tools/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", description: "Echo", inputSchema: { type: "object" } }] } }));
 // tools/call intentionally never answered → request hangs.
});
`,
		);
		chmodSync(fakeServer, 0o700);
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: {
					fake: { transport: "stdio", command: process.execPath, args: [fakeServer], allowedTools: ["echo"] },
				},
			}),
		);
		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		// Probe first so the client is initialized and pooled; tools/call is then
		// the only pending request.
		const probe = await manager.probeServer("fake");
		expect(probe.ok).toBe(true);
		const pending = manager.callTool("fake", "echo", { text: "hi" });
		// Give the request a moment to be sent, then tear down.
		await new Promise<void>((resolve) => setTimeout(resolve, 150));
		await manager.closeAll();
		await expect(
			Promise.race([
				pending,
				new Promise<never>((_, reject) => setTimeout(() => reject(new Error("callTool hung")), 5000)),
			]),
		).rejects.toThrow("MCP client closed");
	});
});

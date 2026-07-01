import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

// Regression guard for the StreamableHttpJsonRpcClient.post id-fallback bug. The previous code:
//   const messageResult = messages.find((item) => item?.id === expectId)
//                        ?? messages.find((item) => item?.id !== undefined);
// The `??` fallback returns the FIRST message with ANY defined id, even one NOT matching expectId.
// In a streamable-HTTP/SSE response a server may emit a result for an EARLIER request (one that
// timed out client-side but wasn't cancelled server-side). That stray result was returned as the
// result of the CURRENT tools/call → the caller got data belonging to a DIFFERENT tool, surfaced to
// the model as if it were the answer. Fix: drop the fallback; if no message has id === expectId,
// throw `MCP HTTP response did not contain a result for id=<expectId>`. The stdio client is immune
// (per-instance monotonic ids); only the HTTP client has this bug.
//
// We drive the REAL StreamableHttpJsonRpcClient.post via the proven createMcpManager→callTool HTTP
// path (mirrors mcp-manager.test.ts's http server pattern). On tools/call the fake server responds
// with an SSE body containing a result for a STRAY id (not the tools/call id) and NO result for the
// real id. Pre-fix: callTool resolves to the stray payload (wrong tool's data). Post-fix: callTool
// rejects with the id-mismatch error.

describe("MCP HTTP response id fallback (StreamableHttpJsonRpcClient.post)", () => {
	let tempRoot: string | undefined;
	let server: ReturnType<typeof createServer> | undefined;

	afterEach(async () => {
		if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
		server = undefined;
		if (tempRoot) {
			rmSync(tempRoot, { recursive: true, force: true });
			tempRoot = undefined;
		}
	});

	it("rejects when the response contains only a stray result for a different id (no id===expectId match)", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-idfb-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });

		let toolsCallId = -1;
		server = createServer((req, res) => {
			let body = "";
			req.setEncoding("utf8");
			req.on("data", (chunk) => {
				body += chunk;
			});
			req.on("end", () => {
				const parsed = body ? JSON.parse(body) : {};
				if (parsed.method === "initialize") {
					res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "sess-1" }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: {
								protocolVersion: "2025-11-25",
								serverInfo: { name: "httpfake" },
								capabilities: { tools: {} },
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
					res.writeHead(200, { "content-type": "application/json" }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: { tools: [{ name: "echo", description: "echo", inputSchema: { type: "object" } }] },
						}),
					);
					return;
				}
				if (parsed.method === "tools/call") {
					// Respond with an SSE body whose ONLY result carries a STRAY id (not parsed.id).
					// This models a server emitting a result for an earlier request that timed out
					// client-side but wasn't cancelled server-side. Pre-fix the `?? any-id` fallback
					// returns this stray as the tools/call result; post-fix post() throws.
					toolsCallId = parsed.id;
					const strayId = parsed.id + 1000;
					const strayPayload = {
						jsonrpc: "2.0",
						id: strayId,
						result: { content: [{ type: "text", text: `STRAY-BELONGS-TO-ID-${strayId}` }], isError: false },
					};
					res.writeHead(200, { "content-type": "text/event-stream" }).end(
						`event: message\ndata: ${JSON.stringify(strayPayload)}\n\n`,
					);
					return;
				}
				res.writeHead(404).end("unknown method");
			});
		});
		await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
		const address = server!.address();
		if (!address || typeof address === "string") throw new Error("missing test server address");

		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: {
					httpfake: { transport: "http", url: `http://127.0.0.1:${address.port}/mcp` },
				},
			}),
		);
		const manager = createMcpManager({ cwd: tempRoot, agentDir });

		// tools/list first so the client is pooled with a known next id, then callTool whose
		// response is the stray-id SSE body above.
		await manager.callTool("httpfake", "echo", { text: "hi" }).then(
			() => {
				throw new Error("callTool unexpectedly resolved with a stray-id result");
			},
			(error) => {
				// Post-fix: post() throws `MCP HTTP response did not contain a result for id=<n>`.
				// Pre-fix: callTool resolves with content "STRAY-BELONGS-TO-ID-<strayId>" (wrong
				// tool's data) → the .then error above fires instead, and this branch never runs.
				expect(toolsCallId).toBeGreaterThan(-1);
				expect(String(error?.message ?? error)).toMatch(/MCP HTTP response did not contain a result for id=/);
			},
		);

		await manager.closeAll();
	});

	it("still resolves correctly when the response contains a matching id (parity, no false negative)", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-idfb-ok-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });

		server = createServer((req, res) => {
			let body = "";
			req.setEncoding("utf8");
			req.on("data", (chunk) => {
				body += chunk;
			});
			req.on("end", () => {
				const parsed = body ? JSON.parse(body) : {};
				if (parsed.method === "initialize") {
					res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "sess-1" }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: {
								protocolVersion: "2025-11-25",
								serverInfo: { name: "httpfake" },
								capabilities: { tools: {} },
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
					res.writeHead(200, { "content-type": "application/json" }).end(
						JSON.stringify({
							jsonrpc: "2.0",
							id: parsed.id,
							result: { tools: [{ name: "echo", description: "echo", inputSchema: { type: "object" } }] },
						}),
					);
					return;
				}
				if (parsed.method === "tools/call") {
					// A PRIOR stray result (id 999999, no pending request) followed by the REAL
					// matching result. The fix must still locate the matching-id result among
					// multiple messages and return it — dropping the fallback must not regress the
					// normal multi-message SSE case.
					const stray = { jsonrpc: "2.0", id: 999999, result: { content: [{ type: "text", text: "STRAY" }] } };
					const real = {
						jsonrpc: "2.0",
						id: parsed.id,
						result: { content: [{ type: "text", text: `http:${parsed.params.arguments.text}` }], isError: false },
					};
					res.writeHead(200, { "content-type": "text/event-stream" }).end(
						`event: message\ndata: ${JSON.stringify(stray)}\n\nevent: message\ndata: ${JSON.stringify(real)}\n\n`,
					);
					return;
				}
				res.writeHead(404).end("unknown method");
			});
		});
		await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
		const address = server!.address();
		if (!address || typeof address === "string") throw new Error("missing test server address");

		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: {
					httpfake: { transport: "http", url: `http://127.0.0.1:${address.port}/mcp` },
				},
			}),
		);
		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const result = await manager.callTool("httpfake", "echo", { text: "live" });
		expect(result.content).toEqual([{ type: "text", text: "http:live" }]);
		await manager.closeAll();
	});
});

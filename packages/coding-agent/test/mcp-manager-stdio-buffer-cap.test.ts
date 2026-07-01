import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { McpManager } from "../src/core/mcp-manager.ts";

// Regression guard for the StdioJsonRpcClient stdout framing-buffer cap bug (opt #59 cap, bug #8).
// onStdout capped `this.buffer` at MCP_STDIO_BUFFER_MAX_CHARS but on overflow only did
// `this.buffer = ""` and returned — it did NOT rejectAll the in-flight request and did NOT set
// `this.closed = true`. The in-flight tools/call whose response was being buffered was left in
// `this.pending` and only resolved/rejected when the per-request setTimeout fired (a silent bounded
// hang). Worse, the client was NOT marked closed so the warm pool reused it for the next call →
// repeated bounded hangs on every subsequent call until the child exited. The Content-Length branch
// (consumeContentLengthMessage length-reject) had the same gap.
//
// Fix: when the cap is hit (both branches), call fatalFramingOverflow() — rejectAll with a framing
// error, set closed=true, and kill the runaway child (mirroring close()). The in-flight request
// rejects with a framing error (NOT a timeout) and isClosed is true so the warm pool drops it.
//
// We exercise the REAL onStdout wiring via the proven callTool→clientPool path (mirrors
// mcp-stdio-buffer-cap.test.ts) with a tiny REPI_MCP_STDIO_BUFFER_MAX_CHARS env override so the cap
// is easy to trip without a 10MB chunk. The constant is captured at module-eval time, so the module
// is re-imported fresh with the env set (mirrors mcp-http-body-bound.test.ts importWithEnv). To
// observe isClosed on the SAME client that overflowed, we first pool the client with a small
// successful echo (response under the cap) and capture its reference, THEN issue the overflowing
// call — withInitializedMcpClient's catch removes the dead client from the pool, but we still hold
// the reference.

/** Re-import the module fresh so MCP_STDIO_BUFFER_MAX_CHARS picks up the env override. */
async function importWithEnv(envValue: string | undefined): Promise<typeof import("../src/core/mcp-manager.ts")> {
	vi.resetModules();
	if (envValue === undefined) delete process.env.REPI_MCP_STDIO_BUFFER_MAX_CHARS;
	else process.env.REPI_MCP_STDIO_BUFFER_MAX_CHARS = envValue;
	return await import("../src/core/mcp-manager.ts");
}

/** A stdio MCP fake: initialize (small), tools/list, and tools/call echoes the text arg. The echo
 * response length is controlled by the caller via the `text` argument so a test can force a response
 * that exceeds the tiny cap (a large `text` → a single newline-delimited line > cap). */
function writeFakeMcpServer(tempRoot: string): string {
	const fakeServer = join(tempRoot, "fake-mcp-overflow.mjs");
	writeFileSync(
		fakeServer,
		`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "f" }, capabilities: { tools: {} } } }));
 if (msg.method === "tools/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", description: "echo", inputSchema: { type: "object" } }] } }));
 if (msg.method === "tools/call") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "echo:" + (msg.params.arguments?.text ?? "") }], isError: false } }));
});
`,
	);
	chmodSync(fakeServer, 0o700);
	return fakeServer;
}

/** A stdio MCP fake whose tools/call prefixes a corrupt Content-Length: 999999999 header when the
 * text arg is the sentinel "overflow" (>> any test cap → consumeContentLengthMessage length-reject).
 * Otherwise it emits a normal small newline-delimited echo so a prior call can pool the client. */
function writeFakeMcpServerContentLength(tempRoot: string): string {
	const fakeServer = join(tempRoot, "fake-mcp-cl.mjs");
	writeFileSync(
		fakeServer,
		`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "f" }, capabilities: { tools: {} } } }));
 if (msg.method === "tools/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", description: "echo", inputSchema: { type: "object" } }] } }));
 if (msg.method === "tools/call") {
  const body = JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "echo:" + (msg.params.arguments?.text ?? "") }], isError: false } });
  if (msg.params.arguments?.text === "overflow") process.stdout.write("Content-Length: 999999999\\n\\n" + body + "\\n");
  else console.log(body);
 }
});
`,
	);
	chmodSync(fakeServer, 0o700);
	return fakeServer;
}

function writeMcpConfig(agentDir: string, fakeServer: string, timeoutMs: number): void {
	mkdirSync(agentDir, { recursive: true });
	writeFileSync(
		join(agentDir, "mcp.json"),
		JSON.stringify({
			mcpServers: {
				fake: {
					transport: "stdio",
					command: process.execPath,
					args: [fakeServer],
					// Short request timeout so the PRE-FIX neuter (no rejectAll on cap hit) fails
					// fast with a timeout instead of hanging the full default 10s.
					timeoutMs,
				},
			},
		}),
	);
}

/** The minimal initialize response (~95 chars) must fit under the cap and be consumed as a complete
 * newline-delimited line; the overflowing tools/call response must exceed it. 256 leaves margin. */
const CAP = "256";

describe("McpManager stdio stdout buffer cap fatal overflow (bug #8)", () => {
	let tempRoot: string | undefined;
	let manager: McpManager | undefined;
	const savedEnv = process.env.REPI_MCP_STDIO_BUFFER_MAX_CHARS;

	afterEach(async () => {
		vi.resetModules();
		if (savedEnv === undefined) delete process.env.REPI_MCP_STDIO_BUFFER_MAX_CHARS;
		else process.env.REPI_MCP_STDIO_BUFFER_MAX_CHARS = savedEnv;
		if (manager) {
			await manager.closeAll();
			manager = undefined;
		}
		if (tempRoot) {
			rmSync(tempRoot, { recursive: true, force: true });
			tempRoot = undefined;
		}
	});

	it("rejects the in-flight tools/call with a framing error (NOT a timeout) and marks the client closed (line-buffer branch)", async () => {
		const mod = await importWithEnv(CAP);
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-buf-line-"));
		const agentDir = join(tempRoot, "agent");
		const fakeServer = writeFakeMcpServer(tempRoot);
		writeMcpConfig(agentDir, fakeServer, 1000);
		manager = mod.createMcpManager({ cwd: tempRoot, agentDir });

		// Pool the client with a small echo whose response (~75 chars) is well under the 256 cap.
		const small = await manager.callTool("fake", "echo", { text: "hi" });
		expect(small.content).toEqual([{ type: "text", text: "echo:hi" }]);
		const pool = (manager as any).clientPool as Map<string, { client: any }>;
		const client = pool.values().next().value?.client;
		expect(client).toBeDefined();

		// Reuse the warm client for a large echo whose single newline-delimited response (~592
		// chars, no Content-Length) exceeds the cap. Pre-fix: the cap branch clears the buffer and
		// returns; the tools/call response is dropped and the request hangs in `pending` until the
		// 1000ms timeout → rejects with "MCP request timeout: tools/call" (isRetryableMcpError
		// matches, so withInitializedMcpClient retries once → same overflow → same timeout). Post-
		// fix: fatalFramingOverflow rejects immediately with a framing error (NOT retryable) and
		// isClosed === true so the warm pool will not reuse this dead client.
		const largeText = "x".repeat(500);
		await expect(manager.callTool("fake", "echo", { text: largeText })).rejects.toThrow(
			/MCP stdio framing buffer exceeded/,
		);
		expect(client.isClosed).toBe(true);
	});

	it("rejects the in-flight request with a framing error on a corrupt Content-Length header (Content-Length branch)", async () => {
		const mod = await importWithEnv(CAP);
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-buf-cl-"));
		const agentDir = join(tempRoot, "agent");
		const fakeServer = writeFakeMcpServerContentLength(tempRoot);
		writeMcpConfig(agentDir, fakeServer, 1000);
		manager = mod.createMcpManager({ cwd: tempRoot, agentDir });

		// Pool the client with a normal (non-overflow) echo so the client is warm.
		const small = await manager.callTool("fake", "echo", { text: "hi" });
		expect(small.content).toEqual([{ type: "text", text: "echo:hi" }]);
		const pool = (manager as any).clientPool as Map<string, { client: any }>;
		const client = pool.values().next().value?.client;
		expect(client).toBeDefined();

		// tools/call with the "overflow" sentinel → the fake server prefixes
		// Content-Length: 999999999 (>> cap). consumeContentLengthMessage's length-reject branch
		// must fatalFramingOverflow instead of just dropping the header and leaving the in-flight
		// call to time out. Pre-fix: header dropped, response lost, request times out. Post-fix:
		// framing error + isClosed === true.
		await expect(manager.callTool("fake", "echo", { text: "overflow" })).rejects.toThrow(
			/MCP stdio framing buffer exceeded/,
		);
		expect(client.isClosed).toBe(true);
	});
});

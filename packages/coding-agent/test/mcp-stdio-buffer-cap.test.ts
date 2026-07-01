import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

// Regression guard for opt #59 — StdioJsonRpcClient's stdout framing `buffer` was the ONLY unbounded
// in-memory field in the MCP stdio path (stderr was capped at 12000 by opt #36). Two unbounded modes:
// (1) newline-delimited framing waits for a `\n` that never arrives → every chunk appends to `buffer`
// with no eviction → a misbehaving/buggy stdio MCP server that emits an unframed run drives the agent
// to OOM; (2) Content-Length framing buffers until `length` bytes arrive → a corrupt
// `Content-Length: 999999999` header would buffer ~1GB before anything catches it. Fix: cap the buffer
// at MCP_STDIO_BUFFER_MAX_CHARS (default 10M) in onStdout (drop on overflow), and reject an
// absurd/non-finite/negative Content-Length in consumeContentLengthMessage (drop the header, continue
// framing). We exercise the REAL onStdout/consumeContentLengthMessage wiring against the real default
// cap (no env override → no cross-file process.env leakage): construct the client via the proven
// callTool→clientPool path, then inject garbage through the private onStdout and read the private
// `buffer` (both accessed via `as any` — StdioJsonRpcClient is a private class, mirroring the
// mcp-manager-lifecycle.test.ts `(manager as any).clientPool` pattern).

/** A long-lived stdio MCP fake that responds to initialize + tools/call and otherwise stays quiet. */
function writeFakeMcpServer(tempRoot: string): string {
	const fakeServer = join(tempRoot, "fake-mcp-cap.mjs");
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

/** Initialize + pool the stdio client via the real callTool path, then return the private client. */
async function pooledClient(tempRoot: string): Promise<any> {
	const agentDir = join(tempRoot, "agent");
	const fakeServer = writeFakeMcpServer(tempRoot);
	writeMcpConfig(agentDir, fakeServer);
	const manager = createMcpManager({ cwd: tempRoot, agentDir });
	await manager.callTool("fake", "echo", { text: "hi" });
	const pool = (manager as any).clientPool as Map<string, { client: any }>;
	const client = pool.values().next().value?.client;
	// Keep the subprocess alive for the duration of the test; closeAll() is the caller's job.
	(client as any)._manager = manager;
	return client;
}

describe("McpManager stdio stdout buffer cap (opt #59)", () => {
	let tempRoot: string | undefined;
	let manager: ReturnType<typeof createMcpManager> | undefined;

	afterEach(async () => {
		if (manager) {
			await manager.closeAll();
			manager = undefined;
		}
		if (tempRoot) {
			rmSync(tempRoot, { recursive: true, force: true });
			tempRoot = undefined;
		}
	});

	it("caps an unframed newline-mode run instead of growing the buffer unbounded", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-cap-"));
		const client = await pooledClient(tempRoot);
		manager = (client as any)._manager as ReturnType<typeof createMcpManager>;
		expect(client).toBeDefined();

		// Start from a clean framing buffer (any leftover from the initialize/echo responses was
		// already consumed as complete newline-delimited lines).
		(client as any).buffer = "";

		// Feed a single chunk with NO newline that exceeds the 10M cap. Pre-fix: `buffer += chunk`
		// with no `\n` and no `Content-Length:` prefix → the while-loop hits `if (!includes("\n"))
		// break` and KEEPS the whole 10,000,001-char buffer (unbounded growth → OOM). Post-fix: the
		// onStdout cap sees length > MCP_STDIO_BUFFER_MAX_CHARS and resets the buffer to "".
		const overCap = "x".repeat(10_000_001);
		expect(overCap.length).toBe(10_000_001);
		(client as any).onStdout(overCap);

		const buffer = (client as any).buffer as string;
		// Post-fix: dropped. Pre-fix: buffer === overCap (10,000,001 chars) → this assertion FAILS.
		expect(buffer).toBe("");
	});

	it("drops a corrupt absurd Content-Length header instead of buffering toward ~1GB", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-cap-cl-"));
		const client = await pooledClient(tempRoot);
		manager = (client as any)._manager as ReturnType<typeof createMcpManager>;
		expect(client).toBeDefined();
		(client as any).buffer = "";

		// A corrupt Content-Length header declaring a ~1GB body. Pre-fix: consumeContentLengthMessage
		// parsed length=999999999, then `buffer.length < start + length` → returned false → the while
		// loop broke and LEFT the header in `buffer`, which would then buffer every subsequent chunk
		// toward 999999999 bytes (only the onStdout cap would eventually catch it, at ~1GB). Post-fix:
		// the length-reject sees 999999999 > MCP_STDIO_BUFFER_MAX_CHARS → drops the header (slices
		// past it) and returns true → framing continues from an empty buffer.
		(client as any).onStdout("Content-Length: 999999999\n\n");

		const buffer = (client as any).buffer as string;
		// Post-fix: header dropped, buffer empty. Pre-fix: buffer still holds the header (non-empty,
		// waiting for 999999999 bytes) → this assertion FAILS.
		expect(buffer).toBe("");

		// Framing recovered: a subsequent well-formed newline-delimited line is consumed (parsed),
		// not stranded behind the dropped header. id 999 has no pending request so handleMessageLine
		// is a no-op, but the line is consumed from the buffer (proving the header was dropped, not
		// retained as a framing prefix). Pre-fix the line would sit unconsumed behind the 1GB header.
		(client as any).onStdout('{"jsonrpc":"2.0","id":999,"result":{"x":1}}\n');
		const bufferAfter = (client as any).buffer as string;
		expect(bufferAfter).toBe("");
	});
});

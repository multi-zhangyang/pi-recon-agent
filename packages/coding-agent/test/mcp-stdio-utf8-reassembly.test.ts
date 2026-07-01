/**
 * opt #233 — StdioJsonRpcClient decodes stdout as UTF-8 via setEncoding so a
 * multi-byte character split across two pipe chunks is reassembled, not
 * replaced with U+FFFD.
 *
 * Pre-fix, `String(chunk)` ran Buffer.toString('utf8') on EACH stdout chunk
 * independently. A CJK/emoji character split across a ~64KB pipe boundary had
 * its incomplete trailing sequence replaced with U+FFFD on both halves. The
 * newline-delimited JSON still parsed (U+FFFD is valid inside a JSON string),
 * so the model silently received garbled non-ASCII tool output with NO error.
 *
 * The fake server writes a tools/call response containing "世界" (each char 3
 * UTF-8 bytes: 世 = E4 B8 96) split ONE BYTE into 世 (E4 | B8 96) across two
 * process.stdout.write calls with a 15ms gap (forces two 'data' chunks).
 * Pre-fix: "世" becomes U+FFFD×3. Post-fix (setEncoding utf8): the StringDecoder
 * buffers E4, then B8, then 96 → emits 世 intact.
 */
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

function writeFakeMcpServer(tempRoot: string): string {
	const fakeServer = join(tempRoot, "fake-mcp-utf8.mjs");
	writeFileSync(
		fakeServer,
		`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  const msg = JSON.parse(line);
  if (msg.method === "initialize") {
    console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { tools: {} } } }));
    return;
  }
  if (msg.method === "tools/list") {
    console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", inputSchema: { type: "object" } }] } }));
    return;
  }
  if (msg.method === "tools/call") {
    const resp = JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "echo:世界" }], isError: false } }) + "\\n";
    const bytes = Buffer.from(resp, "utf8");
    const head = resp.slice(0, resp.indexOf("世"));
    // Split ONE byte into the 3-byte 世 sequence (E4 | B8 96) — across two writes.
    const splitAt = Buffer.from(head, "utf8").length + 1;
    process.stdout.write(bytes.slice(0, splitAt));
    await new Promise((r) => setTimeout(r, 15));
    process.stdout.write(bytes.slice(splitAt));
  }
});
`,
	);
	chmodSync(fakeServer, 0o700);
	return fakeServer;
}

describe("McpManager stdio stdout UTF-8 reassembly (opt #233)", () => {
	let tempRoot: string | undefined;
	let manager: ReturnType<typeof createMcpManager> | undefined;

	afterEach(async () => {
		if (manager) {
			await manager.closeAll();
			manager = undefined;
		}
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("reassembles a multi-byte character split across two stdout chunks", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-utf8-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		const fakeServer = writeFakeMcpServer(tempRoot);
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: { fake: { transport: "stdio", command: process.execPath, args: [fakeServer] } },
			}),
		);

		manager = createMcpManager({ cwd: tempRoot, agentDir });
		const callResult = await manager.callTool("fake", "echo", { text: "x" });
		const text = String(callResult.content[0]?.type === "text" ? callResult.content[0].text : "");

		// Post-fix: "世界" survived the chunk split intact.
		expect(text).toBe("echo:世界");
		// Pre-fix: the split 世 became U+FFFD replacement chars (silent corruption).
		expect(text).not.toContain("�");
	}, 15000);
});

import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

// opt #140: probeAll used a serial `for…await` — each dead/slow server blocked
// the next for up to its full timeout (DEFAULT_MCP_TIMEOUT_MS 10s), so probing N
// servers took N×timeout in the worst case (head-of-line blocking on `/mcp`
// probe-all / `repi mcp probe`). Fix: Promise.all so the probes run concurrently;
// wall-clock is ~max(one timeout) instead of sum. Each probeEntry targets an
// independent server (per-key create serialization in getPooledClient's
// _inflightClient means different servers never contend on the same child), so
// parallelism is safe. This test stands up TWO slow servers (each delays its
// initialize handshake by 1.5s) and asserts probeAll finishes in well under the
// serial time (~3s) — parallel ~1.5s. Pre-fix (neuter back to a serial for-await)
// the probe takes ~3s and the <2500ms assertion fails. Also asserts result order
// follows the config order (Promise.all preserves input order).

describe("McpManager probeAll parallelism (opt #140)", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	it("probes multiple slow servers concurrently, not serially", async () => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-probeall-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });

		// Two fake servers, each delaying its initialize response by 1500ms so a
		// SERIAL probe would take ~3000ms and a PARALLEL probe ~1500ms.
		const root = tempRoot;
		const mkServer = (name: string) => {
			const path = join(root, `fake-${name}.mjs`);
			writeFileSync(
				path,
				`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") {
  setTimeout(() => console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "${name}" }, capabilities: { tools: {} } } })), 1500);
 }
 if (msg.method === "tools/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "${name}_tool", description: "${name} tool", inputSchema: { type: "object" } }] } }));
});
`,
			);
			chmodSync(path, 0o700);
			return path;
		};

		const serverA = mkServer("alpha");
		const serverB = mkServer("beta");
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: {
					alpha: { transport: "stdio", command: process.execPath, args: [serverA] },
					beta: { transport: "stdio", command: process.execPath, args: [serverB] },
				},
			}),
		);

		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const start = Date.now();
		const results = await manager.probeAll();
		const elapsed = Date.now() - start;

		// Both healthy.
		expect(results.map((r) => r.serverId)).toEqual(["alpha", "beta"]);
		expect(results.every((r) => r.ok)).toBe(true);
		expect(results[0].tools.map((t) => t.name)).toEqual(["alpha_tool"]);
		expect(results[1].tools.map((t) => t.name)).toEqual(["beta_tool"]);

		// Parallel: ~1500ms. Serial would be ~3000ms. Threshold 2500ms gives a
		// wide margin either way (neuter→serial ~3000ms fails this).
		expect(elapsed).toBeLessThan(2500);

		await manager.closeAll();
	});
});

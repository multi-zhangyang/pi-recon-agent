import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpManager } from "../src/core/mcp-manager.ts";

// opt #138: the list_resources / list_prompts proxy tool `execute` functions
// dropped the abort `signal` (their siblings callTool / searchTools / readResource
// / getPrompt all forward it). With signal undefined, (a) a user cancel or
// dispose→abort could NOT abort an in-flight resources/list or prompts/list call
// — it ran to the 10s request timeout — and (b) signal undefined into
// withInitializedMcpClient made the retry guard `!signal?.aborted &&
// isRetryableMcpError` evaluate true on a server crash, triggering a retry spawn
// racing closeAll. Fix: forward `signal` into listResources/listPrompts. This
// test proves an ALREADY-aborted signal short-circuits both proxy execute calls
// (they reject with an abort error fast) instead of completing. Pre-fix the
// signal was dropped (undefined) so the call succeeded — neuter reverts the
// forwarding and this test fails (promise resolves instead of rejecting).

describe("McpManager list_resources / list_prompts signal forwarding (opt #138)", () => {
	let tempRoot: string | undefined;

	afterEach(() => {
		if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
		tempRoot = undefined;
	});

	async function setup() {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-mcp-sig-"));
		const agentDir = join(tempRoot, "agent");
		mkdirSync(agentDir, { recursive: true });
		const fakeServer = join(tempRoot, "fake-mcp-sig.mjs");
		writeFileSync(
			fakeServer,
			`import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
 const msg = JSON.parse(line);
 if (msg.method === "initialize") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-11-25", serverInfo: { name: "fake" }, capabilities: { tools: {} } } }));
 if (msg.method === "resources/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { resources: [{ uri: "file:///demo.txt", name: "demo" }] } }));
 if (msg.method === "prompts/list") console.log(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { prompts: [{ name: "triage", description: "Triage target" }] } }));
});
`,
		);
		chmodSync(fakeServer, 0o700);
		writeFileSync(
			join(agentDir, "mcp.json"),
			JSON.stringify({
				mcpServers: {
					fake: { transport: "stdio", command: process.execPath, args: [fakeServer], autoRegisterTools: true },
				},
			}),
		);
		const manager = createMcpManager({ cwd: tempRoot, agentDir });
		const proxies = manager.createProxyToolDefinitions();
		// Order is fixed by createProxyToolDefinitions: call, search_tools,
		// list_resources, read_resource, list_prompts, get_prompt.
		const listResourcesProxy = proxies.find((p) => p.name === "mcp__fake__list_resources");
		const listPromptsProxy = proxies.find((p) => p.name === "mcp__fake__list_prompts");
		if (!listResourcesProxy || !listPromptsProxy) throw new Error("proxy tools not found");
		return { manager, listResourcesProxy, listPromptsProxy };
	}

	// Bounds a hanging execute so a regression (signal dropped → call completes
	// instead of rejecting) fails fast rather than hanging the suite.
	function raceAbort<T>(promise: Promise<T>): Promise<T> {
		return Promise.race([
			promise,
			new Promise<T>((_, reject) =>
				setTimeout(() => reject(new Error("execute was not aborted by the forwarded signal")), 3000),
			),
		]);
	}

	it("aborts an in-flight list_resources proxy call when the signal is already aborted", async () => {
		const { manager, listResourcesProxy } = await setup();

		// Sanity: without an abort signal the call succeeds (server is functional).
		const okResult = await listResourcesProxy.execute("t-ok", {}, undefined, undefined, {} as never);
		expect(
			String(okResult.content[0] && okResult.content[0].type === "text" ? okResult.content[0].text : ""),
		).toContain("file:///demo.txt");

		// Already-aborted signal must short-circuit the call (reject with an abort
		// error) instead of completing. Pre-fix the signal was dropped (undefined)
		// so this resolved with the resource list → expect().rejects failed.
		const aborted = new AbortController();
		aborted.abort();
		await expect(
			raceAbort(listResourcesProxy.execute("t-abort", {}, aborted.signal, undefined, {} as never)),
		).rejects.toThrow(/abort/i);

		await manager.closeAll();
	});

	it("aborts an in-flight list_prompts proxy call when the signal is already aborted", async () => {
		const { manager, listPromptsProxy } = await setup();

		const okResult = await listPromptsProxy.execute("t-ok", {}, undefined, undefined, {} as never);
		expect(
			String(okResult.content[0] && okResult.content[0].type === "text" ? okResult.content[0].text : ""),
		).toContain("name=triage");

		const aborted = new AbortController();
		aborted.abort();
		await expect(
			raceAbort(listPromptsProxy.execute("t-abort", {}, aborted.signal, undefined, {} as never)),
		).rejects.toThrow(/abort/i);

		await manager.closeAll();
	});
});

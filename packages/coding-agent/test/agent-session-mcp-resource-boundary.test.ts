import { afterEach, describe, expect, it } from "vitest";
import { createHarness, type Harness } from "./suite/harness.ts";

interface McpExpansionSession {
	_mcpManager?: {
		readResource(serverId: string, uri: string): Promise<{ content: Array<{ type: "text"; text: string }> }>;
		closeAll(): Promise<void>;
	};
	_expandMcpResourceMentions(text: string): Promise<string>;
}

describe("AgentSession MCP resource prompt boundary", () => {
	let harness: Harness | undefined;

	afterEach(() => harness?.cleanup());

	it("bounds each resource and the combined mention context", async () => {
		harness = await createHarness();
		const internal = harness.session as unknown as McpExpansionSession;
		internal._mcpManager = {
			async readResource(serverId, uri) {
				return { content: [{ type: "text", text: `${serverId}:${uri}:${"x".repeat(30_000)}` }] };
			},
			async closeAll() {},
		};
		const mentions = Array.from({ length: 10 }, (_, index) => `mcp://server-${index}/resource-${index}`).join(" ");

		const expanded = await internal._expandMcpResourceMentions(mentions);

		expect(expanded.length).toBeLessThan(26_000 + mentions.length);
		expect(expanded).toContain("MCP resource mention context");
		expect(expanded).toContain("truncated");
		expect(expanded).not.toContain("x".repeat(10_000));
	});
});

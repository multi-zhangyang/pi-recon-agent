import { describe, expect, it } from "vitest";
import { RpcClient } from "../src/modes/rpc/rpc-client.ts";

type RpcClientPrivate = {
	handleLine: (line: string) => void;
	pendingRequests: Map<string, { resolve: (response: unknown) => void; reject: (error: Error) => void }>;
};

describe("RpcClient late response not dispatched as a phantom event (opt #101 F3)", () => {
	it("drops an unmatched late response instead of broadcasting it to event listeners", () => {
		const client = new RpcClient();
		const priv = client as unknown as RpcClientPrivate;
		const events: unknown[] = [];
		client.onEvent((event) => {
			events.push(event);
		});

		// A late response whose send() already timed out and deleted the pending
		// entry. Pre-fix this fell through to the event-listener broadcast and was
		// dispatched to every listener as a phantom AgentEvent.
		priv.handleLine(JSON.stringify({ type: "response", id: "late-1", command: "prompt", success: true }));
		expect(events).toHaveLength(0);
	});

	it("still resolves a matched response and clears its pending entry", () => {
		const client = new RpcClient();
		const priv = client as unknown as RpcClientPrivate;
		let resolved: unknown;
		priv.pendingRequests.set("req-1", {
			resolve: (response: unknown) => {
				resolved = response;
			},
			reject: () => {},
		});

		priv.handleLine(JSON.stringify({ type: "response", id: "req-1", command: "prompt", success: true }));
		expect(resolved).toEqual({ type: "response", id: "req-1", command: "prompt", success: true });
		expect(priv.pendingRequests.has("req-1")).toBe(false);
	});

	it("still broadcasts genuine events", () => {
		const client = new RpcClient();
		const priv = client as unknown as RpcClientPrivate;
		const events: unknown[] = [];
		client.onEvent((event) => {
			events.push(event);
		});

		priv.handleLine(JSON.stringify({ type: "agent_start" }));
		expect(events).toHaveLength(1);
		expect(events[0]).toEqual({ type: "agent_start" });
	});
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { RpcClient } from "../src/modes/rpc/rpc-client.ts";

// opt #148: RpcClient.handleLine wrapped the JSON.parse AND the event-listener
// broadcast in ONE try/catch whose catch said "Ignore non-JSON lines". A throwing
// listener aborted the for-loop — every subsequent registered listener was
// skipped for that event — AND the error was swallowed under the misleading
// comment. In collectEvents/waitForIdle consumers this silently dropped events
// (a listener that never saw agent_end → 60s timeout). The fix wraps each
// listener(data) in its own try/catch (log best-effort, continue the loop).
//
// handleLine is private but reachable via RpcClient.prototype; it only touches
// this.pendingRequests (Map) and this.eventListeners (array), so a fake `this`
// carrying just those exercises the real dispatch in isolation.

type Ctx = {
	pendingRequests: Map<string, { resolve: (response: unknown) => void; reject: (error: Error) => void }>;
	eventListeners: Array<(event: unknown) => void>;
};

const handleLine = (
	RpcClient.prototype as unknown as {
		handleLine: (this: Ctx, line: string) => void;
	}
).handleLine;

function makeCtx(listeners: Array<(event: unknown) => void>): Ctx {
	return { pendingRequests: new Map(), eventListeners: listeners };
}

describe("RpcClient.handleLine listener isolation (opt #148)", () => {
	const spies: ReturnType<typeof vi.spyOn>[] = [];
	afterEach(() => {
		for (const s of spies) s.mockRestore();
		spies.length = 0;
	});

	it("a throwing listener does not starve subsequent listeners (loop continues)", () => {
		const seen: string[] = [];
		const ctx = makeCtx([
			(e) => {
				seen.push(`a:${(e as { type: string }).type}`);
			},
			() => {
				throw new Error("listener boom");
			},
			(e) => {
				seen.push(`c:${(e as { type: string }).type}`);
			},
		]);
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		spies.push(errSpy);

		expect(() => handleLine.call(ctx, JSON.stringify({ type: "agent_start" }))).not.toThrow();

		// b threw, but c STILL ran — no starvation.
		expect(seen).toEqual(["a:agent_start", "c:agent_start"]);
		expect(errSpy).toHaveBeenCalled();
	});

	it("non-JSON line is ignored and dispatches no listener", () => {
		const seen: string[] = [];
		const ctx = makeCtx([(e) => seen.push((e as { type: string }).type)]);

		expect(() => handleLine.call(ctx, "this is not json")).not.toThrow();
		expect(seen).toEqual([]);
	});

	it("a response resolves its pending request and is not broadcast to event listeners", () => {
		const seen: string[] = [];
		let resolved: unknown;
		const ctx = makeCtx([(e) => seen.push((e as { type: string }).type)]);
		ctx.pendingRequests.set("req-1", {
			resolve: (r) => {
				resolved = r;
			},
			reject: () => {},
		});

		handleLine.call(ctx, JSON.stringify({ type: "response", id: "req-1", ok: true }));

		expect(seen).toEqual([]);
		expect(ctx.pendingRequests.has("req-1")).toBe(false);
		expect(resolved).toEqual({ type: "response", id: "req-1", ok: true });
	});
});

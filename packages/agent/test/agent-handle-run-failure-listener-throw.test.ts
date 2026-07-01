import { type AssistantMessage, type AssistantMessageEvent, EventStream } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { Agent } from "../src/index.ts";
import type { AgentEvent } from "../src/types.ts";

// opt #104 Fix 2 — Agent.handleRunFailure must still emit agent_end if a
// listener throws.
//
// handleRunFailure calls processEvents sequentially with no try/catch. If a
// listener throws on turn_end (or message_start/message_end in the synthetic
// path) the remaining lifecycle events — including agent_end — are never
// emitted, violating the contract that agent_end is the final emitted event.
// The fix wraps each processEvents call so a throwing listener on one event
// does not skip subsequent events (collect first error, continue, rethrow).
//
// To reach the committed branch with turnEndEmitted=false (so handleRunFailure
// emits turn_end ITSELF rather than skipping it), a partial assistant is
// streamed (message_start) and then the stream errors mid-stream. The
// streamError catch (agent-loop streamAssistantResponse) best-effort commits
// the partial via message_end (turnMessageEndEmitted=true) and re-throws BEFORE
// turn_end is ever emitted in the normal flow → handleRunFailure runs the
// committed branch and emits turn_end then agent_end. (Mirrors the opt #97
// F1-phantom no-phantom test setup.)

class MockAssistantStream extends EventStream<AssistantMessageEvent, AssistantMessage> {
	constructor() {
		super(
			(event) => event.type === "done" || event.type === "error",
			(event) => {
				if (event.type === "done") return event.message;
				if (event.type === "error") return event.error;
				throw new Error("Unexpected event type");
			},
		);
	}
}

function createUsage() {
	return {
		input: 0,
		output: 0,
		cacheRead: 0,
		cacheWrite: 0,
		totalTokens: 0,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
	};
}

describe("Agent handleRunFailure emits agent_end even if a turn_end listener throws (opt #104 Fix 2)", () => {
	it("emits agent_end when a turn_end listener throws in the committed path", async () => {
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const partial: AssistantMessage = {
					role: "assistant",
					content: [{ type: "text", text: "" }],
					api: "openai-responses",
					provider: "openai",
					model: "mock",
					usage: createUsage(),
					stopReason: "stop",
					timestamp: Date.now(),
				};
				stream.push({ type: "start", partial });
				(partial.content[0] as { text: string }).text = "partial body";
				stream.push({
					type: "text_delta",
					contentIndex: 0,
					delta: "partial body",
					partial,
				});
				// No done/error — the listener throw on message_update (below)
				// interrupts the for-await before any terminal event, routing to
				// the streamError catch which commits the partial via message_end
				// and re-throws → handleRunFailure (committed, turnEndEmitted=false).
			});
			return stream;
		};
		const agent = new Agent({ streamFn });

		const events: AgentEvent[] = [];
		// The listener throws on message_update to trigger the streamError →
		// handleRunFailure path, AND throws on turn_end to test that agent_end is
		// still emitted afterward. It records agent_end without throwing on it.
		agent.subscribe((event) => {
			events.push(event);
			if (event.type === "message_update") {
				throw new Error("listener exploded on message_update");
			}
			if (event.type === "turn_end") {
				throw new Error("listener exploded on turn_end");
			}
		});

		// handleRunFailure rethrows the turn_end listener error (with the fix, after
		// agent_end is emitted; without the fix, immediately). Either way prompt
		// rejects — the distinguishing assertion is whether agent_end was recorded.
		await expect(agent.prompt("hello")).rejects.toThrow(/turn_end/);

		// The KEY invariant: agent_end MUST be emitted even though the turn_end
		// listener threw. Without the fix, handleRunFailure's sequential
		// processEvents await threw on turn_end and never reached agent_end.
		const agentEnds = events.filter((event) => event.type === "agent_end");
		expect(agentEnds).toHaveLength(1);
	});
});

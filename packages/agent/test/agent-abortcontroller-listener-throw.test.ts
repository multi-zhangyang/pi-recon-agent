import { type AssistantMessage, type AssistantMessageEvent, EventStream } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { Agent } from "../src/index.ts";
import type { AgentEvent } from "../src/types.ts";

// opt #116 — a listener throw (or stream error) mid-stream propagates to
// runWithLifecycle's catch. The in-flight LLM fetch is tied to the run's
// AbortController.signal; pre-fix the catch called handleRunFailure but NEVER
// aborted the controller → the provider IIFE kept streaming (cost/quota leak)
// and kept pushing into the EventStream queue (unbounded growth) after the
// consumer broke out of `for await`. Fix: capture wasAborted, abort the
// controller if not already aborted (cancels the fetch — the provider IIFE
// catches the AbortError and stream.end()s cleanly), then handleRunFailure
// with the ORIGINAL wasAborted so failure labeling stays correct.
//
// This test pins the fix by capturing the signal the streamFn receives
// (=== abortController.signal) and asserting it is aborted after the run. A
// listener throws on the first message_update to trigger the mid-stream throw
// path. Pre-fix the signal stays unaborted.

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

describe("Agent runWithLifecycle aborts the fetch on a mid-stream listener throw (opt #116)", () => {
	it("aborts the run AbortController when a message_update listener throws mid-stream", async () => {
		let capturedSignal: AbortSignal | undefined;
		const streamFn = (_model: unknown, _context: unknown, options?: { signal?: AbortSignal }) => {
			capturedSignal = options?.signal;
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
				// interrupts the for-await before any terminal event.
			});
			return stream;
		};

		const agent = new Agent({ streamFn });

		const events: AgentEvent[] = [];
		// Throw on the first message_update. Do NOT throw on turn_end/agent_end
		// so handleRunFailure completes the committed lifecycle cleanly and
		// prompt resolves (the distinguishing assertion is the signal, not a
		// rethrown error).
		agent.subscribe((event) => {
			events.push(event);
			if (event.type === "message_update") {
				throw new Error("listener exploded on message_update");
			}
		});

		// prompt resolves (handleRunFailure emits turn_end + agent_end for the
		// committed partial without rethrowing). Swallow either outcome — the
		// assertion is on the captured signal.
		await agent.prompt("hello").catch(() => undefined);

		expect(capturedSignal).toBeDefined();
		// The KEY invariant: the run's AbortController was aborted, cancelling
		// the in-flight fetch. Pre-fix the catch never aborted → unaborted.
		expect(capturedSignal!.aborted).toBe(true);
		// agent_end still fired (the failure lifecycle completed).
		expect(events.some((event) => event.type === "agent_end")).toBe(true);
	});
});

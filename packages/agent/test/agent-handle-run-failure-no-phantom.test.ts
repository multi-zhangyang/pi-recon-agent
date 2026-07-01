import { type AssistantMessage, type AssistantMessageEvent, EventStream } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { Agent } from "../src/index.ts";
import type { AgentEvent } from "../src/types.ts";

// Mirrors MockAssistantStream in agent.test.ts but never pushes a terminal
// event — the listener throw interrupts the for-await before any done/error.
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

describe("Agent handleRunFailure no-phantom when a real assistant was already committed (opt #97 F1-phantom mirror)", () => {
	it("emits exactly one assistant message_end and terminates cleanly when a listener throws mid-stream after a partial was streamed", async () => {
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
				// No done/error — the listener throw below interrupts before any terminal.
			});
			return stream;
		};
		const agent = new Agent({ streamFn });

		const events: AgentEvent[] = [];
		// Listener that throws on message_update (a streaming delta) but accepts
		// message_end, so the loop catch's best-effort commit can succeed and set
		// turnMessageEndEmitted before the re-throw routes to handleRunFailure.
		agent.subscribe((event) => {
			events.push(event);
			if (event.type === "message_update") {
				throw new Error("listener exploded on message_update");
			}
		});

		// Pre-fix: handleRunFailure ALWAYS synthesized a full lifecycle
		// (message_start + message_end + turn_end + agent_end) on top of the
		// real committed partial → a SECOND assistant message_end + a PHANTOM
		// assistant message. Post-fix: it sees the committed partial and emits
		// only turn_end + agent_end referencing it.
		await agent.prompt("hello");

		const assistantMessageEnds = events.filter(
			(event) =>
				event.type === "message_end" && (event as { message: { role: string } }).message.role === "assistant",
		);
		expect(assistantMessageEnds).toHaveLength(1);

		const committed = (assistantMessageEnds[0] as { message: AssistantMessage }).message;
		expect(committed.stopReason).toBe("error");
		expect(committed.errorMessage).toBe("listener exploded on message_update");
		const textBlock = committed.content[0];
		if (textBlock.type !== "text") throw new Error("expected text content");
		expect(textBlock.text).toBe("partial body");

		// No phantom second message_start / message_end / turn_end / agent_end.
		expect(events.filter((event) => event.type === "turn_end")).toHaveLength(1);
		expect(events.filter((event) => event.type === "agent_end")).toHaveLength(1);
		const assistantStarts = events.filter(
			(event) =>
				event.type === "message_start" && (event as { message: { role: string } }).message.role === "assistant",
		);
		expect(assistantStarts).toHaveLength(1);

		// The durable state has exactly one assistant (the partial) — no phantom.
		const assistants = agent.state.messages.filter((message) => message.role === "assistant");
		expect(assistants).toHaveLength(1);
	});
});

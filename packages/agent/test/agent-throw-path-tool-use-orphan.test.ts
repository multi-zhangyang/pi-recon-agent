import { type AssistantMessage, type AssistantMessageEvent, EventStream } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { Agent } from "../src/index.ts";
import type { AgentEvent } from "../src/types.ts";

// Foundational opt #261 (throw path): a listener throw mid-stream AFTER
// toolcall_end fired leaves a committed partial carrying a COMPLETE tool_use.
// The loop catch commits the partial via message_end and re-throws to the
// run-failure handler, which pre-fix emitted only turn_end/agent_end → the
// tool_use was orphaned (no tool_result) → next request 400. Post-fix the catch
// synthesizes an isError tool_result per tool_use id BEFORE re-throwing.

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

describe("Agent throw-path orphan tool_use synthesis (opt #261 throw path)", () => {
	it("synthesizes an error tool_result when a listener throws after toolcall_end committed a tool_use", async () => {
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const base: AssistantMessage = {
					role: "assistant",
					content: [],
					api: "openai-responses",
					provider: "openai",
					model: "mock",
					usage: createUsage(),
					stopReason: "stop",
					timestamp: Date.now(),
				};
				stream.push({ type: "start", partial: base });
				// toolcall_start: partial gains an (incomplete) toolCall block.
				const startPartial: AssistantMessage = {
					...base,
					content: [{ type: "toolCall", id: "tool-1", name: "bash", arguments: { command: "" } }],
				};
				stream.push({ type: "toolcall_start", contentIndex: 0, partial: startPartial });
				// toolcall_end: partial now carries a COMPLETE toolCall block. The
				// listener below throws on THIS message_update (after the partial is
				// updated to the complete-toolCall form) → the catch sees a committed
				// partial with a complete tool_use.
				const endPartial: AssistantMessage = {
					...base,
					content: [{ type: "toolCall", id: "tool-1", name: "bash", arguments: { command: "echo hi" } }],
				};
				stream.push({
					type: "toolcall_end",
					contentIndex: 0,
					toolCall: endPartial.content[0] as {
						type: "toolCall";
						id: string;
						name: string;
						arguments: Record<string, unknown>;
					},
					partial: endPartial,
				});
			});
			return stream;
		};
		const agent = new Agent({ streamFn });

		const events: AgentEvent[] = [];
		agent.subscribe((event) => {
			events.push(event);
			// Throw on the toolcall_end message_update — AFTER the partial has been
			// updated to carry the complete toolCall block.
			if (
				event.type === "message_update" &&
				(event as { assistantMessageEvent?: { type?: string } }).assistantMessageEvent?.type === "toolcall_end"
			) {
				throw new Error("listener exploded on toolcall_end");
			}
		});

		await agent.prompt("run it");

		// Exactly one assistant message_end (the committed partial) — no phantom.
		const assistantEnds = events.filter(
			(e) => e.type === "message_end" && (e as { message: { role: string } }).message.role === "assistant",
		);
		expect(assistantEnds).toHaveLength(1);
		const committed = (assistantEnds[0] as { message: AssistantMessage }).message;
		expect(committed.stopReason).toBe("error");
		expect(committed.errorMessage).toBe("listener exploded on toolcall_end");
		// The committed assistant carries the tool_use.
		const toolUse = committed.content.find((b) => b.type === "toolCall");
		expect(toolUse).toBeDefined();

		// Core invariant: a tool_result was synthesized for the tool_use id before
		// the run ended (pre-fix: no tool_result message_end → orphan → next 400).
		const toolResultEnds = events.filter(
			(e) => e.type === "message_end" && (e as { message: { role?: string } }).message.role === "toolResult",
		);
		expect(toolResultEnds).toHaveLength(1);

		// The durable state is balanced: assistant(tool_use) + tool_result.
		const stateToolResults = agent.state.messages.filter((m) => m.role === "toolResult");
		expect(stateToolResults).toHaveLength(1);

		// The synthesized tool_result is an error (the tool was NOT executed).
		const toolExecEnd = events.find((e) => e.type === "tool_execution_end");
		expect(toolExecEnd).toBeDefined();
		if (toolExecEnd?.type === "tool_execution_end") {
			expect(toolExecEnd.isError).toBe(true);
		}

		// Clean termination.
		expect(events.filter((e) => e.type === "turn_end")).toHaveLength(1);
		expect(events.filter((e) => e.type === "agent_end")).toHaveLength(1);
	});
});

/**
 * opt #220 — per-turn reset of run-failure trackers in processEvents.
 *
 * Pre-fix, `turnMessageEndEmitted` / `turnEndEmitted` / `lastCommittedAssistant`
 * were reset ONLY at run start (agent.ts runWithLifecycle). processEvents had
 * no `turn_start` case, so after turn N committed a message and emitted
 * turn_end, all three stayed set for turn N+1. If turn N+1 then threw BEFORE
 * its own message_end (streamFn threw, or a transformContext/convertToLlm/
 * getApiKey/hook threw), handleRunFailure saw the stale turn-N flags → took
 * the "committed" branch → emitted turn_end/agent_end for the turn-N message
 * and RETURNED without surfacing the turn-N+1 error. The error was swallowed
 * (no errorMessage, no failure assistant, agent state inconsistent).
 *
 * Fix: a `turn_start` case in processEvents resets the three flags per turn,
 * routing a later-turn pre-message-end failure to the synthetic failure path
 * that surfaces the error in-band.
 *
 * This test drives a single prompt() that runs two turns: turn 1 commits a
 * clean terminal assistant; a queued follow-up forces turn 2, whose streamFn
 * throws before emitting anything. Pre-fix the error is swallowed; post-fix it
 * is surfaced as a failure assistant + state.errorMessage.
 */
import { type AssistantMessage, type AssistantMessageEvent, EventStream } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { Agent } from "../src/index.ts";

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

function createAssistantMessage(text: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
		api: "openai-responses",
		provider: "openai",
		model: "mock",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
		timestamp: Date.now(),
	};
}

describe("opt #220: per-turn flag reset surfaces a later-turn error instead of swallowing it", () => {
	it("surfaces a turn-2 stream error after turn 1 committed (pre-fix: swallowed)", async () => {
		let callCount = 0;
		const agent = new Agent({
			streamFn: () => {
				callCount++;
				if (callCount === 1) {
					// Turn 1: a clean terminal assistant that commits via message_end.
					const stream = new MockAssistantStream();
					queueMicrotask(() => {
						stream.push({ type: "done", reason: "stop", message: createAssistantMessage("turn 1 done") });
					});
					return stream;
				}
				// Turn 2: throw BEFORE emitting any event (no message_start for turn 2).
				throw new Error("turn 2 exploded");
			},
		});

		// Queue a follow-up so the loop runs a second turn after turn 1 stops
		// (no tool calls) — all within a single prompt() run.
		agent.followUp({
			role: "user",
			content: [{ type: "text", text: "continue" }],
			timestamp: Date.now(),
		});

		await agent.prompt("hello");

		// Turn 2's streamFn was actually invoked (the run reached turn 2).
		expect(callCount).toBeGreaterThanOrEqual(2);
		// The turn-2 error is surfaced in-band, not swallowed.
		expect(agent.state.errorMessage).toBe("turn 2 exploded");
		const failure = agent.state.messages
			.filter((m): m is AssistantMessage => m.role === "assistant")
			.find((m) => m.errorMessage === "turn 2 exploded");
		expect(failure).toBeDefined();
	});

	it("still surfaces a turn-1 error when turn 1 itself throws (regression guard)", async () => {
		const agent = new Agent({
			streamFn: () => {
				throw new Error("turn 1 exploded");
			},
		});

		await agent.prompt("hello");

		expect(agent.state.errorMessage).toBe("turn 1 exploded");
		const failure = agent.state.messages
			.filter((m): m is AssistantMessage => m.role === "assistant")
			.find((m) => m.errorMessage === "turn 1 exploded");
		expect(failure).toBeDefined();
	});
});

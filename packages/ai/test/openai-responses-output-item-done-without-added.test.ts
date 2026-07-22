/**
 * opt #206 — openai-responses `output_item.done` dropped a tool call when the
 * proxy/gateway omitted `response.output_item.added`.
 *
 * The added-handler is what pushes a function_call's toolCall block onto
 * `output.content` (and emits `toolcall_start`). Some proxies/gateways drop
 * that event and emit only `response.output_item.done` for the function_call.
 * In that case `currentBlock` is NOT a toolCall, so the done-handler took its
 * `else` branch: it built a fresh `toolCall` object but only passed it to
 * `stream.push({type:"toolcall_end",...})` — it NEVER pushed it onto
 * `output.content`. The tool call was silently lost from the AssistantMessage
 * (the agent loop never executed it → transcript imbalance), and the
 * `toolcall_end` contentIndex (`blocks.length - 1`) pointed at the wrong
 * (last existing) block.
 *
 * Fix: push the new toolCall onto `output.content` in the else branch BEFORE
 * computing blockIndex() so the tool call survives and the contentIndex is
 * correct.
 *
 * This test feeds a stream that SKIPS `output_item.added` for the
 * function_call (only `output_item.done`) and asserts the tool call IS
 * present in `output.content` and that `toolcall_end` contentIndex points at
 * it. Pre-fix, `output.content` is empty and the contentIndex is -1 (no
 * blocks) → assertions fail.
 */
import type { ResponseStreamEvent } from "openai/resources/responses/responses.js";
import { describe, expect, it, vi } from "vitest";
import { processResponsesStream } from "../src/providers/openai-responses-shared.ts";
import type { AssistantMessage, AssistantMessageEvent, Model } from "../src/types.ts";
import { AssistantMessageEventStream } from "../src/utils/event-stream.ts";

function createOutput(model: Model<"openai-responses">): AssistantMessage {
	return {
		role: "assistant",
		content: [],
		api: model.api,
		provider: model.provider,
		model: model.id,
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

const argumentsJson = '{"path":"README.md","content":"updated"}';

// Emits ONLY output_item.done for the function_call — no output_item.added,
// no function_call_arguments.delta/done. This is the proxy-drop scenario.
async function* createDroppedAddedEvents(): AsyncIterable<ResponseStreamEvent> {
	yield {
		type: "response.output_item.done",
		item: {
			type: "function_call",
			id: "fc_test",
			call_id: "call_test",
			name: "edit",
			arguments: argumentsJson,
		},
	} as ResponseStreamEvent;
	yield {
		type: "response.completed",
		response: { id: "resp_test", status: "completed" },
	} as ResponseStreamEvent;
}

describe("openai responses output_item.done without added keeps the tool call (opt #206)", () => {
	it("pushes the tool call onto output.content when output_item.added was dropped", async () => {
		const model: Model<"openai-responses"> = {
			id: "gpt-5-mini",
			name: "GPT-5 Mini",
			api: "openai-responses",
			provider: "openai",
			baseUrl: "https://api.openai.com/v1",
			reasoning: true,
			input: ["text"],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 400000,
			maxTokens: 128000,
		};
		const output = createOutput(model);
		const stream = new AssistantMessageEventStream();
		const pushSpy = vi.spyOn(stream, "push");

		await processResponsesStream(createDroppedAddedEvents(), output, stream, model);

		// The tool call MUST survive in output.content. Pre-fix this was empty
		// (length 0) — the tool call was silently lost.
		expect(output.content).toHaveLength(1);
		const persistedToolCall = output.content[0];
		expect(persistedToolCall?.type).toBe("toolCall");
		if (!persistedToolCall || persistedToolCall.type !== "toolCall") {
			throw new Error("Expected toolCall block in output.content");
		}
		expect(persistedToolCall.id).toBe("call_test|fc_test");
		expect(persistedToolCall.name).toBe("edit");
		expect(persistedToolCall.arguments).toEqual({ path: "README.md", content: "updated" });

		// The toolcall_end event must point at the freshly-pushed tool call
		// (contentIndex 0, the only block). Pre-fix contentIndex was -1 (no
		// blocks) and toolCall was a detached object not in output.content.
		const emittedEvents = pushSpy.mock.calls.map(([event]) => event as AssistantMessageEvent);
		const toolCallEnd = emittedEvents.find((event) => event.type === "toolcall_end");
		expect(toolCallEnd).toBeDefined();
		if (!toolCallEnd || toolCallEnd.type !== "toolcall_end") {
			throw new Error("Expected toolcall_end event");
		}
		expect(toolCallEnd.contentIndex).toBe(0);
		expect(toolCallEnd.toolCall).toBe(persistedToolCall);
	});
});

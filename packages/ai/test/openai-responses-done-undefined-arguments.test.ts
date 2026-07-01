/**
 * Foundational opt #259 — openai-responses `response.function_call_arguments.done`
 * with `arguments` undefined threw TypeError.
 *
 * The SDK types `arguments` as required, but a Responses-compatible
 * proxy/gateway can emit `.done` with `arguments` missing/undefined. Pre-fix
 * `event.arguments.startsWith(previousPartialJson)` threw TypeError →
 * propagated to the provider's outer catch → the ENTIRE tool-call turn (any
 * already-streamed text/thinking) discarded as stopReason:"error". Fix: fall
 * back to the accumulated `currentBlock.partialJson` (the `.delta` path built
 * it up) when the done event omits the final arguments string.
 */
import type { ResponseStreamEvent } from "openai/resources/responses/responses.js";
import { describe, expect, it } from "vitest";
import { processResponsesStream } from "../src/providers/openai-responses-shared.ts";
import type { AssistantMessage, Model } from "../src/types.ts";
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

// Emits a function_call built up via .delta, then a .done with `arguments`
// undefined (the proxy-drop scenario), then output_item.done + completed.
async function* createEvents(): AsyncIterable<ResponseStreamEvent> {
	yield {
		type: "response.output_item.added",
		item: {
			type: "function_call",
			id: "fc_test",
			call_id: "call_test",
			name: "edit",
			arguments: "",
		},
	} as ResponseStreamEvent;
	yield {
		type: "response.function_call_arguments.delta",
		item_id: "fc_test",
		delta: '{"path":',
	} as ResponseStreamEvent;
	yield { type: "response.function_call_arguments.delta", item_id: "fc_test", delta: '"x"}' } as ResponseStreamEvent;
	// BUG TRIGGER: `.done` with arguments undefined. Pre-fix this threw.
	yield {
		type: "response.function_call_arguments.done",
		item_id: "fc_test",
		arguments: undefined as unknown as string,
	} as ResponseStreamEvent;
	yield {
		type: "response.output_item.done",
		item: {
			type: "function_call",
			id: "fc_test",
			call_id: "call_test",
			name: "edit",
			arguments: '{"path":"x"}',
		},
	} as ResponseStreamEvent;
	yield {
		type: "response.completed",
		response: {
			id: "resp_1",
			status: "completed",
			usage: { input_tokens: 5, output_tokens: 3, total_tokens: 8, input_tokens_details: { cached_tokens: 0 } },
		},
	} as ResponseStreamEvent;
}

describe("openai responses function_call_arguments.done with undefined arguments (opt #259)", () => {
	it("falls back to accumulated partialJson instead of throwing TypeError", async () => {
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

		// Pre-fix: rejected with TypeError "Cannot read properties of undefined
		// (reading 'startsWith')" → provider outer catch → whole turn discarded.
		await expect(processResponsesStream(createEvents(), output, stream, model)).resolves.toBeUndefined();

		// The tool call survives with the parsed args from the accumulated partial.
		expect(output.content).toHaveLength(1);
		const block = output.content[0];
		expect(block?.type).toBe("toolCall");
		if (block?.type === "toolCall") {
			expect(block.name).toBe("edit");
			expect(block.arguments).toEqual({ path: "x" });
		}
		expect(output.stopReason).toBe("toolUse");
		expect(output.errorMessage).toBeUndefined();
	});
});

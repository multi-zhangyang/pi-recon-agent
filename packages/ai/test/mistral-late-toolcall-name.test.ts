import type { CompletionEvent } from "@mistralai/mistralai/models/components";
import { describe, expect, it } from "vitest";
import { getModel } from "../src/models.ts";
import { consumeChatStream } from "../src/providers/mistral.ts";
import type { AssistantMessage, Model, Usage } from "../src/types.ts";
import { AssistantMessageEventStream } from "../src/utils/event-stream.ts";
import { registerMistralFixtures } from "./model-fixtures.ts";

registerMistralFixtures();

// Regression guard for the mistral late tool-call name bug. The tool-call `name`
// was captured only at block CREATION (the first delta for a given `index`). If
// the first delta for an index lacked `function.name` (the name arriving on a
// LATER delta for the same index), `block.name` stayed `undefined` forever → a
// nameless `toolcall_end` was emitted → the tool call couldn't be dispatched.
// Sibling openai-completions.ts:354-360 updates block.name/block.id on EVERY
// delta; mistral now mirrors that pattern.

const emptyUsage: Usage = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

function buildOutput(model: Model<"mistral-conversations">): AssistantMessage {
	return {
		role: "assistant",
		content: [],
		api: model.api,
		provider: model.provider,
		model: model.id,
		usage: emptyUsage,
		stopReason: "stop",
		timestamp: Date.now(),
	};
}

type MistralDelta = CompletionEvent["data"]["choices"][number]["delta"];
type MistralToolCall = NonNullable<NonNullable<MistralDelta["toolCalls"]>[number]>;

/** Streams a single tool call split across two deltas where the FIRST delta has
 *  only `index` + partial `arguments` (no `function.name`) and the LATER delta
 *  carries `function.name` plus the remaining arguments. */
async function* fakeStream(): AsyncIterable<CompletionEvent> {
	// First delta: index + partial arguments, NO function.name.
	yield {
		data: {
			id: "chunk-1",
			model: "repro-model",
			choices: [
				{
					index: 0,
					delta: {
						toolCalls: [
							{
								index: 0,
								function: { arguments: '{"city' },
							},
						] as MistralToolCall[],
					} as MistralDelta,
					finishReason: null,
				},
			],
		},
	} as CompletionEvent;
	// Second delta: same index, NOW carries function.name + remaining arguments.
	yield {
		data: {
			id: "chunk-2",
			model: "repro-model",
			choices: [
				{
					index: 0,
					delta: {
						toolCalls: [
							{
								index: 0,
								function: { name: "get_weather", arguments: '":"Paris"}' },
							},
						] as MistralToolCall[],
					} as MistralDelta,
					finishReason: null,
				},
			],
		},
	} as CompletionEvent;
	// Terminal chunk.
	yield {
		data: {
			id: "chunk-3",
			model: "repro-model",
			choices: [
				{
					index: 0,
					delta: {} as MistralDelta,
					finishReason: "tool_calls",
				},
			],
		},
	} as CompletionEvent;
}

describe("Mistral late tool-call name (mistral.ts)", () => {
	it("captures the tool-call name when it arrives on a later delta for the same index", async () => {
		const model = getModel<"mistral-conversations">("mistral", "devstral-medium-latest")!;
		const output = buildOutput(model);
		const stream = new AssistantMessageEventStream();

		// Pre-fix: block.name stayed undefined (only set at creation, first delta
		// had no function.name) → nameless toolcall_end → tool call not dispatchable.
		// Post-fix: late-name update on every delta sets block.name from the second delta.
		await expect(consumeChatStream(model, output, stream, fakeStream())).resolves.toBeUndefined();

		const toolCall = output.content.find((b) => b.type === "toolCall");
		expect(toolCall).toBeDefined();
		expect((toolCall as { name?: string }).name).toBe("get_weather");
		expect((toolCall as { name?: string }).name).not.toBeUndefined();

		// Arguments were accumulated across both deltas and parsed.
		const args = (toolCall as { arguments?: Record<string, unknown> }).arguments;
		expect(args).toEqual({ city: "Paris" });
	});
});

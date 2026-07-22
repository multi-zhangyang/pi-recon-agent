import type { CompletionEvent } from "@mistralai/mistralai/models/components";
import { describe, expect, it } from "vitest";
import { getModel } from "../src/models.ts";
import { consumeChatStream } from "../src/providers/mistral.ts";
import type { AssistantMessage, Model, Usage } from "../src/types.ts";
import { AssistantMessageEventStream } from "../src/utils/event-stream.ts";
import { registerMistralFixtures } from "./model-fixtures.ts";

registerMistralFixtures();

// Regression guard for opt #178 — consumeChatStream (mistral.ts) read `choice.delta`
// then immediately did `delta.content !== null` with NO null-delta guard. The SDK type
// says `delta: DeltaMessage` (non-nullable), but some Mistral-compatible providers emit
// a terminal chunk `{ choices: [{ finish_reason: "stop", delta: null }] }`. At runtime
// `null.content` throws TypeError → caught by streamMistral's outer catch → the ENTIRE
// accumulated response (text/thinking/tool calls) is discarded as stopReason:"error".
// The sibling openai-completions.ts guards with `if (choice.delta)`. Fix: after the
// finishReason block, `if (!delta) continue;` so a terminal chunk still updates stopReason
// but does not dereference null.

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

/** A fake Mistral stream emitting a content chunk then a terminal chunk with delta: null. */
async function* fakeStream(): AsyncIterable<CompletionEvent> {
	yield {
		data: {
			id: "chunk-1",
			model: "repro-model",
			choices: [
				{
					index: 0,
					delta: { content: "Hello world" } as CompletionEvent["data"]["choices"][number]["delta"],
					finishReason: null,
				},
			],
		},
	} as CompletionEvent;
	// Terminal chunk: some providers omit `delta` on the final chunk. The SDK type
	// lies (says non-nullable), so cast to satisfy TS while simulating the runtime.
	yield {
		data: {
			id: "chunk-1",
			model: "repro-model",
			choices: [
				{
					index: 0,
					// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
					delta: null as unknown as CompletionEvent["data"]["choices"][number]["delta"],
					finishReason: "stop",
				},
			],
		},
	} as CompletionEvent;
}

describe("Mistral null choice.delta guard (opt #178)", () => {
	it("preserves accumulated text and stopReason when the terminal chunk has delta: null", async () => {
		const model = getModel<"mistral-conversations">("mistral", "codestral-latest")!;
		const output = buildOutput(model);
		const stream = new AssistantMessageEventStream();

		// Pre-fix: this threw TypeError ("Cannot read properties of null (reading 'content')")
		// → streamMistral's outer catch discarded the whole response as stopReason:"error".
		// Post-fix: the terminal chunk updates stopReason via finishReason, then `continue`s.
		await expect(consumeChatStream(model, output, stream, fakeStream())).resolves.toBeUndefined();

		// The text from the first chunk is preserved (response NOT discarded).
		const textBlock = output.content.find((b) => b.type === "text");
		expect(textBlock).toBeDefined();
		expect((textBlock as { text: string }).text).toBe("Hello world");

		// stopReason was updated from the terminal chunk's finish_reason and not clobbered.
		expect(output.stopReason).toBe("stop");
	});

	it("streamMistral path does not surface an error when terminal delta is null", async () => {
		// The consumeChatStream path is the only place delta is dereferenced; assert the
		// public contract: no throw, content preserved, no errorMessage — the silent-discard
		// regression under test.
		const model = getModel<"mistral-conversations">("mistral", "codestral-latest")!;
		const output = buildOutput(model);
		const stream = new AssistantMessageEventStream();
		await consumeChatStream(model, output, stream, fakeStream());
		expect(output.stopReason).toBe("stop");
		expect(output.errorMessage).toBeUndefined();
	});
});

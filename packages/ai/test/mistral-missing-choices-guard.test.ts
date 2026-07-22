/**
 * Foundational opt #258 — consumeChatStream (mistral.ts) did `chunk.choices[0]`
 * with NO guard on `choices` itself being undefined/absent. The SDK types
 * `choices` as required, but a usage-only terminal chunk (the include_usage
 * pattern) or a Mistral-compatible proxy can emit `{ id, usage }` with no
 * `choices` field → `chunk.choices[0]` throws TypeError → caught by
 * streamMistral's outer catch → the ENTIRE accumulated response discarded as
 * stopReason:"error". Sibling openai-completions.ts:301 guards the same way.
 * Fix: `Array.isArray(chunk.choices) ? chunk.choices[0] : undefined`.
 */
import type { CompletionEvent } from "@mistralai/mistralai/models/components";
import { describe, expect, it } from "vitest";
import { getModel } from "../src/models.ts";
import { consumeChatStream } from "../src/providers/mistral.ts";
import type { AssistantMessage, Model, Usage } from "../src/types.ts";
import { AssistantMessageEventStream } from "../src/utils/event-stream.ts";
import { registerMistralFixtures } from "./model-fixtures.ts";

registerMistralFixtures();

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

/** A fake Mistral stream: a usage-only chunk (no `choices`) then a content chunk. */
async function* fakeStream(): AsyncIterable<CompletionEvent> {
	// Usage-only chunk — no `choices` field at all (the runtime shape the SDK
	// type hides). Pre-fix `chunk.choices[0]` threw TypeError here.
	yield {
		data: {
			id: "chunk-1",
			model: "repro-model",
			usage: { promptTokens: 7, completionTokens: 0, totalTokens: 7 } as CompletionEvent["data"]["usage"],
		},
	} as CompletionEvent;
	// Then a normal content chunk.
	yield {
		data: {
			id: "chunk-1",
			model: "repro-model",
			choices: [
				{
					index: 0,
					delta: { content: "Hello world" } as CompletionEvent["data"]["choices"][number]["delta"],
					finishReason: "stop",
				},
			],
		},
	} as CompletionEvent;
}

describe("Mistral missing choices guard (opt #258)", () => {
	it("skips a usage-only chunk with no choices field instead of throwing", async () => {
		const model = getModel<"mistral-conversations">("mistral", "codestral-latest")!;
		const output = buildOutput(model);
		const stream = new AssistantMessageEventStream();

		// Pre-fix: TypeError "Cannot read properties of undefined (reading '0')"
		// → outer catch → whole response discarded as stopReason:"error".
		await expect(consumeChatStream(model, output, stream, fakeStream())).resolves.toBeUndefined();

		// The usage from the choices-less chunk was applied.
		expect(output.usage.input).toBe(7);

		// The content chunk after it was processed (not discarded).
		const textBlock = output.content.find((b) => b.type === "text");
		expect(textBlock).toBeDefined();
		expect((textBlock as { text: string }).text).toBe("Hello world");
		expect(output.stopReason).toBe("stop");
		expect(output.errorMessage).toBeUndefined();
	});
});

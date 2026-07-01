import type { ResponseOutputMessage } from "openai/resources/responses/responses.js";
import { describe, expect, it } from "vitest";
import { getModel } from "../src/models.ts";
import { convertResponsesMessages } from "../src/providers/openai-responses-shared.ts";
import type { AssistantMessage, Context, Model, Usage } from "../src/types.ts";

// Regression guard for opt #57 — convertResponsesMessages (openai-responses-shared.ts:174) did a
// bare `JSON.parse(block.thinkingSignature)` with NO try/catch. The thinking branch is only
// reached on the SAME-MODEL replay path (transformMessages:106 keeps a thinking block with a
// signature only when isSameModel — same provider/api/model — so the model can replay its own
// prior encrypted reasoning). convertResponsesMessages runs INSIDE the stream fn's outer try/catch
// (openai-responses.ts:108 → catch at :146), so a corrupt/truncated thinkingSignature in persisted
// history (torn write, manual edit, schema/version mismatch) threw SyntaxError → the catch set
// stopReason="error" → the ENTIRE turn was lost before the request reached the provider (silent
// turn loss). The sibling parseTextSignature at line 52 and openai-completions.ts:888 both guard
// this exact pattern; :174 was the inconsistent outlier. Fix: try/catch + skip the reasoning item
// on parse failure (graceful degradation — the rest of the turn proceeds without the prior
// reasoning signature).

const usage: Usage = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

/** Build a same-model assistant so transformMessages keeps the thinking block (isSameModel path). */
function sameModelAssistant(
	model: Model<"openai-codex-responses">,
	content: AssistantMessage["content"],
): AssistantMessage {
	return {
		role: "assistant",
		content,
		api: model.api,
		provider: model.provider,
		model: model.id,
		usage,
		stopReason: "stop",
		timestamp: Date.now() - 1000,
	};
}

describe("OpenAI Responses corrupt thinkingSignature guard (opt #57)", () => {
	it("skips a corrupt thinkingSignature instead of throwing and losing the turn", () => {
		const model = getModel("openai-codex", "gpt-5.5");
		const assistant = sameModelAssistant(model, [
			{ type: "thinking", thinking: "private reasoning", thinkingSignature: "{ this is not valid json" },
			{ type: "text", text: "visible answer" },
		]);
		const context: Context = {
			systemPrompt: "You are concise.",
			messages: [{ role: "user", content: "hello", timestamp: Date.now() - 2000 }, assistant],
		};

		// Pre-fix: bare JSON.parse("{ this is not valid json") threw SyntaxError →
		// convertResponsesMessages threw (the function has no surrounding try/catch — only its
		// caller does) → the stream fn's outer catch lost the whole turn. Post-fix: the corrupt
		// reasoning item is skipped, no throw.
		expect(() =>
			convertResponsesMessages(model, context, new Set(["openai", "openai-codex", "opencode"])),
		).not.toThrow();

		const input = convertResponsesMessages(model, context, new Set(["openai", "openai-codex", "opencode"]));

		// The assistant text block AFTER the corrupt thinking block is still converted → the turn
		// is NOT lost (the provider still receives the assistant text + the user message). Pre-fix
		// this assertion is unreachable — the call threw before returning.
		const assistantMessages = input.filter(
			(item): item is ResponseOutputMessage =>
				item.type === "message" && "id" in item && typeof item.id === "string" && item.role === "assistant",
		);
		expect(assistantMessages).toHaveLength(1);
		expect((assistantMessages[0].content[0] as { text?: string }).text).toBe("visible answer");

		// No reasoning item pushed for the corrupt signature (it was skipped, not half-parsed).
		const reasoning = input.filter((item) => (item as { type?: string }).type === "reasoning");
		expect(reasoning).toHaveLength(0);
	});

	it("still pushes the reasoning item for a valid thinkingSignature (no behavior change)", () => {
		const model = getModel("openai-codex", "gpt-5.5");
		const assistant = sameModelAssistant(model, [
			{
				type: "thinking",
				thinking: "private reasoning",
				thinkingSignature: JSON.stringify({ id: "rs_abc", type: "reasoning", summary: [] }),
			},
			{ type: "text", text: "visible answer" },
		]);
		const context: Context = {
			systemPrompt: "",
			messages: [{ role: "user", content: "hi", timestamp: Date.now() - 2000 }, assistant],
		};

		const input = convertResponsesMessages(model, context, new Set(["openai", "openai-codex", "opencode"]));
		const reasoning = input.filter((item) => (item as { type?: string }).type === "reasoning");
		expect(reasoning).toHaveLength(1);
		expect((reasoning[0] as { id?: string }).id).toBe("rs_abc");
	});
});

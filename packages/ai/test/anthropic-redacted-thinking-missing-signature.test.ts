import { describe, expect, it } from "vitest";
import { convertMessages } from "../src/providers/anthropic.ts";
import type { AssistantMessage, Message, Model } from "../src/types.ts";

// opt #214: a redacted-thinking block whose signature is missing/empty (torn
// write, manual edit, schema migration) used to be replayed as
// `{type:"redacted_thinking", data: undefined}` via a non-null assertion.
// Anthropic rejects a redacted_thinking block with missing `data`, aborting the
// ENTIRE turn before any output → every subsequent turn failed until the
// history was repaired. The fix gracefully skips the unreplayable block.

function makeModel(): Model<"anthropic-messages"> {
	return {
		id: "claude-opt214",
		name: "Claude opt #214",
		api: "anthropic-messages",
		provider: "anthropic",
		baseUrl: "http://127.0.0.1:9/anthropic",
		reasoning: true,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 200000,
		maxTokens: 4096,
	};
}

function buildMessages(thinkingSignature: string | undefined, withText: boolean): Message[] {
	const content: AssistantMessage["content"] = [
		{
			type: "thinking",
			thinking: "[Reasoning redacted]",
			thinkingSignature,
			redacted: true,
		},
	];
	if (withText) {
		content.push({ type: "text", text: "visible answer" });
	}
	const assistant: AssistantMessage = {
		role: "assistant",
		content,
		provider: "anthropic",
		api: "anthropic-messages",
		model: "claude-opt214",
		timestamp: 1,
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
	};
	return [
		{ role: "user", content: "first", timestamp: 0 },
		assistant,
		{ role: "user", content: "second", timestamp: 2 },
	];
}

function assistantContent(
	params: ReturnType<typeof convertMessages>,
): Array<{ type: string; data?: string }> | undefined {
	const assistant = params.find((m) => m.role === "assistant");
	return assistant?.content as Array<{ type: string; data?: string }> | undefined;
}

describe("opt #214: redacted_thinking without signature degrades gracefully", () => {
	it("drops a redacted-thinking block with missing signature and keeps the rest of the turn", () => {
		// Pre-fix: emitted {type:"redacted_thinking", data: undefined} → Anthropic
		// rejects → whole turn aborted. Post-fix: the unreplayable block is
		// skipped; the text block survives so the turn is still sent.
		const params = convertMessages(buildMessages(undefined, true), makeModel(), false);
		const content = assistantContent(params);
		expect(content).toBeDefined();
		expect(content?.find((b) => b.type === "redacted_thinking")).toBeUndefined();
		expect(content?.find((b) => b.type === "text")).toBeDefined();
	});

	it("drops a redacted-thinking block with empty/whitespace signature", () => {
		const params = convertMessages(buildMessages("   ", true), makeModel(), false);
		const content = assistantContent(params);
		expect(content?.find((b) => b.type === "redacted_thinking")).toBeUndefined();
	});

	it("replays a redacted-thinking block with a valid signature unchanged", () => {
		// Regression guard: a healthy redacted-thinking block still round-trips.
		const params = convertMessages(buildMessages("opaque-redacted-blob", true), makeModel(), false);
		const content = assistantContent(params);
		expect(content).toContainEqual({ type: "redacted_thinking", data: "opaque-redacted-blob" });
	});

	it("skips the whole assistant turn when the only block is an unsignable redacted-thinking", () => {
		// No text, no valid signature → after dropping the redacted block the
		// turn has no content and is skipped (no malformed empty assistant sent).
		const params = convertMessages(buildMessages(undefined, false), makeModel(), false);
		expect(params.find((m) => m.role === "assistant")).toBeUndefined();
	});
});

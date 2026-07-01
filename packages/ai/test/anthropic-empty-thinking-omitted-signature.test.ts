import { describe, expect, it } from "vitest";
import { convertMessages } from "../src/providers/anthropic.ts";
import type { AssistantMessage, Message, Model } from "../src/types.ts";

// opt #212: thinkingDisplay:"omitted" streams an EMPTY thinking string BUT a
// real signature (signature_delta arrives even when thinking_delta does not).
// The replay path used to drop the whole block on `thinking.trim().length === 0`,
// discarding the signature → the model lost its encrypted reasoning context
// across turns (silent multi-turn reasoning degradation). The fix preserves the
// block when a signature is present.

function makeModel(): Model<"anthropic-messages"> {
	return {
		id: "claude-opt212",
		name: "Claude opt #212",
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

function makeAssistant(thinking: string, thinkingSignature: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "thinking", thinking, thinkingSignature }],
		provider: "anthropic",
		api: "anthropic-messages",
		model: "claude-opt212",
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
}

function buildMessages(thinking: string, thinkingSignature: string): Message[] {
	return [
		{ role: "user", content: "first", timestamp: 0 },
		makeAssistant(thinking, thinkingSignature),
		{ role: "user", content: "second", timestamp: 2 },
	];
}

describe("opt #212: empty-thinking + signature preserved on Anthropic replay", () => {
	it("preserves an empty-thinking block that carries a signature (thinkingDisplay omitted)", () => {
		// Pre-fix: `thinking.trim().length === 0` dropped the block → signature
		// lost. Post-fix: the block is replayed with empty thinking text + the
		// signature so the encrypted reasoning chain travels back.
		const params = convertMessages(buildMessages("", "opaque-sig-omitted"), makeModel(), false);
		const assistant = params.find((m) => m.role === "assistant");
		expect(assistant).toBeDefined();
		const content = assistant?.content as Array<{ type: string; thinking?: string; signature?: string }>;
		expect(content).toContainEqual({ type: "thinking", thinking: "", signature: "opaque-sig-omitted" });
	});

	it("still drops an empty-thinking block when there is no signature", () => {
		// No signature → nothing to replay → drop (unchanged behavior). The
		// preserve-when-signature guard must not keep genuinely-empty blocks.
		const params = convertMessages(buildMessages("", ""), makeModel(), false);
		const assistant = params.find((m) => m.role === "assistant");
		// The assistant had only one (empty, no-signature) thinking block; with it
		// dropped, the assistant turn has no content and is skipped entirely.
		expect(assistant).toBeUndefined();
	});

	it("replays a non-empty thinking block with its signature unchanged", () => {
		// Regression guard: the existing non-empty-thinking path is untouched.
		const params = convertMessages(buildMessages("internal reasoning", "opaque-sig"), makeModel(), false);
		const assistant = params.find((m) => m.role === "assistant");
		expect(assistant).toBeDefined();
		const content = assistant?.content as Array<{ type: string; thinking?: string; signature?: string }>;
		expect(content).toContainEqual({ type: "thinking", thinking: "internal reasoning", signature: "opaque-sig" });
	});
});

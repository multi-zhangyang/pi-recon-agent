import { describe, expect, it } from "vitest";
import { getModel } from "../src/models.ts";
import { transformMessages } from "../src/providers/transform-messages.ts";
import type { AssistantMessage, Message, Model, ToolResultMessage } from "../src/types.ts";

// opt #216: an assistant turn with stopReason "error"/"aborted" is skipped by
// transform-messages (incomplete turn). Pre-fix, a toolResult in history for
// one of that skipped assistant's tool calls was still replayed — with NO
// preceding tool_use → provider rejection ("tool result without matching tool
// call"). The fix tracks the skipped assistant's tool-call ids and drops the
// orphaned toolResult too.

const usage = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

function makeModel(): Model<"anthropic-messages"> {
	return getModel("anthropic", "claude-sonnet-4-5") as Model<"anthropic-messages">;
}

function erroredAssistant(toolCallId: string): AssistantMessage {
	return {
		role: "assistant",
		content: [
			{ type: "text", text: "partial" },
			{ type: "toolCall", id: toolCallId, name: "edit", arguments: { path: "x.ts" } },
		],
		provider: "anthropic",
		api: "anthropic-messages",
		model: "claude-sonnet-4-5",
		usage,
		stopReason: "error",
		timestamp: 1,
	};
}

function validAssistant(toolCallId: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "toolCall", id: toolCallId, name: "read", arguments: { path: "y.ts" } }],
		provider: "anthropic",
		api: "anthropic-messages",
		model: "claude-sonnet-4-5",
		usage,
		stopReason: "toolUse",
		timestamp: 3,
	};
}

function toolResult(toolCallId: string, toolName: string): ToolResultMessage {
	return {
		role: "toolResult",
		toolCallId,
		toolName,
		content: [{ type: "text", text: "ok" }],
		isError: false,
		timestamp: 2,
	};
}

describe("opt #216: orphaned toolResult after skipped errored assistant is dropped", () => {
	it("drops a toolResult whose tool_use came from a skipped errored assistant", () => {
		const messages: Message[] = [
			{ role: "user", content: "do it", timestamp: 0 },
			erroredAssistant("call_err_1"),
			toolResult("call_err_1", "edit"),
			{ role: "user", content: "again", timestamp: 4 },
		];
		const out = transformMessages(messages, makeModel());
		// The errored assistant is dropped...
		expect(out.find((m) => m.role === "assistant")).toBeUndefined();
		// ...and so is its orphaned toolResult (no tool_use to answer).
		expect(out.find((m) => m.role === "toolResult")).toBeUndefined();
	});

	it("keeps a toolResult whose tool_use came from a valid assistant", () => {
		// Regression guard: the normal assistant→toolResult flow is untouched.
		const messages: Message[] = [
			{ role: "user", content: "do it", timestamp: 0 },
			validAssistant("call_ok_1"),
			toolResult("call_ok_1", "read"),
		];
		const out = transformMessages(messages, makeModel());
		const assistant = out.find((m) => m.role === "assistant");
		expect(assistant).toBeDefined();
		const result = out.find((m) => m.role === "toolResult");
		expect(result).toBeDefined();
		expect((result as ToolResultMessage).toolCallId).toBe("call_ok_1");
	});

	it("drops only the orphaned result, keeping a later valid assistant + result pair", () => {
		// Errored assistant + orphaned result, followed by a fresh valid turn.
		const messages: Message[] = [
			{ role: "user", content: "first", timestamp: 0 },
			erroredAssistant("call_err_2"),
			toolResult("call_err_2", "edit"),
			{ role: "user", content: "second", timestamp: 4 },
			validAssistant("call_ok_2"),
			toolResult("call_ok_2", "read"),
		];
		const out = transformMessages(messages, makeModel());
		const results = out.filter((m) => m.role === "toolResult") as ToolResultMessage[];
		// Only the valid turn's result survives.
		expect(results).toHaveLength(1);
		expect(results[0].toolCallId).toBe("call_ok_2");
	});
});

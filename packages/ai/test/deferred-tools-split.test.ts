import { Type } from "typebox";
import { describe, expect, it } from "vitest";
import type { AssistantMessage, Context, Tool, ToolResultMessage } from "../src/types.ts";
import { splitDeferredTools } from "../src/utils/deferred-tools.ts";

function makeTool(name: string, description = `${name} tool`): Tool {
	return { name, description, parameters: Type.Object({}) };
}

function makeAssistantToolCall(name: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "toolCall", id: `call-${name}`, name, arguments: {} }],
		api: "anthropic-messages",
		provider: "anthropic",
		model: "test-model",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "toolUse",
		timestamp: 1,
	};
}

function makeMarker(addedToolNames: string[]): ToolResultMessage {
	return {
		role: "toolResult",
		toolCallId: "call-base",
		toolName: "base",
		content: [{ type: "text", text: "loaded" }],
		addedToolNames,
		isError: false,
		timestamp: 2,
	};
}

describe("splitDeferredTools", () => {
	it("splits tools introduced by transcript markers", () => {
		const context: Context = {
			messages: [makeAssistantToolCall("base"), makeMarker(["late"])],
			tools: [makeTool("base"), makeTool("late")],
		};

		const split = splitDeferredTools(context, true);

		expect(split.immediate.map((tool) => tool.name)).toEqual(["base"]);
		expect([...split.deferred.keys()]).toEqual(["late"]);
	});

	it("keeps tools immediate when deferred loading is disabled or they were used before their marker", () => {
		const tools = [makeTool("base"), makeTool("late")];
		const usedBeforeMarker: Context = {
			messages: [makeAssistantToolCall("late"), makeMarker(["late"])],
			tools,
		};

		expect(splitDeferredTools(usedBeforeMarker, false).immediate).toEqual(tools);
		expect(splitDeferredTools(usedBeforeMarker, true).immediate).toEqual(tools);
		expect(splitDeferredTools(usedBeforeMarker, true).deferred.size).toBe(0);
	});

	it("normalizes and deduplicates tool names using the last active definition", () => {
		const canonical = makeTool("Read", "canonical");
		const context: Context = {
			messages: [makeMarker(["READ"])],
			tools: [makeTool("read", "legacy"), canonical],
		};

		const split = splitDeferredTools(context, true, (name) => name.toLowerCase());

		expect(split.immediate).toEqual([]);
		expect(split.deferred.get("read")).toBe(canonical);
	});

	it("ignores markers for tools absent from the current context", () => {
		const base = makeTool("base");
		const split = splitDeferredTools({ messages: [makeMarker(["missing"])], tools: [base] }, true);

		expect(split.immediate).toEqual([base]);
		expect(split.deferred.size).toBe(0);
	});
});

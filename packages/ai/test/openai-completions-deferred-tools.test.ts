import { Type } from "typebox";
import { describe, expect, it } from "vitest";
import { streamSimple } from "../src/stream.ts";
import type { AssistantMessage, Context, Model, Tool, ToolResultMessage } from "../src/types.ts";

interface DeferredTool {
	type: "function";
	function: { name: string };
}

interface DeferredToolMessage {
	role: string;
	content?: unknown;
	tools?: DeferredTool[];
}

interface DeferredToolPayload {
	tools?: DeferredTool[];
	messages: DeferredToolMessage[];
}

class PayloadCaptured extends Error {}

function makeTool(name: string): Tool {
	return { name, description: `${name} tool`, parameters: Type.Object({}) };
}

function makeAssistant(): AssistantMessage {
	return {
		role: "assistant",
		content: [
			{ type: "toolCall", id: "call-1", name: "base", arguments: {} },
			{ type: "toolCall", id: "call-2", name: "base", arguments: {} },
		],
		api: "openai-completions",
		provider: "custom-proxy",
		model: "deferred-tools-model",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "toolUse",
		timestamp: 2,
	};
}

function makeResult(toolCallId: string, addedToolNames: string[]): ToolResultMessage {
	return {
		role: "toolResult",
		toolCallId,
		toolName: "base",
		content: [{ type: "text", text: "done" }],
		addedToolNames,
		isError: false,
		timestamp: 3,
	};
}

function makeContext(): Context {
	return {
		messages: [
			{ role: "user", content: "start", timestamp: 1 },
			makeAssistant(),
			makeResult("call-1", ["late"]),
			makeResult("call-2", ["later"]),
			{ role: "user", content: "continue", timestamp: 4 },
		],
		tools: [makeTool("base"), makeTool("late"), makeTool("later")],
	};
}

function makeModel(deferredToolsMode?: "system-message"): Model<"openai-completions"> {
	return {
		id: "deferred-tools-model",
		name: "Deferred Tools Model",
		api: "openai-completions",
		provider: "custom-proxy",
		baseUrl: "http://127.0.0.1:9/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 128000,
		maxTokens: 4096,
		...(deferredToolsMode ? { compat: { deferredToolsMode } } : {}),
	};
}

async function capturePayload(model: Model<"openai-completions">): Promise<DeferredToolPayload> {
	let captured: DeferredToolPayload | undefined;
	const stream = streamSimple(model, makeContext(), {
		apiKey: "fake-key",
		onPayload: (payload) => {
			captured = payload as DeferredToolPayload;
			throw new PayloadCaptured();
		},
	});
	await stream.result();
	if (!captured) throw new Error("Expected OpenAI Completions payload capture");
	return captured;
}

describe("OpenAI Completions deferred tools", () => {
	it("loads schemas after all consecutive tool results when explicitly enabled", async () => {
		const payload = await capturePayload(makeModel("system-message"));

		expect(payload.tools?.map((tool) => tool.function.name)).toEqual(["base"]);
		expect(payload.messages.map((message) => message.role)).toEqual([
			"user",
			"assistant",
			"tool",
			"tool",
			"system",
			"user",
		]);
		const systemToolMessage = payload.messages[4];
		expect(systemToolMessage).not.toHaveProperty("content");
		expect(systemToolMessage?.tools?.map((tool) => tool.function.name)).toEqual(["late", "later"]);
	});

	it("keeps every tool immediate for custom providers by default", async () => {
		const payload = await capturePayload(makeModel());

		expect(payload.tools?.map((tool) => tool.function.name)).toEqual(["base", "late", "later"]);
		expect(payload.messages.some((message) => message.tools !== undefined)).toBe(false);
	});
});

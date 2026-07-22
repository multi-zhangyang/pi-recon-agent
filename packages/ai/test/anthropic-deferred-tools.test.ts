import { Type } from "typebox";
import { describe, expect, it } from "vitest";
import { streamSimple } from "../src/stream.ts";
import type { AssistantMessage, Context, Model, Tool, ToolResultMessage } from "../src/types.ts";

interface AnthropicToolPayload {
	name: string;
	defer_loading?: boolean;
}

interface AnthropicContentBlock {
	type: string;
	tool_use_id?: string;
	content?: string | Array<{ type: string; tool_name?: string }>;
	text?: string;
	source?: { type: string; media_type: string; data: string };
}

interface AnthropicPayload {
	tools?: AnthropicToolPayload[];
	messages: Array<{ role: string; content: string | AnthropicContentBlock[] }>;
}

class PayloadCaptured extends Error {}

function makeModel(provider: string, compat?: Model<"anthropic-messages">["compat"]): Model<"anthropic-messages"> {
	return {
		id: "claude-opus-4-6",
		name: "Claude Opus 4.6",
		api: "anthropic-messages",
		provider,
		baseUrl: "https://api.anthropic.com",
		reasoning: false,
		input: ["text", "image"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 200000,
		maxTokens: 4096,
		...(compat ? { compat } : {}),
	};
}

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
		api: "anthropic-messages",
		provider: "anthropic",
		model: "claude-opus-4-6",
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

function makeResult(
	toolCallId: string,
	addedToolNames: string[],
	content: ToolResultMessage["content"] = [{ type: "text", text: "done" }],
): ToolResultMessage {
	return {
		role: "toolResult",
		toolCallId,
		toolName: "base",
		content,
		addedToolNames,
		isError: false,
		timestamp: 3,
	};
}

function makeContext(tools: Tool[] = [makeTool("base"), makeTool("late")]): Context {
	return {
		messages: [
			{ role: "user", content: "start", timestamp: 1 },
			makeAssistant(),
			makeResult(
				"call-1",
				["late"],
				[
					{ type: "text", text: "work completed" },
					{ type: "image", mimeType: "image/png", data: "aW1hZ2U=" },
				],
			),
			makeResult("call-2", [], [{ type: "text", text: "second result" }]),
			{ role: "user", content: "continue", timestamp: 4 },
		],
		tools,
	};
}

async function capturePayload(model: Model<"anthropic-messages">, context: Context): Promise<AnthropicPayload> {
	let captured: AnthropicPayload | undefined;
	const stream = streamSimple(model, context, {
		apiKey: "fake-key",
		cacheRetention: "none",
		onPayload: (payload) => {
			captured = payload as AnthropicPayload;
			throw new PayloadCaptured();
		},
	});
	await stream.result();
	if (!captured) throw new Error("Expected Anthropic payload capture");
	return captured;
}

function toolResultContent(payload: AnthropicPayload): AnthropicContentBlock[] {
	const message = payload.messages.find(
		(candidate) =>
			Array.isArray(candidate.content) && candidate.content.some((block) => block.type === "tool_result"),
	);
	if (!message || typeof message.content === "string") throw new Error("Expected Anthropic tool result message");
	return message.content;
}

describe("Anthropic message-anchored deferred tools", () => {
	it("loads a first-party deferred tool at its transcript marker and preserves output siblings", async () => {
		const payload = await capturePayload(makeModel("anthropic"), makeContext());

		expect(payload.tools).toMatchObject([{ name: "base" }, { name: "late", defer_loading: true }]);
		expect(toolResultContent(payload)).toMatchObject([
			{
				type: "tool_result",
				tool_use_id: "call-1",
				content: [{ type: "tool_reference", tool_name: "late" }],
			},
			{ type: "tool_result", tool_use_id: "call-2", content: "second result" },
			{ type: "text", text: "work completed" },
			{ type: "image", source: { type: "base64", media_type: "image/png", data: "aW1hZ2U=" } },
		]);
	});

	it.each([
		["explicitly disabled first-party", makeModel("anthropic", { supportsToolReferences: false })],
		["custom provider default", makeModel("anthropic-proxy")],
		["custom base URL", { ...makeModel("anthropic"), baseUrl: "https://proxy.example/v1" }],
	] as const)("uses the complete immediate list for %s", async (_label, model) => {
		const payload = await capturePayload(model, makeContext());

		expect(payload.tools?.map((tool) => tool.name)).toEqual(["base", "late"]);
		expect(payload.tools?.every((tool) => tool.defer_loading === undefined)).toBe(true);
		expect(toolResultContent(payload)[0]?.content).not.toEqual([{ type: "tool_reference", tool_name: "late" }]);
	});

	it("allows a custom provider to opt in explicitly", async () => {
		const payload = await capturePayload(
			makeModel("anthropic-proxy", { supportsToolReferences: true }),
			makeContext(),
		);

		expect(payload.tools?.find((tool) => tool.name === "late")?.defer_loading).toBe(true);
		expect(toolResultContent(payload)[0]?.content).toEqual([{ type: "tool_reference", tool_name: "late" }]);
	});

	it("keeps every tool immediate when all active tools would otherwise be deferred", async () => {
		const context = makeContext([makeTool("late")]);
		const payload = await capturePayload(makeModel("anthropic"), context);

		expect(payload.tools).toEqual([expect.objectContaining({ name: "late" })]);
		expect(payload.tools?.[0]?.defer_loading).toBeUndefined();
		expect(toolResultContent(payload)[0]?.content).not.toEqual([{ type: "tool_reference", tool_name: "late" }]);
	});
});

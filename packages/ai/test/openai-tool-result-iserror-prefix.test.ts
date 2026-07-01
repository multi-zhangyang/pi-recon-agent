import { describe, expect, it } from "vitest";
import { getModel } from "../src/models.ts";
import { convertMessages } from "../src/providers/openai-completions.ts";
import { convertResponsesMessages } from "../src/providers/openai-responses-shared.ts";
import type {
	AssistantMessage,
	Context,
	Model,
	OpenAICompletionsCompat,
	ToolResultMessage,
	Usage,
} from "../src/types.ts";

const usage: Usage = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

const compat: Required<OpenAICompletionsCompat> = {
	supportsStore: true,
	supportsDeveloperRole: true,
	supportsReasoningEffort: true,
	supportsUsageInStreaming: true,
	maxTokensField: "max_completion_tokens",
	requiresToolResultName: false,
	requiresAssistantAfterToolResult: false,
	requiresThinkingAsText: false,
	requiresReasoningContentOnAssistantMessages: false,
	thinkingFormat: "openai",
	openRouterRouting: {},
	vercelGatewayRouting: {},
	zaiToolStream: false,
	supportsStrictMode: true,
	cacheControlFormat: "anthropic",
	sendSessionAffinityHeaders: false,
	supportsLongCacheRetention: true,
};

function buildAssistant(toolCallId: string, now: number): AssistantMessage {
	const model = getModel("openai", "gpt-4o-mini");
	return {
		role: "assistant",
		content: [{ type: "toolCall", id: toolCallId, name: "edit", arguments: { path: "x.ts" } }],
		api: "openai-completions",
		provider: "openai",
		model: model.id,
		usage,
		stopReason: "toolUse",
		timestamp: now,
	};
}

function buildToolResult(toolCallId: string, text: string, isError: boolean, now: number): ToolResultMessage {
	return {
		role: "toolResult",
		toolCallId,
		toolName: "edit",
		content: [{ type: "text", text }],
		isError,
		timestamp: now,
	};
}

describe("openai-completions tool result isError prefix", () => {
	it("prefixes [tool error] when isError is true so a failed tool is not mistaken for success", () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini");
		const model: Model<"openai-completions"> = { ...baseModel, api: "openai-completions", input: ["text"] };
		const now = Date.now();
		const context: Context = {
			messages: [
				{ role: "user", content: "edit it", timestamp: now - 2 },
				buildAssistant("tool-err", now - 1),
				buildToolResult("tool-err", "Could not find the exact text in x.ts.", true, now),
			],
		};

		const messages = convertMessages(model, context, compat);
		const toolMsg = messages.find((m) => m.role === "tool") as { content: string; tool_call_id: string };
		expect(toolMsg).toBeDefined();
		expect(toolMsg.content).toContain("[tool error]");
		expect(toolMsg.content).toContain("Could not find the exact text");
	});

	it("does not prefix a successful tool result", () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini");
		const model: Model<"openai-completions"> = { ...baseModel, api: "openai-completions", input: ["text"] };
		const now = Date.now();
		const context: Context = {
			messages: [
				{ role: "user", content: "edit it", timestamp: now - 2 },
				buildAssistant("tool-ok", now - 1),
				buildToolResult("tool-ok", "Successfully replaced 1 block(s) in x.ts.", false, now),
			],
		};

		const messages = convertMessages(model, context, compat);
		const toolMsg = messages.find((m) => m.role === "tool") as { content: string };
		expect(toolMsg.content).not.toContain("[tool error]");
		expect(toolMsg.content).toContain("Successfully replaced");
	});
});

describe("openai-responses tool result isError prefix", () => {
	it("prefixes [tool error] on function_call_output when isError is true", () => {
		const model = getModel("openai-codex", "gpt-5.5");
		const now = Date.now();
		const assistant: AssistantMessage = {
			role: "assistant",
			content: [{ type: "toolCall", id: "call_abc|fc_item1", name: "edit", arguments: { path: "x.ts" } }],
			api: "openai-responses",
			provider: "openai-codex",
			model: model.id,
			usage,
			stopReason: "toolUse",
			timestamp: now - 1,
		};
		const toolResult: ToolResultMessage = {
			role: "toolResult",
			toolCallId: "call_abc|fc_item1",
			toolName: "edit",
			content: [{ type: "text", text: "Could not find the exact text in x.ts." }],
			isError: true,
			timestamp: now,
		};
		const context: Context = {
			messages: [{ role: "user", content: "edit it", timestamp: now - 2 }, assistant, toolResult],
		};

		const input = convertResponsesMessages(model, context, new Set(["openai", "openai-codex", "opencode"]));
		const output = input.find(
			(item): item is { type: "function_call_output"; call_id: string; output: string } =>
				item.type === "function_call_output" && typeof (item as { output?: unknown }).output === "string",
		);
		expect(output).toBeDefined();
		expect(output?.output).toContain("[tool error]");
		expect(output?.output).toContain("Could not find the exact text");
	});

	it("does not prefix a successful responses tool result", () => {
		const model = getModel("openai-codex", "gpt-5.5");
		const now = Date.now();
		const assistant: AssistantMessage = {
			role: "assistant",
			content: [{ type: "toolCall", id: "call_abc|fc_item1", name: "edit", arguments: { path: "x.ts" } }],
			api: "openai-responses",
			provider: "openai-codex",
			model: model.id,
			usage,
			stopReason: "toolUse",
			timestamp: now - 1,
		};
		const toolResult: ToolResultMessage = {
			role: "toolResult",
			toolCallId: "call_abc|fc_item1",
			toolName: "edit",
			content: [{ type: "text", text: "Successfully replaced 1 block(s) in x.ts." }],
			isError: false,
			timestamp: now,
		};
		const context: Context = {
			messages: [{ role: "user", content: "edit it", timestamp: now - 2 }, assistant, toolResult],
		};

		const input = convertResponsesMessages(model, context, new Set(["openai", "openai-codex", "opencode"]));
		const output = input.find(
			(item): item is { type: "function_call_output"; call_id: string; output: string } =>
				item.type === "function_call_output" && typeof (item as { output?: unknown }).output === "string",
		);
		expect(output?.output).not.toContain("[tool error]");
		expect(output?.output).toContain("Successfully replaced");
	});
});

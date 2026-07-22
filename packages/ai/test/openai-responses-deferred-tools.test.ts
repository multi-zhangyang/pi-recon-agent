import { Type } from "typebox";
import { describe, expect, it } from "vitest";
import { streamSimple } from "../src/stream.ts";
import type { Api, AssistantMessage, Context, Model, Tool, ToolResultMessage } from "../src/types.ts";

interface ToolSearchCall {
	type: "tool_search_call";
	call_id?: string | null;
	execution?: string;
	status?: string | null;
}

interface ToolSearchOutput {
	type: "tool_search_output";
	call_id?: string | null;
	execution?: string;
	status?: string | null;
	tools: Array<{ type: string; name: string; defer_loading?: boolean }>;
}

interface OpenAIResponsesPayload {
	tools?: Array<{ type: string; name: string; defer_loading?: boolean }>;
	input?: Array<ToolSearchCall | ToolSearchOutput | { type?: string }>;
}

class PayloadCaptured extends Error {}

function makeTool(name: string): Tool {
	return { name, description: `${name} tool`, parameters: Type.Object({}) };
}

function makeAssistant(api: Api, provider: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "toolCall", id: "call-1", name: "base", arguments: {} }],
		api,
		provider,
		model: "gpt-5.4",
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

function makeContext(api: Api = "openai-responses", provider = "openai"): Context {
	const result: ToolResultMessage = {
		role: "toolResult",
		toolCallId: "call-1",
		toolName: "base",
		content: [{ type: "text", text: "loaded" }],
		addedToolNames: ["late"],
		isError: false,
		timestamp: 3,
	};
	return {
		messages: [
			{ role: "user", content: "start", timestamp: 1 },
			makeAssistant(api, provider),
			result,
			{ role: "user", content: "continue", timestamp: 4 },
		],
		tools: [makeTool("base"), makeTool("late")],
	};
}

function makeResponsesModel(
	id = "gpt-5.4",
	provider = "openai",
	baseUrl = "https://api.openai.com/v1",
	compat?: Model<"openai-responses">["compat"],
): Model<"openai-responses"> {
	return {
		id,
		name: id,
		api: "openai-responses",
		provider,
		baseUrl,
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 200000,
		maxTokens: 4096,
		...(compat ? { compat } : {}),
	};
}

function makeCodexModel(id = "gpt-5.4"): Model<"openai-codex-responses"> {
	return {
		id,
		name: id,
		api: "openai-codex-responses",
		provider: "openai-codex",
		baseUrl: "https://chatgpt.com/backend-api",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 200000,
		maxTokens: 4096,
	};
}

function makeCodexToken(): string {
	const claims = { "https://api.openai.com/auth": { chatgpt_account_id: "account" } };
	return `header.${btoa(JSON.stringify(claims))}.signature`;
}

async function capturePayload<TApi extends "openai-responses" | "openai-codex-responses">(
	model: Model<TApi>,
	context: Context,
	apiKey = "fake-key",
): Promise<OpenAIResponsesPayload> {
	let captured: OpenAIResponsesPayload | undefined;
	const stream = streamSimple(model, context, {
		apiKey,
		transport: "sse",
		onPayload: (payload) => {
			captured = payload as OpenAIResponsesPayload;
			throw new PayloadCaptured();
		},
	});
	await stream.result();
	if (!captured) throw new Error("Expected OpenAI Responses payload capture");
	return captured;
}

function findSearchItems(payload: OpenAIResponsesPayload): {
	call: ToolSearchCall | undefined;
	output: ToolSearchOutput | undefined;
} {
	return {
		call: payload.input?.find((item): item is ToolSearchCall => item.type === "tool_search_call"),
		output: payload.input?.find((item): item is ToolSearchOutput => item.type === "tool_search_output"),
	};
}

function expectDeferredAnchor(payload: OpenAIResponsesPayload): void {
	expect(payload.tools?.map((tool) => tool.name)).toEqual(["base"]);
	const { call, output } = findSearchItems(payload);
	expect(call).toMatchObject({ execution: "client", status: "completed" });
	expect(output?.call_id).toBe(call?.call_id);
	expect(output?.tools).toMatchObject([{ type: "function", name: "late", defer_loading: true }]);

	const outputIndex = payload.input?.findIndex((item) => item.type === "function_call_output") ?? -1;
	const callIndex = payload.input?.findIndex((item) => item.type === "tool_search_call") ?? -1;
	const searchOutputIndex = payload.input?.findIndex((item) => item.type === "tool_search_output") ?? -1;
	expect(outputIndex).toBeGreaterThanOrEqual(0);
	expect(callIndex).toBeGreaterThan(outputIndex);
	expect(searchOutputIndex).toBeGreaterThan(callIndex);
}

describe("OpenAI Responses message-anchored deferred tools", () => {
	it("loads a supported first-party tool through client tool search", async () => {
		const payload = await capturePayload(makeResponsesModel(), makeContext());
		expectDeferredAnchor(payload);
	});

	it.each([
		["unsupported model", makeResponsesModel("gpt-5.4-nano")],
		["explicitly disabled", makeResponsesModel("gpt-5.4", "openai", undefined, { supportsToolSearch: false })],
		["custom provider", makeResponsesModel("gpt-5.4", "openai-proxy")],
		["custom base URL", makeResponsesModel("gpt-5.4", "openai", "https://proxy.example/v1")],
	] as const)("uses the complete immediate list for %s", async (_label, model) => {
		const payload = await capturePayload(model, makeContext());

		expect(payload.tools?.map((tool) => tool.name)).toEqual(["base", "late"]);
		expect(findSearchItems(payload)).toEqual({ call: undefined, output: undefined });
	});

	it("allows a custom provider to opt in explicitly", async () => {
		const model = makeResponsesModel("gpt-5.4", "openai-proxy", "https://proxy.example/v1", {
			supportsToolSearch: true,
		});
		const payload = await capturePayload(model, makeContext());

		expectDeferredAnchor(payload);
	});

	it("uses the same native anchor for supported Codex models", async () => {
		const payload = await capturePayload(
			makeCodexModel(),
			makeContext("openai-codex-responses", "openai-codex"),
			makeCodexToken(),
		);

		expectDeferredAnchor(payload);
	});

	it("keeps unsupported Codex models on the complete immediate list", async () => {
		const payload = await capturePayload(
			makeCodexModel("gpt-5.3-codex-spark"),
			makeContext("openai-codex-responses", "openai-codex"),
			makeCodexToken(),
		);

		expect(payload.tools?.map((tool) => tool.name)).toEqual(["base", "late"]);
		expect(findSearchItems(payload)).toEqual({ call: undefined, output: undefined });
	});
});

import { Type } from "typebox";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getModel } from "../src/models.ts";
import { streamSimple } from "../src/stream.ts";
import type { Tool } from "../src/types.ts";
import { registerOpenAIFixtures } from "./model-fixtures.ts";

registerOpenAIFixtures();

const mockState = vi.hoisted(() => ({
	lastParams: undefined as unknown,
	chunks: undefined as
		| Array<null | {
				id?: string;
				choices?: Array<{
					delta: Record<string, unknown>;
					finish_reason: string | null;
					usage?: unknown;
				}>;
				usage?: {
					prompt_tokens: number;
					completion_tokens: number;
					prompt_tokens_details: { cached_tokens: number; cache_write_tokens?: number };
					completion_tokens_details: { reasoning_tokens: number };
				};
		  }>
		| undefined,
}));

vi.mock("openai", () => {
	class FakeOpenAI {
		chat = {
			completions: {
				create: (params: unknown) => {
					mockState.lastParams = params;
					const stream = {
						async *[Symbol.asyncIterator]() {
							const chunks = mockState.chunks ?? [
								{
									choices: [{ delta: {}, finish_reason: "stop" }],
									usage: {
										prompt_tokens: 1,
										completion_tokens: 1,
										prompt_tokens_details: { cached_tokens: 0 },
										completion_tokens_details: { reasoning_tokens: 0 },
									},
								},
							];
							for (const chunk of chunks) {
								yield chunk;
							}
						},
					};
					const promise = Promise.resolve(stream) as Promise<typeof stream> & {
						withResponse: () => Promise<{
							data: typeof stream;
							response: { status: number; headers: Headers };
						}>;
					};
					promise.withResponse = async () => ({
						data: stream,
						response: { status: 200, headers: new Headers() },
					});
					return promise;
				},
			},
		};
	}

	return { default: FakeOpenAI };
});

describe("opt #211: reasoning.encrypted detail preceding tool_calls delta", () => {
	beforeEach(() => {
		mockState.lastParams = undefined;
		mockState.chunks = undefined;
	});

	it("attaches thoughtSignature when the encrypted detail arrives BEFORE the tool_calls delta", async () => {
		// OpenAI o-series-style encrypted reasoning via the completions API:
		// reasoning is generated BEFORE the tool call it accompanies, so the
		// reasoning.encrypted detail typically arrives in an EARLIER SSE chunk
		// than the corresponding tool_calls delta. An eager match at
		// detail-arrival time finds no tool-call block yet -> thoughtSignature
		// was never set -> convertMessages could not replay the encrypted
		// reasoning chain next turn (silent data loss). The fix buffers every
		// encrypted detail and reconciles after the stream loop, when all
		// tool-call blocks exist.
		mockState.chunks = [
			{
				id: "chatcmpl-encrypted-before-toolcall",
				choices: [
					{
						delta: {
							reasoning_details: [
								{
									type: "reasoning.encrypted",
									id: "call_1",
									data: "opaque-encrypted-reasoning-blob",
								},
							],
						},
						finish_reason: null,
					},
				],
			},
			{
				id: "chatcmpl-encrypted-before-toolcall",
				choices: [
					{
						delta: {
							tool_calls: [
								{
									index: 0,
									id: "call_1",
									type: "function",
									function: { name: "edit", arguments: '{"path":"x.txt"}' },
								},
							],
						},
						finish_reason: "tool_calls",
					},
				],
				usage: {
					prompt_tokens: 10,
					completion_tokens: 5,
					prompt_tokens_details: { cached_tokens: 0 },
					completion_tokens_details: { reasoning_tokens: 0 },
				},
			},
		];

		const { compat: _compat, ...baseModel } = getModel<"openai-responses">("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;
		const tool: Tool = {
			name: "edit",
			description: "Edit a file",
			parameters: Type.Object({ path: Type.String() }),
		};
		const s = streamSimple(
			model,
			{
				messages: [
					{
						role: "user",
						content: "Edit x.txt",
						timestamp: Date.now(),
					},
				],
				tools: [tool],
			},
			{ apiKey: "test" },
		);

		const response = await s.result();
		expect(response.stopReason).toBe("toolUse");
		const toolCall = response.content.find((c) => c.type === "toolCall");
		expect(toolCall).toBeDefined();
		if (toolCall?.type !== "toolCall") {
			throw new Error("Expected toolCall content");
		}
		expect(toolCall.id).toBe("call_1");
		// The encrypted detail must have been reconciled onto the tool call as
		// its thoughtSignature (a JSON string carrying the detail). Pre-fix this
		// was undefined because the eager match ran before the tool-call block
		// existed.
		expect(toolCall.thoughtSignature).toBeDefined();
		expect(toolCall.thoughtSignature).toContain("opaque-encrypted-reasoning-blob");
	});

	it("attaches thoughtSignature when the encrypted detail arrives AFTER the tool_calls delta (original order)", async () => {
		// The reconcile pass must also handle the original (detail-after-delta)
		// order so the fix is not a regression for servers that send the detail
		// afterwards.
		mockState.chunks = [
			{
				id: "chatcmpl-encrypted-after-toolcall",
				choices: [
					{
						delta: {
							tool_calls: [
								{
									index: 0,
									id: "call_2",
									type: "function",
									function: { name: "edit", arguments: '{"path":"y.txt"}' },
								},
							],
						},
						finish_reason: null,
					},
				],
			},
			{
				id: "chatcmpl-encrypted-after-toolcall",
				choices: [
					{
						delta: {
							reasoning_details: [
								{
									type: "reasoning.encrypted",
									id: "call_2",
									data: "opaque-blob-after",
								},
							],
						},
						finish_reason: "tool_calls",
					},
				],
				usage: {
					prompt_tokens: 10,
					completion_tokens: 5,
					prompt_tokens_details: { cached_tokens: 0 },
					completion_tokens_details: { reasoning_tokens: 0 },
				},
			},
		];

		const { compat: _compat, ...baseModel } = getModel<"openai-responses">("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;
		const tool: Tool = {
			name: "edit",
			description: "Edit a file",
			parameters: Type.Object({ path: Type.String() }),
		};
		const s = streamSimple(
			model,
			{
				messages: [
					{
						role: "user",
						content: "Edit y.txt",
						timestamp: Date.now(),
					},
				],
				tools: [tool],
			},
			{ apiKey: "test" },
		);

		const response = await s.result();
		expect(response.stopReason).toBe("toolUse");
		const toolCall = response.content.find((c) => c.type === "toolCall");
		if (toolCall?.type !== "toolCall") {
			throw new Error("Expected toolCall content");
		}
		expect(toolCall.id).toBe("call_2");
		expect(toolCall.thoughtSignature).toBeDefined();
		expect(toolCall.thoughtSignature).toContain("opaque-blob-after");
	});
});

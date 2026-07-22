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
				choices?: Array<{ delta: Record<string, unknown>; finish_reason: string | null; usage?: unknown }>;
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

describe("openai-completions numeric tool-call id", () => {
	beforeEach(() => {
		mockState.lastParams = undefined;
		mockState.chunks = undefined;
	});

	it("preserves a numeric id of 0 as the string '0' on the finalized tool_use block", async () => {
		// Some OpenRouter / vLLM-compatible servers send NUMERIC tool-call ids.
		// id `0` is falsy and must not collapse to "".
		mockState.chunks = [
			{
				id: "chatcmpl-numeric-id-zero",
				choices: [
					{
						delta: {
							tool_calls: [
								{
									index: 0,
									id: 0,
									type: "function",
									function: { name: "read", arguments: '{"path":"README.md"}' },
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
			name: "read",
			description: "Read a file",
			parameters: Type.Object({ path: Type.String() }),
		};
		const s = streamSimple(
			model,
			{
				messages: [
					{
						role: "user",
						content: "Read README.md",
						timestamp: Date.now(),
					},
				],
				tools: [tool],
			},
			{ apiKey: "test" },
		);

		const response = await s.result();
		expect(response.stopReason).toBe("toolUse");
		expect(response.content).toHaveLength(1);
		const toolCall = response.content[0];
		expect(toolCall.type).toBe("toolCall");
		if (toolCall.type !== "toolCall") {
			throw new Error("Expected toolCall content");
		}
		expect(toolCall.id).toBe("0");
		expect(toolCall.id).not.toBe("");
		expect(toolCall.name).toBe("read");
		expect(toolCall.arguments).toEqual({ path: "README.md" });
	});

	it("produces two distinct blocks for numeric ids 0 and 1 (no collision from empty-string collapse)", async () => {
		// Without normalization, both id `0` and id `1` would previously still
		// differ, but a regression where id `0` collapses to "" while id `1`
		// becomes "1" must still yield two DISTINCT blocks — and id `0` must be
		// the string "0", not "".
		mockState.chunks = [
			{
				id: "chatcmpl-numeric-ids",
				choices: [
					{
						delta: {
							tool_calls: [
								{
									index: 0,
									id: 0,
									type: "function",
									function: { name: "read", arguments: '{"path":"a.txt"}' },
								},
								{
									index: 1,
									id: 1,
									type: "function",
									function: { name: "grep", arguments: '{"pattern":"TODO"}' },
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
		const tools: Tool[] = [
			{
				name: "read",
				description: "Read a file",
				parameters: Type.Object({ path: Type.String() }),
			},
			{
				name: "grep",
				description: "Search a file",
				parameters: Type.Object({ pattern: Type.String() }),
			},
		];
		const s = streamSimple(
			model,
			{
				messages: [
					{
						role: "user",
						content: "Read a.txt and grep for TODO",
						timestamp: Date.now(),
					},
				],
				tools,
			},
			{ apiKey: "test" },
		);

		const response = await s.result();
		expect(response.stopReason).toBe("toolUse");
		const toolCalls = response.content.filter((c) => c.type === "toolCall");
		expect(toolCalls).toHaveLength(2);
		const ids = toolCalls.map((c) => (c as { id: string }).id);
		expect(ids).toEqual(["0", "1"]);
		expect(new Set(ids).size).toBe(2);
		expect(ids).not.toContain("");
	});

	it("preserves a numeric id across split deltas (id arrives on a later chunk)", async () => {
		// The id may arrive on the first delta for an index while arguments
		// stream in subsequently; the finalized id must still be "0".
		mockState.chunks = [
			{
				id: "chatcmpl-numeric-id-split",
				choices: [
					{
						delta: {
							tool_calls: [
								{
									index: 0,
									id: 0,
									type: "function",
									function: { name: "read", arguments: "" },
								},
							],
						},
						finish_reason: null,
					},
				],
			},
			{
				id: "chatcmpl-numeric-id-split",
				choices: [
					{
						delta: {
							tool_calls: [
								{
									index: 0,
									function: { arguments: '{"path":"README.md"}' },
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
			name: "read",
			description: "Read a file",
			parameters: Type.Object({ path: Type.String() }),
		};
		const s = streamSimple(
			model,
			{
				messages: [
					{
						role: "user",
						content: "Read README.md",
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
		expect(toolCall.id).toBe("0");
		expect(toolCall.id).not.toBe("");
		expect(toolCall.arguments).toEqual({ path: "README.md" });
	});
});

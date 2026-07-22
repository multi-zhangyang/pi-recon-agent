import {
	type AssistantMessage,
	type AssistantMessageEvent,
	type Context,
	EventStream,
	type Message,
	type Model,
	type UserMessage,
} from "@pi-recon/repi-ai";
import { Type } from "typebox";
import { describe, expect, it } from "vitest";
import { agentLoop, compactConsumedToolResults, DEFAULT_FINAL_TURN_PROMPT } from "../src/agent-loop.ts";
import type { AgentLoopConfig, AgentMessage, AgentTool } from "../src/types.ts";

class FauxAssistantStream extends EventStream<AssistantMessageEvent, AssistantMessage> {
	constructor() {
		super(
			(event) => event.type === "done" || event.type === "error",
			(event) => {
				if (event.type === "done") return event.message;
				if (event.type === "error") return event.error;
				throw new Error("Unexpected event");
			},
		);
	}
}

function model(): Model<"openai-responses"> {
	return {
		id: "faux",
		name: "faux",
		api: "openai-responses",
		provider: "faux",
		baseUrl: "https://example.invalid",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 128_000,
		maxTokens: 4096,
	};
}

function assistant(content: AssistantMessage["content"], stopReason: AssistantMessage["stopReason"]): AssistantMessage {
	return {
		role: "assistant",
		content,
		api: "openai-responses",
		provider: "faux",
		model: "faux",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason,
		timestamp: Date.now(),
	};
}

function user(content: string): UserMessage {
	return { role: "user", content, timestamp: Date.now() };
}

function convert(messages: AgentMessage[]): Message[] {
	return messages.filter(
		(message) => message.role === "user" || message.role === "assistant" || message.role === "toolResult",
	) as Message[];
}

function finish(stream: FauxAssistantStream, message: AssistantMessage): void {
	queueMicrotask(() => {
		if (message.stopReason === "error" || message.stopReason === "aborted") {
			throw new Error(`Cannot finish faux success stream with ${message.stopReason}`);
		}
		stream.push({ type: "done", reason: message.stopReason, message });
	});
}

describe("agent loop execution efficiency", () => {
	it("enforces the aggregate consumed-result budget across many small results", () => {
		const messages: AgentMessage[] = [user("probe")];
		for (let index = 0; index < 40; index++) {
			messages.push({
				role: "toolResult",
				toolCallId: `probe-${index}`,
				toolName: "probe",
				content: [{ type: "text", text: "x".repeat(1000) }],
				details: {},
				isError: false,
				timestamp: index,
			});
		}
		messages.push(assistant([{ type: "text", text: "consumed" }], "stop"));

		const projected = compactConsumedToolResults(messages, 4096);
		const chars = projected.reduce(
			(total, message) =>
				total +
				(message.role === "toolResult"
					? message.content.reduce((sum, block) => sum + (block.type === "text" ? block.text.length : 0), 0)
					: 0),
			0,
		);
		expect(chars).toBeLessThanOrEqual(4096);
		expect(messages[1]).toMatchObject({ role: "toolResult", content: [{ text: "x".repeat(1000) }] });
	});

	it("keeps a normal 50KiB consumed result intact when the context budget allows it", () => {
		const resultText = "source-line\n".repeat(Math.ceil((50 * 1024) / 12)).slice(0, 50 * 1024);
		const messages: AgentMessage[] = [
			user("inspect source"),
			{
				role: "toolResult",
				toolCallId: "read-1",
				toolName: "read",
				content: [{ type: "text", text: resultText }],
				details: {},
				isError: false,
				timestamp: 1,
			},
			assistant([{ type: "text", text: "I consumed the source." }], "stop"),
		];

		const projected = compactConsumedToolResults(messages, 128 * 1024);
		expect(projected).toBe(messages);
		expect(projected[1]).toMatchObject({
			role: "toolResult",
			content: [{ type: "text", text: resultText }],
		});
	});

	it("reserves the last bounded request for a tool-free final answer", async () => {
		const schema = Type.Object({ path: Type.String() });
		let executions = 0;
		const tool: AgentTool<typeof schema> = {
			name: "inspect",
			label: "inspect",
			description: "inspect",
			parameters: schema,
			readOnly: true,
			async execute() {
				executions++;
				return { content: [{ type: "text", text: `evidence-${executions}` }], details: {} };
			},
		};
		const providerContexts: Context[] = [];
		let providerCalls = 0;
		const streamFn = (_model: Model<any>, context: Context) => {
			providerContexts.push(context);
			const stream = new FauxAssistantStream();
			const call = providerCalls++;
			const message =
				context.tools && context.tools.length > 0
					? assistant(
							[{ type: "toolCall", id: `inspect-${call}`, name: "inspect", arguments: { path: `p${call}` } }],
							"toolUse",
						)
					: assistant([{ type: "text", text: "final answer from collected evidence" }], "stop");
			finish(stream, message);
			return stream;
		};
		let budgetNotice: { turns: number; maxTurns: number } | undefined;
		const config: AgentLoopConfig = {
			model: model(),
			convertToLlm: convert,
			maxTurns: 3,
			reserveFinalTurn: true,
			onRunBudgetExceeded: (info) => {
				budgetNotice = info;
			},
		};

		const stream = agentLoop(
			[user("inspect and report")],
			{ systemPrompt: "", messages: [], tools: [tool] },
			config,
			undefined,
			streamFn,
		);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();

		expect(providerCalls).toBe(3);
		expect(executions).toBe(2);
		expect(providerContexts[2].tools).toEqual([]);
		expect(providerContexts[2].messages.at(-1)).toMatchObject({ role: "user" });
		expect(messages.some((message) => message.role === "user" && message.content === DEFAULT_FINAL_TURN_PROMPT)).toBe(
			false,
		);
		expect(messages.at(-1)).toMatchObject({ role: "assistant", stopReason: "stop" });
		expect((messages.at(-1) as AssistantMessage).content).toEqual([
			{ type: "text", text: "final answer from collected evidence" },
		]);
		expect(budgetNotice).toEqual({ turns: 3, maxTurns: 3 });
	});

	it("does not report max-turn exhaustion when the provider converges naturally", async () => {
		const schema = Type.Object({ path: Type.String() });
		const tool: AgentTool<typeof schema> = {
			name: "inspect",
			label: "inspect",
			description: "inspect",
			parameters: schema,
			readOnly: true,
			async execute() {
				return { content: [{ type: "text", text: "evidence" }], details: {} };
			},
		};
		let calls = 0;
		const streamFn = () => {
			const stream = new FauxAssistantStream();
			const message =
				calls++ === 0
					? assistant(
							[{ type: "toolCall", id: "inspect-1", name: "inspect", arguments: { path: "." } }],
							"toolUse",
						)
					: assistant([{ type: "text", text: "finished normally" }], "stop");
			finish(stream, message);
			return stream;
		};
		let budgetNotices = 0;
		const stream = agentLoop(
			[user("inspect")],
			{ systemPrompt: "", messages: [], tools: [tool] },
			{
				model: model(),
				convertToLlm: convert,
				maxTurns: 3,
				reserveFinalTurn: true,
				onRunBudgetExceeded: () => {
					budgetNotices++;
				},
			},
			undefined,
			streamFn,
		);
		for await (const _event of stream) {
			// consume
		}

		expect(calls).toBe(2);
		expect(budgetNotices).toBe(0);
		expect((await stream.result()).at(-1)).toMatchObject({ role: "assistant", stopReason: "stop" });
	});

	it("bounds already-consumed tool output in later provider requests without changing the transcript", async () => {
		const schema = Type.Object({ index: Type.Number() });
		const resultChars = 20_000;
		const tool: AgentTool<typeof schema> = {
			name: "probe",
			label: "probe",
			description: "probe",
			parameters: schema,
			readOnly: true,
			async execute(_id, { index }) {
				return { content: [{ type: "text", text: `${index}:${"x".repeat(resultChars - 2)}` }], details: {} };
			},
		};
		const providerToolResultChars: number[] = [];
		let providerCalls = 0;
		const streamFn = (_model: Model<any>, context: Context) => {
			providerToolResultChars.push(
				context.messages.reduce(
					(total, message) =>
						total +
						(message.role === "toolResult"
							? message.content.reduce((sum, block) => sum + (block.type === "text" ? block.text.length : 0), 0)
							: 0),
					0,
				),
			);
			const stream = new FauxAssistantStream();
			const call = providerCalls++;
			const message =
				call < 4
					? assistant(
							[{ type: "toolCall", id: `probe-${call}`, name: "probe", arguments: { index: call } }],
							"toolUse",
						)
					: assistant([{ type: "text", text: "done" }], "stop");
			finish(stream, message);
			return stream;
		};
		const config: AgentLoopConfig = {
			model: model(),
			convertToLlm: convert,
			maxConsumedToolResultChars: 2048,
		};

		const stream = agentLoop(
			[user("run four probes")],
			{ systemPrompt: "", messages: [], tools: [tool] },
			config,
			undefined,
			streamFn,
		);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();
		const persistedResults = messages.filter((message) => message.role === "toolResult");

		expect(providerToolResultChars[1]).toBe(resultChars);
		expect(Math.max(...providerToolResultChars.slice(2))).toBeLessThan(23_000);
		expect(persistedResults).toHaveLength(4);
		for (const result of persistedResults) {
			expect(result.content[0]).toMatchObject({ type: "text" });
			expect(result.content[0].type === "text" ? result.content[0].text.length : 0).toBe(resultChars);
		}
	});

	it("deduplicates exact read-only probes and invalidates them after a mutating call", async () => {
		const readSchema = Type.Object({ path: Type.String(), limit: Type.Number() });
		const mutateSchema = Type.Object({ value: Type.String() });
		let readExecutions = 0;
		let mutateExecutions = 0;
		let afterToolCalls = 0;
		const readTool: AgentTool<typeof readSchema> = {
			name: "read_probe",
			label: "read_probe",
			description: "read",
			parameters: readSchema,
			readOnly: true,
			async execute() {
				readExecutions++;
				return { content: [{ type: "text", text: `read-${readExecutions}` }], details: {} };
			},
		};
		const mutateTool: AgentTool<typeof mutateSchema> = {
			name: "mutate",
			label: "mutate",
			description: "mutate",
			parameters: mutateSchema,
			async execute() {
				mutateExecutions++;
				return { content: [{ type: "text", text: "changed" }], details: {} };
			},
		};
		let call = 0;
		const streamFn = () => {
			const stream = new FauxAssistantStream();
			const messages: AssistantMessage[] = [
				assistant(
					[{ type: "toolCall", id: "read-1", name: "read_probe", arguments: { path: ".", limit: 10 } }],
					"toolUse",
				),
				assistant(
					[{ type: "toolCall", id: "read-2", name: "read_probe", arguments: { limit: 10, path: "." } }],
					"toolUse",
				),
				assistant([{ type: "toolCall", id: "mutate-1", name: "mutate", arguments: { value: "x" } }], "toolUse"),
				assistant(
					[{ type: "toolCall", id: "read-3", name: "read_probe", arguments: { path: ".", limit: 10 } }],
					"toolUse",
				),
				assistant([{ type: "text", text: "done" }], "stop"),
			];
			finish(stream, messages[call++]);
			return stream;
		};

		const stream = agentLoop(
			[user("inspect")],
			{ systemPrompt: "", messages: [], tools: [readTool, mutateTool] },
			{
				model: model(),
				convertToLlm: convert,
				afterToolCall: async () => {
					afterToolCalls++;
					return undefined;
				},
			},
			undefined,
			streamFn,
		);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();
		const duplicate = messages.find((message) => message.role === "toolResult" && message.toolCallId === "read-2");

		expect(readExecutions).toBe(2);
		expect(mutateExecutions).toBe(1);
		expect(afterToolCalls).toBe(4);
		expect(duplicate?.role === "toolResult" ? duplicate.content[0] : undefined).toMatchObject({
			type: "text",
			text: expect.stringContaining("Skipped duplicate read-only probe"),
		});
	});

	it("deduplicates covered read-only probes without crossing partial ranges or mutations", async () => {
		const readSchema = Type.Object({
			path: Type.String(),
			offset: Type.Number(),
			limit: Type.Number(),
		});
		const mutateSchema = Type.Object({ value: Type.String() });
		let readExecutions = 0;
		const readTool: AgentTool<typeof readSchema> = {
			name: "read_probe",
			label: "read_probe",
			description: "read",
			parameters: readSchema,
			readOnly: true,
			readOnlyProbeCovers: (previous, next) => {
				if (previous.path !== next.path) return false;
				const previousEnd = previous.offset + previous.limit - 1;
				const nextEnd = next.offset + next.limit - 1;
				return previous.offset <= next.offset && previousEnd >= nextEnd;
			},
			async execute() {
				readExecutions++;
				return { content: [{ type: "text", text: `read-${readExecutions}` }], details: {} };
			},
		};
		const mutateTool: AgentTool<typeof mutateSchema> = {
			name: "mutate",
			label: "mutate",
			description: "mutate",
			parameters: mutateSchema,
			async execute() {
				return { content: [{ type: "text", text: "changed" }], details: {} };
			},
		};
		let call = 0;
		const streamFn = () => {
			const stream = new FauxAssistantStream();
			const messages: AssistantMessage[] = [
				assistant(
					[
						{
							type: "toolCall",
							id: "range-1",
							name: "read_probe",
							arguments: { path: "a", offset: 100, limit: 100 },
						},
					],
					"toolUse",
				),
				assistant(
					[
						{
							type: "toolCall",
							id: "range-covered",
							name: "read_probe",
							arguments: { path: "a", offset: 120, limit: 10 },
						},
					],
					"toolUse",
				),
				assistant(
					[
						{
							type: "toolCall",
							id: "range-partial",
							name: "read_probe",
							arguments: { path: "a", offset: 50, limit: 100 },
						},
					],
					"toolUse",
				),
				assistant([{ type: "toolCall", id: "mutate-1", name: "mutate", arguments: { value: "x" } }], "toolUse"),
				assistant(
					[
						{
							type: "toolCall",
							id: "range-after-mutation",
							name: "read_probe",
							arguments: { path: "a", offset: 120, limit: 10 },
						},
					],
					"toolUse",
				),
				assistant([{ type: "text", text: "done" }], "stop"),
			];
			finish(stream, messages[call++]);
			return stream;
		};

		const stream = agentLoop(
			[user("inspect")],
			{ systemPrompt: "", messages: [], tools: [readTool, mutateTool] },
			{ model: model(), convertToLlm: convert },
			undefined,
			streamFn,
		);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();
		const covered = messages.find(
			(message) => message.role === "toolResult" && message.toolCallId === "range-covered",
		);

		expect(readExecutions).toBe(3);
		expect(covered?.role === "toolResult" ? covered.content[0] : undefined).toMatchObject({
			type: "text",
			text: expect.stringContaining("already covered this request"),
		});
	});

	it("deduplicates identical read-only probes inside one parallel batch", async () => {
		const schema = Type.Object({ path: Type.String() });
		let executions = 0;
		const tool: AgentTool<typeof schema> = {
			name: "read_probe",
			label: "read_probe",
			description: "read",
			parameters: schema,
			readOnly: true,
			async execute() {
				executions++;
				return { content: [{ type: "text", text: "result" }], details: {} };
			},
		};
		let call = 0;
		const streamFn = () => {
			const stream = new FauxAssistantStream();
			finish(
				stream,
				call++ === 0
					? assistant(
							[
								{ type: "toolCall", id: "read-a", name: "read_probe", arguments: { path: "." } },
								{ type: "toolCall", id: "read-b", name: "read_probe", arguments: { path: "." } },
							],
							"toolUse",
						)
					: assistant([{ type: "text", text: "done" }], "stop"),
			);
			return stream;
		};

		const stream = agentLoop(
			[user("inspect")],
			{ systemPrompt: "", messages: [], tools: [tool] },
			{ model: model(), convertToLlm: convert },
			undefined,
			streamFn,
		);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();
		const duplicate = messages.find((message) => message.role === "toolResult" && message.toolCallId === "read-b");

		expect(executions).toBe(1);
		expect(duplicate?.role === "toolResult" ? duplicate.content[0] : undefined).toMatchObject({
			type: "text",
			text: expect.stringContaining("Skipped duplicate read-only probe"),
		});
	});

	it("deduplicates read-only probes within a mixed batch without crossing a mutation", async () => {
		const readSchema = Type.Object({ path: Type.String() });
		const mutateSchema = Type.Object({ value: Type.String() });
		let readExecutions = 0;
		let mutateExecutions = 0;
		let value = "before";
		const readTool: AgentTool<typeof readSchema> = {
			name: "read_probe",
			label: "read_probe",
			description: "read",
			parameters: readSchema,
			readOnly: true,
			async execute() {
				readExecutions++;
				return { content: [{ type: "text", text: value }], details: {} };
			},
		};
		const mutateTool: AgentTool<typeof mutateSchema> = {
			name: "mutate",
			label: "mutate",
			description: "mutate",
			parameters: mutateSchema,
			async execute(_id, params) {
				mutateExecutions++;
				value = params.value;
				return { content: [{ type: "text", text: "changed" }], details: {} };
			},
		};
		let call = 0;
		const streamFn = () => {
			const stream = new FauxAssistantStream();
			finish(
				stream,
				call++ === 0
					? assistant(
							[
								{ type: "toolCall", id: "before-a", name: "read_probe", arguments: { path: "." } },
								{ type: "toolCall", id: "before-b", name: "read_probe", arguments: { path: "." } },
								{ type: "toolCall", id: "mutate", name: "mutate", arguments: { value: "x" } },
								{ type: "toolCall", id: "after-a", name: "read_probe", arguments: { path: "." } },
								{ type: "toolCall", id: "after-b", name: "read_probe", arguments: { path: "." } },
							],
							"toolUse",
						)
					: assistant([{ type: "text", text: "done" }], "stop"),
			);
			return stream;
		};

		const stream = agentLoop(
			[user("inspect and mutate")],
			{ systemPrompt: "", messages: [], tools: [readTool, mutateTool] },
			{ model: model(), convertToLlm: convert },
			undefined,
			streamFn,
		);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();
		const duplicateBefore = messages.find(
			(message) => message.role === "toolResult" && message.toolCallId === "before-b",
		);
		const duplicateAfter = messages.find(
			(message) => message.role === "toolResult" && message.toolCallId === "after-b",
		);
		const readBefore = messages.find((message) => message.role === "toolResult" && message.toolCallId === "before-a");
		const readAfter = messages.find((message) => message.role === "toolResult" && message.toolCallId === "after-a");

		expect(readExecutions).toBe(2);
		expect(mutateExecutions).toBe(1);
		expect(readBefore?.role === "toolResult" ? readBefore.content[0] : undefined).toMatchObject({
			type: "text",
			text: "before",
		});
		expect(readAfter?.role === "toolResult" ? readAfter.content[0] : undefined).toMatchObject({
			type: "text",
			text: "x",
		});
		expect(duplicateBefore?.role === "toolResult" ? duplicateBefore.details : undefined).toMatchObject({
			duplicateOfToolCallId: "before-a",
		});
		expect(duplicateAfter?.role === "toolResult" ? duplicateAfter.details : undefined).toMatchObject({
			duplicateOfToolCallId: "after-a",
		});
	});
});

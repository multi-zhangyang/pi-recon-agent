import {
	type AssistantMessage,
	type AssistantMessageEvent,
	EventStream,
	type Message,
	type Model,
	type ToolResultMessage,
	type UserMessage,
} from "@pi-recon/repi-ai";
import { Type } from "typebox";
import { describe, expect, it } from "vitest";
import { runAgentLoop } from "../src/agent-loop.ts";
import type { AgentContext, AgentEvent, AgentLoopConfig, AgentMessage, AgentTool } from "../src/types.ts";

// Foundational opt #263: the tool-result emit sequence in both executors was
// unguarded. A throwing emit sink (e.g. a broken listener, or disk-full in
// handleAgentEvent→session.appendMessage behind the emit) at iteration i
// rejected the executor → runLoop (no try/catch at the call site) →
// handleRunFailure/emitRunFailure emitted turn_end(toolResults:[]) for the
// committed assistant carrying ALL N tool_use, but tool_results only for
// [0..i) → the remaining [i..N] tool_use were orphaned → the next provider
// request 400s ("tool_use must be followed by tool_result"). Post-fix each emit
// is wrapped best-effort and EVERY toolResultMessage is still pushed, so the
// batch stays balanced regardless of the emit sink's health.
//
// We drive runAgentLoop directly with a custom emit sink that throws on the
// FIRST tool_result message_end (mid-batch) and assert the run still resolves
// with BOTH tool_results balanced — pre-fix the executor rejected at tool-1's
// emit and tool-2 was never produced (orphan).

class MockAssistantStream extends EventStream<AssistantMessageEvent, AssistantMessage> {
	constructor() {
		super(
			(event) => event.type === "done" || event.type === "error",
			(event) => {
				if (event.type === "done") return event.message;
				if (event.type === "error") return event.error;
				throw new Error("Unexpected event type");
			},
		);
	}
}

function createUsage() {
	return {
		input: 0,
		output: 0,
		cacheRead: 0,
		cacheWrite: 0,
		totalTokens: 0,
		cost: { input: 0, output: 0, cacheWrite: 0, cacheRead: 0, total: 0 },
	};
}

function createModel(): Model<"openai-responses"> {
	return {
		id: "mock",
		name: "mock",
		api: "openai-responses",
		provider: "openai",
		baseUrl: "https://example.invalid",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 8192,
		maxTokens: 2048,
	};
}

function createAssistantMessage(content: AssistantMessage["content"]): AssistantMessage {
	return {
		role: "assistant",
		content,
		api: "openai-responses",
		provider: "openai",
		model: "mock",
		usage: createUsage(),
		stopReason: "stop",
		timestamp: Date.now(),
	};
}

function createUserMessage(text: string): UserMessage {
	return { role: "user", content: text, timestamp: Date.now() };
}

function identityConverter(messages: AgentMessage[]): Message[] {
	return messages.filter((m) => m.role === "user" || m.role === "assistant" || m.role === "toolResult") as Message[];
}

describe("agentLoop tool-result emit-throw batch balance (opt #263)", () => {
	it("sequential executor: a mid-batch emit throw does not orphan the remaining tool_use", async () => {
		const toolSchema = Type.Object({ command: Type.String() });
		const tool: AgentTool<typeof toolSchema, { command: string }> = {
			name: "echo",
			label: "Echo",
			description: "returns its command and terminates the batch",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				return {
					content: [{ type: "text", text: `out: ${params.command}` }],
					details: { command: params.command },
					terminate: true,
				};
			},
		};

		const context: AgentContext = { systemPrompt: "", messages: [], tools: [tool] };
		const userPrompt: AgentMessage = createUserMessage("run the commands");

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			toolExecution: "sequential",
		};

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				stream.push({
					type: "done",
					reason: "stop",
					message: createAssistantMessage([
						{
							type: "toolCall",
							id: "tool-1",
							name: "echo",
							arguments: { command: "echo one" } as { command: string },
						},
						{
							type: "toolCall",
							id: "tool-2",
							name: "echo",
							arguments: { command: "echo two" } as { command: string },
						},
					]),
				});
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		let thrownOnFirstToolResult = false;
		// Custom emit sink: record everything, but throw on the FIRST tool_result
		// message_end (mid-batch) to simulate a broken emit sink / disk-full
		// appendMessage. Pre-fix this rejects the sequential executor before
		// tool-2 is ever produced → orphan tool_use → next request 400.
		const emit = async (event: AgentEvent): Promise<void> => {
			events.push(event);
			if (
				!thrownOnFirstToolResult &&
				event.type === "message_end" &&
				(event as { message: { role?: string; toolCallId?: string } }).message.role === "toolResult"
			) {
				thrownOnFirstToolResult = true;
				throw new Error("emit sink exploded on first tool_result message_end");
			}
		};

		// Delivery still fails loudly, but only after every tool result has been
		// produced and committed to the in-memory context.
		await expect(runAgentLoop([userPrompt], context, config, emit, undefined, streamFn)).rejects.toMatchObject({
			name: "AgentEventDeliveryError",
		});

		const toolResultIds = events
			.filter(
				(event): event is Extract<AgentEvent, { type: "message_end" }> =>
					event.type === "message_end" && event.message.role === "toolResult",
			)
			.map((event) => (event.message as ToolResultMessage).toolCallId)
			.sort();
		// Core invariant: BOTH tool_use have a tool_result (no orphan).
		expect(toolResultIds).toEqual(["tool-1", "tool-2"]);

		// The emit sink DID throw mid-batch (the test actually exercises the path).
		expect(thrownOnFirstToolResult).toBe(true);

		// turn_end is attempted after balancing; agent_end is intentionally not
		// emitted because durable event delivery did not complete.
		expect(events.some((e) => e.type === "turn_end")).toBe(true);
		expect(events.some((e) => e.type === "agent_end")).toBe(false);
	});

	it("parallel executor: a mid-batch emit throw in the post-Promise.all loop does not orphan the remaining tool_use", async () => {
		const toolSchema = Type.Object({ command: Type.String() });
		const tool: AgentTool<typeof toolSchema, { command: string }> = {
			name: "echo",
			label: "Echo",
			description: "returns its command and terminates the batch",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				return {
					content: [{ type: "text", text: `out: ${params.command}` }],
					details: { command: params.command },
					terminate: true,
				};
			},
		};

		const context: AgentContext = { systemPrompt: "", messages: [], tools: [tool] };
		const userPrompt: AgentMessage = createUserMessage("run the commands");

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			toolExecution: "parallel",
		};

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				stream.push({
					type: "done",
					reason: "stop",
					message: createAssistantMessage([
						{
							type: "toolCall",
							id: "tool-1",
							name: "echo",
							arguments: { command: "echo one" } as { command: string },
						},
						{
							type: "toolCall",
							id: "tool-2",
							name: "echo",
							arguments: { command: "echo two" } as { command: string },
						},
						{
							type: "toolCall",
							id: "tool-3",
							name: "echo",
							arguments: { command: "echo three" } as { command: string },
						},
					]),
				});
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		let thrownOnFirstToolResult = false;
		const emit = async (event: AgentEvent): Promise<void> => {
			events.push(event);
			if (
				!thrownOnFirstToolResult &&
				event.type === "message_end" &&
				(event as { message: { role?: string } }).message.role === "toolResult"
			) {
				thrownOnFirstToolResult = true;
				throw new Error("emit sink exploded on first tool_result message_end");
			}
		};

		await expect(runAgentLoop([userPrompt], context, config, emit, undefined, streamFn)).rejects.toMatchObject({
			name: "AgentEventDeliveryError",
		});

		const toolResultIds = events
			.filter(
				(event): event is Extract<AgentEvent, { type: "message_end" }> =>
					event.type === "message_end" && event.message.role === "toolResult",
			)
			.map((event) => (event.message as ToolResultMessage).toolCallId)
			.sort();
		// Core invariant: ALL THREE tool_use have a tool_result (no orphan).
		expect(toolResultIds).toEqual(["tool-1", "tool-2", "tool-3"]);
		expect(thrownOnFirstToolResult).toBe(true);
		expect(events.some((e) => e.type === "turn_end")).toBe(true);
		expect(events.some((e) => e.type === "agent_end")).toBe(false);
	});
});

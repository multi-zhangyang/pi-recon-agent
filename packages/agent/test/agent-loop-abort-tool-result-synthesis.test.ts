import {
	type AssistantMessage,
	type AssistantMessageEvent,
	EventStream,
	type Message,
	type Model,
	type UserMessage,
} from "@pi-recon/repi-ai";
import { Type } from "typebox";
import { describe, expect, it } from "vitest";
import { agentLoop } from "../src/agent-loop.ts";
import type { AgentContext, AgentEvent, AgentLoopConfig, AgentMessage, AgentTool } from "../src/types.ts";

// Foundational opt: the assistant message carrying N tool_use blocks is
// committed to state.messages via message_end BEFORE tool execution. On abort
// mid-batch, both the sequential and parallel executors break on signal?.aborted
// after pushing results only for the tools that got far enough. Pre-fix the
// post-batch abort check emitted turn_end/agent_end and returned with NO
// synthesized tool_result for the un-executed tool_use blocks, leaving
// currentContext.messages = assistant(N tool_use) + toolResult(M<N). The next
// request would send an unbalanced transcript and the provider would 400
// "tool_use must be followed by tool_result". Post-fix the loop synthesizes an
// error tool_result for every tool_use id not already in the finalized results.

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
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
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

function createAssistantMessage(
	content: AssistantMessage["content"],
	stopReason: AssistantMessage["stopReason"] = "stop",
): AssistantMessage {
	return {
		role: "assistant",
		content,
		api: "openai-responses",
		provider: "openai",
		model: "mock",
		usage: createUsage(),
		stopReason,
		timestamp: Date.now(),
	};
}

function createUserMessage(text: string): UserMessage {
	return {
		role: "user",
		content: text,
		timestamp: Date.now(),
	};
}

function identityConverter(messages: AgentMessage[]): Message[] {
	return messages.filter((m) => m.role === "user" || m.role === "assistant" || m.role === "toolResult") as Message[];
}

describe("agentLoop abort mid-batch tool_result synthesis", () => {
	it("synthesizes an error tool_result for every un-executed tool_use id on abort", async () => {
		const toolSchema = Type.Object({ command: Type.String() });
		const executed: string[] = [];
		// A tool that never resolves on its own — it only settles when the abort
		// signal fires, so tool-1 is in-flight when the batch is interrupted.
		const tool: AgentTool<typeof toolSchema, { command: string }> = {
			name: "slow",
			label: "Slow",
			description: "A tool that blocks until aborted",
			parameters: toolSchema,
			async execute(toolCallId, params, signal) {
				executed.push(toolCallId);
				if (signal?.aborted) {
					return {
						content: [{ type: "text", text: "aborted before start" }],
						details: { command: params.command },
					};
				}
				return new Promise((resolve) => {
					const onAbort = () => {
						signal?.removeEventListener("abort", onAbort);
						resolve({
							content: [{ type: "text", text: `aborted: ${toolCallId}` }],
							details: { command: params.command },
						});
					};
					signal?.addEventListener("abort", onAbort, { once: true });
				});
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const userPrompt: AgentMessage = createUserMessage("run the commands");
		const controller = new AbortController();

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			// Force the sequential executor so abort breaks the loop after tool-1
			// and tool-2 is never iterated (deterministic orphan).
			toolExecution: "sequential",
		};

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				// One assistant message carrying TWO tool_use blocks.
				const message = createAssistantMessage(
					[
						{
							type: "toolCall",
							id: "tool-1",
							name: "slow",
							arguments: { command: "echo one" } as { command: string },
						},
						{
							type: "toolCall",
							id: "tool-2",
							name: "slow",
							arguments: { command: "echo two" } as { command: string },
						},
					],
					"stop",
				);
				stream.push({ type: "done", reason: "stop", message });
				// Fire abort on the next macrotask so tool-1's execute() is in
				// flight (registered its abort listener) before the signal fires.
				setTimeout(() => controller.abort(), 0);
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, controller.signal, streamFn);

		for await (const event of stream) {
			events.push(event);
		}

		// tool-1 was in flight when abort fired; tool-2 was never iterated.
		expect(executed).toEqual(["tool-1"]);

		// Collect every tool_use id the assistant emitted, and every tool_result
		// toolCallId the loop finalized (real or synthesized).
		const toolUseIds: string[] = [];
		for (const event of events) {
			if (event.type === "message_end" && event.message.role === "assistant") {
				for (const block of (event.message as AssistantMessage).content) {
					if (block.type === "toolCall") toolUseIds.push(block.id);
				}
			}
		}
		const toolResultIds: string[] = [];
		for (const event of events) {
			if (event.type === "message_end" && (event.message as { role?: string }).role === "toolResult") {
				toolResultIds.push((event.message as { toolCallId: string }).toolCallId);
			}
		}

		expect(toolUseIds.sort()).toEqual(["tool-1", "tool-2"]);

		// The core invariant: EVERY tool_use.id has a matching tool_result before
		// the batch returns. Pre-fix tool-2 was missing and the transcript was
		// unbalanced (provider 400 "tool_use must be followed by tool_result").
		expect(toolResultIds.sort()).toEqual(["tool-1", "tool-2"]);

		// The synthesized tool_result for tool-2 is an error result (NOT executed).
		const tool2Result = events.find(
			(e) => e.type === "tool_execution_end" && (e as { toolCallId: string }).toolCallId === "tool-2",
		);
		expect(tool2Result).toBeDefined();
		if (tool2Result?.type === "tool_execution_end") {
			expect(tool2Result.isError).toBe(true);
		}

		// The run terminated via the abort path (agent_end emitted, no second turn).
		expect(events.some((e) => e.type === "agent_end")).toBe(true);
		// No second assistant turn was requested (abort short-circuits the loop).
		const assistantEnds = events.filter(
			(e) => e.type === "message_end" && (e.message as { role?: string }).role === "assistant",
		);
		expect(assistantEnds.length).toBe(1);
	});
});

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

// opt #134: a "length" stopReason (max_tokens) can cut a tool_use block off
// mid-arguments. The provider's parseStreamingJson silently closes the
// incomplete JSON (e.g. {"command":"rm -rf /opt/da → {"command":"rm -rf /opt/da"}),
// so the finalized toolCall has TRUNCATED but parseable arguments. Pre-fix the
// agent loop executed the tool with the half-completed argument (destructive for
// Bash/Edit/etc) and gave the model no signal to self-correct. Post-fix the loop
// converts each truncated call into an isError tool_result (NOT executed) and
// loops back so the model re-emits the complete call.

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

describe("agentLoop max_tokens-truncated tool call safety (opt #134)", () => {
	it("does NOT execute a tool call truncated by max_tokens; surfaces isError and loops back", async () => {
		const toolSchema = Type.Object({ command: Type.String() });
		const executed: string[] = [];
		const tool: AgentTool<typeof toolSchema, { command: string }> = {
			name: "bash",
			label: "Bash",
			description: "Run a shell command",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				executed.push(params.command);
				return {
					content: [{ type: "text", text: `ran: ${params.command}` }],
					details: { command: params.command },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const userPrompt: AgentMessage = createUserMessage("run the command");

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					// First call: tool_use block cut off mid-arguments by max_tokens.
					// parseStreamingJson would have closed the unterminated JSON, so
					// the finalized arguments are a truncated-but-parseable string.
					const message = createAssistantMessage(
						[
							{
								type: "toolCall",
								id: "tool-1",
								name: "bash",
								// Truncated mid-string — exactly what survives a max_tokens cut.
								arguments: { command: "rm -rf /opt/da" } as { command: string },
							},
						],
						"length",
					);
					stream.push({ type: "done", reason: "length", message });
				} else {
					// Second call: the model re-emits and then finishes.
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					stream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);

		for await (const event of stream) {
			events.push(event);
		}

		// The truncated tool call was NOT executed — the half-completed command
		// never reached the shell. Pre-fix this would be ["rm -rf /opt/da"].
		expect(executed).toEqual([]);

		// A tool_execution_end was emitted for the truncated call, flagged isError.
		const toolEnd = events.find((e) => e.type === "tool_execution_end");
		expect(toolEnd).toBeDefined();
		if (toolEnd?.type === "tool_execution_end") {
			expect(toolEnd.isError).toBe(true);
		}

		// The tool result told the model its args were truncated (not executed),
		// so it can self-correct — no silent garbage execution.
		const toolResultText = events
			.filter((e) => e.type === "message_end")
			.map(
				(e) =>
					(e as { message: { content?: Array<{ type: string; text?: string }>; toolCallId?: string } }).message,
			)
			.filter((m) => m?.toolCallId === "tool-1")
			.flatMap((m) => m.content ?? [])
			.map((c) => (c.type === "text" ? c.text : "") ?? "")
			.join(" ");
		expect(toolResultText).toMatch(/truncated by max_tokens/);
		expect(toolResultText).toMatch(/NOT executed/);

		// The loop continued and the model got a second turn (it re-emits / finishes).
		expect(callIndex).toBeGreaterThanOrEqual(2);
	});
});

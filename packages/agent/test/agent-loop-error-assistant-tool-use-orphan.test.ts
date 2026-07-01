import {
	type AssistantMessage,
	type AssistantMessageEvent,
	EventStream,
	type Message,
	type Model,
	type ToolCall,
	type UserMessage,
} from "@pi-recon/repi-ai";
import { Type } from "typebox";
import { describe, expect, it } from "vitest";
import { agentLoop } from "../src/agent-loop.ts";
import type { AgentContext, AgentEvent, AgentLoopConfig, AgentMessage, AgentTool } from "../src/types.ts";

// Foundational opt #261 (resolve path): an assistant message that FINALIZED
// with stopReason "error"/"aborted" can already carry COMPLETE toolCall blocks
// — e.g. the no-terminal-event resolve path (a proxy SSE body that closed
// cleanly without pushing `done`) commits the streamed partial, which may
// already contain a complete tool_use. The assistant (with tool_use) is
// committed via message_end, but pre-fix the error/aborted early-return emitted
// turn_end/agent_end with NO tool_result for those ids → the durable transcript
// was unbalanced → the next provider request 400s "tool_use must be followed by
// tool_result". Post-fix the loop synthesizes an isError tool_result for every
// tool_use id before the terminal events.

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
	return {
		role: "user",
		content: text,
		timestamp: Date.now(),
	};
}

function identityConverter(messages: AgentMessage[]): Message[] {
	return messages.filter((m) => m.role === "user" || m.role === "assistant" || m.role === "toolResult") as Message[];
}

function toolCall(id: string): ToolCall {
	return { type: "toolCall", id, name: "bash", arguments: { command: "echo hi" } };
}

describe("agentLoop error/aborted assistant with committed tool_use — orphan synthesis (opt #261)", () => {
	it("synthesizes an error tool_result for tool_use blocks on a no-terminal-event (stopReason=error) assistant", async () => {
		const toolSchema = Type.Object({ command: Type.String() });
		const executed: string[] = [];
		const tool: AgentTool<typeof toolSchema, { command: string }> = {
			name: "bash",
			label: "Bash",
			description: "echo",
			parameters: toolSchema,
			async execute(toolCallId, params) {
				executed.push(toolCallId);
				return {
					content: [{ type: "text", text: params.command }],
					details: { command: params.command },
				};
			},
		};

		const context: AgentContext = { systemPrompt: "", messages: [], tools: [tool] };
		const userPrompt: AgentMessage = createUserMessage("run the command");
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			toolExecution: "sequential",
		};

		// The stream emits a start partial that already carries a COMPLETE toolCall
		// block, then ends WITHOUT a terminal `done`/`error` event (the
		// no-terminal-event resolve path). streamAssistantResponse commits the
		// partial as stopReason "error" and returns it → the 235 early-return fires
		// with a committed tool_use and (pre-fix) no tool_result.
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const partial = createAssistantMessage([toolCall("tool-1")]);
				stream.push({ type: "start", partial });
				stream.end();
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const event of stream) {
			events.push(event);
		}

		// The tool was NOT executed — only a synthesized error result.
		expect(executed).toEqual([]);

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

		expect(toolUseIds).toEqual(["tool-1"]);
		// Core invariant: the tool_use id has a matching tool_result before the
		// run ends (pre-fix toolResultIds was [] → unbalanced transcript → 400).
		expect(toolResultIds).toEqual(["tool-1"]);

		// The synthesized tool_result is an error result (NOT executed).
		const tool1End = events.find(
			(e) => e.type === "tool_execution_end" && (e as { toolCallId: string }).toolCallId === "tool-1",
		);
		expect(tool1End).toBeDefined();
		if (tool1End?.type === "tool_execution_end") {
			expect(tool1End.isError).toBe(true);
		}

		// turn_end carries the synthesized tool_result (pre-fix toolResults was []).
		const turnEnd = events.find((e) => e.type === "turn_end");
		expect(turnEnd).toBeDefined();
		if (turnEnd?.type === "turn_end") {
			expect(turnEnd.toolResults.length).toBe(1);
		}

		// The run terminated via the error path (agent_end emitted, no second turn).
		expect(events.some((e) => e.type === "agent_end")).toBe(true);
		const assistantEnds = events.filter(
			(e) => e.type === "message_end" && (e.message as { role?: string }).role === "assistant",
		);
		expect(assistantEnds.length).toBe(1);
	});

	it("synthesizes an error tool_result for tool_use blocks on a stopReason=aborted assistant", async () => {
		const toolSchema = Type.Object({ command: Type.String() });
		const executed: string[] = [];
		const tool: AgentTool<typeof toolSchema, { command: string }> = {
			name: "bash",
			label: "Bash",
			description: "echo",
			parameters: toolSchema,
			async execute(toolCallId, params) {
				executed.push(toolCallId);
				return {
					content: [{ type: "text", text: params.command }],
					details: { command: params.command },
				};
			},
		};

		const context: AgentContext = { systemPrompt: "", messages: [], tools: [tool] };
		const userPrompt: AgentMessage = createUserMessage("run it");
		const config: AgentLoopConfig = { model: createModel(), convertToLlm: identityConverter };
		// An already-aborted signal → the no-terminal-event resolve branch labels
		// the committed partial stopReason "aborted".
		const controller = new AbortController();
		controller.abort();

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const partial = createAssistantMessage([toolCall("tool-9")]);
				stream.push({ type: "start", partial });
				stream.end();
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, controller.signal, streamFn);
		for await (const event of stream) {
			events.push(event);
		}

		expect(executed).toEqual([]);
		const toolResultIds: string[] = [];
		for (const event of events) {
			if (event.type === "message_end" && (event.message as { role?: string }).role === "toolResult") {
				toolResultIds.push((event.message as { toolCallId: string }).toolCallId);
			}
		}
		expect(toolResultIds).toEqual(["tool-9"]);
		expect(events.some((e) => e.type === "agent_end")).toBe(true);
	});
});

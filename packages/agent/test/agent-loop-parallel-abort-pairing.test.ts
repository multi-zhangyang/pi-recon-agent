/**
 * opt #227 — parallel batch abort event pairing guard (session-audit Finding #3).
 *
 * The parallel executor emits tool_execution_start per call in its for-loop,
 * then runs the closures via Promise.all (each closure's try/catch ALWAYS
 * emits tool_execution_end — opt #24). Un-iterated tool_use ids (the for-loop
 * broke on abort before reaching them) get a synthesized tool_execution_end +
 * tool_result via synthesizeAbortedToolCallResults. Together these should keep
 * the batch paired on abort: every tool_use.id has a matching tool_result, and
 * every tool_execution_start has a matching tool_execution_end (no dangling
 * "running" tool in the UI).
 *
 * This is a guard test: if it passes, the parallel executor's abort pairing is
 * already defended (by opt #24 + synthesizeAbortedToolCallResults). It mirrors
 * the existing sequential-executor abort test but forces parallel execution.
 */
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
	return { role: "user", content: text, timestamp: Date.now() };
}

function identityConverter(messages: AgentMessage[]): Message[] {
	return messages.filter((m) => m.role === "user" || m.role === "assistant" || m.role === "toolResult") as Message[];
}

describe("opt #227: parallel batch abort event pairing", () => {
	it("every tool_use has a tool_result and every start has an end (no dangling starts) on abort", async () => {
		const toolSchema = Type.Object({ command: Type.String() });
		// Both tools block until aborted — both are in flight when abort fires.
		const tool: AgentTool<typeof toolSchema, { command: string }> = {
			name: "slow",
			label: "Slow",
			description: "blocks until aborted",
			parameters: toolSchema,
			async execute(toolCallId, params, signal) {
				if (signal?.aborted) {
					return {
						content: [{ type: "text", text: `aborted: ${toolCallId}` }],
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

		const context: AgentContext = { systemPrompt: "", messages: [], tools: [tool] };
		const userPrompt: AgentMessage = createUserMessage("run the commands");
		const controller = new AbortController();

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			// Default → parallel (no sequential tool, no override).
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
							name: "slow",
							arguments: { command: "echo one" } as { command: string },
						},
						{
							type: "toolCall",
							id: "tool-2",
							name: "slow",
							arguments: { command: "echo two" } as { command: string },
						},
					]),
				});
				setTimeout(() => controller.abort(), 0);
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, controller.signal, streamFn);
		for await (const event of stream) {
			events.push(event);
		}

		const starts = events.filter((e) => e.type === "tool_execution_start") as { toolCallId: string }[];
		const ends = events.filter((e) => e.type === "tool_execution_end") as { toolCallId: string }[];
		const toolResultIds = events
			.filter((e) => e.type === "message_end" && (e as { message: { role?: string } }).message.role === "toolResult")
			.map((e) => (e as { message: { toolCallId: string } }).message.toolCallId);

		// Invariant 1: transcript balance — every tool_use has a tool_result.
		expect(toolResultIds.sort()).toEqual(["tool-1", "tool-2"]);
		// Invariant 2: no dangling starts — every start has a matching end.
		const startIds = starts.map((s) => s.toolCallId).sort();
		const endIds = ends.map((e) => e.toolCallId).sort();
		expect(startIds).toEqual(endIds);
		// Invariant 3: the run terminated via the abort path.
		expect(events.some((e) => e.type === "agent_end")).toBe(true);
	});
});

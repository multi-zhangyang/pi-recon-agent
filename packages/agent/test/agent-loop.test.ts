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
import { agentLoop, agentLoopContinue, runAgentLoop } from "../src/agent-loop.ts";
import type { AgentContext, AgentEvent, AgentLoopConfig, AgentMessage, AgentTool } from "../src/types.ts";

// Mock stream for testing - mimics MockAssistantStream
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

// Simple identity converter for tests - just passes through standard messages
function identityConverter(messages: AgentMessage[]): Message[] {
	return messages.filter((m) => m.role === "user" || m.role === "assistant" || m.role === "toolResult") as Message[];
}

describe("agentLoop with AgentMessage", () => {
	it("should emit events with AgentMessage types", async () => {
		const context: AgentContext = {
			systemPrompt: "You are helpful.",
			messages: [],
			tools: [],
		};

		const userPrompt: AgentMessage = createUserMessage("Hello");

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const message = createAssistantMessage([{ type: "text", text: "Hi there!" }]);
				stream.push({ type: "done", reason: "stop", message });
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);

		for await (const event of stream) {
			events.push(event);
		}

		const messages = await stream.result();

		// Should have user message and assistant message
		expect(messages.length).toBe(2);
		expect(messages[0].role).toBe("user");
		expect(messages[1].role).toBe("assistant");

		// Verify event sequence
		const eventTypes = events.map((e) => e.type);
		expect(eventTypes).toContain("agent_start");
		expect(eventTypes).toContain("turn_start");
		expect(eventTypes).toContain("message_start");
		expect(eventTypes).toContain("message_end");
		expect(eventTypes).toContain("turn_end");
		expect(eventTypes).toContain("agent_end");
	});

	it("should handle custom message types via convertToLlm", async () => {
		// Create a custom message type
		interface CustomNotification {
			role: "notification";
			text: string;
			timestamp: number;
		}

		const notification: CustomNotification = {
			role: "notification",
			text: "This is a notification",
			timestamp: Date.now(),
		};

		const context: AgentContext = {
			systemPrompt: "You are helpful.",
			messages: [notification as unknown as AgentMessage], // Custom message in context
			tools: [],
		};

		const userPrompt: AgentMessage = createUserMessage("Hello");

		let convertedMessages: Message[] = [];
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: (messages) => {
				// Filter out notifications, convert rest
				convertedMessages = messages
					.filter((m) => (m as { role: string }).role !== "notification")
					.filter((m) => m.role === "user" || m.role === "assistant" || m.role === "toolResult") as Message[];
				return convertedMessages;
			},
		};

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const message = createAssistantMessage([{ type: "text", text: "Response" }]);
				stream.push({ type: "done", reason: "stop", message });
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);

		for await (const event of stream) {
			events.push(event);
		}

		// The notification should have been filtered out in convertToLlm
		expect(convertedMessages.length).toBe(1); // Only user message
		expect(convertedMessages[0].role).toBe("user");
	});

	it("should apply transformContext before convertToLlm", async () => {
		const context: AgentContext = {
			systemPrompt: "You are helpful.",
			messages: [
				createUserMessage("old message 1"),
				createAssistantMessage([{ type: "text", text: "old response 1" }]),
				createUserMessage("old message 2"),
				createAssistantMessage([{ type: "text", text: "old response 2" }]),
			],
			tools: [],
		};

		const userPrompt: AgentMessage = createUserMessage("new message");

		let transformedMessages: AgentMessage[] = [];
		let convertedMessages: Message[] = [];

		const config: AgentLoopConfig = {
			model: createModel(),
			transformContext: async (messages) => {
				// Keep only last 2 messages (prune old ones)
				transformedMessages = messages.slice(-2);
				return transformedMessages;
			},
			convertToLlm: (messages) => {
				convertedMessages = messages.filter(
					(m) => m.role === "user" || m.role === "assistant" || m.role === "toolResult",
				) as Message[];
				return convertedMessages;
			},
		};

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const message = createAssistantMessage([{ type: "text", text: "Response" }]);
				stream.push({ type: "done", reason: "stop", message });
			});
			return stream;
		};

		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);

		for await (const _ of stream) {
			// consume
		}

		// transformContext should have been called first, keeping only last 2
		expect(transformedMessages.length).toBe(2);
		// Then convertToLlm receives the pruned messages
		expect(convertedMessages.length).toBe(2);
	});

	it("should handle tool calls and results", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const executed: string[] = [];
		const tool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				executed.push(params.value);
				return {
					content: [{ type: "text", text: `echoed: ${params.value}` }],
					details: { value: params.value },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const userPrompt: AgentMessage = createUserMessage("echo something");

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					// First call: return tool call
					const message = createAssistantMessage(
						[{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "hello" } }],
						"toolUse",
					);
					stream.push({ type: "done", reason: "toolUse", message });
				} else {
					// Second call: return final response
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

		// Tool should have been executed
		expect(executed).toEqual(["hello"]);

		// Should have tool execution events
		const toolStart = events.find((e) => e.type === "tool_execution_start");
		const toolEnd = events.find((e) => e.type === "tool_execution_end");
		expect(toolStart).toBeDefined();
		expect(toolEnd).toBeDefined();
		if (toolEnd?.type === "tool_execution_end") {
			expect(toolEnd.isError).toBe(false);
		}
	});

	it("should execute mutated beforeToolCall args without revalidation", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const executed: Array<string | number> = [];
		const tool: AgentTool<typeof toolSchema, { value: string | number }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				executed.push(params.value as string | number);
				return {
					content: [{ type: "text", text: `echoed: ${String(params.value)}` }],
					details: { value: params.value as string | number },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const userPrompt: AgentMessage = createUserMessage("echo something");

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			beforeToolCall: async ({ args }) => {
				const mutableArgs = args as { value: string | number };
				mutableArgs.value = 123;
				return undefined;
			},
		};

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					const message = createAssistantMessage(
						[{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "hello" } }],
						"toolUse",
					);
					stream.push({ type: "done", reason: "toolUse", message });
				} else {
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					stream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return stream;
		};

		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const _event of stream) {
			// consume
		}

		expect(executed).toEqual([123]);
	});

	it("should prepare tool arguments for validation", async () => {
		const replaceSchema = Type.Object({ oldText: Type.String(), newText: Type.String() });
		const toolSchema = Type.Object({ edits: Type.Array(replaceSchema) });
		const executed: Array<Array<{ oldText: string; newText: string }>> = [];
		const tool: AgentTool<typeof toolSchema, { count: number }> = {
			name: "edit",
			label: "Edit",
			description: "Edit tool",
			parameters: toolSchema,
			prepareArguments(args) {
				if (!args || typeof args !== "object") {
					return args as { edits: { oldText: string; newText: string }[] };
				}
				const input = args as {
					edits?: Array<{ oldText: string; newText: string }>;
					oldText?: string;
					newText?: string;
				};
				if (typeof input.oldText !== "string" || typeof input.newText !== "string") {
					return args as { edits: { oldText: string; newText: string }[] };
				}
				return {
					edits: [...(input.edits ?? []), { oldText: input.oldText, newText: input.newText }],
				};
			},
			async execute(_toolCallId, params) {
				executed.push(params.edits);
				return {
					content: [{ type: "text", text: `edited ${params.edits.length}` }],
					details: { count: params.edits.length },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const userPrompt: AgentMessage = createUserMessage("edit something");
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					const message = createAssistantMessage(
						[
							{
								type: "toolCall",
								id: "tool-1",
								name: "edit",
								arguments: { oldText: "before", newText: "after" },
							},
						],
						"toolUse",
					);
					stream.push({ type: "done", reason: "toolUse", message });
				} else {
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					stream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return stream;
		};

		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const _event of stream) {
			// consume
		}

		expect(executed).toEqual([[{ oldText: "before", newText: "after" }]]);
	});

	it("should emit tool_execution_end in completion order but persist tool results in source order", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		let firstResolved = false;
		let parallelObserved = false;
		let releaseFirst: (() => void) | undefined;
		const firstDone = new Promise<void>((resolve) => {
			releaseFirst = resolve;
		});

		const tool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				if (params.value === "first") {
					await firstDone;
					firstResolved = true;
				}
				if (params.value === "second" && !firstResolved) {
					parallelObserved = true;
				}
				return {
					content: [{ type: "text", text: `echoed: ${params.value}` }],
					details: { value: params.value },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const userPrompt: AgentMessage = createUserMessage("echo both");
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			toolExecution: "parallel",
		};

		let callIndex = 0;
		const stream = agentLoop([userPrompt], context, config, undefined, () => {
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					const message = createAssistantMessage(
						[
							{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "first" } },
							{ type: "toolCall", id: "tool-2", name: "echo", arguments: { value: "second" } },
						],
						"toolUse",
					);
					mockStream.push({ type: "done", reason: "toolUse", message });
					setTimeout(() => releaseFirst?.(), 20);
				} else {
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					mockStream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return mockStream;
		});

		const events: AgentEvent[] = [];
		for await (const event of stream) {
			events.push(event);
		}

		const toolExecutionEndIds = events.flatMap((event) => {
			if (event.type !== "tool_execution_end") {
				return [];
			}
			return [event.toolCallId];
		});
		const toolResultIds = events.flatMap((event) => {
			if (event.type !== "message_end" || event.message.role !== "toolResult") {
				return [];
			}
			return [event.message.toolCallId];
		});
		const turnToolResultIds = events.flatMap((event) => {
			if (event.type !== "turn_end") {
				return [];
			}
			return event.toolResults.map((toolResult) => toolResult.toolCallId);
		});

		expect(parallelObserved).toBe(true);
		expect(toolExecutionEndIds).toEqual(["tool-2", "tool-1"]);
		expect(toolResultIds).toEqual(["tool-1", "tool-2"]);
		expect(turnToolResultIds).toEqual(["tool-1", "tool-2"]);
	});

	it("should preserve a parallel batch when the emit sink throws on a tool_execution_update", async () => {
		// Regression: a broken emit sink on a streaming partial-result update used
		// to make executePreparedToolCall's catch re-await the same rejected
		// updateEvents (uncaught re-throw) → the parallel closure rejected →
		// Promise.all rejected → the ENTIRE batch's tool results were lost, and a
		// successful tool got flipped to an error. allSettled makes update emits
		// best-effort so a successful tool stays successful and siblings survive.
		const toolSchema = Type.Object({ value: Type.String() });
		const tool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params, _signal, onUpdate) {
				onUpdate?.({
					content: [{ type: "text", text: `partial: ${params.value}` }],
					details: { value: params.value },
				});
				return {
					content: [{ type: "text", text: `echoed: ${params.value}` }],
					details: { value: params.value },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const userPrompt: AgentMessage = createUserMessage("echo both");
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			toolExecution: "parallel",
		};

		let callIndex = 0;
		const streamFn = () => {
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					const message = createAssistantMessage(
						[
							{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "first" } },
							{ type: "toolCall", id: "tool-2", name: "echo", arguments: { value: "second" } },
						],
						"toolUse",
					);
					mockStream.push({ type: "done", reason: "toolUse", message });
				} else {
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					mockStream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return mockStream;
		};

		const events: AgentEvent[] = [];
		// Emit sink that throws on tool_execution_update for tool-1 only.
		const emit = async (event: AgentEvent): Promise<void> => {
			events.push(event);
			if (event.type === "tool_execution_update" && event.toolCallId === "tool-1") {
				throw new Error("emit sink broken for tool-1 update");
			}
		};

		const messages = await runAgentLoop([userPrompt], context, config, emit, undefined, streamFn);

		// Both tools executed and produced results — batch preserved (not lost to
		// a rejected Promise.all).
		const toolResults = messages.filter((m) => m.role === "toolResult");
		const ids = toolResults.map((m) => (m as { toolCallId: string }).toolCallId);
		expect(ids.sort()).toEqual(["tool-1", "tool-2"]);

		// tool-1 succeeded (its tool succeeded; the broken UPDATE emit must not
		// flip it to an error). tool_execution_end carries isError for the UI.
		const endFor1 = events.find((e) => e.type === "tool_execution_end" && e.toolCallId === "tool-1");
		const endFor2 = events.find((e) => e.type === "tool_execution_end" && e.toolCallId === "tool-2");
		expect(endFor1).toBeDefined();
		expect(endFor2).toBeDefined();
		if (endFor1?.type === "tool_execution_end") expect(endFor1.isError).toBe(false);
		if (endFor2?.type === "tool_execution_end") expect(endFor2.isError).toBe(false);
	});

	it("should cap oversized tool result text at the context boundary", async () => {
		// A misbehaving tool (e.g. an MCP extension) returns a huge text result.
		// The agent-loop caps it (head+tail + marker) before it enters the model's
		// context, while tool_execution_end keeps the original for the UI.
		const huge = "x".repeat(10000);
		const toolSchema = Type.Object({});
		const tool: AgentTool<typeof toolSchema, Record<string, never>> = {
			name: "big",
			label: "Big",
			description: "Returns a huge result",
			parameters: toolSchema,
			async execute() {
				return { content: [{ type: "text", text: huge }], details: {} };
			},
		};

		const context: AgentContext = { systemPrompt: "", messages: [], tools: [tool] };
		const userPrompt = createUserMessage("run big");
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			maxToolResultChars: 100,
		};

		let callIndex = 0;
		const stream = agentLoop([userPrompt], context, config, undefined, () => {
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					mockStream.push({
						type: "done",
						reason: "toolUse",
						message: createAssistantMessage(
							[{ type: "toolCall", id: "tool-1", name: "big", arguments: {} }],
							"toolUse",
						),
					});
				} else {
					mockStream.push({
						type: "done",
						reason: "stop",
						message: createAssistantMessage([{ type: "text", text: "done" }]),
					});
				}
				callIndex++;
			});
			return mockStream;
		});

		const events: AgentEvent[] = [];
		for await (const event of stream) {
			events.push(event);
		}

		// The persisted toolResult message (context boundary) is capped.
		const toolResultMsgs = events.flatMap((event) => {
			if (event.type !== "message_end" || event.message.role !== "toolResult") return [];
			return [event.message];
		});
		const toolResultMsg = toolResultMsgs.find((m) => m.toolCallId === "tool-1");
		expect(toolResultMsg).toBeDefined();
		const cappedText = toolResultMsg!.content[0];
		if (cappedText.type !== "text") throw new Error("expected text content");
		expect(cappedText.text).toContain("characters truncated");
		expect(cappedText.text).toContain("safety cap");
		expect(cappedText.text.length).toBeLessThan(huge.length);
		expect(cappedText.text).not.toContain(huge);
		// Head and tail are preserved (head = tail = 45 for maxChars 100).
		expect(cappedText.text).toContain("x".repeat(45));

		// tool_execution_end keeps the ORIGINAL (uncapped) result for the UI.
		const toolEnd = events.find((e) => e.type === "tool_execution_end");
		expect(toolEnd).toBeDefined();
		if (toolEnd && toolEnd.type === "tool_execution_end") {
			const endText = toolEnd.result.content[0];
			if (endText.type !== "text") throw new Error("expected text content");
			expect(endText.text).toBe(huge);
		}
	});

	it("should inject queued messages after all tool calls complete", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const executed: string[] = [];
		const tool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				executed.push(params.value);
				return {
					content: [{ type: "text", text: `ok:${params.value}` }],
					details: { value: params.value },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const userPrompt: AgentMessage = createUserMessage("start");
		const queuedUserMessage: AgentMessage = createUserMessage("interrupt");

		let queuedDelivered = false;
		let callIndex = 0;
		let sawInterruptInContext = false;

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			toolExecution: "sequential",
			getSteeringMessages: async () => {
				// Return steering message after tool execution has started.
				if (executed.length >= 1 && !queuedDelivered) {
					queuedDelivered = true;
					return [queuedUserMessage];
				}
				return [];
			},
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, undefined, (_model, ctx, _options) => {
			// Check if interrupt message is in context on second call
			if (callIndex === 1) {
				sawInterruptInContext = ctx.messages.some(
					(m) => m.role === "user" && typeof m.content === "string" && m.content === "interrupt",
				);
			}

			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					// First call: return two tool calls
					const message = createAssistantMessage(
						[
							{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "first" } },
							{ type: "toolCall", id: "tool-2", name: "echo", arguments: { value: "second" } },
						],
						"toolUse",
					);
					mockStream.push({ type: "done", reason: "toolUse", message });
				} else {
					// Second call: return final response
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					mockStream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return mockStream;
		});

		for await (const event of stream) {
			events.push(event);
		}

		// Both tools should execute before steering is injected
		expect(executed).toEqual(["first", "second"]);

		const toolEnds = events.filter(
			(e): e is Extract<AgentEvent, { type: "tool_execution_end" }> => e.type === "tool_execution_end",
		);
		expect(toolEnds.length).toBe(2);
		expect(toolEnds[0].isError).toBe(false);
		expect(toolEnds[1].isError).toBe(false);

		// Queued message should appear in events after both tool result messages
		const eventSequence = events.flatMap((event) => {
			if (event.type !== "message_start") return [];
			if (event.message.role === "toolResult") return [`tool:${event.message.toolCallId}`];
			if (event.message.role === "user" && typeof event.message.content === "string") {
				return [event.message.content];
			}
			return [];
		});
		expect(eventSequence).toContain("interrupt");
		expect(eventSequence.indexOf("tool:tool-1")).toBeLessThan(eventSequence.indexOf("interrupt"));
		expect(eventSequence.indexOf("tool:tool-2")).toBeLessThan(eventSequence.indexOf("interrupt"));

		// Interrupt message should be in context when second LLM call is made
		expect(sawInterruptInContext).toBe(true);
	});

	it("should force sequential execution when a tool has executionMode=sequential even with default parallel config", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		let firstResolved = false;
		let parallelObserved = false;
		let releaseFirst: (() => void) | undefined;
		const firstDone = new Promise<void>((resolve) => {
			releaseFirst = resolve;
		});

		const slowTool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "slow",
			label: "Slow",
			description: "Slow tool",
			parameters: toolSchema,
			executionMode: "sequential",
			async execute(_toolCallId, params) {
				if (params.value === "first") {
					await firstDone;
					firstResolved = true;
				}
				if (params.value === "second" && !firstResolved) {
					parallelObserved = true;
				}
				return {
					content: [{ type: "text", text: `slow: ${params.value}` }],
					details: { value: params.value },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [slowTool],
		};

		const userPrompt: AgentMessage = createUserMessage("run both");
		// config is parallel (default), but tool forces sequential
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		let callIndex = 0;
		const stream = agentLoop([userPrompt], context, config, undefined, () => {
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					const message = createAssistantMessage(
						[
							{ type: "toolCall", id: "tool-1", name: "slow", arguments: { value: "first" } },
							{ type: "toolCall", id: "tool-2", name: "slow", arguments: { value: "second" } },
						],
						"toolUse",
					);
					mockStream.push({ type: "done", reason: "toolUse", message });
					setTimeout(() => releaseFirst?.(), 20);
				} else {
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					mockStream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return mockStream;
		});

		const events: AgentEvent[] = [];
		for await (const event of stream) {
			events.push(event);
		}

		// With sequential execution, second tool should NOT start before first finishes
		expect(parallelObserved).toBe(false);

		const toolResultIds = events.flatMap((event) => {
			if (event.type !== "message_end" || event.message.role !== "toolResult") {
				return [];
			}
			return [event.message.toolCallId];
		});
		expect(toolResultIds).toEqual(["tool-1", "tool-2"]);
	});

	it("should force sequential execution when one of multiple tools has executionMode=sequential", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const executionOrder: string[] = [];
		let releaseSlow: (() => void) | undefined;
		const slowDone = new Promise<void>((resolve) => {
			releaseSlow = resolve;
		});

		const slowTool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "slow",
			label: "Slow",
			description: "Slow tool",
			parameters: toolSchema,
			executionMode: "sequential",
			async execute(_toolCallId, params) {
				executionOrder.push(`slow:${params.value}`);
				if (params.value === "a") {
					await slowDone;
				}
				return {
					content: [{ type: "text", text: `slow: ${params.value}` }],
					details: { value: params.value },
				};
			},
		};

		const fastTool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "fast",
			label: "Fast",
			description: "Fast tool",
			parameters: toolSchema,
			// no executionMode = defaults to parallel
			async execute(_toolCallId, params) {
				executionOrder.push(`fast:${params.value}`);
				return {
					content: [{ type: "text", text: `fast: ${params.value}` }],
					details: { value: params.value },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [slowTool, fastTool],
		};

		const userPrompt: AgentMessage = createUserMessage("run both");
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			// parallel by default, but slowTool forces sequential
		};

		let callIndex = 0;
		const stream = agentLoop([userPrompt], context, config, undefined, () => {
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					const message = createAssistantMessage(
						[
							{ type: "toolCall", id: "tool-1", name: "slow", arguments: { value: "a" } },
							{ type: "toolCall", id: "tool-2", name: "fast", arguments: { value: "b" } },
						],
						"toolUse",
					);
					mockStream.push({ type: "done", reason: "toolUse", message });
					setTimeout(() => releaseSlow?.(), 20);
				} else {
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					mockStream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return mockStream;
		});

		const events: AgentEvent[] = [];
		for await (const event of stream) {
			events.push(event);
		}

		// Fast tool should NOT run before slow tool finishes
		expect(executionOrder[0]).toBe("slow:a");
		expect(executionOrder).toContain("fast:b");
	});

	it("should allow parallel execution when all tools have executionMode=parallel", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		let firstResolved = false;
		let parallelObserved = false;
		let releaseFirst: (() => void) | undefined;
		const firstDone = new Promise<void>((resolve) => {
			releaseFirst = resolve;
		});

		const tool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			executionMode: "parallel",
			async execute(_toolCallId, params) {
				if (params.value === "first") {
					await firstDone;
					firstResolved = true;
				}
				if (params.value === "second" && !firstResolved) {
					parallelObserved = true;
				}
				return {
					content: [{ type: "text", text: `echoed: ${params.value}` }],
					details: { value: params.value },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const userPrompt: AgentMessage = createUserMessage("echo both");
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		let callIndex = 0;
		const stream = agentLoop([userPrompt], context, config, undefined, () => {
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					const message = createAssistantMessage(
						[
							{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "first" } },
							{ type: "toolCall", id: "tool-2", name: "echo", arguments: { value: "second" } },
						],
						"toolUse",
					);
					mockStream.push({ type: "done", reason: "toolUse", message });
					setTimeout(() => releaseFirst?.(), 20);
				} else {
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					mockStream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return mockStream;
		});

		const events: AgentEvent[] = [];
		for await (const event of stream) {
			events.push(event);
		}

		// With executionMode=parallel, second tool should start before first finishes
		expect(parallelObserved).toBe(true);
	});

	it("should use prepareNextTurn snapshot before continuing", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const tool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				return {
					content: [{ type: "text", text: `echoed: ${params.value}` }],
					details: { value: params.value },
				};
			},
		};
		const context: AgentContext = {
			systemPrompt: "first prompt",
			messages: [],
			tools: [tool],
		};
		let convertedSecondTurnSystemPrompt = "";
		let prepared = false;
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			prepareNextTurn: async ({ context: currentContext }) => {
				if (prepared) return undefined;
				prepared = true;
				return {
					context: {
						systemPrompt: "second prompt",
						messages: currentContext.messages.slice(),
						tools: currentContext.tools,
					},
				};
			},
		};

		let llmCalls = 0;
		const stream = agentLoop([createUserMessage("echo something")], context, config, undefined, (_model, ctx) => {
			llmCalls++;
			if (llmCalls === 2) {
				convertedSecondTurnSystemPrompt = ctx.systemPrompt ?? "";
			}
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				if (llmCalls === 1) {
					mockStream.push({
						type: "done",
						reason: "toolUse",
						message: createAssistantMessage(
							[{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "hello" } }],
							"toolUse",
						),
					});
				} else {
					mockStream.push({
						type: "done",
						reason: "stop",
						message: createAssistantMessage([{ type: "text", text: "done" }]),
					});
				}
			});
			return mockStream;
		});

		for await (const _event of stream) {
			// consume
		}

		expect(llmCalls).toBe(2);
		expect(convertedSecondTurnSystemPrompt).toBe("second prompt");
	});

	it("should stop after the current turn when shouldStopAfterTurn returns true", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const executed: string[] = [];
		const tool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				executed.push(params.value);
				return {
					content: [{ type: "text", text: `echoed: ${params.value}` }],
					details: { value: params.value },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		let steeringPolls = 0;
		let followUpPolls = 0;
		let callbackToolResultIds: string[] = [];
		let callbackContextRoles: string[] = [];
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			getSteeringMessages: async () => {
				steeringPolls++;
				return [];
			},
			getFollowUpMessages: async () => {
				followUpPolls++;
				return [createUserMessage("follow up should stay queued")];
			},
			shouldStopAfterTurn: async ({ message, toolResults, context }) => {
				expect(message.role).toBe("assistant");
				callbackToolResultIds = toolResults.map((toolResult) => toolResult.toolCallId);
				callbackContextRoles = context.messages.map((contextMessage) => contextMessage.role);
				return true;
			},
		};

		let llmCalls = 0;
		const stream = agentLoop([createUserMessage("echo something")], context, config, undefined, () => {
			llmCalls++;
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				if (llmCalls === 1) {
					const message = createAssistantMessage(
						[{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "hello" } }],
						"toolUse",
					);
					mockStream.push({ type: "done", reason: "toolUse", message });
				} else {
					mockStream.push({
						type: "done",
						reason: "stop",
						message: createAssistantMessage([{ type: "text", text: "should not run" }]),
					});
				}
			});
			return mockStream;
		});

		const events: AgentEvent[] = [];
		for await (const event of stream) {
			events.push(event);
		}

		const messages = await stream.result();
		expect(llmCalls).toBe(1);
		expect(executed).toEqual(["hello"]);
		expect(steeringPolls).toBe(1);
		expect(followUpPolls).toBe(0);
		expect(callbackToolResultIds).toEqual(["tool-1"]);
		expect(callbackContextRoles).toEqual(["user", "assistant", "toolResult"]);
		expect(messages.map((message) => message.role)).toEqual(["user", "assistant", "toolResult"]);
		expect(events.map((event) => event.type)).toEqual([
			"agent_start",
			"turn_start",
			"message_start",
			"message_end",
			"message_start",
			"message_end",
			"tool_execution_start",
			"tool_execution_end",
			"message_start",
			"message_end",
			"turn_end",
			"agent_end",
		]);
	});

	it("should stop after a tool batch when every tool result sets terminate=true", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const tool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				return {
					content: [{ type: "text", text: `echoed: ${params.value}` }],
					details: { value: params.value },
					terminate: true,
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		let llmCalls = 0;
		const stream = agentLoop([createUserMessage("echo something")], context, config, undefined, () => {
			llmCalls++;
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				const message = createAssistantMessage(
					[{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "hello" } }],
					"toolUse",
				);
				mockStream.push({ type: "done", reason: "toolUse", message });
			});
			return mockStream;
		});

		const events: AgentEvent[] = [];
		for await (const event of stream) {
			events.push(event);
		}

		const messages = await stream.result();
		expect(llmCalls).toBe(1);
		expect(messages.map((message) => message.role)).toEqual(["user", "assistant", "toolResult"]);
		expect(events.filter((event) => event.type === "turn_end")).toHaveLength(1);
	});

	it("should continue after parallel tool calls when not all tool results terminate", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const tool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				return {
					content: [{ type: "text", text: `echoed: ${params.value}` }],
					details: { value: params.value },
					terminate: params.value === "first",
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			toolExecution: "parallel",
		};

		let callIndex = 0;
		const stream = agentLoop([createUserMessage("echo both")], context, config, undefined, () => {
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					const message = createAssistantMessage(
						[
							{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "first" } },
							{ type: "toolCall", id: "tool-2", name: "echo", arguments: { value: "second" } },
						],
						"toolUse",
					);
					mockStream.push({ type: "done", reason: "toolUse", message });
				} else {
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					mockStream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return mockStream;
		});

		for await (const _event of stream) {
			// consume
		}

		const messages = await stream.result();
		expect(callIndex).toBe(2);
		expect(messages.map((message) => message.role)).toEqual([
			"user",
			"assistant",
			"toolResult",
			"toolResult",
			"assistant",
		]);
	});

	it("should allow afterToolCall to mark a tool batch as terminating", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const tool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				return {
					content: [{ type: "text", text: `echoed: ${params.value}` }],
					details: { value: params.value },
					addedToolNames: ["new-tool"],
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			afterToolCall: async () => ({ terminate: true }),
		};

		let llmCalls = 0;
		const stream = agentLoop([createUserMessage("echo something")], context, config, undefined, () => {
			llmCalls++;
			const mockStream = new MockAssistantStream();
			queueMicrotask(() => {
				const message = createAssistantMessage(
					[{ type: "toolCall", id: "tool-1", name: "echo", arguments: { value: "hello" } }],
					"toolUse",
				);
				mockStream.push({ type: "done", reason: "toolUse", message });
			});
			return mockStream;
		});

		for await (const _event of stream) {
			// consume
		}

		const messages = await stream.result();
		const toolResult = messages.find((message) => message.role === "toolResult");
		expect(llmCalls).toBe(1);
		expect(toolResult?.addedToolNames).toEqual(["new-tool"]);
	});
});

describe("agentLoopContinue with AgentMessage", () => {
	it("should throw when context has no messages", () => {
		const context: AgentContext = {
			systemPrompt: "You are helpful.",
			messages: [],
			tools: [],
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		expect(() => agentLoopContinue(context, config)).toThrow("Cannot continue: no messages in context");
	});

	it("should continue from existing context without emitting user message events", async () => {
		const userMessage: AgentMessage = createUserMessage("Hello");

		const context: AgentContext = {
			systemPrompt: "You are helpful.",
			messages: [userMessage],
			tools: [],
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const message = createAssistantMessage([{ type: "text", text: "Response" }]);
				stream.push({ type: "done", reason: "stop", message });
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		const stream = agentLoopContinue(context, config, undefined, streamFn);

		for await (const event of stream) {
			events.push(event);
		}

		const messages = await stream.result();

		// Should only return the new assistant message (not the existing user message)
		expect(messages.length).toBe(1);
		expect(messages[0].role).toBe("assistant");

		// Should NOT have user message events (that's the key difference from agentLoop)
		const messageEndEvents = events.filter((e) => e.type === "message_end");
		expect(messageEndEvents.length).toBe(1);
		expect((messageEndEvents[0] as any).message.role).toBe("assistant");
	});

	it("should allow custom message types as last message (caller responsibility)", async () => {
		// Custom message that will be converted to user message by convertToLlm
		interface CustomMessage {
			role: "custom";
			text: string;
			timestamp: number;
		}

		const customMessage: CustomMessage = {
			role: "custom",
			text: "Hook content",
			timestamp: Date.now(),
		};

		const context: AgentContext = {
			systemPrompt: "You are helpful.",
			messages: [customMessage as unknown as AgentMessage],
			tools: [],
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: (messages) => {
				// Convert custom to user message
				return messages
					.map((m) => {
						if ((m as any).role === "custom") {
							return {
								role: "user" as const,
								content: (m as any).text,
								timestamp: m.timestamp,
							};
						}
						return m;
					})
					.filter((m) => m.role === "user" || m.role === "assistant" || m.role === "toolResult") as Message[];
			},
		};

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const message = createAssistantMessage([{ type: "text", text: "Response to custom message" }]);
				stream.push({ type: "done", reason: "stop", message });
			});
			return stream;
		};

		// Should not throw - the custom message will be converted to user message
		const stream = agentLoopContinue(context, config, undefined, streamFn);

		const events: AgentEvent[] = [];
		for await (const event of stream) {
			events.push(event);
		}

		const messages = await stream.result();
		expect(messages.length).toBe(1);
		expect(messages[0].role).toBe("assistant");
	});
});

describe("agentLoop maxTurns budget", () => {
	it("stops gracefully after maxTurns turns instead of looping forever", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		let executeCount = 0;
		const tool: AgentTool<typeof toolSchema, { value: number }> = {
			name: "loop",
			label: "Loop",
			description: "Always-call tool that never lets the agent stop",
			parameters: toolSchema,
			async execute(_toolCallId, _params) {
				executeCount++;
				return {
					content: [{ type: "text", text: `tick ${executeCount}` }],
					details: { value: executeCount },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [tool],
		};

		const userPrompt: AgentMessage = createUserMessage("keep calling loop");

		// Always emit a tool call so the loop would run forever without a budget.
		let streamCallCount = 0;
		const streamFn = () => {
			streamCallCount++;
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const message = createAssistantMessage(
					[{ type: "toolCall", id: `tool-${streamCallCount}`, name: "loop", arguments: { value: "x" } }],
					"toolUse",
				);
				stream.push({ type: "done", reason: "toolUse", message });
			});
			return stream;
		};

		let budgetNotice: { turns: number; maxTurns: number } | undefined;
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			maxTurns: 3,
			onRunBudgetExceeded: (info) => {
				budgetNotice = info;
			},
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const event of stream) {
			events.push(event);
		}
		const messages = await stream.result();

		// Exactly 3 provider requests / tool executions — no 4th turn.
		expect(streamCallCount).toBe(3);
		expect(executeCount).toBe(3);
		// 3 assistant turns + 3 tool-result messages + 1 user prompt = 7.
		expect(messages.length).toBe(7);
		// Budget side-effect fired once with the right counts.
		expect(budgetNotice).toEqual({ turns: 3, maxTurns: 3 });
		// agent_end emitted exactly once and is the last event.
		const agentEnds = events.filter((e) => e.type === "agent_end");
		expect(agentEnds.length).toBe(1);
		expect(events[events.length - 1].type).toBe("agent_end");
		// 3 turn_end events — the in-flight turn always completes before the cap stops.
		expect(events.filter((e) => e.type === "turn_end").length).toBe(3);
	});

	it("does not cap when maxTurns is unset (unbounded default preserved)", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const tool: AgentTool<typeof toolSchema, { value: number }> = {
			name: "loop",
			label: "Loop",
			description: "tool",
			parameters: toolSchema,
			async execute(_toolCallId, _params) {
				return { content: [{ type: "text", text: "ok" }], details: { value: 1 } };
			},
		};

		const context: AgentContext = { systemPrompt: "", messages: [], tools: [tool] };
		const userPrompt: AgentMessage = createUserMessage("call loop then stop");

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					const message = createAssistantMessage(
						[{ type: "toolCall", id: "tool-1", name: "loop", arguments: { value: "x" } }],
						"toolUse",
					);
					stream.push({ type: "done", reason: "toolUse", message });
				} else {
					const message = createAssistantMessage([{ type: "text", text: "done" }]);
					stream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return stream;
		};

		let budgetNotice: { turns: number; maxTurns: number } | undefined;
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			onRunBudgetExceeded: (info) => {
				budgetNotice = info;
			},
		};

		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const _event of stream) {
			// consume
		}
		await stream.result();

		// Without a budget the loop ran its natural 2 turns and never fired the hook.
		expect(callIndex).toBe(2);
		expect(budgetNotice).toBeUndefined();
	});
});

describe("agentLoop length auto-continue", () => {
	it("auto-continues on a length stop with no tool calls", async () => {
		const context: AgentContext = { systemPrompt: "", messages: [], tools: [] };
		const userPrompt: AgentMessage = createUserMessage("write a long answer");

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					// Output hit maxTokens mid-response, no tool calls.
					const message = createAssistantMessage([{ type: "text", text: "part1" }], "length");
					stream.push({ type: "done", reason: "length", message });
				} else {
					const message = createAssistantMessage([{ type: "text", text: "part2" }], "stop");
					stream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return stream;
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			lengthContinueMaxTurns: 3,
		};

		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();

		// Two provider requests: the length-stopped one + the continuation.
		expect(callIndex).toBe(2);
		// user, assistant(part1), user(continue), assistant(part2)
		expect(messages.length).toBe(4);
		expect(messages[1].role).toBe("assistant");
		expect((messages[1] as AssistantMessage).stopReason).toBe("length");
		expect(messages[2].role).toBe("user");
		expect(messages[3].role).toBe("assistant");
		expect((messages[3] as AssistantMessage).stopReason).toBe("stop");
	});

	it("does not auto-continue when lengthContinueMaxTurns is unset", async () => {
		const context: AgentContext = { systemPrompt: "", messages: [], tools: [] };
		const userPrompt: AgentMessage = createUserMessage("write a long answer");

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const message = createAssistantMessage([{ type: "text", text: "part1" }], "length");
				stream.push({ type: "done", reason: "length", message });
				callIndex++;
			});
			return stream;
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();

		// Default: a length stop ends the turn (no continuation).
		expect(callIndex).toBe(1);
		expect(messages.length).toBe(2);
		expect((messages[1] as AssistantMessage).stopReason).toBe("length");
	});

	it("respects the lengthContinueMaxTurns cap", async () => {
		const context: AgentContext = { systemPrompt: "", messages: [], tools: [] };
		const userPrompt: AgentMessage = createUserMessage("write a long answer");

		// Every response length-stops; the cap must bound the continuations.
		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const message = createAssistantMessage([{ type: "text", text: `part${callIndex}` }], "length");
				stream.push({ type: "done", reason: "length", message });
				callIndex++;
			});
			return stream;
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			lengthContinueMaxTurns: 2,
		};

		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();

		// 1 original + 2 continuations = 3 provider requests, then stop.
		expect(callIndex).toBe(3);
		// user + 3*(assistant + user-continue) but last continuation adds assistant
		// without a trailing continue: user, A, U, A, U, A => 6
		expect(messages.length).toBe(6);
		const assistants = messages.filter((m) => m.role === "assistant");
		expect(assistants.length).toBe(3);
		expect((assistants[2] as AssistantMessage).stopReason).toBe("length");
	});
});

describe("agentLoop unknown tool recovery", () => {
	it("returns an error tool result listing available tools for a hallucinated name", async () => {
		const toolSchema = Type.Object({ value: Type.String() });
		const realTool: AgentTool<typeof toolSchema, { value: string }> = {
			name: "echo",
			label: "Echo",
			description: "Echo tool",
			parameters: toolSchema,
			async execute(_toolCallId, params) {
				return {
					content: [{ type: "text", text: `echoed: ${params.value}` }],
					details: { value: params.value },
				};
			},
		};

		const context: AgentContext = {
			systemPrompt: "",
			messages: [],
			tools: [realTool],
		};

		const userPrompt: AgentMessage = createUserMessage("use the hallucinated tool");

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					const message = createAssistantMessage(
						[{ type: "toolCall", id: "tool-1", name: "nonexistent_tool", arguments: { value: "x" } }],
						"toolUse",
					);
					stream.push({ type: "done", reason: "toolUse", message });
				} else {
					const message = createAssistantMessage([{ type: "text", text: "recovered" }]);
					stream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return stream;
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const event of stream) {
			events.push(event);
		}
		const messages = await stream.result();

		// The unknown tool call produces an error tool-result message that lists
		// the available tools so the model can self-correct.
		const toolResults = messages.filter((m) => m.role === "toolResult");
		expect(toolResults.length).toBe(1);
		const tr = toolResults[0] as unknown as {
			content: Array<{ type: string; text?: string }>;
			isError: boolean;
		};
		expect(tr.isError).toBe(true);
		const text = tr.content.map((c) => c.text ?? "").join("");
		expect(text).toContain('"nonexistent_tool" not found');
		expect(text).toContain("Available tools: echo");

		// tool_execution_end marked as an error.
		const toolEnd = events.find((e) => e.type === "tool_execution_end");
		expect(toolEnd && (toolEnd as { isError: boolean }).isError).toBe(true);
	});
});

describe("agentLoop stream retry", () => {
	function createErrorAssistantMessage(errorMessage: string): AssistantMessage {
		return { ...createAssistantMessage([], "error"), errorMessage };
	}

	it("retries a pre-stream transient error and succeeds on the next attempt", async () => {
		const context: AgentContext = { systemPrompt: "", messages: [], tools: [] };
		const userPrompt: AgentMessage = createUserMessage("hi");

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					// Pre-stream failure: error event with no preceding start event.
					stream.push({ type: "error", reason: "error", error: createErrorAssistantMessage("network error") });
				} else {
					const message = createAssistantMessage([{ type: "text", text: "recovered" }]);
					stream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return stream;
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			streamMaxRetries: 2,
			streamRetryBaseDelayMs: 1,
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const event of stream) {
			events.push(event);
		}
		const messages = await stream.result();

		// Two provider requests: the failed one + the retry that succeeded.
		expect(callIndex).toBe(2);
		// Only the successful assistant message is committed: user + assistant.
		expect(messages.length).toBe(2);
		expect((messages[1] as AssistantMessage).stopReason).toBe("stop");
		// Exactly one assistant message_start / message_end — the failed attempt
		// emitted nothing (the only other message_start is the user prompt).
		const starts = events.filter(
			(e) => e.type === "message_start" && (e as { message: { role: string } }).message.role === "assistant",
		);
		const ends = events.filter(
			(e) => e.type === "message_end" && (e as { message: { role: string } }).message.role === "assistant",
		);
		expect(starts.length).toBe(1);
		expect(ends.length).toBe(1);
	});

	it("does not retry when streamMaxRetries is unset", async () => {
		const context: AgentContext = { systemPrompt: "", messages: [], tools: [] };
		const userPrompt: AgentMessage = createUserMessage("hi");

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				stream.push({ type: "error", reason: "error", error: createErrorAssistantMessage("network error") });
				callIndex++;
			});
			return stream;
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
		};

		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();

		// Default: a pre-stream error ends the turn (no retry).
		expect(callIndex).toBe(1);
		expect(messages.length).toBe(2);
		expect((messages[1] as AssistantMessage).stopReason).toBe("error");
	});

	it("respects the streamMaxRetries cap", async () => {
		const context: AgentContext = { systemPrompt: "", messages: [], tools: [] };
		const userPrompt: AgentMessage = createUserMessage("hi");

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				stream.push({ type: "error", reason: "error", error: createErrorAssistantMessage("network error") });
				callIndex++;
			});
			return stream;
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			streamMaxRetries: 2,
			streamRetryBaseDelayMs: 1,
		};

		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();

		// 1 original + 2 retries = 3 provider requests, then the error is surfaced.
		expect(callIndex).toBe(3);
		expect(messages.length).toBe(2);
		expect((messages[1] as AssistantMessage).stopReason).toBe("error");
	});

	it("does not retry a non-retryable error (auth) by default", async () => {
		const context: AgentContext = { systemPrompt: "", messages: [], tools: [] };
		const userPrompt: AgentMessage = createUserMessage("hi");

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				stream.push({ type: "error", reason: "error", error: createErrorAssistantMessage("401 Unauthorized") });
				callIndex++;
			});
			return stream;
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			streamMaxRetries: 3,
			streamRetryBaseDelayMs: 1,
		};

		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);
		for await (const _event of stream) {
			// consume
		}
		const messages = await stream.result();

		// Auth errors are permanent: no retry, error surfaced immediately.
		expect(callIndex).toBe(1);
		expect((messages[1] as AssistantMessage).stopReason).toBe("error");
	});

	it("opt #224: records 'aborted' (not the original error) when the run is aborted during retry backoff", async () => {
		const context: AgentContext = { systemPrompt: "", messages: [], tools: [] };
		const userPrompt: AgentMessage = createUserMessage("hi");
		const controller = new AbortController();

		let callIndex = 0;
		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				if (callIndex === 0) {
					stream.push({ type: "error", reason: "error", error: createErrorAssistantMessage("network error") });
					// Abort DURING the retry backoff: schedule it on a later macrotask
					// so the synchronous retry decision (which checks !signal?.aborted)
					// has already passed and abortableSleep is pending. 20ms < 200ms.
					setTimeout(() => controller.abort(), 20);
				} else {
					// Unreachable: abort stops the retry before a second request.
					const message = createAssistantMessage([{ type: "text", text: "recovered" }]);
					stream.push({ type: "done", reason: "stop", message });
				}
				callIndex++;
			});
			return stream;
		};

		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: identityConverter,
			streamMaxRetries: 2,
			streamRetryBaseDelayMs: 200,
		};

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, controller.signal, streamFn);
		for await (const event of stream) {
			events.push(event);
		}
		const messages = await stream.result();

		// The retry never issued a second provider request — abort stopped it.
		expect(callIndex).toBe(1);
		expect(messages.length).toBe(2);
		// Finding #2: the committed message reflects the abort, not the original
		// transient error. Pre-fix this was stopReason "error" / "network error".
		const committed = messages[1] as AssistantMessage;
		expect(committed.stopReason).toBe("aborted");
		expect(committed.errorMessage).toBe("Operation aborted");
		// The abort terminal events were emitted.
		const ends = events.filter(
			(e) => e.type === "message_end" && (e as { message: { role: string } }).message.role === "assistant",
		);
		expect(ends.length).toBe(1);
	});
});

describe("agentLoop rejection safety", () => {
	it("ends the stream (does not hang) and resolves result to [] when runAgentLoop rejects", async () => {
		// A throwing convertToLlm makes runAgentLoop reject. Without the .catch()
		// on the public agentLoop wrapper, stream.end() would never be called and a
		// consumer iterating the EventStream would hang forever (plus an unhandled
		// rejection). The wrapper must end the stream so iteration completes.
		const context: AgentContext = {
			systemPrompt: "You are helpful.",
			messages: [],
			tools: [],
		};
		const userPrompt: AgentMessage = createUserMessage("Hello");
		const config: AgentLoopConfig = {
			model: createModel(),
			convertToLlm: () => {
				throw new Error("convertToLlm blew up");
			},
		};

		const stream = agentLoop([userPrompt], context, config, undefined, () => new MockAssistantStream());

		// Iteration must terminate (not hang) even though the run rejected.
		const events: AgentEvent[] = [];
		for await (const event of stream) {
			events.push(event);
		}
		// result() resolves (to []) instead of pending forever.
		const messages = await Promise.race([
			stream.result(),
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("result() hung")), 2000)),
		]);
		expect(Array.isArray(messages)).toBe(true);
		expect(messages.length).toBe(0);
	});
});

describe("agentLoop stream ended without a terminal event (FIX 1b)", () => {
	it("synthesizes an error AssistantMessage instead of hanging on response.result()", async () => {
		// A streamFn whose stream emits start + a text delta, then ends WITHOUT a
		// done/error terminal event (e.g. a proxy SSE body that closed cleanly but
		// never pushed `done`). EventStream.end() with no result argument does NOT
		// resolve finalResultPromise, so the old `await response.result()` would
		// hang forever → the turn/runPromise/waitForIdle hang and the streamed
		// partial never gets a message_end. The agent-loop must synthesize an error
		// AssistantMessage and proceed to the commit path.
		const context: AgentContext = { systemPrompt: "", messages: [], tools: [] };
		const userPrompt: AgentMessage = createUserMessage("hi");

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const partial = createAssistantMessage([{ type: "text", text: "" }]);
				stream.push({ type: "start", partial });
				(partial.content[0] as { text: string }).text = "streamed partial";
				stream.push({ type: "text_delta", contentIndex: 0, delta: "streamed partial", partial });
				// End WITHOUT a done/error event.
				stream.end();
			});
			return stream;
		};

		const config: AgentLoopConfig = { model: createModel(), convertToLlm: identityConverter };

		const events: AgentEvent[] = [];
		const stream = agentLoop([userPrompt], context, config, undefined, streamFn);

		// Consume + result() with a timeout: without the fix this hangs.
		const messages = await Promise.race([
			(async () => {
				for await (const event of stream) {
					events.push(event);
				}
				return await stream.result();
			})(),
			new Promise<never>((_, reject) =>
				setTimeout(() => reject(new Error("agent loop hung on stream without terminal event")), 2000),
			),
		]);

		// user prompt + synthesized error assistant message.
		expect(messages.length).toBe(2);
		const assistant = messages[1] as AssistantMessage;
		expect(assistant.role).toBe("assistant");
		expect(assistant.stopReason).toBe("error");
		expect(assistant.errorMessage).toBe("Stream ended without a terminal event");
		// The streamed partial text is preserved on the committed message.
		const textBlock = assistant.content[0];
		if (textBlock.type !== "text") throw new Error("expected text content");
		expect(textBlock.text).toBe("streamed partial");

		// A message_end was emitted for the assistant (the partial was committed,
		// not discarded). Exactly one assistant message_end.
		const assistantEnds = events.filter(
			(e) => e.type === "message_end" && (e as { message: { role: string } }).message.role === "assistant",
		);
		expect(assistantEnds.length).toBe(1);
		// agent_end was emitted (the run terminated cleanly).
		expect(events.some((e) => e.type === "agent_end")).toBe(true);
	});
});

describe("agentLoop streaming emit-throw preserves the partial (FIX 3)", () => {
	it("commits the partial via message_end before re-throwing when emit throws mid-stream", async () => {
		// A harness "*" subscriber throwing inside emit on a message_update (or the
		// stream's async iterator throwing) used to exit the for-await with
		// finalMessage === null and no message_end for the partial → the partial
		// text the UI saw was discarded from the durable transcript. The agent-loop
		// must best-effort emit a message_end for the partial (stopReason "error")
		// before re-throwing so the run-failure path still runs.
		const context: AgentContext = { systemPrompt: "", messages: [], tools: [] };
		const userPrompt: AgentMessage = createUserMessage("hi");

		const streamFn = () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const partial = createAssistantMessage([{ type: "text", text: "" }]);
				stream.push({ type: "start", partial });
				(partial.content[0] as { text: string }).text = "partial body";
				stream.push({ type: "text_delta", contentIndex: 0, delta: "partial body", partial });
			});
			return stream;
		};

		const events: AgentEvent[] = [];
		// Emit sink that throws on message_update (a streaming delta) but accepts
		// message_end (so the catch's best-effort commit can succeed).
		const emit = async (event: AgentEvent): Promise<void> => {
			events.push(event);
			if (event.type === "message_update") {
				throw new Error("emit sink broke on message_update");
			}
		};

		const config: AgentLoopConfig = { model: createModel(), convertToLlm: identityConverter };

		// runAgentLoop rejects (the throw re-propagates after the best-effort
		// commit). Catch it so we can assert the partial was committed first.
		let rejected = false;
		try {
			await runAgentLoop([userPrompt], context, config, emit, undefined, streamFn);
		} catch {
			rejected = true;
		}
		expect(rejected).toBe(true);

		// The partial assistant message got a message_end (stopReason "error")
		// before the re-throw — not discarded from the transcript.
		const assistantEnds = events.filter(
			(e): e is Extract<AgentEvent, { type: "message_end" }> =>
				e.type === "message_end" && (e as { message: { role: string } }).message.role === "assistant",
		);
		expect(assistantEnds.length).toBe(1);
		const committed = assistantEnds[0].message as AssistantMessage;
		expect(committed.stopReason).toBe("error");
		const textBlock = committed.content[0];
		if (textBlock.type !== "text") throw new Error("expected text content");
		expect(textBlock.text).toBe("partial body");
		// The message_start for the assistant was emitted during streaming.
		const assistantStarts = events.filter(
			(e) => e.type === "message_start" && (e as { message: { role: string } }).message.role === "assistant",
		);
		expect(assistantStarts.length).toBe(1);
	});
});

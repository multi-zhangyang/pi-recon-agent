import { type AssistantMessage, type AssistantMessageEvent, EventStream } from "@pi-recon/repi-ai";
import { Type } from "typebox";
import { describe, expect, it } from "vitest";
import { Agent, type AgentTool } from "../src/index.ts";

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

function assistantMessage(
	content: AssistantMessage["content"],
	stopReason: AssistantMessage["stopReason"],
): AssistantMessage {
	return {
		role: "assistant",
		content,
		api: "openai-responses",
		provider: "test",
		model: "test-model",
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

describe("Agent dynamic turn context", () => {
	it("uses live system prompt and tools after a tool changes state", async () => {
		const emptyParameters = Type.Object({});
		const deferredTool: AgentTool<typeof emptyParameters> = {
			name: "deferred_tool",
			label: "Deferred",
			description: "Activated after the first turn",
			parameters: emptyParameters,
			async execute() {
				return { content: [{ type: "text", text: "deferred" }], details: {} };
			},
		};

		let agent: Agent;
		const activationTool: AgentTool<typeof emptyParameters> = {
			name: "activate_capability",
			label: "Activate capability",
			description: "Changes the live Agent state",
			parameters: emptyParameters,
			async execute() {
				agent.state.systemPrompt = "focused prompt";
				agent.state.tools = [deferredTool];
				return { content: [{ type: "text", text: "activated" }], details: {} };
			},
		};

		let providerCalls = 0;
		let secondTurnPrompt = "";
		let secondTurnTools: string[] = [];
		agent = new Agent({
			initialState: { systemPrompt: "initial prompt", tools: [activationTool] },
			streamFn: (_model, context) => {
				providerCalls++;
				const stream = new MockAssistantStream();
				queueMicrotask(() => {
					if (providerCalls === 1) {
						stream.push({
							type: "done",
							reason: "toolUse",
							message: assistantMessage(
								[{ type: "toolCall", id: "activate-1", name: "activate_capability", arguments: {} }],
								"toolUse",
							),
						});
						return;
					}
					secondTurnPrompt = context.systemPrompt ?? "";
					secondTurnTools = context.tools?.map((tool) => tool.name) ?? [];
					stream.push({
						type: "done",
						reason: "stop",
						message: assistantMessage([{ type: "text", text: "done" }], "stop"),
					});
				});
				return stream;
			},
		});

		await agent.prompt("activate the focused capability");

		expect(providerCalls).toBe(2);
		expect(secondTurnPrompt).toBe("focused prompt");
		expect(secondTurnTools).toEqual(["deferred_tool"]);
	});
});

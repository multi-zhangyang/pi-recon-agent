import type { AgentTool } from "@pi-recon/repi-agent-core";
import { fauxAssistantMessage, fauxToolCall } from "@pi-recon/repi-ai";
import { Type } from "typebox";
import { afterEach, describe, expect, it } from "vitest";
import { createHarness, getUserTexts, type Harness } from "../harness.ts";

function createWaitTool(released: Promise<void>): AgentTool {
	return {
		name: "wait",
		label: "Wait",
		description: "Wait until released",
		parameters: Type.Object({}),
		execute: async () => {
			await released;
			return { content: [{ type: "text", text: "released" }], details: {} };
		},
	};
}

describe("regression #6363: agent settled event and idle waiting", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) {
			harnesses.pop()?.cleanup();
		}
	});

	it("emits one agent_settled event after automatic retry finishes", async () => {
		const extensionEvents: string[] = [];
		const publicEvents: string[] = [];
		const harness = await createHarness({
			settings: { retry: { enabled: true, maxRetries: 3, baseDelayMs: 1 } },
			extensionFactories: [
				(repi) => {
					repi.on("agent_end", () => {
						extensionEvents.push("agent_end");
					});
					repi.on("agent_settled", (_event, ctx) => {
						extensionEvents.push(`agent_settled:${ctx.isIdle()}`);
					});
				},
			],
		});
		harnesses.push(harness);
		harness.session.subscribe((event) => {
			if (event.type === "agent_settled") {
				publicEvents.push("agent_settled");
			}
		});
		harness.setResponses([
			fauxAssistantMessage("", { stopReason: "error", errorMessage: "overloaded_error" }),
			fauxAssistantMessage("recovered"),
		]);

		await harness.session.prompt("test");

		expect(harness.eventsOfType("agent_end").map((event) => event.willRetry)).toEqual([true, false]);
		expect(harness.eventsOfType("agent_settled")).toHaveLength(1);
		expect(extensionEvents).toEqual(["agent_end", "agent_end", "agent_settled:true"]);
		expect(publicEvents).toEqual(["agent_settled"]);
	});

	it("settles only after follow-ups queued by agent_end handlers run", async () => {
		let queuedFollowUp = false;
		const settledIdleStates: boolean[] = [];
		const harness = await createHarness({
			extensionFactories: [
				(repi) => {
					repi.on("agent_end", () => {
						if (queuedFollowUp) return;
						queuedFollowUp = true;
						repi.sendUserMessage("status follow-up", { deliverAs: "followUp" });
					});
					repi.on("agent_settled", (_event, ctx) => {
						settledIdleStates.push(ctx.isIdle());
					});
				},
			],
		});
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("first"), fauxAssistantMessage("second")]);

		await harness.session.prompt("hello");

		expect(getUserTexts(harness)).toEqual(["hello", "status follow-up"]);
		expect(harness.eventsOfType("agent_end")).toHaveLength(2);
		expect(harness.eventsOfType("agent_settled")).toHaveLength(1);
		expect(settledIdleStates).toEqual([true]);
	});

	it("resumes a follow-up queued directly by an agent_settled handler", async () => {
		let settlementCount = 0;
		const harness = await createHarness({
			extensionFactories: [
				(repi) => {
					repi.on("agent_settled", () => {
						settlementCount++;
						if (settlementCount === 1) {
							repi.sendUserMessage("settled follow-up", { deliverAs: "followUp" });
						}
					});
				},
			],
		});
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("first"), fauxAssistantMessage("second")]);

		await harness.session.prompt("hello");

		expect(getUserTexts(harness)).toEqual(["hello", "settled follow-up"]);
		expect(harness.faux.state.callCount).toBe(2);
		expect(settlementCount).toBe(2);
		expect(harness.eventsOfType("agent_settled")).toHaveLength(1);
		expect(harness.session.isStreaming).toBe(false);
	});

	it("extension command waitForIdle waits for session-level settlement", async () => {
		let releaseTool = () => {};
		const released = new Promise<void>((resolve) => {
			releaseTool = resolve;
		});
		let markCommandStarted = () => {};
		const commandStarted = new Promise<void>((resolve) => {
			markCommandStarted = resolve;
		});
		const commandResults: boolean[] = [];
		const harness = await createHarness({
			tools: [createWaitTool(released)],
			extensionFactories: [
				(repi) => {
					repi.registerCommand("after-idle", {
						description: "Wait for idle",
						handler: async (_args, ctx) => {
							markCommandStarted();
							await ctx.waitForIdle();
							commandResults.push(ctx.isIdle());
						},
					});
				},
			],
		});
		harnesses.push(harness);
		await harness.session.bindExtensions({
			commandContextActions: {
				waitForIdle: () => harness.session.waitForIdle(),
				newSession: async () => ({ cancelled: false }),
				fork: async () => ({ cancelled: false }),
				navigateTree: async () => ({ cancelled: false }),
				switchSession: async () => ({ cancelled: false }),
				reload: async () => {},
			},
		});
		const toolStarted = new Promise<void>((resolve) => {
			const unsubscribe = harness.session.subscribe((event) => {
				if (event.type === "tool_execution_start" && event.toolName === "wait") {
					unsubscribe();
					resolve();
				}
			});
		});
		harness.setResponses([
			fauxAssistantMessage(fauxToolCall("wait", {}), { stopReason: "toolUse" }),
			fauxAssistantMessage("done"),
		]);

		const promptPromise = harness.session.prompt("start");
		await toolStarted;
		const commandPromise = harness.session.prompt("/after-idle");
		await commandStarted;
		let commandFinished = false;
		void commandPromise.then(() => {
			commandFinished = true;
		});
		await new Promise((resolve) => setTimeout(resolve, 0));
		expect(commandFinished).toBe(false);

		releaseTool();
		await Promise.all([promptPromise, commandPromise]);

		expect(commandResults).toEqual([true]);
		expect(harness.eventsOfType("agent_settled")).toHaveLength(1);
	});

	it("settles an independently triggered queued continuation", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("seeded"), fauxAssistantMessage("continued")]);

		await harness.session.prompt("seed");
		await harness.session.sendCustomMessage(
			{ customType: "continuation", content: "continue from extension", display: false },
			{ deliverAs: "steer", triggerTurn: true },
		);

		expect(harness.eventsOfType("agent_end")).toHaveLength(2);
		expect(harness.eventsOfType("agent_settled")).toHaveLength(2);
		expect(harness.session.isIdle).toBe(true);
	});

	it("holds idle waiters through async settlement and resumes follow-ups queued during it", async () => {
		let releaseSettlement = () => {};
		const settlementReleased = new Promise<void>((resolve) => {
			releaseSettlement = resolve;
		});
		let markSettlementStarted = () => {};
		const settlementStarted = new Promise<void>((resolve) => {
			markSettlementStarted = resolve;
		});
		let settlementCount = 0;
		const harness = await createHarness({
			extensionFactories: [
				(repi) => {
					repi.on("agent_settled", async () => {
						settlementCount++;
						if (settlementCount !== 1) return;
						markSettlementStarted();
						await settlementReleased;
					});
				},
			],
		});
		harnesses.push(harness);
		harness.setResponses([fauxAssistantMessage("first"), fauxAssistantMessage("second")]);

		const firstPrompt = harness.session.prompt("first prompt");
		await settlementStarted;
		expect(harness.session.isIdle).toBe(true);
		expect(harness.session.isStreaming).toBe(true);

		let idleResolved = false;
		const idle = harness.session.waitForIdle().then(() => {
			idleResolved = true;
		});
		await harness.session.prompt("queued during settlement", { streamingBehavior: "followUp" });
		await new Promise((resolve) => setTimeout(resolve, 0));
		expect(idleResolved).toBe(false);

		releaseSettlement();
		await Promise.all([firstPrompt, idle]);

		expect(getUserTexts(harness)).toEqual(["first prompt", "queued during settlement"]);
		expect(harness.faux.state.callCount).toBe(2);
		expect(settlementCount).toBe(2);
		expect(harness.eventsOfType("agent_settled")).toHaveLength(1);
		expect(harness.session.isStreaming).toBe(false);
	});
});

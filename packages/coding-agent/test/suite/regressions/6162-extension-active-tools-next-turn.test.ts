import { fauxAssistantMessage, fauxToolCall } from "@pi-recon/repi-ai";
import { Type } from "typebox";
import { describe, expect, it } from "vitest";
import type { ExtensionFactory } from "../../../src/index.ts";
import { createHarness } from "../harness.ts";

describe("extension active tools next-turn refresh", () => {
	it("records additive active tool changes on the current tool result", async () => {
		const extensionFactories: ExtensionFactory[] = [
			(pi) => {
				pi.registerTool({
					name: "load_more_tools",
					label: "Load More Tools",
					description: "Load more tools",
					parameters: Type.Object({}),
					execute: async () => {
						pi.setActiveTools([...pi.getActiveTools(), "after_load"]);
						return {
							content: [{ type: "text", text: "loaded" }],
							details: {},
						};
					},
				});

				pi.registerTool({
					name: "after_load",
					label: "After Load",
					description: "Tool available after loading",
					parameters: Type.Object({}),
					execute: async () => ({
						content: [{ type: "text", text: "after" }],
						details: {},
					}),
				});
			},
		];
		const harness = await createHarness({ extensionFactories });

		try {
			harness.session.setActiveToolsByName(["load_more_tools"]);

			const addedToolNames: string[][] = [];
			harness.setResponses([
				() => fauxAssistantMessage(fauxToolCall("load_more_tools", {}), { stopReason: "toolUse" }),
				(context) => {
					addedToolNames.push(
						context.messages
							.filter((message) => message.role === "toolResult")
							.flatMap((message) => message.addedToolNames ?? []),
					);
					return fauxAssistantMessage("done");
				},
			]);

			await harness.session.prompt("start");

			expect(harness.session.getActiveToolNames()).toEqual(["load_more_tools", "after_load"]);
			expect(addedToolNames).toEqual([["after_load"]]);
		} finally {
			harness.cleanup();
		}
	});

	it("does not mark active tool replacements as additive", async () => {
		const extensionFactories: ExtensionFactory[] = [
			(pi) => {
				pi.registerTool({
					name: "switch_tools",
					label: "Switch Tools",
					description: "Replace the active tool set",
					parameters: Type.Object({}),
					execute: async () => {
						pi.setActiveTools(["after_switch"]);
						return {
							content: [{ type: "text", text: "switched" }],
							details: {},
						};
					},
				});

				pi.registerTool({
					name: "after_switch",
					label: "After Switch",
					description: "Replacement tool",
					parameters: Type.Object({}),
					execute: async () => ({ content: [{ type: "text", text: "after" }], details: {} }),
				});
			},
		];
		const harness = await createHarness({ extensionFactories });

		try {
			harness.session.setActiveToolsByName(["switch_tools"]);
			const markerSnapshots: string[][] = [];
			harness.setResponses([
				() => fauxAssistantMessage(fauxToolCall("switch_tools", {}), { stopReason: "toolUse" }),
				(context) => {
					markerSnapshots.push(
						context.messages
							.filter((message) => message.role === "toolResult")
							.flatMap((message) => message.addedToolNames ?? []),
					);
					return fauxAssistantMessage("done");
				},
			]);

			await harness.session.prompt("start");

			expect(harness.session.getActiveToolNames()).toEqual(["after_switch"]);
			expect(markerSnapshots).toEqual([[]]);
		} finally {
			harness.cleanup();
		}
	});
});

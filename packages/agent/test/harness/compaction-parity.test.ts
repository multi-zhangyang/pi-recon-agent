import type { AssistantMessage, Message } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import {
	type CompactionSettings,
	DEFAULT_COMPACTION_SETTINGS,
	serializeConversation,
	shouldCompact,
	summaryInputTokenBudget,
} from "../../src/harness/compaction/compaction.ts";

function assistantWithToolArguments(argumentsValue: unknown): Message {
	return {
		role: "assistant",
		content: [
			{ type: "text", text: "calling tool" },
			{
				type: "toolCall",
				id: "call-1",
				name: "read",
				arguments: argumentsValue as Record<string, unknown>,
			},
		],
		api: "anthropic-messages",
		provider: "anthropic",
		model: "test",
		usage: {
			input: 1,
			output: 1,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 2,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
		timestamp: 0,
	} satisfies AssistantMessage;
}

describe("public harness compaction threshold parity", () => {
	it("uses the product-wide defaults and proactive threshold on small windows", () => {
		expect(DEFAULT_COMPACTION_SETTINGS.reserveTokens).toBe(16_384);
		expect(DEFAULT_COMPACTION_SETTINGS.keepRecentTokens).toBe(36_000);
		expect(DEFAULT_COMPACTION_SETTINGS.triggerPercent).toBe(85);
		expect(DEFAULT_COMPACTION_SETTINGS.warningPercent).toBe(80);
		expect(shouldCompact(1, 8192, DEFAULT_COMPACTION_SETTINGS)).toBe(false);
		expect(shouldCompact(6963, 8192, DEFAULT_COMPACTION_SETTINGS)).toBe(false);
		expect(shouldCompact(6964, 8192, DEFAULT_COMPACTION_SETTINGS)).toBe(true);
	});

	it("uses the same small-window floor as the coding runtime for a nearly full reserve", () => {
		const settings: CompactionSettings = {
			...DEFAULT_COMPACTION_SETTINGS,
			reserveTokens: 2047,
		};

		expect(shouldCompact(1024, 2048, settings)).toBe(false);
		expect(shouldCompact(1025, 2048, settings)).toBe(true);
	});

	it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
		"uses the finite 90%% fallback for reserveTokens=%s",
		(reserveTokens) => {
			const settings = { ...DEFAULT_COMPACTION_SETTINGS, reserveTokens, triggerPercent: undefined };
			expect(shouldCompact(7372, 8192, settings)).toBe(false);
			expect(shouldCompact(7373, 8192, settings)).toBe(true);
		},
	);

	it("rejects invalid or empty usage and context-window measurements", () => {
		expect(shouldCompact(0, 8192, DEFAULT_COMPACTION_SETTINGS)).toBe(false);
		expect(shouldCompact(Number.NaN, 8192, DEFAULT_COMPACTION_SETTINGS)).toBe(false);
		expect(shouldCompact(Number.POSITIVE_INFINITY, 8192, DEFAULT_COMPACTION_SETTINGS)).toBe(false);
		expect(shouldCompact(1, 0, DEFAULT_COMPACTION_SETTINGS)).toBe(false);
		expect(shouldCompact(1, Number.NaN, DEFAULT_COMPACTION_SETTINGS)).toBe(false);
	});

	it("keeps branch summary input budgets positive when reserve exceeds the model window", () => {
		expect(summaryInputTokenBudget(8192, 16_384)).toBe(6144);
		expect(summaryInputTokenBudget(8192, Number.NaN)).toBe(6144);
		expect(summaryInputTokenBudget(8192, 2048)).toBe(6144);
	});
});

describe("public harness compaction serialization parity", () => {
	it.each([
		["null", null],
		["undefined", undefined],
	])("serializes a tool call with %s arguments without throwing", (_label, argumentsValue) => {
		const message = assistantWithToolArguments(argumentsValue);

		expect(() => serializeConversation([message])).not.toThrow();
		expect(serializeConversation([message])).toBe("[Assistant]: calling tool\n\n[Assistant tool calls]: read()");
	});

	it("retains placeholders for image-only user and tool-result messages", () => {
		const messages: Message[] = [
			{
				role: "user",
				content: [{ type: "image", data: "user-image-data", mimeType: "image/png" }],
				timestamp: 0,
			},
			{
				role: "toolResult",
				toolCallId: "call-1",
				toolName: "screenshot",
				content: [{ type: "image", data: "tool-image-data", mimeType: "image/png" }],
				isError: false,
				timestamp: 0,
			},
		];

		expect(serializeConversation(messages)).toBe(
			"[User]: [image content omitted]\n\n[Tool result]: [image content omitted]",
		);
	});

	it("preserves text/image ordering without serializing image bytes", () => {
		const messages: Message[] = [
			{
				role: "user",
				content: [
					{ type: "text", text: "before " },
					{ type: "image", data: "base64-secret", mimeType: "image/jpeg" },
					{ type: "text", text: " after" },
				],
				timestamp: 0,
			},
		];

		const serialized = serializeConversation(messages);
		expect(serialized).toBe("[User]: before [image content omitted] after");
		expect(serialized).not.toContain("base64-secret");
	});
});

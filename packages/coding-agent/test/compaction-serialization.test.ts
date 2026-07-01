import type { Message } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { serializeConversation } from "../src/core/compaction/utils.ts";

describe("serializeConversation", () => {
	it("should truncate long tool results keeping head and tail", () => {
		const longContent = "x".repeat(5000);
		const messages: Message[] = [
			{
				role: "toolResult",
				toolCallId: "tc1",
				toolName: "read",
				content: [{ type: "text", text: longContent }],
				isError: false,
				timestamp: Date.now(),
			},
		];

		const result = serializeConversation(messages);

		expect(result).toContain("[Tool result]:");
		// Middle-ellipsis marker reports the elided character count.
		expect(result).toContain("characters truncated");
		// No run long enough to reconstruct the bulk of the original.
		expect(result).not.toContain("x".repeat(3000));
		// Head and tail are both preserved (head = tail = ~900 chars).
		expect(result).toContain("x".repeat(900));
		// The full untruncated content is NOT present.
		expect(result).not.toContain(longContent);
	});

	it("should not truncate short tool results", () => {
		const shortContent = "x".repeat(1500);
		const messages: Message[] = [
			{
				role: "toolResult",
				toolCallId: "tc1",
				toolName: "read",
				content: [{ type: "text", text: shortContent }],
				isError: false,
				timestamp: Date.now(),
			},
		];

		const result = serializeConversation(messages);

		expect(result).toBe(`[Tool result]: ${shortContent}`);
		expect(result).not.toContain("truncated");
	});

	it("should not truncate assistant or user messages", () => {
		const longText = "y".repeat(5000);
		const messages: Message[] = [
			{
				role: "user",
				content: [{ type: "text", text: longText }],
				timestamp: Date.now(),
			},
			{
				role: "assistant",
				content: [{ type: "text", text: longText }],
				api: "anthropic",
				provider: "anthropic",
				model: "test",
				usage: {
					input: 0,
					output: 0,
					cacheRead: 0,
					cacheWrite: 0,
					totalTokens: 0,
					cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
				},
				stopReason: "stop",
				timestamp: Date.now(),
			},
		];

		const result = serializeConversation(messages);

		expect(result).not.toContain("truncated");
		expect(result).toContain(longText);
	});
});

describe("opt #219: serializeConversation surfaces image blocks as a placeholder", () => {
	it("emits [image content omitted] for an image in a user message (text preserved)", () => {
		const messages: Message[] = [
			{
				role: "user",
				content: [
					{ type: "text", text: "what's in this screenshot?" },
					{ type: "image", data: "b64...", mimeType: "image/png" },
				],
				timestamp: Date.now(),
			},
		];
		const result = serializeConversation(messages);
		expect(result).toContain("[User]: what's in this screenshot?");
		expect(result).toContain("[image content omitted]");
	});

	it("emits [image content omitted] for an image in a tool result", () => {
		const messages: Message[] = [
			{
				role: "toolResult",
				toolCallId: "tc1",
				toolName: "read",
				content: [
					{ type: "text", text: "screenshot captured" },
					{ type: "image", data: "b64...", mimeType: "image/png" },
				],
				isError: false,
				timestamp: Date.now(),
			},
		];
		const result = serializeConversation(messages);
		expect(result).toContain("[Tool result]: screenshot captured");
		expect(result).toContain("[image content omitted]");
	});

	it("emits the placeholder for an image-only user turn (previously dropped entirely)", () => {
		// Pre-fix, an image-only user turn serialized to empty content and was
		// skipped — the summary lost the turn completely. Now it records the image.
		const messages: Message[] = [
			{
				role: "user",
				content: [{ type: "image", data: "b64...", mimeType: "image/jpeg" }],
				timestamp: Date.now(),
			},
		];
		const result = serializeConversation(messages);
		expect(result).toContain("[User]: [image content omitted]");
		expect(result.trim().length).toBeGreaterThan(0);
	});
});

/**
 * opt #241 — serializeConversation does not throw on a toolCall block whose
 * `arguments` is null/undefined.
 *
 * The assistant branch did `const args = block.arguments as Record<string,
 * unknown>; Object.entries(args)` with NO runtime guard. `arguments` can be
 * absent (corrupt/migrated session log, a misbehaving custom extension, a
 * future message-type change) — `Object.entries(null)` throws TypeError, and
 * this runs BEFORE the LLM call (outside completeSummarization's try/catch), so
 * the throw propagated out of generateSummary / compact() and aborted
 * compaction. The sibling extractFileOpsFromMessage guards this same way.
 *
 * Fix: guard `if (!args) { toolCalls.push(\`${block.name}()\`); continue; }`.
 * Post-fix serializeConversation returns "read()" and does not throw. Pre-fix
 * (guard removed) Object.entries(null) throws TypeError.
 */
import type { AssistantMessage, Message } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { serializeConversation } from "../src/core/compaction/utils.ts";

function assistantWithToolCall(args: unknown): Message {
	return {
		role: "assistant",
		content: [
			{ type: "text", text: "calling tool" },
			{
				type: "toolCall",
				toolCallId: "tc1",
				name: "read",
				arguments: args as Record<string, unknown>,
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
		timestamp: Date.now(),
	} as AssistantMessage as Message;
}

describe("opt #241: serializeConversation tolerates a toolCall with null/undefined arguments", () => {
	it("does not throw on null arguments (emits read())", () => {
		const messages: Message[] = [assistantWithToolCall(null)];
		expect(() => serializeConversation(messages)).not.toThrow();
		const result = serializeConversation(messages);
		expect(result).toContain("read()");
		expect(result).toContain("calling tool");
	});

	it("does not throw on undefined arguments (emits read())", () => {
		const messages: Message[] = [assistantWithToolCall(undefined)];
		expect(() => serializeConversation(messages)).not.toThrow();
		expect(serializeConversation(messages)).toContain("read()");
	});
});

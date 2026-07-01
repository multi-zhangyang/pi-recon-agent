/**
 * opt #218 — keepRecentTokens clamped to a fraction of contextWindow so
 * compaction actually trims on small-context models.
 *
 * Pre-fix, `settings.keepRecentTokens` (default 36000) was passed verbatim to
 * findCutPoint regardless of the model's contextWindow. On a small-context
 * model (e.g. 16K window), 36000 > contextWindow meant the backwards walk
 * accumulated the WHOLE conversation without ever reaching the budget → cutIndex
 * stayed at cutPoints[0] (keep from the first message) → messagesToSummarize
 * was empty → compaction was a NO-OP, so overflow recovery never brought the
 * context under the window and the next request overflowed again.
 *
 * Fix: findCutPoint/prepareCompaction accept an optional contextWindow and
 * clamp keepRecentTokens to ~50% of it (clampKeepRecentTokens), so the cut
 * trims on small windows while leaving large-window behavior untouched.
 */
import type { AgentMessage } from "@pi-recon/repi-agent-core";
import type { AssistantMessage, Usage } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { DEFAULT_COMPACTION_SETTINGS, findCutPoint, prepareCompaction } from "../src/core/compaction/index.ts";
import type { SessionEntry, SessionMessageEntry } from "../src/core/session-manager.ts";

function createMockUsage(input: number, output: number, cacheRead = 0, cacheWrite = 0): Usage {
	return {
		input,
		output,
		cacheRead,
		cacheWrite,
		totalTokens: input + output + cacheRead + cacheWrite,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
	};
}

function createUserMessage(text: string): AgentMessage {
	return { role: "user", content: text, timestamp: 0 };
}

function createAssistantMessage(text: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
		usage: createMockUsage(100, 50),
		stopReason: "stop",
		timestamp: 0,
		api: "anthropic-messages",
		provider: "anthropic",
		model: "claude-sonnet-4-5",
	};
}

let entryCounter = 0;
let lastId: string | null = null;

function createMessageEntry(message: AgentMessage): SessionMessageEntry {
	const id = `opt218-id-${entryCounter++}`;
	const entry: SessionMessageEntry = {
		type: "message",
		id,
		parentId: lastId,
		timestamp: new Date(0).toISOString(),
		message,
	};
	lastId = id;
	return entry;
}

function buildEntries(pairs: number): SessionEntry[] {
	entryCounter = 0;
	lastId = null;
	const entries: SessionEntry[] = [];
	for (let i = 0; i < pairs; i++) {
		entries.push(createMessageEntry(createUserMessage(`User message number ${i}`)));
		entries.push(createMessageEntry(createAssistantMessage(`Assistant response number ${i}`)));
	}
	return entries;
}

describe("opt #218: keepRecentTokens clamped to contextWindow on small-context models", () => {
	it("clamps the keep-recent budget so findCutPoint trims older messages on a small window", () => {
		// 20 user/assistant pairs. estimateTokens uses text length (/4): each
		// user ~6 tokens, each assistant ~7 tokens → ~13 tokens/pair → ~260 total.
		const entries = buildEntries(20);
		const totalishTokens = entries
			.filter((e) => e.type === "message")
			.reduce((acc, e) => acc + estimateTextTokens((e as SessionMessageEntry).message), 0);
		expect(totalishTokens).toBeGreaterThan(60);

		// Pre-fix behavior (no contextWindow): keepRecentTokens=36000 > total →
		// the walk never reaches budget → keeps everything from the first message.
		const noClamp = findCutPoint(entries, 0, entries.length, 36000);
		expect(noClamp.firstKeptEntryIndex).toBe(0);

		// With a small contextWindow (120), clamp → effectiveKeepRecent=60 → the
		// walk reaches budget partway → trims older messages (cut index > 0).
		const clamped = findCutPoint(entries, 0, entries.length, 36000, 120);
		expect(clamped.firstKeptEntryIndex).toBeGreaterThan(0);
		// And it keeps LESS than the whole conversation.
		expect(clamped.firstKeptEntryIndex).toBeLessThan(entries.length);
	});

	it("does NOT clamp on large-context models (default 36000 unchanged)", () => {
		const entries = buildEntries(20);
		// 200K window → clamp = min(36000, 100000) = 36000 → same as no clamp.
		const large = findCutPoint(entries, 0, entries.length, 36000, 200_000);
		const noClamp = findCutPoint(entries, 0, entries.length, 36000);
		expect(large.firstKeptEntryIndex).toBe(noClamp.firstKeptEntryIndex);
	});

	it("prepareCompaction threads contextWindow and produces messagesToSummarize on a small window", () => {
		const entries = buildEntries(20);
		const settings = { ...DEFAULT_COMPACTION_SETTINGS, keepRecentTokens: 36000 };

		// No contextWindow: no-op compaction (nothing to summarize).
		const noClamp = prepareCompaction(entries, settings);
		expect(noClamp).toBeDefined();
		expect(noClamp!.messagesToSummarize).toHaveLength(0);

		// Small contextWindow: clamp triggers a real cut → older messages summarized.
		const clamped = prepareCompaction(entries, settings, 120);
		expect(clamped).toBeDefined();
		expect(clamped!.messagesToSummarize.length).toBeGreaterThan(0);
	});
});

// Local estimate (chars/4) mirroring compaction.estimateTokens for user/assistant text.
function estimateTextTokens(message: AgentMessage): number {
	if (message.role === "user") {
		const content = message.content;
		const text = typeof content === "string" ? content : "";
		return Math.ceil(text.length / 4);
	}
	if (message.role === "assistant") {
		const chars = (message as AssistantMessage).content
			.filter((b) => b.type === "text")
			.reduce((acc, b) => acc + (b as { text: string }).text.length, 0);
		return Math.ceil(chars / 4);
	}
	return 0;
}

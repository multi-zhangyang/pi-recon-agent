/**
 * opt #226 — isAssistantFromBeforeCompaction uses strict `<` (not `<=`) so a
 * same-millisecond assistant is NOT classified as stale.
 *
 * Pre-fix both compaction-guard sites used `assistantMessage.timestamp <=
 * compactionEntry.timestamp`. A post-compaction assistant sharing the
 * boundary ms (clock-granularity race — the compaction is often created in
 * the same ms as the assistant that triggered it) was wrongly classified as
 * pre-compaction → its overflow check was silently skipped.
 */

import type { AssistantMessage } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { isAssistantFromBeforeCompaction } from "../src/core/agent-session.ts";
import type { CompactionEntry } from "../src/core/session-manager.ts";

const COMPACT_TS = "2025-01-01T00:00:01.000Z";
const COMPACT_MS = new Date(COMPACT_TS).getTime();

function compactionAt(timestamp: string): CompactionEntry {
	return {
		type: "compaction",
		id: "c1",
		parentId: null,
		timestamp,
		summary: "s",
		firstKeptEntryId: "x",
		tokensBefore: 1000,
	};
}

function assistantAt(timestamp: number): AssistantMessage {
	return {
		role: "assistant",
		content: [],
		api: "anthropic-messages",
		provider: "anthropic",
		model: "m",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
		timestamp,
	};
}

describe("opt #226: isAssistantFromBeforeCompaction strict <", () => {
	it("an assistant strictly older than the compaction is pre-compaction; same/younger is not", () => {
		const comp = compactionAt(COMPACT_TS);
		expect(isAssistantFromBeforeCompaction(assistantAt(COMPACT_MS - 1), comp)).toBe(true);
		// Same millisecond: NOT pre-compaction (pre-fix `<=` returned true here — the bug).
		expect(isAssistantFromBeforeCompaction(assistantAt(COMPACT_MS), comp)).toBe(false);
		expect(isAssistantFromBeforeCompaction(assistantAt(COMPACT_MS + 1), comp)).toBe(false);
	});

	it("returns false when there is no compaction entry", () => {
		expect(isAssistantFromBeforeCompaction(assistantAt(COMPACT_MS), null)).toBe(false);
	});
});

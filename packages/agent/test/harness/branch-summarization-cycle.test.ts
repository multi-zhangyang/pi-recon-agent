import { describe, expect, it } from "vitest";
import {
	collectEntriesForBranchSummary,
	prepareBranchEntries,
} from "../../src/harness/compaction/branch-summarization.ts";
import type { Session } from "../../src/harness/session/session.ts";
import type { MessageEntry, SessionTreeEntry } from "../../src/harness/types.ts";
import { SessionError } from "../../src/harness/types.ts";
import { createAssistantMessage, createUserMessage } from "./session-test-utils.ts";

// opt #104 Fix 1 — collectEntriesForBranchSummary cycle guard.
//
// The `while (current && current !== commonAncestorId)` loop walks parentId
// upward via session.getEntry with NO cycle guard. Both getPathToRoot
// implementations were fixed with a visited Set (opt #92 F3), but this walker
// follows parentId independently — a storage whose getPathToRoot lacks the
// guard (or data mutated between the getBranch call and the loop) with
// A.parentId=B, B.parentId=A would spin forever (event-loop-blocking CPU spin
// → OOM). The fix converts a cycle into a typed invalid_session error,
// mirroring the getPathToRoot idiom.
//
// To isolate the walker under test, the mock Session's getBranch returns only
// the leaf entry (a bounded path that does NOT itself spin) so the cycle
// reaches collectEntriesForBranchSummary's own while loop rather than being
// caught first by a cycle-guarded getPathToRoot.

function entry(id: string, parentId: string | null, text: string): MessageEntry {
	return {
		type: "message",
		id,
		parentId,
		timestamp: "2026-01-01T00:00:00.000Z",
		message: text === "a" ? createAssistantMessage(text) : createUserMessage(text),
	};
}

describe("collectEntriesForBranchSummary cycle guard (opt #104 Fix 1)", () => {
	it("throws invalid_session on a parentId cycle instead of hanging", async () => {
		const a = entry("A", "B", "a");
		const b = entry("B", "A", "b");
		const c = entry("C", null, "c"); // separate root
		const byId = new Map<string, SessionTreeEntry>([
			["A", a],
			["B", b],
			["C", c],
		]);

		// getBranch intentionally returns only the leaf entry (no cycle guard, no
		// upward walk) so the cycle reaches the while loop under test. getEntry
		// returns the cycled entries so the loop walks A -> B -> A -> ... .
		const mockSession = {
			async getBranch(fromId?: string): Promise<SessionTreeEntry[]> {
				if (fromId && byId.has(fromId)) return [byId.get(fromId)!];
				return [];
			},
			async getEntry(id: string): Promise<SessionTreeEntry | undefined> {
				return byId.get(id);
			},
		} as unknown as Session;

		const result = await Promise.race([
			collectEntriesForBranchSummary(mockSession, "A", "C").then(
				() => "resolved" as const,
				(error: unknown) => error,
			),
			new Promise<"hung">((resolve) => setTimeout(() => resolve("hung"), 5000)),
		]);

		// A hang would hit the 5000ms timeout and resolve "hung".
		expect(result).not.toBe("hung");
		expect(result).toBeInstanceOf(SessionError);
		if (result instanceof SessionError) {
			expect(result.code).toBe("invalid_session");
			expect(result.message).toMatch(/Cycle detected at entry/);
		}
	});

	it("bounds oversized persisted summaries to the requested token budget", () => {
		const summary = `## Goal\nHEAD\n${"x".repeat(2_000)}\n## Next Steps\nTAIL`;
		const result = prepareBranchEntries(
			[
				{
					type: "compaction",
					id: "summary",
					parentId: null,
					timestamp: "2026-01-01T00:00:00.000Z",
					summary,
					firstKeptEntryId: "kept",
					tokensBefore: 10_000,
				},
			] as SessionTreeEntry[],
			100,
		);

		expect(result.totalTokens).toBeLessThanOrEqual(100);
		const message = result.messages[0];
		expect(message?.role).toBe("compactionSummary");
		if (message?.role === "compactionSummary") {
			expect(message.summary).toContain("summary truncated");
			expect(message.summary).toContain("HEAD");
			expect(message.summary).toContain("TAIL");
		}
	});
});

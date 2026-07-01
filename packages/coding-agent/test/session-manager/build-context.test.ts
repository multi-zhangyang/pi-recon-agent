import { describe, expect, it, vi } from "vitest";
import {
	type BranchSummaryEntry,
	buildSessionContext,
	type CompactionEntry,
	type ModelChangeEntry,
	type SessionEntry,
	type SessionMessageEntry,
	type ThinkingLevelChangeEntry,
} from "../../src/core/session-manager.ts";

/** Compaction entry whose firstKeptEntryId may be undefined (v1-header migration case). */
function compactionAny(
	id: string,
	parentId: string | null,
	summary: string,
	firstKeptEntryId: string | undefined,
): CompactionEntry {
	return {
		type: "compaction",
		id,
		parentId,
		timestamp: "2025-01-01T00:00:00Z",
		summary,
		firstKeptEntryId: firstKeptEntryId as string,
		tokensBefore: 1000,
	};
}

function msg(id: string, parentId: string | null, role: "user" | "assistant", text: string): SessionMessageEntry {
	const base = { type: "message" as const, id, parentId, timestamp: "2025-01-01T00:00:00Z" };
	if (role === "user") {
		return { ...base, message: { role, content: text, timestamp: 1 } };
	}
	return {
		...base,
		message: {
			role,
			content: [{ type: "text", text }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "claude-test",
			usage: {
				input: 1,
				output: 1,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 2,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: 1,
		},
	};
}

function compaction(id: string, parentId: string | null, summary: string, firstKeptEntryId: string): CompactionEntry {
	return {
		type: "compaction",
		id,
		parentId,
		timestamp: "2025-01-01T00:00:00Z",
		summary,
		firstKeptEntryId,
		tokensBefore: 1000,
	};
}

function branchSummary(id: string, parentId: string | null, summary: string, fromId: string): BranchSummaryEntry {
	return { type: "branch_summary", id, parentId, timestamp: "2025-01-01T00:00:00Z", summary, fromId };
}

function thinkingLevel(id: string, parentId: string | null, level: string): ThinkingLevelChangeEntry {
	return { type: "thinking_level_change", id, parentId, timestamp: "2025-01-01T00:00:00Z", thinkingLevel: level };
}

function modelChange(id: string, parentId: string | null, provider: string, modelId: string): ModelChangeEntry {
	return { type: "model_change", id, parentId, timestamp: "2025-01-01T00:00:00Z", provider, modelId };
}

describe("buildSessionContext", () => {
	describe("trivial cases", () => {
		it("empty entries returns empty context", () => {
			const ctx = buildSessionContext([]);
			expect(ctx.messages).toEqual([]);
			expect(ctx.thinkingLevel).toBe("off");
			expect(ctx.model).toBeNull();
		});

		it("single user message", () => {
			const entries: SessionEntry[] = [msg("1", null, "user", "hello")];
			const ctx = buildSessionContext(entries);
			expect(ctx.messages).toHaveLength(1);
			expect(ctx.messages[0].role).toBe("user");
		});

		it("simple conversation", () => {
			const entries: SessionEntry[] = [
				msg("1", null, "user", "hello"),
				msg("2", "1", "assistant", "hi there"),
				msg("3", "2", "user", "how are you"),
				msg("4", "3", "assistant", "great"),
			];
			const ctx = buildSessionContext(entries);
			expect(ctx.messages).toHaveLength(4);
			expect(ctx.messages.map((m) => m.role)).toEqual(["user", "assistant", "user", "assistant"]);
		});

		it("tracks thinking level changes", () => {
			const entries: SessionEntry[] = [
				msg("1", null, "user", "hello"),
				thinkingLevel("2", "1", "high"),
				msg("3", "2", "assistant", "thinking hard"),
			];
			const ctx = buildSessionContext(entries);
			expect(ctx.thinkingLevel).toBe("high");
			expect(ctx.messages).toHaveLength(2);
		});

		it("tracks model from assistant message", () => {
			const entries: SessionEntry[] = [msg("1", null, "user", "hello"), msg("2", "1", "assistant", "hi")];
			const ctx = buildSessionContext(entries);
			expect(ctx.model).toEqual({ provider: "anthropic", modelId: "claude-test" });
		});

		it("tracks model from model change entry", () => {
			const entries: SessionEntry[] = [
				msg("1", null, "user", "hello"),
				modelChange("2", "1", "openai", "gpt-4"),
				msg("3", "2", "assistant", "hi"),
			];
			const ctx = buildSessionContext(entries);
			// Assistant message overwrites model change
			expect(ctx.model).toEqual({ provider: "anthropic", modelId: "claude-test" });
		});
	});

	describe("with compaction", () => {
		it("includes summary before kept messages", () => {
			const entries: SessionEntry[] = [
				msg("1", null, "user", "first"),
				msg("2", "1", "assistant", "response1"),
				msg("3", "2", "user", "second"),
				msg("4", "3", "assistant", "response2"),
				compaction("5", "4", "Summary of first two turns", "3"),
				msg("6", "5", "user", "third"),
				msg("7", "6", "assistant", "response3"),
			];
			const ctx = buildSessionContext(entries);

			// Should have: summary + kept (3,4) + after (6,7) = 5 messages
			expect(ctx.messages).toHaveLength(5);
			expect((ctx.messages[0] as any).summary).toContain("Summary of first two turns");
			expect((ctx.messages[1] as any).content).toBe("second");
			expect((ctx.messages[2] as any).content[0].text).toBe("response2");
			expect((ctx.messages[3] as any).content).toBe("third");
			expect((ctx.messages[4] as any).content[0].text).toBe("response3");
		});

		it("handles compaction keeping from first message", () => {
			const entries: SessionEntry[] = [
				msg("1", null, "user", "first"),
				msg("2", "1", "assistant", "response"),
				compaction("3", "2", "Empty summary", "1"),
				msg("4", "3", "user", "second"),
			];
			const ctx = buildSessionContext(entries);

			// Summary + all messages (1,2,4)
			expect(ctx.messages).toHaveLength(4);
			expect((ctx.messages[0] as any).summary).toContain("Empty summary");
		});

		it("multiple compactions uses latest", () => {
			const entries: SessionEntry[] = [
				msg("1", null, "user", "a"),
				msg("2", "1", "assistant", "b"),
				compaction("3", "2", "First summary", "1"),
				msg("4", "3", "user", "c"),
				msg("5", "4", "assistant", "d"),
				compaction("6", "5", "Second summary", "4"),
				msg("7", "6", "user", "e"),
			];
			const ctx = buildSessionContext(entries);

			// Should use second summary, keep from 4
			expect(ctx.messages).toHaveLength(4);
			expect((ctx.messages[0] as any).summary).toContain("Second summary");
		});
	});

	describe("with branches", () => {
		it("follows path to specified leaf", () => {
			// Tree:
			//   1 -> 2 -> 3 (branch A)
			//         \-> 4 (branch B)
			const entries: SessionEntry[] = [
				msg("1", null, "user", "start"),
				msg("2", "1", "assistant", "response"),
				msg("3", "2", "user", "branch A"),
				msg("4", "2", "user", "branch B"),
			];

			const ctxA = buildSessionContext(entries, "3");
			expect(ctxA.messages).toHaveLength(3);
			expect((ctxA.messages[2] as any).content).toBe("branch A");

			const ctxB = buildSessionContext(entries, "4");
			expect(ctxB.messages).toHaveLength(3);
			expect((ctxB.messages[2] as any).content).toBe("branch B");
		});

		it("includes branch summary in path", () => {
			const entries: SessionEntry[] = [
				msg("1", null, "user", "start"),
				msg("2", "1", "assistant", "response"),
				msg("3", "2", "user", "abandoned path"),
				branchSummary("4", "2", "Summary of abandoned work", "3"),
				msg("5", "4", "user", "new direction"),
			];
			const ctx = buildSessionContext(entries, "5");

			expect(ctx.messages).toHaveLength(4);
			expect((ctx.messages[2] as any).summary).toContain("Summary of abandoned work");
			expect((ctx.messages[3] as any).content).toBe("new direction");
		});

		it("complex tree with multiple branches and compaction", () => {
			// Tree:
			//   1 -> 2 -> 3 -> 4 -> compaction(5) -> 6 -> 7 (main path)
			//              \-> 8 -> 9 (abandoned branch)
			//                    \-> branchSummary(10) -> 11 (resumed from 3)
			const entries: SessionEntry[] = [
				msg("1", null, "user", "start"),
				msg("2", "1", "assistant", "r1"),
				msg("3", "2", "user", "q2"),
				msg("4", "3", "assistant", "r2"),
				compaction("5", "4", "Compacted history", "3"),
				msg("6", "5", "user", "q3"),
				msg("7", "6", "assistant", "r3"),
				// Abandoned branch from 3
				msg("8", "3", "user", "wrong path"),
				msg("9", "8", "assistant", "wrong response"),
				// Branch summary resuming from 3
				branchSummary("10", "3", "Tried wrong approach", "9"),
				msg("11", "10", "user", "better approach"),
			];

			// Main path to 7: summary + kept(3,4) + after(6,7)
			const ctxMain = buildSessionContext(entries, "7");
			expect(ctxMain.messages).toHaveLength(5);
			expect((ctxMain.messages[0] as any).summary).toContain("Compacted history");
			expect((ctxMain.messages[1] as any).content).toBe("q2");
			expect((ctxMain.messages[2] as any).content[0].text).toBe("r2");
			expect((ctxMain.messages[3] as any).content).toBe("q3");
			expect((ctxMain.messages[4] as any).content[0].text).toBe("r3");

			// Branch path to 11: 1,2,3 + branch_summary + 11
			const ctxBranch = buildSessionContext(entries, "11");
			expect(ctxBranch.messages).toHaveLength(5);
			expect((ctxBranch.messages[0] as any).content).toBe("start");
			expect((ctxBranch.messages[1] as any).content[0].text).toBe("r1");
			expect((ctxBranch.messages[2] as any).content).toBe("q2");
			expect((ctxBranch.messages[3] as any).summary).toContain("Tried wrong approach");
			expect((ctxBranch.messages[4] as any).content).toBe("better approach");
		});
	});

	describe("edge cases", () => {
		it("uses last entry when leafId not found", () => {
			const entries: SessionEntry[] = [msg("1", null, "user", "hello"), msg("2", "1", "assistant", "hi")];
			const ctx = buildSessionContext(entries, "nonexistent");
			expect(ctx.messages).toHaveLength(2);
		});

		it("handles orphaned entries gracefully", () => {
			const entries: SessionEntry[] = [
				msg("1", null, "user", "hello"),
				msg("2", "missing", "assistant", "orphan"), // parent doesn't exist
			];
			const ctx = buildSessionContext(entries, "2");
			// Should only get the orphan since parent chain is broken
			expect(ctx.messages).toHaveLength(1);
		});
	});

	describe("opt #222: firstKeptEntryId missing/orphaned fallback (no silent context loss)", () => {
		it("emits all pre-compaction messages when firstKeptEntryId is undefined (v1-header migration)", () => {
			// A v1 compaction whose firstKeptEntryIndex pointed at the session header
			// gets firstKeptEntryId left undefined by migrateV1ToV2. Pre-fix, the
			// kept-window loop matched nothing → only the summary + post-compaction
			// messages were emitted, silently dropping the entire kept window.
			const entries: SessionEntry[] = [
				msg("1", null, "user", "first"),
				msg("2", "1", "assistant", "response1"),
				msg("3", "2", "user", "second"),
				compactionAny("4", "3", "Summary", undefined),
				msg("5", "4", "user", "after"),
			];
			const ctx = buildSessionContext(entries, "5");

			// summary + all 3 pre-compaction (1,2,3) + post-compaction (5) = 5
			expect(ctx.messages).toHaveLength(5);
			expect((ctx.messages[0] as any).summary).toContain("Summary");
			expect((ctx.messages[1] as any).content).toBe("first");
			expect((ctx.messages[2] as any).content[0].text).toBe("response1");
			expect((ctx.messages[3] as any).content).toBe("second");
			expect((ctx.messages[4] as any).content).toBe("after");
		});

		it("emits all pre-compaction messages + warns when firstKeptEntryId is present but not on path", () => {
			// firstKeptEntryId points at an entry on a different branch (orphaned by
			// branching compaction) or a corrupt/unknown id. Pre-fix: silent drop.
			const entries: SessionEntry[] = [
				msg("1", null, "user", "first"),
				msg("2", "1", "assistant", "response1"),
				compactionAny("3", "2", "Summary", "nonexistent-id"),
				msg("4", "3", "user", "after"),
			];
			const warnSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
			try {
				const ctx = buildSessionContext(entries, "4");

				// summary + all pre-compaction (1,2) + post-compaction (4) = 4
				expect(ctx.messages).toHaveLength(4);
				expect((ctx.messages[1] as any).content).toBe("first");
				expect((ctx.messages[2] as any).content[0].text).toBe("response1");
				expect((ctx.messages[3] as any).content).toBe("after");

				// A warning was surfaced naming the unresolvable id.
				const warned = warnSpy.mock.calls.some((c) => String(c[0]).includes('"nonexistent-id"'));
				expect(warned).toBe(true);
			} finally {
				warnSpy.mockRestore();
			}
		});

		it("regression guard: normal firstKeptEntryId still emits only the kept window (no over-inclusion)", () => {
			const entries: SessionEntry[] = [
				msg("1", null, "user", "first"),
				msg("2", "1", "assistant", "response1"),
				msg("3", "2", "user", "second"),
				compactionAny("4", "3", "Summary", "2"),
				msg("5", "4", "user", "after"),
			];
			const ctx = buildSessionContext(entries, "5");

			// summary + kept(2,3) + post(5) = 4; msg 1 is before the kept window → dropped
			expect(ctx.messages).toHaveLength(4);
			expect((ctx.messages[1] as any).content[0].text).toBe("response1");
			expect((ctx.messages[2] as any).content).toBe("second");
			expect((ctx.messages[3] as any).content).toBe("after");
			expect(ctx.messages.some((m) => (m as any).content === "first")).toBe(false);
		});
	});

	describe("opt #223: dangling parentId truncation is surfaced (not silent)", () => {
		it("warns when a mid-chain parentId resolves to no entry (ancestor messages dropped)", () => {
			// 2's parent is "1", but entry "1" is NOT in the loaded set — the walk
			// stops at 2 and the (here absent) ancestor chain is silently dropped.
			const entries: SessionEntry[] = [msg("2", "1", "user", "orphaned-leaf"), msg("3", "2", "assistant", "child")];
			const warnSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
			try {
				const ctx = buildSessionContext(entries, "3");

				// Truncation behavior preserved: only 2 and 3 are on the path.
				expect(ctx.messages).toHaveLength(2);
				expect((ctx.messages[0] as any).content).toBe("orphaned-leaf");
				expect((ctx.messages[1] as any).content[0].text).toBe("child");

				// But a warning naming the dangling parentId is surfaced.
				const warned = warnSpy.mock.calls.some(
					(c) => String(c[0]).includes('"1"') && String(c[0]).includes("truncated"),
				);
				expect(warned).toBe(true);
			} finally {
				warnSpy.mockRestore();
			}
		});

		it("does not warn for a well-formed chain rooted at parentId null", () => {
			const entries: SessionEntry[] = [msg("1", null, "user", "root"), msg("2", "1", "assistant", "ok")];
			const warnSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
			try {
				buildSessionContext(entries, "2");
				const warned = warnSpy.mock.calls.some((c) => String(c[0]).includes("truncated"));
				expect(warned).toBe(false);
			} finally {
				warnSpy.mockRestore();
			}
		});
	});
});

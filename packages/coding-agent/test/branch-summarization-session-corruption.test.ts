import { SessionError } from "@pi-recon/repi-agent-core";
import { describe, expect, it } from "vitest";
import { collectEntriesForBranchSummary, prepareBranchEntries } from "../src/core/compaction/branch-summarization.ts";
import type { ReadonlySessionManager, SessionEntry } from "../src/core/session-manager.ts";

function messageEntry(id: string, parentId: string | null): SessionEntry {
	return {
		type: "message",
		id,
		parentId,
		timestamp: "2026-01-01T00:00:00.000Z",
		message: {
			role: "user",
			content: id,
			timestamp: Date.now(),
		},
	} as SessionEntry;
}

function mockSession(entries: Map<string, SessionEntry>): ReadonlySessionManager {
	let getEntryCalls = 0;
	const session = {
		getBranch(id: string): SessionEntry[] {
			const entry = entries.get(id);
			return entry ? [entry] : [];
		},
		getEntry(id: string): SessionEntry | undefined {
			// A bounded guard keeps a regression that removes the cycle check from
			// blocking the whole test process indefinitely.
			getEntryCalls += 1;
			if (getEntryCalls > 8) throw new Error("parent walk exceeded test bound");
			return entries.get(id);
		},
	} as unknown as ReadonlySessionManager;
	return session;
}

function thrownBy(operation: () => unknown): unknown {
	try {
		operation();
		return undefined;
	} catch (error) {
		return error;
	}
}

describe("branch summary parent-chain corruption", () => {
	it("reports a cyclic parent chain as invalid_session", () => {
		const entries = new Map([
			["A", messageEntry("A", "B")],
			["B", messageEntry("B", "A")],
			["target", messageEntry("target", null)],
		]);
		const error = thrownBy(() => collectEntriesForBranchSummary(mockSession(entries), "A", "target"));

		expect(error).toBeInstanceOf(SessionError);
		expect(error).toMatchObject({ code: "invalid_session" });
		expect((error as Error).message).toContain("Cycle detected at entry A");
	});

	it("reports a missing parent entry as invalid_session", () => {
		const entries = new Map([
			["leaf", messageEntry("leaf", "missing-parent")],
			["target", messageEntry("target", null)],
		]);
		const error = thrownBy(() => collectEntriesForBranchSummary(mockSession(entries), "leaf", "target"));

		expect(error).toBeInstanceOf(SessionError);
		expect(error).toMatchObject({ code: "invalid_session" });
		expect((error as Error).message).toContain("Entry missing-parent not found");
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
			] as SessionEntry[],
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

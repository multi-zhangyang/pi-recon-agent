/**
 * opt #266 — branchWithSummary restores the PRE-CALL leaf on _persist failure,
 * not branchFromId.
 *
 * branchWithSummary sets this.leafId = branchFromId BEFORE _appendEntry.
 * _appendEntry's own rollback (opt #239) captures priorLeafId = this.leafId at
 * that point = branchFromId, and restores THAT on a _persist throw → the leaf
 * silently jumps to branchFromId (the navigation target) even though the
 * branch_summary entry was never persisted → the next appendMessage creates a
 * child of branchFromId, abandoning the original branch with no signal to the
 * user/model. Fix: capture preCallLeafId before the assignment and restore it
 * in a catch around _appendEntry.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type FsModule = typeof import("node:fs");
type AppendFileSyncArgs = Parameters<FsModule["appendFileSync"]>;

// Hoisted mock state: throw ENOSPC exactly once on the NEXT appendFileSync
// after the test re-arms it (used to fail the branch_summary's flushed-append).
const state = vi.hoisted(() => ({ appendThrow: false }));

vi.mock("fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	const realAppendFileSync = actual.appendFileSync;
	return {
		...actual,
		appendFileSync: vi.fn((...args: AppendFileSyncArgs) => {
			if (state.appendThrow) {
				state.appendThrow = false;
				const err = new Error("ENOSPC: no space left on device, write") as Error & { code: string };
				err.code = "ENOSPC";
				throw err;
			}
			return (realAppendFileSync as (...a: AppendFileSyncArgs) => void)(...args);
		}),
	};
});

const { SessionManager } = await import("../src/core/session-manager.ts");

interface Usage {
	input: number;
	output: number;
	cacheRead: number;
	cacheWrite: number;
	totalTokens: number;
	cost: { input: number; output: number; cacheRead: number; cacheWrite: number; total: number };
}

const usage: Usage = {
	input: 1,
	output: 1,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 2,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

describe("opt #266: branchWithSummary restores the pre-call leaf on _persist failure", () => {
	let tempDir: string;

	beforeEach(() => {
		state.appendThrow = false;
		tempDir = mkdtempSync(join(tmpdir(), "session-branch-summary-rollback-266-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("a failed branch_summary append restores leafId to the pre-call leaf, not branchFromId", () => {
		const session = SessionManager.create(tempDir, tempDir);

		// user + assistant → file flushed, leaf = assistantId (the pre-call leaf).
		session.appendMessage({ role: "user", content: "hello", timestamp: 1 });
		session.appendMessage({
			role: "assistant",
			content: [{ type: "text", text: "hi" }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "test",
			usage,
			stopReason: "stop",
			timestamp: 2,
		});
		const preCallLeafId = session.getLeafId();
		expect(preCallLeafId).not.toBeNull();

		// Navigation target = the root user message entry. branchWithSummary will
		// set leafId = rootId, then _appendEntry(branch_summary) → _persist → the
		// flushed appendFileSync path. Arm ENOSPC so that append throws.
		const entries = session.getEntries();
		const rootEntry = entries.find((e) => e.type === "message" && e.parentId === null);
		expect(rootEntry).toBeDefined();
		const rootId = rootEntry!.id;

		state.appendThrow = true;
		// Pre-fix: the branch_summary append throws, _appendEntry rolls back to
		// priorLeafId (= rootId, since leafId was set to rootId before the call),
		// AND branchWithSummary had no outer catch → leafId stays at rootId (the
		// navigation target), abandoning the assistant branch silently.
		// Post-fix: branchWithSummary's catch restores leafId = preCallLeafId.
		expect(() => session.branchWithSummary(rootId, "summary of abandoned path")).toThrow(/ENOSPC/);

		expect(session.getLeafId()).toBe(preCallLeafId);
		// The branch_summary entry must NOT be in memory (rolled back by _appendEntry).
		const branchSummaries = session.getEntries().filter((e) => e.type === "branch_summary");
		expect(branchSummaries).toHaveLength(0);
	});

	it("a successful branchSummary still advances the leaf to the new branch_summary id", () => {
		const session = SessionManager.create(tempDir, tempDir);
		session.appendMessage({ role: "user", content: "hello", timestamp: 1 });
		session.appendMessage({
			role: "assistant",
			content: [{ type: "text", text: "hi" }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "test",
			usage,
			stopReason: "stop",
			timestamp: 2,
		});

		const entries = session.getEntries();
		const rootEntry = entries.find((e) => e.type === "message" && e.parentId === null);
		const rootId = rootEntry!.id;

		// No throw armed → the append succeeds; leaf advances to the new
		// branch_summary entry id (parented at rootId). Confirms the fix doesn't
		// break the happy path.
		const summaryId = session.branchWithSummary(rootId, "summary of abandoned path");
		expect(session.getLeafId()).toBe(summaryId);
		const summaryEntry = session.getEntry(summaryId);
		expect(summaryEntry?.type).toBe("branch_summary");
		expect((summaryEntry as { parentId?: string }).parentId).toBe(rootId);
	});
});

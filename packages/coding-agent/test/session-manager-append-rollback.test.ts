/**
 * opt #239 — _appendEntry rolls back in-memory state when _persist's
 * appendFileSync (flushed-append) path throws, so a failed append can't leave a
 * dangling parentId that drops ancestor history on reload.
 *
 * _appendEntry mutated fileEntries/byId/leafId/_hasAssistant BEFORE calling
 * _persist. The flushed-append branches (`appendFileSync` at the two else
 * paths) had NO recovery — unlike the first-flush openSync("wx") path which
 * unlinks the partial file. A throw (ENOSPC/EIO/EROFS/EACCES) left the entry in
 * memory but NOT on disk. The NEXT successful append then wrote an entry whose
 * parentId pointed at this failed (in-memory-only) id; on reload,
 * buildSessionContext walked from the leaf, hit a parentId absent from the
 * on-disk record set, and truncated the path — silently dropping all ancestor
 * history from the LLM context (DATA-LOSS).
 *
 * Fix: capture pre-append state, wrap _persist in try/catch, roll back on
 * throw, rethrow. The test mocks appendFileSync to throw ENOSPC once on the
 * first flushed-append, then appends again and asserts the on-disk entry chain
 * is contiguous (no dangling parentId referencing the failed entry).
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type FsModule = typeof import("node:fs");
type AppendFileSyncArgs = Parameters<FsModule["appendFileSync"]>;

// Hoisted so the mock factory can reference it (vi.hoisted runs before the
// factory is evaluated). Throw ENOSPC exactly once on the first appendFileSync
// call, then delegate to the real implementation for the retry.
const state = vi.hoisted(() => ({ appendThrow: true }));

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

interface DiskEntry {
	type: string;
	id?: string;
	parentId?: string;
	message?: { role: string; content: unknown };
}

describe("opt #239: _appendEntry rolls back in-memory state on appendFileSync failure", () => {
	let tempDir: string;

	beforeEach(() => {
		state.appendThrow = true;
		tempDir = mkdtempSync(join(tmpdir(), "session-append-rollback-239-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("a failed flushed-append leaves no dangling parentId on disk (chain stays contiguous)", () => {
		const session = SessionManager.create(tempDir, tempDir);
		const sessionFile = session.getSessionFile()!;
		expect(existsSync(sessionFile)).toBe(false);

		// user + assistant → first-flush creates the file (writeFileSync loop,
		// NOT appendFileSync) and sets flushed=true.
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
		expect(existsSync(sessionFile)).toBe(true);

		// Next user append takes the flushed appendFileSync path → mocked ENOSPC.
		// Pre-fix: in-memory mutated (entry added, leafId advanced) but disk
		// unchanged. Post-fix: rolled back so memory matches disk.
		expect(() => session.appendMessage({ role: "user", content: "lost", timestamp: 3 })).toThrow(/ENOSPC/);

		// Next append succeeds (mock delegates now). Pre-fix this writes an entry
		// whose parentId = the failed "lost" entry's id (in-memory-only) → the
		// on-disk chain references an id that was never persisted. Post-fix the
		// parentId is the assistant's id (the real on-disk leaf).
		expect(() => session.appendMessage({ role: "user", content: "after", timestamp: 4 })).not.toThrow();

		const lines = readFileSync(sessionFile, "utf8").trim().split("\n");
		const entries: DiskEntry[] = lines.map((l) => JSON.parse(l));
		const ids = new Set(entries.map((e) => e.id).filter((id): id is string => typeof id === "string"));

		// Every parentId on disk (except the null/undefined root sentinel) must
		// reference an id that is ALSO on disk. Pre-fix the "after" entry's
		// parentId was the failed "lost" entry's id (in-memory-only) → not in ids.
		for (const e of entries) {
			if (e.parentId !== undefined && e.parentId !== null) {
				expect(ids.has(e.parentId)).toBe(true);
			}
		}

		// The failed "lost" entry must NOT be on disk; "after" must be.
		const messages = entries.filter((e) => e.type === "message");
		expect(messages.some((e) => e.message?.content === "lost")).toBe(false);
		expect(messages.some((e) => e.message?.content === "after")).toBe(true);
	}, 15000);
});

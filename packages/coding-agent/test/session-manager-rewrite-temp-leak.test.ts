/**
 * opt #235 — SessionManager._rewriteFile unlinks the partial temp file when
 * the per-entry writeFileSync loop throws mid-rewrite (ENOSPC/EIO/EROFS).
 *
 * Pre-fix, _rewriteFile wrapped only the write loop in `try { ... } finally {
 * closeSync(fd) }` with NO catch — mirroring the pre-opt-#41
 * atomicWriteFileSync pattern. If writeFileSync threw after openSync("wx")
 * created the temp, the finally closed the fd and the error propagated
 * straight out: the chmod + renameSync blocks (which own the temp cleanup)
 * were never reached, so the partial `.<basename>.<pid>.<ts>.<hex>.tmp` file
 * was left permanently in the session dir on EVERY failed rewrite. The
 * original target was untouched (rename never reached) so no data loss — only
 * the temp leaked, accumulating one .tmp per failed migration rewrite.
 *
 * Fix: wrap the whole open→write→chmod→rename sequence in one catch that
 * best-effort unlinks the temp before re-throwing (mirrors atomicWriteFileSync,
 * opt #41). The throw still propagates (the rewrite failed) but the temp is
 * cleaned up.
 *
 * The test pre-writes a v1 session file (version:1) so SessionManager.open →
 * setSessionFile → migrateToCurrentVersion returns true → _rewriteFile. The
 * mocked writeFileSync throws ENOSPC on the first fd-style call (the rewrite's
 * per-entry loop). Pre-fix: open throws ENOSPC AND a .tmp file leaks. Post-fix:
 * open still throws ENOSPC BUT no .tmp file remains.
 */
import { mkdtempSync, readdirSync, writeFileSync as realWriteFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type FsModule = typeof import("node:fs");
type WriteFileSyncArgs = Parameters<FsModule["writeFileSync"]>;

vi.mock("fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	const realWrite = actual.writeFileSync;
	return {
		...actual,
		// Throw ENOSPC on every fd-style writeFileSync (numeric first arg). The
		// _rewriteFile per-entry loop is the only fd-write on this code path
		// (loadEntriesFromFile reads; the v1 file is clean so no torn-heal write;
		// fileEntries non-empty so no corrupt-backup). Append path uses
		// appendFileSync, not writeFileSync.
		writeFileSync: vi.fn((...args: WriteFileSyncArgs) => {
			if (typeof args[0] === "number") {
				const err = new Error("ENOSPC: no space left on device, write") as Error & { code: string };
				err.code = "ENOSPC";
				throw err;
			}
			return (realWrite as (...a: WriteFileSyncArgs) => void)(...args);
		}),
	};
});

// Import AFTER vi.mock so SessionManager picks up the mocked writeFileSync.
const { SessionManager } = await import("../src/core/session-manager.ts");

describe("opt #235: _rewriteFile unlinks the partial temp on mid-rewrite throw", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "session-rewrite-temp-leak-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("a migration rewrite that throws ENOSPC leaves no .tmp file in the session dir", () => {
		// Pre-write a v1 session file (version:1, message without id) so opening
		// it triggers migrateToCurrentVersion → _rewriteFile.
		const v1File = join(tempDir, "v1-session.jsonl");
		realWriteFileSync(
			v1File,
			'{"type":"session","id":"s1","timestamp":"2025-01-01T00:00:00Z","cwd":' +
				JSON.stringify(tempDir) +
				',"version":1}\n' +
				'{"type":"message","timestamp":"2025-01-01T00:00:00Z","message":{"role":"user","content":"a","timestamp":1}}\n',
		);

		// open → constructor → setSessionFile → migrate → _rewriteFile → mock
		// throws ENOSPC on the first per-entry writeFileSync(fd, ...). The fix
		// unlinks the temp before re-throwing; pre-fix the temp leaked.
		expect(() => SessionManager.open(v1File, tempDir, tempDir)).toThrow(/ENOSPC/);

		// The partial temp file must have been cleaned up. Pre-fix exactly one
		// `.<basename>.<pid>.<ts>.<hex>.tmp` file remains; post-fix none.
		const tmpFiles = readdirSync(tempDir).filter((f) => f.endsWith(".tmp"));
		expect(tmpFiles).toEqual([]);

		// The original v1 file is untouched (rename never reached) — no data loss.
		const remaining = readdirSync(tempDir).filter((f) => f.endsWith(".jsonl"));
		expect(remaining).toEqual(["v1-session.jsonl"]);
	});
});

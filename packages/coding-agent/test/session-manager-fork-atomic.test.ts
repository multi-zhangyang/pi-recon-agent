/**
 * opt #205 — forkFrom non-atomic write left a partial fork file on a mid-write
 * failure.
 *
 * `SessionManager.forkFrom` wrote the new session header with
 * `writeFileSync(newSessionFile, header, { flag: "wx" })` then copied source
 * entries in a loop with `appendFileSync`. A crash (SIGKILL/OOM) or an
 * `appendFileSync` throw (ENOSPC mid-loop) left a fresh (wx-created) file on
 * disk with the header but only a SUBSET of source entries — a reader would
 * load a truncated session with no signal, silently losing conversation
 * history. Fix: build the full content (header + all non-header entries) in
 * memory and write via `atomicWriteFileSync` (temp+rename 0o644) so readers
 * see either no file or the complete fork.
 *
 * This test injects ENOSPC mid-fork and asserts NO fork file is left on disk
 * (atomic = all-or-nothing). The injection distinguishes the two paths:
 *  - post-fix: atomicWriteFileSync's internal `writeFileSync(fd, fullContent)`
 *    throws → the temp is unlinked and NO target file is created.
 *  - pre-fix (neuter): `writeFileSync(path, header, {flag:"wx"})` SUCCEEDS
 *    (string-path header write is NOT intercepted), then `appendFileSync` of
 *    the first entry throws → a partial header-only file IS left on disk →
 *    the "no jsonl file" assertion FAILS.
 */
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type FsModule = typeof import("node:fs");
type WriteFileSyncArgs = Parameters<FsModule["writeFileSync"]>;
type AppendFileSyncArgs = Parameters<FsModule["appendFileSync"]>;

// Hoisted flag: throw ENOSPC on the first fork-time entry write only. Off
// during source-session creation so the source persists normally.
const state = vi.hoisted(() => ({ forkThrow: false }));

vi.mock("fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	const realWriteFileSync = actual.writeFileSync;
	const realAppendFileSync = actual.appendFileSync;
	return {
		...actual,
		// Header write is `writeFileSync(path, header, {flag:"wx"})` (string
		// path + options) — delegate to real so the pre-fix path creates the
		// header file. The atomic internal is `writeFileSync(fd, content)` (a
		// NUMERIC fd) — throw here to abort the atomic write mid-content.
		writeFileSync: vi.fn((...args: WriteFileSyncArgs) => {
			if (typeof args[0] === "number" && state.forkThrow) {
				state.forkThrow = false;
				const err = new Error("ENOSPC: no space left on device, write") as Error & { code: string };
				err.code = "ENOSPC";
				throw err;
			}
			return (realWriteFileSync as (...a: WriteFileSyncArgs) => void)(...args);
		}),
		// Pre-fix entry copy uses `appendFileSync(path, entryLine)`. Throw here
		// to abort the pre-fix loop after the header was written.
		appendFileSync: vi.fn((...args: AppendFileSyncArgs) => {
			if (state.forkThrow) {
				state.forkThrow = false;
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

describe("SessionManager forkFrom atomic write — no partial fork on ENOSPC (opt #205)", () => {
	let sourceDir: string;
	let forkDir: string;

	beforeEach(() => {
		state.forkThrow = false;
		sourceDir = mkdtempSync(join(tmpdir(), "session-fork-src-"));
		forkDir = mkdtempSync(join(tmpdir(), "session-fork-dst-"));
	});

	afterEach(() => {
		rmSync(sourceDir, { recursive: true, force: true });
		rmSync(forkDir, { recursive: true, force: true });
	});

	it("leaves NO fork file when the write fails mid-fork (atomic all-or-nothing)", () => {
		// Build a source session with several entries (real fs; forkThrow off).
		const source = SessionManager.create(sourceDir, sourceDir);
		source.appendMessage({ role: "user", content: "hello", timestamp: 1 });
		source.appendMessage({
			role: "assistant",
			content: [{ type: "text", text: "hi there" }],
			usage,
			stopReason: "stop",
			timestamp: 2,
		} as never);
		source.appendMessage({ role: "user", content: "more", timestamp: 3 });
		const sourceFile = source.getSessionFile()!;

		expect(existsSync(sourceFile)).toBe(true);

		// A fresh empty target dir for the fork (so a leftover file is unambiguous).
		const targetSessionDir = join(forkDir, "fork-target");
		expect(existsSync(targetSessionDir)).toBe(false);

		// Arm the ENOSPC injection for the fork write only.
		state.forkThrow = true;
		expect(() => SessionManager.forkFrom(sourceFile, forkDir, targetSessionDir)).toThrowError(/ENOSPC/);

		// Atomic all-or-nothing: NO .jsonl fork file must remain on disk.
		// Pre-fix, the header writeFileSync(flag:"wx") succeeded before the
		// appendFileSync threw, leaving a header-only partial fork file here.
		if (existsSync(targetSessionDir)) {
			const jsonlFiles = readdirSync(targetSessionDir).filter((f) => f.endsWith(".jsonl"));
			expect(jsonlFiles, "no partial fork file should remain after a failed atomic write").toHaveLength(0);
		}
		// If the dir wasn't even created, that's also acceptable (no file at all).
		expect(true).toBe(true);
	});
});

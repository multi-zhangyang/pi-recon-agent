/**
 * opt #243 — findMostRecentSession skips a single .jsonl whose statSync throws
 * instead of aborting the whole listing (which made `pi --continue` silently
 * start a fresh session).
 *
 * The `.map(({path}) => ({path, mtime: statSync(path).mtime}))` step ran
 * statSync per file with no per-file guard. readSessionHeader already
 * swallows its own errors, but statSync did not. If it threw for any single
 * file (deleted between readdir+readHeader and stat, EACCES, broken target
 * after header read), the throw propagated through `.sort` and was caught by
 * the broad outer try → return null for the ENTIRE directory → continueRecent
 * created a brand-new session instead of resuming the real most-recent one.
 *
 * Fix: flatMap with a per-file try/catch that skips just the bad file. The
 * test writes two valid session .jsonl files and mocks statSync to throw on
 * one ("doomed.jsonl"). Post-fix: returns the other ("good.jsonl"). Pre-fix
 * (map restored): returns null.
 */
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type FsModule = typeof import("node:fs");
type StatSyncArgs = Parameters<FsModule["statSync"]>;

const doomedName = vi.hoisted(() => "doomed.jsonl");

vi.mock("fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	const realStatSync = actual.statSync;
	return {
		...actual,
		// readSessionHeader uses readFileSync (passed through), so it succeeds on
		// the doomed file. statSync throws on the doomed path only — simulating a
		// file deleted between header read and stat (or a broken stat target).
		statSync: vi.fn((...args: StatSyncArgs) => {
			const path = args[0];
			if (typeof path === "string" && path.endsWith(doomedName)) {
				const err = new Error("ENOENT: stat doomed") as Error & { code: string };
				err.code = "ENOENT";
				throw err;
			}
			return (realStatSync as (...a: StatSyncArgs) => void)(...args);
		}),
	};
});

const { findMostRecentSession } = await import("../src/core/session-manager.ts");

function writeSession(dir: string, name: string, id: string, cwd = "/tmp"): string {
	const file = join(dir, name);
	writeFileSync(
		file,
		`${JSON.stringify({ type: "session", version: 1, id, timestamp: "2026-06-28T00:00:00.000Z", cwd })}\n`,
	);
	return file;
}

describe("opt #243: findMostRecentSession skips a bad file instead of returning null", () => {
	let dir: string;
	let goodFile: string;

	beforeEach(() => {
		dir = join(tmpdir(), `opt243-findrecent-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(dir, { recursive: true });
		goodFile = writeSession(dir, "good.jsonl", "good-1");
		// doomed.jsonl is a valid session file (readSessionHeader succeeds) but
		// statSync is mocked to throw on it.
		writeSession(dir, doomedName, "doomed-1");
	});

	afterEach(() => {
		if (dir) rmSync(dir, { recursive: true, force: true });
	});

	it("returns the good session when one file's statSync throws (not null)", () => {
		const result = findMostRecentSession(dir);
		// Post-fix: doomed skipped, good returned. Pre-fix: outer catch → null.
		expect(result).toBe(goodFile);
	});

	it("returns null only when EVERY file is bad, not when one is", () => {
		// Sanity: a directory with at least one readable file never returns null
		// just because a sibling is unreadable.
		expect(findMostRecentSession(dir)).not.toBeNull();
	});

	it("broken symlink (ENOENT on stat) is skipped, not fatal", () => {
		// A real broken symlink: stat follows the link → ENOENT. readSessionHeader
		// (readFileSync) also fails → header null → filtered before statSync. This
		// confirms the broader class; the statSync mock above covers the
		// header-ok-but-stat-fails race.
		const dir2 = join(tmpdir(), `opt243-symlink-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		try {
			mkdirSync(dir2, { recursive: true });
			writeSession(dir2, "real.jsonl", "real-1");
			symlinkSync("/nonexistent/target-for-opt243", join(dir2, "broken.jsonl"));
			expect(findMostRecentSession(dir2)).not.toBeNull();
		} finally {
			rmSync(dir2, { recursive: true, force: true });
		}
	});
});

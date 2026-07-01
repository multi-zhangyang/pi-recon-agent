import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appendPrivateTextFile, writePrivateTextFile } from "../../src/core/repi/storage.ts";

// writePrivateTextFile is the SHARED write path for all REPI persisted state
// (playbooks, missions, evidence, memory transactions, tool index). It writes
// atomically (temp+rename, 0o600): a crash mid-write must never leave a
// truncated/partial file — readTextFile swallows the parse failure and returns
// "" (graceful) but the content is SILENTLY LOST. temp+rename replaces the
// inode; the old truncate-then-write kept it — the inode-change assertion is
// the regression probe. appendPrivateTextFile is the SHARED append path for the
// append-only ledgers (tool-trace, runtime failure/repair, evidence, journals);
// it now true-appends (appendFileSync, O(chunk), inode preserved) instead of
// read-modify-write (O(file) read + atomic rewrite per append) — its separator
// contract + 0o600 mode are preserved, see the append test below.

describe("repi/storage writePrivateTextFile atomicity", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-storage-atomic-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("replaces the file atomically: inode changes, mode 0o600, no .tmp leftover, content survives", () => {
		const path = join(tempDir, "playbook.md");
		writePrivateTextFile(path, "first content\n");
		expect(statSync(path).mode & 0o777).toBe(0o600);
		const inodeBefore = statSync(path).ino;

		// A rewrite via temp+rename installs a NEW inode. The old
		// truncate-then-write kept the SAME inode — this assertion fails if the
		// write regresses.
		writePrivateTextFile(path, "second content\n");
		const inodeAfter = statSync(path).ino;
		expect(inodeAfter).not.toBe(inodeBefore);

		// Mode preserved; no stray temp; content complete (not truncated).
		expect(statSync(path).mode & 0o777).toBe(0o600);
		expect(readdirSync(dirname(path)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
		expect(readFileSync(path, "utf8")).toBe("second content\n");
	});

	it("creates a new file atomically at 0o600 with no .tmp leftover", () => {
		const path = join(tempDir, "fresh-mission.md");
		expect(existsSync(path)).toBe(false);
		writePrivateTextFile(path, "mission\n");
		expect(existsSync(path)).toBe(true);
		expect(statSync(path).mode & 0o777).toBe(0o600);
		expect(readdirSync(dirname(path)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
		expect(readFileSync(path, "utf8")).toBe("mission\n");
	});

	it("appendPrivateTextFile appends in place (true append): inode PRESERVED, no .tmp leftover, separator contract intact", () => {
		const path = join(tempDir, "evidence.log");
		appendPrivateTextFile(path, "line one");
		const inodeBefore = statSync(path).ino;
		expect(statSync(path).mode & 0o777).toBe(0o600);

		appendPrivateTextFile(path, "line two");
		const inodeAfter = statSync(path).ino;
		// True append (appendFileSync) writes to the SAME inode — no temp+rename.
		// The old read-modify-write path changed the inode (temp+rename); this
		// assertion flips if the append regresses back to read-modify-write.
		expect(inodeAfter).toBe(inodeBefore);
		expect(readdirSync(dirname(path)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
		// Separator contract preserved EXACTLY: a "\n" is prepended unless the
		// existing content ends with "\n" — including the missing/empty first
		// append ("" doesn't end with "\n"), so the file starts with a leading "\n".
		expect(readFileSync(path, "utf8")).toBe("\nline one\nline two");
		expect(statSync(path).mode & 0o777).toBe(0o600);
	});
});

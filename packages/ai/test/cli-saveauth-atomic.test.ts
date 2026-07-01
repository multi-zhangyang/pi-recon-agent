import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { saveAuth } from "../src/cli.ts";

// opt #149: the repi-ai CLI's saveAuth used writeFileSync (truncate-then-write)
// for auth.json. A crash/SIGINT mid-write truncated the file; loadAuth swallows
// the parse failure → {} → a silent full re-login with no diagnostic. Now an
// atomic temp+rename (same dir) so readers see either the complete old or new
// file. The inode-change probe distinguishes temp+rename (new inode) from
// truncate-then-write (same inode) — same doctrine as opts #38/#41/#42/#43.

function cred(access: string): { type: "oauth"; refresh: string; access: string; expires: number } {
	return { type: "oauth", refresh: `r-${access}`, access, expires: 1234567890 };
}

describe("repi-ai saveAuth atomic write (opt #149)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-auth-149-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("writes atomically — temp+rename replaces the inode between writes", () => {
		const file = join(dir, "auth.json");

		saveAuth({ anthropic: cred("a1") }, file);
		const stat1 = statSync(file);
		const ino1 = stat1.ino;

		saveAuth({ anthropic: cred("a1"), openai: cred("o1") }, file);
		const stat2 = statSync(file);
		const ino2 = stat2.ino;

		// Sanity: the filesystem reports real inodes (some FUSE/overlay mounts
		// report 0; on those this probe can't distinguish, so skip rather than fail).
		if (ino1 === 0 || ino2 === 0) {
			console.warn("inode-change probe not supported on this filesystem (ino=0); skipping");
			return;
		}
		// Atomic temp+rename → a NEW inode replaces the old. Truncate-then-write
		// would keep the SAME inode → this assertion pins the fix.
		expect(ino2).not.toBe(ino1);

		// Content is correct and complete.
		const parsed = JSON.parse(readFileSync(file, "utf-8")) as Record<string, unknown>;
		expect(parsed.anthropic).toBeDefined();
		expect(parsed.openai).toBeDefined();
	});

	it("leaves no orphaned .tmp file after a successful write", () => {
		const file = join(dir, "auth.json");
		saveAuth({ anthropic: cred("a1") }, file);

		const entries = readdirSync(dir).filter((e) => e.endsWith(".tmp"));
		expect(entries).toEqual([]);
		expect(existsSync(file)).toBe(true);
	});
});

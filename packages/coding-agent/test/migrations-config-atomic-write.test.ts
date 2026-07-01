import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrateModelsJsonConfigValues } from "../src/migrations.ts";

// opt #161: 5 migration config-rewrite sites (migrations.ts: settings.json,
// auth.json ×2, models.json, keybindings.json) used bare writeFileSync
// (truncate-then-write) on EXISTING user config. A SIGKILL/OOM/SIGTERM mid-write
// truncated the file → the user's config/auth/models/keybindings was silently
// lost. The sibling state writers (session #38, manifest #41, auth #42, config
// #43) were already atomic; these migration sites were missed. Now routed
// through atomicWriteFileSync (temp+rename in same dir, mode preserved). The
// inode-change probe distinguishes temp+rename (new inode) from truncate-then-
// write (same inode) — same doctrine as #38/#41/#42/#43/#149. Pinned via
// migrateModelsJsonConfigValues (exported, takes agentDir), which rewrites
// models.json when a legacy env-var-name value is migrated to $-prefixed.

describe("migrateModelsJsonConfigValues rewrites models.json atomically (opt #161)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-migrate-atomic-161-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("replaces the inode between writes (temp+rename, not truncate-then-write)", () => {
		const file = join(dir, "models.json");
		// A legacy all-caps env-var-name apiKey value triggers a migration → rewrite.
		writeFileSync(file, JSON.stringify({ providers: { openai: { apiKey: "OPENAI_API_KEY" } } }, null, 2));

		// First migration: OPENAI_API_KEY → $OPENAI_API_KEY.
		migrateModelsJsonConfigValues(dir);
		const stat1 = statSync(file);
		const ino1 = stat1.ino;

		// Second migration: rewrite again with a fresh legacy value to get a
		// second inode. (atomicWriteFileSync preserves existing mode; 0o644.)
		writeFileSync(file, JSON.stringify({ providers: { openai: { apiKey: "ANTHROPIC_API_KEY" } } }, null, 2));
		migrateModelsJsonConfigValues(dir);
		const stat2 = statSync(file);
		const ino2 = stat2.ino;

		// Sanity: the filesystem reports real inodes (some FUSE/overlay mounts
		// report 0; on those this probe can't distinguish, so skip).
		if (ino1 === 0 || ino2 === 0) {
			console.warn("inode-change probe not supported on this filesystem (ino=0); skipping");
			return;
		}
		// Atomic temp+rename → a NEW inode replaces the old. Truncate-then-write
		// would keep the SAME inode → this assertion pins the fix.
		expect(ino2).not.toBe(ino1);

		// Content is correct and complete.
		const parsed = JSON.parse(readFileSync(file, "utf-8")) as Record<string, unknown>;
		const openai = (parsed.providers as Record<string, { apiKey: string }>).openai;
		expect(openai.apiKey).toBe("$ANTHROPIC_API_KEY");
	});

	it("leaves no orphaned .tmp file after a successful atomic write", () => {
		const file = join(dir, "models.json");
		writeFileSync(file, JSON.stringify({ providers: { openai: { apiKey: "OPENAI_API_KEY" } } }, null, 2));
		migrateModelsJsonConfigValues(dir);

		const entries = readdirSync(dir).filter((e) => e.endsWith(".tmp"));
		expect(entries).toEqual([]);
		expect(existsSync(file)).toBe(true);
	});
});

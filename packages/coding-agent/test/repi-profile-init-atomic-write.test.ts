import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ENV_AGENT_DIR } from "../src/config.ts";
import { initializeRepiProfile } from "../src/core/repi-profile-init.ts";

// Foundational opt #265: repi-profile-init writeJson used bare writeFileSync
// (truncate-then-write) for settings.json + profile.json on EVERY startup. A
// crash mid-write truncated the file → readJson swallows the JSON.parse
// failure → settings rebuilt from defaults only → user customizations
// (retry/compaction/model overrides) permanently lost. Routed through
// atomicWriteFileSync (temp+rename, mode-preserved) — same doctrine as the
// opt #43 SettingsManager runtime path. The inode-change probe distinguishes
// temp+rename (new inode) from truncate-then-write (same inode). Driven via
// the public initializeRepiProfile with REPI_CODING_AGENT_DIR pointed at a
// temp dir (the real startup path, no private export needed).

describe("initializeRepiProfile writes settings.json + profile.json atomically (opt #265)", () => {
	let dir: string;
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-init-atomic-265-"));
		process.env[ENV_AGENT_DIR] = dir;
	});
	afterEach(() => {
		delete process.env[ENV_AGENT_DIR];
		rmSync(dir, { recursive: true, force: true });
	});

	it("replaces the settings.json inode between writes (temp+rename, not truncate-then-write)", () => {
		initializeRepiProfile({ repoRoot: dir });
		const settingsPath = join(dir, "settings.json");
		expect(existsSync(settingsPath)).toBe(true);
		const ino1 = statSync(settingsPath).ino;

		// Second init rewrites settings.json unconditionally (the migrate/merge
		// path always calls writeJson at the end).
		initializeRepiProfile({ repoRoot: dir });
		const ino2 = statSync(settingsPath).ino;

		if (ino1 === 0 || ino2 === 0) {
			console.warn("inode-change probe not supported on this filesystem (ino=0); skipping");
			return;
		}
		// Atomic temp+rename → a NEW inode replaces the old. Truncate-then-write
		// keeps the SAME inode → this assertion pins the fix.
		expect(ino2).not.toBe(ino1);

		// Content is complete + parseable (not torn).
		const parsed = JSON.parse(readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
		expect(parsed.retry).toBeDefined();
		expect(parsed.memory).toBeDefined();
	});

	it("replaces the profile.json inode between writes and leaves no .tmp orphan", () => {
		initializeRepiProfile({ repoRoot: dir });
		const manifestPath = join(dir, "recon", "profile.json");
		expect(existsSync(manifestPath)).toBe(true);
		const ino1 = statSync(manifestPath).ino;

		initializeRepiProfile({ repoRoot: dir });
		const ino2 = statSync(manifestPath).ino;

		if (ino1 === 0 || ino2 === 0) {
			console.warn("inode-change probe not supported on this filesystem (ino=0); skipping");
			return;
		}
		expect(ino2).not.toBe(ino1);

		// No orphaned temp files anywhere under the agent dir.
		function collectTmp(root: string): string[] {
			const out: string[] = [];
			for (const entry of readdirSync(root, { withFileTypes: true })) {
				if (entry.name.endsWith(".tmp")) out.push(join(root, entry.name));
				if (entry.isDirectory()) out.push(...collectTmp(join(root, entry.name)));
			}
			return out;
		}
		expect(collectTmp(dir)).toEqual([]);

		// Both files are mode 0o600 (private).
		expect(statSync(join(dir, "settings.json")).mode & 0o777).toBe(0o600);
		expect(statSync(manifestPath).mode & 0o777).toBe(0o600);
	});
});

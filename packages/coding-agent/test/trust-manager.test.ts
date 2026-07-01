import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hasProjectTrustInputs, ProjectTrustStore } from "../src/core/trust-manager.ts";

describe("ProjectTrustStore", () => {
	let tempDir: string;
	let agentDir: string;
	let cwd: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `trust-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		cwd = join(tempDir, "project");
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(cwd, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("stores decisions per cwd", () => {
		const store = new ProjectTrustStore(agentDir);

		expect(store.get(cwd)).toBeNull();
		store.set(cwd, true);
		expect(store.get(cwd)).toBe(true);
		store.set(cwd, false);
		expect(store.get(cwd)).toBe(false);
		store.set(cwd, null);
		expect(store.get(cwd)).toBeNull();
	});

	it("inherits trust decisions from parent directories with child overrides", () => {
		const store = new ProjectTrustStore(agentDir);
		const child = join(cwd, "nested", "case");
		mkdirSync(child, { recursive: true });

		store.set(cwd, true);
		expect(store.get(child)).toBe(true);

		store.set(child, false);
		expect(store.get(child)).toBe(false);

		store.set(child, null);
		expect(store.get(child)).toBe(true);

		store.set(cwd, false);
		expect(store.get(child)).toBe(false);
	});

	it("quarantines malformed trust stores without losing the original content", () => {
		const trustPath = join(agentDir, "trust.json");
		writeFileSync(trustPath, "{not json", "utf-8");
		const store = new ProjectTrustStore(agentDir);

		// Quarantine contract: a corrupted trust file is moved aside (renamed to a
		// .bad.* backup) and the store continues with an empty in-memory state
		// rather than crashing the agent. The malformed content is preserved in
		// the backup, never silently overwritten or destroyed.
		expect(() => store.get(cwd)).not.toThrow();
		expect(store.get(cwd)).toBe(null);

		const backups = readdirSync(agentDir).filter((name) => name.startsWith("trust.json.bad."));
		expect(backups.length).toBe(1);
		expect(readFileSync(join(agentDir, backups[0]), "utf-8")).toBe("{not json");
	});

	it("detects project trust inputs", () => {
		expect(hasProjectTrustInputs(cwd)).toBe(false);

		mkdirSync(join(cwd, ".repi"), { recursive: true });
		expect(hasProjectTrustInputs(cwd)).toBe(true);
		rmSync(join(cwd, ".repi"), { recursive: true, force: true });

		writeFileSync(join(cwd, "AGENTS.md"), "Project instructions");
		expect(hasProjectTrustInputs(cwd)).toBe(true);
		rmSync(join(cwd, "AGENTS.md"), { force: true });

		mkdirSync(join(cwd, ".agents", "skills"), { recursive: true });
		expect(hasProjectTrustInputs(cwd)).toBe(true);
	});

	describe("atomic persistence", () => {
		// trust.json is rewritten via writeTrustFile → atomicWriteFileSync
		// (temp+rename) on every set(). A crash mid-write must never leave a
		// truncated/partial file: readTrustFile self-heals (quarantine aside + {}),
		// but that SILENTLY loses every prior trust decision → the user is
		// re-prompted for dirs already approved. temp+rename replaces the inode;
		// the old truncate-then-write kept it — the inode-change assertion is the
		// regression probe.

		it("set() replaces trust.json atomically: inode changes, mode 0o600, no .tmp leftover, decisions survive", () => {
			const trustPath = join(agentDir, "trust.json");
			const store = new ProjectTrustStore(agentDir);
			store.set(cwd, true);
			expect(existsSync(trustPath)).toBe(true);
			expect(statSync(trustPath).mode & 0o777).toBe(0o600);
			const inodeBefore = statSync(trustPath).ino;

			// A second set() rewrites via temp+rename → new inode. Truncate keeps
			// the inode; this assertion fails if the write regresses.
			store.set(cwd, false);
			const inodeAfter = statSync(trustPath).ino;
			expect(inodeAfter).not.toBe(inodeBefore);

			// Mode 0o600 preserved; no stray temp; decision survives reload.
			expect(statSync(trustPath).mode & 0o777).toBe(0o600);
			expect(readdirSync(dirname(trustPath)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
			const reloaded = new ProjectTrustStore(agentDir);
			expect(reloaded.get(cwd)).toBe(false);
		});
	});
});

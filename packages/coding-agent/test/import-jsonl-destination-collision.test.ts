import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveImportDestination } from "../src/core/agent-session-runtime.ts";

// opt #274: /import's `copyFileSync(resolvedPath, destinationPath)` silently
// truncated any pre-existing session at the same basename (re-import, a
// restored backup, or a coincidental name collision), permanently losing that
// conversation with no warning or backup. The fix computes a collision-free
// destination: when a copy would land on an existing file, suffix the basename
// with a short random tag. Exported as resolveImportDestination for testing.

const tempDirs: string[] = [];

function makeTempDir(): string {
	const dir = mkdtempSync(join(tmpdir(), "opt274-import-dest-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

describe("resolveImportDestination collision avoidance (opt #274)", () => {
	it("returns the plain basename join when no collision and a copy is needed", () => {
		const sessionDir = makeTempDir();
		const srcDir = makeTempDir();
		const src = join(srcDir, "2026-07-01-abc.jsonl");
		writeFileSync(src, '{"type":"session"}\n');

		const { destinationPath, isCopying } = resolveImportDestination(sessionDir, resolve(src));
		expect(isCopying).toBe(true);
		expect(destinationPath).toBe(join(sessionDir, basename(src)));
		expect(existsSync(destinationPath)).toBe(false);
	});

	it("does NOT copy (isCopying=false) when the source already lives in the session dir", () => {
		const sessionDir = makeTempDir();
		const src = join(sessionDir, "2026-07-01-abc.jsonl");
		writeFileSync(src, '{"type":"session"}\n');

		// Same file → open in place, no copy, no collision avoidance (the file
		// IS the source). Previously this path was fine; pin it so the
		// collision guard never fires for the in-place case.
		const { destinationPath, isCopying } = resolveImportDestination(sessionDir, resolve(src));
		expect(isCopying).toBe(false);
		expect(destinationPath).toBe(join(sessionDir, basename(src)));
	});

	it("avoids overwriting an existing same-basename session by suffixing a random tag", () => {
		const sessionDir = makeTempDir();
		const srcDir = makeTempDir();
		const src = join(srcDir, "2026-07-01-abc.jsonl");
		writeFileSync(src, '{"type":"session","src":true}\n');
		// An existing, DIFFERENT session already occupies the destination basename.
		const existing = join(sessionDir, "2026-07-01-abc.jsonl");
		writeFileSync(existing, '{"type":"session","existing":true}\n');

		const { destinationPath, isCopying } = resolveImportDestination(sessionDir, resolve(src));
		expect(isCopying).toBe(true);
		// The destination is NOT the existing file (would have been clobbered before).
		expect(destinationPath).not.toBe(existing);
		// It does not exist yet and lives in sessionDir with the stem prefix.
		expect(existsSync(destinationPath)).toBe(false);
		expect(destinationPath.startsWith(sessionDir)).toBe(true);
		const destBase = basename(destinationPath);
		expect(destBase.startsWith("2026-07-01-abc.")).toBe(true);
		expect(destBase.endsWith(".jsonl")).toBe(true);
		// The existing session is untouched.
		expect(readFileSync(existing, "utf-8")).toContain('"existing":true');
	});

	it("produces a unique destination even if the first random tag also collides", () => {
		const sessionDir = makeTempDir();
		const srcDir = makeTempDir();
		const src = join(srcDir, "sess.jsonl");
		writeFileSync(src, '{"type":"session"}\n');
		// Occupy both the plain basename and a couple of stem.* suffixes by
		// pre-creating files; the do/while must keep retrying until a free name
		// is found. (Random tags make exact collisions unlikely, but the loop
		// is the safety net — fill the dir with many stem.* files to force it.)
		writeFileSync(join(sessionDir, "sess.jsonl"), "x\n");
		for (let i = 0; i < 50; i++) {
			writeFileSync(join(sessionDir, `sess.${i.toString(16).padStart(2, "0")}.jsonl`), "x\n");
		}
		// Also create many random 2-byte-hex names to stress the retry loop.
		for (let i = 0; i < 200; i++) {
			const hex = i.toString(16).padStart(4, "0").slice(-2);
			writeFileSync(join(sessionDir, `sess.${hex}.jsonl`), "x\n");
		}

		const { destinationPath, isCopying } = resolveImportDestination(sessionDir, resolve(src));
		expect(isCopying).toBe(true);
		// The retry loop found a non-existing destination.
		expect(existsSync(destinationPath)).toBe(false);
		expect(basename(destinationPath).startsWith("sess.")).toBe(true);
		expect(basename(destinationPath).endsWith(".jsonl")).toBe(true);
	});
});

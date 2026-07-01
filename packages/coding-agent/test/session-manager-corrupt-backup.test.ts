/**
 * opt #221 — corrupt/unrecoverable session file is backed up before being
 * overwritten with a fresh session (no silent data loss).
 *
 * Pre-fix, setSessionFile's `fileEntries.length === 0` branch called newSession
 * + _rewriteFile and silently replaced the existing file with a blank session,
 * permanently destroying the corrupt content (which may have been partially
 * recoverable — a torn header from a crash during the first flush, or a single
 * bad line). Compounded by healTornTrailingLine writing an EMPTY temp over the
 * original when the only line was a torn header (entries=[]).
 *
 * Fix: (a) healTornTrailingLine refuses to heal to an empty file (returns early
 * when entries.length===0); (b) setSessionFile backs the original up to
 * `<path>.corrupt.<ts>.bak` (best-effort rename + stderr warning) before
 * writing the fresh header.
 */
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadEntriesFromFile, SessionManager } from "../src/core/session-manager.ts";

describe("opt #221: corrupt session file backed up before overwrite", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `opt221-corrupt-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("backs up a fully-corrupt session file and starts a fresh session at the same path", () => {
		const file = join(tempDir, "corrupt.jsonl");
		const corruptContent = "this is not valid json at all";
		writeFileSync(file, corruptContent);

		// Silence the stderr warning so the test output stays clean.
		const warnSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

		const sm = SessionManager.open(file, tempDir);

		// A backup file matching <file>.corrupt.<ts>.bak exists with the original content.
		const backups = readdirSync(tempDir).filter((f) => f.startsWith("corrupt.jsonl.corrupt.") && f.endsWith(".bak"));
		expect(backups).toHaveLength(1);
		expect(readFileSync(join(tempDir, backups[0]), "utf8")).toBe(corruptContent);

		// The session file itself is now a fresh, valid session (parseable header).
		const reloaded = loadEntriesFromFile(file);
		expect(reloaded.length).toBeGreaterThan(0);
		expect(reloaded[0].type).toBe("session");

		// The fresh session is usable.
		expect(sm.getSessionId()).toBeDefined();
		warnSpy.mockRestore();
	});

	it("backs up a torn-header-only file (heal no longer destroys it to empty)", () => {
		const file = join(tempDir, "torn-header.jsonl");
		// A single truncated header line with no trailing newline — the only line.
		const tornContent = '{"type":"session","id":"abc","timestamp":"2025';
		writeFileSync(file, tornContent);

		const warnSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		SessionManager.open(file, tempDir);

		const backups = readdirSync(tempDir).filter(
			(f) => f.startsWith("torn-header.jsonl.corrupt.") && f.endsWith(".bak"),
		);
		expect(backups).toHaveLength(1);
		// The original torn content survives in the backup (pre-fix it was destroyed).
		expect(readFileSync(join(tempDir, backups[0]), "utf8")).toBe(tornContent);

		// And the live file is a fresh valid session.
		const reloaded = loadEntriesFromFile(file);
		expect(reloaded.length).toBeGreaterThan(0);
		expect(reloaded[0].type).toBe("session");
		warnSpy.mockRestore();
	});

	it("does not create a backup for a genuinely empty (size 0) file", () => {
		const file = join(tempDir, "empty.jsonl");
		writeFileSync(file, "");

		const warnSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		SessionManager.open(file, tempDir);

		const backups = readdirSync(tempDir).filter((f) => f.startsWith("empty.jsonl.corrupt."));
		expect(backups).toHaveLength(0);
		// Fresh session written.
		const reloaded = loadEntriesFromFile(file);
		expect(reloaded.length).toBeGreaterThan(0);
		expect(reloaded[0].type).toBe("session");
		warnSpy.mockRestore();
	});

	it("still loads a valid session normally (no backup, no overwrite)", () => {
		const file = join(tempDir, "valid.jsonl");
		writeFileSync(
			file,
			'{"type":"session","id":"abc","timestamp":"2025-01-01T00:00:00Z","cwd":"/tmp"}\n' +
				'{"type":"message","id":"1","parentId":null,"timestamp":"2025-01-01T00:00:01Z","message":{"role":"user","content":"hi","timestamp":1}}\n',
		);

		const sm = SessionManager.open(file, tempDir);

		const backups = readdirSync(tempDir).filter((f) => f.startsWith("valid.jsonl.corrupt."));
		expect(backups).toHaveLength(0);
		expect(sm.getSessionId()).toBe("abc");
	});
});

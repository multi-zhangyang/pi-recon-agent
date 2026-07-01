import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadEntriesFromFile, SessionManager } from "../src/core/session-manager.ts";

// Foundational opt #270: parseSessionEntryLine only caught JSON SYNTAX errors;
// a `type:"message"` line that is valid JSON but has a missing/null `message`
// field (disk corruption, partial write that landed as valid JSON, buggy
// extension/custom writer, version-incompatible client) passed the check and
// entered fileEntries. Then _buildIndex did `entry.message.role === "assistant"`
// → TypeError: Cannot read properties of null/undefined (reading 'role') →
// UNCAUGHT in setSessionFile (no try/catch around _buildIndex) → propagates out
// of the SessionManager constructor → every --continue/open/forkFrom on that
// session aborts. The headerless recovery (backupCorruptSessionFile) only fires
// when fileEntries.length===0, so a header-valid-but-entry-corrupt session was
// permanently unopenable. The fix validates the message shape in
// parseSessionEntryLine (the single chokepoint all entry loading flows through)
// and skips the malformed entry, so the session stays loadable.

const HEADER = '{"type":"session","id":"abc","timestamp":"2025-01-01T00:00:00Z","cwd":"/tmp"}\n';
const GOOD_USER =
	'{"type":"message","id":"g1","parentId":"abc","timestamp":"2025-01-01T00:00:01Z","message":{"role":"user","content":"hi","timestamp":1}}\n';
const GOOD_ASSISTANT =
	'{"type":"message","id":"g2","parentId":"g1","timestamp":"2025-01-01T00:00:02Z","message":{"role":"assistant","content":"hello","timestamp":2,"model":"m","provider":"p"}}\n';

describe("opt #270 — loadEntriesFromFile skips a structurally-corrupt message entry (no crash)", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `opt270-corrupt-msg-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("skips a message entry with message: null (does not throw, keeps siblings)", () => {
		const file = join(tempDir, "null-msg.jsonl");
		const corrupt =
			'{"type":"message","id":"c1","parentId":"abc","timestamp":"2025-01-01T00:00:01Z","message":null}\n';
		writeFileSync(file, `${HEADER}${corrupt}${GOOD_USER}`);

		// Pre-fix: this throws TypeError (entry.message.role) when _buildIndex runs
		// during SessionManager construction. Here loadEntriesFromFile is the loader
		// chokepoint — it must skip the corrupt entry, not surface it.
		const entries = loadEntriesFromFile(file);
		expect(entries).toHaveLength(2);
		expect(entries[0].type).toBe("session");
		expect(entries[1].type).toBe("message");
		expect((entries[1] as { id: string }).id).toBe("g1");
		// The corrupt entry c1 is absent.
		expect(entries.some((e) => (e as { id?: string }).id === "c1")).toBe(false);
	});

	it("skips a message entry with message: undefined (missing field)", () => {
		const file = join(tempDir, "missing-msg.jsonl");
		// `message` field omitted entirely.
		const corrupt = '{"type":"message","id":"c2","parentId":"abc","timestamp":"2025-01-01T00:00:01Z"}\n';
		writeFileSync(file, `${HEADER}${corrupt}${GOOD_ASSISTANT}`);

		const entries = loadEntriesFromFile(file);
		expect(entries).toHaveLength(2);
		expect((entries[1] as { id: string }).id).toBe("g2");
		expect(entries.some((e) => (e as { id?: string }).id === "c2")).toBe(false);
	});

	it("skips a message entry with message.role non-string (e.g. message: 42)", () => {
		const file = join(tempDir, "bad-msg-shape.jsonl");
		const corrupt = '{"type":"message","id":"c3","parentId":"abc","timestamp":"2025-01-01T00:00:01Z","message":42}\n';
		writeFileSync(file, `${HEADER}${corrupt}${GOOD_USER}${GOOD_ASSISTANT}`);

		const entries = loadEntriesFromFile(file);
		// header + g1 + g2; c3 skipped.
		expect(entries).toHaveLength(3);
		expect(entries.some((e) => (e as { id?: string }).id === "c3")).toBe(false);
	});

	it("loads a clean session unchanged (regression guard)", () => {
		const file = join(tempDir, "clean.jsonl");
		writeFileSync(file, `${HEADER}${GOOD_USER}${GOOD_ASSISTANT}`);
		const entries = loadEntriesFromFile(file);
		expect(entries).toHaveLength(3);
		expect((entries[1] as { id: string }).id).toBe("g1");
		expect((entries[2] as { id: string }).id).toBe("g2");
	});

	it("SessionManager.open on a corrupt-message file does not crash in _buildIndex", () => {
		// End-to-end: the crash class is _buildIndex (setSessionFile) throwing
		// `entry.message.role` TypeError during construction. Pre-fix this
		// constructed-throws. Post-fix the corrupt entry is skipped at the
		// parseSessionEntryLine chokepoint so _buildIndex never sees it.
		const file = join(tempDir, "e2e.jsonl");
		const corrupt =
			'{"type":"message","id":"c1","parentId":"abc","timestamp":"2025-01-01T00:00:01Z","message":null}\n';
		writeFileSync(file, `${HEADER}${corrupt}${GOOD_USER}${GOOD_ASSISTANT}`);

		let manager: SessionManager;
		expect(() => {
			manager = SessionManager.open(file);
		}).not.toThrow();
		// The corrupt entry is skipped; the two good messages are loaded (SessionManager
		// may re-id entries during migration, so assert by count + c1 absence, not ids).
		const entries = manager!.getEntries();
		expect(entries).toHaveLength(2);
		expect(entries.some((e) => (e as { id?: string }).id === "c1")).toBe(false);
		expect(entries.every((e) => e.type === "message")).toBe(true);
	});
});

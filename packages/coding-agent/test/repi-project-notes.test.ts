import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// Claude-Code-style project notes (opt #273 follow-on): one file per fact under
// the per-cwd scoped memory root (notes/<slug>.md with frontmatter + MEMORY.md
// index). Verifies the write/read/list/delete/index/injection behavior and that
// notes are per-cwd scoped (no cross-project pollution).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

describe("repi project notes (Claude-Code-style, opt #273 follow-on)", () => {
	let originalAgentDir: string | undefined;
	let tempAgentDir: string;
	let projectCwd: string;

	beforeEach(() => {
		originalAgentDir = process.env[ENV_AGENT_DIR];
		tempAgentDir = mkdtempSync(join(tmpdir(), "repi-notes-"));
		process.env[ENV_AGENT_DIR] = tempAgentDir;
		projectCwd = mkdtempSync(join(tmpdir(), "repi-proj-"));
	});

	afterEach(async () => {
		if (originalAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = originalAgentDir;
		const { setMemoryScopeCwd } = await import("../src/core/repi/storage.ts");
		setMemoryScopeCwd(null);
	});

	async function withScope() {
		const storage = await import("../src/core/repi/storage.ts");
		storage.setMemoryScopeCwd(projectCwd);
		return storage;
	}

	it("writeNote creates a frontmatter file under notes/ + updates MEMORY.md index", async () => {
		const { encodeCwdForScope, memoryNotesIndexPath } = await withScope();
		const { writeNote } = await import("../src/core/repi/memory-notes.ts");
		const res = writeNote({
			name: "user-prefers-quiet",
			description: "user likes minimal stdout",
			type: "user",
			body: "Keep tool output terse.",
		});
		expect(res.ok).toBe(true);
		const encoded = encodeCwdForScope(projectCwd);
		expect(res.path).toBe(
			join(tempAgentDir, "recon", "memory", "projects", encoded, "notes", "user-prefers-quiet.md"),
		);
		expect(existsSync(res.path)).toBe(true);
		const file = readFileSync(res.path, "utf8");
		expect(file).toContain("name: user-prefers-quiet");
		expect(file).toContain("description: user likes minimal stdout");
		expect(file).toContain("type: user");
		expect(file).toContain("Keep tool output terse.");
		// Index created with one line per note.
		expect(existsSync(memoryNotesIndexPath())).toBe(true);
		const index = readFileSync(memoryNotesIndexPath(), "utf8");
		expect(index).toContain("user-prefers-quiet");
		expect(index).toContain("user likes minimal stdout");
	});

	it("notes are per-cwd scoped — project A notes do not appear in project B", async () => {
		const { setMemoryScopeCwd } = await withScope();
		const { writeNote, listNotes } = await import("../src/core/repi/memory-notes.ts");
		writeNote({ name: "project-a-fact", description: "fact in project A", type: "project", body: "A-only" });
		expect(listNotes().map((n) => n.name)).toContain("project-a-fact");
		// Switch to a different project scope.
		const projectB = mkdtempSync(join(tmpdir(), "repi-projB-"));
		setMemoryScopeCwd(projectB);
		const bNotes = listNotes();
		expect(bNotes.map((n) => n.name)).not.toContain("project-a-fact");
		expect(bNotes.length).toBe(0);
	});

	it("readNote returns the parsed body + type; deleteNote removes + rebuilds index", async () => {
		await withScope();
		const { writeNote, readNote, deleteNote, listNotes } = await import("../src/core/repi/memory-notes.ts");
		writeNote({ name: "ref-docs", description: "api docs url", type: "reference", body: "https://example.com/docs" });
		const note = readNote("ref-docs");
		expect(note?.type).toBe("reference");
		expect(note?.body).toBe("https://example.com/docs");
		expect(note?.description).toBe("api docs url");
		const del = deleteNote("ref-docs");
		expect(del.ok).toBe(true);
		expect(readNote("ref-docs")).toBeNull();
		expect(listNotes().map((n) => n.name)).not.toContain("ref-docs");
	});

	it("writeNote rejects invalid names, empty descriptions, and oversized bodies", async () => {
		await withScope();
		const { writeNote } = await import("../src/core/repi/memory-notes.ts");
		expect(writeNote({ name: "Bad Name!", description: "x", type: "project", body: "y" }).ok).toBe(false);
		expect(writeNote({ name: "ok-name", description: "   ", type: "project", body: "y" }).ok).toBe(false);
		expect(writeNote({ name: "ok-name", description: "x", type: "project", body: "x".repeat(70 * 1024) }).ok).toBe(
			false,
		);
	});

	it("normalizeNoteType defaults to project for unknown types; isValidNoteName enforces the slug rule", async () => {
		await withScope();
		const { writeNote, readNote } = await import("../src/core/repi/memory-notes.ts");
		writeNote({ name: "weird-type", description: "d", type: "garbage" as never, body: "b" });
		const note = readNote("weird-type");
		expect(note?.type).toBe("project");
		const { isValidNoteName } = await import("../src/core/repi/memory-notes.ts");
		expect(isValidNoteName("good-name")).toBe(true);
		expect(isValidNoteName("Bad")).toBe(false);
		expect(isValidNoteName("")).toBe(false);
		expect(isValidNoteName("a".repeat(70))).toBe(false);
	});

	it("noteIndexForInjection returns empty when no notes, non-empty bounded preview when notes exist", async () => {
		await withScope();
		const { noteIndexForInjection, writeNote } = await import("../src/core/repi/memory-notes.ts");
		expect(noteIndexForInjection()).toBe("");
		writeNote({ name: "alpha", description: "first note", type: "project", body: "body-a" });
		writeNote({ name: "beta", description: "second note", type: "feedback", body: "body-b" });
		const inj = noteIndexForInjection();
		expect(inj).toContain("## Project memory (re_note index)");
		expect(inj).toContain("alpha");
		expect(inj).toContain("beta");
		// One line per note (no body in the index preview).
		expect(inj).not.toContain("body-a");
	});

	it("rebuildNoteIndex scans notes/ and rewrites MEMORY.md from scratch", async () => {
		await withScope();
		const { writeNote, rebuildNoteIndex, readNoteIndexText } = await import("../src/core/repi/memory-notes.ts");
		const { writePrivateTextFile, memoryNotesDir, memoryNotesIndexPath } = await import(
			"../src/core/repi/storage.ts"
		);
		writeNote({ name: "x", description: "x desc", type: "project", body: "bx" });
		writeNote({ name: "y", description: "y desc", type: "project", body: "by" });
		// Corrupt the index, then rebuild.
		writePrivateTextFile(memoryNotesIndexPath(), "garbage\n");
		rebuildNoteIndex();
		const idx = readNoteIndexText();
		expect(idx).toContain("x");
		expect(idx).toContain("y");
		expect(idx).not.toContain("garbage");
		expect(memoryNotesDir).toBeTruthy();
	});

	it("falls back to the legacy global root when scope is null (no notes dir)", async () => {
		const { setMemoryScopeCwd } = await import("../src/core/repi/storage.ts");
		setMemoryScopeCwd(null);
		const { listNotes, noteIndexForInjection } = await import("../src/core/repi/memory-notes.ts");
		expect(listNotes()).toEqual([]);
		expect(noteIndexForInjection()).toBe("");
	});
});

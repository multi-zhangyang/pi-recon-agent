// Claude-Code-style project notes memory (opt #273 follow-on).
//
// REPI's memory was a complex global v5/v6 distill/skill-capsule/promotion
// system that polluted across projects (fixed per-cwd by opt #273). This
// module adds the Claude Code memory pattern ON TOP of the per-cwd scoped
// store: one file per fact (notes/<slug>.md) with frontmatter (name,
// description, metadata.type: user|feedback|project|reference) + a MEMORY.md
// index (one line per note). Additive — the existing distill/recall/injection
// pipeline is untouched. All paths route through memoryNotesDir() /
// memoryNotesIndexPath() which are per-cwd scoped, so a project's notes are
// isolated to that project's cwd.

import { existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { memoryNotePath, memoryNotesDir, memoryNotesIndexPath, readTextFile, writePrivateTextFile } from "./storage.ts";

export type MemoryNoteType = "user" | "feedback" | "project" | "reference";

export interface MemoryNote {
	name: string;
	description: string;
	type: MemoryNoteType;
	body: string;
}

export interface MemoryNoteIndexEntry {
	name: string;
	description: string;
	type: MemoryNoteType;
}

const VALID_TYPES: readonly MemoryNoteType[] = ["user", "feedback", "project", "reference"];
const NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_DESCRIPTION_LEN = 200;

export function isValidNoteName(name: string): boolean {
	return NAME_RE.test(name);
}

export function normalizeNoteType(type: string | undefined): MemoryNoteType {
	const t = (type ?? "project").trim().toLowerCase() as MemoryNoteType;
	return VALID_TYPES.includes(t) ? t : "project";
}

function ensureNotesDir(): void {
	if (!existsSync(memoryNotesDir())) mkdirSync(memoryNotesDir(), { recursive: true });
}

function escapeIndexDescription(text: string): string {
	// Keep the index one-line-per-note: collapse newlines/tabs to spaces.
	return text
		.replace(/[\r\n\t]+/g, " ")
		.trim()
		.slice(0, MAX_DESCRIPTION_LEN);
}

function renderNoteFile(note: MemoryNote): string {
	const frontmatter = [
		"---",
		`name: ${note.name}`,
		`description: ${escapeIndexDescription(note.description)}`,
		`metadata:`,
		`  type: ${note.type}`,
		"---",
		"",
		note.body.trimEnd(),
		"",
	].join("\n");
	return frontmatter;
}

function parseNoteFile(content: string, name: string): MemoryNote | null {
	// Tolerant frontmatter parse: extract description + type, body is everything
	// after the closing "---" of the frontmatter block.
	const lines = content.split(/\r?\n/);
	if (lines[0]?.trim() !== "---") return null;
	let end = -1;
	for (let i = 1; i < lines.length; i++) {
		if (lines[i].trim() === "---") {
			end = i;
			break;
		}
	}
	if (end < 0) return null;
	let description = "";
	let type: MemoryNoteType = "project";
	for (let i = 1; i < end; i++) {
		const line = lines[i];
		const descMatch = line.match(/^description:\s*(.*)$/);
		if (descMatch) description = descMatch[1].trim();
		const typeMatch = line.match(/^type:\s*(\w+)\s*$/);
		if (typeMatch) type = normalizeNoteType(typeMatch[1]);
		// metadata may be nested (`  type: ...`); accept that form too.
		const nestedTypeMatch = line.match(/^\s+type:\s*(\w+)\s*$/);
		if (nestedTypeMatch) type = normalizeNoteType(nestedTypeMatch[1]);
	}
	const body = lines
		.slice(end + 1)
		.join("\n")
		.trim();
	return { name, description, type, body };
}

export function writeNote(note: MemoryNote): { ok: boolean; error?: string; path: string } {
	const name = note.name.trim();
	if (!isValidNoteName(name)) {
		return {
			ok: false,
			error: `invalid note name "${name}": must match ${NAME_RE} (lowercase, dash-separated)`,
			path: "",
		};
	}
	const description = escapeIndexDescription(note.description);
	if (!description) {
		return { ok: false, error: "description must be a non-empty one-line summary", path: "" };
	}
	const body = note.body ?? "";
	if (Buffer.byteLength(body, "utf8") > MAX_BODY_BYTES) {
		return { ok: false, error: `note body exceeds ${MAX_BODY_BYTES} bytes`, path: "" };
	}
	const type = normalizeNoteType(note.type);
	ensureNotesDir();
	const path = memoryNotePath(name);
	writePrivateTextFile(path, renderNoteFile({ name, description, type, body }));
	rebuildNoteIndex();
	return { ok: true, path };
}

export function readNote(name: string): MemoryNote | null {
	const path = memoryNotePath(name);
	if (!existsSync(path)) return null;
	return parseNoteFile(readTextFile(path, ""), name);
}

export function deleteNote(name: string): { ok: boolean; error?: string } {
	const path = memoryNotePath(name);
	if (!existsSync(path)) return { ok: false, error: `note "${name}" not found` };
	try {
		rmSync(path, { force: true });
	} catch (error) {
		return { ok: false, error: String((error as Error).message ?? error) };
	}
	rebuildNoteIndex();
	return { ok: true };
}

export function listNotes(): MemoryNoteIndexEntry[] {
	const dir = memoryNotesDir();
	if (!existsSync(dir)) return [];
	const entries: MemoryNoteIndexEntry[] = [];
	for (const file of readdirSync(dir)) {
		if (!file.endsWith(".md")) continue;
		const name = file.slice(0, -3);
		const parsed = parseNoteFile(readTextFile(join(dir, file), ""), name);
		if (parsed) {
			entries.push({ name: parsed.name, description: parsed.description, type: parsed.type });
		}
	}
	entries.sort((a, b) => a.name.localeCompare(b.name));
	return entries;
}

export function rebuildNoteIndex(): void {
	const entries = listNotes();
	const lines = [
		"# Project Memory Index",
		"",
		...entries.map(
			(e) =>
				`- [${e.name}](${encodeURIComponent(`notes/${e.name}.md`)}) — ${e.type}: ${escapeIndexDescription(e.description)}`,
		),
		"",
	];
	writePrivateTextFile(memoryNotesIndexPath(), lines.join("\n"));
}

export function readNoteIndexText(): string {
	return readTextFile(memoryNotesIndexPath(), "");
}

// Bounded preview of the index for context injection: keep it small so it can
// sit in the system prompt without dominating context (mirrors Claude Code's
// MEMORY.md auto-load). Caps notes + total chars.
export function noteIndexForInjection(maxNotes = 40, maxChars = 4000): string {
	const entries = listNotes().slice(0, maxNotes);
	if (entries.length === 0) return "";
	const header = "## Project memory (re_note index)";
	const lines = entries.map((e) => `- [${e.type}] ${e.name} — ${escapeIndexDescription(e.description)}`);
	let body = lines.join("\n");
	if (Buffer.byteLength(body, "utf8") > maxChars) {
		body = `${body.slice(0, maxChars)}\n…(truncated; run re_note list for all)`;
	}
	return `${header}\n${body}`;
}

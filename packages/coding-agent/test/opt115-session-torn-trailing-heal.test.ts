import { appendFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadEntriesFromFile } from "../src/core/session-manager.ts";

const HEADER = '{"type":"session","id":"abc","timestamp":"2025-01-01T00:00:00Z","cwd":"/tmp"}\n';
const ENTRY1 =
	'{"type":"message","id":"1","parentId":null,"timestamp":"2025-01-01T00:00:01Z","message":{"role":"user","content":"first","timestamp":1}}\n';
const ENTRY3 =
	'{"type":"message","id":"3","parentId":"1","timestamp":"2025-01-01T00:00:03Z","message":{"role":"user","content":"third","timestamp":3}}\n';

describe("opt #115 — torn-trailing-line heal in loadEntriesFromFile", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `opt115-torn-${Date.now()}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("heals a torn trailing line so the next append does not fuse and lose entries", () => {
		const file = join(tempDir, "torn.jsonl");
		// Crash mid-appendFileSync left a partial final line with no trailing "\n".
		writeFileSync(file, `${HEADER}${ENTRY1}{"type":"message","id":"2","par`);

		// Load skips the torn trailing line and heals the file on disk.
		const first = loadEntriesFromFile(file);
		expect(first).toHaveLength(2);
		expect(first[0].type).toBe("session");
		expect(first[1].type).toBe("message");

		// The heal re-truncated the file: the torn partial is gone, leaving the
		// parseable entries each on their own line with a trailing newline. The
		// healed file is exactly the two parseable entries re-serialized (the
		// torn entry id "2" is absent).
		const healed = readFileSync(file, "utf8");
		expect(healed).not.toContain('"id":"2"');
		expect(healed.endsWith("\n")).toBe(true);
		expect(healed.split("\n").filter((l) => l.trim()).length).toBe(2);

		// The next append no longer fuses onto the (now-removed) torn partial.
		appendFileSync(file, ENTRY3);

		// Reopen: the third entry survives. Without the heal, the append would
		// have fused with the torn partial into one unparseable line and BOTH the
		// torn entry and the newly-appended third entry would be silently lost.
		const reopened = loadEntriesFromFile(file);
		expect(reopened).toHaveLength(3);
		expect(reopened[2].type).toBe("message");
	});

	it("does not rewrite a clean file (no torn trailing line)", () => {
		const file = join(tempDir, "clean.jsonl");
		writeFileSync(file, HEADER + ENTRY1);
		const before = readFileSync(file, "utf8");
		loadEntriesFromFile(file);
		// A clean file with a trailing newline has no torn partial, so the heal
		// path is not taken and the bytes are unchanged.
		expect(readFileSync(file, "utf8")).toBe(before);
	});
});

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readText } from "../src/core/agent-thread-manager.ts";

// opt #156: agent-thread-manager's readText read the ENTIRE worker
// stdout/stderr log into memory via readFileSync then sliced the tail — so a
// worker agent whose log grew to multiple GB (verbose build, `find /`, a
// chatty loop) OOM-crashed the parent (V8 heap / ERR_FS_FILE_TOO_LARGE) before
// the slice ran. The maxChars cap only bounded the returned string, not the
// allocation. Now: stat first; if size > maxBytes (maxChars*8, 64KB floor),
// open + readSync only the tail bytes (dropping a partial leading UTF-8
// codepoint so the tail doesn't begin with U+FFFD), then slice to maxChars.
// Callers hash/merge the TAIL of worker logs, so tail-read preserves semantics.
//
// readText is exercised in isolation via its named export (test seam). The
// byte cap for maxChars=12000 is 96000, so a 200KB file triggers the tail-read
// path without needing a multi-GB fixture.

describe("readText tail-reads large files without loading them whole (opt #156)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-readtext-156-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("returns the last maxChars of a file larger than the byte cap (no whole-file load)", () => {
		const file = join(dir, "big.log");
		// 200000 bytes of 'X' + an identifiable tail marker. 200000 > 96000 cap.
		writeFileSync(file, `${"X".repeat(200000)}END-MARKER`);
		const got = readText(file, 12000);
		// Bounded to maxChars and ends with the tail marker (tail-read preserved it).
		expect(got.length).toBe(12000);
		expect(got.endsWith("END-MARKER")).toBe(true);
	});

	it("small files (under the byte cap) keep the exact full content", () => {
		const file = join(dir, "small.log");
		const body = "line one\nline two\nline three\n";
		writeFileSync(file, body);
		// maxChars default 12000 >> body length → returns the whole file verbatim.
		expect(readText(file)).toBe(body);
	});

	it("a multi-byte tail boundary does not produce a leading replacement char", () => {
		const file = join(dir, "multi.log");
		// "€" is 3 UTF-8 bytes (E2 82 AC). 40000 '€' = 120000 bytes + 1 'a' =
		// 120001 bytes > 96000 cap. The tail-read offset lands mid-codepoint, so
		// the leading-codepoint skip must advance past the partial char instead
		// of decoding a U+FFFD replacement at the start.
		writeFileSync(file, `${"€".repeat(40000)}a`);
		const got = readText(file, 12000);
		expect(got.length).toBeLessThanOrEqual(12000);
		// No replacement char introduced by a mid-codepoint tail start.
		expect(got.includes("�")).toBe(false);
		// Content is only valid '€' and the trailing 'a'.
		expect(/^€*a?$/.test(got)).toBe(true);
	});

	it("a missing file returns empty string (no throw)", () => {
		expect(readText(join(dir, "nope.log"))).toBe("");
	});
});

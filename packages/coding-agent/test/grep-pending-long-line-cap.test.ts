/**
 * opt #256 — defaultGrepReadLineRange pending buffer grew unbounded on a
 * pathological single line (OOM MED).
 *
 * `pending = Buffer.concat([pending, buf.subarray(0, n)])` accumulated bytes
 * until a newline arrived; `if (lastNl === -1) continue` kept accumulating. A
 * file with one giant line (no newline for MBs — a minified JS file or a binary
 * blob) grew `pending` without bound → OOM-crashed the agent when grep read
 * context lines around a match in such a file.
 *
 * Fix: once GREP_MAX_LINE_BUFFER (64KB) bytes buffer with no newline, emit a
 * head-truncated line and scan forward discarding bytes until the real newline
 * (lineNum stays correct). The caller truncates to GREP_MAX_LINE_LENGTH (500)
 * for display, so the head is far more than the model ever sees.
 */
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultGrepReadLineRange } from "../src/core/tools/grep.ts";

describe("defaultGrepReadLineRange pending long-line cap (opt #256)", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-grep-pending-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("caps a pathological single line and preserves correct line numbering for following lines", () => {
		const file = join(tempDir, "giant.txt");
		// One 1.5MB line (no newline within it — exceeds the 1MB read chunk so the
		// first chunk has no newline, triggering the pending-growth path) followed
		// by a normal line. Pre-fix `pending` accumulated the whole 1.5MB; on a
		// multi-MB/minified line this grew unbounded → OOM.
		const giant = "A".repeat(1_500_000);
		writeFileSync(file, `${giant}\nsecond line\n`);

		const { baseLine, lines } = defaultGrepReadLineRange(file, 1, 2);

		expect(baseLine).toBe(1);
		// The giant line is head-truncated to GREP_MAX_LINE_BUFFER (64KB), NOT
		// returned in full (pre-fix this was 1_500_000 chars).
		expect(lines[0].length).toBeLessThanOrEqual(70_000);
		expect(lines[0].startsWith("AAAA")).toBe(true);
		// lineNum stayed correct: the second line is at index 1, intact.
		expect(lines[1]).toBe("second line");
	});

	it("leaves normal short lines untouched", () => {
		const file = join(tempDir, "normal.txt");
		writeFileSync(file, "alpha\nbeta\ngamma\n");

		const { baseLine, lines } = defaultGrepReadLineRange(file, 1, 3);

		expect(baseLine).toBe(1);
		expect(lines).toEqual(["alpha", "beta", "gamma"]);
	});
});

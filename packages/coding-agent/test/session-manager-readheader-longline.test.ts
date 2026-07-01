import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readSessionHeader } from "../src/core/session-manager.ts";

// opt #157: readSessionHeader read only the first 512 bytes via a fixed
// readSync(fd, buffer, 0, 512, 0) → buffer.toString().split("\n")[0] → JSON.parse.
// A long header line (deep cwd + full-path parentSession, which the writer
// stores at persist/fork/resume sites) exceeds 512 bytes → the read truncated
// it mid-JSON → JSON.parse threw → catch returned null → the session was
// silently dropped from findMostRecentSession's --continue/--resume auto-pick.
// Now: read the first line in a loop until a newline, EOF, or a 16 KB cap.
//
// A header whose serialized first line is ~700 bytes (long cwd + long
// parentSession) reproduces the truncation: under the old 512-byte read the
// JSON is split mid-string → JSON.parse throws → null. The fixed loop reads
// past 512 to the newline and parses cleanly.

describe("readSessionHeader reads long first lines past 512 bytes (opt #157)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-session-header-157-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("parses a header whose first line exceeds 512 bytes", () => {
		// Long cwd + long parentSession path → serialized first line ~700 bytes.
		const longCwd = "/".repeat(300);
		const longParent = "/".repeat(300);
		const header = {
			type: "session",
			version: 1,
			id: "abc-123",
			timestamp: "2026-06-28T00:00:00.000Z",
			cwd: longCwd,
			parentSession: longParent,
		};
		const file = join(dir, "long.jsonl");
		// First line is the header JSON; a second line proves we stop at \n.
		writeFileSync(file, `${JSON.stringify(header)}\n{"role":"user"}\n`);

		const got = readSessionHeader(file);
		expect(got).not.toBeNull();
		expect(got?.id).toBe("abc-123");
		expect(got?.cwd).toBe(longCwd);
		expect(got?.parentSession).toBe(longParent);

		// Sanity: the serialized first line really did exceed 512 bytes, so the
		// old fixed read would have truncated it.
		expect(JSON.stringify(header).length).toBeGreaterThan(512);
	});

	it("still parses a short header (under 512 bytes)", () => {
		const header = {
			type: "session",
			id: "short-1",
			timestamp: "2026-06-28T00:00:00.000Z",
			cwd: "/tmp",
		};
		const file = join(dir, "short.jsonl");
		writeFileSync(file, `${JSON.stringify(header)}\n`);
		const got = readSessionHeader(file);
		expect(got?.id).toBe("short-1");
	});

	it("returns null for a header line that hits the 16 KB cap with no newline", () => {
		// A 16 KB+ first line with no newline is pathological; the loop bails at
		// the cap rather than reading unbounded.
		const file = join(dir, "huge.jsonl");
		writeFileSync(file, `${"{".repeat(20 * 1024)}`);
		expect(readSessionHeader(file)).toBeNull();
	});

	it("returns null for a missing file (no throw)", () => {
		expect(readSessionHeader(join(dir, "nope.jsonl"))).toBeNull();
	});
});

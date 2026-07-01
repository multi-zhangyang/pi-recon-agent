import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashFileSha256 } from "../src/core/repi/text.ts";

// opt #158: 5 host-code sites in recon-profile.ts hashed artifact files via
// createHash("sha256").update(readFileSync(path)).digest("hex") — reading the
// ENTIRE file into memory. A multi-GB artifact (memory dump, captured binary,
// coredump, large replay/compiler artifact) OOM-crashed (V8 heap /
// ERR_FS_FILE_TOO_LARGE) before the digest ran. hashFileSha256 stat-firsts:
// small files (<=1 MB) keep the fast readFileSync path; larger files stream
// through the hash in 1 MB positioned-readSync chunks, so memory stays bounded
// to one chunk. The digest covers ALL bytes, so it's byte-identical to the old
// whole-file hash. This test pins correctness for real files of varying sizes
// (incl. chunk-boundary and multi-byte cases).

function refHash(path: string): string {
	// Reference: whole-file readFileSync hash (the old behavior). Safe at test
	// scales (a few MB) — this is the value the new chunked path must reproduce.
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

describe("hashFileSha256 matches whole-file hash across sizes (opt #158)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-hashfile-158-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("small file (under 1 MB fast path) — byte-identical to readFileSync hash", () => {
		const file = join(dir, "small.bin");
		writeFileSync(file, Buffer.from("hello repi artifact", "utf8"));
		expect(hashFileSha256(file)).toBe(refHash(file));
	});

	it("large file (2.5 MB, chunked path) — byte-identical to readFileSync hash", () => {
		const file = join(dir, "large.bin");
		// 2.5 MB of pseudo-random-but-deterministic bytes spanning 2 full chunks + a tail.
		const buf = Buffer.alloc(2_500_000);
		for (let i = 0; i < buf.length; i++) buf[i] = (i * 31 + 7) & 0xff;
		writeFileSync(file, buf);
		expect(hashFileSha256(file)).toBe(refHash(file));
	});

	it("chunk-boundary sizes (exactly 1 MB and 2 MB) — byte-identical", () => {
		for (const size of [1024 * 1024, 2 * 1024 * 1024]) {
			const file = join(dir, `boundary-${size}.bin`);
			const buf = Buffer.alloc(size);
			for (let i = 0; i < buf.length; i++) buf[i] = (i ^ 0xaa) & 0xff;
			writeFileSync(file, buf);
			expect(hashFileSha256(file), `size=${size}`).toBe(refHash(file));
		}
	});

	it("multi-byte content split across a chunk boundary — byte-identical", () => {
		// Fill with a 3-byte UTF-8 char ("€" = E2 82 AC) so chunk edges land
		// mid-codepoint; update() is byte-wise so the hash must still match.
		const file = join(dir, "multi.bin");
		const buf = Buffer.from("€".repeat(400_000), "utf8"); // 1_200_000 bytes → chunked path
		writeFileSync(file, buf);
		expect(hashFileSha256(file)).toBe(refHash(file));
	});
});

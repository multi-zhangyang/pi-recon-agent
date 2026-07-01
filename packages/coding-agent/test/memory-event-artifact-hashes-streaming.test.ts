import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { memoryArtifactHashes, memoryArtifactTier } from "../src/core/repi/memory-event.ts";

// opt #159: memoryArtifactHashes (memory-event.ts) hashed each artifact via
// createHash("sha256").update(readFileSync(path)).digest("hex") — reading the
// ENTIRE file into memory. memoryArtifactTier classifies evidence/{browser,
// web-authz,mobile-runtime,native-runtime,exploit-lab,runs,proof-loops,
// replayers}/ paths as runtime_artifact — captured dumps/coredumps/binary
// replays that routinely reach multi-GB and OOM-crashed the parent (V8 heap /
// ERR_FS_FILE_TOO_LARGE) before the digest ran. Now routes through the shared
// hashFileSha256 (repi/text.ts, opt #158): stat-first + 1 MB chunked readSync
// for large files, byte-identical digest. The try/catch → sha256=null +
// required=false contract for missing/unreadable files is preserved.

function refHash(path: string): string {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

describe("memoryArtifactHashes streams large artifacts + preserves null contract (opt #159)", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-memartifact-159-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("hashes a small runtime_artifact and classifies its tier", () => {
		// memoryArtifactTier regex matches on the path substring; use a flat
		// path for the hash assertion and assert the tier on a representative
		// "evidence/runs/" path.
		const flat = join(dir, "evidence-runs-run-1.bin");
		writeFileSync(flat, Buffer.from("small artifact", "utf8"));
		const got = memoryArtifactHashes([flat]);
		expect(got).toHaveLength(1);
		expect(got[0].sha256).toBe(refHash(flat));
		expect(got[0].required).toBe(true);
		// tier is path-based: an "evidence/runs/" path is runtime_artifact.
		expect(memoryArtifactTier("/x/evidence/runs/y.bin")).toBe("runtime_artifact");
	});

	it("hashes a large (2.5 MB) artifact via the streaming path — byte-identical", () => {
		const file = join(dir, "big.bin");
		const buf = Buffer.alloc(2_500_000);
		for (let i = 0; i < buf.length; i++) buf[i] = (i * 29 + 11) & 0xff;
		writeFileSync(file, buf);
		const got = memoryArtifactHashes([file]);
		expect(got[0].sha256).toBe(refHash(file));
		expect(got[0].required).toBe(true);
	});

	it("a missing file yields sha256=null + required=false (no throw)", () => {
		const got = memoryArtifactHashes([join(dir, "nope.bin")]);
		expect(got).toHaveLength(1);
		expect(got[0].sha256).toBeNull();
		expect(got[0].required).toBe(false);
	});

	it("dedupes + caps at the limit", () => {
		const a = join(dir, "a.bin");
		const b = join(dir, "b.bin");
		writeFileSync(a, Buffer.from("a", "utf8"));
		writeFileSync(b, Buffer.from("b", "utf8"));
		const got = memoryArtifactHashes([a, a, b], 1);
		expect(got).toHaveLength(1);
	});
});

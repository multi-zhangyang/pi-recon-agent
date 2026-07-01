import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { memoryDistillSnippetFromArtifacts } from "../src/core/repi/memory-distill.ts";
import type { MemoryArtifactHash } from "../src/core/repi/memory-event.ts";

// Foundational opt #267: memoryDistillSnippetFromArtifacts read each referenced
// artifact body via bare readFileSync (no stat guard) → a multi-hundred-MB
// artifact (memory dump, pcap, firmware, coredump) loaded the WHOLE file into
// the V8 heap before truncateMiddle → OOM-spike, OR threw ERR_FS_FILE_TOO_LARGE
// swallowed by catch {} → snippet silently dropped, degrading distillation
// routing with no error surfaced. Routed through the stat-guarded readTextFile
// (16MB cap, REPI_READ_TEXT_FILE_MAX_BYTES; returns "" for oversized) and the
// snippet skipped when no usable body is returned. Same class as opt #34/#163.

describe("memoryDistillSnippetFromArtifacts stat-guards oversized artifacts (opt #267)", () => {
	let dir: string;
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "repi-distill-snippet-267-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
		delete process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
	});

	function ref(path: string): MemoryArtifactHash {
		return { path } as MemoryArtifactHash;
	}

	it("produces a path+truncated-body snippet for a small artifact", () => {
		const file = join(dir, "note.txt");
		writeFileSync(file, "the quick brown fox jumps over the lazy dog");
		const snippet = memoryDistillSnippetFromArtifacts([ref(file)], 700);
		expect(snippet).toContain(file);
		expect(snippet).toContain("the quick brown fox");
	});

	it("skips (does NOT OOM / does NOT throw) an oversized artifact via the stat guard", () => {
		// Use a tiny cap so we can exercise the guard without writing 16MB.
		process.env.REPI_READ_TEXT_FILE_MAX_BYTES = "64";
		const file = join(dir, "big.bin");
		// 4KB binary artifact — over the 64-byte cap → readTextFile returns "".
		writeFileSync(file, Buffer.alloc(4096, 0x41));
		// Pre-fix: bare readFileSync loaded the whole file (ok at 4KB, but at
		// >16MB it OOM'd; at >512MB it threw ERR_FS_FILE_TOO_LARGE swallowed).
		// Post-fix: stat guard returns "" → snippet skipped, no crash, no throw.
		const snippet = memoryDistillSnippetFromArtifacts([ref(file)], 700);
		expect(snippet).toBe("");
	});

	it("skips a missing artifact path without throwing", () => {
		const snippet = memoryDistillSnippetFromArtifacts([ref(join(dir, "nope.txt"))], 700);
		expect(snippet).toBe("");
	});

	it("mixes small + oversized: only the small artifact contributes a snippet", () => {
		process.env.REPI_READ_TEXT_FILE_MAX_BYTES = "64";
		const small = join(dir, "small.txt");
		writeFileSync(small, "small content here");
		const big = join(dir, "big.bin");
		writeFileSync(big, Buffer.alloc(4096, 0x41));
		const snippet = memoryDistillSnippetFromArtifacts([ref(big), ref(small)], 700);
		// The oversized artifact is skipped; the small one contributes.
		expect(snippet).not.toContain(big);
		expect(snippet).toContain(small);
		expect(snippet).toContain("small content here");
	});
});

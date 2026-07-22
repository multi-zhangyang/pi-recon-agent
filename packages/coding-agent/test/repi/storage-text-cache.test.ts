import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// readTextFileCached calls readFileSync only on a cache miss. Proving that via
// an ESM namespace spy is impossible (module namespace isn't configurable), so
// vi.mock the fs module with a readFileSync wrapper that delegates to the real
// impl but counts calls. statSync stays real so mtime/size invalidation behaves
// identically. vi.hoisted keeps the counter reference available inside the
// hoisted vi.mock factory.
const { readFileSyncCalls } = vi.hoisted(() => ({ readFileSyncCalls: { current: 0 } }));
vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return {
		...actual,
		readFileSync: vi.fn((...args: Parameters<typeof actual.readFileSync>) => {
			readFileSyncCalls.current++;
			return actual.readFileSync(...args);
		}),
	};
});

const { mkdirSync, rmSync, writeFileSync } = await import("node:fs");
const { readTextFileCached } = await import("../../src/core/repi/storage.ts");

// readTextFileCached is the mtime+size-keyed cache of readTextFile. It pays one
// stat(2) per call and re-reads only when the file changes. Load-bearing
// behaviors: (1) returns the file text (+ fallback default),
// (2) picks up changes (mtime+size invalidation — does NOT cache forever),
// (3) fallback on missing file (and a later write is observed), (4) repeat reads
// skip readFileSync (the within-call double-read + cross-tool-result re-reads).

describe("repi/storage readTextFileCached", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-text-cache-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("returns the file text and matches a fresh read", () => {
		const path = join(tempDir, "report.md");
		writeFileSync(path, "# Core\n\n- fact one\n- fact two\n");
		expect(readTextFileCached(path)).toBe("# Core\n\n- fact one\n- fact two\n");
		// second call returns the same text (cache hit path)
		expect(readTextFileCached(path)).toBe("# Core\n\n- fact one\n- fact two\n");
	});

	it("honors a custom fallback (and the default is empty string)", () => {
		const path = join(tempDir, "absent.md");
		expect(readTextFileCached(path)).toBe("");
		expect(readTextFileCached(path, "fallback")).toBe("fallback");
	});

	it("invalidates on file change (picks up a new write rather than returning the stale cached text)", async () => {
		const path = join(tempDir, "project.md");
		writeFileSync(path, "v1\n");
		expect(readTextFileCached(path)).toBe("v1\n");
		// mtime resolution can be ms on modern filesystems; bump mtime explicitly.
		await new Promise((resolve) => setTimeout(resolve, 5));
		writeFileSync(path, "v2\n");
		expect(readTextFileCached(path)).toBe("v2\n");
	});

	it("returns fallback for a missing file (and a later write is observed)", () => {
		const path = join(tempDir, "absent.md");
		expect(readTextFileCached(path)).toBe("");
		writeFileSync(path, "appeared\n");
		expect(readTextFileCached(path)).toBe("appeared\n");
	});

	it("serves repeat reads from the cache (no readFileSync on a cache hit — regression: was read per call)", () => {
		// A cache hit must skip readFileSync entirely (one stat(2) only). The mocked
		// readFileSync counter proves the 2nd..Nth calls
		// don't re-read, then a re-write (mtime change) proves invalidation re-reads
		// exactly once more.
		const path = join(tempDir, "steps.md");
		writeFileSync(path, "step one\nstep two\n");
		readFileSyncCalls.current = 0;
		expect(readTextFileCached(path)).toBe("step one\nstep two\n"); // miss
		expect(readTextFileCached(path)).toBe("step one\nstep two\n"); // hit
		expect(readTextFileCached(path)).toBe("step one\nstep two\n"); // hit
		expect(readTextFileCached(path)).toBe("step one\nstep two\n"); // hit
		// 4 calls, 1 readFileSync — the within-call double-read + cross-call re-reads
		// all hit the cache.
		expect(readFileSyncCalls.current).toBe(1);
	});
});

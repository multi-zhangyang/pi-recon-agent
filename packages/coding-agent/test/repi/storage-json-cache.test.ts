import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// readJsonObjectFileCached calls readFileSync only on a cache miss. Proving
// that via an ESM namespace spy is impossible (module namespace isn't
// configurable), so vi.mock the fs module with a readFileSync wrapper that
// delegates to the real impl but counts calls. statSync stays real so mtime/size
// invalidation behaves identically. vi.hoisted keeps the counter reference
// available inside the hoisted vi.mock factory.
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
const { readJsonObjectFileCached } = await import("../../src/core/repi/storage.ts");

// readJsonObjectFileCached is the mtime+size-keyed cache of readJsonObjectFile.
// Repeated mission reads pay one stat(2) per call and only re-read+re-parse when
// the file changes. The load-bearing behaviors: (1) returns the parsed value,
// (2) picks up changes (mtime+size invalidation — does NOT cache forever),
// (3) undefined on missing/invalid JSON, (4) invalid JSON is not cached so a
// subsequent valid write is observed.

describe("repi/storage readJsonObjectFileCached", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-json-cache-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("returns the parsed object and matches a fresh read", () => {
		const path = join(tempDir, "settings.json");
		writeFileSync(path, JSON.stringify({ ui: { density: "compact" }, n: 1 }));
		expect(readJsonObjectFileCached<Record<string, unknown>>(path)).toEqual({ ui: { density: "compact" }, n: 1 });
		// second call returns the same value (cache hit path)
		expect(readJsonObjectFileCached<Record<string, unknown>>(path)).toEqual({ ui: { density: "compact" }, n: 1 });
	});

	it("invalidates on file change (picks up a new write rather than returning the stale cached value)", async () => {
		const path = join(tempDir, "settings.json");
		writeFileSync(path, JSON.stringify({ n: 1 }));
		expect(readJsonObjectFileCached<Record<string, unknown>>(path)).toEqual({ n: 1 });
		// mtime resolution can be ms on modern filesystems; bump mtime explicitly.
		await new Promise((resolve) => setTimeout(resolve, 5));
		writeFileSync(path, JSON.stringify({ n: 2 }));
		expect(readJsonObjectFileCached<Record<string, unknown>>(path)).toEqual({ n: 2 });
	});

	it("returns undefined for a missing file (and a later write is observed)", () => {
		const path = join(tempDir, "absent.json");
		expect(readJsonObjectFileCached<Record<string, unknown>>(path)).toBeUndefined();
		writeFileSync(path, JSON.stringify({ appeared: true }));
		expect(readJsonObjectFileCached<Record<string, unknown>>(path)).toEqual({ appeared: true });
	});

	it("does not cache invalid JSON (a subsequent valid write is picked up)", async () => {
		const path = join(tempDir, "corrupt.json");
		writeFileSync(path, "{ not valid json");
		expect(readJsonObjectFileCached<Record<string, unknown>>(path)).toBeUndefined();
		await new Promise((resolve) => setTimeout(resolve, 5));
		writeFileSync(path, JSON.stringify({ fixed: true }));
		expect(readJsonObjectFileCached<Record<string, unknown>>(path)).toEqual({ fixed: true });
	});

	it("serves repeat reads from the cache (no readFileSync on a cache hit — regression: was read+parse per call)", () => {
		// A cache hit must skip readFileSync+JSON.parse entirely (one stat(2)
		// only). The mocked readFileSync counter proves the second/third calls do
		// not re-read.
		const path = join(tempDir, "settings.json");
		writeFileSync(path, JSON.stringify({ n: 1 }));
		readFileSyncCalls.current = 0;
		readJsonObjectFileCached<Record<string, unknown>>(path); // miss
		readJsonObjectFileCached<Record<string, unknown>>(path); // hit
		readJsonObjectFileCached<Record<string, unknown>>(path); // hit
		expect(readFileSyncCalls.current).toBe(1);
	});
});

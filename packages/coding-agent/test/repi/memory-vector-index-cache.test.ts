import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #76 — vector index cache. searchMemoryVectors runs on every tool_result (via
// searchMemoryEvents → buildPerTurnMemoryRecall) and called buildMemoryVectorIndex every
// time, which (1) recomputed embeddings for ALL events (O(events) CPU) AND (2) atomic-rewrote
// the index file (vector-index.json) via writeFileAtomic (temp+rename) every tool_result —
// O(index) disk write of UNCHANGED state (the index is a pure function of events, which only
// change on deposit). #76 caches the built index by events.jsonl mtime+size + embedding
// provider key: a cache hit returns the cached index (0 recompute, 0 write — the index file
// already matches the cached index from the last miss's writeFileAtomic; no reader reads the
// index file content, reports reference only its path). A deposit bumps events.jsonl mtime →
// miss → rebuild + rewrite + re-cache → recall sees the post-deposit index.
//
// These tests prove (1) repeat searchMemoryVectors calls do NOT rewrite the index file (0
// renames onto vector-index.json across N calls once warm — the load-bearing #76 proof that
// buildMemoryVectorIndex is skipped on a hit), (2) a new deposit invalidates (the next search
// rewrites the index + sees the new event), and (3) the cached index returns correct hits
// (the cache doesn't corrupt search results).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { indexRenameCount } = vi.hoisted(() => ({ indexRenameCount: { current: 0 } }));

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return {
		...actual,
		// writeFileAtomic (memory-store.ts) does writePrivateTextFile(tmp) + renameSync(tmp, path).
		// The final rename destination is vector-index.json — one per buildMemoryVectorIndex call.
		// A cache hit skips buildMemoryVectorIndex entirely → 0 renames onto vector-index.json.
		renameSync: vi.fn((...args: Parameters<typeof actual.renameSync>) => {
			if (String(args[1]).endsWith("vector-index.json")) indexRenameCount.current++;
			return actual.renameSync(...args);
		}),
	};
});

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { searchMemoryVectors } = await import("../../src/core/repi/memory-vector.ts");

describe("repi/memory-vector index cache (opt #76)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-vector-cache-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
		indexRenameCount.current = 0;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("repeat searchMemoryVectors calls do NOT rewrite the index file (0 renames once warm)", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "vector cache test rop gadget",
			route: "re",
			outcome: "success",
			lessons: ["use ropper for gadgets"],
			commands: ["ropper --file b"],
		});
		// First call is a cold miss → buildMemoryVectorIndex writes the index (1 rename) + warms
		// the cache. Reset AFTER the warm so we measure only the repeat calls.
		searchMemoryVectors("rop gadget", { route: "re" });
		indexRenameCount.current = 0;
		// Four more calls with unchanged events → all cache hits → buildMemoryVectorIndex is
		// skipped → 0 renames onto vector-index.json. (Temp-neuter the cache → each call rebuilds
		// + rewrites → 4 renames, failing `=== 0` — the load-bearing #76 proof.)
		searchMemoryVectors("rop gadget", { route: "re" });
		searchMemoryVectors("rop gadget", { route: "re" });
		searchMemoryVectors("libc chain", { route: "re" });
		searchMemoryVectors("ret2libc", { route: "re" });
		expect(indexRenameCount.current).toBe(0);
	});

	it("a new deposit invalidates the cache (next search rewrites the index + sees the new event)", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "v1 gadget",
			route: "re",
			outcome: "success",
		});
		searchMemoryVectors("v1 gadget", { route: "re" }); // cold miss → build + write + cache
		indexRenameCount.current = 0;
		// A second deposit writes events.jsonl (atomic temp+rename → mtime+size change) → the
		// index cache must miss and the next search rebuilds + rewrites + sees the new event.
		appendMemoryEventTransaction({
			source: "manual",
			task: "v2 heap overflow",
			route: "re",
			outcome: "success",
		});
		const after = searchMemoryVectors("heap overflow", { route: "re" });
		expect(indexRenameCount.current).toBe(1); // miss → one rewrite
		// The post-deposit index includes the new event (cache didn't serve a stale index).
		expect(after.hits.some((hit) => hit.eventId !== undefined)).toBe(true);
	});

	it("the cached index returns correct hits (cache doesn't corrupt search results)", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "format string vulnerability",
			route: "re",
			outcome: "success",
			lessons: ["use %n for write primitive"],
		});
		const first = searchMemoryVectors("format string", { route: "re" });
		// Second call hits the cache → must return the SAME hits (the cached index is correct).
		const second = searchMemoryVectors("format string", { route: "re" });
		expect(second.hits.length).toBe(first.hits.length);
		expect(second.hits.map((hit) => hit.eventId)).toEqual(first.hits.map((hit) => hit.eventId));
	});
});

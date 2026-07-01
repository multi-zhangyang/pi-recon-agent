import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// jsonlRecords/jsonlScan (repi/jsonl.ts) are called on the per-tool-result memory-recall
// hot path: searchMemoryEvents → readMemoryEvents (events.jsonl) + latestCaseMemoryBySignature
// (case-memory.jsonl) + latestMemoryQualityByEvent (quality ledger) + memoryBlockingGovernance
// BySource (governance ledger) + searchMemoryVectors (re-reads events for the vector index).
// That is 4-5 JSONL file reads on EVERY tool_result when stats.active, of files that only
// change on deposit/governance/quality ops (NOT per tool result). Over a session that is
// thousands of full-file reads + JSON.parses of growing files.
//
// The fix: jsonl.ts's internal readText now delegates to readTextFileCached (the mtime+size
// cache from opt #68) instead of raw readFileSync. One stat(2) per call; on a cache hit
// (mtime+size unchanged) the readFileSync is skipped entirely — the per-call JSON.parse
// still runs, so callers get freshly-parsed rows (no shared-reference mutation risk). On a
// deposit tool_result the append writes events.jsonl BEFORE the recall read (handler order:
// trace → auto-deposit → recall), bumping mtime → cache miss → recall sees post-deposit
// state. The tool-trace ledger (changes every tool call) does NOT use jsonl.ts — it has its
// own uncached reader — so the always-changing hot file is unaffected.
//
// These tests prove (1) repeat reads skip readFileSync, (2) a new append is picked up (not
// stale), (3) missing files fall back and a later append is observed, and (4) the REAL
// searchMemoryEvents recall path re-reads events.jsonl only once across N calls. Events are
// seeded via the real appendMemoryEventTransaction so the MemoryEventV1 shape (scope, hash)
// is valid end-to-end.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { eventsReadCount } = vi.hoisted(() => ({ eventsReadCount: { current: 0 } }));

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return {
		...actual,
		readFileSync: vi.fn((...args: Parameters<typeof actual.readFileSync>) => {
			if (String(args[0]).endsWith("events.jsonl")) eventsReadCount.current++;
			return actual.readFileSync(...args);
		}),
	};
});

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { searchMemoryEvents } = await import("../../src/core/repi/memory-recall.ts");
const { readMemoryEvents } = await import("../../src/core/repi/memory-search.ts");

describe("repi/jsonl cached read on the memory-recall hot path", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-jsonl-cache-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
		eventsReadCount.current = 0;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("readMemoryEvents serves repeat reads from the cache (0 readFileSync across N calls once warm)", () => {
		appendMemoryEventTransaction({ source: "manual", task: "cache-test", route: "re", outcome: "success" });
		// Reset after the append. The append's post-commit verification (jsonlScan of events)
		// warms the mtime+size cache with the post-append text, so the recall-path reads that
		// follow are cache hits — 0 readFileSync. (Temp-neuter to raw readFileSync → 4 reads,
		// one per call, failing this assertion: the load-bearing proof.)
		eventsReadCount.current = 0;
		expect(readMemoryEvents()).toHaveLength(1);
		readMemoryEvents();
		readMemoryEvents();
		readMemoryEvents();
		// 4 calls, 0 readFileSync — every call hit the cache warmed by the append.
		expect(eventsReadCount.current).toBe(0);
		expect(readMemoryEvents()).toHaveLength(1);
		expect(eventsReadCount.current).toBe(0);
	});

	it("readMemoryEvents picks up a new append (mtime invalidation — not stale)", () => {
		appendMemoryEventTransaction({ source: "manual", task: "v1", route: "re", outcome: "success" });
		expect(readMemoryEvents()).toHaveLength(1);
		// A second append writes events.jsonl (atomic temp+rename → mtime+size change) → the
		// cache must miss and the next read sees the new event, not the stale 1-row cache.
		appendMemoryEventTransaction({ source: "manual", task: "v2", route: "re", outcome: "success" });
		const after = readMemoryEvents();
		expect(after).toHaveLength(2);
	});

	it("readMemoryEvents returns [] for a missing events file (and a later append is observed)", () => {
		expect(readMemoryEvents()).toEqual([]);
		appendMemoryEventTransaction({ source: "manual", task: "appear", route: "re", outcome: "success" });
		expect(readMemoryEvents()).toHaveLength(1);
	});

	it("searchMemoryEvents (the recall hot path) re-reads events.jsonl only once across N calls", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "exploit rop gadget",
			route: "re",
			outcome: "success",
			lessons: ["use ropper"],
			commands: ["ropper --file b"],
		});
		// Reset after the append so we measure ONLY the recall-path reads. The append's
		// post-commit verification warms the events cache, so the recall path that follows
		// hits the cache — the per-tool-result recall read-amplification is eliminated when
		// the store is unchanged since the last deposit/verify (the majority of tool results).
		eventsReadCount.current = 0;
		// Three back-to-back recalls (as happens on consecutive tool_results with no deposit
		// between them). All three hit the cache → 0 events.jsonl reads. (Temp-neuter to raw
		// readFileSync → 6 reads, 2 per search × 3, failing this assertion.)
		searchMemoryEvents("rop gadget", { route: "re" });
		searchMemoryEvents("rop gadget", { route: "re" });
		searchMemoryEvents("rop gadget", { route: "re" });
		expect(eventsReadCount.current).toBe(0);
	});
});

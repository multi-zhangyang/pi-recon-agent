import { mkdirSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// F1 (MED CRASH): searchMemoryEvents wrote retrieval-report.json via raw writeFileSync
// (truncate-then-write). A crash mid-write left a truncated file; readJsonObjectFile swallows
// the parse failure → returns undefined → retrieval report silently lost. Fix: route through
// writePrivateTextFile (atomic temp+rename, 0o600). temp+rename replaces the inode; the old
// truncate-then-write kept it — the inode-change assertion is the regression probe.
//
// F6 (HIGH PERF): the per-tool-result recall path re-verified the events hash chain from genesis
// on EVERY call via memoryEventHashChainOk(events) — O(N) JSON.stringify+sha256 per event per
// call, O(R·N) over R tool results. The #84 cache (cachedMemoryEventHashChainOk) is
// mtime+size-guarded keyed by memoryEventsPath(); on a hit it skips the re-walk. The reads below
// it are already cached (#74 jsonl parsed cache), so the load-bearing cost is the WALK — the
// proof counts memoryEventHashChainOk invocations: the first call walks (1), the second cache-
// hits (0). Temp-neuter the hit guard → the second call re-walks → the walk-count assertion fails.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { hashChainWalkCount } = vi.hoisted(() => ({
	hashChainWalkCount: { current: 0 },
}));

vi.mock("../../src/core/repi/memory-event.ts", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../../src/core/repi/memory-event.ts")>();
	return {
		...actual,
		memoryEventHashChainOk: vi.fn((...args: Parameters<typeof actual.memoryEventHashChainOk>) => {
			hashChainWalkCount.current++;
			return actual.memoryEventHashChainOk(...args);
		}),
	};
});

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { cachedMemoryEventHashChainOk, invalidateMemoryEventHashChainCache, searchMemoryEvents } = await import(
	"../../src/core/repi/memory-recall.ts"
);
const { memoryRetrievalReportPath } = await import("../../src/core/repi/storage.ts");

describe("repi/memory-recall F1 retrieval-report atomic write + F6 hash-chain cache", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-recall-atomic-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
		hashChainWalkCount.current = 0;
		invalidateMemoryEventHashChainCache();
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("F1: retrieval-report.json is written atomically (inode changes on rewrite, valid JSON, 0o600)", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "exploit rop gadget",
			route: "re",
			outcome: "success",
			commands: ["ropper --file b"],
		});
		const reportPath = memoryRetrievalReportPath();
		// First call creates the report.
		searchMemoryEvents("rop", { route: "re" });
		expect(statSync(reportPath).mode & 0o777).toBe(0o600);
		const inodeBefore = statSync(reportPath).ino;
		const firstContent = readFileSync(reportPath, "utf8");

		// A rewrite via temp+rename installs a NEW inode. The old truncate-then-write
		// (writeFileSync) kept the SAME inode — this assertion fails if the write regresses.
		searchMemoryEvents("rop", { route: "re" });
		const inodeAfter = statSync(reportPath).ino;
		expect(inodeAfter).not.toBe(inodeBefore);
		expect(statSync(reportPath).mode & 0o777).toBe(0o600);
		// No stray temp files left in the memory dir.
		expect(readdirSync(dirname(reportPath)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
		// Content is complete + valid JSON with the hashChainOk field (not truncated).
		const parsed = JSON.parse(readFileSync(reportPath, "utf8"));
		expect(parsed.kind).toBe("repi-memory-retrieval-report");
		expect(typeof parsed.hashChainOk).toBe("boolean");
		// Byte-identical hit count across rewrites (same query → same hits modulo generatedAt).
		expect(parsed.hits.length).toBe(JSON.parse(firstContent).hits.length);
	});

	it("F6: cachedMemoryEventHashChainOk skips the re-walk on a cache hit (walk count), invalidates on deposit", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "exploit rop gadget",
			route: "re",
			outcome: "success",
		});
		invalidateMemoryEventHashChainCache();
		// First call: cache miss → walk the chain (memoryEventHashChainOk invoked once) + cache.
		hashChainWalkCount.current = 0;
		const ok1 = cachedMemoryEventHashChainOk();
		expect(ok1).toBe(true);
		expect(hashChainWalkCount.current).toBe(1);

		// Second call: cache hit (stat mtime+size unchanged) → NO re-walk (0 invocations).
		hashChainWalkCount.current = 0;
		const ok2 = cachedMemoryEventHashChainOk();
		expect(ok2).toBe(ok1);
		// Temp-neuter the hit guard (`if (false && cached...)`) → the second call re-walks →
		// walkCount >= 1 → this assertion fails.
		expect(hashChainWalkCount.current).toBe(0);

		// A deposit rewrites events.jsonl (atomic temp+rename → mtime+size change) → cache
		// invalidates → the next call re-walks (not stale).
		appendMemoryEventTransaction({
			source: "manual",
			task: "heap tcache poisoning",
			route: "re",
			outcome: "success",
		});
		hashChainWalkCount.current = 0;
		const ok3 = cachedMemoryEventHashChainOk();
		expect(ok3).toBe(true);
		expect(hashChainWalkCount.current).toBe(1);
	});
});

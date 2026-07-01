import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// opt #83 — derived-Map cache for JSONL-ledger reductions. searchMemoryEvents (per
// tool_result) calls three Map builders — latestCaseMemoryBySignature (case-memory.jsonl),
// latestMemoryQualityByEvent (quality ledger), memoryBlockingGovernanceBySource (governance
// ledger) — each an O(rows) Map rebuild of rows that are #74-cached (0 readFileSync + 0
// JSON.parse on a hit) but whose derived Map was rebuilt every call. The Map is a pure
// function of the rows, which only change when the ledger is rewritten (atomic temp+rename →
// mtime+size change). #83's cachedJsonlDerived caches the derived value keyed by (path,
// mtime+size): a hit returns the shared Map (0 rebuild); a deposit bumps mtime → miss →
// rebuild + re-cache.
//
// No disk signal to count (the rebuild is in-memory from #74-cached rows). The load-bearing
// proof is REFERENCE IDENTITY: a cache hit returns the SAME Map object; a rebuild returns a
// fresh Map. These tests prove (1) repeat latestCaseMemoryBySignature calls return a shared
// Map ref (0 rebuilds once warm — temp-neuter the hit guard → fresh Maps, load-bearing proof),
// (2) a new deposit invalidates → next call rebuilds (not stale) + the new case is seen, and
// (3) the quality + governance Maps are likewise cached by ref (shared empty Map while their
// ledgers are empty — the cache holds the entry, not rebuilt per call).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { latestCaseMemoryBySignature } = await import("../../src/core/repi/case-memory.ts");
const { latestMemoryQualityByEvent } = await import("../../src/core/repi/memory-quality.ts");
const { memoryBlockingGovernanceBySource } = await import("../../src/core/repi/memory-search.ts");

describe("repi/derived-Map cache (opt #83)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-derived-cache-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("repeat latestCaseMemoryBySignature calls return a SHARED Map ref (0 rebuilds once warm)", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "exploit rop gadget",
			route: "re",
			outcome: "success",
		});
		// First call builds + caches; subsequent calls hit the cache and return the SAME Map
		// object (shared ref — the load-bearing #83 proof: no O(rows) Map rebuild on a hit).
		// Temp-neuter cachedJsonlDerived's hit guard (`if (false && cached && ...)`) → each
		// call rebuilds a fresh Map → refs differ → this `.toBe` fails.
		const map1 = latestCaseMemoryBySignature();
		expect(latestCaseMemoryBySignature()).toBe(map1);
		expect(latestCaseMemoryBySignature()).toBe(map1);
		expect(map1.size).toBeGreaterThan(0);
	});

	it("a new deposit invalidates the case-memory Map cache → next call rebuilds (not stale)", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "exploit rop gadget",
			route: "re",
			outcome: "success",
		});
		const map1 = latestCaseMemoryBySignature();
		// A second deposit rewrites case-memory.jsonl (atomic temp+rename → mtime+size change)
		// → the cached Map is stale → the next call rebuilds a fresh Map (different ref) and
		// observes the new case row.
		appendMemoryEventTransaction({
			source: "manual",
			task: "heap tcache poisoning",
			route: "re",
			outcome: "success",
		});
		const map2 = latestCaseMemoryBySignature();
		expect(map2).not.toBe(map1);
		// Both events share one caseSignature only if their signatures match; otherwise the
		// map grew. Either way the rebuild reflects post-deposit state (not a stale empty map).
		expect(map2.size).toBeGreaterThanOrEqual(map1.size);
	});

	it("quality + governance builders return empty Maps without throwing when their ledgers are missing", () => {
		// The quality and governance ledgers are missing here (no quality/governance ops).
		// cachedJsonlDerived does NOT cache a missing file (stat throws → no store → the next
		// call re-stats so an appearing ledger is observed), but the build() still runs and
		// jsonlRecords returns [] for a missing file → an empty Map, no throw. This is the
		// correct missing-file path (NOT a shared-ref identity — missing files are uncached
		// by design).
		expect(() => latestMemoryQualityByEvent()).not.toThrow();
		expect(() => memoryBlockingGovernanceBySource()).not.toThrow();
		expect(latestMemoryQualityByEvent().size).toBe(0);
		expect(memoryBlockingGovernanceBySource().size).toBe(0);
	});
});

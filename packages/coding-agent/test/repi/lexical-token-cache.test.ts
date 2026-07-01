import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #81 — lexical token-Set cache (the lexical analog of #76's vector-index cache).
// searchMemoryEvents runs on every tool_result and, per event, built FOUR token Sets via
// memorySearchTokens (event text ×2 — once for the haystack .has() loop, once inside
// memoryHybridSignalScore — plus case text and artifact text). memorySearchTokens is an
// O(text) lower-case+split+uniqueNonEmpty+Set construction of text that is a PURE function
// of (event, caseRow); events.jsonl / case-memory.jsonl only change on deposit, so between
// deposits these Sets re-derive IDENTICAL output R tool_results × N events × 4 times =
// O(R·N·4) wasted CPU over a session. #81 caches them: event/artifact tokens under event.id,
// case tokens under caseSignature, each entry validated by a generation token = (events
// mtime+size, case mtime+size). A deposit bumps mtime → generation changes → stale entries
// rebuilt lazily on the next recall.
//
// There is no disk signal to count (the cache is pure CPU, and memorySearchTokens is called
// WITHIN memory-search.ts so a module-export mock bypasses it). The load-bearing proof is
// REFERENCE IDENTITY: a cache hit returns the SHARED Set object (same ref across calls); a
// rebuild returns a fresh Set (different ref). These tests prove (1) repeat calls with the
// same generation return shared refs (0 rebuilds — temp-neuter the hit guard → fresh refs,
// the load-bearing proof), (2) a new deposit changes the generation → the next call rebuilds
// (not stale) + the new event is seen, and (3) end-to-end searchMemoryEvents returns correct,
// deterministic hits (the cache does not corrupt scoring).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return { ...actual };
});

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const {
	cachedArtifactSearchTokens,
	cachedCaseSearchTokens,
	cachedEventSearchTokens,
	lexicalTokenGeneration,
	readMemoryEvents,
} = await import("../../src/core/repi/memory-search.ts");
const { searchMemoryEvents } = await import("../../src/core/repi/memory-recall.ts");

describe("repi/lexical token-Set cache (opt #81)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-lexical-cache-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("repeat calls with the same generation return SHARED token Set refs (0 rebuilds once warm)", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "exploit rop gadget",
			route: "re",
			outcome: "success",
			lessons: ["use ropper"],
			commands: ["ropper --file b"],
		});
		const event = readMemoryEvents()[0];
		const gen = lexicalTokenGeneration();
		// First call builds + caches; the three subsequent calls hit the cache and return the
		// SAME Set objects (shared refs — the load-bearing #81 proof: no memorySearchTokens
		// rebuild on a hit). Temp-neuter the hit guard (`if (false && hit...)`) → each call
		// rebuilds a fresh Set → refs differ → these `.toBe` assertions fail.
		const eventTokens1 = cachedEventSearchTokens(event, gen);
		const artifactTokens1 = cachedArtifactSearchTokens(event, gen);
		expect(cachedEventSearchTokens(event, gen)).toBe(eventTokens1);
		expect(cachedArtifactSearchTokens(event, gen)).toBe(artifactTokens1);
		expect(cachedEventSearchTokens(event, gen)).toBe(eventTokens1);
		// Case tokens: fetch the case row via searchMemoryEvents' path is internal, so exercise
		// the undefined-caseRow branch (returns the shared EMPTY_TOKEN_SET, stable ref).
		expect(cachedCaseSearchTokens(undefined, gen)).toBe(cachedCaseSearchTokens(undefined, gen));
	});

	it("a new deposit changes the generation → the next call rebuilds (not stale)", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "exploit rop gadget",
			route: "re",
			outcome: "success",
		});
		const event = readMemoryEvents()[0];
		const gen1 = lexicalTokenGeneration();
		const eventTokensGen1 = cachedEventSearchTokens(event, gen1);
		// A second deposit rewrites events.jsonl (atomic temp+rename → mtime+size change) →
		// the generation token changes → the cached entry for event.id is stale → the next
		// call rebuilds a fresh Set (different ref) and returns it.
		appendMemoryEventTransaction({
			source: "manual",
			task: "heap tcache poisoning",
			route: "re",
			outcome: "success",
		});
		const gen2 = lexicalTokenGeneration();
		expect(gen2).not.toBe(gen1);
		const eventTokensGen2 = cachedEventSearchTokens(event, gen2);
		expect(eventTokensGen2).not.toBe(eventTokensGen1);
		// The new event is observed (the cache rebuild did not lose it).
		expect(readMemoryEvents()).toHaveLength(2);
	});

	it("searchMemoryEvents end-to-end returns correct, deterministic hits (cache does not corrupt scoring)", () => {
		appendMemoryEventTransaction({
			source: "manual",
			task: "exploit rop gadget ret2libc",
			route: "re",
			outcome: "success",
			lessons: ["use ropper for gadgets"],
			commands: ["ropper --file b --search 'pop rdi'"],
		});
		// Two back-to-back recalls (as on consecutive tool_results with no deposit between).
		// The second is a full cache hit (same generation). Scores must be identical — the
		// shared token Sets feed the same .has() checks → deterministic scoring, not corrupted
		// by cross-event Set sharing (the read-only-use invariant).
		const hits1 = searchMemoryEvents("rop gadget", { route: "re" });
		const hits2 = searchMemoryEvents("rop gadget", { route: "re" });
		expect(hits1.length).toBeGreaterThan(0);
		expect(hits1[0].event.id).toBe(hits2[0].event.id);
		expect(hits1[0].score).toBe(hits2[0].score);
		expect(hits1[0].reasons).toEqual(hits2[0].reasons);
		// The seeded event is retrievable by its distinctive token.
		expect(hits1.some((hit) => hit.event.task.includes("rop gadget"))).toBe(true);
	});
});

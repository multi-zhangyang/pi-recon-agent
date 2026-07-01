import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #77 — memory-store verification report cache. The per-deposit PREFLIGHT
// (recon-profile.ts:30042, buildMemoryStoreVerificationFromScans {write:false})
// re-walked the ENTIRE events chain on every append — O(events) loop with one
// memoryEventHash (JSON.stringify+sha256 of the whole event object) per row — to
// confirm the store was clean BEFORE appending, even though the previous deposit's
// POST-COMMIT (recon-profile.ts:30161, {write:true}) had already full-walked and
// verified that exact file state. Between deposits nothing touches events.jsonl /
// case-memory.jsonl (lock-held, no external writer), so the preflight re-verified
// byte-identical, already-verified content every time → ~N redundant memoryEventHash
// recomputations per deposit (O(N²) cumulative over a session).
//
// #77 caches the report keyed by (eventsPath, events mtime+size, case mtime+size).
// A read-only verify (options.write===false — the preflight, and any write:false
// caller) that finds both files unchanged since the last full walk returns the cached
// report and SKIPS the O(N) walk. The post-commit (write:true) is NEVER short-
// circuited (the cache-hit guard requires write===false): the append bumps mtime →
// guaranteed miss → full walk → re-cache, so tamper-detection on the append itself
// stays at FULL strength (every deposit's post-commit recomputes every hash).
// write:true/default verifyMemoryStore callers (operator /re_memory verify, sanitize,
// dashboard) also never short-circuit → their behavior is byte-identical.
//
// These tests prove (1) repeat write:false verifies do NOT re-walk the chain
// (0 memoryEventHash calls across N calls once warm — the load-bearing #77 proof
// that buildMemoryStoreVerificationReport is skipped on a hit), (2) a new deposit
// refreshes the cache (the post-commit re-caches post-append state → the next
// write:false returns the NEW event count WITHOUT re-walking, not a stale report),
// and (3) write:true verifies never short-circuit (tamper-detection stays full
// strength). memoryEventHash is wrapped (calling the real impl so the hash chain
// stays valid) and counted — the counter is the direct walk-skipped proof.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { hashCount } = vi.hoisted(() => ({ hashCount: { current: 0 } }));

vi.mock("../../src/core/repi/memory-event.ts", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../../src/core/repi/memory-event.ts")>();
	return {
		...actual,
		// Wrap memoryEventHash (the per-row cost in the verification walk) with a counter.
		// Calls the real impl so the chain stays valid — the counter is additive only.
		// buildMemoryStoreVerificationReport imports memoryEventHash from this module, so
		// the mocked (wrapped) export is what the walk calls. (memoryEventHashChainOk's
		// internal same-module call uses the original binding — not counted, not needed.)
		memoryEventHash: vi.fn((event: Parameters<typeof actual.memoryEventHash>[0]) => {
			hashCount.current++;
			return actual.memoryEventHash(event);
		}),
	};
});

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { buildMemoryStoreVerificationUnlocked, invalidateMemoryStoreVerificationCache } = await import(
	"../../src/core/repi/memory-store.ts"
);

describe("repi/memory-store verification report cache (opt #77)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-verify-cache-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
		invalidateMemoryStoreVerificationCache();
		hashCount.current = 0;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("repeat write:false verifies do NOT re-walk the chain (0 memoryEventHash once warm)", () => {
		// Seed 3 events. Each append's post-commit (write:true) full-walks the post-append
		// state (mtime bumped → miss) + re-caches. After seeding the cache holds the
		// 3-event verified report.
		for (let i = 0; i < 3; i++) {
			appendMemoryEventTransaction({
				source: "manual",
				task: `cache-task-${i}`,
				route: "re",
				outcome: "success",
			});
		}
		// Reset AFTER seeding so we measure only the read-only verifies below.
		hashCount.current = 0;
		// Three read-only verifies with unchanged files → all cache hits →
		// buildMemoryStoreVerificationReport is skipped → 0 memoryEventHash calls.
		// (Temp-neuter the cache-hit guard → each call full-walks 3 events → 9 calls,
		// failing `===0` — the load-bearing #77 proof the walk is genuinely skipped.)
		const r1 = buildMemoryStoreVerificationUnlocked({ write: false });
		const r2 = buildMemoryStoreVerificationUnlocked({ write: false });
		const r3 = buildMemoryStoreVerificationUnlocked({ write: false });
		expect(hashCount.current).toBe(0);
		// Secondary proof: a cache hit returns the SAME report object reference — a
		// fresh buildMemoryStoreVerificationReport builds a new object literal each call,
		// so without the cache r2/r3 would be distinct refs and these would fail.
		expect(r2).toBe(r1);
		expect(r3).toBe(r1);
		expect(r1.storeGrade).toBe("pass");
		expect(r1.eventCount).toBe(3);
	});

	it("a new deposit refreshes the cache (next write:false sees the new event WITHOUT re-walking)", () => {
		for (let i = 0; i < 2; i++) {
			appendMemoryEventTransaction({ source: "manual", task: `v1-${i}`, route: "re", outcome: "success" });
		}
		const before = buildMemoryStoreVerificationUnlocked({ write: false });
		expect(before.eventCount).toBe(2);
		// Append a 3rd event. The post-commit (write:true) full-walks the post-append
		// state (mtime bumped → cache miss) and re-caches the 3-event report.
		appendMemoryEventTransaction({ source: "manual", task: "v2-deposit", route: "re", outcome: "success" });
		// Read-only verify → cache HIT (the post-commit repopulated it with the
		// post-append mtime/size) → 0 memoryEventHash calls. BUT the cached report
		// reflects the 3-event post-deposit state (NOT the stale 2-event one) — the
		// cache was refreshed by the deposit, not served stale. (Temp-neuter the guard
		// → this write:false full-walks 3 events → hashCount=3 fails `===0`.)
		hashCount.current = 0;
		const after = buildMemoryStoreVerificationUnlocked({ write: false });
		expect(hashCount.current).toBe(0); // cache hit — no re-walk
		expect(after.eventCount).toBe(3); // fresh post-deposit report, not stale
		expect(after.storeGrade).toBe("pass");
		expect(after.hashChainOk).toBe(true);
	});

	it("write:true verifies never short-circuit (tamper-detection stays at full strength)", () => {
		for (let i = 0; i < 3; i++) {
			appendMemoryEventTransaction({ source: "manual", task: `wt-${i}`, route: "re", outcome: "success" });
		}
		// The cache is warm (the 3rd append's post-commit populated it). A write:true
		// verify must NOT short-circuit — the cache-hit guard requires write===false,
		// so write:true always full-walks + rewrites the report (operator /re_memory
		// verify, sanitize path). This is the tamper-detection invariant: the post-
		// commit on every deposit recomputes every hash.
		hashCount.current = 0;
		const r1 = buildMemoryStoreVerificationUnlocked({ write: true });
		expect(hashCount.current).toBe(3); // full walk of 3 events, NOT a cache hit
		// A second write:true also full-walks (write:true is never cached-shortcut).
		hashCount.current = 0;
		const r2 = buildMemoryStoreVerificationUnlocked({ write: true });
		expect(hashCount.current).toBe(3);
		// write:true produces FRESH report objects (not the cached ref) — confirms it
		// went through buildMemoryStoreVerificationReport, not the cache shortcut.
		expect(r2).not.toBe(r1);
		expect(r1.storeGrade).toBe("pass");
	});
});

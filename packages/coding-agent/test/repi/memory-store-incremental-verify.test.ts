import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// opt #78 — incremental post-commit verification. The per-deposit POST-COMMIT
// (recon-profile.ts:30161) used to call buildMemoryStoreVerificationUnlocked({write:true}),
// which re-scanned events.jsonl+case-memory.jsonl (mtime bumped → full O(N) re-parse) AND
// re-walked the ENTIRE chain (O(N+1) memoryEventHash = JSON.stringify+sha256 of every
// event) — re-verifying the first N events the PREFLIGHT (:30042) had ALREADY verified
// this same deposit (the preflight `report` is in hand at the call site). Over M deposits
// → O(M·N) = O(N²) re-hashing.
//
// buildMemoryStoreVerificationIncremental builds the post-append report from the preflight
// report + the ONE new event + its case row, verifying ONLY the new event's chain linkage
// (seq, prevHash→preflight.latestEventHash, entryHash===memoryEventHash(event)) + the new
// case row's structural consistency. O(1) instead of O(N). Full-walk fallback on ANY doubt
// (periodic safety net, non-pass preflight, new-event check failure) → the exact prior
// behavior, so the incremental path can only be FASTER, never less safe.
//
// These tests prove (1) the post-commit is O(1) (2 memoryEventHash calls for the new event
// — build + incremental verify — NOT O(N) re-walk; the load-bearing #78 proof), (2) the
// incremental path produces a CORRECT chain (an independent FULL walk after N incremental
// deposits reports storeGrade pass / hashChainOk / eventCount N — the tamper-detection
// check that the incremental path didn't break the chain), and (3) the periodic safety net
// (REPI_MEMORY_FULL_VERIFY_EVERY) falls back to a full walk every K deposits. memoryEventHash
// is wrapped (calling the real impl so the chain stays valid) and counted.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_FULL_VERIFY_EVERY = "REPI_MEMORY_FULL_VERIFY_EVERY";

const { hashCount } = vi.hoisted(() => ({ hashCount: { current: 0 } }));

vi.mock("../../src/core/repi/memory-event.ts", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../../src/core/repi/memory-event.ts")>();
	return {
		...actual,
		// Wrap memoryEventHash (the per-row cost in the verification walk + the new-event
		// build at recon-profile.ts:30113 + the incremental verify's expectedEntryHash).
		// Calls the real impl so the chain stays valid — the counter is additive only.
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

describe("repi/memory-store incremental post-commit verification (opt #78)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousFullVerifyEvery: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-incremental-verify-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		previousFullVerifyEvery = process.env[ENV_FULL_VERIFY_EVERY];
		process.env[ENV_AGENT_DIR] = agentDir;
		delete process.env[ENV_FULL_VERIFY_EVERY];
		invalidateMemoryStoreVerificationCache();
		hashCount.current = 0;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		if (previousFullVerifyEvery === undefined) delete process.env[ENV_FULL_VERIFY_EVERY];
		else process.env[ENV_FULL_VERIFY_EVERY] = previousFullVerifyEvery;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("the post-commit is O(1) — 2 memoryEventHash calls for the new event, NOT an O(N) re-walk", () => {
		// Seed 5 events. Each deposit's post-commit is incremental (preflight pass) and
		// commits the cache → the NEXT preflight (#77) hits → 0 walk hashes. After seeding
		// the cache holds the 5-event state.
		for (let i = 0; i < 5; i++) {
			appendMemoryEventTransaction({
				source: "manual",
				task: `seed-task-${i}`,
				route: "re",
				outcome: "success",
			});
		}
		// Reset AFTER seeding so we measure only the 6th deposit.
		hashCount.current = 0;
		// 6th deposit: preflight (#77 cache hit → 0 walk hashes) + new-event build (1
		// memoryEventHash) + incremental post-commit verify (1 memoryEventHash for
		// expectedEntryHash) = 2 total. The first 5 events are NOT re-hashed.
		// (Temp-neuter buildMemoryStoreVerificationIncremental to always fall back to a
		// full walk → preflight 0 + build 1 + full walk 6 events = 7, failing `===2` —
		// the load-bearing #78 proof the post-commit re-walk is genuinely skipped.)
		appendMemoryEventTransaction({ source: "manual", task: " sixth-deposit", route: "re", outcome: "success" });
		expect(hashCount.current).toBe(2);
	});

	it("the incremental path produces a correct chain (an independent FULL walk agrees)", () => {
		// Deposit 6 events entirely through the incremental post-commit path.
		for (let i = 0; i < 6; i++) {
			appendMemoryEventTransaction({
				source: "manual",
				task: `chain-task-${i}`,
				route: "re",
				outcome: i % 3 === 0 ? "failure" : "success",
				lessons: [`lesson-${i}`],
				commands: [`re_test ${i}`],
			});
		}
		// Force an independent FULL walk (invalidate the #77 cache so the read-only verify
		// can't shortcut, then buildMemoryStoreVerificationUnlocked re-scans + re-walks the
		// whole chain from genesis). If the incremental path had desynchronized the chain
		// (wrong prevHash/seq/entryHash), this full walk would surface it — the tamper-
		// detection check that #78 preserves the chain contract.
		invalidateMemoryStoreVerificationCache();
		const full = buildMemoryStoreVerificationUnlocked({ write: false });
		expect(full.storeGrade).toBe("pass");
		expect(full.hashChainOk).toBe(true);
		expect(full.seqOk).toBe(true);
		expect(full.prevHashOk).toBe(true);
		expect(full.eventCount).toBe(6);
		expect(full.caseIndexOk).toBe(true);
	});

	it("the periodic safety net falls back to a full walk every K deposits", () => {
		// K=2: every 2nd deposit's post-commit is a FULL walk (not incremental).
		process.env[ENV_FULL_VERIFY_EVERY] = "2";
		invalidateMemoryStoreVerificationCache(); // resets the counter too
		// Deposit 1: incremental (counter 1 < 2). Seed + measure only the post-commit cost
		// by counting across the whole deposit: preflight miss (0 events → 0 walk) + build
		// (1) + incremental verify (1) = 2.
		appendMemoryEventTransaction({ source: "manual", task: "k-deposit-1", route: "re", outcome: "success" });
		const afterFirst = hashCount.current;
		expect(afterFirst).toBe(2); // incremental
		// Deposit 2: counter 2 >= K → FULL walk. preflight (#77 cache hit → 0) + build (1)
		// + full walk (2 events) = 3. The full walk re-hashes both events — the safety net.
		hashCount.current = 0;
		appendMemoryEventTransaction({ source: "manual", task: "k-deposit-2", route: "re", outcome: "success" });
		expect(hashCount.current).toBe(3); // full walk (2 events), NOT incremental (would be 2)
		// The chain is still correct after a mix of incremental + full-walk post-commits.
		invalidateMemoryStoreVerificationCache();
		const full = buildMemoryStoreVerificationUnlocked({ write: false });
		expect(full.storeGrade).toBe("pass");
		expect(full.eventCount).toBe(2);
		expect(full.hashChainOk).toBe(true);
	});
});

import { mkdirSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// F3 (HIGH CRASH): appendCompactResumeTransition wrote the V2 transitions hash-chain ledger via
// raw writeFileSync (read-modify-write: previousText + newRow). A crash mid-write truncated the
// ledger; the verifier recomputes prevHash/entryHash from genesis → drift on every row after the
// cut → invalidTransitions → verifyCompactionResumeLedger archives the corrupt ledger and resets
// to empty → ALL transitions silently lost. Fix: route the write (and the archive/reset writes)
// through writePrivateTextFile (atomic temp+rename). Bytes identical (previousText + new row) so
// the genesis-strict verifier is unaffected. The inode-change assertion is the regression probe.
//
// F8 (MED PERF): appendCompactResumeTransition did an O(file) read-modify-write per append (read
// whole file → sha256(previousText) for prevHash). The #85 cache (nextCompactionResumeChain) is
// mtime+size-guarded storing {text, prevHash, mtimeMs, size}; on a hit the O(file) read + sha256
// are skipped. The proof counts readFileSync on the transitions ledger: N appends → 1 read (the
// first cold-reads, the rest cache-hit). Temp-neuter the hit guard → N reads → the assertion
// fails. The ledger is genesis-strict (NOT rotation-safe), so the WRITE stays an atomic full
// rewrite (writePrivateTextFile) — appendPrivateTextFile CANNOT be used (its leading-"\n" on a
// fresh file would desync the stored prevHash from the verifier's empty-line-skipping prevHash).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { ledgerReadCount } = vi.hoisted(() => ({
	ledgerReadCount: { current: 0 },
}));

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	const isLedger = (p: unknown) => String(p).endsWith("compaction-resume-transitions.jsonl");
	return {
		...actual,
		readFileSync: vi.fn((...args: Parameters<typeof actual.readFileSync>) => {
			if (isLedger(args[0])) ledgerReadCount.current++;
			return actual.readFileSync(...args);
		}),
	};
});

const {
	appendCompactResumeTransition,
	archiveCorruptCompactionResumeLedger,
	buildCompactResumeLedgerV2Report,
	invalidateCompactionResumeChainCache,
} = await import("../../src/core/repi/memory-compact-resume.ts");
const { compactResumeTransitionLedgerPath } = await import("../../src/core/repi/storage.ts");

describe("repi/memory-compact-resume F3 atomic ledger write + F8 append cache", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-compact-resume-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
		ledgerReadCount.current = 0;
		invalidateCompactionResumeChainCache();
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("F3+F8: ledger appends are atomic (inode changes) + O(1) read via cache (1 read for N appends) + chain verifies", () => {
		const ledgerPath = compactResumeTransitionLedgerPath();
		const n = 6;
		ledgerReadCount.current = 0;
		// First append cold-reads the ledger (cache miss) + writes atomically.
		appendCompactResumeTransition({
			to: "running",
			reason: "compact triggered",
			idempotencyKey: "key-1",
			command: "re_context compact",
		});
		const inodeBefore = statSync(ledgerPath).ino;
		expect(statSync(ledgerPath).mode & 0o777).toBe(0o600);

		// Appends 2..N use DIFFERENT idempotency keys (so they are not duplicates) and cache-hit
		// (stat unchanged since the prior commit) → 0 reads each.
		for (let i = 2; i <= n; i++) {
			appendCompactResumeTransition({
				to: i % 2 === 0 ? "blocked" : "running",
				reason: `transition ${i}`,
				idempotencyKey: `key-${i}`,
				command: `re_context compact ${i}`,
			});
		}
		// F8: the ledger is read ONCE total (the first cold-read); appends 2..N cache-hit.
		// Pre-#85 read the WHOLE growing ledger on EVERY append (N reads). Temp-neuter the
		// nextCompactionResumeChain hit guard → every append cold-reads → ledgerReadCount >= N.
		expect(ledgerReadCount.current).toBeLessThanOrEqual(1);

		// F3: the second append (key-2) rewrites the ledger via temp+rename → NEW inode. The old
		// truncate-then-write (writeFileSync) kept the SAME inode — this assertion fails if the
		// ledger write regresses.
		const inodeAfter = statSync(ledgerPath).ino;
		expect(inodeAfter).not.toBe(inodeBefore);
		expect(statSync(ledgerPath).mode & 0o777).toBe(0o600);
		// No stray temp files left in the memory dir.
		expect(readdirSync(dirname(ledgerPath)).filter((f) => f.endsWith(".tmp"))).toEqual([]);

		// Correctness: the cached prevHash (full-text sha256) produces a CONTIGUOUS valid chain —
		// the genesis-strict verifier reports ZERO invalid transitions. This is the load-bearing
		// proof that caching prevHash (instead of re-reading per append) doesn't desync the chain.
		const report = buildCompactResumeLedgerV2Report();
		expect(report.transitions).toHaveLength(n);
		expect(report.invalidTransitions).toEqual([]);
		expect(report.currentState).toBe(n % 2 === 0 ? "blocked" : "running");
	});

	it("F3 archive/reset: archiveCorruptCompactionResumeLedger writes atomically (0o600, valid, no .tmp) and resets the source", () => {
		// Seed a ledger so the source path exists.
		appendCompactResumeTransition({
			to: "running",
			reason: "seed",
			idempotencyKey: "seed-key",
		});
		const ledgerPath = compactResumeTransitionLedgerPath();
		const corruptText = readFileSync(ledgerPath, "utf8");
		// Archive the corrupt ledger.
		const archivedPath = archiveCorruptCompactionResumeLedger(ledgerPath, corruptText, [
			"compaction resume ledger prevHash drift at row 1",
		]);
		expect(archivedPath).toBeTruthy();
		const dir = dirname(archivedPath as string);
		// Archived ledger copy + repair.json are 0o600, valid, no stray temp files.
		expect(statSync(archivedPath as string).mode & 0o777).toBe(0o600);
		expect(statSync(join(dir, "repair.json")).mode & 0o777).toBe(0o600);
		expect(readdirSync(dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
		const repair = JSON.parse(readFileSync(join(dir, "repair.json"), "utf8"));
		expect(repair.kind).toBe("repi-compact-ledger-auto-repair");
		// The source ledger is reset to empty (atomic writePrivateTextFile(path, "")).
		expect(readFileSync(ledgerPath, "utf8")).toBe("");
		expect(statSync(ledgerPath).mode & 0o777).toBe(0o600);
		// After reset, a fresh append starts a clean chain from genesis (cache invalidated).
		appendCompactResumeTransition({
			to: "queued",
			reason: "cold-start after repair",
			idempotencyKey: "post-repair-key",
		});
		const report = buildCompactResumeLedgerV2Report();
		expect(report.invalidTransitions).toEqual([]);
		expect(report.transitions).toHaveLength(1);
	});
});

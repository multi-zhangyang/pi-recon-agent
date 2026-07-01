import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// appendMemoryDepositionRuntimeEvent (recon-profile.ts:30171, the auto-deposit hot path
// fired on high-value tool results) USED to append the deposition event bus
// (deposition-events.jsonl) via read-modify-write: readText(whole file) for previousText →
// textWithJsonlLine → writeFileAtomic (writePrivateTextFile(temp) + renameSync) — an O(file)
// atomic rewrite on EVERY deposit, of a file that grows with every deposit (O(N²) write
// bytes over a session). The read side was deduped in opt #71 (the body read hit the cache);
// opt #72 eliminates the read-modify-write ENTIRELY by switching to true-append.
//
// Fix (opt #72): appendPrivateTextFile (the #67 true-append primitive) — appendFileSync writes
// the single new line in O(chunk), with a 1-byte tail read for the newline-separator contract.
// Byte-identical output (same separator contract as textWithJsonlLine). The body read
// (previousText) is gone entirely — only readMemoryDepositionEvents (for seq+prevHash)
// remains. Crash-safety tradeoff (appendFileSync not atomic → partial trailing line on crash)
// is safe: readMemoryDepositionEvents → jsonlRecords skips unparseable lines per-line, and
// memoryDepositionHashChainOk walks the PARSED rows (a partial tail is skipped → the chain
// continues from the last valid row). The memory hash-chain ledger (events.jsonl/case-memory)
// does NOT use this path — it stays atomic (writeFileAtomic) because it is verified byte-perfect.
//
// This test proves (1) the deposition bus is read once per append (jsonlRecords for seq+prevHash,
// no body read), (2) the write is a true-append (appendFileSync on deposition-events.jsonl, NOT
// writeFileAtomic's writeFileSync-to-temp + renameSync). writeback:false isolates the
// deposition-bus append (skips the separate memory-event transaction that touches events.jsonl).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { depositionReadCount, depositionAppendCount, depositionRenameCount } = vi.hoisted(() => ({
	depositionReadCount: { current: 0 },
	depositionAppendCount: { current: 0 },
	depositionRenameCount: { current: 0 },
}));

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	const isDep = (p: unknown) => String(p).endsWith("deposition-events.jsonl");
	return {
		...actual,
		readFileSync: vi.fn((...args: Parameters<typeof actual.readFileSync>) => {
			if (isDep(args[0])) depositionReadCount.current++;
			return actual.readFileSync(...args);
		}),
		appendFileSync: vi.fn((...args: Parameters<typeof actual.appendFileSync>) => {
			if (isDep(args[0])) depositionAppendCount.current++;
			return actual.appendFileSync(...args);
		}),
		renameSync: vi.fn((...args: Parameters<typeof actual.renameSync>) => {
			// writeFileAtomic renames a temp file → deposition-events.jsonl; true-append renames
			// nothing onto deposition-events.jsonl. Match either the temp→dep rename or dep temps.
			const dest = String(args[1]);
			if (dest.endsWith("deposition-events.jsonl")) depositionRenameCount.current++;
			return actual.renameSync(...args);
		}),
	};
});

const { appendMemoryDepositionRuntimeEvent } = await import("../../src/core/recon-profile.ts");
const { memoryDepositionHashChainOk, readMemoryDepositionEvents } = await import(
	"../../src/core/repi/memory-deposition.ts"
);

describe("memory deposition append hot path (opt #72 true-append + #73 chain cache)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-deposition-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
		depositionReadCount.current = 0;
		depositionAppendCount.current = 0;
		depositionRenameCount.current = 0;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("appends the deposition bus in O(chunk) (true-append, #72) with O(1) seq/prevHash (chain cache, #73)", () => {
		const n = 8;
		for (let i = 0; i < n; i++) {
			appendMemoryDepositionRuntimeEvent(
				{
					stage: "tool",
					source: `tool_result:bash`,
					status: "written",
					task: `runtime tool result ${i}`,
					route: "re",
					command: `echo ${i}`,
					stdout: `out ${i}`,
					outcome: "partial",
					lessons: [`lesson ${i}`],
					commands: [`echo ${i}`],
					reason: "high-value scoped auto writeback",
				},
				{ writeback: false },
			);
		}
		// (1) Read (#73 chain cache): the bus is read ONCE total — the first append cold-reads
		// (cache miss → readMemoryDepositionEvents for seq+prevHash), then appends 2..n cache-hit
		// (nextDepositionChain returns seq=prevSeq+1/prevHash=prevEntryHash; the mtime+size guard
		// confirms the file is unchanged since the last commit). Pre-#73 read the WHOLE growing
		// bus on EVERY append (n reads = 8 here); pre-#72 read-modify-write read it TWICE/append
		// (2n = 16). The cache makes the per-deposit read O(1) instead of O(file).
		expect(depositionReadCount.current).toBeLessThanOrEqual(1);

		// (2) Write (#72 true-append): appendFileSync on deposition-events.jsonl once per append,
		// and at most 1 renameSync onto it (the ensureRepiStorage init on the first call, NOT
		// a per-append atomic rewrite). Old read-modify-write (writeFileAtomic) → 0
		// appendFileSync + n+1 renameSync. These two assertions are the load-bearing proof of
		// the true-append conversion (O(chunk) write vs O(file) atomic rewrite per deposit).
		expect(depositionAppendCount.current).toBe(n);
		expect(depositionRenameCount.current).toBeLessThanOrEqual(1);

		// (3) Correctness: the chain cache must produce a CONTIGUOUS valid hash chain — every
		// row's prevHash == predecessor's entryHash, seq 1..n, genesis prevHash="0".repeat(64).
		// This is the load-bearing proof that caching seq+prevHash (instead of re-reading the
		// bus per append) doesn't desync the chain. Read AFTER the I/O-count assertions so the
		// extra readFileSync doesn't perturb the `<= 1` read-count check above.
		const events = readMemoryDepositionEvents();
		expect(events.length).toBe(n);
		expect(events.map((event) => event.seq)).toEqual(Array.from({ length: n }, (_, i) => i + 1));
		expect(events[0]?.prevHash).toBe("0".repeat(64));
		expect(memoryDepositionHashChainOk(events)).toBe(true);
	});
});

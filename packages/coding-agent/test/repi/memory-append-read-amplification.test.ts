import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// appendMemoryEventTransaction (the per-deposit hot path) USED to read the two
// hash-chained JSONL files (events.jsonl + case-memory.jsonl) 8 times per append
// in the common pass-store case:
//   1-2. preflight buildMemoryStoreVerificationUnlocked → jsonlScan(events) + jsonlScan(case)
//   3.   eventScan = jsonlScan(events)            ← same file, no write since preflight
//   4.   caseScan  = jsonlScan(case)              ← same file (pass case), no write since preflight
//   5.   fileDigest(events)                       ← re-reads the whole file just sha256'd
//   6.   fileDigest(case)                         ← re-reads the whole file just sha256'd
//   7-8. post-commit buildMemoryStoreVerificationUnlocked → jsonlScan(events) + jsonlScan(case)
// Over M deposits → 8M full-file reads + JSON.parses of growing files (O(N²)).
//
// The fix is behavior-identical: scan events+case ONCE up front, reuse those scans
// for the preflight verification (buildMemoryStoreVerificationFromScans), and compute
// the transaction beforeSha256/beforeBytes from the already-read .raw text via
// digestFromText (byte-identical to fileDigest for UTF-8 files). Case is re-scanned
// only in the repairable branch (rebuild writes it). Net: 4 reads per append in the
// pass case (events scan + case scan + 2 post-verify) vs 8 before. The post-commit
// verification reads are irreducible (must verify after the atomic write).
//
// This test proves (a) the read count drops, by counting readFileSync on the two
// hash-chained paths, and (b) behavior is preserved — the REAL verifyMemoryStore
// walks the full chain and reports storeGrade "pass" / hashChainOk after N appends.
// The byte-identical digestFromText-vs-fileDigest proof is test 1 (incl. multibyte
// UTF-8, where Buffer.byteLength(string) must equal the on-disk byte count).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { hashChainReadCount } = vi.hoisted(() => ({ hashChainReadCount: { current: 0 } }));

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return {
		...actual,
		readFileSync: vi.fn((...args: Parameters<typeof actual.readFileSync>) => {
			const p = String(args[0]);
			// Count only the two hash-chained JSONL files whose read-amplification we cut.
			if (p.endsWith("events.jsonl") || p.endsWith("case-memory.jsonl")) hashChainReadCount.current++;
			return actual.readFileSync(...args);
		}),
	};
});

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { fileDigest, digestFromText, verifyMemoryStore } = await import("../../src/core/repi/memory-store.ts");
const { jsonlScan } = await import("../../src/core/repi/jsonl.ts");
const { memoryEventsPath, caseMemoryPath } = await import("../../src/core/repi/storage.ts");
const { isMemoryEvent } = await import("../../src/core/repi/memory-event.ts");
const { isCaseMemory } = await import("../../src/core/repi/case-memory.ts");

describe("memory hash-chain append read-amplification", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-mem-append-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		process.env[ENV_AGENT_DIR] = agentDir;
		hashChainReadCount.current = 0;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("digestFromText is byte-identical to fileDigest for a real UTF-8 memory file (incl. multibyte)", () => {
		// The transaction records beforeSha256/beforeBytes computed from scan.raw via
		// digestFromText instead of re-reading via fileDigest. For this to be safe they
		// must be identical. JSONL with a multibyte char (é = 2 UTF-8 bytes) proves
		// Buffer.byteLength(raw, "utf-8") === buffer.length AND sha256Text(raw) ===
		// sha256(buffer) — the case where a naive string-length would diverge.
		const path = join(tempDir, "events.jsonl");
		const line = JSON.stringify({ id: "mem:x", seq: 1, caseSignature: "café-route", prevHash: "0".repeat(64) });
		writeFileSync(path, `${line}\n`);
		const scan = jsonlScan(path, isMemoryEvent, "MemoryEventV1");
		// scan.raw may not parse as a MemoryEvent (shape above is minimal) — that's fine,
		// we only need the raw text for the digest comparison.
		const fromText = digestFromText(scan.raw);
		const fromFile = fileDigest(path);
		expect(fromText.sha256).toBe(fromFile.sha256);
		expect(fromText.bytes).toBe(fromFile.bytes);
		expect(fromText.text).toBe(fromFile.text);
		// Explicit byte-count check: "café" contains a multibyte char.
		expect(fromText.bytes).toBe(Buffer.byteLength(`${line}\n`, "utf-8"));
	});

	it("appends read events+case ~4× per append, not 8× (preflight-scan reuse + digestFromText dedup)", () => {
		const n = 20;
		for (let i = 0; i < n; i++) {
			appendMemoryEventTransaction({
				source: "manual",
				task: `task-${i}`,
				route: "re",
				outcome: i % 4 === 0 ? "failure" : "success",
				lessons: [`lesson-${i}`],
				commands: [`re_test ${i}`],
			});
		}

		// New code: 4 hash-chain reads per append (events scan + case scan + 2 post-verify)
		// → ~4n = 80. Old code: 8 per append → ~8n = 160. The 6n (=120) threshold cleanly
		// separates them (new ~80 < 120; old ~160 > 120) with wide margin.
		expect(hashChainReadCount.current).toBeLessThan(6 * n);

		// Behavior preserved: the REAL store verifier walks the full hash chain + seq
		// + prevHash + case index and reports a clean pass. A broken chain (the one risk
		// of reusing scans / computing digests from text) would surface here.
		const verdict = verifyMemoryStore({ write: false });
		if (!verdict.hashChainOk) throw new Error(`hash chain broke: ${verdict.errors.slice(0, 6).join("; ")}`);
		expect(verdict.storeGrade).toBe("pass");
		expect(verdict.hashChainOk).toBe(true);
		expect(verdict.seqOk).toBe(true);
		expect(verdict.prevHashOk).toBe(true);
		expect(verdict.eventCount).toBe(n);

		// The case-memory index reflects every deposited case (one caseSignature per
		// append here since task differs each time → distinct signatures).
		const caseScan = jsonlScan(caseMemoryPath(), isCaseMemory, "CaseMemoryV1");
		expect(caseScan.rows.length).toBe(n);
	});

	it("chain stays contiguous from genesis across many appends (prevHash links intact)", () => {
		const n = 12;
		for (let i = 0; i < n; i++) {
			appendMemoryEventTransaction({
				source: "reflect",
				task: "contiguity-task",
				route: "re",
				outcome: "partial",
			});
		}
		const eventScan = jsonlScan(memoryEventsPath(), isMemoryEvent, "MemoryEventV1");
		expect(eventScan.rows.length).toBe(n);
		expect(eventScan.rows[0].prevHash).toBe("0".repeat(64));
		for (let i = 1; i < eventScan.rows.length; i++) {
			expect(eventScan.rows[i].prevHash).toBe(eventScan.rows[i - 1].entryHash);
		}
	});
});

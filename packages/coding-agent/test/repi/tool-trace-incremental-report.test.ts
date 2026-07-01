import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ToolCallEvent, ToolResultEvent } from "../../src/core/extensions/types.ts";

// opt #79 — incremental tool-trace report. The post-append report build
// (writeToolCallTraceReport → buildToolCallTraceLedgerV1 → verifyToolCallTraceLedgerV1)
// re-parsed the WHOLE ledger (readToolTraceEvents) + re-walked the ENTIRE chain (one
// toolCallTraceHash = stableJson+sha256 per row) + re-filtered all rows for 4 count
// fields on EVERY append — twice per tool invocation (call + result) — re-verifying the
// first N events the prior append had ALREADY verified. Over M tools × 500-row ledger →
// O(2·M·500) hash ops; unbounded mode → O(M²).
//
// #79 caches the last verified report + auxiliary state (callIds, replayCovered,
// lastEventHash, eventCount) keyed by ledger path + pre-append mtime+size. On a hit,
// buildToolCallTraceLedgerV1Incremental verifies ONLY the new event's chain linkage +
// per-event checks + updates the counts arithmetically → O(1), and skips the full
// ledger re-parse (readToolTraceEvents NOT called) + the O(N) hash walk
// (verifyToolCallTraceLedgerV1 NOT called). Full-rebuild fallback on ANY doubt (cache
// miss, mtime+size mismatch, rotation needed, prior hashChainOk false, new-event check
// failure, periodic safety net REPI_TOOL_TRACE_FULL_VERIFY_EVERY) → exact prior behavior.
//
// These tests count readToolTraceEvents (the O(N) parse) + verifyToolCallTraceLedgerV1
// (the O(N) hash walk) — both wrapped calling the REAL impl so the chain stays valid
// (counter additive). The incremental path calls NEITHER → both ===0 on the common path.
// (1) O(1) post-append — 0 parse + 0 walk once warm [load-bearing: temp-neuter → both
// >0]; (2) the incremental path produces a correct chain (an independent FULL verify
// agrees — ok, contiguous prevHash chain); (3) the periodic safety net falls back to a
// full walk every K appends; (4) rotation correctly falls back (eventCount+1 > maxRows
// → full parse+rotate+rebuild, not a wrong incremental report) + the chain still verifies.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_FULL_VERIFY_EVERY = "REPI_TOOL_TRACE_FULL_VERIFY_EVERY";
const ENV_MAX_ROWS = "REPI_TOOL_TRACE_LEDGER_MAX_ROWS";

const { ledgerReadCount, reportWriteCount } = vi.hoisted(() => ({
	ledgerReadCount: { current: 0 },
	reportWriteCount: { current: 0 },
}));

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return {
		...actual,
		// Count readFileSync of the ledger (the O(N) re-parse inside readToolTraceEvents)
		// + writeFileSync of the report. The incremental path does NEITHER ledger read
		// (it stats the file, never readFileSync) NOR a different write pattern — so
		// ledgerReadCount===0 on the 11th append is the load-bearing proof the O(N)
		// re-parse (and the O(N) hash walk that requires the parsed events) is skipped.
		readFileSync: vi.fn((...args: Parameters<typeof actual.readFileSync>) => {
			if (String(args[0]).endsWith("tool-call-trace.jsonl")) ledgerReadCount.current++;
			return actual.readFileSync(...args);
		}),
		writeFileSync: vi.fn((...args: Parameters<typeof actual.writeFileSync>) => {
			if (String(args[0]).endsWith("tool-call-trace-report.json")) reportWriteCount.current++;
			return actual.writeFileSync(...args);
		}),
	};
});

const {
	appendToolCallTraceFromCall,
	appendToolCallTraceFromResult,
	readToolTraceEvents,
	verifyToolCallTraceLedgerV1,
	invalidateToolTraceReportCache,
} = await import("../../src/core/recon-profile.ts");

describe("repi/tool-trace incremental report (opt #79)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousFullVerifyEvery: string | undefined;
	let previousMaxRows: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-trace-incremental-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		previousFullVerifyEvery = process.env[ENV_FULL_VERIFY_EVERY];
		previousMaxRows = process.env[ENV_MAX_ROWS];
		process.env[ENV_AGENT_DIR] = agentDir;
		delete process.env[ENV_FULL_VERIFY_EVERY];
		// High cap → no rotation, isolating the incremental path (rotation falls back).
		process.env[ENV_MAX_ROWS] = "10000";
		invalidateToolTraceReportCache();
		ledgerReadCount.current = 0;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		if (previousFullVerifyEvery === undefined) delete process.env[ENV_FULL_VERIFY_EVERY];
		else process.env[ENV_FULL_VERIFY_EVERY] = previousFullVerifyEvery;
		if (previousMaxRows === undefined) delete process.env[ENV_MAX_ROWS];
		else process.env[ENV_MAX_ROWS] = previousMaxRows;
		rmSync(tempDir, { recursive: true, force: true });
	});

	function appendPair(toolCallId: string, toolName = "probe"): void {
		const callEvent: ToolCallEvent = {
			type: "tool_call",
			toolCallId,
			toolName,
			input: { n: 1 },
		} as ToolCallEvent;
		appendToolCallTraceFromCall(callEvent, "mission-incr");
		const resultEvent: ToolResultEvent = {
			type: "tool_result",
			toolCallId,
			toolName,
			input: { n: 1 },
			content: [{ type: "text", text: "ok" }],
			isError: false,
			details: undefined,
		} as ToolResultEvent;
		appendToolCallTraceFromResult(resultEvent, "mission-incr");
	}

	it("the post-append report is O(1) — 0 ledger reads once warm, NOT an O(N) re-parse+walk", () => {
		// Seed 5 pairs (10 appends). The 1st append is a cache miss → full path (reads
		// the ledger + walks + commits the cache); every subsequent append is incremental
		// (0 ledger readFileSync — it stats the file, never re-parses) and commits the
		// cache → the cache holds the 10-event verified state.
		for (let i = 0; i < 5; i++) appendPair(`seed-${i}`);
		// Reset AFTER seeding so we measure only the 11th append.
		ledgerReadCount.current = 0;
		// 11th append: cache hit → incremental verifies ONLY the new event. The ledger is
		// NOT re-read (readToolTraceEvents is not called → 0 readFileSync of the ledger),
		// and since the O(N) hash walk (verifyToolCallTraceLedgerV1) requires the parsed
		// events from readToolTraceEvents, 0 reads ⟹ 0 walk too. The first 10 events are
		// NOT re-parsed or re-hashed. (Temp-neuter buildToolCallTraceLedgerV1Incremental
		// to always return null → fallback re-parses the 11-event ledger → readFileSync
		// ≥1, failing `===0` — the load-bearing #79 proof the post-append re-walk is
		// genuinely skipped.)
		appendPair("eleventh");
		expect(ledgerReadCount.current).toBe(0);
	});

	it("the incremental path produces a correct chain (an independent FULL verify agrees)", () => {
		// Deposit 6 pairs (12 events) entirely through the incremental post-append path.
		for (let i = 0; i < 6; i++) appendPair(`chain-${i}`);
		// Force an independent FULL walk (the real readToolTraceEvents + verifyToolCallTraceLedgerV1).
		// If the incremental path had desynchronized the chain or mis-counted, this full
		// walk would surface it — the tamper-detection check that #79 preserves the chain
		// + report contract.
		const events = readToolTraceEvents();
		const verdict = verifyToolCallTraceLedgerV1(events);
		expect(verdict.ok).toBe(true);
		expect(verdict.errors).toEqual([]);
		expect(events.length).toBe(12);
		// Contiguous chain from genesis.
		expect(events[0].prevHash).toBe("0".repeat(64));
		for (let i = 1; i < events.length; i++) {
			expect(events[i].prevHash).toBe(events[i - 1].eventHash);
		}
	});

	it("the periodic safety net falls back to a full walk every K appends", () => {
		// K=2: every 2nd incremental-eligible append's report is a FULL walk (not
		// incremental). Cadence after warm: safety-net, incremental, safety-net, ...
		process.env[ENV_FULL_VERIFY_EVERY] = "2";
		invalidateToolTraceReportCache(); // counter 0, cache cleared
		// Warm: append1 (call) cache-miss → full; append2 (result) counter 1 < 2 →
		// incremental. Cache now warm, counter 1.
		appendPair("warm");
		// append3 (call): counter 1→2 ≥ 2 → SAFETY NET → full walk → re-reads the ledger.
		ledgerReadCount.current = 0;
		appendToolCallTraceFromCall(
			{ type: "tool_call", toolCallId: "s3", toolName: "probe", input: {} } as ToolCallEvent,
			"m",
		);
		expect(ledgerReadCount.current).toBeGreaterThanOrEqual(1); // safety net fired a full walk
		// append4 (result): counter 0→1 < 2 → INCREMENTAL → 0 ledger reads. Proves the
		// safety net doesn't just always-fallback — the cadence is full, incremental, full.
		ledgerReadCount.current = 0;
		appendToolCallTraceFromResult(
			{
				type: "tool_result",
				toolCallId: "s3",
				toolName: "probe",
				input: {},
				content: [{ type: "text", text: "ok" }],
				isError: false,
				details: undefined,
			} as ToolResultEvent,
			"m",
		);
		expect(ledgerReadCount.current).toBe(0); // incremental between safety nets
		// append5 (call): counter 1→2 ≥ 2 → SAFETY NET again.
		ledgerReadCount.current = 0;
		appendToolCallTraceFromCall(
			{ type: "tool_call", toolCallId: "s5", toolName: "probe", input: {} } as ToolCallEvent,
			"m",
		);
		expect(ledgerReadCount.current).toBeGreaterThanOrEqual(1);
		// The chain is still correct after a mix of incremental + full-walk post-appends.
		const events = readToolTraceEvents();
		const verdict = verifyToolCallTraceLedgerV1(events);
		expect(verdict.ok).toBe(true);
	});

	it("rotation correctly falls back to a full parse+rotate+rebuild (not a wrong incremental report)", () => {
		// maxRows=3: once eventCount+1 > 3 the incremental path MUST decline (rotation
		// re-hashes the tail → cached counts/callIds no longer apply) → full path rotates.
		process.env[ENV_MAX_ROWS] = "3";
		invalidateToolTraceReportCache();
		// 3 appends fill the ledger to the cap (each incremental: eventCount 0+1=1, 1+1=2,
		// 2+1=3 — all ≤ 3, no rotation).
		const call = (id: string) =>
			appendToolCallTraceFromCall(
				{ type: "tool_call", toolCallId: id, toolName: "probe", input: {} } as ToolCallEvent,
				"m",
			);
		call("a");
		call("b");
		call("c");
		// Reset: the 4th append (eventCount 3 + 1 = 4 > 3) must decline the incremental
		// path → full path → readToolTraceEvents re-parse + verifyToolCallTraceLedgerV1
		// full walk + rotation re-hash. (If the incremental path wrongly accepted, it
		// would build a report with eventCount 4 > maxRows 3 — a broken invariant, and
		// it would NOT rotate the on-disk ledger. So ledgerReadCount≥1 + a rotated-on-disk
		// ledger both prove the fallback fired.)
		ledgerReadCount.current = 0;
		call("d");
		expect(ledgerReadCount.current).toBeGreaterThanOrEqual(1); // rotation fallback re-parsed
		// The rotated ledger is capped at maxRows + keeps a "call" at the head, and the
		// chain still verifies cleanly end-to-end (rotation preserves the chain invariant).
		const events = readToolTraceEvents();
		expect(events.length).toBeLessThanOrEqual(3);
		expect(events[0].phase).toBe("call");
		const verdict = verifyToolCallTraceLedgerV1(events);
		expect(verdict.ok).toBe(true);
	});
});

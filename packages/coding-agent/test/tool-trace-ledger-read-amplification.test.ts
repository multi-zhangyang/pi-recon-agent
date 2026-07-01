import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ToolCallEvent, ToolResultEvent } from "../src/core/extensions/types.ts";

// The tool-call trace ledger is an append-only hash chain. appendToolCallTraceEvent
// USED to read the whole ledger THREE times per append: (1) latestToolTraceHash to
// get the prevHash (parses the last line), (2) rotateToolCallTraceLedgerIfNeeded
// (readToolTraceEvents to check length + re-hash on rotation), (3) writeToolCallTraceReport
// (readToolTraceEvents again to build + verify the report). Over a session with M
// tool calls (2M appends: call + result) that is ~6M full-ledger reads + JSON.parses.
//
// The fix is behavior-identical: (a) cache the latest eventHash — the prevHash for
// the next append IS the eventHash we just appended (the new last row), invariant
// between appends — so latestToolTraceHash skips its full-file read; (b) read the
// post-append ledger ONCE and share it between rotation + report (rotation returns
// whether it rewrote the file; only then does the report re-read the post-rotation
// state, preserving report freshness). Net: ~1 read per append (the shared one) on
// the non-rotation path, vs ~3 before. This test proves the read count drops by
// counting readFileSync calls on the ledger path (vi.mock node:fs, delegate to real).
//
// The rotation correctness (cache invalidation when rotation re-hashes the tail)
// is covered by tool-trace-ledger-rotation.test.ts — the real verifyToolCallTraceLedgerV1
// accepts the rotated chain there, which a stale-cache bug would break.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_ROWS = "REPI_TOOL_TRACE_LEDGER_MAX_ROWS";

const { ledgerReadCount } = vi.hoisted(() => ({ ledgerReadCount: { current: 0 } }));

vi.mock("node:fs", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs")>();
	return {
		...actual,
		readFileSync: vi.fn((...args: Parameters<typeof actual.readFileSync>) => {
			if (String(args[0]).endsWith("tool-call-trace.jsonl")) ledgerReadCount.current++;
			return actual.readFileSync(...args);
		}),
	};
});

const { appendToolCallTraceFromCall, appendToolCallTraceFromResult, readToolTraceEvents, verifyToolCallTraceLedgerV1 } =
	await import("../src/core/recon-profile.ts");

describe("tool-call trace ledger append read-amplification", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousMaxRows: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-trace-read-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		previousMaxRows = process.env[ENV_MAX_ROWS];
		process.env[ENV_AGENT_DIR] = agentDir;
		// High cap → no rotation, so the shared-read non-rotation path is exercised
		// purely (rotation appends re-read the report once; isolating the common
		// path keeps the read-count discriminator clean).
		process.env[ENV_MAX_ROWS] = "10000";
		ledgerReadCount.current = 0;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		if (previousMaxRows === undefined) delete process.env[ENV_MAX_ROWS];
		else process.env[ENV_MAX_ROWS] = previousMaxRows;
		rmSync(tempDir, { recursive: true, force: true });
	});

	function appendPair(toolCallId: string): void {
		const callEvent: ToolCallEvent = {
			type: "tool_call",
			toolCallId,
			toolName: "probe",
			input: { n: 1 },
		} as ToolCallEvent;
		appendToolCallTraceFromCall(callEvent, "mission-read-test");
		const resultEvent: ToolResultEvent = {
			type: "tool_result",
			toolCallId,
			toolName: "probe",
			input: { n: 1 },
			content: [{ type: "text", text: "ok" }],
			isError: false,
			details: undefined,
		} as ToolResultEvent;
		appendToolCallTraceFromResult(resultEvent, "mission-read-test");
	}

	it("reads the ledger ~once per append, not thrice (cached prevHash + shared rotation/report read)", () => {
		const pairs = 20;
		const appends = pairs * 2;
		for (let i = 0; i < pairs; i++) appendPair(`read-${i}`);

		// New code: ~1 ledger read per append (the shared readToolTraceEvents that
		// serves rotation + report) + 1 for the first append's cold latestToolTraceHash
		// cache → ~appends+1 reads. Old code: 3 reads per append (latestToolTraceHash +
		// rotate + report) → ~3*appends reads. The 2×appends threshold cleanly
		// separates them (new ~41 < 80; old ~120 > 80) with wide margin.
		expect(ledgerReadCount.current).toBeLessThan(2 * appends);

		// Behavior preserved: the chain verifies cleanly end-to-end with the REAL
		// runtime verifier. A broken prevHash chain (the one risk of caching the
		// latest hash) would surface as tool_trace_prev_hash_mismatch here.
		const events = readToolTraceEvents();
		const verdict = verifyToolCallTraceLedgerV1(events);
		if (!verdict.ok) throw new Error(`chain failed verification: ${verdict.errors.join("; ")}`);
		expect(verdict.ok).toBe(true);
		expect(events.length).toBe(appends);
		// The cached prevHash path produces a contiguous chain from genesis.
		expect(events[0].prevHash).toBe("0".repeat(64));
		for (let i = 1; i < events.length; i++) {
			expect(events[i].prevHash).toBe(events[i - 1].eventHash);
		}
	});
});

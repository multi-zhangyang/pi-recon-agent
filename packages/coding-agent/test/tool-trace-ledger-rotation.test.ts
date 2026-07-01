import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ToolCallEvent, ToolResultEvent } from "../src/core/extensions/types.ts";
import {
	appendToolCallTraceFromCall,
	appendToolCallTraceFromResult,
	readToolTraceEvents,
	verifyToolCallTraceLedgerV1,
} from "../src/core/recon-profile.ts";

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_ROWS = "REPI_TOOL_TRACE_LEDGER_MAX_ROWS";

// The tool-call trace ledger is an append-only hash chain that is re-read and
// re-verified on EVERY append (O(n²) over a session) and grows without bound
// on disk. Rotation caps it to the most recent N rows, re-hashing the tail
// forward from genesis so the chain invariant survives. This test is the
// safety net the codebase previously lacked — it drives rotation through the
// real append path and verifies the post-rotation chain with the REAL
// verifyToolCallTraceLedgerV1 (the runtime verifier).

describe("tool-call trace ledger rotation", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousMaxRows: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-trace-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		previousMaxRows = process.env[ENV_MAX_ROWS];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) {
			delete process.env[ENV_AGENT_DIR];
		} else {
			process.env[ENV_AGENT_DIR] = previousAgentDir;
		}
		if (previousMaxRows === undefined) {
			delete process.env[ENV_MAX_ROWS];
		} else {
			process.env[ENV_MAX_ROWS] = previousMaxRows;
		}
		rmSync(tempDir, { recursive: true, force: true });
	});

	function appendPair(toolCallId: string): void {
		const callEvent: ToolCallEvent = {
			type: "tool_call",
			toolCallId,
			toolName: "probe",
			input: { n: 1 },
		} as ToolCallEvent;
		appendToolCallTraceFromCall(callEvent, "mission-test");
		const resultEvent: ToolResultEvent = {
			type: "tool_result",
			toolCallId,
			toolName: "probe",
			input: { n: 1 },
			content: [{ type: "text", text: "ok" }],
			isError: false,
			details: undefined,
		} as ToolResultEvent;
		appendToolCallTraceFromResult(resultEvent, "mission-test");
	}

	it("caps the ledger to maxRows and keeps a chain that verifies cleanly after rotation", () => {
		// Small cap so rotation triggers after a few pairs. Each pair = 2 events.
		process.env[ENV_MAX_ROWS] = "6";
		// Append 10 pairs (20 events) — well past the cap, forcing rotation.
		for (let i = 0; i < 10; i++) {
			appendPair(`call-${i}`);
		}

		const events = readToolTraceEvents();
		// Rotation caps to <= maxRows, then trims forward to start at a "call".
		expect(events.length).toBeLessThanOrEqual(Number(process.env[ENV_MAX_ROWS]));
		expect(events.length).toBeGreaterThan(0);

		// The kept window must start at a "call" phase — a "result" at the head
		// would be orphaned (verifier rejects tool_trace_result_without_call).
		expect(events[0].phase).toBe("call");

		// The rotated head resets prevHash to genesis (the verifier walks from
		// "0".repeat(64)), proving the tail was re-hashed forward, not just
		// truncated leaving stale prevHash links.
		expect(events[0].prevHash).toBe("0".repeat(64));

		// The load-bearing assertion: the REAL runtime verifier accepts the
		// rotated chain. A broken rotation (no re-hash) leaves stale prevHash /
		// eventHash on the surviving head → verify reports
		// tool_trace_prev_hash_mismatch / tool_trace_event_hash_mismatch.
		const verdict = verifyToolCallTraceLedgerV1(events);
		if (!verdict.ok) {
			// Surface the specific errors on failure — a bare ok=false is opaque.
			throw new Error(`rotated chain failed verification: ${verdict.errors.join("; ")}`);
		}
		expect(verdict.ok).toBe(true);
		expect(verdict.errors).toEqual([]);

		// Every result in the kept window has its call present (no orphans).
		const calls = new Set(events.filter((e) => e.phase === "call").map((e) => e.toolCallId));
		for (const e of events) {
			if (e.phase === "result") expect(calls.has(e.toolCallId)).toBe(true);
		}
	});

	it("disables rotation when maxRows=0 (unbounded legacy behavior)", () => {
		process.env[ENV_MAX_ROWS] = "0";
		for (let i = 0; i < 5; i++) {
			appendPair(`unbounded-${i}`);
		}
		const events = readToolTraceEvents();
		// 5 pairs = 10 events, none trimmed.
		expect(events.length).toBe(10);
		expect(verifyToolCallTraceLedgerV1(events).ok).toBe(true);
	});

	it("leaves a sub-cap ledger untouched (no rotation)", () => {
		process.env[ENV_MAX_ROWS] = "100";
		for (let i = 0; i < 3; i++) {
			appendPair(`undercap-${i}`);
		}
		const events = readToolTraceEvents();
		expect(events.length).toBe(6);
		// Head is the first appended event, prevHash = genesis (unchained-rotated).
		expect(events[0].prevHash).toBe("0".repeat(64));
		expect(verifyToolCallTraceLedgerV1(events).ok).toBe(true);
	});
});

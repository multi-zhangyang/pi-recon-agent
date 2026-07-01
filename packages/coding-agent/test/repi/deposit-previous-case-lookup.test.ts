import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// opt #85 — O(1) previous-case lookup on the deposit path. appendMemoryEventTransaction
// (the per-tool_result auto-deposit hot path) used to find the prior case-memory row for the
// new event's caseSignature via `caseScan.rows.filter(r => r.caseSignature === sig).at(-1)` —
// an O(rows) scan of the WHOLE case-memory ledger on EVERY deposit. Over D deposits with N≈D
// case rows that is O(D²) redundant scanning. #85 replaces it with
// `latestCaseMemoryBySignature().get(sig)` — the #83 cached Map (last row per caseSignature,
// last-wins — identical semantics to filter().at(-1) since both read case-memory.jsonl
// top-to-bottom), keyed by (path, mtime+size) so it hits on the unchanged pre-append file.
//
// This is a SAME-BEHAVIOR perf refactor: the Map lookup returns the same `previousCase` value
// as the filter (no reference-identity signal like #81/#83/#84 — both produce the same row
// object value). So the load-bearing proof here is EQUIVALENCE + ACCUMULATION CORRECTNESS:
// depositing two events that SHARE a caseSignature must produce a second case row that
// ACCUMULATES from the first (eventIds grows, quality.reuseCount increments) — which only
// happens if `previousCase` was correctly resolved. A wrong lookup (undefined, or a row from a
// DIFFERENT signature) would drop the accumulation. Cross-signature isolation is also checked
// (two distinct signatures must NOT cross-contaminate), and the real store verifier still
// walks the full hash chain clean (correctness preserved).

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

const { appendMemoryEventTransaction } = await import("../../src/core/recon-profile.ts");
const { readCaseMemoryRows } = await import("../../src/core/repi/case-memory.ts");
const { latestCaseMemoryBySignature } = await import("../../src/core/repi/case-memory.ts");
const { verifyMemoryStore } = await import("../../src/core/repi/memory-store.ts");

describe("repi/deposit previous-case O(1) lookup (opt #85)", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-deposit-prevcase-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("two deposits sharing a caseSignature ACCUMULATE (previousCase resolved via the #83 Map)", () => {
		// First deposit seeds the case. Second deposit with the SAME caseSignature must find the
		// first case row as `previousCase` and accumulate: eventIds grows to 2, reuseCount
		// increments per success. If the lookup returned undefined (signature miss) the second
		// case row would have eventIds=[secondOnly] and reuseCount=1 — accumulation lost.
		appendMemoryEventTransaction({
			source: "manual",
			task: "first rop gadget",
			route: "re",
			caseSignature: "case-shared-sig",
			outcome: "success",
			commands: ["re_test first"],
		});
		appendMemoryEventTransaction({
			source: "manual",
			task: "second rop gadget",
			route: "re",
			caseSignature: "case-shared-sig",
			outcome: "success",
			commands: ["re_test second"],
		});

		// latestCaseMemoryBySignature is the same #83-cached Map the deposit path now uses, so
		// reading through it mirrors the deposit's own previousCase resolution.
		const latest = latestCaseMemoryBySignature();
		const caseRow = latest.get("case-shared-sig");
		expect(caseRow).toBeDefined();
		// Both events accumulated into the one case snapshot.
		expect(caseRow!.eventIds.length).toBe(2);
		// Two successes → reuseCount 2 (caseMemorySnapshotFromEvent increments on success).
		expect(caseRow!.quality.reuseCount).toBe(2);
		// commands from both events merged.
		expect(caseRow!.commands).toEqual(expect.arrayContaining(["re_test first", "re_test second"]));
	});

	it("distinct caseSignatures do NOT cross-contaminate (isolation)", () => {
		// Two deposits with DIFFERENT signatures must each resolve their own previousCase (or
		// undefined for the first) — a buggy lookup that returned the wrong signature's row
		// would leak eventIds/commands across cases.
		appendMemoryEventTransaction({
			source: "manual",
			task: "heap tcache",
			route: "re",
			caseSignature: "case-alpha",
			outcome: "success",
			commands: ["cmd-a"],
		});
		appendMemoryEventTransaction({
			source: "manual",
			task: "format string",
			route: "re",
			caseSignature: "case-beta",
			outcome: "success",
			commands: ["cmd-b"],
		});

		const latest = latestCaseMemoryBySignature();
		const a = latest.get("case-alpha");
		const b = latest.get("case-beta");
		expect(a).toBeDefined();
		expect(b).toBeDefined();
		expect(a!.eventIds.length).toBe(1);
		expect(b!.eventIds.length).toBe(1);
		expect(a!.commands).toEqual(["cmd-a"]);
		expect(b!.commands).toEqual(["cmd-b"]);
	});

	it("the hash chain + case index stay clean after repeated same-signature deposits (correctness)", () => {
		// Repeated deposits on one signature exercise the previousCase path under growth and
		// must keep the store verifier clean (the deposit's case snapshot + hash chain are
		// correct end-to-end). A stale/wrong previousCase would corrupt the case-memory ledger
		// and surface as a verify failure.
		for (let i = 0; i < 6; i++) {
			appendMemoryEventTransaction({
				source: "manual",
				task: `gadget ${i}`,
				route: "re",
				caseSignature: "case-chain",
				outcome: i % 3 === 0 ? "failure" : "success",
				commands: [`re_test ${i}`],
			});
		}
		const verdict = verifyMemoryStore({ write: false });
		expect(verdict.hashChainOk).toBe(true);
		expect(verdict.storeGrade).toBe("pass");
		// All 6 events folded into one case snapshot, eventIds accumulated.
		const rows = readCaseMemoryRows().filter((r) => r.caseSignature === "case-chain");
		const last = rows.at(-1);
		expect(last).toBeDefined();
		expect(last!.eventIds.length).toBe(6);
		// 4 successes (i=1,2,4,5) → reuseCount 4.
		expect(last!.quality.reuseCount).toBe(4);
	});
});

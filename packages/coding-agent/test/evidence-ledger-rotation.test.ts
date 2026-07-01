import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appendEvidence } from "../src/core/recon-profile.ts";
import type { EvidenceRecord } from "../src/core/repi/evidence.ts";
import { evidenceLedgerPath } from "../src/core/repi/storage.ts";

// Companion to the failure-ledger (#53) + repair-queue (#56) rotations. The
// evidence ledger (evidence/ledger.md) is an append-only MARKDOWN audit log,
// appended via the shared read-modify-write appendText (= appendPrivateTextFile:
// read whole file → atomic rewrite) on every appendEvidence call (34 call sites,
// per-phase / per-evidence-command). Before opt #57 it was NEVER rotated →
// unbounded cross-session disk growth + the O(n) read-modify-write per append
// grew with the file. The ledger has NO per-record count semantics and NO hash
// chain; readers (buildEvidenceDigest / evidenceLedgerGraphNodes) already
// truncate to a tail window or slice(-limit), so dropping old records is
// behavior-preserving. Rotation is record-aware (records are multi-line blocks
// each starting with a `## ` header) — it keeps the last N WHOLE records plus
// the `# REPI Evidence Ledger` preamble.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_RECORDS = "REPI_EVIDENCE_LEDGER_MAX_RECORDS";

function makeRecord(i: number): Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number } {
	return {
		kind: "runtime",
		title: `evidence-title-${i}`,
		fact: `fact-${i}: observed value ${i}`,
		command: `echo probe-${i}`,
	};
}

function recordTitles(text: string): string[] {
	return [...text.matchAll(/^##\s+\S+\s+—\s+P\d+\s+—\s+\S+\s+—\s+(.+)$/gm)].map((m) => (m[1] ?? "").trim());
}

describe("runtime evidence-ledger rotation", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousMaxRecords: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-evidence-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		previousAgentDir = process.env[ENV_AGENT_DIR];
		previousMaxRecords = process.env[ENV_MAX_RECORDS];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = previousAgentDir;
		if (previousMaxRecords === undefined) delete process.env[ENV_MAX_RECORDS];
		else process.env[ENV_MAX_RECORDS] = previousMaxRecords;
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("does not rotate when under the cap (maxRecords disabled = 0 keeps all)", () => {
		process.env[ENV_MAX_RECORDS] = "0"; // disable rotation
		for (let i = 1; i <= 5; i++) {
			appendEvidence(makeRecord(i));
		}
		const text = readFileSync(evidenceLedgerPath(), "utf-8");
		const titles = recordTitles(text);
		expect(titles.length).toBe(5);
		// All survive: head and tail both present, preamble preserved.
		expect(titles).toContain("evidence-title-1");
		expect(titles).toContain("evidence-title-5");
		expect(text.startsWith("# REPI Evidence Ledger")).toBe(true);
	});

	it("tail-rotates the evidence ledger, keeping the latest records and dropping the oldest", () => {
		process.env[ENV_MAX_RECORDS] = "4"; // small cap
		for (let i = 1; i <= 10; i++) {
			appendEvidence(makeRecord(i));
		}
		const text = readFileSync(evidenceLedgerPath(), "utf-8");
		const titles = recordTitles(text);
		// Capped to the last 4 whole records.
		expect(titles.length).toBeLessThanOrEqual(4);
		expect(titles.length).toBeGreaterThan(0);
		// Tail kept: the last appended record survives.
		expect(titles).toContain("evidence-title-10");
		// Head dropped: the first record is gone.
		expect(titles).not.toContain("evidence-title-1");
		// Preamble preserved across rotation (no mid-record tear of the header).
		expect(text.startsWith("# REPI Evidence Ledger")).toBe(true);
		// No partial record fragments: every `## ` header parses cleanly (the
		// record-count via regex equals the number of `## ` headers in the file).
		const headerCount = (text.match(/^##\s/gm) ?? []).length;
		expect(headerCount).toBe(titles.length);
	});

	it("keeps whole records (no mid-record tear) after rotation", () => {
		// Each record is a multi-line markdown block. After rotation the kept
		// records must be COMPLETE — fact/command lines intact — not torn at an
		// arbitrary byte/line boundary. Append 6 records, cap 3, then verify the
		// last record's fact + command lines both survive.
		process.env[ENV_MAX_RECORDS] = "3";
		for (let i = 1; i <= 6; i++) {
			appendEvidence(makeRecord(i));
		}
		const text = readFileSync(evidenceLedgerPath(), "utf-8");
		expect(text).toContain("evidence-title-6");
		expect(text).toContain("fact-6: observed value 6");
		expect(text).toContain("echo probe-6");
		// The dropped oldest record's fact line is gone.
		expect(text).not.toContain("fact-1: observed value 1");
	});
});

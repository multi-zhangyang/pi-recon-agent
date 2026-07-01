import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appendEvolution, appendJournal } from "../src/core/recon-profile.ts";
import { memoryPath } from "../src/core/repi/storage.ts";

// Companion to the evidence-ledger rotation (#57) + failure-ledger (#53) +
// repair-queue (#56) rotations. The three memory journals — field-journal.md,
// case-index.md, evolution-log.md — are append-only MARKDOWN audit logs
// appended via the shared read-modify-write appendText (= appendPrivateTextFile)
// on every appendJournal / appendEvolution call, and read per-recall via
// truncateMiddle / slice(-5). Before opt #58 they were NEVER rotated → unbounded
// cross-session disk growth + the O(n) read-modify-write per append grew with
// the file. None has per-record count semantics or a hash chain; readers already
// keep only the tail, so dropping old records is behavior-preserving. field-
// journal + evolution-log are `## `-headered block ledgers (record-aware tail-
// cap); case-index is one `- ` bullet line per entry (line tail-cap). All three
// keep the `# REPI <Name>` preamble. REPI_JOURNAL_MAX_RECORDS (default 500, 0 =
// disable) bounds all three.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_RECORDS = "REPI_JOURNAL_MAX_RECORDS";

function blockRecordAnchors(text: string): string[] {
	return [...text.matchAll(/^##\s+(.+)$/gm)].map((m) => (m[1] ?? "").trim());
}

function caseIndexEntries(text: string): string[] {
	return [...text.matchAll(/^-\s+.+keywords:\s+(.+)$/gm)].map((m) => (m[1] ?? "").trim());
}

describe("runtime memory-journal rotation", () => {
	let tempDir: string;
	let agentDir: string;
	let previousAgentDir: string | undefined;
	let previousMaxRecords: string | undefined;

	beforeEach(() => {
		tempDir = `${tmpdir()}/repi-journal-test-${Date.now()}-${Math.random().toString(36).slice(2)}`;
		agentDir = `${tempDir}/agent`;
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
			appendJournal(`scene-${i}`, `title-${i}`, `body line ${i} with detail`);
		}
		const journal = readFileSync(memoryPath("field-journal.md"), "utf-8");
		const index = readFileSync(memoryPath("case-index.md"), "utf-8");
		// All 5 field-journal records + 5 case-index entries survive.
		expect(blockRecordAnchors(journal).length).toBe(5);
		expect(caseIndexEntries(index).length).toBe(5);
		// Preambles preserved.
		expect(journal.startsWith("# REPI Field Journal")).toBe(true);
		expect(index.startsWith("# REPI Case Index")).toBe(true);
	});

	it("tail-rotates field-journal + case-index together, keeping the latest", () => {
		process.env[ENV_MAX_RECORDS] = "4"; // small cap
		for (let i = 1; i <= 10; i++) {
			appendJournal(`scene-${i}`, `title-${i}`, `body line ${i}`);
		}
		const journal = readFileSync(memoryPath("field-journal.md"), "utf-8");
		const index = readFileSync(memoryPath("case-index.md"), "utf-8");
		const journalAnchors = blockRecordAnchors(journal);
		const indexEntries = caseIndexEntries(index);
		// Both cap to the last 4 records.
		expect(journalAnchors.length).toBeLessThanOrEqual(4);
		expect(journalAnchors.length).toBeGreaterThan(0);
		expect(indexEntries.length).toBeLessThanOrEqual(4);
		// Tail kept: the last appended survives.
		expect(journalAnchors.some((a) => a.endsWith("title-10"))).toBe(true);
		expect(indexEntries.some((e) => e.endsWith("scene-10,title-10"))).toBe(true);
		// Head dropped: the first is gone (endsWith avoids title-10 matching title-1).
		expect(journalAnchors.some((a) => a.endsWith("title-1"))).toBe(false);
		expect(indexEntries.some((e) => e.endsWith("scene-1,title-1"))).toBe(false);
		// Preambles preserved across rotation.
		expect(journal.startsWith("# REPI Field Journal")).toBe(true);
		expect(index.startsWith("# REPI Case Index")).toBe(true);
		// No partial `## ` fragments: header count equals parsed-anchor count.
		expect((journal.match(/^##\s/gm) ?? []).length).toBe(journalAnchors.length);
	});

	it("tail-rotates evolution-log (## block ledger), keeping whole records", () => {
		process.env[ENV_MAX_RECORDS] = "3";
		for (let i = 1; i <= 6; i++) {
			appendEvolution(`evo-title-${i}`, `evolution body line ${i} with detail`);
		}
		const evo = readFileSync(memoryPath("evolution-log.md"), "utf-8");
		const anchors = blockRecordAnchors(evo);
		expect(anchors.length).toBeLessThanOrEqual(3);
		// Tail kept, head dropped, preamble preserved.
		expect(anchors.some((a) => a.includes("evo-title-6"))).toBe(true);
		expect(anchors.some((a) => a.includes("evo-title-1"))).toBe(false);
		expect(evo.startsWith("# REPI Evolution Log")).toBe(true);
		// Whole-record integrity: the last record's body line survives intact
		// (no mid-record tear at a byte/line boundary).
		expect(evo).toContain("evolution body line 6 with detail");
		// The dropped oldest record's body line is gone.
		expect(evo).not.toContain("evolution body line 1 with detail");
	});
});

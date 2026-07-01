import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	contextCompactionLedger,
	rotateCompactionResumeLedgerIfNeeded,
	verifyCompactionResumeLedger,
} from "../src/core/repi/memory-compact-resume.ts";
import { appendPrivateTextFile, memoryPath } from "../src/core/repi/storage.ts";
import { sha256Text } from "../src/core/repi/text.ts";

// opt #106 F4: compaction-resume-ledger.jsonl is an append-only hash chain where
// each row's prevHash = sha256 of ALL prior raw lines (a running prefix hash, not
// a per-record link), so verifyCompactionResumeLedger is O(N²) in hashing and the
// file grows by one row per context-pack with no bound — unlike the sibling
// tool-trace ledger (#48) and memory-quality ledger which rotate. This test
// builds a valid chain of >cap rows (using the verifier's own accumulation scheme
// — prevHash = sha256 of prior non-empty lines each + "\n", genesis "0".repeat(64)
// — so pre-rotation verify returns "pass"), sets a small REPI_COMPACTION_LEDGER_MAX_ROWS
// cap, calls rotateCompactionResumeLedgerIfNeeded(), and asserts (a) the on-disk
// row count is capped, and (b) verifyCompactionResumeLedger still returns "pass" —
// the rotation re-hashes the kept tail forward from a fresh genesis so the verifier
// (which walks from genesis) accepts it cleanly. The regression probe is the
// row-count cap: with rotation neutered the file grows unbounded and the cap
// assertion fails.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_ROWS = "REPI_COMPACTION_LEDGER_MAX_ROWS";

describe("compaction-resume ledger rotation (opt #106 F4)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;
	let prevMaxRows: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt106-rotate-"));
		const agentDir = join(tempDir, "agent");
		mkdirSync(agentDir, { recursive: true });
		prevAgentDir = process.env[ENV_AGENT_DIR];
		prevMaxRows = process.env[ENV_MAX_ROWS];
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (prevAgentDir === undefined) delete process.env[ENV_AGENT_DIR];
		else process.env[ENV_AGENT_DIR] = prevAgentDir;
		if (prevMaxRows === undefined) delete process.env[ENV_MAX_ROWS];
		else process.env[ENV_MAX_ROWS] = prevMaxRows;
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
	});

	function ledgerRows(): number {
		const text = readFileSync(memoryPath("compaction-resume-ledger.jsonl"), "utf-8");
		return text.split(/\r?\n/).filter((line) => line.trim()).length;
	}

	/** Build a chain of `count` rows that verifyCompactionResumeLedger accepts, using
	 * the verifier's own accumulation scheme, and write it to the ledger at once. */
	function writeVerifiableChain(count: number): void {
		const path = memoryPath("compaction-resume-ledger.jsonl");
		mkdirSync(dirname(path), { recursive: true });
		let previousText = "";
		const lines: string[] = [];
		for (let i = 0; i < count; i++) {
			const ts = `2026-01-01T00:00:${String(i).padStart(2, "0")}Z`;
			const prevHash = previousText.trim() ? sha256Text(previousText) : "0".repeat(64);
			const entryHash = sha256Text(`${prevHash}\n${ts}\ncontext-pack`);
			const line = JSON.stringify({ ts, prevHash, entryHash });
			lines.push(line);
			previousText += `${line}\n`;
		}
		writeFileSync(path, `${lines.join("\n")}\n`, "utf-8");
	}

	it("rotation caps on-disk rows and the re-hashed tail still verifies clean", () => {
		const cap = 5;
		process.env[ENV_MAX_ROWS] = String(cap);

		writeVerifiableChain(cap + 8);
		expect(ledgerRows(), "pre-rotation row count").toBe(cap + 8);
		expect(verifyCompactionResumeLedger().status, "pre-rotation verifies clean").toBe("pass");

		rotateCompactionResumeLedgerIfNeeded();

		expect(ledgerRows(), "post-rotation row count capped").toBe(cap);
		// The kept tail was re-hashed forward from a fresh genesis; the verifier
		// walks from genesis, so it accepts the genesis-reset head + re-hashed tail.
		const verdict = verifyCompactionResumeLedger();
		expect(verdict.status, "post-rotation still verifies clean").toBe("pass");
		expect(verdict.blocked, "no chain drift after rotation").toEqual([]);
	});

	it("rotation is a no-op when row count is within the cap", () => {
		const cap = 5;
		process.env[ENV_MAX_ROWS] = String(cap);
		writeVerifiableChain(cap);
		const before = ledgerRows();
		rotateCompactionResumeLedgerIfNeeded();
		expect(ledgerRows(), "no truncation when within cap").toBe(before);
		expect(verifyCompactionResumeLedger().status, "still verifies clean").toBe("pass");
	});

	it("contextCompactionLedger + appendPrivateTextFile produces a chain that verifies clean (no leading-\\n desync)", () => {
		// Production path: the ledger is appended via appendPrivateTextFile, which
		// prepends a leading "\n" on a fresh file. contextCompactionLedger must
		// compute prevHash with the verifier's empty-line-skipping scheme (NOT the
		// raw file hash) or the chain desyncs at row 1+ and verify archives it.
		const path = memoryPath("compaction-resume-ledger.jsonl");
		mkdirSync(dirname(path), { recursive: true });
		for (let i = 0; i < 6; i++) {
			const ts = `2026-01-01T00:00:${String(i).padStart(2, "0")}Z`;
			const { prevHash, entryHash } = contextCompactionLedger(ts);
			appendPrivateTextFile(path, `${JSON.stringify({ ts, prevHash, entryHash })}\n`);
		}
		const verdict = verifyCompactionResumeLedger();
		expect(verdict.status, "production-style chain verifies clean").toBe("pass");
		expect(verdict.blocked, "no chain drift").toEqual([]);
		expect(verdict.rows, "all rows counted").toBe(6);
	});
});

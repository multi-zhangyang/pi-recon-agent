import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonlRecords } from "../src/core/repi/jsonl.ts";
import {
	governanceLedgerMaxRows,
	isMemoryGovernanceLedgerRow,
	rotateGovernanceLedgerIfNeeded,
} from "../src/core/repi/memory-search.ts";
import { writeFileAtomic } from "../src/core/repi/memory-store.ts";
import { appendPrivateTextFile, ensureRepiStorage, memoryGovernanceLedgerPath } from "../src/core/repi/storage.ts";

// opt #107: two REPI state-machinery fixes.
// (1) The memory-governance ledger was appended via bare `writeFileSync(flag:"a")`
// (non-atomic — a crash mid-append leaves a partial trailing JSON line that
// jsonlRecords silently drops per-line) AND had no rotation cap (unbounded growth,
// O(N) cold parse). The append sites now use the shared atomic appendPrivateTextFile
// (#67) + rotateGovernanceLedgerIfNeeded (REPI_GOVERNANCE_LEDGER_MAX_ROWS, default
// 500). The rows have no hash-chain fields so the head is disposable without re-hash
// (same contract as case-memory #99).
// (2) writeFileAtomic (repi/memory-store.ts) orphans its outer .tmp on a renameSync
// throw / mid-sequence crash (no try/catch unlink) — on the deposit hot path a
// transient rename failure would accumulate .tmp files. Now wrapped in try/catch
// that unlinks the orphaned temp before re-throwing.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";
const ENV_MAX_ROWS = "REPI_GOVERNANCE_LEDGER_MAX_ROWS";

vi.setConfig({ testTimeout: 30_000 });

describe("memory-governance ledger rotation (opt #107)", () => {
	let tempDir: string;
	let prevAgentDir: string | undefined;
	let prevMaxRows: string | undefined;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt107-gov-"));
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
		return jsonlRecords(memoryGovernanceLedgerPath(), isMemoryGovernanceLedgerRow).length;
	}

	function appendGovernanceRow(index: number): void {
		const row = {
			kind: "repi-memory-ux-governance-decision",
			action: "promote",
			applied: true,
			sourceEventId: `evt-${index}`,
			eventId: `evt-out-${index}`,
			reason: `row ${index}`,
			id: `gov-${index}`,
		};
		appendPrivateTextFile(memoryGovernanceLedgerPath(), `${JSON.stringify(row)}\n`);
	}

	it("rotation caps on-disk rows to the last REPI_GOVERNANCE_LEDGER_MAX_ROWS and keeps the tail", () => {
		const cap = 5;
		process.env[ENV_MAX_ROWS] = String(cap);

		ensureRepiStorage();
		// Append cap + 8 rows so the tail-keep is observable.
		for (let i = 0; i < cap + 8; i++) appendGovernanceRow(i);
		expect(ledgerRows(), "pre-rotation row count").toBe(cap + 8);

		rotateGovernanceLedgerIfNeeded();

		const rows = jsonlRecords(memoryGovernanceLedgerPath(), isMemoryGovernanceLedgerRow);
		expect(rows.length, "post-rotation row count capped").toBe(cap);
		// The kept tail is the LAST `cap` rows (ids gov-7..gov-12), not the head.
		expect(rows.map((r) => r.id)).toEqual(Array.from({ length: cap }, (_, k) => `gov-${cap + 8 - cap + k}`));
	});

	it("rotation is a no-op when row count is within the cap", () => {
		const cap = 5;
		process.env[ENV_MAX_ROWS] = String(cap);
		ensureRepiStorage();
		for (let i = 0; i < cap; i++) appendGovernanceRow(i);
		const before = ledgerRows();
		rotateGovernanceLedgerIfNeeded();
		expect(ledgerRows(), "no truncation when within cap").toBe(before);
	});

	it("rotation is a no-op when cap is 0 (disabled)", () => {
		process.env[ENV_MAX_ROWS] = "0";
		ensureRepiStorage();
		for (let i = 0; i < 12; i++) appendGovernanceRow(i);
		rotateGovernanceLedgerIfNeeded();
		expect(ledgerRows(), "cap=0 disables rotation").toBe(12);
	});

	it("governanceLedgerMaxRows reads the env and falls back to the default", () => {
		delete process.env[ENV_MAX_ROWS];
		expect(governanceLedgerMaxRows(), "default when unset").toBe(500);
		process.env[ENV_MAX_ROWS] = "42";
		expect(governanceLedgerMaxRows(), "parsed value").toBe(42);
		process.env[ENV_MAX_ROWS] = "0";
		expect(governanceLedgerMaxRows(), "0 honored (disable)").toBe(0);
		process.env[ENV_MAX_ROWS] = "not-a-number";
		expect(governanceLedgerMaxRows(), "non-numeric falls back").toBe(500);
		process.env[ENV_MAX_ROWS] = "-3";
		expect(governanceLedgerMaxRows(), "negative falls back").toBe(500);
	});
});

describe("writeFileAtomic unlinks orphaned .tmp on renameSync throw (opt #107)", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-opt107-atomic-"));
	});

	afterEach(() => {
		if (tempDir) rmSync(tempDir, { recursive: true, force: true });
	});

	it("no .tmp leftover when the final rename fails (target is a directory)", () => {
		// Make the final `path` an existing DIRECTORY: writePrivateTextFile(tmp)
		// succeeds (tmp is a file path in the same parent), but renameSync(tmp, path)
		// throws EISDIR/ENOTDIR because a file cannot replace a non-empty directory.
		// Pre-fix the .tmp is orphaned; post-fix the catch unlinks it before re-throw.
		const dir = join(tempDir, "ledger.jsonl");
		mkdirSync(dir, { recursive: true });
		// Drop a sentinel inside so the dir is non-empty (forces EEXIST/EISDIR-style
		// failure on rename-over even on filesystems that allow empty-dir replace).
		const sentinel = join(dir, "keep");
		mkdirSync(sentinel, { recursive: true });

		// tmp is `${path}.${pid}.${ts}.${rand}.tmp` — a FILE sibling of `dir`.
		// Capture the exact tmp path writeFileAtomic will create so we can assert
		// its absence after the throw. We reconstruct it by globbing post-throw.
		const parent = dirname(dir);

		expect(() => writeFileAtomic(dir, "body\n")).toThrow();

		// No `.tmp` leftover in the parent (the orphaned temp was unlinked).
		const tmpLeftovers = readdirSync(parent).filter((f) => f.endsWith(".tmp"));
		expect(tmpLeftovers, "no orphaned .tmp after renameSync throw").toEqual([]);

		// The original target directory is untouched (rename never succeeded).
		expect(existsSync(sentinel), "target dir preserved").toBe(true);
	});

	it("writes atomically on the normal path (regression guard)", () => {
		const path = join(tempDir, "events.jsonl");
		writeFileAtomic(path, '{"seq":1}\n');
		expect(existsSync(path), "target written").toBe(true);
		expect(statSync(path).mode & 0o777, "mode 0o600").toBe(0o600);
		// No .tmp leftover on the happy path either.
		expect(readdirSync(tempDir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
	});
});

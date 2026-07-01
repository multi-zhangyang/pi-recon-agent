import { mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { writeLocalClaimReleaseMarker } from "../src/core/recon-profile.ts";
import { evidenceLedgerPath } from "../src/core/repi/storage.ts";

// opt #186 — writeLocalClaimReleaseMarker built `source = [..., readText(evidenceLedgerPath()).slice(-12000), ...]`
// then stored `sourceSha256: sha256Text(source)` with NO field recording that the
// ledger was tail-truncated or its original size. Two runs whose ledgers differ
// only in the dropped head → same hash (false match); two runs identical except a
// new tail entry shifting an old one across the 12000 boundary → different hashes
// (false diff) with no way for a verifier to distinguish. Fix: record a
// `sourceTruncated` field { ledger: true, keptChars: 12000, originalChars: <statSync size> }
// so the truncation is VISIBLE to consumers. The marker writer is driven against a
// temp REPI storage layout (REPI_CODING_AGENT_DIR override) with a >12000-char ledger.

const ENV_AGENT_DIR = "REPI_CODING_AGENT_DIR";

describe("claim/release marker truncation metadata (opt #186)", () => {
	let tempDir: string;
	let previousAgentDir: string | undefined;

	beforeEach(() => {
		previousAgentDir = process.env[ENV_AGENT_DIR];
		tempDir = join(
			tmpdir(),
			`repi-claim-release-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
		);
		mkdirSync(tempDir, { recursive: true });
		process.env[ENV_AGENT_DIR] = tempDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) {
			delete process.env[ENV_AGENT_DIR];
		} else {
			process.env[ENV_AGENT_DIR] = previousAgentDir;
		}
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("records sourceTruncated with the original ledger size when the ledger exceeds the 12000-char tail cap", () => {
		// Build a ledger well over the 12000-char tail cap.
		const ledgerDir = join(tempDir, "recon", "evidence");
		mkdirSync(ledgerDir, { recursive: true });
		const ledgerContent = `# Evidence Ledger\n${"x".repeat(50_000)}`;
		writeFileSync(evidenceLedgerPath(), ledgerContent, "utf8");
		const expectedOriginal = statSync(evidenceLedgerPath()).size;

		const markerPath = writeLocalClaimReleaseMarker();
		const marker = JSON.parse(readFileSync(markerPath, "utf8")) as {
			sourceTruncated?: {
				ledger: boolean;
				keptChars: number;
				originalChars: number;
			};
			sourceSha256?: string;
		};

		expect(marker.sourceTruncated).toBeDefined();
		expect(marker.sourceTruncated?.ledger).toBe(true);
		expect(marker.sourceTruncated?.keptChars).toBe(12000);
		// originalChars matches the real on-disk byte size (not the truncated tail).
		expect(marker.sourceTruncated?.originalChars).toBe(expectedOriginal);
		expect(marker.sourceTruncated?.originalChars).toBeGreaterThan(12000);
		// Hash still present (unchanged contract).
		expect(typeof marker.sourceSha256).toBe("string");
		expect(marker.sourceSha256?.length).toBe(64);
	});

	it("records originalChars=0 when the ledger is absent (readText fallback, no spurious truncation claim)", () => {
		// No ledger file written. readText returns "" (fallback); statSync guard
		// yields 0. The marker still records the field so consumers can see the
		// ledger was empty rather than silently absent.
		const markerPath = writeLocalClaimReleaseMarker();
		const marker = JSON.parse(readFileSync(markerPath, "utf8")) as {
			sourceTruncated?: { ledger: boolean; keptChars: number; originalChars: number };
		};

		expect(marker.sourceTruncated).toBeDefined();
		expect(marker.sourceTruncated?.ledger).toBe(true);
		expect(marker.sourceTruncated?.keptChars).toBe(12000);
		expect(marker.sourceTruncated?.originalChars).toBe(0);
	});
});

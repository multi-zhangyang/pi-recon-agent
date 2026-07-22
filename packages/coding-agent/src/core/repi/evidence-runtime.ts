import { join } from "node:path";
import type { AgentThreadRunManifest } from "../agent-thread-manager.ts";
import {
	appendEvidenceRecord,
	buildContextEvidenceTail as buildRepiContextEvidenceTail,
	buildEvidenceDigest as buildRepiEvidenceDigest,
	type EvidenceRecord,
} from "./evidence.ts";
import { type MissionCheckpointStatus, readCurrentMission, updateMissionCheckpoint } from "./mission.ts";
import { ensureReconStorage } from "./resources.ts";
import { appendPrivateTextFile, evidenceLedgerPath, readTextFile, writePrivateTextFile } from "./storage.ts";
import { shellQuote } from "./target.ts";
import { envBoolean, redactSensitiveText, truncateMiddle } from "./text.ts";

function evidenceLedgerMaxRecords(): number {
	const raw = process.env.REPI_EVIDENCE_LEDGER_MAX_RECORDS;
	if (raw === undefined) return 500;
	const value = Math.floor(Number(raw));
	return Number.isFinite(value) && value >= 0 ? value : 500;
}

function rotateEvidenceLedger(): void {
	const maxRecords = evidenceLedgerMaxRecords();
	if (maxRecords <= 0) return;
	const path = evidenceLedgerPath();
	const text = readTextFile(path);
	if (!text.trim()) return;
	const firstHeader = text.search(/^##\s/m);
	if (firstHeader === -1) return;
	const preamble = firstHeader > 0 ? text.slice(0, firstHeader) : "";
	const records = text
		.slice(firstHeader)
		.split(/^##\s/m)
		.map((record) => record.replace(/^\n+/, ""))
		.filter((record) => record.trim());
	if (records.length <= maxRecords) return;
	writePrivateTextFile(
		path,
		`${preamble}${records
			.slice(-maxRecords)
			.map((record) => `## ${record}`)
			.join("\n\n")}\n`,
	);
}

export function appendEvidence(
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
): EvidenceRecord {
	const full = appendEvidenceRecord(
		{ ...record, missionId: record.missionId ?? readCurrentMission()?.id },
		{
			ensureStorage: ensureReconStorage,
			writeText: writePrivateTextFile,
			appendText: appendPrivateTextFile,
			onLedgerUpdated: (updated) => updateMissionCheckpoint("evidence_ledger_updated", "done", updated.title),
		},
	);
	rotateEvidenceLedger();
	return full;
}

export function appendAgentThreadEvidence(
	manifest: AgentThreadRunManifest,
	options: {
		title: string;
		fact: string;
		command: string;
		confidence: string;
		checkpoint?: { name: string; status: MissionCheckpointStatus; note: string };
	},
): EvidenceRecord {
	const path = manifest.mergePath ?? join(manifest.runRoot, "merge.md");
	const streamHashes = [
		manifest.stdoutSha256 ? `stdout_sha256=${manifest.stdoutSha256}` : undefined,
		manifest.stderrSha256 ? `stderr_sha256=${manifest.stderrSha256}` : undefined,
	].filter((value): value is string => Boolean(value));
	const record = appendEvidence({
		kind: "runtime",
		title: options.title,
		fact: redactSensitiveText(`${options.fact}; ${streamHashes.join("; ") || "stream_hashes=missing"}`),
		command: redactSensitiveText(options.command),
		path,
		hash: manifest.stdoutSha256 ?? manifest.stderrSha256,
		verify: `cat ${shellQuote(path)}`,
		confidence: options.confidence,
	});
	if (options.checkpoint) {
		updateMissionCheckpoint(options.checkpoint.name, options.checkpoint.status, options.checkpoint.note);
	}
	return record;
}

export function buildEvidenceDigest(query?: string): string {
	return buildRepiEvidenceDigest(query, {
		ensureStorage: ensureReconStorage,
		readText: readTextFile,
		truncate: truncateMiddle,
	});
}

export function buildContextEvidenceTail(options: { target?: string } = {}): string {
	return buildRepiContextEvidenceTail({
		...options,
		autoContextPack: envBoolean("REPI_EVIDENCE_CONTEXT_PACK") === true,
		ensureStorage: ensureReconStorage,
		readText: readTextFile,
		truncate: truncateMiddle,
	});
}

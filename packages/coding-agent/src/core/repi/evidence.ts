import { existsSync, readFileSync, statSync } from "node:fs";
import { evidenceLedgerPath } from "./storage.ts";

export type EvidenceKind = "runtime" | "traffic" | "served_asset" | "process_config" | "artifact" | "source" | "note";

export type EvidenceRecord = {
	timestamp: string;
	kind: EvidenceKind;
	priority: number;
	title: string;
	fact: string;
	command?: string;
	path?: string;
	offset?: string;
	hash?: string;
	verify?: string;
	confidence?: string;
};

export type EvidenceGraphNode = {
	id: string;
	kind: "evidence";
	label: string;
	status?: string;
	priority?: number;
	note?: string;
};

type EvidenceIoOptions = {
	ensureStorage?: () => void;
	readText?: (path: string, fallback?: string) => string;
	truncate?: (text: string, limit: number) => string;
};

type AppendEvidenceOptions = EvidenceIoOptions & {
	appendText: (path: string, text: string) => void;
	onLedgerUpdated?: (record: EvidenceRecord) => void;
	now?: () => Date;
};

function readTextFile(path: string, fallback = ""): string {
	try {
		return readFileSync(path, "utf-8");
	} catch {
		return fallback;
	}
}

function truncateMiddle(text: string, limit: number): string {
	if (text.length <= limit) return text;
	const head = Math.floor(limit * 0.55);
	const tail = Math.floor(limit * 0.35);
	return `${text.slice(0, head)}\n...<truncated ${text.length - limit} chars>...\n${text.slice(-tail)}`;
}

function lineCount(path: string, readText = readTextFile): number {
	const text = readText(path);
	if (!text.trim()) return 0;
	return text.split(/\r?\n/).filter((line) => line.trim()).length;
}

function slug(text: string): string {
	return text
		.toLowerCase()
		.replace(/[^a-z0-9._-]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 80);
}

export function evidencePriority(kind: EvidenceKind): number {
	switch (kind) {
		case "runtime":
			return 1;
		case "traffic":
			return 2;
		case "served_asset":
			return 3;
		case "process_config":
			return 4;
		case "artifact":
			return 5;
		case "source":
			return 6;
		case "note":
			return 7;
	}
}

export function formatEvidenceRecord(record: EvidenceRecord): string {
	return [
		`## ${record.timestamp} — P${record.priority} — ${record.kind} — ${record.title}`,
		"",
		`- fact: ${record.fact}`,
		record.command ? `- command: \`${record.command.replace(/`/g, "\\`")}\`` : undefined,
		record.path ? `- path: ${record.path}` : undefined,
		record.offset ? `- offset: ${record.offset}` : undefined,
		record.hash ? `- hash: ${record.hash}` : undefined,
		record.verify ? `- verify: ${record.verify}` : undefined,
		record.confidence ? `- confidence: ${record.confidence}` : undefined,
		"",
	]
		.filter((line): line is string => line !== undefined)
		.join("\n");
}

export function appendEvidenceRecord(
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
	options: AppendEvidenceOptions,
): EvidenceRecord {
	options.ensureStorage?.();
	const full: EvidenceRecord = {
		timestamp: (options.now?.() ?? new Date()).toISOString(),
		...record,
		priority: record.priority ?? evidencePriority(record.kind),
	};
	options.appendText(evidenceLedgerPath(), formatEvidenceRecord(full));
	options.onLedgerUpdated?.(full);
	return full;
}

export function buildEvidenceDigest(query?: string, options: EvidenceIoOptions = {}): string {
	options.ensureStorage?.();
	const readText = options.readText ?? readTextFile;
	const truncate = options.truncate ?? truncateMiddle;
	const text = readText(evidenceLedgerPath()).trim();
	if (!text) return "证据 ledger 为空；用 re_evidence append 记录 runtime/traffic/source 等证据。";
	if (!query) return truncate(text, 6000);
	const lower = query.toLowerCase();
	const lines = text
		.split(/\r?\n/)
		.filter((line) => line.toLowerCase().includes(lower))
		.slice(-160);
	return lines.length ? lines.join("\n") : "No matching evidence lines";
}

export function buildStartupEvidenceDigest(
	options: EvidenceIoOptions & { target?: string; autoInject?: boolean } = {},
): string {
	options.ensureStorage?.();
	if (options.autoInject === true) return buildEvidenceDigest(options.target, options);
	const path = evidenceLedgerPath();
	const readText = options.readText ?? readTextFile;
	const rows = lineCount(path, readText);
	const bytes = existsSync(path) ? statSync(path).size : 0;
	return [
		"evidence_startup_isolation:",
		"historical_evidence_ledger=not_injected_by_default",
		`ledger_path=${path}`,
		`ledger_rows=${rows}`,
		`ledger_bytes=${bytes}`,
		"manual_recall:",
		"- re_evidence show",
		"- re_evidence show <query>",
		"opt_in:",
		"- set REPI_EVIDENCE_AUTO_INJECT=1 for legacy startup evidence injection",
	].join("\n");
}

export function buildContextEvidenceTail(
	options: EvidenceIoOptions & { target?: string; autoContextPack?: boolean } = {},
): string {
	const truncate = options.truncate ?? truncateMiddle;
	if (options.autoContextPack === true) return truncate(buildEvidenceDigest(undefined, options), 7000);
	if (options.target) {
		const scoped = buildEvidenceDigest(options.target, options);
		if (scoped && scoped !== "No matching evidence lines" && !scoped.startsWith("证据 ledger 为空")) {
			return truncate(scoped, 7000);
		}
	}
	return buildStartupEvidenceDigest(options);
}

export function evidenceLedgerGraphNodes(
	limit = 14,
	options: Pick<EvidenceIoOptions, "readText"> = {},
): EvidenceGraphNode[] {
	const readText = options.readText ?? readTextFile;
	const text = readText(evidenceLedgerPath());
	const records = [...text.matchAll(/^##\s+(.+?)\s+—\s+P(\d+)\s+—\s+(.+?)\s+—\s+(.+)$/gm)].slice(-limit);
	return records.map((match, index) => ({
		id: `evidence:${index}:${slug(match[4] ?? "evidence")}`,
		kind: "evidence",
		label: match[4]?.trim() ?? "evidence",
		status: match[3]?.trim(),
		priority: Number.parseInt(match[2] ?? "7", 10),
		note: match[1]?.trim(),
	}));
}

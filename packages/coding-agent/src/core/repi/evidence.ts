import { closeSync, existsSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { safeHeadEnd, safeTailStart } from "../tools/truncate.ts";
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

// opt #164 — stat-first OOM guard cap (bytes) for the evidence.ts local
// readTextFile. Shares the SAME REPI_READ_TEXT_FILE_MAX_BYTES knob as
// storage.ts readTextFile (#163) so the two readTextFile impls obey one cap.
// The old readTextFile did readFileSync(path, "utf-8") of the WHOLE file;
// evidence artifacts (captured tool output, binary-as-text dumps, large log
// captures) can be many MB to GB → OOM before any consumer runs. Files over
// the cap return a bounded TAIL (last `cap` bytes) with a leading
// `[truncated ...]` marker, NOT the fallback sentinel, because every
// evidence.ts consumer renders the text to the model and treats it as text
// (split / regex / trim) — none JSON.parse it (the marker line is filtered
// out by buildEvidenceDigest's query filter and ignored by the
// evidenceLedgerGraphNodes `^## ` regex). 0 disables the guard. Consistent
// with opt #34's REPI_READ_MAX_FILE_BYTES (16 MB).
const DEFAULT_READ_TEXT_FILE_MAX_BYTES = 16 * 1024 * 1024;
const EVIDENCE_IO_CHUNK_SIZE = 1024 * 1024;

function resolveReadTextFileMaxBytes(): number {
	const raw = process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
	if (raw !== undefined && raw.trim() !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed) && parsed >= 0) return Math.floor(parsed);
	}
	return DEFAULT_READ_TEXT_FILE_MAX_BYTES;
}

function readBoundedTail(path: string, size: number, cap: number): string {
	const tailLen = Math.min(cap, size);
	const fd = openSync(path, "r");
	try {
		const buf = Buffer.alloc(tailLen);
		const start = size - tailLen;
		let pos = 0;
		while (pos < tailLen) {
			const n = readSync(fd, buf, pos, Math.min(EVIDENCE_IO_CHUNK_SIZE, tailLen - pos), start + pos);
			if (n <= 0) break;
			pos += n;
		}
		const body = buf.subarray(0, pos).toString("utf-8");
		const dropped = size - pos;
		return `[truncated ${dropped} bytes from head, showing last ${pos} bytes of ${size}]\n${body}`;
	} finally {
		try {
			closeSync(fd);
		} catch {
			// Best-effort: fd may already be invalid.
		}
	}
}

export function readTextFile(path: string, fallback = ""): string {
	try {
		const size = statSync(path).size;
		const cap = resolveReadTextFileMaxBytes();
		if (cap > 0 && size > cap) {
			return readBoundedTail(path, size, cap);
		}
		return readFileSync(path, "utf-8");
	} catch {
		return fallback;
	}
}

function truncateMiddle(text: string, limit: number): string {
	if (text.length <= limit) return text;
	const head = Math.floor(limit * 0.55);
	const tail = Math.floor(limit * 0.35);
	const headEnd = safeHeadEnd(text, head);
	const tailStart = safeTailStart(text, text.length - tail);
	return `${text.slice(0, headEnd)}\n...<truncated ${text.length - limit} chars>...\n${text.slice(tailStart)}`;
}

// opt #164 — count non-whitespace lines in `path` via a streaming positioned
// readSync loop, WITHOUT loading the whole file or building a line array. The
// old lineCount did readTextFile (readFileSync whole) then
// text.split(/\r?\n/).filter((line) => line.trim()).length — a multi-GB
// evidence artifact OOM-crashed (V8 heap / ERR_FS_FILE_TOO_LARGE) before the
// count ran. Mirrors the old split-based semantics byte-for-byte on ASCII
// input: a "line" is a segment between `\r?\n` separators that contains at
// least one non-whitespace byte; a file with no such segment returns 0
// (matching the old `if (!text.trim()) return 0`). `\n` (0x0a) ends the
// current segment; `\r` (0x0d) before `\n` is part of the separator but is
// whitespace either way so it does not affect the count; other ASCII
// whitespace (\t \v \f space) does not mark a segment as non-empty. A trailing
// segment without a final `\n` is counted iff it has non-whitespace content
// (the old split yields a final element for non-newline-terminated files).
// Non-ASCII bytes (>=0x80) are treated as content; this diverges from trim()
// only for rare Unicode-whitespace code points (NBSP   etc.), which do
// not occur in evidence artifacts (tool output / logs / binary-as-text).
function lineCountStreaming(path: string): number {
	const stat = statSync(path);
	if (stat.size === 0) return 0;
	const fd = openSync(path, "r");
	try {
		const buf = Buffer.alloc(EVIDENCE_IO_CHUNK_SIZE);
		let pos = 0;
		let count = 0;
		let lineHasNonWs = false;
		while (pos < stat.size) {
			const n = readSync(fd, buf, 0, Math.min(EVIDENCE_IO_CHUNK_SIZE, stat.size - pos), pos);
			if (n <= 0) break;
			for (let i = 0; i < n; i++) {
				const b = buf[i];
				if (b === 0x0a) {
					if (lineHasNonWs) count++;
					lineHasNonWs = false;
				} else if (b === 0x09 || b === 0x0b || b === 0x0c || b === 0x0d || b === 0x20) {
				} else {
					lineHasNonWs = true;
				}
			}
			pos += n;
		}
		if (lineHasNonWs) count++;
		return count;
	} finally {
		try {
			closeSync(fd);
		} catch {
			// Best-effort: fd may already be invalid.
		}
	}
}

export function lineCount(path: string): number {
	try {
		return lineCountStreaming(path);
	} catch {
		return 0;
	}
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
	const rows = lineCount(path);
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

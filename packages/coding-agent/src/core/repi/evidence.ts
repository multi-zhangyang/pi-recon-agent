import { closeSync, existsSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { safeHeadEnd, safeTailStart } from "../tools/truncate.ts";
import { evidenceLedgerPath, writePrivateTextFile } from "./storage.ts";

export type EvidenceKind = "runtime" | "traffic" | "served_asset" | "process_config" | "artifact" | "source" | "note";

export type EvidenceVerdict = "proposed" | "supported" | "contradicted" | "inconclusive" | "proved";

export type EvidenceRecord = {
	timestamp: string;
	missionId?: string;
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
	claimId?: string;
	hypothesis?: string;
	prediction?: string;
	observation?: string;
	counterexample?: string;
	verdict?: EvidenceVerdict;
};

export type ParsedEvidenceRecord = EvidenceRecord & { ledgerIndex: number };

export type EvidenceGraphNode = {
	id: string;
	kind: "evidence";
	label: string;
	status?: string;
	priority?: number;
	note?: string;
};

export type EvidenceClaimState = {
	claimId: string;
	missionId?: string;
	timestamp: string;
	title: string;
	kind: EvidenceKind;
	priority: number;
	hypothesis: string;
	prediction?: string;
	observation?: string;
	counterexample?: string;
	verdict: EvidenceVerdict;
	command?: string;
	verify?: string;
};

export type EvidenceClaimSummary = {
	claims: EvidenceClaimState[];
	open: EvidenceClaimState[];
	proved: EvidenceClaimState[];
	contradicted: EvidenceClaimState[];
	nextCommands: string[];
	lines: string[];
};

type EvidenceIoOptions = {
	ensureStorage?: () => void;
	readText?: (path: string, fallback?: string) => string;
	writeText?: (path: string, text: string) => void;
	truncate?: (text: string, limit: number) => string;
};

type AppendEvidenceOptions = EvidenceIoOptions & {
	appendText: (path: string, text: string) => void;
	onLedgerUpdated?: (record: EvidenceRecord) => void;
	now?: () => Date;
};

const EVIDENCE_LEDGER_PREAMBLE = "# REPI Evidence Ledger\n\n";

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
		record.missionId ? `- mission_id: ${record.missionId}` : undefined,
		record.command ? `- command: \`${record.command.replace(/`/g, "\\`")}\`` : undefined,
		record.path ? `- path: ${record.path}` : undefined,
		record.offset ? `- offset: ${record.offset}` : undefined,
		record.hash ? `- hash: ${record.hash}` : undefined,
		record.verify ? `- verify: ${record.verify}` : undefined,
		record.confidence ? `- confidence: ${record.confidence}` : undefined,
		record.claimId ? `- claim_id: ${record.claimId}` : undefined,
		record.hypothesis ? `- hypothesis: ${record.hypothesis}` : undefined,
		record.prediction ? `- prediction: ${record.prediction}` : undefined,
		record.observation ? `- observation: ${record.observation}` : undefined,
		record.counterexample ? `- counterexample: ${record.counterexample}` : undefined,
		record.verdict ? `- verdict: ${record.verdict}` : undefined,
		"",
	]
		.filter((line): line is string => line !== undefined)
		.join("\n");
}

export function parseEvidenceRecords(text: string): ParsedEvidenceRecord[] {
	const kinds = new Set<EvidenceKind>([
		"runtime",
		"traffic",
		"served_asset",
		"process_config",
		"artifact",
		"source",
		"note",
	]);
	const verdicts = new Set<EvidenceVerdict>(["proposed", "supported", "contradicted", "inconclusive", "proved"]);
	return text
		.split(/^##\s+/m)
		.filter((block) => block.trim())
		.flatMap((block, ledgerIndex) => {
			const header = /^(.+?)\s+—\s+P(\d+)\s+—\s+(.+?)\s+—\s+(.+)$/m.exec(block);
			if (!header) return [];
			const field = (name: string) => new RegExp(`^- ${name}: (.+)$`, "m").exec(block)?.[1]?.trim();
			const commandMatch = /^- command: `((?:\\`|[^`])*)`$/m.exec(block);
			const rawKind = header[3]?.trim() as EvidenceKind | undefined;
			const rawVerdict = field("verdict") as EvidenceVerdict | undefined;
			return [
				{
					ledgerIndex,
					timestamp: header[1]?.trim() ?? "",
					priority: Number.parseInt(header[2] ?? "7", 10),
					kind: rawKind && kinds.has(rawKind) ? rawKind : "note",
					title: header[4]?.trim() ?? "evidence",
					fact: field("fact") ?? "",
					missionId: field("mission_id"),
					command: commandMatch?.[1]?.replace(/\\`/g, "`").trim(),
					path: field("path"),
					offset: field("offset"),
					hash: field("hash"),
					verify: field("verify"),
					confidence: field("confidence"),
					claimId: field("claim_id"),
					hypothesis: field("hypothesis"),
					prediction: field("prediction"),
					observation: field("observation"),
					counterexample: field("counterexample"),
					verdict: rawVerdict && verdicts.has(rawVerdict) ? rawVerdict : undefined,
				} satisfies ParsedEvidenceRecord,
			];
		});
}

/**
 * Keep verdicts honest at the storage boundary. Models may emit a confident
 * verdict before they have attached a replayable probe; the ledger must not
 * promote that narrative into proof. Structured HTO records without a
 * prediction/observation remain proposals, while proved/contradicted claims
 * require the corresponding executable or falsifying anchor.
 */
export function normalizeEvidenceVerdict(
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
): EvidenceVerdict | undefined {
	if (record.verdict === "proved" && (!record.command || !record.verify || !record.observation)) return "inconclusive";
	if (record.verdict === "contradicted" && !record.counterexample && !record.observation) return "inconclusive";
	if (!record.verdict && (record.hypothesis || record.prediction)) return "proposed";
	return record.verdict;
}

export function appendEvidenceRecord(
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
	options: AppendEvidenceOptions,
): EvidenceRecord {
	options.ensureStorage?.();
	const ledgerPath = evidenceLedgerPath();
	// Storage initialization is intentionally lazy, so the first evidence append
	// must create the human-readable ledger preamble itself. Use the dedicated
	// atomic writer instead of appendText here: appendPrivateTextFile preserves a
	// legacy leading-newline contract for empty files, which would put a blank
	// line before the markdown title.
	let ledgerHasBytes = false;
	try {
		ledgerHasBytes = statSync(ledgerPath).size > 0;
	} catch {
		// Missing ledger: the first append creates it below.
	}
	if (!ledgerHasBytes) {
		(options.writeText ?? writePrivateTextFile)(ledgerPath, EVIDENCE_LEDGER_PREAMBLE);
	}
	const full: EvidenceRecord = {
		timestamp: (options.now?.() ?? new Date()).toISOString(),
		...record,
		verdict: normalizeEvidenceVerdict(record),
		priority: record.priority ?? evidencePriority(record.kind),
	};
	options.appendText(ledgerPath, formatEvidenceRecord(full));
	options.onLedgerUpdated?.(full);
	return full;
}

export function buildEvidenceDigest(query?: string, options: EvidenceIoOptions = {}): string {
	options.ensureStorage?.();
	const readText = options.readText ?? readTextFile;
	const truncate = options.truncate ?? truncateMiddle;
	const modelVisibleLimit = 4096;
	const text = readText(evidenceLedgerPath()).trim();
	if (!text) return "证据 ledger 为空；用 re_evidence append 记录 runtime/traffic/source 等证据。";
	if (!query) return truncate(text, modelVisibleLimit);
	const lower = query.toLowerCase();
	const lines = text
		.split(/\r?\n/)
		.filter((line) => line.toLowerCase().includes(lower))
		.slice(-160);
	return lines.length ? truncate(lines.join("\n"), modelVisibleLimit) : "No matching evidence lines";
}

export function buildEvidenceClaimSummary(
	options: Pick<EvidenceIoOptions, "readText"> & { missionId?: string; limit?: number } = {},
): EvidenceClaimSummary {
	const readText = options.readText ?? readTextFile;
	const records = parseEvidenceRecords(readText(evidenceLedgerPath()))
		.filter((record) => !options.missionId || record.missionId === options.missionId)
		.slice(-(options.limit ?? 80));
	const byClaim = new Map<string, EvidenceClaimState>();
	for (const record of records) {
		const hypothesis = record.hypothesis;
		if (!hypothesis) continue;
		const claimId = record.claimId ?? `anonymous:${slug(record.title)}:${slug(record.timestamp)}`;
		const claim: EvidenceClaimState = {
			claimId,
			missionId: record.missionId,
			timestamp: record.timestamp,
			title: record.title,
			kind: record.kind,
			priority: record.priority,
			hypothesis,
			prediction: record.prediction,
			observation: record.observation,
			counterexample: record.counterexample,
			verdict: record.verdict ?? "proposed",
			command: record.command,
			verify: record.verify,
		};
		byClaim.delete(claimId);
		byClaim.set(claimId, claim);
	}
	const claims = Array.from(byClaim.values());
	const open = claims.filter((claim) => ["proposed", "supported", "inconclusive"].includes(claim.verdict));
	const proved = claims.filter((claim) => claim.verdict === "proved");
	const contradicted = claims.filter((claim) => claim.verdict === "contradicted");
	const nextCommandForClaim = (claim: EvidenceClaimState): string | undefined =>
		claim.verdict === "proposed"
			? (claim.command ?? claim.verify)
			: claim.verdict === "supported"
				? claim.verify
				: undefined;
	const nextCommands = Array.from(
		new Set(open.map(nextCommandForClaim).filter((command): command is string => Boolean(command))),
	).slice(0, 12);
	return {
		claims,
		open,
		proved,
		contradicted,
		nextCommands,
		lines: [
			`claim_lifecycle: total=${claims.length} open=${open.length} proved=${proved.length} contradicted=${contradicted.length}`,
			...open
				.slice(-8)
				.map(
					(claim) =>
						`open_claim: id=${claim.claimId} verdict=${claim.verdict} hypothesis=${truncateMiddle(claim.hypothesis, 180)} next=${nextCommandForClaim(claim) ?? "adjudicate recorded observation or add a distinguishing probe"}`,
				),
			...contradicted
				.slice(-6)
				.map(
					(claim) =>
						`refuted_claim: id=${claim.claimId} observation=${truncateMiddle(claim.counterexample ?? claim.observation ?? "missing", 180)}`,
				),
		],
	};
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
	if (options.autoContextPack === true) return truncate(buildEvidenceDigest(undefined, options), 4096);
	if (options.target) {
		const scoped = buildEvidenceDigest(options.target, options);
		if (scoped && scoped !== "No matching evidence lines" && !scoped.startsWith("证据 ledger 为空")) {
			return truncate(scoped, 4096);
		}
	}
	return buildStartupEvidenceDigest(options);
}

export function evidenceLedgerGraphNodes(
	limit = 14,
	options: Pick<EvidenceIoOptions, "readText"> & { missionId?: string } = {},
): EvidenceGraphNode[] {
	const readText = options.readText ?? readTextFile;
	const records = parseEvidenceRecords(readText(evidenceLedgerPath()))
		.filter((record) => !options.missionId || record.missionId === options.missionId)
		.slice(-limit);
	return records.map((record) => ({
		id: `evidence:${record.ledgerIndex}:${slug(record.title)}`,
		kind: "evidence" as const,
		label: record.title,
		status: record.verdict ?? record.kind,
		priority: record.priority,
		note: record.hypothesis ?? record.timestamp,
	}));
}

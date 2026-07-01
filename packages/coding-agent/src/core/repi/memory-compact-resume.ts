import { createHash } from "node:crypto";
import { existsSync, mkdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { normalizeReconCommand } from "./memory-command.ts";
import { writeFileAtomic } from "./memory-store.ts";
import {
	artifactBasename,
	compactResumeLedgerV2ReportPath,
	compactResumeTransitionLedgerPath,
	ensureRepiStorage,
	memoryPath,
	readTextFile as readText,
	reconArchiveDir,
	writePrivateTextFile,
} from "./storage.ts";
import { sha256Text } from "./text.ts";

export type CompactResumeStateV2 = "queued" | "running" | "done" | "blocked" | "exhausted";

export type CompactResumeLedgerTransitionV2 = {
	kind: "repi-compact-resume-ledger-transition";
	schemaVersion: 1;
	from: CompactResumeStateV2;
	to: CompactResumeStateV2;
	at: string;
	command?: string;
	reason: string;
	idempotencyKey: string;
	contextPath?: string;
	contextSha256?: string;
	attempt: number;
	maxAttempts: number;
	entryHash: string;
	prevHash: string;
};

export type CompactResumeLedgerV2Report = {
	kind: "repi-compact-resume-ledger-v2-report";
	schemaVersion: 1;
	generatedAt: string;
	CompactResumeLedgerV2: true;
	append_only_transition_ledger: true;
	idempotent_multi_compact_replay: true;
	auto_resume_budget_enforced: true;
	reportPath: string;
	transitionPath: string;
	currentState: CompactResumeStateV2;
	transitions: CompactResumeLedgerTransitionV2[];
	invalidTransitions: string[];
	exhausted: boolean;
	requiredChecks: string[];
};

export type CompactResumeTransitionLedgerReadV2 = {
	path: string;
	text: string;
	transitions: CompactResumeLedgerTransitionV2[];
	parseErrors: string[];
};

export const COMPACT_RESUME_ALLOWED_TRANSITIONS: Record<CompactResumeStateV2, readonly CompactResumeStateV2[]> = {
	queued: ["queued", "running", "blocked", "exhausted"],
	running: ["done", "blocked", "exhausted"],
	blocked: ["running", "exhausted"],
	done: [],
	exhausted: [],
};

export function compactResumeStateForKey(
	transitions: CompactResumeLedgerTransitionV2[],
	idempotencyKey: string,
): CompactResumeStateV2 {
	return transitions.filter((row) => row.idempotencyKey === idempotencyKey).at(-1)?.to ?? "queued";
}

export function compactResumeAttemptForKey(
	transitions: CompactResumeLedgerTransitionV2[],
	idempotencyKey: string,
): number {
	return transitions.filter((row) => row.idempotencyKey === idempotencyKey).length + 1;
}

export function compactResumeTransitionEntryHash(
	row: Omit<CompactResumeLedgerTransitionV2, "entryHash">,
	options: { normalizeCommand?: (command: string) => string } = {},
): string {
	const normalizeCommand = options.normalizeCommand ?? ((command: string) => command.trim());
	return sha256Text(
		[
			row.prevHash,
			row.at,
			`${row.from}->${row.to}`,
			row.idempotencyKey,
			normalizeCommand(row.command ?? ""),
			row.contextPath ?? "",
			row.contextSha256 ?? "",
			`${row.attempt}/${row.maxAttempts}`,
			row.reason,
		].join("\n"),
	);
}

export function compactResumeTransitionAllowed(from: CompactResumeStateV2, to: CompactResumeStateV2): boolean {
	return COMPACT_RESUME_ALLOWED_TRANSITIONS[from]?.includes(to) ?? false;
}

export function compactResumeTransitionsFromText(path: string, text: string): CompactResumeTransitionLedgerReadV2 {
	const transitions: CompactResumeLedgerTransitionV2[] = [];
	const parseErrors: string[] = [];
	for (const [index, line] of text.split(/\r?\n/).entries()) {
		if (!line.trim()) continue;
		try {
			const row = JSON.parse(line) as CompactResumeLedgerTransitionV2;
			if (row?.kind !== "repi-compact-resume-ledger-transition") {
				parseErrors.push(`row ${index + 1}: transition kind missing`);
				continue;
			}
			transitions.push(row);
		} catch {
			parseErrors.push(`row ${index + 1}: transition JSON corrupt`);
		}
	}
	return { path, text, transitions, parseErrors };
}

export function compactResumeLedgerV2ReportFromText(params: {
	transitionPath: string;
	reportPath: string;
	text: string;
	generatedAt?: string;
	normalizeCommand?: (command: string) => string;
}): CompactResumeLedgerV2Report {
	const normalizeCommand = params.normalizeCommand ?? ((command: string) => command.trim());
	const { transitions, parseErrors } = compactResumeTransitionsFromText(params.transitionPath, params.text);
	const invalidTransitions: string[] = [...parseErrors];
	let previousText = "";
	let rowNumber = 0;
	const groups = new Map<string, CompactResumeLedgerTransitionV2[]>();
	const duplicateKeys = new Set<string>();
	const seenReplayKeys = new Set<string>();
	for (const line of params.text.split(/\r?\n/)) {
		if (!line.trim()) continue;
		rowNumber += 1;
		let row: CompactResumeLedgerTransitionV2 | undefined;
		try {
			row = JSON.parse(line) as CompactResumeLedgerTransitionV2;
		} catch {
			previousText += `${line}\n`;
			continue;
		}
		const expectedPrevHash = previousText.trim() ? sha256Text(previousText) : "0".repeat(64);
		if (row.prevHash !== expectedPrevHash)
			invalidTransitions.push(`append_only_transition_ledger prevHash drift row ${rowNumber}`);
		const { entryHash: _entryHash, ...base } = row;
		const expectedEntryHash = compactResumeTransitionEntryHash(base, { normalizeCommand });
		if (row.entryHash !== expectedEntryHash)
			invalidTransitions.push(`append_only_transition_ledger entryHash drift row ${rowNumber}`);
		if (row.attempt > row.maxAttempts)
			invalidTransitions.push(
				`auto_resume_budget_exceeded row ${rowNumber}: attempt ${row.attempt}/${row.maxAttempts}`,
			);
		const replayKey = [row.idempotencyKey, normalizeCommand(row.command ?? ""), row.to, row.contextPath ?? ""].join(
			"\t",
		);
		if (seenReplayKeys.has(replayKey)) duplicateKeys.add(replayKey);
		seenReplayKeys.add(replayKey);
		if (!groups.has(row.idempotencyKey)) groups.set(row.idempotencyKey, []);
		groups.get(row.idempotencyKey)!.push(row);
		previousText += `${line}\n`;
	}
	for (const duplicateKey of duplicateKeys)
		invalidTransitions.push(`idempotent_multi_compact_replay duplicate transition ${duplicateKey}`);
	for (const [idempotencyKey, rows] of groups.entries()) {
		let current: CompactResumeStateV2 = rows[0]?.from ?? "queued";
		if (current !== "queued")
			invalidTransitions.push(
				`compact_resume_state_machine ${idempotencyKey} must start from queued, got ${current}`,
			);
		for (const [index, row] of rows.entries()) {
			if (row.from !== current)
				invalidTransitions.push(
					`compact_resume_state_machine ${idempotencyKey} row ${index + 1} from mismatch: expected ${current}, got ${row.from}`,
				);
			if (!compactResumeTransitionAllowed(row.from, row.to))
				invalidTransitions.push(`invalid_resume_transition ${idempotencyKey} ${row.from}->${row.to}`);
			current = row.to;
			if ((row.to === "done" || row.to === "exhausted") && index < rows.length - 1)
				invalidTransitions.push(`terminal_resume_transition_reopened ${idempotencyKey} after ${row.to}`);
		}
	}
	const currentState = transitions.at(-1)?.to ?? "queued";
	const exhausted =
		currentState === "exhausted" ||
		transitions.some((row) => row.to === "exhausted" || row.attempt > row.maxAttempts);
	return {
		kind: "repi-compact-resume-ledger-v2-report",
		schemaVersion: 1,
		generatedAt: params.generatedAt ?? new Date().toISOString(),
		CompactResumeLedgerV2: true,
		append_only_transition_ledger: true,
		idempotent_multi_compact_replay: true,
		auto_resume_budget_enforced: true,
		reportPath: params.reportPath,
		transitionPath: params.transitionPath,
		currentState,
		transitions,
		invalidTransitions: Array.from(new Set(invalidTransitions)).slice(0, 120),
		exhausted,
		requiredChecks: [
			"CompactResumeLedgerV2",
			"append_only_transition_ledger",
			"idempotent_multi_compact_replay",
			"auto_resume_budget_enforced",
			"invalid_resume_transition",
			"compact_resume_transition_report_in_context_pack",
		],
	};
}

export function formatCompactResumeLedgerV2(report: CompactResumeLedgerV2Report): string {
	return [
		"compact_resume_ledger_v2:",
		`CompactResumeLedgerV2=${report.CompactResumeLedgerV2}`,
		`append_only_transition_ledger=${report.append_only_transition_ledger}`,
		`idempotent_multi_compact_replay=${report.idempotent_multi_compact_replay}`,
		`auto_resume_budget_enforced=${report.auto_resume_budget_enforced}`,
		`current_state=${report.currentState}`,
		`transitions=${report.transitions.length}`,
		`invalid_transitions=${report.invalidTransitions.length}`,
		`exhausted=${report.exhausted}`,
		`transition_path=${report.transitionPath}`,
		`report_path=${report.reportPath}`,
		"recent_transitions:",
		...(report.transitions.slice(-12).length
			? report.transitions
					.slice(-12)
					.map(
						(row) =>
							`- ${row.from}->${row.to} attempt=${row.attempt}/${row.maxAttempts} command=${row.command ?? "none"} idempotency=${row.idempotencyKey.slice(0, 16)}`,
					)
			: ["- none"]),
		"invalid:",
		...(report.invalidTransitions.length ? report.invalidTransitions.map((item) => `- ${item}`) : ["- none"]),
		"required_checks:",
		...report.requiredChecks.map((item) => `- ${item}`),
	].join("\n");
}

export function contextCompactionLedger(timestamp: string): {
	path: string;
	appendOnly: true;
	prevHash: string;
	entryHash: string;
} {
	const path = memoryPath("compaction-resume-ledger.jsonl");
	const previous = readText(path);
	// Match verifyCompactionResumeLedger's empty-line-skipping accumulation
	// EXACTLY: the verifier recomputes prevHash from the non-empty lines (each +
	// "\n"), NOT the raw file text. The ledger is appended via appendPrivateTextFile,
	// which prepends a leading "\n" on a fresh/empty file; hashing `previous` raw
	// included that leading "\n" while the verifier skipped it → prevHash desynced
	// at row 1+ → every verifyCompactionResumeLedger call archived the ledger as
	// corrupt and reset it to empty (the ledger was effectively non-functional).
	// Hashing the same previousText the verifier uses keeps the chain contiguous.
	const previousText = previous
		.split(/\r?\n/)
		.filter((line) => line.trim())
		.map((line) => `${line}\n`)
		.join("");
	const prevHash = previousText.trim() ? sha256Text(previousText) : "0".repeat(64);
	const entryHash = sha256Text(`${prevHash}\n${timestamp}\ncontext-pack`);
	return { path, appendOnly: true, prevHash, entryHash };
}

const COMPACTION_RESUME_LEDGER_DEFAULT_MAX_ROWS = 500;

function compactionResumeLedgerMaxRows(): number {
	const raw = Number(process.env.REPI_COMPACTION_LEDGER_MAX_ROWS);
	if (Number.isFinite(raw) && raw >= 0) return Math.floor(raw);
	return COMPACTION_RESUME_LEDGER_DEFAULT_MAX_ROWS;
}

/**
 * Cap the compaction-resume ledger on-disk size. The ledger is an append-only
 * hash chain where each row's prevHash = sha256 of ALL prior raw lines (a running
 * prefix hash, not a per-record link), so verifyCompactionResumeLedger is O(N²)
 * in hashing and the file grows by one row per context-pack with no bound. This
 * mirrors the tool-trace ledger rotation (opt #48): if the row count exceeds the
 * cap (REPI_COMPACTION_LEDGER_MAX_ROWS, default 500, 0=disable), keep the last
 * `cap` rows and RE-HASH the kept tail forward from a fresh genesis
 * ("0".repeat(64)). Truncation breaks every surviving record (each prevHash no
 * longer matches the recomputed prefix hash), so the tail is re-serialized with
 * recomputed prevHash + entryHash; the verifier walks from genesis, so a
 * genesis-reset head + re-hashed tail verifies CLEANLY. Atomic rewrite via
 * writePrivateTextFile (temp+rename, 0o600) — a crash mid-rotation cannot leave a
 * half-written ledger. Unparseable rows are preserved verbatim (the verifier
 * flags them) rather than dropped, so audit history is not silently lost.
 */
export function rotateCompactionResumeLedgerIfNeeded(): void {
	const maxRows = compactionResumeLedgerMaxRows();
	if (maxRows <= 0) return;
	const path = memoryPath("compaction-resume-ledger.jsonl");
	const text = readText(path);
	if (!text.trim()) return;
	const lines = text.split(/\r?\n/).filter((line) => line.trim());
	if (lines.length <= maxRows) return;
	const keep = lines.slice(-maxRows);
	let previousText = "";
	const rehashed: string[] = [];
	for (const line of keep) {
		let row: Record<string, unknown>;
		try {
			row = JSON.parse(line) as Record<string, unknown>;
		} catch {
			rehashed.push(line);
			previousText += `${line}\n`;
			continue;
		}
		const prevHash = previousText.trim() ? sha256Text(previousText) : "0".repeat(64);
		const ts = typeof row.ts === "string" ? row.ts : "";
		const entryHash = sha256Text(`${prevHash}\n${ts}\ncontext-pack`);
		row.prevHash = prevHash;
		row.entryHash = entryHash;
		const serialized = JSON.stringify(row);
		rehashed.push(serialized);
		previousText += `${serialized}\n`;
	}
	writePrivateTextFile(path, `${rehashed.join("\n")}\n`);
}

export function readCompactResumeTransitions(): {
	path: string;
	text: string;
	transitions: CompactResumeLedgerTransitionV2[];
	parseErrors: string[];
} {
	const path = compactResumeTransitionLedgerPath();
	const text = readText(path);
	return compactResumeTransitionsFromText(path, text);
}

// opt #85 — compaction-resume transition ledger append cache (the read-side analog of #73's
// deposition chain cache). appendCompactResumeTransition did an O(file) read-modify-write on
// EVERY append: readText(whole ledger) → parse → sha256(previousText) for prevHash → rewrite the
// whole file with the new row appended. The ledger is a hash chain verified from genesis
// (compactResumeLedgerV2ReportFromText recomputes prevHash=sha256(previousText) for EVERY row),
// so it is NOT rotation-safe and must be rewritten in full (atomic temp+rename, F3) — unlike the
// deposition bus (#72 true-append), appendPrivateTextFile CANNOT be used here: its leading-"\n"
// separator on a fresh file would make the stored prevHash (sha256 of raw text WITH the leading
// "\n") diverge from the verifier's prevHash (which skips empty lines) → invalidTransitions.
// So the WRITE stays an atomic full rewrite (writePrivateTextFile, F3), but the READ is cached:
// a path-keyed {text, prevHash, mtimeMs, size} entry, mtime+size-guarded. On a hit the O(file)
// read + O(file) sha256 are skipped (the cached text feeds the write body + duplicate scan, the
// cached prevHash feeds the new row); the append commits the new text + stat so the next append
// hits. The cached prevHash is sha256Text(text) — a pure function of the file content, so the
// mtime+size guard is a valid invalidation (atomic rewrites bump both). Worst case is a false
// MISS (correct but slower), never a false HIT. Path-keyed per REPI_CODING_AGENT_DIR.
const compactionResumeChainCache = new Map<string, { text: string; prevHash: string; mtimeMs: number; size: number }>();

function compactionResumeLedgerStat(path: string): { mtimeMs: number; size: number } | undefined {
	try {
		const st = statSync(path);
		return { mtimeMs: st.mtimeMs, size: st.size };
	} catch {
		return undefined;
	}
}

/**
 * Returns { text, prevHash, transitions } for the next ledger append. Cache hit (stat
 * mtime+size unchanged) → the O(file) read + O(file) sha256 are skipped (cached text feeds the
 * write body + duplicate scan; cached prevHash feeds the new row). Miss → cold read. The caller
 * MUST commitCompactionResumeChain(newText) after the atomic write succeeds so the next append
 * cache-hits.
 */
export function nextCompactionResumeChain(): {
	text: string;
	prevHash: string;
	transitions: CompactResumeLedgerTransitionV2[];
} {
	const path = compactResumeTransitionLedgerPath();
	const cached = compactionResumeChainCache.get(path);
	if (cached) {
		const st = compactionResumeLedgerStat(path);
		if (st && st.mtimeMs === cached.mtimeMs && st.size === cached.size) {
			const { transitions } = compactResumeTransitionsFromText(path, cached.text);
			return { text: cached.text, prevHash: cached.prevHash, transitions };
		}
	}
	const text = readText(path);
	const prevHash = text.trim() ? sha256Text(text) : "0".repeat(64);
	const { transitions } = compactResumeTransitionsFromText(path, text);
	return { text, prevHash, transitions };
}

/** Record the post-append chain state (new full text + stat) so the next append cache-hits.
 *  If the stat fails (file vanished), drop the entry → next append cold-reads. */
export function commitCompactionResumeChain(newText: string): void {
	const path = compactResumeTransitionLedgerPath();
	const st = compactionResumeLedgerStat(path);
	if (st) {
		compactionResumeChainCache.set(path, {
			text: newText,
			prevHash: newText.trim() ? sha256Text(newText) : "0".repeat(64),
			mtimeMs: st.mtimeMs,
			size: st.size,
		});
	} else {
		compactionResumeChainCache.delete(path);
	}
}

/** Drop the cached chain state. Belt-and-suspenders for the stat guard — call after any non-append
 *  rewrite of the ledger (archive/reset) so the next append doesn't depend on a stat tick landing. */
export function invalidateCompactionResumeChainCache(): void {
	compactionResumeChainCache.delete(compactResumeTransitionLedgerPath());
}

export function appendCompactResumeTransition(params: {
	from?: CompactResumeStateV2;
	to: CompactResumeStateV2;
	command?: string;
	reason: string;
	idempotencyKey?: string;
	contextPath?: string;
	contextSha256?: string;
	attempt?: number;
	maxAttempts?: number;
}): CompactResumeLedgerTransitionV2 {
	ensureRepiStorage();
	const path = compactResumeTransitionLedgerPath();
	const chain = nextCompactionResumeChain();
	const idempotencyKey =
		params.idempotencyKey ??
		createHash("sha256")
			.update([params.contextPath ?? "no-context", params.command ?? "", params.reason].join("\n"))
			.digest("hex");
	const normalizedCommand = normalizeReconCommand(params.command ?? "");
	const duplicate = chain.transitions.find(
		(row) =>
			row.idempotencyKey === idempotencyKey &&
			row.to === params.to &&
			normalizeReconCommand(row.command ?? "") === normalizedCommand &&
			(row.contextPath ?? "") === (params.contextPath ?? ""),
	);
	if (duplicate) return duplicate;
	const previousText = chain.text;
	const prevHash = chain.prevHash;
	const from = params.from ?? compactResumeStateForKey(chain.transitions, idempotencyKey);
	const base: Omit<CompactResumeLedgerTransitionV2, "entryHash"> = {
		kind: "repi-compact-resume-ledger-transition",
		schemaVersion: 1,
		from,
		to: params.to,
		at: new Date().toISOString(),
		command: params.command,
		reason: params.reason,
		idempotencyKey,
		contextPath: params.contextPath,
		contextSha256: params.contextSha256,
		attempt: params.attempt ?? compactResumeAttemptForKey(chain.transitions, idempotencyKey),
		maxAttempts: params.maxAttempts ?? 3,
		prevHash,
	};
	const row: CompactResumeLedgerTransitionV2 = {
		...base,
		entryHash: compactResumeTransitionEntryHash(base, { normalizeCommand: normalizeReconCommand }),
	};
	const newText = `${previousText}${previousText && !previousText.endsWith("\n") ? "\n" : ""}${JSON.stringify(row)}\n`;
	writePrivateTextFile(path, newText);
	commitCompactionResumeChain(newText);
	return row;
}

export function buildCompactResumeLedgerV2Report(options: { write?: boolean } = {}): CompactResumeLedgerV2Report {
	ensureRepiStorage();
	const transitionPath = compactResumeTransitionLedgerPath();
	const reportPath = compactResumeLedgerV2ReportPath();
	const report = compactResumeLedgerV2ReportFromText({
		transitionPath,
		reportPath,
		text: readText(transitionPath),
		normalizeCommand: normalizeReconCommand,
	});
	if (options.write !== false) writeFileAtomic(reportPath, `${JSON.stringify(report, null, 2)}\n`);
	return report;
}

export function archiveCorruptCompactionResumeLedger(
	path: string,
	text: string,
	blocked: string[],
): string | undefined {
	if (!text.trim() || process.env.REPI_DISABLE_AUTO_LEDGER_REPAIR === "1") return undefined;
	try {
		const timestamp = new Date().toISOString();
		const dir = join(reconArchiveDir(), `compact-ledger-corrupt-${timestamp.replace(/[:.]/g, "-")}`);
		mkdirSync(dir, { recursive: true });
		const archivedPath = join(dir, artifactBasename(path));
		writePrivateTextFile(archivedPath, text);
		writePrivateTextFile(
			join(dir, "repair.json"),
			`${JSON.stringify(
				{
					kind: "repi-compact-ledger-auto-repair",
					generatedAt: timestamp,
					sourcePath: path,
					archivedPath,
					blocked,
					policy:
						"corrupt legacy compaction ledger is archived and runtime falls back to a fresh cold-start resume queue",
				},
				null,
				2,
			)}\n`,
		);
		writePrivateTextFile(path, "");
		invalidateCompactionResumeChainCache();
		return archivedPath;
	} catch {
		return undefined;
	}
}

export function verifyCompactionResumeLedger(): {
	path: string;
	rows: number;
	status: "pass" | "missing" | "corrupt";
	blocked: string[];
} {
	const path = memoryPath("compaction-resume-ledger.jsonl");
	const text = readText(path);
	if (!text.trim()) return { path, rows: 0, status: "missing", blocked: [] };
	const blocked: string[] = [];
	let previousText = "";
	let rows = 0;
	for (const [index, line] of text.split(/\r?\n/).entries()) {
		if (!line.trim()) continue;
		rows += 1;
		let row: { ts?: string; prevHash?: string; entryHash?: string; contextPath?: string; contextSha256?: string };
		try {
			row = JSON.parse(line) as typeof row;
		} catch {
			blocked.push(`compaction resume ledger JSON corrupt at row ${index + 1}`);
			previousText += `${line}\n`;
			continue;
		}
		const expectedPrevHash = previousText.trim()
			? createHash("sha256").update(previousText).digest("hex")
			: "0".repeat(64);
		if (row.prevHash !== expectedPrevHash)
			blocked.push(`compaction resume ledger prevHash drift at row ${index + 1}`);
		if (!row.ts || !row.entryHash) {
			blocked.push(`compaction resume ledger missing hash fields at row ${index + 1}`);
		} else {
			const expectedEntryHash = createHash("sha256")
				.update(`${expectedPrevHash}\n${row.ts}\ncontext-pack`)
				.digest("hex");
			if (row.entryHash !== expectedEntryHash)
				blocked.push(`compaction resume ledger entryHash drift at row ${index + 1}`);
		}
		if (row.contextPath && !existsSync(row.contextPath))
			blocked.push(`compaction resume ledger contextPath missing at row ${index + 1}: ${row.contextPath}`);
		if (row.contextSha256 && !/^[a-f0-9]{64}$/.test(row.contextSha256))
			blocked.push(`compaction resume ledger contextSha256 invalid at row ${index + 1}`);
		previousText += `${line}\n`;
	}
	if (blocked.length) {
		const archived = archiveCorruptCompactionResumeLedger(path, text, blocked);
		if (archived) return { path, rows: 0, status: "missing", blocked: [] };
	}
	return { path, rows, status: blocked.length ? "corrupt" : "pass", blocked };
}

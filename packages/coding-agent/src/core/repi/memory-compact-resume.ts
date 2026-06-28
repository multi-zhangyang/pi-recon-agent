import { createHash } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
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
	const prevHash = previous.trim() ? createHash("sha256").update(previous).digest("hex") : "0".repeat(64);
	const entryHash = createHash("sha256").update(`${prevHash}\n${timestamp}\ncontext-pack`).digest("hex");
	return { path, appendOnly: true, prevHash, entryHash };
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
	const ledger = readCompactResumeTransitions();
	const idempotencyKey =
		params.idempotencyKey ??
		createHash("sha256")
			.update([params.contextPath ?? "no-context", params.command ?? "", params.reason].join("\n"))
			.digest("hex");
	const normalizedCommand = normalizeReconCommand(params.command ?? "");
	const duplicate = ledger.transitions.find(
		(row) =>
			row.idempotencyKey === idempotencyKey &&
			row.to === params.to &&
			normalizeReconCommand(row.command ?? "") === normalizedCommand &&
			(row.contextPath ?? "") === (params.contextPath ?? ""),
	);
	if (duplicate) return duplicate;
	const previousText = ledger.text;
	const prevHash = previousText.trim() ? createHash("sha256").update(previousText).digest("hex") : "0".repeat(64);
	const from = params.from ?? compactResumeStateForKey(ledger.transitions, idempotencyKey);
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
		attempt: params.attempt ?? compactResumeAttemptForKey(ledger.transitions, idempotencyKey),
		maxAttempts: params.maxAttempts ?? 3,
		prevHash,
	};
	const row: CompactResumeLedgerTransitionV2 = {
		...base,
		entryHash: compactResumeTransitionEntryHash(base, { normalizeCommand: normalizeReconCommand }),
	};
	writeFileSync(
		compactResumeTransitionLedgerPath(),
		`${previousText}${previousText && !previousText.endsWith("\n") ? "\n" : ""}${JSON.stringify(row)}\n`,
		"utf-8",
	);
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
		writeFileSync(archivedPath, text, "utf-8");
		writeFileSync(
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
			"utf-8",
		);
		writeFileSync(path, "", "utf-8");
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

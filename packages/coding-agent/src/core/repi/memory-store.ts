import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type CaseMemoryV1, isCaseMemory, rebuildCaseMemoryFromEvents } from "./case-memory.ts";
import { jsonlScan } from "./jsonl.ts";
import { isMemoryEvent, type MemoryEventV1, memoryEventHash } from "./memory-event.ts";
import {
	caseMemoryPath,
	chmodPrivate,
	ensureRepiStorage,
	memoryEventsPath,
	memoryStoreLockPath,
	memoryStoreReportPath,
	memoryStoreSnapshotPath,
	memoryTransactionPath,
	memoryTransactionsDir,
	writePrivateTextFile,
} from "./storage.ts";
import { sha256Text, uniqueNonEmpty } from "./text.ts";

export type RepiMemoryStoreOperation =
	| "append-memory-event"
	| "append-memory-deposition"
	| "repair-index"
	| "snapshot"
	| (string & {});

export type MemoryTransactionFileDigestV1 = {
	path: string;
	beforeSha256: string;
	afterSha256: string;
	beforeBytes: number;
	afterBytes: number;
};

export type MemoryAppendTransactionV1 = {
	kind: "repi-memory-append-transaction";
	schemaVersion: 1;
	id: string;
	operation: "append-memory-event" | "append-memory-deposition" | "repair-index" | "snapshot";
	status: "prepared" | "committed" | "aborted";
	startedAt: string;
	committedAt?: string;
	lockPath: string;
	eventId?: string;
	caseSignature?: string;
	prevHash?: string;
	entryHash?: string;
	files: MemoryTransactionFileDigestV1[];
	errors: string[];
};

export type MemoryStoreVerificationV1 = {
	kind: "repi-memory-store-verification";
	schemaVersion: 1;
	generatedAt: string;
	MemoryStoreV5: true;
	eventsPath: string;
	caseMemoryPath: string;
	transactionDir: string;
	storeReportPath: string;
	snapshotPath: string;
	lockPath: string;
	eventCount: number;
	caseRowCount: number;
	hashChainOk: boolean;
	seqOk: boolean;
	prevHashOk: boolean;
	caseIndexOk: boolean;
	parseOk: boolean;
	latestEventHash: string;
	storeGrade: "pass" | "repairable" | "blocked";
	errors: string[];
	repairCommands: string[];
	requiredChecks: string[];
};

export type MemoryStoreJsonlScan<T> = {
	rows: T[];
	errors: string[];
};

export type MemoryStoreVerificationBuildInput = {
	eventScan: MemoryStoreJsonlScan<MemoryEventV1>;
	caseScan: MemoryStoreJsonlScan<CaseMemoryV1>;
	eventsPath: string;
	caseMemoryPath: string;
	transactionDir: string;
	storeReportPath: string;
	snapshotPath: string;
	lockPath: string;
	generatedAt?: string;
};

export type RepiMemoryTransactionLike = {
	id: string;
};

export function memoryStoreSleep(ms: number): void {
	Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function withMemoryStoreLock<T>(operation: RepiMemoryStoreOperation, fn: () => T): T {
	mkdirSync(memoryTransactionsDir(), { recursive: true });
	const lockPath = memoryStoreLockPath();
	let acquired = false;
	let lastError: unknown;
	for (let attempt = 0; attempt < 80; attempt++) {
		try {
			mkdirSync(lockPath);
			writeFileSync(
				join(lockPath, "owner.json"),
				`${JSON.stringify(
					{
						kind: "repi-memory-store-lock",
						schemaVersion: 1,
						operation,
						pid: process.pid,
						acquiredAt: new Date().toISOString(),
					},
					null,
					2,
				)}\n`,
				"utf-8",
			);
			acquired = true;
			break;
		} catch (error) {
			lastError = error;
			try {
				const ageMs = Date.now() - statSync(lockPath).mtimeMs;
				if (ageMs > 30_000) rmSync(lockPath, { recursive: true, force: true });
			} catch {}
			memoryStoreSleep(25 + Math.min(200, attempt * 5));
		}
	}
	if (!acquired) throw new Error(`memory_store_lock_timeout:${String(lastError)}`);
	try {
		return fn();
	} finally {
		rmSync(lockPath, { recursive: true, force: true });
	}
}

export function textWithJsonlLine(current: string, line: string): string {
	return `${current}${current.length && !current.endsWith("\n") ? "\n" : ""}${line}\n`;
}

export function writeFileAtomic(path: string, body: string): void {
	const tmp = `${path}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`;
	writePrivateTextFile(tmp, body);
	renameSync(tmp, path);
	chmodPrivate(path, 0o600);
}

export function writeMemoryTransaction<T extends RepiMemoryTransactionLike>(transaction: T): void {
	writePrivateTextFile(memoryTransactionPath(transaction.id), `${JSON.stringify(transaction, null, 2)}\n`);
}

export function buildMemoryStoreVerificationReport(
	input: MemoryStoreVerificationBuildInput,
): MemoryStoreVerificationV1 {
	const { eventScan, caseScan } = input;
	const errors = [...eventScan.errors, ...caseScan.errors];
	let prevHash = "0".repeat(64);
	let hashChainOk = true;
	let seqOk = true;
	let prevHashOk = true;
	const eventIds = new Set<string>();
	const entryHashes = new Set<string>();
	for (const [index, event] of eventScan.rows.entries()) {
		if (event.seq !== index + 1) {
			seqOk = false;
			errors.push(`events:${event.id}:seq_expected_${index + 1}_got_${event.seq}`);
		}
		if (event.prevHash !== prevHash) {
			prevHashOk = false;
			hashChainOk = false;
			errors.push(`events:${event.id}:prev_hash_mismatch`);
		}
		const expectedHash = memoryEventHash(event);
		if (event.entryHash !== expectedHash) {
			hashChainOk = false;
			errors.push(`events:${event.id}:entry_hash_mismatch`);
		}
		if (eventIds.has(event.id)) errors.push(`events:${event.id}:duplicate_id`);
		eventIds.add(event.id);
		entryHashes.add(event.entryHash);
		prevHash = event.entryHash;
	}
	const latestEventByCase = new Map<string, MemoryEventV1>();
	for (const event of eventScan.rows) latestEventByCase.set(event.caseSignature, event);
	const latestCaseRows = new Map<string, CaseMemoryV1>();
	for (const row of caseScan.rows) latestCaseRows.set(row.caseSignature, row);
	let caseIndexOk = caseScan.errors.length === 0;
	for (const [caseSignature, event] of latestEventByCase) {
		const row = latestCaseRows.get(caseSignature);
		if (!row) {
			caseIndexOk = false;
			errors.push(`case-memory:${caseSignature}:missing_latest_row`);
			continue;
		}
		if (row.lastEventHash !== event.entryHash) {
			caseIndexOk = false;
			errors.push(`case-memory:${caseSignature}:last_event_hash_mismatch`);
		}
		if (!row.eventIds.includes(event.id)) {
			caseIndexOk = false;
			errors.push(`case-memory:${caseSignature}:latest_event_id_missing`);
		}
	}
	for (const row of caseScan.rows) {
		for (const eventId of row.eventIds) {
			if (!eventIds.has(eventId)) {
				caseIndexOk = false;
				errors.push(`case-memory:${row.caseSignature}:unknown_event_id:${eventId}`);
			}
		}
		if (!entryHashes.has(row.lastEventHash) && row.lastEventHash !== "0".repeat(64)) {
			caseIndexOk = false;
			errors.push(`case-memory:${row.caseSignature}:unknown_last_event_hash`);
		}
	}
	const eventParseOk = eventScan.errors.length === 0;
	const caseParseOk = caseScan.errors.length === 0;
	const parseOk = eventParseOk && caseParseOk;
	const eventChainOk = hashChainOk && seqOk && prevHashOk && eventParseOk;
	const storeGrade = eventChainOk && caseIndexOk && caseParseOk ? "pass" : eventChainOk ? "repairable" : "blocked";
	return {
		kind: "repi-memory-store-verification",
		schemaVersion: 1,
		generatedAt: input.generatedAt ?? new Date().toISOString(),
		MemoryStoreV5: true,
		eventsPath: input.eventsPath,
		caseMemoryPath: input.caseMemoryPath,
		transactionDir: input.transactionDir,
		storeReportPath: input.storeReportPath,
		snapshotPath: input.snapshotPath,
		lockPath: input.lockPath,
		eventCount: eventScan.rows.length,
		caseRowCount: caseScan.rows.length,
		hashChainOk,
		seqOk,
		prevHashOk,
		caseIndexOk,
		parseOk,
		latestEventHash: eventScan.rows.at(-1)?.entryHash ?? "0".repeat(64),
		storeGrade,
		errors: uniqueNonEmpty(errors, 120),
		repairCommands:
			storeGrade === "repairable"
				? ["re_memory repair-index", "re_memory verify", "re_memory sediment"]
				: storeGrade === "blocked"
					? [
							"inspect memory/events.jsonl parse/hash-chain errors before appending",
							"restore from memory/store-snapshot.json if needed",
						]
					: ["re_memory snapshot"],
		requiredChecks: [
			"memory_store_lock_acquired",
			"hash_chain_verified_before_append",
			"case_memory_rebuilt_from_events",
			"transaction_manifest_committed",
			"repair_index_blocks_on_event_chain_corruption",
		],
	};
}

export function formatMemoryStoreVerification(report: MemoryStoreVerificationV1): string {
	return [
		"memory_store_v5:",
		`status=${report.storeGrade}`,
		`events=${report.eventCount}`,
		`case_rows=${report.caseRowCount}`,
		`hash_chain_ok=${report.hashChainOk}`,
		`seq_ok=${report.seqOk}`,
		`case_index_ok=${report.caseIndexOk}`,
		`parse_ok=${report.parseOk}`,
		`latest_event_hash=${report.latestEventHash}`,
		`events_path=${report.eventsPath}`,
		`case_memory_path=${report.caseMemoryPath}`,
		`transaction_dir=${report.transactionDir}`,
		`store_report=${report.storeReportPath}`,
		`snapshot=${report.snapshotPath}`,
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
		"errors:",
		...(report.errors.length ? report.errors.map((error) => `- ${error}`) : ["- none"]),
		"repair_commands:",
		...report.repairCommands.map((command) => `- ${command}`),
	].join("\n");
}

export function fileDigest(path: string): { sha256: string; bytes: number; text: string } {
	try {
		const buffer = readFileSync(path);
		return {
			sha256: createHash("sha256").update(buffer).digest("hex"),
			bytes: buffer.length,
			text: buffer.toString("utf-8"),
		};
	} catch {
		return { sha256: sha256Text(""), bytes: 0, text: "" };
	}
}

export function buildMemoryStoreVerificationUnlocked(options: { write?: boolean } = {}): MemoryStoreVerificationV1 {
	const eventScan = jsonlScan(memoryEventsPath(), isMemoryEvent, "MemoryEventV1");
	const caseScan = jsonlScan(caseMemoryPath(), isCaseMemory, "CaseMemoryV1");
	const report = buildMemoryStoreVerificationReport({
		eventScan,
		caseScan,
		eventsPath: memoryEventsPath(),
		caseMemoryPath: caseMemoryPath(),
		transactionDir: memoryTransactionsDir(),
		storeReportPath: memoryStoreReportPath(),
		snapshotPath: memoryStoreSnapshotPath(),
		lockPath: memoryStoreLockPath(),
	});
	if (options.write !== false) writeFileAtomic(memoryStoreReportPath(), `${JSON.stringify(report, null, 2)}\n`);
	return report;
}

export function verifyMemoryStore(options: { write?: boolean } = {}): MemoryStoreVerificationV1 {
	ensureRepiStorage();
	return withMemoryStoreLock("snapshot", () => buildMemoryStoreVerificationUnlocked(options));
}

export function repairMemoryStoreIndex(): MemoryStoreVerificationV1 {
	ensureRepiStorage();
	return withMemoryStoreLock("repair-index", () => {
		const before = buildMemoryStoreVerificationUnlocked({ write: false });
		const eventScan = jsonlScan(memoryEventsPath(), isMemoryEvent, "MemoryEventV1");
		if (!before.hashChainOk || !before.seqOk || !before.prevHashOk || eventScan.errors.length > 0) {
			writeFileAtomic(memoryStoreReportPath(), `${JSON.stringify(before, null, 2)}\n`);
			return before;
		}
		const startedAt = new Date().toISOString();
		const events = eventScan.rows;
		const rows = rebuildCaseMemoryFromEvents(events);
		const caseBefore = fileDigest(caseMemoryPath());
		const nextBody = rows.length ? `${rows.map((row) => JSON.stringify(row)).join("\n")}\n` : "";
		const afterSha256 = sha256Text(nextBody);
		const transaction: MemoryAppendTransactionV1 = {
			kind: "repi-memory-append-transaction",
			schemaVersion: 1,
			id: `memtx:${sha256Text(`${startedAt}:repair-index:${before.latestEventHash}`).slice(0, 20)}`,
			operation: "repair-index",
			status: "prepared",
			startedAt,
			lockPath: memoryStoreLockPath(),
			files: [
				{
					path: caseMemoryPath(),
					beforeSha256: caseBefore.sha256,
					afterSha256,
					beforeBytes: caseBefore.bytes,
					afterBytes: Buffer.byteLength(nextBody),
				},
			],
			errors: [],
		};
		writeMemoryTransaction(transaction);
		writeFileAtomic(caseMemoryPath(), nextBody);
		const committed: MemoryAppendTransactionV1 = {
			...transaction,
			status: "committed",
			committedAt: new Date().toISOString(),
		};
		writeMemoryTransaction(committed);
		const after = buildMemoryStoreVerificationUnlocked({ write: true });
		return after;
	});
}

export function snapshotMemoryStore(): MemoryStoreVerificationV1 {
	ensureRepiStorage();
	return withMemoryStoreLock("snapshot", () => {
		const verification = buildMemoryStoreVerificationUnlocked({ write: false });
		const eventScan = jsonlScan(memoryEventsPath(), isMemoryEvent, "MemoryEventV1");
		const caseScan = jsonlScan(caseMemoryPath(), isCaseMemory, "CaseMemoryV1");
		const snapshot = {
			kind: "repi-memory-store-snapshot",
			schemaVersion: 1,
			MemoryStoreV5: true,
			generatedAt: verification.generatedAt,
			verification,
			events: eventScan.rows,
			caseMemory: caseScan.rows,
		};
		const before = fileDigest(memoryStoreSnapshotPath());
		const body = `${JSON.stringify(snapshot, null, 2)}\n`;
		const transaction: MemoryAppendTransactionV1 = {
			kind: "repi-memory-append-transaction",
			schemaVersion: 1,
			id: `memtx:${sha256Text(`${verification.generatedAt}:snapshot:${verification.latestEventHash}`).slice(0, 20)}`,
			operation: "snapshot",
			status: "prepared",
			startedAt: verification.generatedAt,
			lockPath: memoryStoreLockPath(),
			files: [
				{
					path: memoryStoreSnapshotPath(),
					beforeSha256: before.sha256,
					afterSha256: sha256Text(body),
					beforeBytes: before.bytes,
					afterBytes: Buffer.byteLength(body),
				},
			],
			errors: [],
		};
		writeMemoryTransaction(transaction);
		writeFileAtomic(memoryStoreSnapshotPath(), body);
		writeMemoryTransaction({ ...transaction, status: "committed", committedAt: new Date().toISOString() });
		writeFileAtomic(memoryStoreReportPath(), `${JSON.stringify(verification, null, 2)}\n`);
		return verification;
	});
}

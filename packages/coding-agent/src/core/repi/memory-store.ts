import {
	closeSync,
	mkdirSync,
	openSync,
	readFileSync,
	readSync,
	renameSync,
	rmSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { type CaseMemoryV1, isCaseMemory, rebuildCaseMemoryFromEvents } from "./case-memory.ts";
import { jsonlScan, warmJsonlParsedCache } from "./jsonl.ts";
import { isMemoryEvent, type MemoryEventV1, memoryEventHash } from "./memory-event.ts";
import { invalidateMemoryEventHashChainCache } from "./memory-recall.ts";
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
import { hashFileSha256, sha256Text, uniqueNonEmpty } from "./text.ts";

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
	raw: string;
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

export function memoryStoreBusyWaitSleep(ms: number): void {
	// Synchronous fallback when Atomics.wait is unavailable: spin on Date.now() until the
	// deadline. Burns CPU, but this only runs under inter-process lock contention (rare in
	// the single-writer REPI model) and for 25-225ms, so the cost is bounded and acceptable.
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		// spin — no yield; a synchronous sleep cannot await.
	}
}

export function memoryStoreSleep(ms: number): void {
	// Atomics.wait on a zero-filled SharedArrayBuffer is a true synchronous sleep (zero CPU
	// burn): the SAB is zero-initialized so Int32Array[0]===0===expected → it blocks for `ms`
	// until timeout. But SharedArrayBuffer can be unavailable in sandboxed/restricted runtimes
	// (some containers/VMs disable it), and Atomics.wait itself can throw on a non-allowed
	// agent. The lock-contention retry that calls this is NOT otherwise guarded, so a throw
	// here would crash the deposit. Fall back to a bounded busy-wait so contention never
	// crashes — slower path, but correct and robust. opt #82.
	try {
		const sab = new SharedArrayBuffer(4);
		Atomics.wait(new Int32Array(sab), 0, 0, ms);
	} catch {
		memoryStoreBusyWaitSleep(ms);
	}
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
	// opt #107: if renameSync throws (EBUSY/EIO/ENOSPC-metadata/EACCES, or a
	// mid-sequence crash between the two lines), `tmp` is orphaned in dirname(path)
	// permanently — writeFileAtomic runs on the deposit hot path (events.jsonl +
	// case-memory.jsonl every appendMemoryEventTransaction), so a transient rename
	// failure would accumulate .tmp files. Unlink the orphaned temp on any failure
	// before re-throwing (mirrors the atomicWriteFileSync temp-cleanup guard that
	// writePrivateTextFile already applies to ITS internal temp).
	try {
		renameSync(tmp, path);
		chmodPrivate(path, 0o600);
	} catch (error) {
		try {
			unlinkSync(tmp);
		} catch {
			// Best-effort: tmp may already be gone or on a read-only mount.
		}
		throw error;
	}
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
	return assembleMemoryStoreVerificationReport(
		{
			eventsPath: input.eventsPath,
			caseMemoryPath: input.caseMemoryPath,
			transactionDir: input.transactionDir,
			storeReportPath: input.storeReportPath,
			snapshotPath: input.snapshotPath,
			lockPath: input.lockPath,
			generatedAt: input.generatedAt,
		},
		{
			eventCount: eventScan.rows.length,
			caseRowCount: caseScan.rows.length,
			hashChainOk,
			seqOk,
			prevHashOk,
			caseIndexOk,
			eventParseOk,
			caseParseOk,
			latestEventHash: eventScan.rows.at(-1)?.entryHash ?? "0".repeat(64),
			errors,
		},
	);
}

// opt #78 — shared report assembly, extracted so the incremental post-commit verifier
// (buildMemoryStoreVerificationIncremental) can produce a BYTE-IDENTICAL report from
// cached preflight flags + a single newly-appended event WITHOUT re-walking the chain.
// buildMemoryStoreVerificationReport (full walk) and the incremental path both route
// here, so the report shape/storeGrade/repairCommands/requiredChecks can never drift.
function assembleMemoryStoreVerificationReport(
	input: {
		eventsPath: string;
		caseMemoryPath: string;
		transactionDir: string;
		storeReportPath: string;
		snapshotPath: string;
		lockPath: string;
		generatedAt?: string;
	},
	flags: {
		eventCount: number;
		caseRowCount: number;
		hashChainOk: boolean;
		seqOk: boolean;
		prevHashOk: boolean;
		caseIndexOk: boolean;
		eventParseOk: boolean;
		caseParseOk: boolean;
		latestEventHash: string;
		errors: string[];
	},
): MemoryStoreVerificationV1 {
	const parseOk = flags.eventParseOk && flags.caseParseOk;
	const eventChainOk = flags.hashChainOk && flags.seqOk && flags.prevHashOk && flags.eventParseOk;
	const storeGrade =
		eventChainOk && flags.caseIndexOk && flags.caseParseOk ? "pass" : eventChainOk ? "repairable" : "blocked";
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
		eventCount: flags.eventCount,
		caseRowCount: flags.caseRowCount,
		hashChainOk: flags.hashChainOk,
		seqOk: flags.seqOk,
		prevHashOk: flags.prevHashOk,
		caseIndexOk: flags.caseIndexOk,
		parseOk,
		latestEventHash: flags.latestEventHash,
		storeGrade,
		errors: uniqueNonEmpty(flags.errors, 120),
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

// opt #165 — fileDigest used to readFileSync(path) the WHOLE file into a Buffer and
// then buffer.toString("utf-8") a SECOND full-size copy, just to sha256 it and (for
// the `text` field) hand back the full content. Memory artifacts (evidence captures,
// large dumps) can be many MB → a huge file was loaded into memory TWICE before the
// digest ran → OOM / ERR_FS_FILE_TOO_LARGE. The two internal callers
// (repairMemoryStoreIndex, snapshotMemoryStore) only read `.sha256` and `.bytes` and
// NEVER `.text`; the `text` field is kept only for shape parity with digestFromText
// (and the byte-identical parity test). Fix:
//   - sha256: REUSES opt #158/#159 hashFileSha256 (./text.ts) — stat-first, streams
//     through createHash in 1 MB positioned readSync chunks for files > 1 MB, so the
//     digest covers ALL bytes (byte-identical to the old whole-file hash) with memory
//     bounded to one chunk regardless of file size.
//   - bytes: stat.size — no read needed (buffer.length === stat.size for a regular
//     file, so this is byte-identical to the old buffer.length).
//   - text: stat-size GUARD using the SHARED cap REPI_READ_TEXT_FILE_MAX_BYTES
//     (default 16 MB, 0 disables — same knob/name as opt #163 storage.readTextFile,
//     so one cap governs both paths). Files ≤ cap keep the exact readFileSync-utf8
//     path (byte-identical). Oversized files return a BOUNDED TAIL (last
//     FILE_DIGEST_TAIL_MAX bytes) with a truncation marker instead of loading the
//     whole file — the `text` field is never the multi-MB content. The two real
//     consumers ignore `text`, so a bounded tail is a faithful degradation; the
//     marker makes the truncation observable rather than silently wrong.
const FILE_DIGEST_TAIL_MAX = 64 * 1024;
const FILE_DIGEST_TEXT_CAP_DEFAULT = 16 * 1024 * 1024;
function fileDigestTextCap(): number {
	const raw = Number(process.env.REPI_READ_TEXT_FILE_MAX_BYTES);
	if (Number.isFinite(raw) && raw >= 0) return Math.floor(raw);
	return FILE_DIGEST_TEXT_CAP_DEFAULT;
}

// Streaming bounded-tail read: never loads the whole file. Reads the last `max` bytes
// via positioned readSync and decodes UTF-8 (a split leading multi-byte sequence is
// left to String's replacement semantics — the tail is observational, not parsed).
function readFileTailText(path: string, size: number, max: number): string {
	const fd = openSync(path, "r");
	try {
		const len = Math.min(max, size);
		const start = size - len;
		const buf = Buffer.alloc(len);
		let read = 0;
		while (read < len) {
			const n = readSync(fd, buf, read, len - read, start + read);
			if (n <= 0) break;
			read += n;
		}
		const body = buf.subarray(0, read).toString("utf-8");
		return `\n...<fileDigest: file is ${size} bytes > REPI_READ_TEXT_FILE_MAX_BYTES cap; showing last ${len} bytes>...\n${body}`;
	} finally {
		try {
			closeSync(fd);
		} catch {
			// Best-effort: fd may already be invalid.
		}
	}
}

export function fileDigest(path: string): { sha256: string; bytes: number; text: string } {
	try {
		const size = statSync(path).size;
		const cap = fileDigestTextCap();
		const text =
			cap > 0 && size > cap ? readFileTailText(path, size, FILE_DIGEST_TAIL_MAX) : readFileSync(path, "utf-8");
		return { sha256: hashFileSha256(path), bytes: size, text };
	} catch {
		return { sha256: sha256Text(""), bytes: 0, text: "" };
	}
}

// digestFromText: same {sha256,bytes,text} shape as fileDigest, but computed from
// already-read text instead of re-reading the file. Equivalent to fileDigest for
// UTF-8 files (memory events/case files are written as UTF-8 via writeFileAtomic):
// createHash().update(string) hashes the UTF-8 encoding, and Buffer.byteLength counts
// UTF-8 bytes. Used on the memory-append hot path to skip 2 readFileSync per append —
// the file text is already in hand from jsonlScan (.raw), and no write occurs between
// the scan and the digest (lock held), so re-reading would return identical bytes.
export function digestFromText(text: string): { sha256: string; bytes: number; text: string } {
	return { sha256: sha256Text(text), bytes: Buffer.byteLength(text, "utf-8"), text };
}

// opt #77 — memory-store verification report cache. buildMemoryStoreVerificationReport
// is a PURE function of (events.jsonl rows, case-memory.jsonl rows), both rewritten
// atomically (writeFileAtomic temp+rename → fresh mtime+size) on every deposit/sanitize.
// The per-deposit PREFLIGHT (recon-profile.ts:30042, buildMemoryStoreVerificationFromScans
// {write:false}) re-walked the ENTIRE events chain on every append — O(events) loop with
// one memoryEventHash (JSON.stringify+sha256 of the whole event) per row — just to confirm
// the store was clean BEFORE appending, even though the previous deposit's POST-COMMIT
// (recon-profile.ts:30161, {write:true}) had already full-walked and verified that exact
// file state. Between deposits nothing touches events.jsonl/case-memory.jsonl (lock-held,
// no external writer), so the preflight re-verified byte-identical, already-verified content
// every time → ~N redundant memoryEventHash recomputations per deposit (O(N²) cumulative).
//
// The cache keys on (eventsPath, eventsMtime, eventsSize, caseMtime, caseSize). A read-only
// verify (options.write===false — the preflight, and any write:false caller) that finds both
// files unchanged since the last full walk returns the cached report and SKIPS the O(N) walk.
// The post-commit (write:true) is NEVER short-circuited (the guard requires write===false):
// the append bumps mtime → guaranteed cache miss → full walk → re-cache, so tamper-detection
// on the append itself stays at FULL strength (every deposit's post-commit recomputes every
// hash). write:true/default verifyMemoryStore callers (operator /re_memory verify, sanitize,
// dashboard) also never short-circuit → their behavior is byte-identical (full walk + write).
// mtime+size is the universal invalidation: any external rewrite (sanitize poison-cleanup,
// ensureRepiStorage init, manual edit) changes both → miss → full walk; worst case is a false
// MISS (correct but slower), never a false HIT (atomic temp+rename changes mtime on every
// content change — same guarantee #65/#68/#70/#73/#74 rely on). Missing file → don't cache.
const memoryStoreVerificationCache = new Map<
	string,
	{
		eventsMtimeMs: number;
		eventsSize: number;
		caseMtimeMs: number;
		caseSize: number;
		report: MemoryStoreVerificationV1;
	}
>();

function statMemoryStoreFile(path: string): { mtimeMs: number; size: number } | undefined {
	try {
		const s = statSync(path);
		return { mtimeMs: s.mtimeMs, size: s.size };
	} catch {
		return undefined;
	}
}

// Commit a freshly-built report into the #77 cache under the CURRENT file mtime/size.
// Used by the incremental post-commit (opt #78), which builds the post-append report
// WITHOUT going through buildMemoryStoreVerificationFromScans (it doesn't re-scan), so
// it must update the cache manually for the next preflight (write:false) to hit.
function commitMemoryStoreVerificationCache(report: MemoryStoreVerificationV1): void {
	const eventsPath = memoryEventsPath();
	const eventsStat = statMemoryStoreFile(eventsPath);
	const caseStat = statMemoryStoreFile(caseMemoryPath());
	if (eventsStat && caseStat) {
		memoryStoreVerificationCache.set(eventsPath, {
			eventsMtimeMs: eventsStat.mtimeMs,
			eventsSize: eventsStat.size,
			caseMtimeMs: caseStat.mtimeMs,
			caseSize: caseStat.size,
			report,
		});
	} else {
		memoryStoreVerificationCache.delete(eventsPath);
	}
}

// opt #78 — periodic full-verify safety net for the incremental post-commit. The
// incremental path trusts the cached preflight report for the first N events (mtime+size
// guard + atomic-rewrite-preserved verbatim — see buildMemoryStoreVerificationIncremental).
// To bound any residual risk from a subtle incremental-logic bug to a finite window, every
// K deposits we do a FULL walk instead of incremental. env REPI_MEMORY_FULL_VERIFY_EVERY
// (default 256, 0 disables the safety net). Reset by invalidateMemoryStoreVerificationCache.
let depositsSinceFullPostVerify = 0;
function memoryFullVerifyEvery(): number {
	const raw = Number(process.env.REPI_MEMORY_FULL_VERIFY_EVERY);
	return Number.isFinite(raw) && raw >= 0 ? Math.floor(raw) : 256;
}

// Testability + belt-and-suspenders invalidation (the mtime+size guard already invalidates
// on any rewrite; this is for tests that swap the store under the cache and for forced reset).
export function invalidateMemoryStoreVerificationCache(): void {
	memoryStoreVerificationCache.clear();
	depositsSinceFullPostVerify = 0;
}

export function buildMemoryStoreVerificationFromScans(
	eventScan: MemoryStoreJsonlScan<MemoryEventV1>,
	caseScan: MemoryStoreJsonlScan<CaseMemoryV1>,
	options: { write?: boolean } = {},
): MemoryStoreVerificationV1 {
	const eventsPath = memoryEventsPath();
	const casePath = caseMemoryPath();
	const eventsStat = statMemoryStoreFile(eventsPath);
	const caseStat = statMemoryStoreFile(casePath);
	const cached = memoryStoreVerificationCache.get(eventsPath);
	if (
		options.write === false &&
		cached &&
		eventsStat &&
		caseStat &&
		cached.eventsMtimeMs === eventsStat.mtimeMs &&
		cached.eventsSize === eventsStat.size &&
		cached.caseMtimeMs === caseStat.mtimeMs &&
		cached.caseSize === caseStat.size
	) {
		return cached.report; // cache hit: skip the O(events) hash-chain walk
	}
	const report = buildMemoryStoreVerificationReport({
		eventScan,
		caseScan,
		eventsPath,
		caseMemoryPath: casePath,
		transactionDir: memoryTransactionsDir(),
		storeReportPath: memoryStoreReportPath(),
		snapshotPath: memoryStoreSnapshotPath(),
		lockPath: memoryStoreLockPath(),
	});
	if (eventsStat && caseStat) {
		memoryStoreVerificationCache.set(eventsPath, {
			eventsMtimeMs: eventsStat.mtimeMs,
			eventsSize: eventsStat.size,
			caseMtimeMs: caseStat.mtimeMs,
			caseSize: caseStat.size,
			report,
		});
	} else {
		memoryStoreVerificationCache.delete(eventsPath);
	}
	if (options.write !== false) writeFileAtomic(memoryStoreReportPath(), `${JSON.stringify(report, null, 2)}\n`);
	return report;
}

export function buildMemoryStoreVerificationUnlocked(options: { write?: boolean } = {}): MemoryStoreVerificationV1 {
	const eventScan = jsonlScan(memoryEventsPath(), isMemoryEvent, "MemoryEventV1");
	const caseScan = jsonlScan(caseMemoryPath(), isCaseMemory, "CaseMemoryV1");
	return buildMemoryStoreVerificationFromScans(eventScan, caseScan, options);
}

export function verifyMemoryStore(options: { write?: boolean } = {}): MemoryStoreVerificationV1 {
	ensureRepiStorage();
	return withMemoryStoreLock("snapshot", () => buildMemoryStoreVerificationUnlocked(options));
}

// opt #78 — incremental post-commit verification. The per-deposit POST-COMMIT
// (recon-profile.ts:30161) used to call buildMemoryStoreVerificationUnlocked({write:true}),
// which re-scans events.jsonl+case-memory.jsonl (mtime bumped by the append → parsed-cache
// miss → full O(N) re-parse) AND re-walks the ENTIRE chain (O(N+1) memoryEventHash =
// JSON.stringify+sha256 of every event object) — re-verifying the first N events that the
// PREFLIGHT (recon-profile.ts:30042) had ALREADY verified this same deposit (the preflight
// `report` is in hand at the call site). Over M deposits → O(M·N) = O(N²) re-hashing.
//
// The incremental path builds the post-append report from the preflight report + the ONE
// newly-appended event + its case row, verifying ONLY the new event's chain linkage:
//   seq === preflight.eventCount + 1
//   prevHash === preflight.latestEventHash   (chains to the verified tail)
//   entryHash === memoryEventHash(event)      (self-consistency)
// plus the new case row's structural consistency (lastEventHash === event.entryHash,
// eventIds includes event.id — both hold by construction via caseMemorySnapshotFromEvent).
// The first N events are trusted from the preflight report, which was produced by a FULL
// walk (either a #77 cache hit — trusted from a prior full walk — or a fresh miss walk);
// the atomic append (writeFileAtomic temp+rename) rewrites the first N verbatim, so the
// on-disk first N are byte-identical to the preflight-verified state. Under the lock there
// is no concurrent writer. So the post-append chain is fully verified (first N by preflight
// full walk + new event by incremental check) at O(1) instead of O(N).
//
// SAFETY — full-walk fallback on ANY doubt (correctness is never silently weakened):
//   - periodic safety net: every K deposits (REPI_MEMORY_FULL_VERIFY_EVERY, default 256),
//     do a full walk instead of incremental + reset the counter;
//   - preflight.storeGrade !== "pass" → full walk (a repairable-rebuild made the preflight
//     report stale w.r.t. case memory, so its caseIndexOk can't be trusted);
//   - any new-event/new-caseRow check failure → full walk (a construction bug or tamper);
//   - the fallback is buildMemoryStoreVerificationUnlocked({write:true}) — the exact prior
//     behavior — so the incremental path can only make things FASTER, never less safe. A
//     bug in the incremental logic triggers the fallback (full walk), not a wrong report.
// The report is assembled via the SAME assembleMemoryStoreVerificationReport helper as the
// full walk → byte-identical report shape. The cache is committed with the post-append
// mtime/size so the next preflight (write:false) hits.
export function buildMemoryStoreVerificationIncremental(
	preflight: MemoryStoreVerificationV1,
	event: MemoryEventV1,
	caseRow: CaseMemoryV1,
	options: { write?: boolean } = {},
): MemoryStoreVerificationV1 {
	const fullVerifyEvery = memoryFullVerifyEvery();
	depositsSinceFullPostVerify += 1;
	// Periodic safety net + non-pass preflight → full walk (the exact prior behavior).
	if ((fullVerifyEvery > 0 && depositsSinceFullPostVerify >= fullVerifyEvery) || preflight.storeGrade !== "pass") {
		depositsSinceFullPostVerify = 0;
		return buildMemoryStoreVerificationUnlocked(options);
	}
	// Verify the new event's chain linkage. Any failure → full walk (no silent wrong report).
	const expectedSeq = preflight.eventCount + 1;
	const expectedEntryHash = memoryEventHash(event);
	const seqOk = preflight.seqOk && event.seq === expectedSeq;
	const prevHashOk = preflight.prevHashOk && event.prevHash === preflight.latestEventHash;
	const hashOk = preflight.hashChainOk && event.entryHash === expectedEntryHash;
	const caseRowOk = caseRow.lastEventHash === event.entryHash && caseRow.eventIds.includes(event.id);
	if (!seqOk || !prevHashOk || !hashOk || !caseRowOk) {
		depositsSinceFullPostVerify = 0;
		return buildMemoryStoreVerificationUnlocked(options);
	}
	// All checks pass → assemble the post-append report incrementally (no re-walk).
	const report = assembleMemoryStoreVerificationReport(
		{
			eventsPath: memoryEventsPath(),
			caseMemoryPath: caseMemoryPath(),
			transactionDir: memoryTransactionsDir(),
			storeReportPath: memoryStoreReportPath(),
			snapshotPath: memoryStoreSnapshotPath(),
			lockPath: memoryStoreLockPath(),
		},
		{
			eventCount: expectedSeq,
			caseRowCount: preflight.caseRowCount + 1,
			hashChainOk: true,
			seqOk: true,
			prevHashOk: true,
			caseIndexOk: true,
			eventParseOk: true,
			caseParseOk: true,
			latestEventHash: event.entryHash,
			errors: preflight.errors,
		},
	);
	commitMemoryStoreVerificationCache(report);
	if (options.write !== false) writeFileAtomic(memoryStoreReportPath(), `${JSON.stringify(report, null, 2)}\n`);
	return report;
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

// opt #113 — events.jsonl ledger rotation (the last unbounded REPI ledger; sibling of #99
// case-memory, #88 deposition bus, #48 tool-trace, #107 governance). events.jsonl is the
// append-only CHAIN ledger (each row has seq/prevHash/entryHash chained from genesis
// "0".repeat(64)); appendMemoryEventTransaction rewrites the whole file via writeFileAtomic on
// every deposit, so it grows O(D) rows and every cold recall/quality/replay path reads the
// whole chain. Unlike case-memory (#99, NO-chain, raw tail-keep), the events chain is
// CONTIGUOUS (prevHash = predecessor's entryHash, and prevHash is an INPUT to the row's own
// entryHash) → truncating the head breaks every surviving row's linkage. So rotation must
// RE-HASH the kept tail forward from genesis (seq=1, prevHash="0".repeat(64), recompute
// entryHash) — mirroring the sanitize path's co-rewrite template (recon-profile.ts:30649).
// case-memory is CO-ROTATED via rebuildCaseMemoryFromEvents(keptRows) so its eventIds/
// lastEventHash references stay consistent with the re-hashed tail (else verifyMemoryStore
// reports unknown_event_id / last_event_hash_mismatch). Corrupt-store guard: abort (return
// null) when the pre-rotation store is "blocked" (parse error or broken chain) — do NOT
// rewrite a corrupt store. Runs under the CALLER's memory-store lock (the append path holds
// "append-memory-event"; the function does NOT acquire its own lock — the mkdir lock at
// withMemoryStoreLock is non-reentrant, so acquiring "repair-index" from inside the appender
// would deadlock). Env knobs: REPI_MEMORY_EVENTS_MAX_ROWS (default 500, 0=disable, negative/non-numeric→default) +
// REPI_MEMORY_EVENTS_ROTATE_BATCH (default 50). Returns the kept rows when it rewrote the
// file, else null.
function memoryEventsMaxRows(): number {
	const raw = Number(process.env.REPI_MEMORY_EVENTS_MAX_ROWS);
	if (Number.isFinite(raw) && raw >= 0) return Math.floor(raw);
	return 500;
}

function memoryEventsRotateBatch(): number {
	const raw = Number(process.env.REPI_MEMORY_EVENTS_ROTATE_BATCH);
	if (Number.isFinite(raw) && raw >= 0) return Math.floor(raw);
	return 50;
}

export function rotateMemoryEventsLedgerIfNeeded(): MemoryEventV1[] | null {
	const maxRows = memoryEventsMaxRows();
	if (maxRows <= 0) return null;
	const batch = memoryEventsRotateBatch();
	const eventScan = jsonlScan(memoryEventsPath(), isMemoryEvent, "MemoryEventV1");
	const events = eventScan.rows;
	// Batched: only rotate once the row count exceeds maxRows + batch (not every append past the
	// cap) so the hot-path deposit append stays O(chunk); the O(maxRows) rotation amortizes to
	// O(maxRows/batch) per deposit.
	if (events.length <= maxRows + batch) return null;
	// Corrupt-store guard: do NOT rotate a blocked store (parse error or broken chain). The
	// #77 cache is mtime+size guarded — a corrupt file has a different size → cache miss → fresh
	// full walk → accurate verdict (never a false "pass" on corrupt content).
	const caseScan = jsonlScan(caseMemoryPath(), isCaseMemory, "CaseMemoryV1");
	const before = buildMemoryStoreVerificationFromScans(eventScan, caseScan, { write: false });
	if (eventScan.errors.length > 0 || before.storeGrade === "blocked") return null;
	// Keep the tail; re-hash forward from genesis (the chain is contiguous → head truncation
	// breaks every surviving row unless re-hashed). Mirrors the sanitize co-rewrite template.
	const kept = events.slice(-maxRows);
	let prevHash = "0".repeat(64);
	const keptRows: MemoryEventV1[] = kept.map((event, index) => {
		const row: MemoryEventV1 = { ...event, seq: index + 1, prevHash, entryHash: "" };
		row.entryHash = memoryEventHash(row);
		prevHash = row.entryHash;
		return row;
	});
	const eventBody = keptRows.length ? `${keptRows.map((row) => JSON.stringify(row)).join("\n")}\n` : "";
	writeFileAtomic(memoryEventsPath(), eventBody);
	// Co-rotate case-memory so its eventIds/lastEventHash references resolve against the
	// re-hashed tail (rebuildCaseMemoryFromEvents works correctly on a tail-only events file).
	const cases = rebuildCaseMemoryFromEvents(keptRows);
	const caseBody = cases.length ? `${cases.map((row) => JSON.stringify(row)).join("\n")}\n` : "";
	writeFileAtomic(caseMemoryPath(), caseBody);
	// Invalidate the #77 verification cache + #84 recall hash-chain cache (belt-and-suspenders;
	// the atomic-rewrite mtime bump already auto-invalidates both on the next read).
	invalidateMemoryStoreVerificationCache();
	invalidateMemoryEventHashChainCache();
	// Warm the #74 parsed-rows cache from the in-hand post-rotation rows so the next recall
	// path hits (no re-read/re-parse); mirrors recon-profile.ts:30333.
	warmJsonlParsedCache(memoryEventsPath(), isMemoryEvent, keptRows, [], eventBody);
	warmJsonlParsedCache(caseMemoryPath(), isCaseMemory, cases, [], caseBody);
	// Verify the co-rotated store is consistent (case-memory references resolve against the
	// re-hashed tail). Require "pass"; a failure here should not happen given the guard.
	const after = buildMemoryStoreVerificationUnlocked({ write: true });
	if (after.storeGrade !== "pass") return null;
	return keptRows;
}

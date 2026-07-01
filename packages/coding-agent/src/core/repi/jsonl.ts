import { statSync } from "node:fs";
import { readTextFileCached } from "./storage.ts";

// opt #74 — parsed-rows cache layered on the #70 text cache. jsonlRecords/jsonlScan run
// 4-5× per tool_result on the memory-recall hot path (searchMemoryEvents → readMemoryEvents
// + latestCaseMemoryBySignature + latestMemoryQualityByEvent + governance + vectors), each
// doing an O(rows) JSON.parse of the SAME events/case/quality/governance JSONL files that
// only change on deposit/governance/quality ops. #70 cached the TEXT read (one stat(2),
// zero readFileSync on a hit) but the per-call JSON.parse still ran. #74 caches the PARSED
// rows too: on a cache hit (mtime+size unchanged AND same predicate ref) return the cached
// rows/errors/raw directly — zero JSON.parse. Over a session with R tool_results and N
// ledger rows this is O(R·N) parse → O(deposits·N) (only the deposit that bumps mtime
// re-parses; subsequent recall reads hit).
//
// Cache key is (path, predicate ref). Each ledger path has ONE stable predicate in
// practice (events→isMemoryEvent, case→isCaseMemory, quality→isMemoryQualityLedgerRow,
// governance→isMemoryGovernanceLedgerRow [opt #74 extracted this from an inline literal so
// the ref is stable], deposition→isMemoryDepositionRuntimeEvent, claims/replay likewise).
// Keying on the predicate ref prevents cross-predicate contamination if a path ever gains a
// second predicate. The mtime+size guard (the #65/#68/#70 pattern) is the universal
// invalidation: any rewrite (atomic temp+rename or append) bumps mtime → miss → re-parse.
//
// Shared-reference safety (the #70 deferral, now resolved): the cached rows array + row
// objects are returned SHARED — same precedent as #65 readJsonObjectFileCached returning
// cached.value directly. Audited every jsonlRecords/jsonlScan caller (memory-recall.ts,
// memory-search.ts, case-memory.ts, memory-quality.ts, memory-vector.ts, recon-profile.ts,
// memory-deposition.ts, experience-claims, replay): NONE mutate the returned array (every
// push/splice/map is on a freshly-constructed array) or row objects (the only `row.x =`
// assignments are on freshly-built rows, not cached-reader rows). The recall path reads
// fields and builds fresh Maps/arrays. So sharing is safe; a freeze/deep-copy would
// re-introduce the O(rows) cost the cache eliminates. A latent invariant: any new caller
// that mutates a returned row/array would corrupt the cache for all readers — preserve
// "treat jsonlRecords/jsonlScan output as read-only" when adding callers.
//
// Deposit ordering (unchanged from #70): a deposit writes events.jsonl BEFORE the recall
// read (handler order: trace → auto-deposit → recall), bumping mtime → parsed-cache miss →
// recall sees post-deposit rows. The tool-trace ledger (changes every tool call) does NOT
// use jsonl.ts — its own uncached reader — so the always-changing hot file is unaffected.
// Missing files are NOT cached (stat throws → miss → readTextFileCached fallback "" → parse
// [] → but no stat, so nothing is stored → the next call re-stats and observes the file
// once it appears).
const parsedJsonlCache = new Map<
	string,
	{
		mtimeMs: number;
		size: number;
		rows: unknown[];
		errors: string[];
		raw: string;
		predicate: (value: unknown) => boolean;
	}
>();

function readJsonlParsed<T>(
	path: string,
	predicate: (value: unknown) => value is T,
	typeName: string,
): { rows: T[]; errors: string[]; raw: string } {
	let stat: { mtimeMs: number; size: number } | undefined;
	try {
		const s = statSync(path);
		stat = { mtimeMs: s.mtimeMs, size: s.size };
	} catch {
		stat = undefined;
	}
	const cached = parsedJsonlCache.get(path);
	if (
		cached &&
		stat &&
		stat.mtimeMs === cached.mtimeMs &&
		stat.size === cached.size &&
		cached.predicate === predicate
	) {
		return { rows: cached.rows as T[], errors: cached.errors, raw: cached.raw };
	}
	const raw = readTextFileCached(path, "");
	const rows: T[] = [];
	const errors: string[] = [];
	raw.split(/\r?\n/).forEach((line, index) => {
		const trimmed = line.trim();
		if (!trimmed) return;
		try {
			const parsed = JSON.parse(trimmed) as unknown;
			if (predicate(parsed)) rows.push(parsed);
			else if (typeName) errors.push(`${path}:${index + 1}:invalid_${typeName}`);
		} catch (error) {
			if (typeName) errors.push(`${path}:${index + 1}:json_parse_error:${String(error).slice(0, 120)}`);
		}
	});
	if (stat) {
		parsedJsonlCache.set(path, { mtimeMs: stat.mtimeMs, size: stat.size, rows, errors, raw, predicate });
	} else {
		parsedJsonlCache.delete(path);
	}
	return { rows, errors, raw };
}

export function jsonlRecords<T>(path: string, predicate: (value: unknown) => value is T): T[] {
	return readJsonlParsed(path, predicate, "").rows;
}

export function jsonlScan<T>(
	path: string,
	predicate: (value: unknown) => value is T,
	typeName: string,
): { rows: T[]; errors: string[]; raw: string } {
	return readJsonlParsed(path, predicate, typeName);
}

/**
 * opt #78 cache-warm helper. The #78 incremental post-commit verifier no longer
 * calls jsonlScan on the events/case files (that was the O(N) re-parse it eliminated),
 * but that jsonlScan had a second job: it WARMED the #74 parsed-rows cache (and, via
 * readTextFileCached, the #70 text cache) with the POST-append mtime+size+rows, so the
 * per-tool-result recall path that follows a deposit hit the cache (0 readFileSync, 0
 * JSON.parse). Without warming, the first recall after a deposit misses (1 read + 1
 * parse) — a regression in the #68/#70/#74 recall-read-amplification contract.
 *
 * This warms the parsed cache directly from rows + raw the caller already has in hand
 * (the preflight scan rows + the newly-appended row, the post-append text), stats the
 * file to capture the POST-append mtime+size, and records the entry — NO readFileSync,
 * NO JSON.parse. The recall path's jsonlRecords/jsonlScan then hits on (mtime+size,
 * predicate ref) and returns the shared rows without touching the text cache. Idempotent
 * with the full-walk fallback path (which warms via jsonlScan to the same post-append
 * mtime+rows), so calling it unconditionally at the append site is safe.
 */
/**
 * opt #83 — derived-value cache for JSONL-ledger reductions. Several recall-path helpers
 * (latestCaseMemoryBySignature, latestMemoryQualityByEvent, memoryBlockingGovernanceBySource)
 * build a Map/Set from a ledger's rows on EVERY call — O(rows) per call, called per
 * tool_result via searchMemoryEvents. The #74 parsed-rows cache already returns the SHARED
 * rows (0 readFileSync + 0 JSON.parse on a hit), but the derived Map was still rebuilt every
 * call. The Map is a PURE function of the rows, which only change when the ledger is rewritten
 * (deposit/governance/quality op, atomic temp+rename → mtime+size change). Cache the derived
 * value keyed by (path, mtime+size): on a hit return the cached value; on a miss call build()
 * (which reads #74-cached rows) and cache the result. Shared-reference safe — same precedent
 * as #65/#74/#76/#81: every consumer of these Maps reads row fields read-only (.get/.values,
 * no mutation of the Map or its row objects). A deposit bumps mtime → miss → rebuild + re-cache.
 * Missing files are NOT cached (stat throws → no store → next call re-stats), so an appearing
 * file is observed. Idempotent with direct builds. The build() closure MUST be a pure function
 * of the ledger rows (no side effects, no dependence on volatile state) — the cache assumes
 * equal (path, mtime+size) ⇒ equal derived value.
 */
const derivedJsonlCache = new Map<string, { mtimeMs: number; size: number; value: unknown }>();

export function cachedJsonlDerived<T>(path: string, build: () => T): T {
	let stat: { mtimeMs: number; size: number } | undefined;
	try {
		const s = statSync(path);
		stat = { mtimeMs: s.mtimeMs, size: s.size };
	} catch {
		stat = undefined;
	}
	const cached = derivedJsonlCache.get(path);
	if (cached && stat && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
		return cached.value as T;
	}
	const value = build();
	if (stat) derivedJsonlCache.set(path, { mtimeMs: stat.mtimeMs, size: stat.size, value });
	else derivedJsonlCache.delete(path);
	return value;
}

export function warmJsonlParsedCache<T>(
	path: string,
	predicate: (value: unknown) => value is T,
	rows: T[],
	errors: string[],
	raw: string,
): void {
	let stat: { mtimeMs: number; size: number } | undefined;
	try {
		const s = statSync(path);
		stat = { mtimeMs: s.mtimeMs, size: s.size };
	} catch {
		stat = undefined;
	}
	if (stat) {
		parsedJsonlCache.set(path, { mtimeMs: stat.mtimeMs, size: stat.size, rows, errors, raw, predicate });
	} else {
		parsedJsonlCache.delete(path);
	}
}

import { statSync } from "node:fs";
import { LruCache } from "./lru-cache.ts";
import { readTextFileCached } from "./storage.ts";

// Parsed-row cache layered on the text cache. A hit requires unchanged mtime/size
// and the same predicate reference. Rows are shared read-only values; copying
// them on every read would restore the old O(rows) parse cost. Missing files are
// deliberately not cached so a file created later is observed immediately.
const parsedJsonlCache = new LruCache<
	string,
	{
		mtimeMs: number;
		size: number;
		rows: unknown[];
		errors: string[];
		raw: string;
		predicate: (value: unknown) => boolean;
	}
>(256);

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

/** Cache a derived view of a JSONL file until its mtime or size changes. */
const derivedJsonlCache = new LruCache<string, { mtimeMs: number; size: number; value: unknown }>(256);

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

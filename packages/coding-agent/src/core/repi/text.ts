import { createHash } from "node:crypto";
import { closeSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { safeHeadEnd, safeTailStart } from "../tools/truncate.ts";

export function truncateMiddle(text: string, limit: number): string {
	if (text.length <= limit) return text;
	const head = Math.floor(limit * 0.55);
	const tail = Math.floor(limit * 0.35);
	const headEnd = safeHeadEnd(text, head);
	const tailStart = safeTailStart(text, text.length - tail);
	return `${text.slice(0, headEnd)}\n...<truncated ${text.length - limit} chars>...\n${text.slice(tailStart)}`;
}

export function metadataValue(text: string, key: string): string | undefined {
	const match = new RegExp(`^${key}:\\s*(.+)$`, "im").exec(text);
	return match?.[1]?.trim();
}

export function numericMetadataValue(text: string, key: string): number | undefined {
	const value = metadataValue(text, key);
	if (!value) return undefined;
	const parsed = Number(value);
	return Number.isFinite(parsed) ? parsed : undefined;
}

export function slug(value: string): string {
	return (
		value
			.replace(/[^a-z0-9._-]+/gi, "-")
			.replace(/^-+|-+$/g, "")
			.slice(0, 80) || "item"
	);
}

export function uniqueMatches(text: string, pattern: RegExp, limit: number): string[] {
	const seen = new Set<string>();
	for (const match of text.matchAll(pattern)) {
		const value = (match[1] ?? match[0]).trim();
		if (!value) continue;
		seen.add(value);
		if (seen.size >= limit) break;
	}
	return Array.from(seen);
}

export function interestingLines(text: string, pattern: RegExp, limit: number): string[] {
	return text
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => line && pattern.test(line))
		.slice(0, limit);
}

export function sha256Text(text: string): string {
	return createHash("sha256").update(text).digest("hex");
}

// opt #159 (moved from recon-profile.ts #158): hash an artifact file's FULL
// contents without loading it whole. createHash("sha256").update(readFileSync
// (path)) read the ENTIRE file into memory — a multi-GB artifact (memory dump,
// captured binary, coredump, large replay/compiler artifact) OOM-crashed (V8
// heap / ERR_FS_FILE_TOO_LARGE) before the digest ran. stat-first: files <=
// HASH_FILE_FAST_MAX keep the fast readFileSync path; larger files stream
// through the hash in fixed HASH_FILE_CHUNK_SIZE chunks via positioned readSync,
// so memory stays bounded to one chunk regardless of file size. The digest
// covers ALL bytes (unlike opt #156's tail-read), so the hash is byte-identical
// to the old whole-file hash. Shared here so both recon-profile.ts and
// memory-event.ts use one implementation without a circular import (recon-
// profile is the assembly layer that imports repi/*; repi/* must not import
// back from recon-profile).
const HASH_FILE_CHUNK_SIZE = 1024 * 1024;
const HASH_FILE_FAST_MAX = 1024 * 1024;
export function hashFileSha256(path: string): string {
	const stat = statSync(path);
	if (stat.size <= HASH_FILE_FAST_MAX) {
		return createHash("sha256").update(readFileSync(path)).digest("hex");
	}
	const fd = openSync(path, "r");
	try {
		const hash = createHash("sha256");
		const buf = Buffer.alloc(HASH_FILE_CHUNK_SIZE);
		let pos = 0;
		while (pos < stat.size) {
			const n = readSync(fd, buf, 0, Math.min(HASH_FILE_CHUNK_SIZE, stat.size - pos), pos);
			if (n <= 0) break;
			hash.update(buf.subarray(0, n));
			pos += n;
		}
		return hash.digest("hex");
	} finally {
		try {
			closeSync(fd);
		} catch {
			// Best-effort: fd may already be invalid.
		}
	}
}

export function clamp01(value: number | undefined, fallback: number): number {
	if (!Number.isFinite(value)) return fallback;
	return Math.max(0, Math.min(1, Number(value)));
}

export function envBoolean(name: string): boolean | undefined {
	const raw = process.env[name];
	if (raw === undefined) return undefined;
	if (/^(?:1|true|yes|on)$/i.test(raw.trim())) return true;
	if (/^(?:0|false|no|off)$/i.test(raw.trim())) return false;
	return undefined;
}

export function uniqueNonEmpty(values: Array<string | undefined>, limit = 80): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const value of values) {
		const text = String(value ?? "").trim();
		if (!text || text === "none") continue;
		const key = text.toLowerCase();
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(text);
		if (out.length >= limit) break;
	}
	return out;
}

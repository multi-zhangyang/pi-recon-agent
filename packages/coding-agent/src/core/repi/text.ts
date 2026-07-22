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

/** Remove credentials and auth material before text crosses a persistence boundary. */
export function redactSensitiveText(value: string, limit = 2000): string {
	let text = String(value ?? "");
	text = text.replace(/(https?:\/\/)([^\s/@:]+):([^\s/@]+)@/gi, "$1<redacted>@");
	text = text.replace(/(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1<redacted>");
	text = text.replace(/\b(?:sk|rk|ghp|glpat)-[A-Za-z0-9._-]{8,}\b/gi, "<redacted:token>");
	text = text.replace(
		/(\b(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|authorization|cookie|client[_-]?secret|auth[_-]?token)\s*[:=]\s*)(["']?)[^\s"'`,;&}]+\2/gi,
		"$1$2<redacted>$2",
	);
	text = text.replace(
		/([?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|key)=)[^&\s#]+/gi,
		"$1<redacted>",
	);
	return truncateMiddle(text, limit);
}

export function metadataValue(text: string, key: string): string | undefined {
	const match = new RegExp(`^${key}:\\s*(.+)$`, "im").exec(text);
	return match?.[1]?.trim();
}

/**
 * Parse the last line-delimited JSON code block in an artifact. JSON strings
 * may contain Markdown fences (for example a compiler report's embedded
 * shell repro), so a first-match fence regex can stop inside the payload.
 */
export function parseJsonCodeFence<T>(text: string): T | undefined {
	const openings = [...text.matchAll(/^```json[ \t]*\r?$/gim)];
	for (const opening of openings.reverse()) {
		const bodyStart = (opening.index ?? 0) + opening[0].length;
		const body = text.slice(bodyStart).replace(/^\n/, "");
		const closings = [...body.matchAll(/^[ \t]*```[ \t]*\r?$/gm)];
		for (const closing of closings.reverse()) {
			const candidate = body.slice(0, closing.index ?? 0).trim();
			try {
				return JSON.parse(candidate) as T;
			} catch {
				// A later fence may belong to trailing Markdown; try the prior
				// line-delimited close before declaring the artifact malformed.
			}
		}
	}
	return undefined;
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

export function compactStoredArtifact(kind: string, path: string, text: string, limit = 4096): string {
	const signals = text
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(
			(line) =>
				line &&
				(/^(?:#{1,3}\s+|status:|verdict:|score:|mode:|mission_id:|route:|target:|missing:|matched:|blockers?:|gaps?:|next(?:_actions?)?:|checks?:|failures?:)/i.test(
					line,
				) ||
					/^-\s+.*(?:blocked|missing|fail|gap|next|proof|verify)/i.test(line)),
		)
		.slice(0, 24)
		.map((line) => redactSensitiveText(line, 220));
	return truncateMiddle(
		[
			`${kind}:`,
			"status: stored",
			`artifact: ${path}`,
			`bytes: ${Buffer.byteLength(text)}`,
			`sha256: ${sha256Text(text)}`,
			"signals:",
			...(signals.length ? signals.map((line) => `- ${line}`) : ["- none"]),
			"detail: full artifact is available at artifact path",
		].join("\n"),
		limit,
	);
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
// to the old whole-file hash. Shared by the profile assembly layer and
// standalone REPI helpers without introducing a circular import.
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

import { createHash } from "node:crypto";

export function truncateMiddle(text: string, limit: number): string {
	if (text.length <= limit) return text;
	const head = Math.floor(limit * 0.55);
	const tail = Math.floor(limit * 0.35);
	return `${text.slice(0, head)}\n...<truncated ${text.length - limit} chars>...\n${text.slice(-tail)}`;
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

import { existsSync, statSync } from "node:fs";

export function shellQuote(value: string): string {
	return `'${value.replace(/'/g, "'\\''")}'`;
}

export type RepiTargetKind =
	| "missing"
	| "url"
	| "directory"
	| "file"
	| "package"
	| "path-like"
	| "literal"
	| "invalid-natural-language";

export const REPI_POISON_PATTERNS = [
	/两点问题我先提出/i,
	/pow的解速度/i,
	/moonr\/abogus/i,
	/不是你自己的逆向/i,
	/😅/,
] as const;

export function containsRepiPoison(value?: string): boolean {
	const text = value?.trim();
	return Boolean(text && REPI_POISON_PATTERNS.some((pattern) => pattern.test(text)));
}

export function containsEmoji(value: string): boolean {
	return /[\p{Extended_Pictographic}\p{Emoji_Presentation}]/u.test(value);
}

export function looksLikeNaturalLanguageTarget(value?: string): boolean {
	const text = value?.trim();
	if (!text) return false;
	if (containsRepiPoison(text) || containsEmoji(text)) return true;
	if (/^https?:\/\//i.test(text)) return false;
	if (/^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*){1,}$/.test(text)) return false;
	if (/^(?:\.{1,2}|~)?\//.test(text) || /^[A-Za-z]:[\\/]/.test(text)) return false;
	if (/^[\w./@:+%=-]+$/.test(text) && /[./]/.test(text)) return false;
	if (text.length > 160) return true;
	const hasCjk = /[\u3400-\u9fff]/.test(text);
	const hasSentencePunctuation = /[，。！？；、]|,\s*|[!?]\s/.test(text);
	const hasManySpaces = (text.match(/\s+/g) ?? []).length >= 3;
	return (hasCjk && hasSentencePunctuation && !/[\\/]/.test(text)) || (hasManySpaces && !/[\\/]/.test(text));
}

export function classifyRepiTarget(value?: string): { kind: RepiTargetKind; value?: string } {
	const text = value?.trim();
	if (!text || /^<.*>$/.test(text)) return { kind: "missing" };
	if (looksLikeNaturalLanguageTarget(text)) return { kind: "invalid-natural-language", value: text };
	if (/^https?:\/\//i.test(text)) return { kind: "url", value: text };
	if (/^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*){1,}$/.test(text) && !text.endsWith(".apk")) {
		return { kind: "package", value: text };
	}
	try {
		if (existsSync(text)) {
			const stat = statSync(text);
			if (stat.isDirectory()) return { kind: "directory", value: text };
			if (stat.isFile()) return { kind: "file", value: text };
		}
	} catch {
		// best-effort classification only
	}
	if (/^(?:\.{1,2}|~)?[\\/]/.test(text) || /[\\/]/.test(text) || /\.[A-Za-z0-9]{1,8}$/.test(text)) {
		return { kind: "path-like", value: text };
	}
	return { kind: "literal", value: text };
}

export function sanitizeTargetForCommand(value?: string): string | undefined {
	const classified = classifyRepiTarget(value);
	if (classified.kind === "missing" || classified.kind === "invalid-natural-language") return undefined;
	return classified.value;
}

export function commandTarget(value?: string, fallback?: string, placeholder = "<target>"): string {
	return sanitizeTargetForCommand(value) ?? sanitizeTargetForCommand(fallback) ?? placeholder;
}

export function isHttpUrlTarget(value?: string): boolean {
	return classifyRepiTarget(value).kind === "url";
}

export function isDirectoryTarget(value?: string): boolean {
	return classifyRepiTarget(value).kind === "directory";
}

export function commandContainsPoison(command?: string): boolean {
	const text = command?.trim();
	if (!text) return false;
	if (containsRepiPoison(text)) return true;
	const internalTarget = /^re[-_]\S+\s+(?:plan|run|build|tick|pack|dispatch|matrix|draft|audit)?\s*(.+)$/i.exec(
		text,
	)?.[1];
	return Boolean(internalTarget && looksLikeNaturalLanguageTarget(internalTarget));
}

export function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

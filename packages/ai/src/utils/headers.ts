import type { ProviderHeaders } from "../types.ts";

export function headersToRecord(headers: Headers): Record<string, string> {
	const result: Record<string, string> = {};
	for (const [key, value] of headers.entries()) {
		result[key] = value;
	}
	return result;
}

/** Merge header layers case-insensitively while retaining null suppression markers. */
export function mergeProviderHeaders(...sources: (ProviderHeaders | undefined)[]): ProviderHeaders | undefined {
	let merged: ProviderHeaders | undefined;
	for (const source of sources) {
		if (source === undefined) continue;
		merged ??= {};
		for (const [name, value] of Object.entries(source)) {
			const normalizedName = name.toLowerCase();
			for (const existingName of Object.keys(merged)) {
				if (existingName.toLowerCase() === normalizedName) delete merged[existingName];
			}
			merged[name] = value;
		}
	}
	return merged;
}

/** Whether a header layer explicitly supplies or suppresses a name. */
export function hasProviderHeader(headers: ProviderHeaders | undefined, name: string): boolean {
	if (!headers) return false;
	const normalizedName = name.toLowerCase();
	return Object.keys(headers).some((candidate) => candidate.toLowerCase() === normalizedName);
}

/** Remove null suppression markers before passing headers to string-only clients. */
export function providerHeadersToRecord(headers: ProviderHeaders | undefined): Record<string, string> | undefined {
	const merged = mergeProviderHeaders(headers);
	if (!merged) return undefined;
	const result: Record<string, string> = {};
	for (const [key, value] of Object.entries(merged)) {
		if (value !== null) result[key] = value;
	}
	return Object.keys(result).length > 0 ? result : undefined;
}

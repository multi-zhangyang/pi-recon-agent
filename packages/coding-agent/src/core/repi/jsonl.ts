import { readFileSync } from "node:fs";

function readText(path: string, fallback = ""): string {
	try {
		return readFileSync(path, "utf-8");
	} catch {
		return fallback;
	}
}

export function jsonlRecords<T>(path: string, predicate: (value: unknown) => value is T): T[] {
	return readText(path)
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean)
		.flatMap((line) => {
			try {
				const parsed = JSON.parse(line) as unknown;
				return predicate(parsed) ? [parsed] : [];
			} catch {
				return [];
			}
		});
}

export function jsonlScan<T>(
	path: string,
	predicate: (value: unknown) => value is T,
	typeName: string,
): { rows: T[]; errors: string[]; raw: string } {
	const raw = readText(path);
	const rows: T[] = [];
	const errors: string[] = [];
	raw.split(/\r?\n/).forEach((line, index) => {
		const trimmed = line.trim();
		if (!trimmed) return;
		try {
			const parsed = JSON.parse(trimmed) as unknown;
			if (predicate(parsed)) rows.push(parsed);
			else errors.push(`${path}:${index + 1}:invalid_${typeName}`);
		} catch (error) {
			errors.push(`${path}:${index + 1}:json_parse_error:${String(error).slice(0, 120)}`);
		}
	});
	return { rows, errors, raw };
}

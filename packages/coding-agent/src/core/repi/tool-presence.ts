import { accessSync, constants, statSync } from "node:fs";
import { delimiter, join } from "node:path";

export type RepiToolPresenceIndex = Map<string, { present: boolean; path?: string }>;

const hostToolPresenceCache = new Map<string, boolean>();

export function repiToolIndexEntry(
	index: RepiToolPresenceIndex,
	tool: string,
): { present: boolean; path?: string } | undefined {
	const lower = tool.toLowerCase();
	for (const [name, value] of index.entries()) {
		if (name.toLowerCase() === lower) return value;
	}
	const aliases = lower === "radare2" ? ["r2"] : lower === "r2" ? ["radare2"] : lower === "python" ? ["python3"] : [];
	for (const alias of aliases) {
		for (const [name, value] of index.entries()) {
			if (name.toLowerCase() === alias) return value;
		}
	}
	return undefined;
}

export function repiIndexedToolPresent(index: RepiToolPresenceIndex, tool: string): boolean | undefined {
	return repiToolIndexEntry(index, tool)?.present;
}

export function repiHostToolPresent(
	tool: string,
	options: { pathEnv?: string; probe?: (tool: string) => boolean | undefined } = {},
): boolean | undefined {
	const name = tool.trim();
	if (!/^[A-Za-z0-9_.:+-]+$/.test(name)) return undefined;
	const lower = name.toLowerCase();
	const pathEnv = options.pathEnv ?? process.env.PATH ?? "";
	const cacheKey = `${lower}\0${pathEnv}`;
	const cached = hostToolPresenceCache.get(cacheKey);
	if (cached !== undefined) return cached;
	const probed = options.probe?.(name);
	if (probed !== undefined) {
		hostToolPresenceCache.set(cacheKey, probed);
		return probed;
	}
	const extensions =
		process.platform === "win32" ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean) : [""];
	let present = false;
	for (const directory of pathEnv.split(delimiter)) {
		if (!directory) continue;
		for (const extension of extensions) {
			const candidate = join(directory, `${name}${extension}`);
			try {
				accessSync(candidate, process.platform === "win32" ? constants.F_OK : constants.X_OK);
				if (statSync(candidate).isFile()) {
					present = true;
					break;
				}
			} catch {
				// Continue searching the remaining PATH entries.
			}
		}
		if (present) break;
	}
	hostToolPresenceCache.set(cacheKey, present);
	return present;
}

export function repiResolvedToolPresent(
	index: RepiToolPresenceIndex,
	tool: string,
	options: { pathEnv?: string; probe?: (tool: string) => boolean | undefined } = {},
): boolean | undefined {
	return repiIndexedToolPresent(index, tool) ?? repiHostToolPresent(tool, options);
}

import { spawnSync } from "node:child_process";

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
	const result = spawnSync("bash", ["-lc", 'command -v "$1" >/dev/null 2>&1', "repi-tool-presence", name], {
		timeout: 2000,
		stdio: "ignore",
		env: { ...process.env, PATH: pathEnv },
	});
	const present = result.status === 0;
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

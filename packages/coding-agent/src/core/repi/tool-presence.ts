import { accessSync, constants, statSync } from "node:fs";
import { delimiter, join } from "node:path";

export type RepiToolPresenceIndex = Map<string, { present: boolean; path?: string }>;

function executableFilePresent(path: string): boolean {
	try {
		accessSync(path, process.platform === "win32" ? constants.F_OK : constants.X_OK);
		return statSync(path).isFile();
	} catch {
		return false;
	}
}

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
	const pathEnv = options.pathEnv ?? process.env.PATH ?? "";
	const probed = options.probe?.(name);
	if (probed !== undefined) return probed;
	const extensions =
		process.platform === "win32" ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean) : [""];
	let present = false;
	for (const directory of pathEnv.split(delimiter)) {
		if (!directory) continue;
		for (const extension of extensions) {
			const candidate = join(directory, `${name}${extension}`);
			if (executableFilePresent(candidate)) {
				present = true;
				break;
			}
		}
		if (present) break;
	}
	return present;
}

export function repiResolvedToolPresent(
	index: RepiToolPresenceIndex,
	tool: string,
	options: { pathEnv?: string; probe?: (tool: string) => boolean | undefined } = {},
): boolean | undefined {
	const live = repiHostToolPresent(tool, options);
	if (live !== undefined) return live;
	const indexed = repiToolIndexEntry(index, tool);
	if (indexed?.present && indexed.path && executableFilePresent(indexed.path)) return true;
	return indexed?.present;
}

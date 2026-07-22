import type { AuthContext } from "./types.ts";

interface NodeProcessLike {
	env?: Record<string, string | undefined>;
	getBuiltinModule?(specifier: string): unknown;
}

interface NodeFsPromises {
	access(path: string): Promise<void>;
}

interface NodeOs {
	homedir(): string;
}

function getProcess(): NodeProcessLike | undefined {
	return (globalThis as { process?: NodeProcessLike }).process;
}

/** Default Node auth context. Custom hosts and browsers can inject their own. */
export function defaultProviderAuthContext(): AuthContext {
	return {
		async env(name: string): Promise<string | undefined> {
			const value = getProcess()?.env?.[name];
			return typeof value === "string" && value.trim().length > 0 ? value : undefined;
		},

		async fileExists(path: string): Promise<boolean> {
			try {
				const processLike = getProcess();
				const fs = processLike?.getBuiltinModule?.("node:fs/promises") as NodeFsPromises | undefined;
				if (!fs) return false;
				const os = processLike?.getBuiltinModule?.("node:os") as NodeOs | undefined;
				const resolved = path.startsWith("~") && os ? os.homedir() + path.slice(1) : path;
				await fs.access(resolved);
				return true;
			} catch {
				return false;
			}
		},
	};
}

import type { ProviderEnv } from "../types.ts";

let procEnvCache: Map<string, string> | null = null;

/** Recover environment values in Bun sandbox binaries with an empty process.env. */
function getBunSandboxEnvValue(name: string): string | undefined {
	if (typeof process === "undefined" || !process.versions?.bun || Object.keys(process.env).length > 0) {
		return undefined;
	}

	if (procEnvCache === null) {
		procEnvCache = new Map();
		try {
			const { readFileSync } = require("node:fs") as {
				readFileSync(path: string, encoding: BufferEncoding): string;
			};
			const data = readFileSync("/proc/self/environ", "utf-8");
			for (const entry of data.split("\0")) {
				const index = entry.indexOf("=");
				if (index > 0) procEnvCache.set(entry.slice(0, index), entry.slice(index + 1));
			}
		} catch {
			// /proc/self/environ may not exist or may not be readable.
		}
	}

	return procEnvCache.get(name);
}

/** Resolve provider configuration without mutating the process environment. */
export function getProviderEnvValue(name: string, env?: ProviderEnv): string | undefined {
	return (
		env?.[name] ||
		(typeof process !== "undefined" ? process.env[name] : undefined) ||
		getBunSandboxEnvValue(name) ||
		undefined
	);
}

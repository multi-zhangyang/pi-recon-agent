#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const compiledSuffixes = [".d.ts.map", ".js.map", ".d.ts", ".js"];
const sourceExtensions = [".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs"];

function compiledSourceStem(packedPath) {
	if (!packedPath.startsWith("dist/")) return undefined;
	for (const suffix of compiledSuffixes) {
		if (packedPath.endsWith(suffix)) return packedPath.slice("dist/".length, -suffix.length);
	}
	return undefined;
}

export function findPackedOutputsWithoutSources(packageRoot, packedFiles) {
	const stale = [];
	for (const file of packedFiles) {
		const packedPath = typeof file === "string" ? file : file?.path;
		if (typeof packedPath !== "string") continue;
		const stem = compiledSourceStem(packedPath);
		if (stem === undefined) continue;
		const hasSource = sourceExtensions.some((extension) => existsSync(join(packageRoot, "src", `${stem}${extension}`)));
		if (!hasSource) stale.push(packedPath);
	}
	return [...new Set(stale)].sort();
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath === fileURLToPath(import.meta.url)) {
	const packageRoot = process.argv[2];
	if (!packageRoot || process.argv.length > 3) {
		console.error("Usage: node packed-source-closure.mjs <package-root> < npm-pack.json");
		process.exit(2);
	}
	try {
		const parsed = JSON.parse(readFileSync(0, "utf8"));
		const packed = Array.isArray(parsed) ? parsed[0] : parsed;
		const staleOutputs = findPackedOutputsWithoutSources(resolve(packageRoot), packed?.files ?? []);
		console.log(JSON.stringify({ ok: staleOutputs.length === 0, staleOutputs }));
		process.exit(staleOutputs.length === 0 ? 0 : 1);
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exit(2);
	}
}

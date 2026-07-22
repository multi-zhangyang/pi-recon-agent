#!/usr/bin/env node

import { rmSync } from "node:fs";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
if (args.length > 1 || args.includes("--help")) {
	console.log("Usage: node scripts/clean-production-dist.mjs [repo-root]");
	process.exit(args.includes("--help") ? 0 : 2);
}

const root = resolve(args[0] ?? process.cwd());
const productionPackages = ["tui", "ai", "agent", "coding-agent"];

for (const packageName of productionPackages) {
	rmSync(join(root, "packages", packageName, "dist"), { force: true, recursive: true });
}

#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";

const packageDirectories = ["packages/ai", "packages/agent", "packages/tui", "packages/coding-agent"];

function tarballFilename(name, version) {
	return `${name.replace(/^@/, "").replaceAll("/", "-")}-${version}.tgz`;
}

function readPackage(root, directory) {
	return JSON.parse(readFileSync(join(root, directory, "package.json"), "utf8"));
}

function sha256(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

const args = process.argv.slice(2);
if (args.includes("--help") || args.length > 2) {
	console.log("Usage: node scripts/reverse-agent/repi-release-manifest.mjs [repo-root] [assets-dir]");
	process.exit(args.includes("--help") ? 0 : 2);
}

const root = resolve(args[0] ?? process.cwd());
const assetsDir = resolve(root, args[1] ?? "release-assets");

try {
	const rootPackage = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
	const packages = packageDirectories.map((directory) => {
		const packageJson = readPackage(root, directory);
		const filename = tarballFilename(packageJson.name, packageJson.version);
		const path = join(assetsDir, filename);
		if (!existsSync(path)) throw new Error(`missing release tarball: ${filename}`);
		return {
			name: packageJson.name,
			version: packageJson.version,
			filename,
			bytes: statSync(path).size,
			sha256: sha256(path),
		};
	});
	const versions = new Set(packages.map((pkg) => pkg.version));
	if (versions.size !== 1 || !versions.has(rootPackage.version)) {
		throw new Error(`release package versions must all equal root version ${rootPackage.version}`);
	}
	const installArgv = ["npm", "install", "-g", ...packages.map((pkg) => `./${pkg.filename}`)];
	const manifest = {
		kind: "repi-release-manifest",
		schemaVersion: 1,
		version: rootPackage.version,
		allTarballsRequired: true,
		install: {
			argv: installArgv,
			command: installArgv.join(" "),
		},
		packages,
	};
	const output = join(assetsDir, "repi-release-manifest.json");
	writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`);
	console.log(`wrote ${basename(output)} for ${packages.length} same-version tarballs`);
} catch (error) {
	console.error(error instanceof Error ? error.message : String(error));
	process.exit(1);
}

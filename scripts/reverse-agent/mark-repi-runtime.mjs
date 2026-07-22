#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
	accessSync,
	constants,
	existsSync,
	readFileSync,
	readdirSync,
	renameSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const root = resolve(args.find((arg) => !arg.startsWith("--")) ?? process.cwd());
const invalidate = args.includes("--invalidate");
const verify = args.includes("--verify");
const launch = args.includes("--launch");
const manifestRelativePath = "packages/coding-agent/dist/repi-runtime.json";
const runtimeRoots = [
	"packages/tui/dist",
	"packages/ai/dist",
	"packages/agent/dist",
	"packages/coding-agent/dist",
];
const requiredEntries = [
	"packages/tui/dist/index.js",
	"packages/ai/dist/index.js",
	"packages/agent/dist/index.js",
	"packages/coding-agent/dist/cli.js",
	"packages/coding-agent/dist/modes/interactive/theme/dark.json",
	"packages/coding-agent/dist/modes/interactive/theme/light.json",
];

const manifestPath = join(root, manifestRelativePath);
const distCliPath = join(root, "packages", "coding-agent", "dist", "cli.js");
const sourceCliPath = join(root, "packages", "coding-agent", "src", "cli.ts");
const tsxPath = join(root, "node_modules", ".bin", "tsx");

function sha256(content) {
	return createHash("sha256").update(content).digest("hex");
}

function isRuntimeFile(relativePath) {
	return (
		relativePath !== manifestRelativePath &&
		!relativePath.endsWith(".d.ts") &&
		!relativePath.endsWith(".map")
	);
}

function listRuntimeFiles() {
	const files = [];
	const visit = (directory) => {
		for (const entry of readdirSync(directory, { withFileTypes: true })) {
			const path = join(directory, entry.name);
			if (entry.isDirectory()) {
				visit(path);
			} else if (entry.isFile()) {
				const relativePath = relative(root, path).split(sep).join("/");
				if (isRuntimeFile(relativePath)) files.push(relativePath);
			} else {
				throw new Error(`runtime tree contains a non-regular entry: ${relative(root, path)}`);
			}
		}
	};

	for (const runtimeRoot of runtimeRoots) visit(join(root, runtimeRoot));
	files.sort();
	for (const requiredEntry of requiredEntries) {
		if (!files.includes(requiredEntry)) throw new Error(`required runtime entry is missing: ${requiredEntry}`);
	}
	return files;
}

function readRootVersion() {
	const rootPackage = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
	if (typeof rootPackage.version !== "string" || rootPackage.version.length === 0) {
		throw new Error("root package.json has no version");
	}
	return rootPackage.version;
}

function verifyRuntimeManifest() {
	const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
	if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
		throw new Error("manifest must be a JSON object");
	}
	if (manifest.kind !== "repi-source-runtime") {
		throw new Error('manifest.kind must be "repi-source-runtime"');
	}
	if (manifest.schemaVersion !== 2) {
		throw new Error("manifest.schemaVersion must be 2");
	}
	const rootVersion = readRootVersion();
	if (manifest.version !== rootVersion) {
		throw new Error(`manifest.version must match package.json (${rootVersion})`);
	}
	if (!Array.isArray(manifest.entries)) {
		throw new Error("manifest.entries must be an array");
	}
	const runtimeFiles = listRuntimeFiles();
	const runtimePaths = new Set(runtimeFiles);
	if (manifest.entries.length !== runtimeFiles.length) {
		throw new Error(`manifest.entries count does not match runtime file count (${runtimeFiles.length})`);
	}
	const entriesByPath = new Map();
	for (const entry of manifest.entries) {
		if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
			throw new Error("manifest entry must be an object");
		}
		if (typeof entry.path !== "string" || !runtimePaths.has(entry.path)) {
			throw new Error(`manifest entry has an unexpected path: ${String(entry.path)}`);
		}
		if (entriesByPath.has(entry.path)) {
			throw new Error(`manifest entry is duplicated: ${entry.path}`);
		}
		if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 0) {
			throw new Error(`manifest entry has invalid bytes: ${entry.path}`);
		}
		if (typeof entry.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(entry.sha256)) {
			throw new Error(`manifest entry has invalid sha256: ${entry.path}`);
		}
		entriesByPath.set(entry.path, entry);
	}

	for (const relativePath of runtimeFiles) {
		const entry = entriesByPath.get(relativePath);
		if (!entry) throw new Error(`manifest entry is missing: ${relativePath}`);
		const content = readFileSync(join(root, relativePath));
		if (content.byteLength !== entry.bytes) {
			throw new Error(`manifest entry byte count does not match: ${relativePath}`);
		}
		if (sha256(content) !== entry.sha256) {
			throw new Error(`manifest entry sha256 does not match: ${relativePath}`);
		}
	}
}

function getLaunchArgs() {
	const launchIndex = args.indexOf("--launch");
	const separatorIndex = args.indexOf("--", launchIndex + 1);
	if (separatorIndex === -1) throw new Error("--launch requires a -- argument separator");
	return args.slice(separatorIndex + 1);
}

function launchSourceRuntime(launchArgs) {
	try {
		accessSync(tsxPath, constants.X_OK);
		accessSync(sourceCliPath, constants.R_OK);
	} catch {
		console.error("REPI runtime is unavailable: no verified production build or source runner was found.");
		console.error(`Run 'npm install --ignore-scripts && npm run build' in ${root}.`);
		process.exit(1);
	}
	if (typeof process.execve !== "function") {
		console.error("REPI source fallback requires Node.js 22.19.0 or newer.");
		process.exit(1);
	}
	const environment = Object.fromEntries(
		Object.entries(process.env).filter((entry) => typeof entry[1] === "string"),
	);
	process.execve(
		tsxPath,
		[tsxPath, "--tsconfig", join(root, "tsconfig.json"), sourceCliPath, ...launchArgs],
		environment,
	);
	throw new Error("process.execve returned unexpectedly");
}

const selectedModes = [invalidate, verify, launch].filter(Boolean).length;
if (selectedModes > 1) {
	console.error("REPI runtime manifest mode must be one of --invalidate, --verify, or --launch");
	process.exitCode = 2;
} else if (invalidate) {
	if (existsSync(manifestPath)) unlinkSync(manifestPath);
	console.log(`REPI runtime manifest invalidated: ${manifestPath}`);
} else if (verify) {
	try {
		verifyRuntimeManifest();
		console.log(`REPI runtime manifest verified: ${manifestPath}`);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		console.error(`REPI runtime manifest verification failed: ${message}`);
		process.exitCode = 1;
	}
} else if (launch) {
	const launchArgs = getLaunchArgs();
	try {
		verifyRuntimeManifest();
	} catch {
		launchSourceRuntime(launchArgs);
	}
	process.argv = [process.execPath, distCliPath, ...launchArgs];
	await import(pathToFileURL(distCliPath).href);
} else {
	const entries = listRuntimeFiles().map((relativePath) => {
		const path = join(root, relativePath);
		const content = readFileSync(path);
		return {
			path: relativePath,
			bytes: content.byteLength,
			sha256: sha256(content),
		};
	});
	const manifest = {
		kind: "repi-source-runtime",
		schemaVersion: 2,
		version: readRootVersion(),
		builtAt: new Date().toISOString(),
		entries,
	};
	const temporaryPath = `${manifestPath}.${process.pid}.tmp`;
	writeFileSync(temporaryPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
	renameSync(temporaryPath, manifestPath);
	console.log(`REPI runtime manifest: ${manifestPath}`);
}

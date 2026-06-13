import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type ProductCommandSpec = {
	script: string;
	normalizeArgs: (args: string[]) => string[];
};

const PRODUCT_COMMANDS = new Set([
	"health",
	"status",
	"doctor",
	"smoke",
	"selfcheck",
	"dogfood",
	"bugreport",
	"trust",
	"mission",
	"engage",
	"attack",
	"reverse",
	"web",
	"memory",
	"model",
	"models",
	"mcp",
	"swarm",
]);

function parentDirs(start: string): string[] {
	const dirs: string[] = [];
	let current = resolve(start);
	while (true) {
		dirs.push(current);
		const parent = dirname(current);
		if (parent === current) return dirs;
		current = parent;
	}
}

function findSourceRoot(): string | undefined {
	const candidates = [process.env.REPI_REPO_ROOT, process.cwd(), dirname(fileURLToPath(import.meta.url))].filter(
		(item): item is string => Boolean(item),
	);
	for (const candidate of candidates) {
		for (const dir of parentDirs(candidate)) {
			if (existsSync(join(dir, "scripts", "reverse-agent", "repi-doctor.mjs"))) return dir;
		}
	}
	return undefined;
}

function findBundledScriptsRoot(): { scriptsDir: string; commandRoot: string } | undefined {
	const currentDir = dirname(fileURLToPath(import.meta.url));
	for (const dir of parentDirs(currentDir)) {
		const bundled = join(dir, "reverse-agent");
		if (existsSync(join(bundled, "repi-doctor.mjs"))) {
			return { scriptsDir: bundled, commandRoot: dirname(dir) };
		}
	}
	return undefined;
}

function commandSpec(command: string, args: string[]): ProductCommandSpec | undefined {
	switch (command) {
		case "health":
		case "status":
			return { script: "repi-health.mjs", normalizeArgs: (rest) => rest };
		case "doctor":
			return { script: "repi-doctor.mjs", normalizeArgs: (rest) => rest };
		case "smoke":
			return { script: "repi-smoke.mjs", normalizeArgs: (rest) => rest };
		case "selfcheck":
		case "dogfood":
			return { script: "repi-selfcheck.mjs", normalizeArgs: (rest) => rest };
		case "bugreport":
			return { script: "repi-bugreport.mjs", normalizeArgs: (rest) => rest };
		case "trust":
			return { script: "trust-inspect.mjs", normalizeArgs: (rest) => rest };
		case "mission":
			return { script: "repi-mission.mjs", normalizeArgs: (rest) => rest };
		case "engage":
		case "attack":
		case "reverse":
		case "web":
			return { script: "repi-engage.mjs", normalizeArgs: (rest) => rest };
		case "memory": {
			const sub = args[0] ?? "status";
			if (sub === "consolidate") return { script: "memory-consolidate.mjs", normalizeArgs: (rest) => rest.slice(1) };
			return { script: "memory-inspect.mjs", normalizeArgs: (rest) => rest };
		}
		case "model":
		case "models":
			return { script: "model-inspect.mjs", normalizeArgs: (rest) => rest };
		case "mcp":
			return { script: "repi-mcp.mjs", normalizeArgs: (rest) => rest };
		case "swarm": {
			const sub = args[0] ?? "help";
			if (sub === "--help" || sub === "-h") {
				return { script: "repi-swarm-llm-run.mjs", normalizeArgs: () => ["--help"] };
			}
			if (sub === "run-llm")
				return { script: "repi-swarm-llm-run.mjs", normalizeArgs: (rest) => ["llm-run", ...rest.slice(1)] };
			return { script: "repi-swarm-llm-run.mjs", normalizeArgs: (rest) => rest };
		}
		default:
			return undefined;
	}
}

function resolveScript(script: string): { scriptPath: string; commandRoot: string } | undefined {
	const sourceRoot = findSourceRoot();
	if (sourceRoot) {
		const sourceScript = join(sourceRoot, "scripts", "reverse-agent", script);
		if (existsSync(sourceScript)) return { scriptPath: sourceScript, commandRoot: sourceRoot };
	}
	const bundled = findBundledScriptsRoot();
	if (bundled) {
		const bundledScript = join(bundled.scriptsDir, script);
		if (existsSync(bundledScript)) return { scriptPath: bundledScript, commandRoot: bundled.commandRoot };
	}
	return undefined;
}

function productCommandHelp(): string {
	return `REPI product command scripts were not found.

This package entrypoint can run built-in REPI commands when the source tree or bundled dist/reverse-agent scripts are present.
If you installed from source, run from the repository or reinstall with:
  npm run install:repi

If you installed from npm/package archive, rebuild/reinstall the package that includes dist/reverse-agent.
`;
}

export function dispatchRepiProductCommand(args: readonly string[]): boolean {
	const command = args[0];
	if (!command || !PRODUCT_COMMANDS.has(command)) return false;

	const rest = args.slice(1);
	const spec = commandSpec(command, rest);
	if (!spec) return false;
	const resolved = resolveScript(spec.script);
	if (!resolved) {
		console.error(productCommandHelp());
		process.exit(2);
	}
	const sourceWrapper = join(resolved.commandRoot, "repi");
	const binPath = existsSync(sourceWrapper) ? sourceWrapper : process.argv[1];
	const child = spawnSync(process.execPath, [resolved.scriptPath, resolved.commandRoot, ...spec.normalizeArgs(rest)], {
		cwd: resolved.commandRoot,
		env: {
			...process.env,
			REPI_BIN_PATH: binPath,
			REPI_PACKAGE_BIN: process.env.REPI_PACKAGE_BIN || "1",
		},
		stdio: "inherit",
	});
	process.exit(child.status ?? (child.signal ? 128 : 1));
}

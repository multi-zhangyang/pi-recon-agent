import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type ProductCommandSpec = {
	script: string;
	normalizeArgs: (args: string[]) => string[];
};

export const REPI_PRODUCT_COMMANDS = new Set([
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
	"model",
	"models",
	"mcp",
	"swarm",
	"bootstrap",
	"commands",
	"uninstall",
]);

export function isRepiProductCommand(command: string | undefined): boolean {
	return Boolean(command && REPI_PRODUCT_COMMANDS.has(command));
}

/**
 * Product commands may be preceded by launcher flags (for example
 * `repi --offline doctor --json`). Keep command discovery in one place so the
 * bootstrapper and dispatcher cannot disagree about which mode is active.
 */
/** Flags whose next token belongs to the flag rather than to product routing. */
export const REPI_VALUE_FLAGS = new Set([
	"--provider",
	"--model",
	"--api-key",
	"--mode",
	"--name",
	"-n",
	"--session",
	"--session-id",
	"--fork",
	"--session-dir",
	"--models",
	"--tools",
	"-t",
	"--exclude-tools",
	"-xt",
	"--system-prompt",
	"--append-system-prompt",
	"--extension",
	"-e",
	"--skill",
	"--prompt-template",
	"--theme",
	"--export",
	"--thinking",
	"--print",
	"-p",
	"--list-models",
]);

/** Flags that are known to be boolean and therefore do not consume a value. */
const REPI_BOOLEAN_FLAGS = new Set([
	"--help",
	"-h",
	"--version",
	"-v",
	"--continue",
	"-c",
	"--resume",
	"-r",
	"--recon",
	"--reverse-pentest",
	"--no-session",
	"--no-tools",
	"-nt",
	"--no-builtin-tools",
	"-nbt",
	"--no-extensions",
	"-ne",
	"--no-skills",
	"-ns",
	"--no-prompt-templates",
	"-np",
	"--no-themes",
	"--no-context-files",
	"-nc",
	"--verbose",
	"--approve",
	"-a",
	"--no-approve",
	"-na",
	"--offline",
	"--project-context",
	"--with-project-resources",
	"--clean-room",
	"--import-pi-auth",
	"--import-pi-profile",
]);

/**
 * Keep product routing in lockstep with parseArgs: unknown long options use a
 * following non-flag token as their value, while known boolean options do not.
 */
export function repiFlagConsumesNextToken(args: readonly string[], index: number): boolean {
	const arg = args[index];
	if (!arg || arg === "--" || arg.includes("=")) return false;
	if (REPI_VALUE_FLAGS.has(arg)) return true;
	if (REPI_BOOLEAN_FLAGS.has(arg)) return false;
	if (!arg.startsWith("--")) return false;
	const next = args[index + 1];
	return next !== undefined && next !== "--" && !next.startsWith("-") && !next.startsWith("@");
}

const LAUNCHER_FLAGS_BEFORE_NESTED_COMMAND = new Set([
	"--offline",
	"--recon",
	"--reverse-pentest",
	"--clean-room",
	"--project-context",
	"--with-project-resources",
	"--import-pi-auth",
	"--import-pi-profile",
]);

const NESTED_PRODUCT_COMMANDS = new Set(["mcp", "model", "models", "swarm"]);

export function findRepiProductCommand(args: readonly string[]): { command: string; index: number } | undefined {
	for (let index = 0; index < args.length; index++) {
		const arg = args[index];
		if (arg === "--") return undefined;
		if (arg.startsWith("@")) continue;
		// Once print mode is present, every following positional token belongs to
		// the prompt; a word such as `doctor` must never be dispatched as a
		// product command.
		if (arg === "--print" || arg === "-p") return undefined;
		if (repiFlagConsumesNextToken(args, index)) {
			index++;
			continue;
		}
		if (arg.startsWith("--") && arg.includes("=")) continue;
		if (arg.startsWith("-")) continue;
		return isRepiProductCommand(arg) ? { command: arg, index } : undefined;
	}
	return undefined;
}

/** Keep a nested product subcommand first even when launcher flags follow the product command. */
export function normalizeRepiProductCommandArgs(command: string, args: readonly string[]): string[] {
	const normalized = [...args];
	if (!NESTED_PRODUCT_COMMANDS.has(command)) return normalized;

	let index = 0;
	while (index < normalized.length) {
		const arg = normalized[index];
		if (arg === "--help" || arg === "-h") break;
		if (LAUNCHER_FLAGS_BEFORE_NESTED_COMMAND.has(arg) || (arg.startsWith("--") && arg.includes("="))) {
			index++;
			continue;
		}
		if (repiFlagConsumesNextToken(normalized, index)) {
			index += 2;
			continue;
		}
		break;
	}

	if (index === 0 || index >= normalized.length) return normalized;
	return [normalized[index], ...normalized.slice(index + 1), ...normalized.slice(0, index)];
}

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
	const explicitRoot = process.env.REPI_REPO_ROOT;
	if (explicitRoot) {
		for (const dir of parentDirs(explicitRoot)) {
			if (existsSync(join(dir, "scripts", "reverse-agent", "repi-doctor.mjs"))) return dir;
		}
	}

	// A source checkout is identified by the module itself living under
	// <repo>/packages/coding-agent. Never infer a source root from cwd: a project
	// directory may contain a same-named scripts tree controlled by the caller.
	const moduleDir = dirname(fileURLToPath(import.meta.url));
	for (const dir of parentDirs(moduleDir)) {
		const packageRoot = join(dir, "packages", "coding-agent");
		const relativeModuleDir = relative(packageRoot, moduleDir);
		if (
			(!relativeModuleDir || (!relativeModuleDir.startsWith("..") && !isAbsolute(relativeModuleDir))) &&
			existsSync(join(dir, "scripts", "reverse-agent", "repi-doctor.mjs"))
		) {
			return dir;
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
		case "model":
		case "models":
			return { script: "model-inspect.mjs", normalizeArgs: (rest) => rest };
		case "mcp":
			return { script: "repi-mcp.mjs", normalizeArgs: (rest) => rest };
		case "bootstrap":
			return { script: "repi-bootstrap.mjs", normalizeArgs: (rest) => rest };
		case "commands":
			return { script: "repi-commands.mjs", normalizeArgs: (rest) => rest };
		case "uninstall":
			// `repi uninstall <source>` remains the package-manager alias for
			// remove. Lifecycle uninstall has no source and uses its own flags.
			if (isRepiPackageUninstallInvocation(args)) return undefined;
			return { script: "repi-uninstall.mjs", normalizeArgs: (rest) => rest };
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

export function isRepiPackageUninstallInvocation(args: readonly string[]): boolean {
	for (let index = 0; index < args.length; index++) {
		const arg = args[index];
		if (arg === "--") return args[index + 1] !== undefined;
		if (arg === "--source") {
			index++;
			continue;
		}
		if (arg.startsWith("--source=")) continue;
		if (
			arg === "-l" ||
			arg === "--local" ||
			arg === "-a" ||
			arg === "--approve" ||
			arg === "-na" ||
			arg === "--no-approve"
		) {
			return true;
		}
		if (!arg.startsWith("-")) return true;
	}
	return false;
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

/** Resolve a product command script for tests and launcher diagnostics. */
export function resolveRepiProductScript(script: string): { scriptPath: string; commandRoot: string } | undefined {
	return resolveScript(script);
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
	const found = findRepiProductCommand(args);
	if (!found) return false;
	const { command } = found;
	// Keep the command-specific positional arguments first (notably `swarm
	// run`), then append launcher flags that appeared before the command.
	const rest = normalizeRepiProductCommandArgs(command, [
		...args.slice(found.index + 1),
		...args.slice(0, found.index),
	]);
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

import { initializeRepiProfile } from "../core/repi-profile-init.ts";

const PACKAGE_COMMANDS = new Set([
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
	"swarm",
	"install",
	"remove",
	"uninstall",
	"update",
	"list",
	"config",
	"provider-doctor",
	"doctor-provider",
]);
const CLEAN_ROOM_FLAGS = [
	"--no-extensions",
	"--no-skills",
	"--no-prompt-templates",
	"--no-approve",
	"--no-context-files",
];

function hasFlag(args: readonly string[], flag: string): boolean {
	return args.some((arg) => arg === flag || arg.startsWith(`${flag}=`));
}

function firstPositional(args: readonly string[]): string | undefined {
	for (let index = 0; index < args.length; index++) {
		const arg = args[index];
		if (arg === "--") return args[index + 1];
		if (!arg.startsWith("-")) return arg;
		if (
			[
				"--provider",
				"--model",
				"--api-key",
				"--mode",
				"--name",
				"--session",
				"--session-id",
				"--fork",
				"--session-dir",
				"--models",
				"--tools",
				"--exclude-tools",
				"--system-prompt",
				"--append-system-prompt",
				"--extension",
				"--skill",
				"--prompt-template",
				"--theme",
				"--export",
				"--thinking",
			].includes(arg)
		) {
			index++;
		}
	}
	return undefined;
}

function stripRepiWrapperFlags(args: readonly string[]): {
	args: string[];
	projectContext: boolean;
	projectResources: boolean;
	cleanRoom: boolean;
} {
	const normalized: string[] = [];
	let projectContext = false;
	let projectResources = false;
	let cleanRoom = false;
	for (const arg of args) {
		if (arg === "--import-pi-auth" || arg === "--import-pi-profile") {
			process.env.REPI_IMPORT_PI_PROFILE = "1";
			continue;
		}
		if (arg === "--project-context") {
			projectContext = true;
			continue;
		}
		if (arg === "--with-project-resources") {
			projectResources = true;
			continue;
		}
		if (arg === "--clean-room") {
			cleanRoom = true;
			continue;
		}
		normalized.push(arg);
	}
	return { args: normalized, projectContext, projectResources, cleanRoom };
}

export function bootstrapRepiCli(args: readonly string[]): string[] {
	process.env.REPI_CODING_AGENT_APP_NAME = process.env.REPI_CODING_AGENT_APP_NAME || "repi";
	process.env.REPI_CODING_AGENT_CONFIG_DIR = process.env.REPI_CODING_AGENT_CONFIG_DIR || ".repi";
	process.env.REPI_PRIMARY = "1";
	process.env.REPI_PRODUCT = "1";
	process.env.REPI_SKIP_VERSION_CHECK = process.env.REPI_SKIP_VERSION_CHECK || "1";
	process.env.REPI_SKIP_PACKAGE_UPDATE_CHECK = process.env.REPI_SKIP_PACKAGE_UPDATE_CHECK || "1";
	process.env.REPI_TELEMETRY = process.env.REPI_TELEMETRY || "0";
	process.env.REPI_OFFLINE = process.env.REPI_OFFLINE || "0";
	process.env.REPI_PRINT_PROGRESS = process.env.REPI_PRINT_PROGRESS || "1";
	process.env.REPI_PRINT_TIMEOUT_MS = process.env.REPI_PRINT_TIMEOUT_MS || "210000";
	process.env.REPI_PRINT_TIMEOUT_GRACE_MS = process.env.REPI_PRINT_TIMEOUT_GRACE_MS || "30000";
	process.env.REPI_PRINT_MAX_TURNS = process.env.REPI_PRINT_MAX_TURNS || "40";
	process.env.REPI_PRINT_MAX_TOOL_CALLS = process.env.REPI_PRINT_MAX_TOOL_CALLS || "80";
	process.env.REPI_STDIN_READ_TIMEOUT_MS = process.env.REPI_STDIN_READ_TIMEOUT_MS || "1500";
	process.env.REPI_BASH_DEFAULT_TIMEOUT_SECONDS = process.env.REPI_BASH_DEFAULT_TIMEOUT_SECONDS || "120";
	process.env.PI_SKIP_VERSION_CHECK = process.env.PI_SKIP_VERSION_CHECK || process.env.REPI_SKIP_VERSION_CHECK;
	process.env.PI_SKIP_PACKAGE_UPDATE_CHECK =
		process.env.PI_SKIP_PACKAGE_UPDATE_CHECK || process.env.REPI_SKIP_PACKAGE_UPDATE_CHECK;
	process.env.PI_TELEMETRY = process.env.PI_TELEMETRY || process.env.REPI_TELEMETRY;
	process.env.PI_OFFLINE = process.env.PI_OFFLINE || process.env.REPI_OFFLINE;

	const stripped = stripRepiWrapperFlags(args);
	initializeRepiProfile();

	const command = firstPositional(stripped.args);
	if (command && PACKAGE_COMMANDS.has(command)) {
		return stripped.args;
	}

	const prefix: string[] = [];
	if (!hasFlag(stripped.args, "--recon") && !hasFlag(stripped.args, "--reverse-pentest")) {
		prefix.push("--recon");
	}

	if (stripped.cleanRoom) {
		for (const flag of CLEAN_ROOM_FLAGS) {
			if (!hasFlag(stripped.args, flag)) prefix.push(flag);
		}
	}

	return [...prefix, ...stripped.args];
}

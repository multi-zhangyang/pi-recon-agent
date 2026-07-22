import { REPI_MODEL_API_ENV_NAMES, REPI_MODEL_BASE_URL_ENV_NAMES } from "../core/repi-env-provider.ts";
import { initializeRepiProfile } from "../core/repi-profile-init.ts";
import { isRepiProductCommand, repiFlagConsumesNextToken } from "./repi-product-commands.ts";

const PACKAGE_COMMANDS = new Set([
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
const REPI_ENV_MODEL_CONFIG_KEYS = [
	...REPI_MODEL_BASE_URL_ENV_NAMES,
	"REPI_MODEL",
	"REPI_MODEL_ID",
	...REPI_MODEL_API_ENV_NAMES,
] as const;
const REPI_MODEL_API_ALIASES = new Set([
	"openai-compatible",
	"openai-chat",
	"chat",
	"chat-completions",
	"openai-completions",
	"response",
	"responses",
	"openai-response",
	"openai-responses",
	"anthropic",
	"claude",
	"anthropic-compatible",
	"anthropic-messages",
]);

function hasFlag(args: readonly string[], flag: string): boolean {
	return args.some((arg) => arg === flag || arg.startsWith(`${flag}=`));
}

function firstPositional(args: readonly string[]): string | undefined {
	for (let index = 0; index < args.length; index++) {
		const arg = args[index];
		if (arg === "--") return args[index + 1];
		if (arg === "--print" || arg === "-p") return undefined;
		if (repiFlagConsumesNextToken(args, index)) {
			index++;
			continue;
		}
		if (!arg.startsWith("-")) return arg;
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

export function missingRepiEnvModelConfig(
	env: Partial<Record<(typeof REPI_ENV_MODEL_CONFIG_KEYS)[number], string | undefined>> = process.env,
): string[] {
	const hasEnvModelConfig = REPI_ENV_MODEL_CONFIG_KEYS.some((key) => Boolean(env[key]));
	if (!hasEnvModelConfig) return [];
	const missing: string[] = [];
	if (!env.REPI_MODEL && !env.REPI_MODEL_ID) missing.push("REPI_MODEL");
	if (!REPI_MODEL_BASE_URL_ENV_NAMES.some((key) => Boolean(env[key]))) missing.push("REPI_BASE_URL");
	return missing;
}

export function invalidRepiEnvModelApi(
	env: Partial<Record<(typeof REPI_MODEL_API_ENV_NAMES)[number], string | undefined>> = process.env,
): string | undefined {
	const raw = REPI_MODEL_API_ENV_NAMES.map((key) => env[key]).find((value) => Boolean(value));
	if (!raw?.trim()) return undefined;
	const normalized = raw.trim().toLowerCase().replace(/_/g, "-");
	return REPI_MODEL_API_ALIASES.has(normalized) ? undefined : raw;
}

function validateRepiEnvModelConfig(): void {
	const missing = missingRepiEnvModelConfig();
	const invalidApi = invalidRepiEnvModelApi();
	if (missing.length === 0 && !invalidApi) return;
	console.error("REPI env model config is incomplete or invalid; refusing to fall back to a saved/default model.");
	for (const key of missing) console.error(`  missing: ${key}`);
	if (invalidApi) {
		console.error(`  invalid: REPI_MODEL_API=${JSON.stringify(invalidApi)}`);
		console.error("  allowed: openai-compatible | openai-responses | anthropic");
	}
	console.error(`
Use a complete, quoted block, for example:
  export REPI_AUTH_TOKEN="sk-xxxxx"
  export REPI_BASE_URL="https://api.example.com/v1"
  export REPI_PROVIDER="gateway"      # optional display/provider id
  export REPI_MODEL="vendor/model-id"
  export REPI_MODEL_API="openai-compatible"

If your prompt is currently just \`>\`, press Ctrl+C first: bash is waiting for an unmatched quote.`);
	process.exit(2);
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
	process.env.REPI_PRINT_TIMEOUT_TOOL_GRACE_MS = process.env.REPI_PRINT_TIMEOUT_TOOL_GRACE_MS || "300000";
	process.env.REPI_PRINT_MAX_TURNS = process.env.REPI_PRINT_MAX_TURNS || "10";
	process.env.REPI_PRINT_MAX_TOOL_CALLS = process.env.REPI_PRINT_MAX_TOOL_CALLS || "48";
	process.env.REPI_STDIN_READ_TIMEOUT_MS = process.env.REPI_STDIN_READ_TIMEOUT_MS || "1500";
	process.env.REPI_BASH_DEFAULT_TIMEOUT_SECONDS = process.env.REPI_BASH_DEFAULT_TIMEOUT_SECONDS || "120";
	process.env.PI_SKIP_VERSION_CHECK = process.env.PI_SKIP_VERSION_CHECK || process.env.REPI_SKIP_VERSION_CHECK;
	process.env.PI_SKIP_PACKAGE_UPDATE_CHECK =
		process.env.PI_SKIP_PACKAGE_UPDATE_CHECK || process.env.REPI_SKIP_PACKAGE_UPDATE_CHECK;
	process.env.PI_TELEMETRY = process.env.PI_TELEMETRY || process.env.REPI_TELEMETRY;
	process.env.PI_OFFLINE = process.env.PI_OFFLINE || process.env.REPI_OFFLINE;
	if (process.env.REPI_ALLOW_BROWSER_COOKIES && !process.env.PI_ALLOW_BROWSER_COOKIES) {
		process.env.PI_ALLOW_BROWSER_COOKIES = process.env.REPI_ALLOW_BROWSER_COOKIES;
	}

	const stripped = stripRepiWrapperFlags(args);
	if (stripped.projectContext) {
		process.env.REPI_CONTEXT_FILES = "1";
	}
	const profile = initializeRepiProfile();
	process.env.REPI_CODING_AGENT_DIR = process.env.REPI_CODING_AGENT_DIR || profile.agentDir;
	process.env.REPI_CODING_AGENT_SESSION_DIR =
		process.env.REPI_CODING_AGENT_SESSION_DIR || `${profile.agentDir}/sessions`;
	process.env.PI_CODING_AGENT_DIR = process.env.PI_CODING_AGENT_DIR || process.env.REPI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_SESSION_DIR =
		process.env.PI_CODING_AGENT_SESSION_DIR || process.env.REPI_CODING_AGENT_SESSION_DIR;

	const command = firstPositional(stripped.args);
	if (command && (PACKAGE_COMMANDS.has(command) || isRepiProductCommand(command))) {
		return stripped.args;
	}

	validateRepiEnvModelConfig();

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

#!/usr/bin/env node
import { bootstrapRepiCli } from "./cli/repi-bootstrap.ts";
import { dispatchRepiProductCommand } from "./cli/repi-product-commands.ts";
/**
 * CLI entry point for the refactored coding agent.
 * Uses main.ts with AgentSession and new mode modules.
 *
 * Test with: npx tsx src/cli-new.ts [args...]
 */
import { APP_NAME, IS_REPI_PRODUCT, VERSION } from "./config.ts";
import { restoreStdout } from "./core/output-guard.ts";

process.title = APP_NAME;
process.env.REPI_CODING_AGENT = "true";
process.env.PI_CODING_AGENT = "true"; // compatibility flag for older extensions
process.emitWarning = (() => {}) as typeof process.emitWarning;

const TOP_LEVEL_VALUE_FLAGS = new Set([
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
]);

function hasTopLevelPositional(args: readonly string[]): boolean {
	for (let index = 0; index < args.length; index++) {
		const arg = args[index];
		if (arg === "--") return args.length > index + 1;
		if (arg === "--list-models") {
			const next = args[index + 1];
			if (next !== undefined && !next.startsWith("-") && !next.startsWith("@")) index++;
			continue;
		}
		if (arg.startsWith("@")) continue;
		if (TOP_LEVEL_VALUE_FLAGS.has(arg)) {
			index++;
			continue;
		}
		if (arg.startsWith("--") && arg.includes("=")) continue;
		if (arg.startsWith("-")) continue;
		return true;
	}
	return false;
}

function isFastMetadataOnlyRequest(args: readonly string[]): boolean {
	for (let index = 0; index < args.length; index++) {
		const arg = args[index];
		if (
			arg === "--offline" ||
			arg === "--recon" ||
			arg === "--reverse-pentest" ||
			arg === "--help" ||
			arg === "-h" ||
			arg === "--version" ||
			arg === "-v"
		)
			continue;
		if (arg === "--list-models") {
			const next = args[index + 1];
			if (next !== undefined && !next.startsWith("-") && !next.startsWith("@")) index++;
			continue;
		}
		return false;
	}
	return true;
}

async function runFastMetadataCommand(cliArgs: string[]): Promise<boolean> {
	if (!IS_REPI_PRODUCT || hasTopLevelPositional(cliArgs)) return false;
	if (
		!cliArgs.some(
			(arg) => arg === "--help" || arg === "-h" || arg === "--version" || arg === "-v" || arg === "--list-models",
		)
	) {
		return false;
	}
	if (!isFastMetadataOnlyRequest(cliArgs)) return false;

	const { parseArgs, printHelp } = await import("./cli/args.ts");
	const parsed = parseArgs(cliArgs);
	if (parsed.version) {
		console.log(VERSION);
		return true;
	}
	if (parsed.help) {
		printHelp();
		return true;
	}
	if (parsed.listModels !== undefined) {
		const [{ listModels }, { AuthStorage }, { ModelRegistry }] = await Promise.all([
			import("./cli/list-models.ts"),
			import("./core/auth-storage.ts"),
			import("./core/model-registry.ts"),
		]);
		const searchPattern = typeof parsed.listModels === "string" ? parsed.listModels : undefined;
		await listModels(ModelRegistry.create(AuthStorage.create()), searchPattern);
		return true;
	}
	return false;
}

async function runCli(): Promise<void> {
	const cliArgs = IS_REPI_PRODUCT ? bootstrapRepiCli(process.argv.slice(2)) : process.argv.slice(2);
	if (IS_REPI_PRODUCT) dispatchRepiProductCommand(cliArgs);
	if (await runFastMetadataCommand(cliArgs)) return;

	// Configure undici's global dispatcher before provider SDKs issue requests.
	// Runtime settings are applied once SettingsManager has loaded global/project settings.
	const { configureHttpDispatcher } = await import("./core/http-dispatcher.ts");
	configureHttpDispatcher();
	const { main } = await import("./main.ts");
	await main(cliArgs);
}

// Foundational opt #268: catch a top-level rejection from main(). main() is
// async and was called with NO .catch() — an awaited rejection inside it
// (e.g. an extension session_start handler rejecting during interactive init,
// or a model-registry / session-manager load failure in headless modes) would
// become an unhandledRejection. There is no global unhandledRejection handler,
// so Node's default would exit(1); in headless modes that's acceptable, but in
// interactive mode the terminal was already taken over (ui.start) and this
// catch runs BEFORE interactive-mode's uncaughtCrash could restore it (the
// interactive unhandledRejection handler at registerSignalHandlers covers the
// in-mode case; this is the entry-point safety net for rejections that escape
// main entirely). Restore stdout (headless takeover) and surface the error to
// stderr before exiting. (interactive-mode.ts owns terminal/raw-mode restore.)
runCli().catch((error: unknown) => {
	try {
		restoreStdout();
	} catch {}
	console.error(
		`${APP_NAME} exiting due to unhandled error:`,
		error instanceof Error ? error : new Error(String(error)),
	);
	process.exit(1);
});

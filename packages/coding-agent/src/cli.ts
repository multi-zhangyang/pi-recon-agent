#!/usr/bin/env node
import { bootstrapRepiCli } from "./cli/repi-bootstrap.ts";
import { dispatchRepiProductCommand } from "./cli/repi-product-commands.ts";
/**
 * CLI entry point for the refactored coding agent.
 * Uses main.ts with AgentSession and new mode modules.
 *
 * Test with: npx tsx src/cli-new.ts [args...]
 */
import { APP_NAME, IS_REPI_PRODUCT } from "./config.ts";
import { configureHttpDispatcher } from "./core/http-dispatcher.ts";
import { restoreStdout } from "./core/output-guard.ts";
import { main } from "./main.ts";

process.title = APP_NAME;
process.env.REPI_CODING_AGENT = "true";
process.env.PI_CODING_AGENT = "true"; // compatibility flag for older extensions
process.emitWarning = (() => {}) as typeof process.emitWarning;

// Configure undici's global dispatcher before provider SDKs issue requests.
// Runtime settings are applied once SettingsManager has loaded global/project settings.
configureHttpDispatcher();

const cliArgs = IS_REPI_PRODUCT ? bootstrapRepiCli(process.argv.slice(2)) : process.argv.slice(2);
if (IS_REPI_PRODUCT) dispatchRepiProductCommand(cliArgs);
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
main(cliArgs).catch((error: unknown) => {
	try {
		restoreStdout();
	} catch {}
	console.error(
		`${APP_NAME} exiting due to unhandled error:`,
		error instanceof Error ? error : new Error(String(error)),
	);
	process.exit(1);
});

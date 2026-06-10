#!/usr/bin/env node
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(process.argv[2] ?? process.cwd());
const repiLauncher = join(root, "repi");
const piShim = join(root, "pi");
const tempRoot = mkdtempSync(join(tmpdir(), "repi-product-"));
const home = join(tempRoot, "home");

function fail(message, detail = {}) {
	console.error(JSON.stringify({ ok: false, message, tempRoot, ...detail }, null, 2));
	process.exit(1);
}

function runRepi(args) {
	return spawnSync(repiLauncher, args, {
		cwd: root,
		env: {
			...process.env,
			HOME: home,
			REPI_OFFLINE: "1",
			REPI_PRODUCT: "1",
			PI_OFFLINE: "1",
			PI_RECON_PRODUCT: "1",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			PI_SKIP_VERSION_CHECK: "1",
			PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			PI_TELEMETRY: "0",
			REPI_CODING_AGENT_DIR: join(home, ".repi", "agent"),
		},
		encoding: "utf8",
		maxBuffer: 20 * 1024 * 1024,
	});
}

try {
	if (!existsSync(repiLauncher)) fail("missing repi launcher", { repiLauncher });
	if (!existsSync(piShim)) fail("missing pi compatibility shim", { piShim });

	const shimText = readFileSync(piShim, "utf8");
	if (!shimText.includes("no longer owns the `pi` command") || shimText.includes("ARGS=(--recon")) {
		fail("repository pi file is not a non-owning compatibility shim", { piShim });
	}

	const help = runRepi(["--offline", "--help"]);
	if (help.status !== 0) fail("repi --offline --help failed", { code: help.status, stderr: help.stderr.slice(-4000) });
	const combinedHelp = `${help.stdout}\n${help.stderr}`;
	if (!combinedHelp.includes("repi - REPI reverse/pentest autonomous agent")) {
		fail("help output did not use repi product app name", { head: combinedHelp.slice(0, 1600) });
	}
	if (!combinedHelp.includes("built-in reverse/pentest kernel is enabled")) {
		fail("repi help does not advertise built-in recon kernel", { head: combinedHelp.slice(0, 1600) });
	}

	const forbiddenHelp = [
		/update \[source\|self\|pi\]/i,
		/Update pi/i,
		/\bpi update/i,
		/Update Available/i,
		/Package Updates Available/i,
		/pi\.dev\/changelog/i,
		/pi\.dev\/api\/latest-version/i,
		/default:\s*https:\/\/pi\.dev\/session/i,
	];
	for (const pattern of forbiddenHelp) {
		if (pattern.test(combinedHelp)) fail("repi help leaked upstream pi update/branding text", { pattern: String(pattern) });
	}

	const updateHelp = runRepi(["update", "--help"]);
	if (updateHelp.status !== 0) {
		fail("repi update --help failed", { code: updateHelp.status, stderr: updateHelp.stderr.slice(-4000), stdout: updateHelp.stdout.slice(-4000) });
	}
	const combinedUpdateHelp = `${updateHelp.stdout}\n${updateHelp.stderr}`;
	if (!combinedUpdateHelp.includes("repi update [source]")) {
		fail("repi update help did not stay in repi command mode", { head: combinedUpdateHelp.slice(0, 1600) });
	}
	for (const pattern of forbiddenHelp) {
		if (pattern.test(combinedUpdateHelp)) fail("repi update help leaked upstream pi update/branding text", { pattern: String(pattern) });
	}

	const models = runRepi(["--offline", "--list-models"]);
	if (models.status !== 0) {
		fail("repi --offline --list-models failed", {
			code: models.status,
			stderr: models.stderr.slice(-4000),
			stdout: models.stdout.slice(-4000),
		});
	}
	const combined = `${combinedHelp}\n${combinedUpdateHelp}\n${models.stdout}\n${models.stderr}`;
	for (const pattern of [/No models match pattern/i, /No API key found/i, /collision:/i, /Global tools\/ directory contains custom tools/i, /Error:/i]) {
		if (pattern.test(combined)) fail("repi emitted stale upstream/profile error", { pattern: String(pattern) });
	}

	const profilePath = join(home, ".repi", "agent", "recon", "profile.json");
	if (!existsSync(profilePath)) fail("REPI profile manifest was not initialized", { profilePath });
	const profile = JSON.parse(readFileSync(profilePath, "utf8"));
	if (profile.agentDir !== join(home, ".repi", "agent")) fail("profile agentDir mismatch", { profile });

	console.log(
		JSON.stringify(
			{
				ok: true,
				product: "repi",
				repiLauncher,
				piCommandOwnership: "not claimed by this repository",
				updatePrompts: "disabled for repi",
				profile: { agentDir: profile.agentDir, legacyPiImportRequested: profile.legacyPiImported?.requested === true },
			},
			null,
			2,
		),
	);
} finally {
	if (process.env.KEEP_REPI_PRODUCT_TMP !== "1") rmSync(tempRoot, { recursive: true, force: true });
}

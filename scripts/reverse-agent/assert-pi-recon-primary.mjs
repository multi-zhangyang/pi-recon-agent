#!/usr/bin/env node
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(process.argv[2] ?? process.cwd());
const launcher = join(root, "pi");
const tempRoot = mkdtempSync(join(tmpdir(), "pi-recon-primary-"));
const home = join(tempRoot, "home");

function run(args) {
	return spawnSync(launcher, args, {
		cwd: root,
		env: {
			...process.env,
			HOME: home,
			PI_OFFLINE: "1",
			PI_RECON_AGENT_DIR: join(home, ".repi", "agent"),
		},
		encoding: "utf8",
		maxBuffer: 20 * 1024 * 1024,
	});
}

function fail(message, detail = {}) {
	console.error(JSON.stringify({ ok: false, message, tempRoot, ...detail }, null, 2));
	process.exit(1);
}

try {
	if (!existsSync(launcher)) fail("missing Pi-RECON pi launcher", { launcher });
	const help = run(["--offline", "--help"]);
	if (help.status !== 0) fail("pi --offline --help failed", { code: help.status, stderr: help.stderr.slice(-4000) });
	const combinedHelp = `${help.stdout}\n${help.stderr}`;
	if (!combinedHelp.includes("Pi-RECON reverse/pentest autonomous agent")) {
		fail("pi help is not the Pi-RECON primary launcher", { head: combinedHelp.slice(0, 1200) });
	}
	if (!combinedHelp.includes("built-in reverse/pentest kernel is enabled")) {
		fail("pi help does not advertise built-in recon kernel", { head: combinedHelp.slice(0, 1200) });
	}
	const models = run(["--offline", "--list-models"]);
	if (models.status !== 0) fail("pi --offline --list-models failed", { code: models.status, stderr: models.stderr.slice(-4000), stdout: models.stdout.slice(-4000) });
	const combined = `${combinedHelp}\n${models.stdout}\n${models.stderr}`;
	for (const pattern of [/No models match pattern/i, /No API key found/i, /collision:/i, /Global tools\/ directory contains custom tools/i, /Error:/i]) {
		if (pattern.test(combined)) fail("pi primary launcher emitted stale upstream/profile error", { pattern: String(pattern) });
	}
	const profilePath = join(home, ".repi", "agent", "recon", "profile.json");
	if (!existsSync(profilePath)) fail("Pi-RECON profile manifest was not initialized", { profilePath });
	const profile = JSON.parse(readFileSync(profilePath, "utf8"));
	if (profile.agentDir !== join(home, ".repi", "agent")) fail("profile agentDir mismatch", { profile });
	console.log(JSON.stringify({ ok: true, launcher, help: "Pi-RECON", listModels: "pass", profile }, null, 2));
} finally {
	if (process.env.KEEP_PI_RECON_PRIMARY_TMP !== "1") rmSync(tempRoot, { recursive: true, force: true });
}

#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : process.cwd());
const json = process.argv.includes("--json");
const strict = process.argv.includes("--strict");
const tempRoot = mkdtempSync(join(tmpdir(), "repi-cli-ux-gate-"));
const agentDir = join(tempRoot, "agent");

function mkdir(path) {
	mkdirSync(path, { recursive: true, mode: 0o700 });
	try {
		chmodSync(path, 0o700);
	} catch {
		// Best-effort on non-POSIX filesystems.
	}
}

function run(args, env = {}) {
	const result = spawnSync(process.execPath, args, {
		cwd: root,
		env: {
			...process.env,
			REPI_CODING_AGENT_DIR: agentDir,
			REPI_AGENT_DIR: agentDir,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			...env,
		},
		encoding: "utf8",
		timeout: 30_000,
		maxBuffer: 4 * 1024 * 1024,
	});
	return {
		exit: result.status ?? 1,
		stdout: result.stdout ?? "",
		stderr: result.stderr ?? "",
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
}

function runRepi(args, env = {}) {
	const result = spawnSync(join(root, "repi"), args, {
		cwd: root,
		env: {
			...process.env,
			REPI_CODING_AGENT_DIR: agentDir,
			REPI_AGENT_DIR: agentDir,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			REPI_PRINT_PROGRESS: "0",
			...env,
		},
		encoding: "utf8",
		timeout: 30_000,
		maxBuffer: 4 * 1024 * 1024,
	});
	return {
		exit: result.status ?? 1,
		stdout: result.stdout ?? "",
		stderr: result.stderr ?? "",
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
}

function check(id, pass, evidence = {}) {
	return { id, status: pass ? "pass" : "fail", evidence };
}

function nonEmptyLineCount(path) {
	try {
		return readFileSync(path, "utf8").split(/\r?\n/).filter((line) => line.trim()).length;
	} catch {
		return 0;
	}
}

function mode(path) {
	try {
		return statSync(path).mode & 0o777;
	} catch {
		return 0;
	}
}

mkdir(agentDir);
mkdir(join(agentDir, "recon", "memory"));
writeFileSync(
	join(agentDir, "models.json"),
	`${JSON.stringify(
		{
			providers: {
				alpha: {
					api: "openai-completions",
					baseUrl: "https://private-alpha.example.invalid/v1",
					apiKey: "$REPI_ALPHA_KEY",
					models: [{ id: "alpha/model", contextWindow: 262144, maxTokens: 8192, cost: { input: 1, output: 2, cacheRead: 0.1, cacheWrite: 0.2 } }],
				},
				beta: {
					api: "anthropic-messages",
					baseUrl: "https://private-beta.example.invalid",
					apiKey: "$REPI_BETA_KEY",
					models: [{ id: "beta/model", contextWindow: 131072, maxTokens: 4096, cost: { input: 3, output: 4, cacheRead: 0, cacheWrite: 0 } }],
				},
			},
		},
		null,
		2,
	)}\n`,
	{ encoding: "utf8", mode: 0o600 },
);

const memoryEventsPath = join(agentDir, "recon", "memory", "events.jsonl");
writeFileSync(
	memoryEventsPath,
	[
			{
				kind: "repi-memory-event",
				id: "mem-alpha",
				ts: "2026-01-01T00:00:00.000Z",
				outcome: "success",
				route: "test",
				target: "alpha",
				commands: ["alpha"],
				lessons: ["alpha lesson baseUrl=https://api.private-alpha.example.invalid/v1"],
			},
		{ kind: "repi-memory-event", id: "mem-beta", ts: "2026-01-02T00:00:00.000Z", outcome: "success", route: "test", target: "beta", commands: ["beta"], lessons: ["beta lesson"] },
	]
		.map((row) => JSON.stringify(row))
		.join("\n") + "\n",
	{ encoding: "utf8", mode: 0o600 },
);

const checks = [];
const reconProfileSource = readFileSync(join(root, "packages", "coding-agent", "src", "core", "recon-profile.ts"), "utf8");
const printModeSource = readFileSync(join(root, "packages", "coding-agent", "src", "modes", "print-mode.ts"), "utf8");
const selfcheckSource = readFileSync(join(root, "scripts", "reverse-agent", "repi-selfcheck.mjs"), "utf8");
const swarmSource = readFileSync(join(root, "scripts", "reverse-agent", "repi-swarm-llm-run.mjs"), "utf8");
const healthSource = readFileSync(join(root, "scripts", "reverse-agent", "repi-health.mjs"), "utf8");
const missionSource = readFileSync(join(root, "scripts", "reverse-agent", "repi-mission.mjs"), "utf8");
const engageSource = readFileSync(join(root, "scripts", "reverse-agent", "repi-engage.mjs"), "utf8");
checks.push(
	check(
		"memory:runtime-redaction-wired",
		reconProfileSource.includes("function redactMemorySensitiveText") &&
			/sanitizeMemoryText[\s\S]{0,240}redactMemorySensitiveText/.test(reconProfileSource) &&
			/writeFileAtomic[\s\S]{0,220}chmodPrivate\(path, 0o600\)/.test(reconProfileSource),
		{ markers: ["redactMemorySensitiveText", "sanitizeMemoryText", "writeFileAtomic chmodPrivate"] },
	),
);
checks.push(
	check(
		"print:json-guard-and-timeout-wired",
		!/function printTimeoutMs[\s\S]{0,160}mode !== "text"/.test(printModeSource) &&
			!/function printMaxTurns[\s\S]{0,160}mode !== "text"/.test(printModeSource) &&
			/if \(event\.type === "turn_start"\)[\s\S]{0,520}if \(mode === "json"\)/.test(printModeSource) &&
			/activeGuardReject\?\.\(new Error/.test(printModeSource),
		{ markers: ["json timeout", "json turn guard", "guard reject"] },
	),
);
const emptyPrint = runRepi(["--provider", "alpha", "--model", "alpha/model", "--offline", "--no-session", "--no-tools", "-p"], {
	REPI_ALPHA_KEY: "sk-test-redacted",
});
checks.push(
	check("print:empty-prompt-fails", emptyPrint.exit !== 0 && /No prompt provided/.test(`${emptyPrint.stdout}\n${emptyPrint.stderr}`), {
		exit: emptyPrint.exit,
		stdoutTail: emptyPrint.stdout.slice(-600),
		stderrTail: emptyPrint.stderr.slice(-600),
	}),
);
checks.push(
	check(
		"swarm:run-requires-structured-merge",
		/mode === "run" && !merge\.finalPromotionReady/.test(swarmSource) && /mergeFailureReason/.test(swarmSource),
		{ markers: ["finalPromotionReady", "mergeFailureReason"] },
	),
);
checks.push(
	check(
		"selfcheck:redaction-and-spawn-error",
		/child\.on\("error"/.test(selfcheckSource) && /PRIVATE KEY/.test(selfcheckSource) && /https\?:\\\/\\\/api/.test(selfcheckSource),
		{ markers: ["child error handler", "broad redaction"] },
	),
);
const healthRun = runRepi(["health", "--json"], { REPI_ALPHA_KEY: "sk-test-redacted" });
let healthReport = {};
try {
	healthReport = JSON.parse(healthRun.stdout);
} catch {
	healthReport = {};
}
checks.push(
	check(
		"health:operator-dashboard",
		healthRun.exit === 0 &&
			healthReport.kind === "repi-health-report" &&
			Number.isFinite(Number(healthReport.score)) &&
			Array.isArray(healthReport.prioritizedActions) &&
			/doctor.*model.*memory.*swarm.*storage/s.test(healthSource) &&
			/mission control state/.test(healthSource) &&
			/active-engagement/.test(healthSource),
		{ exit: healthRun.exit, stdoutTail: healthRun.stdout.slice(-800), stderrTail: healthRun.stderr.slice(-400) },
	),
);
const missionNew = runRepi(["mission", "new", "audit JWT API for IDOR sk-test-redacted", "--target", "https://mission.example.invalid", "--json"]);
let missionNewReport = {};
try {
	missionNewReport = JSON.parse(missionNew.stdout);
} catch {
	missionNewReport = {};
}
const missionPack = runRepi(["mission", "pack", "--json"]);
let missionPackReport = {};
try {
	missionPackReport = JSON.parse(missionPack.stdout);
} catch {
	missionPackReport = {};
}
checks.push(
	check(
		"mission:control-plane",
		missionNew.exit === 0 &&
			missionPack.exit === 0 &&
			missionNewReport.kind === "repi-mission-report" &&
			missionNewReport.mission?.route?.id === "web-api" &&
			!JSON.stringify(missionNewReport).includes("sk-test-redacted") &&
			missionPackReport.contextPack?.memoryPolicy?.scoped === true &&
			existsSync(String(missionPackReport.output?.jsonPath ?? "")) &&
			/forbidden.*unscoped old-memory injection/s.test(missionSource),
		{
			newExit: missionNew.exit,
			packExit: missionPack.exit,
			newTail: missionNew.stdout.slice(-800),
			packTail: missionPack.stdout.slice(-800),
		},
	),
);
const engageTarget = join(tempRoot, "engage-target.txt");
writeFileSync(engageTarget, "REPI engage probe auth token signature route\\n", { encoding: "utf8", mode: 0o600 });
const engageRun = runRepi(["engage", engageTarget, "--json"]);
let engageReport = {};
try {
	engageReport = JSON.parse(engageRun.stdout);
} catch {
	engageReport = {};
}
checks.push(
	check(
		"engage:active-execution",
		engageRun.exit === 0 &&
			engageReport.kind === "repi-active-engagement-report" &&
			engageReport.summary?.commandCount > 0 &&
			existsSync(join(engageReport.artifactDir ?? "", "commands.jsonl")) &&
			existsSync(join(engageReport.artifactDir ?? "", "next-commands.sh")) &&
			/Active Engagement Engine/.test(engageSource) &&
			/engageFile/.test(engageSource),
		{
			exit: engageRun.exit,
			stdoutTail: engageRun.stdout.slice(-800),
			stderrTail: engageRun.stderr.slice(-400),
		},
	),
);
const listFiltered = run(["scripts/reverse-agent/model-inspect.mjs", root, "list", "--provider", "alpha"]);
checks.push(
	check("model:list-provider-filter", listFiltered.exit === 0 && /alpha\/alpha\/model/.test(listFiltered.stdout) && !/beta\/beta\/model/.test(listFiltered.stdout), {
		exit: listFiltered.exit,
		stdoutTail: listFiltered.stdout.slice(-800),
		stderrTail: listFiltered.stderr.slice(-400),
	}),
);
checks.push(
	check("model:list-redacts-base-url-by-default", !/private-alpha\.example\.invalid|private-beta\.example\.invalid/.test(listFiltered.stdout) && /<redacted:url:[a-f0-9]{16}>/.test(listFiltered.stdout), {
		stdoutTail: listFiltered.stdout.slice(-800),
	}),
);
const listShowUrls = run(["scripts/reverse-agent/model-inspect.mjs", root, "list", "--provider", "alpha", "--show-urls"]);
checks.push(
	check("model:list-show-urls-opt-in", listShowUrls.exit === 0 && /private-alpha\.example\.invalid/.test(listShowUrls.stdout) && !/private-beta\.example\.invalid/.test(listShowUrls.stdout), {
		exit: listShowUrls.exit,
		stdoutTail: listShowUrls.stdout.slice(-800),
	}),
);
const doctorRedacted = run(["scripts/reverse-agent/model-inspect.mjs", root, "doctor"]);
checks.push(
	check("model:doctor-redacts-base-url-by-default", doctorRedacted.exit === 0 && !/private-alpha\.example\.invalid|private-beta\.example\.invalid/.test(doctorRedacted.stdout), {
		exit: doctorRedacted.exit,
		stdoutTail: doctorRedacted.stdout.slice(-800),
	}),
);
const insecureLogin = run(["scripts/reverse-agent/model-inspect.mjs", root, "login", "--provider", "alpha", "--api-key", "sk-test-redacted"]);
checks.push(
	check("model:plain-api-key-arg-rejected", insecureLogin.exit !== 0 && /--api-key-stdin/.test(`${insecureLogin.stdout}\n${insecureLogin.stderr}`), {
		exit: insecureLogin.exit,
		stdoutTail: insecureLogin.stdout.slice(-800),
		stderrTail: insecureLogin.stderr.slice(-400),
	}),
);

const memoryListRedacted = run(["scripts/reverse-agent/memory-inspect.mjs", root, "list", "--all"]);
checks.push(
	check("memory:list-redacts-provider-base-url", memoryListRedacted.exit === 0 && !/api\.private-alpha\.example\.invalid/.test(memoryListRedacted.stdout) && /<redacted:url:[a-f0-9]{16}>/.test(memoryListRedacted.stdout), {
		exit: memoryListRedacted.exit,
		stdoutTail: memoryListRedacted.stdout.slice(-800),
	}),
);

const purgeBlocked = run(["scripts/reverse-agent/memory-inspect.mjs", root, "purge", "--apply", "--all"]);
checks.push(
	check("memory:purge-apply-requires-yes", purgeBlocked.exit !== 0 && /requires --yes/.test(`${purgeBlocked.stdout}\n${purgeBlocked.stderr}`) && nonEmptyLineCount(memoryEventsPath) === 2, {
		exit: purgeBlocked.exit,
		lines: nonEmptyLineCount(memoryEventsPath),
		stderrTail: purgeBlocked.stderr.slice(-400),
	}),
);
const purgeConfirmed = run(["scripts/reverse-agent/memory-inspect.mjs", root, "purge", "--apply", "--yes", "--id", "mem-alpha"]);
checks.push(
	check("memory:purge-confirmed-removes-selected-only", purgeConfirmed.exit === 0 && /removed=1/.test(purgeConfirmed.stdout) && nonEmptyLineCount(memoryEventsPath) === 1 && readFileSync(memoryEventsPath, "utf8").includes("mem-beta"), {
		exit: purgeConfirmed.exit,
		lines: nonEmptyLineCount(memoryEventsPath),
		stdoutTail: purgeConfirmed.stdout.slice(-800),
	}),
);
writeFileSync(memoryEventsPath, `${readFileSync(memoryEventsPath, "utf8")}not-json sk-test-redacted\n`, { encoding: "utf8", mode: 0o600 });
const repairBlocked = run(["scripts/reverse-agent/memory-inspect.mjs", root, "repair", "--apply"]);
checks.push(
	check("memory:repair-apply-requires-yes", repairBlocked.exit !== 0 && /requires --yes/.test(`${repairBlocked.stdout}\n${repairBlocked.stderr}`) && nonEmptyLineCount(memoryEventsPath) === 2, {
		exit: repairBlocked.exit,
		lines: nonEmptyLineCount(memoryEventsPath),
		stderrTail: repairBlocked.stderr.slice(-400),
	}),
);
const repairConfirmed = run(["scripts/reverse-agent/memory-inspect.mjs", root, "repair", "--apply", "--yes", "--json"]);
let repairReport = {};
try {
	repairReport = JSON.parse(repairConfirmed.stdout);
} catch {
	repairReport = {};
}
checks.push(
	check(
		"memory:repair-quarantines-invalid-lines",
		repairConfirmed.exit === 0 &&
			repairReport.invalidLines === 1 &&
			nonEmptyLineCount(memoryEventsPath) === 1 &&
			readFileSync(memoryEventsPath, "utf8").includes("mem-beta") &&
			existsSync(String(repairReport.quarantinePath ?? "")) &&
			!readFileSync(String(repairReport.quarantinePath ?? ""), "utf8").includes("sk-test-redacted"),
		{
			exit: repairConfirmed.exit,
			lines: nonEmptyLineCount(memoryEventsPath),
			stdoutTail: repairConfirmed.stdout.slice(-800),
		},
	),
);

const initAgentDir = join(tempRoot, "profile-agent");
const initRun = run(["scripts/reverse-agent/init-repi-profile.mjs", root], { REPI_CODING_AGENT_DIR: initAgentDir, REPI_AGENT_DIR: initAgentDir });
checks.push(
	check("profile:init-private-directories", initRun.exit === 0 && existsSync(join(initAgentDir, "sessions")) && mode(initAgentDir) === 0o700 && mode(join(initAgentDir, "recon", "memory")) === 0o700 && mode(join(initAgentDir, "recon", "memory", "events.jsonl")) === 0o600, {
		exit: initRun.exit,
		agentDirMode: `0${mode(initAgentDir).toString(8)}`,
		memoryDirMode: `0${mode(join(initAgentDir, "recon", "memory")).toString(8)}`,
		eventsMode: `0${mode(join(initAgentDir, "recon", "memory", "events.jsonl")).toString(8)}`,
	}),
);

const trustRun = run(["scripts/reverse-agent/trust-inspect.mjs", root, "yes", root]);
checks.push(
	check("trust:file-private-mode", trustRun.exit === 0 && mode(join(agentDir, "trust.json")) === 0o600, {
		exit: trustRun.exit,
		trustMode: `0${mode(join(agentDir, "trust.json")).toString(8)}`,
	}),
);

const report = {
	kind: "repi-cli-ux-gate-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	root,
	ok: checks.every((item) => item.status === "pass"),
	checks,
	tempRoot: process.env.KEEP_REPI_CLI_UX_GATE_TMP === "1" ? tempRoot : undefined,
};

if (process.env.KEEP_REPI_CLI_UX_GATE_TMP !== "1") rmSync(tempRoot, { recursive: true, force: true });

if (json) {
	console.log(JSON.stringify(report, null, 2));
} else {
	console.log("REPI CLI UX Gate");
	for (const item of checks) console.log(`${item.status === "pass" ? "PASS" : "FAIL"} ${item.id}`);
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
}

process.exit(report.ok || !strict ? 0 : 1);

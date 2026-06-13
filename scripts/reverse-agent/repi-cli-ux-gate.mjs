#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
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

function run(args, env = {}, input = undefined) {
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
		input,
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

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function sealMemoryEvent(row, index, prevHash) {
	const event = {
		kind: "repi-memory-event",
		schemaVersion: 1,
		source: "gate",
		task: row.task ?? `gate memory ${row.id}`,
		domainTags: ["gate"],
		caseSignature: row.caseSignature ?? row.id,
		failurePatterns: [],
		reuseRules: [],
		artifactHashes: [],
		quality: { confidence: 0.7, replayVerified: false, reuseCount: 0, failureCount: 0, lastUsefulAt: row.ts, decay: 0 },
		...row,
		seq: index + 1,
		prevHash,
		entryHash: "",
	};
	const { entryHash: _entryHash, ...withoutHash } = event;
	event.entryHash = sha256(JSON.stringify(withoutHash));
	return event;
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
				cfdup: {
					api: "openai-completions",
					baseUrl: "https://api.cloudflare.com/client/v4/accounts/example/ai/v1",
					apiKey: "$REPI_CFDUP_KEY",
					models: [
						{ id: "@cf/moonshotai/kimi-@cf/moonshotai/kimi-k2.7-code", contextWindow: 262144, maxTokens: 8192, cost: { input: 0.95, output: 4, cacheRead: 0.19, cacheWrite: 0 } },
					],
				},
			},
		},
		null,
		2,
	)}\n`,
	{ encoding: "utf8", mode: 0o600 },
);

const memoryEventsPath = join(agentDir, "recon", "memory", "events.jsonl");
const fixtureMemorySeed = [
	{
		id: "mem-alpha",
		ts: "2026-01-01T00:00:00.000Z",
		outcome: "success",
		route: "test",
		target: "alpha",
		commands: ["alpha"],
		lessons: ["alpha lesson baseUrl=https://api.private-alpha.example.invalid/v1"],
	},
	{ id: "mem-beta", ts: "2026-01-02T00:00:00.000Z", outcome: "success", route: "test", target: "beta", commands: ["beta"], lessons: ["beta lesson"] },
];
const fixtureMemoryEvents = [];
let fixturePrevHash = "0".repeat(64);
for (const [index, row] of fixtureMemorySeed.entries()) {
	const event = sealMemoryEvent(row, index, fixturePrevHash);
	fixtureMemoryEvents.push(event);
	fixturePrevHash = event.entryHash;
}
writeFileSync(
	memoryEventsPath,
	fixtureMemoryEvents.map((row) => JSON.stringify(row)).join("\n") + "\n",
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
		"compact:sane-threshold-and-safe-autoresume",
		/Number\.isFinite\(contextTokens\)[\s\S]{0,240}contextTokens <= 0/.test(
			readFileSync(join(root, "packages", "coding-agent", "src", "core", "compaction", "compaction.ts"), "utf8"),
		) &&
			/reserveTokens > 0 && reserveTokens < contextWindow/.test(
				readFileSync(join(root, "packages", "coding-agent", "src", "core", "compaction", "compaction.ts"), "utf8"),
			) &&
			/pi-recon-auto-resume[\s\S]{0,700}deliverAs:\s*"steer"[\s\S]{0,120}triggerTurn:\s*true/.test(reconProfileSource) &&
			/_continueQueuedMessages[\s\S]{0,260}agent\.continue/.test(
				readFileSync(join(root, "packages", "coding-agent", "src", "core", "agent-session.ts"), "utf8"),
			) &&
			/hasSummarizableHistory/.test(readFileSync(join(root, "packages", "coding-agent", "src", "core", "agent-session.ts"), "utf8")) &&
			/noBody400[\s\S]{0,260}provider === "cerebras"/.test(
				readFileSync(join(root, "packages", "ai", "src", "utils", "overflow.ts"), "utf8"),
			),
		{ markers: ["no tiny compact", "reserve below context", "queued auto-resume trigger", "generic 400 no-body not overflow"] },
	),
);
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
const legacyAgentDir = join(tempRoot, "legacy-agent");
const legacyBinDir = join(tempRoot, "legacy-bin");
mkdir(legacyAgentDir);
mkdir(legacyBinDir);
const legacyEnv = {
	REPI_CODING_AGENT_DIR: legacyAgentDir,
	REPI_AGENT_DIR: legacyAgentDir,
	REPI_BIN_PATH: join(root, "repi"),
	REPI_INSTALLED_BIN_PATH: join(legacyBinDir, "repi"),
	REPI_LEGACY_KEY: "sk-test-redacted",
};
const legacyInit = run(["scripts/reverse-agent/init-repi-profile.mjs", root], legacyEnv);
writeFileSync(
	join(legacyAgentDir, "models.json"),
	`${JSON.stringify(
		{
			providers: {
				legacy: {
					api: "openai-completions",
					baseUrl: "https://legacy.example.invalid/v1",
					apiKey: "$REPI_LEGACY_KEY",
					models: [{ id: "legacy/model", contextWindow: 8192, maxTokens: 1024 }],
				},
			},
		},
		null,
		2,
	)}\n`,
	{ encoding: "utf8", mode: 0o600 },
);
mkdir(join(legacyAgentDir, "tools"));
mkdir(join(legacyAgentDir, "hooks"));
mkdir(join(legacyAgentDir, "extensions"));
mkdir(join(legacyAgentDir, "skills", "reverse-pentest-orchestrator"));
writeFileSync(join(legacyAgentDir, "tools", "legacy-tool.md"), "# legacy tool\n", { encoding: "utf8", mode: 0o600 });
writeFileSync(join(legacyAgentDir, "hooks", "legacy-hook.ts"), "export default {};\n", { encoding: "utf8", mode: 0o600 });
writeFileSync(join(legacyAgentDir, "extensions", "reverse-pentest-core.ts"), "// REPI reverse-pentest legacy extension\nexport default {};\n", { encoding: "utf8", mode: 0o600 });
writeFileSync(join(legacyAgentDir, "skills", "reverse-pentest-orchestrator", "SKILL.md"), "# Reverse Pentest legacy skill\n", { encoding: "utf8", mode: 0o600 });
const legacyDoctor = run(["scripts/reverse-agent/repi-doctor.mjs", root, "--fix", "--json"], legacyEnv);
let legacyDoctorReport = {};
try {
	legacyDoctorReport = JSON.parse(legacyDoctor.stdout);
} catch {
	legacyDoctorReport = {};
}
const legacyExtensionEntries = existsSync(join(legacyAgentDir, "extensions")) ? readdirSync(join(legacyAgentDir, "extensions")) : [];
const legacyArchiveRoot = join(legacyAgentDir, "recon", "archive");
const legacyArchiveEntries = existsSync(legacyArchiveRoot) ? readdirSync(legacyArchiveRoot) : [];
checks.push(
	check(
		"doctor:legacy-tools-hooks-fix",
		legacyInit.exit === 0 &&
			legacyDoctor.exit === 0 &&
			legacyDoctorReport.fixActions?.some((action) => action.id === "legacy-extension-layout" && action.exit === 0) &&
			legacyDoctorReport.checks?.some((item) => item.id === "runtime:legacy-extension-layout" && item.status === "pass") &&
			legacyExtensionEntries.some((name) => name.startsWith("legacy-tools-")) &&
			legacyExtensionEntries.some((name) => name.startsWith("legacy-hooks-")) &&
			legacyArchiveEntries.some((name) => name.startsWith("legacy-file-profile-")) &&
			!existsSync(join(legacyAgentDir, "tools", "legacy-tool.md")) &&
			!existsSync(join(legacyAgentDir, "hooks")) &&
			!existsSync(join(legacyAgentDir, "extensions", "reverse-pentest-core.ts")) &&
			!existsSync(join(legacyAgentDir, "skills", "reverse-pentest-orchestrator")),
		{
			initExit: legacyInit.exit,
			doctorExit: legacyDoctor.exit,
			stdoutTail: legacyDoctor.stdout.slice(-800),
			stderrTail: legacyDoctor.stderr.slice(-400),
			legacyExtensionEntries,
			legacyArchiveEntries,
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
checks.push(
	check(
		"model:doctor-flags-cloudflare-duplicate-prefix",
		doctorRedacted.exit === 0 && /repeated "@cf\/" prefix/.test(doctorRedacted.stdout) && /kimi-k2\.7-code/.test(doctorRedacted.stdout),
		{ stdoutTail: doctorRedacted.stdout.slice(-1200) },
	),
);
const insecureLogin = run(["scripts/reverse-agent/model-inspect.mjs", root, "login", "--provider", "alpha", "--api-key", "sk-test-redacted"]);
checks.push(
	check("model:plain-api-key-arg-rejected", insecureLogin.exit !== 0 && /--api-key-stdin/.test(`${insecureLogin.stdout}\n${insecureLogin.stderr}`), {
		exit: insecureLogin.exit,
		stdoutTail: insecureLogin.stdout.slice(-800),
		stderrTail: insecureLogin.stderr.slice(-400),
	}),
);
const addLocalAuth = run(
	[
		"scripts/reverse-agent/model-inspect.mjs",
		root,
		"add",
		"--provider",
		"gamma",
		"--api",
		"openai-completions",
		"--base-url",
		"https://private-gamma.example.invalid/v1",
		"--model",
		"gamma/model",
		"--api-key-stdin",
		"--set-default",
		"--json",
	],
	{},
	"fixture-gamma-key",
);
const addLocalAuthReport = (() => {
	try {
		return JSON.parse(addLocalAuth.stdout);
	} catch {
		return undefined;
	}
})();
const authAfterAdd = (() => {
	try {
		return JSON.parse(readFileSync(join(agentDir, "auth.json"), "utf8"));
	} catch {
		return {};
	}
})();
const settingsAfterAdd = (() => {
	try {
		return JSON.parse(readFileSync(join(agentDir, "settings.json"), "utf8"));
	} catch {
		return {};
	}
})();
checks.push(
	check(
		"model:add-api-key-stdin-local-auth",
		addLocalAuth.exit === 0 && addLocalAuthReport?.authWritten === true && authAfterAdd.gamma?.key === "fixture-gamma-key" && !/export REPI_GAMMA_API_KEY/.test(addLocalAuth.stdout),
		{
			exit: addLocalAuth.exit,
			stdoutTail: addLocalAuth.stdout.slice(-1000),
			stderrTail: addLocalAuth.stderr.slice(-400),
		},
	),
);
checks.push(
	check("model:add-set-default-validates-runtime-default", settingsAfterAdd.defaultProvider === "gamma" && settingsAfterAdd.defaultModel === "gamma/model", {
		settingsAfterAdd: { defaultProvider: settingsAfterAdd.defaultProvider, defaultModel: settingsAfterAdd.defaultModel },
	}),
);
const invalidDefault = run(["scripts/reverse-agent/model-inspect.mjs", root, "default", "--provider", "gamma", "--model", "missing/model", "--json"]);
checks.push(
	check("model:default-rejects-missing-custom-model", invalidDefault.exit !== 0 && /model not found under provider gamma/.test(`${invalidDefault.stdout}\n${invalidDefault.stderr}`), {
		exit: invalidDefault.exit,
		stdoutTail: invalidDefault.stdout.slice(-800),
		stderrTail: invalidDefault.stderr.slice(-400),
	}),
);

const memoryListRedacted = run(["scripts/reverse-agent/memory-inspect.mjs", root, "list", "--all", "--verbose"]);
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
const explicitTrustTarget = join(tempRoot, "explicit-trust-target");
const explicitTrustAgentDir = join(tempRoot, "explicit-trust-agent");
mkdir(explicitTrustTarget);
writeFileSync(join(explicitTrustTarget, "AGENTS.md"), "explicit trust fixture\n", { encoding: "utf8", mode: 0o600 });
const explicitTrustRun = run(["scripts/reverse-agent/trust-inspect.mjs", root, "yes", explicitTrustTarget, "--json"], { REPI_CODING_AGENT_DIR: explicitTrustAgentDir, REPI_AGENT_DIR: explicitTrustAgentDir });
const explicitTrustStore = (() => {
	try {
		return JSON.parse(readFileSync(join(explicitTrustAgentDir, "trust.json"), "utf8"));
	} catch {
		return {};
	}
})();
checks.push(
	check("trust:explicit-target-does-not-alias-cwd", explicitTrustRun.exit === 0 && explicitTrustStore[explicitTrustTarget] === true && explicitTrustStore[root] !== true, {
		exit: explicitTrustRun.exit,
		explicitTargetTrusted: explicitTrustStore[explicitTrustTarget] === true,
		cwdTrusted: explicitTrustStore[root] === true,
		stdoutTail: explicitTrustRun.stdout.slice(-800),
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

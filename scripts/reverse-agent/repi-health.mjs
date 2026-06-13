#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const rootArg = args[0] && !args[0].startsWith("--") ? args.shift() : undefined;
const root = resolve(rootArg ?? process.cwd());
const json = args.includes("--json");
const fix = args.includes("--fix");
const selfcheck = args.includes("--selfcheck") || args.includes("--deep");
const deep = args.includes("--deep");
const includeEvidence = args.includes("--include-evidence") || args.includes("--deep-sanitize");
const includeSessions = args.includes("--include-sessions") || args.includes("--deep-sanitize");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const localScriptsDir = dirname(fileURLToPath(import.meta.url));

function usage() {
	return `Usage:
  repi health [--json] [--fix] [--selfcheck|--deep] [--include-evidence] [--include-sessions]

Health is the operator dashboard for release/open-source readiness:
- aggregates doctor/model/memory/swarm/storage state
- includes task-level mission control state and next operator actions
- shows one prioritized action list instead of scattered command output
- --fix applies safe local repairs: profile init, memory repair, memory sanitize (no raw backup)
- --deep additionally runs selfcheck and deep sanitize scopes
`;
}

if (args.includes("--help") || args.includes("-h")) {
	console.log(usage());
	process.exit(0);
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\b(?:A3T|AKIA|ASIA)[A-Z0-9]{16}\b/g, "<redacted:aws-access-key>")
		.replace(/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "<redacted:slack-token>")
		.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "<redacted:jwt>")
		.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "<redacted:private-key>")
		.replace(/(?:AUTH_TOKEN|API_KEY|PASSWORD|SECRET|TOKEN|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CLIENT_SECRET)=\S+/gi, (match) => `${match.split("=")[0]}=<redacted>`)
		.replace(/(authorization|x-api-key|api-key)\s*[:=]\s*bearer\s+[A-Za-z0-9._-]+/gi, "$1: Bearer <redacted>")
		.replace(/(authorization|x-api-key|api-key)\s*[:=]\s*[A-Za-z0-9._-]{12,}/gi, "$1: <redacted>")
		.replace(/(baseUrl|baseURL|endpoint|url)\s*[:=]\s*https?:\/\/[^\s"',}]+/gi, "$1=<redacted:url>")
		.replace(/\bhttps?:\/\/api\.[^\s"',}<)]+/gi, "<redacted:url>");
}

function resolveScript(script) {
	const sourcePath = join(root, script);
	if (existsSync(sourcePath)) return sourcePath;
	const bundledPath = join(localScriptsDir, basename(script));
	if (existsSync(bundledPath)) return bundledPath;
	return sourcePath;
}

function runNode(script, stepArgs = [], options = {}) {
	const result = spawnSync(process.execPath, [resolveScript(script), root, ...stepArgs], {
		cwd: root,
		env: {
			...process.env,
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
			REPI_PRINT_PROGRESS: "0",
		},
		encoding: "utf8",
		timeout: options.timeout ?? 60_000,
		maxBuffer: 16 * 1024 * 1024,
	});
	const stdout = redact(result.stdout ?? "");
	const stderr = redact(result.stderr ?? "");
	let parsed = undefined;
	try {
		parsed = JSON.parse(stdout);
	} catch {
		// Human output or failed JSON command.
	}
	return {
		code: result.status ?? 1,
		stdoutTail: stdout.slice(-4000),
		stderrTail: stderr.slice(-4000),
		error: result.error ? redact(String(result.error.message || result.error)) : undefined,
		parsed,
	};
}

function directorySize(path, limitFiles = 20000) {
	let bytes = 0;
	let files = 0;
	const stack = [path];
	while (stack.length && files < limitFiles) {
		const current = stack.pop();
		if (!current || !existsSync(current)) continue;
		let entries = [];
		try {
			entries = readdirSync(current, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const entry of entries) {
			const child = join(current, entry.name);
			try {
				if (entry.isDirectory()) stack.push(child);
				else if (entry.isFile()) {
					bytes += statSync(child).size;
					files += 1;
				}
			} catch {
				// Ignore transient files.
			}
		}
	}
	return { bytes, mb: Math.round(bytes / 1024 / 1024), files, truncated: files >= limitFiles };
}

function readJsonFile(path) {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return undefined;
	}
}

function item(id, status, summary, evidence = {}, next = []) {
	return { id, status, summary, evidence, next };
}

function scoreItems(items) {
	let score = 100;
	for (const entry of items) {
		if (entry.status === "fail") score -= 25;
		else if (entry.status === "warn") score -= 8;
	}
	return Math.max(0, score);
}

function statusRank(status) {
	return status === "fail" ? 0 : status === "warn" ? 1 : status === "skip" ? 2 : 3;
}

function shortHash(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex").slice(0, 16);
}

const fixActions = [];
if (fix) {
	fixActions.push({ id: "doctor-fix", ...runNode("scripts/reverse-agent/repi-doctor.mjs", ["--fix", "--json"], { timeout: 90_000 }) });
	fixActions.push({ id: "memory-repair", ...runNode("scripts/reverse-agent/memory-inspect.mjs", ["repair", "--apply", "--yes", "--json"], { timeout: 60_000 }) });
	const sanitizeArgs = ["sanitize", "--apply", "--yes", "--json"];
	if (includeEvidence) sanitizeArgs.push("--include-evidence");
	if (includeSessions) sanitizeArgs.push("--include-sessions");
	fixActions.push({ id: "memory-sanitize", ...runNode("scripts/reverse-agent/memory-inspect.mjs", sanitizeArgs, { timeout: 120_000 }) });
}

const doctor = runNode("scripts/reverse-agent/repi-doctor.mjs", ["--json"], { timeout: 60_000 });
const modelDoctor = runNode("scripts/reverse-agent/model-inspect.mjs", ["doctor", "--json"], { timeout: 60_000 });
const memoryDoctor = runNode("scripts/reverse-agent/memory-inspect.mjs", ["doctor", "--json"], { timeout: 60_000 });
const memoryStatus = runNode("scripts/reverse-agent/memory-inspect.mjs", ["status", "--json"], { timeout: 60_000 });
const sanitizeDryArgs = ["sanitize", "--dry-run", "--json"];
if (includeEvidence) sanitizeDryArgs.push("--include-evidence");
if (includeSessions) sanitizeDryArgs.push("--include-sessions");
const memorySanitize = runNode("scripts/reverse-agent/memory-inspect.mjs", sanitizeDryArgs, { timeout: 120_000 });
const missionStatus = runNode("scripts/reverse-agent/repi-mission.mjs", ["status", "--json"], { timeout: 30_000 });
const swarmStatus = runNode("scripts/reverse-agent/repi-swarm-llm-run.mjs", ["status", "latest", "--json"], { timeout: 45_000 });
const latestEngagement = readJsonFile(join(agentDir, "recon", "evidence", "engagements", "latest.json"));
const selfcheckReport = selfcheck
	? runNode(
		"scripts/reverse-agent/repi-selfcheck.mjs",
		[...(deep ? ["--deep"] : []), "--json"],
		{ timeout: deep ? 300_000 : 180_000 },
	)
	: undefined;

const items = [];
items.push(
	item(
		"core-doctor",
		doctor.parsed?.ok ? "pass" : "fail",
		doctor.parsed?.ok ? "core installation/runtime checks pass" : "core doctor failed",
		{ failed: doctor.parsed?.checks?.filter((row) => row.status !== "pass").map((row) => row.id) ?? [], exit: doctor.code },
		["repi doctor --fix"],
	),
);

const modelWarns = modelDoctor.parsed?.diagnostics?.filter((row) => row.level !== "info") ?? [];
const inactiveProviders = modelDoctor.parsed?.providers?.filter((row) => row.authConfigured === false) ?? [];
items.push(
	item(
		"model-control-plane",
		modelDoctor.parsed?.ok ? (modelWarns.length || inactiveProviders.length ? "warn" : "pass") : "fail",
		modelDoctor.parsed?.ok ? `models=${modelDoctor.parsed.modelCount ?? 0}, inactiveProviders=${inactiveProviders.length}` : "model doctor failed",
		{ diagnostics: modelWarns.map((row) => row.id), inactiveProviders: inactiveProviders.map((row) => row.provider).slice(0, 12), exit: modelDoctor.code },
		["repi model list", "repi model doctor", "repi model login --provider <id> --api-key-stdin"],
	),
);

const memDiagnostics = memoryDoctor.parsed?.diagnostics ?? [];
const blockingMemDiagnostics = memDiagnostics.filter((row) => row.level === "fail" && row.id !== "memory-secret-scan");
items.push(
	item(
		"memory-governance",
		blockingMemDiagnostics.length > 0 ? "fail" : memDiagnostics.length > 0 ? "warn" : "pass",
		blockingMemDiagnostics.length > 0
			? "memory doctor has blocking diagnostics"
			: memDiagnostics.length > 0
				? "memory doctor has fixable hygiene diagnostics"
				: "memory doctor clean",
		{ diagnostics: memDiagnostics.map((row) => `${row.level}:${row.id}`), invalidLines: memoryDoctor.parsed?.status?.eventStore?.invalidLines ?? null, exit: memoryDoctor.code },
		["repi memory doctor", "repi memory repair --apply --yes", "repi memory sanitize --dry-run"],
	),
);

const changedSanitize = Number(memorySanitize.parsed?.changedFiles ?? 0);
items.push(
	item(
		"memory-secret-hygiene",
		changedSanitize > 0 ? "warn" : "pass",
		changedSanitize > 0 ? `${changedSanitize} local memory/evidence files would be sanitized` : "no local memory redaction drift detected",
		{ changedFiles: changedSanitize, scannedFiles: memorySanitize.parsed?.scannedFiles ?? null, scopes: { includeEvidence, includeSessions } },
		[includeEvidence || includeSessions ? "repi memory sanitize --apply --yes --include-evidence --include-sessions" : "repi memory sanitize --apply --yes"],
	),
);

const reconSize = directorySize(join(agentDir, "recon"));
const sessionSize = directorySize(join(agentDir, "sessions"));
const storageWarn = reconSize.mb > 500 || sessionSize.mb > 500;
items.push(
	item(
		"local-storage",
		storageWarn ? "warn" : "pass",
		`recon=${reconSize.mb}MB sessions=${sessionSize.mb}MB`,
		{ recon: reconSize, sessions: sessionSize },
		["repi memory purge --dry-run --older-than-days 30", "repi memory export --output /tmp/repi-memory.json"],
	),
);

if (missionStatus.code !== 0) {
	items.push(item("mission-control", "fail", "mission control command failed", { exit: missionStatus.code, stderrTail: missionStatus.stderrTail }, ["repi mission status", "repi mission new <task>"]));
} else if (missionStatus.parsed?.ok && missionStatus.parsed?.mission?.status === "active") {
	items.push(
		item(
			"mission-control",
			"pass",
			`active mission route=${missionStatus.parsed.mission.route?.domain ?? "unknown"}`,
			{
				id: missionStatus.parsed.mission.id,
				taskHash: missionStatus.parsed.mission.task ? shortHash(missionStatus.parsed.mission.task) : null,
				nextActions: missionStatus.parsed.mission.nextActions?.slice(0, 3) ?? [],
			},
			["repi mission status", "repi mission pack"],
		),
	);
} else {
	items.push(item("mission-control", "skip", "no active mission; create one to bind work to a scoped plan", { missionPath: missionStatus.parsed?.missionPath ?? null }, ["repi mission new <task>", "repi mission plan <task>"]));
}

if (latestEngagement?.kind || latestEngagement?.runId) {
	const quality = latestEngagement.summary?.evidenceQuality ?? "unknown";
	const missing = latestEngagement.summary?.missingCritical ?? [];
	items.push(
		item(
			"active-engagement",
			quality === "weak" || missing.length ? "warn" : "pass",
			`latest engagement lane=${latestEngagement.target?.lane ?? "unknown"} quality=${quality}`,
			{
				runId: latestEngagement.runId,
				artifactDir: latestEngagement.artifactDir,
				target: latestEngagement.target?.redacted ?? null,
				missingCritical: missing,
			},
			["repi engage <target>", "cat ~/.repi/agent/recon/evidence/engagements/latest.json", "repi mission pack"],
		),
	);
} else {
	items.push(item("active-engagement", "skip", "no active engagement run yet", {}, ["repi engage <target>"]));
}

if (swarmStatus.parsed?.ok) {
	const narrativeOnly = swarmStatus.parsed?.merge?.narrativeOnlyBlocked === true;
	const failedWorkers = swarmStatus.parsed?.workers?.filter((row) => row.status !== "pass") ?? [];
	const plannedOnly = swarmStatus.parsed?.state === "planned";
	items.push(
		item(
			"swarm-latest",
			plannedOnly ? "skip" : failedWorkers.length || narrativeOnly ? "warn" : "pass",
			`latest swarm state=${swarmStatus.parsed.state}; workers=${swarmStatus.parsed.workers?.length ?? 0}; narrativeOnly=${Boolean(narrativeOnly)}`,
			{ runId: swarmStatus.parsed.runId, failedWorkers, merge: swarmStatus.parsed.merge ?? null },
			["repi swarm status latest", "repi swarm merge latest", "repi swarm run <target> --workers 5"],
		),
	);
} else {
	items.push(item("swarm-latest", "skip", "no completed swarm run found yet", { exit: swarmStatus.code }, ["repi swarm run <target> --workers 3"]));
}

if (selfcheckReport) {
	const failedRows = selfcheckReport.parsed?.rows?.filter((row) => !row.ok) ?? [];
	items.push(
		item(
			"live-selfcheck",
			selfcheckReport.parsed?.ok ? "pass" : "fail",
			selfcheckReport.parsed?.ok ? "model/tool/memory/parallel selfcheck pass" : `${failedRows.length} selfcheck rows failed`,
			{ failedRows: failedRows.map((row) => row.id), exit: selfcheckReport.code, deep },
			["repi selfcheck --provider <id> --model <model>", "repi selfcheck --deep --provider <id> --model <model>"],
		),
	);
} else {
	items.push(item("live-selfcheck", "skip", "not run by default; add --selfcheck or --deep", {}, ["repi health --selfcheck --provider <id> --model <model>"]));
}

const sortedActions = items
	.filter((entry) => entry.status === "fail" || entry.status === "warn")
	.sort((left, right) => statusRank(left.status) - statusRank(right.status))
	.flatMap((entry) => entry.next.map((command) => ({ source: entry.id, command })))
	.slice(0, 12);

const report = {
	kind: "repi-health-report",
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	root,
	agentDir,
	fix,
	deep,
	includeEvidence,
	includeSessions,
	score: scoreItems(items),
	status: items.some((entry) => entry.status === "fail") ? "fail" : items.some((entry) => entry.status === "warn") ? "warn" : "pass",
	items,
	prioritizedActions: sortedActions,
	fixActions: fixActions.map((action) => ({
		id: action.id,
		exit: action.code,
		ok: action.parsed?.ok ?? action.code === 0,
		stdoutTail: action.stdoutTail.slice(-1200),
		stderrTail: action.stderrTail.slice(-1200),
		error: action.error,
	})),
};

if (json) {
	console.log(JSON.stringify(report, null, 2));
} else {
	console.log("REPI Health");
	console.log(`score=${report.score} status=${report.status} root=${root}`);
	for (const action of report.fixActions) console.log(`${action.ok ? "FIXED" : "FIX-FAIL"} ${action.id} exit=${action.exit}`);
	for (const entry of items) {
		const label = entry.status === "pass" ? "PASS" : entry.status === "warn" ? "WARN" : entry.status === "skip" ? "SKIP" : "FAIL";
		console.log(`${label} ${entry.id} :: ${entry.summary}`);
	}
	if (sortedActions.length) {
		console.log("Next actions:");
		for (const action of sortedActions) console.log(`- [${action.source}] ${action.command}`);
	}
	console.log(`verdict: ${report.status}`);
}

process.exit(report.status === "fail" ? 1 : 0);

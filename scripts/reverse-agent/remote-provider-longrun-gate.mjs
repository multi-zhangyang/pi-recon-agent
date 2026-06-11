#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { appendFailureRepairWriteback, failureRepairFromGap, validateFailureRepairBatch } from "./failure-repair-ledger.mjs";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const liveRequested = argv.includes("--live") || process.env.REPI_REMOTE_PROVIDER_LIVE === "1";
const writeEvidence = !argv.includes("--no-write");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_REMOTE_PROVIDER_LONGRUN_TMP === "1";
const sha256 = (value) => createHash("sha256").update(String(value ?? "")).digest("hex");
const SOURCE = "remote_provider_longrun";
const SUPPORTED_APIS = new Set(["openai-completions", "anthropic-messages"]);
const REMOTE_PROVIDER_LONGRUN_NEGATIVE_MARKERS = [
	"negative:remote-provider-live-missing-marker",
	"negative:remote-provider-secret-leak",
	"negative:remote-provider-unbounded-timeout",
	"negative:remote-provider-skipped-without-reason",
	"negative:remote-provider-missing-failure-repair",
];

function markerCheck(id, path, markers) {
	const full = join(root, path);
	if (!existsSync(full)) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readFileSync(full, "utf8");
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function envInt(name, fallback, min, max) {
	const raw = Number.parseInt(process.env[name] ?? "", 10);
	if (!Number.isFinite(raw)) return fallback;
	return Math.max(min, Math.min(max, raw));
}

function buildLiveConfig() {
	const api = process.env.REPI_REMOTE_PROVIDER_API || "openai-completions";
	const providerName = process.env.REPI_REMOTE_PROVIDER_NAME || (api === "anthropic-messages" ? "remote-anthropic-compatible" : "remote-openai-compatible");
	const apiKeyEnv = process.env.REPI_REMOTE_PROVIDER_API_KEY_ENV || "REPI_REMOTE_PROVIDER_API_KEY";
	return {
		api,
		providerName,
		modelId: process.env.REPI_REMOTE_PROVIDER_MODEL || "",
		baseUrl: process.env.REPI_REMOTE_PROVIDER_BASE_URL || "",
		apiKeyEnv,
		apiKeyValue: process.env[apiKeyEnv] || "",
		attempts: envInt("REPI_REMOTE_PROVIDER_ATTEMPTS", 2, 1, 5),
		timeoutMs: envInt("REPI_REMOTE_PROVIDER_TIMEOUT_MS", 60000, 15000, 180000),
	};
}

function configProblems(config) {
	const problems = [];
	if (!SUPPORTED_APIS.has(config.api)) problems.push(`unsupported_api:${config.api}`);
	if (!config.baseUrl) problems.push("missing_env:REPI_REMOTE_PROVIDER_BASE_URL");
	if (!config.modelId) problems.push("missing_env:REPI_REMOTE_PROVIDER_MODEL");
	if (!config.apiKeyEnv || !/^[A-Z_][A-Z0-9_]*$/.test(config.apiKeyEnv)) problems.push("invalid_env:REPI_REMOTE_PROVIDER_API_KEY_ENV");
	if (!config.apiKeyValue) problems.push(`missing_env:${config.apiKeyEnv || "REPI_REMOTE_PROVIDER_API_KEY"}`);
	return problems;
}

function providerCompat(api) {
	if (api === "anthropic-messages") {
		return { supportsLongCacheRetention: false, sendSessionAffinityHeaders: false, supportsCacheControlOnTools: false, supportsEagerToolInputStreaming: true };
	}
	return { supportsDeveloperRole: false, supportsReasoningEffort: false, supportsStore: false, supportsStrictMode: false, supportsUsageInStreaming: false, maxTokensField: "max_tokens" };
}

function buildModelsJson(config) {
	return `${JSON.stringify(
		{
			providers: {
				[config.providerName]: {
					baseUrl: config.baseUrl,
					api: config.api,
					apiKey: `$${config.apiKeyEnv}`,
					compat: providerCompat(config.api),
					models: [{ id: config.modelId, contextWindow: envInt("REPI_REMOTE_PROVIDER_CONTEXT_WINDOW", 8192, 1024, 1048576), maxTokens: envInt("REPI_REMOTE_PROVIDER_MAX_TOKENS", 1024, 64, 65536) }],
				},
			},
		},
		null,
		2,
	)}\n`;
}

function baseEnv(home, isolatedHome, config) {
	return {
		...process.env,
		HOME: home,
		REPI_CODING_AGENT_DIR: isolatedHome,
		REPI_CODING_AGENT_CONFIG_DIR: ".repi",
		REPI_CODING_AGENT_APP_NAME: "repi",
		REPI_CODING_AGENT_SESSION_DIR: join(isolatedHome, "sessions"),
		REPI_PRIMARY: "1",
		REPI_PRODUCT: "1",
		REPI_SKIP_VERSION_CHECK: "1",
		REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
		REPI_TELEMETRY: "0",
		REPI_OFFLINE: "0",
		PI_CODING_AGENT_DIR: isolatedHome,
		PI_CODING_AGENT_CONFIG_DIR: ".repi",
		PI_CODING_AGENT_APP_NAME: "repi",
		PI_RECON_PRIMARY: "1",
		PI_RECON_PRODUCT: "1",
		PI_SKIP_VERSION_CHECK: "1",
		PI_SKIP_PACKAGE_UPDATE_CHECK: "1",
		PI_TELEMETRY: "0",
		PI_OFFLINE: "0",
		REPI_REPO_ROOT: root,
		[config.apiKeyEnv]: config.apiKeyValue,
	};
}

function secretPattern(config) {
	const values = [config.apiKeyValue].filter((value) => typeof value === "string" && value.length >= 8).map((value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
	const parts = ["sk-[A-Za-z0-9]", "ghp_[A-Za-z0-9]", "github_pat_[A-Za-z0-9]", "Bearer\\s+[A-Za-z0-9._:-]{8,}", ...values];
	return new RegExp(parts.join("|"), "i");
}

async function spawnRepi(args, env, cwd, timeoutMs) {
	const command = join(root, "repi");
	const startedAtMs = Date.now();
	let stdout = "";
	let stderr = "";
	let exitCode = null;
	let signal = null;
	let spawnError;
	let timedOut = false;
	let cancelledAt;
	await new Promise((resolveChild) => {
		const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
		const timer = setTimeout(() => {
			timedOut = true;
			cancelledAt = new Date().toISOString();
			child.kill("SIGTERM");
			setTimeout(() => {
				if (child.exitCode === null) child.kill("SIGKILL");
			}, 2000).unref();
		}, timeoutMs);
		child.stdout.on("data", (chunk) => {
			stdout += String(chunk);
		});
		child.stderr.on("data", (chunk) => {
			stderr += String(chunk);
		});
		child.on("error", (error) => {
			spawnError = error;
		});
		child.on("close", (code, sig) => {
			clearTimeout(timer);
			exitCode = code;
			signal = sig;
			resolveChild();
		});
	});
	const endedAtMs = Date.now();
	return { command, args, cwd, stdout, stderr, exitCode, signal, spawnError: spawnError?.message, timedOut, cancelledAt, startedAt: new Date(startedAtMs).toISOString(), endedAt: new Date(endedAtMs).toISOString(), elapsedMs: Math.max(0, endedAtMs - startedAtMs) };
}

function relPath(base, path) {
	const resolvedBase = resolve(base);
	const resolved = resolve(path);
	return resolved.startsWith(resolvedBase) ? resolved.slice(resolvedBase.length + 1) : path;
}

function fileArtifact(base, path) {
	const bytes = readFileSync(path);
	const stat = statSync(path);
	return { path: relPath(base, path), sha256: createHash("sha256").update(bytes).digest("hex"), tier: "runtime_artifact", bytes: bytes.length, mtime: stat.mtime.toISOString(), exists: true };
}

function buildSkippedReport(reason, configProblemsFound = []) {
	return {
		kind: "RemoteProviderLongRunV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		mode: "skipped",
		liveRequested,
		skipReason: reason,
		configProblems: configProblemsFound,
		providerName: undefined,
		api: undefined,
		modelIdSha256: undefined,
		baseUrlSha256: undefined,
		apiKeyEnv: undefined,
		attemptsPlanned: 0,
		timeoutMs: 0,
		listModels: { status: "skipped", stdoutSha256: sha256(""), stderrSha256: sha256("") },
		cases: [],
		failureLedgerEvents: [],
		repairQueue: [],
		failureRepairValidation: { ok: true, failureCount: 0, repairCount: 0 },
		writebackProbe: { status: "skipped", writeback: null, validation: { ok: true, failureCount: 0, repairCount: 0 } },
	};
}

function buildCaseReport({ index, run, config, probeRoot, tempRoot, modelsJson, home, workspace }) {
	const caseId = `remote-longrun-${index}`;
	const marker = `REPI_REMOTE_LONGRUN_OK_${index}`;
	const stdoutPath = join(probeRoot, `${caseId}-stdout.txt`);
	const stderrPath = join(probeRoot, `${caseId}-stderr.txt`);
	const transcriptPath = join(probeRoot, `${caseId}-transcript.jsonl`);
	writeFileSync(stdoutPath, run.stdout, "utf8");
	writeFileSync(stderrPath, run.stderr, "utf8");
	const transcriptText = `${JSON.stringify({ kind: "RemoteProviderLongRunCaseTranscriptV1", caseId, providerName: config.providerName, api: config.api, modelIdSha256: sha256(config.modelId), marker, exitCode: run.exitCode, signal: run.signal, timedOut: run.timedOut, stdoutSha256: sha256(run.stdout), stderrSha256: sha256(run.stderr), startedAt: run.startedAt, endedAt: run.endedAt, elapsedMs: run.elapsedMs })}\n`;
	writeFileSync(transcriptPath, transcriptText, "utf8");
	const combined = `${run.stdout}\n${run.stderr}\n${modelsJson}\n${transcriptText}`;
	const assertions = {
		exitOk: run.exitCode === 0 && !run.timedOut && !run.spawnError,
		stdoutNonEmpty: run.stdout.trim().length > 0,
		markerObserved: run.stdout.includes(marker),
		apiKeyEnvRefOnly: modelsJson.includes(`"$${config.apiKeyEnv}"`) && !modelsJson.includes(config.apiKeyValue),
		boundedTimeout: run.elapsedMs <= config.timeoutMs + 5000,
		isolatedRepiHome: home.includes(".repi") === false && existsSync(join(home, ".repi", "agent")) && !existsSync(join(home, ".pi")) && !existsSync(join(workspace, ".pi")),
		noLiteralSecrets: !secretPattern(config).test(combined),
		noPiHomeImport: !new RegExp("(^|[\\s\"'])~?\\/?\\.pi\\/", "i").test(combined),
		noUpdateBanner: !/Update Available|pi\.dev\/changelog|Run pi update/i.test(combined),
		transcriptCaptured: transcriptText.includes("RemoteProviderLongRunCaseTranscriptV1"),
	};
	const errors = Object.entries(assertions).filter(([, ok]) => !ok).map(([key]) => `assertion_failed:${key}`);
	return {
		report: {
			kind: "RemoteProviderLongRunCaseV1",
			schemaVersion: 1,
			caseId,
			providerName: config.providerName,
			api: config.api,
			modelIdSha256: sha256(config.modelId),
			attempt: index,
			status: errors.length ? "blocked" : "pass",
			exitCode: run.exitCode,
			signal: run.signal,
			timedOut: run.timedOut,
			cancelledAt: run.cancelledAt,
			elapsedMs: run.elapsedMs,
			timeoutMs: config.timeoutMs,
			stdoutPath,
			stderrPath,
			transcriptPath,
			stdoutSha256: sha256(run.stdout),
			stderrSha256: sha256(run.stderr),
			transcriptSha256: sha256(transcriptText),
			assertions,
			errors,
		},
		artifacts: [stdoutPath, stderrPath, transcriptPath].map((path) => fileArtifact(tempRoot, path)),
	};
}

function validateRemoteProviderLongRun(report) {
	const errors = [];
	if (report.kind !== "RemoteProviderLongRunV1") errors.push("report.kind_invalid");
	if (report.mode === "skipped") {
		if (!report.skipReason) errors.push("skipped_without_reason");
		if ((report.cases ?? []).length !== 0) errors.push("skipped_with_cases");
		return { ok: errors.length === 0, errors };
	}
	if (report.mode !== "live") errors.push("mode_invalid");
	if (!SUPPORTED_APIS.has(report.api)) errors.push(`api_unsupported:${report.api}`);
	if (!report.providerName) errors.push("provider_missing");
	if (!report.modelIdSha256 || !/^[a-f0-9]{64}$/.test(report.modelIdSha256)) errors.push("model_hash_missing");
	if (!report.baseUrlSha256 || !/^[a-f0-9]{64}$/.test(report.baseUrlSha256)) errors.push("base_url_hash_missing");
	if (!report.apiKeyEnv || !/^[A-Z_][A-Z0-9_]*$/.test(report.apiKeyEnv)) errors.push("api_key_env_invalid");
	if (report.listModels?.status !== "pass") errors.push("list_models_not_pass");
	if ((report.cases ?? []).length < Math.max(1, report.attemptsPlanned ?? 0)) errors.push("case_count_lt_attempts");
	for (const row of report.cases ?? []) {
		const prefix = `case:${row.caseId}`;
		if (row.status !== "pass") errors.push(`${prefix}.status_not_pass`);
		if (!row.assertions?.exitOk) errors.push(`${prefix}.exit_not_ok`);
		if (!row.assertions?.stdoutNonEmpty) errors.push(`${prefix}.stdout_empty`);
		if (!row.assertions?.markerObserved) errors.push(`${prefix}.marker_missing`);
		if (!row.assertions?.apiKeyEnvRefOnly) errors.push(`${prefix}.api_key_not_env_ref`);
		if (!row.assertions?.boundedTimeout) errors.push(`${prefix}.unbounded_timeout`);
		if (!row.assertions?.isolatedRepiHome) errors.push(`${prefix}.home_not_isolated`);
		if (!row.assertions?.noLiteralSecrets) errors.push(`${prefix}.literal_secret_leak`);
		if (!row.assertions?.noPiHomeImport) errors.push(`${prefix}.pi_home_leak`);
		if (!row.assertions?.noUpdateBanner) errors.push(`${prefix}.update_banner_leak`);
		if (!row.assertions?.transcriptCaptured) errors.push(`${prefix}.transcript_missing`);
	}
	if ((report.failureLedgerEvents ?? []).length > 0 || (report.repairQueue ?? []).length > 0) {
		const failureValidation = validateFailureRepairBatch({ failures: report.failureLedgerEvents ?? [], repairs: report.repairQueue ?? [] });
		if (!failureValidation.ok) errors.push("failure_repair_validation_not_ok");
		if (report.writebackProbe?.status !== "pass" || report.writebackProbe?.validation?.ok !== true) errors.push("writeback_probe_not_pass");
	}
	return { ok: errors.length === 0, errors };
}

function buildSyntheticLiveReport() {
	const failure = {
		id: "fail:remote_provider_longrun:111111111111111111111111",
		ts: "2026-06-11T00:00:00.000Z",
		source: SOURCE,
		scope: `${SOURCE}:synthetic`,
		category: "runtime_failed",
		signature: "111111111111111111111111",
		attempt: 1,
		maxAttempts: 2,
		status: "repair_queued",
		failedGates: ["remote_provider_live_marker"],
		artifacts: [],
		artifactHashes: [],
		repairId: "repair:remote_provider_longrun:111111111111111111111111",
		budget: { retryKey: "111111111111111111111111", remainingAttempts: 1, exhaustedAction: "queue repair and escalate to operator" },
		retryBudget: { retryKey: "111111111111111111111111", remainingAttempts: 1, exhaustedAction: "queue repair and escalate to operator" },
		evidenceWriteback: { failureLedgerPath: ".repi-harness/evidence/failures/ledger.jsonl", repairQueuePath: ".repi-harness/evidence/repairs/queue.jsonl", appendOnly: true, mode: SOURCE },
		blockedConditions: [{ reason: "synthetic remote marker missing", unblock: "rerun remote provider longrun" }],
		rollback: { required: false, baseline: "git status --short", allowlist: [], criteria: ["no unrelated file changes"], restored: false },
	};
	const repair = {
		repairId: failure.repairId,
		fromFailureId: failure.id,
		signature: failure.signature,
		scope: failure.scope,
		action: "rerun",
		commands: ["npm run gate:remote-provider-longrun -- --live"],
		expectedArtifacts: [],
		expectedGates: failure.failedGates,
		preconditions: { liveAllowed: true, providerAllowed: true, requiredSecrets: ["REPI_REMOTE_PROVIDER_API_KEY"] },
		paused: false,
		allowlist: [],
		rollbackCriteria: { baseline: "git status --short", mustRestore: [], verificationCommand: "npm run gate:remote-provider-longrun" },
		repairAction: "rerun",
		blockedConditions: failure.blockedConditions,
		evidenceWriteback: failure.evidenceWriteback,
		regressionGates: ["gate:remote-provider-longrun"],
	};
	return {
		kind: "RemoteProviderLongRunV1",
		schemaVersion: 1,
		generatedAt: "2026-06-11T00:00:00.000Z",
		mode: "live",
		liveRequested: true,
		skipReason: "",
		configProblems: [],
		providerName: "remote-openai-compatible",
		api: "openai-completions",
		modelIdSha256: "a".repeat(64),
		baseUrlSha256: "b".repeat(64),
		apiKeyEnv: "REPI_REMOTE_PROVIDER_API_KEY",
		attemptsPlanned: 1,
		timeoutMs: 60000,
		listModels: { status: "pass", stdoutSha256: "c".repeat(64), stderrSha256: "d".repeat(64) },
		cases: [
			{
				kind: "RemoteProviderLongRunCaseV1",
				schemaVersion: 1,
				caseId: "remote-longrun-1",
				providerName: "remote-openai-compatible",
				api: "openai-completions",
				modelIdSha256: "a".repeat(64),
				attempt: 1,
				status: "pass",
				exitCode: 0,
				signal: null,
				timedOut: false,
				elapsedMs: 1000,
				timeoutMs: 60000,
				stdoutPath: "/tmp/stdout.txt",
				stderrPath: "/tmp/stderr.txt",
				transcriptPath: "/tmp/transcript.jsonl",
				stdoutSha256: "e".repeat(64),
				stderrSha256: "f".repeat(64),
				transcriptSha256: "1".repeat(64),
				assertions: { exitOk: true, stdoutNonEmpty: true, markerObserved: true, apiKeyEnvRefOnly: true, boundedTimeout: true, isolatedRepiHome: true, noLiteralSecrets: true, noPiHomeImport: true, noUpdateBanner: true, transcriptCaptured: true },
				errors: [],
			},
		],
		failureLedgerEvents: [failure],
		repairQueue: [repair],
		failureRepairValidation: { ok: true, failureCount: 1, repairCount: 1 },
		writebackProbe: { status: "pass", writeback: { failurePath: ".repi-harness/evidence/failures/ledger.jsonl", repairPath: ".repi-harness/evidence/repairs/queue.jsonl" }, validation: { ok: true, failureCount: 1, repairCount: 1 } },
	};
}

function mutateReport(report, mutate) {
	const clone = JSON.parse(JSON.stringify(report));
	if (mutate === "liveMissingMarker") clone.cases[0].assertions.markerObserved = false;
	if (mutate === "secretLeak") clone.cases[0].assertions.noLiteralSecrets = false;
	if (mutate === "unboundedTimeout") clone.cases[0].assertions.boundedTimeout = false;
	if (mutate === "skippedWithoutReason") {
		clone.mode = "skipped";
		clone.skipReason = "";
		clone.cases = [];
	}
	if (mutate === "missingFailureRepair") clone.repairQueue = [];
	return clone;
}

function negativeCheck(report, id, mutate, expectedNeedle) {
	const validation = validateRemoteProviderLongRun(mutateReport(report, mutate));
	return { id: `negative:${id}`, status: !validation.ok && validation.errors.some((error) => error.includes(expectedNeedle)) ? "pass" : "fail", evidence: { validation, expectedNeedle } };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "remote-provider-longrun", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return path;
}

async function runLive(tempRoot, config) {
	const probeRoot = join(tempRoot, "remote-provider-longrun");
	const home = join(probeRoot, "home");
	const isolatedHome = join(home, ".repi", "agent");
	const workspace = join(probeRoot, "workspace");
	mkdirSync(isolatedHome, { recursive: true });
	mkdirSync(workspace, { recursive: true });
	const modelsJson = buildModelsJson(config);
	writeFileSync(join(isolatedHome, "models.json"), modelsJson, "utf8");
	const env = baseEnv(home, isolatedHome, config);
	const listRun = await spawnRepi(["--list-models", config.providerName], env, workspace, Math.min(30000, config.timeoutMs));
	writeFileSync(join(probeRoot, "list-models-stdout.txt"), listRun.stdout, "utf8");
	writeFileSync(join(probeRoot, "list-models-stderr.txt"), listRun.stderr, "utf8");
	const cases = [];
	const failureLedgerEvents = [];
	const repairQueue = [];
	for (let index = 1; index <= config.attempts; index++) {
		const marker = `REPI_REMOTE_LONGRUN_OK_${index}`;
		const prompt = `Reply with exactly this marker and no credentials: ${marker}`;
		const run = await spawnRepi(["--provider", config.providerName, "--model", config.modelId, "--no-tools", "--no-session", "--thinking", "off", "-p", prompt], env, workspace, config.timeoutMs);
		const built = buildCaseReport({ index, run, config, probeRoot, tempRoot, modelsJson, home, workspace });
		cases.push(built.report);
		if (built.report.status !== "pass") {
			const { failure, repair } = failureRepairFromGap({
				root: tempRoot,
				source: SOURCE,
				scope: `${SOURCE}:${built.report.caseId}`,
				category: "runtime_failed",
				reason: `remote provider long-run case failed: ${built.report.errors.join(",") || built.report.caseId}`,
				failedGates: [`remote_provider_longrun_${index}`],
				artifacts: built.artifacts,
				attempt: index,
				maxAttempts: config.attempts,
				status: index >= config.attempts ? "exhausted" : "repair_queued",
				action: index >= config.attempts ? "escalate" : "rerun",
				providerAllowed: index < config.attempts,
				liveAllowed: true,
				paused: index >= config.attempts,
				requiredSecrets: [config.apiKeyEnv],
				commands: ["npm run gate:remote-provider-longrun -- --live", "node scripts/reverse-agent/remote-provider-longrun-gate.mjs . --strict --live --no-write"],
				expectedArtifacts: built.artifacts.map((artifact) => artifact.path),
				regressionGates: ["gate:remote-provider-longrun", "gate:provider-runtime-matrix", "gate:provider-failure-injection"],
				verificationCommand: "npm run gate:remote-provider-longrun -- --live",
			});
			failureLedgerEvents.push(failure);
			repairQueue.push(repair);
			built.report.failureId = failure.id;
			built.report.repairId = repair.repairId;
		}
	}
	let failureRepairValidation = { ok: true, failureCount: 0, repairCount: 0 };
	let writebackProbe = { status: "skipped", writeback: null, validation: { ok: true, failureCount: 0, repairCount: 0 } };
	if (failureLedgerEvents.length > 0) {
		failureRepairValidation = validateFailureRepairBatch({ failures: failureLedgerEvents, repairs: repairQueue });
		const writeback = appendFailureRepairWriteback(tempRoot, failureLedgerEvents, repairQueue, failureLedgerEvents[0]?.evidenceWriteback);
		const writtenFailures = existsSync(join(tempRoot, writeback.failurePath))
			? readFileSync(join(tempRoot, writeback.failurePath), "utf8").trim().split(/\n+/).filter(Boolean).map((line) => JSON.parse(line))
			: [];
		const writtenRepairs = existsSync(join(tempRoot, writeback.repairPath))
			? readFileSync(join(tempRoot, writeback.repairPath), "utf8").trim().split(/\n+/).filter(Boolean).map((line) => JSON.parse(line))
			: [];
		const writebackValidation = validateFailureRepairBatch({ failures: writtenFailures, repairs: writtenRepairs });
		writebackProbe = { status: writebackValidation.ok ? "pass" : "blocked", writeback, validation: writebackValidation };
	}
	const listText = `${listRun.stdout}\n${listRun.stderr}`;
	const report = {
		kind: "RemoteProviderLongRunV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		mode: "live",
		liveRequested: true,
		skipReason: "",
		configProblems: [],
		providerName: config.providerName,
		api: config.api,
		modelIdSha256: sha256(config.modelId),
		baseUrlSha256: sha256(config.baseUrl),
		apiKeyEnv: config.apiKeyEnv,
		attemptsPlanned: config.attempts,
		timeoutMs: config.timeoutMs,
		listModels: {
			status: listRun.exitCode === 0 && listText.includes(config.providerName) && listText.includes(config.modelId) && !secretPattern(config).test(listText) ? "pass" : "blocked",
			stdoutSha256: sha256(listRun.stdout),
			stderrSha256: sha256(listRun.stderr),
		},
		cases,
		failureLedgerEvents,
		repairQueue,
		failureRepairValidation,
		writebackProbe,
	};
	return { report, validation: validateRemoteProviderLongRun(report) };
}

async function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-remote-provider-longrun-"));
	const checks = [];
	let report;
	try {
		const config = buildLiveConfig();
		const problems = configProblems(config);
		if (!liveRequested) {
			report = buildSkippedReport("set REPI_REMOTE_PROVIDER_LIVE=1 or pass --live to run a real remote provider long-run", []);
			checks.push({ id: "runtime:remote-provider-longrun-skipped", status: "pass", evidence: { skipReason: report.skipReason } });
		} else if (problems.length > 0) {
			report = buildSkippedReport("live requested but remote provider config is incomplete", problems);
			checks.push({ id: "runtime:remote-provider-longrun-config", status: "fail", evidence: { configProblems: problems } });
		} else {
			const live = await runLive(tempRoot, config);
			report = live.report;
			checks.push({ id: "runtime:remote-provider-longrun-validation", status: live.validation.ok ? "pass" : "fail", evidence: { validation: live.validation, mode: report.mode, providerName: report.providerName, api: report.api, attemptsPlanned: report.attemptsPlanned, cases: report.cases.map((item) => ({ caseId: item.caseId, status: item.status, exitCode: item.exitCode, timedOut: item.timedOut, elapsedMs: item.elapsedMs, assertions: item.assertions, failureId: item.failureId, repairId: item.repairId })) } });
			checks.push({ id: "runtime:remote-provider-longrun-list-models", status: report.listModels.status === "pass" ? "pass" : "fail", evidence: report.listModels });
			checks.push({ id: "runtime:remote-provider-longrun-attempts", status: report.cases.length === report.attemptsPlanned && report.cases.every((item) => item.status === "pass") ? "pass" : "fail", evidence: report.cases.map((item) => ({ caseId: item.caseId, status: item.status, elapsedMs: item.elapsedMs, timeoutMs: item.timeoutMs, assertions: item.assertions })) });
			checks.push({ id: "runtime:remote-provider-longrun-env-redaction", status: report.cases.every((item) => item.assertions.apiKeyEnvRefOnly && item.assertions.noLiteralSecrets) ? "pass" : "fail", evidence: report.cases.map((item) => ({ caseId: item.caseId, apiKeyEnvRefOnly: item.assertions.apiKeyEnvRefOnly, noLiteralSecrets: item.assertions.noLiteralSecrets })) });
			checks.push({ id: "runtime:remote-provider-longrun-session-isolation", status: report.cases.every((item) => item.assertions.isolatedRepiHome && item.assertions.noPiHomeImport && item.assertions.noUpdateBanner) ? "pass" : "fail", evidence: report.cases.map((item) => ({ caseId: item.caseId, isolatedRepiHome: item.assertions.isolatedRepiHome, noPiHomeImport: item.assertions.noPiHomeImport, noUpdateBanner: item.assertions.noUpdateBanner })) });
		}
		const validation = validateRemoteProviderLongRun(report);
		checks.push({ id: "contract:remote-provider-longrun-report", status: validation.ok ? "pass" : "fail", evidence: { validation } });
		const synthetic = buildSyntheticLiveReport();
		checks.push(negativeCheck(synthetic, "remote-provider-live-missing-marker", "liveMissingMarker", "marker_missing"));
		checks.push(negativeCheck(synthetic, "remote-provider-secret-leak", "secretLeak", "literal_secret_leak"));
		checks.push(negativeCheck(synthetic, "remote-provider-unbounded-timeout", "unboundedTimeout", "unbounded_timeout"));
		checks.push(negativeCheck(synthetic, "remote-provider-skipped-without-reason", "skippedWithoutReason", "skipped_without_reason"));
		checks.push(negativeCheck(synthetic, "remote-provider-missing-failure-repair", "missingFailureRepair", "failure_repair_validation_not_ok"));
	} catch (error) {
		checks.push({ id: "runtime:remote-provider-longrun-exception", status: "fail", evidence: { error: String(error), stack: error?.stack } });
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	checks.push(
		markerCheck("code:remote-provider-longrun-types", "packages/coding-agent/src/core/recon-profile.ts", ["type RemoteProviderLongRunV1", "type RemoteProviderLongRunCaseV1", "function verifyRemoteProviderLongRunV1", "remote_provider_longrun_optional_live_skip"]),
		markerCheck("docs:remote-provider-longrun", "README.md", ["Remote provider long-run", "gate:remote-provider-longrun", "RemoteProviderLongRunV1", "REPI_REMOTE_PROVIDER_LIVE"]),
		markerCheck("npm:remote-provider-longrun", "package.json", ["gate:remote-provider-longrun", "remote-provider-longrun-gate.mjs"]),
		markerCheck("harness:remote-provider-longrun", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:remote-provider-longrun", "provider:remote-longrun-optional-live", "RemoteProviderLongRunV1"]),
		markerCheck("autonomy:remote-provider-longrun", "scripts/reverse-agent/autonomy-control-plane.mjs", ["remote_provider_longrun_gate", "RemoteProviderLongRunV1", "runtime:remote-provider-longrun-skipped", "runtime:remote-provider-longrun-attempts"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-remote-provider-longrun-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, mode: report?.mode ?? "unknown", checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Remote Provider Long-run Gate");
		console.log(`ok: ${result.ok}`);
		console.log(`mode: ${result.mode}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
		for (const check of checks) console.log(`- ${check.id}: ${check.status}`);
		if (failed.length) console.log(`failed: ${failed.map((check) => check.id).join(", ")}`);
	}
	if (strict && failed.length) process.exitCode = 1;
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});

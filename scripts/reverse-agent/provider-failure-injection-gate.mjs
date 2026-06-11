#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { appendFailureRepairWriteback, failureRepairFromGap, validateFailureRepairBatch } from "./failure-repair-ledger.mjs";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_PROVIDER_FAILURE_INJECTION_TMP === "1";
const sha256 = (value) => createHash("sha256").update(String(value ?? "")).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");

const SOURCE = "provider_failure_injection";
const PROVIDER_FAILURE_INJECTION_MARKERS = [
	"runtime:provider-failure-http-500",
	"runtime:provider-failure-malformed-sse",
	"runtime:provider-failure-anthropic-error",
	"runtime:provider-failure-repair-ledger",
	"negative:provider-failure-duplicate-signature",
	"negative:provider-failure-exhausted-unpaused-rerun",
];

const FAILURE_CASES = [
	{
		caseId: "provider-failure-http-500",
		providerName: "failure-openai-compatible",
		modelId: "child/openai-http-500",
		api: "openai-completions",
		apiKeyEnv: "REPI_FAILURE_OPENAI_KEY",
		apiKeyValue: "failure-openai-token",
		expectedPath: "/v1/chat/completions",
		failureMode: "http_500",
		failedGate: "provider_http_500_handled",
		attempt: 1,
		maxAttempts: 2,
		status: "repair_queued",
		action: "rerun",
	},
	{
		caseId: "provider-failure-malformed-sse",
		providerName: "failure-openai-compatible",
		modelId: "child/openai-malformed-sse",
		api: "openai-completions",
		apiKeyEnv: "REPI_FAILURE_OPENAI_KEY",
		apiKeyValue: "failure-openai-token",
		expectedPath: "/v1/chat/completions",
		failureMode: "malformed_sse",
		failedGate: "provider_malformed_sse_handled",
		attempt: 1,
		maxAttempts: 2,
		status: "repair_queued",
		action: "rerun",
	},
	{
		caseId: "provider-failure-anthropic-error",
		providerName: "failure-anthropic-compatible",
		modelId: "child/anthropic-error-event",
		api: "anthropic-messages",
		apiKeyEnv: "REPI_FAILURE_ANTHROPIC_KEY",
		apiKeyValue: "failure-anthropic-token",
		expectedPath: "/v1/messages",
		failureMode: "anthropic_error_event",
		failedGate: "provider_anthropic_error_event_handled",
		attempt: 2,
		maxAttempts: 2,
		status: "exhausted",
		action: "escalate",
	},
];

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function closeServer(server) {
	return new Promise((resolveClose) => server.close(() => resolveClose()));
}

function sseData(raw) {
	return `data: ${raw}\n\n`;
}

function anthropicEvent(event, payload) {
	return `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
}

function redactHeaders(headers) {
	const out = {};
	for (const [key, value] of Object.entries(headers ?? {})) {
		const lower = key.toLowerCase();
		if (["authorization", "x-api-key", "api-key", "cf-aig-authorization"].includes(lower)) out[lower] = value ? `<redacted:${sha256(String(value)).slice(0, 16)}>` : undefined;
		else if (["content-type", "user-agent", "anthropic-version", "anthropic-beta", "accept"].includes(lower)) out[lower] = value;
	}
	return out;
}

function secretPattern() {
	const values = FAILURE_CASES.map((item) => item.apiKeyValue.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
	return new RegExp(`sk-[A-Za-z0-9]|ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|${values.join("|")}`, "i");
}

function createFailureServer(requests) {
	return createServer((req, res) => {
		let body = "";
		req.setEncoding("utf8");
		req.on("data", (chunk) => {
			body += chunk;
		});
		req.on("end", () => {
			let parsed;
			try {
				parsed = JSON.parse(body || "{}");
			} catch {
				parsed = undefined;
			}
			requests.push({ method: req.method, url: req.url, headers: req.headers, body, parsed });
			if (req.method === "POST" && req.url === "/v1/chat/completions" && parsed?.model === "child/openai-http-500") {
				res.writeHead(500, { "content-type": "application/json" });
				res.end(JSON.stringify({ error: { message: "REPI injected provider http 500", type: "server_error" } }));
				return;
			}
			if (req.method === "POST" && req.url === "/v1/chat/completions" && parsed?.model === "child/openai-malformed-sse") {
				res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache" });
				res.write(sseData('{"id":"broken","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"BROKEN"}')); // intentionally malformed JSON
				res.end();
				return;
			}
			if (req.method === "POST" && req.url === "/v1/messages" && parsed?.model === "child/anthropic-error-event") {
				res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache" });
				res.write(anthropicEvent("message_start", { type: "message_start", message: { id: "msg_repi_failure", type: "message", role: "assistant", content: [], model: parsed.model, stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 0 } } }));
				res.write(anthropicEvent("error", { type: "error", error: { type: "overloaded_error", message: "REPI injected anthropic error event" } }));
				res.end();
				return;
			}
			res.writeHead(404, { "content-type": "application/json" });
			res.end(JSON.stringify({ error: "unexpected request" }));
		});
	});
}

function buildModelsJson(port) {
	return `${JSON.stringify(
		{
			providers: {
				"failure-openai-compatible": {
					baseUrl: `http://127.0.0.1:${port}/v1`,
					api: "openai-completions",
					apiKey: "$REPI_FAILURE_OPENAI_KEY",
					compat: { supportsDeveloperRole: false, supportsReasoningEffort: false, supportsStore: false, supportsStrictMode: false, supportsUsageInStreaming: false, maxTokensField: "max_tokens" },
					models: [
						{ id: "child/openai-http-500", contextWindow: 8192, maxTokens: 1024 },
						{ id: "child/openai-malformed-sse", contextWindow: 8192, maxTokens: 1024 },
					],
				},
				"failure-anthropic-compatible": {
					baseUrl: `http://127.0.0.1:${port}`,
					api: "anthropic-messages",
					apiKey: "$REPI_FAILURE_ANTHROPIC_KEY",
					compat: { supportsLongCacheRetention: false, sendSessionAffinityHeaders: false, supportsCacheControlOnTools: false, supportsEagerToolInputStreaming: true },
					models: [{ id: "child/anthropic-error-event", contextWindow: 8192, maxTokens: 1024 }],
				},
			},
		},
		null,
		2,
	)}\n`;
}

function baseEnv(home, isolatedHome) {
	return {
		PATH: process.env.PATH ?? "",
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
		REPI_FAILURE_OPENAI_KEY: "failure-openai-token",
		REPI_FAILURE_ANTHROPIC_KEY: "failure-anthropic-token",
	};
}

async function spawnRepi(args, env, cwd, timeoutMs = 45000) {
	const command = join(root, "repi");
	const started = Date.now();
	let stdout = "";
	let stderr = "";
	let exitCode = null;
	let signal = null;
	let spawnError;
	let timedOut = false;
	await new Promise((resolveChild) => {
		const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
			setTimeout(() => {
				if (child.exitCode === null) child.kill("SIGKILL");
			}, 3000).unref();
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
	return { command, args, cwd, stdout, stderr, exitCode, signal, spawnError: spawnError?.message, timedOut, elapsedMs: Math.max(0, Date.now() - started) };
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

function requestForCase(requests, item) {
	return requests.find((request) => request.url === item.expectedPath && request.parsed?.model === item.modelId);
}

function buildRequestLog(caseId, rows) {
	return `${JSON.stringify({ kind: "ProviderFailureInjectionRequestLogV1", caseId, requests: rows.map((row) => ({ method: row.method, path: row.url, headers: redactHeaders(row.headers), model: row.parsed?.model, stream: row.parsed?.stream, bodySha256: sha256(row.body) })) }, null, 2)}\n`;
}

function validateInjectionReport(report) {
	const errors = [];
	if (report.kind !== "ProviderFailureInjectionReportV1") errors.push("report.kind_invalid");
	if ((report.cases ?? []).length < 3) errors.push("case_count_lt_3");
	for (const row of report.cases ?? []) {
		const prefix = `case:${row.caseId}`;
		if (row.status !== "pass") errors.push(`${prefix}.status_not_pass`);
		if (!row.assertions?.requestSeen) errors.push(`${prefix}.request_missing`);
		if (!row.assertions?.exitNonZero) errors.push(`${prefix}.exit_not_failed`);
		if (!row.assertions?.failureTextCaptured) errors.push(`${prefix}.failure_text_missing`);
		if (!row.assertions?.failureRepairLinked) errors.push(`${prefix}.failure_repair_not_linked`);
		if (!row.assertions?.noLiteralSecrets) errors.push(`${prefix}.literal_secret`);
		if (!row.assertions?.noPiHomeImport) errors.push(`${prefix}.pi_home_leak`);
		if (!row.assertions?.noUpdateBanner) errors.push(`${prefix}.update_banner_leak`);
	}
	if (report.failureRepairValidation?.ok !== true) errors.push("failure_repair_validation_not_ok");
	if (report.writebackProbe?.status !== "pass") errors.push("writeback_probe_not_pass");
	return { ok: errors.length === 0, errors };
}

function mutateReport(report, mutate) {
	const clone = JSON.parse(JSON.stringify(report));
	if (mutate === "duplicateSignature") clone.failureLedgerEvents.push({ ...clone.failureLedgerEvents[0] });
	if (mutate === "exhaustedUnpausedRerun") {
		const failure = clone.failureLedgerEvents.find((row) => row.status === "exhausted") ?? clone.failureLedgerEvents[0];
		failure.status = "exhausted";
		failure.budget.remainingAttempts = 0;
		failure.retryBudget.remainingAttempts = 0;
		const repair = clone.repairQueue.find((row) => row.fromFailureId === failure.id) ?? clone.repairQueue[0];
		repair.action = "rerun";
		repair.repairAction = "rerun";
		repair.paused = false;
	}
	if (mutate === "looseFailureField") clone.failureLedgerEvents[0].extra = true;
	if (mutate === "missingRepair") clone.repairQueue.pop();
	clone.failureRepairValidation = validateFailureRepairBatch({ failures: clone.failureLedgerEvents, repairs: clone.repairQueue });
	return clone;
}

function negativeCheck(report, id, mutate, predicate) {
	const mutated = mutateReport(report, mutate);
	const ok = mutated.failureRepairValidation.ok === false && predicate(mutated.failureRepairValidation);
	return { id: `negative:${id}`, status: ok ? "pass" : "fail", evidence: { validation: mutated.failureRepairValidation } };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "provider-failure-injection", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return path;
}

async function runInjection(tempRoot) {
	const probeRoot = join(tempRoot, "provider-failure-injection");
	const home = join(probeRoot, "home");
	const isolatedHome = join(home, ".repi", "agent");
	const workspace = join(probeRoot, "workspace");
	mkdirSync(isolatedHome, { recursive: true });
	mkdirSync(workspace, { recursive: true });
	const requests = [];
	const server = createFailureServer(requests);
	await new Promise((resolveListen, rejectListen) => {
		server.once("error", rejectListen);
		server.listen(0, "127.0.0.1", () => {
			server.off("error", rejectListen);
			resolveListen();
		});
	});
	const port = server.address().port;
	const modelsJson = buildModelsJson(port);
	writeFileSync(join(isolatedHome, "models.json"), modelsJson, "utf8");
	const env = baseEnv(home, isolatedHome);
	const cases = [];
	const failureLedgerEvents = [];
	const repairQueue = [];
	try {
		for (const item of FAILURE_CASES) {
			const beforeCount = requests.length;
			const run = await spawnRepi(["--provider", item.providerName, "--model", item.modelId, "--no-tools", "--no-session", "--thinking", "off", "-p", `Trigger ${item.failureMode}`], env, workspace, 45000);
			const stdoutPath = join(probeRoot, `${item.caseId}-stdout.txt`);
			const stderrPath = join(probeRoot, `${item.caseId}-stderr.txt`);
			const requestLogPath = join(probeRoot, `${item.caseId}-request-log.json`);
			const transcriptPath = join(probeRoot, `${item.caseId}-transcript.jsonl`);
			writeFileSync(stdoutPath, run.stdout, "utf8");
			writeFileSync(stderrPath, run.stderr, "utf8");
			const rows = requests.slice(beforeCount);
			const request = requestForCase(rows, item);
			const requestLogText = buildRequestLog(item.caseId, rows);
			writeFileSync(requestLogPath, requestLogText, "utf8");
			const transcriptText = `${JSON.stringify({ kind: "ProviderFailureInjectionTranscriptV1", caseId: item.caseId, providerName: item.providerName, api: item.api, modelId: item.modelId, failureMode: item.failureMode, exitCode: run.exitCode, signal: run.signal, stdoutSha256: sha256(run.stdout), stderrSha256: sha256(run.stderr), requestLogSha256: sha256(requestLogText), elapsedMs: run.elapsedMs })}\n`;
			writeFileSync(transcriptPath, transcriptText, "utf8");
			const combined = `${run.stdout}\n${run.stderr}\n${requestLogText}\n${transcriptText}\n${modelsJson}`;
			const failureTextCaptured = /error|failed|500|malformed|overloaded|provider|Could not parse|API/i.test(combined);
			const exitNonZero = run.exitCode !== 0 || run.timedOut || Boolean(run.spawnError);
			const artifacts = [stdoutPath, stderrPath, requestLogPath, transcriptPath].map((path) => fileArtifact(tempRoot, path));
			const { failure, repair } = failureRepairFromGap({
				root: tempRoot,
				source: SOURCE,
				scope: `${SOURCE}:${item.caseId}`,
				category: "runtime_failed",
				reason: `${item.failureMode} from ${item.providerName}/${item.modelId}`,
				failedGates: [item.failedGate],
				artifacts,
				attempt: item.attempt,
				maxAttempts: item.maxAttempts,
				status: item.status,
				action: item.action,
				providerAllowed: item.status !== "exhausted",
				liveAllowed: false,
				paused: item.status === "exhausted",
				commands: [`npm run gate:provider-runtime-matrix -- --case ${item.caseId}`, `node scripts/reverse-agent/provider-failure-injection-gate.mjs . --strict --no-write`],
				expectedArtifacts: artifacts.map((artifact) => artifact.path),
				regressionGates: ["gate:provider-runtime-matrix", "gate:provider-failure-injection"],
				verificationCommand: "npm run gate:provider-failure-injection",
			});
			failureLedgerEvents.push(failure);
			repairQueue.push(repair);
			const assertions = {
				requestSeen: !!request && request.method === "POST" && request.url === item.expectedPath,
				exitNonZero,
				failureTextCaptured,
				failureRepairLinked: failure.repairId === repair.repairId && repair.fromFailureId === failure.id && repair.signature === failure.signature,
				noLiteralSecrets: !secretPattern().test(combined),
				noPiHomeImport: !new RegExp("(^|[\\s\"'])~?\\/?\\.pi\\/", "i").test(combined),
				noUpdateBanner: !/Update Available|pi\.dev\/changelog|Run pi update/i.test(combined),
			};
			cases.push({
				kind: "ProviderFailureInjectionCaseV1",
				schemaVersion: 1,
				caseId: item.caseId,
				providerName: item.providerName,
				api: item.api,
				modelId: item.modelId,
				failureMode: item.failureMode,
				status: Object.values(assertions).every(Boolean) ? "pass" : "blocked",
				exitCode: run.exitCode,
				signal: run.signal,
				request: { method: request?.method, path: request?.url, model: request?.parsed?.model, stream: request?.parsed?.stream, bodySha256: request?.body ? sha256(request.body) : undefined },
				stdoutSha256: sha256(run.stdout),
				stderrSha256: sha256(run.stderr),
				requestLogSha256: sha256(requestLogText),
				transcriptSha256: sha256(transcriptText),
				failureId: failure.id,
				repairId: repair.repairId,
				assertions,
			});
		}
	} finally {
		await closeServer(server);
	}
	const failureRepairValidation = validateFailureRepairBatch({ failures: failureLedgerEvents, repairs: repairQueue });
	const writeback = appendFailureRepairWriteback(tempRoot, failureLedgerEvents, repairQueue, failureLedgerEvents[0]?.evidenceWriteback);
	const writtenFailures = existsSync(join(tempRoot, writeback.failurePath))
		? readFileSync(join(tempRoot, writeback.failurePath), "utf8").trim().split(/\n+/).filter(Boolean).map((line) => JSON.parse(line))
		: [];
	const writtenRepairs = existsSync(join(tempRoot, writeback.repairPath))
		? readFileSync(join(tempRoot, writeback.repairPath), "utf8").trim().split(/\n+/).filter(Boolean).map((line) => JSON.parse(line))
		: [];
	const writebackValidation = validateFailureRepairBatch({ failures: writtenFailures, repairs: writtenRepairs });
	const report = {
		kind: "ProviderFailureInjectionReportV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		isolatedHome,
		workspace,
		cases,
		failureLedgerEvents,
		repairQueue,
		failureRepairValidation,
		writebackProbe: {
			status: writebackValidation.ok && writtenFailures.length === failureLedgerEvents.length && writtenRepairs.length === repairQueue.length ? "pass" : "blocked",
			writeback,
			validation: writebackValidation,
		},
	};
	return { report, validation: validateInjectionReport(report) };
}

async function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-provider-failure-injection-"));
	const checks = [];
	let injection;
	try {
		injection = await runInjection(tempRoot);
		const report = injection.report;
		checks.push({ id: "runtime:provider-failure-injection-validation", status: injection.validation.ok ? "pass" : "fail", evidence: { validation: injection.validation, cases: report.cases.map((item) => ({ caseId: item.caseId, status: item.status, assertions: item.assertions, failureId: item.failureId, repairId: item.repairId })) } });
		for (const item of report.cases) checks.push({ id: `runtime:${item.caseId}`, status: item.status === "pass" ? "pass" : "fail", evidence: { caseId: item.caseId, request: item.request, assertions: item.assertions, failureId: item.failureId, repairId: item.repairId } });
		checks.push({ id: "runtime:provider-failure-repair-ledger", status: report.failureRepairValidation.ok ? "pass" : "fail", evidence: report.failureRepairValidation });
		checks.push({ id: "runtime:provider-failure-writeback", status: report.writebackProbe.status === "pass" ? "pass" : "fail", evidence: report.writebackProbe });
		checks.push({ id: "runtime:provider-failure-exhausted-escalates", status: report.failureLedgerEvents.some((failure) => failure.status === "exhausted" && failure.retryBudget.remainingAttempts === 0) && report.repairQueue.some((repair) => repair.action === "escalate" && repair.paused === true) ? "pass" : "fail", evidence: { exhausted: report.failureLedgerEvents.filter((failure) => failure.status === "exhausted"), repairs: report.repairQueue.filter((repair) => repair.action === "escalate") } });
		checks.push(negativeCheck(report, "provider-failure-duplicate-signature", "duplicateSignature", (validation) => validation.dedup.duplicateFailures.length > 0));
		checks.push(negativeCheck(report, "provider-failure-exhausted-unpaused-rerun", "exhaustedUnpausedRerun", (validation) => validation.dedup.exhaustedRetryViolations.length > 0));
		checks.push(negativeCheck(report, "provider-failure-loose-field", "looseFailureField", (validation) => validation.failures.some((row) => row.errors.some((error) => error.code === "additionalProperties"))));
		checks.push(negativeCheck(report, "provider-failure-missing-repair", "missingRepair", (validation) => validation.failures.some((row) => row.errors.some((error) => error.code === "link"))));
	} catch (error) {
		checks.push({ id: "runtime:provider-failure-injection-exception", status: "fail", evidence: { error: String(error), stack: error?.stack } });
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	checks.push(
		markerCheck("code:provider-failure-injection-types", "packages/coding-agent/src/core/recon-profile.ts", ["type ProviderFailureInjectionReportV1", "type ProviderFailureInjectionCaseV1", "function verifyProviderFailureInjectionReportV1"]),
		markerCheck("script:failure-repair-ledger", "scripts/reverse-agent/failure-repair-ledger.mjs", ["failureRepairFromGap", "appendFailureRepairWriteback", "validateFailureRepairBatch", "exhausted_unpaused_retry"]),
		markerCheck("docs:provider-failure-injection", "README.md", ["Provider failure injection", "gate:provider-failure-injection", "ProviderFailureInjectionReportV1", "FailureLedgerEventV1", "RepairQueueItemV1"]),
		markerCheck("npm:provider-failure-injection", "package.json", ["gate:provider-failure-injection", "provider-failure-injection-gate.mjs"]),
		markerCheck("harness:provider-failure-injection", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:provider-failure-injection", "provider:failure-injection-hard-eval", "ProviderFailureInjectionReportV1"]),
		markerCheck("autonomy:provider-failure-injection", "scripts/reverse-agent/autonomy-control-plane.mjs", ["provider_failure_injection_gate", "ProviderFailureInjectionReportV1", "runtime:provider-failure-repair-ledger"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-provider-failure-injection-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Provider Failure Injection Gate");
		console.log(`ok: ${result.ok}`);
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

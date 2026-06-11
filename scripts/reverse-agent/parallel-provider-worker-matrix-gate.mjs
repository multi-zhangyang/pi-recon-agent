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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_PARALLEL_PROVIDER_WORKER_MATRIX_TMP === "1";
const sha256 = (value) => createHash("sha256").update(String(value ?? "")).digest("hex");
const SOURCE = "parallel_provider_worker_matrix";

const WORKER_CASES = [
	{
		workerId: "worker-alpha-openai-pass",
		role: "openai-compatible-verifier",
		providerName: "parallel-openai-compatible",
		modelId: "parallel/openai-alpha",
		api: "openai-completions",
		apiKeyEnv: "REPI_PARALLEL_OPENAI_KEY",
		apiKeyValue: "parallel-openai-token",
		expectedPath: "/v1/chat/completions",
		authHeader: "authorization",
		marker: "PARALLEL_ALPHA_OK",
		mode: "pass",
		delayMs: 250,
		timeoutMs: 45000,
		mergeKey: "claim:provider-runtime-ready",
		claimId: "claim-parallel-alpha-provider-runtime",
	},
	{
		workerId: "worker-beta-anthropic-pass",
		role: "anthropic-compatible-verifier",
		providerName: "parallel-anthropic-compatible",
		modelId: "parallel/anthropic-beta",
		api: "anthropic-messages",
		apiKeyEnv: "REPI_PARALLEL_ANTHROPIC_KEY",
		apiKeyValue: "parallel-anthropic-token",
		expectedPath: "/v1/messages",
		authHeader: "x-api-key",
		marker: "PARALLEL_BETA_OK",
		mode: "pass",
		delayMs: 100,
		timeoutMs: 45000,
		mergeKey: "claim:provider-runtime-ready",
		claimId: "claim-parallel-beta-provider-runtime",
	},
	{
		workerId: "worker-gamma-openai-failure-repair",
		role: "provider-failure-repair",
		providerName: "parallel-openai-compatible",
		modelId: "parallel/openai-gamma-500",
		api: "openai-completions",
		apiKeyEnv: "REPI_PARALLEL_OPENAI_KEY",
		apiKeyValue: "parallel-openai-token",
		expectedPath: "/v1/chat/completions",
		authHeader: "authorization",
		marker: "PARALLEL_GAMMA_SHOULD_FAIL",
		mode: "failure",
		delayMs: 50,
		timeoutMs: 45000,
		mergeKey: "claim:provider-failure-repair",
		claimId: "claim-parallel-gamma-failure-repair",
		attempt: 1,
		maxAttempts: 2,
		status: "repair_queued",
		action: "rerun",
	},
	{
		workerId: "worker-delta-openai-timeout-cancel",
		role: "provider-timeout-cancel",
		providerName: "parallel-openai-compatible",
		modelId: "parallel/openai-delta-slow",
		api: "openai-completions",
		apiKeyEnv: "REPI_PARALLEL_OPENAI_KEY",
		apiKeyValue: "parallel-openai-token",
		expectedPath: "/v1/chat/completions",
		authHeader: "authorization",
		marker: "PARALLEL_DELTA_TIMEOUT",
		mode: "timeout",
		delayMs: 120000,
		timeoutMs: 10000,
		mergeKey: "claim:provider-timeout-cancelled",
		claimId: "claim-parallel-delta-timeout-cancelled",
		attempt: 2,
		maxAttempts: 2,
		status: "exhausted",
		action: "escalate",
	},
];

const PARALLEL_PROVIDER_WORKER_MATRIX_NEGATIVE_MARKERS = [
	"negative:parallel-worker-serial-execution",
	"negative:parallel-worker-missing-claim-merge",
	"negative:parallel-worker-unredacted-secret",
	"negative:parallel-worker-timeout-without-cancel",
	"negative:parallel-worker-missing-repair",
];

function markerCheck(id, path, markers) {
	const full = join(root, path);
	if (!existsSync(full)) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readFileSync(full, "utf8");
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function sseData(payload) {
	return `data: ${JSON.stringify(payload)}\n\n`;
}

function anthropicEvent(event, payload) {
	return `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
}

function closeServer(server) {
	return new Promise((resolveClose) => server.close(() => resolveClose()));
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
	const values = [...new Set(WORKER_CASES.map((item) => item.apiKeyValue))].map((value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
	return new RegExp(`sk-[A-Za-z0-9]|ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|${values.join("|")}`, "i");
}

function delayedResponse(res, delayMs, fn) {
	let closed = false;
	res.on("close", () => {
		closed = true;
	});
	if (delayMs <= 0) {
		if (!closed) fn();
		return;
	}
	const timer = setTimeout(() => {
		if (!closed && !res.writableEnded) fn();
	}, delayMs);
	if (delayMs > 1000) timer.unref();
	res.on("close", () => clearTimeout(timer));
}

function writeOpenAIStream(res, parsed, marker) {
	res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache" });
	res.write(sseData({ id: "chatcmpl-repi-parallel-worker", object: "chat.completion.chunk", created: 0, model: parsed?.model, choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }] }));
	res.write(sseData({ id: "chatcmpl-repi-parallel-worker", object: "chat.completion.chunk", created: 0, model: parsed?.model, choices: [{ index: 0, delta: { content: marker }, finish_reason: null }] }));
	res.write(sseData({ id: "chatcmpl-repi-parallel-worker", object: "chat.completion.chunk", created: 0, model: parsed?.model, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 8, completion_tokens: 3, total_tokens: 11 } }));
	res.write("data: [DONE]\n\n");
	res.end();
}

function writeAnthropicStream(res, parsed, marker) {
	res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache" });
	res.write(anthropicEvent("message_start", { type: "message_start", message: { id: "msg_repi_parallel_worker", type: "message", role: "assistant", content: [], model: parsed?.model, stop_reason: null, stop_sequence: null, usage: { input_tokens: 8, output_tokens: 0 } } }));
	res.write(anthropicEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }));
	res.write(anthropicEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: marker } }));
	res.write(anthropicEvent("content_block_stop", { type: "content_block_stop", index: 0 }));
	res.write(anthropicEvent("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 3 } }));
	res.write(anthropicEvent("message_stop", { type: "message_stop" }));
	res.end();
}

function createParallelProviderServer(requests) {
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
			const workerCase = WORKER_CASES.find((item) => item.modelId === parsed?.model);
			requests.push({ method: req.method, url: req.url, headers: req.headers, body, parsed, workerId: workerCase?.workerId });
			if (!workerCase || req.method !== "POST" || req.url !== workerCase.expectedPath) {
				res.writeHead(404, { "content-type": "application/json" });
				res.end(JSON.stringify({ error: "unexpected request" }));
				return;
			}
			if (workerCase.mode === "timeout") {
				delayedResponse(res, workerCase.delayMs, () => {
					res.writeHead(504, { "content-type": "application/json" });
					res.end(JSON.stringify({ error: { message: "REPI injected slow provider timeout", type: "timeout" } }));
				});
				return;
			}
			if (workerCase.mode === "failure") {
				delayedResponse(res, workerCase.delayMs, () => {
					res.writeHead(500, { "content-type": "application/json" });
					res.end(JSON.stringify({ error: { message: "REPI parallel worker injected provider 500", type: "server_error" } }));
				});
				return;
			}
			if (workerCase.api === "openai-completions") {
				delayedResponse(res, workerCase.delayMs, () => writeOpenAIStream(res, parsed, workerCase.marker));
				return;
			}
			if (workerCase.api === "anthropic-messages") {
				delayedResponse(res, workerCase.delayMs, () => writeAnthropicStream(res, parsed, workerCase.marker));
				return;
			}
			res.writeHead(404, { "content-type": "application/json" });
			res.end(JSON.stringify({ error: "unsupported case" }));
		});
	});
}

function buildModelsJson(port) {
	return `${JSON.stringify(
		{
			providers: {
				"parallel-openai-compatible": {
					baseUrl: `http://127.0.0.1:${port}/v1`,
					api: "openai-completions",
					apiKey: "$REPI_PARALLEL_OPENAI_KEY",
					compat: { supportsDeveloperRole: false, supportsReasoningEffort: false, supportsStore: false, supportsStrictMode: false, supportsUsageInStreaming: false, maxTokensField: "max_tokens" },
					models: WORKER_CASES.filter((item) => item.providerName === "parallel-openai-compatible").map((item) => ({ id: item.modelId, contextWindow: 8192, maxTokens: 1024 })),
				},
				"parallel-anthropic-compatible": {
					baseUrl: `http://127.0.0.1:${port}`,
					api: "anthropic-messages",
					apiKey: "$REPI_PARALLEL_ANTHROPIC_KEY",
					compat: { supportsLongCacheRetention: false, sendSessionAffinityHeaders: false, supportsCacheControlOnTools: false, supportsEagerToolInputStreaming: true },
					models: WORKER_CASES.filter((item) => item.providerName === "parallel-anthropic-compatible").map((item) => ({ id: item.modelId, contextWindow: 8192, maxTokens: 1024 })),
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
		REPI_PARALLEL_OPENAI_KEY: "parallel-openai-token",
		REPI_PARALLEL_ANTHROPIC_KEY: "parallel-anthropic-token",
	};
}

async function spawnRepiWorker(item, env, cwd) {
	const command = join(root, "repi");
	const args = ["--provider", item.providerName, "--model", item.modelId, "--no-tools", "--no-session", "--thinking", "off", "-p", item.mode === "pass" ? `Reply exactly: ${item.marker}` : `Exercise worker ${item.workerId}`];
	const startedAtMs = Date.now();
	const startedAt = new Date(startedAtMs).toISOString();
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
			}, 1500).unref();
		}, item.timeoutMs);
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
	return { item, command, args, cwd, stdout, stderr, exitCode, signal, spawnError: spawnError?.message, timedOut, cancelledAt, startedAt, endedAt: new Date(endedAtMs).toISOString(), startedAtMs, endedAtMs, elapsedMs: Math.max(0, endedAtMs - startedAtMs) };
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

function requestForWorker(requests, item) {
	return requests.find((request) => request.workerId === item.workerId && request.url === item.expectedPath && request.parsed?.model === item.modelId);
}

function buildRequestLog(workerId, rows) {
	return `${JSON.stringify({ kind: "ParallelProviderWorkerRequestLogV1", workerId, requests: rows.map((row) => ({ method: row.method, path: row.url, headers: redactHeaders(row.headers), model: row.parsed?.model, stream: row.parsed?.stream, bodySha256: sha256(row.body) })) }, null, 2)}\n`;
}

function computePeakConcurrency(workers) {
	const points = [];
	for (const worker of workers) {
		points.push({ t: worker.startedAtMs, delta: 1 });
		points.push({ t: worker.endedAtMs, delta: -1 });
	}
	points.sort((a, b) => a.t - b.t || b.delta - a.delta);
	let active = 0;
	let peak = 0;
	for (const point of points) {
		active += point.delta;
		peak = Math.max(peak, active);
	}
	return peak;
}

function buildClaimMerge(workers) {
	const byMergeKey = new Map();
	for (const worker of workers) {
		const rows = byMergeKey.get(worker.mergeKey) ?? [];
		rows.push(worker.workerId);
		byMergeKey.set(worker.mergeKey, rows);
	}
	const conflicts = [];
	for (const [mergeKey, ids] of byMergeKey) {
		if (ids.length < 2) continue;
		const candidates = workers.filter((worker) => ids.includes(worker.workerId));
		const winner = candidates.find((worker) => worker.status === "pass")?.workerId ?? ids[0];
		conflicts.push({
			mergeKey,
			workers: ids,
			status: "resolved",
			winner,
			evidenceRefs: candidates.flatMap((worker) => [worker.requestLogPath, worker.transcriptPath].filter(Boolean)).slice(0, 8),
			resolutionReason: "claim-aware provider worker merge keeps both provider artifacts but promotes the first passing verifier claim after request/transcript hash validation",
		});
	}
	return {
		strategy: "claim-aware provider worker merge",
		claimAwareProviderWorkerMerge: true,
		conflicts,
	};
}

function buildWorkerReport(run, rows, probeRoot, tempRoot, modelsJson) {
	const item = run.item;
	const stdoutPath = join(probeRoot, `${item.workerId}-stdout.txt`);
	const stderrPath = join(probeRoot, `${item.workerId}-stderr.txt`);
	const requestLogPath = join(probeRoot, `${item.workerId}-request-log.json`);
	const transcriptPath = join(probeRoot, `${item.workerId}-transcript.jsonl`);
	writeFileSync(stdoutPath, run.stdout, "utf8");
	writeFileSync(stderrPath, run.stderr, "utf8");
	const request = requestForWorker(rows, item);
	const requestLogText = buildRequestLog(item.workerId, rows);
	writeFileSync(requestLogPath, requestLogText, "utf8");
	const transcriptText = `${JSON.stringify({ kind: "ParallelProviderWorkerTranscriptV1", workerId: item.workerId, role: item.role, providerName: item.providerName, api: item.api, modelId: item.modelId, mode: item.mode, exitCode: run.exitCode, signal: run.signal, timedOut: run.timedOut, stdoutSha256: sha256(run.stdout), stderrSha256: sha256(run.stderr), requestLogSha256: sha256(requestLogText), startedAt: run.startedAt, endedAt: run.endedAt, elapsedMs: run.elapsedMs })}\n`;
	writeFileSync(transcriptPath, transcriptText, "utf8");
	const headerValue = item.authHeader === "authorization" ? request?.headers?.authorization : request?.headers?.[item.authHeader];
	const expectedSecret = item.apiKeyValue;
	const headerMatches = item.authHeader === "authorization" ? headerValue === `Bearer ${expectedSecret}` : headerValue === expectedSecret;
	const combined = `${run.stdout}\n${run.stderr}\n${modelsJson}\n${requestLogText}\n${transcriptText}`;
	const assertions = {
		childProcessLaunched: !run.spawnError,
		requestSeen: !!request && request.method === "POST",
		endpointMatched: request?.url === item.expectedPath,
		modelMatched: request?.parsed?.model === item.modelId,
		streamingUsed: request?.parsed?.stream === true,
		successMarkerObserved: item.mode === "pass" ? run.stdout.includes(item.marker) : true,
		exitOkWhenExpected: item.mode === "pass" ? run.exitCode === 0 && !run.timedOut : true,
		exitFailedWhenExpected: item.mode !== "pass" ? run.exitCode !== 0 || run.timedOut || Boolean(run.spawnError) : true,
		timeoutCancelled: item.mode === "timeout" ? run.timedOut && Boolean(run.cancelledAt) : true,
		apiKeyEnvRefOnly: modelsJson.includes(`"$${item.apiKeyEnv}"`) && !modelsJson.includes(String(expectedSecret)),
		authorizationFromEnv: headerMatches,
		requestLogCaptured: requestLogText.includes("ParallelProviderWorkerRequestLogV1"),
		transcriptCaptured: transcriptText.includes("ParallelProviderWorkerTranscriptV1"),
		noLiteralSecrets: !secretPattern().test(combined),
		noPiHomeImport: !new RegExp("(^|[\\s\"'])~?\\/?\\.pi\\/", "i").test(combined),
		noUpdateBanner: !/Update Available|pi\.dev\/changelog|Run pi update/i.test(combined),
	};
	let status = "blocked";
	if (item.mode === "pass" && Object.values(assertions).every(Boolean)) status = "pass";
	if (item.mode === "failure" && Object.values(assertions).every(Boolean)) status = "repair_queued";
	if (item.mode === "timeout" && Object.values(assertions).every(Boolean)) status = "cancelled";
	const report = {
		kind: "ParallelProviderWorkerMatrixWorkerV1",
		schemaVersion: 1,
		workerId: item.workerId,
		role: item.role,
		providerName: item.providerName,
		api: item.api,
		modelId: item.modelId,
		expectedPath: item.expectedPath,
		mode: item.mode,
		status,
		mergeKey: item.mergeKey,
		claimRefs: [item.claimId],
		startedAt: run.startedAt,
		endedAt: run.endedAt,
		elapsedMs: run.elapsedMs,
		timeoutMs: item.timeoutMs,
		exitCode: run.exitCode,
		signal: run.signal,
		timedOut: run.timedOut,
		cancelledAt: run.cancelledAt,
		stdoutPath,
		stderrPath,
		requestLogPath,
		transcriptPath,
		stdoutSha256: sha256(run.stdout),
		stderrSha256: sha256(run.stderr),
		requestLogSha256: sha256(requestLogText),
		transcriptSha256: sha256(transcriptText),
		request: { method: request?.method, path: request?.url, model: request?.parsed?.model, stream: request?.parsed?.stream, authHeaderSha256: headerValue ? sha256(String(headerValue)) : undefined, bodySha256: request?.body ? sha256(request.body) : undefined },
		assertions,
		errors: Object.entries(assertions).filter(([, ok]) => !ok).map(([key]) => `assertion_failed:${key}`),
	};
	const artifacts = [stdoutPath, stderrPath, requestLogPath, transcriptPath].map((path) => fileArtifact(tempRoot, path));
	return { report, artifacts };
}

function validateParallelProviderWorkerMatrix(report) {
	const errors = [];
	if (report.kind !== "ParallelProviderWorkerMatrixV1") errors.push("report.kind_invalid");
	if ((report.workers ?? []).length < 4) errors.push("worker_count_lt_4");
	if ((report.peakConcurrency ?? 0) < 2) errors.push("peakConcurrency_lt_2");
	if ((report.peakConcurrency ?? 0) > report.maxConcurrency) errors.push("maxConcurrency_exceeded");
	const apis = new Set((report.workers ?? []).filter((worker) => worker.status === "pass").map((worker) => worker.api));
	if (!apis.has("openai-completions")) errors.push("missing_openai_pass_worker");
	if (!apis.has("anthropic-messages")) errors.push("missing_anthropic_pass_worker");
	for (const worker of report.workers ?? []) {
		const prefix = `worker:${worker.workerId}`;
		if (!["pass", "repair_queued", "cancelled"].includes(worker.status)) errors.push(`${prefix}.status_not_terminal`);
		if (!worker.providerName?.startsWith("parallel-")) errors.push(`${prefix}.provider_not_parallel_fixture`);
		if (!worker.modelId?.startsWith("parallel/")) errors.push(`${prefix}.model_not_parallel_fixture`);
		if (!worker.assertions?.childProcessLaunched) errors.push(`${prefix}.child_process_not_launched`);
		if (!worker.assertions?.requestSeen) errors.push(`${prefix}.request_missing`);
		if (!worker.assertions?.endpointMatched) errors.push(`${prefix}.endpoint_mismatch`);
		if (!worker.assertions?.modelMatched) errors.push(`${prefix}.model_mismatch`);
		if (!worker.assertions?.streamingUsed) errors.push(`${prefix}.stream_missing`);
		if (!worker.assertions?.successMarkerObserved) errors.push(`${prefix}.success_marker_missing`);
		if (!worker.assertions?.exitOkWhenExpected) errors.push(`${prefix}.exit_not_ok_when_expected`);
		if (!worker.assertions?.exitFailedWhenExpected) errors.push(`${prefix}.exit_not_failed_when_expected`);
		if (!worker.assertions?.timeoutCancelled) errors.push(`${prefix}.timeout_without_cancel`);
		if (!worker.assertions?.apiKeyEnvRefOnly) errors.push(`${prefix}.api_key_not_env_ref`);
		if (!worker.assertions?.authorizationFromEnv) errors.push(`${prefix}.authorization_not_env`);
		if (!worker.assertions?.requestLogCaptured || !worker.assertions?.transcriptCaptured) errors.push(`${prefix}.artifact_missing`);
		if (!worker.assertions?.noLiteralSecrets) errors.push(`${prefix}.literal_secret_leak`);
		if (!worker.assertions?.noPiHomeImport) errors.push(`${prefix}.pi_home_leak`);
		if (!worker.assertions?.noUpdateBanner) errors.push(`${prefix}.update_banner_leak`);
		if (worker.mode === "failure" && !worker.failureId) errors.push(`${prefix}.failure_repair_not_linked`);
		if (worker.mode === "timeout" && (!worker.timedOut || !worker.cancelledAt)) errors.push(`${prefix}.timeout_without_cancel`);
	}
	const byMergeKey = new Map();
	for (const worker of report.workers ?? []) {
		const rows = byMergeKey.get(worker.mergeKey) ?? [];
		rows.push(worker.workerId);
		byMergeKey.set(worker.mergeKey, rows);
	}
	const resolvedMergeKeys = new Set((report.claimMerge?.conflicts ?? []).filter((conflict) => conflict.status === "resolved" && conflict.winner && (conflict.evidenceRefs ?? []).length > 0).map((conflict) => conflict.mergeKey));
	for (const [mergeKey, ids] of byMergeKey) if (ids.length > 1 && !resolvedMergeKeys.has(mergeKey)) errors.push(`duplicate_mergeKey_unresolved:${mergeKey}`);
	const failureValidation = validateFailureRepairBatch({ failures: report.failureLedgerEvents ?? [], repairs: report.repairQueue ?? [] });
	if (!failureValidation.ok) errors.push("failure_repair_validation_not_ok");
	if (!report.writebackProbe || report.writebackProbe.status !== "pass" || report.writebackProbe.validation?.ok !== true) errors.push("writeback_probe_not_pass");
	if (!(report.failureLedgerEvents ?? []).some((failure) => failure.status === "exhausted" && failure.retryBudget?.remainingAttempts === 0)) errors.push("timeout_exhausted_failure_missing");
	if (!(report.repairQueue ?? []).some((repair) => repair.action === "escalate" && repair.paused === true)) errors.push("timeout_escalation_repair_missing");
	return { ok: errors.length === 0, errors, failureRepairValidation: failureValidation };
}

function mutateReport(report, mutate) {
	const clone = JSON.parse(JSON.stringify(report));
	if (mutate === "serialExecution") clone.peakConcurrency = 1;
	if (mutate === "missingClaimMerge") clone.claimMerge.conflicts = [];
	if (mutate === "unredactedSecret") clone.workers[0].assertions.noLiteralSecrets = false;
	if (mutate === "timeoutWithoutCancel") {
		const worker = clone.workers.find((row) => row.mode === "timeout");
		worker.cancelledAt = undefined;
		worker.assertions.timeoutCancelled = false;
	}
	if (mutate === "missingRepair") clone.repairQueue.pop();
	const validation = validateParallelProviderWorkerMatrix(clone);
	clone.failureRepairValidation = validation.failureRepairValidation;
	return clone;
}

function negativeCheck(report, id, mutate, expectedNeedle) {
	const validation = validateParallelProviderWorkerMatrix(mutateReport(report, mutate));
	return { id: `negative:${id}`, status: !validation.ok && validation.errors.some((error) => error.includes(expectedNeedle)) ? "pass" : "fail", evidence: { validation, expectedNeedle } };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "parallel-provider-worker-matrix", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return path;
}

async function runParallelMatrix(tempRoot) {
	const probeRoot = join(tempRoot, "parallel-provider-worker-matrix");
	const home = join(probeRoot, "home");
	const isolatedHome = join(home, ".repi", "agent");
	const workspace = join(probeRoot, "workspace");
	mkdirSync(isolatedHome, { recursive: true });
	mkdirSync(workspace, { recursive: true });
	const requests = [];
	const server = createParallelProviderServer(requests);
	await new Promise((resolveListen, rejectListen) => {
		server.once("error", rejectListen);
		server.listen(0, "127.0.0.1", () => {
			server.off("error", rejectListen);
			resolveListen();
		});
	});
	const port = server.address().port;
	const modelsJson = buildModelsJson(port);
	const modelsJsonPath = join(isolatedHome, "models.json");
	writeFileSync(modelsJsonPath, modelsJson, "utf8");
	const env = baseEnv(home, isolatedHome);
	const failureLedgerEvents = [];
	const repairQueue = [];
	try {
		const listModels = await new Promise((resolveChild) => {
			const startedAt = Date.now();
			let stdout = "";
			let stderr = "";
			let exitCode = null;
			let signal = null;
			const child = spawn(join(root, "repi"), ["--list-models", "parallel-"], { cwd: workspace, env, stdio: ["ignore", "pipe", "pipe"] });
			const timer = setTimeout(() => child.kill("SIGTERM"), 30000);
			child.stdout.on("data", (chunk) => {
				stdout += String(chunk);
			});
			child.stderr.on("data", (chunk) => {
				stderr += String(chunk);
			});
			child.on("close", (code, sig) => {
				clearTimeout(timer);
				exitCode = code;
				signal = sig;
				resolveChild({ stdout, stderr, exitCode, signal, elapsedMs: Date.now() - startedAt });
			});
		});
		writeFileSync(join(probeRoot, "list-models-stdout.txt"), listModels.stdout, "utf8");
		writeFileSync(join(probeRoot, "list-models-stderr.txt"), listModels.stderr, "utf8");
		const startedWorkers = await Promise.all(WORKER_CASES.map((item) => spawnRepiWorker(item, env, workspace)));
		const workerReports = [];
		for (const run of startedWorkers) {
			const rows = requests.filter((row) => row.workerId === run.item.workerId);
			const built = buildWorkerReport(run, rows, probeRoot, tempRoot, modelsJson);
			workerReports.push(built.report);
			if (run.item.mode !== "pass") {
				const { failure, repair } = failureRepairFromGap({
					root: tempRoot,
					source: SOURCE,
					scope: `${SOURCE}:${run.item.workerId}`,
					category: "runtime_failed",
					reason: `${run.item.mode} in ${run.item.providerName}/${run.item.modelId}`,
					failedGates: [`parallel_worker_${run.item.mode}_handled`],
					artifacts: built.artifacts,
					attempt: run.item.attempt,
					maxAttempts: run.item.maxAttempts,
					status: run.item.status,
					action: run.item.action,
					providerAllowed: run.item.status !== "exhausted",
					liveAllowed: false,
					paused: run.item.status === "exhausted",
					commands: [`npm run gate:parallel-provider-worker-matrix -- --worker ${run.item.workerId}`, "node scripts/reverse-agent/parallel-provider-worker-matrix-gate.mjs . --strict --no-write"],
					expectedArtifacts: built.artifacts.map((artifact) => artifact.path),
					regressionGates: ["gate:parallel-provider-worker-matrix", "gate:provider-runtime-matrix", "gate:provider-failure-injection"],
					verificationCommand: "npm run gate:parallel-provider-worker-matrix",
				});
				failureLedgerEvents.push(failure);
				repairQueue.push(repair);
				built.report.failureId = failure.id;
				built.report.repairId = repair.repairId;
				built.report.assertions.providerWorkerFailureRepairLinked = failure.repairId === repair.repairId && repair.fromFailureId === failure.id && repair.signature === failure.signature;
				built.report.status = built.report.status === "blocked" || !built.report.assertions.providerWorkerFailureRepairLinked ? "blocked" : built.report.status;
			}
		}
		const peakConcurrency = computePeakConcurrency(startedWorkers);
		const claimMerge = buildClaimMerge(workerReports);
		const failureRepairValidation = validateFailureRepairBatch({ failures: failureLedgerEvents, repairs: repairQueue });
		const writeback = appendFailureRepairWriteback(tempRoot, failureLedgerEvents, repairQueue, failureLedgerEvents[0]?.evidenceWriteback);
		const writtenFailures = existsSync(join(tempRoot, writeback.failurePath))
			? readFileSync(join(tempRoot, writeback.failurePath), "utf8").trim().split(/\n+/).filter(Boolean).map((line) => JSON.parse(line))
			: [];
		const writtenRepairs = existsSync(join(tempRoot, writeback.repairPath))
			? readFileSync(join(tempRoot, writeback.repairPath), "utf8").trim().split(/\n+/).filter(Boolean).map((line) => JSON.parse(line))
			: [];
		const writebackValidation = validateFailureRepairBatch({ failures: writtenFailures, repairs: writtenRepairs });
		const listText = `${listModels.stdout}\n${listModels.stderr}`;
		const report = {
			kind: "ParallelProviderWorkerMatrixV1",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			poolId: "parallel-provider-worker-matrix-smoke",
			isolatedHome,
			workspace,
			modelsJsonPath,
			maxConcurrency: WORKER_CASES.length,
			peakConcurrency,
			listModels: {
				status: listModels.exitCode === 0 && WORKER_CASES.every((item) => listText.includes(item.providerName) && listText.includes(item.modelId)) ? "pass" : "blocked",
				stdoutSha256: sha256(listModels.stdout),
				stderrSha256: sha256(listModels.stderr),
				providers: [...new Set(WORKER_CASES.filter((item) => listText.includes(item.providerName)).map((item) => item.providerName))],
			},
			workers: workerReports,
			claimMerge,
			failureLedgerEvents,
			repairQueue,
			failureRepairValidation,
			writebackProbe: {
				status: writebackValidation.ok && writtenFailures.length === failureLedgerEvents.length && writtenRepairs.length === repairQueue.length ? "pass" : "blocked",
				writeback,
				validation: writebackValidation,
			},
		};
		const validation = validateParallelProviderWorkerMatrix(report);
		return { report, validation };
	} finally {
		await closeServer(server);
	}
}

async function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-parallel-provider-worker-matrix-"));
	const checks = [];
	let matrix;
	try {
		matrix = await runParallelMatrix(tempRoot);
		const report = matrix.report;
		checks.push({ id: "runtime:parallel-provider-worker-matrix-validation", status: matrix.validation.ok ? "pass" : "fail", evidence: { validation: matrix.validation, peakConcurrency: report.peakConcurrency, workers: report.workers.map((worker) => ({ workerId: worker.workerId, status: worker.status, request: worker.request, assertions: worker.assertions, failureId: worker.failureId, repairId: worker.repairId })) } });
		checks.push({ id: "runtime:parallel-provider-worker-concurrency", status: report.peakConcurrency >= 2 && report.peakConcurrency <= report.maxConcurrency ? "pass" : "fail", evidence: { peakConcurrency: report.peakConcurrency, maxConcurrency: report.maxConcurrency } });
		checks.push({ id: "runtime:parallel-provider-worker-list-models", status: report.listModels.status === "pass" ? "pass" : "fail", evidence: report.listModels });
		checks.push({ id: "runtime:parallel-provider-worker-openai-pass", status: report.workers.some((worker) => worker.api === "openai-completions" && worker.mode === "pass" && worker.status === "pass") ? "pass" : "fail", evidence: report.workers.filter((worker) => worker.api === "openai-completions") });
		checks.push({ id: "runtime:parallel-provider-worker-anthropic-pass", status: report.workers.some((worker) => worker.api === "anthropic-messages" && worker.status === "pass") ? "pass" : "fail", evidence: report.workers.filter((worker) => worker.api === "anthropic-messages") });
		checks.push({ id: "runtime:parallel-provider-worker-failure-repair", status: report.workers.some((worker) => worker.mode === "failure" && worker.status === "repair_queued" && worker.assertions.providerWorkerFailureRepairLinked) && report.failureRepairValidation.ok ? "pass" : "fail", evidence: { failureRepairValidation: report.failureRepairValidation, failureWorkers: report.workers.filter((worker) => worker.mode === "failure") } });
		checks.push({ id: "runtime:parallel-provider-worker-timeout-cancel", status: report.workers.some((worker) => worker.mode === "timeout" && worker.status === "cancelled" && worker.assertions.timeoutCancelled) ? "pass" : "fail", evidence: report.workers.filter((worker) => worker.mode === "timeout") });
		checks.push({ id: "runtime:parallel-provider-worker-claim-merge", status: report.claimMerge.conflicts.some((conflict) => conflict.status === "resolved" && conflict.winner && conflict.evidenceRefs.length >= 2) ? "pass" : "fail", evidence: report.claimMerge });
		checks.push({ id: "runtime:parallel-provider-worker-env-redaction", status: report.workers.every((worker) => worker.assertions.apiKeyEnvRefOnly && worker.assertions.authorizationFromEnv && worker.assertions.noLiteralSecrets) ? "pass" : "fail", evidence: report.workers.map((worker) => ({ workerId: worker.workerId, apiKeyEnvRefOnly: worker.assertions.apiKeyEnvRefOnly, authorizationFromEnv: worker.assertions.authorizationFromEnv, noLiteralSecrets: worker.assertions.noLiteralSecrets, authHeaderSha256: worker.request.authHeaderSha256 })) });
		checks.push({ id: "runtime:parallel-provider-worker-writeback", status: report.writebackProbe.status === "pass" ? "pass" : "fail", evidence: report.writebackProbe });
		checks.push(negativeCheck(report, "parallel-worker-serial-execution", "serialExecution", "peakConcurrency_lt_2"));
		checks.push(negativeCheck(report, "parallel-worker-missing-claim-merge", "missingClaimMerge", "duplicate_mergeKey_unresolved"));
		checks.push(negativeCheck(report, "parallel-worker-unredacted-secret", "unredactedSecret", "literal_secret_leak"));
		checks.push(negativeCheck(report, "parallel-worker-timeout-without-cancel", "timeoutWithoutCancel", "timeout_without_cancel"));
		checks.push(negativeCheck(report, "parallel-worker-missing-repair", "missingRepair", "failure_repair_validation_not_ok"));
	} catch (error) {
		checks.push({ id: "runtime:parallel-provider-worker-matrix-exception", status: "fail", evidence: { error: String(error), stack: error?.stack } });
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	checks.push(
		markerCheck("code:parallel-provider-worker-matrix-types", "packages/coding-agent/src/core/recon-profile.ts", ["type ParallelProviderWorkerMatrixV1", "type ParallelProviderWorkerMatrixWorkerV1", "function verifyParallelProviderWorkerMatrixV1", "claimAwareProviderWorkerMerge"]),
		markerCheck("docs:parallel-provider-worker-matrix", "README.md", ["Parallel provider worker matrix", "gate:parallel-provider-worker-matrix", "ParallelProviderWorkerMatrixV1", "claim-aware provider worker merge"]),
		markerCheck("npm:parallel-provider-worker-matrix", "package.json", ["gate:parallel-provider-worker-matrix", "parallel-provider-worker-matrix-gate.mjs"]),
		markerCheck("harness:parallel-provider-worker-matrix", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:parallel-provider-worker-matrix", "parallel:provider-worker-matrix-hard-eval", "ParallelProviderWorkerMatrixV1"]),
		markerCheck("autonomy:parallel-provider-worker-matrix", "scripts/reverse-agent/autonomy-control-plane.mjs", ["parallel_provider_worker_matrix_gate", "ParallelProviderWorkerMatrixV1", "runtime:parallel-provider-worker-concurrency", "runtime:parallel-provider-worker-timeout-cancel"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-parallel-provider-worker-matrix-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Parallel Provider Worker Matrix Gate");
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

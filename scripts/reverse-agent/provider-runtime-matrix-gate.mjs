#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_PROVIDER_RUNTIME_MATRIX_TMP === "1";
const sha256 = (value) => createHash("sha256").update(String(value ?? "")).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");

const PROVIDER_CASES = [
	{
		caseId: "openai-compatible-stream",
		providerName: "child-openai-compatible",
		modelId: "child/openai-mock",
		api: "openai-completions",
		baseUrlKind: "openai-v1",
		apiKeyEnv: "REPI_CHILD_OPENAI_MATRIX_KEY",
		marker: "OPENAI_MATRIX_OK",
		expectedPath: "/v1/chat/completions",
		authHeader: "authorization",
	},
	{
		caseId: "anthropic-compatible-stream",
		providerName: "child-anthropic-compatible",
		modelId: "child/anthropic-mock",
		api: "anthropic-messages",
		baseUrlKind: "anthropic-root",
		apiKeyEnv: "REPI_CHILD_ANTHROPIC_MATRIX_KEY",
		marker: "ANTHROPIC_MATRIX_OK",
		expectedPath: "/v1/messages",
		authHeader: "x-api-key",
	},
];

const PROVIDER_RUNTIME_MATRIX_NEGATIVE_MARKERS = ["negative:missing-env-ref", "negative:wrong-endpoint", "negative:update-banner-leak", "negative:missing-anthropic-case", "negative:list-models-missing"];

const SECRET_VALUES = new Map([
	["REPI_CHILD_OPENAI_MATRIX_KEY", "matrix-openai-token"],
	["REPI_CHILD_ANTHROPIC_MATRIX_KEY", "matrix-anthropic-token"],
]);

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function closeServer(server) {
	return new Promise((resolveClose) => server.close(() => resolveClose()));
}

function sseData(payload) {
	return `data: ${JSON.stringify(payload)}\n\n`;
}

function anthropicEvent(event, payload) {
	return `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
}

function redactHeaders(headers) {
	const out = {};
	for (const [key, value] of Object.entries(headers ?? {})) {
		const lower = key.toLowerCase();
		if (["authorization", "x-api-key", "api-key", "cf-aig-authorization"].includes(lower)) {
			out[lower] = value ? `<redacted:${sha256(String(value)).slice(0, 16)}>` : undefined;
		} else if (["content-type", "user-agent", "anthropic-version", "anthropic-beta", "accept"].includes(lower)) {
			out[lower] = value;
		}
	}
	return out;
}

function createMockProviderServer(requests) {
	const server = createServer((req, res) => {
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
			if (req.method === "POST" && req.url === "/v1/chat/completions") {
				res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache" });
				res.write(sseData({ id: "chatcmpl-repi-provider-matrix", object: "chat.completion.chunk", created: 0, model: parsed?.model ?? "child/openai-mock", choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }] }));
				res.write(sseData({ id: "chatcmpl-repi-provider-matrix", object: "chat.completion.chunk", created: 0, model: parsed?.model ?? "child/openai-mock", choices: [{ index: 0, delta: { content: "OPENAI_MATRIX_OK" }, finish_reason: null }] }));
				res.write(sseData({ id: "chatcmpl-repi-provider-matrix", object: "chat.completion.chunk", created: 0, model: parsed?.model ?? "child/openai-mock", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 8, completion_tokens: 3, total_tokens: 11 } }));
				res.write("data: [DONE]\n\n");
				res.end();
				return;
			}
			if (req.method === "POST" && req.url === "/v1/messages") {
				res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache" });
				res.write(anthropicEvent("message_start", { type: "message_start", message: { id: "msg_repi_provider_matrix", type: "message", role: "assistant", content: [], model: parsed?.model ?? "child/anthropic-mock", stop_reason: null, stop_sequence: null, usage: { input_tokens: 8, output_tokens: 0 } } }));
				res.write(anthropicEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }));
				res.write(anthropicEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "ANTHROPIC_MATRIX_OK" } }));
				res.write(anthropicEvent("content_block_stop", { type: "content_block_stop", index: 0 }));
				res.write(anthropicEvent("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 3 } }));
				res.write(anthropicEvent("message_stop", { type: "message_stop" }));
				res.end();
				return;
			}
			res.writeHead(404, { "content-type": "application/json" });
			res.end(JSON.stringify({ error: "not found" }));
		});
	});
	return server;
}

function buildModelsJson(port) {
	const providers = {};
	for (const item of PROVIDER_CASES) {
		providers[item.providerName] = {
			baseUrl: item.baseUrlKind === "openai-v1" ? `http://127.0.0.1:${port}/v1` : `http://127.0.0.1:${port}`,
			api: item.api,
			apiKey: `$${item.apiKeyEnv}`,
			compat:
				item.api === "openai-completions"
					? { supportsDeveloperRole: false, supportsReasoningEffort: false, supportsStore: false, supportsStrictMode: false, supportsUsageInStreaming: false, maxTokensField: "max_tokens" }
					: { supportsLongCacheRetention: false, sendSessionAffinityHeaders: false, supportsCacheControlOnTools: false, supportsEagerToolInputStreaming: true },
			models: [{ id: item.modelId, contextWindow: 8192, maxTokens: 1024 }],
		};
	}
	return `${JSON.stringify({ providers }, null, 2)}\n`;
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
	return { command, args, cwd, stdout, stderr, exitCode, signal, timedOut, spawnError: spawnError?.message, elapsedMs: Math.max(0, Date.now() - started) };
}

function baseEnv(home, isolatedHome) {
	const env = {
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
	};
	for (const [name, value] of SECRET_VALUES) env[name] = value;
	return env;
}

function secretRegex() {
	const escaped = [...SECRET_VALUES.values()].map((value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
	return new RegExp(`sk-[A-Za-z0-9]|ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|${escaped.join("|")}`, "i");
}

function requestForCase(requests, item) {
	return requests.find((request) => request.url === item.expectedPath && request.parsed?.model === item.modelId);
}

function buildCaseReport(item, run, request, probeRoot, modelsJson, requestLogText, transcriptText) {
	const expectedSecret = SECRET_VALUES.get(item.apiKeyEnv);
	const headerValue = item.authHeader === "authorization" ? request?.headers?.authorization : request?.headers?.[item.authHeader];
	const headerMatches = item.authHeader === "authorization" ? headerValue === `Bearer ${expectedSecret}` : headerValue === expectedSecret;
	const combined = `${run.stdout}\n${run.stderr}\n${modelsJson}\n${requestLogText}\n${transcriptText}`;
	const assertions = {
		exitOk: run.exitCode === 0 && !run.timedOut && !run.spawnError,
		requestSeen: !!request && request.method === "POST" && request.url === item.expectedPath,
		modelMatched: request?.parsed?.model === item.modelId,
		streamingUsed: request?.parsed?.stream === true,
		stdoutMarkerObserved: run.stdout.includes(item.marker),
		apiKeyEnvRefOnly: modelsJson.includes(`"$${item.apiKeyEnv}"`) && !modelsJson.includes(String(expectedSecret)),
		authorizationFromEnv: headerMatches,
		noPiHomeImport: !new RegExp("(^|[\\s\"'])~?\\/?\\.pi\\/", "i").test(combined),
		noUpdateBanner: !/Update Available|pi\.dev\/changelog|Run pi update/i.test(combined),
		noLiteralSecrets: !secretRegex().test(combined),
		transcriptCaptured: transcriptText.includes("ProviderRuntimeMatrixCaseTranscriptV1"),
		requestLogCaptured: requestLogText.includes("ProviderRuntimeMatrixRequestLogV1"),
	};
	const errors = Object.entries(assertions).filter(([, ok]) => !ok).map(([key]) => `assertion_failed:${key}`);
	return {
		kind: "ProviderRuntimeMatrixCaseV1",
		schemaVersion: 1,
		caseId: item.caseId,
		providerName: item.providerName,
		api: item.api,
		modelId: item.modelId,
		expectedPath: item.expectedPath,
		authHeader: item.authHeader,
		status: errors.length ? "blocked" : "pass",
		exitCode: run.exitCode,
		signal: run.signal,
		elapsedMs: run.elapsedMs,
		stdoutPath: join(probeRoot, `${item.caseId}-stdout.txt`),
		stderrPath: join(probeRoot, `${item.caseId}-stderr.txt`),
		stdoutSha256: sha256(run.stdout),
		stderrSha256: sha256(run.stderr),
		request: {
			method: request?.method,
			path: request?.url,
			model: request?.parsed?.model,
			stream: request?.parsed?.stream,
			authHeaderSha256: headerValue ? sha256(String(headerValue)) : undefined,
			bodySha256: request?.body ? sha256(request.body) : undefined,
		},
		assertions,
		errors,
	};
}

function validateMatrixReport(report) {
	const errors = [];
	if (report.kind !== "ProviderRuntimeMatrixV1") errors.push("matrix.kind_invalid");
	if (!Array.isArray(report.cases) || report.cases.length < 2) errors.push("matrix.case_count_lt_2");
	for (const item of report.cases ?? []) {
		const prefix = `case:${item.caseId}`;
		if (item.status !== "pass") errors.push(`${prefix}.status_not_pass`);
		if (!item.providerName?.startsWith("child-")) errors.push(`${prefix}.provider_not_child_fixture`);
		if (!item.modelId?.startsWith("child/")) errors.push(`${prefix}.model_not_child_fixture`);
		if (!item.assertions?.exitOk) errors.push(`${prefix}.exit_not_ok`);
		if (!item.assertions?.requestSeen) errors.push(`${prefix}.request_missing`);
		if (!item.assertions?.modelMatched) errors.push(`${prefix}.model_mismatch`);
		if (!item.assertions?.streamingUsed) errors.push(`${prefix}.stream_missing`);
		if (!item.assertions?.stdoutMarkerObserved) errors.push(`${prefix}.stdout_marker_missing`);
		if (!item.assertions?.apiKeyEnvRefOnly) errors.push(`${prefix}.api_key_not_env_ref`);
		if (!item.assertions?.authorizationFromEnv) errors.push(`${prefix}.authorization_not_env`);
		if (!item.assertions?.noPiHomeImport) errors.push(`${prefix}.pi_home_leak`);
		if (!item.assertions?.noUpdateBanner) errors.push(`${prefix}.update_banner_leak`);
		if (!item.assertions?.noLiteralSecrets) errors.push(`${prefix}.literal_secret_leak`);
		if (!item.assertions?.requestLogCaptured || !item.assertions?.transcriptCaptured) errors.push(`${prefix}.artifacts_missing`);
		if (item.api === "openai-completions" && item.request?.path !== "/v1/chat/completions") errors.push(`${prefix}.openai_endpoint_invalid`);
		if (item.api === "anthropic-messages" && item.request?.path !== "/v1/messages") errors.push(`${prefix}.anthropic_endpoint_invalid`);
	}
	if (report.listModels?.status !== "pass") errors.push("list_models_not_pass");
	for (const provider of PROVIDER_CASES.map((item) => item.providerName)) {
		if (!report.listModels?.providers?.includes(provider)) errors.push(`list_models_missing:${provider}`);
	}
	return { ok: errors.length === 0, errors };
}

function mutateReport(report, mutate) {
	const clone = JSON.parse(JSON.stringify(report));
	if (mutate === "missingEnvRef") clone.cases[0].assertions.apiKeyEnvRefOnly = false;
	if (mutate === "wrongEndpoint") clone.cases[0].request.path = "/wrong";
	if (mutate === "updateBannerLeak") clone.cases[0].assertions.noUpdateBanner = false;
	if (mutate === "missingAnthropic") clone.cases = clone.cases.filter((item) => item.api !== "anthropic-messages");
	if (mutate === "listModelsMissing") clone.listModels.providers = clone.listModels.providers.filter((item) => item !== "child-openai-compatible");
	return clone;
}

function negativeCheck(report, id, mutate, expectedNeedle) {
	const result = validateMatrixReport(mutateReport(report, mutate));
	return { id: `negative:${id}`, status: !result.ok && result.errors.some((error) => error.includes(expectedNeedle)) ? "pass" : "fail", evidence: { validation: result, expectedNeedle } };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "provider-runtime-matrix", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return path;
}

async function runMatrix(tempRoot) {
	const probeRoot = join(tempRoot, "provider-runtime-matrix");
	const home = join(probeRoot, "home");
	const isolatedHome = join(home, ".repi", "agent");
	const workspace = join(probeRoot, "workspace");
	mkdirSync(isolatedHome, { recursive: true });
	mkdirSync(workspace, { recursive: true });
	const requests = [];
	const server = createMockProviderServer(requests);
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
	const startedAt = new Date().toISOString();
	try {
		const listRun = await spawnRepi(["--list-models", "child-"], env, workspace, 30000);
		writeFileSync(join(probeRoot, "list-models-stdout.txt"), listRun.stdout, "utf8");
		writeFileSync(join(probeRoot, "list-models-stderr.txt"), listRun.stderr, "utf8");
		const caseReports = [];
		for (const item of PROVIDER_CASES) {
			const beforeCount = requests.length;
			const run = await spawnRepi(["--provider", item.providerName, "--model", item.modelId, "--no-tools", "--no-session", "--thinking", "off", "-p", `Reply exactly: ${item.marker}`], env, workspace, 45000);
			writeFileSync(join(probeRoot, `${item.caseId}-stdout.txt`), run.stdout, "utf8");
			writeFileSync(join(probeRoot, `${item.caseId}-stderr.txt`), run.stderr, "utf8");
			const request = requestForCase(requests.slice(beforeCount), item);
			const redactedRequestLog = {
				kind: "ProviderRuntimeMatrixRequestLogV1",
				caseId: item.caseId,
				requests: requests.slice(beforeCount).map((row) => ({ method: row.method, path: row.url, headers: redactHeaders(row.headers), model: row.parsed?.model, stream: row.parsed?.stream, bodySha256: sha256(row.body) })),
			};
			const requestLogText = `${JSON.stringify(redactedRequestLog, null, 2)}\n`;
			const transcriptText = `${JSON.stringify({ kind: "ProviderRuntimeMatrixCaseTranscriptV1", caseId: item.caseId, providerName: item.providerName, api: item.api, modelId: item.modelId, stdoutSha256: sha256(run.stdout), stderrSha256: sha256(run.stderr), requestLogSha256: sha256(requestLogText), startedAt, endedAt: new Date().toISOString() })}\n`;
			writeFileSync(join(probeRoot, `${item.caseId}-request-log.json`), requestLogText, "utf8");
			writeFileSync(join(probeRoot, `${item.caseId}-transcript.jsonl`), transcriptText, "utf8");
			caseReports.push(buildCaseReport(item, run, request, probeRoot, modelsJson, requestLogText, transcriptText));
		}
		const listModelsText = `${listRun.stdout}\n${listRun.stderr}`;
		const providersSeen = PROVIDER_CASES.filter((item) => listModelsText.includes(item.providerName) && listModelsText.includes(item.modelId)).map((item) => item.providerName);
		const requestLogText = `${JSON.stringify({ kind: "ProviderRuntimeMatrixRequestLogV1", requests: requests.map((row) => ({ method: row.method, path: row.url, headers: redactHeaders(row.headers), model: row.parsed?.model, stream: row.parsed?.stream, bodySha256: sha256(row.body) })) }, null, 2)}\n`;
		writeFileSync(join(probeRoot, "request-log.json"), requestLogText, "utf8");
		const report = {
			kind: "ProviderRuntimeMatrixV1",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			modelsJsonPath,
			requestLogPath: join(probeRoot, "request-log.json"),
			isolatedHome,
			workspace,
			listModels: {
				status: listRun.exitCode === 0 && PROVIDER_CASES.every((item) => listModelsText.includes(item.providerName) && listModelsText.includes(item.modelId)) ? "pass" : "blocked",
				providers: providersSeen,
				stdoutSha256: sha256(listRun.stdout),
				stderrSha256: sha256(listRun.stderr),
			},
			cases: caseReports,
		};
		const validation = validateMatrixReport(report);
		return { report, validation };
	} finally {
		await closeServer(server);
	}
}

async function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-provider-runtime-matrix-"));
	const checks = [];
	let matrix;
	try {
		matrix = await runMatrix(tempRoot);
		const report = matrix.report;
		checks.push({ id: "runtime:provider-matrix-validation", status: matrix.validation.ok ? "pass" : "fail", evidence: { validation: matrix.validation, cases: report.cases.map((item) => ({ caseId: item.caseId, status: item.status, request: item.request, assertions: item.assertions })) } });
		checks.push({ id: "runtime:provider-matrix-list-models", status: report.listModels.status === "pass" ? "pass" : "fail", evidence: report.listModels });
		for (const item of report.cases) {
			checks.push({ id: `runtime:provider-matrix-${item.api}`, status: item.status === "pass" ? "pass" : "fail", evidence: { caseId: item.caseId, providerName: item.providerName, modelId: item.modelId, request: item.request, assertions: item.assertions, errors: item.errors } });
		}
		checks.push({ id: "runtime:provider-matrix-env-ref-only", status: report.cases.every((item) => item.assertions.apiKeyEnvRefOnly && item.assertions.authorizationFromEnv && item.assertions.noLiteralSecrets) ? "pass" : "fail", evidence: report.cases.map((item) => ({ caseId: item.caseId, apiKeyEnvRefOnly: item.assertions.apiKeyEnvRefOnly, authorizationFromEnv: item.assertions.authorizationFromEnv, noLiteralSecrets: item.assertions.noLiteralSecrets, authHeaderSha256: item.request.authHeaderSha256 })) });
		checks.push({ id: "runtime:provider-matrix-artifacts", status: report.cases.every((item) => item.assertions.requestLogCaptured && item.assertions.transcriptCaptured && item.stdoutSha256 && item.stderrSha256) ? "pass" : "fail", evidence: { requestLogPath: report.requestLogPath, cases: report.cases.map((item) => ({ caseId: item.caseId, stdoutSha256: item.stdoutSha256, stderrSha256: item.stderrSha256, requestBodySha256: item.request.bodySha256 })) } });
		checks.push(negativeCheck(report, "missing-env-ref", "missingEnvRef", "api_key_not_env_ref"));
		checks.push(negativeCheck(report, "wrong-endpoint", "wrongEndpoint", "openai_endpoint_invalid"));
		checks.push(negativeCheck(report, "update-banner-leak", "updateBannerLeak", "update_banner_leak"));
		checks.push(negativeCheck(report, "missing-anthropic-case", "missingAnthropic", "case_count_lt_2"));
		checks.push(negativeCheck(report, "list-models-missing", "listModelsMissing", "list_models_missing"));
	} catch (error) {
		checks.push({ id: "runtime:provider-matrix-exception", status: "fail", evidence: { error: String(error), stack: error?.stack } });
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	checks.push(
		markerCheck("code:provider-runtime-matrix-types", "packages/coding-agent/src/core/recon-profile.ts", ["type ProviderRuntimeMatrixV1", "function verifyProviderRuntimeMatrixV1", "ProviderRuntimeMatrixCaseV1"]),
		markerCheck("docs:provider-runtime-matrix", "README.md", ["Provider runtime matrix", "gate:provider-runtime-matrix", "ProviderRuntimeMatrixV1", "OpenAI-compatible", "Anthropic-compatible"]),
		markerCheck("npm:provider-runtime-matrix", "package.json", ["gate:provider-runtime-matrix", "provider-runtime-matrix-gate.mjs"]),
		markerCheck("harness:provider-runtime-matrix", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:provider-runtime-matrix", "provider:runtime-matrix-hard-eval", "ProviderRuntimeMatrixV1"]),
		markerCheck("autonomy:provider-runtime-matrix", "scripts/reverse-agent/autonomy-control-plane.mjs", ["provider_runtime_matrix_gate", "ProviderRuntimeMatrixV1", "runtime:provider-matrix-openai-completions", "runtime:provider-matrix-anthropic-messages"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-provider-runtime-matrix-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Provider Runtime Matrix Gate");
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

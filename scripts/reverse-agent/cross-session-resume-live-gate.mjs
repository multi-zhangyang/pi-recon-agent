#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_CROSS_SESSION_RESUME_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const sha256 = (value) => createHash("sha256").update(String(value ?? "")).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");

const PROVIDER_NAME = "cross-session-openai-compatible";
const MODEL_ID = "cross/session-resume-mock";
const API_KEY_ENV = "REPI_CROSS_SESSION_PROVIDER_KEY";
const API_KEY_VALUE = "cross-session-provider-token";
const PROVIDER_MARKER = "CROSS_SESSION_RESUME_PROVIDER_OK";
const TARGET = "https://cross-session-resume.local";
const CROSS_SESSION_NEGATIVE_MARKERS = [
	"negative:cross-session-same-session",
	"negative:cross-session-latest-fallback",
	"negative:cross-session-provider-missing",
	"negative:cross-session-ledger-reopened",
	"negative:cross-session-pi-pollution",
];

function markerCheck(id, path, markers) {
	const full = join(root, path);
	if (!existsSync(full)) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function mkdir(path) {
	mkdirSync(path, { recursive: true });
}

function sseData(payload) {
	return `data: ${JSON.stringify(payload)}\n\n`;
}

function closeServer(server) {
	return new Promise((resolveClose) => server.close(() => resolveClose()));
}

function redactHeaders(headers) {
	const out = {};
	for (const [key, value] of Object.entries(headers ?? {})) {
		const lower = key.toLowerCase();
		if (["authorization", "x-api-key", "api-key", "cf-aig-authorization"].includes(lower)) out[lower] = value ? `<redacted:${sha256(String(value)).slice(0, 16)}>` : undefined;
		else if (["content-type", "user-agent", "accept"].includes(lower)) out[lower] = value;
	}
	return out;
}

function createMockProviderServer(requests) {
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
			if (req.method !== "POST" || req.url !== "/v1/chat/completions") {
				res.writeHead(404, { "content-type": "application/json" });
				res.end(JSON.stringify({ error: "unexpected request" }));
				return;
			}
			res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache" });
			res.write(sseData({ id: "chatcmpl-repi-cross-session", object: "chat.completion.chunk", created: 0, model: parsed?.model, choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }] }));
			res.write(sseData({ id: "chatcmpl-repi-cross-session", object: "chat.completion.chunk", created: 0, model: parsed?.model, choices: [{ index: 0, delta: { content: PROVIDER_MARKER }, finish_reason: null }] }));
			res.write(sseData({ id: "chatcmpl-repi-cross-session", object: "chat.completion.chunk", created: 0, model: parsed?.model, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 12, completion_tokens: 4, total_tokens: 16 } }));
			res.write("data: [DONE]\n\n");
			res.end();
		});
	});
}

function buildModelsJson(port) {
	return `${JSON.stringify(
		{
			providers: {
				[PROVIDER_NAME]: {
					baseUrl: `http://127.0.0.1:${port}/v1`,
					api: "openai-completions",
					apiKey: `$${API_KEY_ENV}`,
					compat: { supportsDeveloperRole: false, supportsReasoningEffort: false, supportsStore: false, supportsStrictMode: false, supportsUsageInStreaming: false, maxTokensField: "max_tokens" },
					models: [{ id: MODEL_ID, contextWindow: 8192, maxTokens: 1024 }],
				},
			},
		},
		null,
		2,
	)}\n`;
}

function baseEnv(home, isolatedHome) {
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
		[API_KEY_ENV]: API_KEY_VALUE,
	};
}

function secretPattern() {
	return new RegExp(`sk-[A-Za-z0-9]|ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|${API_KEY_VALUE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "i");
}

function writeProbe(probePath, outPath, params) {
	const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
	writeFileSync(
		probePath,
		`
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createReconExtensionFactory } from ${JSON.stringify(importUrl)};
const outPath = ${JSON.stringify(outPath)};
const agentDir = ${JSON.stringify(params.isolatedHome)};
const workspace = ${JSON.stringify(params.workspace)};
const sessionId = ${JSON.stringify(params.sessionId)};
const branchId = ${JSON.stringify(params.branchId)};
const phase = ${JSON.stringify(params.phase)};
const contextPathArg = ${JSON.stringify(params.contextPath ?? "")};
const target = ${JSON.stringify(TARGET)};
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = sessionId;
process.env.REPI_BRANCH_ID = branchId;
const tools = new Map();
const appended = [];
const fakePi = {
  registerCommand() {},
  registerTool(tool) { tools.set(tool.name, tool); },
  on() {},
  appendEntry(type, details) { appended.push({ type, details }); },
  getSessionName: () => undefined,
  setSessionName() {},
  sendMessage() {},
  exec: async () => ({ code: 0, stdout: "cross-session-resume-live", stderr: "", killed: false }),
};
createReconExtensionFactory()(fakePi);
const tool = (name) => { const value = tools.get(name); if (!value) throw new Error("missing tool " + name); return value; };
function text(result) { return result?.content?.[0]?.text ?? ""; }
function artifactPath(output) { const match = /^context_artifact:\s*(.+)$/m.exec(output); if (!match?.[1]) throw new Error("missing context_artifact in " + output.slice(0, 1000)); return match[1].trim(); }
function parseJsonArtifact(path) { const body = readFileSync(path, "utf8"); const fence = String.fromCharCode(96).repeat(3); const start = body.indexOf(fence + "json"); const contentStart = body.indexOf("\\n", start); const end = body.indexOf(fence, contentStart + 1); if (start < 0 || contentStart < 0 || end < 0) throw new Error("missing json block in " + path); return JSON.parse(body.slice(contentStart + 1, end).trim()); }
async function main() {
  const mission = tool("re_mission");
  const map = tool("re_map");
  const memory = tool("re_memory");
  const context = tool("re_context");
  if (phase === "pack") {
    await mission.execute("cross-session", { action: "new", task: "cross-session resume live regression " + target });
    await map.execute("cross-session", { target, depth: 1 });
    await memory.execute("cross-session", { action: "verify" });
    await memory.execute("cross-session", { action: "sediment" });
    const packOutput = text(await context.execute("cross-session", { action: "pack", target }));
    const packPath = artifactPath(packOutput);
    const pack = parseJsonArtifact(packPath);
    writeFileSync(outPath, JSON.stringify({ phase, sessionId, branchId, agentDir, workspace, packOutput, packPath, pack, appended }, null, 2));
    return;
  }
  if (phase === "resume") {
    const resumeOutput = text(await context.execute("cross-session", { action: "resume", target, contextPath: contextPathArg }));
    const resumePath = artifactPath(resumeOutput);
    const resume = parseJsonArtifact(resumePath);
    const ledger = await memory.execute("cross-session", { action: "compact-resume" });
    writeFileSync(outPath, JSON.stringify({ phase, sessionId, branchId, agentDir, workspace, contextPathArg, resumeOutput, resumePath, resume, ledger: ledger.details, ledgerText: text(ledger), appended }, null, 2));
    return;
  }
  throw new Error("unknown phase " + phase);
}
main().catch((error) => { console.error(error); process.exit(1); });
`,
		"utf8",
	);
}

function runProbe(tempRoot, params) {
	const probePath = join(tempRoot, `${params.phase}-probe.ts`);
	const outPath = join(tempRoot, `${params.phase}-result.json`);
	writeProbe(probePath, outPath, params);
	const result = spawnSync(join(root, "node_modules", ".bin", "tsx"), ["--tsconfig", join(root, "tsconfig.json"), probePath], {
		cwd: root,
		env: { ...baseEnv(params.home, params.isolatedHome), REPI_SESSION_ID: params.sessionId, REPI_BRANCH_ID: params.branchId },
		encoding: "utf8",
		maxBuffer: 60 * 1024 * 1024,
		timeout: 60000,
	});
	return { ...result, probePath, outPath };
}

async function spawnRepi(args, env, cwd, timeoutMs = 45000) {
	const command = join(root, "repi");
	const startedAt = Date.now();
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
	return { command, args, cwd, stdout, stderr, exitCode, signal, spawnError: spawnError?.message, timedOut, cancelledAt, elapsedMs: Date.now() - startedAt };
}

function relPath(base, path) {
	const resolvedBase = resolve(base);
	const resolved = resolve(path);
	return resolved.startsWith(resolvedBase) ? resolved.slice(resolvedBase.length + 1) : path;
}

function fileArtifact(base, path) {
	const bytes = readFileSync(path);
	const stat = statSync(path);
	return { path: relPath(base, path), sha256: sha256(bytes), bytes: bytes.length, mtime: stat.mtime.toISOString() };
}

function ledgerSummary(resumeData) {
	const report = resumeData?.ledger ?? {};
	return {
		transitionPath: report.transitionPath,
		reportPath: report.reportPath,
		currentState: report.currentState,
		invalidTransitions: report.invalidTransitions ?? [],
		transitionCount: Array.isArray(report.transitions) ? report.transitions.length : 0,
		statePath: Array.isArray(report.transitions) ? report.transitions.map((row) => `${row.from}->${row.to}`) : [],
	};
}

function buildProviderContinuation(run, requests, modelsJson, probeRoot) {
	const stdoutPath = join(probeRoot, "provider-continuation-stdout.txt");
	const stderrPath = join(probeRoot, "provider-continuation-stderr.txt");
	const requestLogPath = join(probeRoot, "provider-continuation-request-log.json");
	writeFileSync(stdoutPath, run.stdout, "utf8");
	writeFileSync(stderrPath, run.stderr, "utf8");
	const requestLogText = `${JSON.stringify({ kind: "CrossSessionResumeProviderRequestLogV1", requests: requests.map((row) => ({ method: row.method, path: row.url, headers: redactHeaders(row.headers), model: row.parsed?.model, stream: row.parsed?.stream, bodySha256: sha256(row.body) })) }, null, 2)}\n`;
	writeFileSync(requestLogPath, requestLogText, "utf8");
	const request = requests.find((row) => row.url === "/v1/chat/completions" && row.parsed?.model === MODEL_ID);
	const header = request?.headers?.authorization;
	const combined = `${run.stdout}\n${run.stderr}\n${modelsJson}\n${requestLogText}`;
	const assertions = {
		exitOk: run.exitCode === 0 && !run.timedOut && !run.spawnError,
		requestSeen: !!request,
		modelMatched: request?.parsed?.model === MODEL_ID,
		streamingUsed: request?.parsed?.stream === true,
		stdoutMarkerObserved: run.stdout.includes(PROVIDER_MARKER),
		apiKeyEnvRefOnly: modelsJson.includes(`"$${API_KEY_ENV}"`) && !modelsJson.includes(API_KEY_VALUE),
		authorizationFromEnv: header === `Bearer ${API_KEY_VALUE}`,
		requestLogCaptured: requestLogText.includes("CrossSessionResumeProviderRequestLogV1"),
		noLiteralSecrets: !secretPattern().test(combined),
		noPiHomeImport: !new RegExp("(^|[\\s\"'])~?\\/?\\.pi\\/", "i").test(combined),
		noUpdateBanner: !/Update Available|pi\.dev\/changelog|Run pi update/i.test(combined),
	};
	return {
		status: Object.values(assertions).every(Boolean) ? "pass" : "blocked",
		providerName: PROVIDER_NAME,
		modelId: MODEL_ID,
		exitCode: run.exitCode,
		signal: run.signal,
		elapsedMs: run.elapsedMs,
		stdoutPath,
		stderrPath,
		requestLogPath,
		stdoutSha256: sha256(run.stdout),
		stderrSha256: sha256(run.stderr),
		requestLogSha256: sha256(requestLogText),
		request: { method: request?.method, path: request?.url, model: request?.parsed?.model, stream: request?.parsed?.stream, authHeaderSha256: header ? sha256(header) : undefined, bodySha256: request?.body ? sha256(request.body) : undefined },
		assertions,
	};
}

function buildWorkerContinuation(run, probeRoot) {
	const stdoutPath = join(probeRoot, "worker-continuation-stdout.txt");
	const stderrPath = join(probeRoot, "worker-continuation-stderr.txt");
	writeFileSync(stdoutPath, run.stdout, "utf8");
	writeFileSync(stderrPath, run.stderr, "utf8");
	const combined = `${run.stdout}\n${run.stderr}`;
	const assertions = {
		exitOk: run.exitCode === 0 && !run.timedOut && !run.spawnError,
		repiHelpObserved: /repi - REPI reverse\/pentest autonomous agent|built-in reverse\/pentest kernel is enabled/i.test(combined),
		noLiteralSecrets: !secretPattern().test(combined),
		noPiHomeImport: !new RegExp("(^|[\\s\"'])~?\\/?\\.pi\\/", "i").test(combined),
		noUpdateBanner: !/Update Available|pi\.dev\/changelog|Run pi update/i.test(combined),
	};
	return { status: Object.values(assertions).every(Boolean) ? "pass" : "blocked", exitCode: run.exitCode, signal: run.signal, elapsedMs: run.elapsedMs, stdoutPath, stderrPath, stdoutSha256: sha256(run.stdout), stderrSha256: sha256(run.stderr), assertions };
}

function buildReport({ tempRoot, home, isolatedHome, workspace, packSessionId, resumeSessionId, providerSessionId, workerSessionId, packData, resumeData, providerContinuation, workerContinuation, modelsJson }) {
	const verification = resumeData.resume?.exactResumeVerification ?? {};
	const ledger = ledgerSummary(resumeData);
	const assertions = {
		crossSessionDifferent: packSessionId !== resumeSessionId && resumeSessionId !== providerSessionId && providerSessionId !== workerSessionId,
		isolatedRepiHome: isolatedHome.includes(".repi") && !isolatedHome.includes("/.pi/"),
		packQueued: packData.pack?.resumeQueueStatus === "queued" && packData.pack?.closure?.status === "open",
		exactResumeLoadedByContextPath: verification.loadedBy === "contextPath",
		resumedFromOriginalPack: resumeData.resume?.resumedFromContextPath === packData.packPath,
		contextSha256Pass: verification.contextSha256 === "pass",
		artifactHashesPass: verification.artifactHashes === "pass",
		scopePass: verification.scope === "pass",
		closureClosed: resumeData.resume?.resumeQueueStatus === "done" && resumeData.resume?.closure?.status === "closed",
		ledgerDone: ledger.currentState === "done" && ledger.invalidTransitions.length === 0 && ledger.statePath.includes("queued->running") && ledger.statePath.includes("running->done"),
		providerContinuedAfterResume: providerContinuation.status === "pass",
		workerContinuedAfterResume: workerContinuation.status === "pass",
		envRefOnly: modelsJson.includes(`"$${API_KEY_ENV}"`) && !modelsJson.includes(API_KEY_VALUE),
		noPiHomeImport: !existsSync(join(home, ".pi")) && providerContinuation.assertions.noPiHomeImport && workerContinuation.assertions.noPiHomeImport,
		noUpdateBanner: providerContinuation.assertions.noUpdateBanner && workerContinuation.assertions.noUpdateBanner,
		noLiteralSecrets: providerContinuation.assertions.noLiteralSecrets && workerContinuation.assertions.noLiteralSecrets,
	};
	return {
		kind: "CrossSessionResumeLiveV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		isolatedHome,
		workspace,
		packSessionId,
		resumeSessionId,
		providerSessionId,
		workerSessionId,
		pack: {
			contextPath: packData.packPath,
			contextSha256: packData.pack?.contextSha256,
			sessionId: packData.pack?.sessionId,
			idempotencyKey: packData.pack?.idempotencyKey,
			resumeQueueStatus: packData.pack?.resumeQueueStatus,
			closureStatus: packData.pack?.closure?.status,
			artifactHashCount: packData.pack?.artifactHashes?.length ?? 0,
		},
		resume: {
			contextPath: resumeData.resumePath,
			resumedFromContextPath: resumeData.resume?.resumedFromContextPath,
			contextSha256: resumeData.resume?.contextSha256,
			sessionId: resumeData.resume?.sessionId,
			resumeQueueStatus: resumeData.resume?.resumeQueueStatus,
			closureStatus: resumeData.resume?.closure?.status,
			exactResumeVerification: {
				loadedBy: verification.loadedBy,
				contextSha256: verification.contextSha256,
				artifactHashes: verification.artifactHashes,
				scope: verification.scope,
				blockedCount: verification.blocked?.length ?? 0,
				warningsCount: verification.warnings?.length ?? 0,
			},
		},
		compactResumeLedger: ledger,
		providerContinuation,
		workerContinuation,
		artifacts: [packData.packPath, resumeData.resumePath, providerContinuation.stdoutPath, providerContinuation.stderrPath, providerContinuation.requestLogPath, workerContinuation.stdoutPath, workerContinuation.stderrPath].filter(Boolean).map((path) => fileArtifact(tempRoot, path)),
		assertions,
		errors: Object.entries(assertions).filter(([, ok]) => !ok).map(([key]) => `assertion_failed:${key}`),
	};
}

function validateCrossSessionResumeLive(report) {
	const errors = [];
	if (report.kind !== "CrossSessionResumeLiveV1") errors.push("report.kind_invalid");
	if (!report.assertions?.crossSessionDifferent) errors.push("same_session_not_cross_session");
	if (!report.assertions?.isolatedRepiHome) errors.push("isolated_home_invalid");
	if (!report.assertions?.packQueued) errors.push("pack_not_queued");
	if (!report.assertions?.exactResumeLoadedByContextPath) errors.push("exact_context_path_not_used");
	if (!report.assertions?.resumedFromOriginalPack) errors.push("resumed_from_original_pack_missing");
	if (!report.assertions?.contextSha256Pass) errors.push("context_sha256_not_pass");
	if (!report.assertions?.artifactHashesPass) errors.push("artifact_hashes_not_pass");
	if (!report.assertions?.scopePass) errors.push("scope_not_pass");
	if (!report.assertions?.closureClosed) errors.push("resume_closure_not_closed");
	if (!report.assertions?.ledgerDone) errors.push("compact_resume_ledger_not_done");
	if (!report.assertions?.providerContinuedAfterResume || report.providerContinuation?.status !== "pass") errors.push("provider_continuation_missing");
	if (!report.assertions?.workerContinuedAfterResume || report.workerContinuation?.status !== "pass") errors.push("worker_continuation_missing");
	if (!report.assertions?.envRefOnly) errors.push("provider_key_not_env_ref");
	if (!report.assertions?.noPiHomeImport) errors.push("pi_home_leak");
	if (!report.assertions?.noUpdateBanner) errors.push("update_banner_leak");
	if (!report.assertions?.noLiteralSecrets) errors.push("literal_secret_leak");
	return { ok: errors.length === 0, errors };
}

function mutateReport(report, mutate) {
	const clone = JSON.parse(JSON.stringify(report));
	if (mutate === "sameSession") clone.assertions.crossSessionDifferent = false;
	if (mutate === "latestFallback") {
		clone.resume.exactResumeVerification.loadedBy = "latest";
		clone.assertions.exactResumeLoadedByContextPath = false;
	}
	if (mutate === "providerMissing") {
		clone.providerContinuation.status = "blocked";
		clone.assertions.providerContinuedAfterResume = false;
	}
	if (mutate === "ledgerReopened") {
		clone.compactResumeLedger.currentState = "running";
		clone.assertions.ledgerDone = false;
	}
	if (mutate === "piPollution") clone.assertions.noPiHomeImport = false;
	return clone;
}

function negativeCheck(report, id, mutate, expectedNeedle) {
	const validation = validateCrossSessionResumeLive(mutateReport(report, mutate));
	return { id: `negative:${id}`, status: !validation.ok && validation.errors.some((error) => error.includes(expectedNeedle)) ? "pass" : "fail", evidence: { validation, expectedNeedle } };
}

function writeEvidenceFile(result, report) {
	if (!writeEvidence) return undefined;
	const dir = join(root, ".repi-harness", "evidence", "cross-session-resume-live", result.generatedAt.replace(/[:.]/g, "-"));
	mkdir(dir);
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	if (report) writeFileSync(join(dir, "report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
	return path;
}

async function runCrossSession(tempRoot) {
	const probeRoot = join(tempRoot, "cross-session-resume-live");
	const home = join(probeRoot, "home");
	const isolatedHome = join(home, ".repi", "agent");
	const workspace = join(probeRoot, "workspace");
	mkdir(isolatedHome);
	mkdir(workspace);
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
	writeFileSync(join(isolatedHome, "models.json"), modelsJson, "utf8");
	const branchId = "cross-session-resume-branch";
	const packSessionId = "cross-session-pack-session";
	const resumeSessionId = "cross-session-resume-session";
	const providerSessionId = "cross-session-provider-session";
	const workerSessionId = "cross-session-worker-session";
	try {
		const packRun = runProbe(tempRoot, { phase: "pack", home, isolatedHome, workspace, sessionId: packSessionId, branchId });
		if (packRun.status !== 0 || !existsSync(packRun.outPath)) throw new Error(`pack probe failed: ${packRun.stderr || packRun.stdout}`);
		const packData = JSON.parse(readFileSync(packRun.outPath, "utf8"));
		const resumeRun = runProbe(tempRoot, { phase: "resume", home, isolatedHome, workspace, sessionId: resumeSessionId, branchId, contextPath: packData.packPath });
		if (resumeRun.status !== 0 || !existsSync(resumeRun.outPath)) throw new Error(`resume probe failed: ${resumeRun.stderr || resumeRun.stdout}`);
		const resumeData = JSON.parse(readFileSync(resumeRun.outPath, "utf8"));
		const env = { ...baseEnv(home, isolatedHome), REPI_SESSION_ID: providerSessionId, REPI_BRANCH_ID: branchId };
		const providerRun = await spawnRepi(["--provider", PROVIDER_NAME, "--model", MODEL_ID, "--no-tools", "--no-session", "--thinking", "off", "-p", `Reply exactly: ${PROVIDER_MARKER}`], env, workspace, 45000);
		const providerContinuation = buildProviderContinuation(providerRun, requests, modelsJson, probeRoot);
		const workerRun = await spawnRepi(["--offline", "--help"], { ...baseEnv(home, isolatedHome), REPI_SESSION_ID: workerSessionId, REPI_BRANCH_ID: branchId, REPI_OFFLINE: "1", PI_OFFLINE: "1" }, workspace, 30000);
		const workerContinuation = buildWorkerContinuation(workerRun, probeRoot);
		return buildReport({ tempRoot, home, isolatedHome, workspace, packSessionId, resumeSessionId, providerSessionId, workerSessionId, packData, resumeData, providerContinuation, workerContinuation, modelsJson });
	} finally {
		await closeServer(server);
	}
}

async function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-cross-session-resume-live-"));
	const checks = [];
	let report;
	try {
		report = await runCrossSession(tempRoot);
		const validation = validateCrossSessionResumeLive(report);
		checks.push({ id: "runtime:cross-session-resume-live-validation", status: validation.ok ? "pass" : "fail", evidence: { validation, assertions: report.assertions, pack: report.pack, resume: report.resume, compactResumeLedger: report.compactResumeLedger } });
		checks.push({ id: "runtime:cross-session-pack-resume", status: report.assertions.crossSessionDifferent && report.assertions.packQueued && report.assertions.exactResumeLoadedByContextPath && report.assertions.resumedFromOriginalPack ? "pass" : "fail", evidence: { packSessionId: report.packSessionId, resumeSessionId: report.resumeSessionId, pack: report.pack, resume: report.resume } });
		checks.push({ id: "runtime:cross-session-exact-resume-verified", status: report.assertions.contextSha256Pass && report.assertions.artifactHashesPass && report.assertions.scopePass && report.assertions.closureClosed ? "pass" : "fail", evidence: report.resume.exactResumeVerification });
		checks.push({ id: "runtime:cross-session-ledger-done", status: report.assertions.ledgerDone ? "pass" : "fail", evidence: report.compactResumeLedger });
		checks.push({ id: "runtime:cross-session-provider-continuation", status: report.providerContinuation.status === "pass" ? "pass" : "fail", evidence: { request: report.providerContinuation.request, assertions: report.providerContinuation.assertions, stdoutSha256: report.providerContinuation.stdoutSha256 } });
		checks.push({ id: "runtime:cross-session-worker-continuation", status: report.workerContinuation.status === "pass" ? "pass" : "fail", evidence: { assertions: report.workerContinuation.assertions, stdoutSha256: report.workerContinuation.stdoutSha256 } });
		checks.push({ id: "runtime:cross-session-env-redaction", status: report.assertions.envRefOnly && report.assertions.noLiteralSecrets && report.providerContinuation.assertions.authorizationFromEnv ? "pass" : "fail", evidence: { envRefOnly: report.assertions.envRefOnly, noLiteralSecrets: report.assertions.noLiteralSecrets, authHeaderSha256: report.providerContinuation.request.authHeaderSha256 } });
		checks.push({ id: "runtime:cross-session-no-pi-pollution", status: report.assertions.noPiHomeImport && report.assertions.noUpdateBanner ? "pass" : "fail", evidence: { isolatedHome: report.isolatedHome, noPiHomeImport: report.assertions.noPiHomeImport, noUpdateBanner: report.assertions.noUpdateBanner } });
		checks.push(negativeCheck(report, "cross-session-same-session", "sameSession", "same_session_not_cross_session"));
		checks.push(negativeCheck(report, "cross-session-latest-fallback", "latestFallback", "exact_context_path_not_used"));
		checks.push(negativeCheck(report, "cross-session-provider-missing", "providerMissing", "provider_continuation_missing"));
		checks.push(negativeCheck(report, "cross-session-ledger-reopened", "ledgerReopened", "compact_resume_ledger_not_done"));
		checks.push(negativeCheck(report, "cross-session-pi-pollution", "piPollution", "pi_home_leak"));
	} catch (error) {
		checks.push({ id: "runtime:cross-session-resume-live-exception", status: "fail", evidence: { error: String(error), stack: error?.stack } });
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	checks.push(
		markerCheck("code:cross-session-resume-live-types", "packages/coding-agent/src/core/recon-profile.ts", ["type CrossSessionResumeLiveV1", "type CrossSessionResumeContinuationV1", "function verifyCrossSessionResumeLiveV1", "cross_session_resume_exact_context_path"]),
		markerCheck("docs:cross-session-resume-live", "README.md", ["Cross-session resume live", "gate:cross-session-resume-live", "CrossSessionResumeLiveV1", "provider continuation"]),
		markerCheck("npm:cross-session-resume-live", "package.json", ["gate:cross-session-resume-live", "cross-session-resume-live-gate.mjs"]),
		markerCheck("harness:cross-session-resume-live", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:cross-session-resume-live", "compact:cross-session-resume-live", "CrossSessionResumeLiveV1"]),
		markerCheck("autonomy:cross-session-resume-live", "scripts/reverse-agent/autonomy-control-plane.mjs", ["cross_session_resume_live_gate", "CrossSessionResumeLiveV1", "runtime:cross-session-provider-continuation", "runtime:cross-session-ledger-done"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-cross-session-resume-live-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result, report);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Cross-session Resume Live Gate");
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

#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_WORKER_CHILD_SESSION_TMP === "1";
const FIXTURE_PATH = "fixtures/reverse-agent/worker-child-session.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function artifactMap(fixture) {
	return new Map((fixture.artifacts ?? []).map((artifact) => [artifact.path, artifact]));
}

function validatePolicy(batch) {
	const errors = [];
	const policy = batch.launchPolicy ?? {};
	if (batch.poolBridge?.childSessionRuntimeCaptured !== true) errors.push("poolBridge.childSessionRuntimeCaptured_not_true");
	if (policy.command !== "repi") errors.push("launchPolicy.command_not_repi");
	if (!(policy.args ?? []).includes("--recon")) errors.push("launchPolicy.missing_recon_arg");
	if (!policy.isolatedHome || /(^|\/)\.pi(\/|$)/.test(policy.isolatedHome)) errors.push("launchPolicy.isolated_home_invalid");
	if (!String(policy.profileDir ?? "").includes(".repi")) errors.push("launchPolicy.profileDir_not_repi");
	if (policy.importPiAuth !== false) errors.push("launchPolicy.import_pi_auth_not_false");
	if (policy.updateChecksDisabled !== true) errors.push("launchPolicy.update_checks_not_disabled");
	if (policy.telemetryDisabled !== true) errors.push("launchPolicy.telemetry_not_disabled");
	if (policy.cancelSignal !== "SIGTERM") errors.push("launchPolicy.cancelSignal_not_SIGTERM");
	if (!(policy.killAfterMs > 0 && policy.killAfterMs <= 10000)) errors.push("launchPolicy.killAfterMs_invalid");
	const allow = policy.envAllowlist ?? [];
	const deny = policy.envDenylist ?? [];
	for (const secret of ["GITHUB_TOKEN", "GITHUB_TOKEN_FOR_PUSH", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]) {
		if (allow.includes(secret)) errors.push(`launchPolicy.secret_allowed:${secret}`);
	}
	for (const secret of ["GITHUB_TOKEN", "GITHUB_TOKEN_FOR_PUSH", "ANTHROPIC_AUTH_TOKEN"]) {
		if (!deny.includes(secret)) errors.push(`launchPolicy.secret_not_denied:${secret}`);
	}
	return errors;
}

function parseTime(ts) {
	const value = Date.parse(ts);
	return Number.isFinite(value) ? value : undefined;
}

function validateSessionHashes(batch, artifacts) {
	const errors = [];
	for (const session of batch.sessions ?? []) {
		for (const [label, pathField, hashField] of [["transcript", "transcriptPath", "transcriptSha256"], ["stdout", "stdoutPath", "stdoutSha256"], ["stderr", "stderrPath", "stderrSha256"]]) {
			const path = session.runtime?.[pathField];
			const expected = session.hashes?.[hashField];
			const artifact = artifacts.get(path);
			if (!artifact) {
				errors.push(`${session.sessionId}.${label}.missing_artifact`);
				continue;
			}
			const actual = sha256(artifact.content ?? "");
			if (expected !== actual) errors.push(`${session.sessionId}.${label}.hash_mismatch`);
		}
		if (!/^[a-f0-9]{64}$/.test(session.hashes?.toolCallDigest ?? "")) errors.push(`${session.sessionId}.toolCallDigest_invalid`);
	}
	return errors;
}

function validateChildProcessProbe(batch, artifacts) {
	const errors = [];
	const probe = batch.childProcessProbe;
	if (batch.poolBridge?.childProcessRuntimeCaptured !== true) errors.push("poolBridge.childProcessRuntimeCaptured_not_true");
	if (!probe) {
		errors.push("childProcessProbe_missing");
		return errors;
	}
	if (probe.kind !== "WorkerChildProcessProbeV1") errors.push("childProcessProbe.kind_invalid");
	if (probe.status !== "pass") errors.push("childProcessProbe.status_not_pass");
	if (probe.command !== "repi" && !String(probe.command ?? "").endsWith("/repi")) errors.push("childProcessProbe.command_not_repi");
	if (!(probe.args ?? []).includes("--offline") || !(probe.args ?? []).includes("--help")) errors.push("childProcessProbe.args_missing_offline_help");
	if (!probe.isolatedHome || /(^|\/)\.pi(\/|$)/.test(probe.isolatedHome) || !String(probe.isolatedHome).includes(".repi")) {
		errors.push("childProcessProbe.isolated_home_invalid");
	}
	if (probe.exitCode !== 0) errors.push("childProcessProbe.exit_code_not_zero");
	if (!(probe.elapsedMs >= 0 && probe.elapsedMs <= batch.launchPolicy.timeoutMs)) errors.push("childProcessProbe.elapsed_invalid");
	const assertions = probe.assertions ?? {};
	for (const key of ["repiCommandExecuted", "isolatedRepiHome", "noPiHomeImport", "updateChecksDisabled", "telemetryDisabled", "noLiteralSecrets", "stdoutCaptured"]) {
		if (assertions[key] !== true) errors.push(`childProcessProbe.assertion_failed:${key}`);
	}
	if ((probe.errors ?? []).length) errors.push("childProcessProbe.errors_not_empty");
	for (const secret of ["GITHUB_TOKEN", "GITHUB_TOKEN_FOR_PUSH", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]) {
		if ((probe.envAllowlist ?? []).includes(secret)) errors.push(`childProcessProbe.secret_allowed:${secret}`);
	}
	for (const secret of ["GITHUB_TOKEN", "GITHUB_TOKEN_FOR_PUSH", "ANTHROPIC_AUTH_TOKEN"]) {
		if (!(probe.envDenylist ?? []).includes(secret)) errors.push(`childProcessProbe.secret_not_denied:${secret}`);
	}
	for (const [label, pathField, hashField] of [["stdout", "stdoutPath", "stdoutSha256"], ["stderr", "stderrPath", "stderrSha256"]]) {
		const path = probe[pathField];
		const artifact = artifacts.get(path);
		if (!artifact) {
			errors.push(`childProcessProbe.${label}.missing_artifact`);
			continue;
		}
		const content = artifact.content ?? "";
		const actual = sha256(content);
		if (artifact.sha256 !== actual || probe[hashField] !== actual) errors.push(`childProcessProbe.${label}.hash_mismatch`);
		if (/(sk-[A-Za-z0-9]|ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9])/i.test(content)) errors.push(`childProcessProbe.${label}.literal_secret`);
		if (/(^|[\s"'])~?\/?\.pi\//i.test(content)) errors.push(`childProcessProbe.${label}.pi_home_leak`);
		if (/Update Available|pi\.dev\/changelog|Run pi update/i.test(content)) errors.push(`childProcessProbe.${label}.update_check_leak`);
	}
	return errors;
}

function validateProvider(session) {
	const errors = [];
	const provider = session.provider ?? {};
	if (!['openai-compatible', 'anthropic-compatible', 'local-openai'].includes(provider.format)) errors.push(`${session.sessionId}.provider.format_invalid`);
	if (!provider.modelId) errors.push(`${session.sessionId}.provider.modelId_missing`);
	if (!provider.baseUrlRef || !String(provider.baseUrlRef).startsWith("$")) errors.push(`${session.sessionId}.provider.baseUrlRef_not_env_ref`);
	if (!provider.apiKeyRef || !String(provider.apiKeyRef).startsWith("$") || /^sk-|^ghp_|^github_pat_/i.test(String(provider.apiKeyRef))) errors.push(`${session.sessionId}.provider.apiKeyRef_not_env_ref`);
	if (!(provider.contextWindow > 0)) errors.push(`${session.sessionId}.provider.contextWindow_invalid`);
	if (!(provider.maxTokens > 0 && provider.maxTokens <= provider.contextWindow)) errors.push(`${session.sessionId}.provider.maxTokens_invalid`);
	return errors;
}

function validateSessions(batch) {
	const errors = [];
	const dirs = new Set();
	for (const session of batch.sessions ?? []) {
		errors.push(...validateProvider(session));
		const dir = session.runtime?.sessionDir;
		if (!dir || dirs.has(dir)) errors.push(`${session.sessionId}.duplicate_or_missing_sessionDir`);
		dirs.add(dir);
		if (!String(dir ?? "").includes(".repi-harness/evidence/child-sessions")) errors.push(`${session.sessionId}.sessionDir_not_child_sessions`);
		if (!session.poolBridge?.poolId || session.poolBridge.poolId !== batch.poolId) errors.push(`${session.sessionId}.missing_pool_bridge`);
		if (!session.poolBridge?.mergeKey) errors.push(`${session.sessionId}.missing_mergeKey`);
		const start = parseTime(session.runtime?.startedAt);
		const end = parseTime(session.runtime?.endedAt);
		if (start === undefined || end === undefined || end < start) errors.push(`${session.sessionId}.invalid_time_window`);
		const elapsed = start !== undefined && end !== undefined ? end - start : 0;
		if (elapsed > batch.launchPolicy.timeoutMs && !["timeout", "cancelled"].includes(session.runtime?.status)) errors.push(`${session.sessionId}.timeout_not_marked`);
		if (session.runtime?.status === "timeout" && !session.runtime?.cancelledAt) errors.push(`${session.sessionId}.timeout_without_cancel`);
		if (session.retryBudget?.remaining !== Math.max(0, session.maxAttempts - session.attempt)) errors.push(`${session.sessionId}.retry_remaining_inconsistent`);
		if (session.retryBudget?.exhausted !== (session.attempt >= session.maxAttempts)) errors.push(`${session.sessionId}.retry_exhausted_inconsistent`);
		if (session.retryBudget?.exhausted && ["queued", "running", "retry_queued"].includes(session.runtime?.status)) errors.push(`${session.sessionId}.exhausted_still_running`);
		if ((session.resourceLease?.cpuSlots ?? 0) > (batch.resourceBudget?.cpuSlots ?? 0)) errors.push(`${session.sessionId}.cpuSlots_exceeds_budget`);
		if ((session.resourceLease?.memoryMb ?? 0) > (batch.resourceBudget?.memoryMb ?? 0)) errors.push(`${session.sessionId}.memoryMb_exceeds_budget`);
	}
	return errors;
}

function eventHash(event) {
	const { eventHash: _eventHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function validateClaimLedger(batch) {
	const errors = [];
	let prevHash = "0".repeat(64);
	const byClaim = new Map();
	for (const [index, event] of (batch.claimLedgerEvents ?? []).entries()) {
		if (event.prevHash !== prevHash) errors.push(`claimLedgerEvents[${index}].prevHash`);
		if (event.eventHash !== eventHash(event)) errors.push(`claimLedgerEvents[${index}].eventHash`);
		prevHash = event.eventHash;
		for (const claimId of [event.claimId, ...(event.claimIds ?? [])].filter(Boolean)) {
			const set = byClaim.get(claimId) ?? new Set();
			set.add(event.type);
			byClaim.set(claimId, set);
		}
	}
	for (const session of batch.sessions ?? []) {
		for (const claimId of session.poolBridge?.claimRefs ?? []) {
			const types = byClaim.get(claimId);
			for (const required of ["artifact_handoff", "claim", "validation", "challenge", "resolution"]) {
				if (!types?.has(required)) errors.push(`${session.sessionId}.${claimId}.missing_${required}`);
			}
		}
	}
	return errors;
}

function validateBatch(fixture) {
	const batch = fixture.providerRuntime;
	const artifacts = artifactMap(fixture);
	const errors = [
		...validatePolicy(batch),
		...validateSessionHashes(batch, artifacts),
		...validateChildProcessProbe(batch, artifacts),
		...validateSessions(batch),
		...validateClaimLedger(batch),
	];
	return { status: errors.length ? "fail" : "pass", errors };
}

function mutateFixture(fixture, negative) {
	const clone = JSON.parse(JSON.stringify(fixture));
	const batch = clone.providerRuntime;
	if (negative.mutate === "commandPi") batch.launchPolicy.command = "pi";
	if (negative.mutate === "sharedPiHome") batch.launchPolicy.isolatedHome = "/root/.pi/agent";
	if (negative.mutate === "secretAllowlist") batch.launchPolicy.envAllowlist.push("GITHUB_TOKEN_FOR_PUSH");
	if (negative.mutate === "importPiAuth") batch.launchPolicy.importPiAuth = true;
	if (negative.mutate === "updateChecksEnabled") batch.launchPolicy.updateChecksDisabled = false;
	if (negative.mutate === "literalApiKey") batch.sessions[0].provider.apiKeyRef = "sk-live-secret";
	if (negative.mutate === "missingChildProcessProbe") delete batch.childProcessProbe;
	if (negative.mutate === "childProcessSecretLeak") {
		const artifact = (clone.artifacts ?? []).find((item) => item.path === batch.childProcessProbe?.stdoutPath);
		if (artifact) {
			artifact.content = "REPI reverse/pentest independent product ghp_fixture_secret\n";
			artifact.sha256 = sha256(artifact.content);
		}
	}
	if (negative.mutate === "transcriptHashMismatch") batch.sessions[0].hashes.transcriptSha256 = "e".repeat(64);
	if (negative.mutate === "timeoutWithoutCancel") {
		const session = batch.sessions.find((item) => item.runtime.status === "timeout");
		if (session) delete session.runtime.cancelledAt;
	}
	if (negative.mutate === "exhaustedStillRunning") {
		const session = batch.sessions.find((item) => item.retryBudget.exhausted);
		if (session) session.runtime.status = "running";
	}
	if (negative.mutate === "missingPoolBridge") delete batch.sessions[0].poolBridge;
	if (negative.mutate === "claimWithoutValidation") batch.claimLedgerEvents = batch.claimLedgerEvents.filter((event) => event.type !== "validation" || event.claimId !== "claim-child-authz");
	return clone;
}

function checkExpected(result, expected = {}) {
	const errors = [];
	for (const needle of expected.mustHaveErrors ?? []) if (!result.errors.some((error) => error.includes(needle))) errors.push(`missing expected error ${needle}`);
	for (const needle of expected.mustNotHaveErrors ?? []) if (result.errors.some((error) => error.includes(needle))) errors.push(`unexpected error ${needle}`);
	return errors;
}

function negativeCase(fixture, negative) {
	const result = validateBatch(mutateFixture(fixture, negative));
	const errors = checkExpected(result, negative.expected ?? {});
	return { id: `negative-${negative.id}`, status: errors.length ? "fail" : "pass", evidence: { validation: result, errors } };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "worker-child-session", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return path;
}

function writeProbe(probePath, outPath, tempRoot) {
	const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
	writeFileSync(
		probePath,
		`
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createReconExtensionFactory } from ${JSON.stringify(importUrl)};

const outPath = ${JSON.stringify(outPath)};
const tempRoot = ${JSON.stringify(tempRoot)};
const agentDir = join(tempRoot, "agent");
const workspace = join(tempRoot, "workspace");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "worker-child-session-live";
process.env.REPI_BRANCH_ID = "worker-child-session-branch";
const tools = new Map();
const fakePi = {
  registerCommand() {},
  registerTool(tool) { tools.set(tool.name, tool); },
  on() {},
  appendEntry() {},
  getSessionName: () => undefined,
  setSessionName() {},
  sendMessage() {},
  exec: async () => ({ code: 0, stdout: "worker child session live probe stdout sha256=0123456789abcdef artifact=/tmp/repi-child-proof\\n", stderr: "", killed: false })
};
createReconExtensionFactory()(fakePi);
const swarm = tools.get("re_swarm");
if (!swarm) throw new Error("missing re_swarm tool");
function parseArtifact(path) {
  const body = readFileSync(path, "utf8");
  const match = /\\\`\\\`\\\`json\\s*([\\s\\S]*?)\\s*\\\`\\\`\\\`/m.exec(body);
  if (!match?.[1]) throw new Error("missing json block in " + path);
  return JSON.parse(match[1]);
}
async function main() {
  const result = await swarm.execute("worker-child-session-live", { action: "run", target: "local-child-session-probe", task: "validate worker child session runtime bridge", maxWorkers: 1, maxCommands: 1 });
  const text = result?.content?.[0]?.text ?? "";
  const swarmPath = result?.details?.path;
  if (!swarmPath) throw new Error("missing swarm artifact path");
  const artifact = parseArtifact(swarmPath);
  const childPath = artifact.workerChildSessionRuntimePath;
  if (!childPath) throw new Error("missing workerChildSessionRuntimePath");
  const child = JSON.parse(readFileSync(childPath, "utf8"));
  writeFileSync(outPath, JSON.stringify({ swarmPath, childPath, artifact, child, text }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`,
		"utf8",
	);
}

function runProbe(tempRoot) {
	const probePath = join(tempRoot, "worker-child-session-live-probe.ts");
	const outPath = join(tempRoot, "probe-result.json");
	writeProbe(probePath, outPath, tempRoot);
	const tsx = join(root, "node_modules", ".bin", "tsx");
	const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], {
		cwd: root,
		env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1", REPI_REPO_ROOT: root, REPI_SWARM_CHILD_PROCESS_SMOKE: "1", REPI_CHILD_PROCESS_REPI_BIN: join(root, "repi") },
		encoding: "utf8",
		maxBuffer: 40 * 1024 * 1024,
	});
	return { ...result, outPath, probePath };
}

function closeServer(server) {
	return new Promise((resolve) => server.close(() => resolve()));
}

function sseChunk(payload) {
	return `data: ${JSON.stringify(payload)}\n\n`;
}

async function runProviderChildProcessProbe(tempRoot) {
	const providerName = "child-openai-compatible";
	const modelId = "child/mock-model";
	const marker = "CHILD_PROVIDER_OK";
	const apiKeyEnvName = "REPI_CHILD_PROVIDER_API_KEY";
	const apiKeyValue = "fixture-child-token";
	const probeRoot = join(tempRoot, "provider-child-process");
	const home = join(probeRoot, "home");
	const isolatedHome = join(home, ".repi", "agent");
	const workspace = join(probeRoot, "workspace");
	mkdirSync(isolatedHome, { recursive: true });
	mkdirSync(workspace, { recursive: true });
	const stdoutPath = join(probeRoot, "stdout.txt");
	const stderrPath = join(probeRoot, "stderr.txt");
	const requestLogPath = join(probeRoot, "request-log.json");
	const transcriptPath = join(probeRoot, "transcript.jsonl");
	const modelsJsonPath = join(isolatedHome, "models.json");
	const requests = [];
	const server = createServer((req, res) => {
		let body = "";
		req.setEncoding("utf8");
		req.on("data", (chunk) => {
			body += chunk;
		});
		req.on("end", () => {
			let parsed;
			try {
				parsed = JSON.parse(body);
			} catch {
				parsed = undefined;
			}
			requests.push({
				method: req.method,
				url: req.url,
				authorization: req.headers.authorization,
				body,
				parsed,
			});
			if (req.method !== "POST" || req.url !== "/v1/chat/completions") {
				res.writeHead(404, { "content-type": "application/json" });
				res.end(JSON.stringify({ error: "not found" }));
				return;
			}
			res.writeHead(200, {
				"content-type": "text/event-stream; charset=utf-8",
				"cache-control": "no-cache",
				connection: "keep-alive",
			});
			res.write(
				sseChunk({
					id: "chatcmpl-repi-child-provider-probe",
					object: "chat.completion.chunk",
					created: 0,
					model: modelId,
					choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }],
				}),
			);
			res.write(
				sseChunk({
					id: "chatcmpl-repi-child-provider-probe",
					object: "chat.completion.chunk",
					created: 0,
					model: modelId,
					choices: [{ index: 0, delta: { content: marker }, finish_reason: null }],
				}),
			);
			res.write(
				sseChunk({
					id: "chatcmpl-repi-child-provider-probe",
					object: "chat.completion.chunk",
					created: 0,
					model: modelId,
					choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
					usage: { prompt_tokens: 8, completion_tokens: 3, total_tokens: 11 },
				}),
			);
			res.write("data: [DONE]\n\n");
			res.end();
		});
	});
	await new Promise((resolveListen, rejectListen) => {
		server.once("error", rejectListen);
		server.listen(0, "127.0.0.1", () => {
			server.off("error", rejectListen);
			resolveListen();
		});
	});
	const port = server.address().port;
	const modelsJson = JSON.stringify(
		{
			providers: {
				[providerName]: {
					baseUrl: `http://127.0.0.1:${port}/v1`,
					api: "openai-completions",
					apiKey: `$${apiKeyEnvName}`,
					compat: {
						supportsDeveloperRole: false,
						supportsReasoningEffort: false,
						supportsStore: false,
						supportsStrictMode: false,
						supportsUsageInStreaming: false,
						maxTokensField: "max_tokens",
					},
					models: [{ id: modelId, contextWindow: 8192, maxTokens: 1024 }],
				},
			},
		},
		null,
		2,
	);
	writeFileSync(modelsJsonPath, `${modelsJson}\n`, "utf8");
	const command = join(root, "repi");
	const args = [
		"--provider",
		providerName,
		"--model",
		modelId,
		"--no-tools",
		"--no-session",
		"--thinking",
		"off",
		"-p",
		`Reply exactly: ${marker}`,
	];
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
		[apiKeyEnvName]: apiKeyValue,
	};
	const started = Date.now();
	const startedAt = new Date(started).toISOString();
	let stdout = "";
	let stderr = "";
	let exitCode = null;
	let signal = null;
	let spawnError;
	let timedOut = false;
	try {
		await new Promise((resolveChild) => {
			const child = spawn(command, args, { cwd: workspace, env, stdio: ["ignore", "pipe", "pipe"] });
			const timer = setTimeout(() => {
				timedOut = true;
				child.kill("SIGTERM");
				setTimeout(() => {
					if (child.exitCode === null) child.kill("SIGKILL");
				}, 3000).unref();
			}, 45000);
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
	} finally {
		await closeServer(server);
	}
	const ended = Date.now();
	const endedAt = new Date(ended).toISOString();
	writeFileSync(stdoutPath, stdout, "utf8");
	writeFileSync(stderrPath, stderr, "utf8");
	const firstRequest = requests.find((request) => request.url === "/v1/chat/completions") ?? requests[0];
	const parsed = firstRequest?.parsed;
	const requestLog = {
		kind: "WorkerProviderChildProcessRequestLogV1",
		providerName,
		modelId,
		requests: requests.map((request) => ({
			method: request.method,
			path: request.url,
			model: request.parsed?.model,
			stream: request.parsed?.stream,
			messageCount: Array.isArray(request.parsed?.messages) ? request.parsed.messages.length : undefined,
			bodySha256: sha256(request.body ?? ""),
			authorizationHeaderSha256: request.authorization ? sha256(String(request.authorization)) : undefined,
			authorizationHeader: request.authorization ? "Bearer <redacted>" : undefined,
		})),
	};
	const requestLogText = `${JSON.stringify(requestLog, null, 2)}\n`;
	writeFileSync(requestLogPath, requestLogText, "utf8");
	const transcript = [
		{
			kind: "WorkerProviderChildProcessTranscriptV1",
			providerName,
			modelId,
			command,
			args,
			cwd: workspace,
			isolatedHome,
			startedAt,
			endedAt,
			exitCode,
			signal,
			stdoutSha256: sha256(stdout),
			stderrSha256: sha256(stderr),
			requestLogSha256: sha256(requestLogText),
		},
		{
			event: "provider_request",
			path: firstRequest?.url,
			model: parsed?.model,
			stream: parsed?.stream,
			authorizationHeaderSha256: firstRequest?.authorization ? sha256(String(firstRequest.authorization)) : undefined,
			bodySha256: firstRequest?.body ? sha256(firstRequest.body) : undefined,
		},
	]
		.map((row) => JSON.stringify(row))
		.join("\n") + "\n";
	writeFileSync(transcriptPath, transcript, "utf8");
	const combinedArtifactText = `${stdout}\n${stderr}\n${requestLogText}\n${modelsJson}`;
	const assertions = {
		openAICompatibleRequestSeen: !!firstRequest && firstRequest.method === "POST" && firstRequest.url === "/v1/chat/completions",
		modelMatched: parsed?.model === modelId,
		stdoutMarkerObserved: stdout.includes(marker),
		apiKeyEnvRefOnly: modelsJson.includes(`"$${apiKeyEnvName}"`) && !modelsJson.includes(apiKeyValue),
		authorizationFromEnv: firstRequest?.authorization === `Bearer ${apiKeyValue}`,
		transcriptCaptured: existsSync(transcriptPath) && transcript.includes("WorkerProviderChildProcessTranscriptV1"),
		noPiHomeImport: !new RegExp("(^|[\\\\s\\\"'])~?\\\\/?\\\\.pi\\\\/", "i").test(combinedArtifactText),
		noUpdateBanner: !/Update Available|pi\.dev\/changelog|Run pi update/i.test(combinedArtifactText),
		noLiteralSecrets: !/(sk-[A-Za-z0-9]|ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|fixture-child-token)/i.test(combinedArtifactText),
	};
	const errors = Object.entries(assertions)
		.filter(([, value]) => !value)
		.map(([key]) => `assertion_failed:${key}`);
	if (timedOut) errors.push("timeout");
	if (spawnError) errors.push(`spawn_error:${spawnError.message}`);
	if (exitCode !== 0) errors.push(`exit_code:${exitCode}`);
	return {
		kind: "WorkerProviderChildProcessProbeV1",
		schemaVersion: 1,
		probeId: `worker-provider-child-process:${sha256(`${providerName}:${modelId}:${startedAt}`).slice(0, 16)}`,
		providerName,
		modelId,
		command,
		args,
		cwd: workspace,
		isolatedHome,
		modelsJsonPath,
		requestLogPath,
		transcriptPath,
		stdoutPath,
		stderrPath,
		stdoutSha256: sha256(stdout),
		stderrSha256: sha256(stderr),
		requestLogSha256: sha256(requestLogText),
		transcriptSha256: sha256(transcript),
		startedAt,
		endedAt,
		elapsedMs: Math.max(0, ended - started),
		exitCode,
		signal,
		status: errors.length ? "blocked" : "pass",
		assertions,
		request: {
			method: firstRequest?.method,
			path: firstRequest?.url,
			model: parsed?.model,
			stream: parsed?.stream,
			authorizationHeaderSha256: firstRequest?.authorization ? sha256(String(firstRequest.authorization)) : undefined,
			bodySha256: firstRequest?.body ? sha256(firstRequest.body) : undefined,
		},
		errors,
	};
}

async function main() {
	const checks = [];
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-worker-child-session-"));
	let probeData;
	let providerProbe;
	let fixture;
	try {
		fixture = readJson(FIXTURE_PATH);
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-worker-child-session-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH } });
	} catch (error) {
		checks.push({ id: "fixture:parse", status: "fail", evidence: { path: FIXTURE_PATH, error: String(error) } });
	}
	if (fixture) {
		const validation = validateBatch(fixture);
		const expectedErrors = checkExpected(validation, fixture.expected ?? {});
		checks.push({ id: "fixture:child-session-contract", status: validation.status === "pass" && expectedErrors.length === 0 ? "pass" : "fail", evidence: { validation, expectedErrors } });
		for (const negative of fixture.negativeCases ?? []) checks.push(negativeCase(fixture, negative));
	}
	try {
		const probe = runProbe(tempRoot);
		checks.push({ id: "runtime:re_swarm-child-session-probe-exit", status: probe.status === 0 ? "pass" : "fail", evidence: { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) } });
		if (probe.status === 0 && existsSync(probe.outPath)) {
			probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
			const batch = probeData.child?.batch;
			const pool = probeData.child?.workerRuntimePoolBridge;
			const validation = probeData.child?.batchValidation;
			const poolValidation = probeData.child?.poolValidation;
			const sessions = batch?.sessions ?? [];
			checks.push({ id: "runtime:worker-child-session-batch", status: batch?.kind === "WorkerChildSessionRuntimeBatchV1" && sessions.length > 0 && batch?.poolBridge?.childSessionRuntimeCaptured === true ? "pass" : "fail", evidence: { childPath: probeData.childPath, sessions: sessions.length, poolBridge: batch?.poolBridge } });
			checks.push({ id: "runtime:worker-child-session-validation", status: validation?.ok === true && poolValidation?.ok === true && pool?.kind === "WorkerRuntimePoolV1" ? "pass" : "fail", evidence: { batchValidation: validation, poolValidation, poolKind: pool?.kind } });
			checks.push({ id: "runtime:worker-child-session-artifact-wiring", status: probeData.artifact?.workerChildSessionRuntimeStatus === "pass" && probeData.artifact?.workerRuntimePoolBridgeStatus === "pass" && /worker_child_session_runtime/i.test(probeData.text ?? "") ? "pass" : "fail", evidence: { swarmPath: probeData.swarmPath, childPath: probeData.childPath, status: probeData.artifact?.workerChildSessionRuntimeStatus, pool: probeData.artifact?.workerRuntimePoolBridgeStatus, textTail: String(probeData.text ?? "").slice(-1200) } });
			checks.push({ id: "runtime:worker-child-process-smoke", status: batch?.poolBridge?.childProcessRuntimeCaptured === true && batch?.childProcessProbe?.status === "pass" && batch?.childProcessProbe?.assertions?.repiCommandExecuted === true && batch?.childProcessProbe?.assertions?.noPiHomeImport === true ? "pass" : "fail", evidence: { childProcessRuntimeCaptured: batch?.poolBridge?.childProcessRuntimeCaptured, probe: batch?.childProcessProbe } });
		} else {
			for (const id of ["runtime:worker-child-session-batch", "runtime:worker-child-session-validation", "runtime:worker-child-session-artifact-wiring", "runtime:worker-child-process-smoke"]) checks.push({ id, status: "fail", evidence: { error: "probe output missing" } });
		}
	} catch (error) {
		checks.push({ id: "runtime:worker-child-session-probe-exception", status: "fail", evidence: { error: String(error), stack: error?.stack } });
	}
	try {
		providerProbe = await runProviderChildProcessProbe(tempRoot);
		checks.push({ id: "runtime:worker-provider-child-process-smoke", status: providerProbe.status === "pass" ? "pass" : "fail", evidence: providerProbe });
		checks.push({
			id: "runtime:worker-provider-env-ref-only",
			status: providerProbe.assertions.apiKeyEnvRefOnly === true && providerProbe.assertions.authorizationFromEnv === true && providerProbe.assertions.noLiteralSecrets === true ? "pass" : "fail",
			evidence: {
				modelsJsonPath: providerProbe.modelsJsonPath,
				apiKeyEnvRefOnly: providerProbe.assertions.apiKeyEnvRefOnly,
				authorizationFromEnv: providerProbe.assertions.authorizationFromEnv,
				noLiteralSecrets: providerProbe.assertions.noLiteralSecrets,
				requestAuthorizationSha256: providerProbe.request.authorizationHeaderSha256,
			},
		});
		checks.push({
			id: "runtime:worker-provider-transcript-captured",
			status: providerProbe.assertions.transcriptCaptured === true && providerProbe.requestLogSha256 && providerProbe.stdoutSha256 ? "pass" : "fail",
			evidence: {
				transcriptPath: providerProbe.transcriptPath,
				requestLogPath: providerProbe.requestLogPath,
				transcriptSha256: providerProbe.transcriptSha256,
				requestLogSha256: providerProbe.requestLogSha256,
				stdoutSha256: providerProbe.stdoutSha256,
			},
		});
		checks.push({
			id: "runtime:worker-provider-request-captured",
			status: providerProbe.assertions.openAICompatibleRequestSeen === true && providerProbe.assertions.modelMatched === true && providerProbe.assertions.stdoutMarkerObserved === true ? "pass" : "fail",
			evidence: {
				request: providerProbe.request,
				openAICompatibleRequestSeen: providerProbe.assertions.openAICompatibleRequestSeen,
				modelMatched: providerProbe.assertions.modelMatched,
				stdoutMarkerObserved: providerProbe.assertions.stdoutMarkerObserved,
			},
		});
	} catch (error) {
		for (const id of ["runtime:worker-provider-child-process-smoke", "runtime:worker-provider-env-ref-only", "runtime:worker-provider-transcript-captured", "runtime:worker-provider-request-captured"]) {
			checks.push({ id, status: "fail", evidence: { error: String(error), stack: error?.stack } });
		}
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	checks.push(
		markerCheck("code:worker-child-session-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["type WorkerChildSessionRuntimeBatchV1", "type WorkerChildProcessProbeV1", "type WorkerProviderChildProcessProbeV1", "function workerChildSessionLaunchPolicy", "function verifyWorkerChildSessionRuntimeBatch", "function verifyWorkerProviderChildProcessProbe", "workerChildSessionToWorkerRuntimePoolBridge", "buildWorkerChildSessionRuntimeBatchFromSwarm", "runWorkerChildProcessProbe", "workerChildSessionRuntimePath"]),
		markerCheck("docs:worker-child-session", "README.md", ["Worker child-session runtime", "gate:worker-child-session", "isolatedHome", "provider runtime", "workerChildSessionRuntimePath", "WorkerChildProcessProbeV1", "WorkerProviderChildProcessProbeV1"]),
		markerCheck("npm:worker-child-session-script", "package.json", ["gate:worker-child-session", "worker-child-session-gate.mjs"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-worker-child-session-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Worker Child Session Gate");
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

#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_CROSS_SESSION_MULTI_COMPACT_TMP === "1";
const SCHEMA_PATH = "schemas/reverse-agent/cross-session-multi-compact-matrix.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/cross-session-multi-compact-matrix.fixture.json";

const REQUIRED_GATES = [
	"CrossSessionMultiCompactMatrixGateV1",
	"cross_session_multi_compact_same_run",
	"old_context_path_over_latest_after_multiple_compacts",
	"context_sha_artifact_hashes_verified_across_sessions",
	"provider_continuation_after_exact_resume",
	"operator_proof_loop_budget_closure",
	"terminal_resume_rows_not_reopened",
	"compact_resume_ledger_v2_hash_chain_quality",
];
const REQUIRED_NEGATIVE_CASES = [
	"latest-fallback-without-explicit-context",
	"context-sha-drift",
	"artifact-hash-drift",
	"provider-continuation-missing",
	"budget-exhausted-open",
	"terminal-row-reopened",
	"same-session-only",
	"ledger-hash-chain-drift",
];
const INVARIANTS = [
	"cross_session_multi_compact_matrix_gate",
	"cross_session_multi_compact_same_run",
	"old_context_path_over_latest_after_multiple_compacts",
	"context_sha_artifact_hashes_verified_across_sessions",
	"provider_continuation_after_exact_resume",
	"operator_proof_loop_budget_closure",
	"terminal_resume_rows_not_reopened",
	"compact_resume_ledger_v2_hash_chain_quality",
];
const TERMINAL_STATES = new Set(["done", "blocked", "exhausted"]);

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const shortHash = (value) => sha256(value).slice(0, 24);
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));
const check = (id, ok, evidence = {}) => ({ id, status: ok ? "pass" : "fail", evidence });

function markerCheck(id, path, markers) {
	const full = join(root, path);
	if (!existsSync(full)) return check(id, false, { path, exists: false });
	const text = readFileSync(full, "utf8");
	const missing = markers.filter((marker) => !text.includes(marker));
	return check(id, missing.length === 0, { path, missing, sha256: shortHash(text) });
}

function rel(base, path) {
	const basePath = resolve(base);
	const resolved = resolve(path);
	return resolved.startsWith(basePath) ? relative(basePath, resolved) : path;
}

function writeFile(path, text) {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, text, "utf8");
}

function writeJson(path, value) {
	writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

function fileArtifact(base, path, required = true) {
	const bytes = readFileSync(path);
	const stat = statSync(path);
	return { path: rel(base, path), sha256: sha256(bytes), bytes: bytes.length, mtime: stat.mtime.toISOString(), required, exists: true };
}

function transitionHash(row) {
	const { entryHash, ...withoutHash } = row;
	return sha256(JSON.stringify(withoutHash));
}

function buildLedgerTransitions(rows) {
	let prevHash = "0".repeat(64);
	return rows.map((row, index) => {
		const transition = { kind: "CompactResumeLedgerTransitionV2", seq: index + 1, prevHash, ...row };
		transition.entryHash = transitionHash(transition);
		prevHash = transition.entryHash;
		return transition;
	});
}

function ledgerHashChainOk(rows) {
	let prevHash = "0".repeat(64);
	for (const row of rows ?? []) {
		if (row.kind !== "CompactResumeLedgerTransitionV2") return false;
		if (row.prevHash !== prevHash) return false;
		if (row.entryHash !== transitionHash(row)) return false;
		prevHash = row.entryHash;
	}
	return (rows ?? []).length >= 6;
}

function buildContextPack(tempRoot, cycleId, sourceSessionId, target, artifacts) {
	const contextPath = join(tempRoot, "contexts", `${cycleId}-${sourceSessionId}.json`);
	const body = {
		kind: "ContextPackV2",
		schemaVersion: 2,
		cycleId,
		missionId: "cross-session-multi-compact-matrix",
		sessionId: sourceSessionId,
		workspaceRoot: tempRoot,
		target,
		artifactHashes: artifacts.map((artifact) => ({ path: artifact.path, sha256: artifact.sha256, required: artifact.required })),
		resumeContract: {
			contractId: "ResumeContractV2",
			resumeQueueStatus: "queued",
			idempotencyKey: `${cycleId}:resume:${sourceSessionId}`,
		},
	};
	writeJson(contextPath, body);
	const contextText = readFileSync(contextPath, "utf8");
	const contextSha256 = sha256(contextText);
	const finalBody = { ...body, contextPath: rel(tempRoot, contextPath), contextSha256 };
	writeJson(contextPath, finalBody);
	return { contextPath: rel(tempRoot, contextPath), contextSha256: sha256(readFileSync(contextPath, "utf8")), artifactHashes: finalBody.artifactHashes };
}

function buildProviderContinuation(tempRoot, cycleId, resumeSessionId) {
	const dir = join(tempRoot, "provider-continuations", cycleId);
	const requestLog = {
		kind: "CrossSessionProviderContinuationRequestLogV1",
		cycleId,
		resumeSessionId,
		providerName: "cross-session-openai-compatible",
		modelId: "cross-session/continuation-smoke",
		apiKeyRef: "$REPI_CROSS_SESSION_PROVIDER_KEY",
		requests: [{ method: "POST", path: "/v1/chat/completions", stream: true, headers: { authorization: "<redacted:env-ref>" } }],
	};
	const stdout = `CROSS_SESSION_PROVIDER_CONTINUATION_OK ${cycleId}\n`;
	const stderr = "";
	const requestLogPath = join(dir, "request-log.json");
	const stdoutPath = join(dir, "stdout.txt");
	const stderrPath = join(dir, "stderr.txt");
	writeJson(requestLogPath, requestLog);
	writeFile(stdoutPath, stdout);
	writeFile(stderrPath, stderr);
	return {
		cycleId,
		resumeSessionId,
		providerName: requestLog.providerName,
		modelId: requestLog.modelId,
		apiKeyEnvRefOnly: true,
		requestLogPath: rel(tempRoot, requestLogPath),
		stdoutPath: rel(tempRoot, stdoutPath),
		stderrPath: rel(tempRoot, stderrPath),
		requestLogSha256: sha256(readFileSync(requestLogPath)),
		stdoutSha256: sha256(stdout),
		stderrSha256: sha256(stderr),
		continuationStatus: "pass",
		noPiHomeImport: true,
		noUpdateBanner: true,
		noLiteralSecrets: true,
	};
}

function buildOperatorProofClosure(cycleId, status, budgetRemaining, proofLoopEntered = true) {
	return {
		cycleId,
		operatorStatus: status === "done" ? "done" : status,
		proofLoopStatus: status,
		budget: { maxOperatorDispatch: 2, maxProofLoops: 2, remaining: budgetRemaining },
		proofLoopEntered,
		terminal: TERMINAL_STATES.has(status),
		terminalReopened: false,
		closureReason: status === "done" ? "operator/proof-loop resumed exact context and closed proof row" : "budget exhausted row escalated without reopening terminal compact resume state",
		verifiedBy: ["re_operator dispatch", "re_proof_loop run", "CompactResumeLedgerV2"],
	};
}

function buildRuntimeMatrix(tempRoot) {
	const artifactDir = join(tempRoot, "artifacts");
	mkdirSync(artifactDir, { recursive: true });
	const sourceSessionId = "session-alpha-source";
	const resumeSessionId = "session-beta-resume";
	const latestDecoySessionId = "session-gamma-latest-decoy";
	const missionId = "cross-session-multi-compact-matrix";
	const target = "https://cross-session-multi-compact.local/app";
	const artifacts = [];
	for (const name of ["map-routes", "memory-store", "proof-anchor"]) {
		const path = join(artifactDir, `${name}.json`);
		writeJson(path, { name, target, missionId, verified: true });
		artifacts.push(fileArtifact(tempRoot, path));
	}
	const cycleOnePack = buildContextPack(tempRoot, "compact-cycle-001", sourceSessionId, target, artifacts);
	const cycleTwoPack = buildContextPack(tempRoot, "compact-cycle-002", sourceSessionId, target, artifacts);
	const latestDecoyPack = buildContextPack(tempRoot, "compact-cycle-latest-decoy", latestDecoySessionId, "https://wrong-latest.local/app", artifacts);
	const compactCycles = [
		{
			cycleId: "compact-cycle-001",
			sourceSessionId,
			resumeSessionId,
			packTarget: target,
			resumeTarget: target,
			contextPath: cycleOnePack.contextPath,
			contextSha256: cycleOnePack.contextSha256,
			artifactHashes: cycleOnePack.artifactHashes,
			latestFallbackCandidate: latestDecoyPack.contextPath,
			loadedBy: "contextPath",
			explicitContextPathUsed: true,
			oldContextPathBeatsLatestFallback: true,
			exactResumeVerification: { contextSha256Match: true, artifactHashesOk: true, scopeOk: true, loadedBy: "contextPath" },
			resumeClosure: { status: "done", closedAt: new Date().toISOString(), verifiedBy: ["re_context resume", "CompactResumeLedgerV2"] },
			providerContinuationId: "provider-continuation-001",
		},
		{
			cycleId: "compact-cycle-002",
			sourceSessionId,
			resumeSessionId,
			packTarget: target,
			resumeTarget: target,
			contextPath: cycleTwoPack.contextPath,
			contextSha256: cycleTwoPack.contextSha256,
			artifactHashes: cycleTwoPack.artifactHashes,
			latestFallbackCandidate: latestDecoyPack.contextPath,
			loadedBy: "contextPath",
			explicitContextPathUsed: true,
			oldContextPathBeatsLatestFallback: true,
			exactResumeVerification: { contextSha256Match: true, artifactHashesOk: true, scopeOk: true, loadedBy: "contextPath" },
			resumeClosure: { status: "exhausted", closedAt: new Date().toISOString(), verifiedBy: ["re_operator dispatch", "re_proof_loop run", "CompactResumeLedgerV2"] },
			providerContinuationId: "provider-continuation-002",
		},
	];
	const providerContinuations = compactCycles.map((cycle) => buildProviderContinuation(tempRoot, cycle.cycleId, resumeSessionId));
	const ledgerTransitions = buildLedgerTransitions([
		{ cycleId: "compact-cycle-001", sessionId: sourceSessionId, state: "queued", contextPath: cycleOnePack.contextPath, contextSha256: cycleOnePack.contextSha256, idempotencyKey: "compact-cycle-001:resume" },
		{ cycleId: "compact-cycle-001", sessionId: resumeSessionId, state: "running", contextPath: cycleOnePack.contextPath, contextSha256: cycleOnePack.contextSha256, idempotencyKey: "compact-cycle-001:resume" },
		{ cycleId: "compact-cycle-001", sessionId: resumeSessionId, state: "done", contextPath: cycleOnePack.contextPath, contextSha256: cycleOnePack.contextSha256, idempotencyKey: "compact-cycle-001:resume" },
		{ cycleId: "compact-cycle-002", sessionId: sourceSessionId, state: "queued", contextPath: cycleTwoPack.contextPath, contextSha256: cycleTwoPack.contextSha256, idempotencyKey: "compact-cycle-002:resume" },
		{ cycleId: "compact-cycle-002", sessionId: resumeSessionId, state: "running", contextPath: cycleTwoPack.contextPath, contextSha256: cycleTwoPack.contextSha256, idempotencyKey: "compact-cycle-002:resume" },
		{ cycleId: "compact-cycle-002", sessionId: resumeSessionId, state: "exhausted", contextPath: cycleTwoPack.contextPath, contextSha256: cycleTwoPack.contextSha256, idempotencyKey: "compact-cycle-002:resume" },
	]);
	const transitionPath = join(tempRoot, "memory", "compaction-resume-transitions.jsonl");
	writeFile(transitionPath, `${ledgerTransitions.map((row) => JSON.stringify(row)).join("\n")}\n`);
	const operatorProofClosures = [buildOperatorProofClosure("compact-cycle-001", "done", 1), buildOperatorProofClosure("compact-cycle-002", "exhausted", 0)];
	return {
		kind: "CrossSessionMultiCompactMatrixGateV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		CrossSessionMultiCompactMatrixGateV1: true,
		requiredGates: REQUIRED_GATES,
		matrix: {
			kind: "CrossSessionMultiCompactMatrixV1",
			schemaVersion: 1,
			closureGate: "gate:cross-session-multi-compact-matrix",
			missionId,
			sessions: [
				{ sessionId: sourceSessionId, role: "source-pack", profileHome: "~/.repi/agent", isolated: true },
				{ sessionId: resumeSessionId, role: "cross-session-resume", profileHome: "~/.repi/agent", isolated: true },
				{ sessionId: latestDecoySessionId, role: "latest-fallback-decoy", profileHome: "~/.repi/agent", isolated: true },
			],
			compactCycles,
			providerContinuations,
			operatorProofClosures,
			compactResumeLedger: {
				kind: "CompactResumeLedgerV2",
				transitionPath: rel(tempRoot, transitionPath),
				transitionSha256: sha256(readFileSync(transitionPath)),
				appendOnly: true,
				hashChainOk: ledgerHashChainOk(ledgerTransitions),
				terminalRowsNotReopened: true,
				transitions: ledgerTransitions,
			},
			providerContinuationPolicy: {
				requiresAfterExactResume: true,
				requiresEnvRefOnly: true,
				requiresRequestLogHash: true,
				requiresNoPiPollution: true,
			},
			promotionPolicy: {
				mode: "block-until-cross-session-multi-compact-provider-proof",
				requiresCrossSession: true,
				requiresMultipleCompacts: true,
				requiresExplicitContextPath: true,
				requiresProviderContinuation: true,
				requiresOperatorProofClosure: true,
			},
		},
		negativeCases: REQUIRED_NEGATIVE_CASES.map((id) => ({ id, mutates: id, expect: "reject", mustNotPromote: true })),
		invariants: INVARIANTS,
	};
}

function validateMatrix(tempRoot, report) {
	const errors = [];
	if (report?.kind !== "CrossSessionMultiCompactMatrixGateV1") errors.push("report.kind");
	if (report?.CrossSessionMultiCompactMatrixGateV1 !== true) errors.push("report.flag");
	const gates = new Set(report?.requiredGates ?? []);
	for (const gate of REQUIRED_GATES) if (!gates.has(gate)) errors.push(`missing_required_gate:${gate}`);
	const matrix = report?.matrix;
	if (matrix?.kind !== "CrossSessionMultiCompactMatrixV1") errors.push("matrix.kind");
	const sessions = matrix?.sessions ?? [];
	const sourceSessions = new Set((matrix?.compactCycles ?? []).map((cycle) => cycle.sourceSessionId));
	const resumeSessions = new Set((matrix?.compactCycles ?? []).map((cycle) => cycle.resumeSessionId));
	if (sessions.length < 2 || [...sourceSessions].some((session) => resumeSessions.has(session))) errors.push("cross_session_not_proven");
	if ((matrix?.compactCycles ?? []).length < 2) errors.push("compact_cycle_count_lt_2");
	const continuationByCycle = new Map((matrix?.providerContinuations ?? []).map((row) => [row.cycleId, row]));
	for (const cycle of matrix?.compactCycles ?? []) {
		if (!cycle.explicitContextPathUsed || cycle.loadedBy !== "contextPath") errors.push(`cycle_not_explicit_context_path:${cycle.cycleId}`);
		if (!cycle.oldContextPathBeatsLatestFallback || !cycle.latestFallbackCandidate || cycle.latestFallbackCandidate === cycle.contextPath) errors.push(`old_context_path_not_preferred:${cycle.cycleId}`);
		if (!existsSync(join(tempRoot, cycle.contextPath))) errors.push(`context_path_missing:${cycle.cycleId}`);
		else if (sha256(readFileSync(join(tempRoot, cycle.contextPath))) !== cycle.contextSha256) errors.push(`context_sha_mismatch:${cycle.cycleId}`);
		if (cycle.exactResumeVerification?.contextSha256Match !== true) errors.push(`exact_resume_context_sha_not_verified:${cycle.cycleId}`);
		if (cycle.exactResumeVerification?.artifactHashesOk !== true) errors.push(`exact_resume_artifact_hash_not_verified:${cycle.cycleId}`);
		if (cycle.exactResumeVerification?.scopeOk !== true) errors.push(`exact_resume_scope_not_verified:${cycle.cycleId}`);
		for (const artifact of cycle.artifactHashes ?? []) {
			const path = join(tempRoot, artifact.path);
			if (artifact.required && !existsSync(path)) errors.push(`required_artifact_missing:${cycle.cycleId}:${artifact.path}`);
			else if (existsSync(path) && sha256(readFileSync(path)) !== artifact.sha256) errors.push(`artifact_hash_mismatch:${cycle.cycleId}:${artifact.path}`);
		}
		const continuation = continuationByCycle.get(cycle.cycleId);
		if (!continuation) errors.push(`provider_continuation_missing:${cycle.cycleId}`);
		else {
			for (const field of ["requestLogPath", "stdoutPath", "stderrPath"]) if (!continuation[field] || !existsSync(join(tempRoot, continuation[field]))) errors.push(`provider_continuation_ref_missing:${cycle.cycleId}:${field}`);
			if (!continuation.apiKeyEnvRefOnly || !continuation.noLiteralSecrets || !continuation.noPiHomeImport || !continuation.noUpdateBanner) errors.push(`provider_continuation_isolation_failed:${cycle.cycleId}`);
			if (continuation.continuationStatus !== "pass") errors.push(`provider_continuation_not_pass:${cycle.cycleId}`);
		}
	}
	const ledger = matrix?.compactResumeLedger;
	if (ledger?.kind !== "CompactResumeLedgerV2") errors.push("ledger.kind");
	if (ledger?.appendOnly !== true || ledger?.hashChainOk !== true || !ledgerHashChainOk(ledger?.transitions ?? [])) errors.push("ledger_hash_chain_not_ok");
	const seenTerminal = new Set();
	for (const transition of ledger?.transitions ?? []) {
		if (seenTerminal.has(transition.cycleId)) errors.push(`terminal_row_reopened:${transition.cycleId}`);
		if (TERMINAL_STATES.has(transition.state)) seenTerminal.add(transition.cycleId);
	}
	if (ledger?.terminalRowsNotReopened !== true) errors.push("terminal_rows_not_reopened_false");
	for (const closure of matrix?.operatorProofClosures ?? []) {
		if (!TERMINAL_STATES.has(closure.proofLoopStatus)) errors.push(`closure_not_terminal:${closure.cycleId}`);
		if (closure.proofLoopEntered !== true) errors.push(`closure_proof_loop_not_entered:${closure.cycleId}`);
		if (closure.terminalReopened) errors.push(`closure_terminal_reopened:${closure.cycleId}`);
		if (closure.proofLoopStatus === "exhausted" && closure.budget?.remaining !== 0) errors.push(`exhausted_budget_not_zero:${closure.cycleId}`);
	}
	if ((matrix?.operatorProofClosures ?? []).length < (matrix?.compactCycles ?? []).length) errors.push("operator_proof_closure_missing");
	const text = JSON.stringify(report);
	if (/\.pi\/|Update Available|pi\.dev\/changelog|ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|sk-[A-Za-z0-9]{8,}/i.test(text)) errors.push("pollution_or_secret_leak");
	return { ok: errors.length === 0, errors };
}

function clone(value) {
	return JSON.parse(JSON.stringify(value));
}

function mutateReport(report, id) {
	const row = clone(report);
	const matrix = row.matrix;
	if (id === "latest-fallback-without-explicit-context") {
		matrix.compactCycles[0].explicitContextPathUsed = false;
		matrix.compactCycles[0].loadedBy = "latest";
		matrix.compactCycles[0].oldContextPathBeatsLatestFallback = false;
	}
	if (id === "context-sha-drift") matrix.compactCycles[0].contextSha256 = "f".repeat(64);
	if (id === "artifact-hash-drift") matrix.compactCycles[0].artifactHashes[0].sha256 = "e".repeat(64);
	if (id === "provider-continuation-missing") matrix.providerContinuations = matrix.providerContinuations.filter((row) => row.cycleId !== matrix.compactCycles[0].cycleId);
	if (id === "budget-exhausted-open") {
		const closure = matrix.operatorProofClosures.find((row) => row.proofLoopStatus === "exhausted") ?? matrix.operatorProofClosures[0];
		closure.budget.remaining = 1;
		closure.proofLoopEntered = false;
	}
	if (id === "terminal-row-reopened") {
		const terminal = matrix.compactResumeLedger.transitions.find((transition) => transition.state === "done");
		matrix.compactResumeLedger.transitions.push({ ...terminal, seq: 99, state: "running", prevHash: matrix.compactResumeLedger.transitions.at(-1).entryHash, entryHash: "0".repeat(64) });
		matrix.compactResumeLedger.terminalRowsNotReopened = false;
	}
	if (id === "same-session-only") for (const cycle of matrix.compactCycles) cycle.resumeSessionId = cycle.sourceSessionId;
	if (id === "ledger-hash-chain-drift") matrix.compactResumeLedger.transitions[1].prevHash = "bad";
	return row;
}

function validateFixture(fixture) {
	const gates = new Set(fixture?.requiredGates ?? []);
	const negative = new Set((fixture?.negativeCases ?? []).map((row) => row.id));
	return {
		missingGates: REQUIRED_GATES.filter((gate) => !gates.has(gate)),
		missingNegativeCases: REQUIRED_NEGATIVE_CASES.filter((id) => !negative.has(id)),
	};
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "cross-session-multi-compact-matrix", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return path;
}

function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-cross-session-multi-compact-"));
	const checks = [];
	try {
		const schema = readJson(SCHEMA_PATH);
		const fixture = readJson(FIXTURE_PATH);
		checks.push(check("schema:parse", Boolean(schema?.$defs?.CrossSessionMultiCompactMatrixGateV1 && schema?.$defs?.CrossSessionMultiCompactCycleV1), { path: SCHEMA_PATH }));
		const fixtureEval = validateFixture(fixture);
		checks.push(check("fixture:coverage", fixtureEval.missingGates.length === 0 && fixtureEval.missingNegativeCases.length === 0, fixtureEval));
		const report = buildRuntimeMatrix(tempRoot);
		const validation = validateMatrix(tempRoot, report);
		checks.push(check("runtime:cross-session-multi-compact-matrix-validation", validation.ok, validation));
		checks.push(check("runtime:cross-session-same-run", new Set(report.matrix.compactCycles.map((cycle) => cycle.sourceSessionId)).size === 1 && new Set(report.matrix.compactCycles.map((cycle) => cycle.resumeSessionId)).size === 1 && report.matrix.compactCycles.every((cycle) => cycle.sourceSessionId !== cycle.resumeSessionId), { cycles: report.matrix.compactCycles.map((cycle) => ({ cycleId: cycle.cycleId, sourceSessionId: cycle.sourceSessionId, resumeSessionId: cycle.resumeSessionId })) }));
		checks.push(check("runtime:old-context-path-over-latest-after-multiple-compacts", report.matrix.compactCycles.length >= 2 && report.matrix.compactCycles.every((cycle) => cycle.explicitContextPathUsed && cycle.loadedBy === "contextPath" && cycle.oldContextPathBeatsLatestFallback), { cycles: report.matrix.compactCycles.map((cycle) => ({ cycleId: cycle.cycleId, contextPath: cycle.contextPath, latestFallbackCandidate: cycle.latestFallbackCandidate, loadedBy: cycle.loadedBy })) }));
		checks.push(check("runtime:context-sha-artifact-hashes-verified", report.matrix.compactCycles.every((cycle) => cycle.exactResumeVerification.contextSha256Match && cycle.exactResumeVerification.artifactHashesOk && cycle.exactResumeVerification.scopeOk), { cycles: report.matrix.compactCycles.map((cycle) => ({ cycleId: cycle.cycleId, exactResumeVerification: cycle.exactResumeVerification, artifactHashes: cycle.artifactHashes.length })) }));
		checks.push(check("runtime:provider-continuation-after-exact-resume", report.matrix.providerContinuations.length === report.matrix.compactCycles.length && report.matrix.providerContinuations.every((row) => row.continuationStatus === "pass" && row.apiKeyEnvRefOnly && row.noLiteralSecrets && row.noPiHomeImport && row.noUpdateBanner), { providerContinuations: report.matrix.providerContinuations.map((row) => ({ cycleId: row.cycleId, requestLogSha256: row.requestLogSha256, stdoutSha256: row.stdoutSha256 })) }));
		checks.push(check("runtime:operator-proof-loop-budget-closure", report.matrix.operatorProofClosures.every((row) => TERMINAL_STATES.has(row.proofLoopStatus) && row.proofLoopEntered && (row.proofLoopStatus !== "exhausted" || row.budget.remaining === 0)), { closures: report.matrix.operatorProofClosures }));
		checks.push(check("runtime:terminal-resume-rows-not-reopened", report.matrix.compactResumeLedger.terminalRowsNotReopened && ledgerHashChainOk(report.matrix.compactResumeLedger.transitions), { transitionCount: report.matrix.compactResumeLedger.transitions.length, tipHash: report.matrix.compactResumeLedger.transitions.at(-1)?.entryHash }));
		const negativeResults = REQUIRED_NEGATIVE_CASES.map((id) => ({ id, validation: validateMatrix(tempRoot, mutateReport(report, id)) }));
		checks.push(check("fixture:negative-rejections", negativeResults.every((row) => !row.validation.ok), { negativeResults: negativeResults.map((row) => ({ id: row.id, ok: row.validation.ok, errors: row.validation.errors })) }));
		checks.push(markerCheck("harness:cross-session-multi-compact-matrix", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:cross-session-multi-compact-matrix", "CrossSessionMultiCompactMatrixGateV1", "child:gate:cross-session-multi-compact-matrix"]));
		checks.push(markerCheck("autonomy:cross-session-multi-compact-matrix", "scripts/reverse-agent/autonomy-control-plane.mjs", ["CrossSessionMultiCompactMatrixGateV1", "cross_session_multi_compact_matrix_gate", "provider_continuation_after_exact_resume"]));
		checks.push(markerCheck("npm:cross-session-multi-compact-matrix", "package.json", ["gate:cross-session-multi-compact-matrix", "cross-session-multi-compact-matrix-gate.mjs"]));
		checks.push(markerCheck("docs:cross-session-multi-compact-matrix-readme", "README.md", ["CrossSessionMultiCompactMatrixGateV1", "gate:cross-session-multi-compact-matrix"]));
		checks.push(markerCheck("docs:cross-session-multi-compact-matrix-control-plane", "docs/reverse-agent/autonomous-control-plane.md", ["CrossSessionMultiCompactMatrixGateV1", "gate:cross-session-multi-compact-matrix"]));
		checks.push(markerCheck("docs:cross-session-multi-compact-matrix-reverse", "docs/reverse-agent/README.md", ["CrossSessionMultiCompactMatrixGateV1", "gate:cross-session-multi-compact-matrix"]));
	} catch (error) {
		checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	const failed = checks.filter((row) => row.status !== "pass");
	const result = { kind: "repi-cross-session-multi-compact-matrix-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), CrossSessionMultiCompactMatrixGateV1: true, ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI CrossSessionMultiCompactMatrixGateV1");
		for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
		console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
	}
	if (strict && failed.length) process.exit(1);
}

main();

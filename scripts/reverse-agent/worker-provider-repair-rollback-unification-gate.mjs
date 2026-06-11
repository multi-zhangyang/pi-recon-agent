#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { failureRepairFromGap, validateFailureRepairBatch } from "./failure-repair-ledger.mjs";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_WORKER_PROVIDER_REPAIR_ROLLBACK_TMP === "1";
const SCHEMA_PATH = "schemas/reverse-agent/worker-provider-repair-rollback-unification.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/worker-provider-repair-rollback-unification.fixture.json";

const REQUIRED_GATES = [
	"WorkerProviderRepairRollbackUnificationGateV1",
	"same_signature_failure_repair_rollback_regression",
	"provider_worker_state_change_writes_rollback_policy",
	"exhausted_failure_blocks_unpaused_rerun",
	"provider_worker_refs_preserve_manifest_request_log_rollback",
	"compound_provider_retry_window_closes_same_signature",
	"regression_gate_refs_match_repair_queue",
];
const REQUIRED_SCENARIOS = ["provider-worker-state-change", "swarm-worker-provider-repair", "compound-frontier-retry-window", "operator-exhausted-escalation"];
const REQUIRED_NEGATIVE_CASES = [
	"signature-mismatch",
	"missing-rollback-policy",
	"exhausted-unpaused-rerun",
	"missing-provider-request-log-ref",
	"regression-gate-mismatch",
	"policy-failure-repair-unlinked",
];
const INVARIANTS = [
	"worker_provider_repair_rollback_unification_gate",
	"same_signature_failure_repair_rollback_regression",
	"provider_worker_state_change_writes_rollback_policy",
	"exhausted_failure_blocks_unpaused_rerun",
	"provider_worker_refs_preserve_manifest_request_log_rollback",
	"compound_provider_retry_window_closes_same_signature",
	"regression_gate_refs_match_repair_queue",
];
const PROVIDER_WORKER_SCENARIOS = new Set(["provider-worker-state-change", "swarm-worker-provider-repair"]);

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

function fileArtifact(base, path, tier = "runtime_artifact") {
	const bytes = readFileSync(path);
	const stat = statSync(path);
	return { path: rel(base, path), sha256: sha256(bytes), tier, bytes: bytes.length, mtime: stat.mtime.toISOString(), exists: true };
}

function safeWriteJson(path, value) {
	mkdirSync(join(path, ".."), { recursive: true });
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function regressionGate(gateId, command, artifactPath, status = "pass") {
	const body = existsSync(artifactPath) ? readFileSync(artifactPath, "utf8") : "";
	return { gateId, command, status, artifactPath: rel(root, artifactPath), artifactSha256: sha256(body) };
}

function buildRollbackPolicy({ tempRoot, scenarioId, source, failure, repair, artifacts, changedFiles, gateIds }) {
	const baselineFiles = artifacts.map((path) => fileArtifact(tempRoot, path));
	const baselineTree = sha256(JSON.stringify(baselineFiles.map((row) => ({ path: row.path, sha256: row.sha256, bytes: row.bytes }))));
	const regressionGates = gateIds.map((gateId) => regressionGate(gateId, `npm run ${gateId}`, artifacts[0]));
	const failureRepairValidation = validateFailureRepairBatch({ failureLedgerEvents: [failure], repairQueue: [repair] });
	const policy = {
		kind: "RepairRollbackPolicyV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		source,
		workspace: tempRoot,
		baseline: { command: `snapshot(${scenarioId})`, treeSha256: baselineTree, files: baselineFiles.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 })) },
		allowlist: changedFiles,
		repair: {
			commands: repair.commands,
			changedFiles,
			expectedArtifacts: repair.expectedArtifacts,
			regressionGates: gateIds,
		},
		rollback: {
			required: true,
			commands: [`restore ${changedFiles.join(" ")}`],
			restored: true,
			restoredTreeSha256: baselineTree,
			criteria: ["restore baseline tree hash", "no unrelated file changes", "previous passed gates remain passed"],
		},
		regression: {
			before: "pass",
			after: "pass",
			restored: "pass",
			gates: regressionGates,
		},
		failureLedgerEvents: [failure],
		repairQueue: [repair],
		failureRepairValidation,
		assertions: {
			baselineCaptured: true,
			allowlistEnforced: true,
			rollbackRestored: true,
			regressionGatesPassed: true,
			noUnrelatedFileChanges: true,
			failureRepairLinked: failureRepairValidation.ok,
		},
	};
	return policy;
}

function buildScenario(tempRoot, spec) {
	const dir = join(tempRoot, spec.id);
	mkdirSync(dir, { recursive: true });
	const manifestPath = join(dir, `${spec.id}-runtime-manifest.json`);
	const requestLogPath = join(dir, `${spec.id}-request-log.json`);
	const statePath = join(dir, `${spec.id}-repair-state.txt`);
	writeFileSync(statePath, `${spec.id}\nBASELINE_OK\n`, "utf8");
	const manifest = {
		kind: spec.worker ? "WorkerProviderRuntimeManifestV1" : "RuntimeRepairManifestV1",
		scenarioId: spec.id,
		workerId: spec.workerId,
		source: spec.source,
		providerName: spec.providerName,
		modelId: spec.modelId,
		failureSignatureBindingRequired: true,
	};
	const requestLog = {
		kind: spec.worker ? "WorkerProviderRequestLogV1" : "RepairRuntimeRequestLogV1",
		scenarioId: spec.id,
		requests: [{ method: "POST", path: spec.requestPath ?? "/v1/chat/completions", providerName: spec.providerName, modelId: spec.modelId, headers: { authorization: "<redacted:env-ref>" } }],
	};
	safeWriteJson(manifestPath, manifest);
	safeWriteJson(requestLogPath, requestLog);
	const artifactPaths = [manifestPath, requestLogPath, statePath];
	const artifactRows = artifactPaths.map((path) => fileArtifact(tempRoot, path));
	const gateIds = spec.gateIds ?? ["gate:worker-provider-repair-rollback-unification", "gate:repair-rollback-policy"];
	const { failure, repair } = failureRepairFromGap({
		root: tempRoot,
		source: spec.source,
		scope: `${spec.source}:${spec.id}`,
		category: "runtime_failed",
		reason: spec.reason,
		failedGates: gateIds,
		artifacts: artifactRows,
		attempt: spec.attempt,
		maxAttempts: spec.maxAttempts,
		status: spec.status,
		action: spec.action,
		providerAllowed: spec.providerAllowed,
		liveAllowed: false,
		paused: spec.paused,
		rollbackRequired: true,
		allowlist: artifactRows.map((artifact) => artifact.path),
		rollbackCriteria: ["restore baseline tree hash", "preserve provider request log", "rerun regression gate"],
		commands: spec.commands,
		expectedArtifacts: artifactRows.map((artifact) => artifact.path),
		regressionGates: gateIds,
		verificationCommand: "npm run gate:worker-provider-repair-rollback-unification",
		exhaustedAction: spec.status === "exhausted" ? "escalate paused repair; do not rerun provider blindly" : "queue bounded rollback repair",
	});
	failure.rollback.restored = spec.status === "repaired" || spec.status === "rolled_back";
	const policy = buildRollbackPolicy({ tempRoot, scenarioId: spec.id, source: spec.policySource, failure, repair, artifacts: artifactPaths, changedFiles: artifactRows.map((artifact) => artifact.path), gateIds });
	const policyPath = join(dir, `${spec.id}-repair-rollback-policy.json`);
	safeWriteJson(policyPath, policy);
	const policyArtifact = fileArtifact(tempRoot, policyPath);
	failure.artifacts.push(policyArtifact);
	failure.artifactHashes.push({ path: policyArtifact.path, sha256: policyArtifact.sha256 });
	repair.expectedArtifacts.push(policyArtifact.path);
	policy.failureLedgerEvents = [failure];
	policy.repairQueue = [repair];
	policy.failureRepairValidation = validateFailureRepairBatch({ failureLedgerEvents: [failure], repairQueue: [repair] });
	policy.assertions.failureRepairLinked = policy.failureRepairValidation.ok;
	safeWriteJson(policyPath, policy);
	const runtimeRefs = {
		runtimeManifestFile: rel(tempRoot, manifestPath),
		requestLogFile: rel(tempRoot, requestLogPath),
		rollbackPolicyFile: rel(tempRoot, policyPath),
		regressionResultFile: rel(tempRoot, statePath),
	};
	const retryWindow = {
		signature: failure.signature,
		closed: spec.retryWindowClosed,
		attempts: spec.retryAttempts ?? [
			{ attempt: Math.max(1, spec.attempt - 1), status: spec.attempt > 1 ? "repair_queued" : spec.status, signature: failure.signature },
			{ attempt: spec.attempt, status: spec.status, signature: failure.signature },
		],
	};
	return {
		id: spec.id,
		source: spec.source,
		workerId: spec.workerId,
		providerName: spec.providerName,
		modelId: spec.modelId,
		stateChangingRepair: true,
		runtimeRefs,
		failureLedgerEvent: failure,
		repairQueueItem: repair,
		rollbackPolicy: policy,
		retryWindow,
		regressionGateRefs: gateIds,
		assertions: {
			sameSignatureFailureRepairRollback: true,
			rollbackPolicyWritten: true,
			providerWorkerRefsPreserved: spec.worker ? true : undefined,
			retryWindowClosed: spec.retryWindowClosed,
			exhaustedDoesNotUnpausedRerun: spec.status === "exhausted" ? repair.paused === true && repair.action !== "rerun" : true,
		},
	};
}

function buildRuntimeReport(tempRoot) {
	const scenarios = [
		buildScenario(tempRoot, {
			id: "provider-worker-state-change",
			source: "provider-worker",
			policySource: "provider-worker",
			worker: true,
			workerId: "provider-worker-alpha",
			providerName: "openai-compatible",
			modelId: "mock/openai-repair-alpha",
			attempt: 1,
			maxAttempts: 2,
			status: "repair_queued",
			action: "rollback",
			providerAllowed: true,
			paused: false,
			retryWindowClosed: true,
			reason: "provider worker state-changing repair must write rollback policy and preserve request log",
			commands: ["node scripts/reverse-agent/repair-rollback-policy-gate.mjs . --strict --no-write", "npm run gate:provider-failure-injection"],
			gateIds: ["gate:worker-provider-repair-rollback-unification", "gate:provider-failure-injection", "gate:repair-rollback-policy"],
		}),
		buildScenario(tempRoot, {
			id: "swarm-worker-provider-repair",
			source: "provider-worker",
			policySource: "provider-worker",
			worker: true,
			workerId: "re-swarm-worker-beta",
			providerName: "anthropic-compatible",
			modelId: "mock/anthropic-repair-beta",
			requestPath: "/v1/messages",
			attempt: 1,
			maxAttempts: 2,
			status: "rolled_back",
			action: "rollback",
			providerAllowed: true,
			paused: false,
			retryWindowClosed: true,
			reason: "re_swarm provider worker repair must preserve manifest, request-log and rollback evidence refs",
			commands: ["npm run gate:swarm-provider-manifest-parity", "npm run gate:worker-child-session"],
			gateIds: ["gate:worker-provider-repair-rollback-unification", "gate:swarm-provider-manifest-parity", "gate:worker-child-session"],
		}),
		buildScenario(tempRoot, {
			id: "compound-frontier-retry-window",
			source: "compound-frontier",
			policySource: "compound-frontier",
			worker: false,
			workerId: "compound-frontier-gamma",
			providerName: "compound-frontier",
			modelId: "offline/compound-frontier",
			attempt: 2,
			maxAttempts: 2,
			status: "repaired",
			action: "recapture-evidence",
			providerAllowed: false,
			paused: false,
			retryWindowClosed: true,
			retryAttempts: [
				{ attempt: 1, status: "repair_queued" },
				{ attempt: 2, status: "repaired" },
			],
			reason: "compound-frontier repair completion closes same signature across retry window",
			commands: ["npm run gate:compound-frontier", "npm run gate:runtime-claim-ledger"],
			gateIds: ["gate:worker-provider-repair-rollback-unification", "gate:runtime-claim-ledger", "gate:repair-rollback-policy"],
		}),
		buildScenario(tempRoot, {
			id: "operator-exhausted-escalation",
			source: "re_operator",
			policySource: "re_operator",
			worker: false,
			workerId: "operator-proof-loop-delta",
			providerName: "operator",
			modelId: "offline/operator",
			attempt: 3,
			maxAttempts: 3,
			status: "exhausted",
			action: "escalate",
			providerAllowed: false,
			paused: true,
			retryWindowClosed: true,
			reason: "exhausted operator repair must pause and escalate instead of unpaused rerun",
			commands: ["re_operator escalate --reason exhausted-repair-budget"],
			gateIds: ["gate:worker-provider-repair-rollback-unification", "gate:failure-signature-priority", "gate:repair-rollback-policy"],
		}),
	];
	for (const scenario of scenarios) {
		for (const attempt of scenario.retryWindow.attempts) attempt.signature = scenario.failureLedgerEvent.signature;
	}
	return {
		kind: "WorkerProviderRepairRollbackUnificationGateV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		WorkerProviderRepairRollbackUnificationGateV1: true,
		requiredGates: REQUIRED_GATES,
		unificationReport: {
			kind: "WorkerProviderRepairRollbackUnificationReportV1",
			schemaVersion: 1,
			closureGate: "gate:worker-provider-repair-rollback-unification",
			scenarios,
			signatureIndex: scenarios.map((scenario) => ({
				scenarioId: scenario.id,
				signature: scenario.failureLedgerEvent.signature,
				failureId: scenario.failureLedgerEvent.id,
				repairId: scenario.repairQueueItem.repairId,
				rollbackPolicyFile: scenario.runtimeRefs.rollbackPolicyFile,
				regressionGateRefs: scenario.regressionGateRefs,
			})),
			promotionPolicy: {
				mode: "block-until-signature-policy-regression-pass",
				requiresFailureRepairBatch: true,
				requiresRollbackPolicyForStateChange: true,
				requiresProviderWorkerRuntimeRefs: true,
				requiresNoUnpausedRerunWhenExhausted: true,
			},
		},
		negativeCases: REQUIRED_NEGATIVE_CASES.map((id) => ({ id, mutates: id, expect: "reject", mustNotPromote: true })),
		invariants: INVARIANTS,
	};
}

function validateRepairRollbackPolicy(policy) {
	const errors = [];
	if (policy?.kind !== "RepairRollbackPolicyV1") errors.push("policy.kind");
	if (!policy?.baseline?.treeSha256 || !policy?.baseline?.files?.length) errors.push("policy.baseline");
	if (!Array.isArray(policy?.allowlist) || policy.allowlist.length === 0) errors.push("policy.allowlist");
	for (const changed of policy?.repair?.changedFiles ?? []) if (!policy.allowlist.includes(changed)) errors.push(`policy.allowlist_violation:${changed}`);
	if (policy?.rollback?.required !== true || policy?.rollback?.restored !== true) errors.push("policy.rollback_not_restored");
	if (policy?.rollback?.restoredTreeSha256 !== policy?.baseline?.treeSha256) errors.push("policy.rollback_tree_hash_mismatch");
	if (!policy?.regression?.gates?.length || !policy.regression.gates.every((gate) => gate.status === "pass")) errors.push("policy.regression_gate_failed_or_missing");
	if (policy?.regression?.after !== "pass" || policy?.regression?.restored !== "pass") errors.push("policy.regression_status_not_pass");
	for (const key of ["baselineCaptured", "allowlistEnforced", "rollbackRestored", "regressionGatesPassed", "noUnrelatedFileChanges", "failureRepairLinked"]) {
		if (policy?.assertions?.[key] !== true) errors.push(`policy.assertion:${key}`);
	}
	const validation = validateFailureRepairBatch({ failureLedgerEvents: policy?.failureLedgerEvents ?? [], repairQueue: policy?.repairQueue ?? [] });
	if (!validation.ok) errors.push("policy.failure_repair_unlinked");
	return { ok: errors.length === 0, errors, failureRepairValidation: validation };
}

function scenarioArtifactsInclude(scenario, relPathValue) {
	return (scenario.failureLedgerEvent?.artifactHashes ?? []).some((artifact) => artifact.path === relPathValue) || (scenario.failureLedgerEvent?.artifacts ?? []).some((artifact) => artifact.path === relPathValue);
}

function repairLooksLikeUnpausedRerun(repair) {
	return repair?.paused !== true && (/\b(?:rerun|retry)\b/i.test(String(repair?.action ?? "")) || /\b(?:rerun|retry)\b/i.test(String(repair?.repairAction ?? "")) || (repair?.commands ?? []).some((command) => /\b(?:rerun|retry)\b/i.test(String(command))));
}

function validateScenario(scenario) {
	const errors = [];
	const failure = scenario?.failureLedgerEvent;
	const repair = scenario?.repairQueueItem;
	const policy = scenario?.rollbackPolicy;
	if (!scenario?.id) errors.push("scenario.id");
	const batch = validateFailureRepairBatch({ failureLedgerEvents: failure ? [failure] : [], repairQueue: repair ? [repair] : [] });
	if (!batch.ok) errors.push("failure_repair_batch_not_ok");
	if (!failure?.signature || failure.signature !== repair?.signature) errors.push("signature_failure_repair_mismatch");
	if (repair?.fromFailureId !== failure?.id || failure?.repairId !== repair?.repairId) errors.push("failure_repair_link_mismatch");
	const policyValidation = validateRepairRollbackPolicy(policy);
	if (!policyValidation.ok) errors.push(...policyValidation.errors);
	const policyFailure = policy?.failureLedgerEvents?.[0];
	const policyRepair = policy?.repairQueue?.[0];
	if (policyFailure?.signature !== failure?.signature || policyRepair?.signature !== failure?.signature) errors.push("rollback_policy_signature_mismatch");
	if (policyFailure?.id !== failure?.id || policyRepair?.repairId !== repair?.repairId) errors.push("rollback_policy_failure_repair_ref_mismatch");
	const policyGateIds = new Set((policy?.regression?.gates ?? []).map((gate) => gate.gateId));
	for (const gateId of repair?.regressionGates ?? []) if (!policyGateIds.has(gateId)) errors.push(`regression_gate_ref_missing:${gateId}`);
	if (scenario?.stateChangingRepair && !scenario?.runtimeRefs?.rollbackPolicyFile) errors.push("state_changing_repair_missing_rollback_policy_file");
	if (scenario?.runtimeRefs?.rollbackPolicyFile && !scenarioArtifactsInclude(scenario, scenario.runtimeRefs.rollbackPolicyFile)) errors.push("rollback_policy_artifact_not_in_failure_refs");
	if (PROVIDER_WORKER_SCENARIOS.has(scenario?.id)) {
		for (const field of ["runtimeManifestFile", "requestLogFile", "rollbackPolicyFile"]) {
			const value = scenario?.runtimeRefs?.[field];
			if (!value) errors.push(`provider_worker_missing_${field}`);
			else if (!scenarioArtifactsInclude(scenario, value)) errors.push(`provider_worker_ref_not_in_failure_artifacts:${field}`);
		}
	}
	if (failure?.status === "exhausted" && repairLooksLikeUnpausedRerun(repair)) errors.push("exhausted_unpaused_rerun");
	if (failure?.status === "exhausted" && failure?.retryBudget?.remainingAttempts !== 0) errors.push("exhausted_budget_not_zero");
	if (scenario?.retryWindow?.signature !== failure?.signature) errors.push("retry_window_signature_mismatch");
	if (!scenario?.retryWindow?.closed) errors.push("retry_window_not_closed");
	for (const attempt of scenario?.retryWindow?.attempts ?? []) if (attempt.signature !== failure?.signature) errors.push("retry_window_attempt_signature_mismatch");
	return { ok: errors.length === 0, errors, batch, policyValidation };
}

function validateReport(report) {
	const errors = [];
	if (report?.kind !== "WorkerProviderRepairRollbackUnificationGateV1") errors.push("report.kind");
	if (report?.WorkerProviderRepairRollbackUnificationGateV1 !== true) errors.push("report.flag");
	const gates = new Set(report?.requiredGates ?? []);
	for (const gate of REQUIRED_GATES) if (!gates.has(gate)) errors.push(`missing_required_gate:${gate}`);
	const scenarios = report?.unificationReport?.scenarios ?? [];
	const ids = new Set(scenarios.map((scenario) => scenario.id));
	for (const id of REQUIRED_SCENARIOS) if (!ids.has(id)) errors.push(`missing_scenario:${id}`);
	const scenarioResults = scenarios.map((scenario) => ({ id: scenario.id, ...validateScenario(scenario) }));
	for (const result of scenarioResults) if (!result.ok) errors.push(`scenario_invalid:${result.id}:${result.errors.join(",")}`);
	const signatures = new Set(scenarios.map((scenario) => scenario.failureLedgerEvent?.signature).filter(Boolean));
	if (signatures.size !== scenarios.length) errors.push("scenario_signatures_not_unique");
	const text = JSON.stringify(report);
	if (/ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|sk-[A-Za-z0-9]{8,}/i.test(text)) errors.push("literal_secret_leak");
	return { ok: errors.length === 0, errors, scenarioResults };
}

function clone(value) {
	return JSON.parse(JSON.stringify(value));
}

function mutateReport(report, id) {
	const row = clone(report);
	const scenarios = row.unificationReport.scenarios;
	const first = scenarios[0];
	if (id === "signature-mismatch") first.repairQueueItem.signature = "deadbeefsignaturemismatch";
	if (id === "missing-rollback-policy") delete first.rollbackPolicy;
	if (id === "exhausted-unpaused-rerun") {
		const exhausted = scenarios.find((scenario) => scenario.id === "operator-exhausted-escalation") ?? first;
		exhausted.failureLedgerEvent.status = "exhausted";
		exhausted.failureLedgerEvent.retryBudget.remainingAttempts = 0;
		exhausted.failureLedgerEvent.budget.remainingAttempts = 0;
		exhausted.repairQueueItem.action = "rerun";
		exhausted.repairQueueItem.repairAction = "rerun";
		exhausted.repairQueueItem.paused = false;
		exhausted.repairQueueItem.commands = ["repi rerun exhausted provider worker"];
		exhausted.rollbackPolicy.repairQueue = [exhausted.repairQueueItem];
	}
	if (id === "missing-provider-request-log-ref") {
		delete first.runtimeRefs.requestLogFile;
		first.failureLedgerEvent.artifacts = first.failureLedgerEvent.artifacts.filter((artifact) => !String(artifact.path).includes("request-log"));
		first.failureLedgerEvent.artifactHashes = first.failureLedgerEvent.artifactHashes.filter((artifact) => !String(artifact.path).includes("request-log"));
	}
	if (id === "regression-gate-mismatch") first.repairQueueItem.regressionGates.push("gate:missing-regression-after-repair");
	if (id === "policy-failure-repair-unlinked") {
		first.rollbackPolicy.repairQueue = [];
		first.rollbackPolicy.failureRepairValidation = { ok: false, failureCount: 1, repairCount: 0 };
	}
	return row;
}

function validateFixture(fixture) {
	const gates = new Set(fixture?.requiredGates ?? []);
	const scenarios = new Set((fixture?.scenarios ?? []).map((scenario) => scenario.id));
	const negative = new Set((fixture?.negativeCases ?? []).map((row) => row.id));
	return {
		missingGates: REQUIRED_GATES.filter((gate) => !gates.has(gate)),
		missingScenarios: REQUIRED_SCENARIOS.filter((id) => !scenarios.has(id)),
		missingNegativeCases: REQUIRED_NEGATIVE_CASES.filter((id) => !negative.has(id)),
	};
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "worker-provider-repair-rollback-unification", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return path;
}

async function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-worker-provider-repair-rollback-"));
	const checks = [];
	let report;
	try {
		const schema = readJson(SCHEMA_PATH);
		const fixture = readJson(FIXTURE_PATH);
		checks.push(check("schema:parse", Boolean(schema?.$defs?.WorkerProviderRepairRollbackUnificationGateV1 && schema?.$defs?.WorkerProviderRepairRollbackUnificationScenarioV1), { path: SCHEMA_PATH }));
		const fixtureEval = validateFixture(fixture);
		checks.push(check("fixture:coverage", fixtureEval.missingGates.length === 0 && fixtureEval.missingScenarios.length === 0 && fixtureEval.missingNegativeCases.length === 0, fixtureEval));
		report = buildRuntimeReport(tempRoot);
		const validation = validateReport(report);
		checks.push(check("runtime:unification-report-validation", validation.ok, validation));
		checks.push(check("runtime:same-signature-failure-repair-rollback-regression", validation.scenarioResults.every((row) => row.ok && row.errors.every((error) => !/signature|regression/.test(error))), { scenarioResults: validation.scenarioResults.map((row) => ({ id: row.id, ok: row.ok, errors: row.errors })) }));
		checks.push(check("runtime:provider-worker-state-change-rollback-policy", (report.unificationReport.scenarios ?? []).filter((scenario) => PROVIDER_WORKER_SCENARIOS.has(scenario.id)).every((scenario) => scenario.runtimeRefs.rollbackPolicyFile && scenario.rollbackPolicy?.kind === "RepairRollbackPolicyV1" && scenario.rollbackPolicy.assertions?.rollbackRestored), { providerWorkerScenarios: (report.unificationReport.scenarios ?? []).filter((scenario) => PROVIDER_WORKER_SCENARIOS.has(scenario.id)).map((scenario) => ({ id: scenario.id, refs: scenario.runtimeRefs, policyKind: scenario.rollbackPolicy?.kind })) }));
		checks.push(check("runtime:exhausted-blocks-unpaused-rerun", (report.unificationReport.scenarios ?? []).filter((scenario) => scenario.failureLedgerEvent.status === "exhausted").every((scenario) => scenario.repairQueueItem.paused === true && scenario.repairQueueItem.action !== "rerun" && scenario.failureLedgerEvent.retryBudget.remainingAttempts === 0), { exhausted: (report.unificationReport.scenarios ?? []).filter((scenario) => scenario.failureLedgerEvent.status === "exhausted").map((scenario) => ({ id: scenario.id, action: scenario.repairQueueItem.action, paused: scenario.repairQueueItem.paused, remainingAttempts: scenario.failureLedgerEvent.retryBudget.remainingAttempts })) }));
		checks.push(check("runtime:provider-worker-refs-preserved", (report.unificationReport.scenarios ?? []).filter((scenario) => PROVIDER_WORKER_SCENARIOS.has(scenario.id)).every((scenario) => ["runtimeManifestFile", "requestLogFile", "rollbackPolicyFile"].every((field) => scenario.runtimeRefs[field] && scenarioArtifactsInclude(scenario, scenario.runtimeRefs[field]))), { providerWorkerRefs: (report.unificationReport.scenarios ?? []).filter((scenario) => PROVIDER_WORKER_SCENARIOS.has(scenario.id)).map((scenario) => ({ id: scenario.id, refs: scenario.runtimeRefs })) }));
		checks.push(check("runtime:compound-provider-retry-window-closed", (report.unificationReport.scenarios ?? []).some((scenario) => scenario.id === "compound-frontier-retry-window" && scenario.retryWindow.closed && scenario.retryWindow.attempts.every((attempt) => attempt.signature === scenario.failureLedgerEvent.signature)), { compound: (report.unificationReport.scenarios ?? []).find((scenario) => scenario.id === "compound-frontier-retry-window")?.retryWindow }));
		const negativeResults = REQUIRED_NEGATIVE_CASES.map((id) => ({ id, validation: validateReport(mutateReport(report, id)) }));
		checks.push(check("fixture:negative-rejections", negativeResults.every((row) => !row.validation.ok), { negativeResults: negativeResults.map((row) => ({ id: row.id, ok: row.validation.ok, errors: row.validation.errors })) }));
		checks.push(markerCheck("harness:worker-provider-repair-rollback-unification", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:worker-provider-repair-rollback-unification", "WorkerProviderRepairRollbackUnificationGateV1", "child:gate:worker-provider-repair-rollback-unification"]));
		checks.push(markerCheck("autonomy:worker-provider-repair-rollback-unification", "scripts/reverse-agent/autonomy-control-plane.mjs", ["WorkerProviderRepairRollbackUnificationGateV1", "worker_provider_repair_rollback_unification_gate", "provider_worker_state_change_writes_rollback_policy"]));
		checks.push(markerCheck("npm:worker-provider-repair-rollback-unification", "package.json", ["gate:worker-provider-repair-rollback-unification", "worker-provider-repair-rollback-unification-gate.mjs"]));
		checks.push(markerCheck("docs:worker-provider-repair-rollback-unification-readme", "README.md", ["WorkerProviderRepairRollbackUnificationGateV1", "gate:worker-provider-repair-rollback-unification"]));
		checks.push(markerCheck("docs:worker-provider-repair-rollback-unification-control-plane", "docs/reverse-agent/autonomous-control-plane.md", ["WorkerProviderRepairRollbackUnificationGateV1", "gate:worker-provider-repair-rollback-unification"]));
		checks.push(markerCheck("docs:worker-provider-repair-rollback-unification-reverse", "docs/reverse-agent/README.md", ["WorkerProviderRepairRollbackUnificationGateV1", "gate:worker-provider-repair-rollback-unification"]));
	} catch (error) {
		checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	const failed = checks.filter((row) => row.status !== "pass");
	const result = { kind: "repi-worker-provider-repair-rollback-unification-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), WorkerProviderRepairRollbackUnificationGateV1: true, ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI WorkerProviderRepairRollbackUnificationGateV1");
		for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
		console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
	}
	if (strict && failed.length) process.exit(1);
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});

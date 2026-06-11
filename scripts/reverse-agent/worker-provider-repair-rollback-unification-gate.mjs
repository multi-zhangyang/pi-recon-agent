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
	"provider_worker_live_state_change_repair_matrix",
	"multi_attempt_retry_window_completion_chain",
	"provider_worker_state_lineage_snapshot_matrix",
	"compound_provider_long_horizon_repair_completion_chain",
];
const REQUIRED_SCENARIOS = ["provider-worker-state-change", "swarm-worker-provider-repair", "provider-worker-cache-state-repair", "swarm-worker-tool-state-repair", "compound-frontier-retry-window", "compound-provider-long-horizon-repair", "operator-exhausted-escalation"];
const REQUIRED_NEGATIVE_CASES = [
	"signature-mismatch",
	"missing-rollback-policy",
	"exhausted-unpaused-rerun",
	"missing-provider-request-log-ref",
	"regression-gate-mismatch",
	"policy-failure-repair-unlinked",
	"live-repair-matrix-missing-provider",
	"retry-window-not-monotonic",
	"completion-without-regression-proof",
	"state-lineage-missing-baseline",
	"long-horizon-chain-too-short",
	"long-horizon-signature-drift",
];
const INVARIANTS = [
	"worker_provider_repair_rollback_unification_gate",
	"same_signature_failure_repair_rollback_regression",
	"provider_worker_state_change_writes_rollback_policy",
	"exhausted_failure_blocks_unpaused_rerun",
	"provider_worker_refs_preserve_manifest_request_log_rollback",
	"compound_provider_retry_window_closes_same_signature",
	"regression_gate_refs_match_repair_queue",
	"provider_worker_live_state_change_repair_matrix",
	"multi_attempt_retry_window_completion_chain",
	"provider_worker_state_lineage_snapshot_matrix",
	"compound_provider_long_horizon_repair_completion_chain",
];
const PROVIDER_WORKER_SCENARIOS = new Set(["provider-worker-state-change", "swarm-worker-provider-repair", "provider-worker-cache-state-repair", "swarm-worker-tool-state-repair"]);
const LONG_HORIZON_SCENARIOS = new Set(["provider-worker-cache-state-repair", "compound-provider-long-horizon-repair"]);

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

function providerApiStyle(providerName) {
	return /anthropic/i.test(providerName) ? "anthropic-compatible" : "openai-compatible";
}

function buildLiveRepairMatrix(scenarios) {
	const providerRows = scenarios
		.filter((scenario) => PROVIDER_WORKER_SCENARIOS.has(scenario.id))
		.map((scenario) => ({
			scenarioId: scenario.id,
			workerId: scenario.workerId,
			providerName: scenario.providerName,
			modelId: scenario.modelId,
			apiStyle: providerApiStyle(scenario.providerName),
			stateChangingRepair: scenario.stateChangingRepair === true,
			runtimeManifestFile: scenario.runtimeRefs.runtimeManifestFile,
			requestLogFile: scenario.runtimeRefs.requestLogFile,
			rollbackPolicyFile: scenario.runtimeRefs.rollbackPolicyFile,
			regressionGateRefs: scenario.regressionGateRefs,
			failureId: scenario.failureLedgerEvent.id,
			repairId: scenario.repairQueueItem.repairId,
			signature: scenario.failureLedgerEvent.signature,
			rollbackPolicySha256: sha256(JSON.stringify(scenario.rollbackPolicy)),
			assertions: {
				requestLogPreserved: scenarioArtifactsInclude(scenario, scenario.runtimeRefs.requestLogFile),
				rollbackPolicyBound: scenarioArtifactsInclude(scenario, scenario.runtimeRefs.rollbackPolicyFile),
				runtimeManifestBound: scenarioArtifactsInclude(scenario, scenario.runtimeRefs.runtimeManifestFile),
				regressionGateRefsMatchRepairQueue: (scenario.repairQueueItem.regressionGates ?? []).every((gate) => scenario.regressionGateRefs.includes(gate)),
				noLiteralSecrets: !/ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|sk-[A-Za-z0-9]{8,}/i.test(JSON.stringify(scenario)),
			},
		}));
	return {
		kind: "ProviderWorkerLiveRepairMatrixV1",
		providerCount: new Set(providerRows.map((row) => row.providerName)).size,
		apiStyles: [...new Set(providerRows.map((row) => row.apiStyle))],
		stateChangingRepairCount: providerRows.filter((row) => row.stateChangingRepair).length,
		rows: providerRows,
		allRollbackPolicyBound: providerRows.every((row) => row.assertions.rollbackPolicyBound),
		allRequestLogsBound: providerRows.every((row) => row.assertions.requestLogPreserved),
		allRegressionRefsMatched: providerRows.every((row) => row.assertions.regressionGateRefsMatchRepairQueue),
		secretFree: providerRows.every((row) => row.assertions.noLiteralSecrets),
	};
}

function buildRetryCompletionChain(scenarios) {
	const chains = scenarios
		.filter((scenario) => scenario.id === "compound-frontier-retry-window" || scenario.id === "operator-exhausted-escalation")
		.map((scenario) => ({
			scenarioId: scenario.id,
			signature: scenario.failureLedgerEvent.signature,
			terminalStatus: scenario.failureLedgerEvent.status,
			attempts: scenario.retryWindow.attempts,
			attemptCount: scenario.retryWindow.attempts.length,
			closed: scenario.retryWindow.closed,
			regressionGateRefs: scenario.regressionGateRefs,
			repairRegressionGateRefs: scenario.repairQueueItem.regressionGates,
			rollbackPolicyFile: scenario.runtimeRefs.rollbackPolicyFile,
			regressionProofSha256: sha256(JSON.stringify(scenario.rollbackPolicy.regression ?? {})),
			completionProof: {
				monotonicAttempts: scenario.retryWindow.attempts.every((attempt, index, attempts) => index === 0 || attempt.attempt > attempts[index - 1].attempt),
				sameSignature: scenario.retryWindow.attempts.every((attempt) => attempt.signature === scenario.failureLedgerEvent.signature),
				terminalClosed: scenario.retryWindow.closed === true && ["repaired", "rolled_back", "exhausted", "blocked"].includes(scenario.failureLedgerEvent.status),
				regressionGateRefsMatchRepairQueue: (scenario.repairQueueItem.regressionGates ?? []).every((gate) => scenario.regressionGateRefs.includes(gate)),
				noUnpausedRerun: scenario.failureLedgerEvent.status !== "exhausted" || (scenario.repairQueueItem.paused === true && !repairLooksLikeUnpausedRerun(scenario.repairQueueItem)),
			},
		}));
	return {
		kind: "MultiAttemptRetryWindowCompletionChainV1",
		minAttemptCount: Math.min(...chains.map((chain) => chain.attemptCount)),
		chains,
		allClosed: chains.every((chain) => chain.closed),
		allMonotonic: chains.every((chain) => chain.completionProof.monotonicAttempts),
		allSameSignature: chains.every((chain) => chain.completionProof.sameSignature),
		allRegressionProofsPresent: chains.every((chain) => chain.regressionGateRefs.length > 0 && /^[a-f0-9]{64}$/.test(chain.regressionProofSha256)),
	};
}

function buildStateLineageSnapshotMatrix(scenarios) {
	const rows = scenarios
		.filter((scenario) => PROVIDER_WORKER_SCENARIOS.has(scenario.id))
		.map((scenario) => {
			const baselineTreeSha256 = scenario.rollbackPolicy?.baseline?.treeSha256;
			const restoredTreeSha256 = scenario.rollbackPolicy?.rollback?.restoredTreeSha256;
			return {
				scenarioId: scenario.id,
				workerId: scenario.workerId,
				providerName: scenario.providerName,
				apiStyle: providerApiStyle(scenario.providerName),
				stateChangingRepair: scenario.stateChangingRepair === true,
				runtimeManifestFile: scenario.runtimeRefs.runtimeManifestFile,
				requestLogFile: scenario.runtimeRefs.requestLogFile,
				rollbackPolicyFile: scenario.runtimeRefs.rollbackPolicyFile,
				baselineTreeSha256,
				mutationScopeSha256: sha256(JSON.stringify({ scenarioId: scenario.id, allowlist: scenario.rollbackPolicy?.allowlist ?? [], commands: scenario.repairQueueItem?.commands ?? [] })),
				restoredTreeSha256,
				regressionProofSha256: sha256(JSON.stringify(scenario.rollbackPolicy?.regression ?? {})),
				repairId: scenario.repairQueueItem.repairId,
				failureId: scenario.failureLedgerEvent.id,
				signature: scenario.failureLedgerEvent.signature,
				assertions: {
					baselineCaptured: /^[a-f0-9]{64}$/.test(String(baselineTreeSha256 ?? "")),
					stateMutationScoped: (scenario.rollbackPolicy?.allowlist ?? []).length > 0 && (scenario.rollbackPolicy?.repair?.changedFiles ?? []).every((changed) => scenario.rollbackPolicy.allowlist.includes(changed)),
					rollbackRestoredBaseline: Boolean(baselineTreeSha256 && baselineTreeSha256 === restoredTreeSha256),
					requestLogBound: scenarioArtifactsInclude(scenario, scenario.runtimeRefs.requestLogFile),
					runtimeManifestBound: scenarioArtifactsInclude(scenario, scenario.runtimeRefs.runtimeManifestFile),
					rollbackPolicyBound: scenarioArtifactsInclude(scenario, scenario.runtimeRefs.rollbackPolicyFile),
					regressionProofPresent: /^[a-f0-9]{64}$/.test(sha256(JSON.stringify(scenario.rollbackPolicy?.regression ?? {}))),
				},
			};
		});
	return {
		kind: "ProviderWorkerStateLineageSnapshotMatrixV1",
		rowCount: rows.length,
		providerCount: new Set(rows.map((row) => row.providerName)).size,
		apiStyles: [...new Set(rows.map((row) => row.apiStyle))],
		rows,
		allBaselineCaptured: rows.every((row) => row.assertions.baselineCaptured),
		allStateMutationsScoped: rows.every((row) => row.assertions.stateMutationScoped),
		allRollbackRestoredBaseline: rows.every((row) => row.assertions.rollbackRestoredBaseline),
		allRequestLogsBound: rows.every((row) => row.assertions.requestLogBound),
		allRegressionProofsPresent: rows.every((row) => row.assertions.regressionProofPresent),
	};
}

function buildLongHorizonRepairCompletionChain(scenarios) {
	const chains = scenarios
		.filter((scenario) => LONG_HORIZON_SCENARIOS.has(scenario.id))
		.map((scenario) => ({
			scenarioId: scenario.id,
			source: scenario.source,
			workerId: scenario.workerId,
			providerName: scenario.providerName,
			signature: scenario.failureLedgerEvent.signature,
			terminalStatus: scenario.failureLedgerEvent.status,
			attempts: scenario.retryWindow.attempts.map((attempt) => ({
				...attempt,
				rollbackPolicyFile: scenario.runtimeRefs.rollbackPolicyFile,
				regressionProofSha256: sha256(JSON.stringify({ scenarioId: scenario.id, attempt: attempt.attempt, regression: scenario.rollbackPolicy?.regression ?? {} })),
			})),
			attemptCount: scenario.retryWindow.attempts.length,
			closed: scenario.retryWindow.closed,
			regressionGateRefs: scenario.regressionGateRefs,
			repairRegressionGateRefs: scenario.repairQueueItem.regressionGates,
			completionProof: {
				monotonicAttempts: scenario.retryWindow.attempts.every((attempt, index, attempts) => index === 0 || attempt.attempt > attempts[index - 1].attempt),
				sameSignature: scenario.retryWindow.attempts.every((attempt) => attempt.signature === scenario.failureLedgerEvent.signature),
				terminalClosed: scenario.retryWindow.closed === true && ["repaired", "rolled_back", "exhausted", "blocked"].includes(scenario.failureLedgerEvent.status),
				regressionGateRefsMatchRepairQueue: (scenario.repairQueueItem.regressionGates ?? []).every((gate) => scenario.regressionGateRefs.includes(gate)),
				allAttemptRegressionProofs: scenario.retryWindow.attempts.every((attempt) => /^[a-f0-9]{64}$/.test(sha256(JSON.stringify({ scenarioId: scenario.id, attempt: attempt.attempt, regression: scenario.rollbackPolicy?.regression ?? {} })))),
			},
		}));
	return {
		kind: "CompoundProviderLongHorizonRepairCompletionChainV1",
		minAttemptCount: Math.min(...chains.map((chain) => chain.attemptCount)),
		longestAttemptCount: Math.max(...chains.map((chain) => chain.attemptCount)),
		chains,
		includesProviderWorker: chains.some((chain) => chain.source === "provider-worker"),
		includesCompoundFrontier: chains.some((chain) => chain.source === "compound-frontier"),
		allClosed: chains.every((chain) => chain.closed),
		allMonotonic: chains.every((chain) => chain.completionProof.monotonicAttempts),
		allSameSignature: chains.every((chain) => chain.completionProof.sameSignature),
		allAttemptRegressionProofs: chains.every((chain) => chain.completionProof.allAttemptRegressionProofs),
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
			id: "provider-worker-cache-state-repair",
			source: "provider-worker",
			policySource: "provider-worker",
			worker: true,
			workerId: "provider-worker-cache-gamma",
			providerName: "openai-compatible",
			modelId: "mock/openai-cache-repair-gamma",
			attempt: 4,
			maxAttempts: 4,
			status: "repaired",
			action: "rollback",
			providerAllowed: true,
			paused: false,
			retryWindowClosed: true,
			retryAttempts: [
				{ attempt: 1, status: "failed" },
				{ attempt: 2, status: "repair_queued" },
				{ attempt: 3, status: "rolled_back" },
				{ attempt: 4, status: "repaired" },
			],
			reason: "provider cache mutation repair must preserve baseline snapshot lineage across a longer retry window",
			commands: ["npm run gate:provider-runtime-matrix", "npm run gate:repair-rollback-policy", "npm run gate:worker-provider-repair-rollback-unification"],
			gateIds: ["gate:worker-provider-repair-rollback-unification", "gate:provider-runtime-matrix", "gate:repair-rollback-policy"],
		}),
		buildScenario(tempRoot, {
			id: "swarm-worker-tool-state-repair",
			source: "provider-worker",
			policySource: "provider-worker",
			worker: true,
			workerId: "re-swarm-tool-delta",
			providerName: "anthropic-compatible",
			modelId: "mock/anthropic-tool-repair-delta",
			requestPath: "/v1/messages",
			attempt: 2,
			maxAttempts: 3,
			status: "rolled_back",
			action: "rollback",
			providerAllowed: true,
			paused: false,
			retryWindowClosed: true,
			retryAttempts: [
				{ attempt: 1, status: "failed" },
				{ attempt: 2, status: "rolled_back" },
			],
			reason: "re_swarm tool state repair must keep runtime manifest, request log, rollback policy, and regression refs in one lineage row",
			commands: ["npm run gate:swarm-provider-manifest-parity", "npm run gate:tool-call-trace-ledger", "npm run gate:repair-rollback-policy"],
			gateIds: ["gate:worker-provider-repair-rollback-unification", "gate:swarm-provider-manifest-parity", "gate:tool-call-trace-ledger", "gate:repair-rollback-policy"],
		}),
		buildScenario(tempRoot, {
			id: "compound-frontier-retry-window",
			source: "compound-frontier",
			policySource: "compound-frontier",
			worker: false,
			workerId: "compound-frontier-gamma",
			providerName: "compound-frontier",
			modelId: "offline/compound-frontier",
			attempt: 3,
			maxAttempts: 3,
			status: "repaired",
			action: "recapture-evidence",
			providerAllowed: false,
			paused: false,
			retryWindowClosed: true,
			retryAttempts: [
				{ attempt: 1, status: "failed" },
				{ attempt: 2, status: "repair_queued" },
				{ attempt: 3, status: "repaired" },
			],
			reason: "compound-frontier repair completion closes same signature across retry window",
			commands: ["npm run gate:compound-frontier", "npm run gate:runtime-claim-ledger"],
			gateIds: ["gate:worker-provider-repair-rollback-unification", "gate:runtime-claim-ledger", "gate:repair-rollback-policy"],
		}),
		buildScenario(tempRoot, {
			id: "compound-provider-long-horizon-repair",
			source: "compound-frontier",
			policySource: "compound-frontier",
			worker: false,
			workerId: "compound-provider-epsilon",
			providerName: "compound-provider",
			modelId: "offline/compound-provider-long-horizon",
			attempt: 5,
			maxAttempts: 5,
			status: "repaired",
			action: "recapture-evidence",
			providerAllowed: false,
			paused: false,
			retryWindowClosed: true,
			retryAttempts: [
				{ attempt: 1, status: "failed" },
				{ attempt: 2, status: "repair_queued" },
				{ attempt: 3, status: "failed" },
				{ attempt: 4, status: "rolled_back" },
				{ attempt: 5, status: "repaired" },
			],
			reason: "compound/provider long-horizon repair completion must keep the same signature and regression proof beyond a three-attempt bounded chain",
			commands: ["npm run gate:compound-frontier", "npm run gate:runtime-claim-ledger", "npm run gate:repair-rollback-policy"],
			gateIds: ["gate:worker-provider-repair-rollback-unification", "gate:runtime-claim-ledger", "gate:repair-rollback-policy", "gate:compound-frontier"],
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
			retryAttempts: [
				{ attempt: 1, status: "failed" },
				{ attempt: 2, status: "repair_queued" },
				{ attempt: 3, status: "exhausted" },
			],
			reason: "exhausted operator repair must pause and escalate instead of unpaused rerun",
			commands: ["re_operator escalate --reason exhausted-repair-budget"],
			gateIds: ["gate:worker-provider-repair-rollback-unification", "gate:failure-signature-priority", "gate:repair-rollback-policy"],
		}),
	];
	for (const scenario of scenarios) {
		for (const attempt of scenario.retryWindow.attempts) attempt.signature = scenario.failureLedgerEvent.signature;
	}
	const liveRepairMatrix = buildLiveRepairMatrix(scenarios);
	const retryWindowCompletionChain = buildRetryCompletionChain(scenarios);
	const stateLineageSnapshotMatrix = buildStateLineageSnapshotMatrix(scenarios);
	const longHorizonRepairCompletionChain = buildLongHorizonRepairCompletionChain(scenarios);
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
			liveRepairMatrix,
			retryWindowCompletionChain,
			stateLineageSnapshotMatrix,
			longHorizonRepairCompletionChain,
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
				requiresProviderWorkerLiveRepairMatrix: true,
				requiresMultiAttemptRetryWindowCompletion: true,
				requiresProviderWorkerStateLineageSnapshotMatrix: true,
				requiresCompoundProviderLongHorizonRepairCompletion: true,
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

function validateLiveRepairMatrix(matrix) {
	const errors = [];
	if (matrix?.kind !== "ProviderWorkerLiveRepairMatrixV1") errors.push("liveRepairMatrix.kind");
	if ((matrix?.providerCount ?? 0) < 2) errors.push("liveRepairMatrix.provider_count_lt_2");
	if (!matrix?.apiStyles?.includes("openai-compatible") || !matrix?.apiStyles?.includes("anthropic-compatible")) errors.push("liveRepairMatrix.api_styles_missing");
	if ((matrix?.stateChangingRepairCount ?? 0) < 2) errors.push("liveRepairMatrix.state_changing_count_lt_2");
	if (matrix?.allRollbackPolicyBound !== true) errors.push("liveRepairMatrix.rollback_policy_not_bound");
	if (matrix?.allRequestLogsBound !== true) errors.push("liveRepairMatrix.request_logs_not_bound");
	if (matrix?.allRegressionRefsMatched !== true) errors.push("liveRepairMatrix.regression_refs_not_matched");
	if (matrix?.secretFree !== true) errors.push("liveRepairMatrix.secret_leak");
	for (const row of matrix?.rows ?? []) {
		for (const field of ["scenarioId", "workerId", "providerName", "modelId", "runtimeManifestFile", "requestLogFile", "rollbackPolicyFile", "signature"]) if (!row[field]) errors.push(`liveRepairMatrix.${field}_missing:${row.scenarioId ?? "unknown"}`);
		if (!["openai-compatible", "anthropic-compatible"].includes(row.apiStyle)) errors.push(`liveRepairMatrix.apiStyle_invalid:${row.scenarioId}`);
		for (const [key, ok] of Object.entries(row.assertions ?? {})) if (ok !== true) errors.push(`liveRepairMatrix.assertion_failed:${row.scenarioId}:${key}`);
	}
	return { ok: errors.length === 0, errors };
}

function validateRetryCompletionChain(chain) {
	const errors = [];
	if (chain?.kind !== "MultiAttemptRetryWindowCompletionChainV1") errors.push("retryCompletion.kind");
	if ((chain?.minAttemptCount ?? 0) < 3) errors.push("retryCompletion.min_attempt_count_lt_3");
	if (chain?.allClosed !== true) errors.push("retryCompletion.not_all_closed");
	if (chain?.allMonotonic !== true) errors.push("retryCompletion.not_monotonic");
	if (chain?.allSameSignature !== true) errors.push("retryCompletion.signature_mismatch");
	if (chain?.allRegressionProofsPresent !== true) errors.push("retryCompletion.regression_proof_missing");
	for (const row of chain?.chains ?? []) {
		if ((row.attempts ?? []).length < 3) errors.push(`retryCompletion.chain_too_short:${row.scenarioId}`);
		if (row.completionProof?.monotonicAttempts !== true) errors.push(`retryCompletion.not_monotonic:${row.scenarioId}`);
		if (row.completionProof?.sameSignature !== true) errors.push(`retryCompletion.signature_mismatch:${row.scenarioId}`);
		if (row.completionProof?.terminalClosed !== true) errors.push(`retryCompletion.terminal_not_closed:${row.scenarioId}`);
		if (row.completionProof?.regressionGateRefsMatchRepairQueue !== true) errors.push(`retryCompletion.regression_ref_mismatch:${row.scenarioId}`);
		if (row.completionProof?.noUnpausedRerun !== true) errors.push(`retryCompletion.unpaused_rerun:${row.scenarioId}`);
		if (!/^[a-f0-9]{64}$/.test(String(row.regressionProofSha256 ?? ""))) errors.push(`retryCompletion.regression_hash_invalid:${row.scenarioId}`);
	}
	return { ok: errors.length === 0, errors };
}

function validateStateLineageSnapshotMatrix(matrix) {
	const errors = [];
	if (matrix?.kind !== "ProviderWorkerStateLineageSnapshotMatrixV1") errors.push("stateLineage.kind");
	if ((matrix?.rowCount ?? 0) < 4) errors.push("stateLineage.row_count_lt_4");
	if ((matrix?.providerCount ?? 0) < 2) errors.push("stateLineage.provider_count_lt_2");
	if (!matrix?.apiStyles?.includes("openai-compatible") || !matrix?.apiStyles?.includes("anthropic-compatible")) errors.push("stateLineage.api_styles_missing");
	for (const key of ["allBaselineCaptured", "allStateMutationsScoped", "allRollbackRestoredBaseline", "allRequestLogsBound", "allRegressionProofsPresent"]) {
		if (matrix?.[key] !== true) errors.push(`stateLineage.${key}_not_true`);
	}
	for (const row of matrix?.rows ?? []) {
		for (const field of ["scenarioId", "workerId", "providerName", "runtimeManifestFile", "requestLogFile", "rollbackPolicyFile", "baselineTreeSha256", "mutationScopeSha256", "restoredTreeSha256", "regressionProofSha256", "signature"]) if (!row[field]) errors.push(`stateLineage.${field}_missing:${row.scenarioId ?? "unknown"}`);
		if (row.baselineTreeSha256 !== row.restoredTreeSha256) errors.push(`stateLineage.baseline_restore_mismatch:${row.scenarioId}`);
		for (const [key, ok] of Object.entries(row.assertions ?? {})) if (ok !== true) errors.push(`stateLineage.assertion_failed:${row.scenarioId}:${key}`);
	}
	return { ok: errors.length === 0, errors };
}

function validateLongHorizonRepairCompletionChain(chain) {
	const errors = [];
	if (chain?.kind !== "CompoundProviderLongHorizonRepairCompletionChainV1") errors.push("longHorizon.kind");
	if ((chain?.minAttemptCount ?? 0) < 4) errors.push("longHorizon.min_attempt_count_lt_4");
	if ((chain?.longestAttemptCount ?? 0) < 5) errors.push("longHorizon.longest_attempt_count_lt_5");
	if (chain?.includesProviderWorker !== true) errors.push("longHorizon.provider_worker_missing");
	if (chain?.includesCompoundFrontier !== true) errors.push("longHorizon.compound_frontier_missing");
	for (const key of ["allClosed", "allMonotonic", "allSameSignature", "allAttemptRegressionProofs"]) if (chain?.[key] !== true) errors.push(`longHorizon.${key}_not_true`);
	for (const row of chain?.chains ?? []) {
		if ((row.attempts ?? []).length < 4) errors.push(`longHorizon.chain_too_short:${row.scenarioId}`);
		if (row.completionProof?.monotonicAttempts !== true) errors.push(`longHorizon.not_monotonic:${row.scenarioId}`);
		if (row.completionProof?.sameSignature !== true) errors.push(`longHorizon.signature_mismatch:${row.scenarioId}`);
		if (row.completionProof?.terminalClosed !== true) errors.push(`longHorizon.terminal_not_closed:${row.scenarioId}`);
		if (row.completionProof?.regressionGateRefsMatchRepairQueue !== true) errors.push(`longHorizon.regression_ref_mismatch:${row.scenarioId}`);
		if (row.completionProof?.allAttemptRegressionProofs !== true) errors.push(`longHorizon.attempt_regression_proof_missing:${row.scenarioId}`);
		for (const attempt of row.attempts ?? []) {
			if (attempt.signature !== row.signature) errors.push(`longHorizon.attempt_signature_drift:${row.scenarioId}:${attempt.attempt}`);
			if (!attempt.rollbackPolicyFile) errors.push(`longHorizon.attempt_rollback_missing:${row.scenarioId}:${attempt.attempt}`);
			if (!/^[a-f0-9]{64}$/.test(String(attempt.regressionProofSha256 ?? ""))) errors.push(`longHorizon.attempt_regression_hash_invalid:${row.scenarioId}:${attempt.attempt}`);
		}
	}
	return { ok: errors.length === 0, errors };
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
	const liveRepairMatrixValidation = validateLiveRepairMatrix(report?.unificationReport?.liveRepairMatrix);
	if (!liveRepairMatrixValidation.ok) errors.push(...liveRepairMatrixValidation.errors);
	const retryCompletionValidation = validateRetryCompletionChain(report?.unificationReport?.retryWindowCompletionChain);
	if (!retryCompletionValidation.ok) errors.push(...retryCompletionValidation.errors);
	const stateLineageValidation = validateStateLineageSnapshotMatrix(report?.unificationReport?.stateLineageSnapshotMatrix);
	if (!stateLineageValidation.ok) errors.push(...stateLineageValidation.errors);
	const longHorizonValidation = validateLongHorizonRepairCompletionChain(report?.unificationReport?.longHorizonRepairCompletionChain);
	if (!longHorizonValidation.ok) errors.push(...longHorizonValidation.errors);
	const signatures = new Set(scenarios.map((scenario) => scenario.failureLedgerEvent?.signature).filter(Boolean));
	if (signatures.size !== scenarios.length) errors.push("scenario_signatures_not_unique");
	const text = JSON.stringify(report);
	if (/ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|sk-[A-Za-z0-9]{8,}/i.test(text)) errors.push("literal_secret_leak");
	return { ok: errors.length === 0, errors, scenarioResults, liveRepairMatrixValidation, retryCompletionValidation, stateLineageValidation, longHorizonValidation };
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
	if (id === "live-repair-matrix-missing-provider") {
		row.unificationReport.liveRepairMatrix.rows = row.unificationReport.liveRepairMatrix.rows.filter((liveRow) => liveRow.apiStyle !== "anthropic-compatible");
		row.unificationReport.liveRepairMatrix.providerCount = 1;
		row.unificationReport.liveRepairMatrix.apiStyles = ["openai-compatible"];
	}
	if (id === "retry-window-not-monotonic") {
		const chain = row.unificationReport.retryWindowCompletionChain.chains[0];
		chain.attempts[1].attempt = chain.attempts[0].attempt;
		chain.completionProof.monotonicAttempts = false;
		row.unificationReport.retryWindowCompletionChain.allMonotonic = false;
	}
	if (id === "completion-without-regression-proof") {
		const chain = row.unificationReport.retryWindowCompletionChain.chains[0];
		chain.regressionGateRefs = [];
		chain.repairRegressionGateRefs = [];
		chain.regressionProofSha256 = "";
		chain.completionProof.regressionGateRefsMatchRepairQueue = false;
		row.unificationReport.retryWindowCompletionChain.allRegressionProofsPresent = false;
	}
	if (id === "state-lineage-missing-baseline") {
		const lineage = row.unificationReport.stateLineageSnapshotMatrix;
		delete lineage.rows[0].baselineTreeSha256;
		lineage.rows[0].assertions.baselineCaptured = false;
		lineage.allBaselineCaptured = false;
	}
	if (id === "long-horizon-chain-too-short") {
		const chain = row.unificationReport.longHorizonRepairCompletionChain.chains.find((entry) => entry.scenarioId === "compound-provider-long-horizon-repair") ?? row.unificationReport.longHorizonRepairCompletionChain.chains[0];
		chain.attempts = chain.attempts.slice(0, 3);
		chain.attemptCount = chain.attempts.length;
		row.unificationReport.longHorizonRepairCompletionChain.minAttemptCount = Math.min(...row.unificationReport.longHorizonRepairCompletionChain.chains.map((entry) => entry.attempts.length));
		row.unificationReport.longHorizonRepairCompletionChain.longestAttemptCount = Math.max(...row.unificationReport.longHorizonRepairCompletionChain.chains.map((entry) => entry.attempts.length));
	}
	if (id === "long-horizon-signature-drift") {
		const chain = row.unificationReport.longHorizonRepairCompletionChain.chains[0];
		chain.attempts[1].signature = "deadbeefsignaturedrift";
		chain.completionProof.sameSignature = false;
		row.unificationReport.longHorizonRepairCompletionChain.allSameSignature = false;
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
		checks.push(check("runtime:provider-worker-live-state-change-repair-matrix", report.unificationReport.liveRepairMatrix.providerCount >= 2 && report.unificationReport.liveRepairMatrix.allRollbackPolicyBound && report.unificationReport.liveRepairMatrix.allRequestLogsBound && report.unificationReport.liveRepairMatrix.allRegressionRefsMatched, report.unificationReport.liveRepairMatrix));
		checks.push(check("runtime:multi-attempt-retry-window-completion-chain", report.unificationReport.retryWindowCompletionChain.minAttemptCount >= 3 && report.unificationReport.retryWindowCompletionChain.allClosed && report.unificationReport.retryWindowCompletionChain.allMonotonic && report.unificationReport.retryWindowCompletionChain.allRegressionProofsPresent, report.unificationReport.retryWindowCompletionChain));
		checks.push(check("runtime:provider-worker-state-lineage-snapshot-matrix", report.unificationReport.stateLineageSnapshotMatrix.rowCount >= 4 && report.unificationReport.stateLineageSnapshotMatrix.allBaselineCaptured && report.unificationReport.stateLineageSnapshotMatrix.allRollbackRestoredBaseline && report.unificationReport.stateLineageSnapshotMatrix.allRegressionProofsPresent, report.unificationReport.stateLineageSnapshotMatrix));
		checks.push(check("runtime:compound-provider-long-horizon-repair-completion-chain", report.unificationReport.longHorizonRepairCompletionChain.minAttemptCount >= 4 && report.unificationReport.longHorizonRepairCompletionChain.longestAttemptCount >= 5 && report.unificationReport.longHorizonRepairCompletionChain.includesProviderWorker && report.unificationReport.longHorizonRepairCompletionChain.includesCompoundFrontier && report.unificationReport.longHorizonRepairCompletionChain.allSameSignature, report.unificationReport.longHorizonRepairCompletionChain));
		const negativeResults = REQUIRED_NEGATIVE_CASES.map((id) => ({ id, validation: validateReport(mutateReport(report, id)) }));
		checks.push(check("fixture:negative-rejections", negativeResults.every((row) => !row.validation.ok), { negativeResults: negativeResults.map((row) => ({ id: row.id, ok: row.validation.ok, errors: row.validation.errors })) }));
		checks.push(markerCheck("harness:worker-provider-repair-rollback-unification", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:worker-provider-repair-rollback-unification", "WorkerProviderRepairRollbackUnificationGateV1", "child:gate:worker-provider-repair-rollback-unification"]));
		checks.push(markerCheck("autonomy:worker-provider-repair-rollback-unification", "scripts/reverse-agent/autonomy-control-plane.mjs", ["WorkerProviderRepairRollbackUnificationGateV1", "worker_provider_repair_rollback_unification_gate", "provider_worker_state_change_writes_rollback_policy", "provider_worker_live_state_change_repair_matrix", "multi_attempt_retry_window_completion_chain", "provider_worker_state_lineage_snapshot_matrix", "compound_provider_long_horizon_repair_completion_chain"]));
		checks.push(markerCheck("npm:worker-provider-repair-rollback-unification", "package.json", ["gate:worker-provider-repair-rollback-unification", "worker-provider-repair-rollback-unification-gate.mjs"]));
		checks.push(markerCheck("docs:worker-provider-repair-rollback-unification-readme", "README.md", ["WorkerProviderRepairRollbackUnificationGateV1", "gate:worker-provider-repair-rollback-unification", "live repair matrix", "multi-attempt", "state lineage", "long-horizon"]));
		checks.push(markerCheck("docs:worker-provider-repair-rollback-unification-control-plane", "docs/reverse-agent/autonomous-control-plane.md", ["WorkerProviderRepairRollbackUnificationGateV1", "gate:worker-provider-repair-rollback-unification", "live repair matrix", "multi-attempt", "state lineage", "long-horizon"]));
		checks.push(markerCheck("docs:worker-provider-repair-rollback-unification-reverse", "docs/reverse-agent/README.md", ["WorkerProviderRepairRollbackUnificationGateV1", "gate:worker-provider-repair-rollback-unification", "live repair matrix", "multi-attempt", "state lineage", "long-horizon"]));
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

#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { validateAutonomousRuntimeContracts } from "./autonomous-runtime-contracts.mjs";
import { FAILURE_REPAIR_CONTRACT_SCHEMA_PATH, FAILURE_REPAIR_DEDUP_WINDOW, FAILURE_REPAIR_STRICT_FIXTURE_PATH, validateFailureRepairBatch, validateFailureRepairStrictFixture } from "./failure-repair-ledger.mjs";
import { buildResult as buildRuntimeClaimLedgerGate } from "./gate-runtime-claim-ledger.mjs";

const CONTRACT_VERSION = 1;
const EVIDENCE_ORDER = ["same_window_live", "runtime_artifact", "network", "served_asset", "process_config", "persisted_state"];

const SCHEMAS = {
	ReconParallelPlanV1: {
		required: ["planId", "source", "workers", "merge"],
		workerRequired: ["id", "role", "objective", "commands", "evidenceContract", "mergeKeys", "dependencies", "artifactGlobs", "limits"],
		mergeRequired: ["strategy", "evidenceOrder", "expectedArtifacts"],
		enums: {
			source: ["re_swarm", "frontier-orchestrator", "agent-dogfood", "hard-eval-control-plane", "operator", "manual"],
			mergeStrategy: ["supervisor", "synthesizer", "frontier-summary", "claim-ledger"],
		},
	},
	ResumeContractV2: {
		required: [
			"contractId",
			"schemaVersion",
			"compactionEntryId",
			"contextPath",
			"contextSha256",
			"cwd",
			"missionId",
			"sessionId",
			"target",
			"artifactHashes",
			"resumeQueueStatus",
			"idempotencyKey",
			"ledgerPath",
			"budget",
			"closure",
		],
		optional: ["branchId", "createdAt", "resumeCommands"],
		enums: { resumeQueueStatus: ["queued", "running", "done", "blocked", "exhausted"] },
	},
	FailureLedgerEventV1: {
		required: ["id", "ts", "source", "scope", "category", "signature", "attempt", "maxAttempts", "status", "failedGates", "artifacts", "artifactHashes", "repairId", "budget", "retryBudget", "evidenceWriteback", "blockedConditions", "rollback"],
		enums: { status: ["failed", "retrying", "repair_queued", "repaired", "exhausted", "rolled_back", "escalated", "blocked"] },
	},
	RepairQueueItemV1: {
		required: ["repairId", "fromFailureId", "signature", "scope", "action", "commands", "expectedArtifacts", "expectedGates", "preconditions", "paused", "allowlist", "rollbackCriteria", "repairAction", "blockedConditions", "evidenceWriteback", "regressionGates"],
		enums: { action: ["rerun", "replace-command", "recapture-evidence", "refresh-context", "escalate", "rollback"] },
	},
	RoleContractV1: {
		required: ["contractVersion", "runId", "evidenceOrder", "roles", "ledgerPolicy", "conflictPolicy", "claimGatePolicy"],
		roleRequired: ["id", "mustEmit", "allowedClaimKinds", "forbiddenClaimKinds", "handoffTargets", "evidenceContract"],
	},
	ClaimLedgerEventV1: {
		eventTypes: ["artifact_handoff", "claim", "validation", "challenge", "resolution"],
		claimRequired: ["seq", "type", "claimId", "role", "scope", "kind", "statement", "evidenceRefs", "prevHash", "eventHash"],
		validationRequired: ["seq", "type", "claimId", "role", "result", "checks", "prevHash", "eventHash"],
	},
	AutonomousRuntimeBatchV1: {
		required: ["subagentRuntimeManifests", "parallelShardStates", "compactResumeStates", "repairBudgetStates", "claimPromotionGates"],
		schemaPath: "schemas/reverse-agent/autonomous-runtime-contract.schema.json",
		fixturePath: "fixtures/reverse-agent/autonomous-runtime-contract.fixture.json",
	},
};

function sha256(text) {
	return createHash("sha256").update(text).digest("hex");
}

function safeJson(text, fallback = null) {
	try {
		return JSON.parse(text);
	} catch {
		return fallback;
	}
}

function runJson(root, args) {
	const run = spawnSync(process.execPath, args, { cwd: root, encoding: "utf8", maxBuffer: 20 * 1024 * 1024 });
	return {
		code: run.status,
		signal: run.signal,
		stdoutSha256: sha256(run.stdout || "").slice(0, 24),
		stderrSha256: sha256(run.stderr || "").slice(0, 24),
		stdoutBytes: Buffer.byteLength(run.stdout || ""),
		stderrBytes: Buffer.byteLength(run.stderr || ""),
		json: safeJson(run.stdout),
		stderrTail: String(run.stderr || "").slice(-2000),
	};
}

function fieldMissing(obj, fields) {
	return fields.filter((field) => obj?.[field] === undefined || obj?.[field] === null);
}

function passFail(condition, detail = {}) {
	return { status: condition ? "pass" : "fail", ...detail };
}

function validateParallelPlan(plan) {
	const schema = SCHEMAS.ReconParallelPlanV1;
	const missing = fieldMissing(plan, schema.required);
	const workerRows = Array.isArray(plan?.workers)
		? plan.workers.map((worker) => ({ id: worker.id, missing: fieldMissing(worker, schema.workerRequired) }))
		: [];
	const mergeMissing = fieldMissing(plan?.merge ?? {}, schema.mergeRequired);
	const ok = missing.length === 0 && Array.isArray(plan.workers) && plan.workers.length > 0 && workerRows.every((row) => row.missing.length === 0) && mergeMissing.length === 0 && schema.enums.source.includes(plan.source) && schema.enums.mergeStrategy.includes(plan.merge?.strategy);
	return passFail(ok, { missing, workerRows, mergeMissing, workerCount: plan?.workers?.length ?? 0 });
}

function validateResumeContractSchema() {
	const schema = SCHEMAS.ResumeContractV2;
	const required = schema.required;
	const enumOk = schema.enums.resumeQueueStatus.includes("queued") && schema.enums.resumeQueueStatus.includes("blocked") && schema.enums.resumeQueueStatus.includes("exhausted");
	return passFail(
		required.includes("contextSha256") &&
			required.includes("compactionEntryId") &&
			required.includes("artifactHashes") &&
			required.includes("idempotencyKey") &&
			required.includes("ledgerPath") &&
			required.includes("closure") &&
			required.includes("resumeQueueStatus") &&
			enumOk,
		{ required, enumValues: schema.enums.resumeQueueStatus },
	);
}

function validateContextResumeSchemaFile(root) {
	const path = join(root, "schemas/reverse-agent/context-resume-contract.schema.json");
	const schema = existsSync(path) ? safeJson(readFileSync(path, "utf8"), {}) : {};
	const contextPack = schema?.$defs?.ContextPackV2 ?? {};
	const resume = schema?.$defs?.ResumeContractV2 ?? {};
	const contextShaPattern = contextPack?.properties?.contextSha256?.pattern === "^[a-f0-9]{64}$";
	const resumeShaPattern = resume?.properties?.contextSha256?.pattern === "^[a-f0-9]{64}$";
	const artifactMinItems = resume?.properties?.artifactHashes?.minItems >= 1;
	const idempotencyMinLength = resume?.properties?.idempotencyKey?.minLength >= 1;
	const ledgerHashPattern = contextPack?.properties?.compactionLedger?.properties?.entryHash?.pattern === "^[a-f0-9]{64}$";
	const dateTime =
		contextPack?.properties?.createdAt?.format === "date-time" &&
		contextPack?.properties?.artifactIndex?.items?.properties?.mtime?.format === "date-time" &&
		resume?.properties?.closure?.properties?.closedAt?.format === "date-time";
	const ok = Boolean(schema?.$defs?.ContextPackV2 && schema?.$defs?.ResumeContractV2 && contextShaPattern && resumeShaPattern && artifactMinItems && idempotencyMinLength && ledgerHashPattern && dateTime);
	return passFail(ok, { path: "schemas/reverse-agent/context-resume-contract.schema.json", contextShaPattern, resumeShaPattern, artifactMinItems, idempotencyMinLength, ledgerHashPattern, dateTime });
}

function validateFailureRepairSchemaFile(root) {
	const path = join(root, FAILURE_REPAIR_CONTRACT_SCHEMA_PATH);
	const schema = existsSync(path) ? safeJson(readFileSync(path, "utf8"), {}) : {};
	const defs = schema?.$defs ?? {};
	const failure = defs.FailureLedgerEventV1 ?? {};
	const repair = defs.RepairQueueItemV1 ?? {};
	const sharedStrict = ["EvidenceWriteback", "BlockedCondition", "Artifact", "ArtifactHash", "RetryBudget", "Rollback", "Preconditions", "RollbackCriteria"].every((name) => defs[name]?.additionalProperties === false);
	const topStrict = failure.additionalProperties === false && repair.additionalProperties === false;
	const fixturePathOk = schema?.["x-piReconStrictFixture"] === FAILURE_REPAIR_STRICT_FIXTURE_PATH;
	const dedupWindow = schema?.["x-piReconDedupWindow"] ?? {};
	const dedupWindowOk =
		dedupWindow.mode === FAILURE_REPAIR_DEDUP_WINDOW.mode &&
		JSON.stringify(dedupWindow.failureKey) === JSON.stringify(FAILURE_REPAIR_DEDUP_WINDOW.failureKey) &&
		JSON.stringify(dedupWindow.repairKey) === JSON.stringify(FAILURE_REPAIR_DEDUP_WINDOW.repairKey) &&
		(dedupWindow.rejects ?? []).includes("duplicate_failure_signature_attempt");
	const hashPatternOk = defs.HexDigest8To64?.pattern === "^[a-f0-9]{8,64}$" && defs.Sha256?.pattern === "^[a-f0-9]{64}$";
	const failureRequiredOk = SCHEMAS.FailureLedgerEventV1.required.every((field) => failure.required?.includes(field));
	const repairRequiredOk = SCHEMAS.RepairQueueItemV1.required.every((field) => repair.required?.includes(field));
	const oneOfOk = (schema.oneOf ?? []).some((entry) => entry.$ref === "#/$defs/FailureLedgerEventV1") && (schema.oneOf ?? []).some((entry) => entry.$ref === "#/$defs/RepairQueueItemV1");
	const repairNoteAllowed = repair.properties?.note?.type === "string";
	const invariantSet = new Set([...(schema?.["x-piReconInvariants"] ?? []), ...(failure?.["x-piReconInvariants"] ?? []), ...(repair?.["x-piReconInvariants"] ?? [])]);
	const invariantsOk =
		invariantSet.has("strict_additional_properties_false_for_failure_and_repair") &&
		invariantSet.has("local_strict_fixture_must_pass") &&
		invariantSet.has("deterministic_duplicate_signature_attempt_rejected") &&
		invariantSet.has("same_signature_shares_retry_budget");
	const ok = Boolean(schema?.$defs?.FailureLedgerEventV1 && schema?.$defs?.RepairQueueItemV1 && sharedStrict && topStrict && fixturePathOk && dedupWindowOk && hashPatternOk && failureRequiredOk && repairRequiredOk && oneOfOk && repairNoteAllowed && invariantsOk);
	return passFail(ok, {
		path: FAILURE_REPAIR_CONTRACT_SCHEMA_PATH,
		sharedStrict,
		topStrict,
		fixturePathOk,
		dedupWindowOk,
		hashPatternOk,
		failureRequiredOk,
		repairRequiredOk,
		oneOfOk,
		repairNoteAllowed,
		invariantsOk,
	});
}

function validateRoleContract(contract) {
	const schema = SCHEMAS.RoleContractV1;
	const missing = fieldMissing(contract, schema.required);
	const roleRows = Array.isArray(contract?.roles)
		? contract.roles.map((role) => ({ id: role.id, missing: fieldMissing(role, schema.roleRequired) }))
		: [];
	const requiredRoles = ["mapper", "verifier", "adversary", "synthesizer"];
	const roleIds = new Set((contract?.roles ?? []).map((role) => role.id));
	const rolesCovered = requiredRoles.every((role) => roleIds.has(role));
	const requiredEvents = ["artifact_handoff", "claim", "validation", "challenge", "resolution"];
	const eventTypesCovered = requiredEvents.every((eventType) => contract?.ledgerPolicy?.requiredEventTypes?.includes(eventType));
	const policyOk = contract?.ledgerPolicy?.appendOnly === true && contract?.conflictPolicy?.unresolvedBlocksFinal === true && contract?.claimGatePolicy?.finalPassRequiresVerifier === true;
	const rolePayloadsOk = (contract?.roles ?? []).every((role) => role.mustEmit?.length > 0 && role.allowedClaimKinds?.length > 0 && role.evidenceContract?.length > 0);
	const ok = missing.length === 0 && Array.isArray(contract.roles) && contract.roles.length >= 4 && rolesCovered && eventTypesCovered && rolePayloadsOk && roleRows.every((row) => row.missing.length === 0) && Array.isArray(contract.evidenceOrder) && contract.evidenceOrder.includes("same_window_live") && policyOk;
	return passFail(ok, { missing, roleRows, roleCount: contract?.roles?.length ?? 0, rolesCovered, eventTypesCovered, rolePayloadsOk, policyOk });
}

function validateLedgerHashChain(events) {
	if (!Array.isArray(events) || !events.length) return passFail(false, { reason: "ledger empty" });
	const rows = [];
	let prevHash = "0".repeat(64);
	for (const event of events) {
		const { eventHash, ...withoutHash } = event;
		const expected = sha256(JSON.stringify(withoutHash));
		const ok = event.prevHash === prevHash && eventHash === expected;
		rows.push({ seq: event.seq, type: event.type, ok, expected: expected.slice(0, 16), actual: String(eventHash || "").slice(0, 16) });
		prevHash = eventHash;
	}
	return passFail(rows.every((row) => row.ok), { events: rows.length, rows: rows.filter((row) => !row.ok).slice(0, 10) });
}

function validateClaimLedger(events) {
	const schema = SCHEMAS.ClaimLedgerEventV1;
	const hash = validateLedgerHashChain(events);
	const eventTypes = new Set((events || []).map((event) => event.type));
	const claimRows = (events || []).filter((event) => event.type === "claim").map((event) => ({ claimId: event.claimId, missing: fieldMissing(event, schema.claimRequired), evidenceRefs: event.evidenceRefs?.length ?? 0, kind: event.kind }));
	const validationIds = new Set((events || []).filter((event) => event.type === "validation").map((event) => event.claimId));
	const highClaims = claimRows.filter((row) => ["proven", "final_pass"].includes(row.kind));
	const highClaimsValidated = highClaims.every((row) => validationIds.has(row.claimId));
	const ok = hash.status === "pass" && schema.eventTypes.every((type) => eventTypes.has(type)) && claimRows.length > 0 && claimRows.every((row) => row.missing.length === 0 && row.evidenceRefs > 0) && highClaimsValidated;
	return passFail(ok, { hash, eventTypes: [...eventTypes].sort(), claimCount: claimRows.length, highClaimCount: highClaims.length, highClaimsValidated, badClaims: claimRows.filter((row) => row.missing.length || !row.evidenceRefs).slice(0, 10) });
}

function validateFailureRepair(failures, repairs) {
	const strict = validateFailureRepairBatch({ failures, repairs });
	return passFail(strict.ok, {
		failureCount: strict.failureCount,
		repairCount: strict.repairCount,
		dedup: strict.dedup,
		badFailures: strict.failures
			.filter((row) => !row.ok)
			.map((row) => ({ index: row.index, id: row.id, errors: row.errors.slice(0, 10) })),
		badRepairs: strict.repairs
			.filter((row) => !row.ok)
			.map((row) => ({ index: row.index, repairId: row.repairId, errors: row.errors.slice(0, 10) })),
	});
}

function validateFailureRepairStrictFixtureFile(root) {
	const path = join(root, FAILURE_REPAIR_STRICT_FIXTURE_PATH);
	const fixture = existsSync(path) ? safeJson(readFileSync(path, "utf8"), {}) : {};
	const result = validateFailureRepairStrictFixture(fixture);
	return passFail(existsSync(path) && result.ok && result.duplicateRejected && result.looseRejected, {
		path: FAILURE_REPAIR_STRICT_FIXTURE_PATH,
		kind: fixture?.kind ?? "missing",
		validOk: result.validBatch.ok,
		duplicateRejected: result.duplicateRejected,
		looseRejected: result.looseRejected,
		validFailureCount: result.validBatch.failureCount,
		validRepairCount: result.validBatch.repairCount,
		duplicateFailures: result.duplicateBatch.dedup.duplicateFailures,
		looseErrors: result.looseBatch.failures.flatMap((row) => row.errors).filter((error) => error.code === "additionalProperties").slice(0, 5),
	});
}

function validateAutonomousRuntimeContractGate(root) {
	const result = validateAutonomousRuntimeContracts(root);
	return passFail(result.ok, {
		schemaPath: SCHEMAS.AutonomousRuntimeBatchV1.schemaPath,
		fixturePath: SCHEMAS.AutonomousRuntimeBatchV1.fixturePath,
		schema: result.schema?.ok ? "pass" : "fail",
		fixture: result.fixture?.ok ? "pass" : "fail",
		validFixture: result.fixture?.validOk ? "pass" : "fail",
		negativeFixtures: (result.fixture?.negatives ?? []).map((negative) => ({
			name: negative.name,
			expected: negative.expected,
			rejected: negative.rejected,
		})),
	});
}

function buildReleaseGateMetadata({ checks, hardEval, contextAudit, parallelPlan, parallelPlanAudit }) {
	const failedChecks = Object.entries(checks)
		.filter(([, check]) => check.status !== "pass")
		.map(([name]) => name);
	const requiredPlatformGaps = (hardEval?.sourceSummary?.frontierGaps ?? [])
		.filter((gap) => gap.severity === "required")
		.map((gap) => gap.name);
	const unresolvedFrontierGaps = (hardEval?.sourceSummary?.frontierGaps ?? []).map((gap) => `${gap.name}:${gap.severity}`);
	const planSha256 = sha256(JSON.stringify(parallelPlan));
	const claimGateVerdict =
		checks.claimLedger?.status === "pass" && hardEval?.gate?.requiredPlatformClaimsValidated === true
			? "pass"
			: "blocked";
	const runtimeClaimSources = checks.runtimeClaimLedgerMarkers?.sources ?? {};
	const runtimeStrictSources = checks.runtimeClaimLedgerStrictGate?.sources ?? {};
	const releaseBlockingGaps = [
		...failedChecks.map((name) => `check:${name}`),
		...requiredPlatformGaps.map((name) => `required_platform_gap:${name}`),
	];
	return [
		"release_gate.schema=PiReconReleaseGateMetadataV1",
		"release_gate.control_plane_mode=offline|plan-only|no-provider|no-live",
		`release_gate.plan_id=${parallelPlan.planId}`,
		`release_gate.plan_sha256=${planSha256}`,
		`release_gate.plan_worker_count=${parallelPlan.workers.length}`,
		`release_gate.plan_merge_strategy=${parallelPlan.merge.strategy}`,
		`release_gate.parallel_plan_contract=${checks.parallelPlan?.status ?? "missing"}`,
		`release_gate.parallel_plan_audit=${checks.parallelPlanAudit?.status ?? "missing"}`,
		`release_gate.context_compact=${checks.contextCompactAudit?.status ?? "missing"}`,
		`release_gate.failure_repair=${checks.failureRepair?.status ?? "missing"}`,
		`release_gate.failure_repair_schema=${checks.failureRepairSchemaFile?.status ?? "missing"}`,
		`release_gate.failure_repair_fixture=${checks.failureRepairStrictFixture?.status ?? "missing"}`,
		`release_gate.autonomous_runtime_contract=${checks.autonomousRuntimeContract?.status ?? "missing"}`,
		`release_gate.role_contract=${checks.roleContract?.status ?? "missing"}`,
		`release_gate.claim_ledger=${checks.claimLedger?.status ?? "missing"}`,
		`release_gate.runtime_claim_ledger=${checks.runtimeClaimLedgerMarkers?.status ?? "missing"}`,
		`release_gate.runtime_claim_ledger_strict=${checks.runtimeClaimLedgerStrictGate?.status ?? "missing"}`,
		`release_gate.runtime_claim_ledger_strict_complete=${checks.runtimeClaimLedgerStrictGate?.complete ? "true" : "false"}`,
		"release_gate.runtime_claim_ledger_sources=agent-dogfood,re_swarm,compound-frontier",
		`release_gate.runtime_claim_ledger_re_swarm=${runtimeClaimSources.reSwarm === "pass" ? "pass" : "fail"}`,
		`release_gate.runtime_claim_ledger_compound=${runtimeClaimSources.compoundFrontier === "pass" ? "pass" : "fail"}`,
		`release_gate.runtime_claim_ledger_strict_agent_dogfood=${runtimeStrictSources["agent-dogfood"]?.status ?? "missing"}`,
		`release_gate.runtime_claim_ledger_strict_re_swarm=${runtimeStrictSources.re_swarm?.status ?? "missing"}`,
		`release_gate.runtime_claim_ledger_strict_compound=${runtimeStrictSources["compound-frontier"]?.status ?? "missing"}`,
		`release_gate.runtime_parallel_plan_markers=${checks.runtimeParallelPlanMarkers?.status ?? "missing"}`,
		`release_gate.score_separation=orchestration:${hardEval?.scores?.orchestration?.score ?? "missing"}/platform_required:${hardEval?.scores?.platformRequired?.score ?? "missing"}/platform_all:${hardEval?.scores?.platformAll?.score ?? "missing"}`,
		`release_gate.claim_gate_verdict=${claimGateVerdict}`,
		`release_gate.required_platform_gaps=${requiredPlatformGaps.join(",") || "none"}`,
		`release_gate.unresolved_frontier_gaps=${unresolvedFrontierGaps.join(",") || "none"}`,
		`release_gate.release_blocking_gaps=${releaseBlockingGaps.join(",") || "none"}`,
		`release_gate.parallel_plan_preview_workers=${parallelPlanAudit?.planOnlyPreview?.workerCount ?? "missing"}`,
		`release_gate.context_compact_status=${contextAudit?.ok ? "pass" : contextAudit?.summary?.status ?? contextAudit?.status ?? "missing"}`,
		"release_gate.orchestration_score_never_implies_platform_success=true",
		"release_gate.final_claim_requires_claim_ledger_validation=true",
		"release_gate.unresolved_required_platform_gap_blocks_final_pass=true",
	];
}

function validateReleaseGateMetadata(rows) {
	const requiredPrefixes = [
		"release_gate.schema=",
		"release_gate.control_plane_mode=",
		"release_gate.plan_id=",
		"release_gate.plan_sha256=",
		"release_gate.parallel_plan_contract=",
		"release_gate.claim_gate_verdict=",
		"release_gate.failure_repair_schema=",
		"release_gate.failure_repair_fixture=",
		"release_gate.autonomous_runtime_contract=",
		"release_gate.runtime_claim_ledger=",
		"release_gate.runtime_claim_ledger_strict=",
		"release_gate.runtime_claim_ledger_sources=",
		"release_gate.runtime_claim_ledger_re_swarm=",
		"release_gate.runtime_claim_ledger_compound=",
		"release_gate.score_separation=",
		"release_gate.release_blocking_gaps=",
		"release_gate.orchestration_score_never_implies_platform_success=true",
		"release_gate.final_claim_requires_claim_ledger_validation=true",
		"release_gate.unresolved_required_platform_gap_blocks_final_pass=true",
	];
	const missing = requiredPrefixes.filter((prefix) => !rows.some((row) => row.startsWith(prefix)));
	const modeOk = rows.some((row) => row === "release_gate.control_plane_mode=offline|plan-only|no-provider|no-live");
	const scoreSplitOk = rows.some((row) => /^release_gate\.score_separation=orchestration:[^/]+\/platform_required:[^/]+\/platform_all:[^/]+$/.test(row));
	return passFail(missing.length === 0 && modeOk && scoreSplitOk, { missing, modeOk, scoreSplitOk, rowCount: rows.length });
}

function buildParallelPlan(hardEval) {
	const repairs = hardEval?.repairQueue ?? [];
	const workers = [
		{
			id: "claim-ledger-validator",
			role: "verifier",
			objective: "Validate hard-eval claim ledger hash chain, evidence refs, validations, and anti-self-delusion split.",
			commands: ["node scripts/reverse-agent/hard-eval-control-plane.mjs . --json"],
			evidenceContract: ["ledger hash chain passes", "required platform gaps are preserved", "orchestration/platform score split exists"],
			mergeKeys: ["claimId", "scope", "gate", "eventHash"],
			dependencies: [],
			artifactGlobs: [".repi-harness/evidence/hard-eval-control-plane/**/ledger.jsonl", ".repi-harness/evidence/hard-eval-control-plane/**/gate.json"],
			limits: { timeoutMs: 60000, maxCommands: 1 },
		},
		...repairs.map((repair, index) => ({
			id: `repair-plan-${index + 1}`,
			role: repair.scope?.includes("xiaohongshu") ? "web-runtime" : repair.scope?.includes("douyin") ? "js-signing" : "general",
			objective: `Plan paused repair for ${repair.scope} without hiding current platform gap.`,
			commands: repair.commands ?? [],
			evidenceContract: [`failure=${repair.fromFailureId}`, `repair=${repair.repairId}`, "paused until live testing resumes"],
			mergeKeys: ["repairId", "fromFailureId", "scope"],
			dependencies: ["claim-ledger-validator"],
			artifactGlobs: repair.expectedArtifacts ?? [],
			limits: { timeoutMs: 0, maxCommands: 0 },
		})),
	];
	return {
		planId: `autonomous-hardening/${new Date().toISOString()}`,
		source: "hard-eval-control-plane",
		workers,
		merge: {
			strategy: "claim-ledger",
			evidenceOrder: EVIDENCE_ORDER,
			expectedArtifacts: ["result.json", "contract.json", "ledger.jsonl", "failure-ledger.jsonl", "repair-queue.jsonl"],
		},
	};
}

function readMarkers(root, relativePath, markers) {
	const path = join(root, relativePath);
	const text = existsSync(path) ? readFileSync(path, "utf8") : "";
	return { path: relativePath, exists: Boolean(text), markers: markers.map((marker) => ({ marker, present: text.includes(marker) })) };
}

function buildResult(root) {
	const hardEvalRun = runJson(root, ["scripts/reverse-agent/hard-eval-control-plane.mjs", ".", "--json"]);
	const contextAuditRun = runJson(root, ["scripts/reverse-agent/context-compact-audit.mjs", ".", "--json"]);
	const parallelPlanAuditRun = runJson(root, ["scripts/reverse-agent/audit-parallel-plan.mjs", ".", "--json", "--strict"]);
	const hardEval = hardEvalRun.json;
	const contextAudit = contextAuditRun.json;
	const parallelPlanAudit = parallelPlanAuditRun.json;
	const runtimeClaimLedgerGate = buildRuntimeClaimLedgerGate(root);
	const parallelPlan = buildParallelPlan(hardEval);
	const checks = {
		parallelPlan: validateParallelPlan(parallelPlan),
		parallelPlanAudit: passFail(Boolean(parallelPlanAudit?.ok) && parallelPlanAuditRun.code === 0, {
			code: parallelPlanAuditRun.code,
			frontierPlan: parallelPlanAudit?.checks?.frontierPlan?.status ?? "missing",
			planOnlyOutput: parallelPlanAudit?.checks?.planOnlyOutput?.status ?? "missing",
			planOnlyNoProvider: parallelPlanAudit?.checks?.planOnlyNoProvider?.status ?? "missing",
			planOnlyNoEvidenceDir: parallelPlanAudit?.checks?.planOnlyNoEvidenceDir?.status ?? "missing",
			planOnlyFailureRepair: parallelPlanAudit?.checks?.planOnlyFailureRepair?.status ?? "missing",
			dogfoodRuntimeManifest: parallelPlanAudit?.checks?.dogfoodRuntimeManifest?.status ?? "missing",
			runtimeClaimLedger: parallelPlanAudit?.checks?.runtimeClaimLedger?.status ?? "missing",
			stdoutSha256: parallelPlanAuditRun.stdoutSha256,
		}),
		resumeContractV2Schema: validateResumeContractSchema(),
		roleContract: validateRoleContract(hardEval?.contract ?? {}),
		claimLedger: validateClaimLedger(hardEval?.ledger ?? []),
		failureRepair: validateFailureRepair(hardEval?.failures ?? [], hardEval?.repairQueue ?? []),
		failureRepairSchemaFile: validateFailureRepairSchemaFile(root),
		failureRepairStrictFixture: validateFailureRepairStrictFixtureFile(root),
		autonomousRuntimeContract: validateAutonomousRuntimeContractGate(root),
		runtimeClaimLedgerStrictGate: passFail(Boolean(runtimeClaimLedgerGate?.ok), {
			complete: Boolean(runtimeClaimLedgerGate?.complete),
			coverage: runtimeClaimLedgerGate?.coverage ?? "missing",
			artifactDir: runtimeClaimLedgerGate?.artifactDir ?? null,
			missingRuntimeArtifacts: runtimeClaimLedgerGate?.missingRuntimeArtifacts ?? [],
			structuralFailures: runtimeClaimLedgerGate?.structuralFailures ?? [],
			sources: Object.fromEntries(
				Object.entries(runtimeClaimLedgerGate?.sources ?? {})
					.filter(([source]) => source !== "adapter-fixture")
					.map(([source, row]) => [
						source,
						{
							status: row.status,
							loadedStatus: row.loadedStatus,
							allowPlatformGapsOk: Boolean(row.strictValidator?.allowPlatformGaps?.ok),
							strictClaimsOk: Boolean(row.strictValidator?.strictClaims?.ok),
							promotionBlocked: Boolean(row.strictValidator?.promotionBlocked),
							reason: row.reason ?? null,
						},
					]),
			),
			adapterFixture: runtimeClaimLedgerGate?.sources?.["adapter-fixture"]?.status ?? "missing",
		}),
		runtimeFailureRepairMarkers: passFail(true, {
			markers: [
				readMarkers(root, "packages/coding-agent/src/core/recon-profile.ts", ["type FailureLedgerEventV1", "type RepairQueueItemV1", "function runtimeFailureSignature", "function failureToRepair", "function appendFailureRepairLedger", "appendRuntimeFailureRepairFromReplay", "appendRuntimeFailureRepairFromAutofix", "appendRuntimeFailureRepairFromOperator", "appendRuntimeFailureRepairFromProofLoop", "runtimeFailureLedgerPath", "runtimeRepairQueuePath"]),
				readMarkers(root, "repi-profile/extensions/reverse-pentest-core.ts", ["type FailureLedgerEventV1", "type RepairQueueItemV1", "function runtimeFailureSignature", "function failureToRepair", "function appendFailureRepairLedger", "appendRuntimeFailureRepairFromReplay", "appendRuntimeFailureRepairFromAutofix", "appendRuntimeFailureRepairFromOperator", "appendRuntimeFailureRepairFromProofLoop", "runtimeFailureLedgerPath", "runtimeRepairQueuePath"]),
				readMarkers(root, "scripts/reverse-agent/failure-repair-ledger.mjs", ["failureRepairFromGap", "failureRepairFromGaps", "appendFailureRepairWriteback", "FailureLedgerEventV1", "validateFailureRepairBatch", "validateFailureRepairDedup", "FAILURE_REPAIR_DEDUP_WINDOW", "FAILURE_REPAIR_STRICT_FIXTURE_PATH"]),
				readMarkers(root, "bench/recon-remote/compound-frontier/run.mjs", ["failureRepairFromGaps", "failureLedgerEvents", "repairQueue", "failure-ledger.jsonl"]),
				readMarkers(root, "bench/recon-remote/agent-dogfood/parallel-run.mjs", ["failureRepairFromGap", "retryExhausted", "attemptStdoutFile", "failureLedgerEvents", "repair-queue.jsonl"]),
			],
		}),
		contextCompactAudit: passFail(Boolean(contextAudit?.ok), { summary: contextAudit?.summary ?? null }),
		contextRuntimeMarkers: passFail(true, {
			markers: [
				readMarkers(root, "packages/coding-agent/src/core/recon-profile.ts", ["buildContextPack", "contextPackSha256", "contextArtifactHashes", "verifyContextPackResume", "buildExactResumeContextPack", "buildReconCompactionResumeContract", "pi-recon-compaction-auto-resume", "compact_resume_case_memory", "compaction-resume-ledger.jsonl"]),
				readMarkers(root, "repi-profile/extensions/reverse-pentest-core.ts", ["buildContextPack", "contextPackSha256", "contextArtifactHashes", "verifyContextPackResume", "buildExactResumeContextPack", "buildReconCompactionResumeContract", "pi-recon-compaction-auto-resume", "compact_resume_case_memory", "compaction-resume-ledger.jsonl"]),
			],
		}),
		contextResumeSchemaFile: validateContextResumeSchemaFile(root),
		runtimeParallelPlanMarkers: passFail(true, {
			markers: [
				readMarkers(root, "packages/coding-agent/src/core/recon-profile.ts", ["type ReconParallelPlanV1", "function buildSwarmParallelPlan", "planCoverage", "releaseGateMetadata", "function supervisorClaimGatePolicy", "claimGatePolicy"]),
				readMarkers(root, "repi-profile/extensions/reverse-pentest-core.ts", ["type ReconParallelPlanV1", "function buildSwarmParallelPlan", "planCoverage", "releaseGateMetadata", "function supervisorClaimGatePolicy", "claimGatePolicy"]),
			],
		}),
		runtimeClaimLedgerMarkers: passFail(true, {
			sources: {
				agentDogfood: "pending",
				reSwarm: "pending",
				compoundFrontier: "pending",
			},
			markers: [
				readMarkers(root, "bench/recon-remote/agent-dogfood/parallel-run.mjs", ["ClaimLedgerEventV1", "buildRuntimeClaimLedgerEvents", "claim-ledger.jsonl", "runtimeClaimLedgerCaptured", "artifact_handoff", "claim", "validation", "challenge", "resolution"]),
				readMarkers(root, "packages/coding-agent/src/core/recon-profile.ts", ["SwarmClaimLedgerEventV1", "appendSwarmClaimLedgerEvent", "buildSwarmRuntimeClaimLedger", "swarmClaimLedgerHashChainOk", "claimLedgerPath", "claimLedgerEventCount", "claimLedgerTipHash", "runtimeClaimLedgerCaptured", "claim-ledger.jsonl", "artifact_handoff", "claim", "validation", "challenge", "resolution"]),
				readMarkers(root, "repi-profile/extensions/reverse-pentest-core.ts", ["SwarmClaimLedgerEventV1", "appendSwarmClaimLedgerEvent", "buildSwarmRuntimeClaimLedger", "swarmClaimLedgerHashChainOk", "claimLedgerPath", "claimLedgerEventCount", "claimLedgerTipHash", "runtimeClaimLedgerCaptured", "claim-ledger.jsonl", "artifact_handoff", "claim", "validation", "challenge", "resolution"]),
				readMarkers(root, "bench/recon-remote/compound-frontier/run.mjs", ["ClaimLedgerEventV1", "appendCompoundClaimLedgerEvent", "buildCompoundClaimLedgerEvents", "claim-ledger.jsonl", "claimLedgerEvents", "claimLedgerPath", "claimLedgerEventCount", "claimLedgerTipHash", "runtimeClaimLedgerCaptured", "artifact_handoff", "claim", "validation", "challenge", "resolution"]),
				readMarkers(root, "scripts/reverse-agent/audit-parallel-plan.mjs", ["runtimeClaimLedger", "runtime_claim_ledger_sources", "agent-dogfood,re_swarm,compound-frontier"]),
			],
		}),
	};
	checks.contextRuntimeMarkers.status = checks.contextRuntimeMarkers.markers.every((file) => file.exists && file.markers.every((marker) => marker.present)) ? "pass" : "fail";
	checks.runtimeParallelPlanMarkers.status = checks.runtimeParallelPlanMarkers.markers.every((file) => file.exists && file.markers.every((marker) => marker.present)) ? "pass" : "fail";
	checks.runtimeFailureRepairMarkers.status = checks.runtimeFailureRepairMarkers.markers.every((file) => file.exists && file.markers.every((marker) => marker.present)) ? "pass" : "fail";
	checks.runtimeClaimLedgerMarkers.sources = {
		agentDogfood: checks.runtimeClaimLedgerMarkers.markers[0]?.exists && checks.runtimeClaimLedgerMarkers.markers[0]?.markers.every((marker) => marker.present) ? "pass" : "fail",
		reSwarm: checks.runtimeClaimLedgerMarkers.markers.slice(1, 3).every((file) => file.exists && file.markers.every((marker) => marker.present)) ? "pass" : "fail",
		compoundFrontier: checks.runtimeClaimLedgerMarkers.markers[3]?.exists && checks.runtimeClaimLedgerMarkers.markers[3]?.markers.every((marker) => marker.present) ? "pass" : "fail",
	};
	checks.runtimeClaimLedgerMarkers.status = checks.runtimeClaimLedgerMarkers.markers.every((file) => file.exists && file.markers.every((marker) => marker.present)) ? "pass" : "fail";
	const releaseGateMetadata = buildReleaseGateMetadata({ checks, hardEval, contextAudit, parallelPlan, parallelPlanAudit });
	checks.releaseGateMetadata = validateReleaseGateMetadata(releaseGateMetadata);
	const ok = Object.values(checks).every((check) => check.status === "pass");
	return {
		kind: "pi-recon-autonomous-contracts",
		version: CONTRACT_VERSION,
		generatedAt: new Date().toISOString(),
		root,
		mode: "offline-contract-schema-and-ledger-validation",
		ok,
		currentLevel: ok ? "professional reverse/pentest organization with machine-readable control contracts" : "contract gaps",
		topAutonomousDefinition: false,
		topAutonomousReason:
			"Schemas, validators, ReconParallelPlanV1, agent-dogfood subagent runtime manifests plus strict AutonomousRuntimeBatchV1 fixture/gate, agent-dogfood / re_swarm / compound runtime ClaimLedgerEventV1 rows, exact context resume markers/negative fixtures, strict FailureLedgerEventV1/RepairQueueItemV1 fixture + deterministic duplicate rejection, runtime failure/repair ledger hooks, compound/role retry failure-repair outputs, and strict claim final-path gates exist; generic re_swarm independent subagent runtime and live cross-session resume regression remain optional hardening.",
		schemas: SCHEMAS,
		parallelPlan,
		releaseGateMetadata,
		checks,
		hardEval: {
			code: hardEvalRun.code,
			verdict: hardEval?.verdict ?? "missing",
			scores: hardEval?.scores ?? null,
			failures: hardEval?.failures?.length ?? 0,
			repairs: hardEval?.repairQueue?.length ?? 0,
			stdoutSha256: hardEvalRun.stdoutSha256,
		},
		contextCompact: {
			code: contextAuditRun.code,
			ok: Boolean(contextAudit?.ok),
			summary: contextAudit?.summary ?? null,
			stdoutSha256: contextAuditRun.stdoutSha256,
		},
		parallelPlanAudit: {
			code: parallelPlanAuditRun.code,
			ok: Boolean(parallelPlanAudit?.ok),
			frontierPlan: parallelPlanAudit?.frontierPlan ?? null,
			planOnlyPreview: parallelPlanAudit?.planOnlyPreview ?? null,
			stdoutSha256: parallelPlanAuditRun.stdoutSha256,
		},
		runtimeClaimLedgerGate: {
			ok: Boolean(runtimeClaimLedgerGate?.ok),
			complete: Boolean(runtimeClaimLedgerGate?.complete),
			coverage: runtimeClaimLedgerGate?.coverage ?? "missing",
			artifactDir: runtimeClaimLedgerGate?.artifactDir ?? null,
			missingRuntimeArtifacts: runtimeClaimLedgerGate?.missingRuntimeArtifacts ?? [],
		},
		nextNonTestWork: [
			"Keep gate:claim-release marker consumption wired through supervisor/compiler/complete and promote pass markers only after required gaps close.",
			"Keep AutonomousRuntimeBatchV1 as the strict regression gate for sub-agent manifests, shard state, compact resume transitions, repair budgets, and runtime claim promotion.",
			"Close missing live runtime artifacts for agent-dogfood/re_swarm so runtime-claim-ledger strict coverage moves from partial to complete.",
			"Promote optional re_swarm independent sub-agent/session runtime from contract fixture to live runtime mode when provider budget is available.",
		],
	};
}

function formatMarkdown(result) {
	const lines = [
		"# REPI Autonomous Contracts Audit",
		"",
		`generated_at: ${result.generatedAt}`,
		`mode: ${result.mode}`,
		`ok: ${result.ok}`,
		`current_level: ${result.currentLevel}`,
		`top_autonomous_definition: ${result.topAutonomousDefinition}`,
		`top_autonomous_reason: ${result.topAutonomousReason}`,
		"",
		"## Checks",
	];
	for (const [name, check] of Object.entries(result.checks)) lines.push(`- ${name}: ${check.status}`);
	lines.push("", "## Hard eval binding", "", `- verdict: ${result.hardEval.verdict}`, `- orchestration: ${result.hardEval.scores?.orchestration?.score ?? "n/a"}`, `- platform_required: ${result.hardEval.scores?.platformRequired?.score ?? "n/a"}`, `- failures: ${result.hardEval.failures}`, `- repairs: ${result.hardEval.repairs}`);
	lines.push("", "## Parallel plan", "", `- plan_id: ${result.parallelPlan.planId}`, `- workers: ${result.parallelPlan.workers.length}`, `- merge_strategy: ${result.parallelPlan.merge.strategy}`);
	lines.push("", "## Plan-only audit", "", `- ok: ${result.parallelPlanAudit.ok}`, `- frontier_workers: ${result.parallelPlanAudit.frontierPlan?.workerCount ?? "n/a"}`, `- preview_workers: ${result.parallelPlanAudit.planOnlyPreview?.workerCount ?? "n/a"}`, `- preview_kind: ${result.parallelPlanAudit.planOnlyPreview?.kind ?? "n/a"}`);
	lines.push("", "## Release gate metadata");
	for (const row of result.releaseGateMetadata) lines.push(`- ${row}`);
	lines.push("", "## Next non-test work");
	for (const item of result.nextNonTestWork) lines.push(`- ${item}`);
	return `${lines.join("\n")}\n`;
}

function writeOutputs(root, result) {
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const outDir = join(root, ".repi-harness", "evidence", "autonomous-contracts", stamp);
	mkdirSync(outDir, { recursive: true });
	writeFileSync(join(outDir, "result.json"), `${JSON.stringify(result, null, 2)}\n`);
	writeFileSync(join(outDir, "schemas.json"), `${JSON.stringify(result.schemas, null, 2)}\n`);
	writeFileSync(join(outDir, "parallel-plan.json"), `${JSON.stringify(result.parallelPlan, null, 2)}\n`);
	writeFileSync(join(outDir, "release-gate-metadata.txt"), `${result.releaseGateMetadata.join("\n")}\n`);
	writeFileSync(join(outDir, "report.md"), formatMarkdown(result));
	return outDir;
}

function printHelp() {
	console.log(`Usage: node scripts/reverse-agent/autonomous-contracts.mjs [root] [--json] [--write] [--strict]\n\nValidates REPI autonomous control contracts offline: parallel plan, ResumeContractV2 schema, role/claim ledger, failure/repair ledger, and context compact markers.`);
}

function main(argv) {
	if (argv.includes("--help") || argv.includes("-h")) return printHelp();
	const rootArg = argv.find((arg) => !arg.startsWith("-"));
	const root = resolve(rootArg ?? process.cwd());
	const json = argv.includes("--json");
	const write = argv.includes("--write");
	const strict = argv.includes("--strict");
	const result = buildResult(root);
	if (write) result.artifactDir = writeOutputs(root, result).replace(`${root}/`, "");
	if (json) console.log(JSON.stringify(result, null, 2));
	else process.stdout.write(formatMarkdown(result));
	if (strict && !result.ok) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main(process.argv.slice(2));

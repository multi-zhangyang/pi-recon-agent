#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

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
		required: ["id", "ts", "source", "scope", "category", "signature", "attempt", "maxAttempts", "status", "failedGates", "artifacts", "artifactHashes", "repairId", "budget", "rollback"],
		enums: { status: ["failed", "retrying", "repair_queued", "repaired", "exhausted", "rolled_back", "escalated"] },
	},
	RepairQueueItemV1: {
		required: ["repairId", "fromFailureId", "signature", "scope", "action", "commands", "expectedArtifacts", "expectedGates", "preconditions", "paused", "allowlist", "rollbackCriteria", "regressionGates"],
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

function validateRoleContract(contract) {
	const schema = SCHEMAS.RoleContractV1;
	const missing = fieldMissing(contract, schema.required);
	const roleRows = Array.isArray(contract?.roles)
		? contract.roles.map((role) => ({ id: role.id, missing: fieldMissing(role, schema.roleRequired) }))
		: [];
	const policyOk = contract?.ledgerPolicy?.appendOnly === true && contract?.conflictPolicy?.unresolvedBlocksFinal === true && contract?.claimGatePolicy?.finalPassRequiresVerifier === true;
	const ok = missing.length === 0 && Array.isArray(contract.roles) && contract.roles.length >= 4 && roleRows.every((row) => row.missing.length === 0) && Array.isArray(contract.evidenceOrder) && contract.evidenceOrder.includes("same_window_live") && policyOk;
	return passFail(ok, { missing, roleRows, roleCount: contract?.roles?.length ?? 0, policyOk });
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
	const failureSchema = SCHEMAS.FailureLedgerEventV1;
	const repairSchema = SCHEMAS.RepairQueueItemV1;
	const repairIds = new Set((repairs || []).map((repair) => repair.repairId));
	const failureRows = (failures || []).map((failure) => ({
		id: failure.id,
		missing: fieldMissing(failure, failureSchema.required),
		statusOk: failureSchema.enums.status.includes(failure.status),
		attemptOk: Number(failure.attempt) <= Number(failure.maxAttempts),
		repairLinked: repairIds.has(failure.repairId),
		signatureOk: typeof failure.signature === "string" && failure.signature.length >= 8,
		artifactHashesOk: Array.isArray(failure.artifactHashes) && failure.artifactHashes.every((artifact) => artifact?.path && artifact?.sha256),
		budgetOk: Boolean(failure.budget?.retryKey && Number.isFinite(Number(failure.budget?.remainingAttempts)) && failure.budget?.exhaustedAction),
		rollbackOk: failure.rollback?.required === true || failure.rollback?.required === false,
	}));
	const repairRows = (repairs || []).map((repair) => ({
		repairId: repair.repairId,
		missing: fieldMissing(repair, repairSchema.required),
		actionOk: repairSchema.enums.action.includes(repair.action),
		paused: repair.paused === true || repair.paused === false,
		signatureOk: typeof repair.signature === "string" && repair.signature.length >= 8,
		expectedGatesOk: Array.isArray(repair.expectedGates) && repair.expectedGates.length > 0,
		preconditionsOk: repair.preconditions?.liveAllowed === false || repair.preconditions?.liveAllowed === true,
		rollbackCriteriaOk: typeof repair.rollbackCriteria === "object" && repair.rollbackCriteria !== null,
	}));
	const ok =
		failureRows.length > 0 &&
		failureRows.every((row) => row.missing.length === 0 && row.statusOk && row.attemptOk && row.repairLinked && row.signatureOk && row.artifactHashesOk && row.budgetOk && row.rollbackOk) &&
		repairRows.length >= failureRows.length &&
		repairRows.every((row) => row.missing.length === 0 && row.actionOk && row.paused && row.signatureOk && row.expectedGatesOk && row.preconditionsOk && row.rollbackCriteriaOk);
	return passFail(ok, {
		failureCount: failureRows.length,
		repairCount: repairRows.length,
		badFailures: failureRows.filter((row) => row.missing.length || !row.statusOk || !row.attemptOk || !row.repairLinked || !row.signatureOk || !row.artifactHashesOk || !row.budgetOk || !row.rollbackOk),
		badRepairs: repairRows.filter((row) => row.missing.length || !row.actionOk || !row.paused || !row.signatureOk || !row.expectedGatesOk || !row.preconditionsOk || !row.rollbackCriteriaOk),
	});
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
			artifactGlobs: [".pi/evidence/hard-eval-control-plane/**/ledger.jsonl", ".pi/evidence/hard-eval-control-plane/**/gate.json"],
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
	const parallelPlan = buildParallelPlan(hardEval);
	const checks = {
		parallelPlan: validateParallelPlan(parallelPlan),
		parallelPlanAudit: passFail(Boolean(parallelPlanAudit?.ok) && parallelPlanAuditRun.code === 0, {
			code: parallelPlanAuditRun.code,
			frontierPlan: parallelPlanAudit?.checks?.frontierPlan?.status ?? "missing",
			planOnlyOutput: parallelPlanAudit?.checks?.planOnlyOutput?.status ?? "missing",
			planOnlyNoProvider: parallelPlanAudit?.checks?.planOnlyNoProvider?.status ?? "missing",
			planOnlyNoEvidenceDir: parallelPlanAudit?.checks?.planOnlyNoEvidenceDir?.status ?? "missing",
			stdoutSha256: parallelPlanAuditRun.stdoutSha256,
		}),
		resumeContractV2Schema: validateResumeContractSchema(),
		roleContract: validateRoleContract(hardEval?.contract ?? {}),
		claimLedger: validateClaimLedger(hardEval?.ledger ?? []),
		failureRepair: validateFailureRepair(hardEval?.failures ?? [], hardEval?.repairQueue ?? []),
		contextCompactAudit: passFail(Boolean(contextAudit?.ok), { summary: contextAudit?.summary ?? null }),
		contextRuntimeMarkers: passFail(true, {
			markers: [
				readMarkers(root, "packages/coding-agent/src/core/recon-profile.ts", ["buildContextPack", "buildReconCompactionResumeContract", "pi-recon-compaction-auto-resume", "compact_resume_case_memory"]),
				readMarkers(root, ".pi/extensions/reverse-pentest-core.ts", ["buildContextPack", "buildReconCompactionResumeContract", "pi-recon-compaction-auto-resume", "compact_resume_case_memory"]),
			],
		}),
	};
	checks.contextRuntimeMarkers.status = checks.contextRuntimeMarkers.markers.every((file) => file.exists && file.markers.every((marker) => marker.present)) ? "pass" : "fail";
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
		topAutonomousReason: "Schemas and validators exist, but full independent subagent runtime, exact resume loading, and runtime-integrated repair execution still require implementation.",
		schemas: SCHEMAS,
		parallelPlan,
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
		nextNonTestWork: [
			"Extend the verified ReconParallelPlanV1 ingestion path into re_swarm plan output and release-gate metadata.",
			"Persist ResumeContractV2 as append-only compaction-resume-ledger.jsonl and make re_context resume load exact contextPath.",
			"Promote FailureLedgerEventV1 / RepairQueueItemV1 into re_replayer, re_autofix, re_operator, and compound-frontier outputs.",
			"Promote ClaimLedgerEventV1 into re_supervisor and re_compiler so final reports require validated claim IDs.",
		],
	};
}

function formatMarkdown(result) {
	const lines = [
		"# Pi-RECON Autonomous Contracts Audit",
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
	lines.push("", "## Next non-test work");
	for (const item of result.nextNonTestWork) lines.push(`- ${item}`);
	return `${lines.join("\n")}\n`;
}

function writeOutputs(root, result) {
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const outDir = join(root, ".pi", "evidence", "autonomous-contracts", stamp);
	mkdirSync(outDir, { recursive: true });
	writeFileSync(join(outDir, "result.json"), `${JSON.stringify(result, null, 2)}\n`);
	writeFileSync(join(outDir, "schemas.json"), `${JSON.stringify(result.schemas, null, 2)}\n`);
	writeFileSync(join(outDir, "parallel-plan.json"), `${JSON.stringify(result.parallelPlan, null, 2)}\n`);
	writeFileSync(join(outDir, "report.md"), formatMarkdown(result));
	return outDir;
}

function printHelp() {
	console.log(`Usage: node scripts/reverse-agent/autonomous-contracts.mjs [root] [--json] [--write] [--strict]\n\nValidates Pi-RECON autonomous control contracts offline: parallel plan, ResumeContractV2 schema, role/claim ledger, failure/repair ledger, and context compact markers.`);
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

#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const AUTONOMOUS_RUNTIME_SCHEMA_PATH = "schemas/reverse-agent/autonomous-runtime-contract.schema.json";
export const AUTONOMOUS_RUNTIME_FIXTURE_PATH = "fixtures/reverse-agent/autonomous-runtime-contract.fixture.json";

const REQUIRED_EVENT_TYPES = ["artifact_handoff", "claim", "validation", "challenge", "resolution"];
const RUNTIME_STATES = new Set(["queued", "running", "done", "failed", "blocked", "exhausted", "cancelled", "rolled_back"]);
const RESUME_STATES = new Set(["queued", "running", "done", "blocked", "exhausted"]);
const TERMINAL_STATES = new Set(["done", "exhausted"]);
const RESUME_TRANSITIONS = new Map([
	[null, new Set(["queued"])],
	["queued", new Set(["running", "blocked", "exhausted"])],
	["running", new Set(["done", "blocked", "exhausted"])],
	["blocked", new Set(["queued", "exhausted"])],
]);

const BATCH_KEYS = [
	"kind",
	"schemaVersion",
	"runId",
	"subagentRuntimeManifests",
	"parallelShardStates",
	"compactResumeStates",
	"repairBudgetStates",
	"claimPromotionGates",
];
const SUBAGENT_KEYS = [
	"kind",
	"schemaVersion",
	"runId",
	"roleId",
	"workerId",
	"attempt",
	"status",
	"pid",
	"parentPid",
	"sessionDir",
	"stdoutPath",
	"stderrPath",
	"stdoutSha256",
	"stderrSha256",
	"startedAt",
	"endedAt",
	"elapsedMs",
	"exitCode",
	"signal",
	"model",
	"toolCallDigest",
	"claimLedgerPath",
	"failureLedgerPath",
	"repairQueuePath",
	"resourceLimits",
	"retryBudget",
	"mergeKeys",
	"evidenceRefs",
];
const MODEL_KEYS = ["provider", "modelId", "modelCalls", "toolCalls", "toolResults"];
const LIMIT_KEYS = ["timeoutMs", "maxCommands", "maxOutputBytes", "cancelOnTimeout"];
const RETRY_KEYS = ["signature", "attempt", "maxAttempts", "remaining", "exhausted"];
const SHARD_KEYS = [
	"shardId",
	"source",
	"state",
	"dependencies",
	"dependents",
	"leaseId",
	"resourceLimits",
	"startedAt",
	"endedAt",
	"resultManifestPath",
	"stdoutSha256",
	"stderrSha256",
	"mergeKeys",
	"blockedReason",
];
const RESUME_KEYS = [
	"contractId",
	"compactionEntryId",
	"contextPath",
	"contextSha256",
	"queueState",
	"idempotencyKey",
	"transitionLog",
	"resumeBudget",
	"operatorQueueRef",
	"proofLoopEntry",
	"blockedReason",
];
const TRANSITION_KEYS = ["from", "to", "at", "reason"];
const REPAIR_BUDGET_KEYS = [
	"signature",
	"failureId",
	"repairId",
	"state",
	"retryBudget",
	"allowlist",
	"rollbackCriteria",
	"regressionGates",
	"evidenceWriteback",
];
const CLAIM_GATE_KEYS = [
	"source",
	"ledgerPath",
	"hashChainOk",
	"eventTypes",
	"strictValidator",
	"finalPromotionBlocked",
	"unresolvedChallenges",
	"artifactRefs",
	"claimIds",
	"validatorCommand",
];

function sha256(text) {
	return createHash("sha256").update(text).digest("hex");
}

function readJson(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

function safeJson(path, fallback = {}) {
	try {
		return readJson(path);
	} catch {
		return fallback;
	}
}

function push(errors, path, code, message) {
	errors.push({ path, code, message });
}

function assertObject(value, path, errors) {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		push(errors, path, "type", "expected object");
		return false;
	}
	return true;
}

function checkKeys(obj, allowed, required, path, errors) {
	if (!assertObject(obj, path, errors)) return;
	const allowedSet = new Set(allowed);
	for (const key of Object.keys(obj)) {
		if (!allowedSet.has(key)) push(errors, `${path}.${key}`, "additionalProperties", "unexpected field");
	}
	for (const key of required) {
		if (!Object.prototype.hasOwnProperty.call(obj, key)) push(errors, `${path}.${key}`, "required", "missing required field");
	}
}

function checkString(value, path, errors, { minLength = 1, pattern } = {}) {
	if (typeof value !== "string") return push(errors, path, "type", "expected string");
	if (value.length < minLength) push(errors, path, "minLength", `expected at least ${minLength}`);
	if (pattern && !pattern.test(value)) push(errors, path, "pattern", `does not match ${pattern}`);
}

function checkInteger(value, path, errors, { min = 0, nullable = false } = {}) {
	if (nullable && value === null) return;
	if (!Number.isInteger(value)) return push(errors, path, "type", "expected integer");
	if (value < min) push(errors, path, "minimum", `expected >= ${min}`);
}

function checkArray(value, path, errors, { minItems = 0 } = {}) {
	if (!Array.isArray(value)) return push(errors, path, "type", "expected array");
	if (value.length < minItems) push(errors, path, "minItems", `expected at least ${minItems}`);
}

function checkIsoDate(value, path, errors) {
	checkString(value, path, errors);
	if (typeof value === "string" && Number.isNaN(Date.parse(value))) push(errors, path, "format", "expected date-time");
}

function checkDigest(value, path, errors, full = false) {
	checkString(value, path, errors, { pattern: full ? /^[a-f0-9]{64}$/ : /^[a-f0-9]{8,64}$/ });
}

function validateResourceLimits(value, path, errors) {
	checkKeys(value, LIMIT_KEYS, LIMIT_KEYS, path, errors);
	if (!value || typeof value !== "object") return;
	checkInteger(value.timeoutMs, `${path}.timeoutMs`, errors);
	checkInteger(value.maxCommands, `${path}.maxCommands`, errors);
	checkInteger(value.maxOutputBytes, `${path}.maxOutputBytes`, errors);
	if (typeof value.cancelOnTimeout !== "boolean") push(errors, `${path}.cancelOnTimeout`, "type", "expected boolean");
}

function validateRetryBudget(value, path, errors) {
	checkKeys(value, RETRY_KEYS, RETRY_KEYS, path, errors);
	if (!value || typeof value !== "object") return;
	checkString(value.signature, `${path}.signature`, errors, { minLength: 8 });
	checkInteger(value.attempt, `${path}.attempt`, errors);
	checkInteger(value.maxAttempts, `${path}.maxAttempts`, errors, { min: 1 });
	checkInteger(value.remaining, `${path}.remaining`, errors);
	if (typeof value.exhausted !== "boolean") push(errors, `${path}.exhausted`, "type", "expected boolean");
	if (Number.isInteger(value.attempt) && Number.isInteger(value.maxAttempts) && Number.isInteger(value.remaining)) {
		if (value.attempt > value.maxAttempts) push(errors, `${path}.attempt`, "retryBudget", "attempt exceeds maxAttempts");
		const expectedRemainingCeiling = Math.max(value.maxAttempts - value.attempt, 0);
		if (value.remaining > expectedRemainingCeiling) push(errors, `${path}.remaining`, "retryBudget", "remaining exceeds maxAttempts-attempt");
		if (value.exhausted !== (value.remaining === 0 || value.attempt >= value.maxAttempts)) {
			push(errors, `${path}.exhausted`, "retryBudget", "exhausted must reflect remaining=0 or attempt>=maxAttempts");
		}
	}
}

function validateModel(value, path, errors) {
	checkKeys(value, MODEL_KEYS, MODEL_KEYS, path, errors);
	if (!value || typeof value !== "object") return;
	checkString(value.provider, `${path}.provider`, errors);
	checkString(value.modelId, `${path}.modelId`, errors);
	for (const key of ["modelCalls", "toolCalls", "toolResults"]) checkInteger(value[key], `${path}.${key}`, errors);
}

function validateSubagent(value, path, errors) {
	checkKeys(value, SUBAGENT_KEYS, SUBAGENT_KEYS, path, errors);
	if (!value || typeof value !== "object") return;
	if (value.kind !== "SubagentRuntimeManifestV1") push(errors, `${path}.kind`, "const", "expected SubagentRuntimeManifestV1");
	if (value.schemaVersion !== 1) push(errors, `${path}.schemaVersion`, "const", "expected 1");
	for (const key of ["runId", "roleId", "workerId", "sessionDir", "stdoutPath", "stderrPath", "claimLedgerPath", "failureLedgerPath", "repairQueuePath"]) checkString(value[key], `${path}.${key}`, errors);
	checkInteger(value.attempt, `${path}.attempt`, errors, { min: 1 });
	if (!RUNTIME_STATES.has(value.status)) push(errors, `${path}.status`, "enum", "invalid runtime status");
	checkInteger(value.pid, `${path}.pid`, errors, { min: 1, nullable: true });
	checkInteger(value.parentPid, `${path}.parentPid`, errors, { min: 1, nullable: true });
	checkDigest(value.stdoutSha256, `${path}.stdoutSha256`, errors);
	checkDigest(value.stderrSha256, `${path}.stderrSha256`, errors);
	checkIsoDate(value.startedAt, `${path}.startedAt`, errors);
	checkIsoDate(value.endedAt, `${path}.endedAt`, errors);
	checkInteger(value.elapsedMs, `${path}.elapsedMs`, errors);
	checkInteger(value.exitCode, `${path}.exitCode`, errors, { min: -255, nullable: true });
	if (!(typeof value.signal === "string" || value.signal === null)) push(errors, `${path}.signal`, "type", "expected string or null");
	validateModel(value.model, `${path}.model`, errors);
	checkDigest(value.toolCallDigest, `${path}.toolCallDigest`, errors);
	validateResourceLimits(value.resourceLimits, `${path}.resourceLimits`, errors);
	validateRetryBudget(value.retryBudget, `${path}.retryBudget`, errors);
	checkArray(value.mergeKeys, `${path}.mergeKeys`, errors, { minItems: 1 });
	checkArray(value.evidenceRefs, `${path}.evidenceRefs`, errors, { minItems: 1 });
}

function validateShard(value, path, errors) {
	checkKeys(value, SHARD_KEYS, SHARD_KEYS, path, errors);
	if (!value || typeof value !== "object") return;
	checkString(value.shardId, `${path}.shardId`, errors);
	if (!["re_swarm", "frontier-orchestrator", "agent-dogfood", "operator", "manual"].includes(value.source)) push(errors, `${path}.source`, "enum", "invalid shard source");
	if (!RUNTIME_STATES.has(value.state)) push(errors, `${path}.state`, "enum", "invalid runtime state");
	checkArray(value.dependencies, `${path}.dependencies`, errors);
	checkArray(value.dependents, `${path}.dependents`, errors);
	checkString(value.leaseId, `${path}.leaseId`, errors);
	validateResourceLimits(value.resourceLimits, `${path}.resourceLimits`, errors);
	checkIsoDate(value.startedAt, `${path}.startedAt`, errors);
	checkIsoDate(value.endedAt, `${path}.endedAt`, errors);
	checkString(value.resultManifestPath, `${path}.resultManifestPath`, errors);
	checkDigest(value.stdoutSha256, `${path}.stdoutSha256`, errors);
	checkDigest(value.stderrSha256, `${path}.stderrSha256`, errors);
	checkArray(value.mergeKeys, `${path}.mergeKeys`, errors, { minItems: 1 });
	if (!(typeof value.blockedReason === "string" || value.blockedReason === null)) push(errors, `${path}.blockedReason`, "type", "expected string or null");
}

function validateResumeState(value, path, errors) {
	checkKeys(value, RESUME_KEYS, RESUME_KEYS, path, errors);
	if (!value || typeof value !== "object") return;
	for (const key of ["contractId", "compactionEntryId", "contextPath", "idempotencyKey", "operatorQueueRef", "proofLoopEntry"]) checkString(value[key], `${path}.${key}`, errors);
	checkDigest(value.contextSha256, `${path}.contextSha256`, errors, true);
	if (!RESUME_STATES.has(value.queueState)) push(errors, `${path}.queueState`, "enum", "invalid resume queueState");
	checkArray(value.transitionLog, `${path}.transitionLog`, errors, { minItems: 1 });
	let previous = null;
	(value.transitionLog ?? []).forEach((transition, index) => {
		const tPath = `${path}.transitionLog[${index}]`;
		checkKeys(transition, TRANSITION_KEYS, TRANSITION_KEYS, tPath, errors);
		if (!transition || typeof transition !== "object") return;
		if (transition.from !== previous) push(errors, `${tPath}.from`, "invalid_resume_transition", `expected from=${previous}`);
		const allowed = RESUME_TRANSITIONS.get(previous);
		if (!allowed?.has(transition.to)) push(errors, `${tPath}.to`, "invalid_resume_transition", `cannot transition ${previous} -> ${transition.to}`);
		checkIsoDate(transition.at, `${tPath}.at`, errors);
		checkString(transition.reason, `${tPath}.reason`, errors);
		previous = transition.to;
	});
	if (previous !== null && previous !== value.queueState) push(errors, `${path}.queueState`, "invalid_resume_transition", `queueState ${value.queueState} does not match last transition ${previous}`);
	if (TERMINAL_STATES.has(value.queueState) && value.blockedReason) push(errors, `${path}.blockedReason`, "state", "terminal resume state must not carry blockedReason");
	validateRetryBudget(value.resumeBudget, `${path}.resumeBudget`, errors);
	if (!(typeof value.blockedReason === "string" || value.blockedReason === null)) push(errors, `${path}.blockedReason`, "type", "expected string or null");
}

function validateRepairBudgetState(value, path, errors) {
	checkKeys(value, REPAIR_BUDGET_KEYS, REPAIR_BUDGET_KEYS, path, errors);
	if (!value || typeof value !== "object") return;
	for (const key of ["signature", "failureId", "repairId"]) checkString(value[key], `${path}.${key}`, errors, { minLength: key === "signature" ? 8 : 1 });
	if (!RUNTIME_STATES.has(value.state)) push(errors, `${path}.state`, "enum", "invalid runtime state");
	validateRetryBudget(value.retryBudget, `${path}.retryBudget`, errors);
	if (value.retryBudget?.signature && value.signature !== value.retryBudget.signature) push(errors, `${path}.retryBudget.signature`, "retryBudget", "repair signature must share retry budget signature");
	for (const key of ["allowlist", "rollbackCriteria", "regressionGates", "evidenceWriteback"]) checkArray(value[key], `${path}.${key}`, errors, { minItems: 1 });
}

function validateClaimGate(value, path, errors) {
	checkKeys(value, CLAIM_GATE_KEYS, CLAIM_GATE_KEYS, path, errors);
	if (!value || typeof value !== "object") return;
	if (!["agent-dogfood", "re_swarm", "compound-frontier", "hard-eval", "manual"].includes(value.source)) push(errors, `${path}.source`, "enum", "invalid claim gate source");
	checkString(value.ledgerPath, `${path}.ledgerPath`, errors);
	if (typeof value.hashChainOk !== "boolean") push(errors, `${path}.hashChainOk`, "type", "expected boolean");
	checkArray(value.eventTypes, `${path}.eventTypes`, errors, { minItems: 5 });
	for (const eventType of REQUIRED_EVENT_TYPES) {
		if (!value.eventTypes?.includes(eventType)) push(errors, `${path}.eventTypes`, "missing_event_type", `missing ${eventType}`);
	}
	if (value.strictValidator !== "validate-claim-ledger.mjs") push(errors, `${path}.strictValidator`, "const", "expected validate-claim-ledger.mjs");
	if (typeof value.finalPromotionBlocked !== "boolean") push(errors, `${path}.finalPromotionBlocked`, "type", "expected boolean");
	checkArray(value.unresolvedChallenges, `${path}.unresolvedChallenges`, errors);
	checkArray(value.artifactRefs, `${path}.artifactRefs`, errors, { minItems: 1 });
	checkArray(value.claimIds, `${path}.claimIds`, errors, { minItems: 1 });
	checkString(value.validatorCommand, `${path}.validatorCommand`, errors, { pattern: /validate-claim-ledger\.mjs/ });
	if (value.hashChainOk !== true) push(errors, `${path}.hashChainOk`, "claimPromotion", "hash chain must pass before promotion check");
	if (value.unresolvedChallenges?.length > 0 && value.finalPromotionBlocked !== true) push(errors, `${path}.finalPromotionBlocked`, "claimPromotion", "unresolved challenges must block final promotion");
}

export function validateAutonomousRuntimeBatch(batch) {
	const errors = [];
	checkKeys(batch, BATCH_KEYS, BATCH_KEYS, "$", errors);
	if (!batch || typeof batch !== "object") return { ok: false, errors };
	if (batch.kind !== "PiReconAutonomousRuntimeBatchV1") push(errors, "$.kind", "const", "expected PiReconAutonomousRuntimeBatchV1");
	if (batch.schemaVersion !== 1) push(errors, "$.schemaVersion", "const", "expected 1");
	checkString(batch.runId, "$.runId", errors);
	const arrays = [
		["subagentRuntimeManifests", validateSubagent],
		["parallelShardStates", validateShard],
		["compactResumeStates", validateResumeState],
		["repairBudgetStates", validateRepairBudgetState],
		["claimPromotionGates", validateClaimGate],
	];
	for (const [key, validator] of arrays) {
		checkArray(batch[key], `$.${key}`, errors);
		(batch[key] ?? []).forEach((item, index) => validator(item, `$.${key}[${index}]`, errors));
	}
	const seenSubagents = new Set();
	for (const manifest of batch.subagentRuntimeManifests ?? []) {
		const key = `${manifest.runId}:${manifest.roleId}:${manifest.workerId}:${manifest.attempt}`;
		if (seenSubagents.has(key)) push(errors, "$.subagentRuntimeManifests", "duplicate_subagent_runtime_attempt", key);
		seenSubagents.add(key);
	}
	const seenShards = new Set();
	for (const shard of batch.parallelShardStates ?? []) {
		if (seenShards.has(shard.shardId)) push(errors, "$.parallelShardStates", "duplicate_shard", shard.shardId);
		seenShards.add(shard.shardId);
		for (const dep of shard.dependencies ?? []) {
			if (!seenShards.has(dep) && !(batch.parallelShardStates ?? []).some((candidate) => candidate.shardId === dep)) {
				push(errors, `$.parallelShardStates.${shard.shardId}.dependencies`, "missing_dependency", dep);
			}
		}
	}
	const retryBudgetBySignature = new Map();
	for (const item of [...(batch.subagentRuntimeManifests ?? []), ...(batch.repairBudgetStates ?? [])]) {
		const budget = item.retryBudget;
		if (!budget?.signature) continue;
		const digest = JSON.stringify({ maxAttempts: budget.maxAttempts, remaining: budget.remaining, exhausted: budget.exhausted });
		const existing = retryBudgetBySignature.get(budget.signature);
		if (existing && existing !== digest) push(errors, "$.retryBudget", "inconsistent_retry_budget", budget.signature);
		retryBudgetBySignature.set(budget.signature, digest);
	}
	return { ok: errors.length === 0, errors };
}

export function validateAutonomousRuntimeSchemaFile(root = process.cwd()) {
	const path = join(root, AUTONOMOUS_RUNTIME_SCHEMA_PATH);
	const schema = safeJson(path, null);
	const errors = [];
	if (!schema) push(errors, AUTONOMOUS_RUNTIME_SCHEMA_PATH, "missing", "schema missing or invalid JSON");
	const defs = schema?.$defs ?? {};
	const requiredDefs = [
		"SubagentRuntimeManifestV1",
		"ParallelShardStateV1",
		"CompactResumeStateV2",
		"RepairBudgetStateV1",
		"RuntimeClaimPromotionGateV1",
	];
	for (const def of requiredDefs) {
		if (!defs[def]) push(errors, `#/$defs/${def}`, "required", "missing definition");
		if (defs[def]?.additionalProperties !== false) push(errors, `#/$defs/${def}.additionalProperties`, "strict", "must be false");
	}
	const fixtureOk = schema?.["x-piReconStrictFixture"] === AUTONOMOUS_RUNTIME_FIXTURE_PATH;
	if (!fixtureOk) push(errors, "$.x-piReconStrictFixture", "fixture", "fixture path mismatch");
	const invariants = new Set(schema?.["x-piReconInvariants"] ?? []);
	for (const invariant of [
		"subagent_manifest_records_pid_session_stdout_stderr_model_tool_digest",
		"parallel_shard_state_records_dependencies_timeout_cancel_resource_limits_and_merge_keys",
		"compact_resume_state_is_idempotent_and_tracks_queued_running_done_blocked_exhausted",
		"repair_budget_state_shares_signature_budget_allowlist_rollback_and_regression_gates",
		"claim_promotion_gate_requires_strict_claim_ledger_validator_before_final_promotion",
	]) {
		if (!invariants.has(invariant)) push(errors, "$.x-piReconInvariants", "invariant", `missing ${invariant}`);
	}
	return { ok: errors.length === 0, path: AUTONOMOUS_RUNTIME_SCHEMA_PATH, errors };
}

export function validateAutonomousRuntimeFixture(root = process.cwd()) {
	const path = join(root, AUTONOMOUS_RUNTIME_FIXTURE_PATH);
	const fixture = safeJson(path, null);
	if (!fixture) return { ok: false, path: AUTONOMOUS_RUNTIME_FIXTURE_PATH, valid: { ok: false, errors: [{ code: "missing" }] }, negatives: [] };
	const valid = validateAutonomousRuntimeBatch(fixture.validBatch);
	const negatives = Object.entries(fixture.negativeBatches ?? {}).map(([name, entry]) => {
		const result = validateAutonomousRuntimeBatch(entry.batch);
		const expected = entry.expectError;
		const rejected = !result.ok && result.errors.some((error) => error.code === expected);
		return { name, expected, rejected, errorCodes: [...new Set(result.errors.map((error) => error.code))].sort(), errors: result.errors.slice(0, 12) };
	});
	return {
		ok: valid.ok && negatives.length >= 3 && negatives.every((negative) => negative.rejected),
		path: AUTONOMOUS_RUNTIME_FIXTURE_PATH,
		kind: fixture.kind ?? "missing",
		valid,
		negatives,
	};
}

export function validateAutonomousRuntimeContracts(root = process.cwd()) {
	const schema = validateAutonomousRuntimeSchemaFile(root);
	const fixture = validateAutonomousRuntimeFixture(root);
	return {
		kind: "pi-recon-autonomous-runtime-contract-validation",
		generatedAt: new Date().toISOString(),
		root,
		ok: schema.ok && fixture.ok,
		schema,
		fixture: {
			ok: fixture.ok,
			path: fixture.path,
			kind: fixture.kind,
			validOk: fixture.valid?.ok ?? false,
			validErrorCount: fixture.valid?.errors?.length ?? 0,
			negatives: fixture.negatives,
		},
	};
}

function formatMarkdown(result) {
	const lines = [
		"# REPI Autonomous Runtime Contract Gate",
		"",
		`generated_at: ${result.generatedAt}`,
		`ok: ${result.ok}`,
		`schema: ${result.schema.ok ? "pass" : "fail"}`,
		`fixture: ${result.fixture.ok ? "pass" : "fail"}`,
		"",
		"## Negative fixtures",
	];
	for (const negative of result.fixture.negatives ?? []) {
		lines.push(`- ${negative.name}: ${negative.rejected ? "pass" : "fail"} expected=${negative.expected} codes=${negative.errorCodes.join(",")}`);
	}
	if (!result.schema.ok || !result.fixture.ok) {
		lines.push("", "## Errors");
		for (const error of [...(result.schema.errors ?? []), ...(result.fixture.valid?.errors ?? [])].slice(0, 40)) {
			lines.push(`- ${error.path ?? "$"} ${error.code}: ${error.message ?? ""}`);
		}
	}
	return `${lines.join("\n")}\n`;
}

function writeOutputs(root, result) {
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const outDir = join(root, ".repi-harness", "evidence", "autonomous-runtime-contracts", stamp);
	mkdirSync(outDir, { recursive: true });
	writeFileSync(join(outDir, "result.json"), `${JSON.stringify(result, null, 2)}\n`);
	writeFileSync(join(outDir, "report.md"), formatMarkdown(result));
	return outDir;
}

function printHelp() {
	console.log(`Usage: node scripts/reverse-agent/autonomous-runtime-contracts.mjs [root] [--json] [--write] [--strict]\n\nValidates strict autonomous runtime contracts for sub-agent manifests, shard states, compact resume state, repair budgets, and claim promotion gates.`);
}

function main(argv) {
	if (argv.includes("--help") || argv.includes("-h")) return printHelp();
	const rootArg = argv.find((arg) => !arg.startsWith("-"));
	const root = resolve(rootArg ?? process.cwd());
	const result = validateAutonomousRuntimeContracts(root);
	if (argv.includes("--write")) result.artifactDir = writeOutputs(root, result).replace(`${root}/`, "");
	if (argv.includes("--json")) console.log(JSON.stringify(result, null, 2));
	else process.stdout.write(formatMarkdown(result));
	if (argv.includes("--strict") && !result.ok) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main(process.argv.slice(2));

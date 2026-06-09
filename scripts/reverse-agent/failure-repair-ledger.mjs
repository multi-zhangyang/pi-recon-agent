import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export const FAILURE_REPAIR_WRITEBACK = {
	failureLedgerPath: ".pi/evidence/failures/ledger.jsonl",
	repairQueuePath: ".pi/evidence/repairs/queue.jsonl",
	appendOnly: true,
	mode: "offline-runtime-control-plane",
};

export const FAILURE_REPAIR_CONTRACT_MARKERS = ["FailureLedgerEventV1", "RepairQueueItemV1"];
export const FAILURE_REPAIR_CONTRACT_SCHEMA_PATH = "schemas/reverse-agent/failure-repair-contract.schema.json";
export const FAILURE_REPAIR_STRICT_FIXTURE_PATH = "fixtures/reverse-agent/failure-repair-strict.fixture.json";
export const FAILURE_REPAIR_DEDUP_WINDOW = {
	mode: "deterministic-batch-signature-window",
	failureKey: ["source", "scope", "signature", "attempt"],
	repairKey: ["repairId"],
	budgetKey: ["signature", "retryBudget.retryKey", "budget.retryKey"],
	rejects: ["duplicate_failure_signature_attempt", "duplicate_repair_id", "failure_repair_signature_mismatch"],
};

const HEX_8_64 = /^[a-f0-9]{8,64}$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const FAILURE_STATUS = new Set(["failed", "retrying", "repair_queued", "repaired", "exhausted", "rolled_back", "escalated", "blocked"]);
const FAILURE_CATEGORY = new Set(["artifact_stale", "runtime_failed", "tool_missing", "contract_gap", "same_window_gap", "same_window_xhs_gap", "same_window_douyin_gap", "same_window_bilibili_gap", "platform_claim_gap"]);
const REPAIR_ACTION = new Set(["rerun", "replace-command", "recapture-evidence", "refresh-context", "escalate", "rollback"]);
const ARTIFACT_TIERS = new Set(["same_window_live", "runtime_artifact", "network", "served_asset", "process_config", "persisted_state"]);
const FAILURE_KEYS = new Set([
	"id",
	"ts",
	"source",
	"scope",
	"category",
	"signature",
	"attempt",
	"maxAttempts",
	"status",
	"failedGates",
	"artifacts",
	"artifactHashes",
	"repairId",
	"budget",
	"retryBudget",
	"evidenceWriteback",
	"blockedConditions",
	"rollback",
]);
const REPAIR_KEYS = new Set([
	"repairId",
	"fromFailureId",
	"signature",
	"scope",
	"action",
	"commands",
	"expectedArtifacts",
	"expectedGates",
	"preconditions",
	"paused",
	"allowlist",
	"rollbackCriteria",
	"repairAction",
	"blockedConditions",
	"evidenceWriteback",
	"regressionGates",
	"note",
]);

export function sha256Bytes(data) {
	return createHash("sha256").update(data).digest("hex");
}

function isRecord(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function pushError(errors, path, code, message) {
	errors.push({ path, code, message });
}

function unknownKeys(value, allowed) {
	if (!isRecord(value)) return [];
	return Object.keys(value).filter((key) => !allowed.has(key));
}

function requireRecord(value, path, errors) {
	if (!isRecord(value)) {
		pushError(errors, path, "type", "expected object");
		return false;
	}
	return true;
}

function requireString(value, path, errors, { minLength = 1, pattern = null, enumSet = null } = {}) {
	if (typeof value !== "string") {
		pushError(errors, path, "type", "expected string");
		return;
	}
	if (value.length < minLength) pushError(errors, path, "minLength", `expected length >= ${minLength}`);
	if (pattern && !pattern.test(value)) pushError(errors, path, "pattern", `value does not match ${pattern}`);
	if (enumSet && !enumSet.has(value)) pushError(errors, path, "enum", `unexpected value ${value}`);
}

function requireInteger(value, path, errors, { min = 0 } = {}) {
	if (!Number.isInteger(value)) {
		pushError(errors, path, "type", "expected integer");
		return;
	}
	if (value < min) pushError(errors, path, "minimum", `expected >= ${min}`);
}

function requireBoolean(value, path, errors) {
	if (typeof value !== "boolean") pushError(errors, path, "type", "expected boolean");
}

function requireArray(value, path, errors, { minItems = 0, item = null } = {}) {
	if (!Array.isArray(value)) {
		pushError(errors, path, "type", "expected array");
		return;
	}
	if (value.length < minItems) pushError(errors, path, "minItems", `expected at least ${minItems} item(s)`);
	if (item) value.forEach((entry, index) => item(entry, `${path}[${index}]`, errors));
}

function validateEvidenceWriteback(value, path, errors) {
	if (!requireRecord(value, path, errors)) return;
	const allowed = new Set(["failureLedgerPath", "repairQueuePath", "appendOnly", "mode"]);
	for (const key of unknownKeys(value, allowed)) pushError(errors, `${path}.${key}`, "additionalProperties", "unexpected evidenceWriteback field");
	requireString(value.failureLedgerPath, `${path}.failureLedgerPath`, errors);
	requireString(value.repairQueuePath, `${path}.repairQueuePath`, errors);
	if (value.appendOnly !== true) pushError(errors, `${path}.appendOnly`, "const", "appendOnly must be true");
	if (value.mode !== undefined) requireString(value.mode, `${path}.mode`, errors);
}

function validateBlockedCondition(value, path, errors) {
	if (!requireRecord(value, path, errors)) return;
	const allowed = new Set(["reason", "unblock"]);
	for (const key of unknownKeys(value, allowed)) pushError(errors, `${path}.${key}`, "additionalProperties", "unexpected blocked condition field");
	requireString(value.reason, `${path}.reason`, errors);
	requireString(value.unblock, `${path}.unblock`, errors);
}

function validateArtifact(value, path, errors) {
	if (!requireRecord(value, path, errors)) return;
	const allowed = new Set(["path", "sha256", "tier", "bytes", "mtime", "exists"]);
	for (const key of unknownKeys(value, allowed)) pushError(errors, `${path}.${key}`, "additionalProperties", "unexpected artifact field");
	requireString(value.path, `${path}.path`, errors);
	requireString(value.sha256, `${path}.sha256`, errors, { pattern: HEX_64 });
	requireString(value.tier, `${path}.tier`, errors, { enumSet: ARTIFACT_TIERS });
	if (value.bytes !== undefined) requireInteger(value.bytes, `${path}.bytes`, errors);
	if (value.mtime !== undefined) requireString(value.mtime, `${path}.mtime`, errors, { pattern: ISO_DATE });
	if (value.exists !== undefined) requireBoolean(value.exists, `${path}.exists`, errors);
}

function validateArtifactHash(value, path, errors) {
	if (!requireRecord(value, path, errors)) return;
	const allowed = new Set(["path", "sha256"]);
	for (const key of unknownKeys(value, allowed)) pushError(errors, `${path}.${key}`, "additionalProperties", "unexpected artifact hash field");
	requireString(value.path, `${path}.path`, errors);
	requireString(value.sha256, `${path}.sha256`, errors, { pattern: HEX_64 });
}

function validateRetryBudget(value, path, errors) {
	if (!requireRecord(value, path, errors)) return;
	const allowed = new Set(["retryKey", "remainingAttempts", "exhaustedAction"]);
	for (const key of unknownKeys(value, allowed)) pushError(errors, `${path}.${key}`, "additionalProperties", "unexpected retry budget field");
	requireString(value.retryKey, `${path}.retryKey`, errors, { pattern: HEX_8_64 });
	requireInteger(value.remainingAttempts, `${path}.remainingAttempts`, errors);
	requireString(value.exhaustedAction, `${path}.exhaustedAction`, errors);
}

function validateRollback(value, path, errors) {
	if (!requireRecord(value, path, errors)) return;
	const allowed = new Set(["required", "baseline", "allowlist", "criteria", "restored"]);
	for (const key of unknownKeys(value, allowed)) pushError(errors, `${path}.${key}`, "additionalProperties", "unexpected rollback field");
	requireBoolean(value.required, `${path}.required`, errors);
	requireString(value.baseline, `${path}.baseline`, errors);
	requireArray(value.allowlist, `${path}.allowlist`, errors, { item: requireString });
	requireArray(value.criteria, `${path}.criteria`, errors, { item: requireString });
	requireBoolean(value.restored, `${path}.restored`, errors);
}

function validatePreconditions(value, path, errors) {
	if (!requireRecord(value, path, errors)) return;
	const allowed = new Set(["liveAllowed", "providerAllowed", "requiredSecrets"]);
	for (const key of unknownKeys(value, allowed)) pushError(errors, `${path}.${key}`, "additionalProperties", "unexpected preconditions field");
	requireBoolean(value.liveAllowed, `${path}.liveAllowed`, errors);
	requireBoolean(value.providerAllowed, `${path}.providerAllowed`, errors);
	requireArray(value.requiredSecrets, `${path}.requiredSecrets`, errors, { item: requireString });
}

function validateRollbackCriteria(value, path, errors) {
	if (!requireRecord(value, path, errors)) return;
	const allowed = new Set(["baseline", "mustRestore", "verificationCommand"]);
	for (const key of unknownKeys(value, allowed)) pushError(errors, `${path}.${key}`, "additionalProperties", "unexpected rollback criteria field");
	requireString(value.baseline, `${path}.baseline`, errors);
	requireArray(value.mustRestore, `${path}.mustRestore`, errors, { item: requireString });
	requireString(value.verificationCommand, `${path}.verificationCommand`, errors, { minLength: 0 });
}

export function validateFailureLedgerEventV1(failure, options = {}) {
	const errors = [];
	if (!requireRecord(failure, "$", errors)) return { ok: false, errors };
	for (const key of unknownKeys(failure, FAILURE_KEYS)) pushError(errors, `$.${key}`, "additionalProperties", "unexpected FailureLedgerEventV1 field");
	const missing = [...FAILURE_KEYS].filter((key) => failure[key] === undefined || failure[key] === null);
	for (const key of missing) pushError(errors, `$.${key}`, "required", "missing required field");
	requireString(failure.id, "$.id", errors, { pattern: /^fail:[A-Za-z0-9_.:-]+:[a-f0-9]{8,64}(?::[0-9]+)?$/ });
	requireString(failure.ts, "$.ts", errors, { pattern: ISO_DATE });
	requireString(failure.source, "$.source", errors);
	requireString(failure.scope, "$.scope", errors);
	requireString(failure.category, "$.category", errors, { enumSet: FAILURE_CATEGORY });
	requireString(failure.signature, "$.signature", errors, { pattern: HEX_8_64 });
	requireInteger(failure.attempt, "$.attempt", errors);
	requireInteger(failure.maxAttempts, "$.maxAttempts", errors);
	if (Number.isInteger(failure.attempt) && Number.isInteger(failure.maxAttempts) && failure.attempt > failure.maxAttempts) pushError(errors, "$.attempt", "maximum", "attempt must be <= maxAttempts");
	requireString(failure.status, "$.status", errors, { enumSet: FAILURE_STATUS });
	requireArray(failure.failedGates, "$.failedGates", errors, { minItems: 1, item: requireString });
	requireArray(failure.artifacts, "$.artifacts", errors, { item: validateArtifact });
	requireArray(failure.artifactHashes, "$.artifactHashes", errors, { item: validateArtifactHash });
	requireString(failure.repairId, "$.repairId", errors, { pattern: /^repair:[A-Za-z0-9_.:-]+:[a-f0-9]{8,64}$/ });
	validateRetryBudget(failure.budget, "$.budget", errors);
	validateRetryBudget(failure.retryBudget, "$.retryBudget", errors);
	if (failure.signature && failure.budget?.retryKey && failure.signature !== failure.budget.retryKey) pushError(errors, "$.budget.retryKey", "const", "budget retryKey must equal signature");
	if (failure.signature && failure.retryBudget?.retryKey && failure.signature !== failure.retryBudget.retryKey) pushError(errors, "$.retryBudget.retryKey", "const", "retryBudget retryKey must equal signature");
	validateEvidenceWriteback(failure.evidenceWriteback, "$.evidenceWriteback", errors);
	requireArray(failure.blockedConditions, "$.blockedConditions", errors, { minItems: 1, item: validateBlockedCondition });
	validateRollback(failure.rollback, "$.rollback", errors);
	if (options.repairIds && !options.repairIds.has(failure.repairId)) pushError(errors, "$.repairId", "link", "repairId not found in repair queue");
	return { ok: errors.length === 0, errors };
}

export function validateRepairQueueItemV1(repair, options = {}) {
	const errors = [];
	if (!requireRecord(repair, "$", errors)) return { ok: false, errors };
	for (const key of unknownKeys(repair, REPAIR_KEYS)) pushError(errors, `$.${key}`, "additionalProperties", "unexpected RepairQueueItemV1 field");
	for (const key of REPAIR_KEYS) {
		if (key !== "note" && (repair[key] === undefined || repair[key] === null)) pushError(errors, `$.${key}`, "required", "missing required field");
	}
	requireString(repair.repairId, "$.repairId", errors, { pattern: /^repair:[A-Za-z0-9_.:-]+:[a-f0-9]{8,64}$/ });
	requireString(repair.fromFailureId, "$.fromFailureId", errors, { pattern: /^fail:[A-Za-z0-9_.:-]+:[a-f0-9]{8,64}(?::[0-9]+)?$/ });
	requireString(repair.signature, "$.signature", errors, { pattern: HEX_8_64 });
	requireString(repair.scope, "$.scope", errors);
	requireString(repair.action, "$.action", errors, { enumSet: REPAIR_ACTION });
	requireArray(repair.commands, "$.commands", errors, { item: requireString });
	requireArray(repair.expectedArtifacts, "$.expectedArtifacts", errors, { item: requireString });
	requireArray(repair.expectedGates, "$.expectedGates", errors, { minItems: 1, item: requireString });
	validatePreconditions(repair.preconditions, "$.preconditions", errors);
	requireBoolean(repair.paused, "$.paused", errors);
	requireArray(repair.allowlist, "$.allowlist", errors, { item: requireString });
	validateRollbackCriteria(repair.rollbackCriteria, "$.rollbackCriteria", errors);
	requireString(repair.repairAction, "$.repairAction", errors, { enumSet: REPAIR_ACTION });
	if (repair.action && repair.repairAction && repair.action !== repair.repairAction) pushError(errors, "$.repairAction", "const", "repairAction must equal action");
	requireArray(repair.blockedConditions, "$.blockedConditions", errors, { minItems: 1, item: validateBlockedCondition });
	validateEvidenceWriteback(repair.evidenceWriteback, "$.evidenceWriteback", errors);
	requireArray(repair.regressionGates, "$.regressionGates", errors, { minItems: 1, item: requireString });
	if (repair.note !== undefined) requireString(repair.note, "$.note", errors);
	if (options.failureIds && !options.failureIds.has(repair.fromFailureId)) pushError(errors, "$.fromFailureId", "link", "fromFailureId not found in failure ledger");
	return { ok: errors.length === 0, errors };
}

export function failureRepairDeterministicKey(item, fields = FAILURE_REPAIR_DEDUP_WINDOW.failureKey) {
	return fields
		.map((field) => {
			const parts = field.split(".");
			let value = item;
			for (const part of parts) value = value?.[part];
			return String(value ?? "");
		})
		.join("|");
}

function collectDuplicates(items, keyFn) {
	const seen = new Map();
	const duplicates = [];
	items.forEach((item, index) => {
		const key = keyFn(item);
		const first = seen.get(key);
		if (first !== undefined) duplicates.push({ key, first, duplicate: index });
		else seen.set(key, index);
	});
	return duplicates;
}

export function validateFailureRepairDedup(failures = [], repairs = [], options = {}) {
	const window = options.window ?? FAILURE_REPAIR_DEDUP_WINDOW;
	const duplicateFailures = collectDuplicates(failures, (failure) => failureRepairDeterministicKey(failure, window.failureKey));
	const duplicateRepairs = collectDuplicates(repairs, (repair) => failureRepairDeterministicKey(repair, window.repairKey));
	const repairById = new Map(repairs.map((repair) => [repair.repairId, repair]));
	const failureRepairMismatches = [];
	const retryBudgetMismatches = [];
	for (const failure of failures) {
		const repair = repairById.get(failure.repairId);
		if (!repair) continue;
		if (repair.fromFailureId !== failure.id || repair.signature !== failure.signature || repair.scope !== failure.scope) {
			failureRepairMismatches.push({
				failureId: failure.id,
				repairId: failure.repairId,
				expected: { fromFailureId: failure.id, signature: failure.signature, scope: failure.scope },
				actual: { fromFailureId: repair.fromFailureId, signature: repair.signature, scope: repair.scope },
			});
		}
		if (failure.budget?.retryKey !== failure.signature || failure.retryBudget?.retryKey !== failure.signature) {
			retryBudgetMismatches.push({ failureId: failure.id, signature: failure.signature, budgetRetryKey: failure.budget?.retryKey, retryBudgetRetryKey: failure.retryBudget?.retryKey });
		}
	}
	return {
		ok: duplicateFailures.length === 0 && duplicateRepairs.length === 0 && failureRepairMismatches.length === 0 && retryBudgetMismatches.length === 0,
		window,
		duplicateFailures,
		duplicateRepairs,
		failureRepairMismatches,
		retryBudgetMismatches,
	};
}

export function validateFailureRepairBatch(batch, options = {}) {
	const failures = batch?.failures ?? batch?.failureLedgerEvents ?? [];
	const repairs = batch?.repairs ?? batch?.repairQueue ?? [];
	const repairIds = new Set(repairs.map((repair) => repair.repairId));
	const failureIds = new Set(failures.map((failure) => failure.id));
	const failureRows = failures.map((failure, index) => ({ index, id: failure?.id, ...validateFailureLedgerEventV1(failure, { ...options, repairIds }) }));
	const repairRows = repairs.map((repair, index) => ({ index, repairId: repair?.repairId, ...validateRepairQueueItemV1(repair, { ...options, failureIds }) }));
	const dedup = validateFailureRepairDedup(failures, repairs, options);
	const ok = failures.length > 0 && repairs.length >= failures.length && failureRows.every((row) => row.ok) && repairRows.every((row) => row.ok) && dedup.ok;
	return {
		ok,
		failureCount: failures.length,
		repairCount: repairs.length,
		failures: failureRows,
		repairs: repairRows,
		dedup,
	};
}

export function validateFailureRepairStrictFixture(fixture, options = {}) {
	const validBatch = validateFailureRepairBatch(fixture?.valid, options);
	const duplicateBatch = validateFailureRepairBatch(fixture?.invalidDuplicate, options);
	const looseBatch = validateFailureRepairBatch(fixture?.invalidLoose, options);
	return {
		ok: validBatch.ok && !duplicateBatch.ok && !looseBatch.ok,
		validBatch,
		duplicateBatch,
		looseBatch,
		duplicateRejected: !duplicateBatch.ok && duplicateBatch.dedup.duplicateFailures.length > 0,
		looseRejected: !looseBatch.ok && looseBatch.failures.some((row) => row.errors.some((error) => error.code === "additionalProperties")),
	};
}

export function relPath(root, path) {
	const resolvedRoot = resolve(root || ".");
	const value = String(path || "");
	const resolved = value.startsWith("/") ? value : resolve(resolvedRoot, value);
	return resolved.startsWith(resolvedRoot) ? resolved.slice(resolvedRoot.length + 1) : value;
}

export function artifactHash(root, path, tier = "runtime_artifact") {
	if (!path) return null;
	const full = String(path).startsWith("/") ? String(path) : join(root, String(path));
	if (!existsSync(full)) return null;
	const bytes = readFileSync(full);
	const stat = statSync(full);
	return {
		path: relPath(root, full),
		sha256: sha256Bytes(bytes),
		tier,
		bytes: bytes.length,
		mtime: stat.mtime.toISOString(),
	};
}

export function failureRepairFromGap(params) {
	const root = resolve(params.root || ".");
	const source = params.source || "pi-recon-runtime";
	const scope = params.scope || `${source}:gap`;
	const failedGates = (params.failedGates || []).filter(Boolean);
	const reason = params.reason || `failed gates: ${failedGates.join(",") || scope}`;
	const attempt = Math.max(0, Number(params.attempt ?? 1));
	const maxAttempts = Math.max(attempt, Number(params.maxAttempts ?? attempt));
	const remainingAttempts = Math.max(0, maxAttempts - attempt);
	const signature = sha256Bytes(`${source}:${scope}:${failedGates.join(",")}:${reason}`).slice(0, 24);
	const failureId = `fail:${source}:${signature}`;
	const repairId = `repair:${source}:${signature}`;
	const evidenceWriteback = params.evidenceWriteback || { ...FAILURE_REPAIR_WRITEBACK, mode: source };
	const artifactRows = (params.artifacts || [])
		.map((artifact) => (typeof artifact === "string" ? artifactHash(root, artifact, "runtime_artifact") : artifact))
		.filter(Boolean);
	const blockedConditions = [
		{
			reason,
			unblock: params.unblock || (params.commands || [])[0] || `inspect ${source} failed gates`,
		},
	];
	const rollback = {
		required: Boolean(params.rollbackRequired),
		baseline: params.baseline || "git status --short",
		allowlist: params.allowlist || [],
		criteria: params.rollbackCriteria || ["no unrelated file changes", "previous passed gates remain passed"],
		restored: false,
	};
	const retryBudget = {
		retryKey: signature,
		remainingAttempts,
		exhaustedAction: params.exhaustedAction || "queue repair and escalate to operator",
	};
	const failure = {
		id: failureId,
		ts: new Date().toISOString(),
		source,
		scope,
		category: params.category || "contract_gap",
		signature,
		attempt,
		maxAttempts,
		status: params.status || (remainingAttempts > 0 ? "repair_queued" : "exhausted"),
		failedGates,
		artifacts: artifactRows,
		artifactHashes: artifactRows.map(({ path, sha256 }) => ({ path, sha256 })),
		repairId,
		budget: retryBudget,
		retryBudget,
		evidenceWriteback,
		blockedConditions,
		rollback,
	};
	const action = params.action || "rerun";
	const repair = {
		repairId,
		fromFailureId: failureId,
		signature,
		scope,
		action,
		repairAction: action,
		commands: params.commands || [],
		expectedArtifacts: params.expectedArtifacts || artifactRows.map((artifact) => artifact.path),
		expectedGates: failedGates,
		preconditions: {
			liveAllowed: Boolean(params.liveAllowed),
			providerAllowed: Boolean(params.providerAllowed),
			requiredSecrets: params.requiredSecrets || [],
		},
		paused: params.paused ?? !(params.liveAllowed || params.providerAllowed),
		allowlist: rollback.allowlist,
		rollbackCriteria: {
			baseline: rollback.baseline,
			mustRestore: rollback.allowlist,
			verificationCommand: params.verificationCommand || "npm run gate:autonomous-contracts",
		},
		blockedConditions,
		evidenceWriteback,
		regressionGates: params.regressionGates || failedGates,
	};
	return { failure, repair };
}

export function failureRepairFromGaps(params) {
	const failures = [];
	const repairs = [];
	for (const gap of params.gaps || []) {
		const name = gap.name || gap.gate || gap.id || "gap";
		const failedGates = gap.failedGates || [name];
		const { failure, repair } = failureRepairFromGap({
			...params,
			scope: params.scope || `${params.source}:${name}`,
			reason: gap.reason || gap.required || `gate ${name} did not pass`,
			failedGates,
			artifacts: params.artifacts,
		});
		failures.push(failure);
		repairs.push(repair);
	}
	return {
		failureLedgerEvents: failures,
		repairQueue: repairs,
		failureRepairWriteback: params.evidenceWriteback || { ...FAILURE_REPAIR_WRITEBACK, mode: params.source || "pi-recon-runtime" },
	};
}

export function appendFailureRepairWriteback(root, failures, repairs, evidenceWriteback = FAILURE_REPAIR_WRITEBACK) {
	const resolvedRoot = resolve(root || ".");
	const failurePath = join(resolvedRoot, evidenceWriteback.failureLedgerPath);
	const repairPath = join(resolvedRoot, evidenceWriteback.repairQueuePath);
	mkdirSync(dirname(failurePath), { recursive: true });
	mkdirSync(dirname(repairPath), { recursive: true });
	if (failures?.length) {
		const current = existsSync(failurePath) ? readFileSync(failurePath, "utf8") : "";
		writeFileSync(
			failurePath,
			`${current}${current.endsWith("\n") || !current ? "" : "\n"}${failures.map((item) => JSON.stringify(item)).join("\n")}\n`,
			"utf8",
		);
	}
	if (repairs?.length) {
		const current = existsSync(repairPath) ? readFileSync(repairPath, "utf8") : "";
		writeFileSync(
			repairPath,
			`${current}${current.endsWith("\n") || !current ? "" : "\n"}${repairs.map((item) => JSON.stringify(item)).join("\n")}\n`,
			"utf8",
		);
	}
	return { failurePath: relPath(resolvedRoot, failurePath), repairPath: relPath(resolvedRoot, repairPath) };
}

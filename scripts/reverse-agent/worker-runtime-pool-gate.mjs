#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const FIXTURE_PATH = "fixtures/reverse-agent/worker-runtime-pool.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function parseTime(ts) {
	const value = Date.parse(ts);
	return Number.isFinite(value) ? value : undefined;
}

function validateHashes(pool, artifacts) {
	const errors = [];
	const map = new Map((artifacts ?? []).map((artifact) => [artifact.path, artifact]));
	for (const worker of pool.workers ?? []) {
		for (const [field, pathField, hashField] of [["stdout", "stdoutPath", "stdoutSha256"], ["stderr", "stderrPath", "stderrSha256"]]) {
			const artifact = map.get(worker[pathField]);
			if (!artifact) {
				errors.push(`${worker.workerId}.${field}.missing_artifact`);
				continue;
			}
			const actual = sha256(artifact.content ?? "");
			if (worker[hashField] !== actual) errors.push(`${worker.workerId}.${field}.hash_mismatch`);
		}
		if (!/^[a-f0-9]{64}$/.test(worker.toolCallDigest ?? "")) errors.push(`${worker.workerId}.toolCallDigest`);
	}
	return errors;
}

function validateConcurrency(pool) {
	const errors = [];
	const workers = (pool.workers ?? []).filter((worker) => ["running", "passed", "failed", "timeout", "cancelled"].includes(worker.status));
	const points = [];
	for (const worker of workers) {
		const start = parseTime(worker.startedAt);
		const end = parseTime(worker.endedAt);
		if (start === undefined || end === undefined || end < start) {
			errors.push(`${worker.workerId}.invalid_time_window`);
			continue;
		}
		points.push({ t: start, delta: 1, workerId: worker.workerId });
		points.push({ t: end, delta: -1, workerId: worker.workerId });
		const elapsed = end - start;
		if (elapsed > worker.timeoutMs && worker.status !== "timeout" && worker.status !== "cancelled") errors.push(`${worker.workerId}.timeout_not_marked`);
		if (worker.status === "timeout" && pool.cancelOnTimeout && !worker.cancelledAt) errors.push(`${worker.workerId}.timeout_without_cancel`);
	}
	points.sort((a, b) => a.t - b.t || a.delta - b.delta);
	let active = 0;
	let peak = 0;
	for (const point of points) {
		active += point.delta;
		peak = Math.max(peak, active);
		if (active > pool.maxConcurrency) errors.push(`maxConcurrency_exceeded:${active}>${pool.maxConcurrency}@${new Date(point.t).toISOString()}`);
	}
	return { errors, peak };
}

function validateResourceBudget(pool) {
	const errors = [];
	const budget = pool.resourceBudget ?? {};
	for (const worker of pool.workers ?? []) {
		const lease = worker.resourceLease ?? {};
		if (lease.cpuSlots > budget.cpuSlots) errors.push(`${worker.workerId}.cpuSlots_exceeds_budget`);
		if (lease.memoryMb > budget.memoryMb) errors.push(`${worker.workerId}.memoryMb_exceeds_budget`);
		if (lease.maxProcesses > budget.maxProcesses) errors.push(`${worker.workerId}.maxProcesses_exceeds_budget`);
	}
	for (const group of pool.parallelGroups ?? []) {
		const groupWorkers = (pool.workers ?? []).filter((worker) => group.workers?.includes(worker.workerId));
		const cpu = groupWorkers.reduce((sum, worker) => sum + Number(worker.resourceLease?.cpuSlots ?? 0), 0);
		const mem = groupWorkers.reduce((sum, worker) => sum + Number(worker.resourceLease?.memoryMb ?? 0), 0);
		const procs = groupWorkers.reduce((sum, worker) => sum + Number(worker.resourceLease?.maxProcesses ?? 0), 0);
		if (cpu > budget.cpuSlots) errors.push(`${group.groupId}.cpuSlots_exceeds_budget:${cpu}>${budget.cpuSlots}`);
		if (mem > budget.memoryMb) errors.push(`${group.groupId}.memoryMb_exceeds_budget:${mem}>${budget.memoryMb}`);
		if (procs > budget.maxProcesses) errors.push(`${group.groupId}.maxProcesses_exceeds_budget:${procs}>${budget.maxProcesses}`);
		if (groupWorkers.length > group.maxConcurrency) errors.push(`${group.groupId}.maxConcurrency_exceeded`);
		for (const dep of group.dependsOn ?? []) {
			const depGroup = pool.parallelGroups?.find((item) => item.groupId === dep);
			if (!depGroup) errors.push(`${group.groupId}.missing_dependency:${dep}`);
		}
	}
	return errors;
}

function validateRetryBudget(pool) {
	const errors = [];
	for (const worker of pool.workers ?? []) {
		if (worker.attempt > worker.maxAttempts) errors.push(`${worker.workerId}.attempt_exceeds_maxAttempts`);
		if (worker.retryBudget?.remaining !== Math.max(0, worker.maxAttempts - worker.attempt)) errors.push(`${worker.workerId}.retry_remaining_inconsistent`);
		if (worker.retryBudget?.exhausted !== (worker.attempt >= worker.maxAttempts)) errors.push(`${worker.workerId}.retry_exhausted_inconsistent`);
		if (worker.status === "retry_queued" && worker.retryBudget?.exhausted) errors.push(`${worker.workerId}.exhausted_still_retrying`);
		if (worker.status === "exhausted" && !worker.retryBudget?.exhausted) errors.push(`${worker.workerId}.exhausted_without_budget`);
	}
	return errors;
}

function validateMerge(pool) {
	const errors = [];
	const collisions = new Map();
	for (const worker of pool.workers ?? []) {
		const keys = Array.isArray(worker.mergeKey) ? worker.mergeKey : [worker.mergeKey];
		for (const key of keys.filter(Boolean)) {
			const rows = collisions.get(key) ?? [];
			rows.push(worker.workerId);
			collisions.set(key, rows);
		}
	}
	const resolved = new Set((pool.mergeProtocol?.conflicts ?? []).filter((row) => row.status === "resolved").map((row) => row.mergeKey));
	for (const [key, workers] of collisions) {
		if (workers.length > 1 && !resolved.has(key)) errors.push(`duplicate_mergeKey_unresolved:${key}`);
	}
	for (const row of pool.mergeProtocol?.conflicts ?? []) {
		if (!row.winner || !row.evidenceRefs?.length || !row.resolutionReason) errors.push(`merge_conflict_missing_evidence:${row.mergeKey}`);
	}
	return errors;
}

function eventHash(event) {
	const { eventHash: _eventHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function validateClaimLedger(events) {
	const errors = [];
	let prevHash = "0".repeat(64);
	for (const [index, event] of (events ?? []).entries()) {
		if (event.prevHash !== prevHash) errors.push(`claimLedgerEvents[${index}].prevHash`);
		if (event.eventHash !== eventHash(event)) errors.push(`claimLedgerEvents[${index}].eventHash`);
		prevHash = event.eventHash;
	}
	const byClaim = new Map();
	for (const event of events ?? []) {
		const id = event.claimId ?? event.claimIds?.[0];
		if (!id) continue;
		const rows = byClaim.get(id) ?? [];
		rows.push(event.type);
		byClaim.set(id, rows);
	}
	for (const [claimId, types] of byClaim) {
		for (const required of ["artifact_handoff", "claim", "validation", "challenge", "resolution"]) if (!types.includes(required)) errors.push(`${claimId}.missing_${required}`);
	}
	return errors;
}

function validateClaimRefs(pool) {
	const errors = [];
	const ledgerClaimIds = new Set((pool.claimLedgerEvents ?? []).flatMap((event) => [event.claimId, ...(event.claimIds ?? [])]).filter(Boolean));
	for (const worker of pool.workers ?? []) {
		for (const claim of worker.claimRefs ?? []) if (!ledgerClaimIds.has(claim)) errors.push(`${worker.workerId}.claim_without_ledger:${claim}`);
	}
	return errors;
}

function validatePool(fixture) {
	const pool = fixture.workerRuntimePool;
	const hashErrors = validateHashes(pool, fixture.artifacts);
	const concurrency = validateConcurrency(pool);
	const resourceErrors = validateResourceBudget(pool);
	const retryErrors = validateRetryBudget(pool);
	const mergeErrors = validateMerge(pool);
	const ledgerErrors = validateClaimLedger(pool.claimLedgerEvents ?? []);
	const claimRefErrors = validateClaimRefs(pool);
	const errors = [...hashErrors, ...concurrency.errors, ...resourceErrors, ...retryErrors, ...mergeErrors, ...ledgerErrors, ...claimRefErrors];
	return { status: errors.length ? "fail" : "pass", errors, peakConcurrency: concurrency.peak };
}

function mutateFixture(fixture, negative) {
	const clone = JSON.parse(JSON.stringify(fixture));
	const pool = clone.workerRuntimePool;
	if (negative.mutate === "exceedsMaxConcurrency") pool.maxConcurrency = 1;
	if (negative.mutate === "duplicateMergeKeyUnresolved") pool.mergeProtocol.conflicts = [];
	if (negative.mutate === "timeoutWithoutCancel") {
		const worker = pool.workers.find((item) => item.status === "timeout");
		if (worker) delete worker.cancelledAt;
	}
	if (negative.mutate === "retryBudgetInconsistent") pool.workers[0].retryBudget.remaining = 99;
	if (negative.mutate === "claimWithoutValidation") pool.claimLedgerEvents = pool.claimLedgerEvents.filter((event) => event.type !== "validation" || event.claimId !== "claim-authz-replay");
	if (negative.mutate === "stdoutHashMismatch") pool.workers[0].stdoutSha256 = "e".repeat(64);
	if (negative.mutate === "exhaustedStillRetrying") {
		const worker = pool.workers.find((item) => item.status === "exhausted");
		if (worker) worker.status = "retry_queued";
	}
	return clone;
}

function checkExpected(poolResult, expected = {}) {
	const errors = [];
	if (expected.maxPeakConcurrency !== undefined && poolResult.peakConcurrency > expected.maxPeakConcurrency) errors.push(`peak concurrency ${poolResult.peakConcurrency} > ${expected.maxPeakConcurrency}`);
	for (const needle of expected.mustNotHaveErrors ?? []) if (poolResult.errors.some((error) => error.includes(needle))) errors.push(`unexpected error ${needle}`);
	for (const needle of expected.mustHaveErrors ?? []) if (!poolResult.errors.some((error) => error.includes(needle))) errors.push(`missing expected error ${needle}`);
	return errors;
}

function negativeCase(fixture, negative) {
	const mutated = mutateFixture(fixture, negative);
	const result = validatePool(mutated);
	const errors = checkExpected(result, negative.expected ?? {});
	return { id: `negative-${negative.id}`, status: errors.length ? "fail" : "pass", evidence: { validation: result, errors } };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "worker-runtime-pool", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "result.json");
	writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
	return path;
}

function main() {
	const checks = [];
	let fixture;
	try {
		fixture = readJson(FIXTURE_PATH);
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-worker-runtime-pool-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH } });
	} catch (error) {
		checks.push({ id: "fixture:parse", status: "fail", evidence: { path: FIXTURE_PATH, error: String(error) } });
	}
	if (fixture) {
		const result = validatePool(fixture);
		const expectedErrors = checkExpected(result, fixture.expected ?? {});
		checks.push({ id: "fixture:pool-contract", status: result.status === "pass" && expectedErrors.length === 0 ? "pass" : "fail", evidence: { validation: result, expectedErrors } });
		for (const negative of fixture.negativeCases ?? []) checks.push(negativeCase(fixture, negative));
	}
	checks.push(
		markerCheck("code:worker-runtime-pool", "packages/coding-agent/src/core/recon-profile.ts", ["type WorkerRuntimePoolV1", "function verifyWorkerRuntimePool", "workerRuntimePoolEvidenceContract", "claimAwareWorkerMergeProtocol"]),
		markerCheck("docs:worker-runtime-pool", "README.md", ["Worker Runtime Pool", "gate:worker-runtime-pool", "timeout/cancel", "claim-aware merge"]),
		markerCheck("npm:worker-runtime-pool-script", "package.json", ["gate:worker-runtime-pool", "worker-runtime-pool-gate.mjs"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-worker-runtime-pool-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Worker Runtime Pool Gate");
		console.log(`ok: ${result.ok}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
		for (const check of checks) console.log(`- ${check.id}: ${check.status}`);
		if (failed.length) console.log(`failed: ${failed.map((check) => check.id).join(", ")}`);
	}
	if (strict && failed.length) process.exitCode = 1;
}

main();

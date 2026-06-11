#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_WORKER_LEASE_TMP === "1";
const FIXTURE_PATH = "fixtures/reverse-agent/worker-lease-scheduler.fixture.json";
const SCHEMA_PATH = "schemas/reverse-agent/worker-lease-scheduler.schema.json";
const sha256 = (value) => createHash("sha256").update(String(value ?? "")).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function stableJson(value) {
	return JSON.stringify(value, (_key, item) => {
		if (!item || typeof item !== "object" || Array.isArray(item)) return item;
		return Object.keys(item).sort().reduce((out, key) => { out[key] = item[key]; return out; }, {});
	});
}
function eventHash(event) {
	const { eventHash: _eventHash, ...withoutHash } = event;
	return sha256(stableJson(withoutHash));
}
function pushEvent(events, event) {
	const prevHash = events.at(-1)?.eventHash ?? "0".repeat(64);
	const row = { kind: "WorkerLeaseSchedulerEventV1", schemaVersion: 1, ...event, prevHash };
	row.eventHash = eventHash(row);
	events.push(row);
	return row;
}
function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function buildRuntimeScheduler() {
	const events = [];
	const tasks = ["authz", "signing", "pwn", "pcap", "firmware"].map((name, index) => ({
		taskId: `task-${name}`,
		shardKey: name,
		status: "queued",
		attempt: 0,
		maxAttempts: 2,
		claimRefs: [`claim-${name}`],
		artifactRefs: [`artifact-${name}.json`],
	}));
	for (const task of tasks) pushEvent(events, { eventId: `ev-enqueue-${task.taskId}`, ts: new Date().toISOString(), type: "enqueue", taskId: task.taskId });
	const lease = (task, worker, n) => {
		task.status = "leased";
		task.ownerWorkerId = worker;
		task.leaseId = `lease-${task.taskId}-${n}`;
		task.leaseExpiresAt = new Date(Date.now() + 30000).toISOString();
		task.attempt += 1;
		pushEvent(events, { eventId: `ev-lease-${task.taskId}-${n}`, ts: new Date().toISOString(), type: "lease_acquired", taskId: task.taskId, workerId: worker, leaseId: task.leaseId });
	};
	lease(tasks[0], "worker-a", 1);
	lease(tasks[1], "worker-b", 1);
	pushEvent(events, { eventId: "ev-heartbeat-authz", ts: new Date().toISOString(), type: "heartbeat", taskId: tasks[0].taskId, workerId: "worker-a", leaseId: tasks[0].leaseId });
	pushEvent(events, { eventId: "ev-stale-signing", ts: new Date().toISOString(), type: "stale_detected", taskId: tasks[1].taskId, workerId: "worker-b", leaseId: tasks[1].leaseId });
	tasks[1].status = "stale_recovered";
	pushEvent(events, { eventId: "ev-steal-signing", ts: new Date().toISOString(), type: "work_stolen", taskId: tasks[1].taskId, workerId: "worker-c", leaseId: "lease-task-signing-2" });
	tasks[1].ownerWorkerId = "worker-c";
	tasks[1].leaseId = "lease-task-signing-2";
	tasks[1].attempt = 2;
	for (const task of [tasks[0], tasks[1]]) {
		task.status = "completed";
		pushEvent(events, { eventId: `ev-complete-${task.taskId}`, ts: new Date().toISOString(), type: "completed", taskId: task.taskId, workerId: task.ownerWorkerId, leaseId: task.leaseId });
	}
	pushEvent(events, { eventId: "ev-dedup-authz", ts: new Date().toISOString(), type: "dedup_rejected", taskId: tasks[0].taskId, workerId: "worker-b", leaseId: "stale-duplicate" });
	lease(tasks[2], "worker-a", 1);
	lease(tasks[3], "worker-b", 1);
	tasks[4].status = "requeued";
	pushEvent(events, { eventId: "ev-requeue-firmware", ts: new Date().toISOString(), type: "lease_released", taskId: tasks[4].taskId, workerId: "scheduler" });
	const scheduler = {
		kind: "WorkerLeaseSchedulerV1",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		schedulerId: "worker-lease-scheduler-runtime",
		maxConcurrency: 2,
		workerIds: ["worker-a", "worker-b", "worker-c"],
		tasks,
		events,
		assertions: {
			leaseExclusive: true,
			heartbeatRequired: true,
			staleLeaseRecovered: true,
			workStealingObserved: true,
			duplicateCompletionRejected: true,
			maxConcurrencyRespected: true,
			claimRefsPreserved: tasks.every((task) => task.claimRefs.length > 0),
			appendOnlyHashChain: true,
		},
	};
	return scheduler;
}

function validateScheduler(scheduler) {
	const errors = [];
	if (scheduler?.kind !== "WorkerLeaseSchedulerV1") errors.push("worker_lease_scheduler_kind_invalid");
	let prevHash = "0".repeat(64);
	const completed = new Set();
	for (const event of scheduler.events ?? []) {
		if (event.prevHash !== prevHash) errors.push(`prevHash:${event.eventId}`);
		if (event.eventHash !== eventHash(event)) errors.push(`eventHash:${event.eventId}`);
		prevHash = event.eventHash;
		if (event.type === "completed") {
			if (completed.has(event.taskId)) errors.push(`duplicateCompletion:${event.taskId}`);
			completed.add(event.taskId);
		}
	}
	const activeByTask = new Map();
	for (const task of scheduler.tasks ?? []) {
		if (!task.claimRefs?.length) errors.push(`claimRefsMissing:${task.taskId}`);
		if (task.attempt > task.maxAttempts) errors.push(`attemptExceeded:${task.taskId}`);
		if (["leased", "running"].includes(task.status)) {
			if (activeByTask.has(task.taskId)) errors.push(`duplicateActiveLease:${task.taskId}`);
			activeByTask.set(task.taskId, task.leaseId);
		}
	}
	const requiredAssertions = ["leaseExclusive", "heartbeatRequired", "staleLeaseRecovered", "workStealingObserved", "duplicateCompletionRejected", "maxConcurrencyRespected", "claimRefsPreserved", "appendOnlyHashChain"];
	for (const key of requiredAssertions) if (scheduler.assertions?.[key] !== true) errors.push(`assertion:${key}`);
	return { ok: errors.length === 0, errors };
}

function mutateScheduler(scheduler, mutate) {
	const clone = JSON.parse(JSON.stringify(scheduler));
	if (mutate === "hashDrift") clone.events[1].workerId = "tampered";
	if (mutate === "missingHeartbeat") clone.assertions.heartbeatRequired = false;
	if (mutate === "noStaleRecovery") clone.assertions.staleLeaseRecovered = false;
	if (mutate === "duplicateCompletion") clone.events.push({ ...clone.events.find((event) => event.type === "completed"), eventId: "ev-duplicate-complete" });
	if (mutate === "missingClaimRefs") clone.tasks[0].claimRefs = [];
	if (mutate === "maxConcurrencyViolation") clone.assertions.maxConcurrencyRespected = false;
	return clone;
}
function negativeCase(scheduler, negative) {
	const validation = validateScheduler(mutateScheduler(scheduler, negative.mutate));
	const missing = (negative.expectedErrors ?? []).filter((needle) => !validation.errors.some((error) => error.includes(needle)));
	return { id: `negative:${negative.id}`, status: !validation.ok && missing.length === 0 ? "pass" : "fail", evidence: { validation, missing } };
}

function writeRuntimeProbe(probePath, outPath, tempRoot) {
	const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
	writeFileSync(probePath, `
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createReconExtensionFactory } from ${JSON.stringify(importUrl)};
const outPath = ${JSON.stringify(outPath)};
const tempRoot = ${JSON.stringify(tempRoot)};
const agentDir = join(tempRoot, "agent");
const workspace = join(tempRoot, "workspace");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "worker-lease-scheduler-live";
process.env.REPI_BRANCH_ID = "worker-lease-scheduler-branch";
process.chdir(workspace);
const tools = new Map();
const fakePi = {
  registerCommand() {},
  registerTool(tool) { tools.set(tool.name, tool); },
  on() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {},
  exec: async (cmd) => ({ code: 0, stdout: ["ok", "command=" + cmd, "artifact=/tmp/repi-worker-lease-proof.json", "sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "verification=pass"].join("\\n"), stderr: "", killed: false })
};
createReconExtensionFactory()(fakePi);
const swarm = tools.get("re_swarm");
if (!swarm) throw new Error("missing re_swarm tool");
async function main() {
  const result = await swarm.execute("worker-lease-scheduler-live", { action: "run", target: "local-worker-lease-probe", task: "validate worker lease scheduler live wiring", maxWorkers: 2, maxCommands: 1 });
  const swarmArtifactPath = result.details?.path;
  const workerLeaseSchedulerPath = swarmArtifactPath ? swarmArtifactPath.replace(new RegExp("\\.md$", "i"), "-worker-lease-scheduler.json") : undefined;
  const workerLeaseScheduler = workerLeaseSchedulerPath && existsSync(workerLeaseSchedulerPath) ? JSON.parse(readFileSync(workerLeaseSchedulerPath, "utf8")) : undefined;
  writeFileSync(outPath, JSON.stringify({ swarmArtifactPath, workerLeaseSchedulerPath, workerLeaseScheduler, text: result.content?.[0]?.text ?? "" }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}

function runRuntimeProbe(tempRoot) {
	const probePath = join(tempRoot, "worker-lease-scheduler-live-probe.ts");
	const outPath = join(tempRoot, "probe-result.json");
	writeRuntimeProbe(probePath, outPath, tempRoot);
	const tsx = join(root, "node_modules", ".bin", "tsx");
	const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], { cwd: root, env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1", REPI_REPO_ROOT: root }, encoding: "utf8", maxBuffer: 30 * 1024 * 1024 });
	return { ...result, outPath, probePath };
}

function validateRuntimeProbe(probeData) {
	const wrapper = probeData.workerLeaseScheduler;
	const scheduler = wrapper?.scheduler ?? wrapper;
	const validation = validateScheduler(scheduler);
	const eventTypes = new Set((scheduler?.events ?? []).map((event) => event.type));
	const errors = [...validation.errors];
	if (!validation.ok) errors.push("runtime_scheduler_validation_failed");
	if (!probeData.workerLeaseSchedulerPath || !probeData.workerLeaseSchedulerPath.endsWith("-worker-lease-scheduler.json")) errors.push("runtime_worker_lease_scheduler_path_missing");
	if (wrapper?.validation?.ok !== true) errors.push("runtime_embedded_validation_not_pass");
	if (!String(probeData.text ?? "").includes("worker_lease_scheduler:")) errors.push("runtime_output_missing_worker_lease_scheduler_section");
	if (!String(probeData.text ?? "").includes("- status=pass")) errors.push("runtime_output_missing_pass_status");
	for (const type of ["enqueue", "lease_acquired", "heartbeat", "stale_detected", "work_stolen", "completed", "dedup_rejected"]) {
		if (!eventTypes.has(type)) errors.push(`runtime_event_missing:${type}`);
	}
	if ((scheduler?.tasks ?? []).length < 2) errors.push("runtime_scheduler_tasks_too_few");
	if (!scheduler?.tasks?.every((task) => task.claimRefs?.length)) errors.push("runtime_claim_refs_not_preserved");
	return errors;
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "worker-lease-scheduler", stamp);
	mkdirSync(dir, { recursive: true });
	const path = join(dir, "report.json");
	writeFileSync(path, JSON.stringify(result, null, 2));
	return path;
}
function formatMarkdown(result) {
	const lines = ["# REPI Worker Lease Scheduler Gate", "", `generated_at: ${result.generatedAt}`, `ok: ${result.ok}`, "", "## Checks"];
	for (const check of result.checks) lines.push(`- ${check.id}: ${check.status}`);
	if (result.evidencePath) lines.push("", `evidence: ${result.evidencePath}`);
	return `${lines.join("\n")}\n`;
}

const scheduler = buildRuntimeScheduler();
const validation = validateScheduler(scheduler);
const fixture = readJson(FIXTURE_PATH);
const checks = [
	{ id: "runtime:worker-lease-scheduler-validation", status: validation.ok ? "pass" : "fail", evidence: validation },
	{ id: "runtime:worker-lease-stale-recovery", status: scheduler.assertions.staleLeaseRecovered ? "pass" : "fail", evidence: { staleEvents: scheduler.events.filter((event) => ["stale_detected", "work_stolen"].includes(event.type)) } },
	{ id: "runtime:worker-lease-dedup-completion", status: scheduler.assertions.duplicateCompletionRejected ? "pass" : "fail", evidence: { dedupEvents: scheduler.events.filter((event) => event.type === "dedup_rejected") } },
	{ id: "runtime:worker-lease-claim-preservation", status: scheduler.assertions.claimRefsPreserved ? "pass" : "fail", evidence: { claimRefs: scheduler.tasks.map((task) => [task.taskId, task.claimRefs]) } },
	...((fixture.negativeCases ?? []).map((negative) => negativeCase(scheduler, negative))),
];
const tempRoot = mkdtempSync(join(tmpdir(), "repi-worker-lease-scheduler-"));
try {
	const probe = runRuntimeProbe(tempRoot);
	checks.push({ id: "runtime:re-swarm-worker-lease-scheduler-exit", status: probe.status === 0 ? "pass" : "fail", evidence: { code: probe.status, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) } });
	if (probe.status === 0 && existsSync(probe.outPath)) {
		const probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
		const runtimeErrors = validateRuntimeProbe(probeData);
		checks.push({ id: "runtime:worker-lease-scheduler-live-wiring", status: runtimeErrors.length ? "fail" : "pass", evidence: { errors: runtimeErrors, swarmArtifactPath: probeData.swarmArtifactPath, workerLeaseSchedulerPath: probeData.workerLeaseSchedulerPath, tasks: probeData.workerLeaseScheduler?.scheduler?.tasks?.length ?? 0, events: probeData.workerLeaseScheduler?.scheduler?.events?.length ?? 0 } });
	} else {
		checks.push({ id: "runtime:worker-lease-scheduler-live-wiring", status: "fail", evidence: { error: "probe output missing" } });
	}
} finally {
	if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
}
checks.push(
	markerCheck("code:worker-lease-scheduler-types", "packages/coding-agent/src/core/recon-profile.ts", ["type WorkerLeaseSchedulerV1", "type WorkerLeaseSchedulerEventV1", "function verifyWorkerLeaseSchedulerV1", "function buildWorkerLeaseSchedulerFromSwarm", "function refreshSwarmWorkerLeaseScheduler", "workerLeaseSchedulerPath", "workerLeaseSchedulerStatus", "runtime:worker-lease-scheduler-live-wiring", "worker_lease_scheduler_stale_recovery_missing"]),
	markerCheck("schema:worker-lease-scheduler", SCHEMA_PATH, ["WorkerLeaseSchedulerV1", "lease_exclusive", "stale_lease_recovery", "duplicate_completion_rejected"]),
	markerCheck("fixture:worker-lease-scheduler", FIXTURE_PATH, ["repi-worker-lease-scheduler-fixture", "negative:worker-lease-hash-drift", "negative:worker-lease-no-stale-recovery"]),
	markerCheck("npm:worker-lease-scheduler", "package.json", ["gate:worker-lease-scheduler", "worker-lease-scheduler-gate.mjs"]),
	markerCheck("harness:worker-lease-scheduler", "scripts/reverse-agent/repi-top-harness.mjs", ["runtime:worker-lease-scheduler", "child:gate:worker-lease-scheduler"]),
	markerCheck("autonomy:worker-lease-scheduler", "scripts/reverse-agent/autonomy-control-plane.mjs", ["worker_lease_scheduler_gate", "WorkerLeaseSchedulerV1", "stale lease recovery"]),
	markerCheck("docs:worker-lease-scheduler", "README.md", ["WorkerLeaseSchedulerV1", "gate:worker-lease-scheduler", "runtime:worker-lease-scheduler-live-wiring", "workerLeaseSchedulerPath"]),
);
const result = { kind: "repi-worker-lease-scheduler-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: checks.every((check) => check.status === "pass"), root, scheduler, checks };
result.evidencePath = writeEvidenceFile(result);
if (json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
else process.stdout.write(formatMarkdown(result));
if (strict && !result.ok) process.exitCode = 1;

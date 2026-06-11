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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_MATURATION_TMP === "1";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-maturation-runtime.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function unique(values, limit = 80) {
	const seen = new Set();
	const out = [];
	for (const value of values) {
		const text = String(value ?? "").trim();
		if (!text) continue;
		const key = text.toLowerCase();
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(text);
		if (out.length >= limit) break;
	}
	return out;
}

function rowHash(row) {
	const { entryHash, ...withoutHash } = row;
	return sha256(JSON.stringify(withoutHash));
}

function actionFromDecision(decision, score) {
	if (decision.action === "quarantine" || (decision.blockers ?? []).some((blocker) => /scope_blocked|quarantine|forbidden_leak|poison/i.test(blocker))) return "quarantine";
	if (decision.action === "avoid" || decision.action === "expire") return "demote";
	if (decision.action === "wait-feedback") return "feedback-required";
	if (!(decision.sourceReplayRowIds ?? []).length && (decision.causalScore ?? 0) <= 0 && ["inject", "reuse"].includes(decision.action)) return "replay-required";
	if (["inject", "reuse"].includes(decision.action) && score >= 72 && (decision.evidenceRefs ?? []).length) return "promote";
	return "retain";
}

function daysSince(timestamp, now) {
	const then = Date.parse(timestamp ?? "");
	const current = Date.parse(now ?? "");
	if (!Number.isFinite(then) || !Number.isFinite(current) || current < then) return 0;
	return Number(((current - then) / 86400000).toFixed(2));
}

function retentionFromDecision(decision, action, maturityScore, generatedAt) {
	const lastUsefulAt = decision.lastUsefulAt ?? decision.ts ?? generatedAt;
	const stalenessDays = daysSince(lastUsefulAt, generatedAt);
	const failureCount = Number(decision.failureCount ?? 0);
	const reuseCount = Number(decision.reuseCount ?? 0);
	const replayBonus = (decision.sourceReplayRowIds ?? []).length ? 8 : 0;
	const decayPenalty = Number(Math.max(0, Math.min(55, stalenessDays * 0.18 + failureCount * 6 + (action === "feedback-required" ? 6 : 0) + (action === "replay-required" ? 8 : 0) - reuseCount * 1.5 - replayBonus)).toFixed(2));
	const retentionScore = Number(Math.max(0, Math.min(100, maturityScore - decayPenalty + replayBonus + Math.min(10, reuseCount * 1.5))).toFixed(2));
	let retentionAction = "keep";
	if (action === "quarantine" || (decision.blockers ?? []).some((blocker) => /scope_blocked|quarantine|poison|forbidden/i.test(blocker))) retentionAction = "quarantine";
	else if ((action === "demote" && retentionScore < 35) || (stalenessDays > 90 && retentionScore < 55)) retentionAction = "expire";
	else if (action === "demote") retentionAction = "decay";
	else if (action === "feedback-required") retentionAction = "feedback";
	else if (action === "replay-required" || stalenessDays > 30) retentionAction = "rehearse";
	const eventId = decision.sourceEventIds?.[0] ?? decision.id;
	const retentionCommands = unique([
		retentionAction === "rehearse" ? `re_memory replay # retention_rehearsal event=${eventId}` : undefined,
		retentionAction === "feedback" ? `re_memory feedback # retention_feedback event=${eventId}` : undefined,
		retentionAction === "decay" || retentionAction === "expire" || retentionAction === "quarantine" ? `re_memory supervise # retention_${retentionAction} event=${eventId}` : undefined,
		retentionAction === "keep" ? `re_memory quality # retention_keep event=${eventId}` : undefined,
	], 8);
	return { retentionAction, retentionScore, stalenessDays, decayPenalty, lastUsefulAt, retentionCommands };
}

function buildMaturation(data) {
	const generatedAt = data.now ?? new Date().toISOString();
	const rows = [];
	let prevHash = "0".repeat(64);
	for (const decision of data.activeDecisions ?? []) {
		const maturityScore = Number(Math.max(0, Math.min(100, decision.activeScore * 0.38 + decision.qualityScore * 0.25 + decision.causalScore * 0.22 + decision.confidence * 100 * 0.15)).toFixed(2));
		const action = actionFromDecision(decision, maturityScore);
		const retention = retentionFromDecision(decision, action, maturityScore, generatedAt);
		const base = {
			kind: "repi-memory-maturation-row",
			schemaVersion: 1,
			id: `mmr:${sha256(`${decision.id}:${action}:${maturityScore}`).slice(0, 22)}`,
			ts: generatedAt,
			MemoryMaturationRuntimeV15: true,
			automatic_memory_maturation_pipeline: true,
			tool_result_to_strategy_loop: true,
			closed_loop_writeback: true,
			retention_decay_scheduler: true,
			stale_memory_rehearsal_queue: true,
			usefulness_backprop_to_maturation: true,
			action,
			retentionAction: retention.retentionAction,
			stagePath: unique(["memory-event", "episode", "lesson", (decision.sourceStrategyCapsuleIds ?? []).length ? "strategy-capsule" : undefined, "active-decision", retention.retentionAction !== "keep" ? "retention-decay" : undefined, action === "feedback-required" ? "feedback-closure" : undefined, action === "replay-required" || retention.retentionAction === "rehearse" ? "ab-replay" : undefined], 10),
			route: decision.route,
			targetScope: decision.targetScope,
			sourceEventIds: decision.sourceEventIds ?? [],
			sourceStrategyCapsuleIds: decision.sourceStrategyCapsuleIds ?? [],
			sourceActiveDecisionIds: [decision.id],
			sourceQualityRowIds: decision.sourceQualityRowIds ?? [],
			sourceReplayRowIds: decision.sourceReplayRowIds ?? [],
			maturityScore,
			retentionScore: retention.retentionScore,
			stalenessDays: retention.stalenessDays,
			decayPenalty: retention.decayPenalty,
			lastUsefulAt: retention.lastUsefulAt,
			activeScore: decision.activeScore,
			qualityScore: decision.qualityScore,
			causalScore: decision.causalScore,
			confidence: decision.confidence,
			evidenceRefs: decision.evidenceRefs ?? [],
			commands: decision.commands ?? [],
			verifierCommands: decision.verifierCommands ?? [],
			fallbackCommands: decision.fallbackCommands ?? [],
			avoidCommands: decision.avoidCommands ?? [],
			feedbackCommands: unique([...(decision.feedbackWritebackCommands ?? []), action === "feedback-required" ? `re_memory feedback # maturation_close_feedback ${decision.sourceEventIds?.[0] ?? decision.id}` : undefined], 16),
			retentionCommands: retention.retentionCommands,
			nextCommands: unique([action === "promote" ? "re_memory playbooks" : undefined, action === "replay-required" ? "re_memory replay" : undefined, action === "feedback-required" ? "re_memory feedback" : undefined, ...retention.retentionCommands, "re_memory mature", "re_context pack"], 14),
			blockers: decision.blockers ?? [],
			rationale: [`active_action=${decision.action}`, `maturity_score=${maturityScore}`, `retention_action=${retention.retentionAction}`, `retention_score=${retention.retentionScore}`, "MemoryMaturationRuntimeV15"],
			prevHash,
		};
		const row = { ...base, entryHash: rowHash(base) };
		prevHash = row.entryHash;
		rows.push(row);
	}
	const byAction = (action) => rows.filter((row) => row.action === action);
	return {
		kind: "repi-memory-maturation-runtime-report",
		schemaVersion: 1,
		generatedAt,
		MemoryMaturationRuntimeV15: true,
		automatic_memory_maturation_pipeline: true,
		tool_result_to_strategy_loop: true,
		closed_loop_writeback: true,
		retention_decay_scheduler: true,
		stale_memory_rehearsal_queue: true,
		usefulness_backprop_to_maturation: true,
		promotion_demotion_replay_backed: true,
		cross_session_maturation_ready: true,
		reportPath: "memory/maturation-runtime-report.json",
		ledgerPath: "memory/maturation-runtime-ledger.jsonl",
		actionBoardPath: "memory/maturation-action-board.md",
		sourceActiveKernelReportPath: "memory/active-kernel-report.json",
		rowCount: rows.length,
		promotedEventIds: unique(byAction("promote").flatMap((row) => row.sourceEventIds), 64),
		retainedEventIds: unique(byAction("retain").flatMap((row) => row.sourceEventIds), 64),
		demotedEventIds: unique(byAction("demote").flatMap((row) => row.sourceEventIds), 64),
		quarantinedEventIds: unique(byAction("quarantine").flatMap((row) => row.sourceEventIds), 64),
		pendingFeedbackEventIds: unique(byAction("feedback-required").flatMap((row) => row.sourceEventIds), 64),
		replayRequiredEventIds: unique(byAction("replay-required").flatMap((row) => row.sourceEventIds), 64),
		retentionQueueEventIds: unique(rows.filter((row) => row.retentionAction === "rehearse" || row.retentionAction === "feedback" || row.retentionAction === "decay" || row.retentionAction === "expire").flatMap((row) => row.sourceEventIds), 64),
		expiredEventIds: unique(rows.filter((row) => row.retentionAction === "expire").flatMap((row) => row.sourceEventIds), 64),
		operatorCommands: unique(rows.filter((row) => row.action === "promote" || row.action === "retain").flatMap((row) => row.commands), 32),
		feedbackCommands: unique(rows.flatMap((row) => row.feedbackCommands), 32),
		retentionCommands: unique(rows.flatMap((row) => row.retentionCommands), 32),
		status: rows.length === 0 ? "empty" : byAction("quarantine").length && !byAction("promote").length && !byAction("retain").length ? "blocked" : byAction("feedback-required").length || byAction("replay-required").length || byAction("demote").length || byAction("quarantine").length ? "warn" : "pass",
		rows,
		requiredGates: ["MemoryMaturationRuntimeV15", "automatic_memory_maturation_pipeline", "tool_result_to_strategy_loop", "closed_loop_writeback", "retention_decay_scheduler", "stale_memory_rehearsal_queue", "usefulness_backprop_to_maturation", "promotion_demotion_replay_backed", "cross_session_maturation_ready"],
		nextCommands: ["re_memory mature", "re_memory feedback", "re_memory replay", "re_memory retention", "re_context pack"],
	};
}

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function checkExpected(report, expected) {
	const errors = [];
	const byEvent = new Map(report.rows.flatMap((row) => row.sourceEventIds.map((eventId) => [eventId, row])));
	for (const id of expected.mustPromoteEventIds ?? []) if (byEvent.get(id)?.action !== "promote") errors.push(`event ${id} not promote action=${byEvent.get(id)?.action}`);
	for (const id of expected.mustFeedbackEventIds ?? []) if (byEvent.get(id)?.action !== "feedback-required") errors.push(`event ${id} not feedback-required action=${byEvent.get(id)?.action}`);
	for (const id of expected.mustReplayRequiredEventIds ?? []) if (byEvent.get(id)?.action !== "replay-required") errors.push(`event ${id} not replay-required action=${byEvent.get(id)?.action}`);
	for (const id of expected.mustDemoteEventIds ?? []) if (byEvent.get(id)?.action !== "demote") errors.push(`event ${id} not demote action=${byEvent.get(id)?.action}`);
	for (const id of expected.mustRehearseEventIds ?? []) if (byEvent.get(id)?.retentionAction !== "rehearse") errors.push(`event ${id} not retention rehearse action=${byEvent.get(id)?.retentionAction}`);
	for (const id of expected.mustRetentionQueueEventIds ?? []) if (!report.retentionQueueEventIds.includes(id)) errors.push(`event ${id} missing retention queue`);
	for (const gate of expected.mustHaveRequiredGates ?? []) if (!report.requiredGates.includes(gate)) errors.push(`missing gate ${gate}`);
	for (const artifact of expected.mustHaveArtifacts ?? []) if (![report.reportPath, report.ledgerPath, report.actionBoardPath].some((path) => path.includes(artifact))) errors.push(`missing artifact ${artifact}`);
	if (!report.rows.every((row, index) => row.entryHash === rowHash(row) && (index === 0 ? row.prevHash === "0".repeat(64) : row.prevHash === report.rows[index - 1].entryHash))) errors.push("maturation hash chain mismatch");
	return errors;
}

function mutateFixture(fixture, negative) {
	const clone = JSON.parse(JSON.stringify(fixture));
	const decision = clone.activeDecisions.find((row) => row.id === negative.decisionId);
	if (decision && negative.mutate === "dropEvidence") decision.evidenceRefs = [];
	if (decision && negative.mutate === "scopeBlock") decision.blockers = [...(decision.blockers ?? []), "scope_blocked"];
	return clone;
}

function checkNegative(fixture, negative) {
	const report = buildMaturation(mutateFixture(fixture, negative));
	const decision = report.rows.find((row) => row.sourceActiveDecisionIds.includes(negative.decisionId));
	const errors = [];
	if (negative.expectAction && decision?.action !== negative.expectAction) errors.push(`expected ${negative.expectAction} got ${decision?.action}`);
	if (negative.expectNotAction && decision?.action === negative.expectNotAction) errors.push(`unexpected action ${negative.expectNotAction}`);
	return { id: `negative:${negative.id}`, status: errors.length ? "fail" : "pass", evidence: { errors, decision } };
}

function writeProbe(probePath, outPath, tempRoot) {
	const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
	writeFileSync(probePath, `
import { mkdirSync, writeFileSync } from "node:fs";
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
process.env.REPI_SESSION_ID = "memory-maturation-runtime-live";
process.env.REPI_BRANCH_ID = "memory-maturation-runtime-branch";
const tools = new Map();
const fakePi = { registerCommand() {}, registerTool(tool) { tools.set(tool.name, tool); }, on() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {}, exec: async () => ({ code: 0, stdout: "ok", stderr: "", killed: false }) };
createReconExtensionFactory()(fakePi);
const memory = tools.get("re_memory");
if (!memory) throw new Error("missing re_memory tool");
async function main() {
  await memory.execute("learn", { action: "learn", text: "outcome=success replayVerified=true playbookCandidate=true artifactPath=.repi-harness/evidence/mature/proof.txt re_lane run authz-bola https://app.local", route: "web/authz", target: "https://app.local" });
  const result = await memory.execute("mature", { action: "mature", query: "authz", route: "web/authz", target: "https://app.local" });
  writeFileSync(outPath, JSON.stringify(result.details, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}

function runProbe(tempRoot) {
	const probePath = join(tempRoot, "memory-maturation-runtime-probe.ts");
	const outPath = join(tempRoot, "probe-result.json");
	writeProbe(probePath, outPath, tempRoot);
	const tsx = join(root, "node_modules", ".bin", "tsx");
	const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], { cwd: root, env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1", REPI_REPO_ROOT: root }, encoding: "utf8", maxBuffer: 30 * 1024 * 1024 });
	return { ...result, outPath, probePath };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "memory-maturation-runtime", stamp);
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
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-memory-maturation-runtime-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH } });
	} catch (error) {
		checks.push({ id: "fixture:parse", status: "fail", evidence: { path: FIXTURE_PATH, error: String(error) } });
	}
	if (fixture) {
		const report = buildMaturation(fixture);
		const expectedErrors = checkExpected(report, fixture.expected ?? {});
		checks.push({ id: "fixture:maturation-policy", status: expectedErrors.length ? "fail" : "pass", evidence: { errors: expectedErrors, rows: report.rows.map((row) => ({ id: row.id, action: row.action, events: row.sourceEventIds, maturityScore: row.maturityScore })) } });
		for (const negative of fixture.negativeCases ?? []) checks.push(checkNegative(fixture, negative));
	}
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-maturation-"));
	try {
		const probe = runProbe(tempRoot);
		checks.push({ id: "runtime:re-memory-mature-exit", status: probe.status === 0 ? "pass" : "fail", evidence: { code: probe.status, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) } });
		if (probe.status === 0 && existsSync(probe.outPath)) {
			const report = JSON.parse(readFileSync(probe.outPath, "utf8"));
			checks.push({ id: "runtime:maturation-report", status: report.MemoryMaturationRuntimeV15 === true && report.retention_decay_scheduler === true && report.stale_memory_rehearsal_queue === true && report.usefulness_backprop_to_maturation === true && report.rowCount > 0 && report.rows?.every((row, index) => row.retentionAction && Array.isArray(row.retentionCommands) && row.entryHash === rowHash(row) && (index === 0 ? row.prevHash === "0".repeat(64) : row.prevHash === report.rows[index - 1].entryHash)) ? "pass" : "fail", evidence: { status: report.status, rows: report.rowCount, reportPath: report.reportPath, ledgerPath: report.ledgerPath } });
		} else checks.push({ id: "runtime:maturation-report", status: "fail", evidence: { error: "probe output missing" } });
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	checks.push(
		markerCheck("code:memory-maturation-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryMaturationRuntimeV15", "buildMemoryMaturationRuntimeReport", "formatMemoryMaturationRuntime", "memoryMaturationRuntimeReportPath", "automatic_memory_maturation_pipeline", "retention_decay_scheduler", "tool_result_to_strategy_loop", "closed_loop_writeback", "retention_decay_scheduler", "stale_memory_rehearsal_queue", "usefulness_backprop_to_maturation"]),
		markerCheck("profile:memory-maturation-runtime", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryMaturationRuntimeV15", "buildMemoryMaturationRuntimeReport", "formatMemoryMaturationRuntime", "memoryMaturationRuntimeReportPath", "automatic_memory_maturation_pipeline", "retention_decay_scheduler"]),
		markerCheck("schema:memory-maturation-runtime", "schemas/reverse-agent/memory-maturation-runtime.schema.json", ["MemoryMaturationRuntimeV15", "repi-memory-maturation-runtime-report", "automatic_memory_maturation_pipeline", "tool_result_to_strategy_loop", "closed_loop_writeback", "retention_decay_scheduler", "stale_memory_rehearsal_queue"]),
		markerCheck("fixture:memory-maturation-runtime", "fixtures/reverse-agent/memory-maturation-runtime.fixture.json", ["repi-memory-maturation-runtime-fixture", "mustPromoteEventIds", "mustReplayRequiredEventIds", "mustRehearseEventIds", "maturation-runtime-ledger.jsonl"]),
		markerCheck("docs:memory-maturation-readme", "README.md", ["MemoryMaturationRuntimeV15", "re_memory mature", "maturation-runtime-report.json", "retention_decay_scheduler"]),
		markerCheck("docs:memory-maturation-recon", "packages/coding-agent/docs/recon.md", ["MemoryMaturationRuntimeV15", "maturation-runtime-ledger.jsonl", "gate:memory-maturation-runtime", "stale_memory_rehearsal_queue"]),
		markerCheck("docs:memory-maturation-reverse", "docs/reverse-agent/README.md", ["MemoryMaturationRuntimeV15", "maturation-action-board.md", "gate:memory-maturation-runtime", "usefulness_backprop_to_maturation"]),
		markerCheck("npm:memory-maturation-script", "package.json", ["gate:memory-maturation-runtime", "memory-maturation-runtime-gate.mjs"]),
		markerCheck("harness:memory-maturation-child", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:memory-maturation-runtime", "memory:maturation-runtime"]),
		markerCheck("autonomy:memory-maturation-runtime", "scripts/reverse-agent/autonomy-control-plane.mjs", ["MemoryMaturationRuntimeV15", "memory_maturation_runtime_v15", "automatic_memory_maturation_pipeline", "retention_decay_scheduler"])
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-memory-maturation-runtime-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Maturation Runtime Gate");
		console.log(`ok: ${result.ok}`);
		for (const check of checks) console.log(`- ${check.status === "pass" ? "PASS" : "FAIL"} ${check.id}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
		if (failed.length) console.log(JSON.stringify(failed, null, 2));
	}
	if (strict && failed.length) process.exit(1);
}

main();

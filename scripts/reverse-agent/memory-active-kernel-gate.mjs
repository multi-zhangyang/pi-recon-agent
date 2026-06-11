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
const FIXTURE_PATH = "fixtures/reverse-agent/memory-active-kernel.fixture.json";
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

function decisionHash(decision) {
	const { entryHash, ...withoutHash } = decision;
	return sha256(JSON.stringify(withoutHash));
}

function decisionFrom(input) {
	const decision = {
		kind: "repi-memory-active-kernel-decision",
		schemaVersion: 1,
		MemoryActiveKernelV14: true,
		unified_memory_decision_engine: true,
		active_recall_scheduler: true,
		scope_safe_strategy_injection: true,
		...input,
		entryHash: ""
	};
	decision.entryHash = decisionHash(decision);
	return decision;
}

function buildActiveKernel(data) {
	const generatedAt = data.now ?? new Date().toISOString();
	const qualityByEvent = new Map((data.qualityRows ?? []).map((row) => [row.eventId, row]));
	const eventById = new Map((data.events ?? []).map((event) => [event.id, event]));
	const decisions = [];
	for (const capsule of data.strategyCapsules ?? []) {
		const qualityRows = (capsule.sourceQualityEventIds ?? []).flatMap((eventId) => qualityByEvent.get(eventId) ? [qualityByEvent.get(eventId)] : []);
		const avgQuality = qualityRows.length ? qualityRows.reduce((sum, row) => sum + row.qualityScore, 0) / qualityRows.length : capsule.qualityScore;
		const activeScore = Math.max(0, Math.min(100, capsule.causalScore * 0.42 + avgQuality * 0.34 + capsule.confidence * 100 * 0.16 + (capsule.recommendedCommands?.length ? 8 : 0) + (capsule.lifecycle === "promoted" ? 6 : capsule.lifecycle === "demoted" ? -22 : capsule.lifecycle === "quarantined" ? -40 : 0)));
		const action = capsule.lifecycle === "quarantined" ? "quarantine" : capsule.lifecycle === "demoted" ? "avoid" : activeScore >= 74 && capsule.recommendedCommands?.length ? "inject" : activeScore >= 62 && capsule.recommendedCommands?.length ? "reuse" : "verify";
		decisions.push(decisionFrom({
			id: `mak:strategy:${sha256(`${capsule.id}:${action}:${activeScore.toFixed(2)}`).slice(0, 22)}`,
			ts: generatedAt,
			action,
			route: capsule.route,
			targetScope: capsule.targetScope,
			source: "strategy",
			sourceEventIds: capsule.sourceQualityEventIds ?? [],
			sourceStrategyCapsuleIds: [capsule.id],
			sourceQualityRowIds: qualityRows.map((row) => row.id),
			sourceReplayRowIds: capsule.sourceReplayRowIds ?? [],
			activeScore: Number(activeScore.toFixed(2)),
			causalScore: capsule.causalScore,
			qualityScore: Number(avgQuality.toFixed(2)),
			confidence: capsule.confidence,
			commands: capsule.recommendedCommands ?? [],
			verifierCommands: capsule.verifierCommands ?? [],
			fallbackCommands: capsule.fallbackCommands ?? [],
			avoidCommands: capsule.avoidCommands ?? [],
			evidenceRefs: capsule.evidenceRefs ?? [],
			triggerConditions: capsule.triggerConditions ?? [],
			applicabilityBoundary: capsule.applicabilityBoundary ?? [],
			rationale: [`strategy_lifecycle=${capsule.lifecycle}`, `active_score=${activeScore.toFixed(2)}`],
			preflightChecks: ["re_memory scope", "re_memory replay", "re_memory active"],
			feedbackWritebackCommands: (capsule.sourceQualityEventIds ?? []).map((eventId) => `re_memory append # active_kernel_feedback event=${eventId} decision=${action}`),
			compactResumeHints: capsule.compactResumeHints ?? ["include active-kernel-report in context pack"],
			blockers: action === "quarantine" ? ["strategy_capsule_quarantined"] : action === "avoid" ? ["strategy_capsule_demoted"] : []
		}));
	}
	for (const row of data.qualityRows ?? []) {
		if (!["demote", "quarantine", "expire"].includes(row.lifecycleDecision) && row.pendingFeedbackCount === 0 && !row.scopeBlocked) continue;
		if (decisions.some((decision) => decision.sourceEventIds.includes(row.eventId))) continue;
		const event = eventById.get(row.eventId);
		const action = row.scopeBlocked ? "quarantine" : row.pendingFeedbackCount > 0 ? "wait-feedback" : row.lifecycleDecision === "quarantine" ? "quarantine" : row.lifecycleDecision === "expire" ? "expire" : "avoid";
		decisions.push(decisionFrom({
			id: `mak:quality:${sha256(`${row.eventId}:${action}:${row.qualityScore}`).slice(0, 22)}`,
			ts: generatedAt,
			action,
			route: row.route,
			targetScope: row.targetScope,
			source: row.pendingFeedbackCount > 0 ? "feedback" : "quality",
			sourceEventIds: [row.eventId],
			sourceStrategyCapsuleIds: [],
			sourceQualityRowIds: [row.id],
			sourceReplayRowIds: [],
			activeScore: row.qualityScore,
			causalScore: 0,
			qualityScore: row.qualityScore,
			confidence: row.baseConfidence,
			commands: action === "wait-feedback" ? row.nextCommands ?? [] : [],
			verifierCommands: action === "wait-feedback" ? ["re_memory feedback", "re_verifier matrix"] : [],
			fallbackCommands: ["re_memory quality", "re_memory supervise"],
			avoidCommands: ["avoid", "quarantine", "expire"].includes(action) ? event?.commands ?? [] : [],
			evidenceRefs: row.evidenceRefs ?? [],
			triggerConditions: [`quality_decision=${row.lifecycleDecision}`],
			applicabilityBoundary: ["do not inject until active kernel state changes"],
			rationale: [`quality_score=${row.qualityScore}`, `signals=${(row.signals ?? []).join(",")}`],
			preflightChecks: ["re_memory feedback", "re_memory quality"],
			feedbackWritebackCommands: [`re_memory append # close_active_kernel_feedback event=${row.eventId}`],
			compactResumeHints: ["carry active kernel decision across compact resume"],
			blockers: row.scopeBlocked ? ["scope_blocked"] : []
		}));
	}
	const sorted = decisions.sort((a, b) => b.activeScore - a.activeScore || a.id.localeCompare(b.id));
	const active = sorted.filter((decision) => ["inject", "reuse", "verify", "repair"].includes(decision.action));
	const byAction = (action) => sorted.filter((decision) => decision.action === action);
	const pack = {
		kind: "repi-memory-active-injection-pack",
		schemaVersion: 1,
		generatedAt,
		MemoryActiveKernelV14: true,
		active_recall_scheduler: true,
		budget: { maxDecisions: 12, maxCommands: 32, maxTokens: 4200 },
		decisions: active,
		commands: unique(active.filter((decision) => decision.action === "inject" || decision.action === "reuse").flatMap((decision) => decision.commands), 32),
		verifierRules: unique(active.flatMap((decision) => decision.verifierCommands), 24),
		fallbackCommands: unique(active.flatMap((decision) => decision.fallbackCommands), 16),
		avoidCommands: unique(sorted.flatMap((decision) => decision.avoidCommands), 24),
		scopeLocks: unique(active.map((decision) => `${decision.route}:${decision.targetScope}`), 24),
		feedbackWriteback: "append active_kernel_feedback after every injected/reused decision",
		compactResumeHints: unique(active.flatMap((decision) => decision.compactResumeHints), 16),
		requiredGates: ["MemoryActiveKernelV14", "unified_memory_decision_engine", "active_recall_scheduler", "quality_replay_strategy_fusion", "scope_safe_strategy_injection", "feedback_driven_promotion", "cross_session_compact_ready"]
	};
	return {
		kind: "repi-memory-active-kernel-report",
		schemaVersion: 1,
		generatedAt,
		MemoryActiveKernelV14: true,
		unified_memory_decision_engine: true,
		active_recall_scheduler: true,
		cross_session_compact_ready: true,
		feedback_driven_promotion: true,
		scope_safe_strategy_injection: true,
		reportPath: "memory/active-kernel-report.json",
		injectionPackPath: "memory/active-injection-pack.json",
		strategyBoardPath: "memory/active-strategy-board.md",
		decisionCount: sorted.length,
		injectDecisionIds: byAction("inject").map((decision) => decision.id),
		reuseDecisionIds: byAction("reuse").map((decision) => decision.id),
		verifyDecisionIds: byAction("verify").map((decision) => decision.id),
		repairDecisionIds: byAction("repair").map((decision) => decision.id),
		avoidDecisionIds: byAction("avoid").map((decision) => decision.id),
		quarantineDecisionIds: byAction("quarantine").map((decision) => decision.id),
		pendingFeedbackDecisionIds: byAction("wait-feedback").map((decision) => decision.id),
		expiredDecisionIds: byAction("expire").map((decision) => decision.id),
		operatorInjectionCommands: pack.commands,
		verifierCommands: pack.verifierRules,
		fallbackCommands: pack.fallbackCommands,
		avoidCommands: pack.avoidCommands,
		status: sorted.length === 0 ? "empty" : active.length === 0 && (byAction("avoid").length || byAction("quarantine").length) ? "blocked" : byAction("verify").length || byAction("wait-feedback").length || byAction("avoid").length || byAction("quarantine").length ? "warn" : "pass",
		decisions: sorted,
		activeInjectionPack: pack,
		requiredGates: pack.requiredGates,
		policy: { MemoryActiveKernelV14: true, unifiedMemoryDecisionEngine: true, activeRecallScheduler: true, qualityReplayStrategyFusion: true, scopeSafeStrategyInjection: true, feedbackDrivenPromotion: true, crossSessionCompactReady: true },
		nextCommands: ["re_memory active", "re_operator plan", "re_verifier matrix", "re_context pack"]
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
	const byStrategy = new Map(report.decisions.flatMap((decision) => decision.sourceStrategyCapsuleIds.map((id) => [id, decision])));
	const byEvent = new Map(report.decisions.flatMap((decision) => decision.sourceEventIds.map((id) => [id, decision])));
	for (const id of expected.mustInjectStrategyIds ?? []) if (byStrategy.get(id)?.action !== "inject") errors.push(`strategy ${id} not inject action=${byStrategy.get(id)?.action}`);
	for (const id of expected.mustReuseStrategyIds ?? []) if (byStrategy.get(id)?.action !== "reuse") errors.push(`strategy ${id} not reuse action=${byStrategy.get(id)?.action}`);
	for (const id of expected.mustAvoidEventIds ?? []) if (byEvent.get(id)?.action !== "avoid") errors.push(`event ${id} not avoid action=${byEvent.get(id)?.action}`);
	for (const id of expected.mustWaitFeedbackEventIds ?? []) if (byEvent.get(id)?.action !== "wait-feedback") errors.push(`event ${id} not wait-feedback action=${byEvent.get(id)?.action}`);
	for (const gate of expected.mustHaveRequiredGates ?? []) if (!report.requiredGates.includes(gate)) errors.push(`missing gate ${gate}`);
	for (const artifact of expected.mustHaveArtifacts ?? []) if (![report.reportPath, report.injectionPackPath, report.strategyBoardPath].some((path) => path.includes(artifact))) errors.push(`missing artifact ${artifact}`);
	if (!report.activeInjectionPack?.commands?.length) errors.push("active injection pack has no commands");
	if (!report.decisions.every((decision) => decision.entryHash === decisionHash(decision))) errors.push("decision hash mismatch");
	return errors;
}

function applyMutation(fixture, negative) {
	const data = JSON.parse(JSON.stringify(fixture));
	if (negative.mutate === "removeCommands") {
		const strategy = data.strategyCapsules.find((row) => row.id === negative.strategyId);
		if (strategy) strategy.recommendedCommands = [];
	}
	if (negative.mutate === "quarantineStrategy") {
		const strategy = data.strategyCapsules.find((row) => row.id === negative.strategyId);
		if (strategy) strategy.lifecycle = "quarantined";
	}
	if (negative.mutate === "scopeBlock") {
		const row = data.qualityRows.find((item) => item.eventId === negative.eventId);
		if (row) row.scopeBlocked = true;
	}
	return data;
}

function checkNegative(fixture, negative) {
	const report = buildActiveKernel(applyMutation(fixture, negative));
	const decision = negative.strategyId
		? report.decisions.find((row) => row.sourceStrategyCapsuleIds.includes(negative.strategyId))
		: report.decisions.find((row) => row.sourceEventIds.includes(negative.eventId));
	const errors = [];
	if (negative.expectAction && decision?.action !== negative.expectAction) errors.push(`expected ${negative.expectAction} got ${decision?.action}`);
	if (negative.expectNotAction && decision?.action === negative.expectNotAction) errors.push(`unexpected action ${negative.expectNotAction}`);
	return { id: `negative:${negative.id}`, status: errors.length ? "fail" : "pass", evidence: { errors, decision } };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "memory-active-kernel", stamp);
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
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-memory-active-kernel-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH } });
	} catch (error) {
		checks.push({ id: "fixture:parse", status: "fail", evidence: { path: FIXTURE_PATH, error: String(error) } });
	}
	if (fixture) {
		const report = buildActiveKernel(fixture);
		const expectedErrors = checkExpected(report, fixture.expected ?? {});
		checks.push({ id: "fixture:active-kernel-policy", status: expectedErrors.length ? "fail" : "pass", evidence: { errors: expectedErrors, decisions: report.decisions.map((decision) => ({ id: decision.id, action: decision.action, sourceEvents: decision.sourceEventIds, sourceStrategies: decision.sourceStrategyCapsuleIds, activeScore: decision.activeScore })) } });
		for (const negative of fixture.negativeCases ?? []) checks.push(checkNegative(fixture, negative));
	}
	checks.push(
		markerCheck("code:memory-active-kernel-runtime", "packages/coding-agent/src/core/recon-profile.ts", ["MemoryActiveKernelV14", "buildMemoryActiveKernelReport", "formatMemoryActiveKernel", "memoryActiveKernelReportPath", "unified_memory_decision_engine", "active_recall_scheduler", "active_kernel_feedback"]),
		markerCheck("profile:memory-active-kernel-runtime", "repi-profile/extensions/reverse-pentest-core.ts", ["MemoryActiveKernelV14", "buildMemoryActiveKernelReport", "formatMemoryActiveKernel", "memoryActiveKernelReportPath", "active_recall_scheduler"]),
		markerCheck("schema:memory-active-kernel", "schemas/reverse-agent/memory-active-kernel.schema.json", ["MemoryActiveKernelV14", "repi-memory-active-kernel-report", "repi-memory-active-injection-pack", "unified_memory_decision_engine"]),
		markerCheck("fixture:memory-active-kernel", "fixtures/reverse-agent/memory-active-kernel.fixture.json", ["repi-memory-active-kernel-fixture", "mustInjectStrategyIds", "mustAvoidEventIds", "cross_session_compact_ready"]),
		markerCheck("docs:memory-active-kernel-readme", "README.md", ["MemoryActiveKernelV14", "re_memory active", "active-kernel-report.json"]),
		markerCheck("docs:memory-active-kernel-recon", "packages/coding-agent/docs/recon.md", ["MemoryActiveKernelV14", "active-injection-pack.json", "gate:memory-active-kernel"]),
		markerCheck("docs:memory-active-kernel-reverse", "docs/reverse-agent/README.md", ["MemoryActiveKernelV14", "active-strategy-board.md", "gate:memory-active-kernel"]),
		markerCheck("npm:memory-active-kernel-script", "package.json", ["gate:memory-active-kernel", "memory-active-kernel-gate.mjs"]),
		markerCheck("harness:memory-active-kernel-child", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:memory-active-kernel", "memory:active-kernel"]),
		markerCheck("autonomy:memory-active-kernel", "scripts/reverse-agent/autonomy-control-plane.mjs", ["MemoryActiveKernelV14", "memory_active_kernel_v14", "active_recall_scheduler"])
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-memory-active-kernel-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Active Kernel Gate");
		console.log(`ok: ${result.ok}`);
		for (const check of checks) console.log(`- ${check.status === "pass" ? "PASS" : "FAIL"} ${check.id}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
		if (failed.length) console.log(JSON.stringify(failed, null, 2));
	}
	if (strict && failed.length) process.exit(1);
}

main();

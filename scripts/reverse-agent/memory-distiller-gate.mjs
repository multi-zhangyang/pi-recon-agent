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

const FIXTURE_PATH = "fixtures/reverse-agent/memory-distiller.fixture.json";
const HEX64 = /^[a-f0-9]{64}$/;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function eventHash(event) {
	const { entryHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function unique(values, limit = 80) {
	const seen = new Set();
	const out = [];
	for (const value of values) {
		const text = String(value ?? "").trim();
		if (!text || text === "none") continue;
		const key = text.toLowerCase();
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(text);
		if (out.length >= limit) break;
	}
	return out;
}

function validateHashChain(events) {
	const errors = [];
	let prevHash = "0".repeat(64);
	const ids = new Set();
	for (const [index, event] of (events ?? []).entries()) {
		if (event.kind !== "repi-memory-event") errors.push(`events[${index}].kind`);
		if (event.seq !== index + 1) errors.push(`events[${index}].seq`);
		if (ids.has(event.id)) errors.push(`events[${index}].duplicate_id`);
		ids.add(event.id);
		if (event.prevHash !== prevHash) errors.push(`events[${index}].prevHash`);
		if (!HEX64.test(event.entryHash ?? "") || event.entryHash !== eventHash(event)) errors.push(`events[${index}].entryHash`);
		prevHash = event.entryHash;
	}
	return errors;
}

function groupByCase(events) {
	const groups = new Map();
	for (const event of events ?? []) {
		const key = event.caseSignature;
		if (!groups.has(key)) groups.set(key, []);
		groups.get(key).push(event);
	}
	return groups;
}

function normalizeCommand(command, target) {
	let text = String(command ?? "").trim();
	if (!text) return undefined;
	if (target) text = text.split(target).join("<target>");
	text = text.replace(/https?:\/\/[^\s'"`]+/gi, "<target>");
	return /Bearer\s+real-|secret|password=/i.test(text) ? undefined : text;
}

function routeSet(events) {
	return new Set(events.map((event) => String(event.route ?? "").trim().toLowerCase()).filter(Boolean));
}

function latestTs(events) {
	return events.map((event) => Date.parse(event.ts)).filter(Number.isFinite).sort((a, b) => b - a)[0] ?? 0;
}

function targetHosts(events) {
	return new Set(
		events
			.map((event) => {
				try {
					return new URL(event.target).host.toLowerCase();
				} catch {
					return String(event.target ?? "").toLowerCase();
				}
			})
			.filter(Boolean),
	);
}

function contaminationForCase(caseSignature, events, now) {
	const routes = routeSet(events);
	const hosts = targetHosts(events);
	const failures = events.filter((event) => event.outcome === "failure" || event.outcome === "blocked");
	const successes = events.filter((event) => event.outcome === "success");
	const highConfidenceFailures = failures.filter((event) => Number(event.quality?.confidence ?? 0) >= 0.78);
	const ageDays = Math.floor((Date.parse(now) - latestTs(events)) / 86_400_000);
	const reasons = [];
	if (routes.size > 1) reasons.push(`cross_route_contamination:${[...routes].join(",")}`);
	if (hosts.size > 2) reasons.push(`cross_target_contamination:${[...hosts].join(",")}`);
	if (successes.length > 0 && highConfidenceFailures.length > 0) reasons.push("contradicted_success_failure_high_confidence");
	if (ageDays > 180 && successes.length === 0) reasons.push(`stale_negative_memory:${ageDays}d`);
	const failurePressure = failures.length + events.reduce((sum, event) => sum + Number(event.quality?.failureCount ?? 0), 0);
	if (failurePressure >= Math.max(2, successes.length + 2)) reasons.push(`failure_pressure:${failurePressure}`);
	return reasons.length
		? { caseSignature, status: "quarantine", reasons, eventIds: events.map((event) => event.id), routes: [...routes], hosts: [...hosts] }
		: { caseSignature, status: "clean", reasons: [], eventIds: events.map((event) => event.id), routes: [...routes], hosts: [...hosts] };
}

function patternId(caseSignature, type) {
	return `pattern:${caseSignature}:${type}`;
}

function distill(events, options = {}) {
	const now = options.now ?? new Date().toISOString();
	const quarantine = [];
	const patterns = [];
	for (const [caseSignature, rows] of groupByCase(events)) {
		const finding = contaminationForCase(caseSignature, rows, now);
		if (finding.status === "quarantine") quarantine.push(finding);
		const clean = finding.status === "clean";
		const successes = rows.filter((event) => event.outcome === "success");
		const failures = rows.filter((event) => event.outcome === "failure" || event.outcome === "blocked");
		const best = [...successes].sort((a, b) => Number(b.quality?.confidence ?? 0) - Number(a.quality?.confidence ?? 0))[0];
		const confidence = Math.max(...rows.map((event) => Number(event.quality?.confidence ?? 0)), 0);
		const commands = unique(successes.flatMap((event) => (event.commands ?? []).map((command) => normalizeCommand(command, event.target))).filter(Boolean), 12);
		if (best && commands.length && clean && confidence >= 0.72) {
			patterns.push({
				kind: "repi-memory-distilled-pattern",
				schemaVersion: 1,
				id: patternId(caseSignature, "command_template"),
				caseSignature,
				route: best.route,
				patternType: "command_template",
				lifecycle: best.quality?.replayVerified ? "promoted" : "candidate",
				confidence: Number(confidence.toFixed(2)),
				sourceEventIds: rows.map((event) => event.id),
				sourceHashes: rows.map((event) => event.entryHash),
				commands,
				reuseRules: unique(rows.flatMap((event) => event.reuseRules ?? []), 10),
				failurePatterns: unique(rows.flatMap((event) => event.failurePatterns ?? []), 10),
				evidenceRefs: unique(rows.flatMap((event) => (event.artifactHashes ?? []).map((artifact) => artifact.path)), 20),
				summary: unique([best.lessons?.[0], best.reuseRules?.[0], best.task], 3).join(" | "),
			});
		}
		if (clean && successes.some((event) => event.quality?.replayVerified || event.promotion?.verifierRuleCandidate)) {
			patterns.push({
				kind: "repi-memory-distilled-pattern",
				schemaVersion: 1,
				id: patternId(caseSignature, "verifier_rule"),
				caseSignature,
				route: best?.route ?? rows[0]?.route,
				patternType: "verifier_rule",
				lifecycle: "candidate",
				confidence: Number(Math.min(0.93, confidence).toFixed(2)),
				sourceEventIds: rows.map((event) => event.id),
				sourceHashes: rows.map((event) => event.entryHash),
				commands: unique(["re_verifier matrix", "re_replayer run", ...commands], 8),
				reuseRules: unique(["Require replay/verifier evidence before promoting this claim.", ...rows.flatMap((event) => event.reuseRules ?? [])], 10),
				failurePatterns: unique(failures.flatMap((event) => event.failurePatterns ?? []), 10),
				evidenceRefs: unique(rows.flatMap((event) => (event.artifactHashes ?? []).map((artifact) => artifact.path)), 20),
				summary: `Verifier rule distilled from ${successes.length} successful event(s) for ${caseSignature}.`,
			});
		}
	}
	const injectionPlan = {
		mandatory_memory_injection_chain: ["retrieve", "rank", "inject", "execute", "verify", "feedback"],
		retrievalReport: "memory/retrieval-report.json",
		distillationReport: "memory/distillation-report.json",
		patternBook: "memory/pattern-book.md",
		quarantine: "memory/quarantine.json",
		promotedPatternIds: patterns.filter((pattern) => pattern.lifecycle === "promoted").map((pattern) => pattern.id),
	};
	return { kind: "repi-memory-distillation-report", schemaVersion: 1, generatedAt: now, hashChainOk: validateHashChain(events).length === 0, patterns, quarantine, injectionPlan };
}

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function checkExpected(report, expected = {}) {
	const errors = [];
	const patternIds = new Set(report.patterns.map((pattern) => pattern.id));
	const promotedIds = new Set(report.patterns.filter((pattern) => pattern.lifecycle === "promoted").map((pattern) => pattern.id));
	const quarantineCases = new Set(report.quarantine.map((finding) => finding.caseSignature));
	const commands = new Set(report.patterns.flatMap((pattern) => pattern.commands ?? []));
	for (const id of expected.mustPromotePatternIds ?? []) if (!promotedIds.has(id)) errors.push(`missing promoted pattern ${id}`);
	for (const id of expected.mustHavePatternIds ?? []) if (!patternIds.has(id)) errors.push(`missing pattern ${id}`);
	for (const id of expected.mustNotHavePatternIds ?? []) if (patternIds.has(id)) errors.push(`unexpected pattern ${id}`);
	for (const item of expected.mustQuarantineCaseSignatures ?? []) if (!quarantineCases.has(item)) errors.push(`missing quarantine ${item}`);
	for (const command of expected.mustHaveCommandTemplates ?? []) if (!commands.has(command)) errors.push(`missing command template ${command}`);
	for (const command of expected.mustNotHaveCommandTemplates ?? []) if (commands.has(command)) errors.push(`unexpected command template ${command}`);
	const chain = report.injectionPlan?.mandatory_memory_injection_chain ?? [];
	for (const stage of expected.mustHaveInjectionStages ?? []) if (!chain.includes(stage)) errors.push(`missing injection stage ${stage}`);
	return errors;
}

function negativeCase(fixture, negative) {
	const events = JSON.parse(JSON.stringify(fixture.events ?? []));
	if (negative.mutate === "hashDrift" && events[0]) events[0].entryHash = "f".repeat(64);
	if (negative.mutate === "crossRoute" && events[0]) {
		const clone = { ...events[0], id: "mem:negative-cross-route", seq: events.length + 1, route: "pwn", target: "./vuln", prevHash: events.at(-1)?.entryHash ?? "0".repeat(64), entryHash: "" };
		clone.entryHash = eventHash(clone);
		events.push(clone);
	}
	if (negative.mutate === "lowConfidence" && events[0]) events[0].quality.confidence = 0.2;
	const hashErrors = validateHashChain(events);
	if (negative.expect === "hash_chain_blocked") return { id: `negative-${negative.id}`, status: hashErrors.length ? "pass" : "fail", evidence: { hashErrors } };
	const report = distill(events, { now: fixture.now });
	const errors = checkExpected(report, negative.expected ?? {});
	return { id: `negative-${negative.id}`, status: errors.length ? "fail" : "pass", evidence: { errors, quarantine: report.quarantine, patterns: report.patterns.map((pattern) => ({ id: pattern.id, lifecycle: pattern.lifecycle })) } };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "memory-distiller", stamp);
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
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-memory-distiller-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH } });
	} catch (error) {
		checks.push({ id: "fixture:parse", status: "fail", evidence: { path: FIXTURE_PATH, error: String(error) } });
	}
	if (fixture) {
		const hashErrors = validateHashChain(fixture.events ?? []);
		checks.push({ id: "fixture:hash-chain", status: hashErrors.length ? "fail" : "pass", evidence: { errors: hashErrors, events: fixture.events?.length ?? 0 } });
		const report = distill(fixture.events ?? [], { now: fixture.now });
		const expectedErrors = checkExpected(report, fixture.expected ?? {});
		checks.push({ id: "scenario:distill-promote-quarantine", status: expectedErrors.length ? "fail" : "pass", evidence: { errors: expectedErrors, patterns: report.patterns, quarantine: report.quarantine, injectionPlan: report.injectionPlan } });
		for (const negative of fixture.negativeCases ?? []) checks.push(negativeCase(fixture, negative));
	}
	checks.push(
		markerCheck("code:memory-v3-distiller", "packages/coding-agent/src/core/recon-profile.ts", ["type MemoryDistilledPatternV1", "function distillMemoryPatterns", "memoryDistillationReportPath", "memory_pattern_book", "mandatory_memory_injection_chain"]),
		markerCheck("code:memory-contamination-quarantine", "packages/coding-agent/src/core/recon-profile.ts", ["memory_contamination_quarantine", "function detectMemoryContamination", "memoryQuarantinePath", "quarantinedReason"]),
		markerCheck("docs:memory-v3", "README.md", ["Memory v3", "gate:memory-distiller", "distillation-report.json", "quarantine.json"]),
		markerCheck("npm:memory-distiller-script", "package.json", ["gate:memory-distiller", "memory-distiller-gate.mjs"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-memory-distiller-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Distiller Gate");
		console.log(`ok: ${result.ok}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
		for (const check of checks) console.log(`- ${check.id}: ${check.status}`);
		if (failed.length) console.log(`failed: ${failed.map((check) => check.id).join(", ")}`);
	}
	if (strict && failed.length) process.exitCode = 1;
}

main();

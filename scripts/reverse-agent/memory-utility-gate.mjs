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

const FIXTURE_PATH = "fixtures/reverse-agent/memory-utility.fixture.json";
const HEX64 = /^[a-f0-9]{64}$/;

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function readText(path) {
	return readFileSync(join(root, path), "utf8");
}

function readJson(path) {
	return JSON.parse(readText(path));
}

function eventHash(event) {
	const { entryHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function tokens(text) {
	return [...new Set(String(text ?? "").toLowerCase().split(/[^a-z0-9\u4e00-\u9fff]+/).filter((token) => token.length >= 2))];
}

function memoryTextForSearch(event) {
	return [
		event.task,
		event.route,
		event.target ?? "",
		event.source,
		event.outcome,
		...(event.domainTags ?? []),
		...(event.lessons ?? []),
		...(event.failurePatterns ?? []),
		...(event.reuseRules ?? []),
		...(event.commands ?? []),
		...(event.artifactHashes ?? []).map((artifact) => `${artifact.path} ${artifact.tier} ${artifact.sha256 ?? ""}`),
	].join("\n").toLowerCase();
}

function routeMatches(eventRoute, route) {
	const left = String(eventRoute ?? "").trim().toLowerCase();
	const right = String(route ?? "").trim().toLowerCase();
	if (!right) return true;
	if (!left) return false;
	return left === right || left.includes(right) || right.includes(left);
}

function scoreEvent(event, scenario) {
	if (scenario.route && !routeMatches(event.route, scenario.route)) return { event, score: -999, reasons: ["route_mismatch"] };
	const queryTokens = tokens(scenario.query);
	const haystack = memoryTextForSearch(event);
	const haystackTokens = new Set(tokens(haystack));
	const reasons = [];
	let score = 0;
	for (const token of queryTokens) {
		if (haystackTokens.has(token)) {
			score += 4;
			reasons.push(`token:${token}`);
		}
	}
	if (scenario.route && routeMatches(event.route, scenario.route)) {
		score += 6;
		reasons.push("route");
	}
	if (scenario.target && String(event.target ?? "").toLowerCase().includes(String(scenario.target).toLowerCase())) {
		score += 6;
		reasons.push("target");
	}
	const timestamp = Date.parse(event.ts);
	const ageDays = Number.isNaN(timestamp) ? 365 : Math.max(0, Math.floor((Date.now() - timestamp) / 86_400_000));
	const quality = event.quality ?? {};
	const decay = Math.min(25, ageDays * 0.08 + Number(quality.decay ?? 0) * 12 + Number(quality.failureCount ?? 0) * 4);
	score += Number(quality.confidence ?? 0) * 10 + (quality.replayVerified ? 8 : 0) + Number(quality.reuseCount ?? 0) * 2;
	score -= decay;
	if (event.outcome === "success") score += 6;
	if (event.outcome === "blocked" || event.outcome === "failure") score -= event.outcome === "failure" ? 10 : 8;
	if (queryTokens.length > 0 && !reasons.some((reason) => reason.startsWith("token:"))) score = -999;
	return { event, score, reasons };
}

function searchMemory(events, scenario) {
	return events
		.map((event) => scoreEvent(event, scenario))
		.filter((hit) => hit.score > 0)
		.sort((left, right) => right.score - left.score || right.event.seq - left.event.seq)
		.slice(0, scenario.limit ?? 8);
}

function normalizeCommand(command, oldTarget, target) {
	let normalized = String(command ?? "").trim();
	if (!normalized) return undefined;
	if (target && oldTarget && oldTarget !== "<none>") normalized = normalized.split(oldTarget).join(target);
	if (target) normalized = normalized.replace(/<target>|<TARGET>|<URL>|<none>/gi, target);
	return /<target>|<TARGET>|<URL>|<none>/i.test(normalized) ? undefined : normalized;
}

function commandSuggestions(hits, scenario) {
	const seen = new Set();
	const commands = [];
	for (const hit of hits) {
		const event = hit.event;
		if (scenario.route && !routeMatches(event.route, scenario.route)) continue;
		if ((event.quality?.confidence ?? 0) < 0.45 || event.outcome === "failure") continue;
		for (const command of event.commands ?? []) {
			const normalized = normalizeCommand(command, event.target, scenario.target);
			if (!normalized || seen.has(normalized)) continue;
			seen.add(normalized);
			commands.push({ command: normalized, eventId: event.id, score: Number(hit.score.toFixed(2)) });
		}
	}
	return commands.slice(0, scenario.maxCommands ?? 8);
}

function validateHashChain(events) {
	const errors = [];
	let prevHash = "0".repeat(64);
	const ids = new Set();
	for (const [index, event] of events.entries()) {
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

function checkScenario(events, scenario) {
	const hits = searchMemory(events, scenario);
	const suggestions = commandSuggestions(hits, scenario);
	const hitIds = hits.map((hit) => hit.event.id);
	const suggestionCommands = suggestions.map((item) => item.command);
	const errors = [];
	if (scenario.expectedFirstEventId && hitIds[0] !== scenario.expectedFirstEventId) {
		errors.push(`expected first hit ${scenario.expectedFirstEventId}, got ${hitIds[0] ?? "none"}`);
	}
	for (const id of scenario.mustRecallEventIds ?? []) if (!hitIds.includes(id)) errors.push(`missing recall ${id}`);
	const topWindow = hitIds.slice(0, scenario.mustNotRecallTopN ?? 3);
	for (const id of scenario.mustNotRecallEventIds ?? []) if (topWindow.includes(id)) errors.push(`bad top recall ${id}`);
	for (const command of scenario.mustSuggestCommands ?? []) if (!suggestionCommands.includes(command)) errors.push(`missing command ${command}`);
	for (const command of scenario.mustNotSuggestCommands ?? []) if (suggestionCommands.includes(command)) errors.push(`bad command ${command}`);
	if (scenario.minTopScore !== undefined && (hits[0]?.score ?? 0) < scenario.minTopScore) errors.push(`top score below ${scenario.minTopScore}`);
	return {
		id: scenario.id,
		status: errors.length ? "fail" : "pass",
		errors,
		topHits: hits.slice(0, 5).map((hit) => ({ id: hit.event.id, score: Number(hit.score.toFixed(2)), reasons: hit.reasons, outcome: hit.event.outcome, confidence: hit.event.quality?.confidence })),
		suggestions,
	};
}

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "memory-utility", stamp);
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
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-memory-utility-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH, scenarioCount: fixture.scenarios?.length ?? 0 } });
	} catch (error) {
		checks.push({ id: "fixture:parse", status: "fail", evidence: { path: FIXTURE_PATH, error: String(error) } });
	}
	if (fixture) {
		const chainErrors = validateHashChain(fixture.events ?? []);
		checks.push({ id: "fixture:hash-chain", status: chainErrors.length ? "fail" : "pass", evidence: { errors: chainErrors.slice(0, 20), events: fixture.events?.length ?? 0 } });
		for (const scenario of fixture.scenarios ?? []) {
			const row = checkScenario(fixture.events ?? [], scenario);
			checks.push({ id: `scenario:${scenario.id}`, status: row.status, evidence: row });
		}
	}
	checks.push(
		markerCheck("code:memory-utility-scoring", "packages/coding-agent/src/core/recon-profile.ts", [
			"function searchMemoryEvents",
			"function memorySearchTokens",
			"function memoryRouteMatches",
			"event.quality.confidence * 10",
			"event.quality.replayVerified ? 8 : 0",
			"event.quality.failureCount",
			"event.quality.decay",
			"event.outcome === \"blocked\" || event.outcome === \"failure\"",
			"function structuredMemoryCommandCandidates",
			"memoryRouteMatches(hit.event.route, mission.route.domain)",
			"normalizeHistoricalCommand(command",
			"memory_event_reuse",
		]),
		markerCheck("docs:memory-utility", "README.md", ["Memory utility hard-eval", "gate:memory-utility", "正确召回"]),
		markerCheck("npm:memory-utility-script", "package.json", ["gate:memory-utility", "memory-utility-gate.mjs"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-memory-utility-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Utility Gate");
		console.log(`ok: ${result.ok}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
		for (const check of checks) console.log(`- ${check.id}: ${check.status}`);
		if (failed.length) console.log(`failed: ${failed.map((check) => check.id).join(", ")}`);
	}
	if (strict && failed.length) process.exitCode = 1;
}

main();

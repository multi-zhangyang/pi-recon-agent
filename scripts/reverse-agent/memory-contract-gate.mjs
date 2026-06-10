#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");

const SCHEMA_PATH = "schemas/reverse-agent/memory-event.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-event.fixture.json";

const EVENT_KEYS = [
	"kind",
	"schemaVersion",
	"id",
	"seq",
	"ts",
	"source",
	"task",
	"route",
	"target",
	"domainTags",
	"caseSignature",
	"outcome",
	"lessons",
	"failurePatterns",
	"reuseRules",
	"commands",
	"artifacts",
	"artifactHashes",
	"quality",
	"promotion",
	"prevHash",
	"entryHash",
];
const CASE_KEYS = [
	"kind",
	"schemaVersion",
	"id",
	"ts",
	"caseSignature",
	"route",
	"target",
	"domainTags",
	"summary",
	"eventIds",
	"commands",
	"reuseRules",
	"failurePatterns",
	"quality",
	"sourceEvents",
	"lastEventHash",
];
const SOURCES = new Set(["reflect", "complete", "proof_loop", "replayer", "autofix", "operator", "manual", "knowledge_graph"]);
const OUTCOMES = new Set(["success", "failure", "partial", "blocked", "repair"]);
const TIERS = new Set(["runtime_artifact", "process_config", "persisted_state", "persisted_memory", "artifact"]);

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function readText(path) {
	return readFileSync(join(root, path), "utf8");
}

function readJson(path) {
	return JSON.parse(readText(path));
}

function push(errors, path, code, message) {
	errors.push({ path, code, message });
}

function isObject(value) {
	return value && typeof value === "object" && !Array.isArray(value);
}

function checkKeys(value, allowed, required, path, errors) {
	if (!isObject(value)) return push(errors, path, "type", "expected object");
	const allowedSet = new Set(allowed);
	for (const key of Object.keys(value)) if (!allowedSet.has(key)) push(errors, `${path}.${key}`, "additionalProperties", "unexpected field");
	for (const key of required) if (!Object.prototype.hasOwnProperty.call(value, key)) push(errors, `${path}.${key}`, "required", "missing field");
}

function checkString(value, path, errors, pattern) {
	if (typeof value !== "string" || !value) return push(errors, path, "type", "expected non-empty string");
	if (pattern && !pattern.test(value)) push(errors, path, "pattern", `does not match ${pattern}`);
}

function checkArray(value, path, errors, { min = 0 } = {}) {
	if (!Array.isArray(value)) return push(errors, path, "type", "expected array");
	if (value.length < min) push(errors, path, "minItems", `expected >= ${min}`);
}

function checkIso(value, path, errors) {
	checkString(value, path, errors);
	if (typeof value === "string" && Number.isNaN(Date.parse(value))) push(errors, path, "format", "expected ISO date-time");
}

function validateQuality(value, path, errors) {
	checkKeys(value, ["confidence", "replayVerified", "reuseCount", "failureCount", "lastUsefulAt", "decay", "retrievalScore"], ["confidence", "replayVerified", "reuseCount", "failureCount", "lastUsefulAt", "decay"], path, errors);
	if (!isObject(value)) return;
	if (typeof value.confidence !== "number" || value.confidence < 0 || value.confidence > 1) push(errors, `${path}.confidence`, "range", "confidence must be 0..1");
	if (typeof value.replayVerified !== "boolean") push(errors, `${path}.replayVerified`, "type", "expected boolean");
	for (const key of ["reuseCount", "failureCount"]) if (!Number.isInteger(value[key]) || value[key] < 0) push(errors, `${path}.${key}`, "type", "expected non-negative integer");
	checkIso(value.lastUsefulAt, `${path}.lastUsefulAt`, errors);
	if (typeof value.decay !== "number" || value.decay < 0) push(errors, `${path}.decay`, "type", "expected non-negative number");
}

function validateArtifact(value, path, errors) {
	checkKeys(value, ["path", "sha256", "tier", "required"], ["path", "sha256", "tier"], path, errors);
	if (!isObject(value)) return;
	checkString(value.path, `${path}.path`, errors);
	if (!(value.sha256 === null || (typeof value.sha256 === "string" && /^[a-f0-9]{64}$/.test(value.sha256)))) push(errors, `${path}.sha256`, "pattern", "expected sha256 or null");
	if (!TIERS.has(value.tier)) push(errors, `${path}.tier`, "enum", "unknown artifact tier");
}

function eventHash(event) {
	const { entryHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function validateEvent(event, index, errors) {
	const path = `events[${index}]`;
	checkKeys(event, EVENT_KEYS, EVENT_KEYS.filter((key) => key !== "target"), path, errors);
	if (!isObject(event)) return;
	if (event.kind !== "repi-memory-event") push(errors, `${path}.kind`, "const", "expected repi-memory-event");
	if (event.schemaVersion !== 1) push(errors, `${path}.schemaVersion`, "const", "expected 1");
	checkString(event.id, `${path}.id`, errors, /^mem:[a-f0-9]{20}$/);
	if (!Number.isInteger(event.seq) || event.seq !== index + 1) push(errors, `${path}.seq`, "sequence", "seq must be 1-based and contiguous");
	checkIso(event.ts, `${path}.ts`, errors);
	if (!SOURCES.has(event.source)) push(errors, `${path}.source`, "enum", "unknown source");
	if (!OUTCOMES.has(event.outcome)) push(errors, `${path}.outcome`, "enum", "unknown outcome");
	for (const key of ["task", "route", "caseSignature", "prevHash", "entryHash"]) checkString(event[key], `${path}.${key}`, errors, key.endsWith("Hash") ? /^[a-f0-9]{64}$/ : undefined);
	for (const key of ["domainTags", "lessons", "failurePatterns", "reuseRules", "commands", "artifacts", "artifactHashes"]) checkArray(event[key], `${path}.${key}`, errors, { min: key === "domainTags" ? 1 : 0 });
	for (const [artifactIndex, artifact] of (event.artifactHashes ?? []).entries()) validateArtifact(artifact, `${path}.artifactHashes[${artifactIndex}]`, errors);
	validateQuality(event.quality, `${path}.quality`, errors);
	checkKeys(event.promotion, ["playbookCandidate", "workerRoutingHint", "verifierRuleCandidate"], ["playbookCandidate", "verifierRuleCandidate"], `${path}.promotion`, errors);
	const expected = eventHash(event);
	if (event.entryHash !== expected) push(errors, `${path}.entryHash`, "hash", `hash mismatch expected=${expected.slice(0, 16)}`);
}

function validateCase(row, index, eventById, eventHashes, errors) {
	const path = `caseMemory[${index}]`;
	checkKeys(row, CASE_KEYS, CASE_KEYS.filter((key) => key !== "target"), path, errors);
	if (!isObject(row)) return;
	if (row.kind !== "repi-case-memory") push(errors, `${path}.kind`, "const", "expected repi-case-memory");
	if (row.schemaVersion !== 1) push(errors, `${path}.schemaVersion`, "const", "expected 1");
	for (const key of ["id", "caseSignature", "route", "summary", "lastEventHash"]) checkString(row[key], `${path}.${key}`, errors, key === "lastEventHash" ? /^[a-f0-9]{64}$/ : undefined);
	checkIso(row.ts, `${path}.ts`, errors);
	for (const key of ["domainTags", "eventIds", "commands", "reuseRules", "failurePatterns", "sourceEvents"]) checkArray(row[key], `${path}.${key}`, errors, { min: key === "domainTags" || key === "eventIds" ? 1 : 0 });
	for (const id of row.eventIds ?? []) if (!eventById.has(id)) push(errors, `${path}.eventIds`, "reference", `unknown event id ${id}`);
	if (!eventHashes.has(row.lastEventHash)) push(errors, `${path}.lastEventHash`, "reference", "lastEventHash must reference an event entryHash");
	validateQuality(row.quality, `${path}.quality`, errors);
}

function validateContract(contract) {
	const errors = [];
	checkKeys(contract, ["kind", "schemaVersion", "events", "caseMemory", "retrievalReport"], ["kind", "schemaVersion", "events", "caseMemory", "retrievalReport"], "contract", errors);
	if (!isObject(contract)) return errors;
	if (contract.kind !== "repi-memory-contract") push(errors, "kind", "const", "expected repi-memory-contract");
	if (contract.schemaVersion !== 1) push(errors, "schemaVersion", "const", "expected 1");
	checkArray(contract.events, "events", errors, { min: 1 });
	checkArray(contract.caseMemory, "caseMemory", errors, { min: 1 });
	const ids = new Set();
	let prevHash = "0".repeat(64);
	for (const [index, event] of (contract.events ?? []).entries()) {
		validateEvent(event, index, errors);
		if (ids.has(event.id)) push(errors, `events[${index}].id`, "unique", "duplicate event id");
		ids.add(event.id);
		if (event.prevHash !== prevHash) push(errors, `events[${index}].prevHash`, "hashChain", "prevHash does not match previous entryHash");
		prevHash = event.entryHash;
	}
	const eventById = new Map((contract.events ?? []).map((event) => [event.id, event]));
	const eventHashes = new Set((contract.events ?? []).map((event) => event.entryHash));
	for (const [index, row] of (contract.caseMemory ?? []).entries()) validateCase(row, index, eventById, eventHashes, errors);
	const report = contract.retrievalReport;
	checkKeys(report, ["kind", "schemaVersion", "query", "route", "target", "generatedAt", "hashChainOk", "hits"], ["kind", "schemaVersion", "query", "hashChainOk", "hits"], "retrievalReport", errors);
	if (isObject(report)) {
		if (report.kind !== "repi-memory-retrieval-report") push(errors, "retrievalReport.kind", "const", "expected retrieval report");
		if (report.hashChainOk !== true) push(errors, "retrievalReport.hashChainOk", "hashChain", "fixture chain should be OK");
		for (const [index, hit] of (report.hits ?? []).entries()) if (!eventById.has(hit.id)) push(errors, `retrievalReport.hits[${index}].id`, "reference", "unknown event id");
	}
	return errors;
}

function markerCheck(id, path, markers) {
	const full = join(root, path);
	if (!existsSync(full)) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readFileSync(full, "utf8");
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function negativeChecks(fixture) {
	const cases = [];
	const deletedHash = structuredClone(fixture);
	delete deletedHash.events[0].entryHash;
	cases.push(["negative:missing-entryHash", deletedHash]);
	const badConfidence = structuredClone(fixture);
	badConfidence.events[0].quality.confidence = 1.5;
	cases.push(["negative:confidence-range", badConfidence]);
	const duplicate = structuredClone(fixture);
	duplicate.events.push({ ...structuredClone(duplicate.events[0]), seq: 2, prevHash: duplicate.events[0].entryHash });
	cases.push(["negative:duplicate-id", duplicate]);
	const badChain = structuredClone(fixture);
	badChain.events[0].prevHash = "f".repeat(64);
	cases.push(["negative:hash-chain", badChain]);
	const badHit = structuredClone(fixture);
	badHit.retrievalReport.hits[0].id = "mem:" + "0".repeat(20);
	cases.push(["negative:retrieval-ref", badHit]);
	return cases.map(([id, contract]) => {
		const errors = validateContract(contract);
		return { id, status: errors.length ? "pass" : "fail", evidence: { rejectedErrors: errors.slice(0, 8) } };
	});
}

function main() {
	const checks = [];
	let schema;
	let fixture;
	try {
		schema = readJson(SCHEMA_PATH);
		checks.push({ id: "schema:parse", status: schema?.$defs?.MemoryEventV1 ? "pass" : "fail", evidence: { path: SCHEMA_PATH } });
	} catch (error) {
		checks.push({ id: "schema:parse", status: "fail", evidence: { path: SCHEMA_PATH, error: String(error) } });
	}
	try {
		fixture = readJson(FIXTURE_PATH);
		const errors = validateContract(fixture);
		checks.push({ id: "fixture:memory-contract", status: errors.length ? "fail" : "pass", evidence: { path: FIXTURE_PATH, errors: errors.slice(0, 20) } });
	} catch (error) {
		checks.push({ id: "fixture:memory-contract", status: "fail", evidence: { path: FIXTURE_PATH, error: String(error) } });
	}
	if (fixture) checks.push(...negativeChecks(fixture));
	checks.push(
		markerCheck("code:memory-v2-runtime", "packages/coding-agent/src/core/recon-profile.ts", [
			"type MemoryEventV1",
			"function memoryEventsPath",
			"function caseMemoryPath",
			"function appendMemoryEvent",
			"function appendReplayerMemoryEvent",
			"function appendAutofixMemoryEvent",
			"function appendProofLoopMemoryEvent",
			"function appendCompletionMemoryEvent",
			"appendReplayerMemoryEvent(replay, path)",
			"appendAutofixMemoryEvent(autofix, path)",
			"appendProofLoopMemoryEvent(proof, path)",
			"appendCompletionMemoryEvent(audit",
			"function searchMemoryEvents",
			"memory_event_reuse",
			"<memory_events_tail>",
		]),
		markerCheck("docs:memory-v3-readme", "README.md", ["Memory v3", "events.jsonl", "case-memory.jsonl", "gate:memory-contract"]),
		markerCheck("docs:memory-v3-recon", "packages/coding-agent/docs/recon.md", ["Memory v3", "events.jsonl", "search-events", "gate:memory-contract"]),
		markerCheck("profile:memory-v3-knowledge", "repi-profile/SYSTEM.md", ["Memory v3", "events.jsonl", "case-memory.jsonl", "re_memory search-events"]),
		markerCheck("npm:memory-contract-script", "package.json", ["gate:memory-contract", "memory-contract-gate.mjs"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-memory-contract-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, checks };
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Contract Gate");
		console.log(`ok: ${result.ok}`);
		for (const check of checks) console.log(`- ${check.id}: ${check.status}`);
		if (failed.length) console.log(`failed: ${failed.map((check) => check.id).join(", ")}`);
	}
	if (strict && failed.length) process.exitCode = 1;
}

main();

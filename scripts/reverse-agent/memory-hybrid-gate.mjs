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

const FIXTURE_PATH = "fixtures/reverse-agent/memory-hybrid.fixture.json";
const HEX64 = /^[a-f0-9]{64}$/;

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function eventHash(event) {
	const { entryHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function tokens(text) {
	return [...new Set(String(text ?? "").toLowerCase().split(/[^a-z0-9\u4e00-\u9fff]+/).filter((token) => token.length >= 2))];
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

function routeMatches(eventRoute, route) {
	const left = String(eventRoute ?? "").trim().toLowerCase();
	const right = String(route ?? "").trim().toLowerCase();
	if (!right) return true;
	if (!left) return false;
	return left === right || left.includes(right) || right.includes(left);
}

function semanticAliases(token) {
	const aliases = {
		acl: ["authz", "authorization", "permission", "role", "ownership"],
		authorization: ["authz", "permission", "role", "ownership"],
		authz: ["authorization", "permission", "role", "ownership", "principal"],
		bola: ["authz", "authorization", "ownership", "object", "principal"],
		idor: ["authz", "authorization", "ownership", "object", "principal"],
		owner: ["ownership", "principal", "object", "tenant"],
		ownership: ["owner", "principal", "object", "tenant", "authz"],
		tenant: ["ownership", "principal", "object", "scope"],
		crash: ["segfault", "core", "overflow", "primitive", "pwn"],
		exploit: ["pwn", "poc", "payload", "primitive", "replay"],
		leak: ["libc", "address", "rop", "pwn"],
		ret2libc: ["rop", "libc", "pwn", "chain"],
		segfault: ["crash", "core", "overflow", "primitive"],
		signature: ["sign", "hmac", "crypto", "nonce", "timestamp"],
		signing: ["sign", "signature", "hmac", "crypto", "nonce"],
		packet: ["pcap", "stream", "tshark", "flow"],
		stream: ["pcap", "packet", "tshark", "flow"],
		rootfs: ["firmware", "squashfs", "binwalk", "iot"],
		metadata: ["cloud", "iam", "instance", "k8s", "kubernetes"],
		ioc: ["malware", "c2", "yara", "capa", "floss"],
	};
	return aliases[token] ?? [];
}

function hybridTokens(queryTokens) {
	return unique(queryTokens.flatMap((token) => semanticAliases(token)), 48);
}

function memoryText(event) {
	return [event.task, event.route, event.target ?? "", event.source, event.outcome, ...(event.domainTags ?? []), ...(event.lessons ?? []), ...(event.failurePatterns ?? []), ...(event.reuseRules ?? []), ...(event.commands ?? []), ...(event.artifactHashes ?? []).map((artifact) => `${artifact.path} ${artifact.tier} ${artifact.sha256 ?? ""}`)].join("\n").toLowerCase();
}

function artifactText(event) {
	return (event.artifactHashes ?? []).map((artifact) => `${artifact.path} ${artifact.tier}`).join("\n").toLowerCase();
}

function caseRowsFromEvents(events) {
	const rows = new Map();
	for (const event of events) {
		const previous = rows.get(event.caseSignature);
		const quality = {
			confidence: Math.max(previous?.quality?.confidence ?? 0, event.quality?.confidence ?? 0),
			replayVerified: Boolean(previous?.quality?.replayVerified || event.quality?.replayVerified),
			reuseCount: (previous?.quality?.reuseCount ?? 0) + (event.outcome === "success" ? 1 : 0),
			failureCount: (previous?.quality?.failureCount ?? 0) + (event.outcome === "failure" || event.outcome === "blocked" ? 1 : 0),
			lastUsefulAt: event.ts,
			decay: Math.max(0, (previous?.quality?.decay ?? 0) * 0.9 + (event.outcome === "failure" ? 0.2 : 0)),
		};
		rows.set(event.caseSignature, {
			caseSignature: event.caseSignature,
			route: event.route,
			target: event.target,
			domainTags: event.domainTags ?? [],
			summary: unique([event.lessons?.[0], event.reuseRules?.[0], event.failurePatterns?.[0], event.task], 4).join(" | "),
			commands: unique([...(previous?.commands ?? []), ...(event.commands ?? [])], 40),
			reuseRules: unique([...(previous?.reuseRules ?? []), ...(event.reuseRules ?? [])], 40),
			failurePatterns: unique([...(previous?.failurePatterns ?? []), ...(event.failurePatterns ?? [])], 40),
			quality,
		});
	}
	return rows;
}

function caseText(row) {
	if (!row) return "";
	return [row.summary, row.route, row.target ?? "", ...(row.domainTags ?? []), ...(row.commands ?? []), ...(row.reuseRules ?? []), ...(row.failurePatterns ?? [])].join("\n").toLowerCase();
}

function overlapScore({ checkTokens, haystack, prefix, points, max, reasons }) {
	let score = 0;
	for (const token of checkTokens) {
		if (!haystack.has(token)) continue;
		score += points;
		reasons.push(`${prefix}:${token}`);
		if (score >= max) return max;
	}
	return score;
}

function scoreEvent(event, scenario, caseRows) {
	if (scenario.route && !routeMatches(event.route, scenario.route)) return { event, score: -999, reasons: ["route_mismatch"] };
	const queryTokens = tokens(scenario.query);
	const semantic = hybridTokens(queryTokens);
	const haystack = new Set(tokens(memoryText(event)));
	const artifactHaystack = new Set(tokens(artifactText(event)));
	const row = caseRows.get(event.caseSignature);
	const caseHaystack = new Set(tokens(caseText(row)));
	const reasons = [];
	let score = 0;
	for (const token of queryTokens) {
		if (haystack.has(token)) {
			score += 4;
			reasons.push(`token:${token}`);
		}
	}
	score += overlapScore({ checkTokens: semantic, haystack, prefix: "memory_semantic_hybrid_reuse", points: 2, max: 12, reasons });
	score += overlapScore({ checkTokens: queryTokens, haystack: caseHaystack, prefix: "case-memory-hybrid", points: 2.5, max: 12, reasons });
	score += overlapScore({ checkTokens: [...queryTokens, ...semantic], haystack: artifactHaystack, prefix: "artifact-hybrid", points: 3, max: 9, reasons });
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
	if (row) {
		const reuseBoost = Math.min(12, row.quality.reuseCount * 1.5);
		const penalty = Math.min(18, row.quality.failureCount * 3 + row.quality.decay * 10);
		if (reuseBoost > 0) {
			score += reuseBoost;
			reasons.push("case-memory-feedback:reuse");
		}
		if (row.quality.replayVerified && !quality.replayVerified) {
			score += 3;
			reasons.push("case-memory-feedback:verified");
		}
		if (penalty > 0) {
			score -= penalty;
			reasons.push("case-memory-feedback:penalty");
		}
	}
	if (event.outcome === "success") score += 6;
	if (event.outcome === "blocked" || event.outcome === "failure") score -= event.outcome === "failure" ? 10 : 8;
	if (queryTokens.length > 0 && !reasons.some((reason) => /^(?:token:|memory_semantic_hybrid_reuse:|case-memory-hybrid:|artifact-hybrid:)/.test(reason))) score = -999;
	return { event, score, reasons };
}

function searchMemory(events, scenario) {
	const caseRows = caseRowsFromEvents(events);
	return events.map((event) => scoreEvent(event, scenario, caseRows)).filter((hit) => hit.score > 0).sort((left, right) => right.score - left.score || right.event.seq - left.event.seq).slice(0, scenario.limit ?? 8);
}

function normalizeCommand(command, oldTarget, target) {
	let normalized = String(command ?? "").trim();
	if (!normalized) return undefined;
	if (target && oldTarget && oldTarget !== "<none>") normalized = normalized.split(oldTarget).join(target);
	if (target) normalized = normalized.replace(/<target>|<TARGET>|<URL>|<none>/gi, target);
	return /<target>|<TARGET>|<URL>|<none>/i.test(normalized) ? undefined : normalized;
}

function suggestions(hits, scenario) {
	const seen = new Set();
	const out = [];
	for (const hit of hits) {
		if ((hit.event.quality?.confidence ?? 0) < 0.45 || hit.event.outcome === "failure") continue;
		for (const command of hit.event.commands ?? []) {
			const normalized = normalizeCommand(command, hit.event.target, scenario.target);
			if (!normalized || seen.has(normalized)) continue;
			seen.add(normalized);
			out.push({ command: normalized, eventId: hit.event.id, score: Number(hit.score.toFixed(2)) });
		}
	}
	return out.slice(0, scenario.maxCommands ?? 8);
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
	const hitIds = hits.map((hit) => hit.event.id);
	const commands = suggestions(hits, scenario).map((item) => item.command);
	const topReasons = hits[0]?.reasons ?? [];
	const errors = [];
	if (scenario.expectedFirstEventId && hitIds[0] !== scenario.expectedFirstEventId) errors.push(`expected first hit ${scenario.expectedFirstEventId}, got ${hitIds[0] ?? "none"}`);
	for (const id of scenario.mustRecallEventIds ?? []) if (!hitIds.includes(id)) errors.push(`missing recall ${id}`);
	for (const id of scenario.mustNotRecallEventIds ?? []) if (hitIds.slice(0, scenario.mustNotRecallTopN ?? 3).includes(id)) errors.push(`bad top recall ${id}`);
	for (const prefix of scenario.mustHaveTopReasonPrefixes ?? []) if (!topReasons.some((reason) => reason.startsWith(prefix))) errors.push(`missing top reason prefix ${prefix}`);
	for (const command of scenario.mustSuggestCommands ?? []) if (!commands.includes(command)) errors.push(`missing command ${command}`);
	for (const command of scenario.mustNotSuggestCommands ?? []) if (commands.includes(command)) errors.push(`bad command ${command}`);
	if (scenario.minTopScore !== undefined && (hits[0]?.score ?? 0) < scenario.minTopScore) errors.push(`top score below ${scenario.minTopScore}`);
	return { id: scenario.id, status: errors.length ? "fail" : "pass", errors, topHits: hits.slice(0, 5).map((hit) => ({ id: hit.event.id, score: Number(hit.score.toFixed(2)), reasons: hit.reasons, outcome: hit.event.outcome })), suggestions: suggestions(hits, scenario) };
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
	const dir = join(root, ".repi-harness", "evidence", "memory-hybrid", stamp);
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
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-memory-hybrid-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH, scenarioCount: fixture.scenarios?.length ?? 0 } });
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
		markerCheck("code:memory-hybrid-retrieval", "packages/coding-agent/src/core/recon-profile.ts", ["function memorySemanticAliases", "function memoryHybridQueryTokens", "function memoryCaseTextForSearch", "function memoryArtifactTextForSearch", "function memoryHybridSignalScore", "memory_semantic_hybrid_reuse", "case-memory-hybrid", "artifact-hybrid"]),
		markerCheck("docs:memory-hybrid", "README.md", ["Memory hybrid retrieval", "gate:memory-hybrid", "语义轻量召回"]),
		markerCheck("npm:memory-hybrid-script", "package.json", ["gate:memory-hybrid", "memory-hybrid-gate.mjs"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-memory-hybrid-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Hybrid Gate");
		console.log(`ok: ${result.ok}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
		for (const check of checks) console.log(`- ${check.id}: ${check.status}`);
		if (failed.length) console.log(`failed: ${failed.map((check) => check.id).join(", ")}`);
	}
	if (strict && failed.length) process.exitCode = 1;
}

main();

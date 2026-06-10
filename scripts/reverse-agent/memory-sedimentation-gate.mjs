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

const FIXTURE_PATH = "fixtures/reverse-agent/memory-sedimentation.fixture.json";
const HEX64 = /^[a-f0-9]{64}$/;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

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

function eventHash(event) {
	const { entryHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function sealEvents(seedEvents) {
	let prevHash = "0".repeat(64);
	return (seedEvents ?? []).map((seed, index) => {
		const event = {
			kind: "repi-memory-event",
			schemaVersion: 1,
			seq: index + 1,
			artifacts: seed.artifacts ?? seed.artifactHashes ?? [],
			...seed,
			prevHash,
			entryHash: "",
		};
		event.entryHash = eventHash(event);
		prevHash = event.entryHash;
		return event;
	});
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

function tokens(text) {
	return unique(String(text ?? "").toLowerCase().split(/[^a-z0-9\u4e00-\u9fff]+/), 160).filter((token) => token.length >= 2);
}

function aliases(token) {
	const map = {
		authz: ["authorization", "permission", "ownership", "principal"],
		idor: ["authz", "ownership", "object", "principal"],
		bola: ["authz", "ownership", "object", "principal"],
		signing: ["signature", "hmac", "nonce", "timestamp"],
		hmac: ["signing", "signature", "crypto"],
		crash: ["pwn", "overflow", "primitive"],
		rop: ["pwn", "libc", "chain"],
	};
	return map[token] ?? [];
}

function targetScope(target) {
	const raw = String(target ?? "").trim();
	if (!raw) return "";
	try {
		return new URL(raw).host.toLowerCase();
	} catch {
		return raw.toLowerCase();
	}
}

function groupByCase(events) {
	const groups = new Map();
	for (const event of events ?? []) {
		const rows = groups.get(event.caseSignature) ?? [];
		rows.push(event);
		groups.set(event.caseSignature, rows);
	}
	return groups;
}

function detectContamination(events, now) {
	const findings = [];
	for (const [caseSignature, rows] of groupByCase(events)) {
		const routes = unique(rows.map((event) => String(event.route ?? "").toLowerCase()), 12);
		const targets = unique(rows.map((event) => targetScope(event.target)), 16);
		const successes = rows.filter((event) => event.outcome === "success");
		const failures = rows.filter((event) => event.outcome === "failure" || event.outcome === "blocked");
		const highConfidenceFailures = failures.filter((event) => Number(event.quality?.confidence ?? 0) >= 0.78);
		const latest = Math.max(...rows.map((event) => Date.parse(event.ts)).filter(Number.isFinite), 0);
		const ageDays = latest > 0 ? Math.floor((Date.parse(now) - latest) / 86_400_000) : 0;
		const failurePressure = failures.length + rows.reduce((sum, event) => sum + Number(event.quality?.failureCount ?? 0), 0);
		const reasons = unique([
			routes.length > 1 ? `cross_route_contamination:${routes.join(",")}` : undefined,
			targets.length > 2 ? `cross_target_contamination:${targets.join(",")}` : undefined,
			successes.length > 0 && highConfidenceFailures.length > 0 ? "contradicted_success_failure_high_confidence" : undefined,
			ageDays > 180 && successes.length === 0 ? `stale_negative_memory:${ageDays}d` : undefined,
			failurePressure >= Math.max(2, successes.length + 2) ? `failure_pressure:${failurePressure}` : undefined,
		], 8);
		findings.push({ caseSignature, status: reasons.length ? "quarantine" : "clean", reasons, eventIds: rows.map((event) => event.id), routes, targets });
	}
	return findings;
}

function eventText(event) {
	return [
		event.task,
		event.route,
		event.target,
		...(event.domainTags ?? []),
		...(event.lessons ?? []),
		...(event.failurePatterns ?? []),
		...(event.reuseRules ?? []),
		...(event.commands ?? []),
		...(event.artifactHashes ?? []).map((artifact) => `${artifact.path} ${artifact.tier} ${artifact.sha256 ?? ""}`),
	].join("\n");
}

function verifierRefs(event) {
	const commandRefs = (event.commands ?? []).filter((command) => /\bre_(?:verifier|replayer|proof_loop|complete)\b|\bnpm\s+run\s+gate:/i.test(command));
	return unique([
		...(event.quality?.replayVerified ? [`replay_verified:event=${event.id}`] : []),
		...(event.promotion?.verifierRuleCandidate ? [`verifier_rule_candidate:event=${event.id}`] : []),
		...commandRefs,
	], 12);
}

function commandFingerprint(command) {
	return `cmd:${sha256(String(command ?? "").toLowerCase()).slice(0, 16)}`;
}

function gradeEvent(event, finding, now) {
	const artifactReady = (event.artifactHashes ?? []).some((artifact) => typeof artifact.sha256 === "string" && artifact.sha256.length >= 32);
	const verifierReady = Boolean(event.quality?.replayVerified || event.promotion?.verifierRuleCandidate || verifierRefs(event).length > 0);
	const successful = event.outcome === "success" || event.outcome === "repair";
	const failed = event.outcome === "failure" || event.outcome === "blocked";
	const ageDays = Math.max(0, Math.floor((Date.parse(now) - Date.parse(event.ts)) / 86_400_000));
	let grade = 0;
	grade += Number(event.quality?.confidence ?? 0) * 38;
	grade += event.quality?.replayVerified ? 18 : 0;
	grade += event.promotion?.playbookCandidate ? 6 : 0;
	grade += event.promotion?.verifierRuleCandidate ? 7 : 0;
	grade += successful ? 12 : 0;
	grade += artifactReady ? 8 : 0;
	grade += Math.min(10, Number(event.quality?.reuseCount ?? 0) * 2);
	grade -= failed ? 18 : 0;
	grade -= Math.min(22, Number(event.quality?.failureCount ?? 0) * 5 + Number(event.quality?.decay ?? 0) * 18 + ageDays * 0.03);
	const blockers = unique([
		finding?.status === "quarantine" ? `memory_contamination_quarantine:${finding.reasons.join(",")}` : undefined,
		!artifactReady ? "artifact_sha256_missing" : undefined,
		!verifierReady ? "verifier_or_replay_missing" : undefined,
		failed ? `negative_outcome:${event.outcome}` : undefined,
	], 8);
	const hardQuarantine = Boolean(finding?.status === "quarantine" && finding.reasons.some((reason) => !/^failure_pressure:/i.test(reason)));
	let action = "retain";
	if (hardQuarantine) action = "quarantine";
	else if (failed || grade < 34) action = "demote";
	else if (grade >= 70 && successful && artifactReady && verifierReady && !finding?.reasons.length) action = "inject";
	return { grade: Number(Math.max(0, Math.min(100, grade)).toFixed(2)), action, blockers };
}

function contradictionEntry(finding) {
	const base = {
		kind: "repi-memory-contradiction-ledger-entry",
		schemaVersion: 1,
		id: `memory-contradiction:${finding.caseSignature}`,
		caseSignature: finding.caseSignature,
		status: finding.reasons.some((reason) => /contradicted/i.test(reason)) ? "contradicted" : finding.status,
		reasons: finding.reasons,
		eventIds: finding.eventIds,
		routes: finding.routes,
		targets: finding.targets,
	};
	return { ...base, entryHash: sha256(JSON.stringify(base)) };
}

function sediment(events, options = {}) {
	const now = options.now ?? new Date().toISOString();
	const hashErrors = validateHashChain(events);
	const contamination = detectContamination(events, now);
	const byCase = new Map(contamination.map((finding) => [finding.caseSignature, finding]));
	const entries = events.map((event) => {
		const grading = gradeEvent(event, byCase.get(event.caseSignature), now);
		const normalizedTokens = unique([...tokens(eventText(event)), ...tokens(eventText(event)).flatMap(aliases)], 96);
		return {
			kind: "repi-memory-semantic-index-entry",
			schemaVersion: 1,
			id: `memory-semantic:${event.id}`,
			eventId: event.id,
			caseSignature: event.caseSignature,
			route: event.route,
			targetScope: targetScope(event.target),
			domainTags: event.domainTags ?? [],
			normalizedTokens,
			commandFingerprints: unique((event.commands ?? []).map(commandFingerprint), 20),
			artifactRefs: (event.artifactHashes ?? []).filter((artifact) => artifact.sha256),
			verifierRefs: verifierRefs(event),
			claimRefs: unique([...(event.lessons ?? []), ...(event.reuseRules ?? []), ...(event.failurePatterns ?? [])], 12),
			grade: grading.grade,
			action: grading.action,
			blockers: grading.blockers,
			reuseSummary: event.lessons?.[0] ?? event.task,
		};
	}).sort((left, right) => right.grade - left.grade || left.eventId.localeCompare(right.eventId));
	const injectionEntries = entries.filter((entry) => entry.action === "inject" && entry.blockers.length === 0).slice(0, options.maxEntries ?? 8);
	const eventById = new Map(events.map((event) => [event.id, event]));
	const injectionPacket = {
		kind: "repi-memory-injection-packet",
		schemaVersion: 1,
		generatedAt: now,
		mandatory_memory_injection_packet: true,
		budget: { maxEntries: options.maxEntries ?? 8, maxCommands: 32, maxTokens: 3500 },
		entries: injectionEntries,
		commands: unique(injectionEntries.flatMap((entry) => eventById.get(entry.eventId)?.commands ?? []), 32),
		verifierRules: unique(injectionEntries.flatMap((entry) => entry.verifierRefs), 32),
		requiredGates: ["artifact_sha256_required", "promotion_requires_verifier_or_replay", "quarantine_blocks_injection", "feedback_writeback_required_after_execution", "memory_sedimentation_grade>=70"],
		feedbackWriteback: "After executing an injected command, append MemoryEventV1 feedback with outcome, artifact sha256 and verifier result.",
	};
	return {
		kind: "repi-memory-sedimentation-report",
		schemaVersion: 1,
		generatedAt: now,
		hashChainOk: hashErrors.length === 0,
		hashErrors,
		semanticIndexPath: "memory/semantic-index.json",
		contradictionLedgerPath: "memory/contradiction-ledger.jsonl",
		injectionPacketPath: "memory/injection-packet.json",
		distillationReportPath: "memory/distillation-report.json",
		entries,
		contradictions: contamination.filter((finding) => finding.status === "quarantine").map(contradictionEntry),
		injectionPacket,
		policy: {
			MemorySedimentationV1: true,
			promotionRequiresArtifactSha256: true,
			promotionRequiresVerifierOrReplay: true,
			quarantineBlocksInjection: true,
			failureFeedbackDemotes: true,
		},
	};
}

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function checkExpected(report, expected = {}) {
	const errors = [];
	const byEvent = new Map(report.entries.map((entry) => [entry.eventId, entry]));
	const injectable = new Set(report.injectionPacket.entries.map((entry) => entry.eventId));
	const quarantined = new Set(report.contradictions.map((entry) => entry.caseSignature));
	const gates = new Set(report.injectionPacket.requiredGates);
	for (const id of expected.mustInjectEventIds ?? []) if (!injectable.has(id)) errors.push(`missing injectable event ${id}`);
	for (const id of expected.mustNotInjectEventIds ?? []) if (injectable.has(id)) errors.push(`unexpected injectable event ${id}`);
	for (const id of expected.mustDemoteEventIds ?? []) if (byEvent.get(id)?.action !== "demote") errors.push(`missing demotion ${id} action=${byEvent.get(id)?.action}`);
	for (const id of expected.mustQuarantineCaseSignatures ?? []) if (!quarantined.has(id)) errors.push(`missing quarantine ${id}`);
	for (const gate of expected.mustHaveRequiredGates ?? []) if (!gates.has(gate)) errors.push(`missing required gate ${gate}`);
	for (const artifact of expected.mustHaveArtifacts ?? []) {
		if (![report.semanticIndexPath, report.contradictionLedgerPath, report.injectionPacketPath, "memory/sedimentation-report.json"].some((path) => path.includes(artifact))) errors.push(`missing artifact path ${artifact}`);
	}
	if (!report.policy?.MemorySedimentationV1) errors.push("policy.MemorySedimentationV1 missing");
	return errors;
}

function applyNegativeMutation(events, negative) {
	const rows = JSON.parse(JSON.stringify(events));
	const event = rows.find((row) => row.id === negative.eventId);
	if (negative.mutate === "removeArtifactSha" && event) event.artifactHashes = [];
	if (negative.mutate === "removeVerifier" && event) {
		event.quality.replayVerified = false;
		event.promotion.verifierRuleCandidate = false;
		event.commands = event.commands.filter((command) => !/re_verifier|re_replayer|gate:/i.test(command));
	}
	if (negative.mutate === "crossRoute" && event) {
		const clone = { ...event, id: `${event.id}-pwn-clone`, route: "pwn", target: "./vuln", domainTags: ["pwn", "rop"], commands: ["python3 exploit.py ./vuln"] };
		rows.push(clone);
	}
	if (negative.mutate === "failureFeedback" && event) {
		event.outcome = "failure";
		event.quality.replayVerified = false;
		event.quality.failureCount = 4;
		event.quality.decay = 0.8;
		event.failurePatterns = ["memory_reuse_feedback_failed exit=1 verdict=weak"];
	}
	let sealed = sealEvents(rows.map(({ kind, schemaVersion, seq, prevHash, entryHash, artifacts, ...seed }) => seed));
	if (negative.mutate === "hashDrift" && sealed[0]) sealed[0].entryHash = "f".repeat(64);
	return sealed;
}

function checkNegative(fixture, events, negative) {
	const mutated = applyNegativeMutation(events, negative);
	const report = sediment(mutated, { now: fixture.now });
	if (negative.expect === "hash_chain_blocked") {
		return { id: `negative:${negative.id}`, status: report.hashChainOk ? "fail" : "pass", evidence: { hashErrors: report.hashErrors } };
	}
	const errors = [];
	const byEvent = new Map(report.entries.map((entry) => [entry.eventId, entry]));
	const injectable = new Set(report.injectionPacket.entries.map((entry) => entry.eventId));
	const quarantined = new Set(report.contradictions.map((entry) => entry.caseSignature));
	if (negative.expectNotInject && injectable.has(negative.expectNotInject)) errors.push(`unexpected injectable event ${negative.expectNotInject}`);
	if (negative.expectQuarantine && !quarantined.has(negative.expectQuarantine)) errors.push(`missing quarantine ${negative.expectQuarantine}`);
	if (negative.expectDemote && byEvent.get(negative.expectDemote)?.action !== "demote") errors.push(`missing demotion ${negative.expectDemote}`);
	return { id: `negative:${negative.id}`, status: errors.length ? "fail" : "pass", evidence: { errors, entry: byEvent.get(negative.eventId), injectable: [...injectable], quarantined: [...quarantined] } };
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "memory-sedimentation", stamp);
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
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-memory-sedimentation-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH } });
	} catch (error) {
		checks.push({ id: "fixture:parse", status: "fail", evidence: { path: FIXTURE_PATH, error: String(error) } });
	}
	if (fixture) {
		const events = sealEvents(fixture.seedEvents ?? []);
		const report = sediment(events, { now: fixture.now });
		checks.push({ id: "fixture:hash-chain", status: report.hashChainOk ? "pass" : "fail", evidence: { errors: report.hashErrors } });
		const expectedErrors = checkExpected(report, fixture.expected ?? {});
		checks.push({ id: "fixture:sedimentation-policy", status: expectedErrors.length ? "fail" : "pass", evidence: { errors: expectedErrors, injection: report.injectionPacket.entries.map((entry) => ({ eventId: entry.eventId, grade: entry.grade })), contradictions: report.contradictions } });
		for (const negative of fixture.negativeCases ?? []) checks.push(checkNegative(fixture, events, negative));
	}
	checks.push(
		markerCheck("code:memory-sedimentation-runtime", "packages/coding-agent/src/core/recon-profile.ts", [
			"type MemorySemanticIndexEntryV1",
			"type MemorySedimentationReportV1",
			"function buildMemorySemanticIndex",
			"function formatMemorySedimentation",
			"mandatory_memory_injection_packet",
			"memory_sedimentation_grade>=70",
			"quarantine_blocks_injection",
			"memory-sediment:",
		]),
		markerCheck("docs:memory-sedimentation", "README.md", ["Memory v4 sedimentation", "gate:memory-sedimentation", "semantic-index.json", "injection-packet.json"]),
		markerCheck("docs:memory-sedimentation-recon", "packages/coding-agent/docs/recon.md", ["Memory v4 sedimentation", "re_memory sediment", "contradiction-ledger.jsonl"]),
		markerCheck("npm:memory-sedimentation-script", "package.json", ["gate:memory-sedimentation", "memory-sedimentation-gate.mjs"]),
		markerCheck("harness:memory-sedimentation-child", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:memory-sedimentation", "memory:v4-sedimentation"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-memory-sedimentation-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Memory Sedimentation Gate");
		console.log(`ok: ${result.ok}`);
		for (const check of checks) console.log(`- ${check.status === "pass" ? "PASS" : "FAIL"} ${check.id}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
		if (failed.length) console.log(JSON.stringify(failed, null, 2));
	}
	if (strict && failed.length) process.exit(1);
}

main();

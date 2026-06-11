#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const REQUIRED_RUNTIME_CLAIM_EVENT_TYPES = ["artifact_handoff", "claim", "validation", "challenge", "resolution"];
export const RUNTIME_CLAIM_LEDGER_SOURCES = ["agentDogfood", "reSwarm", "compoundFrontier"];
const ZERO_HASH = "0".repeat(64);

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function safeJson(text, fallback = null) {
	try {
		return JSON.parse(text);
	} catch {
		return fallback;
	}
}

function toPosix(path) {
	return path.replace(/\\/g, "/");
}

function resolvePath(root, path) {
	if (!path) return "";
	if (existsSync(path)) return resolve(path);
	return resolve(root, path);
}

function relPath(root, path) {
	if (!path) return "";
	return toPosix(relative(root, resolvePath(root, path)));
}

function readJson(root, path) {
	const resolved = resolvePath(root, path);
	return existsSync(resolved) ? safeJson(readFileSync(resolved, "utf8"), null) : null;
}

function readJsonl(root, path) {
	const resolved = resolvePath(root, path);
	if (!existsSync(resolved)) return [];
	return readFileSync(resolved, "utf8")
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean)
		.map((line) => safeJson(line))
		.filter(Boolean);
}

function fileDigest(root, path) {
	if (!path) return { path: "", exists: false };
	const resolved = resolvePath(root, path);
	const relativePath = relPath(root, path);
	if (!existsSync(resolved)) return { path: relativePath, exists: false };
	const bytes = readFileSync(resolved);
	return { path: relativePath, exists: true, bytes: bytes.length, sha256: sha256(bytes) };
}

function listFiles(dir, predicate, depth = 3) {
	if (!existsSync(dir) || depth < 0) return [];
	const rows = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) rows.push(...listFiles(path, predicate, depth - 1));
		else if (entry.isFile() && predicate(path)) rows.push(path);
	}
	return rows;
}

function latest(paths) {
	return paths.sort().at(-1) ?? null;
}

export function runtimeClaimEventHash(event) {
	const { eventHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function appendStrictEvent(events, event) {
	const row = {
		seq: events.length + 1,
		prevHash: events.at(-1)?.eventHash ?? ZERO_HASH,
		...event,
	};
	row.eventHash = runtimeClaimEventHash(row);
	events.push(row);
	return row;
}

export function runtimeClaimHashChainOk(events = []) {
	if (!Array.isArray(events) || events.length === 0) return false;
	let prevHash = ZERO_HASH;
	for (let index = 0; index < events.length; index += 1) {
		const event = events[index];
		if (event.seq !== index + 1 || event.prevHash !== prevHash || event.eventHash !== runtimeClaimEventHash(event)) return false;
		prevHash = event.eventHash;
	}
	return true;
}

export function runtimeClaimLedgerCaptured(events = []) {
	const types = new Set(events.map((event) => event?.type).filter(Boolean));
	return runtimeClaimHashChainOk(events) && REQUIRED_RUNTIME_CLAIM_EVENT_TYPES.every((type) => types.has(type));
}

function sourceLabel(source) {
	return {
		agentDogfood: "agent-dogfood",
		reSwarm: "re_swarm",
		compoundFrontier: "compound-frontier",
		adapterFixture: "adapter-fixture",
	}[source] ?? source;
}

function latestResult(root, relativeDir) {
	return latest(listFiles(join(root, relativeDir), (path) => path.endsWith("/result.json"), 2));
}

function latestSwarmLedger(root) {
	return latest(listFiles(join(root, ".repi-harness", "evidence", "swarms"), (path) => /claim-ledger\.jsonl$/.test(path), 1));
}

export function loadRuntimeClaimLedgerSource(root, source) {
	if (source === "agentDogfood" || source === "compoundFrontier") {
		const family = source === "agentDogfood" ? "agent-parallel-dogfood" : "compound-frontier";
		const providerResultAbs = latestResult(root, `.repi-harness/evidence/remote/${family}`);
		const planOnlyResultAbs = source === "agentDogfood" ? latestResult(root, ".repi-harness/evidence/runtime/agent-dogfood-plan-only") : "";
		const resultAbs = providerResultAbs || planOnlyResultAbs;
		if (!resultAbs) return { source, status: "missing_runtime_artifact", reason: `missing latest ${family}/result.json` };
		const resultPath = relPath(root, resultAbs);
		const result = readJson(root, resultPath) ?? {};
		const ledgerPath = result.claimLedgerPath ?? relPath(root, join(dirname(resultAbs), "claim-ledger.jsonl"));
		const events = Array.isArray(result.claimLedgerEvents) ? result.claimLedgerEvents : readJsonl(root, ledgerPath);
		if (!events.length) return { source, status: "missing_runtime_artifact", reason: `${family} result exists but runtime claim ledger is missing`, resultPath, ledgerPath, result };
		return { source, status: "loaded", resultPath, ledgerPath, result, events };
	}
	if (source === "reSwarm") {
		const ledgerAbs = latestSwarmLedger(root);
		if (!ledgerAbs) return { source, status: "missing_runtime_artifact", reason: "missing .repi-harness/evidence/swarms/*-claim-ledger.jsonl" };
		const ledgerPath = relPath(root, ledgerAbs);
		const events = readJsonl(root, ledgerPath);
		if (!events.length) return { source, status: "missing_runtime_artifact", reason: "re_swarm runtime claim ledger is empty", ledgerPath };
		return { source, status: "loaded", ledgerPath, events };
	}
	throw new Error(`unknown runtime claim ledger source: ${source}`);
}

export function discoverRuntimeClaimLedgerSources(root) {
	return RUNTIME_CLAIM_LEDGER_SOURCES.map((source) => loadRuntimeClaimLedgerSource(root, source));
}

function roleContract(runId) {
	const baseEvidence = ["same_window_live", "runtime_artifact", "network", "served_asset", "process_config", "persisted_state"];
	return {
		contractVersion: 1,
		runId,
		evidenceOrder: baseEvidence,
		ledgerPolicy: { appendOnly: true, prevHash: "required", eventHash: "required", requiredEventTypes: REQUIRED_RUNTIME_CLAIM_EVENT_TYPES },
		conflictPolicy: { tableRequired: true, evidenceOrder: baseEvidence, unresolvedBlocksFinal: true },
		claimGatePolicy: { provenRequiresArtifactSha256: true, provenRequiresJsonQuery: true, finalPassRequiresVerifier: true, unresolvedChallengeBlocks: true },
		roles: [
			{ id: "mapper", mustEmit: ["artifact_handoff", "claim"], allowedClaimKinds: ["observed", "proven", "gap", "stale", "inferred"], forbiddenClaimKinds: ["final_pass_without_validation"], handoffTargets: ["verifier", "adversary", "synthesizer"], evidenceContract: ["artifact_handoff sha256 is present", "claim evidenceRefs bind artifactId/query/op/value"] },
			{ id: "verifier", mustEmit: ["validation"], allowedClaimKinds: ["observed", "proven", "gap", "frontier_gap", "stale", "inferred", "final_pass"], forbiddenClaimKinds: ["final_pass_without_artifact_validation"], mustValidateClaimKinds: ["proven", "final_pass"], handoffTargets: ["adversary", "synthesizer"], evidenceContract: ["validation result is pass/fail", "checks preserve observed values"] },
			{ id: "adversary", mustEmit: ["challenge"], allowedClaimKinds: ["gap", "frontier_gap", "stale", "inferred"], forbiddenClaimKinds: ["unresolved_final_pass"], mustChallengeScopes: ["agent-dogfood", "re_swarm", "compound-frontier"], handoffTargets: ["synthesizer"], evidenceContract: ["required gaps receive upheld challenge", "runtime ledger promotion is blocked on structural gaps"] },
			{ id: "synthesizer", mustEmit: ["resolution"], allowedClaimKinds: ["observed", "proven", "gap", "frontier_gap", "stale", "inferred", "final_pass"], forbiddenClaimKinds: ["platform_success_from_orchestration_only"], mustResolve: ["all_required_gaps", "all_conflicts", "runtime_claim_ledger_promotion"], handoffTargets: [], evidenceContract: ["resolution cites claimIds", "strict validator result is preserved"] },
		],
	};
}

function evidenceSummary(root, loaded, evidencePath) {
	const events = loaded.events ?? [];
	const eventTypes = [...new Set(events.map((event) => event?.type).filter(Boolean))].sort();
	const eventTypeCounts = events.reduce((acc, event) => {
		if (event?.type) acc[event.type] = (acc[event.type] || 0) + 1;
		return acc;
	}, {});
	const hashChainOk = runtimeClaimHashChainOk(events);
	const captured = runtimeClaimLedgerCaptured(events);
	const artifactDigests = [
		fileDigest(root, loaded.resultPath),
		fileDigest(root, loaded.ledgerPath),
	].filter((item) => item.path);
	return {
		kind: "pi-recon-runtime-claim-ledger-evidence",
		version: 1,
		generatedAt: new Date().toISOString(),
		source: sourceLabel(loaded.source),
		resultPath: loaded.resultPath ?? null,
		ledgerPath: loaded.ledgerPath ?? null,
		evidencePath,
		verdict: loaded.result?.verdict ?? null,
		runtimeClaimLedgerCaptured: captured,
		hashChainOk,
		tipHash: events.at(-1)?.eventHash ?? "",
		requiredEventTypes: REQUIRED_RUNTIME_CLAIM_EVENT_TYPES,
		eventTypes,
		eventTypeCounts,
		missingEventTypes: REQUIRED_RUNTIME_CLAIM_EVENT_TYPES.filter((type) => !eventTypes.includes(type)),
		eventCount: events.length,
		firstSeq: events[0]?.seq ?? null,
		lastSeq: events.at(-1)?.seq ?? null,
		artifactDigests,
		claimCount: events.filter((event) => event.type === "claim").length,
		validationCount: events.filter((event) => event.type === "validation").length,
		challengeCount: events.filter((event) => event.type === "challenge").length,
		resolutionCount: events.filter((event) => event.type === "resolution").length,
	};
}

export function normalizeRuntimeClaimLedgerToStrictInput(root, loaded, options = {}) {
	if (loaded?.status !== "loaded") return { ok: false, status: loaded?.status ?? "missing_runtime_artifact", reason: loaded?.reason ?? "runtime claim ledger not loaded" };
	const outDir = options.outDir ?? join(root, ".repi-harness", "evidence", "runtime-claim-ledger", "adapter-preview");
	mkdirSync(outDir, { recursive: true });
	const source = sourceLabel(loaded.source);
	const evidencePath = relPath(root, join(outDir, `${source.replace(/[^a-zA-Z0-9_.-]+/g, "-")}-evidence.json`));
	const summary = evidenceSummary(root, loaded, evidencePath);
	writeFileSync(resolvePath(root, evidencePath), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
	const artifactId = `${source}:runtime-evidence`;
	const claimId = `${source}.runtime_claim_ledger_captured`;
	const kind = summary.runtimeClaimLedgerCaptured ? "proven" : "gap";
	const ledger = [];
	appendStrictEvent(ledger, { type: "artifact_handoff", artifactId, family: "runtime_claim_ledger", tier: "runtime_artifact", path: evidencePath, exists: true, bytes: statSync(resolvePath(root, evidencePath)).size, sha256: sha256(readFileSync(resolvePath(root, evidencePath))) });
	appendStrictEvent(ledger, { type: "claim", claimId, role: "mapper", scope: source, kind, required: true, statement: summary.runtimeClaimLedgerCaptured ? `${source} runtime ClaimLedgerEventV1 rows are hash-chain valid and complete.` : `${source} runtime claim ledger is not promotable.`, evidenceRefs: [{ artifactId, query: "runtimeClaimLedgerCaptured", op: "==", value: true }, { artifactId, query: "hashChainOk", op: "==", value: true }] });
	appendStrictEvent(ledger, { type: "validation", claimId, role: "verifier", result: summary.runtimeClaimLedgerCaptured ? "pass" : "fail", checks: { hashChainOk: summary.hashChainOk, requiredEventTypesCovered: summary.missingEventTypes.length === 0, eventCount: summary.eventCount }, evidenceRefs: [{ artifactId, query: "eventCount", op: ">", value: 0 }] });
	appendStrictEvent(ledger, { type: "challenge", claimId, role: "adversary", scope: source, challenge: summary.runtimeClaimLedgerCaptured ? "strict adversarial check confirms no runtime claim-ledger promotion gap for this source" : "do not promote runtime claim ledger until hash-chain and event coverage pass", evidenceRefs: [{ artifactId, query: "runtimeClaimLedgerCaptured", op: "==", value: summary.runtimeClaimLedgerCaptured }] });
	appendStrictEvent(ledger, { type: "resolution", claimIds: [claimId], role: "synthesizer", resolution: summary.runtimeClaimLedgerCaptured ? "runtime claim-ledger source may promote after strict validator pass" : "promotion blocked; preserve missing/gap and route to repair queue", evidenceRefs: [{ artifactId, query: "eventCount", op: ">", value: 0 }] });
	const strictInput = {
		kind: "pi-recon-runtime-claim-ledger-adapted-input",
		version: 1,
		generatedAt: new Date().toISOString(),
		source,
		contract: roleContract(`runtime-claim-ledger/${source}/${new Date().toISOString()}`),
		ledger,
		gate: { artifactPathsExist: true, artifactHashesBound: true, claimLedgerPresent: true, requiredPlatformClaimsValidated: summary.runtimeClaimLedgerCaptured, orchestrationClaimsValidated: summary.runtimeClaimLedgerCaptured, orchestrationSeparatedFromPlatform: true, antiSelfDelusion: true },
		scores: {
			orchestration: { score: summary.runtimeClaimLedgerCaptured ? 100 : 50, passed: summary.runtimeClaimLedgerCaptured ? 1 : 0, total: 1 },
			platformRequired: { score: summary.runtimeClaimLedgerCaptured ? 100 : 0, passedWeight: summary.runtimeClaimLedgerCaptured ? 1 : 0, maxWeight: 1, total: 1, passed: summary.runtimeClaimLedgerCaptured ? 1 : 0 },
			platformAll: { score: summary.runtimeClaimLedgerCaptured ? 100 : 0, passedWeight: summary.runtimeClaimLedgerCaptured ? 1 : 0, maxWeight: 1, total: 1, passed: summary.runtimeClaimLedgerCaptured ? 1 : 0 },
		},
		claims: { platform: [{ claimId, scope: source, gate: "runtimeClaimLedgerCaptured", required: true, kind }], orchestration: [] },
		runtimeSource: summary,
	};
	return { ok: true, status: "adapted", evidencePath, summary, strictInput };
}

export function buildRuntimeClaimLedgerAdapterFixture(root, outDir) {
	mkdirSync(outDir, { recursive: true });
	const events = [];
	for (const type of REQUIRED_RUNTIME_CLAIM_EVENT_TYPES) appendStrictEvent(events, { type, claimId: "adapter-fixture.runtime_claim", role: type === "validation" ? "verifier" : type === "challenge" ? "adversary" : type === "resolution" ? "synthesizer" : "mapper", scope: "adapter-fixture", kind: type === "claim" ? "proven" : undefined, statement: type === "claim" ? "adapter fixture covers runtime claim ledger event types" : undefined, result: type === "validation" ? "pass" : undefined, checks: type === "validation" ? { fixture: true } : undefined, claimIds: type === "resolution" ? ["adapter-fixture.runtime_claim"] : undefined, evidenceRefs: [] });
	const ledgerPath = relPath(root, join(outDir, "adapter-fixture-runtime-ledger.jsonl"));
	writeFileSync(resolvePath(root, ledgerPath), `${events.map((event) => JSON.stringify(event)).join("\n")}\n`, "utf8");
	return { source: "adapterFixture", status: "loaded", ledgerPath, result: { verdict: "adapter-fixture-pass" }, events };
}

function printHelp() {
	console.log("Usage: node scripts/reverse-agent/runtime-claim-ledger-adapter.mjs [root] [--json] [--source agentDogfood|reSwarm|compoundFrontier|adapterFixture] [--out-dir <dir>");
}

function main(argv) {
	if (argv.includes("--help") || argv.includes("-h")) return printHelp();
	const rootArg = argv.find((arg, index) => !arg.startsWith("-") && argv[index - 1] !== "--source" && argv[index - 1] !== "--out-dir");
	const root = resolve(rootArg ?? process.cwd());
	const source = argv.includes("--source") ? argv[argv.indexOf("--source") + 1] : "compoundFrontier";
	const outDir = resolve(root, argv.includes("--out-dir") ? argv[argv.indexOf("--out-dir") + 1] : join(".repi-harness", "evidence", "runtime-claim-ledger", "adapter-cli"));
	const loaded = source === "adapterFixture" ? buildRuntimeClaimLedgerAdapterFixture(root, outDir) : loadRuntimeClaimLedgerSource(root, source);
	const adapted = normalizeRuntimeClaimLedgerToStrictInput(root, loaded, { outDir });
	const result = { kind: "pi-recon-runtime-claim-ledger-adapter", generatedAt: new Date().toISOString(), root, loaded, adapted };
	if (argv.includes("--json")) console.log(JSON.stringify(result, null, 2));
	else if (adapted.ok) console.log(JSON.stringify(adapted.strictInput, null, 2));
	else console.error(JSON.stringify(result, null, 2));
	if (!adapted.ok) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main(process.argv.slice(2));

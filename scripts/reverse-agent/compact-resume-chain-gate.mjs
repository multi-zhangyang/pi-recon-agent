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

const FIXTURE_PATH = "fixtures/reverse-agent/compact-resume-chain.fixture.json";
const HASH_OMIT = new Set(["contextSha256", "exactResumeVerification", "resumedFromContextPath"]);
const ALLOWED_TRANSITIONS = new Map([
	["queued", new Set(["running", "blocked", "exhausted"])],
	["running", new Set(["done", "blocked", "exhausted"])],
	["blocked", new Set(["running", "exhausted"])],
	["done", new Set([])],
	["exhausted", new Set([])],
]);

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function readText(path) {
	return readFileSync(join(root, path), "utf8");
}

function readJson(path) {
	return JSON.parse(readText(path));
}

function contextPayload(value) {
	if (Array.isArray(value)) return value.map(contextPayload);
	if (value && typeof value === "object") {
		return Object.fromEntries(
			Object.entries(value)
				.filter(([key]) => !HASH_OMIT.has(key))
				.map(([key, item]) => [key, contextPayload(item)]),
		);
	}
	return value;
}

function contextSha(pack) {
	return sha256(JSON.stringify(contextPayload(pack)));
}

function artifactMap(fixture) {
	return new Map((fixture.artifacts ?? []).map((artifact) => [artifact.path, artifact]));
}

function verifyContextPack(pack, fixture, options = {}) {
	const blocked = [];
	const warnings = [];
	if (!pack || typeof pack !== "object") return { status: "blocked", blocked: ["context pack missing"], warnings };
	if (pack.schemaVersion !== 2) blocked.push("schemaVersion must be 2");
	const actualHash = contextSha(pack);
	if (!pack.contextSha256) blocked.push("contextSha256 missing");
	else if (pack.contextSha256 !== actualHash) blocked.push("contextSha256 drift");
	if (pack.resumeContract?.contextSha256 && pack.resumeContract.contextSha256 !== pack.contextSha256) blocked.push("resumeContract contextSha256 mismatch");
	if (pack.resumeContract?.contextPath && pack.resumeContract.contextPath !== pack.contextPath) blocked.push("resumeContract contextPath mismatch");
	if (!pack.artifactHashes?.length) blocked.push("artifactHashes missing");
	const artifacts = artifactMap(fixture);
	for (const artifact of pack.artifactHashes ?? []) {
		if (!artifact.required) continue;
		const stored = artifacts.get(artifact.path);
		if (!stored) {
			blocked.push(`artifact missing: ${artifact.path}`);
			continue;
		}
		const current = stored.sha256 ?? sha256(stored.content ?? "");
		if (artifact.sha256 !== current) blocked.push(`artifact hash drift: ${artifact.path}`);
	}
	const expectedTarget = options.target ?? fixture.expected?.target;
	if (expectedTarget && pack.scope?.target && pack.scope.target !== expectedTarget) blocked.push(`target mismatch: ${pack.scope.target} != ${expectedTarget}`);
	const expectedWorkspace = options.workspaceRoot ?? fixture.expected?.workspaceRoot;
	if (expectedWorkspace && pack.scope?.workspaceRoot && pack.scope.workspaceRoot !== expectedWorkspace) blocked.push(`workspaceRoot mismatch: ${pack.scope.workspaceRoot} != ${expectedWorkspace}`);
	const expectedBranch = options.branchId ?? fixture.expected?.branchId;
	if (expectedBranch && pack.scope?.branchId && pack.scope.branchId !== expectedBranch) blocked.push(`branch mismatch: ${pack.scope.branchId} != ${expectedBranch}`);
	if (pack.mode === "resume" || pack.resumedFromContextPath) {
		if (pack.resumeQueueStatus !== "done") blocked.push(`context resume queue not done: ${pack.resumeQueueStatus ?? "missing"}`);
		if (pack.closure?.status !== "closed") blocked.push(`context resume closure not closed: ${pack.closure?.status ?? "missing"}`);
	}
	return { status: blocked.length ? "blocked" : "pass", blocked, warnings, actualHash };
}

function verifyLedger(rows) {
	const blocked = [];
	let previousText = "";
	const seenIdempotency = new Set();
	for (const [index, row] of (rows ?? []).entries()) {
		const expectedPrevHash = previousText.trim() ? sha256(previousText) : "0".repeat(64);
		if (row.prevHash !== expectedPrevHash) blocked.push(`ledger prevHash drift row ${index + 1}`);
		const expectedEntryHash = sha256(`${expectedPrevHash}\n${row.ts}\ncontext-pack`);
		if (row.entryHash !== expectedEntryHash) blocked.push(`ledger entryHash drift row ${index + 1}`);
		if (seenIdempotency.has(row.idempotencyKey)) blocked.push(`duplicate idempotencyKey row ${index + 1}: ${row.idempotencyKey}`);
		seenIdempotency.add(row.idempotencyKey);
		previousText += `${JSON.stringify(row)}\n`;
	}
	return { status: blocked.length ? "fail" : "pass", blocked, rows: rows?.length ?? 0 };
}

function verifyTransitions(transitions, finalState) {
	const blocked = [];
	let current = transitions?.[0]?.from;
	if (current !== "queued") blocked.push(`resume transition must start from queued, got ${current ?? "missing"}`);
	for (const [index, transition] of (transitions ?? []).entries()) {
		if (transition.from !== current) blocked.push(`transition ${index + 1} from mismatch: expected ${current}, got ${transition.from}`);
		if (!ALLOWED_TRANSITIONS.get(transition.from)?.has(transition.to)) blocked.push(`invalid_resume_transition ${transition.from}->${transition.to}`);
		current = transition.to;
	}
	if (finalState && current !== finalState) blocked.push(`final resume state ${current} != ${finalState}`);
	return { status: blocked.length ? "fail" : "pass", blocked, finalState: current };
}

function verifyTelemetry(telemetry) {
	const blocked = [];
	if (telemetry?.kind !== "pi-recon-compaction-resume-telemetry") blocked.push("telemetry kind missing");
	if (!telemetry?.contractVerified) blocked.push("contract not verified");
	if (!telemetry?.autoResumeTriggered) blocked.push("auto resume not triggered");
	if (!telemetry?.proofLoopEntered) blocked.push("proof loop not entered");
	const queued = (telemetry?.commandStatus ?? []).filter((row) => row.status === "queued");
	const blockedRows = (telemetry?.commandStatus ?? []).filter((row) => row.status === "blocked");
	if (queued.length) blocked.push(`queued compact resume commands: ${queued.map((row) => row.command).join(", ")}`);
	if (blockedRows.length) blocked.push(`blocked compact resume commands: ${blockedRows.map((row) => row.command).join(", ")}`);
	if (!(telemetry?.commandStatus ?? []).some((row) => /^re[-_]proof[-_]loop\s+run\b/i.test(row.command) && row.status === "done")) blocked.push("proof-loop resume command not done");
	return { status: blocked.length ? "fail" : "pass", blocked };
}

function verifyNegativeCase(fixture, negative) {
	const pack = JSON.parse(JSON.stringify(fixture.contextPack));
	let ledgerRows = JSON.parse(JSON.stringify(fixture.ledgerRows ?? []));
	let transitions = JSON.parse(JSON.stringify(fixture.resumeTransitions ?? []));
	const options = { ...(fixture.expected ?? {}) };
	if (negative.mutate === "contextSha256") pack.contextSha256 = "f".repeat(64);
	if (negative.mutate === "artifactHash") pack.artifactHashes[0].sha256 = "e".repeat(64);
	if (negative.mutate === "target") options.target = `${fixture.expected.target}-other`;
	if (negative.mutate === "branch") options.branchId = `${fixture.expected.branchId}-other`;
	if (negative.mutate === "duplicateIdempotency" && ledgerRows[1]) ledgerRows[1].idempotencyKey = ledgerRows[0].idempotencyKey;
	if (negative.mutate === "invalidTransition") transitions = [{ from: "queued", to: "running" }, { from: "running", to: "queued" }];
	if (negative.mutate === "exhaustedOpenClosure") {
		pack.mode = "resume";
		pack.resumedFromContextPath = fixture.contextPack.contextPath;
		pack.resumeQueueStatus = "exhausted";
		pack.closure = { status: "open", closedAt: null, reason: "budget exhausted without closure", verifiedBy: "fixture" };
		pack.contextSha256 = contextSha(pack);
	}
	const results = [
		...verifyContextPack(pack, fixture, options).blocked,
		...verifyLedger(ledgerRows).blocked,
		...verifyTransitions(transitions, negative.finalState ?? fixture.expected?.finalResumeState).blocked,
	];
	const matched = results.some((row) => row.includes(negative.expect));
	return { id: negative.id, status: matched ? "pass" : "fail", evidence: { mutate: negative.mutate, expect: negative.expect, blocked: results } };
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
	const dir = join(root, ".repi-harness", "evidence", "compact-resume-chain", stamp);
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
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-compact-resume-chain-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH } });
	} catch (error) {
		checks.push({ id: "fixture:parse", status: "fail", evidence: { path: FIXTURE_PATH, error: String(error) } });
	}
	if (fixture) {
		const context = verifyContextPack(fixture.contextPack, fixture);
		checks.push({ id: "fixture:context-pack-exact", status: context.status === "pass" ? "pass" : "fail", evidence: context });
		const ledger = verifyLedger(fixture.ledgerRows ?? []);
		checks.push({ id: "fixture:append-only-ledger", status: ledger.status, evidence: ledger });
		const transitions = verifyTransitions(fixture.resumeTransitions ?? [], fixture.expected?.finalResumeState);
		checks.push({ id: "fixture:resume-state-machine", status: transitions.status, evidence: transitions });
		const telemetry = verifyTelemetry(fixture.autoResumeTelemetry);
		checks.push({ id: "fixture:auto-resume-telemetry", status: telemetry.status, evidence: telemetry });
		for (const negative of fixture.negativeCases ?? []) checks.push(verifyNegativeCase(fixture, negative));
	}
	checks.push(
		markerCheck("code:compact-resume-ledger-verifier", "packages/coding-agent/src/core/recon-profile.ts", ["function verifyCompactionResumeLedger", "compaction resume ledger prevHash drift", "compaction resume ledger entryHash drift", "compaction resume ledger verified"]),
		markerCheck("docs:compact-resume-chain", "README.md", ["Compact/resume chain hard-eval", "gate:compact-resume-chain", "跨 session 精确恢复"]),
		markerCheck("npm:compact-resume-chain-script", "package.json", ["gate:compact-resume-chain", "compact-resume-chain-gate.mjs"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-compact-resume-chain-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Compact/Resume Chain Gate");
		console.log(`ok: ${result.ok}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
		for (const check of checks) console.log(`- ${check.id}: ${check.status}`);
		if (failed.length) console.log(`failed: ${failed.map((check) => check.id).join(", ")}`);
	}
	if (strict && failed.length) process.exitCode = 1;
}

main();

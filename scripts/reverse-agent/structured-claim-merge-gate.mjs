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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_STRUCTURED_CLAIM_TMP === "1";
const FIXTURE_PATH = "fixtures/reverse-agent/structured-claim-merge.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function claimLedgerEventHash(event) {
	const { eventHash, ...withoutHash } = event;
	return sha256(JSON.stringify(withoutHash));
}

function claimLedgerHashChainOk(events) {
	let prevHash = "0".repeat(64);
	for (const event of events) {
		if (event.kind !== "ClaimLedgerEventV1" || event.prevHash !== prevHash) return false;
		if (event.eventHash !== claimLedgerEventHash(event)) return false;
		prevHash = event.eventHash;
	}
	return events.length > 0;
}

function markerCheck(id, path, markers) {
	if (!existsSync(join(root, path))) return { id, status: "fail", evidence: { path, exists: false } };
	const text = readText(path);
	const missing = markers.filter((marker) => !text.includes(marker));
	return { id, status: missing.length ? "fail" : "pass", evidence: { path, missing, sha256: sha256(text).slice(0, 24) } };
}

function artifactMap(fixture) {
	return new Map((fixture.artifacts ?? []).map((artifact) => [artifact.path, artifact]));
}

function jsonQuery(content, query) {
	let value = JSON.parse(content);
	const parts = String(query ?? "").replace(/^\$\.?/, "").split(".").filter(Boolean);
	for (const part of parts) {
		if (Array.isArray(value)) value = value[Number(part)];
		else value = value?.[part];
	}
	return value;
}

function valuesEqual(actual, expected, op = "==") {
	if (op === "contains") return Array.isArray(actual) ? actual.includes(expected) : String(actual ?? "").includes(String(expected));
	if (op === "includes_all") return Array.isArray(expected) && expected.every((item) => Array.isArray(actual) ? actual.includes(item) : String(actual ?? "").includes(String(item)));
	return JSON.stringify(actual) === JSON.stringify(expected);
}

function validateArtifactRef(ref, artifacts, options = {}) {
	const errors = [];
	const artifact = artifacts.get(ref.path);
	if (!artifact) return [`artifact_missing:${ref.path}`];
	const actualSha = sha256(artifact.content ?? "");
	if (ref.sha256 !== actualSha) errors.push(`artifact_sha_mismatch:${ref.path}`);
	if (!ref.jsonQuery) errors.push(`artifact_json_query_missing:${ref.path}`);
	else {
		try {
			const actual = jsonQuery(artifact.content ?? "{}", ref.jsonQuery);
			if (!valuesEqual(actual, ref.expected, ref.op)) errors.push(`artifact_json_query_mismatch:${ref.path}:${ref.jsonQuery}`);
		} catch (error) {
			errors.push(`artifact_json_query_error:${ref.path}:${String(error)}`);
		}
	}
	if (options.requireVerifier !== false && ref.verifierPass !== true) errors.push(`artifact_verifier_not_pass:${ref.path}`);
	return errors;
}

function validateClaimRows(merge, artifacts) {
	const errors = [];
	for (const claim of merge.claimRows ?? []) {
		if (!claim.claimId) errors.push("claim.claimId_missing");
		if (!claim.mergeKey) errors.push(`${claim.claimId}.mergeKey_missing`);
		if (!claim.artifactRefs?.length) errors.push(`${claim.claimId}.artifactRefs_missing`);
		for (const ref of claim.artifactRefs ?? []) errors.push(...validateArtifactRef(ref, artifacts, { requireVerifier: claim.status === "proven" }).map((error) => `${claim.claimId}.${error}`));
		for (const challenge of claim.challenges ?? []) {
			if (challenge.status !== "resolved") errors.push(`${claim.claimId}.unresolved_adversary_challenge:${challenge.challengeId}`);
		}
		if (claim.status === "proven" && !(claim.artifactRefs ?? []).some((ref) => ref.verifierPass === true)) errors.push(`${claim.claimId}.proven_without_verifier_pass`);
	}
	return errors;
}

function validateConflicts(merge) {
	const errors = [];
	const claims = new Map((merge.claimRows ?? []).map((claim) => [claim.claimId, claim]));
	const conflictsByClaim = new Map();
	for (const conflict of merge.conflictTable ?? []) {
		if ((conflict.claimIds ?? []).length < 2) errors.push(`${conflict.conflictId}.too_few_claims`);
		if (conflict.status !== "resolved") errors.push(`${conflict.conflictId}.unresolved_conflict`);
		if (!conflict.winnerClaimId || !claims.has(conflict.winnerClaimId)) errors.push(`${conflict.conflictId}.missing_winner`);
		if (!conflict.winningEvidenceRefs?.length) errors.push(`${conflict.conflictId}.missing_winning_evidence`);
		if (!conflict.resolutionReason) errors.push(`${conflict.conflictId}.missing_resolution_reason`);
		for (const claimId of conflict.claimIds ?? []) {
			const rows = conflictsByClaim.get(claimId) ?? [];
			rows.push(conflict);
			conflictsByClaim.set(claimId, rows);
		}
		for (const loser of (conflict.claimIds ?? []).filter((id) => id !== conflict.winnerClaimId)) {
			if (!(conflict.downgradeLosers ?? []).includes(loser)) errors.push(`${conflict.conflictId}.loser_not_downgraded:${loser}`);
		}
	}
	return { errors, conflictsByClaim };
}

function validatePromotionGate(merge, artifacts, conflictsByClaim) {
	const errors = [];
	const claims = new Map((merge.claimRows ?? []).map((claim) => [claim.claimId, claim]));
	for (const finalClaim of merge.promotionGate?.finalClaims ?? []) {
		const claim = claims.get(finalClaim.claimId);
		if (!claim) {
			errors.push(`final_claim_missing:${finalClaim.claimId}`);
			continue;
		}
		if (finalClaim.promotion !== "final_pass") errors.push(`${finalClaim.claimId}.promotion_not_final_pass`);
		if (claim.status !== "proven") errors.push(`${finalClaim.claimId}.final_pass_claim_not_proven:${claim.status}`);
		if (finalClaim.verifierPass !== true) errors.push(`${finalClaim.claimId}.final_pass_without_verifier_pass`);
		for (const challenge of claim.challenges ?? []) if (challenge.status !== "resolved") errors.push(`${finalClaim.claimId}.final_pass_unresolved_challenge:${challenge.challengeId}`);
		for (const conflict of conflictsByClaim.get(finalClaim.claimId) ?? []) {
			if (conflict.status !== "resolved") errors.push(`${finalClaim.claimId}.final_pass_unresolved_conflict:${conflict.conflictId}`);
			if (conflict.winnerClaimId !== finalClaim.claimId) errors.push(`${finalClaim.claimId}.final_pass_lost_conflict:${conflict.conflictId}`);
		}
		if (!finalClaim.artifactRefs?.length) errors.push(`${finalClaim.claimId}.final_pass_artifacts_missing`);
		for (const ref of finalClaim.artifactRefs ?? []) errors.push(...validateArtifactRef(ref, artifacts, { requireVerifier: true }).map((error) => `${finalClaim.claimId}.final_${error}`));
	}
	return errors;
}

function validateMerge(fixture) {
	const artifacts = artifactMap(fixture);
	const merge = fixture.structuredClaimMerge;
	const claimErrors = validateClaimRows(merge, artifacts);
	const conflict = validateConflicts(merge);
	const promotionErrors = validatePromotionGate(merge, artifacts, conflict.conflictsByClaim);
	const errors = [...claimErrors, ...conflict.errors, ...promotionErrors];
	return { status: errors.length ? "fail" : "pass", errors };
}

function mutateFixture(fixture, negative) {
	const clone = JSON.parse(JSON.stringify(fixture));
	const merge = clone.structuredClaimMerge;
	if (negative.mutate === "missingArtifactSha") merge.claimRows[0].artifactRefs[0].sha256 = "e".repeat(64);
	if (negative.mutate === "verifierFail") merge.promotionGate.finalClaims[0].verifierPass = false;
	if (negative.mutate === "unresolvedChallenge") merge.claimRows[0].challenges[0].status = "open";
	if (negative.mutate === "unresolvedConflict") merge.conflictTable[0].status = "unresolved";
	if (negative.mutate === "finalGapPromoted") {
		merge.claimRows.find((claim) => claim.claimId === "claim-authz-weak").status = "gap";
		merge.promotionGate.finalClaims = [{ ...merge.promotionGate.finalClaims[0], claimId: "claim-authz-weak" }];
	}
	if (negative.mutate === "jsonQueryMismatch") merge.claimRows[0].artifactRefs[0].expected = "wrong";
	if (negative.mutate === "missingWinnerEvidence") merge.conflictTable[0].winningEvidenceRefs = [];
	return clone;
}

function checkExpected(result, expected = {}) {
	const errors = [];
	for (const needle of expected.mustHaveErrors ?? []) if (!result.errors.some((error) => error.includes(needle))) errors.push(`missing expected error ${needle}`);
	for (const needle of expected.mustNotHaveErrors ?? []) if (result.errors.some((error) => error.includes(needle))) errors.push(`unexpected error ${needle}`);
	return errors;
}

function negativeCase(fixture, negative) {
	const result = validateMerge(mutateFixture(fixture, negative));
	const errors = checkExpected(result, negative.expected ?? {});
	return { id: `negative-${negative.id}`, status: errors.length ? "fail" : "pass", evidence: { validation: result, errors } };
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
process.env.REPI_SESSION_ID = "structured-claim-merge-live";
process.env.REPI_BRANCH_ID = "structured-claim-merge-branch";
process.chdir(workspace);
const tools = new Map();
const fakePi = {
  registerCommand() {},
  registerTool(tool) { tools.set(tool.name, tool); },
  on() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {},
  exec: async (cmd) => ({ code: 0, stdout: ["ok", "command=" + cmd, "artifact=/tmp/repi-structured-claim-proof.json", "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "verification=pass"].join("\\n"), stderr: "", killed: false })
};
createReconExtensionFactory()(fakePi);
const swarm = tools.get("re_swarm");
if (!swarm) throw new Error("missing re_swarm tool");
async function main() {
  const result = await swarm.execute("structured-claim-live", { action: "run", target: "local-structured-claim-probe", task: "validate structured claim merge live wiring", maxWorkers: 1, maxCommands: 1 });
  const swarmArtifactPath = result.details?.path;
  const structuredClaimMergePath = swarmArtifactPath ? swarmArtifactPath.replace(new RegExp("\\.md$", "i"), "-structured-claim-merge.json") : undefined;
  const claimLedgerPath = swarmArtifactPath ? swarmArtifactPath.replace(new RegExp("\\.md$", "i"), "-claim-ledger.jsonl") : undefined;
  const structuredClaimMerge = structuredClaimMergePath && existsSync(structuredClaimMergePath) ? JSON.parse(readFileSync(structuredClaimMergePath, "utf8")) : undefined;
  const claimLedger = claimLedgerPath && existsSync(claimLedgerPath) ? readFileSync(claimLedgerPath, "utf8").trim().split(new RegExp("\\r?\\n")).filter(Boolean).map((line) => JSON.parse(line)) : [];
  writeFileSync(outPath, JSON.stringify({ swarmArtifactPath, structuredClaimMergePath, claimLedgerPath, structuredClaimMerge, claimLedger, text: result.content?.[0]?.text ?? "" }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}

function runRuntimeProbe(tempRoot) {
	const probePath = join(tempRoot, "structured-claim-merge-live-probe.ts");
	const outPath = join(tempRoot, "probe-result.json");
	writeRuntimeProbe(probePath, outPath, tempRoot);
	const tsx = join(root, "node_modules", ".bin", "tsx");
	const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], { cwd: root, env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1", REPI_REPO_ROOT: root }, encoding: "utf8", maxBuffer: 30 * 1024 * 1024 });
	return { ...result, outPath, probePath };
}

function validateRuntimeProbe(probeData) {
	const merge = probeData.structuredClaimMerge;
	const ledger = probeData.claimLedger ?? [];
	const types = new Set(ledger.map((event) => event.type));
	const finalClaims = merge?.promotionGate?.finalClaims ?? [];
	const blockedClaims = merge?.promotionGate?.blockedClaims ?? [];
	const errors = [];
	if (merge?.kind !== "StructuredClaimMergeV1") errors.push("runtime_structured_merge_missing");
	if (!probeData.structuredClaimMergePath || !probeData.structuredClaimMergePath.endsWith("-structured-claim-merge.json")) errors.push("runtime_structured_merge_path_missing");
	if (!claimLedgerHashChainOk(ledger)) errors.push("runtime_claim_ledger_hash_chain_invalid");
	for (const type of ["artifact_handoff", "claim", "validation", "challenge", "resolution"]) if (!types.has(type)) errors.push(`runtime_claim_ledger_missing_${type}`);
	if (!Array.isArray(merge?.claimRows) || merge.claimRows.length < 2) errors.push("runtime_claim_rows_too_few");
	const runtimeConflicts = merge?.conflictTable ?? [];
	if (!runtimeConflicts.length) errors.push("runtime_conflict_table_missing");
	for (const conflict of runtimeConflicts) {
		if (conflict.status !== "resolved") errors.push(`runtime_conflict_unresolved:${conflict.conflictId}`);
		if (!conflict.winnerClaimId) errors.push(`runtime_conflict_winner_missing:${conflict.conflictId}`);
		if (!conflict.winningEvidenceRefs?.length) errors.push(`runtime_conflict_winning_evidence_missing:${conflict.conflictId}`);
		if (!conflict.downgradeLosers?.length) errors.push(`runtime_conflict_loser_downgrade_missing:${conflict.conflictId}`);
		if (!String(conflict.resolutionReason ?? "").includes("structured_conflict_arbitration_live_wiring")) errors.push(`runtime_conflict_resolution_marker_missing:${conflict.conflictId}`);
	}
	if (!finalClaims.length) errors.push("runtime_final_claim_missing");
	if (!blockedClaims.length) errors.push("runtime_blocked_claim_missing");
	const loserIds = new Set(runtimeConflicts.flatMap((conflict) => conflict.downgradeLosers ?? []));
	for (const finalClaim of finalClaims) if (loserIds.has(finalClaim.claimId)) errors.push(`runtime_loser_promoted:${finalClaim.claimId}`);
	for (const finalClaim of finalClaims) {
		if (finalClaim.verifierPass !== true) errors.push(`runtime_final_without_verifier:${finalClaim.claimId}`);
		if (!finalClaim.artifactRefs?.length) errors.push(`runtime_final_without_artifacts:${finalClaim.claimId}`);
		for (const ref of finalClaim.artifactRefs ?? []) {
			if (!ref.sha256) errors.push(`runtime_final_artifact_sha_missing:${finalClaim.claimId}`);
			if (!ref.jsonQuery) errors.push(`runtime_final_json_query_missing:${finalClaim.claimId}`);
		}
	}
	if (!String(probeData.text ?? "").includes("structured_claim_merge:")) errors.push("runtime_output_missing_structured_claim_merge_section");
	if (!String(probeData.text ?? "").includes("- status=blocked")) errors.push("runtime_output_missing_blocked_status");
	for (const policy of ["final_pass_requires_json_query", "unresolved_adversary_challenge_blocks_final", "artifact_sha256_required"]) {
		if (!(merge?.promotionGate?.policies ?? []).includes(policy)) errors.push(`runtime_policy_missing:${policy}`);
	}
	return errors;
}

function writeEvidenceFile(result) {
	if (!writeEvidence) return undefined;
	const stamp = result.generatedAt.replace(/[:.]/g, "-");
	const dir = join(root, ".repi-harness", "evidence", "structured-claim-merge", stamp);
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
		checks.push({ id: "fixture:parse", status: fixture.kind === "repi-structured-claim-merge-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH } });
	} catch (error) {
		checks.push({ id: "fixture:parse", status: "fail", evidence: { path: FIXTURE_PATH, error: String(error) } });
	}
	if (fixture) {
		const validation = validateMerge(fixture);
		const expectedErrors = checkExpected(validation, fixture.expected ?? {});
		checks.push({ id: "fixture:structured-merge-contract", status: validation.status === "pass" && expectedErrors.length === 0 ? "pass" : "fail", evidence: { validation, expectedErrors } });
		for (const negative of fixture.negativeCases ?? []) checks.push(negativeCase(fixture, negative));
	}
	const tempRoot = mkdtempSync(join(tmpdir(), "repi-structured-claim-merge-"));
	try {
		const probe = runRuntimeProbe(tempRoot);
		checks.push({ id: "runtime:re-swarm-structured-merge-exit", status: probe.status === 0 ? "pass" : "fail", evidence: { code: probe.status, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) } });
		if (probe.status === 0 && existsSync(probe.outPath)) {
			const probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
			const runtimeErrors = validateRuntimeProbe(probeData);
			checks.push({ id: "runtime:structured-claim-live-wiring", status: runtimeErrors.length ? "fail" : "pass", evidence: { errors: runtimeErrors, swarmArtifactPath: probeData.swarmArtifactPath, structuredClaimMergePath: probeData.structuredClaimMergePath, claimRows: probeData.structuredClaimMerge?.claimRows?.length ?? 0, finalClaims: probeData.structuredClaimMerge?.promotionGate?.finalClaims?.length ?? 0, blockedClaims: probeData.structuredClaimMerge?.promotionGate?.blockedClaims?.length ?? 0, claimLedgerEvents: probeData.claimLedger?.length ?? 0 } });
		} else {
			checks.push({ id: "runtime:structured-claim-live-wiring", status: "fail", evidence: { error: "probe output missing" } });
		}
	} finally {
		if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
	}
	checks.push(
		markerCheck("code:structured-claim-merge", "packages/coding-agent/src/core/recon-profile.ts", ["type StructuredClaimMergeV1", "function claimPromotionEvidenceContract", "function verifyStructuredClaimMergePromotion", "function buildStructuredClaimMergeFromSwarm", "function resolveStructuredClaimConflict", "function structuredClaimConflictScore", "structured_conflict_arbitration_live_wiring", "function structuredClaimMergeGateFromSwarm", "status=blocked_by_structured_claim_merge", "structured claim merge blocks final claim", "final_pass_requires_json_query", "unresolved_adversary_challenge_blocks_final"]),
		markerCheck("schema:structured-claim-merge", "schemas/reverse-agent/structured-claim-merge.schema.json", ["StructuredClaimMergeV1", "strict_final_claim_promotion", "final_pass_requires_json_query", "unresolved_adversary_challenge_blocks_final"]),
		markerCheck("docs:structured-claim-merge", "README.md", ["Structured claim merge", "gate:structured-claim-merge", "final_pass_requires_json_query", "unresolved_adversary_challenge_blocks_final", "runtime:structured-claim-live-wiring", "structured_conflict_arbitration_live_wiring"]),
		markerCheck("npm:structured-claim-merge-script", "package.json", ["gate:structured-claim-merge", "structured-claim-merge-gate.mjs"]),
	);
	const failed = checks.filter((check) => check.status !== "pass");
	const result = { kind: "repi-structured-claim-merge-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
	const evidencePath = writeEvidenceFile(result);
	if (evidencePath) result.evidencePath = evidencePath;
	if (json) console.log(JSON.stringify(result, null, 2));
	else {
		console.log("# REPI Structured Claim Merge Gate");
		console.log(`ok: ${result.ok}`);
		if (evidencePath) console.log(`evidence: ${evidencePath}`);
		for (const check of checks) console.log(`- ${check.id}: ${check.status}`);
		if (failed.length) console.log(`failed: ${failed.map((check) => check.id).join(", ")}`);
	}
	if (strict && failed.length) process.exitCode = 1;
}

main();

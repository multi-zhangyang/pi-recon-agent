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
const SCHEMA_PATH = "schemas/reverse-agent/agent-dogfood-structured-claims.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/agent-dogfood-structured-claims.fixture.json";
const REQUIRED_GATES = [
  "AgentDogfoodStructuredClaimMergeGateV1",
  "agent_dogfood_structured_claim_merge",
  "narrative_only_observation_never_promotes",
  "final_pass_requires_json_query",
  "final_pass_requires_verifier",
  "unresolved_challenge_blocks_final",
  "claim_ledger_events_reference_structured_claims",
  "runtime_manifest_artifact_ref_required",
];
const REQUIRED_NEGATIVE_CASES = [
  "narrative-only-final-pass",
  "missing-json-query",
  "verifier-false-final-pass",
  "unresolved-challenge-final-pass",
  "missing-runtime-manifest-artifact-ref",
];
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const check = (id, ok, evidence = {}) => ({ id, status: ok ? "pass" : "fail", evidence });
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));
const clone = (value) => JSON.parse(JSON.stringify(value));

function markerCheck(id, path, markers) {
  const full = join(root, path);
  if (!existsSync(full)) return check(id, false, { path, exists: false });
  const body = readFileSync(full, "utf8");
  const missing = markers.filter((marker) => !body.includes(marker));
  return check(id, missing.length === 0, { path, missing, sha256: sha256(body).slice(0, 24) });
}

function claimById(merge, claimId) {
  return (merge.claimRows || []).find((row) => row.claimId === claimId);
}

function validateStructuredClaims(pkg) {
  const merge = pkg.structuredClaimMerge;
  const errors = [];
  if (merge?.kind !== "StructuredClaimMergeV1") errors.push("merge.kind");
  if (!Array.isArray(merge?.claimRows) || merge.claimRows.length < 1) errors.push("claimRows.empty");
  for (const row of merge?.claimRows || []) {
    if (!row.claimId) errors.push("claim.claimId_missing");
    if (!row.workerId) errors.push(`${row.claimId}.workerId_missing`);
    if (!row.mergeKey) errors.push(`${row.claimId}.mergeKey_missing`);
    if (!row.promotionBoundary) errors.push(`${row.claimId}.promotionBoundary_missing`);
    if (row.status === "proven" && !row.artifactRefs?.length) errors.push(`${row.claimId}.runtime_manifest_artifact_ref_missing`);
    for (const ref of row.artifactRefs || []) {
      if (!ref.path) errors.push(`${row.claimId}.artifact.path_missing`);
      if (!/^[a-f0-9]{32,64}$/.test(ref.sha256 || "")) errors.push(`${row.claimId}.artifact.sha256_invalid`);
      if (!ref.jsonQuery) errors.push(`${row.claimId}.artifact.jsonQuery_missing`);
      if (row.status === "proven" && ref.verifierPass !== true) errors.push(`${row.claimId}.artifact.verifier_not_pass`);
    }
  }
  const policies = new Set(merge?.promotionGate?.policies || []);
  for (const policy of ["final_pass_requires_json_query", "final_pass_requires_verifier", "unresolved_adversary_challenge_blocks_final", "narrative_only_observation_never_promotes", "agent_dogfood_structured_claim_merge"]) {
    if (!policies.has(policy)) errors.push(`policy_missing:${policy}`);
  }
  for (const finalClaim of merge?.promotionGate?.finalClaims || []) {
    const row = claimById(merge, finalClaim.claimId);
    if (!row) {
      errors.push(`final_claim_missing:${finalClaim.claimId}`);
      continue;
    }
    if (row.status !== "proven") errors.push(`${finalClaim.claimId}.final_pass_claim_not_proven:${row.status}`);
    if (finalClaim.verifierPass !== true) errors.push(`${finalClaim.claimId}.final_pass_without_verifier_pass`);
    if (!finalClaim.artifactRefs?.length) errors.push(`${finalClaim.claimId}.final_pass_artifacts_missing`);
    for (const ref of finalClaim.artifactRefs || []) {
      if (!ref.jsonQuery) errors.push(`${finalClaim.claimId}.final_artifact_json_query_missing`);
      if (ref.verifierPass !== true) errors.push(`${finalClaim.claimId}.final_artifact_verifier_not_pass`);
      if (!/^[a-f0-9]{32,64}$/.test(ref.sha256 || "")) errors.push(`${finalClaim.claimId}.final_artifact_sha256_invalid`);
    }
    for (const challenge of row.challenges || []) {
      if (challenge.status !== "resolved") errors.push(`${finalClaim.claimId}.final_pass_unresolved_challenge:${challenge.challengeId}`);
    }
  }
  if (pkg.claimLedgerEvent) {
    if (!pkg.claimLedgerEvent.structuredClaimRef) errors.push("claimLedgerEvent.structuredClaimRef_missing");
    if (!pkg.claimLedgerEvent.structuredClaimMergePath) errors.push("claimLedgerEvent.structuredClaimMergePath_missing");
  }
  return { ok: errors.length === 0, errors };
}

function mutatePackage(pkg, id) {
  const row = clone(pkg);
  const merge = row.structuredClaimMerge;
  if (id === "narrative-only-final-pass") merge.promotionGate.finalClaims[0].artifactRefs = [];
  if (id === "missing-json-query") delete merge.promotionGate.finalClaims[0].artifactRefs[0].jsonQuery;
  if (id === "verifier-false-final-pass") merge.promotionGate.finalClaims[0].verifierPass = false;
  if (id === "unresolved-challenge-final-pass") {
    merge.promotionGate.finalClaims = [{ ...merge.promotionGate.finalClaims[0], claimId: "agent-dogfood.mapper.strict_run", artifactRefs: merge.claimRows[1].artifactRefs }];
  }
  if (id === "missing-runtime-manifest-artifact-ref") merge.claimRows[0].artifactRefs = [];
  return row;
}

function validateFixture(fixture) {
  const gates = new Set(fixture.requiredGates || []);
  const negativeIds = new Set((fixture.negativeCases || []).map((row) => row.id));
  const pkg = { structuredClaimMerge: fixture.structuredClaimMerge, claimLedgerEvent: fixture.claimLedgerEvent };
  const positive = validateStructuredClaims(pkg);
  const negativeResults = REQUIRED_NEGATIVE_CASES.map((id) => {
    const result = validateStructuredClaims(mutatePackage(pkg, id));
    return { id, rejected: !result.ok, errors: result.errors };
  });
  return {
    missingGates: REQUIRED_GATES.filter((gate) => !gates.has(gate)),
    missingNegativeCases: REQUIRED_NEGATIVE_CASES.filter((id) => !negativeIds.has(id)),
    positive,
    negativeResults,
  };
}

function main() {
  const checks = [];
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", Boolean(schema?.$defs?.AgentDogfoodStructuredClaimMergeGateV1 && schema?.$defs?.AgentDogfoodStructuredClaimMergeV1), { path: SCHEMA_PATH }));
    const fixtureEval = validateFixture(fixture);
    checks.push(check("fixture:coverage", fixtureEval.missingGates.length === 0 && fixtureEval.missingNegativeCases.length === 0, fixtureEval));
    checks.push(check("fixture:positive-structured-claims", fixtureEval.positive.ok, fixtureEval.positive));
    checks.push(check("fixture:negative-structured-claims", fixtureEval.negativeResults.every((row) => row.rejected), { negativeResults: fixtureEval.negativeResults }));
    checks.push(markerCheck("runtime:agent-dogfood-structured-claim-writer", "bench/recon-remote/agent-dogfood/parallel-run.mjs", [
      "StructuredClaimMergeV1",
      "structuredClaimMergePath",
      "structuredClaimRows",
      "structuredClaimRef",
      "narrative_only_observation_never_promotes",
      "artifactRefForJsonPath",
      "structuredClaimMergeCaptured",
    ]));
    checks.push(markerCheck("harness:agent-dogfood-structured-claims", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:agent-dogfood-structured-claims", "AgentDogfoodStructuredClaimMergeGateV1", "child:gate:agent-dogfood-structured-claims"]));
    checks.push(markerCheck("autonomy:agent-dogfood-structured-claims", "scripts/reverse-agent/autonomy-control-plane.mjs", ["agent_dogfood_structured_claim_merge_gate", "AgentDogfoodStructuredClaimMergeGateV1", "narrative_only_observation_never_promotes"]));
    checks.push(markerCheck("npm:agent-dogfood-structured-claims", "package.json", ["gate:agent-dogfood-structured-claims", "agent-dogfood-structured-claims-gate.mjs"]));
    checks.push(markerCheck("docs:agent-dogfood-structured-claims-readme", "README.md", ["AgentDogfoodStructuredClaimMergeGateV1", "gate:agent-dogfood-structured-claims"]));
    checks.push(markerCheck("docs:agent-dogfood-structured-claims-reverse", "docs/reverse-agent/README.md", ["AgentDogfoodStructuredClaimMergeGateV1", "gate:agent-dogfood-structured-claims"]));
    checks.push(markerCheck("docs:agent-dogfood-structured-claims-control-plane", "docs/reverse-agent/autonomous-control-plane.md", ["AgentDogfoodStructuredClaimMergeGateV1", "gate:agent-dogfood-structured-claims"]));
    checks.push(markerCheck("docs:agent-dogfood-structured-claims-recon", "packages/coding-agent/docs/recon.md", ["AgentDogfoodStructuredClaimMergeGateV1", "gate:agent-dogfood-structured-claims"]));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = { kind: "repi-agent-dogfood-structured-claims-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), AgentDogfoodStructuredClaimMergeGateV1: true, ok: failed.length === 0, root, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "agent-dogfood-structured-claims", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI AgentDogfoodStructuredClaimMergeGateV1");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
  }
  if (strict && failed.length) process.exit(1);
}
main();

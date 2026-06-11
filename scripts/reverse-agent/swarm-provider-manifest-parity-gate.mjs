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
const SCHEMA_PATH = "schemas/reverse-agent/swarm-provider-manifest-parity.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/swarm-provider-manifest-parity.fixture.json";
const REQUIRED_GATES = [
  "SwarmProviderManifestParityGateV1",
  "swarm_subagent_manifest_fields_match_provider_worker",
  "child_session_runtime_bridge_matches_provider_worker",
  "claim_refs_preserved_across_manifest_provider_merge",
  "failure_repair_refs_preserved_across_provider_worker",
  "multi_provider_workers_share_claim_failure_merge_ledger",
  "provider_worker_retry_repair_rows_bound_to_worker_manifest",
  "provider_env_refs_only",
  "runtime_artifacts_have_hashes",
  "narrative_only_provider_worker_not_promoted",
];
const REQUIRED_NEGATIVE_CASES = [
  "worker-id-mismatch",
  "claim-ref-dropped",
  "missing-runtime-hash",
  "literal-provider-secret",
  "failure-repair-unlinked",
  "single-provider-matrix",
  "shared-ledger-worker-missing",
  "retry-repair-manifest-unbound",
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

function hasHash(value) {
  return /^[a-f0-9]{64}$/.test(String(value || ""));
}

function envRef(value) {
  return typeof value === "string" && value.startsWith("$") && !/^\$?(sk-|ghp_|github_pat_)/i.test(value);
}

function validateParityPackage(pkg) {
  const errors = [];
  const report = pkg.parityReport;
  const manifest = pkg.swarmManifest;
  const childSession = pkg.childSession?.sessions?.[0];
  const provider = pkg.providerWorker;
  const sharedLedger = report?.sharedMergeLedger;
  const retryRepairBindings = report?.retryRepairBindings || [];
  if (report?.kind !== "SwarmProviderManifestParityReportV1") errors.push("parityReport.kind");
  if (report?.closureGate !== "gate:swarm-provider-manifest-parity") errors.push("parityReport.closureGate");
  const rows = report?.parityRows || [];
  if (rows.length < 2) errors.push("parityRows.minItems");
  const providerNames = new Set();
  const rowWorkerIds = new Set();
  const rowClaimRefs = new Set();
  const rowFailureRepairRefs = new Set();
  const rowByWorkerId = new Map();
  for (const row of rows) {
    if (!row.workerId) errors.push("row.workerId_missing");
    else {
      rowWorkerIds.add(row.workerId);
      rowByWorkerId.set(row.workerId, row);
    }
    if (!row.runtimeManifestFile) errors.push(`${row.workerId}.runtimeManifestFile_missing`);
    if (!hasHash(row.runtimeManifestSha256)) errors.push(`${row.workerId}.runtimeManifestSha256_missing`);
    if (!row.sessionDir) errors.push(`${row.workerId}.sessionDir_missing`);
    if (!row.providerName || !row.modelId) errors.push(`${row.workerId}.provider_missing`);
    if (row.providerName) providerNames.add(row.providerName);
    if (!row.claimRefs?.length) errors.push(`${row.workerId}.claimRefs_missing`);
    for (const claimRef of row.claimRefs || []) rowClaimRefs.add(claimRef);
    for (const failureRepairRef of row.failureRepairRefs || []) rowFailureRepairRefs.add(failureRepairRef);
    if (!hasHash(row.hashes?.stdoutSha256) || !hasHash(row.hashes?.stderrSha256) || !hasHash(row.hashes?.transcriptSha256)) errors.push(`${row.workerId}.hashes_missing`);
    if (!row.retryBudget?.signature || row.retryBudget?.exhausted === true || (row.retryBudget?.remaining ?? -1) < 0) errors.push(`${row.workerId}.retryBudget_invalid`);
    if (!row.ledgerPaths?.claimLedgerPath || !row.ledgerPaths?.failureLedgerPath || !row.ledgerPaths?.repairQueuePath) errors.push(`${row.workerId}.ledgerPaths_missing`);
    for (const [key, ok] of Object.entries(row.parityChecks || {})) if (ok !== true) errors.push(`${row.workerId}.parityCheck_failed:${key}`);
    if (row.promotionAllowed && !row.parityChecks?.providerEnvRefsOnly) errors.push(`${row.workerId}.promotion_without_env_ref`);
    if (row.promotionAllowed && row.failureRepairRefs?.length) errors.push(`${row.workerId}.failure_worker_promoted`);
  }
  if (providerNames.size < 2) errors.push("multi_provider_workers_share_claim_failure_merge_ledger.provider_count_lt_2");
  if (sharedLedger?.kind !== "SwarmProviderSharedMergeLedgerV1") errors.push("sharedMergeLedger.kind");
  if (!sharedLedger?.claimLedgerPath || !sharedLedger?.failureLedgerPath || !sharedLedger?.repairQueuePath) errors.push("sharedMergeLedger.paths_missing");
  if (!hasHash(sharedLedger?.ledgerTipSha256) || sharedLedger?.hashChain !== true) errors.push("sharedMergeLedger.hash_chain_invalid");
  for (const providerName of providerNames) if (!sharedLedger?.providerNames?.includes(providerName)) errors.push(`sharedMergeLedger.provider_missing:${providerName}`);
  for (const workerId of rowWorkerIds) if (!sharedLedger?.workerIds?.includes(workerId)) errors.push(`sharedMergeLedger.worker_missing:${workerId}`);
  for (const claimRef of rowClaimRefs) if (!sharedLedger?.claimRefs?.includes(claimRef)) errors.push(`sharedMergeLedger.claim_missing:${claimRef}`);
  for (const failureRepairRef of rowFailureRepairRefs) if (!sharedLedger?.failureRepairRefs?.includes(failureRepairRef)) errors.push(`sharedMergeLedger.failure_repair_missing:${failureRepairRef}`);

  const failureRows = rows.filter((row) => row.failureRepairRefs?.length);
  if (failureRows.length < 1) errors.push("provider_worker_retry_repair_rows_bound_to_worker_manifest.no_failure_rows");
  for (const row of failureRows) {
    const failureRefs = new Set(row.failureRepairRefs || []);
    const bindings = retryRepairBindings.filter((binding) => binding.workerId === row.workerId);
    if (bindings.length < 1) {
      errors.push(`${row.workerId}.retryRepairBinding_missing`);
      continue;
    }
    for (const binding of bindings) {
      if (binding.runtimeManifestFile !== row.runtimeManifestFile) errors.push(`${row.workerId}.retryRepairBinding.runtimeManifestFile_mismatch`);
      if (binding.runtimeManifestSha256 !== row.runtimeManifestSha256 || !hasHash(binding.runtimeManifestSha256)) errors.push(`${row.workerId}.retryRepairBinding.runtimeManifestSha256_mismatch`);
      if (binding.providerName !== row.providerName || binding.modelId !== row.modelId) errors.push(`${row.workerId}.retryRepairBinding.provider_mismatch`);
      if (binding.retrySignature !== row.retryBudget?.signature) errors.push(`${row.workerId}.retryRepairBinding.retrySignature_mismatch`);
      if (!failureRefs.has(binding.failureRef) || !failureRefs.has(binding.repairRef)) errors.push(`${row.workerId}.retryRepairBinding.failureRepairRef_mismatch`);
      if (!binding.rollbackPolicyRef || !binding.regressionGate) errors.push(`${row.workerId}.retryRepairBinding.rollback_or_regression_missing`);
    }
  }
  if (manifest && provider) {
    if (manifest.workerId !== provider.workerId) errors.push("manifest_provider.workerId_mismatch");
    if (manifest.stdoutSha256 !== provider.stdoutSha256 || manifest.stderrSha256 !== provider.stderrSha256) errors.push("manifest_provider.hash_mismatch");
    if (manifest.runtimeManifestSha256 !== provider.runtimeManifestSha256 || !hasHash(provider.runtimeManifestSha256)) errors.push("manifest_provider.runtimeManifestSha256_mismatch");
    if (!provider.claimRefs?.some((claim) => manifest.mergeKeys?.includes(provider.mergeKey) || childSession?.poolBridge?.claimRefs?.includes(claim))) errors.push("manifest_provider.claimRefs_not_preserved");
  }
  if (childSession && provider) {
    if (childSession.workerId !== provider.workerId) errors.push("child_provider.workerId_mismatch");
    if (childSession.hashes?.stdoutSha256 !== provider.stdoutSha256 || childSession.hashes?.stderrSha256 !== provider.stderrSha256 || childSession.hashes?.transcriptSha256 !== provider.transcriptSha256) errors.push("child_provider.hash_mismatch");
    if (!envRef(childSession.provider?.apiKeyRef) || !envRef(childSession.provider?.baseUrlRef)) errors.push("child_provider.env_ref_invalid");
    if (!childSession.poolBridge?.claimRefs?.some((claim) => provider.claimRefs?.includes(claim))) errors.push("child_provider.claimRefs_dropped");
  }
  if (provider) {
    if (provider.assertions?.apiKeyEnvRefOnly !== true || provider.assertions?.authorizationFromEnv !== true || provider.assertions?.noLiteralSecrets !== true) errors.push("provider.assertions.env_redaction_failed");
    if (provider.status !== "pass" && provider.assertions?.providerWorkerFailureRepairLinked !== true) errors.push("provider.failure_repair_unlinked");
  }
  return { ok: errors.length === 0, errors };
}

function mutatePackage(pkg, id) {
  const row = clone(pkg);
  if (id === "worker-id-mismatch") row.providerWorker.workerId = "other-worker";
  if (id === "claim-ref-dropped") row.providerWorker.claimRefs = [];
  if (id === "missing-runtime-hash") row.providerWorker.stdoutSha256 = "";
  if (id === "literal-provider-secret") row.childSession.sessions[0].provider.apiKeyRef = "sk-live-secret";
  if (id === "failure-repair-unlinked") row.parityReport.parityRows[1].parityChecks.failureRepairLinked = false;
  if (id === "single-provider-matrix") {
    for (const parityRow of row.parityReport.parityRows) parityRow.providerName = "parallel-openai-compatible";
    row.parityReport.sharedMergeLedger.providerNames = ["parallel-openai-compatible"];
  }
  if (id === "shared-ledger-worker-missing") row.parityReport.sharedMergeLedger.workerIds = row.parityReport.sharedMergeLedger.workerIds.filter((workerId) => workerId !== "worker-beta-anthropic-pass");
  if (id === "retry-repair-manifest-unbound") row.parityReport.retryRepairBindings[0].retrySignature = "re_swarm:other-worker";
  return row;
}

function validateFixture(fixture) {
  const gates = new Set(fixture.requiredGates || []);
  const negativeIds = new Set((fixture.negativeCases || []).map((row) => row.id));
  const positive = validateParityPackage(fixture);
  const negativeResults = REQUIRED_NEGATIVE_CASES.map((id) => {
    const result = validateParityPackage(mutatePackage(fixture, id));
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
    checks.push(check("schema:parse", Boolean(schema?.$defs?.SwarmProviderManifestParityGateV1 && schema?.$defs?.SwarmProviderManifestParityReportV1), { path: SCHEMA_PATH }));
    const fixtureEval = validateFixture(fixture);
    checks.push(check("fixture:coverage", fixtureEval.missingGates.length === 0 && fixtureEval.missingNegativeCases.length === 0, fixtureEval));
    checks.push(check("fixture:positive-parity", fixtureEval.positive.ok, fixtureEval.positive));
    checks.push(check("fixture:negative-parity", fixtureEval.negativeResults.every((row) => row.rejected), { negativeResults: fixtureEval.negativeResults }));
    checks.push(markerCheck("runtime:swarm-provider-manifest-parity-core", "packages/coding-agent/src/core/recon-profile.ts", [
      "SubagentRuntimeManifestV1",
      "WorkerChildSessionRuntimeBatchV1",
      "workerChildSessionRuntimePath",
      "workerChildSessionToWorkerRuntimePoolBridge",
      "ParallelProviderWorkerMatrixV1",
      "claimAwareProviderWorkerMerge",
    ]));
    checks.push(markerCheck("runtime:swarm-provider-manifest-parity-worker-child", "scripts/reverse-agent/worker-child-session-gate.mjs", ["runtime:worker-child-session-batch", "runtime:worker-provider-child-process-smoke", "WorkerProviderChildProcessProbeV1", "provider runtime"]));
    checks.push(markerCheck("runtime:swarm-provider-manifest-parity-provider-worker", "scripts/reverse-agent/parallel-provider-worker-matrix-gate.mjs", ["ParallelProviderWorkerMatrixV1", "runtime:parallel-provider-worker-claim-merge", "runtime:parallel-provider-worker-failure-repair", "claimAwareProviderWorkerMerge"]));
    checks.push(markerCheck("harness:swarm-provider-manifest-parity", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:swarm-provider-manifest-parity", "SwarmProviderManifestParityGateV1", "child:gate:swarm-provider-manifest-parity"]));
    checks.push(markerCheck("autonomy:swarm-provider-manifest-parity", "scripts/reverse-agent/autonomy-control-plane.mjs", ["swarm_provider_manifest_parity_gate", "SwarmProviderManifestParityGateV1", "gate:swarm-provider-manifest-parity", "SwarmProviderSharedMergeLedgerV1", "SwarmProviderRetryRepairBindingV1"]));
    checks.push(markerCheck("npm:swarm-provider-manifest-parity", "package.json", ["gate:swarm-provider-manifest-parity", "swarm-provider-manifest-parity-gate.mjs"]));
    checks.push(markerCheck("docs:swarm-provider-manifest-parity-readme", "README.md", ["SwarmProviderManifestParityGateV1", "gate:swarm-provider-manifest-parity", "multi-provider", "retry/repair"]));
    checks.push(markerCheck("docs:swarm-provider-manifest-parity-control-plane", "docs/reverse-agent/autonomous-control-plane.md", ["SwarmProviderManifestParityGateV1", "gate:swarm-provider-manifest-parity", "multi-provider", "retry/repair"]));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = { kind: "repi-swarm-provider-manifest-parity-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), SwarmProviderManifestParityGateV1: true, ok: failed.length === 0, root, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "swarm-provider-manifest-parity", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI SwarmProviderManifestParityGateV1");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
  }
  if (strict && failed.length) process.exit(1);
}
main();

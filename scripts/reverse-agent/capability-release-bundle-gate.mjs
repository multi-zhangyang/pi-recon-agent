#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/capability-release-bundle.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/capability-release-bundle.fixture.json";

const REQUIRED_GATES = [
  "release_claims_require_command_evidence",
  "release_claims_require_source_hashes",
  "independent_product_boundary_before_capability_claim",
  "autonomy_control_plane_before_capability_claim",
  "closure_readiness_before_capability_claim",
  "top_autonomous_status_explicit",
  "no_literal_secret_in_release_evidence",
  "no_narrative_only_release_promotion",
];
const REQUIRED_NEGATIVE_CASES = [
  "claim-without-command-evidence",
  "failed-command-promoted",
  "secret-leak-in-evidence",
  "top-autonomous-true-with-ready-gaps",
  "missing-source-hash",
  "narrative-only-promotion",
  "missing-bundle-sha",
];
const REQUIRED_CLAIMS = ["independent_product_boundary", "professional_control_plane", "closure_gate_readiness", "not_top_autonomous_yet"];
const SOURCE_FILES = [
  "repi",
  "package.json",
  "README.md",
  "scripts/reverse-agent/repi-top-harness.mjs",
  "scripts/reverse-agent/autonomy-control-plane.mjs",
  "scripts/reverse-agent/autonomous-closure-readiness-gate.mjs",
  "scripts/reverse-agent/capability-release-bundle-gate.mjs",
  "docs/reverse-agent/autonomous-control-plane.md",
  "packages/coding-agent/docs/recon.md",
];
const SECRET_PATTERN = /(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:proj-)?[A-Za-z0-9]{20,})/;

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const shortHash = (value) => sha256(value).slice(0, 24);
const check = (id, ok, evidence = {}) => ({ id, status: ok ? "pass" : "fail", evidence });
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));
const clone = (value) => JSON.parse(JSON.stringify(value));

function markerCheck(id, path, markers) {
  const full = join(root, path);
  if (!existsSync(full)) return check(id, false, { path, exists: false });
  const text = readFileSync(full, "utf8");
  const missing = markers.filter((marker) => !text.includes(marker));
  return check(id, missing.length === 0, { path, missing, sha256: shortHash(text) });
}

function runNodeCommand(id, args, evidenceTier) {
  const result = spawnSync(process.execPath, args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, PI_OFFLINE: "1", PI_SKIP_VERSION_CHECK: "1", REPI_SKIP_VERSION_CHECK: "1" },
    maxBuffer: 80 * 1024 * 1024,
  });
  const stdout = result.stdout || "";
  const stderr = result.stderr || "";
  return {
    id,
    command: `node ${args.join(" ")}`,
    code: result.status ?? 1,
    stdoutSha256: sha256(stdout),
    stderrSha256: sha256(stderr),
    secretFree: !SECRET_PATTERN.test(`${stdout}\n${stderr}`),
    evidenceTier,
    stdout,
    stderr,
  };
}

function publicCommand(row) {
  const { stdout, stderr, ...pub } = row;
  return pub;
}

function parseJsonCommand(row) {
  try {
    return JSON.parse(row.stdout);
  } catch {
    return null;
  }
}

function gitHead() {
  const result = spawnSync("git", ["rev-parse", "--short=12", "HEAD"], { cwd: root, encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : "unknown";
}

function sourceFileRows() {
  return SOURCE_FILES.map((path) => {
    const full = join(root, path);
    return existsSync(full)
      ? { path, exists: true, sha256: sha256(readFileSync(full)) }
      : { path, exists: false, sha256: "" };
  });
}

function bundleDigest(bundle) {
  const copy = clone(bundle);
  copy.bundleSha256 = "";
  return sha256(JSON.stringify(copy));
}

function validateReleaseBundlePackage(pkg) {
  const errors = [];
  if (pkg?.kind !== "CapabilityClaimReleaseBundleGateV1") errors.push("pkg.kind");
  if (pkg?.CapabilityClaimReleaseBundleGateV1 !== true) errors.push("pkg.CapabilityClaimReleaseBundleGateV1");
  const gates = new Set(pkg?.requiredGates || []);
  for (const gate of REQUIRED_GATES) if (!gates.has(gate)) errors.push(`requiredGate_missing:${gate}`);
  const negativeIds = new Set((pkg?.negativeCases || []).map((row) => row.id));
  for (const id of REQUIRED_NEGATIVE_CASES) if (!negativeIds.has(id)) errors.push(`negativeCase_missing:${id}`);

  const bundle = pkg?.releaseBundle;
  if (bundle?.kind !== "CapabilityClaimReleaseBundleV1") errors.push("bundle.kind");
  if (!/^[a-f0-9]{64}$/.test(String(bundle?.bundleSha256 || ""))) errors.push("bundle.bundleSha256_invalid");
  if (!Array.isArray(bundle?.sourceFiles) || bundle.sourceFiles.length < 5) errors.push("sourceFiles.minItems");
  for (const file of bundle?.sourceFiles || []) {
    if (file.exists !== true) errors.push(`${file.path || "unknown"}.exists_not_true`);
    if (!/^[a-f0-9]{64}$/.test(String(file.sha256 || ""))) errors.push(`${file.path || "unknown"}.sha256_invalid`);
  }
  const commands = new Map((bundle?.evidenceCommands || []).map((row) => [row.id, row]));
  if (commands.size < 4) errors.push("evidenceCommands.minItems");
  for (const command of bundle?.evidenceCommands || []) {
    if (command.code !== 0) errors.push(`${command.id}.code_nonzero`);
    if (command.secretFree !== true) errors.push(`${command.id}.secretFree_not_true`);
    if (!/^[a-f0-9]{64}$/.test(String(command.stdoutSha256 || ""))) errors.push(`${command.id}.stdoutSha256_invalid`);
    if (!/^[a-f0-9]{64}$/.test(String(command.stderrSha256 || ""))) errors.push(`${command.id}.stderrSha256_invalid`);
  }
  const sourceRefs = new Set((bundle?.sourceFiles || []).map((row) => row.path));
  const claims = bundle?.releaseClaims || [];
  const claimIds = new Set(claims.map((row) => row.claimId));
  for (const claimId of REQUIRED_CLAIMS) if (!claimIds.has(claimId)) errors.push(`claim_missing:${claimId}`);
  for (const claim of claims) {
    if (claim.narrativeOnly !== false) errors.push(`${claim.claimId}.narrativeOnly_not_false`);
    if (!Array.isArray(claim.evidenceCommandIds) || claim.evidenceCommandIds.length < 1) errors.push(`${claim.claimId}.evidenceCommandIds_missing`);
    for (const id of claim.evidenceCommandIds || []) {
      if (!commands.has(id)) errors.push(`${claim.claimId}.unknown_command:${id}`);
      else if (commands.get(id).code !== 0 || commands.get(id).secretFree !== true) errors.push(`${claim.claimId}.bad_command:${id}`);
    }
    if (!Array.isArray(claim.sourceFileRefs) || claim.sourceFileRefs.length < 1) errors.push(`${claim.claimId}.sourceFileRefs_missing`);
    for (const ref of claim.sourceFileRefs || []) if (!sourceRefs.has(ref)) errors.push(`${claim.claimId}.unknown_source:${ref}`);
    if (claim.claimId === "not_top_autonomous_yet" && (claim.status !== "explicit_gap" || claim.promotionAllowed !== false)) errors.push("not_top_autonomous_yet.must_be_explicit_gap");
    if (claim.claimId !== "not_top_autonomous_yet" && claim.promotionAllowed !== true) errors.push(`${claim.claimId}.promotion_not_allowed`);
  }
  if (bundle?.autonomySummary?.normalUseGuarantee !== true) errors.push("autonomySummary.normalUseGuarantee_not_true");
  if (bundle?.autonomySummary?.topAutonomousDefinition !== false) errors.push("autonomySummary.topAutonomousDefinition_not_false");
  if ((bundle?.autonomySummary?.gapCount ?? 0) < 1) errors.push("autonomySummary.gapCount_missing");
  if ((bundle?.autonomySummary?.closureGateCount ?? 0) < 1) errors.push("autonomySummary.closureGateCount_missing");
  if (bundle?.closureReadinessSummary?.failedRows !== 0) errors.push("closureReadinessSummary.failedRows_nonzero");
  if (bundle?.closureReadinessSummary?.allClosureGatesExecutable !== true) errors.push("closureReadinessSummary.allClosureGatesExecutable_not_true");
  if (bundle?.closureReadinessSummary?.allClosureGatesHarnessed !== true) errors.push("closureReadinessSummary.allClosureGatesHarnessed_not_true");
  if ((bundle?.closureReadinessSummary?.readyRows ?? 0) < 1) errors.push("closureReadinessSummary.readyRows_missing");
  if (bundle?.promotionPolicy?.mode !== "release_capability_claim_gate") errors.push("promotionPolicy.mode");
  if (bundle?.promotionPolicy?.narrativeOnlyPromotionBlocked !== true) errors.push("promotionPolicy.narrativeOnlyPromotionBlocked");
  if (bundle?.promotionPolicy?.topAutonomousClaimBlockedUntilClosed !== true) errors.push("promotionPolicy.topAutonomousClaimBlockedUntilClosed");
  if (bundle?.promotionPolicy?.requiresAllCommandsPass !== true) errors.push("promotionPolicy.requiresAllCommandsPass");
  if (bundle?.promotionPolicy?.requiresNoSecretLeak !== true) errors.push("promotionPolicy.requiresNoSecretLeak");
  return { ok: errors.length === 0, errors };
}

function mutateFixture(fixture, id) {
  const row = clone(fixture);
  const bundle = row.releaseBundle;
  if (id === "claim-without-command-evidence") bundle.releaseClaims[0].evidenceCommandIds = [];
  if (id === "failed-command-promoted") bundle.evidenceCommands[0].code = 1;
  if (id === "secret-leak-in-evidence") bundle.evidenceCommands[0].secretFree = false;
  if (id === "top-autonomous-true-with-ready-gaps") bundle.autonomySummary.topAutonomousDefinition = true;
  if (id === "missing-source-hash") bundle.sourceFiles[0].sha256 = "";
  if (id === "narrative-only-promotion") bundle.releaseClaims[1].narrativeOnly = true;
  if (id === "missing-bundle-sha") bundle.bundleSha256 = "";
  return row;
}

function buildRuntimeBundle() {
  const product = runNodeCommand("gate:repi-product", ["scripts/reverse-agent/assert-repi-product.mjs", root], "product_boundary");
  const isolation = runNodeCommand("gate:repi-isolation", ["scripts/reverse-agent/assert-repi-isolated.mjs", root], "product_boundary");
  const surface = runNodeCommand("gate:repi-product-surface", ["scripts/reverse-agent/repi-product-surface-audit.mjs", root, "--strict"], "product_boundary");
  const autonomy = runNodeCommand("gate:autonomy-control", ["scripts/reverse-agent/autonomy-control-plane.mjs", root, "--strict", "--json"], "control_plane_json");
  const closure = runNodeCommand("gate:autonomous-closure-readiness", ["scripts/reverse-agent/autonomous-closure-readiness-gate.mjs", root, "--strict", "--no-write", "--json"], "closure_gate");
  const commandRows = [product, isolation, surface, autonomy, closure];
  const publicCommands = commandRows.map(publicCommand);
  const autonomyJson = parseJsonCommand(autonomy);
  const closureJson = parseJsonCommand(closure);
  const sources = sourceFileRows();
  const bundle = {
    kind: "CapabilityClaimReleaseBundleV1",
    schemaVersion: 1,
    releaseId: `repi-release-${new Date().toISOString().replace(/[:.]/g, "-")}`,
    gitHead: gitHead(),
    sourceFiles: sources,
    evidenceCommands: publicCommands,
    releaseClaims: [
      {
        claimId: "independent_product_boundary",
        statement: "REPI owns repi only, keeps upstream pi separate, and blocks profile/update branding leakage before capability claims.",
        status: "proven",
        evidenceCommandIds: ["gate:repi-product", "gate:repi-isolation", "gate:repi-product-surface"],
        sourceFileRefs: ["repi", "package.json", "scripts/reverse-agent/repi-top-harness.mjs"],
        narrativeOnly: false,
        promotionAllowed: true,
      },
      {
        claimId: "professional_control_plane",
        statement: "REPI has a professional reverse/pentest organization control plane with normalUseGuarantee=true.",
        status: "proven",
        evidenceCommandIds: ["gate:autonomy-control"],
        sourceFileRefs: ["scripts/reverse-agent/autonomy-control-plane.mjs", "README.md"],
        narrativeOnly: false,
        promotionAllowed: true,
      },
      {
        claimId: "closure_gate_readiness",
        statement: "Every hardening gap closureGate is package-addressable, harnessed, documented, and strict --no-write green.",
        status: "proven",
        evidenceCommandIds: ["gate:autonomous-closure-readiness"],
        sourceFileRefs: ["scripts/reverse-agent/autonomous-closure-readiness-gate.mjs", "scripts/reverse-agent/repi-top-harness.mjs"],
        narrativeOnly: false,
        promotionAllowed: true,
      },
      {
        claimId: "not_top_autonomous_yet",
        statement: "REPI explicitly keeps topAutonomousDefinition=false while hardening gaps are ready_for_live rather than closed.",
        status: "explicit_gap",
        evidenceCommandIds: ["gate:autonomy-control", "gate:autonomous-closure-readiness"],
        sourceFileRefs: ["scripts/reverse-agent/autonomy-control-plane.mjs"],
        narrativeOnly: false,
        promotionAllowed: false,
      },
    ],
    autonomySummary: {
      normalUseGuarantee: autonomyJson?.normalUseGuarantee === true,
      topAutonomousDefinition: autonomyJson?.topAutonomousDefinition === true,
      gapCount: autonomyJson?.hardeningGapLedger?.gapCount ?? 0,
      closureGateCount: autonomyJson?.hardeningGapLedger?.closureGateCount ?? 0,
    },
    closureReadinessSummary: {
      readyRows: closureJson?.readinessMatrix?.summary?.readyRows ?? 0,
      failedRows: closureJson?.readinessMatrix?.summary?.failedRows ?? 999,
      allClosureGatesExecutable: closureJson?.readinessMatrix?.summary?.allClosureGatesExecutable === true,
      allClosureGatesHarnessed: closureJson?.readinessMatrix?.summary?.allClosureGatesHarnessed === true,
    },
    promotionPolicy: {
      mode: "release_capability_claim_gate",
      narrativeOnlyPromotionBlocked: true,
      topAutonomousClaimBlockedUntilClosed: true,
      requiresAllCommandsPass: true,
      requiresNoSecretLeak: true,
    },
    bundleSha256: "",
  };
  bundle.bundleSha256 = bundleDigest(bundle);
  return { bundle, commandRows };
}

function main() {
  const checks = [];
  let releaseBundle = null;
  let commandResults = [];
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", Boolean(schema?.$defs?.CapabilityClaimReleaseBundleGateV1 && schema?.$defs?.CapabilityClaimReleaseBundleV1), { path: SCHEMA_PATH }));
    checks.push(check("fixture:required-gates", REQUIRED_GATES.every((gate) => fixture.requiredGates?.includes(gate)), { required: REQUIRED_GATES, present: fixture.requiredGates }));
    const positive = validateReleaseBundlePackage(fixture);
    const negativeResults = REQUIRED_NEGATIVE_CASES.map((id) => {
      const mutated = mutateFixture(fixture, id);
      const result = validateReleaseBundlePackage(mutated);
      return { id, rejected: !result.ok, errors: result.errors };
    });
    checks.push(check("fixture:positive-release-bundle", positive.ok, positive));
    checks.push(check("fixture:negative-release-bundle", negativeResults.every((row) => row.rejected), { negativeResults }));

    const runtime = buildRuntimeBundle();
    releaseBundle = runtime.bundle;
    commandResults = runtime.commandRows.map((row) => ({ id: row.id, code: row.code, secretFree: row.secretFree, stdoutSha256: row.stdoutSha256.slice(0, 24), stderrSha256: row.stderrSha256.slice(0, 24), stderrTail: row.stderr.slice(-800) }));
    const runtimePackage = {
      kind: "CapabilityClaimReleaseBundleGateV1",
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      CapabilityClaimReleaseBundleGateV1: true,
      requiredGates: REQUIRED_GATES,
      releaseBundle,
      negativeCases: fixture.negativeCases,
      invariants: REQUIRED_GATES,
    };
    const runtimeValidation = validateReleaseBundlePackage(runtimePackage);
    checks.push(check("runtime:capability-claim-release-bundle", runtimeValidation.ok, { ...runtimeValidation, bundleSha256: releaseBundle.bundleSha256, commandResults }));
    checks.push(check("runtime:no-narrative-only-release-promotion", releaseBundle.releaseClaims.every((claim) => claim.narrativeOnly === false && claim.evidenceCommandIds.length > 0), { claims: releaseBundle.releaseClaims.map((claim) => ({ claimId: claim.claimId, status: claim.status, promotionAllowed: claim.promotionAllowed })) }));
    checks.push(check("runtime:top-autonomous-status-explicit", releaseBundle.autonomySummary.topAutonomousDefinition === false && releaseBundle.releaseClaims.some((claim) => claim.claimId === "not_top_autonomous_yet" && claim.status === "explicit_gap" && claim.promotionAllowed === false), { autonomySummary: releaseBundle.autonomySummary }));
    checks.push(check("runtime:all-release-evidence-secret-free", runtime.commandRows.every((row) => row.secretFree), { commandResults }));

    checks.push(markerCheck("harness:capability-release-bundle", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:capability-release-bundle", "CapabilityClaimReleaseBundleGateV1", "child:gate:capability-release-bundle"]));
    checks.push(markerCheck("autonomy:capability-release-bundle", "scripts/reverse-agent/autonomy-control-plane.mjs", ["capability_claim_release_bundle_gate", "CapabilityClaimReleaseBundleGateV1", "gate:capability-release-bundle"]));
    checks.push(markerCheck("npm:capability-release-bundle", "package.json", ["gate:capability-release-bundle", "capability-release-bundle-gate.mjs"]));
    checks.push(markerCheck("docs:capability-release-bundle-readme", "README.md", ["CapabilityClaimReleaseBundleGateV1", "gate:capability-release-bundle"]));
    checks.push(markerCheck("docs:capability-release-bundle-control-plane", "docs/reverse-agent/autonomous-control-plane.md", ["CapabilityClaimReleaseBundleGateV1", "gate:capability-release-bundle"]));
    checks.push(markerCheck("docs:capability-release-bundle-recon", "packages/coding-agent/docs/recon.md", ["CapabilityClaimReleaseBundleGateV1", "gate:capability-release-bundle"]));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = {
    kind: "repi-capability-release-bundle-gate",
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    CapabilityClaimReleaseBundleGateV1: true,
    capability_claim_release_bundle_gate: true,
    ok: failed.length === 0,
    root,
    checks,
    releaseBundle,
    commandResults,
  };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "capability-release-bundle", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (releaseBundle) writeFileSync(join(dir, "release-bundle.json"), `${JSON.stringify(releaseBundle, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI CapabilityClaimReleaseBundleGateV1");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
    if (releaseBundle) console.log(`bundle: ${releaseBundle.bundleSha256} claims=${releaseBundle.releaseClaims.length} commands=${releaseBundle.evidenceCommands.length}`);
  }
  if (strict && failed.length) process.exit(1);
}

main();

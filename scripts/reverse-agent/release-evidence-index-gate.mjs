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
const SCHEMA_PATH = "schemas/reverse-agent/release-evidence-index.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/release-evidence-index.fixture.json";

const REQUIRED_GATES = [
  "release_evidence_index_has_source_hashes",
  "release_evidence_index_has_command_artifacts",
  "release_evidence_index_links_autonomy_gap_ledger",
  "release_evidence_index_links_closure_readiness",
  "release_evidence_index_links_capability_bundle",
  "release_evidence_index_links_ci_pipeline",
  "release_evidence_index_hash_chain_valid",
  "release_evidence_index_secret_free",
];
const REQUIRED_NEGATIVE_CASES = [
  "missing-autonomy-gap-ledger",
  "missing-closure-readiness-ref",
  "missing-capability-bundle-ref",
  "missing-ci-pipeline-ref",
  "command-nonzero-promoted",
  "source-hash-missing",
  "hash-chain-drift",
  "secret-leak-in-command",
];
const SOURCE_FILES = [
  "package.json",
  "README.md",
  "scripts/reverse-agent/repi-top-harness.mjs",
  "scripts/reverse-agent/autonomy-control-plane.mjs",
  "scripts/reverse-agent/autonomous-closure-readiness-gate.mjs",
  "scripts/reverse-agent/capability-release-bundle-gate.mjs",
  "scripts/reverse-agent/release-ci-pipeline-gate.mjs",
  "scripts/reverse-agent/release-evidence-index-gate.mjs",
  "schemas/reverse-agent/release-evidence-index.schema.json",
  "fixtures/reverse-agent/release-evidence-index.fixture.json",
  ".github/workflows/repi-harness.yml",
  "docs/reverse-agent/repi-harness.github-actions.yml",
];
const COMMANDS = [
  {
    id: "gate:autonomy-control",
    args: ["scripts/reverse-agent/autonomy-control-plane.mjs", root, "--strict", "--json"],
    parsedKind: "pi-recon-autonomy-control-plane",
  },
  {
    id: "gate:autonomous-closure-readiness",
    args: ["scripts/reverse-agent/autonomous-closure-readiness-gate.mjs", root, "--strict", "--no-write", "--json"],
    parsedKind: "repi-autonomous-closure-readiness-gate",
  },
  {
    id: "gate:capability-release-bundle",
    args: ["scripts/reverse-agent/capability-release-bundle-gate.mjs", root, "--strict", "--no-write", "--json"],
    parsedKind: "repi-capability-release-bundle-gate",
  },
  {
    id: "gate:release-ci-pipeline",
    args: ["scripts/reverse-agent/release-ci-pipeline-gate.mjs", root, "--strict", "--no-write", "--json"],
    parsedKind: "repi-release-ci-pipeline-gate",
  },
];
const SECRET_PATTERN = /(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:proj-)?[A-Za-z0-9]{20,})/;
const ZERO_HASH = "0".repeat(64);

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

function gitHead() {
  const result = spawnSync("git", ["rev-parse", "--short=12", "HEAD"], { cwd: root, encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : "unknown";
}

function sourceFileRows() {
  return SOURCE_FILES.map((path) => {
    const full = join(root, path);
    if (!existsSync(full)) return { path, exists: false, sha256: "", bytes: 0 };
    const bytes = readFileSync(full);
    return { path, exists: true, sha256: sha256(bytes), bytes: bytes.length };
  });
}

function runCommand(spec) {
  const result = spawnSync(process.execPath, spec.args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, PI_OFFLINE: "1", PI_SKIP_VERSION_CHECK: "1", REPI_SKIP_VERSION_CHECK: "1" },
    maxBuffer: 120 * 1024 * 1024,
  });
  const stdout = result.stdout || "";
  const stderr = result.stderr || "";
  let parsed = null;
  try { parsed = JSON.parse(stdout); } catch {}
  return {
    id: spec.id,
    command: `node ${spec.args.join(" ")}`,
    code: result.status ?? 1,
    stdoutSha256: sha256(stdout),
    stderrSha256: sha256(stderr),
    parsedKind: parsed?.kind || spec.parsedKind,
    secretFree: !SECRET_PATTERN.test(`${stdout}\n${stderr}`),
    stdout,
    stderr,
    parsed,
  };
}

function publicCommand(row) {
  const { stdout, stderr, parsed, ...pub } = row;
  return pub;
}

function rowHash(row) {
  const { rowHash: _ignore, ...body } = row;
  return sha256(JSON.stringify(body));
}

function buildIndexRows(sourceFiles, commandEvidence, summaries) {
  const rawRows = [];
  for (const file of sourceFiles) rawRows.push({ evidenceId: `source:${file.path}`, evidenceType: "source_file", sourceRef: file.path, sha256: file.sha256 || ZERO_HASH });
  for (const command of commandEvidence) rawRows.push({ evidenceId: `cmd:${command.id}`, evidenceType: "command_output", sourceRef: command.id, sha256: command.stdoutSha256 || ZERO_HASH });
  for (const summary of summaries) rawRows.push({ evidenceId: summary.evidenceId, evidenceType: "parsed_summary", sourceRef: summary.sourceRef, sha256: sha256(JSON.stringify(summary.value ?? null)) });
  let prevHash = ZERO_HASH;
  return rawRows.map((row, index) => {
    const withChain = { seq: index + 1, ...row, prevHash, rowHash: "" };
    withChain.rowHash = rowHash(withChain);
    prevHash = withChain.rowHash;
    return withChain;
  });
}

function buildRuntimeIndex() {
  const sourceFiles = sourceFileRows();
  const commandRuns = COMMANDS.map(runCommand);
  const commandEvidence = commandRuns.map(publicCommand);
  const autonomy = commandRuns.find((row) => row.id === "gate:autonomy-control")?.parsed;
  const closure = commandRuns.find((row) => row.id === "gate:autonomous-closure-readiness")?.parsed;
  const capability = commandRuns.find((row) => row.id === "gate:capability-release-bundle")?.parsed;
  const ci = commandRuns.find((row) => row.id === "gate:release-ci-pipeline")?.parsed;
  const summaries = [
    { evidenceId: "summary:autonomy-gap-ledger", sourceRef: "hardeningGapLedger", value: autonomy?.hardeningGapLedgerSummary ?? autonomy?.hardeningGapLedger ?? null },
    { evidenceId: "summary:closure-readiness", sourceRef: "AutonomousClosureReadinessGateV1", value: closure?.readinessMatrix?.summary ?? null },
    { evidenceId: "summary:capability-release-bundle", sourceRef: "CapabilityClaimReleaseBundleV1", value: capability?.releaseBundle?.summary ?? capability?.releaseBundle ?? null },
    { evidenceId: "summary:release-ci-pipeline", sourceRef: "ReleaseCiPipelineV1", value: ci?.pipeline?.orderPolicy ?? ci?.pipeline ?? null },
  ];
  const indexRows = buildIndexRows(sourceFiles, commandEvidence, summaries);
  return {
    kind: "ReleaseEvidenceIndexV1",
    schemaVersion: 1,
    releaseId: `repi-release-evidence-${new Date().toISOString().replace(/[:.]/g, "-")}`,
    gitHead: gitHead(),
    sourceFiles,
    commandEvidence,
    indexRows,
    summary: {
      normalUseGuarantee: autonomy?.normalUseGuarantee === true,
      topAutonomousDefinition: autonomy?.topAutonomousDefinition === true,
      closureReadyRows: closure?.readinessMatrix?.summary?.readyRows ?? 0,
      closureFailedRows: closure?.readinessMatrix?.summary?.failedRows ?? 999,
      capabilityClaimCount: capability?.releaseBundle?.releaseClaims?.length ?? 0,
      ciWorkflowCount: ci?.pipeline?.workflows?.length ?? 0,
    },
    hashChainTip: indexRows.at(-1)?.rowHash ?? ZERO_HASH,
    promotionPolicy: {
      mode: "release_evidence_index",
      allCommandsMustPass: true,
      allSourcesMustHash: true,
      secretFreeRequired: true,
      topAutonomousFalseUntilClosed: true,
    },
    commandRunDetails: commandRuns.map((row) => ({ id: row.id, code: row.code, secretFree: row.secretFree, parsedKind: row.parsedKind, stderrTail: row.stderr.slice(-800), stdoutSha256: row.stdoutSha256.slice(0, 24) })),
  };
}

function validateHashChain(rows) {
  let prevHash = ZERO_HASH;
  for (const row of rows || []) {
    if (row.prevHash !== prevHash) return false;
    if (row.rowHash !== rowHash(row)) return false;
    prevHash = row.rowHash;
  }
  return (rows || []).length >= 12;
}

function validateEvidenceIndexPackage(pkg) {
  const errors = [];
  if (pkg?.kind !== "ReleaseEvidenceIndexGateV1") errors.push("pkg.kind");
  if (pkg?.ReleaseEvidenceIndexGateV1 !== true) errors.push("pkg.ReleaseEvidenceIndexGateV1");
  const gates = new Set(pkg?.requiredGates || []);
  for (const gate of REQUIRED_GATES) if (!gates.has(gate)) errors.push(`requiredGate_missing:${gate}`);
  const negativeIds = new Set((pkg?.negativeCases || []).map((row) => row.id));
  for (const id of REQUIRED_NEGATIVE_CASES) if (!negativeIds.has(id)) errors.push(`negativeCase_missing:${id}`);
  const idx = pkg?.evidenceIndex;
  if (idx?.kind !== "ReleaseEvidenceIndexV1") errors.push("index.kind");
  if (!Array.isArray(idx?.sourceFiles) || idx.sourceFiles.length < 8) errors.push("sourceFiles.minItems");
  for (const file of idx?.sourceFiles || []) {
    if (file.exists !== true) errors.push(`${file.path || "unknown"}.exists_not_true`);
    if (!/^[a-f0-9]{64}$/.test(String(file.sha256 || ""))) errors.push(`${file.path || "unknown"}.sha256_invalid`);
    if ((file.bytes ?? 0) < 1) errors.push(`${file.path || "unknown"}.bytes_invalid`);
  }
  const commands = new Map((idx?.commandEvidence || []).map((row) => [row.id, row]));
  for (const spec of COMMANDS) {
    if (!commands.has(spec.id)) errors.push(`command_missing:${spec.id}`);
    else {
      const row = commands.get(spec.id);
      if (row.code !== 0) errors.push(`${spec.id}.code_nonzero`);
      if (row.secretFree !== true) errors.push(`${spec.id}.secretFree_not_true`);
      if (row.parsedKind !== spec.parsedKind) errors.push(`${spec.id}.parsedKind_mismatch:${row.parsedKind}`);
      if (!/^[a-f0-9]{64}$/.test(String(row.stdoutSha256 || ""))) errors.push(`${spec.id}.stdoutSha256_invalid`);
      if (!/^[a-f0-9]{64}$/.test(String(row.stderrSha256 || ""))) errors.push(`${spec.id}.stderrSha256_invalid`);
    }
  }
  const rowRefs = new Set((idx?.indexRows || []).map((row) => row.sourceRef));
  for (const requiredRef of ["hardeningGapLedger", "AutonomousClosureReadinessGateV1", "CapabilityClaimReleaseBundleV1", "ReleaseCiPipelineV1", "gate:autonomy-control", "gate:autonomous-closure-readiness", "gate:capability-release-bundle", "gate:release-ci-pipeline"]) {
    if (!rowRefs.has(requiredRef)) errors.push(`indexRow_sourceRef_missing:${requiredRef}`);
  }
  if (!validateHashChain(idx?.indexRows)) errors.push("indexRows.hash_chain_invalid");
  if (idx?.hashChainTip !== idx?.indexRows?.at?.(-1)?.rowHash) errors.push("hashChainTip_mismatch");
  if (idx?.summary?.normalUseGuarantee !== true) errors.push("summary.normalUseGuarantee_not_true");
  if (idx?.summary?.topAutonomousDefinition !== false) errors.push("summary.topAutonomousDefinition_not_false");
  if ((idx?.summary?.closureReadyRows ?? 0) < 1) errors.push("summary.closureReadyRows_missing");
  if (idx?.summary?.closureFailedRows !== 0) errors.push("summary.closureFailedRows_nonzero");
  if ((idx?.summary?.capabilityClaimCount ?? 0) < 4) errors.push("summary.capabilityClaimCount_missing");
  if ((idx?.summary?.ciWorkflowCount ?? 0) < 2) errors.push("summary.ciWorkflowCount_missing");
  const policy = idx?.promotionPolicy || {};
  if (policy.mode !== "release_evidence_index") errors.push("promotionPolicy.mode");
  for (const key of ["allCommandsMustPass", "allSourcesMustHash", "secretFreeRequired", "topAutonomousFalseUntilClosed"]) if (policy[key] !== true) errors.push(`promotionPolicy.${key}_not_true`);
  return { ok: errors.length === 0, errors };
}

function mutateFixture(fixture, id) {
  const row = clone(fixture);
  const idx = row.evidenceIndex;
  if (id === "missing-autonomy-gap-ledger") idx.indexRows = idx.indexRows.filter((r) => r.sourceRef !== "hardeningGapLedger");
  if (id === "missing-closure-readiness-ref") idx.commandEvidence = idx.commandEvidence.filter((r) => r.id !== "gate:autonomous-closure-readiness");
  if (id === "missing-capability-bundle-ref") idx.commandEvidence = idx.commandEvidence.filter((r) => r.id !== "gate:capability-release-bundle");
  if (id === "missing-ci-pipeline-ref") idx.commandEvidence = idx.commandEvidence.filter((r) => r.id !== "gate:release-ci-pipeline");
  if (id === "command-nonzero-promoted") idx.commandEvidence[0].code = 1;
  if (id === "source-hash-missing") idx.sourceFiles[0].sha256 = "";
  if (id === "hash-chain-drift") idx.indexRows[3].prevHash = "f".repeat(64);
  if (id === "secret-leak-in-command") idx.commandEvidence[0].secretFree = false;
  return row;
}

function main() {
  const checks = [];
  let evidenceIndex = null;
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", Boolean(schema?.$defs?.ReleaseEvidenceIndexGateV1 && schema?.$defs?.ReleaseEvidenceIndexV1), { path: SCHEMA_PATH }));
    checks.push(check("fixture:required-gates", REQUIRED_GATES.every((gate) => fixture.requiredGates?.includes(gate)), { required: REQUIRED_GATES, present: fixture.requiredGates }));
    const positive = validateEvidenceIndexPackage(fixture);
    const negativeResults = REQUIRED_NEGATIVE_CASES.map((id) => {
      const result = validateEvidenceIndexPackage(mutateFixture(fixture, id));
      return { id, rejected: !result.ok, errors: result.errors };
    });
    checks.push(check("fixture:positive-release-evidence-index", positive.ok, positive));
    checks.push(check("fixture:negative-release-evidence-index", negativeResults.every((row) => row.rejected), { negativeResults }));
    evidenceIndex = buildRuntimeIndex();
    const runtimePackage = {
      kind: "ReleaseEvidenceIndexGateV1",
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      ReleaseEvidenceIndexGateV1: true,
      requiredGates: REQUIRED_GATES,
      evidenceIndex,
      negativeCases: fixture.negativeCases,
      invariants: REQUIRED_GATES,
    };
    const runtimeValidation = validateEvidenceIndexPackage(runtimePackage);
    checks.push(check("runtime:release-evidence-index", runtimeValidation.ok, { ...runtimeValidation, summary: evidenceIndex.summary, hashChainTip: evidenceIndex.hashChainTip, commandRunDetails: evidenceIndex.commandRunDetails }));
    checks.push(check("runtime:release-evidence-index-hash-chain", validateHashChain(evidenceIndex.indexRows), { rowCount: evidenceIndex.indexRows.length, hashChainTip: evidenceIndex.hashChainTip }));
    checks.push(check("runtime:release-evidence-index-secret-free", evidenceIndex.commandEvidence.every((row) => row.secretFree), { commands: evidenceIndex.commandEvidence.map(({ id, secretFree }) => ({ id, secretFree })) }));
    checks.push(check("runtime:release-evidence-index-links", ["hardeningGapLedger", "AutonomousClosureReadinessGateV1", "CapabilityClaimReleaseBundleV1", "ReleaseCiPipelineV1"].every((ref) => evidenceIndex.indexRows.some((row) => row.sourceRef === ref)), { refs: evidenceIndex.indexRows.map((row) => row.sourceRef) }));

    checks.push(markerCheck("harness:release-evidence-index", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:release-evidence-index", "ReleaseEvidenceIndexGateV1", "child:gate:release-evidence-index"]));
    checks.push(markerCheck("autonomy:release-evidence-index", "scripts/reverse-agent/autonomy-control-plane.mjs", ["release_evidence_index_gate", "ReleaseEvidenceIndexGateV1", "gate:release-evidence-index"]));
    checks.push(markerCheck("npm:release-evidence-index", "package.json", ["gate:release-evidence-index", "release-evidence-index-gate.mjs"]));
    checks.push(markerCheck("docs:release-evidence-index-readme", "README.md", ["ReleaseEvidenceIndexGateV1", "gate:release-evidence-index"]));
    checks.push(markerCheck("docs:release-evidence-index-control-plane", "docs/reverse-agent/autonomous-control-plane.md", ["ReleaseEvidenceIndexGateV1", "gate:release-evidence-index"]));
    checks.push(markerCheck("docs:release-evidence-index-reverse", "docs/reverse-agent/README.md", ["ReleaseEvidenceIndexGateV1", "gate:release-evidence-index"]));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = {
    kind: "repi-release-evidence-index-gate",
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    ReleaseEvidenceIndexGateV1: true,
    release_evidence_index_gate: true,
    ok: failed.length === 0,
    root,
    checks,
    evidenceIndex,
  };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "release-evidence-index", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (evidenceIndex) writeFileSync(join(dir, "release-evidence-index.json"), `${JSON.stringify(evidenceIndex, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI ReleaseEvidenceIndexGateV1");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
    if (evidenceIndex) console.log(`index: rows=${evidenceIndex.indexRows.length} tip=${evidenceIndex.hashChainTip}`);
  }
  if (strict && failed.length) process.exit(1);
}

main();

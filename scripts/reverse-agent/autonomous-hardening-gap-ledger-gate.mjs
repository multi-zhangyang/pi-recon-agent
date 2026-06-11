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
const SCHEMA_PATH = "schemas/reverse-agent/autonomous-hardening-gap-ledger.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/autonomous-hardening-gap-ledger.fixture.json";
const REQUIRED_PILLARS = ["parallel_scheduling", "long_context_compaction", "failure_self_repair", "automatic_division_validation"];
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

function validateLedger(ledger, manifest = { topAutonomousDefinition: false }) {
  const errors = [];
  if (ledger?.kind !== "AutonomousHardeningGapLedgerV1") errors.push("ledger.kind");
  if (!Array.isArray(ledger?.gaps) || ledger.gaps.length < REQUIRED_PILLARS.length) errors.push("ledger.gaps.minItems");
  const pillars = new Set((ledger?.gaps || []).map((gap) => gap.pillar));
  for (const pillar of REQUIRED_PILLARS) if (!pillars.has(pillar)) errors.push(`missing_pillar:${pillar}`);
  const closureGates = new Set();
  for (const gap of ledger?.gaps || []) {
    if (gap.kind !== "AutonomousHardeningGapV1") errors.push(`${gap.gapId || "unknown"}.kind`);
    if (!gap.gapId) errors.push("gapId_missing");
    if (!/^gate:[a-z0-9-]+$/.test(gap.closureGate || "")) errors.push(`${gap.gapId}.closureGate_missing_or_invalid`);
    else closureGates.add(gap.closureGate);
    if (!Array.isArray(gap.regressionCommands) || gap.regressionCommands.length < 1) errors.push(`${gap.gapId}.regressionCommands_missing`);
    if (!gap.nextCommand) errors.push(`${gap.gapId}.nextCommand_missing`);
    if (!Array.isArray(gap.acceptanceCriteria) || gap.acceptanceCriteria.length < 3) errors.push(`${gap.gapId}.acceptanceCriteria_missing`);
    if (!Array.isArray(gap.missingRuntimeProof) || gap.missingRuntimeProof.length < 1) errors.push(`${gap.gapId}.missingRuntimeProof_missing`);
    if (!Array.isArray(gap.artifacts) || gap.artifacts.length < 1) errors.push(`${gap.gapId}.artifacts_missing`);
    if (gap.readyForImplementation !== true) errors.push(`${gap.gapId}.readyForImplementation_not_true`);
  }
  if (ledger?.gapCount !== ledger?.gaps?.length) errors.push("ledger.gapCount_mismatch");
  if (ledger?.closureGateCount !== closureGates.size) errors.push("ledger.closureGateCount_mismatch");
  if (manifest.topAutonomousDefinition === true && (ledger?.gaps || []).some((gap) => gap.status !== "closed")) errors.push("top_autonomous_true_with_open_gaps");
  if (!String(ledger?.promotionPolicy || "").includes("topAutonomousDefinition")) errors.push("ledger.promotionPolicy_missing_top_autonomous_guard");
  return { ok: errors.length === 0, errors };
}

function mutateFixture(fixture, id) {
  const row = clone(fixture);
  if (id === "missing-closure-gate") delete row.gaps[0].closureGate;
  if (id === "missing-regression-command") row.gaps[0].regressionCommands = [];
  if (id === "missing-acceptance-criteria") row.gaps[0].acceptanceCriteria = [];
  return row;
}

function runAutonomyJson() {
  const result = spawnSync(process.execPath, ["scripts/reverse-agent/autonomy-control-plane.mjs", root, "--json"], { cwd: root, encoding: "utf8", maxBuffer: 80 * 1024 * 1024 });
  let parsed = null;
  try { parsed = JSON.parse(result.stdout); } catch {}
  return { code: result.status, stdoutTail: (result.stdout || "").slice(-2000), stderrTail: (result.stderr || "").slice(-4000), parsed };
}

function main() {
  const checks = [];
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", Boolean(schema?.$defs?.AutonomousHardeningGapLedgerV1 && schema?.$defs?.AutonomousHardeningGapV1), { path: SCHEMA_PATH }));
    const fixturePositive = validateLedger(fixture, { topAutonomousDefinition: false });
    const negativeResults = (fixture.negativeCases || []).map((negative) => {
      const mutated = mutateFixture(fixture, negative.id);
      const manifest = { topAutonomousDefinition: negative.id === "top-autonomous-true-with-open-gaps" };
      const result = validateLedger(mutated, manifest);
      return { id: negative.id, rejected: !result.ok, errors: result.errors };
    });
    checks.push(check("fixture:positive-ledger", fixturePositive.ok, fixturePositive));
    checks.push(check("fixture:negative-ledger", negativeResults.every((row) => row.rejected), { negativeResults }));
    const runtime = runAutonomyJson();
    checks.push(check("runtime:autonomy-json", runtime.code === 0 && Boolean(runtime.parsed?.hardeningGapLedger), { code: runtime.code, stderrTail: runtime.stderrTail, stdoutTail: runtime.stdoutTail }));
    if (runtime.parsed?.hardeningGapLedger) {
      const runtimeValidation = validateLedger(runtime.parsed.hardeningGapLedger, runtime.parsed);
      checks.push(check("runtime:hardening-gap-ledger", runtimeValidation.ok, runtimeValidation));
      checks.push(check("runtime:gap-summary", runtime.parsed.hardeningGapLedgerSummary?.gapCount === runtime.parsed.hardeningGapLedger.gapCount && runtime.parsed.topAutonomousDefinition === false, { summary: runtime.parsed.hardeningGapLedgerSummary, topAutonomousDefinition: runtime.parsed.topAutonomousDefinition }));
    } else {
      checks.push(check("runtime:hardening-gap-ledger", false, { error: "missing runtime ledger" }));
      checks.push(check("runtime:gap-summary", false, { error: "missing runtime ledger" }));
    }
    checks.push(markerCheck("autonomy:hardening-gap-ledger", "scripts/reverse-agent/autonomy-control-plane.mjs", ["AutonomousHardeningGapLedgerV1", "hardeningGapLedger", "closureGate", "readyForImplementation", "topAutonomousDefinition remains false"]));
    checks.push(markerCheck("harness:hardening-gap-ledger", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:autonomous-hardening-gap-ledger", "AutonomousHardeningGapLedgerV1", "child:gate:autonomous-hardening-gap-ledger"]));
    checks.push(markerCheck("npm:hardening-gap-ledger", "package.json", ["gate:autonomous-hardening-gap-ledger", "autonomous-hardening-gap-ledger-gate.mjs"]));
    checks.push(markerCheck("docs:hardening-gap-ledger-readme", "README.md", ["AutonomousHardeningGapLedgerV1", "gate:autonomous-hardening-gap-ledger"]));
    checks.push(markerCheck("docs:hardening-gap-ledger-control-plane", "docs/reverse-agent/autonomous-control-plane.md", ["AutonomousHardeningGapLedgerV1", "gate:autonomous-hardening-gap-ledger"]));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const output = { kind: "repi-autonomous-hardening-gap-ledger-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), AutonomousHardeningGapLedgerV1: true, ok: failed.length === 0, root, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "autonomous-hardening-gap-ledger", output.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(output, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(output, null, 2));
  else {
    console.log("# REPI AutonomousHardeningGapLedgerV1");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
  }
  if (strict && failed.length) process.exit(1);
}
main();

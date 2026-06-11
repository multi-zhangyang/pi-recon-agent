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
const SCHEMA_PATH = "schemas/reverse-agent/release-ci-pipeline.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/release-ci-pipeline.fixture.json";

const REQUIRED_GATES = [
  "ci_uses_repi_command_not_pi_takeover",
  "ci_installs_with_ignore_scripts",
  "product_boundary_before_capability_claim",
  "closure_readiness_before_capability_release",
  "capability_release_before_top_harness",
  "top_harness_before_repository_check",
  "no_generated_diff_after_checks",
  "ci_no_live_provider_or_secret_dependency",
  "release_ci_pipeline_before_evidence_index",
  "release_evidence_index_before_top_harness",
];
const REQUIRED_NEGATIVE_CASES = [
  "missing-product-boundary-gate",
  "capability-before-closure-readiness",
  "missing-capability-release-bundle",
  "missing-no-diff-guard",
  "live-provider-secret-required",
  "pi-command-takeover",
  "repository-check-before-top-harness",
];
const WORKFLOW_PATHS = [".github/workflows/repi-harness.yml", "docs/reverse-agent/repi-harness.github-actions.yml"];
const REQUIRED_COMMANDS = [
  { name: "Install dependencies", command: "npm ci --ignore-scripts", evidenceTier: "install" },
  { name: "REPI product boundary gate", command: "npm run gate:repi-product", evidenceTier: "product_boundary" },
  { name: "REPI profile isolation gate", command: "npm run gate:repi-isolation", evidenceTier: "product_boundary" },
  { name: "REPI product surface gate", command: "npm run gate:repi-product-surface", evidenceTier: "product_boundary" },
  { name: "REPI closure readiness gate", command: "npm run gate:autonomous-closure-readiness -- --no-write", evidenceTier: "closure_readiness" },
  { name: "REPI capability release bundle gate", command: "npm run gate:capability-release-bundle -- --no-write", evidenceTier: "capability_release" },
  { name: "REPI release CI pipeline gate", command: "npm run gate:release-ci-pipeline -- --no-write", evidenceTier: "release_ci_pipeline" },
  { name: "REPI release evidence index gate", command: "npm run gate:release-evidence-index -- --no-write", evidenceTier: "release_evidence_index" },
  { name: "Top-level REPI independence harness", command: "npm run gate:repi-harness", evidenceTier: "top_harness" },
  { name: "Full repository check", command: "npm run check", evidenceTier: "repository_check" },
  { name: "No generated diff", command: "git diff --check && git diff --exit-code", evidenceTier: "diff_guard" },
];
const FORBIDDEN_PATTERNS = [
  /secrets\./i,
  /REPI_REMOTE_PROVIDER_LIVE\s*[:=]\s*["']?1/i,
  /REPI_PROVIDER_BACKED_DOGFOOD_LIVE\s*[:=]\s*["']?1/i,
  /ANTHROPIC_AUTH_TOKEN/i,
  /OPENAI_API_KEY/i,
  /REPI_REMOTE_PROVIDER_API_KEY/i,
  /npm\s+run\s+install:recon-pi/i,
  /\bpi\s+update\b/i,
  /ln\s+-s.*\bpi\b/i,
];

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

function commandOrder(text, command) {
  if (command === "git diff --check && git diff --exit-code") {
    const a = text.indexOf("git diff --check");
    const b = text.indexOf("git diff --exit-code");
    return a >= 0 && b > a ? a : -1;
  }
  return text.indexOf(command);
}

function workflowFromText(path, text) {
  const steps = REQUIRED_COMMANDS.map((spec) => ({
    name: spec.name,
    command: spec.command,
    order: commandOrder(text, spec.command),
    required: true,
    evidenceTier: spec.evidenceTier,
  }));
  const nodeMatch = text.match(/node-version:\s*['"]?(\d+)['"]?/);
  const forbiddenMatches = FORBIDDEN_PATTERNS.filter((pattern) => pattern.test(text)).map((pattern) => String(pattern));
  return {
    path,
    exists: true,
    sha256: sha256(text),
    nodeVersion: nodeMatch?.[1] || "",
    permissionsReadOnly: /permissions:\s*\n\s*contents:\s*read/m.test(text),
    steps,
    forbiddenPatternsAbsent: forbiddenMatches.length === 0,
    forbiddenMatches,
  };
}

function publicWorkflow(row) {
  const { forbiddenMatches, ...pub } = row;
  return pub;
}

function buildRuntimePipeline() {
  const workflows = WORKFLOW_PATHS.map((path) => {
    const full = join(root, path);
    if (!existsSync(full)) {
      return { path, exists: false, sha256: "", nodeVersion: "", permissionsReadOnly: false, steps: [], forbiddenPatternsAbsent: false, forbiddenMatches: ["missing"] };
    }
    return workflowFromText(path, readFileSync(full, "utf8"));
  });
  const publicWorkflows = workflows.map(publicWorkflow);
  return {
    kind: "ReleaseCiPipelineV1",
    schemaVersion: 1,
    workflows: publicWorkflows,
    orderPolicy: computeOrderPolicy(publicWorkflows),
    promotionPolicy: {
      mode: "release_ci_pipeline_readiness",
      noLiveProviderSecretDependency: workflows.every((row) => row.forbiddenPatternsAbsent),
      repiCommandOnly: workflows.every((row) => row.steps.some((step) => step.command.includes("gate:repi-product")) && !row.forbiddenMatches.some((match) => match.includes("pi"))),
      noPiTakeover: workflows.every((row) => row.forbiddenPatternsAbsent),
      noNarrativeOnlyRelease: workflows.every((row) => row.steps.some((step) => step.command.includes("gate:capability-release-bundle"))),
    },
  };
}

function stepOrder(workflow, command) {
  return workflow.steps.find((step) => step.command === command)?.order ?? -1;
}

function computeOrderPolicy(workflows) {
  const productBoundaryBeforeCapability = workflows.every((workflow) => {
    const cap = stepOrder(workflow, "npm run gate:capability-release-bundle -- --no-write");
    return ["npm run gate:repi-product", "npm run gate:repi-isolation", "npm run gate:repi-product-surface"].every((cmd) => stepOrder(workflow, cmd) >= 0 && stepOrder(workflow, cmd) < cap);
  });
  const closureReadinessBeforeCapability = workflows.every((workflow) => stepOrder(workflow, "npm run gate:autonomous-closure-readiness -- --no-write") >= 0 && stepOrder(workflow, "npm run gate:autonomous-closure-readiness -- --no-write") < stepOrder(workflow, "npm run gate:capability-release-bundle -- --no-write"));
  const capabilityBeforeTopHarness = workflows.every((workflow) => stepOrder(workflow, "npm run gate:capability-release-bundle -- --no-write") >= 0 && stepOrder(workflow, "npm run gate:capability-release-bundle -- --no-write") < stepOrder(workflow, "npm run gate:repi-harness"));
  const releaseCiPipelineBeforeEvidenceIndex = workflows.every((workflow) => stepOrder(workflow, "npm run gate:release-ci-pipeline -- --no-write") >= 0 && stepOrder(workflow, "npm run gate:release-ci-pipeline -- --no-write") < stepOrder(workflow, "npm run gate:release-evidence-index -- --no-write"));
  const releaseEvidenceIndexBeforeTopHarness = workflows.every((workflow) => stepOrder(workflow, "npm run gate:release-evidence-index -- --no-write") >= 0 && stepOrder(workflow, "npm run gate:release-evidence-index -- --no-write") < stepOrder(workflow, "npm run gate:repi-harness"));
  const topHarnessBeforeCheck = workflows.every((workflow) => stepOrder(workflow, "npm run gate:repi-harness") >= 0 && stepOrder(workflow, "npm run gate:repi-harness") < stepOrder(workflow, "npm run check"));
  const diffGuardLast = workflows.every((workflow) => {
    const diff = stepOrder(workflow, "git diff --check && git diff --exit-code");
    return diff >= 0 && workflow.steps.every((step) => step.order <= diff || step.order < 0);
  });
  return { productBoundaryBeforeCapability, closureReadinessBeforeCapability, capabilityBeforeTopHarness, releaseCiPipelineBeforeEvidenceIndex, releaseEvidenceIndexBeforeTopHarness, topHarnessBeforeCheck, diffGuardLast };
}

function validatePipelinePackage(pkg) {
  const errors = [];
  if (pkg?.kind !== "ReleaseCiPipelineGateV1") errors.push("pkg.kind");
  if (pkg?.ReleaseCiPipelineGateV1 !== true) errors.push("pkg.ReleaseCiPipelineGateV1");
  const gates = new Set(pkg?.requiredGates || []);
  for (const gate of REQUIRED_GATES) if (!gates.has(gate)) errors.push(`requiredGate_missing:${gate}`);
  const negativeIds = new Set((pkg?.negativeCases || []).map((row) => row.id));
  for (const id of REQUIRED_NEGATIVE_CASES) if (!negativeIds.has(id)) errors.push(`negativeCase_missing:${id}`);
  const pipeline = pkg?.pipeline;
  if (pipeline?.kind !== "ReleaseCiPipelineV1") errors.push("pipeline.kind");
  if (!Array.isArray(pipeline?.workflows) || pipeline.workflows.length < 2) errors.push("workflows.minItems");
  for (const workflow of pipeline?.workflows || []) {
    if (workflow.exists !== true) errors.push(`${workflow.path}.missing`);
    if (!/^[a-f0-9]{64}$/.test(String(workflow.sha256 || ""))) errors.push(`${workflow.path}.sha256_invalid`);
    if (!["22", "24"].includes(String(workflow.nodeVersion))) errors.push(`${workflow.path}.nodeVersion_invalid`);
    if (workflow.permissionsReadOnly !== true) errors.push(`${workflow.path}.permissions_not_read_only`);
    if (workflow.forbiddenPatternsAbsent !== true) errors.push(`${workflow.path}.forbiddenPatterns_present`);
    const commands = new Set((workflow.steps || []).map((step) => step.command));
    for (const spec of REQUIRED_COMMANDS) if (!commands.has(spec.command)) errors.push(`${workflow.path}.missing_command:${spec.command}`);
    for (const step of workflow.steps || []) {
      if (step.required !== true) errors.push(`${workflow.path}.${step.command}.not_required`);
      if (step.order < 0) errors.push(`${workflow.path}.${step.command}.order_missing`);
    }
  }
  for (const [key, value] of Object.entries(pipeline?.orderPolicy || {})) if (value !== true) errors.push(`orderPolicy.${key}_not_true`);
  const policy = pipeline?.promotionPolicy || {};
  for (const key of ["noLiveProviderSecretDependency", "repiCommandOnly", "noPiTakeover", "noNarrativeOnlyRelease"]) if (policy[key] !== true) errors.push(`promotionPolicy.${key}_not_true`);
  if (policy.mode !== "release_ci_pipeline_readiness") errors.push("promotionPolicy.mode");
  return { ok: errors.length === 0, errors };
}

function mutateFixture(fixture, id) {
  const row = clone(fixture);
  const workflow = row.pipeline.workflows[0];
  const removeCommand = (command) => { workflow.steps = workflow.steps.filter((step) => step.command !== command); };
  if (id === "missing-product-boundary-gate") removeCommand("npm run gate:repi-product");
  if (id === "capability-before-closure-readiness") {
    const closure = workflow.steps.find((step) => step.command.includes("autonomous-closure-readiness"));
    const cap = workflow.steps.find((step) => step.command.includes("capability-release-bundle"));
    [closure.order, cap.order] = [cap.order, closure.order];
    row.pipeline.orderPolicy = computeOrderPolicy(row.pipeline.workflows);
  }
  if (id === "missing-capability-release-bundle") removeCommand("npm run gate:capability-release-bundle -- --no-write");
  if (id === "missing-no-diff-guard") removeCommand("git diff --check && git diff --exit-code");
  if (id === "live-provider-secret-required") workflow.forbiddenPatternsAbsent = false;
  if (id === "pi-command-takeover") row.pipeline.promotionPolicy.noPiTakeover = false;
  if (id === "repository-check-before-top-harness") {
    const top = workflow.steps.find((step) => step.command === "npm run gate:repi-harness");
    const checkStep = workflow.steps.find((step) => step.command === "npm run check");
    [top.order, checkStep.order] = [checkStep.order, top.order];
    row.pipeline.orderPolicy = computeOrderPolicy(row.pipeline.workflows);
  }
  return row;
}

function main() {
  const checks = [];
  let pipeline = null;
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", Boolean(schema?.$defs?.ReleaseCiPipelineGateV1 && schema?.$defs?.ReleaseCiPipelineV1), { path: SCHEMA_PATH }));
    checks.push(check("fixture:required-gates", REQUIRED_GATES.every((gate) => fixture.requiredGates?.includes(gate)), { required: REQUIRED_GATES, present: fixture.requiredGates }));
    const positive = validatePipelinePackage(fixture);
    const negativeResults = REQUIRED_NEGATIVE_CASES.map((id) => {
      const mutated = mutateFixture(fixture, id);
      const result = validatePipelinePackage(mutated);
      return { id, rejected: !result.ok, errors: result.errors };
    });
    checks.push(check("fixture:positive-ci-pipeline", positive.ok, positive));
    checks.push(check("fixture:negative-ci-pipeline", negativeResults.every((row) => row.rejected), { negativeResults }));
    pipeline = buildRuntimePipeline();
    const runtimePackage = {
      kind: "ReleaseCiPipelineGateV1",
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      ReleaseCiPipelineGateV1: true,
      requiredGates: REQUIRED_GATES,
      pipeline,
      negativeCases: fixture.negativeCases,
      invariants: REQUIRED_GATES,
    };
    const runtimeValidation = validatePipelinePackage(runtimePackage);
    checks.push(check("runtime:release-ci-pipeline", runtimeValidation.ok, { ...runtimeValidation, workflows: pipeline.workflows.map((workflow) => ({ path: workflow.path, steps: workflow.steps.map((step) => ({ command: step.command, order: step.order })), orderPolicy: pipeline.orderPolicy, promotionPolicy: pipeline.promotionPolicy })) }));
    checks.push(check("runtime:ci-product-before-capability", pipeline.orderPolicy.productBoundaryBeforeCapability && pipeline.orderPolicy.closureReadinessBeforeCapability, { orderPolicy: pipeline.orderPolicy }));
    checks.push(check("runtime:ci-no-live-secret-dependency", pipeline.promotionPolicy.noLiveProviderSecretDependency && pipeline.workflows.every((workflow) => workflow.forbiddenPatternsAbsent), { promotionPolicy: pipeline.promotionPolicy }));
    checks.push(check("runtime:ci-diff-guard-last", pipeline.orderPolicy.diffGuardLast, { orderPolicy: pipeline.orderPolicy }));

    checks.push(markerCheck("harness:release-ci-pipeline", "scripts/reverse-agent/repi-top-harness.mjs", ["gate:release-ci-pipeline", "ReleaseCiPipelineGateV1", "child:gate:release-ci-pipeline"]));
    checks.push(markerCheck("autonomy:release-ci-pipeline", "scripts/reverse-agent/autonomy-control-plane.mjs", ["release_ci_pipeline_gate", "ReleaseCiPipelineGateV1", "gate:release-ci-pipeline"]));
    checks.push(markerCheck("npm:release-ci-pipeline", "package.json", ["gate:release-ci-pipeline", "release-ci-pipeline-gate.mjs"]));
    checks.push(markerCheck("docs:release-ci-pipeline-readme", "README.md", ["ReleaseCiPipelineGateV1", "gate:release-ci-pipeline"]));
    checks.push(markerCheck("docs:release-ci-pipeline-control-plane", "docs/reverse-agent/autonomous-control-plane.md", ["ReleaseCiPipelineGateV1", "gate:release-ci-pipeline"]));
    checks.push(markerCheck("docs:release-ci-pipeline-reverse", "docs/reverse-agent/README.md", ["ReleaseCiPipelineGateV1", "gate:release-ci-pipeline"]));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = {
    kind: "repi-release-ci-pipeline-gate",
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    ReleaseCiPipelineGateV1: true,
    release_ci_pipeline_gate: true,
    ok: failed.length === 0,
    root,
    checks,
    pipeline,
  };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "release-ci-pipeline", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (pipeline) writeFileSync(join(dir, "pipeline.json"), `${JSON.stringify(pipeline, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI ReleaseCiPipelineGateV1");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
  }
  if (strict && failed.length) process.exit(1);
}

main();

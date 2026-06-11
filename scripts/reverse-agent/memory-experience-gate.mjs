#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_EXPERIENCE_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/memory-experience.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-experience.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function check(id, status, evidence = {}) {
  return { id, status: status ? "pass" : "fail", evidence };
}
function typeOk(value, type) {
  if (Array.isArray(type)) return type.some((item) => typeOk(value, item));
  if (type === "array") return Array.isArray(value);
  if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
  if (type === "integer") return Number.isInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  if (type === "null") return value === null;
  return typeof value === type;
}
function resolveRef(schema, ref) {
  if (!ref?.startsWith("#/$defs/")) throw new Error(`unsupported ref: ${ref}`);
  return schema.$defs?.[ref.slice("#/$defs/".length)];
}
function validateSchema(value, node, schema, path = "$") {
  if (!node) return [];
  if (node.$ref) return validateSchema(value, resolveRef(schema, node.$ref), schema, path);
  const errors = [];
  if (node.const !== undefined && value !== node.const) errors.push(`${path}: const ${JSON.stringify(node.const)} expected`);
  if (node.enum && !node.enum.includes(value)) errors.push(`${path}: enum ${node.enum.join("|")} expected`);
  if (node.type && !typeOk(value, node.type)) {
    errors.push(`${path}: type ${JSON.stringify(node.type)} expected`);
    return errors;
  }
  if (typeof value === "string") {
    if (node.minLength && value.length < node.minLength) errors.push(`${path}: minLength ${node.minLength}`);
    if (node.pattern && !new RegExp(node.pattern).test(value)) errors.push(`${path}: pattern ${node.pattern}`);
    if (node.format === "date-time" && Number.isNaN(Date.parse(value))) errors.push(`${path}: invalid date-time`);
  }
  if (typeof value === "number") {
    if (node.minimum !== undefined && value < node.minimum) errors.push(`${path}: minimum ${node.minimum}`);
    if (node.maximum !== undefined && value > node.maximum) errors.push(`${path}: maximum ${node.maximum}`);
  }
  if (Array.isArray(value)) {
    if (node.minItems && value.length < node.minItems) errors.push(`${path}: minItems ${node.minItems}`);
    if (node.items) value.forEach((item, index) => errors.push(...validateSchema(item, node.items, schema, `${path}[${index}]`)));
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const key of node.required ?? []) if (!(key in value)) errors.push(`${path}.${key}: required`);
    for (const [key, propSchema] of Object.entries(node.properties ?? {})) {
      if (key in value) errors.push(...validateSchema(value[key], propSchema, schema, `${path}.${key}`));
    }
    if (node.additionalProperties === false) {
      const allowed = new Set(Object.keys(node.properties ?? {}));
      for (const key of Object.keys(value)) if (!allowed.has(key)) errors.push(`${path}.${key}: additionalProperty`);
    }
  }
  return errors;
}

function validateFixture(fixture) {
  const required = [
    "MemoryExperienceEngineV8",
    "episode_model_v8",
    "structured_claim_extraction",
    "lesson_promotion_gate",
    "contradiction_resolution",
    "usefulness_backprop",
    "experience_report_in_context_pack",
    "operator_memory_injection_commands",
  ];
  const gates = new Set(fixture.requiredGates ?? []);
  const scenarios = new Set(fixture.validScenarios ?? []);
  return {
    missingGates: required.filter((gate) => !gates.has(gate)),
    missingScenarios: [
      "success-event-promotes-command-strategy-lesson",
      "failure-event-demotes-avoid-lesson",
      "contradictory-command-enters-conflict-resolution",
      "context-pack-embeds-experience-report",
      "orchestrator-runs-experience-promotion-step",
    ].filter((id) => !scenarios.has(id)),
  };
}

function writeProbe(probePath, outPath, tempRoot) {
  const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
  writeFileSync(probePath, `
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createReconExtensionFactory } from ${JSON.stringify(importUrl)};

const outPath = ${JSON.stringify(outPath)};
const tempRoot = ${JSON.stringify(tempRoot)};
const agentDir = join(tempRoot, "agent");
const workspace = join(tempRoot, "workspace");
const artifact = join(tempRoot, "runtime-proof.txt");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
writeFileSync(artifact, "verified runtime artifact for MemoryExperienceEngineV8\\n");
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "memory-experience-session";
process.env.REPI_BRANCH_ID = "memory-experience-branch";
const tools = new Map();
const handlers = new Map();
const fakePi = {
  registerCommand() {},
  registerTool(tool) { tools.set(tool.name, tool); },
  on(name, handler) { handlers.set(name, handler); },
  appendEntry() {},
  getSessionName: () => undefined,
  setSessionName() {},
  sendMessage() {},
  exec: async () => ({ code: 0, stdout: "memory-experience-probe", stderr: "", killed: false }),
};
createReconExtensionFactory()(fakePi);
const memory = tools.get("re_memory");
const context = tools.get("re_context");
if (!memory || !context) throw new Error("missing re_memory or re_context");
function text(result) { return result?.content?.[0]?.text ?? ""; }
function artifactPath(output, label) {
  const match = new RegExp(label + ": (.+)").exec(output);
  if (!match?.[1]) throw new Error("missing artifact label " + label + " in output\\n" + output.slice(0, 1000));
  return match[1].trim();
}
function parseJsonArtifact(path) {
  const body = readFileSync(path, "utf8");
  const fence = String.fromCharCode(96).repeat(3);
  const start = body.indexOf(fence + "json");
  const contentStart = body.indexOf("\\n", start);
  const end = body.indexOf(fence, contentStart + 1);
  if (start < 0 || contentStart < 0 || end < 0) throw new Error("missing json block in " + path);
  return JSON.parse(body.slice(contentStart + 1, end).trim());
}
async function main() {
  await handlers.get("before_agent_start")?.({ prompt: "web 渗透 API authz replay 经验沉淀", systemPrompt: "base" }, { hasUI: false, ui: {} });
  const success = await memory.execute("memory-experience", { action: "deposit", scene: "web", title: "verified authz replay", command: "curl https://target.local/api/proof", route: "web", target: "https://target.local", text: "outcome=success confidence=0.92 replayVerified=true playbookCandidate=true verifierRuleCandidate=true artifactPath=" + artifact + "\\ncurl https://target.local/api/proof\\ncurl https://target.local/api/good\\nverified authz replay command" });
  const failure = await memory.execute("memory-experience", { action: "append", scene: "web", title: "authz replay failure", text: "outcome=failure confidence=0.71 route=web target=https://target.local\\ncurl https://target.local/api/proof\\ncurl https://target.local/api/bad\\n403 after stale token; repair by refreshing session before replay" });
  const experienceResult = await memory.execute("memory-experience", { action: "experience" });
  const report = experienceResult.details;
  const claimsTextBeforePack = readFileSync(report.claimsPath, "utf8");
  const episodesTextBeforePack = readFileSync(report.episodesPath, "utf8");
  const orchestratorResult = await memory.execute("memory-experience", { action: "orchestrate", phase: "pre-operator", query: "authz replay target.local", target: "https://target.local" });
  const orchestrator = orchestratorResult.details;
  const packOutput = text(await context.execute("memory-experience", { action: "pack", target: "https://target.local" }));
  const packPath = artifactPath(packOutput, "context_artifact");
  const pack = parseJsonArtifact(packPath);
  writeFileSync(outPath, JSON.stringify({ tempRoot, agentDir, successText: text(success), failureText: text(failure), reportText: text(experienceResult), report, orchestrator, packPath, pack, episodesText: episodesTextBeforePack, claimsText: claimsTextBeforePack, lessonBookText: readFileSync(report.lessonBookPath, "utf8") }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}

function runProbe(tempRoot) {
  const probePath = join(tempRoot, "memory-experience-probe.ts");
  const outPath = join(tempRoot, "probe-result.json");
  writeProbe(probePath, outPath, tempRoot);
  const tsx = join(root, "node_modules", ".bin", "tsx");
  const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], {
    cwd: root,
    env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1" },
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
  });
  return { ...result, outPath, probePath };
}

function main() {
  const checks = [];
  const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-experience-"));
  let probeData;
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", schema?.$defs?.MemoryExperienceReportV8 && schema?.$defs?.MemoryExperienceClaimV8 && schema?.$defs?.MemoryExperienceLessonV8, { path: SCHEMA_PATH }));
    const fixtureEval = validateFixture(fixture);
    checks.push(check("fixture:experience-scenarios", fixtureEval.missingGates.length === 0 && fixtureEval.missingScenarios.length === 0, fixtureEval));
    const probe = runProbe(tempRoot);
    checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
    if (probe.status === 0 && existsSync(probe.outPath)) {
      probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
      const schemaErrors = validateSchema(probeData.report, schema.$defs.MemoryExperienceReportV8, schema, "$.report");
      const gates = new Set(probeData.report.requiredGates ?? []);
      const claims = probeData.claimsText.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
      const episodes = probeData.episodesText.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
      checks.push(check("runtime:report-schema", schemaErrors.length === 0, { errors: schemaErrors, reportPath: probeData.report.reportPath, sha256: sha256(JSON.stringify(probeData.report)).slice(0, 24) }));
      checks.push(check("runtime:episode-model", probeData.report.episodeCount >= 2 && episodes.every((row) => row.MemoryExperienceEngineV8 && row.entryHash), { episodeCount: probeData.report.episodeCount, episodes: episodes.map((row) => row.id) }));
      checks.push(check("runtime:structured-claim-extraction", probeData.report.claimCount >= 3 && claims.some((row) => row.claimType === "command_strategy") && claims.some((row) => row.claimType === "failure_signature"), { claimCount: probeData.report.claimCount, claimTypes: claims.map((row) => row.claimType) }));
      checks.push(check("runtime:lesson-promotion-gate", probeData.report.lessonCount >= 1 && probeData.report.promotedClaimIds.length >= 1 && probeData.report.promotionCoverage > 0, { lessonCount: probeData.report.lessonCount, promoted: probeData.report.promotedClaimIds, coverage: probeData.report.promotionCoverage }));
      checks.push(check("runtime:failure-demotion", probeData.report.demotedClaimIds.length >= 1 || probeData.report.avoidCommands.length >= 1, { demoted: probeData.report.demotedClaimIds, avoid: probeData.report.avoidCommands }));
      checks.push(check("runtime:contradiction-resolution", probeData.report.conflictedClaimIds.length >= 1 && claims.some((row) => row.status === "conflicted" && row.contradictionEventIds.length), { conflicted: probeData.report.conflictedClaimIds }));
      checks.push(check("runtime:usefulness-backprop", probeData.report.recentLessons.some((lesson) => lesson.backprop?.source?.includes("usefulness_backprop")), { lessons: probeData.report.recentLessons }));
      checks.push(check("runtime:operator-injection-commands", probeData.report.operatorInjectionCommands.some((command) => /curl https:\/\/target\.local\/api\/proof/.test(command)), { commands: probeData.report.operatorInjectionCommands }));
      checks.push(check("runtime:context-pack-embeds-experience", probeData.pack.memoryExperience?.MemoryExperienceEngineV8 === true && (probeData.pack.artifactIndex ?? []).some((entry) => /memory_experience_report/.test(entry.kind)), { packPath: probeData.packPath, memoryExperience: probeData.pack.memoryExperience }));
      checks.push(check("runtime:orchestrator-wiring", probeData.orchestrator?.memoryExperienceStatus && (probeData.orchestrator?.requiredGates ?? []).includes("MemoryExperienceEngineV8") && (probeData.orchestrator?.steps ?? []).some((step) => step.id === "experience_claim_lesson_promotion"), { memoryExperienceStatus: probeData.orchestrator?.memoryExperienceStatus, steps: probeData.orchestrator?.steps?.map((step) => step.id) }));
      checks.push(check("runtime:required-gates", ["MemoryExperienceEngineV8", "episode_model_v8", "structured_claim_extraction", "lesson_promotion_gate", "contradiction_resolution", "usefulness_backprop", "experience_report_in_context_pack", "operator_memory_injection_commands"].every((gate) => gates.has(gate)), { requiredGates: probeData.report.requiredGates }));
    } else {
      for (const id of ["runtime:report-schema", "runtime:episode-model", "runtime:structured-claim-extraction", "runtime:lesson-promotion-gate", "runtime:failure-demotion", "runtime:contradiction-resolution", "runtime:usefulness-backprop", "runtime:operator-injection-commands", "runtime:context-pack-embeds-experience", "runtime:orchestrator-wiring", "runtime:required-gates"]) checks.push(check(id, false, { error: "probe output missing" }));
    }
    checks.push(check("code:experience-markers", ["MemoryExperienceEngineV8", "buildMemoryExperienceReport", "formatMemoryExperienceReport", "memoryExperienceReportPath", "lesson_promotion_gate"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["MemoryExperienceEngineV8", "buildMemoryExperienceReport"] }));
    checks.push(check("profile:experience-markers", ["MemoryExperienceEngineV8", "buildMemoryExperienceReport", "formatMemoryExperienceReport", "memoryExperienceReportPath", "lesson_promotion_gate"].every((marker) => readText("repi-profile/extensions/reverse-pentest-core.ts").includes(marker)), { markers: ["MemoryExperienceEngineV8", "buildMemoryExperienceReport"] }));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  } finally {
    if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = { kind: "repi-memory-experience-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "memory-experience", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI Memory Experience Gate");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
  }
  if (strict && failed.length) process.exit(1);
}

main();

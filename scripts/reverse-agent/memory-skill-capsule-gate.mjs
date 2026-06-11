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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_SKILL_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/memory-skill-capsule.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-skill-capsule.fixture.json";
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
    if (node.format === "date-time" && Number.isNaN(Date.parse(value))) errors.push(`${path}: invalid date-time`);
  }
  if (typeof value === "number") {
    if (node.minimum !== undefined && value < node.minimum) errors.push(`${path}: minimum ${node.minimum}`);
    if (node.maximum !== undefined && value > node.maximum) errors.push(`${path}: maximum ${node.maximum}`);
  }
  if (Array.isArray(value) && node.items) value.forEach((item, index) => errors.push(...validateSchema(item, node.items, schema, `${path}[${index}]`)));
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const key of node.required ?? []) if (!(key in value)) errors.push(`${path}.${key}: required`);
    for (const [key, propSchema] of Object.entries(node.properties ?? {})) if (key in value) errors.push(...validateSchema(value[key], propSchema, schema, `${path}.${key}`));
    if (node.additionalProperties === false) {
      const allowed = new Set(Object.keys(node.properties ?? {}));
      for (const key of Object.keys(value)) if (!allowed.has(key)) errors.push(`${path}.${key}: additionalProperty`);
    }
  }
  return errors;
}
function validateFixture(fixture) {
  const required = [
    "MemorySkillCapsuleV9",
    "skill_capsule_assetization",
    "verified_skill_promotion_gate",
    "operator_skill_injection",
    "memory_skill_capsules_in_context_pack",
    "experience_to_skill_capsule",
    "distilled_pattern_to_skill_capsule",
  ];
  const scenarios = [
    "experience-lesson-becomes-operator-skill-capsule",
    "promoted-pattern-becomes-verifier-skill-capsule",
    "avoid-lesson-becomes-demotion-skill-capsule",
    "context-pack-embeds-skill-capsule-report",
    "orchestrator-runs-skill-capsule-injection-step",
  ];
  const gates = new Set(fixture.requiredGates ?? []);
  const fixtureScenarios = new Set(fixture.validScenarios ?? []);
  return { missingGates: required.filter((gate) => !gates.has(gate)), missingScenarios: scenarios.filter((scenario) => !fixtureScenarios.has(scenario)) };
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
const artifact = join(tempRoot, "skill-proof.txt");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
writeFileSync(artifact, "verified runtime artifact for MemorySkillCapsuleV9\\n");
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "memory-skill-session";
process.env.REPI_BRANCH_ID = "memory-skill-branch";
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
  exec: async () => ({ code: 0, stdout: "memory-skill-probe", stderr: "", killed: false }),
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
  await handlers.get("before_agent_start")?.({ prompt: "web authz skill capsule 经验资产化", systemPrompt: "base" }, { hasUI: false, ui: {} });
  await memory.execute("memory-skill", { action: "deposit", scene: "web", title: "verified skill replay", command: "curl https://target.local/api/skill-proof", route: "web", target: "https://target.local", text: "outcome=success confidence=0.94 replayVerified=true playbookCandidate=true verifierRuleCandidate=true artifactPath=" + artifact + "\\ncurl https://target.local/api/skill-proof\\nverified operator skill command" });
  await memory.execute("memory-skill", { action: "append", scene: "web", title: "avoid stale skill", text: "outcome=failure confidence=0.76 route=web target=https://target.local\\ncurl https://target.local/api/stale\\nstale token failure; avoid stale token replay" });
  const skillResult = await memory.execute("memory-skill", { action: "skills", route: "web", target: "https://target.local" });
  const report = skillResult.details;
  const ledgerText = readFileSync(report.capsuleLedgerPath, "utf8");
  const orchestratorResult = await memory.execute("memory-skill", { action: "orchestrate", phase: "pre-operator", query: "skill-proof target.local", target: "https://target.local" });
  const orchestrator = orchestratorResult.details;
  const packOutput = text(await context.execute("memory-skill", { action: "pack", target: "https://target.local" }));
  const packPath = artifactPath(packOutput, "context_artifact");
  const pack = parseJsonArtifact(packPath);
  writeFileSync(outPath, JSON.stringify({ tempRoot, agentDir, reportText: text(skillResult), report, ledgerText, orchestrator, packPath, pack, capsuleBookText: readFileSync(report.capsuleBookPath, "utf8") }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}
function runProbe(tempRoot) {
  const probePath = join(tempRoot, "memory-skill-capsule-probe.ts");
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
  const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-skill-"));
  let probeData;
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", schema?.$defs?.MemorySkillCapsuleReportV9 && schema?.$defs?.MemorySkillCapsuleV9, { path: SCHEMA_PATH }));
    const fixtureEval = validateFixture(fixture);
    checks.push(check("fixture:skill-capsule-scenarios", fixtureEval.missingGates.length === 0 && fixtureEval.missingScenarios.length === 0, fixtureEval));
    const probe = runProbe(tempRoot);
    checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
    if (probe.status === 0 && existsSync(probe.outPath)) {
      probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
      const reportErrors = validateSchema(probeData.report, schema.$defs.MemorySkillCapsuleReportV9, schema, "$.report");
      const capsules = probeData.ledgerText.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
      const capsuleErrors = capsules.flatMap((capsule, index) => validateSchema(capsule, schema.$defs.MemorySkillCapsuleV9, schema, `$.capsules[${index}]`));
      const gates = new Set(probeData.report.requiredGates ?? []);
      const stepIds = new Set((probeData.orchestrator?.steps ?? []).map((step) => step.id));
      checks.push(check("runtime:report-schema", reportErrors.length === 0, { errors: reportErrors, reportPath: probeData.report.reportPath, sha256: sha256(JSON.stringify(probeData.report)).slice(0, 24) }));
      checks.push(check("runtime:capsule-ledger-schema", capsuleErrors.length === 0 && capsules.length === probeData.report.capsuleCount && capsules.every((row) => row.MemorySkillCapsuleV9 && row.entryHash), { errors: capsuleErrors, capsuleCount: capsules.length }));
      checks.push(check("runtime:experience-lesson-to-operator-capsule", capsules.some((row) => row.skillType === "operator_playbook" && row.operatorCommands.some((command) => /skill-proof/.test(command))), { capsules: capsules.map((row) => ({ id: row.id, type: row.skillType, commands: row.operatorCommands })) }));
      checks.push(check("runtime:avoid-lesson-to-avoid-capsule", capsules.some((row) => row.skillType === "avoid_rule" && row.avoidCommands.length), { avoidCapsules: capsules.filter((row) => row.skillType === "avoid_rule") }));
      checks.push(check("runtime:verified-promotion-gate", capsules.some((row) => ["artifact_sha256", "experience_promotion", "replay_or_verifier"].includes(row.promotionGate)), { gates: capsules.map((row) => row.promotionGate) }));
      checks.push(check("runtime:operator-skill-injection", probeData.report.operatorInjectionCommands.some((command) => /skill-proof/.test(command)) && probeData.report.nextCommands.some((command) => /re_operator plan/.test(command)), { commands: probeData.report.operatorInjectionCommands, nextCommands: probeData.report.nextCommands }));
      checks.push(check("runtime:context-pack-embeds-skill-capsules", probeData.pack.memorySkillCapsules?.MemorySkillCapsuleV9 === true && (probeData.pack.artifactIndex ?? []).some((entry) => /memory_skill_capsule_report/.test(entry.kind)), { packPath: probeData.packPath, memorySkillCapsules: probeData.pack.memorySkillCapsules }));
      checks.push(check("runtime:orchestrator-wiring", stepIds.has("skill_capsule_operator_injection") && (probeData.orchestrator?.requiredGates ?? []).includes("MemorySkillCapsuleV9"), { steps: Array.from(stepIds), gates: probeData.orchestrator?.requiredGates }));
      checks.push(check("runtime:required-gates", ["MemorySkillCapsuleV9", "skill_capsule_assetization", "verified_skill_promotion_gate", "operator_skill_injection", "memory_skill_capsules_in_context_pack", "experience_to_skill_capsule", "distilled_pattern_to_skill_capsule"].every((gate) => gates.has(gate)), { requiredGates: probeData.report.requiredGates }));
    } else {
      for (const id of ["runtime:report-schema", "runtime:capsule-ledger-schema", "runtime:experience-lesson-to-operator-capsule", "runtime:avoid-lesson-to-avoid-capsule", "runtime:verified-promotion-gate", "runtime:operator-skill-injection", "runtime:context-pack-embeds-skill-capsules", "runtime:orchestrator-wiring", "runtime:required-gates"]) checks.push(check(id, false, { error: "probe output missing" }));
    }
    checks.push(check("code:skill-capsule-markers", ["MemorySkillCapsuleV9", "buildMemorySkillCapsuleReport", "formatMemorySkillCapsules", "memorySkillCapsuleReportPath", "skill_capsule_assetization"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["MemorySkillCapsuleV9", "buildMemorySkillCapsuleReport"] }));
    checks.push(check("profile:skill-capsule-markers", ["MemorySkillCapsuleV9", "buildMemorySkillCapsuleReport", "formatMemorySkillCapsules", "memorySkillCapsuleReportPath", "skill_capsule_assetization"].every((marker) => readText("repi-profile/extensions/reverse-pentest-core.ts").includes(marker)), { markers: ["MemorySkillCapsuleV9", "buildMemorySkillCapsuleReport"] }));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  } finally {
    if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = { kind: "repi-memory-skill-capsule-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "memory-skill-capsule", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI Memory Skill Capsule Gate");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
  }
  if (strict && failed.length) process.exit(1);
}
main();

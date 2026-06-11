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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_DISTILL_PROMOTION_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/memory-distill-promotion.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-distill-promotion.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));
function check(id, status, evidence = {}) { return { id, status: status ? "pass" : "fail", evidence }; }
function typeOk(value, type) {
  if (Array.isArray(type)) return type.some((item) => typeOk(value, item));
  if (type === "array") return Array.isArray(value);
  if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
  if (type === "integer") return Number.isInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  if (type === "null") return value === null;
  return typeof value === type;
}
function resolveRef(schema, ref) { if (!ref?.startsWith("#/$defs/")) throw new Error(`unsupported ref: ${ref}`); return schema.$defs?.[ref.slice("#/$defs/".length)]; }
function validateSchema(value, node, schema, path = "$") {
  if (!node) return [];
  if (node.$ref) return validateSchema(value, resolveRef(schema, node.$ref), schema, path);
  const errors = [];
  if (node.const !== undefined && value !== node.const) errors.push(`${path}: const ${JSON.stringify(node.const)} expected`);
  if (node.enum && !node.enum.includes(value)) errors.push(`${path}: enum ${node.enum.join("|")} expected`);
  if (node.type && !typeOk(value, node.type)) { errors.push(`${path}: type ${JSON.stringify(node.type)} expected`); return errors; }
  if (typeof value === "string" && node.format === "date-time" && Number.isNaN(Date.parse(value))) errors.push(`${path}: invalid date-time`);
  if (typeof value === "number") { if (node.minimum !== undefined && value < node.minimum) errors.push(`${path}: minimum ${node.minimum}`); if (node.maximum !== undefined && value > node.maximum) errors.push(`${path}: maximum ${node.maximum}`); }
  if (Array.isArray(value) && node.items) value.forEach((item, index) => errors.push(...validateSchema(item, node.items, schema, `${path}[${index}]`)));
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const key of node.required ?? []) if (!(key in value)) errors.push(`${path}.${key}: required`);
    for (const [key, propSchema] of Object.entries(node.properties ?? {})) if (key in value) errors.push(...validateSchema(value[key], propSchema, schema, `${path}.${key}`));
    if (node.additionalProperties === false) { const allowed = new Set(Object.keys(node.properties ?? {})); for (const key of Object.keys(value)) if (!allowed.has(key)) errors.push(`${path}.${key}: additionalProperty`); }
  }
  return errors;
}
function validateFixture(fixture) {
  const required = ["MemoryDistillPromotionV10", "provider_distill_contract", "artifact_to_claim_distillation", "verifier_backed_promotion_gate", "skill_capsule_promotion_writeback", "memory_distill_promotion_in_context_pack", "memory_distill_orchestrator_step"];
  const scenarios = ["local-provider-contract-fallback-is-deterministic", "skill-capsule-promotes-artifact-backed-candidate", "experience-claim-enters-distill-candidate-ledger", "provider-api-key-is-env-ref-only", "context-pack-embeds-distill-promotion-report", "orchestrator-runs-distill-promotion-step"];
  const gates = new Set(fixture.requiredGates ?? []);
  const valid = new Set(fixture.validScenarios ?? []);
  return { missingGates: required.filter((gate) => !gates.has(gate)), missingScenarios: scenarios.filter((scenario) => !valid.has(scenario)) };
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
const artifact = join(tempRoot, "distill-proof.txt");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
writeFileSync(artifact, "verified runtime artifact for MemoryDistillPromotionV10\\nclaim: replay proves authorization bypass route\\n");
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "memory-distill-session";
process.env.REPI_BRANCH_ID = "memory-distill-branch";
process.env.REPI_MEMORY_DISTILL_PROVIDER = "openai-compatible";
process.env.REPI_MEMORY_DISTILL_API_KEY_ENV = "REPI_TEST_DISTILL_KEY";
const tools = new Map();
const handlers = new Map();
const fakePi = { registerCommand() {}, registerTool(tool) { tools.set(tool.name, tool); }, on(name, handler) { handlers.set(name, handler); }, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {}, exec: async () => ({ code: 0, stdout: "memory-distill-probe", stderr: "", killed: false }) };
createReconExtensionFactory()(fakePi);
const memory = tools.get("re_memory");
const context = tools.get("re_context");
if (!memory || !context) throw new Error("missing re_memory or re_context");
function text(result) { return result?.content?.[0]?.text ?? ""; }
function artifactPath(output, label) { const match = new RegExp(label + ": (.+)").exec(output); if (!match?.[1]) throw new Error("missing artifact label " + label + " in output\\n" + output.slice(0, 1000)); return match[1].trim(); }
function parseJsonArtifact(path) { const body = readFileSync(path, "utf8"); const fence = String.fromCharCode(96).repeat(3); const start = body.indexOf(fence + "json"); const contentStart = body.indexOf("\\n", start); const end = body.indexOf(fence, contentStart + 1); if (start < 0 || contentStart < 0 || end < 0) throw new Error("missing json block in " + path); return JSON.parse(body.slice(contentStart + 1, end).trim()); }
async function main() {
  await handlers.get("before_agent_start")?.({ prompt: "web authz provider distill promotion", systemPrompt: "base" }, { hasUI: false, ui: {} });
  await memory.execute("memory-distill", { action: "deposit", scene: "web", title: "verified distill replay", command: "curl https://target.local/api/distill-proof", route: "web", target: "https://target.local", text: "outcome=success confidence=0.95 replayVerified=true playbookCandidate=true verifierRuleCandidate=true artifactPath=" + artifact + "\\ncurl https://target.local/api/distill-proof\\nverified provider distill command" });
  await memory.execute("memory-distill", { action: "append", scene: "web", title: "distill stale failure", text: "outcome=failure confidence=0.74 route=web target=https://target.local\\ncurl https://target.local/api/distill-stale\\nstale provider route; avoid stale replay" });
  const reportResult = await memory.execute("memory-distill", { action: "distill-promote", route: "web", target: "https://target.local" });
  const report = reportResult.details;
  const ledgerText = readFileSync(report.candidateLedgerPath, "utf8");
  const orchestratorResult = await memory.execute("memory-distill", { action: "orchestrate", phase: "pre-operator", query: "distill-proof target.local", target: "https://target.local" });
  const orchestrator = orchestratorResult.details;
  const packOutput = text(await context.execute("memory-distill", { action: "pack", target: "https://target.local" }));
  const packPath = artifactPath(packOutput, "context_artifact");
  const pack = parseJsonArtifact(packPath);
  writeFileSync(outPath, JSON.stringify({ reportText: text(reportResult), report, ledgerText, orchestrator, packPath, pack, promotionBookText: readFileSync(report.promotionBookPath, "utf8") }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}
function runProbe(tempRoot) {
  const probePath = join(tempRoot, "memory-distill-promotion-probe.ts");
  const outPath = join(tempRoot, "probe-result.json");
  writeProbe(probePath, outPath, tempRoot);
  const tsx = join(root, "node_modules", ".bin", "tsx");
  const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], { cwd: root, env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1" }, encoding: "utf8", maxBuffer: 50 * 1024 * 1024 });
  return { ...result, outPath, probePath };
}
function main() {
  const checks = [];
  const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-distill-promotion-"));
  let probeData;
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", schema?.$defs?.MemoryDistillPromotionReportV10 && schema?.$defs?.MemoryDistillCandidateV10 && schema?.$defs?.MemoryDistillProviderV10, { path: SCHEMA_PATH }));
    const fixtureEval = validateFixture(fixture);
    checks.push(check("fixture:distill-promotion-scenarios", fixtureEval.missingGates.length === 0 && fixtureEval.missingScenarios.length === 0, fixtureEval));
    const probe = runProbe(tempRoot);
    checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
    if (probe.status === 0 && existsSync(probe.outPath)) {
      probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
      const reportErrors = validateSchema(probeData.report, schema.$defs.MemoryDistillPromotionReportV10, schema, "$.report");
      const candidates = probeData.ledgerText.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
      const candidateErrors = candidates.flatMap((candidate, index) => validateSchema(candidate, schema.$defs.MemoryDistillCandidateV10, schema, `$.candidates[${index}]`));
      const gates = new Set(probeData.report.requiredGates ?? []);
      const stepIds = new Set((probeData.orchestrator?.steps ?? []).map((step) => step.id));
      checks.push(check("runtime:report-schema", reportErrors.length === 0, { errors: reportErrors, reportPath: probeData.report.reportPath, sha256: sha256(JSON.stringify(probeData.report)).slice(0, 24) }));
      checks.push(check("runtime:candidate-ledger-schema", candidateErrors.length === 0 && candidates.length === probeData.report.candidateCount && candidates.every((row) => row.MemoryDistillPromotionV10 && row.entryHash), { errors: candidateErrors, candidateCount: candidates.length }));
      checks.push(check("runtime:provider-contract-fallback", probeData.report.provider.requestedBackend === "openai-compatible" && probeData.report.provider.backend === "local-rule" && probeData.report.provider.apiKeyEnv === "REPI_TEST_DISTILL_KEY" && !JSON.stringify(probeData.report.provider).includes("sk-"), { provider: probeData.report.provider }));
      checks.push(check("runtime:artifact-backed-promotion", candidates.some((row) => row.promotionDecision === "promote" && row.evidenceRefs.some((ref) => ref.sha256)), { promoted: candidates.filter((row) => row.promotionDecision === "promote").map((row) => row.id) }));
      checks.push(check("runtime:experience-claim-candidates", candidates.some((row) => row.sourceType === "experience_claim"), { sourceTypes: candidates.map((row) => row.sourceType) }));
      checks.push(check("runtime:operator-injection", probeData.report.operatorInjectionCommands.some((command) => /distill-proof/.test(command)) && probeData.report.nextCommands.some((command) => /re_operator plan/.test(command)), { commands: probeData.report.operatorInjectionCommands, nextCommands: probeData.report.nextCommands }));
      checks.push(check("runtime:context-pack-embeds-distill-promotion", probeData.pack.memoryDistillPromotion?.MemoryDistillPromotionV10 === true && (probeData.pack.artifactIndex ?? []).some((entry) => /memory_distill_promotion_report/.test(entry.kind)), { packPath: probeData.packPath, memoryDistillPromotion: probeData.pack.memoryDistillPromotion }));
      checks.push(check("runtime:orchestrator-wiring", stepIds.has("distill_promotion_provider_gate") && (probeData.orchestrator?.requiredGates ?? []).includes("MemoryDistillPromotionV10"), { steps: Array.from(stepIds), gates: probeData.orchestrator?.requiredGates }));
      checks.push(check("runtime:required-gates", ["MemoryDistillPromotionV10", "provider_distill_contract", "artifact_to_claim_distillation", "verifier_backed_promotion_gate", "skill_capsule_promotion_writeback", "memory_distill_promotion_in_context_pack", "memory_distill_orchestrator_step"].every((gate) => gates.has(gate)), { requiredGates: probeData.report.requiredGates }));
    } else {
      for (const id of ["runtime:report-schema", "runtime:candidate-ledger-schema", "runtime:provider-contract-fallback", "runtime:artifact-backed-promotion", "runtime:experience-claim-candidates", "runtime:operator-injection", "runtime:context-pack-embeds-distill-promotion", "runtime:orchestrator-wiring", "runtime:required-gates"]) checks.push(check(id, false, { error: "probe output missing" }));
    }
    checks.push(check("code:distill-promotion-markers", ["MemoryDistillPromotionV10", "buildMemoryDistillPromotionReport", "formatMemoryDistillPromotion", "memoryDistillPromotionReportPath", "provider_distill_contract"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["MemoryDistillPromotionV10", "buildMemoryDistillPromotionReport"] }));
    checks.push(check("profile:distill-promotion-markers", ["MemoryDistillPromotionV10", "buildMemoryDistillPromotionReport", "formatMemoryDistillPromotion", "memoryDistillPromotionReportPath", "provider_distill_contract"].every((marker) => readText("repi-profile/extensions/reverse-pentest-core.ts").includes(marker)), { markers: ["MemoryDistillPromotionV10", "buildMemoryDistillPromotionReport"] }));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  } finally {
    if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = { kind: "repi-memory-distill-promotion-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "memory-distill-promotion", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2)); else { console.log("# REPI Memory Distill Promotion Gate"); for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`); console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`); }
  if (strict && failed.length) process.exit(1);
}
main();

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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_REPLAY_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/memory-replay-evaluator.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-replay-evaluator.fixture.json";
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
  if (typeof value === "string") { if (node.minLength && value.length < node.minLength) errors.push(`${path}: minLength ${node.minLength}`); if (node.format === "date-time" && Number.isNaN(Date.parse(value))) errors.push(`${path}: invalid date-time`); }
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
  const required = ["MemoryReplayEvaluatorV12", "memory_ab_replay", "causal_attribution_signal", "replay_delta_feedback_writeback", "append_only_replay_ledger", "memory_replay_in_quality_ledger", "memory_replay_in_context_pack", "memory_replay_orchestrator_step"];
  const scenarios = ["memory-ab-replay-promotes-useful-memory", "causal-attribution-estimates-saved-steps", "quality-ledger-consumes-replay-signal", "context-pack-embeds-replay-report", "orchestrator-runs-replay-causal-step"];
  const gates = new Set(fixture.requiredGates ?? []);
  const valid = new Set(fixture.validScenarios ?? []);
  return { missingGates: required.filter((gate) => !gates.has(gate)), missingScenarios: scenarios.filter((scenario) => !valid.has(scenario)) };
}
function writeProbe(probePath, outPath, tempRoot) {
  const importUrl = pathToFileURL(join(root, "packages/coding-agent/src/core/recon-profile.ts")).href;
  writeFileSync(probePath, `
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createReconExtensionFactory } from ${JSON.stringify(importUrl)};
const outPath = ${JSON.stringify(outPath)};
const tempRoot = ${JSON.stringify(tempRoot)};
const agentDir = join(tempRoot, "agent");
const workspace = join(tempRoot, "workspace");
const proof = join(tempRoot, "memory-replay-proof.txt");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
writeFileSync(proof, "verified runtime artifact for MemoryReplayEvaluatorV12\\n");
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "memory-replay-session";
process.env.REPI_BRANCH_ID = "memory-replay-branch";
const tools = new Map();
const handlers = new Map();
const fakePi = { registerCommand() {}, registerTool(tool) { tools.set(tool.name, tool); }, on(name, handler) { handlers.set(name, handler); }, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {}, exec: async () => ({ code: 0, stdout: "memory-replay-probe", stderr: "", killed: false }) };
createReconExtensionFactory()(fakePi);
const memory = tools.get("re_memory");
const context = tools.get("re_context");
if (!memory || !context) throw new Error("missing re_memory or re_context");
function text(result) { return result?.content?.[0]?.text ?? ""; }
function artifactPath(output, label) { const match = new RegExp(label + ": (.+)").exec(output); if (!match?.[1]) throw new Error("missing artifact label " + label + " in output\\n" + output.slice(0, 1000)); return match[1].trim(); }
function parseJsonArtifact(path) { const body = readFileSync(path, "utf8"); const fence = String.fromCharCode(96).repeat(3); const start = body.indexOf(fence + "json"); const contentStart = body.indexOf("\\n", start); const end = body.indexOf(fence, contentStart + 1); if (start < 0 || contentStart < 0 || end < 0) throw new Error("missing json block in " + path); return JSON.parse(body.slice(contentStart + 1, end).trim()); }
function rowHash(row) { const { entryHash, ...withoutHash } = row; return createHash("sha256").update(JSON.stringify(withoutHash)).digest("hex"); }
async function main() {
  await handlers.get("before_agent_start")?.({ prompt: "web authz memory replay evaluator", systemPrompt: "base" }, { hasUI: false, ui: {} });
  const success = await memory.execute("memory-replay", { action: "deposit", scene: "web", title: "ab replay verified proof", command: "curl https://target.local/api/ab-replay-proof", route: "web", target: "https://target.local", text: "outcome=success confidence=0.97 replayVerified=true playbookCandidate=true verifierRuleCandidate=true artifactPath=" + proof + "\\ncurl https://target.local/api/ab-replay-proof\\nab replay proof authz reusable verified" });
  const stale = await memory.execute("memory-replay", { action: "deposit", scene: "web", title: "ab replay stale failure", command: "curl https://target.local/api/ab-replay-stale", route: "web", target: "https://target.local", text: "outcome=failure confidence=0.74 artifactPath=" + proof + "\\ncurl https://target.local/api/ab-replay-stale\\nstale ab replay route should not win" });
  const successId = success.details.deposition.memoryEventId;
  const staleId = stale.details.deposition.memoryEventId;
  await memory.execute("memory-replay", { action: "append", scene: "web", title: "ab replay positive feedback", text: "outcome=success confidence=0.94 route=web target=https://target.local memory_reuse_feedback_promote event=" + successId + "\\nverified reuse succeeded for ab replay proof" });
  await memory.execute("memory-replay", { action: "eval" });
  const qualityBefore = (await memory.execute("memory-replay", { action: "quality", route: "web", target: "https://target.local" })).details;
  const replayResult = await memory.execute("memory-replay", { action: "replay", query: "ab replay proof authz reusable", route: "web", target: "https://target.local" });
  const report = replayResult.details;
  const qualityAfter = (await memory.execute("memory-replay", { action: "quality", route: "web", target: "https://target.local" })).details;
  const ledgerRows = readFileSync(report.ledgerPath, "utf8").split(/\\r?\\n/).filter(Boolean).map((line) => JSON.parse(line));
  const orchestrator = (await memory.execute("memory-replay", { action: "orchestrate", phase: "pre-operator", query: "ab replay proof authz reusable", target: "https://target.local" })).details;
  const packOutput = text(await context.execute("memory-replay", { action: "pack", target: "https://target.local" }));
  const packPath = artifactPath(packOutput, "context_artifact");
  const pack = parseJsonArtifact(packPath);
  const hashErrors = [];
  let prev = "0".repeat(64);
  for (const row of ledgerRows) { if (row.prevHash !== prev) hashErrors.push("prev:" + row.id); if (row.entryHash !== rowHash(row)) hashErrors.push("hash:" + row.id); prev = row.entryHash; }
  writeFileSync(outPath, JSON.stringify({ reportText: text(replayResult), report, ledgerRows, hashErrors, successId, staleId, qualityBefore, qualityAfter, orchestrator, packPath, pack, boardText: readFileSync(report.boardPath, "utf8") }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}
function runProbe(tempRoot) {
  const probePath = join(tempRoot, "memory-replay-evaluator-probe.ts");
  const outPath = join(tempRoot, "probe-result.json");
  writeProbe(probePath, outPath, tempRoot);
  const tsx = join(root, "node_modules", ".bin", "tsx");
  const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], { cwd: root, env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1" }, encoding: "utf8", maxBuffer: 60 * 1024 * 1024 });
  return { ...result, outPath, probePath };
}
function main() {
  const checks = [];
  const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-replay-"));
  let probeData;
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", schema?.$defs?.MemoryReplayEvaluatorReportV12 && schema?.$defs?.MemoryReplayEvaluatorRowV12, { path: SCHEMA_PATH }));
    const fixtureEval = validateFixture(fixture);
    checks.push(check("fixture:replay-evaluator-scenarios", fixtureEval.missingGates.length === 0 && fixtureEval.missingScenarios.length === 0, fixtureEval));
    const probe = runProbe(tempRoot);
    checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
    if (probe.status === 0 && existsSync(probe.outPath)) {
      probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
      const reportErrors = validateSchema(probeData.report, schema.$defs.MemoryReplayEvaluatorReportV12, schema, "$.report");
      const rowErrors = probeData.ledgerRows.flatMap((row, index) => validateSchema(row, schema.$defs.MemoryReplayEvaluatorRowV12, schema, `$.rows[${index}]`));
      const gateSet = new Set(probeData.report.requiredGates ?? []);
      const stepIds = new Set((probeData.orchestrator?.steps ?? []).map((step) => step.id));
      const qualityRows = new Map((probeData.qualityAfter?.rows ?? []).map((row) => [row.eventId, row]));
      const successQuality = qualityRows.get(probeData.successId);
      checks.push(check("runtime:report-schema", reportErrors.length === 0, { errors: reportErrors, reportPath: probeData.report.reportPath, sha256: sha256(JSON.stringify(probeData.report)).slice(0, 24) }));
      checks.push(check("runtime:ledger-row-schema", rowErrors.length === 0 && probeData.ledgerRows.every((row) => row.MemoryReplayEvaluatorV12 && row.entryHash), { errors: rowErrors, rows: probeData.ledgerRows.length }));
      checks.push(check("runtime:append-only-hash-chain", probeData.hashErrors.length === 0 && probeData.ledgerRows.length >= probeData.report.rowCount, { hashErrors: probeData.hashErrors, rows: probeData.ledgerRows.length }));
      checks.push(check("runtime:ab-replay-improves-memory", probeData.report.attributionEventIds.includes(probeData.successId) && probeData.report.improvedScenarioIds.length > 0 && probeData.report.totalSavedStepEstimate > 0, { attributionEventIds: probeData.report.attributionEventIds, improved: probeData.report.improvedScenarioIds, saved: probeData.report.totalSavedStepEstimate }));
      checks.push(check("runtime:causal-score-and-writeback", probeData.report.averageCausalScore >= 60 && probeData.report.rows.some((row) => row.feedbackWritebackCommands.some((cmd) => /memory_ab_replay_promote/.test(cmd))), { averageCausalScore: probeData.report.averageCausalScore, rows: probeData.report.rows }));
      checks.push(check("runtime:quality-ledger-consumes-replay", successQuality?.signals?.includes("ab_replay_improved") && successQuality.qualityScore >= 60, { successQuality }));
      checks.push(check("runtime:context-pack-embeds-replay", probeData.pack.memoryReplay?.MemoryReplayEvaluatorV12 === true && (probeData.pack.artifactIndex ?? []).some((entry) => /memory_replay_report/.test(entry.kind)), { packPath: probeData.packPath, memoryReplay: probeData.pack.memoryReplay }));
      checks.push(check("runtime:orchestrator-wiring", stepIds.has("memory_ab_replay_causal_attribution") && (probeData.orchestrator?.requiredGates ?? []).includes("MemoryReplayEvaluatorV12"), { steps: Array.from(stepIds), gates: probeData.orchestrator?.requiredGates }));
      checks.push(check("runtime:required-gates", ["MemoryReplayEvaluatorV12", "memory_ab_replay", "causal_attribution_signal", "replay_delta_feedback_writeback", "append_only_replay_ledger", "memory_replay_in_quality_ledger", "memory_replay_in_context_pack", "memory_replay_orchestrator_step"].every((gate) => gateSet.has(gate)), { requiredGates: probeData.report.requiredGates }));
    } else {
      for (const id of ["runtime:report-schema", "runtime:ledger-row-schema", "runtime:append-only-hash-chain", "runtime:ab-replay-improves-memory", "runtime:causal-score-and-writeback", "runtime:quality-ledger-consumes-replay", "runtime:context-pack-embeds-replay", "runtime:orchestrator-wiring", "runtime:required-gates"]) checks.push(check(id, false, { error: "probe output missing" }));
    }
    checks.push(check("code:replay-evaluator-markers", ["MemoryReplayEvaluatorV12", "buildMemoryReplayEvaluatorReport", "formatMemoryReplayEvaluator", "memoryReplayEvaluatorReportPath", "memory_ab_replay", "causal_attribution_signal"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["MemoryReplayEvaluatorV12", "buildMemoryReplayEvaluatorReport"] }));
    checks.push(check("profile:replay-evaluator-markers", ["MemoryReplayEvaluatorV12", "buildMemoryReplayEvaluatorReport", "formatMemoryReplayEvaluator", "memoryReplayEvaluatorReportPath", "memory_ab_replay", "causal_attribution_signal"].every((marker) => readText("repi-profile/extensions/reverse-pentest-core.ts").includes(marker)), { markers: ["MemoryReplayEvaluatorV12", "buildMemoryReplayEvaluatorReport"] }));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  } finally {
    if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = { kind: "repi-memory-replay-evaluator-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "memory-replay-evaluator", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2)); else { console.log("# REPI Memory Replay Evaluator Gate"); for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`); console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`); }
  if (strict && failed.length) process.exit(1);
}
main();

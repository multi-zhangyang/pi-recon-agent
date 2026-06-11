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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_QUALITY_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/memory-quality-ledger.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-quality-ledger.fixture.json";
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
  const required = ["MemoryQualityLedgerV11", "active_memory_policy", "quality_score_feedback_loop", "usefulness_feedback_writeback", "append_only_quality_ledger", "memory_quality_drives_sedimentation", "memory_quality_in_context_pack", "memory_quality_orchestrator_step"];
  const scenarios = ["retrieval-and-injection-increase-quality-score", "positive-feedback-promotes-memory", "negative-feedback-demotes-memory", "pending-injected-memory-requires-feedback", "quality-ledger-drives-sedimentation", "context-pack-embeds-quality-report", "orchestrator-runs-quality-feedback-loop"];
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
const proof = join(tempRoot, "quality-proof.txt");
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
writeFileSync(proof, "verified runtime artifact for MemoryQualityLedgerV11\\n");
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "memory-quality-session";
process.env.REPI_BRANCH_ID = "memory-quality-branch";
const tools = new Map();
const handlers = new Map();
const fakePi = { registerCommand() {}, registerTool(tool) { tools.set(tool.name, tool); }, on(name, handler) { handlers.set(name, handler); }, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {}, exec: async () => ({ code: 0, stdout: "memory-quality-probe", stderr: "", killed: false }) };
createReconExtensionFactory()(fakePi);
const memory = tools.get("re_memory");
const context = tools.get("re_context");
if (!memory || !context) throw new Error("missing re_memory or re_context");
function text(result) { return result?.content?.[0]?.text ?? ""; }
function artifactPath(output, label) { const match = new RegExp(label + ": (.+)").exec(output); if (!match?.[1]) throw new Error("missing artifact label " + label + " in output\\n" + output.slice(0, 1000)); return match[1].trim(); }
function parseJsonArtifact(path) { const body = readFileSync(path, "utf8"); const fence = String.fromCharCode(96).repeat(3); const start = body.indexOf(fence + "json"); const contentStart = body.indexOf("\\n", start); const end = body.indexOf(fence, contentStart + 1); if (start < 0 || contentStart < 0 || end < 0) throw new Error("missing json block in " + path); return JSON.parse(body.slice(contentStart + 1, end).trim()); }
function rowHash(row) { const { entryHash, ...withoutHash } = row; return createHash("sha256").update(JSON.stringify(withoutHash)).digest("hex"); }
async function main() {
  await handlers.get("before_agent_start")?.({ prompt: "web authz memory quality ledger", systemPrompt: "base" }, { hasUI: false, ui: {} });
  const success = await memory.execute("memory-quality", { action: "deposit", scene: "web", title: "quality verified replay", command: "curl https://target.local/api/quality-proof", route: "web", target: "https://target.local", text: "outcome=success confidence=0.96 replayVerified=true playbookCandidate=true verifierRuleCandidate=true artifactPath=" + proof + "\\ncurl https://target.local/api/quality-proof\\nquality proof reusable authz replay" });
  const pending = await memory.execute("memory-quality", { action: "deposit", scene: "web", title: "quality pending replay", command: "curl https://target.local/api/quality-pending", route: "web", target: "https://target.local", text: "outcome=success confidence=0.9 replayVerified=true playbookCandidate=true verifierRuleCandidate=true artifactPath=" + proof + "\\ncurl https://target.local/api/quality-pending\\npending feedback reusable replay" });
  const failure = await memory.execute("memory-quality", { action: "deposit", scene: "web", title: "quality stale failure", command: "curl https://target.local/api/quality-stale", route: "web", target: "https://target.local", text: "outcome=failure confidence=0.8 route=web target=https://target.local\\ncurl https://target.local/api/quality-stale\\nstale route failed; avoid reuse" });
  const successId = success.details.deposition.memoryEventId;
  const pendingId = pending.details.deposition.memoryEventId;
  const failureId = failure.details.deposition.memoryEventId;
  await memory.execute("memory-quality", { action: "append", scene: "web", title: "quality positive feedback", text: "outcome=success confidence=0.93 route=web target=https://target.local memory_reuse_feedback_promote event=" + successId + "\\nverified reuse succeeded for quality proof" });
  await memory.execute("memory-quality", { action: "append", scene: "web", title: "quality negative feedback", text: "outcome=failure confidence=0.81 route=web target=https://target.local memory_reuse_feedback_demote event=" + failureId + "\\nverified reuse failed for stale quality route" });
  await memory.execute("memory-quality", { action: "search-events", query: "quality proof authz replay", route: "web", target: "https://target.local" });
  await memory.execute("memory-quality", { action: "eval" });
  await memory.execute("memory-quality", { action: "feedback" });
  const qualityResult = await memory.execute("memory-quality", { action: "quality", route: "web", target: "https://target.local" });
  const report = qualityResult.details;
  const ledgerRows = readFileSync(report.ledgerPath, "utf8").split(/\\r?\\n/).filter(Boolean).map((line) => JSON.parse(line));
  const orchestratorResult = await memory.execute("memory-quality", { action: "orchestrate", phase: "pre-operator", query: "quality proof target.local", target: "https://target.local" });
  const orchestrator = orchestratorResult.details;
  const packOutput = text(await context.execute("memory-quality", { action: "pack", target: "https://target.local" }));
  const packPath = artifactPath(packOutput, "context_artifact");
  const pack = parseJsonArtifact(packPath);
  const hashErrors = [];
  let prev = "0".repeat(64);
  for (const row of ledgerRows) { if (row.prevHash !== prev) hashErrors.push("prev:" + row.id); if (row.entryHash !== rowHash(row)) hashErrors.push("hash:" + row.id); prev = row.entryHash; }
  writeFileSync(outPath, JSON.stringify({ reportText: text(qualityResult), report, ledgerRows, hashErrors, successId, pendingId, failureId, orchestrator, packPath, pack, boardText: readFileSync(report.boardPath, "utf8") }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}
function runProbe(tempRoot) {
  const probePath = join(tempRoot, "memory-quality-ledger-probe.ts");
  const outPath = join(tempRoot, "probe-result.json");
  writeProbe(probePath, outPath, tempRoot);
  const tsx = join(root, "node_modules", ".bin", "tsx");
  const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], { cwd: root, env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1" }, encoding: "utf8", maxBuffer: 50 * 1024 * 1024 });
  return { ...result, outPath, probePath };
}
function main() {
  const checks = [];
  const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-quality-"));
  let probeData;
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", schema?.$defs?.MemoryQualityLedgerReportV11 && schema?.$defs?.MemoryQualityLedgerRowV11, { path: SCHEMA_PATH }));
    const fixtureEval = validateFixture(fixture);
    checks.push(check("fixture:quality-ledger-scenarios", fixtureEval.missingGates.length === 0 && fixtureEval.missingScenarios.length === 0, fixtureEval));
    const probe = runProbe(tempRoot);
    checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
    if (probe.status === 0 && existsSync(probe.outPath)) {
      probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
      const reportErrors = validateSchema(probeData.report, schema.$defs.MemoryQualityLedgerReportV11, schema, "$.report");
      const rowErrors = probeData.ledgerRows.flatMap((row, index) => validateSchema(row, schema.$defs.MemoryQualityLedgerRowV11, schema, `$.rows[${index}]`));
      const latestByEvent = new Map(probeData.ledgerRows.map((row) => [row.eventId, row]));
      const successRow = latestByEvent.get(probeData.successId);
      const pendingRow = latestByEvent.get(probeData.pendingId);
      const failureRow = latestByEvent.get(probeData.failureId);
      const gateSet = new Set(probeData.report.requiredGates ?? []);
      const stepIds = new Set((probeData.orchestrator?.steps ?? []).map((step) => step.id));
      checks.push(check("runtime:report-schema", reportErrors.length === 0, { errors: reportErrors, reportPath: probeData.report.reportPath, sha256: sha256(JSON.stringify(probeData.report)).slice(0, 24) }));
      checks.push(check("runtime:ledger-row-schema", rowErrors.length === 0 && probeData.ledgerRows.every((row) => row.MemoryQualityLedgerV11 && row.entryHash), { errors: rowErrors, rows: probeData.ledgerRows.length }));
      checks.push(check("runtime:append-only-hash-chain", probeData.hashErrors.length === 0 && probeData.ledgerRows.length >= probeData.report.rowCount, { hashErrors: probeData.hashErrors, rows: probeData.ledgerRows.length }));
      checks.push(check("runtime:positive-feedback-promotes", successRow && ["promote", "retain"].includes(successRow.lifecycleDecision) && successRow.positiveFeedbackCount > 0 && successRow.qualityScore >= 60, { successRow }));
      checks.push(check("runtime:negative-feedback-demotes", failureRow && failureRow.lifecycleDecision === "demote" && failureRow.negativeFeedbackCount > 0, { failureRow }));
      checks.push(check("runtime:pending-feedback-tracked", pendingRow && pendingRow.injectedCount >= 1 && (pendingRow.pendingFeedbackCount >= 1 || probeData.report.requiredFeedbackEventIds.includes(probeData.pendingId)), { pendingRow, requiredFeedbackEventIds: probeData.report.requiredFeedbackEventIds }));
      checks.push(check("runtime:quality-drives-sedimentation", probeData.report.requiredGates.includes("memory_quality_drives_sedimentation") && probeData.report.nextCommands.includes("re_memory quality"), { requiredGates: probeData.report.requiredGates, nextCommands: probeData.report.nextCommands }));
      checks.push(check("runtime:operator-injection", probeData.report.operatorInjectionCommands.some((command) => /quality-proof|quality-pending/.test(command)), { commands: probeData.report.operatorInjectionCommands }));
      checks.push(check("runtime:context-pack-embeds-quality", probeData.pack.memoryQuality?.MemoryQualityLedgerV11 === true && (probeData.pack.artifactIndex ?? []).some((entry) => /memory_quality_report/.test(entry.kind)), { packPath: probeData.packPath, memoryQuality: probeData.pack.memoryQuality }));
      checks.push(check("runtime:orchestrator-wiring", stepIds.has("memory_quality_feedback_loop") && (probeData.orchestrator?.requiredGates ?? []).includes("MemoryQualityLedgerV11"), { steps: Array.from(stepIds), gates: probeData.orchestrator?.requiredGates }));
      checks.push(check("runtime:required-gates", ["MemoryQualityLedgerV11", "active_memory_policy", "quality_score_feedback_loop", "usefulness_feedback_writeback", "append_only_quality_ledger", "memory_quality_drives_sedimentation", "memory_quality_in_context_pack", "memory_quality_orchestrator_step"].every((gate) => gateSet.has(gate)), { requiredGates: probeData.report.requiredGates }));
    } else {
      for (const id of ["runtime:report-schema", "runtime:ledger-row-schema", "runtime:append-only-hash-chain", "runtime:positive-feedback-promotes", "runtime:negative-feedback-demotes", "runtime:pending-feedback-tracked", "runtime:quality-drives-sedimentation", "runtime:operator-injection", "runtime:context-pack-embeds-quality", "runtime:orchestrator-wiring", "runtime:required-gates"]) checks.push(check(id, false, { error: "probe output missing" }));
    }
    checks.push(check("code:quality-ledger-markers", ["MemoryQualityLedgerV11", "buildMemoryQualityLedgerReport", "formatMemoryQualityLedger", "memoryQualityReportPath", "active_memory_policy", "quality_score_feedback_loop"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["MemoryQualityLedgerV11", "buildMemoryQualityLedgerReport"] }));
    checks.push(check("profile:quality-ledger-markers", ["MemoryQualityLedgerV11", "buildMemoryQualityLedgerReport", "formatMemoryQualityLedger", "memoryQualityReportPath", "active_memory_policy", "quality_score_feedback_loop"].every((marker) => readText("repi-profile/extensions/reverse-pentest-core.ts").includes(marker)), { markers: ["MemoryQualityLedgerV11", "buildMemoryQualityLedgerReport"] }));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  } finally {
    if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = { kind: "repi-memory-quality-ledger-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "memory-quality-ledger", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2)); else { console.log("# REPI Memory Quality Ledger Gate"); for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`); console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`); }
  if (strict && failed.length) process.exit(1);
}
main();

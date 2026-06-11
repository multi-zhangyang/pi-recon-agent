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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_MEMORY_DEPOSITION_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/memory-deposition.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/memory-deposition.fixture.json";
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
    "MemoryDepositionEngineV7",
    "runtime_step_event_bus",
    "post_tool_writeback_autocapture",
    "append_only_deposition_ledger",
    "memory_event_hash_binding",
    "claim_compact_resume_binding",
    "deposition_report_in_context_pack",
  ];
  const gates = new Set(fixture.requiredGates ?? []);
  const scenarios = new Set(fixture.validScenarios ?? []);
  return {
    missingGates: required.filter((gate) => !gates.has(gate)),
    missingScenarios: ["manual-runtime-deposit-writes-memory-event", "tool-result-autocapture-writes-deposition-row", "context-pack-embeds-deposition-report"].filter((id) => !scenarios.has(id)),
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
writeFileSync(artifact, "verified runtime artifact for MemoryDepositionEngineV7\\n");
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "memory-deposition-session";
process.env.REPI_BRANCH_ID = "memory-deposition-branch";
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
  exec: async () => ({ code: 0, stdout: "memory-deposition-probe", stderr: "", killed: false }),
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
  await handlers.get("before_agent_start")?.({ prompt: "web 渗透 API 安全 authz replay 逆向", systemPrompt: "base" }, { hasUI: false, ui: {} });
  await handlers.get("tool_result")?.({ type: "tool_result", toolCallId: "tc1", toolName: "bash", input: { command: "printf runtime-proof" }, content: [{ type: "text", text: "runtime-proof output" }], isError: false, details: { code: 0 } }, { hasUI: false, ui: {} });
  const manual = await memory.execute("memory-deposition", { action: "deposit", scene: "web", title: "manual runtime writeback", command: "curl https://target.local/api/proof", target: "https://target.local", text: "outcome=success confidence=0.91 replayVerified=true artifactPath=" + artifact + " verified authz replay command" });
  const reportResult = await memory.execute("memory-deposition", { action: "deposition-report" });
  const report = reportResult.details;
  const packOutput = text(await context.execute("memory-deposition", { action: "pack", target: "https://target.local" }));
  const packPath = artifactPath(packOutput, "context_artifact");
  const pack = parseJsonArtifact(packPath);
  writeFileSync(outPath, JSON.stringify({ tempRoot, agentDir, manualText: text(manual), reportText: text(reportResult), report, packPath, pack, eventBusText: readFileSync(report.depositionEventBusPath, "utf8") }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}

function runProbe(tempRoot) {
  const probePath = join(tempRoot, "memory-deposition-probe.ts");
  const outPath = join(tempRoot, "probe-result.json");
  writeProbe(probePath, outPath, tempRoot);
  const tsx = join(root, "node_modules", ".bin", "tsx");
  const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], {
    cwd: root,
    env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1" },
    encoding: "utf8",
    maxBuffer: 40 * 1024 * 1024,
  });
  return { ...result, outPath, probePath };
}

function main() {
  const checks = [];
  const tempRoot = mkdtempSync(join(tmpdir(), "repi-memory-deposition-"));
  let probeData;
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", schema?.$defs?.MemoryDepositionReportV7 && schema?.$defs?.MemoryDepositionRuntimeEventV7, { path: SCHEMA_PATH }));
    const fixtureEval = validateFixture(fixture);
    checks.push(check("fixture:deposition-scenarios", fixtureEval.missingGates.length === 0 && fixtureEval.missingScenarios.length === 0, fixtureEval));
    const probe = runProbe(tempRoot);
    checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
    if (probe.status === 0 && existsSync(probe.outPath)) {
      probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
      const schemaErrors = validateSchema(probeData.report, schema.$defs.MemoryDepositionReportV7, schema, "$.report");
      const gates = new Set(probeData.report.requiredGates ?? []);
      const events = probeData.eventBusText.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
      checks.push(check("runtime:report-schema", schemaErrors.length === 0, { errors: schemaErrors, reportPath: probeData.report.depositionReportPath, sha256: sha256(JSON.stringify(probeData.report)).slice(0, 24) }));
      checks.push(check("runtime:manual-deposit-memory-binding", /memory_deposition_event:/.test(probeData.manualText) && events.some((event) => event.command?.includes("curl https://target.local/api/proof") && event.memoryEventId), { manualText: probeData.manualText.slice(0, 800), eventCount: events.length }));
      checks.push(check("runtime:tool-result-autocapture", events.some((event) => event.source === "tool_result:bash" && event.stage === "shell" && event.memoryEventId), { sources: events.map((event) => event.source) }));
      checks.push(check("runtime:append-only-event-bus", events.every((event, index) => event.seq === index + 1 && event.entryHash && event.prevHash), { seq: events.map((event) => event.seq), latest: events.at(-1)?.entryHash }));
      checks.push(check("runtime:report-counters", probeData.report.runtimeEventCount >= 2 && probeData.report.memoryWritebackCount >= 2 && probeData.report.autoWritebackCoverage >= 0.85, { report: probeData.report }));
      checks.push(check("runtime:context-pack-embeds-deposition", probeData.pack.memoryDeposition?.MemoryDepositionEngineV7 === true && (probeData.pack.artifactIndex ?? []).some((entry) => /memory_deposition_report/.test(entry.kind)), { packPath: probeData.packPath, memoryDeposition: probeData.pack.memoryDeposition }));
      checks.push(check("runtime:orchestrator-wiring", probeData.pack.memoryOrchestrator?.memoryDepositionStatus && (probeData.pack.memoryOrchestrator?.requiredGates ?? []).includes("MemoryDepositionEngineV7"), { memoryOrchestrator: probeData.pack.memoryOrchestrator }));
      checks.push(check("runtime:required-gates", ["MemoryDepositionEngineV7", "runtime_step_event_bus", "post_tool_writeback_autocapture", "append_only_deposition_ledger", "memory_event_hash_binding", "claim_compact_resume_binding", "deposition_report_in_context_pack"].every((gate) => gates.has(gate)), { requiredGates: probeData.report.requiredGates }));
    } else {
      for (const id of ["runtime:report-schema", "runtime:manual-deposit-memory-binding", "runtime:tool-result-autocapture", "runtime:append-only-event-bus", "runtime:report-counters", "runtime:context-pack-embeds-deposition", "runtime:orchestrator-wiring", "runtime:required-gates"]) checks.push(check(id, false, { error: "probe output missing" }));
    }
    checks.push(check("code:deposition-markers", ["MemoryDepositionEngineV7", "appendMemoryDepositionRuntimeEvent", "buildMemoryDepositionReport", "memoryDepositionEventBusPath", "post_tool_writeback_autocapture"].every((marker) => readText("packages/coding-agent/src/core/recon-profile.ts").includes(marker)), { markers: ["MemoryDepositionEngineV7", "buildMemoryDepositionReport"] }));
    checks.push(check("profile:deposition-markers", ["MemoryDepositionEngineV7", "appendMemoryDepositionRuntimeEvent", "buildMemoryDepositionReport", "memoryDepositionEventBusPath", "post_tool_writeback_autocapture"].every((marker) => readText("repi-profile/extensions/reverse-pentest-core.ts").includes(marker)), { markers: ["MemoryDepositionEngineV7", "buildMemoryDepositionReport"] }));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  } finally {
    if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = { kind: "repi-memory-deposition-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "memory-deposition", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI Memory Deposition Gate");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
  }
  if (strict && failed.length) process.exit(1);
}

main();

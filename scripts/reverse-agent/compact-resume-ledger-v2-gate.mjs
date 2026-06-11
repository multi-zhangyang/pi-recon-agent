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
const keepTmp = argv.includes("--keep-tmp") || process.env.KEEP_REPI_COMPACT_RESUME_LEDGER_V2_TMP === "1";
const writeEvidence = !argv.includes("--no-write");
const SCHEMA_PATH = "schemas/reverse-agent/compact-resume-ledger-v2.schema.json";
const FIXTURE_PATH = "fixtures/reverse-agent/compact-resume-ledger-v2.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));
const ALLOWED = new Map([
  ["queued", new Set(["queued", "running", "blocked", "exhausted"])],
  ["running", new Set(["done", "blocked", "exhausted"])],
  ["blocked", new Set(["running", "exhausted"])],
  ["done", new Set([])],
  ["exhausted", new Set([])],
]);

function check(id, status, evidence = {}) { return { id, status: status ? "pass" : "fail", evidence }; }
function normalizeCommand(command = "") { return command.trim().replace(/^\//, "").replace(/^re-/i, "re_").replace(/\s+/g, " "); }
function transitionHash(row) {
  return sha256([row.prevHash, row.at, `${row.from}->${row.to}`, row.idempotencyKey, normalizeCommand(row.command ?? ""), row.contextPath ?? "", row.contextSha256 ?? "", `${row.attempt}/${row.maxAttempts}`, row.reason].join("\n"));
}
function fixtureTransitionErrors(rows) {
  const errors = [];
  let current = rows[0]?.from ?? "queued";
  if (current !== "queued") errors.push(`compact_resume_state_machine must start from queued, got ${current}`);
  const seen = new Set();
  for (const [index, row] of rows.entries()) {
    if (row.from !== current) errors.push(`from mismatch row ${index + 1}: expected ${current}, got ${row.from}`);
    if (!ALLOWED.get(row.from)?.has(row.to)) errors.push(`invalid_resume_transition ${row.from}->${row.to}`);
    if ((row.attempt ?? 1) > (row.maxAttempts ?? 3)) errors.push(`auto_resume_budget_exceeded row ${index + 1}`);
    const replayKey = [row.idempotencyKey ?? "fixture-key", row.command ?? "fixture-command", row.to, row.contextPath ?? "fixture-context"].join("\t");
    if (seen.has(replayKey)) errors.push(`idempotent_multi_compact_replay duplicate ${replayKey}`);
    seen.add(replayKey);
    current = row.to;
    if ((row.to === "done" || row.to === "exhausted") && index < rows.length - 1) errors.push(`terminal_resume_transition_reopened after ${row.to}`);
  }
  return errors;
}
function validateFixture(fixture) {
  const required = ["CompactResumeLedgerV2", "append_only_transition_ledger", "idempotent_multi_compact_replay", "auto_resume_budget_enforced", "invalid_resume_transition", "compact_resume_transition_report_in_context_pack"];
  const gates = new Set(fixture.requiredGates ?? []);
  const validErrors = (fixture.validScenarios ?? []).flatMap((scenario) =>
    fixtureTransitionErrors((scenario.transitions ?? []).map((row) => ({ idempotencyKey: sha256(`fixture-${scenario.id}`), command: "re_context resume", attempt: 1, maxAttempts: 3, ...row }))).map((error) => `${scenario.id}: ${error}`),
  );
  const negativeResults = (fixture.negativeCases ?? []).map((negative) => {
    let rows = (negative.transitions ?? [{ from: "queued", to: "running" }, { from: "queued", to: "running" }]).map((row) => ({ idempotencyKey: sha256("fixture-negative"), command: "re_context resume", attempt: row.attempt ?? 1, maxAttempts: row.maxAttempts ?? 3, ...row }));
    if (negative.duplicate) rows = [rows[0], { ...rows[0] }];
    const errors = fixtureTransitionErrors(rows);
    return { id: negative.id, matched: errors.some((item) => item.includes(negative.expect)), errors };
  });
  return { missingGates: required.filter((gate) => !gates.has(gate)), validErrors, negativeResults };
}
function validateReport(report) {
  const errors = [];
  if (report?.kind !== "repi-compact-resume-ledger-v2-report") errors.push("report kind mismatch");
  for (const key of ["CompactResumeLedgerV2", "append_only_transition_ledger", "idempotent_multi_compact_replay", "auto_resume_budget_enforced"]) if (report?.[key] !== true) errors.push(`${key} missing`);
  const gates = new Set(report?.requiredGates ?? []);
  for (const gate of ["CompactResumeLedgerV2", "append_only_transition_ledger", "idempotent_multi_compact_replay", "auto_resume_budget_enforced", "invalid_resume_transition", "compact_resume_transition_report_in_context_pack"]) if (!gates.has(gate)) errors.push(`required gate missing: ${gate}`);
  if (!Array.isArray(report?.transitions)) errors.push("transitions missing");
  return errors;
}
function verifyTransitionHashes(transitionPath) {
  const errors = [];
  const text = readFileSync(transitionPath, "utf8");
  let previousText = "";
  let rows = 0;
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    rows += 1;
    let row;
    try { row = JSON.parse(line); } catch { errors.push(`row ${index + 1} corrupt`); previousText += `${line}\n`; continue; }
    const expectedPrevHash = previousText.trim() ? sha256(previousText) : "0".repeat(64);
    if (row.prevHash !== expectedPrevHash) errors.push(`prevHash drift row ${index + 1}`);
    const { entryHash, ...base } = row;
    const expectedEntryHash = transitionHash(base);
    if (entryHash !== expectedEntryHash) errors.push(`entryHash drift row ${index + 1}`);
    previousText += `${line}\n`;
  }
  return { rows, errors };
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
mkdirSync(agentDir, { recursive: true });
mkdirSync(workspace, { recursive: true });
process.chdir(workspace);
process.env.REPI_CODING_AGENT_DIR = agentDir;
process.env.REPI_SESSION_ID = "compact-resume-ledger-v2-session";
process.env.REPI_BRANCH_ID = "compact-resume-ledger-v2-branch";
const tools = new Map();
const fakePi = { registerCommand() {}, registerTool(tool) { tools.set(tool.name, tool); }, on() {}, appendEntry() {}, getSessionName: () => undefined, setSessionName() {}, sendMessage() {}, exec: async () => ({ code: 0, stdout: "compact-v2-probe", stderr: "", killed: false }) };
createReconExtensionFactory()(fakePi);
const context = tools.get("re_context");
const memory = tools.get("re_memory");
if (!context || !memory) throw new Error("missing re_context or re_memory");
function text(result) { return result?.content?.[0]?.text ?? ""; }
function artifactPath(output) { const match = /^context_artifact:\s*(.+)$/m.exec(output); if (!match?.[1]) throw new Error("missing context artifact in " + output.slice(0, 1000)); return match[1].trim(); }
function parsePack(path) { const body = readFileSync(path, "utf8"); const fence = String.fromCharCode(96).repeat(3); const start = body.indexOf(fence + "json"); const contentStart = body.indexOf("\\n", start); const end = body.indexOf(fence, contentStart + 1); return JSON.parse(body.slice(contentStart + 1, end).trim()); }
async function main() {
  const packOutput = text(await context.execute("compact-v2", { action: "pack", target: "https://ledger-v2.local" }));
  const packPath = artifactPath(packOutput);
  const pack = parsePack(packPath);
  const resumeOutput = text(await context.execute("compact-v2", { action: "resume", contextPath: packPath, target: "https://ledger-v2.local" }));
  const resumePath = artifactPath(resumeOutput);
  const resumePack = parsePack(resumePath);
  const ledger = await memory.execute("compact-v2", { action: "compact-resume" });
  const report = ledger.details;
  writeFileSync(outPath, JSON.stringify({ tempRoot, agentDir, packPath, resumePath, pack, resumePack, report, ledgerText: text(ledger), transitionPath: report.transitionPath, reportPath: report.reportPath }, null, 2));
}
main().catch((error) => { console.error(error); process.exit(1); });
`, "utf8");
}
function runProbe(tempRoot) {
  const probePath = join(tempRoot, "compact-resume-ledger-v2-probe.ts");
  const outPath = join(tempRoot, "probe-result.json");
  writeProbe(probePath, outPath, tempRoot);
  const tsx = join(root, "node_modules", ".bin", "tsx");
  const result = spawnSync(tsx, ["--tsconfig", join(root, "tsconfig.json"), probePath], { cwd: root, env: { ...process.env, PI_OFFLINE: "1", REPI_OFFLINE: "1" }, encoding: "utf8", maxBuffer: 40 * 1024 * 1024 });
  return { ...result, outPath, probePath };
}
function main() {
  const checks = [];
  const tempRoot = mkdtempSync(join(tmpdir(), "repi-compact-resume-ledger-v2-"));
  let probeData;
  try {
    const schema = readJson(SCHEMA_PATH);
    const fixture = readJson(FIXTURE_PATH);
    checks.push(check("schema:parse", schema?.$defs?.CompactResumeLedgerV2Report && schema?.$defs?.CompactResumeLedgerTransitionV2, { path: SCHEMA_PATH }));
    const fixtureEval = validateFixture(fixture);
    checks.push(check("fixture:state-machine", fixtureEval.missingGates.length === 0 && fixtureEval.validErrors.length === 0 && fixtureEval.negativeResults.every((row) => row.matched), fixtureEval));
    const probe = runProbe(tempRoot);
    checks.push(check("runtime:probe-exit", probe.status === 0, { code: probe.status, signal: probe.signal, stdoutTail: (probe.stdout ?? "").slice(-2000), stderrTail: (probe.stderr ?? "").slice(-4000) }));
    if (probe.status === 0 && existsSync(probe.outPath)) {
      probeData = JSON.parse(readFileSync(probe.outPath, "utf8"));
      const reportErrors = validateReport(probeData.report);
      const hashCheck = verifyTransitionHashes(probeData.transitionPath);
      const transitions = probeData.report.transitions ?? [];
      const statePath = transitions.map((row) => `${row.from}->${row.to}`);
      checks.push(check("runtime:report-contract", reportErrors.length === 0, { reportErrors, reportPath: probeData.reportPath }));
      checks.push(check("runtime:append-only-transition-ledger", hashCheck.errors.length === 0 && hashCheck.rows >= 3, hashCheck));
      checks.push(check("runtime:queued-running-done", statePath.includes("queued->queued") && statePath.includes("queued->running") && statePath.includes("running->done") && probeData.report.currentState === "done", { statePath, currentState: probeData.report.currentState }));
      checks.push(check("runtime:idempotent-multi-compact-replay", probeData.report.invalidTransitions.length === 0 && new Set(transitions.map((row) => [row.idempotencyKey, row.command, row.to, row.contextPath].join("\t"))).size === transitions.length, { invalidTransitions: probeData.report.invalidTransitions }));
      checks.push(check("runtime:auto-resume-budget", transitions.every((row) => row.attempt <= row.maxAttempts) && probeData.report.auto_resume_budget_enforced === true, { attempts: transitions.map((row) => `${row.attempt}/${row.maxAttempts}`) }));
      checks.push(check("runtime:context-pack-embeds-v2", probeData.pack.compactResumeLedgerV2?.CompactResumeLedgerV2 === true && /compact_resume_ledger_v2/i.test(probeData.ledgerText), { packPath: probeData.packPath, embedded: probeData.pack.compactResumeLedgerV2 }));
    } else {
      for (const id of ["runtime:report-contract", "runtime:append-only-transition-ledger", "runtime:queued-running-done", "runtime:idempotent-multi-compact-replay", "runtime:auto-resume-budget", "runtime:context-pack-embeds-v2"]) checks.push(check(id, false, { error: "probe output missing" }));
    }
    const core = readText("packages/coding-agent/src/core/recon-profile.ts");
    checks.push(check("code:v2-markers", ["CompactResumeLedgerV2", "appendCompactResumeTransition", "buildCompactResumeLedgerV2Report", "formatCompactResumeLedgerV2", "compact_resume_transition_report_in_context_pack", "idempotent_multi_compact_replay", "auto_resume_budget_enforced"].every((marker) => core.includes(marker)), { markers: ["CompactResumeLedgerV2", "appendCompactResumeTransition"] }));
  } catch (error) {
    checks.push(check("gate:exception", false, { error: String(error), stack: error?.stack }));
  } finally {
    if (!keepTmp) rmSync(tempRoot, { recursive: true, force: true });
  }
  const failed = checks.filter((row) => row.status !== "pass");
  const result = { kind: "repi-compact-resume-ledger-v2-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, tempRoot: keepTmp ? tempRoot : undefined, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "compact-resume-ledger-v2", result.generatedAt.replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    if (probeData) writeFileSync(join(dir, "probe-result.json"), `${JSON.stringify(probeData, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI CompactResumeLedgerV2 Gate");
    for (const row of checks) console.log(`- ${row.status === "pass" ? "PASS" : "FAIL"} ${row.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
  }
  if (strict && failed.length) process.exit(1);
}
main();

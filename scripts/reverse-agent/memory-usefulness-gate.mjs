#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

const argv = process.argv.slice(2);
const rootArg = argv.find((arg) => !arg.startsWith("-"));
const root = resolve(rootArg ?? process.cwd());
const strict = argv.includes("--strict");
const json = argv.includes("--json");
const writeEvidence = !argv.includes("--no-write");
const FIXTURE_PATH = "fixtures/reverse-agent/memory-usefulness.fixture.json";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readText = (path) => readFileSync(join(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

function unique(values, limit = 80) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const text = String(value ?? "").trim();
    if (!text || text === "none") continue;
    const key = text.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(text);
    if (out.length >= limit) break;
  }
  return out;
}

function eventHash(event) {
  const { entryHash, ...withoutHash } = event;
  return sha256(JSON.stringify(withoutHash));
}

function sealEvents(seedEvents) {
  let prevHash = "0".repeat(64);
  return (seedEvents ?? []).map((seed, index) => {
    const event = { ...seed, seq: index + 1, prevHash, entryHash: "" };
    event.entryHash = eventHash(event);
    prevHash = event.entryHash;
    return event;
  });
}

function validateHashChain(events) {
  const errors = [];
  let prevHash = "0".repeat(64);
  const seqs = new Set();
  for (const [index, event] of events.entries()) {
    if (event.seq !== index + 1) errors.push(`seq:${event.id}:${event.seq}`);
    if (seqs.has(event.seq)) errors.push(`duplicate_seq:${event.seq}`);
    seqs.add(event.seq);
    if (event.prevHash !== prevHash) errors.push(`prevHash:${event.id}`);
    if (event.entryHash !== eventHash(event)) errors.push(`entryHash:${event.id}`);
    prevHash = event.entryHash;
  }
  return errors;
}

function tokens(text) {
  return unique(String(text ?? "").toLowerCase().split(/[^a-z0-9\u4e00-\u9fff]+/), 200).filter((token) => token.length >= 2);
}

function aliases(token) {
  const map = {
    acl: ["authz", "authorization", "permission", "ownership"],
    idor: ["authz", "ownership", "object", "principal"],
    bola: ["authz", "ownership", "object", "principal"],
    owner: ["ownership", "principal", "object"],
    ownership: ["owner", "principal", "object", "authz"],
    crash: ["segfault", "core", "overflow", "primitive", "pwn"],
    offset: ["cyclic", "rip", "crash", "core"],
    cyclic: ["offset", "crash", "pattern", "pwn"]
  };
  return map[token] ?? [];
}

function memoryText(event) {
  return [
    event.task,
    event.route,
    event.target ?? "",
    event.source,
    event.outcome,
    ...(event.domainTags ?? []),
    ...(event.lessons ?? []),
    ...(event.failurePatterns ?? []),
    ...(event.reuseRules ?? []),
    ...(event.commands ?? []),
    ...(event.artifactHashes ?? []).map((artifact) => `${artifact.path} ${artifact.tier} ${artifact.sha256 ?? ""}`)
  ].join("\n").toLowerCase();
}

function search(events, scenario) {
  const queryTokens = tokens(scenario.query);
  const semantic = unique(queryTokens.flatMap(aliases), 60);
  return events.flatMap((event) => {
    if (scenario.route && event.route !== scenario.route) return [];
    const hay = new Set(tokens(memoryText(event)));
    const reasons = [];
    let score = 0;
    for (const token of queryTokens) if (hay.has(token)) { score += 4; reasons.push(`token:${token}`); }
    for (const token of semantic) if (hay.has(token)) { score += 2; reasons.push(`memory_semantic_hybrid_reuse:${token}`); }
    score += Number(event.quality?.confidence ?? 0) * 10;
    if (event.quality?.replayVerified) score += 8;
    score += Number(event.quality?.reuseCount ?? 0) * 2;
    score -= Number(event.quality?.failureCount ?? 0) * 4;
    score -= Number(event.quality?.decay ?? 0) * 12;
    if (event.outcome === "success") score += 6;
    if (event.outcome === "failure" || event.outcome === "blocked") score -= 10;
    if (score <= 0 || !reasons.length) return [];
    return [{ event, score, reasons }];
  }).sort((left, right) => right.score - left.score || right.event.seq - left.event.seq);
}

function evaluate(events, scenarios) {
  const results = scenarios.map((scenario) => {
    const topK = scenario.topK ?? 3;
    const hits = search(events, scenario).slice(0, Math.max(topK, 8));
    const ids = hits.map((hit) => hit.event.id);
    const expectedRank = ids.findIndex((id) => scenario.expectedEventIds.includes(id)) + 1 || undefined;
    const forbiddenHitIds = ids.slice(0, topK).filter((id) => scenario.forbiddenEventIds.includes(id));
    const hitAt1 = Boolean(expectedRank && expectedRank <= 1);
    const hitAtK = Boolean(expectedRank && expectedRank <= topK);
    return { ...scenario, hitAt1, hitAtK, reciprocalRank: expectedRank ? 1 / expectedRank : 0, forbiddenHitIds, hits: hits.map((hit) => ({ eventId: hit.event.id, score: Number(hit.score.toFixed(2)), reasons: hit.reasons })) };
  });
  const count = results.length || 1;
  return {
    results,
    aggregate: {
      hitAt1: results.filter((row) => row.hitAt1).length / count,
      hitAtK: results.filter((row) => row.hitAtK).length / count,
      mrr: results.reduce((sum, row) => sum + row.reciprocalRank, 0) / count,
      forbiddenLeakRate: results.filter((row) => row.forbiddenHitIds.length > 0).length / count
    }
  };
}

async function sleep(ms) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

async function withLock(lockPath, fn) {
  for (let attempt = 0; attempt < 200; attempt++) {
    try {
      mkdirSync(lockPath);
      break;
    } catch {
      await sleep(2 + (attempt % 5));
    }
  }
  if (!existsSync(lockPath)) throw new Error("lock_timeout");
  try {
    return await fn();
  } finally {
    rmSync(lockPath, { recursive: true, force: true });
  }
}

async function concurrentAppendProbe(writers) {
  const dir = join(tmpdir(), `repi-memory-usefulness-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  const eventsPath = join(dir, "events.jsonl");
  const lockPath = join(dir, ".store.lock");
  writeFileSync(eventsPath, "", "utf8");
  async function append(index) {
    await withLock(lockPath, async () => {
      const rows = readFileSync(eventsPath, "utf8").split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
      const event = {
        kind: "repi-memory-event",
        schemaVersion: 1,
        id: `mem:concurrent-${index}`,
        seq: rows.length + 1,
        ts: "2026-06-10T00:00:00.000Z",
        source: "operator",
        task: `concurrent writer ${index}`,
        route: "Harness",
        domainTags: ["concurrent", "memory-store"],
        caseSignature: `case-concurrent-${index}`,
        outcome: "success",
        lessons: ["concurrent append preserved hash chain"],
        failurePatterns: [],
        reuseRules: ["append under lock"],
        commands: ["true"],
        artifacts: [],
        artifactHashes: [],
        quality: { confidence: 0.7, replayVerified: true, reuseCount: 0, failureCount: 0, lastUsefulAt: "2026-06-10T00:00:00.000Z", decay: 0 },
        promotion: { playbookCandidate: false, verifierRuleCandidate: true },
        prevHash: rows.at(-1)?.entryHash ?? "0".repeat(64),
        entryHash: ""
      };
      event.entryHash = eventHash(event);
      writeFileSync(eventsPath, `${rows.map((row) => JSON.stringify(row)).join("\n")}${rows.length ? "\n" : ""}${JSON.stringify(event)}\n`, "utf8");
    });
  }
  await Promise.all(Array.from({ length: writers }, (_, index) => append(index + 1)));
  const rows = readFileSync(eventsPath, "utf8").split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  const errors = validateHashChain(rows);
  rmSync(dir, { recursive: true, force: true });
  return { rows: rows.length, errors };
}

function childProcess(script, args) {
  return new Promise((resolveProcess) => {
    const child = spawn(process.execPath, [script, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("close", (code, signal) => resolveProcess({ code, signal, stdout, stderr }));
    child.on("error", (error) => resolveProcess({ code: -1, signal: null, stdout, stderr: String(error) }));
  });
}

async function childProcessConcurrentAppendProbe(writers) {
  const dir = join(tmpdir(), `repi-memory-child-process-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  const eventsPath = join(dir, "events.jsonl");
  const workerPath = join(dir, "memory-writer.mjs");
  writeFileSync(eventsPath, "", "utf8");
  writeFileSync(
    workerPath,
    `
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2];
const index = Number(process.argv[3]);
const eventsPath = join(dir, "events.jsonl");
const lockPath = join(dir, ".store.lock");
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
function eventHash(event) {
  const { entryHash, ...withoutHash } = event;
  return sha256(JSON.stringify(withoutHash));
}
function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}
let acquired = false;
for (let attempt = 0; attempt < 300; attempt++) {
  try {
    mkdirSync(lockPath);
    acquired = true;
    break;
  } catch {
    if (existsSync(lockPath)) sleep(3 + (index % 7));
  }
}
if (!acquired) {
  console.error("child_lock_timeout", index);
  process.exit(2);
}
try {
  const rows = readFileSync(eventsPath, "utf8").split(/\\r?\\n/).filter(Boolean).map((line) => JSON.parse(line));
  const event = {
    kind: "repi-memory-event",
    schemaVersion: 1,
    id: "mem:child-process-" + index,
    seq: rows.length + 1,
    ts: "2026-06-10T00:00:00.000Z",
    source: "operator",
    task: "child process memory writer " + index,
    route: "Harness",
    domainTags: ["child-process", "memory-store", "concurrency"],
    caseSignature: "case-child-process-" + index,
    outcome: "success",
    lessons: ["child process append preserved MemoryStoreV5 hash chain"],
    failurePatterns: [],
    reuseRules: ["append under cross-process lock"],
    commands: ["true"],
    artifacts: [],
    artifactHashes: [],
    quality: { confidence: 0.76, replayVerified: true, reuseCount: 0, failureCount: 0, lastUsefulAt: "2026-06-10T00:00:00.000Z", decay: 0 },
    promotion: { playbookCandidate: false, verifierRuleCandidate: true },
    prevHash: rows.at(-1)?.entryHash ?? "0".repeat(64),
    entryHash: ""
  };
  event.entryHash = eventHash(event);
  writeFileSync(eventsPath, \`\${rows.map((row) => JSON.stringify(row)).join("\\n")}\${rows.length ? "\\n" : ""}\${JSON.stringify(event)}\\n\`, "utf8");
  console.log("child_written", index, event.seq);
} finally {
  rmSync(lockPath, { recursive: true, force: true });
}
`,
    "utf8",
  );
  const childResults = await Promise.all(Array.from({ length: writers }, (_, index) => childProcess(workerPath, [dir, String(index + 1)])));
  const rows = readFileSync(eventsPath, "utf8").split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  const errors = validateHashChain(rows);
  const failedChildren = childResults
    .map((result, index) => ({ ...result, index: index + 1 }))
    .filter((result) => result.code !== 0);
  rmSync(dir, { recursive: true, force: true });
  return { rows: rows.length, errors, failedChildren };
}

function markerCheck(id, file, markers, forbidden = []) {
  const path = join(root, file);
  const text = existsSync(path) ? readFileSync(path, "utf8") : "";
  const missing = markers.filter((marker) => !text.includes(marker));
  const forbiddenHits = forbidden.filter((pattern) => pattern instanceof RegExp ? pattern.test(text) : text.includes(pattern));
  return { id, status: existsSync(path) && missing.length === 0 && forbiddenHits.length === 0 ? "pass" : "fail", evidence: { file, missing, forbiddenHits: forbiddenHits.map(String) } };
}

async function run() {
  const checks = [];
  let fixture;
  try {
    fixture = readJson(FIXTURE_PATH);
    const events = sealEvents(fixture.events);
    const chainErrors = validateHashChain(events);
    const evalResult = evaluate(events, fixture.scenarios);
    const thresholds = fixture.thresholds ?? {};
    checks.push({ id: "fixture:parse", status: fixture.kind === "repi-memory-usefulness-fixture" ? "pass" : "fail", evidence: { path: FIXTURE_PATH } });
    checks.push({ id: "fixture:hash-chain", status: chainErrors.length === 0 ? "pass" : "fail", evidence: { errors: chainErrors } });
    checks.push({ id: "eval:hit-at-1", status: evalResult.aggregate.hitAt1 >= (thresholds.minHitAt1 ?? 1) ? "pass" : "fail", evidence: evalResult.aggregate });
    checks.push({ id: "eval:hit-at-k", status: evalResult.aggregate.hitAtK >= (thresholds.minHitAtK ?? 1) ? "pass" : "fail", evidence: evalResult.aggregate });
    checks.push({ id: "eval:mrr", status: evalResult.aggregate.mrr >= (thresholds.minMrr ?? 1) ? "pass" : "fail", evidence: evalResult.aggregate });
    checks.push({ id: "eval:forbidden-leak", status: evalResult.aggregate.forbiddenLeakRate <= (thresholds.maxForbiddenLeakRate ?? 0) ? "pass" : "fail", evidence: { aggregate: evalResult.aggregate, results: evalResult.results } });
    const concurrent = await concurrentAppendProbe(fixture.concurrentAppend?.writers ?? 8);
    checks.push({ id: "concurrency:hash-chain", status: concurrent.rows === (fixture.concurrentAppend?.writers ?? 8) && concurrent.errors.length === 0 ? "pass" : "fail", evidence: concurrent });
    const childConcurrent = await childProcessConcurrentAppendProbe(fixture.concurrentAppend?.writers ?? 8);
    checks.push({
      id: "concurrency:child-process-hash-chain",
      status: childConcurrent.rows === (fixture.concurrentAppend?.writers ?? 8) && childConcurrent.errors.length === 0 && childConcurrent.failedChildren.length === 0 ? "pass" : "fail",
      evidence: childConcurrent
    });
  } catch (error) {
    checks.push({ id: "fixture:parse", status: "fail", evidence: { error: String(error) } });
  }
  checks.push(markerCheck("code:memory-usefulness-runtime", "packages/coding-agent/src/core/recon-profile.ts", [
    "type MemoryUsefulnessEvalReportV1",
    "type MemoryUsefulnessEvalScenarioV1",
    "function evaluateMemoryUsefulness",
    "function formatMemoryUsefulnessEval",
    "memory_usefulness_eval:",
    "forbiddenHitIds",
    "hitAtK",
    "MemoryUsefulnessEvalV1"
  ]));
  checks.push(markerCheck("docs:memory-usefulness-readme", "README.md", ["Memory usefulness eval", "gate:memory-usefulness", "hit@k", "forbiddenHitIds", "child-process", "re_memory eval"]));
  checks.push(markerCheck("docs:memory-usefulness-recon", "packages/coding-agent/docs/recon.md", ["Memory usefulness eval", "re_memory eval", "forbiddenLeakRate", "child-process"]));
  checks.push(markerCheck("profile:memory-usefulness", "repi-profile/SYSTEM.md", ["Memory usefulness eval", "re_memory eval", "forbiddenHitIds", "child-process"]));
  checks.push(markerCheck("npm:memory-usefulness-script", "package.json", ["gate:memory-usefulness", "memory-usefulness-gate.mjs"]));
  const failed = checks.filter((check) => check.status !== "pass");
  const result = { kind: "repi-memory-usefulness-gate", schemaVersion: 1, generatedAt: new Date().toISOString(), ok: failed.length === 0, root, checks };
  if (writeEvidence) {
    const dir = join(root, ".repi-harness", "evidence", "memory-usefulness", new Date().toISOString().replace(/[:.]/g, "-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "result.json"), `${JSON.stringify(result, null, 2)}\n`, "utf8");
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log("# REPI Memory Usefulness Gate");
    for (const check of checks) console.log(`- ${check.status === "pass" ? "PASS" : "FAIL"} ${check.id}`);
    console.log(`summary: ${failed.length ? "fail" : "pass"} checks=${checks.length}`);
  }
  if (strict && failed.length) process.exit(1);
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

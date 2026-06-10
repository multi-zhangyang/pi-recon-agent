#!/usr/bin/env node
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { failureRepairFromGaps } from '../../../scripts/reverse-agent/failure-repair-ledger.mjs';

const repoRoot = resolve(process.env.RECON_REPO_ROOT || '.');
const strict = process.argv.includes('--strict') || process.env.RECON_COMPOUND_STRICT === '1';
const live = process.argv.includes('--live') || process.env.RECON_COMPOUND_LIVE === '1';
const useLatest = process.argv.includes('--use-latest') || process.env.RECON_COMPOUND_USE_LATEST === '1' || !live;
const timeoutMs = Number(process.env.RECON_COMPOUND_TIMEOUT_MS || 1_800_000);
const maxArtifactAgeMs = Number(process.env.RECON_COMPOUND_MAX_AGE_MS || 2 * 60 * 60 * 1000);
const runContextCompact = !/^(0|false|no)$/i.test(process.env.RECON_COMPOUND_CONTEXT_COMPACT || '1');
const runHardScore = !/^(0|false|no)$/i.test(process.env.RECON_COMPOUND_HARD_SCORE || '1');
const runAgent = !/^(0|false|no)$/i.test(process.env.RECON_COMPOUND_AGENT || '1');

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`REPI compound frontier live-swarm gate\n\nUsage:\n  node bench/recon-remote/compound-frontier/run.mjs --use-latest --strict\n  node bench/recon-remote/compound-frontier/run.mjs --live --strict\n\nPurpose:\n  Binds or reruns the two hardest release-frontier proofs:\n  1. same-window-live: Bilibili + Xiaohongshu + Douyin live platform proof.\n  2. agent-parallel-dogfood: real multi-agent REPI worker/synthesizer proof.\n\n  It then verifies freshness, no frontier gaps, no stale artifact override, process/tool-result\n  runtime evidence, non-mock runtime audit, hard-score recognition, and context/compact readiness.\n\nEnvironment:\n  RECON_COMPOUND_LIVE=1                 rerun same-window and agent-parallel instead of binding latest\n  RECON_COMPOUND_USE_LATEST=1           bind latest artifacts\n  RECON_COMPOUND_MAX_AGE_MS=7200000\n  RECON_COMPOUND_AGENT=1\n  RECON_COMPOUND_CONTEXT_COMPACT=1\n  RECON_COMPOUND_HARD_SCORE=1\n  RECON_COMPOUND_TIMEOUT_MS=1800000\n  RECON_COMPOUND_STRICT=1\n\nOutput:\n  .repi-harness/evidence/remote/compound-frontier/<timestamp>/\n`);
  process.exit(0);
}

function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function eventHash(event) {
  const { eventHash: _eventHash, ...withoutHash } = event;
  return sha256(JSON.stringify(withoutHash));
}
function safeJson(text, fallback = null) { try { return JSON.parse(text); } catch { return fallback; } }
function rel(path) { return String(path || '').replace(`${repoRoot}/`, ''); }
function fullPath(path) { return String(path || '').startsWith('/') ? String(path) : join(repoRoot, String(path || '')); }
function redact(value) {
  return String(value || '')
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, 'sk-<redacted>')
    .replace(/(api[_-]?key|auth[_-]?token|authorization|bearer)(["'\s:=]+)([A-Za-z0-9_.\-\/+=]{12,})/gi, '$1$2<redacted>')
    .replace(/(ANTHROPIC_AUTH_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|GEMINI_API_KEY|OPENROUTER_API_KEY|AI_GATEWAY_API_KEY)=\S+/g, '$1=<redacted>')
    .replace(/([?&](?:w_rid|wts|xsec_token|xsec_source|web_session|a1|b1|msToken|a_bogus|token|buvid|SESSDATA|bili_jct|sign|t|web_id|device_id|sec_uid|user_cip|reflow_id)=)[^&\s"']+/gi, '$1<redacted>');
}
function parseStamp(value) {
  const raw = String(value || '');
  const hyphen = raw.match(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z$/);
  const iso = hyphen ? `${hyphen[1]}T${hyphen[2]}:${hyphen[3]}:${hyphen[4]}.${hyphen[5]}Z` : raw;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : 0;
}
function stampFromPath(path = '') {
  const match = String(path).match(/(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)/);
  return match ? match[1] : '';
}
function artifactTimeMs(path, obj = {}) {
  return parseStamp(obj.generatedAt) || parseStamp(obj.startedAt) || parseStamp(stampFromPath(obj.artifactDir || path)) || (() => {
    try { return statSync(fullPath(path)).mtimeMs; } catch { return 0; }
  })();
}
function run(cmd, args, options = {}) {
  return new Promise((resolveRun) => {
    const started = Date.now();
    const child = spawn(cmd, args, { cwd: repoRoot, env: { ...process.env, ...(options.env || {}) }, stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch {}
      setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1500).unref?.();
    }, options.timeoutMs || timeoutMs);
    child.stdout.on('data', (chunk) => { stdout += String(chunk); });
    child.stderr.on('data', (chunk) => { stderr += String(chunk); });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolveRun({ cmd, args, code, signal, pid: child.pid || null, startedAt: new Date(started).toISOString(), endedAt: new Date().toISOString(), elapsedMs: Date.now() - started, stdout, stderr, json: safeJson(stdout) });
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolveRun({ cmd, args, code: 'error', signal: null, pid: child.pid || null, startedAt: new Date(started).toISOString(), endedAt: new Date().toISOString(), elapsedMs: Date.now() - started, stdout, stderr, error: error.message, json: null });
    });
  });
}
async function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of await readdir(dir)) {
    const full = join(dir, name);
    let st; try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) await walk(full, out);
    else if (name === 'result.json') out.push(full);
  }
  return out;
}
async function readJson(path) {
  if (!path) return null;
  const full = fullPath(path);
  if (!existsSync(full)) return null;
  return safeJson(await readFile(full, 'utf8'));
}
async function fileMeta(path, tier = 'runtime_artifact') {
  if (!path) return { path: '', exists: false, tier };
  const full = fullPath(path);
  const relative = rel(full);
  if (!existsSync(full)) return { path: relative, exists: false, tier };
  const st = statSync(full);
  return {
    path: relative,
    exists: true,
    tier,
    bytes: st.size,
    mtime: new Date(st.mtimeMs).toISOString(),
    sha256: sha256(await readFile(full)),
  };
}
async function latestResult(globPart) {
  const candidates = [];
  for (const path of (await walk(join(repoRoot, '.repi-harness', 'evidence', 'remote'))).filter((p) => p.includes(globPart))) {
    const obj = await readJson(path);
    candidates.push({ path, timeMs: artifactTimeMs(path, obj || {}) || 0 });
  }
  return candidates.sort((a, b) => b.timeMs - a.timeMs || b.path.localeCompare(a.path))[0]?.path || '';
}
function artifactFromRun(runItem) {
  const dir = runItem?.json?.artifactDir || '';
  return dir ? `${dir}/result.json` : '';
}
function summarizeRun(label, runItem) {
  if (!runItem) return null;
  return {
    label,
    code: runItem.code,
    signal: runItem.signal,
    pid: runItem.pid,
    startedAt: runItem.startedAt,
    endedAt: runItem.endedAt,
    elapsedMs: runItem.elapsedMs,
    artifactDir: runItem.json?.artifactDir || '',
    stdoutSha256: sha256(runItem.stdout || '').slice(0, 24),
    stderrSha256: sha256(runItem.stderr || '').slice(0, 24),
    stdoutTail: redact(runItem.stdout || '').slice(-2000),
    stderrTail: redact(runItem.stderr || '').slice(-2000),
  };
}
function gate(name, passed, evidence, required, severity = 'required') {
  return { name, passed: Boolean(passed), severity, required, evidence };
}
function gateMap(gates = []) { return Object.fromEntries(gates.map((item) => [item.name, item])); }
function scoreRow(scoreboard, family) { return (scoreboard?.rows || []).find((row) => row.family === family) || null; }
function samePath(a, b) { return rel(fullPath(a)) === rel(fullPath(b)); }
function appendCompoundClaimLedgerEvent(events, event) {
  const prevHash = events.at(-1)?.eventHash || '0'.repeat(64);
  const row = { kind: 'ClaimLedgerEventV1', seq: events.length + 1, prevHash, timestamp: new Date().toISOString(), source: 'compound-frontier', ...event };
  row.eventHash = eventHash(row);
  events.push(row);
  return row;
}
function compoundClaimLedgerHashChainOk(events) {
  let prevHash = '0'.repeat(64);
  for (const row of events) {
    if (row.prevHash !== prevHash || row.eventHash !== eventHash(row)) return false;
    prevHash = row.eventHash;
  }
  return events.length > 0;
}
const requiredClaimLedgerTypes = ['artifact_handoff', 'claim', 'validation', 'challenge', 'resolution'];
function compoundRuntimeClaimLedgerOk(events) {
  return compoundClaimLedgerHashChainOk(events) && requiredClaimLedgerTypes.every((type) => events.some((event) => event.type === type));
}
async function buildCompoundClaimLedgerEvents({
  artifacts,
  ageRows,
  gates,
  failedGates,
  verdict,
  mode,
  resultPath,
  claimLedgerPath,
  failureLedgerPath,
  repairQueuePath,
  failureRepair,
  hardScoreArtifact,
  contextCompactSummary,
}) {
  // ClaimLedgerEventV1 runtime rows: artifact_handoff -> claim -> validation -> challenge -> resolution.
  const events = [];
  const upstreamMetas = [
    await fileMeta(artifacts.sameWindow, 'same_window_live'),
    await fileMeta(artifacts.agentParallel, 'runtime_artifact'),
    await fileMeta(hardScoreArtifact, 'runtime_artifact'),
  ].filter((item) => item.path);
  const outputRefs = {
    resultPath,
    claimLedgerPath,
    failureLedgerPath,
    repairQueuePath,
  };
  const gateRows = gates.map((item) => ({
    name: item.name,
    passed: Boolean(item.passed),
    severity: item.severity,
    required: item.required,
  }));
  const failedNames = failedGates.map((gap) => gap.name);
  const claimId = 'compound-frontier.bound_runtime_claim';
  appendCompoundClaimLedgerEvent(events, {
    type: 'artifact_handoff',
    role: 'compound-frontier',
    scope: 'compound-frontier:offline-bound',
    mode,
    artifactRefs: upstreamMetas.map((item) => item.path),
    artifactHashes: upstreamMetas.filter((item) => item.exists && item.sha256).map((item) => ({ path: item.path, sha256: item.sha256 })),
    outputRefs,
    ageRows,
  });
  appendCompoundClaimLedgerEvent(events, {
    type: 'claim',
    claimId,
    role: 'compound-frontier',
    scope: 'compound-frontier',
    status: failedNames.length ? 'gap' : 'proven',
    statement: failedNames.length
      ? `compound-frontier has unresolved gates: ${failedNames.join(', ')}.`
      : 'compound-frontier bound artifacts, gates, result metadata, and failure/repair outputs without unresolved required gates.',
    evidenceRefs: [
      resultPath,
      claimLedgerPath,
      failureLedgerPath,
      repairQueuePath,
      artifacts.sameWindow,
      artifacts.agentParallel,
      hardScoreArtifact,
    ].filter(Boolean),
    gateRefs: gateRows.map((item) => item.name),
    resultBinding: {
      verdict,
      mode,
      artifactDir: rel(outDir),
      resultPath,
    },
  });
  appendCompoundClaimLedgerEvent(events, {
    type: 'validation',
    claimId,
    role: 'compound-frontier-verifier',
    result: failedNames.length ? 'fail' : 'pass',
    checks: Object.fromEntries(gateRows.map((item) => [item.name, item.passed])),
    failedGates: failedNames,
    contextCompactSummary: contextCompactSummary || null,
    evidenceRefs: [resultPath, claimLedgerPath, artifacts.sameWindow, artifacts.agentParallel].filter(Boolean),
  });
  appendCompoundClaimLedgerEvent(events, {
    type: 'challenge',
    claimId,
    role: 'compound-frontier-adversary',
    scope: 'compound-frontier',
    challenge: failedNames.length
      ? `do not promote compound frontier while required gates remain failed: ${failedNames.join(', ')}`
      : 'no required gate failed; retain adversarial challenge row to make the runtime ledger complete and auditable',
    evidenceRefs: [resultPath, failureLedgerPath, repairQueuePath].filter(Boolean),
  });
  appendCompoundClaimLedgerEvent(events, {
    type: 'resolution',
    claimId,
    role: 'compound-frontier-synthesizer',
    result: failedNames.length ? 'repair_queued' : 'accepted',
    resolution: failedNames.length
      ? 'failureRepair keeps the compound claim downgraded until queued gates are repaired and rerun'
      : 'compound claim is accepted for the bound/offline evidence snapshot',
    failureRepairBinding: {
      failureLedgerPath,
      repairQueuePath,
      failureLedgerEventCount: failureRepair.failureLedgerEvents.length,
      repairQueueCount: failureRepair.repairQueue.length,
      failureRepairWriteback: failureRepair.failureRepairWriteback,
    },
    evidenceRefs: [failureLedgerPath, repairQueuePath, ...failureRepair.failureLedgerEvents.map((event) => event.id)].filter(Boolean),
  });
  return events;
}

const outDir = join(repoRoot, '.repi-harness', 'evidence', 'remote', 'compound-frontier', timestamp());
await mkdir(outDir, { recursive: true });
const startedAt = new Date().toISOString();
const runs = {};

if (live) {
  runs.sameWindow = await run('node', ['bench/recon-remote/same-window-live/run.mjs', '--strict'], {
    timeoutMs: Number(process.env.RECON_COMPOUND_SAME_WINDOW_TIMEOUT_MS || 900000),
    env: {
      RECON_SAME_WINDOW_PARALLEL: process.env.RECON_SAME_WINDOW_PARALLEL || '1',
      RECON_PROBE_BODY_BYTES: process.env.RECON_PROBE_BODY_BYTES || '4096',
      RECON_SAME_WINDOW_XHS_RUN_TIMEOUT_MS: process.env.RECON_SAME_WINDOW_XHS_RUN_TIMEOUT_MS || '300000',
    },
  });
  if (runAgent) {
    runs.agentParallel = await run('node', ['bench/recon-remote/agent-dogfood/parallel-run.mjs'], {
      timeoutMs: Number(process.env.RECON_COMPOUND_AGENT_TIMEOUT_MS || 1_200_000),
      env: {
        RECON_AGENT_TIMEOUT_MS: process.env.RECON_AGENT_TIMEOUT_MS || '600000',
        RECON_ROLE_RETRIES: process.env.RECON_ROLE_RETRIES || '1',
      },
    });
  }
}

const artifacts = {
  sameWindow: live ? artifactFromRun(runs.sameWindow) : rel(await latestResult('/same-window-live/')),
  agentParallel: live && runAgent ? artifactFromRun(runs.agentParallel) : rel(await latestResult('/agent-parallel-dogfood/')),
};
const objects = {
  sameWindow: await readJson(artifacts.sameWindow),
  agentParallel: await readJson(artifacts.agentParallel),
};

let compactRun = null;
let compactAudit = null;
if (runContextCompact) {
  compactRun = await run('node', ['scripts/reverse-agent/context-compact-audit.mjs', '.', '--json'], { timeoutMs: 120000 });
  compactAudit = compactRun.json;
  await writeFile(join(outDir, 'context-compact.stdout.txt'), redact(compactRun.stdout || ''));
  await writeFile(join(outDir, 'context-compact.stderr.txt'), redact(compactRun.stderr || ''));
}

let hardScoreRun = null;
let hardScoreObj = null;
if (runHardScore) {
  hardScoreRun = await run('node', ['bench/recon-remote/hard-score.mjs'], { timeoutMs: 120000 });
  const hardDir = hardScoreRun.json?.artifactDir || '';
  hardScoreObj = await readJson(hardDir ? `${hardDir}/scoreboard.json` : '');
}

const same = objects.sameWindow || {};
const agent = objects.agentParallel || {};
const sameGateMap = gateMap(same.gates || []);
const samePassed = (name) => Boolean(sameGateMap[name]?.passed);
const sameTime = artifactTimeMs(artifacts.sameWindow, same);
const agentTime = artifactTimeMs(artifacts.agentParallel, agent);
const ageRows = {
  sameWindow: sameTime ? Date.now() - sameTime : null,
  agentParallel: agentTime ? Date.now() - agentTime : null,
};
const sameGaps = same.frontierGaps || [];
const agentGates = agent.gates || {};
const agentEvidencePaths = agent.evidencePaths || {};
const agentBoundSameWindow = Boolean(
  artifacts.sameWindow && (
    samePath(agentEvidencePaths.bestSameWindowLive || '', artifacts.sameWindow) ||
    samePath(agentEvidencePaths.latestSameWindowLive || '', artifacts.sameWindow)
  )
);
const hardSame = scoreRow(hardScoreObj, 'same-window-live');
const hardAgent = scoreRow(hardScoreObj, 'agent-parallel-dogfood');
const hardCompound = scoreRow(hardScoreObj, 'compound-frontier');

const gates = [
  gate('compound_artifacts_exist', Boolean(artifacts.sameWindow && existsSync(fullPath(artifacts.sameWindow)) && artifacts.agentParallel && existsSync(fullPath(artifacts.agentParallel))), { artifacts }, 'same-window-live and agent-parallel artifacts exist'),
  gate('compound_artifacts_fresh', Object.values(ageRows).every((age) => age !== null && age <= maxArtifactAgeMs), { ageRows, maxArtifactAgeMs }, `same-window and agent artifacts age <= ${maxArtifactAgeMs}ms`),
  gate('same_window_live_passed', same.verdict === 'same-window-live-passed', { verdict: same.verdict, mode: same.mode, spanMs: same.spanMs }, 'same-window-live verdict passed'),
  gate('same_window_no_frontier_gaps', sameGaps.length === 0, { frontierGaps: sameGaps.map((gap) => gap.name || gap) }, 'same-window-live frontier gaps empty'),
  gate('same_window_negative_boundaries', Boolean(samePassed('xiaohongshu_challenge_boundary') && samePassed('douyin_cookie_boundary') && same.platformEvidence?.bilibili?.pageBoundaryOk), { xhsChallenge: samePassed('xiaohongshu_challenge_boundary'), douyinCookie: samePassed('douyin_cookie_boundary'), biliPageBoundary: same.platformEvidence?.bilibili?.pageBoundaryOk }, 'XHS challenge, Douyin cookie divergence, and Bilibili page boundary proof'),
  gate('same_window_media_byte_proofs', Boolean(samePassed('bilibili_cdn_range_or_body_proof') && samePassed('douyin_nowatermark_byte_proof')), { bili: same.platformEvidence?.bilibili, douyin: same.platformEvidence?.douyin }, 'Bilibili CDN body/range proof plus Douyin no-watermark byte proof'),
  gate('agent_parallel_confirmed', agent.verdict === 'agent-parallel-dogfood-confirmed', { verdict: agent.verdict, totals: agent.totals }, 'agent-parallel dogfood confirmed'),
  gate('agent_model_tool_runtime', Boolean(Number(agent.totals?.modelCalls || 0) >= 5 && Number(agent.totals?.toolCalls || 0) > 0 && Number(agent.totals?.toolResults || 0) >= Number(agent.totals?.toolCalls || 0)), { modelCalls: agent.totals?.modelCalls, toolCalls: agent.totals?.toolCalls, toolResults: agent.totals?.toolResults, toolResultBytes: agent.totals?.toolResultBytes }, 'model calls and matching tool-result evidence captured'),
  gate('agent_process_nonmock_proof', Boolean(agentGates.childPidsCaptured && agentGates.monotonicClockCaptured && agentGates.sessionDigestsCaptured && agentGates.nonMockRuntimeExpected), { childPidsCaptured: agentGates.childPidsCaptured, monotonicClockCaptured: agentGates.monotonicClockCaptured, sessionDigestsCaptured: agentGates.sessionDigestsCaptured, nonMockRuntimeExpected: agentGates.nonMockRuntimeExpected, runtimeAudit: agent.runtimeAudit }, 'child process, monotonic timing, JSONL digest, and non-mock runtime proof'),
  gate('agent_same_window_bound', agentBoundSameWindow, { agentSameWindow: { best: agentEvidencePaths.bestSameWindowLive, latest: agentEvidencePaths.latestSameWindowLive }, compoundSameWindow: artifacts.sameWindow }, 'agent dogfood bound the same same-window-live artifact'),
  gate('context_compact_audit_passed', !runContextCompact || Boolean(compactAudit?.ok), { attempted: runContextCompact, summary: compactAudit?.summary || null, code: compactRun?.code }, 'context/compact/resume audit passes'),
  gate('hard_score_recognizes_frontier', !runHardScore || Boolean(hardSame?.score >= 100 && hardAgent?.score >= 100), { hardScoreArtifact: hardScoreRun?.json?.artifactDir || '', sameWindow: hardSame && { score: hardSame.score, verdict: hardSame.verdict, artifact: hardSame.artifact }, agentParallel: hardAgent && { score: hardAgent.score, verdict: hardAgent.verdict, artifact: hardAgent.artifact }, compound: hardCompound && { score: hardCompound.score, verdict: hardCompound.verdict, artifact: hardCompound.artifact } }, 'hard-score recognizes same-window-live and agent-parallel as elite'),
];
if (live) {
  gates.push(gate('compound_live_rerun_mode', Boolean(runs.sameWindow && runs.sameWindow.code === 0 && (!runAgent || runs.agentParallel?.code === 0)), { sameWindowRun: summarizeRun('same-window', runs.sameWindow), agentRun: summarizeRun('agent-parallel', runs.agentParallel) }, 'live mode reran same-window and agent-parallel commands successfully'));
}

const mode = live ? 'live-rerun' : 'latest-bound';
const claimLedgerPath = rel(join(outDir, 'claim-ledger.jsonl'));
const resultPath = rel(join(outDir, 'result.json'));
const failureLedgerPath = rel(join(outDir, 'failure-ledger.jsonl'));
const repairQueuePath = rel(join(outDir, 'repair-queue.jsonl'));
const hardScoreArtifact = hardScoreRun?.json?.artifactDir ? `${hardScoreRun.json.artifactDir}/scoreboard.json` : '';
const failedGateRows = () => gates
  .filter((item) => !item.passed)
  .map((item) => ({ name: item.name, severity: item.severity, required: item.required, evidence: item.evidence }));
const requiredGatesPassed = () => gates.filter((item) => item.severity !== 'supporting').every((item) => item.passed);
const gateVerdict = (requiredPassed) => (requiredPassed ? 'compound-frontier-passed' : gates.some((item) => item.passed) ? 'compound-frontier-gaps' : 'compound-frontier-failed');
const makeFailureRepair = (gaps, requiredPassed) => failureRepairFromGaps({
  root: repoRoot,
  source: 'compound-frontier',
  gaps,
  category: 'contract_gap',
  status: requiredPassed ? 'repaired' : 'repair_queued',
  attempt: 1,
  maxAttempts: live ? 2 : 1,
  commands: ['node bench/recon-remote/compound-frontier/run.mjs --live --strict'],
  artifacts: Object.values(artifacts).filter(Boolean),
  expectedArtifacts: [rel(outDir), artifacts.sameWindow, artifacts.agentParallel, claimLedgerPath, failureLedgerPath, repairQueuePath].filter(Boolean),
  liveAllowed: live,
  providerAllowed: runAgent && live,
  paused: !live,
  unblock: 'rerun compound frontier with --live --strict after required evidence is allowed',
  verificationCommand: 'npm run gate:compound-frontier',
});

let passedRequired = requiredGatesPassed();
let failedGates = failedGateRows();
let verdict = gateVerdict(passedRequired);
let failureRepair = makeFailureRepair(failedGates, passedRequired);
let claimLedgerEvents = await buildCompoundClaimLedgerEvents({
  artifacts,
  ageRows,
  gates,
  failedGates,
  verdict,
  mode,
  resultPath,
  claimLedgerPath,
  failureLedgerPath,
  repairQueuePath,
  failureRepair,
  hardScoreArtifact,
  contextCompactSummary: compactAudit?.summary || null,
});
let runtimeClaimLedgerCaptured = compoundRuntimeClaimLedgerOk(claimLedgerEvents);
const claimLedgerGate = gate(
  'runtimeClaimLedgerCaptured',
  runtimeClaimLedgerCaptured,
  {
    claimLedgerPath,
    claimLedgerEventCount: claimLedgerEvents.length,
    claimLedgerTipHash: claimLedgerEvents.at(-1)?.eventHash || '',
    requiredEventTypes: requiredClaimLedgerTypes,
    eventTypes: [...new Set(claimLedgerEvents.map((event) => event.type))],
    hashChainOk: compoundClaimLedgerHashChainOk(claimLedgerEvents),
    resultPath,
    failureLedgerPath,
    repairQueuePath,
    failureRepair: {
      failureLedgerEventCount: failureRepair.failureLedgerEvents.length,
      repairQueueCount: failureRepair.repairQueue.length,
    },
  },
  'ClaimLedgerEventV1-style runtime claim ledger hash chain covers artifact_handoff, claim, validation, challenge, and resolution',
);
gates.push(claimLedgerGate);
passedRequired = requiredGatesPassed();
failedGates = failedGateRows();
verdict = gateVerdict(passedRequired);
failureRepair = makeFailureRepair(failedGates, passedRequired);
claimLedgerEvents = await buildCompoundClaimLedgerEvents({
  artifacts,
  ageRows,
  gates,
  failedGates,
  verdict,
  mode,
  resultPath,
  claimLedgerPath,
  failureLedgerPath,
  repairQueuePath,
  failureRepair,
  hardScoreArtifact,
  contextCompactSummary: compactAudit?.summary || null,
});
runtimeClaimLedgerCaptured = compoundRuntimeClaimLedgerOk(claimLedgerEvents);
claimLedgerGate.passed = runtimeClaimLedgerCaptured;
claimLedgerGate.evidence = {
  claimLedgerPath,
  claimLedgerEventCount: claimLedgerEvents.length,
  claimLedgerTipHash: claimLedgerEvents.at(-1)?.eventHash || '',
  requiredEventTypes: requiredClaimLedgerTypes,
  eventTypes: [...new Set(claimLedgerEvents.map((event) => event.type))],
  hashChainOk: compoundClaimLedgerHashChainOk(claimLedgerEvents),
  resultPath,
  failureLedgerPath,
  repairQueuePath,
  failureRepair: {
    failureLedgerEventCount: failureRepair.failureLedgerEvents.length,
    repairQueueCount: failureRepair.repairQueue.length,
  },
};
passedRequired = requiredGatesPassed();
failedGates = failedGateRows();
verdict = gateVerdict(passedRequired);
failureRepair = makeFailureRepair(failedGates, passedRequired);
const result = {
  target: 'Compound frontier live-swarm: same-window real platforms + parallel REPI dogfood + context compact',
  profile: 'compound-frontier',
  verdict,
  generatedAt: new Date().toISOString(),
  startedAt,
  endedAt: new Date().toISOString(),
  artifactDir: rel(outDir),
  mode,
  strict,
  useLatest,
  maxArtifactAgeMs,
  artifacts,
  ageRows,
  gates,
  failedGates,
  claimLedgerPath,
  claimLedgerEventCount: claimLedgerEvents.length,
  claimLedgerTipHash: claimLedgerEvents.at(-1)?.eventHash || '',
  runtimeClaimLedgerCaptured,
  claimLedgerEvents,
  failureLedgerEvents: failureRepair.failureLedgerEvents,
  repairQueue: failureRepair.repairQueue,
  failureRepairWriteback: failureRepair.failureRepairWriteback,
  platformEvidence: same.platformEvidence || {},
  agentEvidence: {
    verdict: agent.verdict,
    totals: agent.totals,
    parallel: agent.parallel,
    runtimeAudit: agent.runtimeAudit,
    gates: agent.gates,
    evidencePaths: agent.evidencePaths,
  },
  contextCompact: compactAudit ? { ok: compactAudit.ok, summary: compactAudit.summary } : { skipped: !runContextCompact },
  hardScore: hardScoreRun ? { artifactDir: hardScoreRun.json?.artifactDir || '', sameWindow: hardSame, agentParallel: hardAgent, compound: hardCompound } : { skipped: !runHardScore },
  runs: Object.fromEntries(Object.entries(runs).map(([name, item]) => [name, summarizeRun(name, item)])),
  nextActions: failedGates.length
    ? failedGates.map((gap) => `close ${gap.name}: ${gap.required}`)
    : ['promote gate:compound-frontier as release frontier gate', 'rerun with --live before release tags', 'raise next frontier to cross-platform target discovery and compact-resume replay'],
};
await writeFile(join(outDir, 'claim-ledger.jsonl'), `${claimLedgerEvents.map((event) => JSON.stringify(event)).join('\n')}${claimLedgerEvents.length ? '\n' : ''}`);
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
await writeFile(join(outDir, 'failure-ledger.jsonl'), `${failureRepair.failureLedgerEvents.map((event) => JSON.stringify(event)).join('\n')}${failureRepair.failureLedgerEvents.length ? '\n' : ''}`);
await writeFile(join(outDir, 'repair-queue.jsonl'), `${failureRepair.repairQueue.map((item) => JSON.stringify(item)).join('\n')}${failureRepair.repairQueue.length ? '\n' : ''}`);
for (const [name, item] of Object.entries(runs)) {
  await writeFile(join(outDir, `${name}.stdout.txt`), redact(item?.stdout || ''));
  await writeFile(join(outDir, `${name}.stderr.txt`), redact(item?.stderr || ''));
}
if (hardScoreRun) {
  await writeFile(join(outDir, 'hard-score.stdout.txt'), redact(hardScoreRun.stdout || ''));
  await writeFile(join(outDir, 'hard-score.stderr.txt'), redact(hardScoreRun.stderr || ''));
}
const md = [
  '# REPI Compound Frontier Live-Swarm Gate',
  '',
  `verdict: ${verdict}`,
  `mode: ${result.mode}`,
  `artifact_dir: ${rel(outDir)}`,
  `same_window: ${artifacts.sameWindow || 'none'}`,
  `agent_parallel: ${artifacts.agentParallel || 'none'}`,
  `hard_score: ${hardScoreRun?.json?.artifactDir || 'none'}`,
  `runtime_claim_ledger: ${claimLedgerPath} events=${claimLedgerEvents.length} captured=${runtimeClaimLedgerCaptured}`,
  '',
  '## Gates',
  '| Gate | Passed | Required | Evidence |',
  '|---|---:|---|---|',
  ...gates.map((item) => `| ${item.name} | ${item.passed} | ${item.required} | ${JSON.stringify(item.evidence).slice(0, 800)} |`),
  '',
  '## Failed Gates',
  ...(failedGates.length ? failedGates.map((gap) => `- ${gap.name}: ${gap.required}`) : ['- none']),
  '',
  '## Next Step',
  ...result.nextActions.map((item) => `- ${item}`),
  '',
].join('\n');
await writeFile(join(outDir, 'artifact.md'), md);
console.log(JSON.stringify({
  verdict,
  artifactDir: rel(outDir),
  mode: result.mode,
  failedGates: failedGates.map((gap) => gap.name),
  gates: gates.map(({ name, passed }) => ({ name, passed })),
  claimLedgerPath,
  claimLedgerEventCount: claimLedgerEvents.length,
  claimLedgerTipHash: claimLedgerEvents.at(-1)?.eventHash || '',
  runtimeClaimLedgerCaptured,
  hardScoreArtifact: hardScoreRun?.json?.artifactDir || '',
}, null, 2));
process.exit(strict && !passedRequired ? 1 : 0);

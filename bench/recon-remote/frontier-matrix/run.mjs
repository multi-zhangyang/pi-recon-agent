#!/usr/bin/env node
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const repoRoot = resolve(process.env.RECON_REPO_ROOT || '.');
const evidenceRoot = join(repoRoot, '.pi', 'evidence', 'remote');
const live = process.argv.includes('--live') || process.env.RECON_MATRIX_LIVE === '1';
const strict = process.argv.includes('--strict') || process.env.RECON_MATRIX_STRICT === '1';
const timeoutMs = Number(process.env.RECON_MATRIX_TIMEOUT_MS || 900000);
const selectedCaseIds = new Set(String(process.env.RECON_MATRIX_CASES || '').split(',').map((x) => x.trim()).filter(Boolean));

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`Pi-RECON real frontier matrix\n\nUsage:\n  node bench/recon-remote/frontier-matrix/run.mjs\n  node bench/recon-remote/frontier-matrix/run.mjs --live\n  node bench/recon-remote/frontier-matrix/run.mjs --live --strict\n\nPurpose:\n  Evaluates multiple live real-platform cases instead of relying on one latest artifact:\n  - Bilibili runtime WBI positive case\n  - Xiaohongshu auto-discovery target note/feed positive case\n  - Xiaohongshu search-notes permission negative-control case\n  - Douyin a_bogus structured API replay positive case\n  - Frontier strict aggregate gate\n\nEnvironment:\n  RECON_MATRIX_LIVE=1\n  RECON_MATRIX_STRICT=1\n  RECON_MATRIX_CASES=bilibili_wbi_runtime,xhs_auto_discovery,xhs_search_negative,douyin_structured_api\n  RECON_MATRIX_TIMEOUT_MS=900000\n\nOutput:\n  .pi/evidence/remote/frontier-matrix/<timestamp>/\n`);
  process.exit(0);
}

function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function safeJson(text, fallback = null) { try { return JSON.parse(text); } catch { return fallback; } }
function rel(path) { return String(path || '').replace(`${repoRoot}/`, ''); }
function evidenceTime(path) { return basename(dirname(path)); }
function redact(value) {
  return String(value || '')
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, 'sk-<redacted>')
    .replace(/(ANTHROPIC_AUTH_TOKEN|OPENAI_API_KEY|GEMINI_API_KEY|OPENROUTER_API_KEY|AI_GATEWAY_API_KEY)=\S+/g, '$1=<redacted>')
    .replace(/([?&](?:w_rid|wts|xsec_token|xsec_source|web_session|a1|b1|msToken|a_bogus|token|buvid|SESSDATA|bili_jct|sign|t)=)[^&\s"']+/gi, '$1<redacted>')
    .replace(/((?:xsec_token|xsec_source)(?:%3D|%253D))(?:(?!%26|%2526)[^&\s"']+)/gi, '$1<redacted>');
}
async function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of await readdir(dir)) {
    const full = join(dir, name);
    let st;
    try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) await walk(full, out);
    else if (name === 'result.json') out.push(full);
  }
  return out;
}
async function readJson(path) {
  if (!path) return null;
  const full = path.startsWith('/') ? path : join(repoRoot, path);
  try { return safeJson(await readFile(full, 'utf8')); } catch { return null; }
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
      resolveRun({ cmd, args, code, signal, elapsedMs: Date.now() - started, stdout, stderr, json: safeJson(stdout) });
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolveRun({ cmd, args, code: 'error', signal: null, elapsedMs: Date.now() - started, stdout, stderr, error: error.message, json: null });
    });
  });
}
function artifactFromRun(runItem) {
  const dir = runItem?.run?.json?.artifactDir || '';
  return dir ? `${dir}/result.json` : '';
}
function familyOf(path, obj = {}) {
  if (obj.profile) return obj.profile;
  if (path.includes('/douyin-nowatermark/')) return 'douyin-nowatermark';
  if (path.includes('/frontier-gate/')) return 'frontier-gate';
  return obj.family || 'unknown';
}
async function latestArtifacts() {
  const latest = new Map();
  for (const path of (await walk(evidenceRoot)).filter((p) => !p.includes('/hard-score/') && !p.includes('/frontier-matrix/')).sort()) {
    const obj = await readJson(path);
    if (!obj) continue;
    const family = familyOf(path, obj);
    const key = `${family}:${obj.target || obj.finalUrl || ''}`;
    const prev = latest.get(key);
    if (!prev || evidenceTime(path) > prev.time) latest.set(key, { path: rel(path), fullPath: path, time: evidenceTime(path), family, obj });
  }
  return [...latest.values()];
}
function findLatest(entries, predicate) {
  return entries.filter((entry) => predicate(entry.obj, entry)).sort((a, b) => b.time.localeCompare(a.time))[0] || null;
}
function xhsTargetOk(obj) {
  const best = obj?.xhsReplay?.bestTargetNote2xxSignedReplay || obj?.signatureTrace?.bestTargetNote2xxSignedReplay;
  return Boolean(best && Number(best.status) >= 200 && Number(best.status) < 300 && best.structured?.noteStructured && /h5-note-info|web-feed|web-api-note|web-note-or-feed|web-search-notes/i.test(best.endpointClass || ''));
}
function xhsSearchNegativeOk(obj) {
  const challenge = obj?.xhsReplay?.challengeMatrix || [];
  const permissionDenied = challenge.some((item) => item.endpointClass === 'web-search-notes' && item.challengeKind === 'permissionDenied');
  const loginMissing = challenge.some((item) => item.endpointClass === 'web-search-notes' && item.challengeKind === 'loginMissing');
  return Boolean(obj?.xhsReplay?.attempted && !xhsTargetOk(obj) && permissionDenied && loginMissing && obj?.verdict !== 'xhs-note-signed-api-replay-confirmed' && obj?.verdict !== 'xhs-auto-discovery-target-note-replay-confirmed');
}
function douyinStructuredOk(obj) {
  const replayed = obj?.runtimeApiReplay?.bestReplayedStructuredApi || obj?.signatureSurface?.runtimeReplayedStructuredApi;
  return Boolean(replayed && Number(replayed.status || 0) >= 200 && Number(replayed.status || 0) < 300 && replayed.structured?.structured);
}
function summarizeScenario(id, weight, obj, artifact, command, runItem) {
  const common = { id, weight, artifact, command, run: runItem ? { code: runItem.run?.code, signal: runItem.run?.signal, elapsedMs: runItem.run?.elapsedMs, stdoutSha256: sha256(runItem.run?.stdout || '').slice(0, 24), stderrSha256: sha256(runItem.run?.stderr || '').slice(0, 24), stdoutTail: redact(runItem.run?.stdout || '').slice(-1000), stderrTail: redact(runItem.run?.stderr || '').slice(-1000) } : undefined };
  if (!obj) return { ...common, passed: false, score: 0, evidence: { reason: 'artifact missing' } };
  if (id === 'bilibili_wbi_runtime') {
    const signerEvents = obj.signatureTrace?.signerLog?.length || 0;
    const bundleHints = obj.signatureTrace?.bundleHints?.length || 0;
    const signedReqs = obj.signatureTrace?.signedRequestCount || 0;
    const passed = Boolean(obj.wbiRegression?.selfTest?.ok && obj.wbiRegression?.signedEndpoint && signedReqs >= 1 && (signerEvents >= 1 || bundleHints >= 1));
    return { ...common, passed, score: passed ? weight : Math.min(weight - 1, (obj.wbiRegression?.selfTest?.ok ? 8 : 0) + Math.min(8, signedReqs * 3 + signerEvents + bundleHints * 2)), evidence: { verdict: obj.verdict, selfTest: obj.wbiRegression?.selfTest?.ok, signedEndpoint: obj.wbiRegression?.signedEndpoint, signerEvents, bundleHints, signedReqs, media: obj.mediaProbeMatrix?.reachableMedia || 0 } };
  }
  if (id === 'xhs_auto_discovery') {
    const best = obj.xhsReplay?.bestTargetNote2xxSignedReplay || null;
    const passed = Boolean(obj.verdict === 'xhs-auto-discovery-target-note-replay-confirmed' && xhsTargetOk(obj) && obj.xhsDiscovery?.candidateCount >= 1 && obj.xhsDiscovery?.attempts?.some((item) => item.bestTargetNote2xx));
    return { ...common, passed, score: passed ? weight : Math.min(weight - 1, (obj.xhsDiscovery?.candidateCount ? 8 : 0) + (xhsTargetOk(obj) ? 14 : 0) + Math.min(5, Math.floor((obj.signatureTrace?.signerLog?.length || 0) / 10))), evidence: { verdict: obj.verdict, candidates: obj.xhsDiscovery?.candidateCount || 0, attempts: obj.xhsDiscovery?.attempts?.length || 0, effectiveTarget: obj.effectiveTarget || '', bestEndpoint: best?.endpointClass || '', bestMethod: best?.method || '', bestStatus: best?.status || null, noteItemCount: best?.structured?.noteItemCount || 0, signerEvents: obj.signatureTrace?.signerLog?.length || 0 } };
  }
  if (id === 'xhs_search_negative') {
    const passed = xhsSearchNegativeOk(obj);
    const searchRows = (obj.xhsReplay?.challengeMatrix || []).filter((item) => item.endpointClass === 'web-search-notes').slice(0, 8);
    return { ...common, passed, score: passed ? weight : Math.min(weight - 1, obj.xhsReplay?.attempted ? 7 : 0), evidence: { verdict: obj.verdict, replayAttempted: obj.xhsReplay?.attempted, bestTargetNote2xx: xhsTargetOk(obj), searchRows, best2xx: obj.xhsReplay?.best2xxSignedReplay?.endpointClass || '' } };
  }
  if (id === 'douyin_structured_api') {
    const replayed = obj.runtimeApiReplay?.bestReplayedStructuredApi || obj.signatureSurface?.runtimeReplayedStructuredApi;
    const passed = douyinStructuredOk(obj);
    return { ...common, passed, score: passed ? weight : Math.min(weight - 1, (obj.runtimeApiReplay?.attempted ? 8 : 0) + (obj.runtimeApiReplay?.observedStructuredApi ? 8 : 0)), evidence: { verdict: obj.verdict, replayedStructuredApi2xx: passed, variant: replayed?.variant || '', status: replayed?.status || null, awemeCount: replayed?.structured?.awemeCount || 0, signals: obj.signatureSurface?.signals?.length || 0, bundles: obj.signatureSurface?.bundleHints?.length || 0 } };
  }
  if (id === 'frontier_strict') {
    const passed = obj.verdict === 'frontier-passed' && (obj.gates || []).every((gate) => gate.passed);
    return { ...common, passed, score: passed ? weight : 0, evidence: { verdict: obj.verdict, frontierScore: obj.frontierScore, grade: obj.grade, gates: (obj.gates || []).map((gate) => ({ name: gate.name, passed: gate.passed, score: Math.min(gate.score, gate.weight), weight: gate.weight })) } };
  }
  return { ...common, passed: false, score: 0, evidence: { reason: 'unknown scenario' } };
}

const scenarios = [
  {
    id: 'bilibili_wbi_runtime',
    weight: 20,
    command: ['node', ['bench/recon-remote/real-platform/run.mjs', process.env.RECON_MATRIX_BILI_URL || 'https://www.bilibili.com/video/BV1odL76QE6B', 'bilibili-video']],
    env: { RECON_BROWSER: '1', RECON_TIMEOUT_MS: '45000', RECON_QUIET_MS: '5000', RECON_PROBE_LIMIT: '4' },
    timeoutMs: 180000,
    latest: (obj) => obj.profile === 'bilibili-video',
  },
  {
    id: 'xhs_auto_discovery',
    weight: 30,
    command: ['node', ['bench/recon-remote/real-platform/run.mjs', process.env.RECON_MATRIX_XHS_DISCOVERY_URL || 'https://www.xhs-download.org/zh', 'xiaohongshu-note']],
    env: { RECON_BROWSER: '1', RECON_XHS_AUTO_DISCOVER: '1', RECON_XHS_DISCOVERY_LIMIT: '1', RECON_TIMEOUT_MS: '45000', RECON_QUIET_MS: '5000', RECON_XHS_PROBE_WAIT_MS: '15000', RECON_XHS_REPLAY_LIMIT: '10', RECON_MAX_BODY_BYTES: '700000' },
    timeoutMs: 180000,
    latest: (obj) => obj.profile === 'xiaohongshu-note' && obj.verdict === 'xhs-auto-discovery-target-note-replay-confirmed',
  },
  {
    id: 'xhs_search_negative',
    weight: 15,
    command: ['node', ['bench/recon-remote/real-platform/run.mjs', process.env.RECON_MATRIX_XHS_SEARCH_URL || 'https://www.xiaohongshu.com/search_result?keyword=%E7%BE%8E%E9%A3%9F', 'xiaohongshu-note']],
    env: { RECON_BROWSER: '1', RECON_XHS_AUTO_DISCOVER: '1', RECON_XHS_DISCOVERY_LIMIT: '1', RECON_TIMEOUT_MS: '45000', RECON_QUIET_MS: '5000', RECON_XHS_PROBE_WAIT_MS: '15000', RECON_XHS_REPLAY_LIMIT: '10', RECON_MAX_BODY_BYTES: '700000' },
    timeoutMs: 180000,
    latest: (obj) => obj.profile === 'xiaohongshu-note' && /xiaohongshu\.com\/search_result/i.test(obj.target || ''),
  },
  {
    id: 'douyin_structured_api',
    weight: 25,
    command: ['node', ['bench/recon-remote/douyin-nowatermark/run.mjs', process.env.RECON_MATRIX_DOUYIN_URL || 'https://www.douyin.com/video/7636072173723945829']],
    env: { RECON_BROWSER: '1', RECON_API_PROBE: '1', RECON_PROBE_LIMIT: '12', RECON_BROWSER_TIMEOUT_MS: '30000', RECON_BROWSER_QUIET_MS: '2500' },
    timeoutMs: 180000,
    latest: (obj) => obj.profile === 'douyin-nowatermark' || obj.target?.includes('douyin.com'),
  },
];
const activeScenarios = scenarios.filter((scenario) => !selectedCaseIds.size || selectedCaseIds.has(scenario.id));
const outDir = join(evidenceRoot, 'frontier-matrix', timestamp());
await mkdir(outDir, { recursive: true });
const started = Date.now();
const runs = [];
const entriesBefore = await latestArtifacts();

for (const scenario of activeScenarios) {
  if (!live) continue;
  const [cmd, args] = scenario.command;
  const runResult = await run(cmd, args, { timeoutMs: scenario.timeoutMs, env: scenario.env });
  runs.push({ id: scenario.id, scenario, run: runResult });
  await writeFile(join(outDir, `${scenario.id}.stdout.txt`), redact(runResult.stdout || ''));
  await writeFile(join(outDir, `${scenario.id}.stderr.txt`), redact(runResult.stderr || ''));
}

const frontierRun = await run('node', ['bench/recon-remote/frontier-gate/run.mjs', '--strict'], { timeoutMs: 120000 });
runs.push({ id: 'frontier_strict', scenario: { id: 'frontier_strict', weight: 10, command: ['node', ['bench/recon-remote/frontier-gate/run.mjs', '--strict']] }, run: frontierRun });
await writeFile(join(outDir, 'frontier_strict.stdout.txt'), redact(frontierRun.stdout || ''));
await writeFile(join(outDir, 'frontier_strict.stderr.txt'), redact(frontierRun.stderr || ''));

const entriesAfter = await latestArtifacts();
const scenarioResults = [];
for (const scenario of activeScenarios) {
  const runItem = runs.find((item) => item.id === scenario.id);
  const artifact = live ? artifactFromRun(runItem) : findLatest(entriesBefore, scenario.latest)?.path || '';
  const obj = await readJson(artifact || findLatest(entriesAfter, scenario.latest)?.path || '');
  scenarioResults.push(summarizeScenario(scenario.id, scenario.weight, obj, artifact || findLatest(entriesAfter, scenario.latest)?.path || '', `${scenario.command[0]} ${scenario.command[1].join(' ')}`, runItem));
}
const frontierArtifact = artifactFromRun(runs.find((item) => item.id === 'frontier_strict'));
const frontierObj = await readJson(frontierArtifact);
scenarioResults.push(summarizeScenario('frontier_strict', 10, frontierObj, frontierArtifact, 'node bench/recon-remote/frontier-gate/run.mjs --strict', runs.find((item) => item.id === 'frontier_strict')));

const matrixScore = scenarioResults.reduce((sum, row) => sum + Math.min(row.weight, row.score), 0);
const matrixMaxScore = scenarioResults.reduce((sum, row) => sum + row.weight, 0);
const passed = scenarioResults.every((row) => row.passed);
const grade = matrixScore >= 90 ? 'elite' : matrixScore >= 75 ? 'advanced' : matrixScore >= 55 ? 'solid' : matrixScore >= 35 ? 'basic' : 'weak';
const result = {
  target: 'Real-platform hardest frontier matrix: Bilibili + Xiaohongshu positives/negative + Douyin + frontier strict',
  profile: 'frontier-matrix',
  verdict: passed ? 'frontier-matrix-passed' : 'frontier-matrix-incomplete',
  generatedAt: new Date().toISOString(),
  artifactDir: rel(outDir),
  mode: live ? 'live-rerun' : 'latest-evidence',
  strict,
  elapsedMs: Date.now() - started,
  matrixScore,
  matrixMaxScore,
  matrixPercent: Number(((matrixScore / matrixMaxScore) * 100).toFixed(2)),
  grade,
  scenarios: scenarioResults,
  nextActions: scenarioResults.filter((row) => !row.passed).map((row) => `${row.id}: inspect ${row.artifact || 'missing artifact'} and rerun ${row.command}`),
};
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
const md = [
  '# Pi-RECON Real Frontier Matrix',
  '',
  `verdict: ${result.verdict}`,
  `mode: ${result.mode}`,
  `matrix_score: ${matrixScore}/${matrixMaxScore} (${result.matrixPercent}%)`,
  `grade: ${grade}`,
  `artifact_dir: ${rel(outDir)}`,
  '',
  '## Scenarios',
  '| Scenario | Passed | Score | Artifact | Evidence |',
  '|---|---:|---:|---|---|',
  ...scenarioResults.map((row) => `| ${row.id} | ${row.passed} | ${Math.min(row.score, row.weight)}/${row.weight} | ${row.artifact || ''} | ${JSON.stringify(row.evidence)} |`),
  '',
  '## Next Step',
  ...(result.nextActions.length ? result.nextActions.map((item) => `- ${item}`) : ['- none']),
  '',
].join('\n');
await writeFile(join(outDir, 'artifact.md'), md);
console.log(JSON.stringify({ verdict: result.verdict, artifactDir: result.artifactDir, mode: result.mode, matrixScore, matrixMaxScore, matrixPercent: result.matrixPercent, grade, scenarios: scenarioResults.map(({ id, passed, score, weight }) => ({ id, passed, score: Math.min(score, weight), weight })) }, null, 2));
process.exit(strict && !passed ? 1 : 0);

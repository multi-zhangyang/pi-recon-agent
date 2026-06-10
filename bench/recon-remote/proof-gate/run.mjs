#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const repoRoot = resolve(process.env.RECON_REPO_ROOT || '.');
const timeoutMs = Number(process.env.RECON_GATE_TIMEOUT_MS || 600000);
const useLatest = process.argv.includes('--use-latest') || process.env.RECON_GATE_LATEST === '1';
const runAgent = process.env.RECON_GATE_AGENT === '1' || (process.env.RECON_GATE_AGENT !== '0' && Boolean(process.env.RECON_AGENT_MODEL || process.env.ANTHROPIC_MODEL));
const targets = {
  bilibili: process.env.RECON_GATE_BILI_URL || 'https://www.bilibili.com/video/BV1odL76QE6B',
  xhs: process.env.RECON_GATE_XHS_URL || 'https://www.xiaohongshu.com/explore/66237c6e000000001c00893f',
  douyin: process.env.RECON_GATE_DOUYIN_URL || 'https://www.douyin.com/video/7636072173723945829',
};

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`REPI remote proof gate\n\nUsage:\n  node bench/recon-remote/proof-gate/run.mjs\n  node bench/recon-remote/proof-gate/run.mjs --use-latest\n\nLive default tracks:\n  - Bilibili WBI + optional CDP signer trace\n  - Xiaohongshu x-s runtime signer/replay challenge\n  - Douyin a_bogus/no-watermark/CDP/API probe\n  - Agent dogfood rerun when RECON_AGENT_MODEL or ANTHROPIC_MODEL is configured; RECON_GATE_AGENT=0 scores latest dogfood evidence only\n\nEnvironment:\n  RECON_GATE_TIMEOUT_MS=600000\n  RECON_GATE_AGENT=auto|1|0     1 forces dogfood rerun; 0 skips rerun but can score latest evidence\n  RECON_GATE_LATEST=1          Score latest artifacts without rerunning live targets\n  RECON_GATE_BILI_URL=<url>\n  RECON_GATE_XHS_URL=<url>\n  RECON_GATE_DOUYIN_URL=<url>\n\nOutput:\n  .repi-harness/evidence/remote/proof-gate/<timestamp>/\n`);
  process.exit(0);
}

function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function safeJson(text, fallback = null) { try { return JSON.parse(text); } catch { return fallback; } }
function redact(value) {
  return String(value || '')
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, 'sk-<redacted>')
    .replace(/(ANTHROPIC_AUTH_TOKEN|OPENAI_API_KEY|GEMINI_API_KEY|OPENROUTER_API_KEY|AI_GATEWAY_API_KEY)=\S+/g, '$1=<redacted>')
    .replace(/([?&](?:w_rid|xsec_token|web_session|a1|b1|msToken|a_bogus|token|buvid|SESSDATA|bili_jct)=)[^&\s"']+/gi, '$1<redacted>');
}
function rel(path) { return String(path || '').replace(`${repoRoot}/`, ''); }
function childEnv(extra = {}) { return { ...process.env, ...extra }; }
function run(cmd, args, options = {}) {
  return new Promise((resolveRun) => {
    const started = Date.now();
    const child = spawn(cmd, args, { cwd: repoRoot, env: childEnv(options.env || {}), stdio: ['ignore', 'pipe', 'pipe'], shell: false });
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
async function readJson(path) {
  if (!path) return null;
  const full = path.startsWith('/') ? path : join(repoRoot, path);
  if (!existsSync(full)) return null;
  return safeJson(await readFile(full, 'utf8'));
}
function latestRow(scoreboard, family) {
  return (scoreboard?.rows || []).find((row) => row.family === family) || null;
}
function sameArtifact(left, right) {
  if (!left || !right) return false;
  const a = String(left).replace(`${repoRoot}/`, '');
  const b = String(right).replace(`${repoRoot}/`, '');
  return a === b || resolve(repoRoot, a) === resolve(repoRoot, b);
}
function rowFor(scoreboard, family, artifactHint, { strict = false } = {}) {
  if (artifactHint) {
    const matched = (scoreboard?.rows || []).find((row) => row.family === family && sameArtifact(row.artifact, artifactHint));
    if (matched) return matched;
    if (strict) return null;
  }
  return latestRow(scoreboard, family);
}
function runArtifact(runs, label) {
  const artifactDir = runs.find((item) => item.label === label)?.run?.json?.artifactDir || '';
  if (!artifactDir) return '';
  return artifactDir.endsWith('/result.json') ? artifactDir : `${artifactDir}/result.json`;
}
function gate(name, passed, evidence, required) { return { name, passed: Boolean(passed), evidence, required }; }
function summarizeRun(item) {
  return {
    label: item.label,
    code: item.run?.code,
    signal: item.run?.signal,
    elapsedMs: item.run?.elapsedMs,
    artifactDir: item.run?.json?.artifactDir,
    stdoutSha256: sha256(item.run?.stdout || '').slice(0, 24),
    stderrSha256: sha256(item.run?.stderr || '').slice(0, 24),
    stdoutTail: redact(item.run?.stdout || '').slice(-2000),
    stderrTail: redact(item.run?.stderr || '').slice(-1000),
  };
}

const outDir = join(repoRoot, '.repi-harness', 'evidence', 'remote', 'proof-gate', timestamp());
await mkdir(outDir, { recursive: true });
const started = Date.now();
const runs = [];

if (!useLatest) {
  runs.push({ label: 'bilibili-video', run: await run('node', ['bench/recon-remote/real-platform/run.mjs', targets.bilibili, 'bilibili-video'], { timeoutMs: 180000, env: { RECON_BROWSER: process.env.RECON_GATE_BILI_BROWSER || '1', RECON_TIMEOUT_MS: process.env.RECON_GATE_BILI_TIMEOUT_MS || '45000', RECON_QUIET_MS: process.env.RECON_GATE_BILI_QUIET_MS || '5000', RECON_PROBE_LIMIT: process.env.RECON_GATE_BILI_PROBE_LIMIT || '4' } }) });
  runs.push({ label: 'xiaohongshu-note', run: await run('node', ['bench/recon-remote/real-platform/run.mjs', targets.xhs, 'xiaohongshu-note'], { timeoutMs: 180000, env: { RECON_TIMEOUT_MS: process.env.RECON_GATE_XHS_TIMEOUT_MS || '45000', RECON_QUIET_MS: process.env.RECON_GATE_XHS_QUIET_MS || '5000' } }) });
  runs.push({ label: 'douyin-nowatermark', run: await run('node', ['bench/recon-remote/douyin-nowatermark/run.mjs', targets.douyin], { timeoutMs: 180000, env: { RECON_BROWSER: process.env.RECON_GATE_DOUYIN_BROWSER || '1', RECON_API_PROBE: process.env.RECON_GATE_DOUYIN_API_PROBE || '1', RECON_PROBE_LIMIT: process.env.RECON_GATE_DOUYIN_PROBE_LIMIT || '8', RECON_BROWSER_TIMEOUT_MS: process.env.RECON_GATE_DOUYIN_TIMEOUT_MS || '20000', RECON_BROWSER_QUIET_MS: process.env.RECON_GATE_DOUYIN_QUIET_MS || '2000' } }) });
  if (runAgent) {
    const prompt = process.env.RECON_AGENT_PROMPT || 'REPI proof-gate quick gate. Execute node bench/recon-remote/hard-score.mjs, then output Outcome / Key Evidence / Verification / Next Step. Cover Bilibili WBI, Xiaohongshu x-s, Douyin a_bogus with one evidence line and one next command each. Do not edit files.';
    runs.push({ label: 'agent-dogfood', run: await run('node', ['bench/recon-remote/agent-dogfood/run.mjs'], { timeoutMs: Number(process.env.RECON_GATE_AGENT_TIMEOUT_MS || 420000), env: { RECON_AGENT_PROMPT: prompt, RECON_AGENT_TIMEOUT_MS: process.env.RECON_AGENT_TIMEOUT_MS || '420000' } }) });
  }
}

const scoreRun = await run('node', ['bench/recon-remote/hard-score.mjs'], { timeoutMs: 60000 });
runs.push({ label: 'hard-score', run: scoreRun });
const scoreboard = await readJson(scoreRun.json?.artifactDir ? join(scoreRun.json.artifactDir, 'scoreboard.json') : '');
const liveArtifacts = {
  bilibili: runArtifact(runs, 'bilibili-video'),
  xhs: runArtifact(runs, 'xiaohongshu-note'),
  douyin: runArtifact(runs, 'douyin-nowatermark'),
  agent: runArtifact(runs, 'agent-dogfood'),
};
const rows = {
  bilibili: rowFor(scoreboard, 'bilibili-video', liveArtifacts.bilibili, { strict: !useLatest }),
  xhs: rowFor(scoreboard, 'xiaohongshu-note', liveArtifacts.xhs, { strict: !useLatest }),
  douyin: rowFor(scoreboard, 'douyin-nowatermark', liveArtifacts.douyin, { strict: !useLatest }),
  agent: rowFor(scoreboard, 'agent-dogfood', liveArtifacts.agent, { strict: runAgent }),
};
const artifacts = {
  bilibili: await readJson(rows.bilibili?.artifact),
  xhs: await readJson(rows.xhs?.artifact),
  douyin: await readJson(rows.douyin?.artifact),
  agent: await readJson(rows.agent?.artifact),
};
const gates = [
  gate('bilibili_wbi_signed_media', rows.bilibili?.score >= 75 && /confirmed/.test(rows.bilibili?.verdict || '') && artifacts.bilibili?.wbiRegression?.selfTest?.ok, { score: rows.bilibili?.score, verdict: rows.bilibili?.verdict, artifact: rows.bilibili?.artifact, selfTest: artifacts.bilibili?.wbiRegression?.selfTest?.ok, media: artifacts.bilibili?.mediaProbeMatrix?.reachableMedia }, 'score>=75, confirmed verdict, WBI self-test ok'),
  gate('xiaohongshu_xs_runtime_challenge', rows.xhs?.score >= 80 && artifacts.xhs?.xhsReplay?.attempted && Number(artifacts.xhs?.xhsReplay?.status) === 461 && (artifacts.xhs?.signatureTrace?.signerLog?.length || 0) >= 10, { score: rows.xhs?.score, verdict: rows.xhs?.verdict, artifact: rows.xhs?.artifact, replay: artifacts.xhs?.xhsReplay?.status, signerEvents: artifacts.xhs?.signatureTrace?.signerLog?.length }, 'score>=80, signed replay attempted, 461 reproduced, signer_events>=10'),
  gate('douyin_abogus_nowatermark', rows.douyin?.score >= 80 && rows.douyin?.verdict === 'strong-candidate' && (artifacts.douyin?.signatureSurface?.signals?.length || 0) >= 5 && (artifacts.douyin?.signatureSurface?.bundleHints?.length || 0) >= 5, { score: rows.douyin?.score, verdict: rows.douyin?.verdict, artifact: rows.douyin?.artifact, signals: artifacts.douyin?.signatureSurface?.signals?.length, bundles: artifacts.douyin?.signatureSurface?.bundleHints?.length }, 'score>=80, strong candidate, signature signals>=5, bundle hints>=5'),
];
if (runAgent || rows.agent) {
  gates.push(gate('agent_dogfood_recon_model_tools', rows.agent?.score >= 70 && rows.agent?.verdict === 'agent-dogfood-confirmed' && artifacts.agent?.checks?.modelCalled && artifacts.agent?.checks?.toolUsed, { score: rows.agent?.score, verdict: rows.agent?.verdict, artifact: rows.agent?.artifact, checks: artifacts.agent?.checks, toolCalls: artifacts.agent?.session?.toolCalls, modelCalls: artifacts.agent?.session?.modelCalls }, 'score>=70, confirmed verdict, modelCalled and toolUsed'));
}
const passed = gates.every((item) => item.passed);
const verdict = passed ? 'proof-gate-passed' : 'proof-gate-failed';
const result = {
  target: 'Bilibili + Xiaohongshu + Douyin + REPI dogfood remote gate',
  profile: 'proof-gate',
  verdict,
  generatedAt: new Date().toISOString(),
  artifactDir: rel(outDir),
  mode: useLatest ? 'latest-only' : 'live-rerun',
  elapsedMs: Date.now() - started,
  runAgent,
  targets,
  liveArtifacts,
  scoreboardArtifact: scoreRun.json?.artifactDir || '',
  rows,
  gates,
  runs: runs.map(summarizeRun),
  nextActions: passed
    ? ['raise threshold toward elite: Douyin a_bogus rebuild, XHS 2xx replay, Bili runtime WBI bundle trace', 'wire proof-gate into release/check workflow', 'trend proof-gate history across commits']
    : gates.filter((item) => !item.passed).map((item) => `repair gate ${item.name}: ${item.required}`),
};
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
for (const item of runs) {
  await writeFile(join(outDir, `${item.label}.stdout.txt`), redact(item.run?.stdout || ''));
  await writeFile(join(outDir, `${item.label}.stderr.txt`), redact(item.run?.stderr || ''));
}
const md = [
  '# REPI Remote Proof Gate',
  '',
  `verdict: ${verdict}`,
  `mode: ${result.mode}`,
  `artifact_dir: ${rel(outDir)}`,
  `scoreboard: ${result.scoreboardArtifact}`,
  '',
  '## Gates',
  '| Gate | Passed | Required | Evidence |',
  '|---|---:|---|---|',
  ...gates.map((item) => `| ${item.name} | ${item.passed} | ${item.required} | ${JSON.stringify(item.evidence)} |`),
  '',
  '## Runs',
  ...runs.map((item) => `- ${item.label}: code=${item.run?.code} signal=${item.run?.signal || ''} elapsed_ms=${item.run?.elapsedMs} artifact=${item.run?.json?.artifactDir || ''}`),
  '',
  '## Next Step',
  ...result.nextActions.map((item) => `- ${item}`),
  '',
].join('\n');
await writeFile(join(outDir, 'artifact.md'), md);
console.log(JSON.stringify({ verdict, artifactDir: rel(outDir), mode: result.mode, gates: gates.map(({ name, passed }) => ({ name, passed })), scoreboardArtifact: result.scoreboardArtifact }, null, 2));
process.exit(passed ? 0 : 1);

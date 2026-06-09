#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const repoRoot = resolve(process.env.RECON_REPO_ROOT || '.');
const useLatest = process.argv.includes('--use-latest') || process.env.RECON_SAME_WINDOW_USE_LATEST === '1';
const strict = process.argv.includes('--strict') || process.env.RECON_SAME_WINDOW_STRICT === '1';
const parallel = !/^(0|false|no)$/i.test(process.env.RECON_SAME_WINDOW_PARALLEL || '1');
const timeoutMs = Number(process.env.RECON_SAME_WINDOW_TIMEOUT_MS || 900000);
const maxWindowMs = Number(process.env.RECON_SAME_WINDOW_MAX_SPAN_MS || 15 * 60 * 1000);
const maxArtifactAgeMs = Number(process.env.RECON_SAME_WINDOW_MAX_AGE_MS || 30 * 60 * 1000);
const targets = {
  bilibili: process.env.RECON_SAME_WINDOW_BILI_URL || 'https://www.bilibili.com/video/BV1Ee9EBnEfo?p=2',
  xiaohongshu: process.env.RECON_SAME_WINDOW_XHS_URL || 'https://www.xhs-download.org/zh',
  douyin: process.env.RECON_SAME_WINDOW_DOUYIN_URL || 'https://www.douyin.com/video/7636072173723945829',
};

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`Pi-RECON same-window live frontier gate\n\nUsage:\n  node bench/recon-remote/same-window-live/run.mjs\n  node bench/recon-remote/same-window-live/run.mjs --strict\n  node bench/recon-remote/same-window-live/run.mjs --use-latest\n\nPurpose:\n  Reruns or binds Bilibili, Xiaohongshu, and Douyin evidence inside one freshness window,\n  then separates proven live facts from frontier gaps. This gate is intentionally harder than\n  hard-score: Bilibili must prove per-page WBI plus CDN range/body evidence, Xiaohongshu\n  must prove target note/feed x-s 2xx, and Douyin must prove structured replay plus media-byte\n  no-watermark evidence. Partial/failure verdicts are expected and useful.\n\nEnvironment:\n  RECON_SAME_WINDOW_BILI_URL=<url>\n  RECON_SAME_WINDOW_XHS_URL=<url>\n  RECON_SAME_WINDOW_XHS_AUTO_DISCOVER=1\n  RECON_SAME_WINDOW_XHS_DISCOVERY_LIMIT=1\n  RECON_SAME_WINDOW_DOUYIN_URL=<url>\n  RECON_SAME_WINDOW_PARALLEL=1\n  RECON_SAME_WINDOW_TIMEOUT_MS=900000\n  RECON_SAME_WINDOW_MAX_SPAN_MS=900000\n  RECON_SAME_WINDOW_MAX_AGE_MS=1800000\n  RECON_SAME_WINDOW_STRICT=1\n  RECON_SAME_WINDOW_USE_LATEST=1\n\nOutput:\n  .pi/evidence/remote/same-window-live/<timestamp>/\n`);
  process.exit(0);
}

function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function safeJson(text, fallback = null) { try { return JSON.parse(text); } catch { return fallback; } }
function rel(path) { return String(path || '').replace(`${repoRoot}/`, ''); }
function fullPath(path) { return String(path || '').startsWith('/') ? String(path) : join(repoRoot, String(path || '')); }
function redact(value) {
  return String(value || '')
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, 'sk-<redacted>')
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
  return parseStamp(obj.generatedAt) || parseStamp(stampFromPath(obj.artifactDir || path)) || (() => {
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
      resolveRun({ cmd, args, code, signal, startedAt: new Date(started).toISOString(), endedAt: new Date().toISOString(), elapsedMs: Date.now() - started, stdout, stderr, json: safeJson(stdout) });
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolveRun({ cmd, args, code: 'error', signal: null, startedAt: new Date(started).toISOString(), endedAt: new Date().toISOString(), elapsedMs: Date.now() - started, stdout, stderr, error: error.message, json: null });
    });
  });
}
async function readJson(path) {
  if (!path) return null;
  const full = fullPath(path);
  if (!existsSync(full)) return null;
  return safeJson(await readFile(full, 'utf8'));
}
async function latestResult(globPart) {
  const { readdir } = await import('node:fs/promises');
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
  const candidates = [];
  for (const path of (await walk(join(repoRoot, '.pi', 'evidence', 'remote'))).filter((p) => p.includes(globPart))) {
    const obj = await readJson(path);
    candidates.push({ path, timeMs: artifactTimeMs(path, obj || {}) || 0 });
  }
  return candidates.sort((a, b) => b.timeMs - a.timeMs || b.path.localeCompare(a.path))[0]?.path || '';
}
function artifactFromRun(runItem) {
  const dir = runItem?.run?.json?.artifactDir || '';
  return dir ? `${dir}/result.json` : '';
}
function gate(name, passed, evidence, required, severity = 'required') {
  return { name, passed: Boolean(passed), severity, required, evidence };
}
function probeAttempts(obj) { return (obj?.probes || []).flatMap((p) => p.probe?.attempts || p.attempts || []); }
function mediaReachableCount(obj) {
  return Number(obj?.mediaProbeMatrix?.reachableMedia || 0) || (obj?.probes || []).filter((p) => p.probe?.classification?.media && p.probe?.classification?.reachable).length;
}
function biliEvidence(obj = {}) {
  const attempts = probeAttempts(obj);
  const hasRange206 = Number(obj?.mediaProbeMatrix?.range206 || 0) > 0 || attempts.some((a) => Number(a.status) === 206 || /bytes/i.test(a.headers?.['content-range'] || ''));
  const hasBodyHash = (obj?.probes || []).some((p) => p.probe?.bodySha256 || p.bodySha256 || p.sha256);
  const contentLengthOk = attempts.some((a) => Number(a.headers?.['content-length'] || 0) > 1024 * 64);
  const pageBoundaryOk = Boolean(obj?.pageBoundary?.pageMatchesRequest && obj?.pageBoundary?.cidDiffersFromFirst && obj?.selectedCid === obj?.pageBoundary?.selectedCid);
  return { attempts: attempts.length, hasRange206, hasBodyHash, contentLengthOk, pageBoundaryOk, reachableMedia: mediaReachableCount(obj) };
}
function xhsEvidence(obj = {}) {
  const target = obj?.xhsReplay?.bestTargetNote2xxSignedReplay || obj?.signatureTrace?.bestTargetNote2xxSignedReplay || null;
  const best2xx = obj?.xhsReplay?.best2xxSignedReplay || obj?.signatureTrace?.best2xxSignedReplay || null;
  const signedHeaders = obj?.xhsReplay?.signedHeaderNames || [];
  return {
    attempted: Boolean(obj?.xhsReplay?.attempted),
    replayStatus: obj?.xhsReplay?.status,
    signedHeaderCount: signedHeaders.length,
    signedHeaders,
    signedRequestCount: Number(obj?.signatureTrace?.signedRequestCount || 0),
    signerEvents: Number((obj?.signatureTrace?.signerLog || []).length || 0),
    best2xxStatus: best2xx?.status || null,
    best2xxEndpoint: best2xx?.endpointClass || null,
    target2xxStatus: target?.status || null,
    target2xxEndpoint: target?.endpointClass || null,
    targetNoteStructured: Boolean(target?.structured?.noteStructured),
  };
}
function douyinEvidence(obj = {}) {
  const replayed = obj?.runtimeApiReplay?.bestReplayedStructuredApi || obj?.signatureSurface?.runtimeReplayedStructuredApi || null;
  const observed = obj?.runtimeApiReplay?.observedStructuredApi || obj?.signatureSurface?.runtimeObservedStructuredApi || null;
  const divergence = obj?.runtimeApiReplay?.firstDivergence || null;
  const strongProbes = (obj?.probes || []).filter((p) => p.classification?.noWatermarkLikely && p.classification?.reachable);
  const byteProof = strongProbes.some((p) =>
    p.classification?.byteProof ||
    p.bodyProof ||
    p.sha256 ||
    p.bodySha256 ||
    Number(p.bytes || p.bodyBytes || 0) > 0 ||
    (p.attempts || []).some((a) =>
      (a.sha256 || a.bodySha256) &&
      Number(a.bytes || 0) > 0 &&
      (Number(a.status) === 206 || /bytes/i.test(a.headers?.['content-range'] || '') || /^GET bytes=/i.test(a.method || ''))
    )
  );
  return {
    observed2xx: Boolean(observed && Number(observed.status) >= 200 && Number(observed.status) < 300 && observed.structured?.structured),
    replayed2xx: Boolean(replayed && Number(replayed.status) >= 200 && Number(replayed.status) < 300 && replayed.structured?.structured),
    replayVariant: replayed?.variant || null,
    awemeCount: Number(replayed?.structured?.awemeCount || observed?.structured?.awemeCount || 0),
    noCookieDiverged: Boolean(divergence?.variant === 'no-cookie' && divergence?.divergence?.replayBodySha256 === 'e3b0c44298fc1c149afbf4c8'),
    strongProbeCount: strongProbes.length,
    byteProof,
    signalCount: Number((obj?.signatureSurface?.signals || obj?.signatureSurface?.antiBotSignals || []).length || 0),
    bundleHintCount: Number((obj?.signatureSurface?.bundleHints || []).length || 0),
  };
}
function summarizeRun(item) {
  return {
    label: item.label,
    code: item.run?.code,
    signal: item.run?.signal,
    startedAt: item.run?.startedAt,
    endedAt: item.run?.endedAt,
    elapsedMs: item.run?.elapsedMs,
    artifactDir: item.run?.json?.artifactDir || '',
    stdoutSha256: sha256(item.run?.stdout || '').slice(0, 24),
    stderrSha256: sha256(item.run?.stderr || '').slice(0, 24),
    stdoutTail: redact(item.run?.stdout || '').slice(-2000),
    stderrTail: redact(item.run?.stderr || '').slice(-2000),
  };
}

const outDir = join(repoRoot, '.pi', 'evidence', 'remote', 'same-window-live', timestamp());
await mkdir(outDir, { recursive: true });
const startedAt = new Date().toISOString();
const runs = [];

async function liveRuns() {
  const specs = [
    {
      label: 'bilibili',
      cmd: 'node',
      args: ['bench/recon-remote/real-platform/run.mjs', targets.bilibili, 'bilibili-video'],
      env: { RECON_BROWSER: process.env.RECON_SAME_WINDOW_BILI_BROWSER || '1', RECON_TIMEOUT_MS: process.env.RECON_SAME_WINDOW_BILI_TIMEOUT_MS || '50000', RECON_QUIET_MS: process.env.RECON_SAME_WINDOW_BILI_QUIET_MS || '5000', RECON_PROBE_LIMIT: process.env.RECON_SAME_WINDOW_BILI_PROBE_LIMIT || '6' },
      timeoutMs: Number(process.env.RECON_SAME_WINDOW_BILI_RUN_TIMEOUT_MS || 240000),
    },
    {
      label: 'xiaohongshu',
      cmd: 'node',
      args: ['bench/recon-remote/real-platform/run.mjs', targets.xiaohongshu, 'xiaohongshu-note'],
      env: { RECON_BROWSER: process.env.RECON_SAME_WINDOW_XHS_BROWSER || '1', RECON_TIMEOUT_MS: process.env.RECON_SAME_WINDOW_XHS_TIMEOUT_MS || '60000', RECON_QUIET_MS: process.env.RECON_SAME_WINDOW_XHS_QUIET_MS || '5000', RECON_XHS_PROBE_WAIT_MS: process.env.RECON_SAME_WINDOW_XHS_PROBE_WAIT_MS || '15000', RECON_XHS_AUTO_DISCOVER: process.env.RECON_SAME_WINDOW_XHS_AUTO_DISCOVER || process.env.RECON_XHS_AUTO_DISCOVER || '1', RECON_XHS_DISCOVERY_LIMIT: process.env.RECON_SAME_WINDOW_XHS_DISCOVERY_LIMIT || process.env.RECON_XHS_DISCOVERY_LIMIT || '1' },
      timeoutMs: Number(process.env.RECON_SAME_WINDOW_XHS_RUN_TIMEOUT_MS || 240000),
    },
    {
      label: 'douyin',
      cmd: 'node',
      args: ['bench/recon-remote/douyin-nowatermark/run.mjs', targets.douyin],
      env: { RECON_BROWSER: process.env.RECON_SAME_WINDOW_DOUYIN_BROWSER || '1', RECON_API_PROBE: process.env.RECON_SAME_WINDOW_DOUYIN_API_PROBE || '1', RECON_PROBE_LIMIT: process.env.RECON_SAME_WINDOW_DOUYIN_PROBE_LIMIT || '12', RECON_BROWSER_TIMEOUT_MS: process.env.RECON_SAME_WINDOW_DOUYIN_TIMEOUT_MS || '45000', RECON_BROWSER_QUIET_MS: process.env.RECON_SAME_WINDOW_DOUYIN_QUIET_MS || '2500' },
      timeoutMs: Number(process.env.RECON_SAME_WINDOW_DOUYIN_RUN_TIMEOUT_MS || 240000),
    },
  ];
  if (parallel) {
    const results = await Promise.all(specs.map(async (spec) => ({ label: spec.label, run: await run(spec.cmd, spec.args, { env: spec.env, timeoutMs: spec.timeoutMs }) })));
    runs.push(...results);
  } else {
    for (const spec of specs) runs.push({ label: spec.label, run: await run(spec.cmd, spec.args, { env: spec.env, timeoutMs: spec.timeoutMs }) });
  }
}

if (!useLatest) await liveRuns();
else {
  runs.push({ label: 'bilibili', run: { code: 0, signal: null, startedAt, endedAt: new Date().toISOString(), elapsedMs: 0, stdout: '', stderr: '', json: { artifactDir: (await latestResult('/real-platform/bilibili-video/')).replace(/\/result\.json$/, '') } } });
  runs.push({ label: 'xiaohongshu', run: { code: 0, signal: null, startedAt, endedAt: new Date().toISOString(), elapsedMs: 0, stdout: '', stderr: '', json: { artifactDir: (await latestResult('/real-platform/xiaohongshu-note/')).replace(/\/result\.json$/, '') } } });
  runs.push({ label: 'douyin', run: { code: 0, signal: null, startedAt, endedAt: new Date().toISOString(), elapsedMs: 0, stdout: '', stderr: '', json: { artifactDir: (await latestResult('/douyin-nowatermark/')).replace(/\/result\.json$/, '') } } });
}

const artifacts = Object.fromEntries(runs.map((item) => [item.label, artifactFromRun(item)]));
const objects = {
  bilibili: await readJson(artifacts.bilibili),
  xiaohongshu: await readJson(artifacts.xiaohongshu),
  douyin: await readJson(artifacts.douyin),
};
const times = Object.fromEntries(Object.entries(artifacts).map(([name, path]) => [name, artifactTimeMs(path, objects[name]) || 0]));
const existingTimes = Object.values(times).filter(Boolean);
const spanMs = existingTimes.length ? Math.max(...existingTimes) - Math.min(...existingTimes) : null;
const ageRows = Object.fromEntries(Object.entries(times).map(([name, ms]) => [name, ms ? Date.now() - ms : null]));
const bili = biliEvidence(objects.bilibili);
const xhs = xhsEvidence(objects.xiaohongshu);
const douyin = douyinEvidence(objects.douyin);

const gates = [
  gate('same_window_artifacts_exist', ['bilibili', 'xiaohongshu', 'douyin'].every((name) => artifacts[name] && existsSync(fullPath(artifacts[name]))), { artifacts }, 'three live artifacts exist'),
  gate('same_window_span', spanMs !== null && spanMs <= maxWindowMs, { spanMs, maxWindowMs, times, ageRows }, `artifact timestamps span <= ${maxWindowMs}ms`),
  gate('same_window_fresh', Object.values(ageRows).every((age) => age !== null && age <= maxArtifactAgeMs), { ageRows, maxArtifactAgeMs }, `each artifact age <= ${maxArtifactAgeMs}ms`),
  gate('bilibili_wbi_per_page_cid', Boolean(objects.bilibili?.wbiRegression?.selfTest?.ok && objects.bilibili?.wbiRegression?.signedEndpoint && bili.pageBoundaryOk), { verdict: objects.bilibili?.verdict, selectedPage: objects.bilibili?.selectedPage, selectedCid: objects.bilibili?.selectedCid, pageBoundary: objects.bilibili?.pageBoundary, wbi: objects.bilibili?.wbiRegression }, 'WBI self-test + signed endpoint + requested page CID boundary'),
  gate('bilibili_cdn_range_or_body_proof', Boolean(bili.reachableMedia >= 1 && (bili.hasRange206 || bili.hasBodyHash)), bili, 'reachable media plus Range 206/content-range or stored body hash', 'frontier'),
  gate('bilibili_cdn_head_fallback', Boolean(bili.reachableMedia >= 1 && bili.contentLengthOk), bili, 'fallback: HEAD 200 with content-length proves candidate reachability', 'supporting'),
  gate('xiaohongshu_xs_signed_trace', Boolean(xhs.signedRequestCount >= 1 && xhs.signerEvents >= 10 && xhs.signedHeaderCount >= 2), xhs, 'signed x-s/x-t trace and signer events'),
  gate('xiaohongshu_target_note_2xx', Boolean(xhs.targetNoteStructured && Number(xhs.target2xxStatus) >= 200 && Number(xhs.target2xxStatus) < 300), xhs, 'eligible target note/feed/search-notes structured 2xx', 'frontier'),
  gate('xiaohongshu_challenge_boundary', Boolean(xhs.attempted && (Number(xhs.replayStatus) === 461 || xhs.best2xxStatus)), xhs, 'signed replay attempted and challenge or structured 2xx boundary recorded', 'supporting'),
  gate('douyin_abogus_structured_replay', Boolean(douyin.replayed2xx && douyin.awemeCount >= 1 && douyin.signalCount >= 1), douyin, 'browser-captured signed API replayed with structured 2xx JSON'),
  gate('douyin_cookie_boundary', Boolean(douyin.noCookieDiverged), douyin, 'no-cookie replay diverges from exact-cookie/observed structured body'),
  gate('douyin_nowatermark_byte_proof', Boolean(douyin.strongProbeCount >= 1 && douyin.byteProof), douyin, 'no-watermark media candidate has byte/hash proof', 'frontier'),
];
const requiredGates = gates.filter((item) => item.severity !== 'supporting');
const passedRequired = requiredGates.every((item) => item.passed);
const frontierGaps = gates.filter((item) => !item.passed).map((item) => ({ name: item.name, severity: item.severity, required: item.required, evidence: item.evidence }));
const verdict = passedRequired ? 'same-window-live-passed' : gates.some((item) => item.passed) ? 'same-window-live-frontier-gaps' : 'same-window-live-failed';
const scoreRun = await run('node', ['bench/recon-remote/hard-score.mjs'], { timeoutMs: 60000 });
const result = {
  target: 'Same-window live Bilibili + Xiaohongshu + Douyin frontier gate',
  profile: 'same-window-live',
  verdict,
  generatedAt: new Date().toISOString(),
  artifactDir: rel(outDir),
  mode: useLatest ? 'latest-bound' : 'live-rerun',
  strict,
  parallel,
  targets,
  maxWindowMs,
  maxArtifactAgeMs,
  spanMs,
  ageRows,
  artifacts,
  platformEvidence: { bilibili: bili, xiaohongshu: xhs, douyin },
  gates,
  frontierGaps,
  runs: runs.map(summarizeRun),
  hardScoreArtifact: scoreRun.json?.artifactDir || '',
  hardScoreRun: { code: scoreRun.code, elapsedMs: scoreRun.elapsedMs, stdoutSha256: sha256(scoreRun.stdout || '').slice(0, 24), stderrSha256: sha256(scoreRun.stderr || '').slice(0, 24) },
  nextActions: frontierGaps.length ? frontierGaps.map((gap) => `close ${gap.name}: ${gap.required}`) : ['promote same-window-live as release frontier gate', 'rerun with stricter max span and body-byte probes'],
};
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
for (const item of runs.concat([{ label: 'hard-score', run: scoreRun }])) {
  await writeFile(join(outDir, `${item.label}.stdout.txt`), redact(item.run?.stdout || ''));
  await writeFile(join(outDir, `${item.label}.stderr.txt`), redact(item.run?.stderr || ''));
}
const md = [
  '# Pi-RECON Same-Window Live Frontier Gate',
  '',
  `verdict: ${verdict}`,
  `mode: ${result.mode}`,
  `parallel: ${parallel}`,
  `artifact_dir: ${rel(outDir)}`,
  `span_ms: ${spanMs}`,
  `hard_score: ${result.hardScoreArtifact}`,
  '',
  '## Gates',
  '| Gate | Severity | Passed | Required | Evidence |',
  '|---|---|---:|---|---|',
  ...gates.map((item) => `| ${item.name} | ${item.severity} | ${item.passed} | ${item.required} | ${JSON.stringify(item.evidence).slice(0, 600)} |`),
  '',
  '## Runs',
  ...runs.map((item) => `- ${item.label}: code=${item.run?.code} signal=${item.run?.signal || ''} elapsed_ms=${item.run?.elapsedMs} artifact=${item.run?.json?.artifactDir || ''}`),
  '',
  '## Frontier Gaps',
  ...(frontierGaps.length ? frontierGaps.map((gap) => `- ${gap.name}: ${gap.required}`) : ['- none']),
  '',
  '## Next Step',
  ...result.nextActions.map((item) => `- ${item}`),
  '',
].join('\n');
await writeFile(join(outDir, 'artifact.md'), md);
console.log(JSON.stringify({ verdict, artifactDir: rel(outDir), mode: result.mode, spanMs, gates: gates.map(({ name, severity, passed }) => ({ name, severity, passed })), frontierGaps: frontierGaps.map((gap) => gap.name), hardScoreArtifact: result.hardScoreArtifact }, null, 2));
process.exit(strict && !passedRequired ? 1 : 0);

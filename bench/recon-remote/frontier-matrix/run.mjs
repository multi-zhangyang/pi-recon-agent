#!/usr/bin/env node
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const repoRoot = resolve(process.env.RECON_REPO_ROOT || '.');
const evidenceRoot = join(repoRoot, '.repi-harness', 'evidence', 'remote');
function argValue(name, fallback = '') {
  const prefix = `--${name}=`;
  const inline = process.argv.find((arg) => arg.startsWith(prefix));
  if (inline) return inline.slice(prefix.length);
  const idx = process.argv.indexOf(`--${name}`);
  if (idx >= 0 && process.argv[idx + 1] && !process.argv[idx + 1].startsWith('--')) return process.argv[idx + 1];
  return fallback;
}
const live = process.argv.includes('--live') || process.env.RECON_MATRIX_LIVE === '1';
const strict = process.argv.includes('--strict') || process.env.RECON_MATRIX_STRICT === '1';
const allowStaleEvidence = process.argv.includes('--allow-stale-evidence') || process.env.RECON_MATRIX_ALLOW_STALE_EVIDENCE === '1' || process.env.RECON_EVIDENCE_ALLOW_STALE === '1';
const freshnessDisabled = allowStaleEvidence || process.env.RECON_MATRIX_FRESHNESS === '0' || process.env.RECON_MATRIX_FRESH === '0' || process.env.RECON_EVIDENCE_FRESHNESS === '0';
const freshnessEnabled = !freshnessDisabled && (process.argv.includes('--fresh') || process.env.RECON_MATRIX_FRESHNESS === '1' || process.env.RECON_MATRIX_FRESH === '1' || process.env.RECON_EVIDENCE_FRESHNESS === '1' || strict);
const maxArtifactAgeHours = Number(argValue('max-artifact-age-hours', process.env.RECON_MATRIX_MAX_ARTIFACT_AGE_HOURS || process.env.RECON_EVIDENCE_MAX_AGE_HOURS || 24));
const maxArtifactAgeMs = Number(argValue('max-artifact-age-ms', process.env.RECON_MATRIX_MAX_ARTIFACT_AGE_MS || process.env.RECON_EVIDENCE_MAX_AGE_MS || maxArtifactAgeHours * 60 * 60 * 1000));
const maxClockSkewMs = Number(argValue('max-clock-skew-ms', process.env.RECON_MATRIX_MAX_CLOCK_SKEW_MS || process.env.RECON_EVIDENCE_MAX_CLOCK_SKEW_MS || 300000));
const timeoutMs = Number(process.env.RECON_MATRIX_TIMEOUT_MS || 900000);
const selectedCaseIds = new Set(String(process.env.RECON_MATRIX_CASES || '').split(',').map((x) => x.trim()).filter(Boolean));

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`REPI real frontier matrix\n\nUsage:\n  node bench/recon-remote/frontier-matrix/run.mjs\n  node bench/recon-remote/frontier-matrix/run.mjs --live\n  node bench/recon-remote/frontier-matrix/run.mjs --live --strict\n  node bench/recon-remote/frontier-matrix/run.mjs --strict --fresh\n\nPurpose:\n  Evaluates multiple live real-platform cases instead of relying on one latest artifact:\n  - Bilibili runtime WBI positive case\n  - Bilibili signed media/CDN boundary positive case\n  - Bilibili multi-page container WBI/media positive case\n  - Bilibili per-page CID boundary positive case\n  - Xiaohongshu auto-discovery target note/feed positive case\n  - Xiaohongshu auto-discovery hit-rate/provenance positive case\n  - Xiaohongshu search-notes permission negative-control case\n  - Douyin a_bogus structured API replay positive case\n  - Douyin no-cookie replay divergence negative-control case\n  - Frontier strict aggregate gate\n  - Freshness gate to prevent stale latest-evidence self-hype\n\nEnvironment:\n  RECON_MATRIX_LIVE=1\n  RECON_MATRIX_STRICT=1\n  RECON_MATRIX_FRESHNESS=1       Enforce max artifact age. Strict mode enables this unless disabled.\n  RECON_MATRIX_FRESH=1           Alias for RECON_MATRIX_FRESHNESS.\n  RECON_MATRIX_MAX_ARTIFACT_AGE_HOURS=24\n  RECON_MATRIX_MAX_ARTIFACT_AGE_MS=<ms>\n  RECON_MATRIX_MAX_CLOCK_SKEW_MS=300000\n  RECON_MATRIX_CASES=bilibili_wbi_runtime,bilibili_media_cdn_boundary,bilibili_multipage_wbi_container,bilibili_per_page_cid_boundary,xhs_auto_discovery,xhs_discovery_hit_rate,xhs_search_negative,douyin_structured_api,douyin_cookie_boundary\n  RECON_MATRIX_TIMEOUT_MS=900000\n\nOutput:\n  .repi-harness/evidence/remote/frontier-matrix/<timestamp>/\n`);
  process.exit(0);
}

function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function safeJson(text, fallback = null) { try { return JSON.parse(text); } catch { return fallback; } }
function rel(path) { return String(path || '').replace(`${repoRoot}/`, ''); }
function evidenceTime(path) { return basename(dirname(path)); }
function parseEvidenceTimestamp(value) {
  const raw = String(value || '');
  const hyphen = raw.match(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z$/);
  const iso = hyphen ? `${hyphen[1]}T${hyphen[2]}:${hyphen[3]}:${hyphen[4]}.${hyphen[5]}Z` : raw;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : 0;
}
function artifactTimestampFromPath(path) {
  const match = String(path || '').match(/(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)/);
  return match ? match[1] : evidenceTime(path || '');
}
function timestampSource(path, obj = null) {
  const candidates = [
    ['generatedAt', obj?.generatedAt],
    ['artifactDir', artifactTimestampFromPath(obj?.artifactDir || '')],
    ['path', artifactTimestampFromPath(path || '')],
  ];
  for (const [source, value] of candidates) {
    const ms = parseEvidenceTimestamp(value);
    if (ms) return { source, value, ms };
  }
  const full = path ? (path.startsWith('/') ? path : join(repoRoot, path)) : '';
  if (full) {
    try {
      const st = statSync(full);
      return { source: 'mtime', value: new Date(st.mtimeMs).toISOString(), ms: st.mtimeMs };
    } catch {}
  }
  return { source: 'missing', value: '', ms: 0 };
}
function artifactFreshness(path, obj = null, consumer = '') {
  const stamp = timestampSource(path, obj);
  const ageMs = stamp.ms ? Date.now() - stamp.ms : null;
  const missing = !path || !existsSync(path.startsWith('/') ? path : join(repoRoot, path));
  const futureSkew = ageMs !== null && ageMs < -maxClockSkewMs;
  const stale = freshnessEnabled && (missing || ageMs === null || futureSkew || ageMs > maxArtifactAgeMs);
  return {
    consumer,
    enabled: freshnessEnabled,
    fresh: !stale,
    stale,
    missing,
    artifact: rel(path || ''),
    profile: obj?.profile || obj?.family || '',
    mode: obj?.mode || '',
    timeSource: stamp.source,
    artifactTime: stamp.value || '',
    ageMs,
    maxAgeMs: maxArtifactAgeMs,
    maxAgeHours: Number((maxArtifactAgeMs / 3600000).toFixed(4)),
    maxClockSkewMs,
  };
}
async function freshnessForArtifact(consumer, path) {
  const obj = await readJson(path);
  return artifactFreshness(path, obj, consumer);
}
async function buildFreshnessReport(scenarioResults, frontierObj) {
  const rows = [];
  const seen = new Set();
  const add = async (consumer, artifact) => {
    if (!artifact) return;
    const key = `${consumer}:${artifact}`;
    if (seen.has(key)) return;
    seen.add(key);
    rows.push(await freshnessForArtifact(consumer, artifact));
  };
  for (const row of scenarioResults) await add(`frontier-matrix:${row.id}`, row.artifact);
  for (const [name, artifact] of Object.entries(frontierObj?.artifacts || {})) await add(`frontier-gate:${name}`, artifact);
  const staleRows = rows.filter((row) => row.stale);
  return {
    enabled: freshnessEnabled,
    enforced: freshnessEnabled,
    allowStaleEvidence,
    referenceTime: new Date().toISOString(),
    maxAgeMs: maxArtifactAgeMs,
    maxArtifactAgeHours: Number((maxArtifactAgeMs / 3600000).toFixed(4)),
    maxClockSkewMs,
    passed: !freshnessEnabled || staleRows.length === 0,
    staleCount: staleRows.length,
    rows,
    staleArtifacts: staleRows.map((row) => ({ consumer: row.consumer, artifact: row.artifact, artifactTime: row.artifactTime, ageMs: row.ageMs, timeSource: row.timeSource, missing: row.missing })),
  };
}
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
function xhsDiscoveryHitRate(obj) {
  const discovery = obj?.xhsDiscovery || {};
  const candidates = Array.isArray(discovery.candidates) ? discovery.candidates : [];
  const attempts = Array.isArray(discovery.attempts) ? discovery.attempts : [];
  const tokenizedCandidates = candidates.filter((candidate) => (
    candidate?.noteId
    && candidate?.hasXsecToken
    && /xiaohongshu\.com\/explore\//i.test(candidate.redactedUrl || candidate.url || '')
    && candidate.source
  ));
  const successfulAttempts = attempts.filter((attempt) => (
    attempt?.bestTargetNote2xx
    && Number(attempt.status || attempt.replayStatus || 0) >= 200
    && Number(attempt.status || attempt.replayStatus || 0) < 300
    && Number(attempt.noteItemCount || 0) >= 1
    && Array.isArray(attempt.signedHeaderNames)
    && attempt.signedHeaderNames.length >= 2
    && Number(attempt.signerEvents || 0) >= 1
    && Number(attempt.bundleHints || 0) >= 1
  ));
  const hitRate = attempts.length ? successfulAttempts.length / attempts.length : 0;
  const minHitRate = Number(process.env.RECON_MATRIX_XHS_DISCOVERY_MIN_HIT_RATE || 1);
  const passed = Boolean(
    obj?.verdict === 'xhs-auto-discovery-target-note-replay-confirmed'
    && discovery.enabled
    && discovery.attempted
    && candidates.length >= 1
    && tokenizedCandidates.length >= 1
    && attempts.length >= 1
    && successfulAttempts.length >= 1
    && hitRate >= minHitRate
    && xhsTargetOk(obj)
  );
  return { passed, hitRate, minHitRate, candidates, tokenizedCandidates, attempts, successfulAttempts };
}
function douyinStructuredOk(obj) {
  const replayed = obj?.runtimeApiReplay?.bestReplayedStructuredApi || obj?.signatureSurface?.runtimeReplayedStructuredApi;
  return Boolean(replayed && Number(replayed.status || 0) >= 200 && Number(replayed.status || 0) < 300 && replayed.structured?.structured);
}
function bilibiliMediaBoundary(obj) {
  const matrix = obj?.mediaProbeMatrix || {};
  const byKind = matrix.byKind || {};
  const byStatus = matrix.byStatus || {};
  const hostClasses = matrix.hostClasses || {};
  const hostClassNames = Object.entries(hostClasses).filter(([, count]) => Number(count || 0) > 0).map(([name]) => name);
  const statusNames = Object.entries(byStatus).filter(([, count]) => Number(count || 0) > 0).map(([name]) => name);
  const signedReqs = obj?.signatureTrace?.signedRequestCount || 0;
  const reachable = Number(matrix.reachableMedia || 0);
  const hasDashVideo = Number(byKind['dash-video'] || 0) >= 1;
  const hasBackup = Object.entries(byKind).some(([name, count]) => /backup/i.test(name) && Number(count || 0) >= 1);
  const hasReachableStatus = statusNames.some((status) => ['200', '206'].includes(String(status)));
  const hostDiversity = hostClassNames.length >= 2;
  const passed = Boolean(
    obj?.wbiRegression?.selfTest?.ok
    && obj?.wbiRegression?.signedEndpoint
    && signedReqs >= 1
    && reachable >= 4
    && hasDashVideo
    && hasBackup
    && hostDiversity
    && hasReachableStatus
  );
  return { passed, matrix, byKind, byStatus, hostClasses, hostClassNames, statusNames, signedReqs, reachable, hasDashVideo, hasBackup, hostDiversity, hasReachableStatus };
}
function bilibiliMultipageContainer(obj) {
  const pages = Number(obj?.pagelist?.pages || 0);
  const playurls = Array.isArray(obj?.playurls) ? obj.playurls : [];
  const matrix = obj?.mediaProbeMatrix || {};
  const hostClasses = matrix.hostClasses || {};
  const hostClassCount = Object.values(hostClasses).filter((count) => Number(count || 0) > 0).length;
  const signedDashPlayurl = playurls.find((item) => item?.signed && Number(item.code || 0) === 0 && item.hasDash);
  const mediaCandidates = Array.isArray(obj?.mediaCandidates) ? obj.mediaCandidates : [];
  const wbiCandidates = mediaCandidates.filter((item) => item.source === 'wbi-playurl');
  const wbiKinds = [...new Set(wbiCandidates.map((item) => item.kind).filter(Boolean))];
  const targetPage = (() => {
    try { return Number(new URL(obj?.target || '').searchParams.get('p') || 1); } catch { return 1; }
  })();
  const passed = Boolean(
    obj?.profile === 'bilibili-video'
    && obj?.verdict === 'bilibili-wbi-media-api-confirmed'
    && pages >= 2
    && targetPage >= 2
    && obj?.wbiRegression?.selfTest?.ok
    && obj?.wbiRegression?.signedEndpoint
    && signedDashPlayurl
    && wbiCandidates.length >= 2
    && wbiKinds.includes('dash-video')
    && wbiKinds.includes('dash-audio')
    && Number(matrix.reachableMedia || 0) >= 2
    && hostClassCount >= 2
  );
  return { passed, pages, targetPage, signedDashPlayurl, wbiCandidateCount: wbiCandidates.length, wbiKinds, reachableMedia: Number(matrix.reachableMedia || 0), hostClassCount, hostClasses };
}
function bilibiliPerPageCidBoundary(obj) {
  const selected = obj?.pageBoundary || obj?.pagelist?.selected || {};
  const rows = Array.isArray(obj?.pagelist?.rows) ? obj.pagelist.rows : [];
  const requestedPage = Number(selected.requestedPage || obj?.requestedPage || 1);
  const selectedPage = Number(selected.selectedPage || obj?.selectedPage || 0);
  const selectedCid = selected.selectedCid || obj?.selectedCid || obj?.cid || null;
  const firstCid = selected.firstCid || rows[0]?.cid || null;
  const requestedRow = rows.find((row) => Number(row.page) === requestedPage) || rows[Math.max(0, requestedPage - 1)] || null;
  const signedDashPlayurl = (obj?.playurls || []).find((item) => item?.signed && Number(item.code || 0) === 0 && item.hasDash);
  const cidMatchesRequestedRow = Boolean(requestedRow?.cid && selectedCid && String(requestedRow.cid) === String(selectedCid));
  const cidMatchesResult = Boolean(selectedCid && obj?.cid && String(selectedCid) === String(obj.cid));
  const cidDiffersFromFirst = Boolean(selected.cidDiffersFromFirst || (selectedCid && firstCid && String(selectedCid) !== String(firstCid)));
  const passed = Boolean(
    obj?.profile === 'bilibili-video'
    && obj?.verdict === 'bilibili-wbi-media-api-confirmed'
    && Number(obj?.pagelist?.pages || selected.pageCount || 0) >= 2
    && requestedPage >= 2
    && selectedPage === requestedPage
    && selected.pageMatchesRequest !== false
    && selectedCid
    && cidMatchesRequestedRow
    && cidMatchesResult
    && cidDiffersFromFirst
    && obj?.wbiRegression?.selfTest?.ok
    && obj?.wbiRegression?.signedEndpoint
    && signedDashPlayurl
    && Number(obj?.mediaProbeMatrix?.reachableMedia || 0) >= 2
  );
  return { passed, requestedPage, selectedPage, selectedCid, firstCid, requestedRow, cidMatchesRequestedRow, cidMatchesResult, cidDiffersFromFirst, signedDashPlayurl, rowSample: rows.slice(0, 5) };
}
function douyinCookieBoundary(obj) {
  const replay = obj?.runtimeApiReplay || {};
  const attempts = Array.isArray(replay.attempts) ? replay.attempts : [];
  const observed = replay.observedStructuredApi || obj?.signatureSurface?.runtimeObservedStructuredApi || {};
  const exact = replay.bestReplayedStructuredApi || obj?.signatureSurface?.runtimeReplayedStructuredApi || attempts.find((attempt) => attempt.variant === 'exact-cookie' && attempt.structured?.structured);
  const noCookie = attempts.find((attempt) => (
    attempt.variant === 'no-cookie'
    && Number(attempt.status || 0) >= 200
    && Number(attempt.status || 0) < 300
    && !attempt.structured?.structured
    && Number(attempt.structured?.awemeCount || 0) === 0
    && (
      Number(attempt.bytes || 0) === 0
      || Boolean(attempt.divergence?.observedBodySha256 && attempt.divergence?.replayBodySha256 && attempt.divergence.observedBodySha256 !== attempt.divergence.replayBodySha256)
    )
  ));
  const exactOk = Boolean(exact && Number(exact.status || 0) >= 200 && Number(exact.status || 0) < 300 && exact.structured?.structured && Number(exact.structured?.awemeCount || 0) >= 1);
  const observedOk = Boolean(observed?.structured?.structured && Number(observed.structured?.awemeCount || 0) >= 1);
  const passed = Boolean(replay.attempted && observedOk && exactOk && noCookie && douyinStructuredOk(obj));
  return { passed, observed, exact, noCookie, attempts };
}
function summarizeScenario(id, weight, obj, artifact, command, runItem) {
  const common = { id, weight, artifact, freshness: artifactFreshness(artifact, obj, id), command, run: runItem ? { code: runItem.run?.code, signal: runItem.run?.signal, elapsedMs: runItem.run?.elapsedMs, stdoutSha256: sha256(runItem.run?.stdout || '').slice(0, 24), stderrSha256: sha256(runItem.run?.stderr || '').slice(0, 24), stdoutTail: redact(runItem.run?.stdout || '').slice(-1000), stderrTail: redact(runItem.run?.stderr || '').slice(-1000) } : undefined };
  if (!obj) return { ...common, passed: false, score: 0, evidence: { reason: 'artifact missing' } };
  if (id === 'bilibili_wbi_runtime') {
    const signerEvents = obj.signatureTrace?.signerLog?.length || 0;
    const bundleHints = obj.signatureTrace?.bundleHints?.length || 0;
    const signedReqs = obj.signatureTrace?.signedRequestCount || 0;
    const passed = Boolean(obj.wbiRegression?.selfTest?.ok && obj.wbiRegression?.signedEndpoint && signedReqs >= 1 && (signerEvents >= 1 || bundleHints >= 1));
    return { ...common, passed, score: passed ? weight : Math.min(weight - 1, (obj.wbiRegression?.selfTest?.ok ? 8 : 0) + Math.min(8, signedReqs * 3 + signerEvents + bundleHints * 2)), evidence: { verdict: obj.verdict, selfTest: obj.wbiRegression?.selfTest?.ok, signedEndpoint: obj.wbiRegression?.signedEndpoint, signerEvents, bundleHints, signedReqs, media: obj.mediaProbeMatrix?.reachableMedia || 0 } };
  }
  if (id === 'bilibili_media_cdn_boundary') {
    const boundary = bilibiliMediaBoundary(obj);
    return { ...common, passed: boundary.passed, score: boundary.passed ? weight : Math.min(weight - 1, (boundary.reachable >= 4 ? 3 : 0) + (boundary.hostDiversity ? 2 : 0) + (boundary.hasBackup ? 2 : 0) + (boundary.signedReqs >= 1 ? 2 : 0)), evidence: { verdict: obj.verdict, reachableMedia: boundary.reachable, total: boundary.matrix.total || 0, byKind: boundary.byKind, byStatus: boundary.byStatus, hostClasses: boundary.hostClasses, hostClassCount: boundary.hostClassNames.length, signedReqs: boundary.signedReqs, wbiSelfTest: obj.wbiRegression?.selfTest?.ok, signedEndpoint: obj.wbiRegression?.signedEndpoint, hasDashVideo: boundary.hasDashVideo, hasBackup: boundary.hasBackup, hasReachableStatus: boundary.hasReachableStatus } };
  }
  if (id === 'bilibili_multipage_wbi_container') {
    const multi = bilibiliMultipageContainer(obj);
    return { ...common, passed: multi.passed, score: multi.passed ? weight : Math.min(weight - 1, (multi.pages >= 2 ? 2 : 0) + (multi.targetPage >= 2 ? 1 : 0) + (multi.signedDashPlayurl ? 2 : 0) + (multi.wbiCandidateCount >= 2 ? 2 : 0) + (multi.hostClassCount >= 2 ? 1 : 0) + (multi.reachableMedia >= 2 ? 1 : 0)), evidence: { verdict: obj.verdict, target: obj.target || '', pages: multi.pages, targetPage: multi.targetPage, cid: obj.cid || null, wbiSelfTest: obj.wbiRegression?.selfTest?.ok, signedEndpoint: obj.wbiRegression?.signedEndpoint, signedDashPlayurl: Boolean(multi.signedDashPlayurl), wbiCandidateCount: multi.wbiCandidateCount, wbiKinds: multi.wbiKinds, reachableMedia: multi.reachableMedia, hostClassCount: multi.hostClassCount, hostClasses: multi.hostClasses } };
  }
  if (id === 'bilibili_per_page_cid_boundary') {
    const boundary = bilibiliPerPageCidBoundary(obj);
    return { ...common, passed: boundary.passed, score: boundary.passed ? weight : Math.min(weight - 1, (boundary.requestedPage >= 2 ? 2 : 0) + (boundary.selectedPage === boundary.requestedPage ? 3 : 0) + (boundary.cidMatchesRequestedRow ? 3 : 0) + (boundary.cidDiffersFromFirst ? 2 : 0) + (boundary.signedDashPlayurl ? 2 : 0)), evidence: { verdict: obj.verdict, target: obj.target || '', requestedPage: boundary.requestedPage, selectedPage: boundary.selectedPage, selectedCid: boundary.selectedCid, resultCid: obj.cid || null, firstCid: boundary.firstCid, requestedRow: boundary.requestedRow, cidMatchesRequestedRow: boundary.cidMatchesRequestedRow, cidMatchesResult: boundary.cidMatchesResult, cidDiffersFromFirst: boundary.cidDiffersFromFirst, pageMatchesRequest: obj.pageBoundary?.pageMatchesRequest ?? obj.pagelist?.selected?.pageMatchesRequest, wbiSelfTest: obj.wbiRegression?.selfTest?.ok, signedEndpoint: obj.wbiRegression?.signedEndpoint, signedDashPlayurl: Boolean(boundary.signedDashPlayurl), reachableMedia: obj.mediaProbeMatrix?.reachableMedia || 0, rowSample: boundary.rowSample } };
  }
  if (id === 'xhs_auto_discovery') {
    const best = obj.xhsReplay?.bestTargetNote2xxSignedReplay || null;
    const passed = Boolean(obj.verdict === 'xhs-auto-discovery-target-note-replay-confirmed' && xhsTargetOk(obj) && obj.xhsDiscovery?.candidateCount >= 1 && obj.xhsDiscovery?.attempts?.some((item) => item.bestTargetNote2xx));
    return { ...common, passed, score: passed ? weight : Math.min(weight - 1, (obj.xhsDiscovery?.candidateCount ? 8 : 0) + (xhsTargetOk(obj) ? 14 : 0) + Math.min(5, Math.floor((obj.signatureTrace?.signerLog?.length || 0) / 10))), evidence: { verdict: obj.verdict, candidates: obj.xhsDiscovery?.candidateCount || 0, attempts: obj.xhsDiscovery?.attempts?.length || 0, effectiveTarget: obj.effectiveTarget || '', bestEndpoint: best?.endpointClass || '', bestMethod: best?.method || '', bestStatus: best?.status || null, noteItemCount: best?.structured?.noteItemCount || 0, signerEvents: obj.signatureTrace?.signerLog?.length || 0 } };
  }
  if (id === 'xhs_discovery_hit_rate') {
    const stats = xhsDiscoveryHitRate(obj);
    const attempted = stats.attempts.length;
    const successful = stats.successfulAttempts.length;
    return { ...common, passed: stats.passed, score: stats.passed ? weight : Math.min(weight - 1, (stats.tokenizedCandidates.length ? 4 : 0) + (successful ? 4 : 0) + (xhsTargetOk(obj) ? 3 : 0)), evidence: { verdict: obj.verdict, candidateCount: stats.candidates.length, tokenizedCandidateCount: stats.tokenizedCandidates.length, attempted, successful, hitRate: Number(stats.hitRate.toFixed(4)), minHitRate: stats.minHitRate, candidateSources: [...new Set(stats.tokenizedCandidates.map((candidate) => candidate.source).filter(Boolean))].slice(0, 8), signedHeaderEvidence: stats.successfulAttempts.map((attempt) => ({ endpoint: attempt.endpointClass, method: attempt.method, status: attempt.status || attempt.replayStatus, noteItemCount: attempt.noteItemCount || 0, signedHeaderCount: attempt.signedHeaderNames?.length || 0, signerEvents: attempt.signerEvents || 0, bundleHints: attempt.bundleHints || 0 })).slice(0, 4) } };
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
  if (id === 'douyin_cookie_boundary') {
    const boundary = douyinCookieBoundary(obj);
    return { ...common, passed: boundary.passed, score: boundary.passed ? weight : Math.min(weight - 1, (boundary.observed?.structured?.structured ? 3 : 0) + (boundary.exact?.structured?.structured ? 4 : 0) + (boundary.noCookie ? 3 : 0)), evidence: { verdict: obj.verdict, replayAttempted: obj.runtimeApiReplay?.attempted, observedStructured: Boolean(boundary.observed?.structured?.structured), exactCookieStructured: Boolean(boundary.exact?.structured?.structured), exactCookieStatus: boundary.exact?.status || null, exactCookieAwemeCount: boundary.exact?.structured?.awemeCount || 0, noCookieStatus: boundary.noCookie?.status || null, noCookieBytes: boundary.noCookie?.bytes ?? null, noCookieStructured: Boolean(boundary.noCookie?.structured?.structured), noCookieAwemeCount: boundary.noCookie?.structured?.awemeCount || 0, noCookieDiverged: Boolean(boundary.noCookie?.divergence?.observedBodySha256 && boundary.noCookie?.divergence?.replayBodySha256 && boundary.noCookie.divergence.observedBodySha256 !== boundary.noCookie.divergence.replayBodySha256), attemptVariants: boundary.attempts.map((attempt) => attempt.variant).slice(0, 8) } };
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
    id: 'bilibili_media_cdn_boundary',
    weight: 10,
    derivedFrom: 'bilibili_wbi_runtime',
    command: ['node', ['bench/recon-remote/real-platform/run.mjs', process.env.RECON_MATRIX_BILI_URL || 'https://www.bilibili.com/video/BV1odL76QE6B', 'bilibili-video']],
    latest: (obj) => obj.profile === 'bilibili-video',
  },
  {
    id: 'bilibili_multipage_wbi_container',
    weight: 10,
    command: ['node', ['bench/recon-remote/real-platform/run.mjs', process.env.RECON_MATRIX_BILI_MULTIPAGE_URL || 'https://www.bilibili.com/video/BV1Ee9EBnEfo?p=2', 'bilibili-video']],
    env: { RECON_BROWSER: '1', RECON_TIMEOUT_MS: '45000', RECON_QUIET_MS: '5000', RECON_PROBE_LIMIT: '4' },
    timeoutMs: 180000,
    latest: (obj) => obj.profile === 'bilibili-video' && Number(obj.pagelist?.pages || 0) >= 2,
  },
  {
    id: 'bilibili_per_page_cid_boundary',
    weight: 15,
    derivedFrom: 'bilibili_multipage_wbi_container',
    command: ['node', ['bench/recon-remote/real-platform/run.mjs', process.env.RECON_MATRIX_BILI_MULTIPAGE_URL || 'https://www.bilibili.com/video/BV1Ee9EBnEfo?p=2', 'bilibili-video']],
    latest: (obj) => obj.profile === 'bilibili-video' && Number(obj.pagelist?.pages || 0) >= 2 && Number(obj.pageBoundary?.requestedPage || obj.requestedPage || 1) >= 2,
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
    id: 'xhs_discovery_hit_rate',
    weight: 10,
    derivedFrom: 'xhs_auto_discovery',
    command: ['node', ['bench/recon-remote/real-platform/run.mjs', process.env.RECON_MATRIX_XHS_DISCOVERY_URL || 'https://www.xhs-download.org/zh', 'xiaohongshu-note']],
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
  {
    id: 'douyin_cookie_boundary',
    weight: 10,
    derivedFrom: 'douyin_structured_api',
    command: ['node', ['bench/recon-remote/douyin-nowatermark/run.mjs', process.env.RECON_MATRIX_DOUYIN_URL || 'https://www.douyin.com/video/7636072173723945829']],
    latest: (obj) => obj.profile === 'douyin-nowatermark' || obj.target?.includes('douyin.com'),
  },
];
const activeScenarios = scenarios.filter((scenario) => !selectedCaseIds.size || selectedCaseIds.has(scenario.id));
const scenarioById = new Map(scenarios.map((scenario) => [scenario.id, scenario]));
const liveScenarios = [];
const liveScenarioIds = new Set();
for (const scenario of activeScenarios) {
  const sourceScenario = scenario.derivedFrom ? scenarioById.get(scenario.derivedFrom) : scenario;
  if (!sourceScenario?.command || liveScenarioIds.has(sourceScenario.id)) continue;
  liveScenarios.push(sourceScenario);
  liveScenarioIds.add(sourceScenario.id);
}
const outDir = join(evidenceRoot, 'frontier-matrix', timestamp());
await mkdir(outDir, { recursive: true });
const started = Date.now();
const runs = [];
const entriesBefore = await latestArtifacts();

for (const scenario of liveScenarios) {
  if (!live) continue;
  const [cmd, args] = scenario.command;
  const runResult = await run(cmd, args, { timeoutMs: scenario.timeoutMs, env: scenario.env });
  runs.push({ id: scenario.id, scenario, run: runResult });
  await writeFile(join(outDir, `${scenario.id}.stdout.txt`), redact(runResult.stdout || ''));
  await writeFile(join(outDir, `${scenario.id}.stderr.txt`), redact(runResult.stderr || ''));
}

const frontierArgs = ['bench/recon-remote/frontier-gate/run.mjs', '--strict'];
if (freshnessEnabled) frontierArgs.push('--fresh');
if (allowStaleEvidence) frontierArgs.push('--allow-stale-evidence');
const frontierRun = await run('node', frontierArgs, {
  timeoutMs: 120000,
  env: {
    RECON_EVIDENCE_MAX_AGE_MS: String(maxArtifactAgeMs),
    RECON_EVIDENCE_MAX_CLOCK_SKEW_MS: String(maxClockSkewMs),
    ...(freshnessEnabled ? { RECON_EVIDENCE_FRESHNESS: '1' } : {}),
    ...(allowStaleEvidence ? { RECON_EVIDENCE_ALLOW_STALE: '1' } : {}),
  },
});
runs.push({ id: 'frontier_strict', scenario: { id: 'frontier_strict', weight: 10, command: ['node', frontierArgs] }, run: frontierRun });
await writeFile(join(outDir, 'frontier_strict.stdout.txt'), redact(frontierRun.stdout || ''));
await writeFile(join(outDir, 'frontier_strict.stderr.txt'), redact(frontierRun.stderr || ''));

const entriesAfter = await latestArtifacts();
const scenarioResults = [];
for (const scenario of activeScenarios) {
  const runItem = runs.find((item) => item.id === scenario.id) || (scenario.derivedFrom ? runs.find((item) => item.id === scenario.derivedFrom) : null);
  const artifact = live ? artifactFromRun(runItem) : findLatest(entriesBefore, scenario.latest)?.path || '';
  const obj = await readJson(artifact || findLatest(entriesAfter, scenario.latest)?.path || '');
  scenarioResults.push(summarizeScenario(scenario.id, scenario.weight, obj, artifact || findLatest(entriesAfter, scenario.latest)?.path || '', `${scenario.command[0]} ${scenario.command[1].join(' ')}`, runItem));
}
const frontierArtifact = artifactFromRun(runs.find((item) => item.id === 'frontier_strict'));
const frontierObj = await readJson(frontierArtifact);
scenarioResults.push(summarizeScenario('frontier_strict', 10, frontierObj, frontierArtifact, `node ${frontierArgs.join(' ')}`, runs.find((item) => item.id === 'frontier_strict')));
const freshness = await buildFreshnessReport(scenarioResults, frontierObj);

const matrixScore = scenarioResults.reduce((sum, row) => sum + Math.min(row.weight, row.score), 0);
const matrixMaxScore = scenarioResults.reduce((sum, row) => sum + row.weight, 0);
const freshnessPassed = freshness.passed;
const passed = scenarioResults.every((row) => row.passed) && freshnessPassed;
const matrixPercent = matrixMaxScore ? Number(((matrixScore / matrixMaxScore) * 100).toFixed(2)) : 0;
const grade = matrixPercent >= 90 ? 'elite' : matrixPercent >= 75 ? 'advanced' : matrixPercent >= 55 ? 'solid' : matrixPercent >= 35 ? 'basic' : 'weak';
const result = {
  target: 'Real-platform hardest frontier matrix: Bilibili + Xiaohongshu positives/negative + Douyin + frontier strict',
  profile: 'frontier-matrix',
  verdict: passed ? 'frontier-matrix-passed' : 'frontier-matrix-incomplete',
  generatedAt: new Date().toISOString(),
  artifactDir: rel(outDir),
  mode: live ? 'live-rerun' : 'latest-evidence',
  strict,
  freshness,
  elapsedMs: Date.now() - started,
  matrixScore,
  matrixMaxScore,
  matrixPercent,
  grade,
  scenarios: scenarioResults,
  nextActions: [
    ...scenarioResults.filter((row) => !row.passed).map((row) => `${row.id}: inspect ${row.artifact || 'missing artifact'} and rerun ${row.command}`),
    ...(!freshnessPassed ? ['freshness: rerun with --live --strict or increase RECON_MATRIX_MAX_ARTIFACT_AGE_HOURS only for forensic replay'] : []),
  ],
};
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
const md = [
  '# REPI Real Frontier Matrix',
  '',
  `verdict: ${result.verdict}`,
  `mode: ${result.mode}`,
  `matrix_score: ${matrixScore}/${matrixMaxScore} (${result.matrixPercent}%)`,
  `grade: ${grade}`,
  `freshness: enabled=${result.freshness.enabled} passed=${result.freshness.passed} max_age_hours=${result.freshness.maxArtifactAgeHours}`,
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
console.log(JSON.stringify({ verdict: result.verdict, artifactDir: result.artifactDir, mode: result.mode, matrixScore, matrixMaxScore, matrixPercent: result.matrixPercent, grade, freshness: { enabled: freshness.enabled, passed: freshness.passed, staleCount: freshness.staleCount }, scenarios: scenarioResults.map(({ id, passed, score, weight }) => ({ id, passed, score: Math.min(score, weight), weight })) }, null, 2));
process.exit(strict && !passed ? 1 : 0);

#!/usr/bin/env node
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const repoRoot = resolve(process.env.RECON_REPO_ROOT || '.');
const evidenceRoot = join(repoRoot, '.pi', 'evidence', 'remote');
const timeoutMs = Number(process.env.RECON_FRONTIER_TIMEOUT_MS || 900000);
const live = process.argv.includes('--live') || process.env.RECON_FRONTIER_LIVE === '1';
const strict = process.argv.includes('--strict') || process.env.RECON_FRONTIER_STRICT === '1';

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`Pi-RECON frontier gate\n\nUsage:\n  node bench/recon-remote/frontier-gate/run.mjs\n  node bench/recon-remote/frontier-gate/run.mjs --live\n  node bench/recon-remote/frontier-gate/run.mjs --strict\n\nPurpose:\n  Measures the next frontier beyond proof-gate: Douyin a_bogus rebuild/structured 2xx API,\n  Xiaohongshu x-s 2xx signed replay, Bilibili runtime WBI signer bundle trace, and agent\n  frontier planning. Non-strict mode exits 0 with verdict frontier-incomplete so it can track\n  hard gaps without pretending they are solved.\n\nEnvironment:\n  RECON_FRONTIER_LIVE=1          Rerun live proof-gate before assessment\n  RECON_FRONTIER_STRICT=1        Exit nonzero unless all frontier gates pass\n  RECON_FRONTIER_TIMEOUT_MS=900000\n\nOutput:\n  .pi/evidence/remote/frontier-gate/<timestamp>/\n`);
  process.exit(0);
}

function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function safeJson(text, fallback = null) { try { return JSON.parse(text); } catch { return fallback; } }
function rel(path) { return String(path || '').replace(`${repoRoot}/`, ''); }
function evidenceTime(path) { return basename(dirname(path)); }
function familyOf(path, obj = {}) {
  if (obj.profile) return obj.profile;
  if (path.includes('/douyin-nowatermark/')) return 'douyin-nowatermark';
  if (path.includes('/proof-gate/')) return 'proof-gate';
  if (path.includes('/agent-dogfood/')) return 'agent-dogfood';
  return obj.profile || obj.family || 'unknown';
}
function redact(value) {
  return String(value || '')
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, 'sk-<redacted>')
    .replace(/([?&](?:w_rid|xsec_token|web_session|a1|b1|msToken|a_bogus|token|buvid|SESSDATA|bili_jct|web_id|device_id)=)[^&\s"']+/gi, '$1<redacted>')
    .replace(/(ANTHROPIC_AUTH_TOKEN|OPENAI_API_KEY|GEMINI_API_KEY|OPENROUTER_API_KEY|AI_GATEWAY_API_KEY)=\S+/g, '$1=<redacted>');
}
async function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of await readdir(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) await walk(full, out);
    else if (name === 'result.json') out.push(full);
  }
  return out;
}
async function readJson(path) {
  if (!path) return null;
  const full = path.startsWith('/') ? path : join(repoRoot, path);
  if (!existsSync(full)) return null;
  return safeJson(await readFile(full, 'utf8'));
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
async function latestArtifacts(paths) {
  const latest = new Map();
  for (const path of paths.sort()) {
    const obj = safeJson(statSync(path).size ? await readFile(path, 'utf8') : '');
    if (!obj) continue;
    const family = familyOf(path, obj);
    const key = family === 'proof-gate' ? `${family}:${obj.mode || 'unknown'}` : family;
    const prev = latest.get(key);
    if (!prev || evidenceTime(path) > prev.time) latest.set(key, { path: rel(path), fullPath: path, time: evidenceTime(path), family, obj });
  }
  return latest;
}
function pass(name, passed, score, weight, evidence, required, nextCommand) {
  return { name, passed: Boolean(passed), score, weight, evidence, required, nextCommand };
}
function hasHeader(headers, wanted) {
  const lower = new Set((headers || []).map((h) => String(h).toLowerCase()));
  return wanted.every((h) => lower.has(h));
}
function structuredDouyinApi(result) {
  return (result?.apiProbeResults || []).some((probe) => {
    const status = Number(probe.status || 0);
    const head = String(probe.bodyHead || '');
    if (status < 200 || status >= 300) return false;
    if (!head || /encrypt_data_miss|verify|captcha|login|forbid|blocked/i.test(head)) return false;
    return /aweme|desc|video|play_addr|status_code"?\s*:\s*0|item_list|aweme_detail/i.test(head);
  });
}
function observedParam(result, name) {
  const matrix = result?.signatureSurface?.urlParamMatrix || result?.signatureSurface?.endpointParamMatrix || [];
  return matrix.some((row) => (row.params || []).some((param) => String(param).toLowerCase() === name.toLowerCase()))
    || (result?.signatureSurface?.signals || []).some((signal) => String(signal).toLowerCase() === name.toLowerCase());
}
function runtimeSignedDouyin(result) {
  return (result?.signatureSurface?.runtimeFetchHits || []).some((url) => /a_bogus|msToken|aweme|iteminfo/i.test(url));
}
function xhs2xxReplay(result) {
  const status = Number(result?.xhsReplay?.status || 0);
  const body = String(result?.xhsReplay?.bodyHead || '');
  return result?.xhsReplay?.attempted && status >= 200 && status < 300 && !/"data"\s*:\s*\{\s*\}/.test(body) && /"success"\s*:\s*true|"code"\s*:\s*0|note|image|user/i.test(body);
}
function proofLiveBound(result) {
  if (!result || result.verdict !== 'proof-gate-passed' || result.mode !== 'live-rerun') return false;
  const liveArtifacts = result.liveArtifacts || {};
  return ['bilibili', 'xhs', 'douyin'].every((name) => {
    const liveArtifact = String(liveArtifacts[name] || '');
    const rowArtifact = String(result.rows?.[name]?.artifact || '');
    return liveArtifact && rowArtifact && (liveArtifact === rowArtifact || liveArtifact.endsWith(rowArtifact) || rowArtifact.endsWith(liveArtifact));
  });
}

const outDir = join(evidenceRoot, 'frontier-gate', timestamp());
await mkdir(outDir, { recursive: true });
const started = Date.now();
const runs = [];
if (live) {
  const gateRun = await run('node', ['bench/recon-remote/proof-gate/run.mjs'], { timeoutMs, env: { RECON_GATE_AGENT: process.env.RECON_GATE_AGENT || '0' } });
  runs.push({ label: 'proof-gate-live', run: gateRun });
}
const scoreRun = await run('node', ['bench/recon-remote/hard-score.mjs'], { timeoutMs: 60000 });
runs.push({ label: 'hard-score', run: scoreRun });

const latest = await latestArtifacts((await walk(evidenceRoot)).filter((p) => !p.includes('/hard-score/')));
const bili = latest.get('bilibili-video')?.obj || null;
const xhs = latest.get('xiaohongshu-note')?.obj || null;
const douyin = latest.get('douyin-nowatermark')?.obj || null;
const agent = latest.get('agent-dogfood')?.obj || null;
const proofLive = latest.get('proof-gate:live-rerun')?.obj || null;
const proofLatest = latest.get('proof-gate:latest-only')?.obj || null;

const gates = [];
const biliSignerEvents = bili?.signatureTrace?.signerLog?.length || 0;
const biliBundleHints = bili?.signatureTrace?.bundleHints?.length || 0;
const biliSignedReqs = bili?.signatureTrace?.signedRequestCount || 0;
const biliWbiOk = Boolean(bili?.wbiRegression?.selfTest?.ok && bili?.wbiRegression?.signedEndpoint);
gates.push(pass(
  'bilibili_runtime_wbi_bundle_trace',
  biliWbiOk && (biliSignerEvents >= 1 || biliBundleHints >= 1) && biliSignedReqs >= 1,
  (biliWbiOk ? 8 : 0) + (bili?.mediaProbeMatrix?.reachableMedia >= 4 ? 3 : 0) + Math.min(9, biliSignerEvents * 2 + biliBundleHints * 3 + biliSignedReqs * 3),
  20,
  { artifact: latest.get('bilibili-video')?.path, verdict: bili?.verdict, wbiSelfTest: bili?.wbiRegression?.selfTest?.ok, signedEndpoint: bili?.wbiRegression?.signedEndpoint, signerEvents: biliSignerEvents, bundleHints: biliBundleHints, signedRequestCount: biliSignedReqs },
  'WBI self-test + signed endpoint + browser/runtime signer or bundle trace + signed request observed',
  'RECON_BROWSER=1 RECON_GATE_BILI_TIMEOUT_MS=45000 node bench/recon-remote/real-platform/run.mjs https://www.bilibili.com/video/BV1odL76QE6B bilibili-video'
));

const xhsHeaders = xhs?.xhsReplay?.signedHeaderNames || [];
const xhsSignerEvents = xhs?.signatureTrace?.signerLog?.length || 0;
const xhsBundles = xhs?.signatureTrace?.bundleHints?.length || 0;
const xhsStatus = Number(xhs?.xhsReplay?.status || 0);
const xhsHeaderOk = hasHeader(xhsHeaders, ['x-s', 'x-t', 'x-s-common']);
gates.push(pass(
  'xiaohongshu_xs_2xx_signed_replay',
  xhsHeaderOk && xhs2xxReplay(xhs) && xhsSignerEvents >= 20,
  (xhsHeaderOk ? 6 : 0) + (xhs?.xhsReplay?.attempted ? 3 : 0) + (xhsStatus === 461 ? 3 : 0) + Math.min(3, Math.floor(xhsSignerEvents / 25)) + Math.min(3, xhsBundles * 2) + (xhs2xxReplay(xhs) ? 10 : 0),
  25,
  { artifact: latest.get('xiaohongshu-note')?.path, verdict: xhs?.verdict, status: xhsStatus || null, signedHeaders: xhsHeaders, signerEvents: xhsSignerEvents, bundleHints: xhsBundles, replayDivergence: xhs?.signatureTrace?.replayDivergence || xhs?.xhsReplay?.replayDivergence },
  'x-s/x-t/x-s-common captured + signed replay returns structured 2xx note data + signer events >=20',
  "RECON_TIMEOUT_MS=45000 RECON_QUIET_MS=5000 node bench/recon-remote/real-platform/run.mjs 'https://www.xiaohongshu.com/explore/66237c6e000000001c00893f' xiaohongshu-note"
));

const dySignals = douyin?.signatureSurface?.signals?.length || 0;
const dyBundles = douyin?.signatureSurface?.bundleHints?.length || 0;
const dyStrong = (douyin?.probes || []).filter((probe) => probe.classification?.noWatermarkLikely && probe.classification?.reachable).length;
const dyABogus = observedParam(douyin, 'a_bogus');
const dyMsToken = observedParam(douyin, 'msToken');
const dyRuntimeSigned = runtimeSignedDouyin(douyin);
const dyStructured = structuredDouyinApi(douyin);
gates.push(pass(
  'douyin_abogus_rebuild_structured_api',
  dyABogus && dyMsToken && dyRuntimeSigned && dyStructured,
  (dyABogus ? 5 : 0) + (dyMsToken ? 3 : 0) + (dyRuntimeSigned ? 3 : 0) + Math.min(4, Math.floor(dySignals / 4) + Math.floor(dyBundles / 8)) + (dyStrong ? 2 : 0) + (dyStructured ? 13 : 0),
  30,
  { artifact: latest.get('douyin-nowatermark')?.path, verdict: douyin?.verdict, aBogusObserved: dyABogus, msTokenObserved: dyMsToken, runtimeSignedFetch: dyRuntimeSigned, structuredApi2xx: dyStructured, signatureSignals: dySignals, bundleHints: dyBundles, strongMediaCandidates: dyStrong },
  'a_bogus/msToken observed + runtime signed fetch anchored + independently replayed structured 2xx aweme API',
  'RECON_BROWSER=1 RECON_API_PROBE=1 RECON_PROBE_LIMIT=16 node bench/recon-remote/douyin-nowatermark/run.mjs https://www.douyin.com/video/7636072173723945829'
));

const agentText = `${agent?.stdoutTail || ''}\n${(agent?.nextActions || []).join('\n')}`;
const agentFrontierMentions = [/a_bogus/i, /x-s|xhs|小红书/i, /wbi|bilibili|B站/i, /Next Step|下一步|frontier|2xx|rebuild|重建/i].filter((re) => re.test(agentText)).length;
gates.push(pass(
  'agent_frontier_gap_reasoning',
  agent?.verdict === 'agent-dogfood-confirmed' && agent?.checks?.modelCalled && agent?.checks?.toolUsed && agentFrontierMentions >= 3,
  (agent?.checks?.modelCalled ? 4 : 0) + (agent?.checks?.toolUsed ? 4 : 0) + Math.min(7, agentFrontierMentions * 2),
  15,
  { artifact: latest.get('agent-dogfood')?.path, verdict: agent?.verdict, checks: agent?.checks, modelCalls: agent?.session?.modelCalls, toolCalls: agent?.session?.toolCalls, frontierMentions: agentFrontierMentions },
  'Dogfood agent made model/tool calls and named frontier gaps/next commands across Bili/XHS/Douyin',
  'RECON_AGENT_MODEL=<model> node bench/recon-remote/agent-dogfood/run.mjs'
));

gates.push(pass(
  'cross_platform_live_binding',
  proofLiveBound(proofLive),
  proofLiveBound(proofLive) ? 10 : proofLatest?.verdict === 'proof-gate-passed' ? 6 : 0,
  10,
  { artifact: latest.get('proof-gate:live-rerun')?.path, latestOnlyArtifact: latest.get('proof-gate:latest-only')?.path, liveVerdict: proofLive?.verdict, liveMode: proofLive?.mode, latestOnlyVerdict: proofLatest?.verdict },
  'Latest live proof-gate passed and its rows are bound to artifacts from the same invocation',
  'RECON_GATE_AGENT=0 node bench/recon-remote/proof-gate/run.mjs'
));

const frontierScore = gates.reduce((sum, gate) => sum + Math.min(gate.weight, gate.score), 0);
const frontierMaxScore = gates.reduce((sum, gate) => sum + gate.weight, 0);
const passed = gates.every((gate) => gate.passed);
const grade = frontierScore >= 90 ? 'elite' : frontierScore >= 75 ? 'advanced' : frontierScore >= 55 ? 'solid' : frontierScore >= 35 ? 'basic' : 'weak';
const dimensions = {
  signature_rebuild: Math.min(20, Math.round((gates[0].score / gates[0].weight) * 8 + (gates[2].score / gates[2].weight) * 12)),
  signed_replay: Math.min(15, Math.round((gates[1].score / gates[1].weight) * 8 + (gates[2].score / gates[2].weight) * 7)),
  anti_bot_challenge: Math.min(15, Math.round((gates[1].score / gates[1].weight) * 7 + (gates[2].score / gates[2].weight) * 8)),
  cdn_media_probe: Math.min(10, (dyStrong ? 5 : 0) + (bili?.mediaProbeMatrix?.reachableMedia >= 4 ? 5 : 0)),
  runtime_capture_depth: Math.min(12, Math.round(((bili?.browser?.requests || 0) >= 30 ? 3 : 1) + ((xhs?.browser?.requests || 0) >= 250 ? 5 : 3) + ((douyin?.browser?.requests || 0) >= 80 ? 4 : 2))),
  exploit_chain: Math.min(10, Math.round((frontierScore / frontierMaxScore) * 10)),
  bundle_trace: Math.min(10, Math.round((biliBundleHints ? 2 : 0) + Math.min(4, xhsBundles * 2) + Math.min(4, Math.floor(dyBundles / 5)))),
  regression_readiness: passed ? 8 : proofLiveBound(proofLive) ? 5 : proofLatest?.verdict === 'proof-gate-passed' ? 4 : 0,
};
const result = {
  target: 'Bilibili WBI runtime trace + Xiaohongshu x-s 2xx replay + Douyin a_bogus structured API + Pi-RECON dogfood frontier',
  profile: 'frontier-gate',
  verdict: passed ? 'frontier-passed' : 'frontier-incomplete',
  generatedAt: new Date().toISOString(),
  artifactDir: rel(outDir),
  mode: live ? 'live-rerun' : 'latest-evidence',
  strict,
  elapsedMs: Date.now() - started,
  frontierScore,
  frontierMaxScore,
  frontierPercent: Number(((frontierScore / frontierMaxScore) * 100).toFixed(2)),
  grade,
  dimensions,
  gates,
  artifacts: {
    bilibili: latest.get('bilibili-video')?.path || '',
    xiaohongshu: latest.get('xiaohongshu-note')?.path || '',
    douyin: latest.get('douyin-nowatermark')?.path || '',
    agentDogfood: latest.get('agent-dogfood')?.path || '',
    proofGateLive: latest.get('proof-gate:live-rerun')?.path || '',
    proofGateLatest: latest.get('proof-gate:latest-only')?.path || '',
  },
  runs: runs.map((item) => ({
    label: item.label,
    code: item.run.code,
    signal: item.run.signal,
    elapsedMs: item.run.elapsedMs,
    artifactDir: item.run.json?.artifactDir || '',
    stdoutSha256: sha256(item.run.stdout || '').slice(0, 24),
    stderrSha256: sha256(item.run.stderr || '').slice(0, 24),
    stdoutTail: redact(item.run.stdout || '').slice(-2000),
    stderrTail: redact(item.run.stderr || '').slice(-1000),
  })),
  nextActions: gates.filter((gate) => !gate.passed).map((gate) => `${gate.name}: ${gate.nextCommand}`),
};
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
const md = [
  '# Pi-RECON Frontier Gate',
  '',
  `verdict: ${result.verdict}`,
  `mode: ${result.mode}`,
  `frontier_score: ${frontierScore}/${frontierMaxScore} (${result.frontierPercent}%)`,
  `grade: ${grade}`,
  `artifact_dir: ${rel(outDir)}`,
  '',
  '## Gates',
  '| Gate | Passed | Score | Required | Evidence |',
  '|---|---:|---:|---|---|',
  ...gates.map((gate) => `| ${gate.name} | ${gate.passed} | ${Math.min(gate.score, gate.weight)}/${gate.weight} | ${gate.required} | ${JSON.stringify(gate.evidence)} |`),
  '',
  '## Frontier Gaps',
  ...(result.nextActions.length ? result.nextActions.map((item) => `- ${item}`) : ['- none']),
  '',
].join('\n');
await writeFile(join(outDir, 'artifact.md'), md);
console.log(JSON.stringify({ verdict: result.verdict, artifactDir: result.artifactDir, mode: result.mode, frontierScore, frontierMaxScore, frontierPercent: result.frontierPercent, grade, gates: gates.map(({ name, passed, score, weight }) => ({ name, passed, score: Math.min(score, weight), weight })) }, null, 2));
process.exit(strict && !passed ? 1 : 0);

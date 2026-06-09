#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

const evidenceRoot = process.argv[2] || '.pi/evidence/remote';
const includeAll = process.argv.includes('--all');
const maxPossibleScore = 100;

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`Pi-RECON remote hard-score evaluator\n\nUsage:\n  node bench/recon-remote/hard-score.mjs [.pi/evidence/remote] [--all]\n\nScores latest remote benchmark artifacts across:\n  - signature_rebuild\n  - signed_replay\n  - anti_bot_challenge\n  - cdn_media_probe\n  - runtime_capture_depth\n  - exploit_chain\n  - bundle_trace\n  - regression_readiness\n\nOutput:\n  .pi/evidence/remote/hard-score/<timestamp>/scoreboard.json\n  .pi/evidence/remote/hard-score/<timestamp>/scoreboard.md\n`);
  process.exit(0);
}

function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function safeNum(value) { return Number.isFinite(Number(value)) ? Number(value) : 0; }
function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    let st;
    try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) walk(full, out);
    else if (name === 'result.json') out.push(full);
  }
  return out;
}
function safeJson(text) { try { return JSON.parse(text); } catch { return null; } }
function hostOf(target = '') { try { return new URL(target).hostname; } catch { return 'unknown'; } }
function clamp(n, max) { return Math.max(0, Math.min(max, n)); }
function grade(score) {
  if (score >= 90) return 'elite';
  if (score >= 75) return 'advanced';
  if (score >= 55) return 'solid';
  if (score >= 35) return 'basic';
  return 'weak';
}
function inferFamily(path, obj) {
  if (obj.profile) return obj.profile;
  if (obj.family) return obj.family;
  if (path.includes('/douyin-nowatermark/')) return 'douyin-nowatermark';
  if (path.includes('/agent-dogfood/')) return 'agent-dogfood';
  if (path.includes('/frontier-gate/')) return 'frontier-gate';
  if (path.includes('/proof-gate/')) return 'proof-gate';
  if (path.includes('/public-webapp/')) return obj.profile || 'public-webapp';
  return obj.profile || 'unknown';
}
function latestKey(path, obj) {
  const family = inferFamily(path, obj);
  return `${family} ${hostOf(obj.target || obj.finalUrl || '')} ${obj.target || obj.finalUrl || ''}`;
}
function evidenceTime(path) { return basename(dirname(path)); }
function countReachableMedia(obj) {
  if (Array.isArray(obj.probes)) {
    return obj.probes.filter((p) => p.probe?.classification?.media && p.probe?.classification?.reachable).length;
  }
  return 0;
}
function countStrongDouyin(obj) {
  if (!Array.isArray(obj.probes)) return 0;
  return obj.probes.filter((p) => p.classification?.noWatermarkLikely && p.classification?.reachable).length;
}
function findingIds(obj) { return (obj.findings || []).map((f) => typeof f === 'string' ? f : `${f.id || ''}`); }
function hasFinding(obj, re) {
  return (obj.findings || []).some((f) => re.test(typeof f === 'string' ? f : `${f.id || ''} ${f.evidence || ''}`));
}
function xhsTargetNoteEndpoint(endpointClass = '') {
  return /h5-note-info|web-feed|web-api-note|web-note-or-feed|web-search-notes/i.test(endpointClass);
}
function severityCount(obj, levels) {
  const wanted = new Set(levels);
  return (obj.findings || []).filter((f) => wanted.has(String(f.severity || '').toLowerCase())).length;
}
function probeStatusCount(obj, lo = 200, hi = 399) {
  return (obj.probes || []).filter((p) => safeNum(p.status) >= lo && safeNum(p.status) <= hi).length;
}
function scoreArtifact(path, obj) {
  const family = inferFamily(path, obj);
  const dimensions = {
    signature_rebuild: 0,
    signed_replay: 0,
    anti_bot_challenge: 0,
    cdn_media_probe: 0,
    runtime_capture_depth: 0,
    exploit_chain: 0,
    bundle_trace: 0,
    regression_readiness: 0,
  };
  const evidence = [];

  const browser = obj.browser || {};
  const requests = safeNum(browser.requests);
  const responses = safeNum(browser.responses);
  const bodies = safeNum(browser.bodies);
  if (requests >= 250 && responses >= 200) dimensions.runtime_capture_depth = 15;
  else if (requests >= 100 && responses >= 80) dimensions.runtime_capture_depth = 12;
  else if (requests >= 30 && responses >= 20) dimensions.runtime_capture_depth = 8;
  else if (requests || responses || bodies) dimensions.runtime_capture_depth = 4;
  if (dimensions.runtime_capture_depth) evidence.push(`runtime ${requests}/${responses}/${bodies}`);

  if (family === 'bilibili-video') {
    const signedOk = (obj.playurls || []).some((p) => p.signed && p.code === 0 && p.hasDash);
    const unsignedOk = (obj.playurls || []).some((p) => !p.signed && p.code === 0);
    const reachable = countReachableMedia(obj);
    const bundleHints = obj.signatureTrace?.bundleHints?.length || 0;
    const signerEvents = obj.signatureTrace?.signerLog?.length || 0;
    if (obj.nav?.hasWbiImg && signedOk) dimensions.signature_rebuild = 20;
    else if (obj.nav?.hasWbiImg) dimensions.signature_rebuild = 12;
    if (signedOk) dimensions.signed_replay = 15;
    else if (unsignedOk) dimensions.signed_replay = 9;
    dimensions.cdn_media_probe = clamp(reachable * 4, 15);
    dimensions.exploit_chain = signedOk && reachable ? 10 : unsignedOk ? 6 : 0;
    if (obj.nav?.code === -101) dimensions.anti_bot_challenge = 4;
    dimensions.bundle_trace = clamp(bundleHints * 2 + signerEvents, 10);
    if (obj.mediaProbeMatrix?.reachableMedia) dimensions.regression_readiness = 6;
    if (obj.wbiRegression?.selfTest?.ok) dimensions.regression_readiness = Math.max(dimensions.regression_readiness, 8);
    evidence.push(`bili wbi=${Boolean(signedOk)} reachable_media=${reachable} selftest=${Boolean(obj.wbiRegression?.selfTest?.ok)} bundles=${bundleHints} signer_events=${signerEvents}`);
  } else if (family === 'xiaohongshu-note') {
    const signedHeaders = obj.xhsReplay?.signedHeaderNames?.length || 0;
    const antiSignals = new Set(obj.antiBotSignals || []);
    const bundleHints = obj.signatureTrace?.bundleHints?.length || 0;
    const signedReqs = obj.signatureTrace?.signedRequestCount || 0;
    const signerEvents = obj.signatureTrace?.signerLog?.length || 0;
    const best2xx = obj.xhsReplay?.best2xxSignedReplay || obj.signatureTrace?.best2xxSignedReplay;
    const bestNote2xx = obj.xhsReplay?.bestTargetNote2xxSignedReplay || obj.signatureTrace?.bestTargetNote2xxSignedReplay || obj.xhsReplay?.bestNote2xxSignedReplay || obj.signatureTrace?.bestNote2xxSignedReplay;
    const targetNoteOk = Boolean(bestNote2xx?.structured?.noteStructured && xhsTargetNoteEndpoint(bestNote2xx.endpointClass));
    if (signedHeaders >= 4 || signedReqs >= 2 || signerEvents >= 10) dimensions.signature_rebuild = 16;
    else if (signedHeaders >= 3) dimensions.signature_rebuild = 14;
    else if (antiSignals.size >= 4) dimensions.signature_rebuild = 8;
    if (targetNoteOk) dimensions.signed_replay = 15;
    else if (best2xx?.structured?.anyStructured) dimensions.signed_replay = 13;
    else if (obj.xhsReplay?.attempted && safeNum(obj.xhsReplay.status) >= 200 && safeNum(obj.xhsReplay.status) < 300) dimensions.signed_replay = 12;
    else if (obj.xhsReplay?.attempted) dimensions.signed_replay = 11;
    if (safeNum(obj.xhsReplay?.status) === 461 || obj.xhsReplay?.headers?.verifytype) dimensions.anti_bot_challenge = 15;
    else if (antiSignals.size >= 5) dimensions.anti_bot_challenge = 11;
    else if (antiSignals.size) dimensions.anti_bot_challenge = 5;
    dimensions.bundle_trace = clamp(bundleHints * 3 + Math.ceil(signerEvents / 12), 10);
    dimensions.exploit_chain = obj.xhsReplay?.attempted ? 8 : 4;
    if (obj.signatureTrace?.replayDivergence) dimensions.regression_readiness = 6;
    if (signerEvents >= 10) dimensions.regression_readiness = Math.max(dimensions.regression_readiness, 8);
    evidence.push(`xhs signed_headers=${signedHeaders} signed_reqs=${signedReqs} replay=${obj.xhsReplay?.status || 'none'} best2xx=${best2xx?.endpointClass || 'none'} best_target_note_2xx=${targetNoteOk} bundles=${bundleHints} signer_events=${signerEvents}`);
    if (/xhs-note-signed-api-replay-confirmed/.test(obj.verdict || '') && !targetNoteOk) evidence.push('stale_verdict_note_confirmed_without_target_note=true');
  } else if (family === 'douyin-nowatermark') {
    const strong = countStrongDouyin(obj);
    const transform = (obj.transformHypotheses || []).some((h) => /playwm|watermark/i.test(`${h.source} ${h.hypothesis} ${h.reason}`));
    const signals = obj.signatureSurface?.signals?.length || obj.signatureSurface?.antiBotSignals?.length || 0;
    const bundleHints = obj.signatureSurface?.bundleHints?.length || 0;
    const observedApi = obj.runtimeApiReplay?.observedStructuredApi || obj.signatureSurface?.runtimeObservedStructuredApi;
    const replayedApi = obj.runtimeApiReplay?.bestReplayedStructuredApi || obj.signatureSurface?.runtimeReplayedStructuredApi;
    const observedApi2xx = Boolean(observedApi && safeNum(observedApi.status) >= 200 && safeNum(observedApi.status) < 300 && observedApi.structured?.structured);
    const replayedApi2xx = Boolean(replayedApi && safeNum(replayedApi.status) >= 200 && safeNum(replayedApi.status) < 300 && replayedApi.structured?.structured);
    if (replayedApi2xx) dimensions.signature_rebuild = 18;
    else if (observedApi2xx) dimensions.signature_rebuild = 14;
    else if (transform) dimensions.signature_rebuild = 9;
    if (signals >= 3) dimensions.anti_bot_challenge = 10;
    else if (signals) dimensions.anti_bot_challenge = 5;
    if (replayedApi2xx) dimensions.anti_bot_challenge = Math.max(dimensions.anti_bot_challenge, 12);
    if (strong) dimensions.cdn_media_probe = 15;
    dimensions.signed_replay = replayedApi2xx ? 15 : observedApi2xx ? 10 : strong ? 8 : 4;
    dimensions.exploit_chain = replayedApi2xx ? 14 : obj.verdict === 'strong-candidate' ? 10 : 4;
    dimensions.bundle_trace = clamp(bundleHints * 3, 10);
    if (replayedApi2xx) dimensions.regression_readiness = 10;
    else if (observedApi2xx || obj.runtimeApiReplay?.attempted) dimensions.regression_readiness = 6;
    else if (obj.apiProbeResults?.length || obj.signatureSurface?.endpointParamMatrix?.length) dimensions.regression_readiness = 5;
    if (obj.browser?.requests >= 80) dimensions.runtime_capture_depth = Math.max(dimensions.runtime_capture_depth, 12);
    evidence.push(`douyin strong=${strong} transform=${transform} sig_signals=${signals} bundles=${bundleHints} observed_api=${observedApi2xx ? observedApi?.structured?.awemeCount || 0 : 'none'} replay_api=${replayedApi2xx ? `${replayedApi.variant || 'unknown'}:${replayedApi?.structured?.awemeCount || 0}` : 'none'}`);
  } else if (family === 'juice-shop-hard') {
    const ids = findingIds(obj);
    if (hasFinding(obj, /juice_sqli_login_bypass_admin_jwt/)) dimensions.exploit_chain = 20;
    if (hasFinding(obj, /admin_users_api|admin_config_api|basket_items|authenticated_basket/)) dimensions.signed_replay = 15;
    dimensions.runtime_capture_depth = Math.max(dimensions.runtime_capture_depth, clamp(probeStatusCount(obj) * 2, 8));
    dimensions.signature_rebuild = hasFinding(obj, /juice_sqli_login_bypass_admin_jwt/) ? 6 : 0;
    dimensions.regression_readiness = hasFinding(obj, /admin_users_api|admin_config_api/) ? 8 : 4;
    evidence.push(`juice auth-bypass findings=${ids.filter(Boolean).join(',').slice(0, 120)}`);
  } else if (family === 'testfire') {
    const xss = hasFinding(obj, /reflected_xss_confirmed/);
    const sqli = hasFinding(obj, /sqli_login_bypass_confirmed/);
    if (sqli && xss) dimensions.exploit_chain = 18;
    else if (sqli || xss) dimensions.exploit_chain = 12;
    dimensions.signed_replay = sqli ? 10 : 0;
    dimensions.runtime_capture_depth = Math.max(dimensions.runtime_capture_depth, clamp(probeStatusCount(obj) * 2, 8));
    dimensions.regression_readiness = sqli || xss ? 6 : 0;
    evidence.push(`testfire xss=${xss} sqli=${sqli} high=${severityCount(obj, ['high', 'critical'])}`);
  } else if (family === 'agent-dogfood') {
    const checks = obj.checks || {};
    const modelCalls = safeNum(obj.session?.modelCalls);
    const toolCalls = safeNum(obj.session?.toolCalls);
    if (checks.reconProfile || /--recon/.test(obj.command || '')) dimensions.signature_rebuild = 10;
    if (checks.modelCalled || modelCalls) dimensions.signed_replay = 15;
    if (checks.platformsOk) dimensions.anti_bot_challenge = 5;
    if (checks.toolUsed || toolCalls) dimensions.runtime_capture_depth = 12;
    if (checks.sectionsOk && checks.platformsOk) dimensions.exploit_chain = 12;
    if (checks.hardScoreMentioned && obj.scoreRun?.artifactDir) dimensions.regression_readiness = 15;
    dimensions.bundle_trace = clamp(toolCalls * 2, 8);
    evidence.push(`agent model_calls=${modelCalls} tool_calls=${toolCalls} checks=${Object.entries(checks).filter(([, v]) => v).map(([k]) => k).join(',')}`);
  } else if (family === 'proof-gate') {
    const gates = obj.gates || [];
    const passed = gates.filter((item) => item.passed).length;
    const total = gates.length || 1;
    const allPassed = obj.verdict === 'proof-gate-passed' && passed === total;
    const liveBound = obj.mode === 'live-rerun' && ['bilibili', 'xhs', 'douyin'].every((name) => {
      const liveArtifact = String(obj.liveArtifacts?.[name] || '');
      const rowArtifact = String(obj.rows?.[name]?.artifact || '');
      return liveArtifact && rowArtifact && liveArtifact === rowArtifact;
    });
    dimensions.signature_rebuild = allPassed ? 16 : clamp(passed * 3, 12);
    dimensions.signed_replay = gates.some((item) => /bilibili|agent/.test(item.name) && item.passed) ? 13 : 0;
    dimensions.anti_bot_challenge = gates.some((item) => /xiaohongshu|douyin/.test(item.name) && item.passed) ? 13 : 0;
    dimensions.cdn_media_probe = gates.some((item) => /bilibili|douyin/.test(item.name) && item.passed) ? 13 : 0;
    dimensions.runtime_capture_depth = allPassed ? (liveBound ? 10 : 8) : clamp(passed * 2, 8);
    dimensions.exploit_chain = allPassed ? (liveBound ? 8 : 6) : clamp(passed * 2, 6);
    dimensions.bundle_trace = gates.some((item) => /xiaohongshu|douyin|bilibili/.test(item.name) && item.passed) ? 7 : 0;
    dimensions.regression_readiness = obj.scoreboardArtifact ? 5 : 0;
    evidence.push(`proof gates=${passed}/${total} mode=${obj.mode || 'unknown'} live_bound=${liveBound} agent=${Boolean(obj.runAgent)}`);
  } else if (family === 'frontier-gate') {
    Object.assign(dimensions, obj.dimensions || {});
    const gates = obj.gates || [];
    const passed = gates.filter((item) => item.passed).length;
    const total = gates.length || 1;
    const failed = gates.filter((item) => !item.passed).map((item) => item.name).join(',');
    evidence.push(`frontier score=${obj.frontierScore || 0}/${obj.frontierMaxScore || 100} gates=${passed}/${total} failed=${failed || 'none'}`);
  } else if ((obj.findings || []).length) {
    dimensions.exploit_chain = clamp((obj.findings || []).length * 2, 10);
  }

  const rawScore = Object.values(dimensions).reduce((a, b) => a + b, 0);
  const score = clamp(rawScore, maxPossibleScore);
  return {
    artifact: path,
    time: evidenceTime(path),
    family,
    target: obj.target || obj.finalUrl || '<unknown>',
    verdict: obj.verdict || '<none>',
    score,
    rawScore,
    maxPossibleScore,
    grade: grade(score),
    dimensions,
    evidence,
  };
}

const paths = walk(evidenceRoot)
  .filter((p) => !p.includes('/hard-score/'))
  .sort();
const rows = [];
for (const path of paths) {
  let obj = null;
  try {
    obj = safeJson(await readFile(path, 'utf8'));
  } catch {
    continue;
  }
  if (!obj) continue;
  rows.push(scoreArtifact(path, obj));
}
const latest = new Map();
for (const row of rows) {
  const key = latestKey(row.artifact, row);
  const prev = latest.get(key);
  if (!prev || row.time > prev.time) latest.set(key, row);
}
const selected = (includeAll ? rows : [...latest.values()]).sort((a, b) => b.score - a.score || b.rawScore - a.rawScore || a.family.localeCompare(b.family));
const summary = {
  generatedAt: new Date().toISOString(),
  sourceRoot: evidenceRoot,
  mode: includeAll ? 'all-artifacts' : 'latest-per-target',
  count: selected.length,
  maxPossibleScore,
  topScore: selected[0]?.score || 0,
  rows: selected,
};
const outDir = join('.pi', 'evidence', 'remote', 'hard-score', timestamp());
await mkdir(outDir, { recursive: true });
await writeFile(join(outDir, 'scoreboard.json'), `${JSON.stringify(summary, null, 2)}\n`);
const md = [
  '# Pi-RECON Remote Hard Scoreboard',
  '',
  `generated_at: ${summary.generatedAt}`,
  `mode: ${summary.mode}`,
  `source_root: ${evidenceRoot}`,
  `artifact_dir: ${outDir}`,
  `max_possible_score: ${maxPossibleScore}`,
  '',
  '| Score | Grade | Family | Verdict | Target | Key evidence |',
  '|---:|---|---|---|---|---|',
  ...selected.map((row) => `| ${row.score} | ${row.grade} | ${row.family} | ${row.verdict} | ${row.target} | ${row.evidence.join('; ')} |`),
  '',
  '## Dimensions',
  '',
  '- signature_rebuild: WBI/signature/header derivation or transform reconstruction.',
  '- signed_replay: signed/read-only/API replay or equivalent authenticated chain.',
  '- anti_bot_challenge: captured/reproduced anti-bot, verification, token or header boundary.',
  '- cdn_media_probe: HEAD/range proof against signed media CDN resources.',
  '- runtime_capture_depth: browser/CDP request/response/body capture depth.',
  '- exploit_chain: end-to-end impact chain depth for public benchmark fixtures or real-platform media/API proof.',
  '- bundle_trace: JS/runtime bundle evidence that anchors signer or anti-bot logic.',
  '- regression_readiness: self-tests, deterministic signer checks, replay divergence, or probe matrix suitable for future regression.',
  '',
].join('\n');
await writeFile(join(outDir, 'scoreboard.md'), md);
console.log(JSON.stringify({ artifactDir: outDir, count: selected.length, top: selected.slice(0, 5).map((row) => ({ family: row.family, score: row.score, grade: row.grade, verdict: row.verdict })) }, null, 2));

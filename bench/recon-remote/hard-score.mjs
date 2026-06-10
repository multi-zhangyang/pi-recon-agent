#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

const evidenceRoot = process.argv[2] || '.repi-harness/evidence/remote';
const includeAll = process.argv.includes('--all');
const maxPossibleScore = 100;
const PLATFORM_CLAIM_GATES = [
  { scope: 'bilibili.same_window_artifacts', gate: 'same_window_artifacts_exist', required: true, weight: 1 },
  { scope: 'bilibili.wbi_per_page_cid', gate: 'bilibili_wbi_per_page_cid', required: true, weight: 3 },
  { scope: 'bilibili.cdn_range_or_body_proof', gate: 'bilibili_cdn_range_or_body_proof', required: false, weight: 1 },
  { scope: 'xiaohongshu.xs_signed_trace', gate: 'xiaohongshu_xs_signed_trace', required: true, weight: 3 },
  { scope: 'xiaohongshu.target_note_2xx', gate: 'xiaohongshu_target_note_2xx', required: false, weight: 2 },
  { scope: 'douyin.abogus_structured_replay', gate: 'douyin_abogus_structured_replay', required: true, weight: 3 },
  { scope: 'douyin.cookie_boundary', gate: 'douyin_cookie_boundary', required: true, weight: 2 },
  { scope: 'douyin.nowatermark_byte_proof', gate: 'douyin_nowatermark_byte_proof', required: false, weight: 1 },
];
let latestSameWindowCache = undefined;


if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`REPI remote hard-score evaluator\n\nUsage:\n  node bench/recon-remote/hard-score.mjs [.repi-harness/evidence/remote] [--all]\n\nScores latest remote benchmark artifacts across:\n  - signature_rebuild\n  - signed_replay\n  - anti_bot_challenge\n  - cdn_media_probe\n  - runtime_capture_depth\n  - exploit_chain\n  - bundle_trace\n  - regression_readiness\n\nOutput:\n  .repi-harness/evidence/remote/hard-score/<timestamp>/scoreboard.json\n  .repi-harness/evidence/remote/hard-score/<timestamp>/scoreboard.md\n`);
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
function resolveMaybe(path = '') {
  if (!path) return '';
  if (existsSync(path)) return path;
  const fromCwd = join(process.cwd(), path);
  return existsSync(fromCwd) ? fromCwd : path;
}
function latestSameWindowResultPath() {
  if (latestSameWindowCache !== undefined) return latestSameWindowCache;
  latestSameWindowCache = walk(evidenceRoot)
    .filter((path) => path.includes('/same-window-live/') && path.endsWith('/result.json'))
    .sort()
    .at(-1) || '';
  return latestSameWindowCache;
}
function gateByName(obj, name) {
  return (obj?.gates || []).find((gate) => gate?.name === name) || null;
}
function weightedClaimScore(claims, predicate) {
  const selected = claims.filter(predicate);
  const max = selected.reduce((sum, claim) => sum + claim.weight, 0);
  const got = selected.filter((claim) => claim.passed).reduce((sum, claim) => sum + claim.weight, 0);
  return { score: max ? Math.round((got / max) * 100) : 0, passedWeight: got, maxWeight: max, passed: selected.filter((claim) => claim.passed).length, total: selected.length };
}
function sameWindowClaimSnapshot(pathOrObj = '') {
  let artifact = '';
  let obj = null;
  if (typeof pathOrObj === 'string') {
    artifact = pathOrObj || latestSameWindowResultPath();
    const resolved = resolveMaybe(artifact);
    if (artifact && existsSync(resolved)) obj = safeJson(readFileSync(resolved, 'utf8'));
  } else {
    obj = pathOrObj;
  }
  const claims = PLATFORM_CLAIM_GATES.map((spec) => {
    const gate = gateByName(obj, spec.gate);
    const passed = Boolean(gate?.passed);
    return { ...spec, passed, kind: passed ? 'proven' : spec.required ? 'gap' : 'frontier_gap', severity: gate?.severity || (spec.required ? 'required' : 'frontier') };
  });
  const required = weightedClaimScore(claims, (claim) => claim.required);
  const all = weightedClaimScore(claims, () => true);
  const gaps = claims.filter((claim) => !claim.passed).map((claim) => ({ scope: claim.scope, gate: claim.gate, required: claim.required, kind: claim.kind, severity: claim.severity }));
  return { artifact, verdict: obj?.verdict || null, requiredScore: required.score, allScore: all.score, required, all, gaps, requiredGaps: gaps.filter((gap) => gap.required), claims };
}
function claimSplitText(snapshot) {
  if (!snapshot) return 'platform_claim=none';
  return `platform_required=${snapshot.requiredScore} platform_all=${snapshot.allScore} required_gaps=${snapshot.requiredGaps.map((gap) => gap.gate).join(',') || 'none'}`;
}

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
  const scoreMeta = {};

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
  } else if (family === 'agent-parallel-dogfood') {
    const gates = obj.gates || {};
    const roles = obj.roles || [];
    const roleRuns = obj.roleRuns || [];
    const totals = obj.totals || {};
    const parallel = obj.parallel || {};
    const synthesizer = obj.synthesizerRun;
    const synthOk = Boolean(obj.gates?.synthesizerReconciled || synthesizer?.checks?.roleSpecific);
    const synthTools = safeNum(synthesizer?.session?.toolCalls);
    const retryCount = [...roleRuns, synthesizer].filter(Boolean).reduce((acc, role) => acc + safeNum(role.retryCount), 0);
    const roleCount = safeNum((roles.length || roleRuns.length) + (synthesizer ? 1 : 0));
    const modelCalls = safeNum(totals.modelCalls);
    const toolCalls = safeNum(totals.toolCalls);
    const toolResults = safeNum(totals.toolResults);
    const toolResultBytes = safeNum(totals.toolResultBytes);
    const toolNames = totals.toolNames || {};
    const evidencePaths = obj.evidencePaths || {};
    const sameWindowPath = evidencePaths.sameWindowLive || evidencePaths.bestSameWindowLive || evidencePaths.latestSameWindowLive;
    const platformClaimSnapshot = sameWindowClaimSnapshot(sameWindowPath);
    const embeddedHardEval = obj.hardEvalControl || {};
    scoreMeta.scoreType = 'orchestration';
    scoreMeta.platformClaimScore = embeddedHardEval.scores?.platformRequired?.score ?? platformClaimSnapshot.requiredScore;
    scoreMeta.platformAllClaimScore = embeddedHardEval.scores?.platformAll?.score ?? platformClaimSnapshot.allScore;
    scoreMeta.platformClaimGaps = embeddedHardEval.claims?.platform
      ? embeddedHardEval.claims.platform.filter((claim) => claim.kind !== 'proven').map((claim) => ({ scope: claim.scope, gate: claim.gate, required: claim.required, kind: claim.kind }))
      : platformClaimSnapshot.gaps;
    scoreMeta.boundSameWindowArtifact = sameWindowPath || platformClaimSnapshot.artifact || '';
    scoreMeta.scoreWarning = scoreMeta.platformClaimScore < 100 ? 'orchestration score is not platform claim success' : '';
    const platformPaths = [
      evidencePaths.bilibili || evidencePaths.bestBilibili || evidencePaths.latestBilibili,
      evidencePaths.xiaohongshu || evidencePaths.bestXiaohongshu || evidencePaths.latestXiaohongshu,
      evidencePaths.douyin || evidencePaths.bestDouyin || evidencePaths.latestDouyin,
    ].filter(Boolean).length;
    if (gates.allRolesCoverPlatforms && gates.sameWindowCovered && sameWindowPath && roleCount >= 3) dimensions.signature_rebuild = 20;
    else if (gates.allRolesCoverPlatforms && roleCount >= 3) dimensions.signature_rebuild = 18;
    else if (platformPaths >= 3) dimensions.signature_rebuild = 12;
    else if (platformPaths) dimensions.signature_rebuild = 6;
    if (gates.allRolesModelCalled && modelCalls >= roleCount) dimensions.signed_replay = 15;
    else if (modelCalls) dimensions.signed_replay = 8;
    if (gates.antiSelfDelusion && gates.roleSpecificPassed && synthOk) dimensions.anti_bot_challenge = 15;
    else if (roleRuns.some((role) => role.id === 'adversary')) dimensions.anti_bot_challenge = 7;
    if (platformPaths >= 3 && sameWindowPath && gates.allRolesCiteArtifacts) dimensions.cdn_media_probe = 15;
    else if (platformPaths >= 2) dimensions.cdn_media_probe = 9;
    if (gates.allRolesUsedTools && gates.commandToolPresent && gates.readToolPresent && gates.childPidsCaptured && gates.monotonicClockCaptured && gates.toolResultsCaptured && toolCalls >= roleCount * 2) dimensions.runtime_capture_depth = 15;
    else if (toolCalls) dimensions.runtime_capture_depth = 8;
    if (/^agent-parallel-dogfood-confirmed/.test(obj.verdict || '') && gates.strongParallelOverlap && synthOk) dimensions.exploit_chain = 15;
    else if (gates.parallelOverlap) dimensions.exploit_chain = 10;
    dimensions.bundle_trace = clamp(Object.keys(toolNames).length * 2 + roleRuns.filter((role) => role.session?.files?.length).length + roleRuns.filter((role) => role.session?.fileDigests?.length).length + (synthTools ? 2 : 0), 10);
    if (gates.hardScoreCovered && gates.sameWindowCovered && gates.allRolesCiteArtifacts && gates.roleSpecificPassed && gates.sessionDigestsCaptured && gates.nonMockRuntimeExpected && synthOk) dimensions.regression_readiness = 12;
    else if (obj.scoreRun?.artifactDir || evidencePaths.hardScore) dimensions.regression_readiness = 7;
    evidence.push(`parallel roles=${roleCount} synth=${synthOk} retries=${retryCount} model_calls=${modelCalls} tool_calls=${toolCalls} tool_results=${toolResults} tool_result_bytes=${toolResultBytes} overlap=${parallel.overlapPairs || 0}/${parallel.maxPairs || 0} speedup=${parallel.speedup || 0} same_window=${sameWindowPath || 'none'} process=${Boolean(gates.childPidsCaptured && gates.monotonicClockCaptured)} nonmock=${Boolean(gates.nonMockRuntimeExpected)} gates=${Object.entries(gates).filter(([, v]) => v).map(([k]) => k).join(',')}`);
    evidence.push(`score_split orchestration=true ${claimSplitText({ requiredScore: scoreMeta.platformClaimScore, allScore: scoreMeta.platformAllClaimScore, requiredGaps: (scoreMeta.platformClaimGaps || []).filter((gap) => gap.required) })}`);
  } else if (family === 'compound-frontier') {
    const gates = obj.gates || [];
    const gateMap = Object.fromEntries(gates.map((item) => [item.name, item]));
    const passed = (name) => Boolean(gateMap[name]?.passed);
    const passedCount = gates.filter((item) => item.passed).length;
    const failed = (obj.failedGates || []).map((item) => item.name || item);
    const same = obj.hardScore?.sameWindow || null;
    const agent = obj.hardScore?.agentParallel || null;
    if (passed('same_window_live_passed') && passed('agent_parallel_confirmed')) dimensions.signature_rebuild = 20;
    else if (passed('same_window_live_passed') || passed('agent_parallel_confirmed')) dimensions.signature_rebuild = 12;
    if (passed('same_window_live_passed') && passed('same_window_no_frontier_gaps')) dimensions.signed_replay = 15;
    else if (passed('same_window_live_passed')) dimensions.signed_replay = 10;
    if (passed('same_window_negative_boundaries') && passed('agent_process_nonmock_proof')) dimensions.anti_bot_challenge = 15;
    else if (passed('same_window_negative_boundaries')) dimensions.anti_bot_challenge = 10;
    if (passed('same_window_media_byte_proofs')) dimensions.cdn_media_probe = 15;
    if (passed('agent_model_tool_runtime') && passed('agent_process_nonmock_proof') && passed('context_compact_audit_passed')) dimensions.runtime_capture_depth = 15;
    else if (passed('agent_model_tool_runtime')) dimensions.runtime_capture_depth = 10;
    if (obj.verdict === 'compound-frontier-passed' && passed('agent_same_window_bound')) dimensions.exploit_chain = 15;
    else if (passed('same_window_live_passed') && passed('agent_parallel_confirmed')) dimensions.exploit_chain = 10;
    dimensions.bundle_trace = clamp((passed('agent_parallel_confirmed') ? 5 : 0) + (passed('context_compact_audit_passed') ? 3 : 0) + (passed('hard_score_recognizes_frontier') ? 2 : 0), 10);
    if (passed('hard_score_recognizes_frontier') && passed('compound_artifacts_fresh') && passed('agent_same_window_bound')) dimensions.regression_readiness = 10;
    else if (passed('hard_score_recognizes_frontier')) dimensions.regression_readiness = 6;
    evidence.push(`compound mode=${obj.mode || 'unknown'} gates=${passedCount}/${gates.length} failed=${failed.join(',') || 'none'} same_window=${obj.artifacts?.sameWindow || 'none'} agent=${obj.artifacts?.agentParallel || 'none'} hard_same=${same?.score || 'none'} hard_agent=${agent?.score || 'none'}`);
  } else if (family === 'same-window-live') {
    const gates = obj.gates || [];
    const gateMap = Object.fromEntries(gates.map((item) => [item.name, item]));
    const passed = (name) => Boolean(gateMap[name]?.passed);
    const frontierGaps = obj.frontierGaps || [];
    const spanMs = safeNum(obj.spanMs);
    if (passed('bilibili_wbi_per_page_cid')) dimensions.signature_rebuild += 8;
    if (passed('xiaohongshu_xs_signed_trace')) dimensions.signature_rebuild += 6;
    if (passed('douyin_abogus_structured_replay')) dimensions.signature_rebuild += 6;
    dimensions.signature_rebuild = clamp(dimensions.signature_rebuild, 20);
    if (passed('xiaohongshu_target_note_2xx')) dimensions.signed_replay += 7;
    if (passed('douyin_abogus_structured_replay')) dimensions.signed_replay += 6;
    if (passed('bilibili_wbi_per_page_cid')) dimensions.signed_replay += 2;
    dimensions.signed_replay = clamp(dimensions.signed_replay, 15);
    if (passed('xiaohongshu_xs_signed_trace')) dimensions.anti_bot_challenge += 5;
    if (passed('xiaohongshu_challenge_boundary')) dimensions.anti_bot_challenge += 4;
    if (passed('douyin_cookie_boundary')) dimensions.anti_bot_challenge += 4;
    if (passed('bilibili_wbi_per_page_cid')) dimensions.anti_bot_challenge += 2;
    dimensions.anti_bot_challenge = clamp(dimensions.anti_bot_challenge, 15);
    if (passed('bilibili_cdn_range_or_body_proof')) dimensions.cdn_media_probe += 8;
    else if (passed('bilibili_cdn_head_fallback')) dimensions.cdn_media_probe += 4;
    if (passed('douyin_nowatermark_byte_proof')) dimensions.cdn_media_probe += 7;
    dimensions.cdn_media_probe = clamp(dimensions.cdn_media_probe, 15);
    if (passed('same_window_artifacts_exist')) dimensions.runtime_capture_depth += 5;
    if (passed('same_window_span')) dimensions.runtime_capture_depth += 5;
    if (passed('same_window_fresh')) dimensions.runtime_capture_depth += 5;
    dimensions.runtime_capture_depth = clamp(dimensions.runtime_capture_depth, 15);
    if (obj.verdict === 'same-window-live-passed') dimensions.exploit_chain = 15;
    else if (['bilibili_wbi_per_page_cid', 'xiaohongshu_xs_signed_trace', 'douyin_abogus_structured_replay'].filter(passed).length >= 2) dimensions.exploit_chain = 9;
    else if (gates.some((item) => item.passed)) dimensions.exploit_chain = 4;
    dimensions.bundle_trace = clamp((passed('xiaohongshu_xs_signed_trace') ? 4 : 0) + (passed('douyin_abogus_structured_replay') ? 3 : 0) + (passed('bilibili_wbi_per_page_cid') ? 3 : 0), 10);
    dimensions.regression_readiness = obj.hardScoreArtifact ? 5 : 0;
    if (obj.mode === 'live-rerun') dimensions.regression_readiness += 3;
    if (Array.isArray(frontierGaps)) dimensions.regression_readiness += 2;
    dimensions.regression_readiness = clamp(dimensions.regression_readiness, 10);
    const platformClaimSnapshot = sameWindowClaimSnapshot(obj);
    scoreMeta.scoreType = 'platform-claims';
    scoreMeta.platformClaimScore = platformClaimSnapshot.requiredScore;
    scoreMeta.platformAllClaimScore = platformClaimSnapshot.allScore;
    scoreMeta.platformClaimGaps = platformClaimSnapshot.gaps;
    scoreMeta.scoreWarning = platformClaimSnapshot.requiredScore < 100 ? 'latest same-window required platform claims are incomplete' : '';
    evidence.push(`same-window mode=${obj.mode || 'unknown'} span_ms=${spanMs} passed=${gates.filter((item) => item.passed).length}/${gates.length} gaps=${frontierGaps.map((gap) => gap.name).join(',') || 'none'}`);
    evidence.push(`score_split ${claimSplitText(platformClaimSnapshot)}`);
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
  let score = clamp(rawScore, maxPossibleScore);
  if (family === 'same-window-live' && obj.verdict !== 'same-window-live-passed') {
    score = Math.min(score, 89);
  }
  if (family === 'compound-frontier' && obj.verdict !== 'compound-frontier-passed') {
    score = Math.min(score, 89);
  }
  if (scoreMeta.scoreType === 'orchestration') scoreMeta.orchestrationScore = score;
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
    ...scoreMeta,
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
const scoreSeparation = {
  topScore: selected[0]?.score || 0,
  topOrchestrationScore: selected.filter((row) => row.scoreType === 'orchestration').sort((a, b) => (b.orchestrationScore || 0) - (a.orchestrationScore || 0))[0]?.orchestrationScore || 0,
  topPlatformClaimScore: selected.filter((row) => Number.isFinite(row.platformClaimScore)).sort((a, b) => (b.platformClaimScore || 0) - (a.platformClaimScore || 0))[0]?.platformClaimScore || 0,
  orchestrationPlatformWarnings: selected
    .filter((row) => row.scoreType === 'orchestration' && Number(row.platformClaimScore) < 100)
    .map((row) => ({ artifact: row.artifact, family: row.family, orchestrationScore: row.orchestrationScore, platformClaimScore: row.platformClaimScore, gaps: row.platformClaimGaps || [] })),
};
const summary = {
  generatedAt: new Date().toISOString(),
  sourceRoot: evidenceRoot,
  mode: includeAll ? 'all-artifacts' : 'latest-per-target',
  count: selected.length,
  maxPossibleScore,
  topScore: selected[0]?.score || 0,
  scoreSeparation,
  rows: selected,
};
const outDir = join('.repi-harness', 'evidence', 'remote', 'hard-score', timestamp());
await mkdir(outDir, { recursive: true });
await writeFile(join(outDir, 'scoreboard.json'), `${JSON.stringify(summary, null, 2)}\n`);
const md = [
  '# REPI Remote Hard Scoreboard',
  '',
  `generated_at: ${summary.generatedAt}`,
  `mode: ${summary.mode}`,
  `source_root: ${evidenceRoot}`,
  `artifact_dir: ${outDir}`,
  `max_possible_score: ${maxPossibleScore}`,
  '',
  '| Score | Claim split | Grade | Family | Verdict | Target | Key evidence |',
  '|---:|---|---|---|---|---|---|',
  ...selected.map((row) => `| ${row.score} | ${row.scoreType === 'orchestration' ? `orch=${row.orchestrationScore ?? row.score}; platform=${row.platformClaimScore ?? 'n/a'}` : Number.isFinite(row.platformClaimScore) ? `platform=${row.platformClaimScore}; all=${row.platformAllClaimScore}` : 'n/a'} | ${row.grade} | ${row.family} | ${row.verdict} | ${row.target} | ${row.evidence.join('; ')} |`),
  '',
  '## Score separation',
  '',
  `- top_score: ${summary.scoreSeparation.topScore}`,
  `- top_orchestration_score: ${summary.scoreSeparation.topOrchestrationScore}`,
  `- top_platform_claim_score: ${summary.scoreSeparation.topPlatformClaimScore}`,
  ...(summary.scoreSeparation.orchestrationPlatformWarnings.length ? summary.scoreSeparation.orchestrationPlatformWarnings.map((row) => `- warning: ${row.family} orchestration=${row.orchestrationScore} platform_claim=${row.platformClaimScore} gaps=${row.gaps.map((gap) => gap.gate).join(',') || 'none'}`) : ['- warning: none']),
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
console.log(JSON.stringify({
  artifactDir: outDir,
  count: selected.length,
  scoreSeparation: summary.scoreSeparation,
  top: selected.slice(0, 5).map((row) => ({
    family: row.family,
    score: row.score,
    scoreType: row.scoreType || 'platform-or-target',
    orchestrationScore: row.orchestrationScore ?? null,
    platformClaimScore: row.platformClaimScore ?? null,
    grade: row.grade,
    verdict: row.verdict,
  })),
}, null, 2));

#!/usr/bin/env node
import { readFile, readdir } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const repoRoot = resolve(process.env.RECON_REPO_ROOT || '.');
const evidenceRoot = join(repoRoot, '.repi-harness', 'evidence', 'remote');
const matrixRunner = 'bench/recon-remote/frontier-matrix/run.mjs';
const argv = process.argv.slice(2);

const caseCatalog = [
  {
    id: 'xhs_auto_discovery',
    platform: 'xiaohongshu',
    polarity: 'positive',
    difficulty: 98,
    agentLane: 'signed replay + discovery',
    purpose: 'Seed page -> tokenized note discovery -> target note/feed signed 2xx replay.',
  },
  {
    id: 'xhs_discovery_hit_rate',
    platform: 'xiaohongshu',
    polarity: 'positive',
    difficulty: 96,
    agentLane: 'discovery quality + provenance',
    purpose: 'Derived hit-rate/provenance gate over tokenized XHS auto-discovery attempts.',
  },
  {
    id: 'douyin_structured_api',
    platform: 'douyin',
    polarity: 'positive',
    difficulty: 94,
    agentLane: 'runtime anti-bot replay',
    purpose: 'Observed structured aweme API plus independent a_bogus/msToken replay evidence.',
  },
  {
    id: 'douyin_cookie_boundary',
    platform: 'douyin',
    polarity: 'negative',
    difficulty: 92,
    agentLane: 'cookie boundary verifier',
    purpose: 'No-cookie replay may be HTTP 200 but must remain structurally empty/divergent while exact-cookie replay is structured.',
  },
  {
    id: 'bilibili_wbi_runtime',
    platform: 'bilibili',
    polarity: 'positive',
    difficulty: 88,
    agentLane: 'runtime signer trace',
    purpose: 'WBI self-test, signer/bundle trace, signed request count, media probe.',
  },
  {
    id: 'bilibili_media_cdn_boundary',
    platform: 'bilibili',
    polarity: 'positive',
    difficulty: 86,
    agentLane: 'signed media/CDN boundary',
    purpose: 'Derived WBI media boundary over reachable DASH media, backup media, HTTP status, and host-class diversity.',
  },
  {
    id: 'bilibili_multipage_wbi_container',
    platform: 'bilibili',
    polarity: 'positive',
    difficulty: 84,
    agentLane: 'multi-page WBI container',
    purpose: 'Default p=2 multi-page target with WBI signed DASH playurl, WBI media candidates, reachable media, and host diversity.',
  },
  {
    id: 'bilibili_per_page_cid_boundary',
    platform: 'bilibili',
    polarity: 'positive',
    difficulty: 90,
    agentLane: 'per-page CID boundary',
    purpose: 'Derived p=2 boundary requiring selected page/CID, pagelist row CID, result CID, WBI playurl, and media probes to bind to the same non-first page.',
  },
  {
    id: 'xhs_search_negative',
    platform: 'xiaohongshu',
    polarity: 'negative',
    difficulty: 82,
    agentLane: 'negative-control verifier',
    purpose: 'Search/notes permission/login boundary must not inflate into target note/feed success.',
  },
];
const catalogById = new Map(caseCatalog.map((item) => [item.id, item]));

function hasFlag(name) { return argv.includes(`--${name}`); }
function optionValue(name, fallback = '') {
  const prefix = `--${name}=`;
  const inline = argv.find((item) => item.startsWith(prefix));
  if (inline) return inline.slice(prefix.length);
  const idx = argv.indexOf(`--${name}`);
  if (idx >= 0 && argv[idx + 1] && !argv[idx + 1].startsWith('--')) return argv[idx + 1];
  return fallback;
}
function csv(value) { return String(value || '').split(',').map((item) => item.trim()).filter(Boolean); }
function uniq(items) { return [...new Set(items.filter(Boolean))]; }
function safeJson(text, fallback = null) { try { return JSON.parse(text); } catch { return fallback; } }
function positiveNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
function evidenceTime(path) { return basename(dirname(path)); }
function rel(path) { return String(path || '').replace(`${repoRoot}/`, ''); }
function redact(value) {
  return String(value || '')
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, 'sk-<redacted>')
    .replace(/(api[_-]?key|auth[_-]?token|authorization|bearer)(["'\s:=]+)([A-Za-z0-9_.\-/+=]{12,})/gi, '$1$2<redacted>')
    .replace(/(ANTHROPIC_AUTH_TOKEN|OPENAI_API_KEY|GEMINI_API_KEY|OPENROUTER_API_KEY|AI_GATEWAY_API_KEY)=\S+/g, '$1=<redacted>')
    .replace(/([?&](?:w_rid|wts|xsec_token|xsec_source|web_session|a1|b1|msToken|a_bogus|token|buvid|SESSDATA|bili_jct|sign|t)=)[^&\s"']+/gi, '$1<redacted>');
}

async function walkResults(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of await readdir(dir)) {
    const full = join(dir, name);
    let st;
    try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) await walkResults(full, out);
    else if (name === 'result.json') out.push(full);
  }
  return out;
}
async function readJson(path) {
  if (!path) return null;
  const full = path.startsWith('/') ? path : join(repoRoot, path);
  return safeJson(await readFile(full, 'utf8').catch(() => ''));
}
async function latestMatrixArtifact() {
  const paths = await walkResults(join(evidenceRoot, 'frontier-matrix'));
  return paths.sort((a, b) => evidenceTime(b).localeCompare(evidenceTime(a)))[0] || '';
}
async function latestMatrixResult() {
  const path = await latestMatrixArtifact();
  const obj = await readJson(path);
  return obj ? { path: rel(path), obj } : null;
}
function parseMatrixStdout(stdout) {
  const direct = safeJson(stdout);
  if (direct) return direct;
  const match = String(stdout || '').match(/\{[\s\S]*\}\s*$/);
  return match ? safeJson(match[0]) : null;
}
function run(cmd, args, { env = {}, timeoutMs = 900000 } = {}) {
  return new Promise((resolveRun) => {
    const started = Date.now();
    const child = spawn(cmd, args, { cwd: repoRoot, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch {}
      setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1500).unref?.();
    }, timeoutMs);
    child.stdout.on('data', (chunk) => { stdout += String(chunk); });
    child.stderr.on('data', (chunk) => { stderr += String(chunk); });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolveRun({ code, signal, elapsedMs: Date.now() - started, stdout, stderr });
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolveRun({ code: 'error', signal: null, elapsedMs: Date.now() - started, stdout, stderr, error: error.message });
    });
  });
}
function commandFor(caseIds, { live = false, strict = false, fresh = false } = {}) {
  const args = [matrixRunner];
  if (live) args.push('--live');
  if (strict) args.push('--strict');
  if (fresh) args.push('--fresh');
  return {
    env: { RECON_MATRIX_CASES: caseIds.join(',') },
    args,
    shell: `RECON_MATRIX_CASES=${caseIds.join(',')} node ${args.join(' ')}`,
  };
}
function shardCases(caseIds, shardCount) {
  const count = Math.max(1, Math.min(Number(shardCount) || 1, caseIds.length || 1));
  const shards = Array.from({ length: count }, () => []);
  for (let idx = 0; idx < caseIds.length; idx += 1) shards[idx % count].push(caseIds[idx]);
  return shards.filter((items) => items.length);
}
function ensureControls(order, maxCases) {
  const selected = uniq(order).filter((id) => catalogById.has(id));
  if (!Number.isFinite(maxCases) || maxCases <= 0 || maxCases >= selected.length) return selected;
  const limited = selected.slice(0, maxCases);
  if (maxCases >= 2 && !limited.some((id) => catalogById.get(id)?.polarity === 'negative')) {
    const negative = selected.find((id) => catalogById.get(id)?.polarity === 'negative');
    if (negative) limited[limited.length - 1] = negative;
  }
  return uniq(limited);
}
function selectBalanced(maxCases) {
  const order = ['xhs_auto_discovery', 'xhs_discovery_hit_rate', 'douyin_structured_api', 'douyin_cookie_boundary', 'bilibili_wbi_runtime', 'bilibili_per_page_cid_boundary', 'bilibili_media_cdn_boundary', 'bilibili_multipage_wbi_container', 'xhs_search_negative'];
  return ensureControls(order, maxCases);
}
function selectCases({ explicitCases, strategy, maxCases, latest }) {
  if (explicitCases.length) return ensureControls(explicitCases, maxCases);
  if (strategy === 'quick') return ensureControls(['xhs_auto_discovery', 'xhs_search_negative'], maxCases);
  if (strategy === 'balanced') return selectBalanced(maxCases);
  const hardest = [...caseCatalog].sort((a, b) => b.difficulty - a.difficulty).map((item) => item.id);
  if (strategy === 'failed-first') {
    const failed = (latest?.obj?.scenarios || []).filter((row) => catalogById.has(row.id) && !row.passed).map((row) => row.id);
    return ensureControls([...failed, ...hardest], maxCases);
  }
  return ensureControls(hardest, maxCases);
}
function decisiveEvidence(row) {
  const ev = row?.evidence || {};
  if (row?.id === 'bilibili_wbi_runtime') return `verdict=${ev.verdict || 'n/a'} selfTest=${ev.selfTest} signedReqs=${ev.signedReqs || 0} signerEvents=${ev.signerEvents || 0} bundleHints=${ev.bundleHints || 0} media=${ev.media || 0}`;
  if (row?.id === 'bilibili_media_cdn_boundary') return `verdict=${ev.verdict || 'n/a'} reachableMedia=${ev.reachableMedia || 0}/${ev.total || 0} hostClassCount=${ev.hostClassCount || 0} hasBackup=${ev.hasBackup} signedReqs=${ev.signedReqs || 0}`;
  if (row?.id === 'bilibili_multipage_wbi_container') return `verdict=${ev.verdict || 'n/a'} pages=${ev.pages || 0} targetPage=${ev.targetPage || 0} wbiCandidates=${ev.wbiCandidateCount || 0} reachableMedia=${ev.reachableMedia || 0} hostClassCount=${ev.hostClassCount || 0}`;
  if (row?.id === 'bilibili_per_page_cid_boundary') return `verdict=${ev.verdict || 'n/a'} requestedPage=${ev.requestedPage || 0} selectedPage=${ev.selectedPage || 0} selectedCid=${ev.selectedCid || 'n/a'} cidMatchesRow=${ev.cidMatchesRequestedRow} differsFirst=${ev.cidDiffersFromFirst}`;
  if (row?.id === 'xhs_auto_discovery') return `verdict=${ev.verdict || 'n/a'} endpoint=${ev.bestEndpoint || 'n/a'} method=${ev.bestMethod || 'n/a'} status=${ev.bestStatus || 'n/a'} noteItemCount=${ev.noteItemCount || 0} candidates=${ev.candidates || 0}`;
  if (row?.id === 'xhs_discovery_hit_rate') return `verdict=${ev.verdict || 'n/a'} hitRate=${ev.hitRate ?? 'n/a'} successful=${ev.successful || 0}/${ev.attempted || 0} tokenized=${ev.tokenizedCandidateCount || 0}/${ev.candidateCount || 0}`;
  if (row?.id === 'xhs_search_negative') {
    const rows = (ev.searchRows || []).map((item) => `${item.variant}:${item.challengeKind || item.jsonCode || item.status}`).join(',');
    return `verdict=${ev.verdict || 'n/a'} bestTargetNote2xx=${ev.bestTargetNote2xx} searchBoundary=[${rows || 'n/a'}]`;
  }
  if (row?.id === 'douyin_structured_api') return `verdict=${ev.verdict || 'n/a'} replay2xx=${ev.replayedStructuredApi2xx} status=${ev.status || 'n/a'} awemeCount=${ev.awemeCount || 0} signals=${ev.signals || 0} bundles=${ev.bundles || 0}`;
  if (row?.id === 'douyin_cookie_boundary') return `verdict=${ev.verdict || 'n/a'} observedStructured=${ev.observedStructured} exactAwemeCount=${ev.exactCookieAwemeCount || 0} noCookieStatus=${ev.noCookieStatus || 'n/a'} noCookieStructured=${ev.noCookieStructured} noCookieDiverged=${ev.noCookieDiverged}`;
  if (row?.id === 'frontier_strict') return `verdict=${ev.verdict || 'n/a'} frontierScore=${ev.frontierScore || 'n/a'} grade=${ev.grade || 'n/a'}`;
  return JSON.stringify(ev);
}
function summarizeMatrix(matrixPath, result, selectedCaseIds, runMeta = null) {
  const rows = (result?.scenarios || []).map((row) => {
    const meta = catalogById.get(row.id) || { platform: 'aggregate', polarity: 'aggregate', difficulty: 0, agentLane: 'aggregate gate', purpose: 'Aggregate frontier strict gate.' };
    return {
      id: row.id,
      platform: meta.platform,
      polarity: meta.polarity,
      difficulty: meta.difficulty,
      agentLane: meta.agentLane,
      passed: Boolean(row.passed),
      score: Math.min(Number(row.score || 0), Number(row.weight || 0)),
      weight: Number(row.weight || 0),
      artifact: row.artifact || '',
      command: row.command || '',
      decisive: decisiveEvidence(row),
    };
  });
  const failed = rows.filter((row) => !row.passed);
  return {
    mode: 'summary',
    verdict: result?.verdict || 'frontier-matrix-missing',
    grade: result?.grade || 'unknown',
    matrixScore: result?.matrixScore || 0,
    matrixMaxScore: result?.matrixMaxScore || 0,
    matrixPercent: result?.matrixPercent || 0,
    generatedAt: result?.generatedAt || '',
    freshness: result?.freshness || null,
    matrixArtifact: matrixPath || (result?.artifactDir ? `${result.artifactDir}/result.json` : ''),
    selectedCases: selectedCaseIds,
    positives: rows.filter((row) => row.polarity === 'positive'),
    negatives: rows.filter((row) => row.polarity === 'negative'),
    aggregate: rows.filter((row) => row.polarity === 'aggregate'),
    evidencePaths: rows.map((row) => row.artifact).filter(Boolean),
    compactContext: rows.map((row) => `${row.id}:${row.passed ? 'PASS' : 'FAIL'}:${row.artifact || 'missing'}:${row.decisive}`),
    run: runMeta,
    nextActions: failed.length
      ? failed.map((row) => `${row.id}: inspect ${row.artifact || 'missing artifact'}; rerun ${row.command || commandFor([row.id]).shell}`)
      : ['matrix clean: raise max-cases/live strict cadence, or shard by platform for parallel dogfood review'],
  };
}
function caseEvidenceContract(id) {
  const meta = catalogById.get(id) || {};
  const base = [`case=${id}`, `platform=${meta.platform || 'unknown'}`, `polarity=${meta.polarity || 'unknown'}`, `difficulty=${meta.difficulty || 0}`];
  if (meta.platform === 'xiaohongshu') return [...base, 'require x-s/x-t signed trace or explicit challenge boundary', 'target note/feed/search structured 2xx must not be inferred from generic user endpoint'];
  if (meta.platform === 'douyin') return [...base, 'require observed structured aweme API', 'require replay/cookie boundary split', 'no-watermark media byte proof must be hash/range backed'];
  if (meta.platform === 'bilibili') return [...base, 'require WBI self-test and signed playurl', 'CID/page boundary must bind selected p/cid', 'media proof must include reachable CDN body/range or HEAD fallback'];
  return base;
}
function caseMergeKeys(cases) {
  return cases.flatMap((id) => {
    const meta = catalogById.get(id) || {};
    return [`case:${id}`, `platform:${meta.platform || 'unknown'}`, `polarity:${meta.polarity || 'unknown'}`];
  });
}
function makeParallelPlan(selectedCases, options, latest, shards) {
  const workers = shards.map((shard) => ({
    id: shard.id,
    role: 'frontier-shard-runner',
    shardId: shard.id,
    caseIds: shard.cases,
    objective: `Run or review frontier matrix shard ${shard.id}: ${shard.cases.join(', ')}. Preserve positive/negative boundaries and emit only artifact-backed claims.`,
    commands: [shard.command],
    prompt: [
      'Use live/runtime evidence before old scoreboards.',
      'Do not convert generic 2xx or orchestration success into platform success.',
      'Return Outcome / Key Evidence / Verification / Next Step with artifact paths.',
    ],
    evidenceContract: shard.cases.flatMap(caseEvidenceContract),
    mergeKeys: caseMergeKeys(shard.cases),
    dependencies: [],
    artifactGlobs: ['.repi-harness/evidence/remote/frontier-matrix/**/result.json', '.repi-harness/evidence/remote/real-platform/**/result.json', '.repi-harness/evidence/remote/douyin-nowatermark/**/result.json'],
    limits: { timeoutMs: options.timeoutMs, maxCommands: 1 },
  }));
  return {
    kind: 'ReconParallelPlanV1',
    schemaVersion: 1,
    planId: `frontier-orchestrator/${new Date().toISOString()}`,
    target: 'Bilibili/Xiaohongshu/Douyin frontier matrix',
    source: 'frontier-orchestrator',
    strategy: options.strategy,
    latestMatrixArtifact: latest?.path || '',
    workers,
    merge: {
      strategy: 'frontier-summary',
      evidenceOrder: ['same_window_live', 'runtime_artifact', 'network', 'served_asset', 'process_config', 'persisted_state'],
      expectedArtifacts: ['.repi-harness/evidence/remote/frontier-matrix/**/result.json'],
      command: 'node bench/recon-remote/frontier-orchestrator/run.mjs --summarize-latest --json',
      conflictPolicy: 'latest runtime evidence and negative controls overrule stale green platform rows',
    },
  };
}
function makePlan(selectedCases, options, latest) {
  const shards = shardCases(selectedCases, options.shards).map((cases, idx) => ({
    id: `agent-${idx + 1}`,
    cases,
    lane: cases.map((id) => `${id}:${catalogById.get(id)?.agentLane || 'unknown'}`),
    command: commandFor(cases, options).shell,
    evidenceContract: cases.flatMap(caseEvidenceContract),
    mergeKeys: caseMergeKeys(cases),
    expectedArtifacts: ['.repi-harness/evidence/remote/frontier-matrix/**/result.json'],
  }));
  const parallelPlan = makeParallelPlan(selectedCases, options, latest, shards);
  return {
    mode: 'plan',
    strategy: options.strategy,
    selectedCases,
    strict: options.strict,
    live: options.live,
    fresh: options.fresh,
    matrixCommand: commandFor(selectedCases, options).shell,
    requestedShardCount: options.shards,
    shardStrategy: 'round-robin',
    shardCount: shards.length,
    shards,
    kind: parallelPlan.kind,
    schemaVersion: parallelPlan.schemaVersion,
    planId: parallelPlan.planId,
    source: parallelPlan.source,
    workers: parallelPlan.workers,
    merge: parallelPlan.merge,
    parallelPlan,
    latestMatrixArtifact: latest?.path || '',
    caseNotes: selectedCases.map((id) => ({ id, ...catalogById.get(id) })),
    contextPolicy: [
      'Each shard keeps only its matrix result path, decisive evidence line, and failed next action.',
      'Final merge reads frontier-matrix/result.json instead of replaying full stdout/stderr into context.',
      'Negative controls stay separate from positive replay cases to prevent generic 2xx inflation.',
      'Strict/fresh matrix runs reject stale latest-evidence artifacts instead of carrying old green results forward.',
      'parallelPlan is machine-readable ReconParallelPlanV1 for agent-dogfood --plan-json / --plan-only.',
    ],
  };
}
function printMarkdown(output) {
  if (output.mode === 'plan') {
    console.log([
      '# REPI Frontier Orchestrator Plan',
      '',
      '## Outcome',
      `- strategy=${output.strategy} live=${output.live} strict=${output.strict} fresh=${output.fresh}`,
      `- selected=${output.selectedCases.join(',')}`,
      '',
      '## Key Evidence',
      `- latest_matrix=${output.latestMatrixArtifact || 'none'}`,
      `- matrix_command=\`${output.matrixCommand}\``,
      '',
      '## Verification',
      ...output.shards.map((shard) => `- ${shard.id}: ${shard.cases.join(',')} -> \`${shard.command}\``),
      '',
      '## Parallel Plan',
      `- plan_id=${output.parallelPlan?.planId || 'none'}`,
      `- workers=${output.parallelPlan?.workers?.length || 0} merge=${output.parallelPlan?.merge?.strategy || 'none'}`,
      '- JSON mode exposes this as `parallelPlan` for `agent-dogfood/parallel-run.mjs --plan-json`.',
      '',
      '## Next Step',
      '- Run the matrix command, or dispatch shard commands to parallel agents and merge with `--summarize-latest`.',
      '',
    ].join('\n'));
    return;
  }
  console.log([
    '# REPI Frontier Orchestrator Summary',
    '',
    '## Outcome',
    `- verdict=${output.verdict} score=${output.matrixScore}/${output.matrixMaxScore} percent=${output.matrixPercent}% grade=${output.grade}`,
    `- freshness=${output.freshness ? `enabled=${output.freshness.enabled} passed=${output.freshness.passed} max_age_hours=${output.freshness.maxArtifactAgeHours}` : 'n/a'}`,
    `- matrix_artifact=${output.matrixArtifact || 'missing'}`,
    '',
    '## Key Evidence',
    '- Positive samples:',
    ...(output.positives.length ? output.positives.map((row) => `  - ${row.id}: passed=${row.passed} score=${row.score}/${row.weight} artifact=${row.artifact || 'missing'} evidence=${row.decisive}`) : ['  - none']),
    '- Negative samples:',
    ...(output.negatives.length ? output.negatives.map((row) => `  - ${row.id}: passed=${row.passed} score=${row.score}/${row.weight} artifact=${row.artifact || 'missing'} evidence=${row.decisive}`) : ['  - none']),
    '- Aggregate:',
    ...(output.aggregate.length ? output.aggregate.map((row) => `  - ${row.id}: passed=${row.passed} score=${row.score}/${row.weight} evidence=${row.decisive}`) : ['  - none']),
    '',
    '## Verification',
    ...output.evidencePaths.map((path) => `- ${path}`),
    '',
    '## Next Step',
    ...output.nextActions.map((item) => `- ${item}`),
    '',
  ].join('\n'));
}
function usage() {
  console.log(`REPI frontier orchestrator\n\nUsage:\n  node bench/recon-remote/frontier-orchestrator/run.mjs --plan\n  node bench/recon-remote/frontier-orchestrator/run.mjs --live --strict\n  node bench/recon-remote/frontier-orchestrator/run.mjs --summarize-latest --json\n\nModes:\n  default            Select cases, run frontier-matrix, summarize positive/negative evidence.\n  --plan             Print selected cases and per-agent shard commands only; no evidence writes.\n  --summarize-latest Read latest frontier-matrix result and compact it; no matrix run.\n\nSelection:\n  --strategy=hardest|failed-first|balanced|quick   default: hardest\n  --cases=<a,b>                                  explicit matrix case ids\n  --max-cases=N                                  default: all known cases\n  --shards=N                                     emit parallel-agent shard commands\n\nExecution:\n  --live              Pass --live to frontier-matrix.\n  --strict            Pass --strict and exit non-zero when the matrix fails.\n  --timeout-ms=N      default: RECON_ORCH_TIMEOUT_MS or 900000\n  --json              Emit JSON instead of markdown.\n\nKnown cases:\n${caseCatalog.map((item) => `  - ${item.id} (${item.polarity}, ${item.platform}, difficulty=${item.difficulty})`).join('\n')}\n`);
}

if (hasFlag('help') || hasFlag('h')) {
  usage();
  process.exit(0);
}

const explicitCases = csv(optionValue('cases', process.env.RECON_ORCH_CASES || ''));
const unknown = explicitCases.filter((id) => !catalogById.has(id));
if (unknown.length) {
  console.error(`Unknown frontier matrix case(s): ${unknown.join(', ')}`);
  process.exit(2);
}
const options = {
  live: hasFlag('live') || process.env.RECON_ORCH_LIVE === '1',
  strict: hasFlag('strict') || process.env.RECON_ORCH_STRICT === '1',
  fresh: hasFlag('fresh') || process.env.RECON_ORCH_FRESH === '1',
  plan: hasFlag('plan') || hasFlag('dry-run'),
  summarizeLatest: hasFlag('summarize-latest') || hasFlag('latest'),
  json: hasFlag('json') || optionValue('format', process.env.RECON_ORCH_FORMAT || '') === 'json',
  strategy: optionValue('strategy', process.env.RECON_ORCH_STRATEGY || 'hardest'),
  maxCases: positiveNumber(optionValue('max-cases', process.env.RECON_ORCH_MAX_CASES || String(caseCatalog.length)), caseCatalog.length),
  shards: positiveNumber(optionValue('shards', process.env.RECON_ORCH_SHARDS || '1'), 1),
  timeoutMs: positiveNumber(optionValue('timeout-ms', process.env.RECON_ORCH_TIMEOUT_MS || '900000'), 900000),
};
if (!['hardest', 'failed-first', 'balanced', 'quick'].includes(options.strategy)) {
  console.error(`Unknown strategy: ${options.strategy}`);
  process.exit(2);
}

const latest = await latestMatrixResult();
const selectedCases = selectCases({ explicitCases, strategy: options.strategy, maxCases: options.maxCases, latest });
if (!selectedCases.length) {
  console.error('No matrix cases selected.');
  process.exit(2);
}

if (options.plan) {
  const plan = makePlan(selectedCases, options, latest);
  if (options.json) console.log(JSON.stringify(plan, null, 2));
  else printMarkdown(plan);
  process.exit(0);
}

let matrixPath = latest?.path || '';
let matrixObj = latest?.obj || null;
let runMeta = null;
if (!options.summarizeLatest) {
  const cmd = commandFor(selectedCases, options);
  const runResult = await run('node', cmd.args, { env: cmd.env, timeoutMs: options.timeoutMs });
  const stdoutJson = parseMatrixStdout(runResult.stdout);
  matrixPath = stdoutJson?.artifactDir ? `${stdoutJson.artifactDir}/result.json` : '';
  matrixObj = await readJson(matrixPath);
  if (!matrixObj) {
    const fallback = await latestMatrixResult();
    matrixPath = fallback?.path || matrixPath;
    matrixObj = fallback?.obj || matrixObj;
  }
  runMeta = {
    command: cmd.shell,
    code: runResult.code,
    signal: runResult.signal,
    elapsedMs: runResult.elapsedMs,
    stdoutTail: redact(runResult.stdout).slice(-1200),
    stderrTail: redact(runResult.stderr).slice(-1200),
  };
  if (!matrixObj) {
    console.error(JSON.stringify({ verdict: 'frontier-orchestrator-failed', reason: 'matrix result missing', run: runMeta }, null, 2));
    process.exit(1);
  }
}

if (!matrixObj) {
  console.error('No frontier-matrix result found. Run with --live or run frontier-matrix first.');
  process.exit(1);
}
const summary = summarizeMatrix(matrixPath, matrixObj, selectedCases, runMeta);
if (options.json) console.log(JSON.stringify(summary, null, 2));
else printMarkdown(summary);
const failed = summary.verdict !== 'frontier-matrix-passed' || [...summary.positives, ...summary.negatives, ...summary.aggregate].some((row) => !row.passed);
process.exit(options.strict && failed ? 1 : 0);

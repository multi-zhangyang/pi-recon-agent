#!/usr/bin/env node
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { failureRepairFromGap } from '../../../scripts/reverse-agent/failure-repair-ledger.mjs';

const repoRoot = resolve(process.env.RECON_REPO_ROOT || '.');
const argv = process.argv.slice(2);
function hasArgFlag(name) { return argv.includes(`--${name}`); }
function optionArg(name, fallback = '') {
  const prefix = `--${name}=`;
  const inline = argv.find((item) => item.startsWith(prefix));
  if (inline) return inline.slice(prefix.length);
  const idx = argv.indexOf(`--${name}`);
  if (idx >= 0 && argv[idx + 1] && !argv[idx + 1].startsWith('--')) return argv[idx + 1];
  return fallback;
}
function positionalArgs() {
  const out = [];
  const optionsWithValues = new Set(['plan-json']);
  for (let idx = 0; idx < argv.length; idx += 1) {
    const item = argv[idx];
    if (item.startsWith('--')) {
      const optionName = item.slice(2);
      if (optionsWithValues.has(optionName) && !item.includes('=') && argv[idx + 1] && !argv[idx + 1].startsWith('--')) idx += 1;
      continue;
    }
    out.push(item);
  }
  return out;
}
function parseJsonOrNull(text) { try { return JSON.parse(text); } catch { return null; } }
const planOnly = hasArgFlag('plan-only') || /^(1|true|yes|on)$/i.test(process.env.RECON_PARALLEL_PLAN_ONLY || '');
const planJsonPath = optionArg('plan-json', process.env.RECON_PARALLEL_PLAN_JSON || '');
const positionals = positionalArgs();
const provider = process.env.RECON_AGENT_PROVIDER || positionals[0] || 'aigateway';
const model = process.env.RECON_AGENT_MODEL || positionals[1] || process.env.ANTHROPIC_MODEL || '';
const thinking = process.env.RECON_AGENT_THINKING || 'low';
const tools = process.env.RECON_AGENT_TOOLS || 'read,grep,find,ls,bash';
const timeoutMs = Number(process.env.RECON_AGENT_TIMEOUT_MS || process.env.RECON_PARALLEL_TIMEOUT_MS || 300000);
const agentCmd = process.env.RECON_AGENT_CMD || './pi-test.sh';
const extraArgs = (process.env.RECON_AGENT_EXTRA_ARGS || '').split(/\s+/).filter(Boolean);
const roleFilter = (process.env.RECON_PARALLEL_ROLES || '').split(',').map((x) => x.trim()).filter(Boolean);
const maxToolCallsHint = Number(process.env.RECON_PARALLEL_MAX_TOOL_CALLS || 4);
const maxWordsHint = Number(process.env.RECON_PARALLEL_MAX_WORDS || 500);
const runSynthesizer = !/^(0|false|no)$/i.test(process.env.RECON_SYNTHESIZER || '1');
const roleRetries = Number(process.env.RECON_ROLE_RETRIES || 1);
const authEnvKeys = [
  'ANTHROPIC_AUTH_TOKEN',
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_OAUTH_TOKEN',
  'OPENAI_API_KEY',
  'AI_GATEWAY_API_KEY',
  'OPENROUTER_API_KEY',
  'GEMINI_API_KEY',
  'GROQ_API_KEY',
  'OPENCODE_API_KEY',
];
const endpointEnvKeys = ['ANTHROPIC_BASE_URL', 'OPENAI_BASE_URL', 'AI_GATEWAY_BASE_URL', 'OPENROUTER_BASE_URL'];
const rawParallelPlan = planJsonPath
  ? parseJsonOrNull(readFileSync(planJsonPath.startsWith('/') ? planJsonPath : join(repoRoot, planJsonPath), 'utf8'))
  : null;
const loadedParallelPlan = rawParallelPlan?.parallelPlan || rawParallelPlan;
if (planJsonPath && !loadedParallelPlan) {
  console.error(`Failed to read --plan-json ${planJsonPath}`);
  process.exit(2);
}

const PLAN_REQUIRED = ['planId', 'source', 'workers', 'merge'];
const PLAN_WORKER_REQUIRED = ['id', 'role', 'objective', 'commands', 'evidenceContract', 'mergeKeys', 'dependencies', 'artifactGlobs', 'limits'];
const PLAN_MERGE_REQUIRED = ['strategy', 'evidenceOrder', 'expectedArtifacts'];
function missingFields(obj, fields) {
  return fields.filter((field) => obj?.[field] === undefined || obj?.[field] === null);
}
function validateParallelPlan(plan) {
  if (!plan) return { valid: true, mode: 'builtin-agent-dogfood' };
  const missing = missingFields(plan, PLAN_REQUIRED);
  const workerRows = Array.isArray(plan.workers)
    ? plan.workers.map((worker) => ({ id: worker.id || '', missing: missingFields(worker, PLAN_WORKER_REQUIRED) }))
    : [];
  const mergeMissing = missingFields(plan.merge || {}, PLAN_MERGE_REQUIRED);
  const duplicateWorkerIds = Array.isArray(plan.workers)
    ? plan.workers.map((worker) => worker.id).filter((id, index, ids) => id && ids.indexOf(id) !== index)
    : [];
  const valid = missing.length === 0
    && Array.isArray(plan.workers)
    && plan.workers.length > 0
    && workerRows.every((row) => row.id && row.missing.length === 0)
    && mergeMissing.length === 0
    && duplicateWorkerIds.length === 0;
  return {
    valid,
    missing,
    workerRows,
    mergeMissing,
    duplicateWorkerIds: [...new Set(duplicateWorkerIds)],
    workerCount: plan?.workers?.length || 0,
  };
}
const parallelPlanValidation = validateParallelPlan(loadedParallelPlan);
if (planJsonPath && !parallelPlanValidation.valid) {
  const { failure, repair } = failureRepairFromGap({
    root: repoRoot,
    source: 'agent-dogfood-plan-only',
    scope: `agent-dogfood-plan-only:${planJsonPath}`,
    category: 'contract_gap',
    status: 'blocked',
    failedGates: ['recon_parallel_plan_valid'],
    reason: 'invalid ReconParallelPlanV1 supplied to --plan-json',
    attempt: 1,
    maxAttempts: 1,
    commands: [`node bench/recon-remote/agent-dogfood/parallel-run.mjs --plan-json ${planJsonPath} --plan-only --json`],
    artifacts: [planJsonPath],
    paused: true,
    unblock: 'fix the ReconParallelPlanV1 required fields and rerun plan-only',
    verificationCommand: 'npm run audit:parallel-plan',
  });
  console.error(JSON.stringify({
    error: 'invalid ReconParallelPlanV1',
    planJson: planJsonPath,
    validation: parallelPlanValidation,
    failureLedgerEvents: [failure],
    repairQueue: [repair],
    failureRepairWriteback: failure.evidenceWriteback,
  }, null, 2));
  process.exit(2);
}


if (argv.includes('--help') || argv.includes('-h') || (!model && !planOnly)) {
  console.log(`Pi-RECON parallel agent dogfood benchmark\n\nUsage:\n  RECON_AGENT_PROVIDER=openai RECON_AGENT_MODEL=gpt-4.1 node bench/recon-remote/agent-dogfood/parallel-run.mjs\n  node bench/recon-remote/agent-dogfood/parallel-run.mjs <provider> <model>\n  node bench/recon-remote/agent-dogfood/parallel-run.mjs --plan-json plan.json --plan-only --json\n\nPurpose:\n  Launches multiple real Pi-RECON --recon agents in parallel against the latest real-platform evidence,\n  then runs a synthesizer agent that reconciles worker disagreements. The harness gates real model calls,\n  tool calls, parallel overlap, platform coverage, artifact paths, and anti-self-delusion review.\n\nEnvironment:\n  RECON_AGENT_PROVIDER=<provider>       default: aigateway\n  RECON_AGENT_MODEL=<model>             required unless argv[3] or ANTHROPIC_MODEL is set\n  RECON_AGENT_THINKING=low\n  RECON_AGENT_TOOLS=read,grep,find,ls,bash\n  RECON_AGENT_TIMEOUT_MS=300000\n  RECON_AGENT_CMD=./pi-test.sh\n  RECON_AGENT_EXTRA_ARGS='--offline'    optional extra Pi CLI args\n  RECON_PARALLEL_ROLES=a,b              optional subset: mapper,verifier,adversary,planner\n  RECON_PARALLEL_MAX_TOOL_CALLS=4        prompt-level cap to prevent runaway workers\n  RECON_PARALLEL_MAX_WORDS=500           prompt-level output cap per worker\n  RECON_SYNTHESIZER=1                    run the sequential conflict-synthesizer; set 0 to skip\n  RECON_ROLE_RETRIES=1                   retry failed/flaky role runs before judging the gate\n  RECON_PARALLEL_PLAN_JSON=<path>        optional ReconParallelPlanV1 manifest.\n  RECON_PARALLEL_PLAN_ONLY=1             print normalized plan without launching providers.\n\nOutput:\n  .pi/evidence/remote/agent-parallel-dogfood/<timestamp>/\n`);
  process.exit(model || planOnly ? 0 : 2);
}

function roleFromPlanWorker(worker) {
  const title = worker.title || `${worker.role || 'worker'} ${worker.id}`;
  const commands = (worker.commands || []).map((command) => `- ${command}`).join('\n') || '- inspect artifacts only';
  const evidence = (worker.evidenceContract || []).map((item) => `- ${item}`).join('\n') || '- cite concrete artifact-backed evidence';
  const planPrompt = Array.isArray(worker.prompt) ? worker.prompt.join('\n') : (worker.prompt || '');
  const merge = (worker.mergeKeys || []).join(', ') || 'none';
  const artifacts = (worker.artifactGlobs || []).join(', ') || 'none';
  return {
    id: worker.id,
    title,
    planWorker: worker,
    prompt: `${planPrompt ? `${planPrompt}\n\n` : ''}Role: ${title}. Execute or review a ReconParallelPlanV1 worker packet.\n\nObjective:\n${worker.objective || 'No objective supplied.'}\n\nCommands allowed by the plan:\n${commands}\n\nEvidence contract:\n${evidence}\n\nMerge keys: ${merge}\nExpected artifact globs: ${artifacts}\nLimits: ${JSON.stringify(worker.limits || {})}\n\nRequired actions:\n1. Use tools to inspect the supplied artifacts and commands before making claims.\n2. Keep orchestration success separate from target/platform claim success.\n3. If a command would require live testing and this run is only plan review, mark it as paused instead of claiming completion.\n4. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n5. Do not edit files.`,
  };
}

const builtinRoles = [
  {
    id: 'mapper',
    title: 'Evidence Mapper',
    prompt: `Role: evidence mapper. Build a precise map of the latest real-platform Pi-RECON evidence.\n\nRequired actions:\n1. Use ls/read/grep/find tools to inspect the supplied artifact paths, latest hard-score artifact, and same-window-live artifact first.\n2. Identify the decisive fields for Bilibili WBI/per-page CID, Xiaohongshu x-s/signed replay, Douyin a_bogus/structured replay, and same-window freshness/gaps.\n3. Separate live same-window runtime evidence from stale, inferred, or weak evidence.\n4. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n5. Do not edit files.`,
  },
  {
    id: 'verifier',
    title: 'Command Verifier',
    prompt: `Role: command verifier. Prove or disprove the claims by executing local verification commands.\n\nRequired actions:\n1. Execute: node bench/recon-remote/hard-score.mjs\n2. Use read/grep/ls/bash to verify concrete result.json fields for same-window-live, Bilibili, Xiaohongshu, and Douyin.\n3. Report exact commands, exit status when visible, artifact paths, and the decisive field/value pairs.\n4. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n5. Do not edit files.`,
  },
  {
    id: 'adversary',
    title: 'Anti-Self-Delusion Auditor',
    prompt: `Role: adversarial auditor. Your job is to attack the benchmark's confidence and find self-delusion.\n\nRequired actions:\n1. Use read/grep/ls/find tools to inspect latest scoreboard, same-window-live result, and platform artifacts.\n2. For Bilibili, Xiaohongshu, and Douyin, say what is strongly proven, what is only inferred, and what is missing.\n3. Explicitly flag stale verdicts, weak evidence, indirect proof, contradictions, null/empty proof, or any gap that would make a top-tier agent claim invalid. If a stale artifact conflicts with the same-window result, call it stale and do not overrule live same-window evidence.\n4. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n5. Do not edit files.`,
  },
  {
    id: 'planner',
    title: 'Hard Frontier Planner',
    prompt: `Role: hard frontier planner. Design the next hardest benchmark step for a top-tier reverse/pentest agent.\n\nRequired actions:\n1. Use read/grep/ls tools to inspect current score/evidence before proposing work, including same-window-live.\n2. Propose a concrete multi-agent benchmark plan that raises difficulty without self-delusion.\n3. Include commands, pass/fail gates, artifact invariants, context/compact requirements, and rollback criteria.\n4. Cover same-window freshness, Bilibili WBI/per-page CID, Xiaohongshu x-s, Douyin a_bogus/no-watermark transform, and Pi-RECON agent orchestration.\n5. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n6. Do not edit files.`,
  },
];
const allRoles = loadedParallelPlan?.workers?.length ? loadedParallelPlan.workers.map(roleFromPlanWorker) : builtinRoles;
const roles = roleFilter.length ? allRoles.filter((role) => roleFilter.includes(role.id)) : allRoles;
if (!roles.length) throw new Error(`No roles selected from RECON_PARALLEL_ROLES=${process.env.RECON_PARALLEL_ROLES || ''}`);
const expectedWorkerRoleIds = roles.map((role) => role.id);
function defaultMergeContract() {
  return { strategy: 'synthesizer', evidenceOrder: ['same_window_live', 'runtime_artifact'], expectedArtifacts: ['.pi/evidence/remote/**/result.json'] };
}
function normalizedPlanSummary() {
  return {
    kind: 'pi-recon-parallel-plan-preview',
    mode: planOnly ? 'plan-only' : 'run',
    planOnly,
    willLaunchProvider: !planOnly,
    provider,
    providerDefaulted: !process.env.RECON_AGENT_PROVIDER && !positionals[0],
    modelConfigured: Boolean(model),
    planJson: planJsonPath || '',
    source: loadedParallelPlan?.source || 'builtin-agent-dogfood',
    planId: loadedParallelPlan?.planId || '',
    target: loadedParallelPlan?.target || 'Pi-RECON parallel dogfood',
    validation: parallelPlanValidation,
    workerCount: roles.length,
    workers: roles.map((role) => ({
      id: role.id,
      title: role.title,
      role: role.planWorker?.role || role.id,
      objective: role.planWorker?.objective || role.prompt.split('\n')[0],
      commands: role.planWorker?.commands || [],
      evidenceContract: role.planWorker?.evidenceContract || [],
      mergeKeys: role.planWorker?.mergeKeys || [],
      dependencies: role.planWorker?.dependencies || [],
      artifactGlobs: role.planWorker?.artifactGlobs || [],
      limits: role.planWorker?.limits || {},
    })),
    merge: loadedParallelPlan?.merge || defaultMergeContract(),
  };
}
function workerContract() {
  return {
    contractVersion: 1,
    runId: loadedParallelPlan?.planId || `agent-dogfood/${new Date().toISOString()}`,
    source: loadedParallelPlan?.source || 'builtin-agent-dogfood',
    evidenceOrder: loadedParallelPlan?.merge?.evidenceOrder || defaultMergeContract().evidenceOrder,
    ledgerPolicy: {
      appendOnly: true,
      prevHash: 'required',
      eventHash: 'required',
      requiredEventTypes: ['artifact_handoff', 'claim', 'validation', 'challenge', 'resolution'],
    },
    conflictPolicy: {
      tableRequired: true,
      evidenceOrder: loadedParallelPlan?.merge?.evidenceOrder || defaultMergeContract().evidenceOrder,
      unresolvedBlocksFinal: true,
    },
    claimGatePolicy: {
      provenRequiresArtifactSha256: true,
      provenRequiresJsonQuery: true,
      finalPassRequiresVerifier: true,
      unresolvedChallengeBlocks: true,
    },
    roles: roles.map((role) => ({
      id: role.id,
      title: role.title,
      mustEmit: ['Outcome', 'Key Evidence', 'Verification', 'Next Step'],
      allowedClaimKinds: ['observed', 'proven', 'gap', 'frontier_gap', 'stale', 'inferred'],
      forbiddenClaimKinds: ['unsupported_final_pass', 'platform_success_from_orchestration_only'],
      handoffTargets: ['synthesizer'],
      mergeKeys: role.planWorker?.mergeKeys || [],
      evidenceContract: role.planWorker?.evidenceContract || [],
      artifactGlobs: role.planWorker?.artifactGlobs || [],
    })),
    merge: loadedParallelPlan?.merge || defaultMergeContract(),
  };
}
const planPreview = normalizedPlanSummary();
const roleContract = workerContract();
function platformPatternsFromText(text) {
  const patterns = [];
  if (/bilibili|platform=bilibili|WBI|B站/i.test(text)) patterns.push(/Bilibili|B站|WBI/i);
  if (/xiaohongshu|platform=xiaohongshu|XHS|x-s|小红书/i.test(text)) patterns.push(/Xiaohongshu|小红书|XHS|x-s/i);
  if (/douyin|platform=douyin|a_bogus|抖音/i.test(text)) patterns.push(/Douyin|抖音|a_bogus/i);
  return patterns;
}
function platformPatternsForPlan() {
  if (!loadedParallelPlan) {
    return [/Bilibili|B站|WBI/i, /Xiaohongshu|小红书|XHS|x-s/i, /Douyin|抖音|a_bogus/i];
  }
  const workerText = JSON.stringify((loadedParallelPlan.workers || []).map((worker) => ({
    id: worker.id,
    caseIds: worker.caseIds,
    evidenceContract: worker.evidenceContract,
    mergeKeys: worker.mergeKeys,
  })));
  return platformPatternsFromText(workerText);
}
function platformPatternsForRole(role) {
  if (!role?.planWorker) return platformRequirementPatterns;
  const rolePatterns = platformPatternsFromText(JSON.stringify({
    id: role.planWorker.id,
    caseIds: role.planWorker.caseIds,
    evidenceContract: role.planWorker.evidenceContract,
    mergeKeys: role.planWorker.mergeKeys,
    objective: role.planWorker.objective,
  }));
  return rolePatterns.length ? rolePatterns : platformRequirementPatterns;
}
function platformFocusForPlan() {
  if (!loadedParallelPlan) return ['Bilibili', 'Xiaohongshu', 'Douyin'];
  const planText = JSON.stringify((loadedParallelPlan.workers || []).map((worker) => ({
    id: worker.id,
    caseIds: worker.caseIds,
    evidenceContract: worker.evidenceContract,
    mergeKeys: worker.mergeKeys,
  })));
  const names = [];
  if (/bilibili|platform=bilibili|WBI|B站/i.test(planText)) names.push('Bilibili/WBI');
  if (/xiaohongshu|platform=xiaohongshu|XHS|x-s|小红书/i.test(planText)) names.push('Xiaohongshu/x-s');
  if (/douyin|platform=douyin|a_bogus|抖音/i.test(planText)) names.push('Douyin/a_bogus');
  return names.length ? names : ['plan-specific target'];
}
const platformRequirementPatterns = platformPatternsForPlan();
const platformFocus = platformFocusForPlan();
const requireSameWindowCoverage = !loadedParallelPlan || /same[-_ ]?window|same_window_live/i.test(JSON.stringify(loadedParallelPlan));
const requireHardScoreCoverage = !loadedParallelPlan || /hard[-_ ]?score|scoreboard|hard-eval-control-plane|claim-ledger/i.test(JSON.stringify(loadedParallelPlan));
if (planOnly) {
  const summary = { ...planPreview, planOnly: true, willLaunchProvider: false };
  if (hasArgFlag('json')) console.log(JSON.stringify(summary, null, 2));
  else {
    console.log(`# Pi-RECON Parallel Plan Only\n\n- source=${summary.source}\n- plan_id=${summary.planId || 'none'}\n- workers=${summary.workerCount}\n- merge=${summary.merge.strategy || 'none'}\n\n## Workers`);
    for (const worker of summary.workers) console.log(`- ${worker.id}: ${worker.title} commands=${worker.commands.length} evidence=${worker.evidenceContract.length}`);
  }
  process.exit(0);
}

function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function safeJson(text, fallback = null) { try { return JSON.parse(text); } catch { return fallback; } }
function rel(path) { return String(path || '').replace(`${repoRoot}/`, ''); }
function redact(value) {
  return String(value || '')
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, 'sk-<redacted>')
    .replace(/(api[_-]?key|auth[_-]?token|authorization|bearer)(["'\s:=]+)([A-Za-z0-9_.\-\/+=]{12,})/gi, '$1$2<redacted>')
    .replace(/(ANTHROPIC_AUTH_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|GEMINI_API_KEY|OPENROUTER_API_KEY|AI_GATEWAY_API_KEY)=\S+/g, '$1=<redacted>');
}
function truthyEnvFlag(value) { return /^(1|true|yes|on)$/i.test(String(value || '')); }
function publicEnvPresence(keys) {
  return Object.fromEntries(keys.map((key) => [key, process.env[key] ? { set: true, length: String(process.env[key]).length } : { set: false, length: 0 }]));
}
function publicEndpointEnv(keys) {
  return Object.fromEntries(keys.map((key) => {
    const value = process.env[key] || '';
    if (!value) return [key, { set: false }];
    try {
      const url = new URL(value);
      return [key, { set: true, protocol: url.protocol, host: url.host }];
    } catch {
      return [key, { set: true, sha256: sha256(value).slice(0, 16), length: value.length }];
    }
  }));
}
function mockOfflineEnvSnapshot() {
  const interesting = Object.entries(process.env)
    .filter(([key]) => /(^PI_OFFLINE$|(^|_)OFFLINE($|_)|(^|_)MOCK($|_)|(^|_)FAKE($|_)|NO_NETWORK|NO_MODEL|STUB|FIXTURE)/i.test(key))
    .map(([key, value]) => [key, redact(value).slice(0, 160)]);
  return Object.fromEntries(interesting);
}
function processProbe(pid) {
  if (!pid || !existsSync(`/proc/${pid}`)) return { pid: pid || null, exists: false };
  const readProc = (name) => {
    try { return readFileSync(`/proc/${pid}/${name}`); } catch { return Buffer.alloc(0); }
  };
  const cmdline = readProc('cmdline');
  const comm = readProc('comm').toString('utf8').trim();
  const stat = readProc('stat').toString('utf8');
  const statParts = stat.split(/\s+/);
  return {
    pid,
    exists: true,
    argv0: cmdline.toString('utf8').split('\0').filter(Boolean)[0] || '',
    cmdlineBytes: cmdline.length,
    cmdlineSha256: sha256(cmdline).slice(0, 24),
    comm,
    ppid: Number(statParts[3] || 0) || null,
  };
}
async function fileDigest(path) {
  if (!path || !existsSync(path)) return null;
  const buffer = await readFile(path).catch(() => null);
  if (!buffer) return null;
  return { path: rel(path), bytes: buffer.length, sha256: sha256(buffer).slice(0, 24) };
}
async function writeSubagentRuntimeManifest({ role, attempt, roleSessionDir, runResult, session, stdoutPath, stderrPath }) {
  const sessionDir = rel(roleSessionDir);
  const sessionFiles = Array.isArray(session?.files) ? session.files : [];
  const toolResultCount = Number(session?.toolResults || 0);
  const stdout = await fileDigest(stdoutPath);
  const stderr = await fileDigest(stderrPath);
  const manifest = {
    kind: 'pi-recon-subagent-runtime-manifest',
    schemaVersion: 1,
    roleId: role.id,
    title: role.title || '',
    attempt,
    pid: runResult.pid,
    parentPid: runResult.parentPid,
    exitCode: runResult.code,
    signal: runResult.signal,
    startedAt: runResult.startedAt,
    endedAt: runResult.endedAt,
    elapsedMs: runResult.elapsedMs,
    argvSha256: runResult.argvSha256,
    processAtSpawn: runResult.processAtSpawn,
    monotonic: runResult.monotonic,
    stdout,
    stderr,
    sessionDir,
    sessionFiles,
    toolResultCount,
    session: {
      dir: sessionDir,
      files: sessionFiles,
      fileCount: sessionFiles.length,
      fileDigests: session?.fileDigests || [],
      sessionIds: session?.sessionIds || [],
      sessionCwds: session?.sessionCwds || {},
      toolCallCount: Number(session?.toolCalls || 0),
      toolResultCount,
      toolResultErrors: Number(session?.toolResultErrors || 0),
      toolResultBytes: Number(session?.toolResultBytes || 0),
      toolNames: session?.toolNames || {},
      toolResultNames: session?.toolResultNames || {},
      toolResultDigests: session?.toolResultDigests || [],
    },
    modelProvider: {
      requestedProvider: provider,
      requestedModel: model,
      thinking,
      requestedTools: tools.split(',').map((x) => x.trim()).filter(Boolean),
      observedProviders: session?.providers || {},
      observedModels: session?.models || {},
      modelCalls: Number(session?.modelCalls || 0),
      modelResponseIds: session?.modelResponseIds || [],
      stopReasons: session?.stopReasons || {},
      usageTokens: Number(session?.usageTokens || 0),
    },
    plan: {
      source: planPreview.source,
      planId: planPreview.planId || '',
      workerId: role.id,
      mergeKeys: role.planWorker?.mergeKeys || [],
      evidenceContract: role.planWorker?.evidenceContract || [],
    },
  };
  const manifestPath = join(outDir, `${role.id}.attempt-${attempt}.runtime-manifest.json`);
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { runtimeManifest: manifest, runtimeManifestFile: rel(manifestPath) };
}
async function runtimeAudit() {
  const offlineRequested = extraArgs.includes('--offline') || truthyEnvFlag(process.env.PI_OFFLINE);
  const noEnvRequested = extraArgs.includes('--no-env');
  const mockOfflineEnv = mockOfflineEnvSnapshot();
  const mockEnvDetected = Object.keys(mockOfflineEnv).some((key) => !/^PI_RECON_REPLAY/i.test(key));
  return {
    harnessPid: process.pid,
    harnessPpid: process.ppid,
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    cwd: repoRoot,
    agentCmd,
    agentCmdDigest: await fileDigest(agentCmd.startsWith('/') ? agentCmd : join(repoRoot, agentCmd)),
    extraArgs: extraArgs.map(redact),
    providerConfigured: Boolean(provider),
    modelConfigured: Boolean(model),
    authEnvPresence: publicEnvPresence(authEnvKeys),
    endpointEnv: publicEndpointEnv(endpointEnvKeys),
    offlineRequested,
    noEnvRequested,
    mockOfflineEnv,
    mockEnvDetected,
    nonMockRuntimeExpected: Boolean(provider && model && !offlineRequested && !noEnvRequested && !mockEnvDetected),
  };
}
async function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of await readdir(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) await walk(full, out);
    else out.push(full);
  }
  return out;
}
async function walkJsonl(dir) {
  return (await walk(dir)).filter((path) => path.endsWith('.jsonl')).sort();
}
async function latestResultPath(predicate) {
  const paths = (await walk(join(repoRoot, '.pi', 'evidence', 'remote')))
    .filter((path) => path.endsWith('/result.json'))
    .filter(predicate)
    .sort();
  return paths.at(-1) || '';
}
function run(cmd, args, options = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const startedMonoNs = process.hrtime.bigint();
    const argvSha256 = sha256(JSON.stringify([cmd, ...args])).slice(0, 24);
    const child = spawn(cmd, args, { cwd: repoRoot, env: process.env, stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    const childPid = child.pid || null;
    const processAtSpawn = processProbe(childPid);
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
      const endedMonoNs = process.hrtime.bigint();
      const elapsedMs = Date.now() - started;
      resolve({
        cmd,
        args,
        argvSha256,
        pid: childPid,
        parentPid: process.pid,
        processAtSpawn,
        code,
        signal,
        startedAt: new Date(started).toISOString(),
        endedAt: new Date().toISOString(),
        elapsedMs,
        monotonic: {
          startedNs: startedMonoNs.toString(),
          endedNs: endedMonoNs.toString(),
          elapsedMs: Number((endedMonoNs - startedMonoNs) / 1000000n),
          driftMs: Math.abs(elapsedMs - Number((endedMonoNs - startedMonoNs) / 1000000n)),
        },
        stdout,
        stderr,
      });
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      const endedMonoNs = process.hrtime.bigint();
      const elapsedMs = Date.now() - started;
      resolve({
        cmd,
        args,
        argvSha256,
        pid: childPid,
        parentPid: process.pid,
        processAtSpawn,
        code: 'error',
        signal: null,
        startedAt: new Date(started).toISOString(),
        endedAt: new Date().toISOString(),
        elapsedMs,
        monotonic: {
          startedNs: startedMonoNs.toString(),
          endedNs: endedMonoNs.toString(),
          elapsedMs: Number((endedMonoNs - startedMonoNs) / 1000000n),
          driftMs: Math.abs(elapsedMs - Number((endedMonoNs - startedMonoNs) / 1000000n)),
        },
        stdout,
        stderr,
        error: error.message,
      });
    });
  });
}
async function parseSessions(jsonlPaths) {
  const summary = {
    files: jsonlPaths.map(rel),
    fileDigests: [],
    sessionIds: [],
    sessionCwds: {},
    firstTimestamp: '',
    lastTimestamp: '',
    messages: 0,
    modelCalls: 0,
    modelResponseIds: [],
    stopReasons: {},
    toolCalls: 0,
    toolCallDigests: [],
    toolResults: 0,
    toolResultErrors: 0,
    toolResultBytes: 0,
    toolResultDigests: [],
    toolNames: {},
    toolResultNames: {},
    providers: {},
    models: {},
    usageTokens: 0,
  };
  for (const path of jsonlPaths) {
    const text = await readFile(path, 'utf8').catch(() => '');
    summary.fileDigests.push({ path: rel(path), bytes: Buffer.byteLength(text), sha256: sha256(text).slice(0, 24) });
    for (const line of text.split(/\n/)) {
      const obj = safeJson(line);
      if (!obj) continue;
      if (obj.timestamp) {
        summary.firstTimestamp = summary.firstTimestamp ? [summary.firstTimestamp, obj.timestamp].sort()[0] : obj.timestamp;
        summary.lastTimestamp = summary.lastTimestamp ? [summary.lastTimestamp, obj.timestamp].sort().at(-1) : obj.timestamp;
      }
      if (obj.type === 'session') {
        if (obj.id) summary.sessionIds.push(obj.id);
        if (obj.cwd) summary.sessionCwds[obj.cwd] = (summary.sessionCwds[obj.cwd] || 0) + 1;
      }
      if (obj.type === 'message' && obj.message) {
        summary.messages += 1;
        if (obj.message.provider || obj.message.model) {
          summary.modelCalls += 1;
          if (obj.message.provider) summary.providers[obj.message.provider] = (summary.providers[obj.message.provider] || 0) + 1;
          if (obj.message.model) summary.models[obj.message.model] = (summary.models[obj.message.model] || 0) + 1;
          if (obj.message.responseId) summary.modelResponseIds.push(String(obj.message.responseId).slice(0, 80));
          if (obj.message.stopReason) summary.stopReasons[obj.message.stopReason] = (summary.stopReasons[obj.message.stopReason] || 0) + 1;
          if (obj.message.usage?.totalTokens) summary.usageTokens += Number(obj.message.usage.totalTokens) || 0;
        }
        if (obj.message.role === 'toolResult') {
          const toolName = obj.message.toolName || 'unknown';
          const contentText = (obj.message.content || []).map((part) => part.text || '').join('\n');
          const bytes = Buffer.byteLength(contentText);
          summary.toolResults += 1;
          summary.toolResultBytes += bytes;
          if (obj.message.isError) summary.toolResultErrors += 1;
          summary.toolResultNames[toolName] = (summary.toolResultNames[toolName] || 0) + 1;
          summary.toolResultDigests.push({
            id: obj.message.toolCallId || '',
            name: toolName,
            isError: Boolean(obj.message.isError),
            bytes,
            sha256: sha256(contentText).slice(0, 24),
          });
        }
        for (const part of obj.message.content || []) {
          if (part.type === 'toolCall') {
            summary.toolCalls += 1;
            summary.toolNames[part.name || 'unknown'] = (summary.toolNames[part.name || 'unknown'] || 0) + 1;
            const argsText = typeof part.arguments === 'string' ? part.arguments : JSON.stringify(part.arguments || {});
            summary.toolCallDigests.push({
              id: part.id || '',
              name: part.name || 'unknown',
              argumentBytes: Buffer.byteLength(argsText),
              argumentSha256: sha256(argsText).slice(0, 24),
            });
          }
        }
      }
    }
  }
  return summary;
}
function hasAll(text, patterns) { return patterns.every((re) => re.test(text)); }
function hasAnyTool(session, names) { return names.some((name) => Number(session.toolNames?.[name] || 0) > 0); }
function outputChecks(role, output, session, code) {
  const sectionsOk = hasAll(output, [/Outcome/i, /Key Evidence/i, /Verification/i, /Next Step/i]);
  const platformsOk = platformPatternsForRole(role).every((pattern) => pattern.test(output));
  const sameWindowMentioned = !requireSameWindowCoverage || /same-window-live|same_window|spanMs|frontierGaps/i.test(output);
  const hardScoreMentioned = !requireHardScoreCoverage || /hard-score|scoreboard|bench\/recon-remote\/hard-score|hard-eval-control-plane|claim ledger|claim-ledger/i.test(output);
  const artifactPathsOk = /\.pi\/evidence\/remote\//.test(output);
  const modelCalled = session.modelCalls > 0;
  const toolUsed = session.toolCalls > 0;
  const roleSpecific = role.id === 'verifier'
    ? hasAnyTool(session, ['bash']) && /node bench\/recon-remote\/hard-score\.mjs|hard-score/i.test(output)
    : role.id === 'adversary'
      ? /gap|missing|not proven|not verified|stale|weak|indirect|contradict|null|empty|override|downgrad|self-delusion|自嗨|缺口|不足|未证明|未验证|陈旧|间接|矛盾|空|降级/i.test(output)
      : role.id === 'planner'
        ? /command|gate|invariant|pass\/fail|rollback|命令|门禁|不变量|回滚/i.test(output)
        : role.id === 'synthesizer'
          ? expectedWorkerRoleIds.filter((id) => new RegExp(id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i').test(output)).length >= Math.min(3, expectedWorkerRoleIds.length) && /conflict|disagreement|reconcile|overrule|synthesi[sz]e|accepted|rejected|downgrad|冲突|分歧|调和|采纳|驳回|降级|综合/i.test(output)
          : hasAnyTool(session, ['read', 'ls', 'grep', 'find', 'bash']);
  return { exitOk: code === 0, modelCalled, toolUsed, sectionsOk, platformsOk, sameWindowMentioned, hardScoreMentioned, artifactPathsOk, roleSpecific };
}
function overlapStats(runs) {
  const intervals = runs.map((run) => ({ start: Date.parse(run.startedAt), end: Date.parse(run.endedAt), elapsedMs: run.elapsedMs })).filter((x) => Number.isFinite(x.start) && Number.isFinite(x.end));
  let overlapPairs = 0;
  for (let i = 0; i < intervals.length; i += 1) {
    for (let j = i + 1; j < intervals.length; j += 1) {
      if (Math.max(intervals[i].start, intervals[j].start) < Math.min(intervals[i].end, intervals[j].end)) overlapPairs += 1;
    }
  }
  const wallStart = Math.min(...intervals.map((x) => x.start));
  const wallEnd = Math.max(...intervals.map((x) => x.end));
  const wallMs = wallEnd - wallStart;
  const sumMs = intervals.reduce((acc, x) => acc + x.elapsedMs, 0);
  return {
    roleCount: intervals.length,
    overlapPairs,
    maxPairs: intervals.length * (intervals.length - 1) / 2,
    wallMs,
    sumMs,
    speedup: wallMs > 0 ? Number((sumMs / wallMs).toFixed(2)) : 0,
    anyOverlap: overlapPairs > 0,
    fullOverlap: intervals.length > 1 && overlapPairs === intervals.length * (intervals.length - 1) / 2,
  };
}

const outDir = join(repoRoot, '.pi', 'evidence', 'remote', 'agent-parallel-dogfood', timestamp());
await mkdir(outDir, { recursive: true });
const sessionRoot = join(outDir, 'sessions');
await mkdir(sessionRoot, { recursive: true });
await writeFile(join(outDir, 'parallel-plan-preview.json'), `${JSON.stringify({ ...planPreview, artifactDir: rel(outDir), planOnly: false, willLaunchProvider: true }, null, 2)}\n`);
await writeFile(join(outDir, 'role-contract.json'), `${JSON.stringify(roleContract, null, 2)}\n`);
if (loadedParallelPlan) await writeFile(join(outDir, 'parallel-plan-source.json'), `${JSON.stringify(loadedParallelPlan, null, 2)}\n`);
const audit = await runtimeAudit();

const scoreRun = await run('node', ['bench/recon-remote/hard-score.mjs'], { timeoutMs: 60000 });
const scoreJson = safeJson(scoreRun.stdout);
const hardEvalRun = await run('node', ['scripts/reverse-agent/hard-eval-control-plane.mjs', '.', '--json'], { timeoutMs: 60000 });
const hardEvalJson = safeJson(hardEvalRun.stdout);
const hardEvalPlatformGaps = (hardEvalJson?.claims?.platform || []).filter((claim) => claim.kind !== 'proven');
const hardEvalRequiredPlatformGaps = hardEvalPlatformGaps.filter((claim) => claim.required);
const scoreArtifactDir = scoreJson?.artifactDir || '';
const scoreboard = safeJson(await readFile(join(repoRoot, scoreArtifactDir, 'scoreboard.json'), 'utf8').catch(() => ''), {});
function bestFamilyArtifact(family) {
  return (scoreboard.rows || [])
    .filter((row) => row.family === family && row.artifact)
    .sort((a, b) => Number(b.score || 0) - Number(a.score || 0) || String(b.time || '').localeCompare(String(a.time || '')))
    .at(0)?.artifact || '';
}
const evidencePaths = {
  hardScore: scoreArtifactDir,
  bestSameWindowLive: bestFamilyArtifact('same-window-live'),
  latestSameWindowLive: rel(await latestResultPath((path) => path.includes('/same-window-live/'))),
  bestBilibili: bestFamilyArtifact('bilibili-video'),
  latestBilibili: rel(await latestResultPath((path) => path.includes('/real-platform/bilibili-video/'))),
  bestXiaohongshu: bestFamilyArtifact('xiaohongshu-note'),
  latestXiaohongshu: rel(await latestResultPath((path) => path.includes('/real-platform/xiaohongshu-note/'))),
  bestDouyin: bestFamilyArtifact('douyin-nowatermark'),
  latestDouyin: rel(await latestResultPath((path) => path.includes('/douyin-nowatermark/'))),
  frontierMatrix: rel(await latestResultPath((path) => path.includes('/frontier-matrix/'))),
  latestAgentDogfood: rel(await latestResultPath((path) => path.includes('/agent-dogfood/'))),
};
const sharedContext = `

Shared authoritative evidence paths:
${JSON.stringify(evidencePaths, null, 2)}

Hard eval control split:
${JSON.stringify({
  verdict: hardEvalJson?.verdict || 'missing',
  orchestrationScore: hardEvalJson?.scores?.orchestration?.score ?? null,
  platformRequiredScore: hardEvalJson?.scores?.platformRequired?.score ?? null,
  platformAllScore: hardEvalJson?.scores?.platformAll?.score ?? null,
  requiredPlatformGaps: hardEvalRequiredPlatformGaps.map((claim) => ({ scope: claim.scope, gate: claim.gate, kind: claim.kind })),
}, null, 2)}

Evidence order: live same-window runtime behavior > platform runtime artifact fields > network traffic > actively served assets > process config > persisted artifacts/source/comments. Treat same-window-live as the current release frontier: if older platform artifacts conflict with it, explicitly classify the older artifact as stale instead of overuling the fresher same-window proof. Do not claim success unless the artifact fields prove it. If evidence is missing or indirect, say so. Treat orchestration success and platform claim success as separate states; if hard eval control reports required platform gaps, the worker must not summarize the platform as fully passed.

Parallel plan contract:
${JSON.stringify({
  source: planPreview.source,
  planId: planPreview.planId,
  target: planPreview.target,
  workers: planPreview.workers.map((worker) => ({ id: worker.id, role: worker.role, mergeKeys: worker.mergeKeys })),
  merge: planPreview.merge,
  validation: planPreview.validation,
}, null, 2)}
`;
const boundedWork = `\n\nOperational bounds for this parallel worker:\n- Use at most ${maxToolCallsHint} tool calls unless a required command fails.\n- Keep the final answer under ${maxWordsHint} words.\n- Stop immediately after the Next Step section; do not continue exploring once the required gates are covered.\n- Prefer decisive jq/grep/read checks over broad recursive inspection.\n`;
const requiredCitations = `\n\nRequired citations for every role:\n- Mention the hard-score or scoreboard artifact path explicitly when the plan requires hard-score coverage.\n- Mention the same-window-live artifact path explicitly when the plan requires same-window coverage.\n- Mention at least one .pi/evidence/remote artifact path for each plan focus: ${platformFocus.join(', ')}.\n`;

function strictRunPassed(runResult) {
  return Boolean(runResult?.checks?.exitOk && runResult?.checks?.modelCalled && runResult?.checks?.toolUsed && runResult?.checks?.sectionsOk && runResult?.checks?.platformsOk && runResult?.checks?.sameWindowMentioned && runResult?.checks?.hardScoreMentioned && runResult?.checks?.artifactPathsOk && runResult?.checks?.roleSpecific);
}

async function withRetries(label, launcher) {
  const attempts = [];
  let last = null;
  for (let attempt = 0; attempt <= roleRetries; attempt += 1) {
    last = await launcher(attempt);
    attempts.push({
      attempt,
      code: last.code,
      signal: last.signal,
      pid: last.pid,
      argvSha256: last.argvSha256,
      elapsedMs: last.elapsedMs,
      monotonic: last.monotonic,
      stdoutBytes: last.stdoutBytes,
      stderrBytes: last.stderrBytes,
      stdoutFile: last.attemptStdoutFile || last.stdoutFile,
      stderrFile: last.attemptStderrFile || last.stderrFile,
      runtimeManifestFile: last.runtimeManifestFile,
      sessionFiles: last.session?.files || [],
      toolResults: last.session?.toolResults || 0,
      checks: last.checks,
      stderrTail: last.stderrTail,
    });
    if (strictRunPassed(last)) return { ...last, retryCount: attempt, attempts };
  }
  return { ...last, retryCount: Math.max(0, attempts.length - 1), attempts, retryExhausted: true, retryLabel: label };
}

async function launchRole(role, attempt = 0) {
  const roleSessionDir = join(sessionRoot, role.id);
  await mkdir(roleSessionDir, { recursive: true });
  const retryHint = attempt ? `\n\nRetry attempt ${attempt}: the previous attempt did not satisfy the harness gates. Keep the same task, use tools early, and produce the required sections without extra exploration.\n` : '';
  const prompt = `${role.prompt}${retryHint}${sharedContext}${boundedWork}${requiredCitations}`;
  const args = [
    '--recon',
    '--provider', provider,
    '--model', model,
    '--thinking', thinking,
    '--tools', tools,
    '--approve',
    '--session-dir', roleSessionDir,
    ...extraArgs,
    '-p', prompt,
  ];
  const runResult = await run(agentCmd, args, { timeoutMs });
  const sessionFiles = await walkJsonl(roleSessionDir);
  const session = await parseSessions(sessionFiles);
  const output = `${runResult.stdout}\n${runResult.stderr}`;
  const checks = outputChecks(role, output, session, runResult.code);
  const attemptStdoutPath = join(outDir, `${role.id}.attempt-${attempt}.stdout.txt`);
  const attemptStderrPath = join(outDir, `${role.id}.attempt-${attempt}.stderr.txt`);
  await writeFile(attemptStdoutPath, redact(runResult.stdout));
  await writeFile(attemptStderrPath, redact(runResult.stderr));
  await writeFile(join(outDir, `${role.id}.stdout.txt`), redact(runResult.stdout));
  await writeFile(join(outDir, `${role.id}.stderr.txt`), redact(runResult.stderr));
  const { runtimeManifest, runtimeManifestFile } = await writeSubagentRuntimeManifest({
    role,
    attempt,
    roleSessionDir,
    runResult,
    session,
    stdoutPath: attemptStdoutPath,
    stderrPath: attemptStderrPath,
  });
  return {
    id: role.id,
    title: role.title,
    attempt,
    command: redact(`${agentCmd} ${args.map((arg) => JSON.stringify(arg)).join(' ')}`),
    code: runResult.code,
    signal: runResult.signal,
    pid: runResult.pid,
    parentPid: runResult.parentPid,
    argvSha256: runResult.argvSha256,
    processAtSpawn: runResult.processAtSpawn,
    monotonic: runResult.monotonic,
    startedAt: runResult.startedAt,
    endedAt: runResult.endedAt,
    elapsedMs: runResult.elapsedMs,
    stdoutBytes: Buffer.byteLength(runResult.stdout),
    stderrBytes: Buffer.byteLength(runResult.stderr),
    stdoutSha256: sha256(runResult.stdout).slice(0, 24),
    stderrSha256: sha256(runResult.stderr).slice(0, 24),
    stdoutFile: `${rel(outDir)}/${role.id}.stdout.txt`,
    stderrFile: `${rel(outDir)}/${role.id}.stderr.txt`,
    attemptStdoutFile: rel(attemptStdoutPath),
    attemptStderrFile: rel(attemptStderrPath),
    runtimeManifestFile,
    runtimeManifest,
    session,
    checks,
    stdoutTail: redact(runResult.stdout).slice(-5000),
    stderrTail: redact(runResult.stderr).slice(-2000),
  };
}

async function launchRoleWithRetry(role) {
  return withRetries(role.id, (attempt) => launchRole(role, attempt));
}

async function launchSynthesizer(workerSummaryPath, workerRuns, attempt = 0) {
  const role = { id: 'synthesizer', title: 'Conflict Synthesizer' };
  const roleSessionDir = join(sessionRoot, role.id);
  await mkdir(roleSessionDir, { recursive: true });
  const workerOutputPaths = Object.fromEntries(workerRuns.map((run) => [run.id, {
    stdout: `${rel(outDir)}/${run.id}.stdout.txt`,
    stderr: `${rel(outDir)}/${run.id}.stderr.txt`,
  }]));
  const workerNames = expectedWorkerRoleIds.join(', ');
  const retryHint = attempt ? `\n\nRetry attempt ${attempt}: the previous synthesizer attempt did not satisfy the harness gates. Mention these worker IDs (${workerNames}) and explicitly accept/reject/downgrade disputed claims.\n` : '';
  const prompt = `Role: conflict synthesizer. You are the sequential supervisor after the parallel Pi-RECON workers.\n\nRequired actions:\n1. Use tools to read ${workerSummaryPath} and inspect the worker outputs: ${JSON.stringify(workerOutputPaths)}.\n2. Reconcile worker disagreements across: ${workerNames}. Explicitly say which claims are accepted, rejected, or downgraded.\n3. Use the evidence order to resolve conflicts: live same-window runtime > platform runtime artifacts > network traffic > served assets > config > persisted artifacts/source/comments.\n4. Cover plan focus (${platformFocus.join(', ')}), same-window freshness/gaps when applicable, and Pi-RECON orchestration.\n5. Cite the hard-score/scoreboard artifact when applicable, same-window-live artifact when applicable, and at least one .pi/evidence/remote artifact path per plan focus.\n6. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n7. Do not edit files.${retryHint}${boundedWork}${requiredCitations}`;
  const args = [
    '--recon',
    '--provider', provider,
    '--model', model,
    '--thinking', thinking,
    '--tools', tools,
    '--approve',
    '--session-dir', roleSessionDir,
    ...extraArgs,
    '-p', prompt,
  ];
  const runResult = await run(agentCmd, args, { timeoutMs });
  const sessionFiles = await walkJsonl(roleSessionDir);
  const session = await parseSessions(sessionFiles);
  const output = `${runResult.stdout}\n${runResult.stderr}`;
  const checks = outputChecks(role, output, session, runResult.code);
  const attemptStdoutPath = join(outDir, `${role.id}.attempt-${attempt}.stdout.txt`);
  const attemptStderrPath = join(outDir, `${role.id}.attempt-${attempt}.stderr.txt`);
  await writeFile(attemptStdoutPath, redact(runResult.stdout));
  await writeFile(attemptStderrPath, redact(runResult.stderr));
  await writeFile(join(outDir, `${role.id}.stdout.txt`), redact(runResult.stdout));
  await writeFile(join(outDir, `${role.id}.stderr.txt`), redact(runResult.stderr));
  const { runtimeManifest, runtimeManifestFile } = await writeSubagentRuntimeManifest({
    role,
    attempt,
    roleSessionDir,
    runResult,
    session,
    stdoutPath: attemptStdoutPath,
    stderrPath: attemptStderrPath,
  });
  return {
    id: role.id,
    title: role.title,
    attempt,
    command: redact(`${agentCmd} ${args.map((arg) => JSON.stringify(arg)).join(' ')}`),
    code: runResult.code,
    signal: runResult.signal,
    pid: runResult.pid,
    parentPid: runResult.parentPid,
    argvSha256: runResult.argvSha256,
    processAtSpawn: runResult.processAtSpawn,
    monotonic: runResult.monotonic,
    startedAt: runResult.startedAt,
    endedAt: runResult.endedAt,
    elapsedMs: runResult.elapsedMs,
    stdoutBytes: Buffer.byteLength(runResult.stdout),
    stderrBytes: Buffer.byteLength(runResult.stderr),
    stdoutSha256: sha256(runResult.stdout).slice(0, 24),
    stderrSha256: sha256(runResult.stderr).slice(0, 24),
    stdoutFile: `${rel(outDir)}/${role.id}.stdout.txt`,
    stderrFile: `${rel(outDir)}/${role.id}.stderr.txt`,
    attemptStdoutFile: rel(attemptStdoutPath),
    attemptStderrFile: rel(attemptStderrPath),
    runtimeManifestFile,
    runtimeManifest,
    session,
    checks,
    stdoutTail: redact(runResult.stdout).slice(-5000),
    stderrTail: redact(runResult.stderr).slice(-2000),
  };
}

async function launchSynthesizerWithRetry(workerSummaryPath, workerRuns) {
  return withRetries('synthesizer', (attempt) => launchSynthesizer(workerSummaryPath, workerRuns, attempt));
}

const startedAt = new Date().toISOString();
const roleRuns = await Promise.all(roles.map((role) => launchRoleWithRetry(role)));
const workersEndedAt = new Date().toISOString();
const parallel = overlapStats(roleRuns);
const workerSummaryPath = rel(join(outDir, 'worker-summary.json'));
await writeFile(join(outDir, 'worker-summary.json'), `${JSON.stringify({
  planPreview,
  roleContractPath: `${rel(outDir)}/role-contract.json`,
  parallelPlanSourcePath: loadedParallelPlan ? `${rel(outDir)}/parallel-plan-source.json` : '',
  evidencePaths,
  roles: roles.map(({ id, title }) => ({ id, title })),
  roleRuns: roleRuns.map((role) => ({
    id: role.id,
    title: role.title,
    code: role.code,
    signal: role.signal,
    pid: role.pid,
    processAtSpawn: role.processAtSpawn,
    monotonic: role.monotonic,
    elapsedMs: role.elapsedMs,
    runtimeManifestFile: role.runtimeManifestFile,
    session: role.session,
    checks: role.checks,
    stdoutFile: `${rel(outDir)}/${role.id}.stdout.txt`,
    stderrFile: `${rel(outDir)}/${role.id}.stderr.txt`,
    stdoutTail: role.stdoutTail,
  })),
}, null, 2)}\n`);
const synthesizerRun = runSynthesizer ? await launchSynthesizerWithRetry(workerSummaryPath, roleRuns) : null;
const endedAt = new Date().toISOString();
const allRuns = synthesizerRun ? [...roleRuns, synthesizerRun] : roleRuns;
const totals = allRuns.reduce((acc, role) => {
  acc.messages += role.session.messages;
  acc.modelCalls += role.session.modelCalls;
  acc.toolCalls += role.session.toolCalls;
  acc.toolResults += role.session.toolResults;
  acc.toolResultErrors += role.session.toolResultErrors;
  acc.toolResultBytes += role.session.toolResultBytes;
  acc.usageTokens += role.session.usageTokens;
  for (const [name, count] of Object.entries(role.session.toolNames || {})) acc.toolNames[name] = (acc.toolNames[name] || 0) + count;
  for (const [name, count] of Object.entries(role.session.toolResultNames || {})) acc.toolResultNames[name] = (acc.toolResultNames[name] || 0) + count;
  for (const [name, count] of Object.entries(role.session.providers || {})) acc.providers[name] = (acc.providers[name] || 0) + count;
  for (const [name, count] of Object.entries(role.session.models || {})) acc.models[name] = (acc.models[name] || 0) + count;
  return acc;
}, { messages: 0, modelCalls: 0, toolCalls: 0, toolResults: 0, toolResultErrors: 0, toolResultBytes: 0, usageTokens: 0, toolNames: {}, toolResultNames: {}, providers: {}, models: {} });
const gateNames = ['exitOk', 'modelCalled', 'toolUsed', 'sectionsOk', 'platformsOk', 'hardScoreMentioned', 'artifactPathsOk', 'roleSpecific'];
const roleGateMatrix = Object.fromEntries(allRuns.map((role) => [role.id, role.checks]));
function subagentRuntimeManifestCaptured(role) {
  const manifest = role.runtimeManifest || {};
  const stdout = manifest.stdout || {};
  const stderr = manifest.stderr || {};
  return manifest.kind === 'pi-recon-subagent-runtime-manifest'
    && manifest.roleId === role.id
    && Number.isInteger(manifest.attempt)
    && Number(manifest.pid || 0) > 0
    && manifest.exitCode !== undefined
    && Boolean(stdout.path && stdout.sha256)
    && Boolean(stderr.path && stderr.sha256)
    && Boolean(manifest.sessionDir)
    && Array.isArray(manifest.sessionFiles)
    && typeof manifest.toolResultCount === 'number'
    && Boolean(manifest.session?.dir)
    && Array.isArray(manifest.session?.files)
    && typeof manifest.session?.toolResultCount === 'number'
    && manifest.modelProvider?.requestedProvider === provider
    && manifest.modelProvider?.requestedModel === model
    && Boolean(role.runtimeManifestFile);
}
const subagentRuntimeManifests = allRuns.map((role) => ({
  roleId: role.id,
  attempt: role.runtimeManifest?.attempt ?? role.attempt ?? null,
  file: role.runtimeManifestFile || '',
  pid: role.runtimeManifest?.pid ?? role.pid ?? null,
  exitCode: role.runtimeManifest?.exitCode ?? role.code ?? null,
  stdout: role.runtimeManifest?.stdout || null,
  stderr: role.runtimeManifest?.stderr || null,
  sessionDir: role.runtimeManifest?.sessionDir || '',
  sessionFiles: role.runtimeManifest?.sessionFiles || [],
  toolResultCount: role.runtimeManifest?.toolResultCount ?? 0,
  modelProvider: role.runtimeManifest?.modelProvider || null,
  captured: subagentRuntimeManifestCaptured(role),
}));
const subagentRuntimeManifestIndexPath = rel(join(outDir, 'subagent-runtime-manifests.json'));
const gates = {
  allRolesExited: allRuns.every((role) => role.checks.exitOk),
  allRolesModelCalled: allRuns.every((role) => role.checks.modelCalled),
  allRolesUsedTools: allRuns.every((role) => role.checks.toolUsed),
  allRolesStructured: allRuns.every((role) => role.checks.sectionsOk),
  allRolesCoverPlatforms: allRuns.every((role) => role.checks.platformsOk),
  sameWindowCovered: allRuns.every((role) => role.checks.sameWindowMentioned),
  allRolesCiteArtifacts: allRuns.every((role) => role.checks.artifactPathsOk),
  hardScoreCovered: allRuns.every((role) => role.checks.hardScoreMentioned),
  roleSpecificPassed: allRuns.every((role) => role.checks.roleSpecific),
  parallelOverlap: parallel.anyOverlap,
  strongParallelOverlap: parallel.fullOverlap || parallel.speedup >= 1.6,
  commandToolPresent: Number(totals.toolNames.bash || 0) > 0,
  readToolPresent: ['read', 'ls', 'grep', 'find'].some((name) => Number(totals.toolNames[name] || 0) > 0),
  antiSelfDelusion: Boolean(roleRuns.find((role) => role.id === 'adversary')?.checks.roleSpecific),
  synthesizerEnabled: runSynthesizer,
  synthesizerExited: !runSynthesizer || Boolean(synthesizerRun?.checks.exitOk),
  synthesizerModelCalled: !runSynthesizer || Boolean(synthesizerRun?.checks.modelCalled),
  synthesizerUsedTools: !runSynthesizer || Boolean(synthesizerRun?.checks.toolUsed),
  synthesizerReconciled: !runSynthesizer || Boolean(synthesizerRun?.checks.roleSpecific),
  childPidsCaptured: allRuns.every((role) => Number(role.pid || 0) > 0 && role.processAtSpawn?.exists),
  monotonicClockCaptured: allRuns.every((role) => Number(role.monotonic?.elapsedMs || 0) >= 0 && Number(role.monotonic?.driftMs || 0) < 5000),
  toolResultsCaptured: totals.toolCalls > 0 && totals.toolResults >= totals.toolCalls && allRuns.every((role) => role.session.toolCalls === 0 || role.session.toolResults >= role.session.toolCalls),
  sessionDigestsCaptured: allRuns.every((role) => (role.session.fileDigests || []).length > 0 && (role.session.fileDigests || []).every((item) => item.sha256 && item.bytes > 0)),
  subagentRuntimeManifestsCaptured: allRuns.every(subagentRuntimeManifestCaptured),
  nonMockRuntimeExpected: audit.nonMockRuntimeExpected,
  hardEvalControlRun: hardEvalRun.code === 0 && hardEvalJson?.kind === 'pi-recon-hard-eval-control-plane',
  orchestrationPlatformScoreSplit: Boolean(hardEvalJson?.antiSelfDelusion?.orchestrationPlatformSplit),
  platformClaimGapsCaptured: hardEvalRequiredPlatformGaps.length ? (hardEvalJson?.failures || []).length >= hardEvalPlatformGaps.length : Boolean(hardEvalJson?.gate?.requiredPlatformClaimsValidated),
};
const confirmed = Object.values(gates).every(Boolean);
const partial = totals.modelCalls > 0 && allRuns.some((role) => role.checks.toolUsed);
const platformRequiredClaimsValidated = Boolean(hardEvalJson?.gate?.requiredPlatformClaimsValidated);
const verdict = confirmed
  ? platformRequiredClaimsValidated
    ? 'agent-parallel-dogfood-confirmed'
    : 'agent-parallel-dogfood-confirmed-platform-gaps'
  : partial
    ? 'agent-parallel-dogfood-partial'
    : 'agent-parallel-dogfood-failed';
const roleFailureRepairRows = allRuns
  .filter((role) => role.retryExhausted || !strictRunPassed(role))
  .map((role) => {
    const failedGates = Object.entries(role.checks || {}).filter(([, passed]) => !passed).map(([name]) => name);
    const artifacts = [
      role.stdoutFile,
      role.stderrFile,
      ...(role.attempts || []).flatMap((attempt) => [attempt.stdoutFile, attempt.stderrFile]),
      ...(role.session?.fileDigests || []).map((item) => item.path),
    ].filter(Boolean);
    return failureRepairFromGap({
      root: repoRoot,
      source: 'agent-dogfood',
      scope: `agent-dogfood:${role.id}`,
      category: role.retryExhausted ? 'runtime_failed' : 'contract_gap',
      status: role.retryExhausted ? 'exhausted' : 'repair_queued',
      failedGates: failedGates.length ? failedGates : ['role_strict_run_passed'],
      reason: `${role.id} failed role gate(s): ${failedGates.join(',') || 'strictRunPassed=false'}`,
      attempt: (role.attempts || []).length || 1,
      maxAttempts: roleRetries + 1,
      commands: [`RECON_PARALLEL_ROLES=${role.id} node bench/recon-remote/agent-dogfood/parallel-run.mjs ${provider} ${model}`],
      artifacts,
      providerAllowed: true,
      paused: false,
      unblock: `rerun role ${role.id} with tighter prompt/tool evidence or inspect per-attempt artifacts`,
      verificationCommand: 'npm run gate:agent-parallel',
      regressionGates: gateNames,
    });
  });
const failureLedgerEvents = roleFailureRepairRows.map((row) => row.failure);
const repairQueue = roleFailureRepairRows.map((row) => row.repair);
const result = {
  target: 'Pi-RECON multi-agent parallel dogfood against hardest real-platform evidence',
  profile: 'agent-parallel-dogfood',
  verdict,
  generatedAt: new Date().toISOString(),
  startedAt,
  workersEndedAt,
  endedAt,
  artifactDir: rel(outDir),
  provider,
  model,
  thinking,
  tools: tools.split(',').map((x) => x.trim()).filter(Boolean),
  bounds: { maxToolCallsHint, maxWordsHint, roleRetries },
  runtimeAudit: audit,
  roles: roles.map(({ id, title }) => ({ id, title })),
  synthesizer: runSynthesizer ? { id: 'synthesizer', title: 'Conflict Synthesizer' } : null,
  evidencePaths,
  parallelPlan: {
    enabled: Boolean(loadedParallelPlan),
    planJson: planJsonPath || '',
    planId: loadedParallelPlan?.planId || '',
    source: loadedParallelPlan?.source || 'builtin-agent-dogfood',
    target: loadedParallelPlan?.target || 'Pi-RECON parallel dogfood',
    workerCount: roles.length,
    workerIds: roles.map((role) => role.id),
    merge: loadedParallelPlan?.merge || defaultMergeContract(),
    validation: parallelPlanValidation,
    artifacts: {
      preview: `${rel(outDir)}/parallel-plan-preview.json`,
      source: loadedParallelPlan ? `${rel(outDir)}/parallel-plan-source.json` : '',
      roleContract: `${rel(outDir)}/role-contract.json`,
    },
  },
  scoreRun: {
    code: scoreRun.code,
    pid: scoreRun.pid,
    argvSha256: scoreRun.argvSha256,
    processAtSpawn: scoreRun.processAtSpawn,
    monotonic: scoreRun.monotonic,
    elapsedMs: scoreRun.elapsedMs,
    artifactDir: scoreJson?.artifactDir || '',
    stdoutSha256: sha256(scoreRun.stdout).slice(0, 24),
  },
  hardEvalControl: {
    code: hardEvalRun.code,
    pid: hardEvalRun.pid,
    argvSha256: hardEvalRun.argvSha256,
    processAtSpawn: hardEvalRun.processAtSpawn,
    monotonic: hardEvalRun.monotonic,
    elapsedMs: hardEvalRun.elapsedMs,
    stdoutSha256: sha256(hardEvalRun.stdout).slice(0, 24),
    verdict: hardEvalJson?.verdict || 'missing',
    scores: hardEvalJson?.scores || null,
    gate: hardEvalJson?.gate || null,
    antiSelfDelusion: hardEvalJson?.antiSelfDelusion || null,
    platformGaps: hardEvalPlatformGaps.map((claim) => ({ scope: claim.scope, gate: claim.gate, kind: claim.kind, required: claim.required })),
    failures: (hardEvalJson?.failures || []).map((failure) => ({ id: failure.id, scope: failure.scope, category: failure.category, failedGates: failure.failedGates })),
    repairQueue: (hardEvalJson?.repairQueue || []).map((repair) => ({ repairId: repair.repairId, scope: repair.scope, action: repair.action, paused: repair.paused })),
  },
  parallel,
  totals,
  gates,
  roleGateMatrix,
  subagentRuntimeManifestIndex: subagentRuntimeManifestIndexPath,
  subagentRuntimeManifests,
  failureLedgerEvents,
  repairQueue,
  failureRepairWriteback: failureLedgerEvents[0]?.evidenceWriteback || {
    failureLedgerPath: '.pi/evidence/failures/ledger.jsonl',
    repairQueuePath: '.pi/evidence/repairs/queue.jsonl',
    appendOnly: true,
    mode: 'agent-dogfood',
  },
  roleRuns,
  synthesizerRun,
  nextActions: confirmed
    ? platformRequiredClaimsValidated
      ? [
          'make this parallel+synthesizer dogfood gate part of release gating',
          'raise the next gate to a live same-window Bilibili/Xiaohongshu/Douyin run',
          'optionally run live frontier-matrix before the parallel agents when budget allows',
        ]
      : [
          'do not report platform success: hard-eval-control-plane captured required platform gaps',
          'consume hardEvalControl.repairQueue when live testing is explicitly resumed',
          'keep orchestration score and platform claim score separate in hard-score and release notes',
        ]
    : [
        'inspect each role stdout/stderr and session jsonl for the failed gates',
        'rerun with a longer timeout or smaller RECON_PARALLEL_ROLES subset',
        'tighten role prompts to force missing tool use, artifact citations, or anti-self-delusion language',
      ],
};
await writeFile(join(outDir, 'subagent-runtime-manifests.json'), `${JSON.stringify({
  kind: 'pi-recon-subagent-runtime-manifest-index',
  schemaVersion: 1,
  manifestCount: subagentRuntimeManifests.length,
  manifests: subagentRuntimeManifests,
}, null, 2)}\n`);
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
await writeFile(join(outDir, 'failure-ledger.jsonl'), `${failureLedgerEvents.map((event) => JSON.stringify(event)).join('\n')}${failureLedgerEvents.length ? '\n' : ''}`);
await writeFile(join(outDir, 'repair-queue.jsonl'), `${repairQueue.map((item) => JSON.stringify(item)).join('\n')}${repairQueue.length ? '\n' : ''}`);
const md = [
  '# Pi-RECON Parallel Agent Dogfood Artifact',
  '',
  `verdict: ${verdict}`,
  `provider: ${provider}`,
  `model: ${model}`,
  `artifact_dir: ${rel(outDir)}`,
  '',
  '## Outcome',
  `- roles=${roles.map((role) => role.id).join(',')}${synthesizerRun ? ',synthesizer' : ''}`,
  `- model_calls=${totals.modelCalls} tool_calls=${totals.toolCalls} tool_results=${totals.toolResults} tool_result_bytes=${totals.toolResultBytes} tool_names=${JSON.stringify(totals.toolNames)}`,
  `- parallel_overlap_pairs=${parallel.overlapPairs}/${parallel.maxPairs} speedup=${parallel.speedup}`,
  `- synthesizer=${synthesizerRun ? `exit=${synthesizerRun.code} model_calls=${synthesizerRun.session.modelCalls} tool_calls=${synthesizerRun.session.toolCalls}` : 'disabled'}`,
  `- runtime_audit non_mock_expected=${audit.nonMockRuntimeExpected} offline=${audit.offlineRequested} no_env=${audit.noEnvRequested} mock_env=${audit.mockEnvDetected} agent_cmd_sha=${audit.agentCmdDigest?.sha256 || 'none'}`,
  '',
  '## Key Evidence',
  `- hard_score_artifact=${evidencePaths.hardScore || 'none'} code=${scoreRun.code}`,
  `- hard_eval_control verdict=${hardEvalJson?.verdict || 'missing'} code=${hardEvalRun.code} orchestration_score=${hardEvalJson?.scores?.orchestration?.score ?? 'n/a'} platform_required_score=${hardEvalJson?.scores?.platformRequired?.score ?? 'n/a'} required_gaps=${hardEvalRequiredPlatformGaps.map((claim) => claim.gate).join(',') || 'none'}`,
  `- parallel_plan source=${planPreview.source} plan_id=${planPreview.planId || 'builtin'} workers=${planPreview.workerCount} merge=${planPreview.merge?.strategy || 'none'} validation=${planPreview.validation?.valid}`,
  `- subagent_runtime_manifest_index=${subagentRuntimeManifestIndexPath} captured=${gates.subagentRuntimeManifestsCaptured}`,
  `- same_window_live=${evidencePaths.bestSameWindowLive || evidencePaths.latestSameWindowLive || 'none'}`,
  `- best_bilibili=${evidencePaths.bestBilibili || 'none'}`,
  `- best_xiaohongshu=${evidencePaths.bestXiaohongshu || 'none'}`,
  `- best_douyin=${evidencePaths.bestDouyin || 'none'}`,
  `- gates=${JSON.stringify(gates)}`,
  '',
  '## Verification',
  ...allRuns.map((role) => `- ${role.id}: pid=${role.pid} exit=${role.code} elapsed_ms=${role.elapsedMs} mono_ms=${role.monotonic?.elapsedMs} model_calls=${role.session.modelCalls} tool_calls=${role.session.toolCalls} tool_results=${role.session.toolResults} session_sha=${role.session.fileDigests?.[0]?.sha256 || 'none'} checks=${JSON.stringify(role.checks)}`),
  '',
  '## Next Step',
  ...result.nextActions.map((item) => `- ${item}`),
  '',
].join('\n');
await writeFile(join(outDir, 'artifact.md'), md);
console.log(JSON.stringify({
  verdict,
  artifactDir: rel(outDir),
  provider,
  model,
  roles: roles.map((role) => role.id).concat(synthesizerRun ? ['synthesizer'] : []),
  totals,
  parallel,
  runtimeAudit: {
    nonMockRuntimeExpected: audit.nonMockRuntimeExpected,
    offlineRequested: audit.offlineRequested,
    noEnvRequested: audit.noEnvRequested,
    mockEnvDetected: audit.mockEnvDetected,
    agentCmdSha256: audit.agentCmdDigest?.sha256 || '',
  },
  gates,
  subagentRuntimeManifestIndex: subagentRuntimeManifestIndexPath,
  subagentRuntimeManifestFiles: subagentRuntimeManifests.map((row) => row.file),
  hardEvalControl: {
    verdict: hardEvalJson?.verdict || 'missing',
    orchestrationScore: hardEvalJson?.scores?.orchestration?.score ?? null,
    platformRequiredScore: hardEvalJson?.scores?.platformRequired?.score ?? null,
    requiredPlatformGaps: hardEvalRequiredPlatformGaps.map((claim) => ({ scope: claim.scope, gate: claim.gate, kind: claim.kind })),
  },
  parallelPlan: {
    source: planPreview.source,
    planId: planPreview.planId,
    workerCount: planPreview.workerCount,
    merge: planPreview.merge?.strategy || '',
    validation: planPreview.validation,
  },
}, null, 2));

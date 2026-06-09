#!/usr/bin/env node
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const repoRoot = resolve(process.env.RECON_REPO_ROOT || '.');
const provider = process.env.RECON_AGENT_PROVIDER || process.argv[2] || 'aigateway';
const model = process.env.RECON_AGENT_MODEL || process.argv[3] || process.env.ANTHROPIC_MODEL || '';
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

if (process.argv.includes('--help') || process.argv.includes('-h') || !model) {
  console.log(`Pi-RECON parallel agent dogfood benchmark\n\nUsage:\n  RECON_AGENT_PROVIDER=openai RECON_AGENT_MODEL=gpt-4.1 node bench/recon-remote/agent-dogfood/parallel-run.mjs\n  node bench/recon-remote/agent-dogfood/parallel-run.mjs <provider> <model>\n\nPurpose:\n  Launches multiple real Pi-RECON --recon agents in parallel against the latest real-platform evidence,\n  then runs a synthesizer agent that reconciles worker disagreements. The harness gates real model calls,\n  tool calls, parallel overlap, platform coverage, artifact paths, and anti-self-delusion review.\n\nEnvironment:\n  RECON_AGENT_PROVIDER=<provider>       default: aigateway\n  RECON_AGENT_MODEL=<model>             required unless argv[3] or ANTHROPIC_MODEL is set\n  RECON_AGENT_THINKING=low\n  RECON_AGENT_TOOLS=read,grep,find,ls,bash\n  RECON_AGENT_TIMEOUT_MS=300000\n  RECON_AGENT_CMD=./pi-test.sh\n  RECON_AGENT_EXTRA_ARGS='--offline'    optional extra Pi CLI args\n  RECON_PARALLEL_ROLES=a,b              optional subset: mapper,verifier,adversary,planner\n  RECON_PARALLEL_MAX_TOOL_CALLS=4        prompt-level cap to prevent runaway workers\n  RECON_PARALLEL_MAX_WORDS=500           prompt-level output cap per worker\n  RECON_SYNTHESIZER=1                    run the sequential conflict-synthesizer; set 0 to skip\n  RECON_ROLE_RETRIES=1                   retry failed/flaky role runs before judging the gate\n\nOutput:\n  .pi/evidence/remote/agent-parallel-dogfood/<timestamp>/\n`);
  process.exit(model ? 0 : 2);
}

const allRoles = [
  {
    id: 'mapper',
    title: 'Evidence Mapper',
    prompt: `Role: evidence mapper. Build a precise map of the latest real-platform Pi-RECON evidence.\n\nRequired actions:\n1. Use ls/read/grep/find tools to inspect the supplied artifact paths and the latest hard-score artifact.\n2. Identify the decisive fields for Bilibili WBI/per-page CID, Xiaohongshu x-s/signed replay, and Douyin a_bogus/structured replay.\n3. Separate live-runtime evidence from stale, inferred, or weak evidence.\n4. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n5. Do not edit files.`,
  },
  {
    id: 'verifier',
    title: 'Command Verifier',
    prompt: `Role: command verifier. Prove or disprove the claims by executing local verification commands.\n\nRequired actions:\n1. Execute: node bench/recon-remote/hard-score.mjs\n2. Use read/grep/ls/bash to verify concrete result.json fields for Bilibili, Xiaohongshu, and Douyin.\n3. Report exact commands, exit status when visible, artifact paths, and the decisive field/value pairs.\n4. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n5. Do not edit files.`,
  },
  {
    id: 'adversary',
    title: 'Anti-Self-Delusion Auditor',
    prompt: `Role: adversarial auditor. Your job is to attack the benchmark's confidence and find self-delusion.\n\nRequired actions:\n1. Use read/grep/ls/find tools to inspect latest scoreboard and artifacts.\n2. For Bilibili, Xiaohongshu, and Douyin, say what is strongly proven, what is only inferred, and what is missing.\n3. Explicitly flag stale verdicts, weak evidence, indirect proof, or any gap that would make a top-tier agent claim invalid.\n4. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n5. Do not edit files.`,
  },
  {
    id: 'planner',
    title: 'Hard Frontier Planner',
    prompt: `Role: hard frontier planner. Design the next hardest benchmark step for a top-tier reverse/pentest agent.\n\nRequired actions:\n1. Use read/grep/ls tools to inspect current score/evidence before proposing work.\n2. Propose a concrete multi-agent benchmark plan that raises difficulty without self-delusion.\n3. Include commands, pass/fail gates, artifact invariants, context/compact requirements, and rollback criteria.\n4. Cover Bilibili WBI/per-page CID, Xiaohongshu x-s, Douyin a_bogus/no-watermark transform, and Pi-RECON agent orchestration.\n5. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n6. Do not edit files.`,
  },
];
const roles = roleFilter.length ? allRoles.filter((role) => roleFilter.includes(role.id)) : allRoles;
if (!roles.length) throw new Error(`No roles selected from RECON_PARALLEL_ROLES=${process.env.RECON_PARALLEL_ROLES || ''}`);

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
    const child = spawn(cmd, args, { cwd: repoRoot, env: process.env, stdio: ['ignore', 'pipe', 'pipe'], shell: false });
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
      resolve({ cmd, args, code, signal, startedAt: new Date(started).toISOString(), endedAt: new Date().toISOString(), elapsedMs: Date.now() - started, stdout, stderr });
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({ cmd, args, code: 'error', signal: null, startedAt: new Date(started).toISOString(), endedAt: new Date().toISOString(), elapsedMs: Date.now() - started, stdout, stderr, error: error.message });
    });
  });
}
async function parseSessions(jsonlPaths) {
  const summary = { files: jsonlPaths.map(rel), messages: 0, modelCalls: 0, toolCalls: 0, toolNames: {}, providers: {}, models: {}, usageTokens: 0 };
  for (const path of jsonlPaths) {
    const text = await readFile(path, 'utf8').catch(() => '');
    for (const line of text.split(/\n/)) {
      const obj = safeJson(line);
      if (!obj) continue;
      if (obj.type === 'message' && obj.message) {
        summary.messages += 1;
        if (obj.message.provider || obj.message.model) {
          summary.modelCalls += 1;
          if (obj.message.provider) summary.providers[obj.message.provider] = (summary.providers[obj.message.provider] || 0) + 1;
          if (obj.message.model) summary.models[obj.message.model] = (summary.models[obj.message.model] || 0) + 1;
          if (obj.message.usage?.totalTokens) summary.usageTokens += Number(obj.message.usage.totalTokens) || 0;
        }
        for (const part of obj.message.content || []) {
          if (part.type === 'toolCall') {
            summary.toolCalls += 1;
            summary.toolNames[part.name || 'unknown'] = (summary.toolNames[part.name || 'unknown'] || 0) + 1;
          }
        }
      }
    }
  }
  return summary;
}
function hasAll(text, patterns) { return patterns.every((re) => re.test(text)); }
function hasAnyTool(session, names) { return names.some((name) => Number(session.toolNames?.[name] || 0) > 0); }
function matchCount(text, patterns) { return patterns.filter((re) => re.test(text)).length; }
function outputChecks(role, output, session, code) {
  const sectionsOk = hasAll(output, [/Outcome/i, /Key Evidence/i, /Verification/i, /Next Step/i]);
  const platformsOk = hasAll(output, [/Bilibili|B站|WBI/i, /Xiaohongshu|小红书|XHS|x-s/i, /Douyin|抖音|a_bogus/i]);
  const hardScoreMentioned = /hard-score|scoreboard|bench\/recon-remote\/hard-score/i.test(output);
  const artifactPathsOk = /\.pi\/evidence\/remote\//.test(output);
  const modelCalled = session.modelCalls > 0;
  const toolUsed = session.toolCalls > 0;
  const roleSpecific = role.id === 'verifier'
    ? hasAnyTool(session, ['bash']) && /node bench\/recon-remote\/hard-score\.mjs|hard-score/i.test(output)
    : role.id === 'adversary'
      ? /gap|missing|not proven|not verified|stale|weak|indirect|self-delusion|自嗨|缺口|不足|未证明|未验证|陈旧|间接/i.test(output)
      : role.id === 'planner'
        ? /command|gate|invariant|pass\/fail|rollback|命令|门禁|不变量|回滚/i.test(output)
        : role.id === 'synthesizer'
          ? matchCount(output, [/mapper/i, /verifier/i, /adversary/i, /planner/i]) >= 3 && /conflict|disagreement|reconcile|overrule|synthesi[sz]e|accepted|rejected|downgrad|冲突|分歧|调和|采纳|驳回|降级|综合/i.test(output)
          : hasAnyTool(session, ['read', 'ls', 'grep', 'find', 'bash']);
  return { exitOk: code === 0, modelCalled, toolUsed, sectionsOk, platformsOk, hardScoreMentioned, artifactPathsOk, roleSpecific };
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

const scoreRun = await run('node', ['bench/recon-remote/hard-score.mjs'], { timeoutMs: 60000 });
const scoreJson = safeJson(scoreRun.stdout);
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
  bestBilibili: bestFamilyArtifact('bilibili-video'),
  latestBilibili: rel(await latestResultPath((path) => path.includes('/real-platform/bilibili-video/'))),
  bestXiaohongshu: bestFamilyArtifact('xiaohongshu-note'),
  latestXiaohongshu: rel(await latestResultPath((path) => path.includes('/real-platform/xiaohongshu-note/'))),
  bestDouyin: bestFamilyArtifact('douyin-nowatermark'),
  latestDouyin: rel(await latestResultPath((path) => path.includes('/douyin-nowatermark/'))),
  frontierMatrix: rel(await latestResultPath((path) => path.includes('/frontier-matrix/'))),
  latestAgentDogfood: rel(await latestResultPath((path) => path.includes('/agent-dogfood/'))),
};
const sharedContext = `\n\nShared authoritative evidence paths:\n${JSON.stringify(evidencePaths, null, 2)}\n\nEvidence order: live runtime behavior > network traffic > actively served assets > process config > persisted artifacts/source/comments. Do not claim success unless the artifact fields prove it. If evidence is missing or indirect, say so.\n`;
const boundedWork = `\n\nOperational bounds for this parallel worker:\n- Use at most ${maxToolCallsHint} tool calls unless a required command fails.\n- Keep the final answer under ${maxWordsHint} words.\n- Stop immediately after the Next Step section; do not continue exploring once the required gates are covered.\n- Prefer decisive jq/grep/read checks over broad recursive inspection.\n`;
const requiredCitations = `\n\nRequired citations for every role:\n- Mention the hard-score or scoreboard artifact path explicitly.\n- Mention at least one .pi/evidence/remote artifact path for each platform family: Bilibili, Xiaohongshu, and Douyin.\n`;

function strictRunPassed(runResult) {
  return Boolean(runResult?.checks?.exitOk && runResult?.checks?.modelCalled && runResult?.checks?.toolUsed && runResult?.checks?.sectionsOk && runResult?.checks?.platformsOk && runResult?.checks?.hardScoreMentioned && runResult?.checks?.artifactPathsOk && runResult?.checks?.roleSpecific);
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
      elapsedMs: last.elapsedMs,
      stdoutBytes: last.stdoutBytes,
      stderrBytes: last.stderrBytes,
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
  await writeFile(join(outDir, `${role.id}.stdout.txt`), redact(runResult.stdout));
  await writeFile(join(outDir, `${role.id}.stderr.txt`), redact(runResult.stderr));
  return {
    id: role.id,
    title: role.title,
    command: redact(`${agentCmd} ${args.map((arg) => JSON.stringify(arg)).join(' ')}`),
    code: runResult.code,
    signal: runResult.signal,
    startedAt: runResult.startedAt,
    endedAt: runResult.endedAt,
    elapsedMs: runResult.elapsedMs,
    stdoutBytes: Buffer.byteLength(runResult.stdout),
    stderrBytes: Buffer.byteLength(runResult.stderr),
    stdoutSha256: sha256(runResult.stdout).slice(0, 24),
    stderrSha256: sha256(runResult.stderr).slice(0, 24),
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
  const retryHint = attempt ? `\n\nRetry attempt ${attempt}: the previous synthesizer attempt did not satisfy the harness gates. Mention at least three worker role names and explicitly accept/reject/downgrade disputed claims.\n` : '';
  const prompt = `Role: conflict synthesizer. You are the sequential supervisor after the parallel Pi-RECON workers.\n\nRequired actions:\n1. Use tools to read ${workerSummaryPath} and inspect the worker outputs: ${JSON.stringify(workerOutputPaths)}.\n2. Reconcile mapper/verifier/adversary/planner disagreements. Explicitly say which claims are accepted, rejected, or downgraded.\n3. Use the evidence order to resolve conflicts: live runtime > network traffic > served assets > config > persisted artifacts/source/comments.\n4. Cover Bilibili WBI/per-page CID, Xiaohongshu x-s/signed replay, Douyin a_bogus/no-watermark transform, and Pi-RECON orchestration.\n5. Cite the hard-score/scoreboard artifact plus at least one .pi/evidence/remote artifact path per platform.\n6. Output exactly these sections: Outcome / Key Evidence / Verification / Next Step.\n7. Do not edit files.${retryHint}${boundedWork}${requiredCitations}`;
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
  await writeFile(join(outDir, `${role.id}.stdout.txt`), redact(runResult.stdout));
  await writeFile(join(outDir, `${role.id}.stderr.txt`), redact(runResult.stderr));
  return {
    id: role.id,
    title: role.title,
    command: redact(`${agentCmd} ${args.map((arg) => JSON.stringify(arg)).join(' ')}`),
    code: runResult.code,
    signal: runResult.signal,
    startedAt: runResult.startedAt,
    endedAt: runResult.endedAt,
    elapsedMs: runResult.elapsedMs,
    stdoutBytes: Buffer.byteLength(runResult.stdout),
    stderrBytes: Buffer.byteLength(runResult.stderr),
    stdoutSha256: sha256(runResult.stdout).slice(0, 24),
    stderrSha256: sha256(runResult.stderr).slice(0, 24),
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
  evidencePaths,
  roles: roles.map(({ id, title }) => ({ id, title })),
  roleRuns: roleRuns.map((role) => ({
    id: role.id,
    title: role.title,
    code: role.code,
    signal: role.signal,
    elapsedMs: role.elapsedMs,
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
  acc.usageTokens += role.session.usageTokens;
  for (const [name, count] of Object.entries(role.session.toolNames || {})) acc.toolNames[name] = (acc.toolNames[name] || 0) + count;
  for (const [name, count] of Object.entries(role.session.providers || {})) acc.providers[name] = (acc.providers[name] || 0) + count;
  for (const [name, count] of Object.entries(role.session.models || {})) acc.models[name] = (acc.models[name] || 0) + count;
  return acc;
}, { messages: 0, modelCalls: 0, toolCalls: 0, usageTokens: 0, toolNames: {}, providers: {}, models: {} });
const gateNames = ['exitOk', 'modelCalled', 'toolUsed', 'sectionsOk', 'platformsOk', 'hardScoreMentioned', 'artifactPathsOk', 'roleSpecific'];
const roleGateMatrix = Object.fromEntries(allRuns.map((role) => [role.id, role.checks]));
const gates = {
  allRolesExited: allRuns.every((role) => role.checks.exitOk),
  allRolesModelCalled: allRuns.every((role) => role.checks.modelCalled),
  allRolesUsedTools: allRuns.every((role) => role.checks.toolUsed),
  allRolesStructured: allRuns.every((role) => role.checks.sectionsOk),
  allRolesCoverPlatforms: allRuns.every((role) => role.checks.platformsOk),
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
};
const confirmed = Object.values(gates).every(Boolean);
const partial = totals.modelCalls > 0 && allRuns.some((role) => role.checks.toolUsed);
const verdict = confirmed ? 'agent-parallel-dogfood-confirmed' : partial ? 'agent-parallel-dogfood-partial' : 'agent-parallel-dogfood-failed';
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
  roles: roles.map(({ id, title }) => ({ id, title })),
  synthesizer: runSynthesizer ? { id: 'synthesizer', title: 'Conflict Synthesizer' } : null,
  evidencePaths,
  scoreRun: {
    code: scoreRun.code,
    elapsedMs: scoreRun.elapsedMs,
    artifactDir: scoreJson?.artifactDir || '',
    stdoutSha256: sha256(scoreRun.stdout).slice(0, 24),
  },
  parallel,
  totals,
  gates,
  roleGateMatrix,
  roleRuns,
  synthesizerRun,
  nextActions: confirmed
    ? [
        'make this parallel+synthesizer dogfood gate part of release gating',
        'raise the next gate to a live same-window Bilibili/Xiaohongshu/Douyin run',
        'optionally run live frontier-matrix before the parallel agents when budget allows',
      ]
    : [
        'inspect each role stdout/stderr and session jsonl for the failed gates',
        'rerun with a longer timeout or smaller RECON_PARALLEL_ROLES subset',
        'tighten role prompts to force missing tool use, artifact citations, or anti-self-delusion language',
      ],
};
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
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
  `- model_calls=${totals.modelCalls} tool_calls=${totals.toolCalls} tool_names=${JSON.stringify(totals.toolNames)}`,
  `- parallel_overlap_pairs=${parallel.overlapPairs}/${parallel.maxPairs} speedup=${parallel.speedup}`,
  `- synthesizer=${synthesizerRun ? `exit=${synthesizerRun.code} model_calls=${synthesizerRun.session.modelCalls} tool_calls=${synthesizerRun.session.toolCalls}` : 'disabled'}`,
  '',
  '## Key Evidence',
  `- hard_score_artifact=${evidencePaths.hardScore || 'none'} code=${scoreRun.code}`,
  `- best_bilibili=${evidencePaths.bestBilibili || 'none'}`,
  `- best_xiaohongshu=${evidencePaths.bestXiaohongshu || 'none'}`,
  `- best_douyin=${evidencePaths.bestDouyin || 'none'}`,
  `- gates=${JSON.stringify(gates)}`,
  '',
  '## Verification',
  ...allRuns.map((role) => `- ${role.id}: exit=${role.code} elapsed_ms=${role.elapsedMs} model_calls=${role.session.modelCalls} tool_calls=${role.session.toolCalls} checks=${JSON.stringify(role.checks)}`),
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
  gates,
}, null, 2));

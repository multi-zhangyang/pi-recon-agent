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
const timeoutMs = Number(process.env.RECON_AGENT_TIMEOUT_MS || 240000);
const agentCmd = process.env.RECON_AGENT_CMD || './pi-test.sh';
const extraArgs = (process.env.RECON_AGENT_EXTRA_ARGS || '').split(/\s+/).filter(Boolean);
const prompt = process.env.RECON_AGENT_PROMPT || '';

if (process.argv.includes('--help') || process.argv.includes('-h') || !model) {
  console.log(`REPI agent dogfood benchmark\n\nUsage:\n  RECON_AGENT_PROVIDER=openai RECON_AGENT_MODEL=gpt-4.1 node bench/recon-remote/agent-dogfood/run.mjs\n  node bench/recon-remote/agent-dogfood/run.mjs <provider> <model>\n\nPurpose:\n  Runs the REPI agent itself against latest remote benchmark evidence, requiring a real model/provider call.\n\nEnvironment:\n  RECON_AGENT_PROVIDER=<provider>       default: aigateway\n  RECON_AGENT_MODEL=<model>             required unless argv[3] or ANTHROPIC_MODEL is set\n  RECON_AGENT_THINKING=low\n  RECON_AGENT_TOOLS=read,grep,find,ls,bash\n  RECON_AGENT_TIMEOUT_MS=240000\n  RECON_AGENT_CMD=./pi-test.sh\n  RECON_AGENT_EXTRA_ARGS='--offline'    optional extra CLI args\n  RECON_AGENT_PROMPT='<custom prompt>'  optional prompt override\n\nOutput:\n  .repi-harness/evidence/remote/agent-dogfood/<timestamp>/\n`);
  process.exit(model ? 0 : 2);
}

function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function safeJson(text, fallback = null) { try { return JSON.parse(text); } catch { return fallback; } }
function redact(value) {
  return String(value || '')
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, 'sk-<redacted>')
    .replace(/(api[_-]?key|auth[_-]?token|authorization|bearer)(["'\s:=]+)([A-Za-z0-9_.\-\/+=]{12,})/gi, '$1$2<redacted>')
    .replace(/(ANTHROPIC_AUTH_TOKEN|OPENAI_API_KEY|GEMINI_API_KEY|OPENROUTER_API_KEY|AI_GATEWAY_API_KEY)=\S+/g, '$1=<redacted>');
}
async function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of await readdir(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) await walk(full, out);
    else if (name.endsWith('.jsonl')) out.push(full);
  }
  return out;
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
      resolve({ cmd, args, code, signal, elapsedMs: Date.now() - started, stdout, stderr });
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({ cmd, args, code: 'error', signal: null, elapsedMs: Date.now() - started, stdout, stderr, error: error.message });
    });
  });
}
async function parseSessions(jsonlPaths) {
  const summary = { files: jsonlPaths, messages: 0, modelCalls: 0, toolCalls: 0, toolNames: {}, providers: {}, models: {}, usageTokens: 0 };
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

const outDir = join(repoRoot, '.repi-harness', 'evidence', 'remote', 'agent-dogfood', timestamp());
await mkdir(outDir, { recursive: true });
const sessionDir = join(outDir, 'sessions');
await mkdir(sessionDir, { recursive: true });

const scoreRun = await run('node', ['bench/recon-remote/hard-score.mjs'], { timeoutMs: 60000 });
const scoreJson = safeJson(scoreRun.stdout);
const scoreArtifact = scoreJson?.artifactDir || '';

const dogfoodPrompt = prompt || `REPI dogfood benchmark. You are running inside the REPI --recon profile.\n\nRequired actions:\n1. Execute: node bench/recon-remote/hard-score.mjs\n2. Read the latest remote evidence and the scoreboard artifact ${scoreArtifact || '<latest hard-score>'}.\n3. Produce Outcome → Key Evidence → Verification → Next Step.\n4. Cover exactly these real-platform tracks: Bilibili WBI, Xiaohongshu x-s, Douyin a_bogus.\n5. Include concrete artifact paths and commands for the next hardest benchmark step.\n6. Do not edit files in this dogfood run.`;

const agentArgs = [
  '--recon',
  '--provider', provider,
  '--model', model,
  '--thinking', thinking,
  '--tools', tools,
  '--approve',
  '--session-dir', sessionDir,
  ...extraArgs,
  '-p', dogfoodPrompt,
];
const agentRun = await run(agentCmd, agentArgs, { timeoutMs });
const sessionFiles = (await walk(sessionDir)).sort();
const session = await parseSessions(sessionFiles);
const output = `${agentRun.stdout}\n${agentRun.stderr}`;
const sectionsOk = hasAll(output, [/Outcome/i, /Key Evidence/i, /Verification/i, /Next Step/i]);
const platformsOk = hasAll(output, [/Bilibili|B站/i, /Xiaohongshu|小红书|XHS|x-s/i, /Douyin|抖音|a_bogus/i]);
const hardScoreMentioned = /hard-score|scoreboard|bench\/recon-remote\/hard-score/i.test(output);
const modelCalled = session.modelCalls > 0 || agentRun.stdout.length > 200;
const toolUsed = session.toolCalls > 0 || /node bench\/recon-remote\/hard-score\.mjs|已执行|executed/i.test(output);
const reconProfile = agentArgs.includes('--recon');
const verdict = agentRun.code === 0 && modelCalled && sectionsOk && platformsOk && hardScoreMentioned
  ? 'agent-dogfood-confirmed'
  : agentRun.code === 0 && modelCalled
    ? 'agent-dogfood-partial'
    : 'agent-dogfood-failed';
const result = {
  target: 'REPI agent against latest remote benchmark evidence',
  profile: 'agent-dogfood',
  verdict,
  generatedAt: new Date().toISOString(),
  artifactDir: outDir.replace(`${repoRoot}/`, ''),
  provider,
  model,
  thinking,
  tools: tools.split(',').map((x) => x.trim()).filter(Boolean),
  scoreRun: {
    code: scoreRun.code,
    elapsedMs: scoreRun.elapsedMs,
    artifactDir: scoreArtifact,
    stdoutSha256: sha256(scoreRun.stdout).slice(0, 24),
  },
  agentRun: {
    code: agentRun.code,
    signal: agentRun.signal,
    elapsedMs: agentRun.elapsedMs,
    stdoutBytes: Buffer.byteLength(agentRun.stdout),
    stderrBytes: Buffer.byteLength(agentRun.stderr),
    stdoutSha256: sha256(agentRun.stdout).slice(0, 24),
    stderrSha256: sha256(agentRun.stderr).slice(0, 24),
  },
  session,
  checks: { reconProfile, modelCalled, toolUsed, sectionsOk, platformsOk, hardScoreMentioned },
  command: redact(`${agentCmd} ${agentArgs.map((arg) => JSON.stringify(arg)).join(' ')}`),
  stdoutTail: redact(agentRun.stdout).slice(-8000),
  stderrTail: redact(agentRun.stderr).slice(-4000),
  nextActions: verdict === 'agent-dogfood-confirmed'
    ? ['add this dogfood artifact to release gating', 'raise score threshold for real-platform advanced tracks', 'compare agent next commands with actual harness roadmap']
    : ['inspect stdout/stderr/session jsonl for missing tool/model evidence', 'rerun with a stronger provider/model or longer timeout', 'tighten prompt to force hard-score command execution'],
};
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
await writeFile(join(outDir, 'stdout.txt'), redact(agentRun.stdout));
await writeFile(join(outDir, 'stderr.txt'), redact(agentRun.stderr));
const md = [
  '# REPI Agent Dogfood Artifact',
  '',
  `verdict: ${verdict}`,
  `provider: ${provider}`,
  `model: ${model}`,
  `artifact_dir: ${outDir.replace(`${repoRoot}/`, '')}`,
  '',
  '## Key Evidence',
  `- hard_score_artifact=${scoreArtifact || 'none'} code=${scoreRun.code}`,
  `- agent_exit=${agentRun.code} elapsed_ms=${agentRun.elapsedMs}`,
  `- session_model_calls=${session.modelCalls} tool_calls=${session.toolCalls} tool_names=${JSON.stringify(session.toolNames)}`,
  `- checks=${JSON.stringify(result.checks)}`,
  '',
  '## Verification',
  `- JSON: ${outDir.replace(`${repoRoot}/`, '')}/result.json`,
  `- stdout: ${outDir.replace(`${repoRoot}/`, '')}/stdout.txt`,
  `- stderr: ${outDir.replace(`${repoRoot}/`, '')}/stderr.txt`,
  '',
  '## Next Step',
  ...result.nextActions.map((item) => `- ${item}`),
  '',
].join('\n');
await writeFile(join(outDir, 'artifact.md'), md);
console.log(JSON.stringify({ verdict, artifactDir: outDir.replace(`${repoRoot}/`, ''), provider, model, checks: result.checks, session: { modelCalls: session.modelCalls, toolCalls: session.toolCalls, toolNames: session.toolNames } }, null, 2));

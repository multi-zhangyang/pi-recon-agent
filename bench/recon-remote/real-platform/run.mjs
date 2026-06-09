#!/usr/bin/env node
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

const target = process.env.RECON_TARGET_URL || process.argv[2];
const profileArg = String(process.env.RECON_PROFILE || process.argv[3] || 'auto').toLowerCase();
const probeLimit = Number(process.env.RECON_PROBE_LIMIT || 16);
const timeoutMs = Number(process.env.RECON_TIMEOUT_MS || 35000);
const quietMs = Number(process.env.RECON_QUIET_MS || 2500);
const maxBodyBytes = Number(process.env.RECON_MAX_BODY_BYTES || 500000);
const browserMode = String(process.env.RECON_BROWSER || 'auto').toLowerCase();
const chromeBin = process.env.RECON_CHROME_BIN || process.env.CHROME_BIN || '';
const userAgent = process.env.RECON_USER_AGENT || 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36 Pi-RECON-real-platform';

if (!target || target === '--help' || target === '-h') {
  console.log(`Pi-RECON real platform hard benchmark\n\nUsage:\n  node bench/recon-remote/real-platform/run.mjs <url> [auto|bilibili-video|xiaohongshu-note|generic-cdp]\n\nExamples:\n  node bench/recon-remote/real-platform/run.mjs https://www.bilibili.com/video/BV1odL76QE6B bilibili-video\n  node bench/recon-remote/real-platform/run.mjs 'https://www.xiaohongshu.com/explore/66237c6e000000001c00893f' xiaohongshu-note\n\nEnvironment:\n  RECON_BROWSER=auto|1|0\n  RECON_PROBE_LIMIT=16\n  RECON_TIMEOUT_MS=35000\n  RECON_QUIET_MS=2500\n  RECON_MAX_BODY_BYTES=500000\n  RECON_CHROME_BIN=<path>\n\nOutput:\n  .pi/evidence/remote/real-platform/<profile>/<host>/<timestamp>/\n`);
  process.exit(target ? 0 : 2);
}

function timestamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function slug(value) { return String(value || 'x').replace(/[^a-zA-Z0-9_.-]+/g, '_').slice(0, 120) || 'x'; }
function unique(items) { return [...new Set(items.filter(Boolean))]; }
function safeJsonParse(text, fallback = null) { try { return JSON.parse(text); } catch { return fallback; } }

function assertHttpUrl(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error(`Unsupported URL protocol: ${url.protocol}`);
  return url;
}

function detectProfile(url) {
  if (profileArg !== 'auto') return profileArg;
  const host = url.hostname.toLowerCase();
  if (host.includes('bilibili.com') || host.includes('b23.tv')) return 'bilibili-video';
  if (host.includes('xiaohongshu.com') || host.includes('xhslink.com')) return 'xiaohongshu-note';
  return 'generic-cdp';
}

function requestHeaders(extra = {}) {
  return {
    'user-agent': userAgent,
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7',
    'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
    ...extra,
  };
}

function sanitizeHeaders(headers = {}) {
  const out = {};
  for (const [key, value] of Object.entries(headers || {})) {
    if (/cookie|authorization|token|session|csrf|xsrf|buvid|sid|a1/i.test(key)) out[key] = '<redacted>';
    else out[key] = value;
  }
  return out;
}

function redactUrl(value) {
  try {
    const url = new URL(String(value || ''));
    for (const key of [...url.searchParams.keys()]) {
      if (/token|w_rid|wts|buvid|sid|sess|csrf|a1|xsec|web_session|msToken|a_bogus|hmac|upsig|trid|oi|mid|hdnts|deadline|uparams|qn_dyeid/i.test(key)) url.searchParams.set(key, '<redacted>');
    }
    return url.toString();
  } catch {
    return String(value || '').replace(/(token|w_rid|buvid|xsec_token|msToken|a_bogus)=([^&\s]+)/gi, '$1=<redacted>');
  }
}

async function fetchText(url, options = {}) {
  const res = await fetch(url, { redirect: options.redirect || 'manual', headers: requestHeaders(options.headers || {}) });
  const buffer = Buffer.from(await res.arrayBuffer());
  return {
    url,
    status: res.status,
    headers: sanitizeHeaders(Object.fromEntries(res.headers.entries())),
    bytes: buffer.length,
    sha256: sha256(buffer).slice(0, 24),
    text: buffer.subarray(0, maxBodyBytes).toString('utf8'),
  };
}

async function fetchJson(url, options = {}) {
  const item = await fetchText(url, { ...options, headers: { accept: 'application/json,text/plain,*/*', ...(options.headers || {}) } });
  return { ...item, json: safeJsonParse(item.text) };
}

async function probeUrl(url, headers = {}) {
  const attempts = [];
  let current = url;
  for (let i = 0; i < 4; i++) {
    try {
      const res = await fetch(current, { method: 'HEAD', redirect: 'manual', headers: requestHeaders(headers) });
      const h = sanitizeHeaders(Object.fromEntries(res.headers.entries()));
      attempts.push({ method: 'HEAD', url: redactUrl(current), status: res.status, headers: h });
      if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.get('location')) {
        current = new URL(res.headers.get('location'), current).toString();
        continue;
      }
      if (![200, 206].includes(res.status)) {
        const gr = await fetch(current, { method: 'GET', redirect: 'manual', headers: requestHeaders({ ...headers, range: 'bytes=0-0' }) });
        const buf = Buffer.from(await gr.arrayBuffer());
        attempts.push({ method: 'GET bytes=0-0', url: redactUrl(current), status: gr.status, headers: sanitizeHeaders(Object.fromEntries(gr.headers.entries())), bytes: buf.length, sha256: sha256(buf).slice(0, 24) });
      }
      break;
    } catch (error) {
      attempts.push({ method: 'probe', url: redactUrl(current), status: 'error', error: error instanceof Error ? error.message : String(error) });
      break;
    }
  }
  const hay = attempts.map((a) => `${a.url} ${a.headers?.['content-type'] || ''} ${a.headers?.location || ''}`).join(' ').toLowerCase();
  const media = /video|audio|mp4|m4s|mpegurl|octet-stream|\.m4s|\.mp4|\.m3u8/.test(hay);
  const reachable = attempts.some((a) => [200, 206, 301, 302, 303, 307, 308].includes(Number(a.status)));
  return { originalUrl: redactUrl(url), attempts, classification: { media, reachable } };
}

function extractBvid(text) {
  return String(text || '').match(/BV[0-9A-Za-z]{10}/)?.[0] || '';
}

function collectBiliMedia(playJson) {
  const data = playJson?.data || playJson?.result || {};
  const out = [];
  for (const durl of data.durl || []) {
    out.push({ kind: 'durl', quality: data.quality, url: durl.url, size: durl.size, length: durl.length });
    for (const backup of durl.backup_url || durl.backupUrl || []) out.push({ kind: 'durl-backup', quality: data.quality, url: backup });
  }
  for (const item of data.dash?.video || []) {
    out.push({ kind: 'dash-video', id: item.id, codecs: item.codecs, bandwidth: item.bandwidth, url: item.baseUrl || item.base_url });
    for (const backup of item.backupUrl || item.backup_url || []) out.push({ kind: 'dash-video-backup', id: item.id, codecs: item.codecs, url: backup });
  }
  for (const item of data.dash?.audio || []) {
    out.push({ kind: 'dash-audio', id: item.id, codecs: item.codecs, bandwidth: item.bandwidth, url: item.baseUrl || item.base_url });
    for (const backup of item.backupUrl || item.backup_url || []) out.push({ kind: 'dash-audio-backup', id: item.id, codecs: item.codecs, url: backup });
  }
  return out.filter((x) => x.url);
}

async function runBilibili(url, outDir) {
  const page = await fetchText(url.toString(), { headers: { referer: 'https://www.bilibili.com/' } });
  let finalUrl = url.toString();
  if ([301, 302, 303, 307, 308].includes(page.status) && page.headers.location) {
    finalUrl = new URL(page.headers.location, url).toString();
  }
  const bvid = extractBvid(finalUrl) || extractBvid(page.text);
  if (!bvid) return { verdict: 'missing-bvid', page };
  const referer = `https://www.bilibili.com/video/${bvid}/`;
  const view = await fetchJson(`https://api.bilibili.com/x/web-interface/view?bvid=${encodeURIComponent(bvid)}`, { headers: { referer } });
  const pagelist = await fetchJson(`https://api.bilibili.com/x/player/pagelist?bvid=${encodeURIComponent(bvid)}`, { headers: { referer } });
  const cid = view.json?.data?.cid || pagelist.json?.data?.[0]?.cid;
  const playurls = [];
  if (cid) {
    for (const fnval of [4048, 80, 16, 0]) {
      const api = `https://api.bilibili.com/x/player/playurl?bvid=${encodeURIComponent(bvid)}&cid=${encodeURIComponent(cid)}&qn=80&fnval=${fnval}&fourk=1`;
      playurls.push({ fnval, ...(await fetchJson(api, { headers: { referer } })) });
    }
  }
  const media = unique(playurls.flatMap((p) => collectBiliMedia(p.json).map((m) => JSON.stringify(m)))).map((x) => JSON.parse(x));
  const probes = [];
  for (const item of media.slice(0, probeLimit)) probes.push({ ...item, url: redactUrl(item.url), probe: await probeUrl(item.url, { referer, origin: 'https://www.bilibili.com' }) });
  const strong = probes.filter((p) => p.probe.classification.media && p.probe.classification.reachable);
  const verdict = view.json?.code === 0 && playurls.some((p) => p.json?.code === 0) && strong.length ? 'bilibili-media-api-confirmed' : media.length ? 'bilibili-media-candidates-needs-replay' : 'bilibili-no-media-candidate';
  return {
    verdict,
    bvid,
    aid: view.json?.data?.aid,
    cid,
    title: view.json?.data?.title,
    owner: view.json?.data?.owner ? { mid: '<redacted>', name: view.json.data.owner.name } : undefined,
    page: { status: page.status, bytes: page.bytes, sha256: page.sha256, finalUrl: redactUrl(finalUrl) },
    view: { status: view.status, code: view.json?.code, bytes: view.bytes },
    pagelist: { status: pagelist.status, code: pagelist.json?.code, pages: pagelist.json?.data?.length || 0 },
    playurls: playurls.map((p) => ({ fnval: p.fnval, status: p.status, code: p.json?.code, quality: p.json?.data?.quality, accept_quality: p.json?.data?.accept_quality, accept_description: p.json?.data?.accept_description, hasDash: Boolean(p.json?.data?.dash), durlCount: p.json?.data?.durl?.length || 0 })),
    mediaCandidates: media.slice(0, 80).map((m) => ({ ...m, url: redactUrl(m.url) })),
    probes,
    nextActions: ['bind playurl API + media HEAD/range probes into re_replayer', 'diff fnval=4048/80/16/0 media capability', 'capture browser/CDP if API code changes or WBI gates appear'],
  };
}

async function which(command) {
  for (const dir of (process.env.PATH || '').split(':')) {
    const full = join(dir, command);
    if (existsSync(full)) return full;
  }
  return '';
}

async function resolveChrome() {
  if (chromeBin) return chromeBin;
  for (const name of ['google-chrome', 'chromium', 'chromium-browser']) {
    const found = await which(name);
    if (found) return found;
  }
  return '';
}

async function waitForDevToolsPort(profileDir, deadlineMs) {
  const file = join(profileDir, 'DevToolsActivePort');
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    try {
      const text = await readFile(file, 'utf8');
      const [port] = text.trim().split(/\s+/);
      if (port) return Number(port);
    } catch {}
    await sleep(100);
  }
  throw new Error('DevToolsActivePort timeout');
}

async function cdpHttp(port, path, init = {}) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, init);
  const text = await res.text();
  if (!res.ok) throw new Error(`CDP HTTP ${res.status}: ${text.slice(0, 200)}`);
  return JSON.parse(text);
}

function cdpClient(wsUrl, artifact) {
  const ws = new WebSocket(wsUrl);
  let id = 0;
  let closing = false;
  const pending = new Map();
  const open = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('CDP websocket open timeout')), 10000);
    ws.onopen = () => { clearTimeout(timer); resolve(); };
  });
  ws.onerror = (event) => { if (!closing) artifact.errors.push({ type: 'websocket', message: String(event?.message || 'cdp websocket error') }); };
  ws.onmessage = (event) => {
    const msg = safeJsonParse(String(event.data));
    if (!msg) return;
    if (msg.id && pending.has(msg.id)) {
      const item = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) item.reject(new Error(JSON.stringify(msg.error)));
      else item.resolve(msg.result || {});
      return;
    }
    const p = msg.params || {};
    if (msg.method === 'Network.requestWillBeSent') artifact.requests.push({ id: p.requestId, type: p.type, method: p.request?.method, url: redactUrl(p.request?.url), headers: sanitizeHeaders(p.request?.headers || {}), initiator: p.initiator?.type });
    if (msg.method === 'Network.responseReceived') artifact.responses.push({ id: p.requestId, type: p.type, url: redactUrl(p.response?.url), status: p.response?.status, mimeType: p.response?.mimeType, headers: sanitizeHeaders(p.response?.headers || {}) });
    if (msg.method === 'Network.loadingFailed') artifact.failures.push({ id: p.requestId, type: p.type, errorText: p.errorText });
  };
  async function send(method, params = {}) {
    await open;
    const requestId = ++id;
    ws.send(JSON.stringify({ id: requestId, method, params }));
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(requestId); reject(new Error(`CDP command timeout ${method}`)); }, 12000);
      pending.set(requestId, { resolve: (v) => { clearTimeout(timer); resolve(v); }, reject: (e) => { clearTimeout(timer); reject(e); } });
    });
  }
  async function close() { closing = true; try { ws.close(); } catch {} }
  return { open, send, close };
}

async function captureCdp(url, outDir) {
  const chrome = await resolveChrome();
  const artifact = { mode: 'chrome-cdp', chrome: chrome || 'missing', target: url.toString(), capturedAt: new Date().toISOString(), requests: [], responses: [], failures: [], bodies: [], storage: {}, errors: [], skipped: false };
  if (!chrome || ['0', 'off', 'false'].includes(browserMode)) { artifact.skipped = true; artifact.skipReason = chrome ? 'browser disabled' : 'chrome missing'; return artifact; }
  const profileDir = join(outDir, `chrome-profile-${randomUUID()}`);
  await mkdir(profileDir, { recursive: true });
  const child = spawn(chrome, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profileDir}`, '--no-first-run', '--no-default-browser-check', '--disable-dev-shm-usage', '--disable-gpu', '--no-sandbox', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += String(chunk).slice(0, 2000); });
  try {
    const port = await waitForDevToolsPort(profileDir, 10000);
    const target = (await cdpHttp(port, `/json/new?${encodeURIComponent('about:blank')}`, { method: 'PUT' }));
    const client = cdpClient(target.webSocketDebuggerUrl, artifact);
    await client.open;
    await client.send('Page.enable');
    await client.send('Runtime.enable');
    await client.send('Network.enable', { maxTotalBufferSize: 50000000, maxResourceBufferSize: 5000000 });
    await client.send('Network.setUserAgentOverride', { userAgent });
    await client.send('Page.navigate', { url: url.toString() });
    let lastCount = -1;
    let lastChange = Date.now();
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const count = artifact.requests.length + artifact.responses.length + artifact.failures.length;
      if (count !== lastCount) { lastCount = count; lastChange = Date.now(); }
      if (Date.now() - lastChange > quietMs && artifact.responses.length) break;
      await sleep(250);
    }
    for (const response of artifact.responses.filter((r) => /json|text|html|javascript/i.test(r.mimeType || '')).slice(-60)) {
      try {
        const body = await client.send('Network.getResponseBody', { requestId: response.id });
        const text = body.base64Encoded ? Buffer.from(body.body || '', 'base64').toString('utf8') : String(body.body || '');
        artifact.bodies.push({ id: response.id, url: response.url, mimeType: response.mimeType, length: text.length, sha256: sha256(text).slice(0, 24), text: text.slice(0, maxBodyBytes) });
      } catch (error) { artifact.bodies.push({ id: response.id, url: response.url, error: error instanceof Error ? error.message : String(error) }); }
    }
    const evalResult = await client.send('Runtime.evaluate', { returnByValue: true, awaitPromise: true, expression: `JSON.stringify({href:location.href,title:document.title,html:document.documentElement.outerHTML.slice(0, ${maxBodyBytes}),localStorage:{...localStorage},sessionStorage:{...sessionStorage},cookies:document.cookie})` });
    artifact.storage = safeJsonParse(evalResult.result?.value || '{}', {});
    artifact.storage.cookies = artifact.storage.cookies ? '<redacted>' : '';
    await client.close();
  } catch (error) {
    artifact.errors.push({ type: 'capture', message: error instanceof Error ? error.stack || error.message : String(error) });
  } finally {
    artifact.stderrHead = stderr.slice(0, 2000);
    try { child.kill('SIGTERM'); } catch {}
    setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1500).unref?.();
    await rm(profileDir, { recursive: true, force: true }).catch(() => {});
  }
  return artifact;
}

function analyzeXhs(url, cdp) {
  const text = [cdp.storage?.html || '', JSON.stringify(cdp.storage || {}), ...(cdp.bodies || []).map((b) => b.text || ''), ...(cdp.requests || []).map((r) => r.url || ''), ...(cdp.responses || []).map((r) => r.url || '')].join('\n');
  const noteIds = unique([String(url).match(/explore\/([0-9a-f]{24})/i)?.[1], ...[...text.matchAll(/(?:note_id|noteId|id)["']?\s*[:=]\s*["']?([0-9a-f]{24})/gi)].map((m) => m[1]), ...[...text.matchAll(/explore\/([0-9a-f]{24})/gi)].map((m) => m[1])]);
  const webApis = unique((cdp.requests || []).map((r) => r.url).filter((u) => /\/api\/sns\/web|edith|xiaohongshu\.com\/api|xsec|web_session/i.test(u || '')));
  const antiBot = unique([...[...text.matchAll(/x-s-common|x-s|x-t|xsec_token|web_session|a1|b1|unread|captcha|verify/gi)].map((m) => m[0])]);
  const imagePattern = new RegExp('https?:\\/\\/[^\\n\"\'<>]+(?:sns-webpic|xhscdn|xhscdn\\.com|xiaohongshu)[^\\n\"\'<>]+', 'gi');
  const images = unique([...text.matchAll(imagePattern)].map((m) => redactUrl(m[0]))).slice(0, 40);
  const verdict = noteIds.length && webApis.length ? 'xhs-note-runtime-api-captured' : noteIds.length ? 'xhs-note-id-captured-api-gated' : antiBot.length ? 'xhs-anti-bot-surface-captured' : 'xhs-runtime-capture-inconclusive';
  return { verdict, noteIds, webApiHints: webApis.map(redactUrl).slice(0, 80), antiBotSignals: antiBot.slice(0, 40), imageHints: images, browser: { requests: cdp.requests.length, responses: cdp.responses.length, bodies: cdp.bodies.length, failures: cdp.failures.length, errors: cdp.errors } };
}

async function runXhs(url, outDir) {
  const cdp = await captureCdp(url, outDir);
  await writeFile(join(outDir, 'browser.json'), `${JSON.stringify(cdp, null, 2)}\n`);
  if (cdp.storage?.html) await writeFile(join(outDir, 'browser.html'), cdp.storage.html);
  return { ...analyzeXhs(url, cdp), browserArtifact: join(outDir, 'browser.json'), nextActions: ['classify /api/sns/web/* endpoints and required x-s/x-t/x-s-common headers', 'extract note id/xsec_token from rendered state', 'replay read-only endpoints with captured header shape if present'] };
}

async function runGeneric(url, outDir) {
  const cdp = await captureCdp(url, outDir);
  await writeFile(join(outDir, 'browser.json'), `${JSON.stringify(cdp, null, 2)}\n`);
  return { verdict: cdp.responses?.length ? 'generic-cdp-captured' : 'generic-cdp-no-response', browser: { requests: cdp.requests.length, responses: cdp.responses.length, bodies: cdp.bodies.length, failures: cdp.failures.length, errors: cdp.errors }, browserArtifact: join(outDir, 'browser.json'), nextActions: ['inspect browser.json for APIs, signatures, storage, websocket anchors'] };
}

const url = assertHttpUrl(target);
const profile = detectProfile(url);
const outDir = join('.pi', 'evidence', 'remote', 'real-platform', slug(profile), slug(url.hostname), timestamp());
await mkdir(outDir, { recursive: true });
const started = Date.now();
let result;
if (profile === 'bilibili-video') result = await runBilibili(url, outDir);
else if (profile === 'xiaohongshu-note') result = await runXhs(url, outDir);
else result = await runGeneric(url, outDir);
result = { target: redactUrl(url.toString()), profile, artifactDir: outDir, elapsedMs: Date.now() - started, ...result };
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);

const md = [
  '# Pi-RECON Real Platform Hard Benchmark Artifact',
  '',
  `target: ${result.target}`,
  `profile: ${profile}`,
  `verdict: ${result.verdict}`,
  `artifact_dir: ${outDir}`,
  '',
  '## Key Evidence',
  ...(profile === 'bilibili-video' ? [
    `- bvid=${result.bvid || 'none'} aid=${result.aid || 'none'} cid=${result.cid || 'none'}`,
    `- title=${result.title || 'none'}`,
    `- view_code=${result.view?.code} playurl_profiles=${(result.playurls || []).map((p) => `${p.fnval}:${p.code}:q${p.quality}`).join(', ')}`,
    `- media_candidates=${result.mediaCandidates?.length || 0} reachable_media_probes=${(result.probes || []).filter((p) => p.probe.classification.media && p.probe.classification.reachable).length}`,
  ] : profile === 'xiaohongshu-note' ? [
    `- note_ids=${result.noteIds?.join(', ') || 'none'}`,
    `- web_api_hints=${result.webApiHints?.length || 0}`,
    `- anti_bot_signals=${result.antiBotSignals?.join(', ') || 'none'}`,
    `- browser=${JSON.stringify(result.browser)}`,
  ] : [`- browser=${JSON.stringify(result.browser)}`]),
  '',
  '## Probe / API Matrix',
  ...(profile === 'bilibili-video'
    ? [
        ...(result.playurls || []).map((p) => `- playurl fnval=${p.fnval} status=${p.status} code=${p.code} quality=${p.quality} dash=${p.hasDash} durl=${p.durlCount}`),
        ...(result.probes || []).slice(0, 20).map((p) => `- media ${p.kind} id=${p.id || ''} reachable=${p.probe.classification.reachable} media=${p.probe.classification.media} url=${redactUrl(p.url)}`),
      ]
    : profile === 'xiaohongshu-note'
      ? (result.webApiHints || []).slice(0, 30).map((u) => `- ${u}`)
      : []),
  '',
  '## Verification',
  `- JSON: ${join(outDir, 'result.json')}`,
  result.browserArtifact ? `- Browser artifact: ${result.browserArtifact}` : '- Browser artifact: not generated',
  '- Media probes use HEAD or range requests only; no full video download is performed.',
  '',
  '## Next Step',
  ...(result.nextActions || []).map((x) => `- ${x}`),
  '',
].join('\n');
await writeFile(join(outDir, 'artifact.md'), md);
console.log(JSON.stringify({ target: result.target, profile, verdict: result.verdict, artifactDir: outDir, key: profile === 'bilibili-video' ? { bvid: result.bvid, cid: result.cid, mediaProbes: result.probes?.length || 0 } : result.browser }, null, 2));

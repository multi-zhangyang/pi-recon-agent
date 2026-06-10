#!/usr/bin/env node
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

const targetUrl = process.env.DOUYIN_SHARE_URL || process.argv[2];
const maxRedirects = Number(process.env.RECON_MAX_REDIRECTS || 10);
const maxProbeRedirects = Number(process.env.RECON_MAX_PROBE_REDIRECTS || 5);
const maxBodyBytes = Number(process.env.RECON_MAX_BODY_BYTES || 5_000_000);
const probeLimit = Number(process.env.RECON_PROBE_LIMIT || 28);
const probeBodyBytes = Number(process.env.RECON_PROBE_BODY_BYTES || 4096);
const browserMode = String(process.env.RECON_BROWSER || 'auto').toLowerCase(); // auto|1|0
const browserTimeoutMs = Number(process.env.RECON_BROWSER_TIMEOUT_MS || 45_000);
const browserQuietMs = Number(process.env.RECON_BROWSER_QUIET_MS || 2_500);
const apiProbe = /^(1|true|yes)$/i.test(process.env.RECON_API_PROBE || '');
const redactHeaders = !/^(0|false|no)$/i.test(process.env.RECON_REDACT_HEADERS || '1');
const chromeBin = process.env.RECON_CHROME_BIN || process.env.CHROME_BIN || '';
const userAgent = process.env.RECON_USER_AGENT ||
  'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Mobile Safari/537.36';

if (!targetUrl || targetUrl === '--help' || targetUrl === '-h') {
  console.log(`REPI Douyin no-watermark live benchmark\n\nUsage:\n  DOUYIN_SHARE_URL=<share-url> node bench/recon-remote/douyin-nowatermark/run.mjs\n  node bench/recon-remote/douyin-nowatermark/run.mjs <share-url>\n\nEnvironment:\n  RECON_BROWSER=auto|1|0        CDP capture through local Chrome; auto runs when static extraction is weak\n  RECON_BROWSER_TIMEOUT_MS=45000\n  RECON_BROWSER_QUIET_MS=2500\n  RECON_PROBE_LIMIT=28          Probe top media candidates with HEAD/range requests\n  RECON_PROBE_BODY_BYTES=4096   Bounded prefix bytes to hash for media Range probes\n  RECON_API_PROBE=1             Probe generated aweme detail endpoint hypotheses\n  RECON_MAX_REDIRECTS=10        Manual redirect chain limit\n  RECON_MAX_BODY_BYTES=5000000\n  RECON_USER_AGENT=<ua>\n  RECON_COOKIE=<cookie>         Optional runtime cookie, redacted in artifacts by default\n  RECON_EXTRA_HEADERS_JSON='{"x-foo":"bar"}'\n  RECON_CHROME_BIN=<path>\n\nOutput:\n  .repi-harness/evidence/remote/douyin-nowatermark/<timestamp>/\n`);
  process.exit(targetUrl ? 0 : 2);
}

function assertHttpUrl(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error(`Unsupported URL protocol: ${url.protocol}`);
  return url.toString();
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function safeJsonParse(value, fallback = {}) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function redactValue(value) {
  if (Array.isArray(value)) return value.map(() => '<redacted>');
  return value ? '<redacted>' : value;
}

function sanitizeHeaders(headers = {}) {
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    if (redactHeaders && /cookie|authorization|token|x-tt-token|passport|session|csrf|xsrf/i.test(key)) out[key] = redactValue(value);
    else out[key] = value;
  }
  return out;
}

function decodeLoose(value) {
  let out = String(value || '');
  for (let i = 0; i < 4; i++) {
    const before = out;
    out = out
      .replace(/\\u0026/g, '&')
      .replace(/\\u003d/g, '=')
      .replace(/\\u002f/gi, '/')
      .replace(/\\\//g, '/')
      .replace(/&quot;/g, '"')
      .replace(/&#34;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&#39;/g, "'")
      .replace(/&amp;/g, '&')
      .replace(/\u0026/g, '&')
      .replace(/\u003d/g, '=')
      .replace(/\u002f/gi, '/');
    try {
      out = decodeURIComponent(out);
    } catch {}
    if (out === before) break;
  }
  return out;
}

function unique(items) {
  return [...new Set(items.filter(Boolean))];
}

function normalizeUrlCandidate(value) {
  const decoded = decodeLoose(value)
    .replace(/^["'`]+|["'`]+$/g, '')
    .replace(/[),.;\]}]+$/g, '');
  try {
    const url = new URL(decoded);
    if (!['http:', 'https:'].includes(url.protocol)) return '';
    if (/[`"'{}]|\$\{/.test(decoded)) return '';
    return url.toString();
  } catch {
    return '';
  }
}

function extraHeaders() {
  const headers = safeJsonParse(process.env.RECON_EXTRA_HEADERS_JSON || '{}', {});
  if (process.env.RECON_COOKIE) headers.cookie = process.env.RECON_COOKIE;
  return headers;
}

function requestHeaders(extra = {}) {
  return {
    'user-agent': userAgent,
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7',
    'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'cache-control': 'no-cache',
    pragma: 'no-cache',
    referer: 'https://www.douyin.com/',
    ...extraHeaders(),
    ...extra,
  };
}

function responseHeaders(res) {
  return sanitizeHeaders(Object.fromEntries(res.headers.entries()));
}

async function readTextBody(res) {
  const type = res.headers.get('content-type') || '';
  if (!/text|json|javascript|html|xml|x-www-form-urlencoded/i.test(type)) return '';
  const buffer = Buffer.from(await res.arrayBuffer());
  return buffer.subarray(0, maxBodyBytes).toString('utf8');
}

async function readResponsePrefix(res, maxBytes) {
  const limit = Math.max(0, Number(maxBytes) || 0);
  if (!limit) return Buffer.alloc(0);
  const reader = res.body?.getReader?.();
  if (!reader) {
    const buffer = Buffer.from(await res.arrayBuffer());
    return buffer.subarray(0, limit);
  }
  const chunks = [];
  let total = 0;
  while (total < limit) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = Buffer.from(value);
    const take = Math.min(chunk.length, limit - total);
    if (take > 0) {
      chunks.push(chunk.subarray(0, take));
      total += take;
    }
    if (total >= limit) {
      try { await reader.cancel(); } catch {}
      break;
    }
  }
  return Buffer.concat(chunks, total);
}

async function fetchRedirectChain(url) {
  const chain = [];
  let current = assertHttpUrl(url);
  for (let i = 0; i <= maxRedirects; i++) {
    const res = await fetch(current, { redirect: 'manual', headers: requestHeaders() });
    const headers = responseHeaders(res);
    chain.push({ url: current, status: res.status, headers });
    const location = res.headers.get('location');
    if (![301, 302, 303, 307, 308].includes(res.status) || !location) {
      const body = await readTextBody(res);
      return { chain, finalUrl: current, finalStatus: res.status, finalHeaders: headers, body };
    }
    current = new URL(location, current).toString();
  }
  throw new Error(`redirect chain exceeded ${maxRedirects}`);
}

function extractUrls(text) {
  const raw = [];
  const patterns = [
    /https?:\\?\/\\?\/[^\s"'<>\\]+/g,
    /https?:\\u002f\\u002f[^\s"'<>\\]+/gi,
    /https?:%2f%2f[^\s"'<>\\]+/gi,
    /https%3a%2f%2f[^\s"'<>\\]+/gi,
  ];
  for (const pattern of patterns) {
    for (const match of String(text || '').matchAll(pattern)) raw.push(match[0]);
  }
  return unique(raw.map(normalizeUrlCandidate).filter(Boolean));
}

function isLikelyVideoId(value) {
  const id = String(value || '');
  // Douyin media vid values are usually long opaque tokens like v2800fgi0000...,
  // while frontend bundles contain many short emoji/static asset names in uri fields.
  return /^[a-zA-Z0-9_]{14,}$/.test(id) && /\d/.test(id) && !/^web_/i.test(id);
}

function extractIds(text, urls) {
  const blob = `${String(text || '')}\n${urls.join('\n')}`;
  const awemeIds = unique([
    ...[...blob.matchAll(/(?:aweme_id|item_id|modal_id|object_id|itemId|awemeId)["']?\s*[:=]\s*["']?([0-9]{8,})/gi)].map((m) => m[1]),
    ...[...blob.matchAll(/\/(?:video|share\/video)\/([0-9]{8,})/gi)].map((m) => m[1]),
    ...[...blob.matchAll(/item_ids=([0-9]{8,})/gi)].map((m) => m[1]),
    ...[...blob.matchAll(/__vid=([0-9]{8,})/gi)].map((m) => m[1]),
  ]);
  const videoIds = unique([
    ...[...blob.matchAll(/(?:video_id|videoId|vid)["']?\s*[:=]\s*["']?([a-zA-Z0-9_]{8,})/g)].map((m) => m[1]),
    ...[...blob.matchAll(/(?:playAddrUri|play_addr_uri)["']?\s*[:=]\s*["']?([a-zA-Z0-9_]{8,})/g)].map((m) => m[1]),
  ].filter(isLikelyVideoId));
  return { awemeIds, videoIds };
}

function extractStateHints(text) {
  const blob = String(text || '');
  const hints = [];
  const named = [
    ['RENDER_DATA', /id=["']RENDER_DATA["'][^>]*>([\s\S]*?)<\/script>/i],
    ['SIGI_STATE', /id=["']SIGI_STATE["'][^>]*>([\s\S]*?)<\/script>/i],
    ['NEXT_DATA', /id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i],
  ];
  for (const [name, pattern] of named) {
    const match = blob.match(pattern);
    if (match?.[1]) hints.push({ name, sha256: sha256(match[1]).slice(0, 24), length: match[1].length, head: decodeLoose(match[1]).slice(0, 800) });
  }
  for (const key of ['play_addr', 'playAddr', 'download_addr', 'downloadAddr', 'video_id', 'aweme_id', 'playwm']) {
    const index = blob.indexOf(key);
    if (index >= 0) hints.push({ name: `keyword:${key}`, index, head: decodeLoose(blob.slice(Math.max(0, index - 180), index + 800)) });
  }
  return hints.slice(0, 30);
}

function scoreCandidate(url, context = '') {
  const lower = `${url} ${context}`.toLowerCase();
  let score = 0;
  if (/\.mp4(?:\?|$)|\.m3u8(?:\?|$)|mime_type=video|mime_type=video_mp4|video_id=|\/play\//i.test(url)) score += 5;
  if (/douyin|byte|bytedance|snssdk|pstatp|ixigua|toutiao|akamaized|byteimg|bytecdn|amemv/.test(lower)) score += 2;
  if (/playaddr|play_addr|play_url|playapi|downloadaddr|download_addr|bit_rate|video_id=|mime_type=video|\/aweme\/v1\/play/i.test(lower)) score += 3;
  if (/aweme|iteminfo|detail|feed|post/.test(lower)) score += 1;
  if (/cover|avatar|image|jpeg|jpg|png|webp|music|audio|css|font|svg|favicon|captcha|verify/.test(lower)) score -= 4;
  if (/\.(?:js|css|png|jpe?g|webp|svg|gif|woff2?)(?:\?|$)|\/static\/js\/|secsdk|security|monitor_browser|slardar|collect\//i.test(lower)) score -= 10;
  if (/douyin_pc_client|weboff|douyinstatic|bytednsdoc.*download|static-resource|app-download|download\/douyin/i.test(lower)) score -= 8;
  if (/watermark|playwm|wm=|watermarked/.test(lower)) score -= 2;
  if (/playwm/.test(lower)) score += 1; // useful transformation source even if watermarked
  return score;
}

function buildTransformHypotheses(urls) {
  const out = [];
  for (const url of urls) {
    const lower = url.toLowerCase();
    const variants = new Set();
    if (lower.includes('/playwm/')) variants.add(url.replace(/\/playwm\//i, '/play/'));
    if (lower.includes('playwm')) variants.add(url.replace(/playwm/ig, 'play'));
    if (/watermark=1/i.test(url)) variants.add(url.replace(/watermark=1/ig, 'watermark=0'));
    if (/wm=1/i.test(url)) variants.add(url.replace(/wm=1/ig, 'wm=0'));
    if (/logo_name=/i.test(url)) {
      const parsed = new URL(url);
      parsed.searchParams.delete('logo_name');
      variants.add(parsed.toString());
    }
    for (const variant of variants) {
      if (variant !== url) out.push({ source: url, hypothesis: variant, reason: 'watermark-to-play candidate transform' });
    }
  }
  return unique(out.map((x) => JSON.stringify(x))).map((x) => JSON.parse(x));
}

function buildApiHypotheses(ids) {
  const out = [];
  for (const id of ids.awemeIds || []) {
    out.push({
      awemeId: id,
      url: `https://www.douyin.com/aweme/v1/web/aweme/detail/?aweme_id=${encodeURIComponent(id)}&device_platform=webapp&aid=6383&channel=channel_pc_web`,
      reason: 'web aweme detail endpoint hypothesis',
    });
    out.push({
      awemeId: id,
      url: `https://www.iesdouyin.com/web/api/v2/aweme/iteminfo/?item_ids=${encodeURIComponent(id)}`,
      reason: 'legacy iteminfo endpoint hypothesis',
    });
  }
  return unique(out.map((x) => JSON.stringify(x))).map((x) => JSON.parse(x));
}

async function fetchApiHypotheses(hypotheses) {
  const results = [];
  for (const hypothesis of hypotheses.slice(0, Math.min(8, probeLimit))) {
    try {
      const res = await fetch(hypothesis.url, { headers: requestHeaders({ accept: 'application/json,text/plain,*/*' }), redirect: 'manual' });
      const body = await readTextBody(res);
      results.push({ ...hypothesis, status: res.status, headers: responseHeaders(res), bodySha256: sha256(body).slice(0, 24), bodyHead: body.slice(0, 1500), urls: extractUrls(body), ids: extractIds(body, extractUrls(body)) });
    } catch (error) {
      results.push({ ...hypothesis, status: 'error', error: error instanceof Error ? error.message : String(error) });
    }
  }
  return results;
}

async function probeOnce(url, method, headers = {}) {
  const res = await fetch(url, { method, redirect: 'manual', headers: requestHeaders(headers) });
  const attempt = {
    url,
    method: method === 'GET' && headers.range ? `GET ${headers.range}` : method,
    status: res.status,
    headers: responseHeaders(res),
  };
  if (method === 'GET') {
    const buffer = await readResponsePrefix(res, probeBodyBytes);
    attempt.bytes = buffer.length;
    attempt.bodySha256 = sha256(buffer).slice(0, 24);
  }
  return attempt;
}

function isProbeMediaLike(attempt) {
  const headers = attempt?.headers || {};
  const status = Number(attempt?.status);
  const type = String(headers['content-type'] || '').toLowerCase();
  const text = `${attempt?.url || ''} ${headers.location || ''} ${type}`.toLowerCase();
  const staticAsset = /javascript|text\/css|image\/|font\/|\.(?:js|css|png|jpe?g|webp|svg|gif|woff2?)(?:\?|$)/i.test(text);
  return !staticAsset && [200, 206].includes(status) && (
    /video\//.test(type) ||
    /octet-stream|mpegurl|application\/vnd\.apple\.mpegurl|mp4/.test(type) ||
    /\.mp4(?:\?|$)|\.m3u8(?:\?|$)|mime_type=video|mime_type=video_mp4|\/video\/tos\//i.test(text)
  );
}

function summarizeProbeBytes(attempts) {
  const bodyAttempt = (attempts || []).find((attempt) => Number(attempt.bytes || 0) > 0 && (attempt.bodySha256 || attempt.sha256));
  return {
    bodyProof: Boolean(bodyAttempt),
    bodySha256: bodyAttempt?.bodySha256 || bodyAttempt?.sha256 || '',
    bodyBytes: Number(bodyAttempt?.bytes || 0),
    range206: (attempts || []).some((attempt) => Number(attempt.status) === 206 || /bytes/i.test(attempt.headers?.['content-range'] || '')),
  };
}

async function probeUrl(url) {
  const attempts = [];
  let current = url;
  for (let i = 0; i <= maxProbeRedirects; i++) {
    try {
      const head = await probeOnce(current, 'HEAD');
      attempts.push(head);
      const location = head.headers?.location;
      if ([301, 302, 303, 307, 308].includes(Number(head.status)) && location) {
        current = new URL(location, current).toString();
        continue;
      }
      if (isProbeMediaLike(head)) {
        try {
          const ranged = await probeOnce(current, 'GET', { range: `bytes=0-${Math.max(0, probeBodyBytes - 1)}` });
          attempts.push(ranged);
        } catch (error) {
          attempts.push({ url: current, method: `GET bytes=0-${Math.max(0, probeBodyBytes - 1)}`, status: 'error', error: error instanceof Error ? error.message : String(error) });
        }
      } else {
        try {
          const ranged = await probeOnce(current, 'GET', { range: 'bytes=0-0' });
          attempts.push(ranged);
        } catch (error) {
          attempts.push({ url: current, method: 'GET bytes=0-0', status: 'error', error: error instanceof Error ? error.message : String(error) });
        }
      }
      break;
    } catch (error) {
      attempts.push({ url: current, method: 'HEAD', status: 'error', error: error instanceof Error ? error.message : String(error) });
      try {
        attempts.push(await probeOnce(current, 'GET', { range: 'bytes=0-0' }));
      } catch (rangeError) {
        attempts.push({ url: current, method: 'GET bytes=0-0', status: 'error', error: rangeError instanceof Error ? rangeError.message : String(rangeError) });
      }
      break;
    }
  }
  return { url, attempts, finalAttempt: attempts.at(-1) || null, ...summarizeProbeBytes(attempts) };
}

function classifyProbe(probe) {
  const attempts = probe.attempts || [];
  const text = attempts.map((attempt) => {
    const headers = attempt.headers || {};
    return `${attempt.url || ''} ${headers.location || ''} ${headers['content-type'] || ''} ${headers['content-range'] || ''}`;
  }).join(' ').toLowerCase();
  const typeText = attempts.map((attempt) => String(attempt.headers?.['content-type'] || '')).join(' ').toLowerCase();
  const finalUrlText = attempts.map((attempt) => `${attempt.url || ''} ${attempt.headers?.location || ''}`).join(' ').toLowerCase();
  const staticAsset = /javascript|text\/css|image\/|font\/|\.(?:js|css|png|jpe?g|webp|svg|gif|woff2?)(?:\?|$)/i.test(typeText + ' ' + finalUrlText);
  const video = !staticAsset && (
    /video\//.test(typeText) ||
    /mpegurl|application\/vnd\.apple\.mpegurl/.test(typeText) ||
    /\.mp4(?:\?|$)|\.m3u8(?:\?|$)|mime_type=video|mime_type=video_mp4/.test(finalUrlText) ||
    /\/video\/tos\//.test(finalUrlText)
  );
  const noWatermarkLikely = video && !/watermark|playwm|watermarked/.test(text);
  const reachable = attempts.some((attempt) => [200, 206, 301, 302, 303, 307, 308].includes(Number(attempt.status)));
  const bytes = summarizeProbeBytes(attempts);
  return { video, noWatermarkLikely, reachable, byteProof: bytes.bodyProof, range206: bytes.range206 };
}

async function which(command) {
  const paths = (process.env.PATH || '').split(':');
  for (const dir of paths) {
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

async function waitForDevToolsPort(profileDir, timeoutMs) {
  const file = join(profileDir, 'DevToolsActivePort');
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const text = await readFile(file, 'utf8');
      const [port] = text.trim().split(/\s+/);
      if (port) return Number(port);
    } catch {}
    await sleep(100);
  }
  throw new Error(`Chrome DevToolsActivePort not created within ${timeoutMs}ms`);
}

async function cdpHttp(port, path, init = {}) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, init);
  const text = await res.text();
  if (!res.ok) throw new Error(`CDP HTTP ${res.status} ${path}: ${text.slice(0, 200)}`);
  return JSON.parse(text);
}

async function createCdpTarget(port) {
  try {
    return await cdpHttp(port, `/json/new?${encodeURIComponent('about:blank')}`, { method: 'PUT' });
  } catch {
    const list = await cdpHttp(port, '/json/list');
    const page = list.find((item) => item.type === 'page' && item.webSocketDebuggerUrl) || list.find((item) => item.webSocketDebuggerUrl);
    if (!page) throw new Error('no CDP page target available');
    return page;
  }
}

function createCdpClient(wsUrl, artifact) {
  const ws = new WebSocket(wsUrl);
  let id = 0;
  let closing = false;
  const pending = new Map();
  ws.onmessage = (event) => {
    const message = safeJsonParse(String(event.data), null);
    if (!message) return;
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(JSON.stringify(message.error)));
      else resolve(message.result || {});
      return;
    }
    if (message.method) handleCdpEvent(message, artifact);
  };
  ws.onerror = (event) => {
    if (!closing) artifact.errors.push({ type: 'websocket', message: String(event?.message || 'cdp websocket error') });
  };
  const open = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('CDP websocket open timeout')), 10_000);
    ws.onopen = () => { clearTimeout(timer); resolve(); };
  });
  async function send(method, params = {}) {
    await open;
    const requestId = ++id;
    ws.send(JSON.stringify({ id: requestId, method, params }));
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(requestId);
        reject(new Error(`CDP command timeout: ${method}`));
      }, 12_000);
      pending.set(requestId, {
        resolve: (value) => { clearTimeout(timer); resolve(value); },
        reject: (error) => { clearTimeout(timer); reject(error); },
      });
    });
  }
  async function close() {
    closing = true;
    try { ws.close(); } catch {}
  }
  return { send, close, open };
}

function handleCdpEvent(message, artifact) {
  const p = message.params || {};
  if (message.method === 'Network.requestWillBeSent') {
    artifact.requests.push({
      id: p.requestId,
      loaderId: p.loaderId,
      type: p.type,
      documentURL: p.documentURL,
      timestamp: p.timestamp,
      wallTime: p.wallTime,
      method: p.request?.method,
      url: p.request?.url,
      headers: sanitizeHeaders(p.request?.headers || {}),
      replayHeaders: p.request?.headers || {},
      postData: p.request?.postData ? '<captured-post-data>' : undefined,
      initiator: p.initiator?.type,
    });
  } else if (message.method === 'Network.responseReceived') {
    const response = p.response || {};
    artifact.responses.push({
      id: p.requestId,
      type: p.type,
      url: response.url,
      status: response.status,
      mimeType: response.mimeType,
      headers: sanitizeHeaders(response.headers || {}),
      remoteIPAddress: response.remoteIPAddress,
      encodedDataLength: response.encodedDataLength,
      fromDiskCache: response.fromDiskCache,
    });
  } else if (message.method === 'Network.loadingFailed') {
    artifact.failures.push({ id: p.requestId, type: p.type, errorText: p.errorText, canceled: p.canceled });
  } else if (message.method === 'Network.webSocketCreated') {
    artifact.websockets.push({ id: p.requestId, url: p.url });
  } else if (message.method === 'Network.webSocketFrameSent' || message.method === 'Network.webSocketFrameReceived') {
    artifact.wsFrames.push({ id: p.requestId, direction: message.method.endsWith('Sent') ? 'sent' : 'recv', payloadHead: String(p.response?.payloadData || '').slice(0, 1200) });
  } else if (message.method === 'Page.loadEventFired') {
    artifact.pageEvents.push({ event: 'load', timestamp: p.timestamp });
  } else if (message.method === 'Page.domContentEventFired') {
    artifact.pageEvents.push({ event: 'domcontentloaded', timestamp: p.timestamp });
  }
}

async function captureResponseBodies(client, artifact) {
  const responses = artifact.responses.filter((response) => /json|text|html|javascript|xml|x-www-form-urlencoded/i.test(response.mimeType || '')).slice(-80);
  for (const response of responses) {
    if (artifact.bodies.some((body) => body.id === response.id)) continue;
    try {
      const body = await client.send('Network.getResponseBody', { requestId: response.id });
      const text = body.base64Encoded ? Buffer.from(body.body || '', 'base64').toString('utf8') : String(body.body || '');
      artifact.bodies.push({
        id: response.id,
        url: response.url,
        mimeType: response.mimeType,
        base64Encoded: Boolean(body.base64Encoded),
        length: text.length,
        sha256: sha256(text).slice(0, 24),
        text: text.slice(0, Math.min(maxBodyBytes, 500_000)),
      });
    } catch (error) {
      artifact.bodyErrors.push({ id: response.id, url: response.url, error: error instanceof Error ? error.message : String(error) });
    }
  }
}

async function runtimeEvaluate(client, expression) {
  const result = await client.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true, timeout: 8_000 });
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails).slice(0, 600));
  return result.result?.value;
}

async function captureChromeCdp(url, outDir) {
  const chrome = await resolveChrome();
  const artifact = {
    mode: 'chrome-cdp',
    chrome: chrome || 'missing',
    target: url,
    capturedAt: new Date().toISOString(),
    requests: [],
    responses: [],
    failures: [],
    websockets: [],
    wsFrames: [],
    bodies: [],
    bodyErrors: [],
    pageEvents: [],
    storage: {},
    errors: [],
    skipped: false,
  };
  if (!chrome) {
    artifact.skipped = true;
    artifact.skipReason = 'chrome binary not found';
    return artifact;
  }
  const profileDir = join(outDir, `chrome-profile-${randomUUID()}`);
  await mkdir(profileDir, { recursive: true });
  const args = [
    '--headless=new',
    '--remote-debugging-port=0',
    `--user-data-dir=${profileDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--no-sandbox',
    'about:blank',
  ];
  const child = spawn(chrome, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += String(chunk).slice(0, 2000); });
  try {
    const port = await waitForDevToolsPort(profileDir, 10_000);
    artifact.devtoolsPort = port;
    const target = await createCdpTarget(port);
    const client = createCdpClient(target.webSocketDebuggerUrl, artifact);
    await client.open;
    await client.send('Page.enable');
    await client.send('Runtime.enable');
    await client.send('Network.enable', { maxTotalBufferSize: 50_000_000, maxResourceBufferSize: 5_000_000 });
    await client.send('Network.setUserAgentOverride', { userAgent });
    const headers = { ...extraHeaders(), Referer: 'https://www.douyin.com/' };
    if (Object.keys(headers).length) await client.send('Network.setExtraHTTPHeaders', { headers });
    await client.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `(() => {\n        window.__PI_RECON_FETCH_LOG__ = [];\n        const oldFetch = window.fetch;\n        window.fetch = function(input, init) {\n          try { window.__PI_RECON_FETCH_LOG__.push({ kind: 'fetch', url: String(input && input.url || input), method: init && init.method || 'GET', at: Date.now() }); } catch {}\n          return oldFetch.apply(this, arguments);\n        };\n        const oldOpen = XMLHttpRequest.prototype.open;\n        XMLHttpRequest.prototype.open = function(method, url) {\n          try { window.__PI_RECON_FETCH_LOG__.push({ kind: 'xhr', method, url: String(url), at: Date.now() }); } catch {}\n          return oldOpen.apply(this, arguments);\n        };\n      })();`,
    });
    await client.send('Page.navigate', { url });
    const deadline = Date.now() + browserTimeoutMs;
    let lastCount = -1;
    let lastChange = Date.now();
    while (Date.now() < deadline) {
      const count = artifact.requests.length + artifact.responses.length + artifact.failures.length;
      if (count !== lastCount) {
        lastCount = count;
        lastChange = Date.now();
      }
      if (artifact.pageEvents.some((event) => event.event === 'load') && Date.now() - lastChange >= browserQuietMs) break;
      await sleep(250);
    }
    await captureResponseBodies(client, artifact);
    artifact.storage = safeJsonParse(await runtimeEvaluate(client, `JSON.stringify((() => {\n      const selected = {};\n      for (const key of Object.keys(window)) {\n        if (/INITIAL|RENDER|SIGI|STATE|DATA|aweme|video|douyin|item/i.test(key)) {\n          try { selected[key] = JSON.stringify(window[key]).slice(0, 200000); } catch (e) { selected[key] = String(window[key]).slice(0, 2000); }\n        }\n      }\n      const scripts = Array.from(document.querySelectorAll('script')).map((script, index) => ({ index, id: script.id || '', type: script.type || '', text: script.textContent || '' }))\n        .filter(script => /json|ld\+json|SIGI|RENDER|NEXT|INITIAL|STATE/i.test(script.id + ' ' + script.type + ' ' + script.text.slice(0, 120)))\n        .slice(0, 25)\n        .map(script => ({ ...script, sha256: '', text: script.text.slice(0, 200000) }));\n      return {\n        href: location.href,\n        title: document.title,\n        localStorage: { ...localStorage },\n        sessionStorage: { ...sessionStorage },\n        piReconFetchLog: window.__PI_RECON_FETCH_LOG__ || [],\n        selectedWindowState: selected,\n        scripts,\n      };\n    })())`), {});
    try {
      const allCookies = await client.send('Network.getAllCookies');
      const scopedCookies = (allCookies.cookies || []).filter((cookie) => {
        const domain = String(cookie.domain || '').replace(/^\./, '');
        return domain && /douyin|bytedance|zijieapi|mssdk|snssdk|iesdouyin/i.test(domain);
      });
      artifact.storage.cookieNames = scopedCookies.map((cookie) => cookie.name).slice(0, 80);
      artifact.storage.cookieHeader = scopedCookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ');
    } catch (error) {
      artifact.errors.push({ type: 'cookies', message: error instanceof Error ? error.message : String(error) });
    }
    artifact.finalUrl = artifact.storage.href;
    artifact.html = String(await runtimeEvaluate(client, 'document.documentElement ? document.documentElement.outerHTML : document.body.innerHTML')).slice(0, maxBodyBytes);
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

function textSourcesFromBrowser(browser) {
  if (!browser || browser.skipped) return [];
  const sources = [];
  if (browser.html) sources.push({ name: 'browser.html', text: browser.html });
  for (const body of browser.bodies || []) sources.push({ name: `browser.body:${body.url}`, text: body.text || '' });
  sources.push({ name: 'browser.storage', text: JSON.stringify(browser.storage || {}) });
  sources.push({ name: 'browser.urls', text: [...(browser.requests || []).map((x) => x.url), ...(browser.responses || []).map((x) => x.url)].join('\n') });
  return sources;
}

function redactUrlParams(value) {
  try {
    const url = new URL(String(value || ''));
    for (const key of [...url.searchParams.keys()]) {
      if (/token|msToken|a_bogus|webid|web_id|device_id|user_cip|verifyFp|fp|ttwid|signature|x-bogus|sec_user|sec_uid|reflow_id|passport|session|csrf|xsrf/i.test(key)) url.searchParams.set(key, 'REDACTED');
    }
    return url.toString();
  } catch {
    return String(value || '').replace(/((?:msToken|a_bogus|webid|web_id|device_id|user_cip|verifyFp|fp|ttwid|_signature|X-Bogus|sec_uid|reflow_id)=)[^&\s"']+/gi, '$1REDACTED');
  }
}

function redactSnippet(value) {
  return String(value || '')
    .replace(/((?:msToken|a_bogus|webid|verifyFp|fp|ttwid|_signature|X-Bogus|token|cookie)[\"']?\s*[:=]\s*[\"']?)([^\"'&\s<>\\]+)/gi, '$1<redacted>')
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '<redacted.jwt>');
}

function compactSnippet(text, term, radius = 120) {
  const source = String(text || '');
  const index = source.toLowerCase().indexOf(String(term || '').toLowerCase());
  if (index < 0) return '';
  return redactSnippet(source.slice(Math.max(0, index - radius), Math.min(source.length, index + String(term).length + radius))).replace(/\s+/g, ' ').slice(0, radius * 2 + 80);
}

function analyzeSignatureSurface(sources, urls, browserArtifact, apiHypotheses) {
  const terms = ['a_bogus', 'msToken', 'webid', 'web_id', 'device_id', 'verifyFp', 'fp', 'ttwid', 's_v_web_id', 'X-Bogus', '_signature', 'sec_user_id', 'sec_uid', 'passport_csrf_token', 'odin_tt'];
  const urlParamMatrix = [];
  for (const candidate of urls || []) {
    try {
      const parsed = new URL(candidate);
      const hits = [...parsed.searchParams.keys()].filter((key) => terms.some((term) => key.toLowerCase() === term.toLowerCase()));
      if (hits.length) urlParamMatrix.push({ url: redactUrlParams(candidate), params: hits.sort() });
    } catch {}
  }
  const joined = sources.map((source) => source.text || '').join('\n');
  const signals = unique(terms.filter((term) => new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i').test(joined) || urlParamMatrix.some((item) => item.params.some((p) => p.toLowerCase() === term.toLowerCase()))));
  const runtimeFetchHits = unique((browserArtifact?.storage?.piReconFetchLog || [])
    .map((item) => item.url)
    .filter((url) => /msToken|a_bogus|webid|verifyFp|X-Bogus|aweme|detail|iteminfo|feed|post/i.test(url || ''))
    .map(redactUrlParams))
    .slice(0, 60);
  const bundleHints = sources
    .filter((source) => /browser\.body:.*(?:\.m?js|javascript|douyin|secsdk|webmssdk|slardar|security)/i.test(source.name))
    .map((source) => {
      const hits = unique(terms.filter((term) => source.text.toLowerCase().includes(term.toLowerCase())));
      if (!hits.length) return null;
      return {
        source: redactUrlParams(source.name.replace(/^browser\.body:/, '')),
        sha256: sha256(source.text).slice(0, 24),
        length: source.text.length,
        hits,
        snippets: hits.slice(0, 5).map((term) => ({ term, snippet: compactSnippet(source.text, term) })),
      };
    })
    .filter(Boolean)
    .slice(0, 20);
  const endpointParamMatrix = unique((apiHypotheses || []).map((item) => {
    const parsed = new URL(item.url);
    return JSON.stringify({ reason: item.reason, endpoint: `${parsed.origin}${parsed.pathname}`, params: [...parsed.searchParams.keys()].sort() });
  })).map((item) => JSON.parse(item));
  return {
    signals,
    antiBotSignals: signals.filter((signal) => /a_bogus|msToken|webid|verifyFp|fp|ttwid|X-Bogus|_signature|passport|odin/i.test(signal)),
    urlParamMatrix: urlParamMatrix.slice(0, 80),
    runtimeFetchHits,
    bundleHints,
    endpointParamMatrix,
  };
}

function douyinApiShape(text = '') {
  const parsed = safeJsonParse(text, null);
  const awemeList = Array.isArray(parsed?.aweme_list) ? parsed.aweme_list : [];
  const itemList = Array.isArray(parsed?.item_list) ? parsed.item_list : [];
  const awemeDetail = parsed?.aweme_detail || parsed?.item || null;
  const statusCode = parsed?.status_code ?? parsed?.statusCode ?? parsed?.code;
  const awemeIds = unique([
    ...awemeList.map((item) => item?.aweme_id || item?.item_id).filter(Boolean),
    ...itemList.map((item) => item?.aweme_id || item?.item_id).filter(Boolean),
    awemeDetail?.aweme_id || awemeDetail?.item_id,
  ].filter(Boolean).map(String));
  const body = JSON.stringify(parsed || {}).slice(0, 200_000);
  const mediaUrlCount = (body.match(/https?:\/\/[^"'\\]+(?:douyinpic|douyinvod|byteimg|ixigua|pstatp|snssdk)[^"'\\]*/gi) || []).length;
  const challengeText = String(parsed?.status_msg || parsed?.msg || parsed?.message || '');
  const structured = Boolean(
    parsed &&
    (awemeList.length || itemList.length || awemeDetail || /aweme_id|play_addr|download_addr|video|desc|sec_uid/i.test(body)) &&
    !/encrypt_data_miss|captcha|verify|forbid|blocked/i.test(challengeText)
  );
  return {
    structured,
    statusCode,
    awemeCount: awemeIds.length || awemeList.length || itemList.length || (awemeDetail ? 1 : 0),
    awemeIds: awemeIds.slice(0, 20),
    mediaUrlCount,
  };
}

function isDouyinRuntimeApi(request) {
  const url = request?.url || '';
  if (String(request?.method || 'GET').toUpperCase() !== 'GET') return false;
  return /\/web\/api\/v2\/aweme\/post\/|\/aweme\/v1\/web\/aweme\/detail\/|\/web\/api\/v2\/aweme\/iteminfo\//i.test(url)
    || (/aweme|iteminfo|detail|post/i.test(url) && /a_bogus|msToken|web_id|webid|device_id/i.test(url));
}

function douyinReplayHeaders(seed, variant, browser) {
  const headers = { ...(seed.replayHeaders || seed.headers || {}) };
  for (const key of Object.keys(headers)) {
    if (/^(host|content-length|accept-encoding|connection|cookie)$/i.test(key) || /^:/.test(key) || /^sec-fetch-/i.test(key)) delete headers[key];
    else if (String(headers[key]).includes('<redacted>')) delete headers[key];
  }
  headers['user-agent'] = headers['user-agent'] || headers['User-Agent'] || userAgent;
  headers.accept = headers.accept || headers.Accept || 'application/json,text/plain,*/*';
  headers.referer = headers.referer || headers.Referer || browser?.finalUrl || browser?.target || 'https://www.douyin.com/';
  if (variant === 'exact-cookie' && browser?.storage?.cookieHeader) headers.cookie = browser.storage.cookieHeader;
  return headers;
}

async function replayDouyinRuntimeApis(browser) {
  if (!browser || browser.skipped) return { attempted: false, reason: 'browser not captured' };

  const seeds = unique((browser.requests || []).filter(isDouyinRuntimeApi).map((request) => request.id))
    .map((id) => {
      const request = (browser.requests || []).find((item) => item.id === id);
      const response = (browser.responses || []).find((item) => item.id === id);
      const body = (browser.bodies || []).find((item) => item.id === id);
      return { request, response, body, observedShape: douyinApiShape(body?.text || '') };
    })
    .filter((item) => item.request)
    .sort((a, b) =>
      (b.observedShape.structured ? 1 : 0) - (a.observedShape.structured ? 1 : 0) ||
      (b.body?.length || 0) - (a.body?.length || 0) ||
      Number(b.response?.status || 0) - Number(a.response?.status || 0)
    )
    .slice(0, Number(process.env.RECON_DOUYIN_RUNTIME_API_LIMIT || 4));

  if (!seeds.length) return { attempted: false, reason: 'no runtime signed API seed captured' };

  const attempts = [];
  for (const seed of seeds) {
    for (const variant of ['no-cookie', 'exact-cookie']) {
      const headers = douyinReplayHeaders(seed.request, variant, browser);
      try {
        const response = await fetch(seed.request.url, { method: 'GET', redirect: 'manual', headers });
        const buffer = Buffer.from(await response.arrayBuffer());
        const fullText = buffer.subarray(0, 500_000).toString('utf8');
        const text = fullText.slice(0, 3000);
        const bodySha256 = sha256(buffer);
        const shape = douyinApiShape(fullText);
        attempts.push({
          variant,
          url: redactUrlParams(seed.request.url),
          status: response.status,
          headers: responseHeaders(response),
          bytes: buffer.length,
          sha256: bodySha256.slice(0, 24),
          structured: shape,
          observed: {
            status: seed.response?.status,
            mimeType: seed.response?.mimeType,
            bodySha256: seed.body?.sha256,
            structured: seed.observedShape,
          },
          divergence: seed.response ? {
            statusChanged: Number(seed.response.status) !== Number(response.status),
            observedStatus: seed.response.status,
            replayStatus: response.status,
            observedBodySha256: seed.body?.sha256,
            replayBodySha256: bodySha256.slice(0, 24),
          } : undefined,
          bodyHead: redactSnippet(text).slice(0, 800),
        });
      } catch (error) {
        attempts.push({
          variant,
          url: redactUrlParams(seed.request.url),
          status: 'error',
          error: error instanceof Error ? error.message : String(error),
          observed: {
            status: seed.response?.status,
            bodySha256: seed.body?.sha256,
            structured: seed.observedShape,
          },
        });
      }
    }
  }

  const observedStructured = seeds.find((seed) =>
    Number(seed.response?.status || 0) >= 200 && Number(seed.response?.status || 0) < 300 && seed.observedShape.structured
  ) || null;
  const bestReplay = attempts.find((item) =>
    Number(item.status) >= 200 && Number(item.status) < 300 && item.structured?.structured
  ) || null;
  const firstDivergence = attempts.find((item) =>
    item.divergence?.statusChanged ||
    (item.divergence?.observedBodySha256 && item.divergence.observedBodySha256 !== item.divergence.replayBodySha256)
  ) || null;

  return {
    attempted: true,
    seedCount: seeds.length,
    attemptCount: attempts.length,
    cookieNames: (browser.storage?.cookieNames || []).slice(0, 30),
    observedStructuredApi: observedStructured ? {
      url: redactUrlParams(observedStructured.request.url),
      status: observedStructured.response?.status,
      bodySha256: observedStructured.body?.sha256,
      structured: observedStructured.observedShape,
      bodyHead: redactSnippet(observedStructured.body?.text || '').slice(0, 800),
    } : null,
    bestReplayedStructuredApi: bestReplay ? {
      variant: bestReplay.variant,
      url: bestReplay.url,
      status: bestReplay.status,
      structured: bestReplay.structured,
      bodyHead: bestReplay.bodyHead,
    } : null,
    firstDivergence: firstDivergence ? {
      variant: firstDivergence.variant,
      url: firstDivergence.url,
      status: firstDivergence.status,
      structured: firstDivergence.structured,
      observed: firstDivergence.observed,
      divergence: firstDivergence.divergence,
      bodyHead: firstDivergence.bodyHead,
      error: firstDivergence.error,
    } : null,
    attempts: attempts.map((item) => ({
      variant: item.variant,
      url: item.url,
      status: item.status,
      bytes: item.bytes,
      sha256: item.sha256,
      structured: item.structured,
      observed: item.observed,
      divergence: item.divergence,
      bodyHead: item.bodyHead,
      error: item.error,
    })),
  };
}

function sanitizeBrowserArtifactForDisk(browser) {
  if (!browser) return browser;
  const redactObject = (value) => {
    if (Array.isArray(value)) return value.map(redactObject);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, /cookie|token|session|csrf|passport|ttwid|msToken|a_bogus|webid|web_id|device_id|sec_uid|reflow_id|verifyFp/i.test(key) ? '<redacted>' : redactObject(inner)]));
    return typeof value === 'string' ? redactSnippet(redactUrlParams(value)).slice(0, 200000) : value;
  };
  return {
    ...browser,
    target: redactUrlParams(browser.target),
    finalUrl: redactUrlParams(browser.finalUrl),
    requests: (browser.requests || []).map((request) => {
      const { replayHeaders, ...safeRequest } = request;
      return { ...safeRequest, url: redactUrlParams(request.url), documentURL: redactUrlParams(request.documentURL), headers: sanitizeHeaders(request.headers || {}) };
    }),
    responses: (browser.responses || []).map((response) => ({ ...response, url: redactUrlParams(response.url), headers: sanitizeHeaders(response.headers || {}) })),
    websockets: (browser.websockets || []).map((ws) => ({ ...ws, url: redactUrlParams(ws.url) })),
    bodies: (browser.bodies || []).map((body) => ({ ...body, url: redactUrlParams(body.url), text: redactSnippet(body.text || '').slice(0, 500000) })),
    storage: redactObject(browser.storage || {}),
    html: redactSnippet(browser.html || '').slice(0, maxBodyBytes),
  };
}

function shouldRunBrowser(prelim) {
  if (browserMode === '0' || browserMode === 'false' || browserMode === 'off') return false;
  if (browserMode === '1' || browserMode === 'true' || browserMode === 'on') return true;
  return !prelim.mediaCandidates.some((item) => item.score >= 7) || prelim.ids.awemeIds.length === 0;
}

function buildPrelim(text, urls) {
  const ids = extractIds(text, urls);
  const mediaCandidates = urls
    .map((url) => ({ url, score: scoreCandidate(url) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score || a.url.localeCompare(b.url));
  return { ids, mediaCandidates };
}

const started = Date.now();
const outDir = join('.repi-harness', 'evidence', 'remote', 'douyin-nowatermark', timestamp());
await mkdir(outDir, { recursive: true });

let staticResult;
try {
  staticResult = await fetchRedirectChain(targetUrl);
} catch (error) {
  const message = error instanceof Error ? error.stack || error.message : String(error);
  await writeFile(join(outDir, 'error.txt'), message);
  console.error(message);
  process.exit(1);
}

const initialUrls = extractUrls(staticResult.body).concat(staticResult.finalUrl);
const prelim = buildPrelim(`${staticResult.body}\n${staticResult.finalUrl}`, unique(initialUrls));
let browserArtifact = null;
if (shouldRunBrowser(prelim)) {
  browserArtifact = await captureChromeCdp(staticResult.finalUrl || targetUrl, outDir);
  const safeBrowserArtifact = sanitizeBrowserArtifactForDisk(browserArtifact);
  await writeFile(join(outDir, 'browser.json'), `${JSON.stringify(safeBrowserArtifact, null, 2)}\n`);
  if (safeBrowserArtifact?.html) await writeFile(join(outDir, 'browser.html'), safeBrowserArtifact.html);
}

const sources = [
  { name: 'static.body', text: staticResult.body },
  { name: 'static.finalUrl', text: staticResult.finalUrl },
  ...textSourcesFromBrowser(browserArtifact),
];
const allText = sources.map((source) => `\n/* ${source.name} */\n${source.text}`).join('\n');
let urls = unique(sources.flatMap((source) => extractUrls(source.text)).concat(staticResult.finalUrl));
let ids = extractIds(allText, urls);
const apiHypotheses = buildApiHypotheses(ids);
let apiProbeResults = [];
if (apiProbe && apiHypotheses.length) {
  apiProbeResults = await fetchApiHypotheses(apiHypotheses);
  const apiText = apiProbeResults.map((item) => `${item.url}\n${item.bodyHead || ''}\n${(item.urls || []).join('\n')}`).join('\n');
  urls = unique(urls.concat(apiProbeResults.flatMap((item) => item.urls || [])));
  ids = extractIds(`${allText}\n${apiText}`, urls);
}

const stateHints = sources.flatMap((source) => extractStateHints(source.text).map((hint) => ({ source: source.name, ...hint })));
const contextByUrl = new Map();
for (const source of sources) {
  for (const url of extractUrls(source.text)) contextByUrl.set(url, `${contextByUrl.get(url) || ''} ${source.name}`);
}
for (const response of browserArtifact?.responses || []) contextByUrl.set(response.url, `${contextByUrl.get(response.url) || ''} ${response.type || ''} ${response.mimeType || ''}`);

const mediaCandidates = urls
  .map((url) => ({ url, score: scoreCandidate(url, contextByUrl.get(url) || '') }))
  .filter((item) => item.score > 0)
  .sort((a, b) => b.score - a.score || a.url.localeCompare(b.url));
const hypotheses = buildTransformHypotheses(urls);
const signatureSurface = analyzeSignatureSurface(sources, urls, browserArtifact, apiHypotheses);
const runtimeApiReplay = await replayDouyinRuntimeApis(browserArtifact);
if (runtimeApiReplay.observedStructuredApi) signatureSurface.runtimeObservedStructuredApi = runtimeApiReplay.observedStructuredApi;
if (runtimeApiReplay.bestReplayedStructuredApi) signatureSurface.runtimeReplayedStructuredApi = runtimeApiReplay.bestReplayedStructuredApi;
const primaryProbeBudget = Math.max(4, Math.ceil(probeLimit / 2));
const probeTargets = unique([
  ...mediaCandidates.slice(0, primaryProbeBudget).map((x) => x.url),
  ...hypotheses.slice(0, Math.max(6, Math.floor(probeLimit / 2))).map((x) => x.hypothesis),
  ...mediaCandidates.slice(primaryProbeBudget, probeLimit).map((x) => x.url),
]).slice(0, probeLimit);

const probes = [];
for (const url of probeTargets) probes.push(await probeUrl(url));
const classified = probes.map((probe) => ({ ...probe, classification: classifyProbe(probe) }));
const strong = classified.filter((probe) => probe.classification.noWatermarkLikely && probe.classification.reachable);
const video = classified.filter((probe) => probe.classification.video && probe.classification.reachable);
const browserCaptured = browserArtifact && !browserArtifact.skipped && (browserArtifact.requests?.length || browserArtifact.responses?.length);
const verdict = strong.length
  ? 'strong-candidate'
  : video.length
    ? 'video-candidate'
    : browserCaptured && mediaCandidates.length
      ? 'needs-manual-replay'
      : mediaCandidates.length
        ? 'needs-browser-capture'
        : 'no-candidate';

const json = {
  target: targetUrl,
  finalUrl: staticResult.finalUrl,
  finalStatus: staticResult.finalStatus,
  elapsedMs: Date.now() - started,
  verdict,
  ids,
  redirectChain: staticResult.chain,
  extractedUrlCount: urls.length,
  sourceSummary: sources.map((source) => ({ name: source.name, bytes: Buffer.byteLength(source.text || ''), urlCount: extractUrls(source.text).length })),
  browser: browserArtifact ? {
    mode: browserArtifact.mode,
    skipped: Boolean(browserArtifact.skipped),
    skipReason: browserArtifact.skipReason,
    finalUrl: browserArtifact.finalUrl,
    requests: browserArtifact.requests?.length || 0,
    responses: browserArtifact.responses?.length || 0,
    bodies: browserArtifact.bodies?.length || 0,
    websockets: browserArtifact.websockets?.length || 0,
    errors: browserArtifact.errors || [],
    artifact: join(outDir, 'browser.json'),
  } : { skipped: true, skipReason: 'RECON_BROWSER disabled or static extraction strong enough' },
  stateHints: stateHints.slice(0, 80),
  apiHypotheses: apiHypotheses.slice(0, 20),
  apiProbeResults: apiProbeResults.map((item) => ({ ...item, bodyHead: item.bodyHead ? item.bodyHead.slice(0, 500) : item.bodyHead })),
  signatureSurface,
  runtimeApiReplay,
  mediaCandidates: mediaCandidates.slice(0, 100),
  transformHypotheses: hypotheses.slice(0, 60),
  probes: classified,
  nextActions: verdict === 'strong-candidate'
    ? ['verify candidate redirect chain in browser/CDP artifact', 'bind candidate into re_replayer matrix', 'record final CDN URL and response headers in verifier artifact']
    : verdict === 'video-candidate'
      ? ['compare playwm/play redirects', 'enable RECON_API_PROBE=1 if aweme_id is present', 'rerun with RECON_BROWSER=1 and a runtime cookie if browser challenge blocks media']
      : ['rerun with RECON_BROWSER=1', 'enable RECON_API_PROBE=1 after aweme_id extraction', 'inspect browser.json responses and stateHints for play_addr/download_addr/url_list'],
};

await writeFile(join(outDir, 'body.html'), staticResult.body);
await writeFile(join(outDir, 'result.json'), `${JSON.stringify(json, null, 2)}\n`);

const md = [
  '# REPI Douyin No-Watermark Interface Artifact',
  '',
  `target: ${targetUrl}`,
  `final_url: ${staticResult.finalUrl}`,
  `verdict: ${verdict}`,
  `artifact_dir: ${outDir}`,
  '',
  '## IDs',
  `aweme_ids: ${ids.awemeIds.join(', ') || 'none'}`,
  `video_ids: ${ids.videoIds.join(', ') || 'none'}`,
  '',
  '## Redirect chain',
  ...staticResult.chain.map((entry, index) => `- ${index} status=${entry.status} url=${entry.url}`),
  '',
  '## Browser/CDP capture',
  browserArtifact
    ? `- skipped=${Boolean(browserArtifact.skipped)} requests=${browserArtifact.requests?.length || 0} responses=${browserArtifact.responses?.length || 0} bodies=${browserArtifact.bodies?.length || 0} final=${browserArtifact.finalUrl || 'unknown'}`
    : '- not run',
  browserArtifact ? `- artifact: ${join(outDir, 'browser.json')}` : '',
  '',
  '## State hints',
  ...(stateHints.slice(0, 20).map((hint) => `- ${hint.source} ${hint.name} ${hint.index !== undefined ? `index=${hint.index}` : `len=${hint.length || 0}`} head=${String(hint.head || '').replace(/\s+/g, ' ').slice(0, 220)}`) || ['- none']),
  '',
  '## API endpoint hypotheses',
  ...(apiHypotheses.slice(0, 10).map((item) => `- ${item.reason}: ${item.url}`) || ['- none']),
  '',
  '## Signature / anti-bot surface',
  `signals: ${signatureSurface.signals.join(', ') || 'none'}`,
  `runtime_fetch_hits: ${signatureSurface.runtimeFetchHits.length}`,
  ...(signatureSurface.urlParamMatrix.slice(0, 15).map((item) => `- params=${item.params.join(',')} url=${item.url}`) || ['- no signed query params observed']),
  ...(signatureSurface.bundleHints.slice(0, 10).map((hint) => `- bundle hits=${hint.hits.join(',')} len=${hint.length} sha=${hint.sha256} source=${hint.source}`) || ['- no signer bundle hints']),
  '',
  '## Runtime signed API replay',
  `attempted: ${Boolean(runtimeApiReplay.attempted)} seeds=${runtimeApiReplay.seedCount || 0} attempts=${runtimeApiReplay.attemptCount || 0}`,
  runtimeApiReplay.observedStructuredApi
    ? `- observed_structured status=${runtimeApiReplay.observedStructuredApi.status} aweme_count=${runtimeApiReplay.observedStructuredApi.structured?.awemeCount || 0} url=${runtimeApiReplay.observedStructuredApi.url}`
    : `- observed_structured: none${runtimeApiReplay.reason ? ` (${runtimeApiReplay.reason})` : ''}`,
  runtimeApiReplay.bestReplayedStructuredApi
    ? `- replay_structured variant=${runtimeApiReplay.bestReplayedStructuredApi.variant} status=${runtimeApiReplay.bestReplayedStructuredApi.status} aweme_count=${runtimeApiReplay.bestReplayedStructuredApi.structured?.awemeCount || 0} url=${runtimeApiReplay.bestReplayedStructuredApi.url}`
    : '- replay_structured: none',
  runtimeApiReplay.firstDivergence
    ? `- first_divergence variant=${runtimeApiReplay.firstDivergence.variant} status=${runtimeApiReplay.firstDivergence.status} url=${runtimeApiReplay.firstDivergence.url}`
    : '- first_divergence: none',
  '',
  '## Top media candidates',
  ...(mediaCandidates.slice(0, 25).map((item) => `- score=${item.score} ${item.url}`) || ['- none']),
  '',
  '## Transform hypotheses',
  ...(hypotheses.slice(0, 25).map((item) => `- ${item.reason}: ${item.hypothesis}`) || ['- none']),
  '',
  '## Probe results',
  ...classified.map((probe) => `- video=${probe.classification.video} no_watermark_likely=${probe.classification.noWatermarkLikely} reachable=${probe.classification.reachable} attempts=${probe.attempts.map((a) => `${a.method}:${a.status}`).join('>')} url=${probe.url}`),
  '',
  '## Verification',
  `- JSON: ${join(outDir, 'result.json')}`,
  `- Static body: ${join(outDir, 'body.html')}`,
  browserArtifact ? `- Browser artifact: ${join(outDir, 'browser.json')}` : '- Browser artifact: not generated',
  '- Probes use HEAD or range requests only; full video download is not performed by this harness.',
  '',
  '## Next Step',
  ...(json.nextActions.map((x) => `- ${x}`)),
  '',
].filter((line) => line !== '').join('\n');
await writeFile(join(outDir, 'artifact.md'), md);

console.log(JSON.stringify({
  verdict,
  artifactDir: outDir,
  finalUrl: staticResult.finalUrl,
  awemeIds: ids.awemeIds,
  videoCandidates: video.length,
  strongCandidates: strong.length,
  browserRequests: browserArtifact?.requests?.length || 0,
  browserResponses: browserArtifact?.responses?.length || 0,
  runtimeApiReplay: {
    attempted: runtimeApiReplay.attempted,
    observedStructured: Boolean(runtimeApiReplay.observedStructuredApi),
    replayedStructured: Boolean(runtimeApiReplay.bestReplayedStructuredApi),
  },
}, null, 2));

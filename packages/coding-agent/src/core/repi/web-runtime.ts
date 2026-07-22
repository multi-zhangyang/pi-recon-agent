import { join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import type { ArtifactScopeFilterOptions } from "./artifact-scope.ts";
import type { EvidenceRecord } from "./evidence.ts";
import type { MissionCheckpointStatus, MissionState } from "./mission.ts";
import { shellQuote } from "./target.ts";
import { compactStoredArtifact, interestingLines, slug, truncateMiddle } from "./text.ts";

/**
 * The small execution shape consumed by the mission checkpoint helper.  Keep
 * the fields broad because the host profile also uses this shape for other
 * runtime adapters.
 */
export type WebRuntimeCheckpointExecution = {
	status?: unknown;
	command?: unknown;
	exit?: unknown;
	stdoutHash?: unknown;
	stdoutSha256?: unknown;
	stdout_sha256?: unknown;
	stderrHash?: unknown;
	stderrSha256?: unknown;
	stderr_sha256?: unknown;
};

/**
 * Host callbacks for the web runtime.  The module deliberately does not
 * import recon-profile.ts: that file owns the orchestration callbacks and
 * would create a dependency cycle once this runtime is wired into it.
 */
export type WebRuntimeDependencies = {
	ensureReconStorage: () => void;
	readCurrentMission: () => MissionState | undefined;
	readText: (path: string, fallback?: string) => string;
	recentMarkdownArtifacts: (dir: string, limit: number) => string[];
	evidenceBrowserDir: () => string;
	evidenceWebAuthzDir: () => string;
	evidenceMapsDir: () => string;
	evidenceRunsDir: () => string;
	writePrivateTextFile: (path: string, content: string) => void;
	latestScopedMarkdownArtifact: (
		kind: string,
		dir: string,
		options?: ArtifactScopeFilterOptions,
	) => string | undefined;
	latestKernelArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	latestVerifierArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	latestCompilerArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	latestReplayerArtifactPath: (options?: ArtifactScopeFilterOptions) => string | undefined;
	appendEvidence: (record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number }) => void;
	updateMissionCheckpoint: (name: string, status: MissionCheckpointStatus, note?: string) => void;
	runtimeCheckpointStatus: (
		mode: "plan" | "run" | "bundle",
		executions: readonly WebRuntimeCheckpointExecution[],
		target?: string,
	) => MissionCheckpointStatus;
	replayHash: (text: string) => string;
};

export type LiveBrowserExecution = {
	label: string;
	command: string;
	status: "planned" | "passed" | "failed" | "blocked";
	exit?: number;
	killed?: boolean;
	stdoutHash?: string;
	stderrHash?: string;
	stdoutHead?: string;
	stderrHead?: string;
};

export type LiveBrowserArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "run";
	url?: string;
	timeoutMs: number;
	captureScript: string;
	runtimeMatrix: string[];
	authMatrix: string[];
	idorBolaProbes: string[];
	websocketProbes: string[];
	replayCommands: string[];
	executions: LiveBrowserExecution[];
	runtimeAnchors: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

export type WebAuthzStateExecution = {
	label: string;
	command: string;
	status: "planned" | "passed" | "failed" | "blocked";
	exit?: number;
	killed?: boolean;
	stdoutHash?: string;
	stderrHash?: string;
	stdoutHead?: string;
	stderrHead?: string;
};

export type WebAuthzStateArtifact = {
	timestamp: string;
	missionId?: string;
	route?: string;
	target?: string;
	mode: "plan" | "run";
	url?: string;
	timeoutMs: number;
	captureScript: string;
	routeInventory: string[];
	principalMatrix: string[];
	objectProbes: string[];
	stateMachine: string[];
	sequenceReplay: string[];
	ownershipChecks: string[];
	rollbackChecks: string[];
	replayCommands: string[];
	executions: WebAuthzStateExecution[];
	runtimeAnchors: string[];
	nextActions: string[];
	sourceArtifacts: string[];
};

export type LiveBrowserOptions = {
	target?: string;
	url?: string;
	timeoutMs?: number;
};

export type LiveBrowserArtifactOptions = LiveBrowserOptions & {
	mode?: "plan" | "run";
	executions?: LiveBrowserExecution[];
	runtimeAnchors?: string[];
};

export type WebAuthzStateArtifactOptions = WebRuntimeOptions & {
	mode?: "plan" | "run";
	executions?: WebAuthzStateExecution[];
	runtimeAnchors?: string[];
};

export type WebRuntimeOptions = {
	target?: string;
	url?: string;
	timeoutMs?: number;
};

export function latestLiveBrowserArtifactPath(
	dependencies: WebRuntimeDependencies,
	options: ArtifactScopeFilterOptions = {},
): string | undefined {
	return dependencies.latestScopedMarkdownArtifact("browser", dependencies.evidenceBrowserDir(), options);
}

export function inferBrowserUrl(target: string | undefined, dependencies: WebRuntimeDependencies): string | undefined {
	const trimmed = target?.trim();
	if (trimmed) return /^https?:\/\//i.test(trimmed) ? trimmed : undefined;
	const latestMap = dependencies.recentMarkdownArtifacts(dependencies.evidenceMapsDir(), 1)[0];
	const mapText = latestMap ? dependencies.readText(latestMap) : "";
	const targetLine = /^target=(https?:\/\/\S+)/m.exec(mapText)?.[1];
	if (targetLine) return targetLine.replace(/["'`]+$/g, "");
	const urlLine = /(https?:\/\/[^\s"'`<>]+)/i.exec(mapText)?.[1];
	return urlLine?.replace(/[),.;]+$/g, "");
}

export function liveBrowserInvalidUrlReason(target?: string, url?: string): string | undefined {
	const candidate = url?.trim() || target?.trim();
	if (!candidate) return undefined;
	return /^https?:\/\//i.test(candidate) ? undefined : `invalid_url target=${candidate}`;
}

export function liveBrowserNodeScript(): string {
	return String.raw`const url = process.argv[2];
const timeout = Number(process.argv[3] || 15000);
function log(prefix, obj) {
  const parts = Object.entries(obj || {}).map(([k, v]) => String(k) + '=' + String(v).replace(/\s+/g, ' ').slice(0, 300));
  console.log(prefix + ' ' + parts.join(' '));
}
async function plainFetch() {
  const started = Date.now();
  const response = await fetch(url, { redirect: 'manual', headers: { 'User-Agent': 'REPI live-browser fallback' } });
  const text = await response.text();
  log('[browser-request]', { method: 'GET', url, resource: 'document', engine: 'fetch' });
  log('[browser-response]', { status: response.status, url: response.url || url, content_type: response.headers.get('content-type') || '', elapsed_ms: Date.now() - started, bytes: text.length });
  console.log('[browser-body-head] ' + text.slice(0, 1200).replace(/\s+/g, ' '));
}
async function playwrightCapture() {
  let playwright;
  try { playwright = require('playwright'); } catch { return false; }
	const fs = require('node:fs');
	const path = require('node:path');
	const os = require('node:os');
	const profileDir = process.env.REPI_BROWSER_PROFILE_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'repi-browser-profile-'));
	const artifactDir = process.env.REPI_BROWSER_ARTIFACT_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'repi-browser-artifacts-'));
	fs.mkdirSync(profileDir, { recursive: true, mode: 0o700 });
	fs.mkdirSync(artifactDir, { recursive: true, mode: 0o700 });
	const harPath = path.join(artifactDir, 'network.har');
	const tracePath = path.join(artifactDir, 'trace.zip');
	const storagePath = path.join(artifactDir, 'storage-state.json');
	const context = await playwright.chromium.launchPersistentContext(profileDir, {
	  headless: true,
	  ignoreHTTPSErrors: true,
	  recordHar: { path: harPath, mode: 'full', content: 'embed' },
	});
	await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
  const page = await context.newPage();
  page.on('request', (request) => log('[browser-request]', { method: request.method(), url: request.url(), resource: request.resourceType() }));
  page.on('response', (response) => log('[browser-response]', { status: response.status(), url: response.url(), content_type: response.headers()['content-type'] || '' }));
  page.on('websocket', (ws) => {
    log('[browser-websocket]', { url: ws.url() });
    ws.on('framereceived', (frame) => log('[browser-ws-frame-in]', { bytes: String(frame.payload || '').length, head: String(frame.payload || '').slice(0, 180) }));
    ws.on('framesent', (frame) => log('[browser-ws-frame-out]', { bytes: String(frame.payload || '').length, head: String(frame.payload || '').slice(0, 180) }));
  });
  await page.goto(url, { waitUntil: 'networkidle', timeout });
  const storage = await page.evaluate(() => ({
    href: location.href,
    title: document.title,
    cookies: document.cookie,
    localStorage: Object.keys(localStorage).map((key) => [key, String(localStorage.getItem(key) || '').slice(0, 120)]),
    sessionStorage: Object.keys(sessionStorage).map((key) => [key, String(sessionStorage.getItem(key) || '').slice(0, 120)]),
    forms: Array.from(document.forms).map((form) => ({ action: form.action, method: form.method, inputs: Array.from(form.elements).map((el) => el.getAttribute('name') || el.id || el.tagName).slice(0, 20) })).slice(0, 12),
    links: Array.from(document.links).map((a) => a.href).filter((href) => /api|graphql|admin|user|account|id=|uuid|token|auth/i.test(href)).slice(0, 40),
  }));
  console.log('[browser-storage] ' + JSON.stringify(storage).slice(0, 4000));
	await context.storageState({ path: storagePath });
	await context.tracing.stop({ path: tracePath });
	await context.close();
	log('[browser-artifacts]', { profile: profileDir, har: harPath, trace: tracePath, storage: storagePath });
  return true;
}
(async () => {
  if (!url || !/^https?:\/\//i.test(url)) {
    console.log('[browser-error] missing-or-invalid-url url=' + String(url || ''));
    process.exitCode = 2;
    return;
  }
  try {
    const usedPlaywright = await playwrightCapture();
    if (!usedPlaywright) await plainFetch();
  } catch (error) {
    console.log('[browser-error] ' + (error && error.stack ? error.stack : String(error)).replace(/\s+/g, ' ').slice(0, 2000));
    process.exitCode = 1;
  }
})();`;
}

export function liveBrowserShellCommand(url: string, timeoutMs: number): string {
	return [
		"cat > /tmp/repi-live-browser.js <<'JS'",
		liveBrowserNodeScript(),
		"JS",
		`timeout ${Math.ceil(timeoutMs / 1000) + 5}s node /tmp/repi-live-browser.js ${shellQuote(url)} ${Math.floor(timeoutMs)}`,
	].join("\n");
}

export function liveBrowserAnchors(stdout: string, stderr: string): string[] {
	const text = `${stdout}\n${stderr}`;
	return [
		...interestingLines(text, /\[browser-request\]/i, 20).map((line) => `request:${truncateMiddle(line, 260)}`),
		...interestingLines(text, /\[browser-response\]/i, 20).map((line) => `response:${truncateMiddle(line, 260)}`),
		...interestingLines(text, /\[browser-websocket\]|\[browser-ws-frame/i, 12).map(
			(line) => `websocket:${truncateMiddle(line, 260)}`,
		),
		...interestingLines(text, /\[browser-storage\]/i, 8).map((line) => `storage:${truncateMiddle(line, 260)}`),
		...interestingLines(text, /\[browser-error\]/i, 8).map((line) => `error:${truncateMiddle(line, 260)}`),
	].slice(0, 60);
}

export function buildLiveBrowserArtifact(
	options: LiveBrowserArtifactOptions,
	dependencies: WebRuntimeDependencies,
): LiveBrowserArtifact {
	dependencies.ensureReconStorage();
	const mission = dependencies.readCurrentMission();
	const invalidUrl = liveBrowserInvalidUrlReason(options.target, options.url);
	const url = invalidUrl ? undefined : (options.url ?? inferBrowserUrl(options.target, dependencies));
	const timeoutMs = Math.max(3000, Math.min(120000, Math.floor(options.timeoutMs ?? 15000)));
	const captureCommand = url
		? liveBrowserShellCommand(url, timeoutMs)
		: invalidUrl
			? `# blocked: invalid_url; re_live_browser requires an explicit http(s):// URL, got ${shellQuote(options.url ?? options.target ?? "")}`
			: "# missing URL: run re_map https://target first or pass target/url";
	const replayCommands = [
		url ? `curl -k -i --max-time 15 ${shellQuote(url)}` : "curl -k -i --max-time 15 <URL>",
		url
			? `node /tmp/repi-live-browser.js ${shellQuote(url)} ${timeoutMs}`
			: "node /tmp/repi-live-browser.js <URL> 15000",
		"re_live_browser run <URL>",
	];
	const authMatrix = [
		"capture anonymous baseline: cookies/localStorage/sessionStorage + request/response status",
		"capture authenticated baseline with supplied browser profile or cookie jar when available",
		"diff anonymous vs authenticated routes, status codes, redirects, object ids, CSRF/JWT/session fields",
		"negative control: replay authenticated object request without credential or with second identity",
	];
	const idorBolaProbes = [
		url
			? `replace numeric/id/uuid path or query tokens in ${url} and replay with same cookies`
			: "replace object id in <URL> and replay",
		"compare status/body length/cache headers before and after object id mutation",
		"record ownership proof: object id, actor/session, expected deny/allow, response hash",
	];
	const websocketProbes = [
		"record [browser-websocket] endpoints and inbound/outbound frame heads",
		"replay connection with same origin/cookie headers and mutate object/channel identifiers",
		"bind each frame to state transition or authz decision before claiming impact",
	];
	const runtimeMatrix = [
		`url=${url ?? "<missing>"}`,
		`mode=${options.mode ?? "plan"}`,
		`timeout_ms=${timeoutMs}`,
		"engine=playwright-if-installed, node-fetch-fallback",
		"captures=request,response,websocket,storage,forms,links,body-head",
		...(invalidUrl ? [`status=blocked reason=${invalidUrl}`] : []),
	];
	const nextActions = Array.from(
		new Set([
			invalidUrl
				? "re_map <URL> 2 # blocked: invalid_url; pass explicit http(s):// URL"
				: url
					? `re_live_browser run ${url}`
					: "re_map <URL> 2",
			"re_lane plan state <URL>",
			"re_operator plan",
			"re_verifier matrix",
		]),
	).slice(0, 12);
	return {
		timestamp: new Date().toISOString(),
		missionId: mission?.id,
		route: mission?.route.domain,
		target: options.target,
		mode: options.mode ?? "plan",
		url,
		timeoutMs,
		captureScript: captureCommand,
		runtimeMatrix,
		authMatrix,
		idorBolaProbes,
		websocketProbes,
		replayCommands,
		executions: options.executions ?? [],
		runtimeAnchors:
			options.runtimeAnchors ?? (invalidUrl ? [`error:${invalidUrl}; pass an explicit http(s):// URL`] : []),
		nextActions,
		sourceArtifacts: [
			dependencies.recentMarkdownArtifacts(dependencies.evidenceMapsDir(), 1)[0],
			dependencies.latestKernelArtifactPath(),
		].filter((path): path is string => Boolean(path)),
	};
}

export function formatLiveBrowser(
	browser: LiveBrowserArtifact,
	path?: string,
	options: { includeCaptureScript?: boolean } = {},
): string {
	return [
		"live_browser:",
		path ? `browser_artifact: ${path}` : undefined,
		`timestamp: ${browser.timestamp}`,
		`mode: ${browser.mode}`,
		`mission_id: ${browser.missionId ?? "none"}`,
		`route: ${browser.route ?? "none"}`,
		`target: ${browser.target ?? "<none>"}`,
		`url: ${browser.url ?? "<missing>"}`,
		`timeout_ms: ${browser.timeoutMs}`,
		"runtime_matrix:",
		...(browser.runtimeMatrix.length ? browser.runtimeMatrix.map((item) => `- ${item}`) : ["- none"]),
		"request_response_log:",
		...(browser.executions.length
			? browser.executions.map(
					(item) =>
						`- ${item.label} [${item.status}] exit=${item.exit ?? "n/a"} stdout_sha256=${item.stdoutHash ?? "n/a"} stderr_sha256=${item.stderrHash ?? "n/a"}`,
				)
			: ["- planned capture; run re_live_browser run <URL>"]),
		"runtime_anchors:",
		...(browser.runtimeAnchors.length ? browser.runtimeAnchors.map((item) => `- ${item}`) : ["- none"]),
		"auth_matrix:",
		...(browser.authMatrix.length ? browser.authMatrix.map((item) => `- ${item}`) : ["- none"]),
		"idor_bola_probe_templates:",
		...(browser.idorBolaProbes.length ? browser.idorBolaProbes.map((item) => `- ${item}`) : ["- none"]),
		"websocket_probes:",
		...(browser.websocketProbes.length ? browser.websocketProbes.map((item) => `- ${item}`) : ["- none"]),
		"replay_commands:",
		...(browser.replayCommands.length ? browser.replayCommands.map((item) => `- ${item}`) : ["- none"]),
		...(options.includeCaptureScript ? ["capture_script:", "```bash", browser.captureScript, "```"] : []),
		"browser_next_actions:",
		...(browser.nextActions.length ? browser.nextActions.map((item) => `- ${item}`) : ["- re_map <URL> 2"]),
		`next_browser_command: ${browser.mode === "run" ? "re_verifier matrix" : "re_live_browser run <URL>"}`,
		"source_artifacts:",
		...(browser.sourceArtifacts.length ? browser.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
	]
		.filter(Boolean)
		.join("\n");
}

export function writeLiveBrowserArtifact(browser: LiveBrowserArtifact, dependencies: WebRuntimeDependencies): string {
	dependencies.ensureReconStorage();
	const path = join(
		dependencies.evidenceBrowserDir(),
		`${browser.timestamp.replace(/[:.]/g, "-")}-${slug(browser.url ?? browser.target ?? "browser")}-${browser.mode}.md`,
	);
	dependencies.writePrivateTextFile(
		path,
		[
			"# REPI Live Browser Artifact",
			"",
			formatLiveBrowser(browser, path, { includeCaptureScript: true }),
			"",
			"## JSON",
			"",
			"```json",
			JSON.stringify(browser, null, 2),
			"```",
			"",
		].join("\n"),
	);
	dependencies.appendEvidence({
		kind: browser.mode === "run" ? "runtime" : "artifact",
		title: `live-browser-${browser.mode} ${browser.url ?? browser.target ?? "no-url"}`,
		fact: `Live browser ${browser.mode}: url=${browser.url ?? "<missing>"}, executions=${browser.executions.length}, anchors=${browser.runtimeAnchors.length}`,
		command: `re_live_browser ${browser.mode}${browser.url ? ` ${browser.url}` : ""}`,
		path,
		verify: `cat ${path}`,
		confidence: "browser/XHR/WS runtime capture",
	});
	dependencies.updateMissionCheckpoint(
		"live_browser_ready",
		dependencies.runtimeCheckpointStatus(browser.mode, browser.executions, browser.url ?? browser.target),
		path,
	);
	return path;
}

export async function runLiveBrowser(
	pi: ExtensionAPI,
	options: LiveBrowserOptions = {},
	dependencies: WebRuntimeDependencies,
): Promise<string> {
	const invalidUrl = liveBrowserInvalidUrlReason(options.target, options.url);
	const url = invalidUrl ? undefined : (options.url ?? inferBrowserUrl(options.target, dependencies));
	const timeoutMs = Math.max(3000, Math.min(120000, Math.floor(options.timeoutMs ?? 15000)));
	if (invalidUrl || !url) {
		const browser = buildLiveBrowserArtifact({ ...options, mode: "run", timeoutMs }, dependencies);
		browser.executions.push({
			label: "browser-runtime-capture",
			command: browser.captureScript,
			status: "blocked",
		});
		browser.runtimeAnchors.push(
			invalidUrl
				? `error:${invalidUrl}; re_live_browser does not fallback to historical URLs`
				: "error:missing concrete URL; run re_map <URL> or pass target/url",
		);
		const path = writeLiveBrowserArtifact(browser, dependencies);
		return formatLiveBrowser(browser, path);
	}
	const command = liveBrowserShellCommand(url, timeoutMs);
	const result = await pi.exec("bash", ["-lc", command], { timeout: timeoutMs + 10000 });
	const anchors = liveBrowserAnchors(result.stdout, result.stderr);
	const browser = buildLiveBrowserArtifact(
		{
			...options,
			url,
			mode: "run",
			timeoutMs,
			executions: [
				{
					label: "browser-runtime-capture",
					command,
					status: result.code === 0 ? "passed" : "failed",
					exit: result.code,
					killed: result.killed,
					stdoutHash: dependencies.replayHash(result.stdout),
					stderrHash: dependencies.replayHash(result.stderr),
					stdoutHead: truncateMiddle(result.stdout.trim(), 3000),
					stderrHead: truncateMiddle(result.stderr.trim(), 2000),
				},
			],
			runtimeAnchors: anchors,
		},
		dependencies,
	);
	const path = writeLiveBrowserArtifact(browser, dependencies);
	return [
		formatLiveBrowser(browser, path),
		result.stdout.trim() ? ["stdout_head:", "```", truncateMiddle(result.stdout.trim(), 1600), "```"].join("\n") : "",
		result.stderr.trim() ? ["stderr_head:", "```", truncateMiddle(result.stderr.trim(), 800), "```"].join("\n") : "",
	]
		.filter(Boolean)
		.join("\n");
}

export function buildLiveBrowserOutput(
	action: "plan" | "show" = "plan",
	options: LiveBrowserOptions = {},
	dependencies: WebRuntimeDependencies,
): string {
	if (action === "show") {
		const path = latestLiveBrowserArtifactPath(dependencies);
		if (!path) return "live_browser:\nstatus: missing\nnext: re_live_browser plan <URL>";
		return compactStoredArtifact("live_browser", path, dependencies.readText(path));
	}
	const browser = buildLiveBrowserArtifact({ ...options, mode: "plan" }, dependencies);
	const path = writeLiveBrowserArtifact(browser, dependencies);
	return formatLiveBrowser(browser, path);
}

export function latestWebAuthzStateArtifactPath(
	dependencies: WebRuntimeDependencies,
	options: ArtifactScopeFilterOptions = {},
): string | undefined {
	return dependencies.latestScopedMarkdownArtifact("web_authz", dependencies.evidenceWebAuthzDir(), options);
}

export function inferWebAuthzUrl(target: string | undefined, dependencies: WebRuntimeDependencies): string | undefined {
	const trimmed = target?.trim();
	if (trimmed && /^https?:\/\//i.test(trimmed)) return trimmed;
	if (trimmed) return undefined;
	for (const path of [
		latestLiveBrowserArtifactPath(dependencies),
		dependencies.recentMarkdownArtifacts(dependencies.evidenceMapsDir(), 1)[0],
		latestWebAuthzStateArtifactPath(dependencies),
	]) {
		if (!path) continue;
		const text = dependencies.readText(path);
		const match = /(?:url|target|sample)[:=]\s*(https?:\/\/\S+)/i.exec(text)?.[1]?.replace(/["'`),]+$/, "");
		if (match) return match;
	}
	return trimmed || undefined;
}

export function webAuthzStateNodeScript(): string {
	return `import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
const target = process.argv[2] || process.env.REPI_URL || '';
const principals = (process.env.REPI_AUTHZ_PRINCIPALS || 'anon,A,B').split(',').map(function (x) { return x.trim(); }).filter(Boolean);
const limit = Math.max(1, Math.min(25, Number(process.env.REPI_AUTHZ_LIMIT || '8')));
function boolEnv(name) { return /^(1|true|yes|on)$/i.test(process.env[name] || ''); }
function warnEnv(name, purpose) { if (!process.env[name]) console.log('[web-authz-warn]', 'missing_env=' + name, 'purpose=' + purpose); }
function digest(buf) { return crypto.createHash('sha256').update(buf).digest('hex').slice(0, 16); }
function principalHeaders(name) {
  const suffix = name.toUpperCase();
  const headers = { 'User-Agent': 'REPI-web-authz-state/' + name };
  const cookie = process.env['COOKIE_' + suffix] || (name === 'anon' ? '' : process.env.COOKIE_A || '');
  const auth = process.env['AUTH_' + suffix] || (name === 'anon' ? '' : process.env.AUTH_A || '');
  if (cookie) headers.Cookie = cookie;
  if (auth) headers.Authorization = auth;
  return headers;
}
function routePath(raw) { try { return new URL(raw, target || 'http://127.0.0.1/').pathname; } catch (_) { return raw || '<missing>'; } }
function sequenceUrls() {
  const seq = process.env.REPI_AUTHZ_SEQUENCE || target;
  return seq.split(',').map(function (x) { return x.trim(); }).filter(Boolean).slice(0, limit);
}
async function fetchState(principal, url, method, body) {
  const init = { method: method || 'GET', headers: principalHeaders(principal), redirect: 'manual' };
  if (body) { init.body = body; init.headers['Content-Type'] = process.env.REPI_AUTHZ_CONTENT_TYPE || 'application/json'; }
  try {
    const response = await fetch(url, init);
    const data = Buffer.from(await response.arrayBuffer());
    return { principal, method: init.method, url, route: routePath(url), status: response.status, bytes: data.length, hash: digest(data) };
  } catch (error) {
    return { principal, method: init.method, url, route: routePath(url), status: 'ERR', bytes: 0, hash: 'ERR', error: String(error && error.message || error) };
  }
}
const states = [];
if (!target) {
  console.log('[web-authz-blocked] reason=missing_url');
} else {
  for (const name of ['COOKIE_A', 'AUTH_A', 'COOKIE_B', 'AUTH_B']) warnEnv(name, 'optional principal credential; branch may be skipped or share anon state');
  for (const principal of principals) {
    const state = await fetchState(principal, target, 'GET');
    states.push(state);
    console.log('[web-authz-state]', 'principal=' + principal, 'route=' + state.route, 'method=' + state.method, 'status=' + state.status, 'bytes=' + state.bytes, 'hash=' + state.hash);
  }
  const route = states[0] ? states[0].route : routePath(target);
  const statusVector = states.map(function (s) { return s.principal + ':' + s.status + ':' + s.hash; }).join(',');
  const uniqueBodies = new Set(states.map(function (s) { return s.hash; })).size;
  const sameStatus = new Set(states.map(function (s) { return String(s.status); })).size === 1;
  console.log('[web-authz-matrix]', 'route=' + route, 'principals=' + principals.join(','), 'states=' + states.length, 'same_status=' + String(sameStatus), 'unique_bodies=' + uniqueBodies, 'vector=' + statusVector);
}
const objectA = process.env.REPI_OBJECT_A || '';
const objectB = process.env.REPI_OBJECT_B || '';
const objectChecks = [];
if (objectA && objectB) {
  const a = await fetchState('A', objectA, 'GET');
  const b = await fetchState('B', objectA, 'GET');
  const alt = await fetchState('A', objectB, 'GET');
  objectChecks.push({ owner: a, crossPrincipal: b, alternateObject: alt });
  console.log('[web-authz-object]', 'route=' + a.route, 'owner=A', 'principal_a_status=' + a.status, 'principal_b_status=' + b.status, 'same_body_ab=' + String(a.hash === b.hash), 'alt_status=' + alt.status, 'potential_bola=' + String(a.status === b.status && a.hash !== b.hash));
} else {
  console.log('[web-authz-object]', 'status=skipped', 'reason=set_REPI_OBJECT_A_and_REPI_OBJECT_B');
}
const sequence = [];
for (const principal of principals.filter(function (p) { return p !== 'anon'; })) {
  const rows = [];
  for (const url of sequenceUrls()) rows.push(await fetchState(principal, url, 'GET'));
  sequence.push({ principal, rows });
  console.log('[web-authz-sequence]', 'principal=' + principal, 'steps=' + rows.length, 'statuses=' + rows.map(function (r) { return r.status; }).join(','), 'hashes=' + rows.map(function (r) { return r.hash; }).join(','));
}
let rollback = { skipped: true, reason: 'set_REPI_AUTHZ_MUTATE=1_and_REPI_MUTATION_URL' };
if (boolEnv('REPI_AUTHZ_MUTATE') && process.env.REPI_MUTATION_URL) {
  const url = process.env.REPI_MUTATION_URL;
  const method = process.env.REPI_MUTATION_METHOD || 'PATCH';
  const before = await fetchState('A', url, 'GET');
  const mutate = await fetchState('A', url, method, process.env.REPI_MUTATION_BODY || '{}');
  const restore = process.env.REPI_RESTORE_BODY ? await fetchState('A', url, method, process.env.REPI_RESTORE_BODY) : { status: 'SKIP', hash: 'SKIP' };
  const after = await fetchState('A', url, 'GET');
  rollback = { skipped: false, url, method, before, mutate, restore, after, restored: before.hash === after.hash };
  console.log('[web-authz-rollback]', 'route=' + routePath(url), 'method=' + method, 'before=' + before.hash, 'mutate=' + mutate.hash, 'after=' + after.hash, 'restored=' + String(rollback.restored));
} else {
  console.log('[web-authz-rollback]', 'status=skipped', 'reason=set_REPI_AUTHZ_MUTATE=1_and_REPI_MUTATION_URL');
}
const artifact = { target, principals, states, objectChecks, sequence, rollback, capturedAt: new Date().toISOString() };
writeFileSync('/tmp/repi-web-authz-state.json', JSON.stringify(artifact, null, 2));
console.log('[web-authz-artifact]', '/tmp/repi-web-authz-state.json');`;
}

export function webAuthzStateShellCommand(url?: string, timeoutMs = 15000): string {
	const urlArg = shellQuote(url?.trim() ?? "");
	const runTimeout = Math.max(3, Math.ceil(timeoutMs / 1000));
	return [
		"set +e",
		`URL=${urlArg}`,
		`printf "[web-authz-env] node=%s curl=%s jq=%s python3=%s timeout=%s\\n" "$(command -v node || true)" "$(command -v curl || true)" "$(command -v jq || true)" "$(command -v python3 || true)" "${runTimeout}s"`,
		"cat > /tmp/repi-web-authz-state.mjs <<'NODE'",
		webAuthzStateNodeScript(),
		"NODE",
		`echo "[web-authz-script] /tmp/repi-web-authz-state.mjs artifact=/tmp/repi-web-authz-state.json principals=\${REPI_AUTHZ_PRINCIPALS:-anon,A,B}"`,
		`if command -v node >/dev/null 2>&1 && [ -n "$URL" ]; then timeout ${runTimeout}s node /tmp/repi-web-authz-state.mjs "$URL" 2>&1 | sed "s/^/[web-authz-run] /"; else echo "[web-authz-blocked] reason=node_or_url_missing url=$URL"; fi`,
	].join("\n");
}

export function webAuthzStateAnchors(stdout: string, stderr: string): string[] {
	const text = `${stdout}\n${stderr}`;
	return [
		...interestingLines(text, /\[web-authz-env\]/i, 8).map(
			(line) => `web authz tool readiness anchors: ${truncateMiddle(line, 260)}`,
		),
		...interestingLines(text, /\[web-authz-state\]/i, 30).map(
			(line) => `web authz principal state anchors: ${truncateMiddle(line, 260)}`,
		),
		...interestingLines(text, /\[web-authz-matrix\]/i, 12).map(
			(line) => `web authz matrix anchors: ${truncateMiddle(line, 260)}`,
		),
		...interestingLines(text, /\[web-authz-object\]/i, 12).map(
			(line) => `web authz object ownership anchors: ${truncateMiddle(line, 260)}`,
		),
		...interestingLines(text, /\[web-authz-sequence\]/i, 20).map(
			(line) => `web authz sequence replay anchors: ${truncateMiddle(line, 260)}`,
		),
		...interestingLines(text, /\[web-authz-rollback\]/i, 12).map(
			(line) => `web authz rollback anchors: ${truncateMiddle(line, 260)}`,
		),
		...interestingLines(text, /\[web-authz-artifact\]|\[web-authz-script\]/i, 8).map(
			(line) => `web authz artifact anchors: ${truncateMiddle(line, 260)}`,
		),
		...interestingLines(text, /\[web-authz-blocked\]/i, 12).map(
			(line) => `web authz blocked anchors: ${truncateMiddle(line, 260)}`,
		),
	].slice(0, 120);
}

export function buildWebAuthzStateArtifact(
	options: WebAuthzStateArtifactOptions,
	dependencies: WebRuntimeDependencies,
): WebAuthzStateArtifact {
	dependencies.ensureReconStorage();
	const mission = dependencies.readCurrentMission();
	const url = inferWebAuthzUrl(options.url ?? options.target, dependencies);
	const timeoutMs = Math.max(3000, Math.min(180000, Math.floor(options.timeoutMs ?? 15000)));
	const captureScript = webAuthzStateShellCommand(url, timeoutMs);
	const routeInventory = [
		url ? `target=${url}: route/principal state baseline` : "target=<missing>: pass URL or run re_live_browser first",
		"reuse browser route graph/auth matrix when present; otherwise probe target URL directly",
	];
	const principalMatrix = [
		"principals default to anon,A,B; set COOKIE_A/COOKIE_B or AUTH_A/AUTH_B and REPI_AUTHZ_PRINCIPALS",
		"record per-principal status/body hash and flag same-status/different-body transitions",
	];
	const objectProbes = [
		"set REPI_OBJECT_A and REPI_OBJECT_B to compare owner/cross-principal/alternate object responses",
		"potential BOLA/IDOR requires controlled positive and negative principal checks before impact claim",
	];
	const stateMachine = [
		"direct state probe: anon/A/B -> status, bytes, body hash for each protected route",
		"state diff binds route, principal, auth material, and response hash into artifact JSON",
	];
	const sequenceReplay = [
		"set REPI_AUTHZ_SEQUENCE=url1,url2,... to replay ordered request sequence for each principal",
		"compare statuses/hashes across principals and rerun via re_replayer before final report",
	];
	const ownershipChecks = [
		"object ownership checks compare A reading own object, B reading A object, and A reading alternate object",
		"evidence must include route, object identifiers, principals, status and body-hash deltas",
	];
	const rollbackChecks = [
		"mutating rollback is skipped by default; enable with REPI_AUTHZ_MUTATE=1 and REPI_MUTATION_URL/BODY/RESTORE_BODY",
		"rollback proof records before/mutate/restore/after hashes and restored verdict",
	];
	const replayCommands = [
		`re_web_authz_state run ${url ?? "<url>"} ${timeoutMs}`,
		"COOKIE_A=... COOKIE_B=... AUTH_A=... AUTH_B=... re_web_authz_state run <url>",
		"REPI_OBJECT_A=https://target/api/objects/1 REPI_OBJECT_B=https://target/api/objects/2 re_web_authz_state run <url>",
		"cat /tmp/repi-web-authz-state.json",
	];
	const nextActions = Array.from(
		new Set(
			[
				url && (options.mode ?? "plan") !== "run" ? `re_web_authz_state run ${url} ${timeoutMs}` : undefined,
				"re_live_browser run <url>",
				"re_verifier matrix",
				"re_compiler draft",
				"re_replayer run",
				"re_graph build",
			].filter((item): item is string => Boolean(item)),
		),
	).slice(0, 12);
	return {
		timestamp: new Date().toISOString(),
		missionId: mission?.id,
		route: mission?.route.domain,
		target: options.target?.trim() || url,
		mode: options.mode ?? "plan",
		url,
		timeoutMs,
		captureScript,
		routeInventory,
		principalMatrix,
		objectProbes,
		stateMachine,
		sequenceReplay,
		ownershipChecks,
		rollbackChecks,
		replayCommands,
		executions: options.executions ?? [],
		runtimeAnchors: options.runtimeAnchors ?? [],
		nextActions,
		sourceArtifacts: [
			latestLiveBrowserArtifactPath(dependencies),
			dependencies.recentMarkdownArtifacts(dependencies.evidenceMapsDir(), 1)[0],
			dependencies.recentMarkdownArtifacts(dependencies.evidenceRunsDir(), 1)[0],
			dependencies.latestVerifierArtifactPath(),
			dependencies.latestCompilerArtifactPath(),
			dependencies.latestReplayerArtifactPath(),
		].filter((path): path is string => Boolean(path)),
	};
}

export function formatWebAuthzState(
	authz: WebAuthzStateArtifact,
	path?: string,
	options: { includeCaptureScript?: boolean } = {},
): string {
	return [
		"web_authz_state:",
		path ? `web_authz_artifact: ${path}` : undefined,
		`timestamp: ${authz.timestamp}`,
		`mode: ${authz.mode}`,
		`mission_id: ${authz.missionId ?? "none"}`,
		`route: ${authz.route ?? "none"}`,
		`target: ${authz.target ?? "<missing>"}`,
		`url: ${authz.url ?? "<missing>"}`,
		`timeout_ms: ${authz.timeoutMs}`,
		"route_inventory:",
		...(authz.routeInventory.length ? authz.routeInventory.map((item) => `- ${item}`) : ["- none"]),
		"principal_matrix:",
		...(authz.principalMatrix.length ? authz.principalMatrix.map((item) => `- ${item}`) : ["- none"]),
		"object_probes:",
		...(authz.objectProbes.length ? authz.objectProbes.map((item) => `- ${item}`) : ["- none"]),
		"state_machine:",
		...(authz.stateMachine.length ? authz.stateMachine.map((item) => `- ${item}`) : ["- none"]),
		"sequence_replay:",
		...(authz.sequenceReplay.length ? authz.sequenceReplay.map((item) => `- ${item}`) : ["- none"]),
		"ownership_checks:",
		...(authz.ownershipChecks.length ? authz.ownershipChecks.map((item) => `- ${item}`) : ["- none"]),
		"rollback_checks:",
		...(authz.rollbackChecks.length ? authz.rollbackChecks.map((item) => `- ${item}`) : ["- none"]),
		"executions:",
		...(authz.executions.length
			? authz.executions.map(
					(item) =>
						`- ${item.label} [${item.status}] exit=${item.exit ?? "n/a"} stdout_sha256=${item.stdoutHash ?? "n/a"} stderr_sha256=${item.stderrHash ?? "n/a"}`,
				)
			: ["- planned web authz state capture; run re_web_authz_state run <url> [timeout-ms]"]),
		"runtime_anchors:",
		...(authz.runtimeAnchors.length ? authz.runtimeAnchors.map((item) => `- ${item}`) : ["- none"]),
		"replay_commands:",
		...(authz.replayCommands.length ? authz.replayCommands.map((item) => `- ${item}`) : ["- none"]),
		...(options.includeCaptureScript ? ["capture_script:", "```bash", authz.captureScript, "```"] : []),
		"web_authz_next_actions:",
		...(authz.nextActions.length ? authz.nextActions.map((item) => `- ${item}`) : ["- re_verifier matrix"]),
		`next_web_authz_command: ${authz.mode === "run" ? "re_verifier matrix" : `re_web_authz_state run ${authz.url ?? "<url>"}`}`,
		"source_artifacts:",
		...(authz.sourceArtifacts.length ? authz.sourceArtifacts.map((item) => `- ${item}`) : ["- none"]),
	]
		.filter(Boolean)
		.join("\n");
}

export function writeWebAuthzStateArtifact(authz: WebAuthzStateArtifact, dependencies: WebRuntimeDependencies): string {
	dependencies.ensureReconStorage();
	const path = join(
		dependencies.evidenceWebAuthzDir(),
		`${authz.timestamp.replace(/[:.]/g, "-")}-${slug(authz.url ?? authz.target ?? "web-authz")}-${authz.mode}.md`,
	);
	dependencies.writePrivateTextFile(
		path,
		[
			"# REPI Web Authz State Artifact",
			"",
			formatWebAuthzState(authz, path, { includeCaptureScript: true }),
			"",
			"## JSON",
			"",
			"```json",
			JSON.stringify(authz, null, 2),
			"```",
			"",
		].join("\n"),
	);
	dependencies.appendEvidence({
		kind: authz.mode === "run" ? "runtime" : "artifact",
		title: `web-authz-state-${authz.mode} ${authz.url ?? authz.target ?? "no-url"}`,
		fact: `Web authz state ${authz.mode}: url=${authz.url ?? "<missing>"}, executions=${authz.executions.length}, anchors=${authz.runtimeAnchors.length}`,
		command: `re_web_authz_state ${authz.mode}${authz.url ? ` ${authz.url}` : ""}`,
		path,
		verify: `cat ${path}`,
		confidence: "web/API authz state machine runtime capture",
	});
	dependencies.updateMissionCheckpoint(
		"web_authz_ready",
		dependencies.runtimeCheckpointStatus(authz.mode, authz.executions, authz.url ?? authz.target),
		path,
	);
	return path;
}

export async function runWebAuthzState(
	pi: ExtensionAPI,
	options: WebRuntimeOptions = {},
	dependencies: WebRuntimeDependencies,
): Promise<string> {
	const url = inferWebAuthzUrl(options.url ?? options.target, dependencies);
	const timeoutMs = Math.max(3000, Math.min(180000, Math.floor(options.timeoutMs ?? 15000)));
	const command = webAuthzStateShellCommand(url, timeoutMs);
	const result = await pi.exec("bash", ["-lc", command], { timeout: timeoutMs + 10000 });
	const anchors = webAuthzStateAnchors(result.stdout, result.stderr);
	const authz = buildWebAuthzStateArtifact(
		{
			...options,
			url,
			mode: "run",
			timeoutMs,
			executions: [
				{
					label: "web-authz-state-capture",
					command,
					status: /\[web-authz-blocked\] reason=(missing_url|node_or_url_missing)/i.test(
						`${result.stdout}\n${result.stderr}`,
					)
						? "blocked"
						: result.code === 0
							? "passed"
							: "failed",
					exit: result.code,
					killed: result.killed,
					stdoutHash: dependencies.replayHash(result.stdout),
					stderrHash: dependencies.replayHash(result.stderr),
					stdoutHead: truncateMiddle(result.stdout.trim(), 3000),
					stderrHead: truncateMiddle(result.stderr.trim(), 2000),
				},
			],
			runtimeAnchors: anchors,
		},
		dependencies,
	);
	const path = writeWebAuthzStateArtifact(authz, dependencies);
	return [
		formatWebAuthzState(authz, path),
		result.stdout.trim() ? ["stdout_head:", "```", truncateMiddle(result.stdout.trim(), 1600), "```"].join("\n") : "",
		result.stderr.trim() ? ["stderr_head:", "```", truncateMiddle(result.stderr.trim(), 800), "```"].join("\n") : "",
	]
		.filter(Boolean)
		.join("\n");
}

export function buildWebAuthzStateOutput(
	action: "plan" | "show" = "plan",
	options: WebRuntimeOptions = {},
	dependencies: WebRuntimeDependencies,
): string {
	if (action === "show") {
		const path = latestWebAuthzStateArtifactPath(dependencies);
		if (!path) return "web_authz_state:\nstatus: missing\nnext: re_web_authz_state plan <url>";
		return compactStoredArtifact("web_authz_state", path, dependencies.readText(path));
	}
	const authz = buildWebAuthzStateArtifact({ ...options, mode: "plan" }, dependencies);
	const path = writeWebAuthzStateArtifact(authz, dependencies);
	return formatWebAuthzState(authz, path);
}

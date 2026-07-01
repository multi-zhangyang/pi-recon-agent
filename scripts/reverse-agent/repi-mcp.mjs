#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { capStdioBuffer, killWithGrace, safeWriteLine, drainHttpBody, readHttpTextBounded } from "./lib/mcp-stdio-helpers.mjs";

// REPI opt #173: stdio MCP child hardening knobs.
// REPI_MCP_STDIO_MAX_BYTES caps the accumulated stdout buffer (rolling tail).
// 0 disables the cap. Default 8MB — comfortably fits normal JSON-RPC frames
// while bounding a runaway/misbehaving server before the 10s timeout OOMs us.
const STDIO_MAX_BYTES = Number(process.env.REPI_MCP_STDIO_MAX_BYTES ?? 0) || (8 * 1024 * 1024);
// SIGTERM→SIGKILL grace window for stdio MCP children that ignore SIGTERM.
const STDIO_KILL_GRACE_MS = Number(process.env.REPI_MCP_STDIO_KILL_GRACE_MS ?? 0) || 2000;
// HTTP MCP body cap. `Response.text()` is all-or-nothing; keep remote MCP
// failures from turning into CLI OOMs while leaving room for normal resources.
const HTTP_BODY_MAX_BYTES = Number(process.env.REPI_MCP_HTTP_BODY_MAX_BYTES ?? 0) || (8 * 1024 * 1024);

const root = process.argv[2] && !process.argv[2].startsWith("-") ? process.argv[2] : process.cwd();
const argv = process.argv.slice(process.argv[2] && !process.argv[2].startsWith("-") ? 3 : 2);
const command = argv[0] ?? "status";
const json = argv.includes("--json");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const cwd = process.cwd();

function usage() {
	return `REPI MCP manager

Usage:
  repi mcp status [--json]
  repi mcp list [--json]
  repi mcp probe <server-id> [--json]
  repi mcp search <server-id> [query] [--json]
  repi mcp call <server-id> <tool-name> [json-args] [--json]
  repi mcp resources <server-id> [--json]
  repi mcp read-resource <server-id> <uri> [--json]
  repi mcp prompts <server-id> [--json]
  repi mcp get-prompt <server-id> <prompt-name> [json-args] [--json]
  repi mcp auth-info <server-id> [--json]

Config files:
  ~/.repi/agent/mcp.json
  <cwd>/.repi/mcp.json

Example ~/.repi/agent/mcp.json:
{
  "mcpServers": {
    "demo": { "transport": "stdio", "command": "node", "args": ["/path/server.js"], "autoRegisterTools": true },
    "remote": { "transport": "http", "url": "https://mcp.example.com/mcp", "headers": { "Authorization": "Bearer $MCP_API_KEY" }, "autoRegisterTools": true }
  }
}
`;
}

function redact(text) {
	return String(text ?? "")
		.replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/(API_KEY|AUTH_TOKEN|TOKEN|SECRET|PASSWORD)=([^\s]+)/gi, "$1=<redacted>");
}
function readJson(path) {
	if (!existsSync(path)) return undefined;
	try { return JSON.parse(readFileSync(path, "utf8")); } catch { return undefined; }
}
function redactConfig(cfg) {
	const out = { ...cfg };
	if (out.env) out.env = Object.fromEntries(Object.entries(out.env).map(([k, v]) => [k, String(v).startsWith("$") ? v : "<redacted>"]));
	if (out.headers) out.headers = Object.fromEntries(Object.entries(out.headers).map(([k, v]) => [k, String(v).startsWith("$") ? v : "<redacted>"]));
	if (out.bearerToken) out.bearerToken = String(out.bearerToken).startsWith("$") ? out.bearerToken : "<redacted>";
	if (out.oauth?.accessToken) out.oauth = { ...out.oauth, accessToken: String(out.oauth.accessToken).startsWith("$") ? out.oauth.accessToken : "<redacted>" };
	return out;
}
function redactServers(servers) { return servers.map(s => ({ ...s, config: redactConfig(s.config) })); }
function configPaths() { return [join(agentDir, "mcp.json"), join(cwd, ".repi", "mcp.json")]; }
function loadServers() {
	const map = new Map();
	for (const sourcePath of configPaths()) {
		const parsed = readJson(sourcePath);
		if (!parsed) continue;
		const servers = parsed.mcpServers || parsed.servers || {};
		for (const [id, cfg] of Object.entries(servers)) map.set(id, { id, config: { transport: cfg.url ? "http" : "stdio", ...cfg }, sourcePath });
	}
	return [...map.values()].sort((a,b)=>a.id.localeCompare(b.id));
}
function envValue(value) { return String(value).startsWith("$") ? (process.env[String(value).slice(1)] || "") : String(value); }
function envMap(env) { const out = { ...process.env }; for (const [k,v] of Object.entries(env || {})) out[k] = envValue(v); return out; }
function headerValue(value) { return envValue(value).replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_m, name) => process.env[name] || ""); }
function headerMap(cfg, sessionId, protocolVersion = "2025-11-25") {
	const headers = { ...(cfg.headers || {}), Accept: "application/json, text/event-stream", "Content-Type": "application/json", "MCP-Protocol-Version": protocolVersion };
	for (const [k, v] of Object.entries(headers)) headers[k] = headerValue(v);
	if (cfg.bearerToken && !Object.keys(headers).some(k => k.toLowerCase() === "authorization")) headers.Authorization = `Bearer ${envValue(cfg.bearerToken)}`;
	if (cfg.oauth?.accessToken && !Object.keys(headers).some(k => k.toLowerCase() === "authorization")) headers.Authorization = `${cfg.oauth.tokenType || "Bearer"} ${envValue(cfg.oauth.accessToken)}`;
	if (sessionId) headers["Mcp-Session-Id"] = sessionId;
	return headers;
}
function parseSseJsonMessages(text) {
	const messages = [];
	for (const rawEvent of String(text || "").split(/\r?\n\r?\n/)) {
		const data = rawEvent.split(/\r?\n/).filter(line => line.startsWith("data:")).map(line => line.slice(5).trimStart()).join("\n").trim();
		if (!data || data === "[DONE]") continue;
		try { messages.push(JSON.parse(data)); } catch {}
	}
	return messages;
}
function parseBearerParam(header, key) {
	const match = String(header || "").match(new RegExp(`${key}=(?:"([^"]+)"|([^,\\s]+))`, "i"));
	return match?.[1] || match?.[2];
}
async function authInfo(entry) {
	const cfg = entry.config;
	if ((cfg.transport || "stdio") !== "http") return { serverId: entry.id, ok: false, transport: cfg.transport || "stdio", error: "auth_info_only_applies_to_http_mcp" };
	if (!cfg.url) return { serverId: entry.id, ok: false, transport: "http", error: "missing_url" };
	const timeoutMs = cfg.timeoutMs || 10000;
	let status; let wwwAuthenticate; let resourceMetadataUrl = cfg.oauth?.resourceMetadataUrl; let resourceMetadata;
	try {
		if (!resourceMetadataUrl) {
			const controller = new AbortController(); const timer = setTimeout(() => controller.abort(new Error("MCP HTTP request timeout")), timeoutMs);
			try {
				const response = await fetch(cfg.url, { method: "POST", headers: { Accept: "application/json, text/event-stream", "Content-Type": "application/json", "MCP-Protocol-Version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "repi", version: "cli" } } }), signal: controller.signal });
				status = response.status;
				wwwAuthenticate = redact(response.headers.get("www-authenticate") || "");
				const raw = parseBearerParam(response.headers.get("www-authenticate"), "resource_metadata") || parseBearerParam(response.headers.get("www-authenticate"), "resource_metadata_uri");
				if (raw) resourceMetadataUrl = new URL(raw, cfg.url).toString();
				// opt #173 / #49: we only read headers here — drain the body so
				// the keep-alive socket is released back to the pool instead of
				// being stranded until GC.
				await drainHttpBody(response);
			} finally { clearTimeout(timer); }
		}
		if (resourceMetadataUrl) {
			const controller = new AbortController(); const timer = setTimeout(() => controller.abort(new Error("MCP HTTP request timeout")), timeoutMs);
			try {
				const response = await fetch(resourceMetadataUrl, { headers: { Accept: "application/json" }, signal: controller.signal });
				status = status || response.status;
				const text = await readHttpTextBounded(response, HTTP_BODY_MAX_BYTES, "mcp_oauth_metadata_body");
				try { resourceMetadata = JSON.parse(text); } catch { resourceMetadata = redact(text.slice(0, 2000)); }
			} finally { clearTimeout(timer); }
		}
		return { serverId: entry.id, ok: true, transport: "http", url: cfg.url, status, wwwAuthenticate, resourceMetadataUrl, resourceMetadata };
	} catch (error) {
		return { serverId: entry.id, ok: false, transport: "http", url: cfg.url, status, wwwAuthenticate, resourceMetadataUrl, error: redact(error.message || String(error)) };
	}
}
async function httpJsonRpcPost(entry, state, message, expectId) {
	const cfg = entry.config;
	if (!cfg.url) throw new Error("missing_url");
	const timeoutMs = cfg.timeoutMs || 10000;
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(new Error("MCP HTTP request timeout")), timeoutMs);
	try {
		const response = await fetch(cfg.url, { method: "POST", headers: headerMap(cfg, state.sessionId, state.protocolVersion), body: JSON.stringify(message), signal: controller.signal });
		const sessionId = response.headers.get("mcp-session-id");
		if (sessionId) state.sessionId = sessionId;
		if (!expectId && response.ok) {
			await drainHttpBody(response);
			return undefined;
		}
		const bodyText = await readHttpTextBounded(response, HTTP_BODY_MAX_BYTES, "mcp_http_response_body");
		if (!response.ok) throw new Error(`MCP HTTP ${response.status}${bodyText ? `: ${redact(bodyText).slice(0,1000)}` : ""}`);
		if (!expectId) return undefined;
		const contentType = response.headers.get("content-type") || "";
		let messages = [];
		if (contentType.includes("text/event-stream")) messages = parseSseJsonMessages(bodyText);
		else {
			try {
				const parsed = JSON.parse(bodyText);
				messages = Array.isArray(parsed) ? parsed : [parsed];
			} catch {
				messages = parseSseJsonMessages(bodyText);
			}
		}
		const msg = messages.find(item => item?.id === expectId) || messages.find(item => item?.id !== undefined);
		if (!msg) throw new Error("MCP HTTP response did not contain a JSON-RPC result");
		if (msg.error) throw new Error(redact(JSON.stringify(msg.error)));
		return msg.result || {};
	} finally {
		clearTimeout(timer);
	}
}
async function httpMcpRequest(entry, method, params, mapResult) {
	const cfg = entry.config;
	if (cfg.disabled) return { serverId: entry.id, ok: false, transport: "http", url: cfg.url, error: "server_disabled" };
	if (!cfg.url) return { serverId: entry.id, ok: false, transport: "http", error: "missing_url" };
	async function attempt() {
		const state = { sessionId: undefined, protocolVersion: "2025-11-25" };
		const init = await httpJsonRpcPost(entry, state, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "repi", version: "cli" } } }, 1);
		if (typeof init?.protocolVersion === "string") state.protocolVersion = init.protocolVersion;
		await httpJsonRpcPost(entry, state, { jsonrpc: "2.0", method: "notifications/initialized" });
		const raw = await httpJsonRpcPost(entry, state, { jsonrpc: "2.0", id: 2, method, params: params || {} }, 2);
		return mapResult(raw || {}, entry, init || {});
	}
	try {
		return await attempt();
	} catch (error) {
		const message = error?.message || String(error);
		if (/MCP HTTP (?:404|408|409|429|500|502|503|504)|MCP HTTP request timeout|fetch failed|ECONN|socket|connection|reset|terminated|timeout/i.test(message)) {
			try {
				return await attempt();
			} catch (retryError) {
				return { serverId: entry.id, ok: false, transport: "http", url: cfg.url, error: redact(retryError?.message || String(retryError)) };
			}
		}
		return { serverId: entry.id, ok: false, transport: "http", url: cfg.url, error: redact(message) };
	}
}
function writeLine(child, msg) { safeWriteLine(child.stdin, `${JSON.stringify(msg)}\n`); }
function toolAllowed(cfg, toolName) {
	const allowed = new Set(cfg.allowedTools || []);
	const blocked = new Set(cfg.blockedTools || []);
	return (allowed.size === 0 || allowed.has(toolName)) && !blocked.has(toolName);
}
function parseJsonArgs(raw) {
	if (!raw || raw === "--json") return {};
	try {
		const parsed = JSON.parse(raw);
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
	} catch (error) {
		throw new Error(`invalid_json_args: ${error.message}`);
	}
}
function normalizeCallContent(result) {
	const content = Array.isArray(result?.content) ? result.content : [];
	const normalized = [];
	for (const item of content) {
		if (item?.type === "text" && typeof item.text === "string") {
			normalized.push({ type: "text", text: redact(item.text) });
		} else if (item?.type === "image" && typeof item.data === "string" && typeof item.mimeType === "string") {
			normalized.push({ type: "image", data: item.data, mimeType: item.mimeType });
		} else if (item) {
			normalized.push({ type: "text", text: redact(JSON.stringify(item)) });
		}
	}
	if (!normalized.length) normalized.push({ type: "text", text: "MCP tool returned no content." });
	return normalized;
}
function normalizeResourceRead(result, uri) {
	const normalized = [];
	for (const item of Array.isArray(result?.contents) ? result.contents : []) {
		if (typeof item?.text === "string") {
			normalized.push({ type: "text", text: redact([`uri=${item.uri || uri}`, item.mimeType ? `mimeType=${item.mimeType}` : undefined, "", item.text].filter(v => v !== undefined).join("\n")) });
		} else if (typeof item?.blob === "string" && typeof item?.mimeType === "string" && item.mimeType.startsWith("image/")) {
			normalized.push({ type: "image", data: item.blob, mimeType: item.mimeType });
		} else if (item) {
			normalized.push({ type: "text", text: redact(JSON.stringify(item)) });
		}
	}
	if (!normalized.length) normalized.push({ type: "text", text: "MCP resource returned no content." });
	return normalized;
}
function normalizePromptGet(result, promptName) {
	const lines = [`prompt=${promptName}`];
	if (typeof result?.description === "string") lines.push(`description=${redact(result.description)}`);
	const messages = Array.isArray(result?.messages) ? result.messages : [];
	for (const [index, message] of messages.entries()) {
		const role = typeof message?.role === "string" ? message.role : "unknown";
		const content = message?.content;
		if (content?.type === "text" && typeof content.text === "string") {
			lines.push(`\n[${index}] role=${role}\n${redact(content.text)}`);
		} else if (content?.type === "image") {
			lines.push(`\n[${index}] role=${role}\n[image:${content.mimeType || "unknown"}]`);
		} else {
			lines.push(`\n[${index}] role=${role}\n${redact(JSON.stringify(content ?? message))}`);
		}
	}
	return lines.join("\n");
}
function simpleMcpRequest(entry, method, params, mapResult) {
	if ((entry.config.transport || "stdio") === "http") return httpMcpRequest(entry, method, params, mapResult);
	return new Promise((resolveRequest) => {
		const cfg = entry.config;
		if (cfg.disabled) return resolveRequest({ serverId: entry.id, ok: false, transport: cfg.transport || "stdio", error: "server_disabled" });
		if (!cfg.command) return resolveRequest({ serverId: entry.id, ok: false, transport: "stdio", error: "missing_command" });
		const timeoutMs = cfg.timeoutMs || 10000;
		const child = spawn(cfg.command, cfg.args || [], { cwd: cfg.cwd ? resolve(cfg.cwd) : root, env: envMap(cfg.env), stdio: ["pipe", "pipe", "pipe"] });
		let buffer = ""; let stderr = ""; let stage = "init"; let done = false; let id = 1;
		function finish(result) { if (done) return; done = true; clearTimeout(timer); killWithGrace(child, STDIO_KILL_GRACE_MS).then(() => resolveRequest({ ...result, stderrTail: stderr.slice(-1000) })); }
		function req(reqMethod, reqParams) { const rid = id++; writeLine(child, { jsonrpc: "2.0", id: rid, method: reqMethod, ...(reqParams ? { params: reqParams } : {}) }); return rid; }
		const timer = setTimeout(() => finish({ serverId: entry.id, ok: false, transport: "stdio", error: `timeout_${stage}` }), timeoutMs);
		child.stderr.on("data", c => { stderr += redact(String(c)); if (stderr.length > 4000) stderr = stderr.slice(-4000); });
		child.on("error", e => finish({ serverId: entry.id, ok: false, transport: "stdio", error: redact(e.message) }));
		child.on("close", (code, signal) => { if (!done) finish({ serverId: entry.id, ok: false, transport: "stdio", error: `server_exited code=${code} signal=${signal}` }); });
		// Foundational opt #272: piped child stdio emits 'error' (EIO/EPIPE)
		// independent of the child's own 'error'/'close' — finish() calls
		// killWithGrace (SIGTERM→SIGKILL) on timeout/server_exited, and killing a
		// child mid-write to its stdout/stderr pipe tears the pipe → the parent-
		// side Readable emits 'error' with NO listener → Unhandled 'error' event
		// crashes the whole `repi mcp` run. Swallow so the close handler still
		// resolves with whatever was captured. Same doctrine as opt #188
		// (repi-swarm-llm-run) / #36 (mcp-manager) / #40 (waitForChildProcess).
		child.stdout?.on("error", () => {});
		child.stderr?.on("error", () => {});
		child.stdout.on("data", chunk => {
			buffer = capStdioBuffer(buffer, chunk, STDIO_MAX_BYTES);
			while (buffer.includes("\n")) {
				const idx = buffer.indexOf("\n"); const line = buffer.slice(0, idx).trim(); buffer = buffer.slice(idx + 1);
				if (!line) continue;
				let msg; try { msg = JSON.parse(line); } catch { continue; }
				if (msg.error) return finish({ serverId: entry.id, ok: false, transport: "stdio", error: redact(JSON.stringify(msg.error)) });
				if (stage === "init" && msg.id === 1) { stage = method; writeLine(child, { jsonrpc: "2.0", method: "notifications/initialized" }); req(method, params || {}); continue; }
				if (stage === method && msg.id === 2) return finish(mapResult(msg.result || {}, entry));
			}
		});
		req("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "repi", version: "cli" } });
	});
}
function probe(entry) {
	if ((entry.config.transport || "stdio") === "http") {
		return httpMcpRequest(entry, "tools/list", {}, (raw, selected, init) => ({
			serverId: selected.id,
			ok: true,
			transport: "http",
			url: selected.config.url,
			protocolVersion: init.protocolVersion || "2025-11-25",
			tools: Array.isArray(raw.tools) ? raw.tools.map(t => ({ name: t.name, description: t.description })).filter(t => t.name && toolAllowed(selected.config, t.name)) : [],
		}));
	}
	return new Promise((resolveProbe) => {
		const cfg = entry.config;
		if (cfg.disabled) return resolveProbe({ serverId: entry.id, ok: false, transport: cfg.transport || "stdio", tools: [], error: "server_disabled" });
		if (!cfg.command) return resolveProbe({ serverId: entry.id, ok: false, transport: "stdio", tools: [], error: "missing_command" });
		const timeoutMs = cfg.timeoutMs || 10000;
		const child = spawn(cfg.command, cfg.args || [], { cwd: cfg.cwd ? resolve(cfg.cwd) : root, env: envMap(cfg.env), stdio: ["pipe", "pipe", "pipe"] });
		let buffer = ""; let stderr = ""; let stage = "init"; let done = false; const pending = new Map(); let id = 1;
		function finish(result) { if (done) return; done = true; clearTimeout(timer); killWithGrace(child, STDIO_KILL_GRACE_MS).then(() => resolveProbe({ ...result, stderrTail: stderr.slice(-1000) })); }
		function req(method, params) { const rid = id++; writeLine(child, { jsonrpc: "2.0", id: rid, method, ...(params ? { params } : {}) }); return rid; }
		const timer = setTimeout(() => finish({ serverId: entry.id, ok: false, transport: "stdio", tools: [], error: `timeout_${stage}` }), timeoutMs);
		child.stderr.on("data", c => { stderr += redact(String(c)); if (stderr.length > 4000) stderr = stderr.slice(-4000); });
		child.on("error", e => finish({ serverId: entry.id, ok: false, transport: "stdio", tools: [], error: redact(e.message) }));
		child.on("close", (code, signal) => { if (!done) finish({ serverId: entry.id, ok: false, transport: "stdio", tools: [], error: `server_exited code=${code} signal=${signal}` }); });
		// Foundational opt #272: swallow piped-stdio 'error' (EIO/EPIPE on kill)
		// so it doesn't crash the run. See simpleMcpRequest for the full rationale.
		child.stdout?.on("error", () => {});
		child.stderr?.on("error", () => {});
		child.stdout.on("data", chunk => {
			buffer = capStdioBuffer(buffer, chunk, STDIO_MAX_BYTES);
			while (buffer.includes("\n")) {
				const idx = buffer.indexOf("\n"); const line = buffer.slice(0, idx).trim(); buffer = buffer.slice(idx + 1);
				if (!line) continue;
				let msg; try { msg = JSON.parse(line); } catch { continue; }
				if (msg.error) return finish({ serverId: entry.id, ok: false, transport: "stdio", tools: [], error: redact(JSON.stringify(msg.error)) });
				if (stage === "init" && msg.id === 1) { stage = "tools"; writeLine(child, { jsonrpc: "2.0", method: "notifications/initialized" }); req("tools/list", {}); continue; }
				if (stage === "tools" && msg.id === 2) {
					const tools = Array.isArray(msg.result?.tools) ? msg.result.tools
						.map(t => ({ name: t.name, description: t.description }))
						.filter(t => t.name && toolAllowed(cfg, t.name)) : [];
					return finish({ serverId: entry.id, ok: true, transport: "stdio", protocolVersion: "2025-11-25", tools });
				}
			}
		});
		req("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "repi", version: "cli" } });
	});
}
function callTool(entry, toolName, args) {
	if ((entry.config.transport || "stdio") === "http") {
		if (!toolAllowed(entry.config, toolName)) return Promise.resolve({ serverId: entry.id, toolName, ok: false, transport: "http", url: entry.config.url, error: "tool_not_allowed" });
		return httpMcpRequest(entry, "tools/call", { name: toolName, arguments: args || {} }, (raw, selected) => ({
			serverId: selected.id,
			toolName,
			ok: !raw?.isError,
			transport: "http",
			url: selected.config.url,
			isError: raw?.isError === true,
			content: normalizeCallContent(raw),
		}));
	}
	return new Promise((resolveCall) => {
		const cfg = entry.config;
		if (cfg.disabled) return resolveCall({ serverId: entry.id, toolName, ok: false, transport: cfg.transport || "stdio", error: "server_disabled" });
		if (!cfg.command) return resolveCall({ serverId: entry.id, toolName, ok: false, transport: "stdio", error: "missing_command" });
		if (!toolAllowed(cfg, toolName)) return resolveCall({ serverId: entry.id, toolName, ok: false, transport: "stdio", error: "tool_not_allowed" });
		const timeoutMs = cfg.timeoutMs || 10000;
		const child = spawn(cfg.command, cfg.args || [], { cwd: cfg.cwd ? resolve(cfg.cwd) : root, env: envMap(cfg.env), stdio: ["pipe", "pipe", "pipe"] });
		let buffer = ""; let stderr = ""; let stage = "init"; let done = false; let id = 1;
		function finish(result) { if (done) return; done = true; clearTimeout(timer); killWithGrace(child, STDIO_KILL_GRACE_MS).then(() => resolveCall({ ...result, stderrTail: stderr.slice(-1000) })); }
		function req(method, params) { const rid = id++; writeLine(child, { jsonrpc: "2.0", id: rid, method, ...(params ? { params } : {}) }); return rid; }
		const timer = setTimeout(() => finish({ serverId: entry.id, toolName, ok: false, transport: "stdio", error: `timeout_${stage}` }), timeoutMs);
		child.stderr.on("data", c => { stderr += redact(String(c)); if (stderr.length > 4000) stderr = stderr.slice(-4000); });
		child.on("error", e => finish({ serverId: entry.id, toolName, ok: false, transport: "stdio", error: redact(e.message) }));
		child.on("close", (code, signal) => { if (!done) finish({ serverId: entry.id, toolName, ok: false, transport: "stdio", error: `server_exited code=${code} signal=${signal}` }); });
		// Foundational opt #272: swallow piped-stdio 'error' (EIO/EPIPE on kill)
		// so it doesn't crash the run. See simpleMcpRequest for the full rationale.
		child.stdout?.on("error", () => {});
		child.stderr?.on("error", () => {});
		child.stdout.on("data", chunk => {
			buffer = capStdioBuffer(buffer, chunk, STDIO_MAX_BYTES);
			while (buffer.includes("\n")) {
				const idx = buffer.indexOf("\n"); const line = buffer.slice(0, idx).trim(); buffer = buffer.slice(idx + 1);
				if (!line) continue;
				let msg; try { msg = JSON.parse(line); } catch { continue; }
				if (msg.error) return finish({ serverId: entry.id, toolName, ok: false, transport: "stdio", error: redact(JSON.stringify(msg.error)) });
				if (stage === "init" && msg.id === 1) { stage = "call"; writeLine(child, { jsonrpc: "2.0", method: "notifications/initialized" }); req("tools/call", { name: toolName, arguments: args || {} }); continue; }
				if (stage === "call" && msg.id === 2) {
					return finish({ serverId: entry.id, toolName, ok: !msg.result?.isError, transport: "stdio", isError: msg.result?.isError === true, content: normalizeCallContent(msg.result) });
				}
			}
		});
		req("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "repi", version: "cli" } });
	});
}
function textStatus(servers) {
	const lines = ["MCP servers:", `config_paths: ${configPaths().join(", ")}`];
	if (!servers.length) lines.push("- none");
	for (const s of servers) lines.push(`- ${s.id} [${s.config.transport || "stdio"}${s.config.disabled ? ", disabled" : ""}${s.config.autoRegisterTools || s.config.enableTools ? ", tools:auto" : ""}] source=${s.sourcePath}`);
	return lines.join("\n");
}
function textProbe(results) {
	const lines = ["MCP probe results:"];
	for (const r of results) {
		lines.push(`- ${r.serverId} [${r.ok ? "ok" : "fail"}] tools=${r.tools?.length || 0}${r.error ? ` error=${r.error}` : ""}`);
		for (const t of (r.tools || []).slice(0,20)) lines.push(`  tool: ${t.name}${t.description ? ` — ${t.description}` : ""}`);
	}
	return lines.join("\n");
}
function textSearch(result) {
	const lines = [`MCP tool search: ${result.serverId} [${result.ok ? "ok" : "fail"}] query=${JSON.stringify(result.query || "")} total=${result.total || 0}`];
	if (result.error) lines.push(`error=${result.error}`);
	for (const t of (result.tools || [])) lines.push(`- ${t.name}${t.description ? ` — ${t.description}` : ""}${t.inputSchema ? `\n  inputSchema=${JSON.stringify(t.inputSchema)}` : ""}`);
	return lines.join("\n");
}
function textCall(result) {
	const lines = [`MCP call: ${result.serverId}/${result.toolName} [${result.ok ? "ok" : "fail"}]`];
	if (result.error) lines.push(`error=${result.error}`);
	for (const item of result.content || []) {
		if (item.type === "text") lines.push(item.text);
		else lines.push(`[${item.type}:${item.mimeType || "unknown"}]`);
	}
	if (result.stderrTail) lines.push(`stderr_tail=${result.stderrTail.replace(/\s+/g, " ").slice(-500)}`);
	return lines.join("\n");
}
function textResources(result) {
	const lines = [`MCP resources: ${result.serverId} [${result.ok ? "ok" : "fail"}]`];
	if (result.error) lines.push(`error=${result.error}`);
	for (const resource of result.resources || []) {
		lines.push(`- ${resource.uri}${resource.name ? ` — ${resource.name}` : ""}`);
		if (resource.mimeType) lines.push(`  mimeType=${resource.mimeType}`);
		if (resource.description) lines.push(`  description=${resource.description}`);
	}
	if (result.stderrTail) lines.push(`stderr_tail=${result.stderrTail.replace(/\s+/g, " ").slice(-500)}`);
	return lines.join("\n");
}
function textResource(result) {
	const lines = [`MCP resource: ${result.serverId}/${result.uri} [${result.ok ? "ok" : "fail"}]`];
	if (result.error) lines.push(`error=${result.error}`);
	for (const item of result.content || []) {
		if (item.type === "text") lines.push(item.text);
		else lines.push(`[${item.type}:${item.mimeType || "unknown"}]`);
	}
	if (result.stderrTail) lines.push(`stderr_tail=${result.stderrTail.replace(/\s+/g, " ").slice(-500)}`);
	return lines.join("\n");
}
function textPrompts(result) {
	const lines = [`MCP prompts: ${result.serverId} [${result.ok ? "ok" : "fail"}]`];
	if (result.error) lines.push(`error=${result.error}`);
	for (const prompt of result.prompts || []) {
		lines.push(`- ${prompt.name}${prompt.description ? ` — ${prompt.description}` : ""}`);
		if (prompt.arguments) lines.push(`  arguments=${JSON.stringify(prompt.arguments)}`);
	}
	if (result.stderrTail) lines.push(`stderr_tail=${result.stderrTail.replace(/\s+/g, " ").slice(-500)}`);
	return lines.join("\n");
}
function textAuthInfo(result) {
	const lines = [`MCP auth info: ${result.serverId} [${result.ok ? "ok" : "fail"}] transport=${result.transport || "unknown"}`];
	if (result.url) lines.push(`url=${result.url}`);
	if (result.status) lines.push(`status=${result.status}`);
	if (result.wwwAuthenticate) lines.push(`wwwAuthenticate=${result.wwwAuthenticate}`);
	if (result.resourceMetadataUrl) lines.push(`resourceMetadataUrl=${result.resourceMetadataUrl}`);
	if (result.resourceMetadata) lines.push(`resourceMetadata=${JSON.stringify(result.resourceMetadata, null, 2)}`);
	if (result.error) lines.push(`error=${result.error}`);
	return lines.join("\n");
}
function textPrompt(result) {
	const lines = [`MCP prompt: ${result.serverId}/${result.name} [${result.ok ? "ok" : "fail"}]`];
	if (result.error) lines.push(`error=${result.error}`);
	if (result.text) lines.push(result.text);
	if (result.stderrTail) lines.push(`stderr_tail=${result.stderrTail.replace(/\s+/g, " ").slice(-500)}`);
	return lines.join("\n");
}

if (["--help", "-h", "help"].includes(command)) { console.log(usage()); process.exit(0); }
const servers = loadServers();
if (["status", "config"].includes(command)) {
	const report = { kind: "repi-mcp-status", ok: true, configPaths: configPaths(), servers: redactServers(servers) };
	console.log(json ? JSON.stringify(report, null, 2) : textStatus(servers));
	process.exit(0);
}
if (command === "auth-info" || command === "auth") {
	const target = argv[1];
	if (!target) { console.error(usage()); process.exit(2); }
	const selected = servers.find(s => s.id === target || s.id.startsWith(target));
	const result = selected ? await authInfo(selected) : { serverId: target, ok: false, transport: "http", error: "server_not_found" };
	console.log(json ? JSON.stringify(result, null, 2) : textAuthInfo(result));
	process.exit(result.ok ? 0 : 1);
}
if (command === "search" || command === "find") {
	const target = argv[1];
	const query = argv.filter(arg => arg !== "--json").slice(2).join(" ").trim();
	if (!target) { console.error(usage()); process.exit(2); }
	const selected = servers.find(s => s.id === target || s.id.startsWith(target));
	if (!selected) {
		const result = { serverId: target, ok: false, query, total: 0, limit: 20, tools: [], error: "server_not_found" };
		console.log(json ? JSON.stringify(result, null, 2) : textSearch(result));
		process.exit(1);
	}
	const probed = await probe(selected);
	const allTools = probed.tools || [];
	const lower = query.toLowerCase();
	const matched = allTools.filter(t => !lower || `${t.name}\n${t.description || ""}`.toLowerCase().includes(lower));
	const result = { serverId: selected.id, ok: probed.ok, query, total: matched.length, limit: 20, tools: matched.slice(0, 20), error: probed.error };
	console.log(json ? JSON.stringify(result, null, 2) : textSearch(result));
	process.exit(result.ok ? 0 : 1);
}
if (command === "call") {
	const target = argv[1];
	const toolName = argv[2];
	if (!target || !toolName) { console.error(usage()); process.exit(2); }
	let args;
	try { args = parseJsonArgs(argv[3]); } catch (error) { console.error(error.message); process.exit(2); }
	const selected = servers.find(s => s.id === target || s.id.startsWith(target));
	const result = selected ? await callTool(selected, toolName, args) : { serverId: target, toolName, ok: false, transport: "stdio", error: "server_not_found" };
	console.log(json ? JSON.stringify(result, null, 2) : textCall(result));
	process.exit(result.ok ? 0 : 1);
}
if (command === "resources") {
	const target = argv[1];
	if (!target) { console.error(usage()); process.exit(2); }
	const selected = servers.find(s => s.id === target || s.id.startsWith(target));
	const result = selected ? await simpleMcpRequest(selected, "resources/list", {}, (raw, entry) => ({
		serverId: entry.id,
		ok: true,
		transport: entry.config.transport || "stdio",
		url: entry.config.transport === "http" ? entry.config.url : undefined,
		resources: Array.isArray(raw.resources) ? raw.resources.filter(r => typeof r?.uri === "string").map(r => ({ uri: r.uri, name: r.name, description: r.description, mimeType: r.mimeType })) : [],
	})) : { serverId: target, ok: false, transport: "stdio", resources: [], error: "server_not_found" };
	console.log(json ? JSON.stringify(result, null, 2) : textResources(result));
	process.exit(result.ok ? 0 : 1);
}
if (command === "read-resource" || command === "resource" || command === "read") {
	const target = argv[1];
	const uri = argv[2];
	if (!target || !uri) { console.error(usage()); process.exit(2); }
	const selected = servers.find(s => s.id === target || s.id.startsWith(target));
	const result = selected ? await simpleMcpRequest(selected, "resources/read", { uri }, (raw, entry) => ({
		serverId: entry.id,
		uri,
		ok: true,
		transport: entry.config.transport || "stdio",
		url: entry.config.transport === "http" ? entry.config.url : undefined,
		content: normalizeResourceRead(raw, uri),
	})) : { serverId: target, uri, ok: false, transport: "stdio", error: "server_not_found" };
	console.log(json ? JSON.stringify(result, null, 2) : textResource(result));
	process.exit(result.ok ? 0 : 1);
}
if (command === "prompts") {
	const target = argv[1];
	if (!target) { console.error(usage()); process.exit(2); }
	const selected = servers.find(s => s.id === target || s.id.startsWith(target));
	const result = selected ? await simpleMcpRequest(selected, "prompts/list", {}, (raw, entry) => ({
		serverId: entry.id,
		ok: true,
		transport: entry.config.transport || "stdio",
		url: entry.config.transport === "http" ? entry.config.url : undefined,
		prompts: Array.isArray(raw.prompts) ? raw.prompts.filter(p => typeof p?.name === "string").map(p => ({ name: p.name, description: p.description, arguments: p.arguments })) : [],
	})) : { serverId: target, ok: false, transport: "stdio", prompts: [], error: "server_not_found" };
	console.log(json ? JSON.stringify(result, null, 2) : textPrompts(result));
	process.exit(result.ok ? 0 : 1);
}
if (command === "get-prompt" || command === "prompt") {
	const target = argv[1];
	const name = argv[2];
	if (!target || !name) { console.error(usage()); process.exit(2); }
	let args;
	try { args = parseJsonArgs(argv[3]); } catch (error) { console.error(error.message); process.exit(2); }
	const selected = servers.find(s => s.id === target || s.id.startsWith(target));
	const result = selected ? await simpleMcpRequest(selected, "prompts/get", { name, arguments: args || {} }, (raw, entry) => ({
		serverId: entry.id,
		name,
		ok: true,
		transport: entry.config.transport || "stdio",
		url: entry.config.transport === "http" ? entry.config.url : undefined,
		text: normalizePromptGet(raw, name),
	})) : { serverId: target, name, ok: false, transport: "stdio", error: "server_not_found" };
	console.log(json ? JSON.stringify(result, null, 2) : textPrompt(result));
	process.exit(result.ok ? 0 : 1);
}
if (["list", "probe", "tools"].includes(command)) {
	const target = command === "probe" ? argv[1] : undefined;
	const selected = target ? servers.filter(s => s.id === target || s.id.startsWith(target)) : servers.filter(s => !s.config.disabled);
	const results = [];
	for (const server of selected) results.push(await probe(server));
	const report = { kind: "repi-mcp-probe", ok: results.every(r => r.ok), results };
	console.log(json ? JSON.stringify(report, null, 2) : textProbe(results));
	process.exit(report.ok ? 0 : 1);
}
console.error(usage());
process.exit(2);

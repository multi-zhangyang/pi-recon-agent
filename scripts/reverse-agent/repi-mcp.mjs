#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

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

Config files:
  ~/.repi/agent/mcp.json
  <cwd>/.repi/mcp.json

Example ~/.repi/agent/mcp.json:
{
  "mcpServers": {
    "demo": { "transport": "stdio", "command": "node", "args": ["/path/server.js"], "autoRegisterTools": true }
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
function writeLine(child, msg) { child.stdin.write(`${JSON.stringify(msg)}\n`, "utf8"); }
function probe(entry) {
	return new Promise((resolveProbe) => {
		const cfg = entry.config;
		if (cfg.disabled) return resolveProbe({ serverId: entry.id, ok: false, transport: cfg.transport || "stdio", tools: [], error: "server_disabled" });
		if ((cfg.transport || "stdio") === "http") return resolveProbe({ serverId: entry.id, ok: false, transport: "http", url: cfg.url, tools: [], error: "http_transport_configured_but_not_started_yet" });
		if (!cfg.command) return resolveProbe({ serverId: entry.id, ok: false, transport: "stdio", tools: [], error: "missing_command" });
		const timeoutMs = cfg.timeoutMs || 10000;
		const child = spawn(cfg.command, cfg.args || [], { cwd: cfg.cwd ? resolve(cfg.cwd) : root, env: envMap(cfg.env), stdio: ["pipe", "pipe", "pipe"] });
		let buffer = ""; let stderr = ""; let stage = "init"; let done = false; const pending = new Map(); let id = 1;
		function finish(result) { if (done) return; done = true; clearTimeout(timer); try { child.kill("SIGTERM"); } catch {} resolveProbe({ ...result, stderrTail: stderr.slice(-1000) }); }
		function req(method, params) { const rid = id++; writeLine(child, { jsonrpc: "2.0", id: rid, method, ...(params ? { params } : {}) }); return rid; }
		const timer = setTimeout(() => finish({ serverId: entry.id, ok: false, transport: "stdio", tools: [], error: `timeout_${stage}` }), timeoutMs);
		child.stderr.on("data", c => { stderr += redact(String(c)); if (stderr.length > 4000) stderr = stderr.slice(-4000); });
		child.on("error", e => finish({ serverId: entry.id, ok: false, transport: "stdio", tools: [], error: redact(e.message) }));
		child.on("close", (code, signal) => { if (!done) finish({ serverId: entry.id, ok: false, transport: "stdio", tools: [], error: `server_exited code=${code} signal=${signal}` }); });
		child.stdout.on("data", chunk => {
			buffer += String(chunk);
			while (buffer.includes("\n")) {
				const idx = buffer.indexOf("\n"); const line = buffer.slice(0, idx).trim(); buffer = buffer.slice(idx + 1);
				if (!line) continue;
				let msg; try { msg = JSON.parse(line); } catch { continue; }
				if (msg.error) return finish({ serverId: entry.id, ok: false, transport: "stdio", tools: [], error: redact(JSON.stringify(msg.error)) });
				if (stage === "init" && msg.id === 1) { stage = "tools"; writeLine(child, { jsonrpc: "2.0", method: "notifications/initialized" }); req("tools/list", {}); continue; }
				if (stage === "tools" && msg.id === 2) {
					const allowed = new Set(cfg.allowedTools || []);
					const blocked = new Set(cfg.blockedTools || []);
					const tools = Array.isArray(msg.result?.tools) ? msg.result.tools
						.map(t => ({ name: t.name, description: t.description }))
						.filter(t => t.name && (allowed.size === 0 || allowed.has(t.name)) && !blocked.has(t.name)) : [];
					return finish({ serverId: entry.id, ok: true, transport: "stdio", protocolVersion: "2025-11-25", tools });
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

if (["--help", "-h", "help"].includes(command)) { console.log(usage()); process.exit(0); }
const servers = loadServers();
if (["status", "config"].includes(command)) {
	const report = { kind: "repi-mcp-status", ok: true, configPaths: configPaths(), servers: redactServers(servers) };
	console.log(json ? JSON.stringify(report, null, 2) : textStatus(servers));
	process.exit(0);
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

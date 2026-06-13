import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { APP_NAME, getAgentDir, VERSION } from "../config.ts";

export type McpTransport = "stdio" | "http";

export interface McpServerConfig {
	transport?: McpTransport;
	command?: string;
	args?: string[];
	cwd?: string;
	env?: Record<string, string>;
	url?: string;
	headers?: Record<string, string>;
	disabled?: boolean;
	timeoutMs?: number;
	allowedTools?: string[];
	blockedTools?: string[];
}

export interface McpConfigFile {
	mcpServers?: Record<string, McpServerConfig>;
	servers?: Record<string, McpServerConfig>;
}

export interface McpServerEntry {
	id: string;
	config: McpServerConfig;
	sourcePath: string;
}

export interface McpToolSummary {
	name: string;
	description?: string;
	inputSchema?: unknown;
}

export interface McpProbeResult {
	serverId: string;
	ok: boolean;
	transport: McpTransport;
	command?: string;
	url?: string;
	protocolVersion?: string;
	serverInfo?: unknown;
	capabilities?: unknown;
	tools: McpToolSummary[];
	stderrTail?: string;
	error?: string;
}

export interface McpManagerOptions {
	cwd: string;
	agentDir?: string;
}

const DEFAULT_MCP_TIMEOUT_MS = 10000;

const SECRET_PATTERNS: Array<[RegExp, string]> = [
	[/\bsk-[A-Za-z0-9_-]{8,}\b/g, "<redacted:api-key>"],
	[/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>"],
	[/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>"],
	[/(Authorization\s*[:=]\s*Bearer\s+)[^\s"']+/gi, "$1<redacted>"],
	[/(API_KEY|AUTH_TOKEN|TOKEN|SECRET|PASSWORD)=([^\s]+)/gi, "$1=<redacted>"],
];

function redact(text: string): string {
	let out = text;
	for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement);
	return out;
}

function readJsonFile(path: string): McpConfigFile | undefined {
	if (!existsSync(path)) return undefined;
	try {
		return JSON.parse(readFileSync(path, "utf8")) as McpConfigFile;
	} catch {
		return undefined;
	}
}

function normalizeTransport(config: McpServerConfig): McpTransport {
	if (config.transport === "http" || config.url) return "http";
	return "stdio";
}

function envValue(value: string): string {
	if (value.startsWith("$") && value.length > 1) return process.env[value.slice(1)] ?? "";
	return value;
}

function expandEnv(env?: Record<string, string>): NodeJS.ProcessEnv {
	const result: NodeJS.ProcessEnv = { ...process.env };
	for (const [key, value] of Object.entries(env ?? {})) result[key] = envValue(value);
	return result;
}

function redactedConfig(config: McpServerConfig): McpServerConfig {
	const env = config.env
		? Object.fromEntries(
				Object.entries(config.env).map(([key, value]) => [key, value.startsWith("$") ? value : "<redacted>"]),
			)
		: undefined;
	const headers = config.headers
		? Object.fromEntries(
				Object.entries(config.headers).map(([key, value]) => [key, value.startsWith("$") ? value : "<redacted>"]),
			)
		: undefined;
	return { ...config, env, headers };
}

class StdioJsonRpcClient {
	private child: ReturnType<typeof spawn>;
	private nextId = 1;
	private buffer = "";
	private stderr = "";
	private pending = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void }>();

	constructor(entry: McpServerEntry) {
		const config = entry.config;
		if (!config.command) throw new Error(`MCP stdio server ${entry.id} is missing command`);
		this.child = spawn(config.command, config.args ?? [], {
			cwd: config.cwd ? resolve(config.cwd) : process.cwd(),
			env: expandEnv(config.env),
			stdio: ["pipe", "pipe", "pipe"],
		});
		this.child.stdout?.on("data", (chunk) => this.onStdout(String(chunk)));
		this.child.stderr?.on("data", (chunk) => {
			this.stderr += redact(String(chunk));
			if (this.stderr.length > 12000) this.stderr = this.stderr.slice(-12000);
		});
		this.child.on("error", (error) => this.rejectAll(error));
		this.child.on("close", (code, signal) =>
			this.rejectAll(new Error(`MCP server exited code=${code ?? "null"} signal=${signal ?? "null"}`)),
		);
	}

	get stderrTail(): string {
		return this.stderr.slice(-4000);
	}

	request(method: string, params?: Record<string, unknown>, timeoutMs = DEFAULT_MCP_TIMEOUT_MS): Promise<any> {
		const id = this.nextId++;
		const message = { jsonrpc: "2.0", id, method, ...(params ? { params } : {}) };
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				reject(new Error(`MCP request timeout: ${method}`));
			}, timeoutMs);
			this.pending.set(id, {
				resolve: (value) => {
					clearTimeout(timer);
					resolve(value);
				},
				reject: (error) => {
					clearTimeout(timer);
					reject(error);
				},
			});
			this.write(message);
		});
	}

	notify(method: string, params?: Record<string, unknown>): void {
		this.write({ jsonrpc: "2.0", method, ...(params ? { params } : {}) });
	}

	close(): void {
		try {
			this.child.stdin?.end();
		} catch {}
		if (this.child.exitCode === null) this.child.kill("SIGTERM");
		setTimeout(() => {
			if (this.child.exitCode === null) this.child.kill("SIGKILL");
		}, 1000).unref();
	}

	private write(message: unknown): void {
		this.child.stdin?.write(`${JSON.stringify(message)}\n`, "utf8");
	}

	private onStdout(chunk: string): void {
		this.buffer += chunk;
		while (this.buffer.includes("\n")) {
			const index = this.buffer.indexOf("\n");
			const line = this.buffer.slice(0, index).trim();
			this.buffer = this.buffer.slice(index + 1);
			if (!line) continue;
			let message: any;
			try {
				message = JSON.parse(line);
			} catch {
				continue;
			}
			if (message.id === undefined) continue;
			const pending = this.pending.get(message.id);
			if (!pending) continue;
			this.pending.delete(message.id);
			if (message.error) pending.reject(new Error(redact(JSON.stringify(message.error))));
			else pending.resolve(message.result);
		}
	}

	private rejectAll(error: Error): void {
		for (const pending of this.pending.values()) pending.reject(error);
		this.pending.clear();
	}
}

export class McpManager {
	private cwd: string;
	private agentDir: string;

	constructor(options: McpManagerOptions) {
		this.cwd = resolve(options.cwd);
		this.agentDir = options.agentDir ?? getAgentDir();
	}

	configPaths(): string[] {
		return [join(this.agentDir, "mcp.json"), join(this.cwd, ".repi", "mcp.json")];
	}

	loadServers(): McpServerEntry[] {
		const servers = new Map<string, McpServerEntry>();
		for (const sourcePath of this.configPaths()) {
			const parsed = readJsonFile(sourcePath);
			if (!parsed) continue;
			const table = parsed.mcpServers ?? parsed.servers ?? {};
			for (const [id, config] of Object.entries(table)) {
				servers.set(id, { id, config: { transport: normalizeTransport(config), ...config }, sourcePath });
			}
		}
		return Array.from(servers.values()).sort((a, b) => a.id.localeCompare(b.id));
	}

	getServer(id: string): McpServerEntry | undefined {
		return this.loadServers().find((server) => server.id === id || server.id.startsWith(id));
	}

	async probeServer(id: string): Promise<McpProbeResult> {
		const entry = this.getServer(id);
		if (!entry) return { serverId: id, ok: false, transport: "stdio", tools: [], error: "server_not_found" };
		return this.probeEntry(entry);
	}

	async probeAll(): Promise<McpProbeResult[]> {
		const entries = this.loadServers().filter((entry) => !entry.config.disabled);
		const results: McpProbeResult[] = [];
		for (const entry of entries) results.push(await this.probeEntry(entry));
		return results;
	}

	formatConfig(): string {
		const entries = this.loadServers();
		const lines = ["MCP servers:"];
		lines.push(`config_paths: ${this.configPaths().join(", ")}`);
		if (entries.length === 0) {
			lines.push("- none");
			lines.push(
				'example: create ~/.repi/agent/mcp.json with { "mcpServers": { "demo": { "transport": "stdio", "command": "node", "args": ["server.js"] } } }',
			);
			return lines.join("\n");
		}
		for (const entry of entries) {
			const config = redactedConfig(entry.config);
			const transport = normalizeTransport(config);
			const target =
				transport === "stdio" ? [config.command, ...(config.args ?? [])].filter(Boolean).join(" ") : config.url;
			lines.push(
				`- ${entry.id} [${transport}${config.disabled ? ", disabled" : ""}] ${target ?? "<missing-target>"}`,
			);
			lines.push(`  source=${entry.sourcePath}`);
		}
		return lines.join("\n");
	}

	formatProbeResults(results: McpProbeResult[]): string {
		const lines = ["MCP probe results:"];
		if (results.length === 0) {
			lines.push("- none");
			return lines.join("\n");
		}
		for (const result of results) {
			lines.push(
				`- ${result.serverId} [${result.ok ? "ok" : "fail"}] transport=${result.transport} tools=${result.tools.length}`,
			);
			if (result.protocolVersion) lines.push(`  protocol=${result.protocolVersion}`);
			if (result.error) lines.push(`  error=${result.error}`);
			for (const tool of result.tools.slice(0, 20))
				lines.push(`  tool: ${tool.name}${tool.description ? ` — ${tool.description}` : ""}`);
			if (result.tools.length > 20) lines.push(`  ... ${result.tools.length - 20} more tools`);
			if (result.stderrTail) lines.push(`  stderr_tail=${result.stderrTail.replace(/\s+/g, " ").slice(-500)}`);
		}
		return lines.join("\n");
	}

	private async probeEntry(entry: McpServerEntry): Promise<McpProbeResult> {
		const transport = normalizeTransport(entry.config);
		if (entry.config.disabled)
			return { serverId: entry.id, ok: false, transport, tools: [], error: "server_disabled" };
		if (transport === "http") {
			return {
				serverId: entry.id,
				ok: false,
				transport,
				url: entry.config.url,
				tools: [],
				error: "http_transport_configured_but_not_started_yet",
			};
		}

		const client = new StdioJsonRpcClient(entry);
		try {
			const timeoutMs = entry.config.timeoutMs ?? DEFAULT_MCP_TIMEOUT_MS;
			const init = await client.request(
				"initialize",
				{
					protocolVersion: "2025-11-25",
					capabilities: {},
					clientInfo: { name: APP_NAME, version: VERSION },
				},
				timeoutMs,
			);
			client.notify("notifications/initialized");
			const listed = await client.request("tools/list", {}, timeoutMs).catch((error) => ({ error }));
			const rawTools = Array.isArray(listed?.tools) ? listed.tools : [];
			const allowed = new Set(entry.config.allowedTools ?? []);
			const blocked = new Set(entry.config.blockedTools ?? []);
			const tools = rawTools
				.filter((tool: any) => typeof tool?.name === "string")
				.filter((tool: any) => allowed.size === 0 || allowed.has(tool.name))
				.filter((tool: any) => !blocked.has(tool.name))
				.map((tool: any) => ({
					name: tool.name,
					description: typeof tool.description === "string" ? tool.description : undefined,
					inputSchema: tool.inputSchema,
				}));
			return {
				serverId: entry.id,
				ok: true,
				transport,
				command: [entry.config.command, ...(entry.config.args ?? [])].filter(Boolean).join(" "),
				protocolVersion: typeof init?.protocolVersion === "string" ? init.protocolVersion : undefined,
				serverInfo: init?.serverInfo,
				capabilities: init?.capabilities,
				tools,
				stderrTail: client.stderrTail,
			};
		} catch (error) {
			return {
				serverId: entry.id,
				ok: false,
				transport,
				command: [entry.config.command, ...(entry.config.args ?? [])].filter(Boolean).join(" "),
				tools: [],
				stderrTail: client.stderrTail,
				error: redact(error instanceof Error ? error.message : String(error)),
			};
		} finally {
			client.close();
		}
	}
}

export function createMcpManager(options: McpManagerOptions): McpManager {
	return new McpManager(options);
}

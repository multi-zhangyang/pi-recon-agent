import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import type { AgentToolResult } from "@pi-recon/repi-agent-core";
import { Type } from "typebox";
import { APP_NAME, getAgentDir, VERSION } from "../config.ts";
import { drainResponseBody } from "../utils/http-drain.ts";
import type { ToolDefinition } from "./extensions/types.ts";
import { atomicWriteFileSync } from "./tools/atomic-write.ts";
import { safeHeadEnd, safeTailStart } from "./tools/truncate.ts";

export type McpTransport = "stdio" | "http";

export interface McpServerConfig {
	transport?: McpTransport;
	command?: string;
	args?: string[];
	cwd?: string;
	env?: Record<string, string>;
	url?: string;
	headers?: Record<string, string>;
	/** Optional bearer token value or env reference, e.g. "$MCP_TOKEN". */
	bearerToken?: string;
	/** OAuth login-state foundation. accessToken may be an env reference; full browser flow is handled by future auth helpers. */
	oauth?: {
		accessToken?: string;
		tokenType?: "Bearer";
		clientId?: string;
		scopes?: string[];
		authorizationServerMetadataUrl?: string;
		resourceMetadataUrl?: string;
	};
	disabled?: boolean;
	timeoutMs?: number;
	allowedTools?: string[];
	blockedTools?: string[];
	/** Keep direct MCP tool schemas out of the runtime registry; use search + proxy call instead. */
	deferToolSchemas?: boolean;
	/** Reuse initialized MCP sessions between nearby calls. Defaults on. */
	pool?: boolean;
	/** Idle milliseconds before a pooled MCP session is closed. */
	poolIdleMs?: number;
	/** Opt-in: expose this server as runtime LLM-callable MCP tools. */
	autoRegisterTools?: boolean;
	/** Compatibility alias for older local configs. */
	enableTools?: boolean;
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

export interface McpResourceSummary {
	uri: string;
	name?: string;
	description?: string;
	mimeType?: string;
}

export interface McpPromptSummary {
	name: string;
	description?: string;
	arguments?: unknown;
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

export interface McpToolArtifact {
	path: string;
	sha256: string;
	bytes: number;
	previewChars: number;
}

export interface McpToolCallDetails {
	serverId: string;
	toolName: string;
	isError: boolean;
	contentItems: number;
	artifacts?: McpToolArtifact[];
	stderrTail?: string;
}

export interface McpToolCallResult {
	content: AgentToolResult<McpToolCallDetails>["content"];
	details: McpToolCallDetails;
	isError: boolean;
}

export interface McpResourceListResult {
	serverId: string;
	ok: boolean;
	resources: McpResourceSummary[];
	stderrTail?: string;
	error?: string;
}

export interface McpPromptListResult {
	serverId: string;
	ok: boolean;
	prompts: McpPromptSummary[];
	stderrTail?: string;
	error?: string;
}

export interface McpToolSearchResult {
	serverId: string;
	ok: boolean;
	query?: string;
	total: number;
	limit: number;
	tools: McpToolSummary[];
	stderrTail?: string;
	error?: string;
}

export interface McpAuthInfoResult {
	serverId: string;
	ok: boolean;
	transport: McpTransport;
	url?: string;
	status?: number;
	wwwAuthenticate?: string;
	resourceMetadataUrl?: string;
	resourceMetadata?: unknown;
	error?: string;
}

export interface McpManagerOptions {
	cwd: string;
	agentDir?: string;
}

const DEFAULT_MCP_TIMEOUT_MS = 10000;
const DEFAULT_MCP_POOL_IDLE_MS = 30000;
const MCP_TOOL_ARTIFACT_THRESHOLD_CHARS = 20000;
const MCP_TOOL_INLINE_PREVIEW_CHARS = 12000;
const MCP_TOOL_FALLBACK_TRUNCATE_CHARS = 64000;

/**
 * Cap the StdioJsonRpcClient stdout framing buffer so a misbehaving/buggy MCP server can't drive
 * the process to OOM. Two unbounded cases: (1) newline-delimited mode waits for a `\n` that never
 * comes → `buffer` grows with every chunk; (2) Content-Length mode buffers until `length` bytes
 * arrive → a corrupt `Content-Length: 999999999` header would buffer ~1GB. The stderr sibling is
 * capped at 12000 (opt #36); the stdout buffer was the lone unbounded one. 10M chars is well above
 * any legitimate MCP message (tool results/resources are capped at the context boundary ~256K,
 * opt #15). `REPI_MCP_STDIO_BUFFER_MAX_CHARS` env overrides; 0 disables (legacy unbounded). opt #59.
 */
const MCP_STDIO_BUFFER_MAX_CHARS = (() => {
	const raw = process.env.REPI_MCP_STDIO_BUFFER_MAX_CHARS;
	if (raw === undefined || raw === "") return 10_000_000;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return 10_000_000;
	if (n === 0) return Number.POSITIVE_INFINITY;
	return Math.floor(n);
})();

/**
 * Bound an MCP HTTP response body BEFORE `response.text()` loads it all into memory. The HTTP
 * JSON-RPC client (`StreamableHttpJsonRpcClient.post`) previously did `await response.text()` on the
 * whole success-path body then `text.split(/\r?\n\r?\n/)` over it — unbounded, so a misbehaving or
 * hostile (user-configured) MCP server returning a very large `text/event-stream` or JSON response
 * drove the process to OOM. opt #49 only covered DRAINING the body on the error/non-ok path; the
 * success path was the lone unbounded read (the stdio client's stdout buffer is already capped via
 * `MCP_STDIO_BUFFER_MAX_CHARS`, opt #59). 16 MB matches the read-tool large-file guard doctrine
 * (opt #34, `REPI_READ_MAX_FILE_BYTES`) and is well above any legitimate MCP message (tool results
 * are capped at the context boundary ~256K, opt #15). `REPI_MCP_HTTP_BODY_MAX_BYTES` env overrides;
 * 0 disables (legacy unbounded). opt #170.
 */
const MCP_HTTP_BODY_MAX_BYTES = (() => {
	const raw = process.env.REPI_MCP_HTTP_BODY_MAX_BYTES;
	if (raw === undefined || raw === "") return 16 * 1024 * 1024;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return 16 * 1024 * 1024;
	if (n === 0) return Number.POSITIVE_INFINITY;
	return Math.floor(n);
})();

const mcpProxyToolSchema = Type.Object({
	tool: Type.String({
		description:
			"Exact MCP tool name exposed by this server. If a router/search server recommends call_tool({ name: 'X', args: {...} }), set tool='call_tool' and pass {name:'X', args:{...}} in arguments; do not set tool='X' unless tools/list exposes X.",
	}),
	arguments: Type.Optional(
		Type.Record(Type.String(), Type.Any(), { description: "Arguments passed to the MCP tool" }),
	),
});

const mcpToolSearchSchema = Type.Object({
	query: Type.Optional(Type.String({ description: "Substring to match against MCP tool name/description" })),
	limit: Type.Optional(Type.Number({ description: "Maximum tools to return", minimum: 1, maximum: 100 })),
	includeSchema: Type.Optional(Type.Boolean({ description: "Include MCP inputSchema snippets in the result" })),
});

const mcpResourceListSchema = Type.Object({});

const mcpResourceReadSchema = Type.Object({
	uri: Type.String({ description: "MCP resource URI to read" }),
});

const mcpPromptListSchema = Type.Object({});

const mcpPromptGetSchema = Type.Object({
	name: Type.String({ description: "MCP prompt name to get" }),
	arguments: Type.Optional(Type.Record(Type.String(), Type.Any(), { description: "Prompt arguments" })),
});

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

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
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

function envCsv(name: string): string[] {
	return (process.env[name] ?? "")
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
}

function expandHeaderValue(value: string): string {
	return envValue(value).replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_match, name: string) => process.env[name] ?? "");
}

function expandEnv(env?: Record<string, string>): NodeJS.ProcessEnv {
	const result: NodeJS.ProcessEnv = { ...process.env };
	for (const [key, value] of Object.entries(env ?? {})) result[key] = envValue(value);
	return result;
}

function expandHeaders(config: McpServerConfig): Record<string, string> {
	const headers: Record<string, string> = {};
	for (const [key, value] of Object.entries(config.headers ?? {})) headers[key] = expandHeaderValue(value);
	if (config.bearerToken && !Object.keys(headers).some((key) => key.toLowerCase() === "authorization")) {
		headers.Authorization = `Bearer ${envValue(config.bearerToken)}`;
	}
	if (config.oauth?.accessToken && !Object.keys(headers).some((key) => key.toLowerCase() === "authorization")) {
		const tokenType = config.oauth.tokenType ?? "Bearer";
		headers.Authorization = `${tokenType} ${envValue(config.oauth.accessToken)}`;
	}
	return headers;
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
	const bearerToken = config.bearerToken
		? config.bearerToken.startsWith("$")
			? config.bearerToken
			: "<redacted>"
		: undefined;
	const oauth = config.oauth
		? {
				...config.oauth,
				accessToken: config.oauth.accessToken
					? config.oauth.accessToken.startsWith("$")
						? config.oauth.accessToken
						: "<redacted>"
					: undefined,
			}
		: undefined;
	return { ...config, env, headers, bearerToken, oauth };
}

function sanitizeToolNamePart(value: string, fallback: string): string {
	const sanitized = value
		.replace(/[^A-Za-z0-9_]/g, "_")
		.replace(/_+/g, "_")
		.replace(/^_+|_+$/g, "");
	return (sanitized || fallback).slice(0, 64);
}

function shortHash(value: string): string {
	return createHash("sha1").update(value).digest("hex").slice(0, 8);
}

function createMcpToolName(serverId: string, toolName: string): string {
	const server = sanitizeToolNamePart(serverId, "server");
	const tool = sanitizeToolNamePart(toolName, "tool");
	const base = `mcp__${server}__${tool}`;
	if (base.length <= 96) return base;
	return `mcp__${server.slice(0, 32)}__${tool.slice(0, 40)}__${shortHash(`${serverId}/${toolName}`)}`;
}

function createMcpProxyToolName(serverId: string): string {
	return `mcp__${sanitizeToolNamePart(serverId, "server")}__call`;
}

function createMcpToolSearchToolName(serverId: string): string {
	return `mcp__${sanitizeToolNamePart(serverId, "server")}__search_tools`;
}

function createMcpResourceListToolName(serverId: string): string {
	return `mcp__${sanitizeToolNamePart(serverId, "server")}__list_resources`;
}

function createMcpResourceReadToolName(serverId: string): string {
	return `mcp__${sanitizeToolNamePart(serverId, "server")}__read_resource`;
}

function createMcpPromptListToolName(serverId: string): string {
	return `mcp__${sanitizeToolNamePart(serverId, "server")}__list_prompts`;
}

function createMcpPromptGetToolName(serverId: string): string {
	return `mcp__${sanitizeToolNamePart(serverId, "server")}__get_prompt`;
}

function normalizeInputSchema(inputSchema: unknown): ToolDefinition["parameters"] {
	if (!isRecord(inputSchema)) return Type.Object({}, { additionalProperties: true });
	const schema = structuredClone(inputSchema) as Record<string, unknown>;
	if (!schema.type && isRecord(schema.properties)) schema.type = "object";
	return schema as ToolDefinition["parameters"];
}

function normalizeToolArgs(args: unknown): Record<string, unknown> {
	return isRecord(args) ? args : {};
}

function textFromContent(content: McpToolCallResult["content"]): string {
	return content
		.map((item) => (item.type === "text" ? item.text : `[image:${item.mimeType}]`))
		.join("\n")
		.trim();
}

interface NormalizedMcpContent {
	content: McpToolCallResult["content"];
	artifacts: McpToolArtifact[];
}

export function inlineMcpText(text: string): string {
	const redacted = redact(text);
	if (redacted.length <= MCP_TOOL_FALLBACK_TRUNCATE_CHARS) return redacted;
	const headEnd = safeHeadEnd(redacted, MCP_TOOL_FALLBACK_TRUNCATE_CHARS);
	return `${redacted.slice(0, headEnd)}

[truncated MCP tool output at ${MCP_TOOL_FALLBACK_TRUNCATE_CHARS} chars]`;
}

function toAgentToolResult(result: McpToolCallResult): AgentToolResult<McpToolCallDetails> {
	if (result.isError) throw new Error(textFromContent(result.content) || "MCP tool returned an error");
	return { content: result.content, details: result.details };
}

interface McpJsonRpcClient {
	stderrTail: string;
	readonly isClosed: boolean;
	/** Process id of a stdio server child, when present (HTTP clients return undefined). */
	readonly childPid?: number;
	request(method: string, params?: Record<string, unknown>, timeoutMs?: number, signal?: AbortSignal): Promise<any>;
	notify(
		method: string,
		params?: Record<string, unknown>,
		timeoutMs?: number,
		signal?: AbortSignal,
	): Promise<void> | void;
	close(timeoutMs?: number): Promise<void> | void;
}

interface PooledMcpClient {
	key: string;
	fingerprint: string;
	client: McpJsonRpcClient;
	init: any;
	idleTimer?: NodeJS.Timeout;
}

export function parseSseJsonMessages(text: string): any[] {
	const messages: any[] = [];
	for (const rawEvent of text.split(/\r?\n\r?\n/)) {
		const dataLines = rawEvent
			.split(/\r?\n/)
			.filter((line) => line.startsWith("data:"))
			.map((line) => line.slice(5).trimStart());
		if (dataLines.length === 0) continue;
		const data = dataLines.join("\n").trim();
		if (!data || data === "[DONE]") continue;
		try {
			messages.push(JSON.parse(data));
		} catch {}
	}
	return messages;
}

/**
 * Read an MCP HTTP response body into a string with a hard byte cap ({@link MCP_HTTP_BODY_MAX_BYTES}),
 * streaming via `response.body.getReader()` so a huge body is aborted mid-stream instead of loaded
 * whole. If `Content-Length` exceeds the cap, aborts WITHOUT reading the body. If the accumulated
 * bytes would exceed the cap, cancels the reader and throws. A normal response under the cap is
 * returned byte-for-byte identical to `await response.text()` (UTF-8 decode of the bounded buffer).
 * Exported for testing. opt #170.
 */
export async function readBoundedResponseBody(response: Response): Promise<string> {
	if (MCP_HTTP_BODY_MAX_BYTES === Number.POSITIVE_INFINITY) return await response.text();
	const contentLength = response.headers.get("content-length");
	if (contentLength) {
		const n = Number(contentLength);
		if (Number.isFinite(n) && n > MCP_HTTP_BODY_MAX_BYTES) {
			await drainResponseBody(response);
			throw new Error(
				`MCP HTTP response body exceeded REPI_MCP_HTTP_BODY_MAX_BYTES (${MCP_HTTP_BODY_MAX_BYTES} bytes; Content-Length: ${n})`,
			);
		}
	}
	if (!response.body) return await response.text();
	const reader = response.body.getReader();
	const chunks: Buffer[] = [];
	let total = 0;
	let exceeded = false;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			if (total + value.byteLength > MCP_HTTP_BODY_MAX_BYTES) {
				exceeded = true;
				break;
			}
			total += value.byteLength;
			chunks.push(Buffer.from(value));
		}
	} finally {
		if (exceeded) await reader.cancel().catch(() => {});
		else {
			try {
				reader.releaseLock();
			} catch {}
		}
	}
	if (exceeded) {
		throw new Error(
			`MCP HTTP response body exceeded REPI_MCP_HTTP_BODY_MAX_BYTES (${MCP_HTTP_BODY_MAX_BYTES} bytes; read ${total})`,
		);
	}
	return Buffer.concat(chunks).toString("utf8");
}

/**
 * Parse a bounded MCP HTTP response body into JSON-RPC messages. Kept in sync
 * with the client's success-path parse so the body cap and the parser are
 * independently testable. Exported for testing. opt #170.
 */
export function parseHttpResponseMessages(contentType: string, bodyText: string): any[] {
	if (!bodyText.trim()) return [];
	if (contentType.includes("text/event-stream")) return parseSseJsonMessages(bodyText);
	try {
		const parsed = JSON.parse(bodyText);
		return Array.isArray(parsed) ? parsed : [parsed];
	} catch {
		const sseMessages = parseSseJsonMessages(bodyText);
		if (sseMessages.length > 0) return sseMessages;
		throw new Error(`MCP HTTP response was not JSON/SSE: ${redact(bodyText.slice(0, 1000))}`);
	}
}

function createAbortController(timeoutMs: number, signal?: AbortSignal): { signal: AbortSignal; cleanup: () => void } {
	const controller = new AbortController();
	const onAbort = () => controller.abort(signal?.reason);
	const timer = setTimeout(() => controller.abort(new Error("MCP HTTP request timeout")), timeoutMs);
	if (signal?.aborted) controller.abort(signal.reason);
	else signal?.addEventListener("abort", onAbort, { once: true });
	return {
		signal: controller.signal,
		cleanup: () => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", onAbort);
		},
	};
}

function killProcessGroup(pid: number | undefined, signal: NodeJS.Signals): void {
	if (!pid) return;
	try {
		process.kill(-pid, signal);
	} catch {
		try {
			process.kill(pid, signal);
		} catch {}
	}
}

function parseBearerAuthParam(header: string | null, key: string): string | undefined {
	if (!header) return undefined;
	const pattern = new RegExp(`${key}=(?:"([^"]+)"|([^,\\s]+))`, "i");
	const match = header.match(pattern);
	return match?.[1] ?? match?.[2];
}

class StreamableHttpJsonRpcClient implements McpJsonRpcClient {
	private nextId = 1;
	private protocolVersion = "2025-11-25";
	private sessionId: string | undefined;
	private entry: McpServerEntry;
	private closed = false;

	constructor(entry: McpServerEntry) {
		this.entry = entry;
		if (!entry.config.url) throw new Error(`MCP HTTP server ${entry.id} is missing url`);
	}

	get stderrTail(): string {
		return "";
	}

	get isClosed(): boolean {
		return this.closed;
	}

	async request(
		method: string,
		params?: Record<string, unknown>,
		timeoutMs = DEFAULT_MCP_TIMEOUT_MS,
		signal?: AbortSignal,
	): Promise<any> {
		const id = this.nextId++;
		const result = await this.post(
			{ jsonrpc: "2.0", id, method, ...(params ? { params } : {}) },
			timeoutMs,
			signal,
			id,
		);
		if (method === "initialize" && isRecord(result)) {
			if (typeof result.protocolVersion === "string") this.protocolVersion = result.protocolVersion;
		}
		return result;
	}

	async notify(
		method: string,
		params?: Record<string, unknown>,
		timeoutMs = DEFAULT_MCP_TIMEOUT_MS,
		signal?: AbortSignal,
	): Promise<void> {
		await this.post({ jsonrpc: "2.0", method, ...(params ? { params } : {}) }, timeoutMs, signal);
	}

	async close(timeoutMs = 1000): Promise<void> {
		this.closed = true;
		if (!this.sessionId) return;
		const abort = createAbortController(timeoutMs, undefined);
		try {
			await fetch(this.entry.config.url as string, {
				method: "DELETE",
				headers: this.buildHeaders(true, false),
				signal: abort.signal,
			})
				.then((response) => drainResponseBody(response))
				.catch(() => undefined);
		} finally {
			abort.cleanup();
		}
	}

	private async post(
		message: Record<string, unknown>,
		timeoutMs: number,
		signal?: AbortSignal,
		expectId?: number,
	): Promise<any> {
		const abort = createAbortController(timeoutMs, signal);
		let response: Response;
		try {
			response = await fetch(this.entry.config.url as string, {
				method: "POST",
				headers: this.buildHeaders(true, true),
				body: JSON.stringify(message),
				signal: abort.signal,
			});
			const sessionId = response.headers.get("mcp-session-id");
			if (sessionId) this.sessionId = sessionId;
			const bodyText = await readBoundedResponseBody(response);
			if (!response.ok) {
				const body = redact(bodyText);
				throw new Error(`MCP HTTP ${response.status}${body ? `: ${body.slice(0, 1000)}` : ""}`);
			}
			if (!expectId) return undefined;
			const messages = parseHttpResponseMessages(response.headers.get("content-type") ?? "", bodyText);
			// Match the result by id ONLY. A streamable-HTTP/SSE response may emit a stray
			// result for an EARLIER request (one that timed out client-side but wasn't
			// cancelled server-side); the previous `?? messages.find((item) => item?.id !==
			// undefined)` fallback returned that stray as the result of the CURRENT tools/call
			// → the caller received data belonging to a DIFFERENT tool/resource, surfaced to
			// the model as if it were the answer. With no matching id, reject instead.
			const messageResult = messages.find((item) => item?.id === expectId);
			if (!messageResult) throw new Error(`MCP HTTP response did not contain a result for id=${expectId}`);
			if (messageResult.error) throw new Error(redact(JSON.stringify(messageResult.error)));
			return messageResult.result;
		} catch (error) {
			throw new Error(redact(error instanceof Error ? error.message : String(error)));
		} finally {
			abort.cleanup();
		}
	}

	private buildHeaders(includeSession: boolean, includeJsonContent: boolean): Record<string, string> {
		const headers: Record<string, string> = {
			...expandHeaders(this.entry.config),
			Accept: "application/json, text/event-stream",
		};
		if (includeJsonContent) headers["Content-Type"] = "application/json";
		if (this.protocolVersion) headers["MCP-Protocol-Version"] = this.protocolVersion;
		if (includeSession && this.sessionId) headers["Mcp-Session-Id"] = this.sessionId;
		return headers;
	}
}

export class StdioJsonRpcClient implements McpJsonRpcClient {
	private child: ReturnType<typeof spawn>;
	private nextId = 1;
	private buffer = "";
	private stderr = "";
	private pending = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void }>();
	private closed = false;
	/** Tracked 1s SIGTERM→SIGKILL escalation timer from close(). Cleared in the
	 * child 'close'/'error' handler so a process that exits promptly on SIGTERM
	 * does not later fire SIGKILL at a possibly-recycled pid/process-group, and
	 * so the closure (holding this.child) is released. Mirrors exec.ts
	 * clearTimers/sigkillTimer. */
	private killGraceTimer: ReturnType<typeof setTimeout> | undefined;

	constructor(entry: McpServerEntry) {
		const config = entry.config;
		if (!config.command) throw new Error(`MCP stdio server ${entry.id} is missing command`);
		this.child = spawn(config.command, config.args ?? [], {
			cwd: config.cwd ? resolve(config.cwd) : process.cwd(),
			env: expandEnv(config.env),
			detached: true,
			stdio: ["pipe", "pipe", "pipe"],
		});
		this.child.unref();
		(this.child.stdin as any)?.unref?.();
		(this.child.stdout as any)?.unref?.();
		(this.child.stderr as any)?.unref?.();
		// opt #233: decode stdout/stderr as UTF-8 via Node's StringDecoder so a
		// multi-byte character split across two pipe chunks (~64KB boundaries) is
		// reassembled, not replaced with U+FFFD. Pre-fix, `String(chunk)` ran
		// Buffer.toString('utf8') on EACH chunk independently — an incomplete
		// trailing sequence (CJK 3 bytes, emoji 4 bytes) became U+FFFD on both
		// halves, silently corrupting any non-ASCII tool/resource result crossing a
		// chunk boundary (newline-delimited JSON parsed fine with U+FFFD inside a
		// string value, so the model received garbled text with NO error). For
		// stdout this is data-loss; for stderr it's cosmetic but consistent.
		this.child.stdout?.setEncoding("utf8");
		this.child.stderr?.setEncoding("utf8");
		this.child.stdout?.on("data", (chunk) => this.onStdout(String(chunk)));
		this.child.stderr?.on("data", (chunk) => {
			this.stderr += redact(String(chunk));
			if (this.stderr.length > 12000)
				this.stderr = this.stderr.slice(safeTailStart(this.stderr, this.stderr.length - 12000));
		});
		// Attach error listeners on the stdio streams themselves. The child "error"
		// listener does NOT cover stream-level errors: if the server process dies
		// while a request is in flight, a subsequent write() to stdin emits EPIPE on
		// the stdin stream (not the child), and stdout/stderr can emit 'error' on a
		// broken pipe — with no listener Node throws `Unhandled 'error' event` and
		// crashes the agent on a recoverable condition. Swallow here; the child
		// "close" handler already rejectsAll() and marks the client closed.
		this.child.stdin?.on("error", () => {});
		this.child.stdout?.on("error", () => {});
		this.child.stderr?.on("error", () => {});
		this.child.on("error", (error) => {
			this.clearKillGraceTimer();
			this.rejectAll(error);
		});
		this.child.on("close", (code, signal) => {
			this.closed = true;
			this.clearKillGraceTimer();
			this.rejectAll(new Error(`MCP server exited code=${code ?? "null"} signal=${signal ?? "null"}`));
		});
	}

	get stderrTail(): string {
		return this.stderr.slice(safeTailStart(this.stderr, this.stderr.length - 4000));
	}

	get isClosed(): boolean {
		return this.closed || this.child.exitCode !== null;
	}

	get childPid(): number | undefined {
		return this.child.pid;
	}

	request(
		method: string,
		params?: Record<string, unknown>,
		timeoutMs = DEFAULT_MCP_TIMEOUT_MS,
		signal?: AbortSignal,
	): Promise<any> {
		const id = this.nextId++;
		const message = { jsonrpc: "2.0", id, method, ...(params ? { params } : {}) };
		return new Promise((resolve, reject) => {
			// opt #248: reject immediately on a closed client. Pre-fix this fell
			// through to write(), which no-ops on a dead stdin (:837 guard) — the
			// request then sat in this.pending and was rejected by the child 'close'
			// handler's rejectAll with "MCP server exited" (a RETRYABLE error, which
			// made withInitializedMcpClient spawn a pointless new child) or, if the
			// close event already fired, by the timeout timer after the full
			// timeoutMs. A request issued against an already-closed client should
			// fail fast with the non-retryable "MCP client closed" rejection
			// close() uses.
			if (this.closed) {
				reject(new Error("MCP client closed"));
				return;
			}
			if (signal?.aborted) {
				reject(new Error("Operation aborted"));
				return;
			}
			const cleanup = () => {
				clearTimeout(timer);
				signal?.removeEventListener("abort", onAbort);
			};
			const onAbort = () => {
				this.pending.delete(id);
				cleanup();
				reject(new Error("Operation aborted"));
			};
			const timer = setTimeout(() => {
				this.pending.delete(id);
				signal?.removeEventListener("abort", onAbort);
				reject(new Error(`MCP request timeout: ${method}`));
			}, timeoutMs);
			signal?.addEventListener("abort", onAbort, { once: true });
			this.pending.set(id, {
				resolve: (value) => {
					cleanup();
					resolve(value);
				},
				reject: (error) => {
					cleanup();
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
		this.closed = true;
		// Reject in-flight requests immediately rather than waiting for the child
		// 'close' event (up to ~1s while SIGTERM→exit / SIGKILL escalation plays
		// out). The child 'close'/'error' handlers also call rejectAll; clearing
		// here first makes theirs a no-op (the map is empty) and bounds caller
		// latency at teardown. A response arriving in the race window after this
		// is dropped (pending.get → undefined), which is correct — the caller
		// already received a "closed" rejection.
		this.rejectAll(new Error("MCP client closed"));
		try {
			this.child.stdin?.end();
		} catch {}
		if (this.child.exitCode === null) killProcessGroup(this.child.pid, "SIGTERM");
		// Track the SIGKILL escalation timer so the child 'close'/'error' handler
		// can clear it when the process exits promptly on SIGTERM (no late SIGKILL
		// at a possibly-recycled pid/process-group, no closure leak). unref'd so a
		// child that dies on SIGTERM does not keep the event loop alive for 1s.
		this.killGraceTimer = setTimeout(() => {
			if (this.child.exitCode === null) killProcessGroup(this.child.pid, "SIGKILL");
			this.killGraceTimer = undefined;
		}, 1000);
		this.killGraceTimer.unref();
	}

	/** Clear the tracked SIGKILL escalation timer. Idempotent — safe to call from
	 * both the 'close' and 'error' handlers, and a no-op when close() was never
	 * called or the timer already fired. */
	private clearKillGraceTimer(): void {
		if (this.killGraceTimer) {
			clearTimeout(this.killGraceTimer);
			this.killGraceTimer = undefined;
		}
	}

	private write(message: unknown): void {
		// Guard against writing to a dead/closed stdin. After the server exits,
		// this.closed is set by the "close" handler; this.child.stdin.destroyed
		// covers the race where close hasn't fired yet but the pipe is already
		// gone. Without this guard, write() to a pipe with no reader emits EPIPE
		// on the stdin stream — now swallowed by the listener above, but skipping
		// the write entirely is cleaner and avoids pointless error noise.
		if (this.closed || (this.child.stdin as any)?.destroyed) return;
		this.child.stdin?.write(`${JSON.stringify(message)}\n`, "utf8");
	}

	private onStdout(chunk: string): void {
		this.buffer += chunk;
		// Cap the framing buffer (opt #59): if it exceeds the cap, framing is unrecoverable here —
		// a legitimate message under the cap would already have been consumed by
		// consumeContentLengthMessage or split on `\n`. A misbehaving/buggy stdio MCP server can't
		// drive the process to OOM with an unframed run (no `\n`) or a corrupt Content-Length
		// header. Backstops the Content-Length length-reject in consumeContentLengthMessage.
		// Fatal: reject every in-flight request with a framing error (NOT a per-request timeout)
		// and mark the client closed so the warm pool stops reusing this dead client for the next
		// call (which would otherwise hang the same way until the child exits). Previously this
		// only cleared the buffer, leaving the in-flight tools/call in `pending` to resolve/reject
		// only when its setTimeout fired — a silent bounded hang, repeated on every reused call.
		if (this.buffer.length > MCP_STDIO_BUFFER_MAX_CHARS) {
			this.fatalFramingOverflow();
			return;
		}
		while (this.buffer.length > 0) {
			if (this.buffer.startsWith("Content-Length:")) {
				if (!this.consumeContentLengthMessage()) break;
				continue;
			}
			if (!this.buffer.includes("\n")) break;
			const index = this.buffer.indexOf("\n");
			const line = this.buffer.slice(0, index).trim();
			this.buffer = this.buffer.slice(index + 1);
			if (!line) continue;
			this.handleMessageLine(line);
		}
	}

	private consumeContentLengthMessage(): boolean {
		const headerEnd = this.buffer.includes("\r\n\r\n")
			? this.buffer.indexOf("\r\n\r\n")
			: this.buffer.indexOf("\n\n");
		if (headerEnd < 0) return false;
		const delimiter = this.buffer.slice(headerEnd, headerEnd + 4).startsWith("\r\n") ? "\r\n\r\n" : "\n\n";
		const header = this.buffer.slice(0, headerEnd);
		const match = header.match(/Content-Length:\s*(\d+)/i);
		if (!match) {
			this.buffer = this.buffer.slice(headerEnd + delimiter.length);
			return true;
		}
		const length = Number(match[1]);
		// Reject an absurd/non-finite/negative declared Content-Length (opt #59): without this the
		// client buffers until `length` bytes arrive — a corrupt `Content-Length: 999999999` header
		// would buffer ~1GB before the onStdout cap catches it. Fatal (same as the onStdout cap): a
		// corrupt length for an in-flight response loses that response, so reject the in-flight
		// request with a framing error (NOT a timeout) and mark the client closed so the warm pool
		// stops reusing it. Legitimate lengths (≤ cap) fall through and buffer as before.
		if (!Number.isFinite(length) || length < 0 || length > MCP_STDIO_BUFFER_MAX_CHARS) {
			this.fatalFramingOverflow();
			return true;
		}
		const start = headerEnd + delimiter.length;
		if (this.buffer.length < start + length) return false;
		const body = this.buffer.slice(start, start + length);
		this.buffer = this.buffer.slice(start + length);
		this.handleMessageLine(body.trim());
		return true;
	}

	private handleMessageLine(line: string): void {
		let message: any;
		try {
			message = JSON.parse(line);
		} catch {
			return;
		}
		if (message.id === undefined) return;
		const pending = this.pending.get(message.id);
		if (!pending) return;
		this.pending.delete(message.id);
		if (message.error) pending.reject(new Error(redact(JSON.stringify(message.error))));
		else pending.resolve(message.result);
	}

	private rejectAll(error: Error): void {
		for (const pending of this.pending.values()) pending.reject(error);
		this.pending.clear();
	}

	/** Fatal framing-buffer overflow (opt #59 cap hit, both the onStdout line-buffer branch and the
	 * consumeContentLengthMessage length-reject branch): the stdout framing buffer exceeded
	 * `MCP_STDIO_BUFFER_MAX_CHARS`, so framing is unrecoverable. Drop the buffer, mark the client
	 * closed so the warm pool stops reusing this dead client, reject every in-flight request with a
	 * framing error (NOT a per-request setTimeout timeout — the in-flight tools/call whose response
	 * was being buffered would otherwise sit in `pending` for up to the request timeout), and kill
	 * the runaway child so it can't keep streaming/leaking. Mirrors close()'s SIGTERM→SIGKILL kill
	 * sequence; the child 'close' handler's later rejectAll is a no-op (map cleared here). */
	private fatalFramingOverflow(): void {
		this.buffer = "";
		this.closed = true;
		this.clearKillGraceTimer();
		this.rejectAll(new Error(`MCP stdio framing buffer exceeded ${MCP_STDIO_BUFFER_MAX_CHARS} chars`));
		try {
			this.child.stdin?.end();
		} catch {}
		if (this.child.exitCode === null) killProcessGroup(this.child.pid, "SIGTERM");
		this.killGraceTimer = setTimeout(() => {
			if (this.child.exitCode === null) killProcessGroup(this.child.pid, "SIGKILL");
			this.killGraceTimer = undefined;
		}, 1000);
		this.killGraceTimer.unref();
	}
}

export class McpManager {
	private cwd: string;
	private agentDir: string;
	private clientPool = new Map<string, PooledMcpClient>();
	/**
	 * Per-key in-flight creation mutex. Two concurrent callers hitting
	 * getPooledClient for the same key on a cold/stale pool used to BOTH await
	 * createInitializedClient (which spawns a detached+unref'd stdio child) and
	 * both clientPool.set(key, ...) — the second overwrote the first, orphaning
	 * the first's child: it's not in clientPool so closeAll() and the exit-reap
	 * hook never reach it (cost/quota leak, like opt #46). The second concurrent
	 * waiter now reuses the first's in-flight creation promise.
	 */
	private _inflightClient = new Map<string, Promise<PooledMcpClient>>();
	/**
	 * Per-key child PIDs of stdio MCP clients whose `initialize` handshake is
	 * still in flight (spawned but not yet pooled). The child is spawned inside
	 * `createInitializedClient` BEFORE the creation promise resolves and is
	 * added to `clientPool` — during that window (up to the 10s initialize
	 * timeout) the child is only reachable via this map. Without it both
	 * teardown paths (`closeAll` iterates `clientPool` only; the process
	 * `exit` reap hook iterates `clientPool` only) miss it, so a parent exit
	 * during initialize reparents the detached+unref'd child to init and it
	 * keeps running (cost/quota leak — the same class opt #46 addressed for
	 * pooled clients, but the inflight map was excluded). Cleared in the
	 * creation promise's `finally` once the child is pooled (covered by the
	 * pooled reap path) or the create failed (child already closed).
	 *
	 * opt #234: the value is a `Set<number>` (per-spawn), not a single pid.
	 * For pooled servers `_inflightClient` serializes creation per key so only
	 * one create is ever in flight per key — the set holds one pid. For
	 * `pool:false` servers (opt #234 gated inflight sharing off so each
	 * concurrent caller spawns its OWN child) N concurrent creates on the same
	 * key can be in flight at once; a single-pid map would have the second
	 * `.set(key, pid)` overwrite the first → the first child orphaned during
	 * the init window. The set holds every in-flight spawn's pid so closeAll +
	 * the exit-reap hook reach all of them.
	 */
	private _inflightChildPids = new Map<string, Set<number>>();
	/**
	 * Foundational opt #139: for `pool:false` servers, getPooledClient's
	 * createPromise `.finally` clears `_inflightChildPids` AND the
	 * `if (!poolingEnabled) return created` path never adds the client to
	 * `clientPool` — so for the ENTIRE duration of the in-flight tool callback
	 * (the resources/list, tools/call, etc. request, up to the 10s timeout or
	 * longer for streaming) the non-pooled stdio child's pid is in NEITHER
	 * `clientPool` NOR `_inflightChildPids`. A process exit (or closeAll) in that
	 * window would miss it → the detached+unref'd child is reparented to init and
	 * keeps running (cost/quota leak — same class opt #46 fixed for pooled
	 * clients, but the non-pooled in-flight call path was excluded). This map
	 * tracks non-pooled pids for the duration of each callback (registered in
	 * withInitializedMcpClient before the await, cleared in its finally), so the
	 * exit-reap hook + closeAll can reach them. Pooled clients are already
	 * covered by `clientPool` during their callback (schedulePooledClientClose
	 * runs only AFTER the callback), so they are NOT duplicated here.
	 *
	 * opt #234: `Set<number>` per key (per-spawn), same reason as
	 * `_inflightChildPids`: opt #234 gated pool:false inflight sharing off, so
	 * N concurrent `pool:false` calls on the same server each register their
	 * own pid here for the duration of their callback. A single-pid map would
	 * have the second caller's `.set(key, pid)` overwrite the first's → the
	 * first child orphaned mid-callback (the exact leak opt #139 fixed for the
	 * single-call case). The set holds every concurrent caller's pid.
	 */
	private _inflightNonPooledPids = new Map<string, Set<number>>();
	/**
	 * Foundational opt #141: set synchronously at the start of closeAll() so a
	 * racing retry in withInitializedMcpClient (or any new public call) cannot
	 * SPAWN A FRESH CHILD after the manager has been torn down. Pre-fix only the
	 * abort `signal` guarded the retry (`!signal?.aborted && isRetryableMcpError`),
	 * so a closeAll triggered by a DIFFERENT signal than the in-flight call's
	 * (e.g. session-replacement dispose vs an agent-loop abort) left the retry
	 * guard true on a transient/retryable error → getPooledClient(forceNew) →
	 * createInitializedClient spawned a new detached stdio child AFTER closeAll
	 * had already killed the pool — a spawn-after-dispose leak (the new child was
	 * tracked, but the manager is dead and the user/session is gone). With
	 * opt #138's signal forwarding this is largely defended for the list proxies,
	 * but callTool/searchTools/readResource/getPrompt and any non-aborted retry
	 * path still need the explicit disposed gate.
	 */
	private _disposed = false;
	/**
	 * Synchronous process.on('exit') safety net (opt #46 sibling). If the agent
	 * process quits while pooled stdio MCP children are live, the detached+unref'd
	 * children would be reparented to init and keep running (cost/quota leak). The
	 * hook SIGKILLs every pooled stdio child's process group. Installed only while
	 * the pool is non-empty and removed when it drains, bounding live listeners to
	 * concurrent managers. dispose()-wired closeAll() covers session replacement.
	 */
	private _exitReapHook: (() => void) | undefined;
	/**
	 * loadServers() cache keyed by {mtimeMs,size} of BOTH config paths. Without
	 * this every MCP operation (getServer/callTool/searchTools/...) re-reads and
	 * re-parses both mcp.json files from disk synchronously. Invalidates naturally
	 * on mtime/size change. Callers treat the result as read-only (verified: they
	 * .find/.filter/.map, none mutate), so sharing the cached array is safe.
	 */
	private _loadServersCache?: { sig: string; entries: McpServerEntry[] };

	constructor(options: McpManagerOptions) {
		this.cwd = resolve(options.cwd);
		this.agentDir = options.agentDir ?? getAgentDir();
	}

	configPaths(): string[] {
		return [join(this.agentDir, "mcp.json"), join(this.cwd, ".repi", "mcp.json")];
	}

	loadServers(): McpServerEntry[] {
		if (process.env.REPI_MCP_DISABLED === "1") return [];
		// Cache by {mtimeMs,size} of both config paths to avoid re-reading +
		// re-parsing both mcp.json files on every MCP operation. Stat is cheap
		// sync I/O vs full read+parse+Map+sort on every callTool/searchTools.
		const sig = this.configSignature();
		if (this._loadServersCache && this._loadServersCache.sig === sig) {
			return this._loadServersCache.entries;
		}
		const servers = new Map<string, McpServerEntry>();
		for (const sourcePath of this.configPaths()) {
			const parsed = readJsonFile(sourcePath);
			if (!parsed) continue;
			const table = parsed.mcpServers ?? parsed.servers ?? {};
			for (const [id, config] of Object.entries(table)) {
				servers.set(id, { id, config: { transport: normalizeTransport(config), ...config }, sourcePath });
			}
		}
		const allowedServers = new Set(envCsv("REPI_MCP_ALLOWED_SERVERS"));
		const entries = Array.from(servers.values())
			.filter((server) => allowedServers.size === 0 || allowedServers.has(server.id))
			.sort((a, b) => a.id.localeCompare(b.id));
		this._loadServersCache = { sig, entries };
		return entries;
	}

	/** Build a cache signature from mtimeMs+size of both config paths. */
	private configSignature(): string {
		const parts: string[] = [];
		for (const sourcePath of this.configPaths()) {
			let stat: { mtimeMs: number; size: number } | undefined;
			try {
				const s = statSync(sourcePath);
				stat = { mtimeMs: s.mtimeMs, size: s.size };
			} catch {
				stat = undefined;
			}
			parts.push(`${sourcePath}:${stat ? `${stat.mtimeMs}:${stat.size}` : "missing"}`);
		}
		return parts.join("|");
	}

	getServer(id: string): McpServerEntry | undefined {
		return this.loadServers().find((server) => server.id === id || server.id.startsWith(id));
	}

	async probeServer(id: string, signal?: AbortSignal): Promise<McpProbeResult> {
		const entry = this.getServer(id);
		if (!entry) return { serverId: id, ok: false, transport: "stdio", tools: [], error: "server_not_found" };
		return this.probeEntry(entry, signal);
	}

	async probeAll(signal?: AbortSignal): Promise<McpProbeResult[]> {
		const entries = this.loadServers().filter((entry) => !entry.config.disabled);
		// Foundational opt #140: probe servers in PARALLEL, not serially. The serial
		// `for…await` meant each dead/unreachable server blocked the next for up to
		// its full timeoutMs (DEFAULT_MCP_TIMEOUT_MS 10s) → N dead servers ≈ N×10s
		// head-of-line blocking for a `/mcp` probe-all or `repi mcp probe`. Each
		// probeEntry targets an independent server (per-key create serialization in
		// getPooledClient's _inflightClient means different servers never contend on
		// the same child), so Promise.all is safe and bounds wall-clock to ~max
		// (one timeout) instead of sum. Result order follows entries (Promise.all
		// preserves input order regardless of completion order).
		return Promise.all(entries.map((entry) => this.probeEntry(entry, signal)));
	}

	async callTool(
		serverId: string,
		toolName: string,
		args?: unknown,
		signal?: AbortSignal,
	): Promise<McpToolCallResult> {
		const entry = this.getServer(serverId);
		if (!entry) throw new Error(`MCP server not found: ${serverId}`);
		if (entry.config.disabled) throw new Error(`MCP server is disabled: ${entry.id}`);
		if (!this.isToolAllowed(entry, toolName)) throw new Error(`MCP tool is not allowed: ${entry.id}/${toolName}`);
		return this.withInitializedMcpClient(
			entry,
			async (client) => {
				const timeoutMs = entry.config.timeoutMs ?? DEFAULT_MCP_TIMEOUT_MS;
				const result = await client.request(
					"tools/call",
					{ name: toolName, arguments: normalizeToolArgs(args) },
					timeoutMs,
					signal,
				);
				const isError = isRecord(result) && result.isError === true;
				const normalized = this.normalizeMcpContent(entry.id, toolName, result);
				return {
					content: normalized.content,
					isError,
					details: {
						serverId: entry.id,
						toolName,
						isError,
						contentItems: normalized.content.length,
						artifacts: normalized.artifacts.length > 0 ? normalized.artifacts : undefined,
						stderrTail: client.stderrTail || undefined,
					},
				};
			},
			signal,
		);
	}

	async searchTools(
		serverId: string,
		query = "",
		options?: { limit?: number; includeSchema?: boolean },
		signal?: AbortSignal,
	): Promise<McpToolSearchResult> {
		const entry = this.getServer(serverId);
		const limit = Math.max(1, Math.min(100, Math.trunc(options?.limit ?? 20)));
		const normalizedQuery = query.trim().toLowerCase();
		if (!entry) return { serverId, ok: false, query, total: 0, limit, tools: [], error: "server_not_found" };
		if (entry.config.disabled)
			return { serverId: entry.id, ok: false, query, total: 0, limit, tools: [], error: "server_disabled" };
		const probe = await this.probeEntry(entry, signal);
		if (!probe.ok)
			return {
				serverId: entry.id,
				ok: false,
				query,
				total: 0,
				limit,
				tools: [],
				stderrTail: probe.stderrTail,
				error: probe.error ?? "MCP tools/list failed",
			};
		const matched = probe.tools.filter((tool) => {
			if (!normalizedQuery) return true;
			return `${tool.name}\n${tool.description ?? ""}`.toLowerCase().includes(normalizedQuery);
		});
		const tools = matched.slice(0, limit).map((tool) => ({
			name: tool.name,
			description: tool.description,
			inputSchema: options?.includeSchema ? tool.inputSchema : undefined,
		}));
		return {
			serverId: entry.id,
			ok: true,
			query,
			total: matched.length,
			limit,
			tools,
			stderrTail: probe.stderrTail,
		};
	}

	async inspectAuth(serverId: string, signal?: AbortSignal): Promise<McpAuthInfoResult> {
		const entry = this.getServer(serverId);
		if (!entry) return { serverId, ok: false, transport: "stdio", error: "server_not_found" };
		const transport = normalizeTransport(entry.config);
		if (transport !== "http") {
			return { serverId: entry.id, ok: false, transport, error: "auth_info_only_applies_to_http_mcp" };
		}
		if (!entry.config.url) return { serverId: entry.id, ok: false, transport, error: "missing_url" };
		const timeoutMs = entry.config.timeoutMs ?? DEFAULT_MCP_TIMEOUT_MS;
		let status: number | undefined;
		let wwwAuthenticate: string | undefined;
		let resourceMetadataUrl = entry.config.oauth?.resourceMetadataUrl;
		try {
			if (!resourceMetadataUrl) {
				const abort = createAbortController(timeoutMs, signal);
				let response: Response | undefined;
				try {
					response = await fetch(entry.config.url, {
						method: "POST",
						headers: {
							Accept: "application/json, text/event-stream",
							"Content-Type": "application/json",
							"MCP-Protocol-Version": "2025-11-25",
						},
						body: JSON.stringify({
							jsonrpc: "2.0",
							id: 1,
							method: "initialize",
							params: {
								protocolVersion: "2025-11-25",
								capabilities: {},
								clientInfo: { name: APP_NAME, version: VERSION },
							},
						}),
						signal: abort.signal,
					});
					status = response.status;
					wwwAuthenticate = redact(response.headers.get("www-authenticate") ?? "");
					const rawMetadataUrl =
						parseBearerAuthParam(response.headers.get("www-authenticate"), "resource_metadata") ??
						parseBearerAuthParam(response.headers.get("www-authenticate"), "resource_metadata_uri");
					if (rawMetadataUrl) resourceMetadataUrl = new URL(rawMetadataUrl, entry.config.url).toString();
				} finally {
					abort.cleanup();
					// The initialize response body (a JSON-RPC result or SSE stream) is
					// never read here — only status + www-authenticate are needed for
					// OAuth resource-metadata discovery. Drain it so undici releases the
					// socket instead of holding an unread body until GC.
					if (response) await drainResponseBody(response);
				}
			}
			let resourceMetadata: unknown;
			if (resourceMetadataUrl) {
				const abort = createAbortController(timeoutMs, signal);
				try {
					const response = await fetch(resourceMetadataUrl, {
						method: "GET",
						headers: { Accept: "application/json" },
						signal: abort.signal,
					});
					status = status ?? response.status;
					const text = await readBoundedResponseBody(response);
					try {
						resourceMetadata = JSON.parse(text);
					} catch {
						resourceMetadata = redact(text.slice(0, 2000));
					}
				} finally {
					abort.cleanup();
				}
			}
			return {
				serverId: entry.id,
				ok: true,
				transport,
				url: entry.config.url,
				status,
				wwwAuthenticate,
				resourceMetadataUrl,
				resourceMetadata,
			};
		} catch (error) {
			return {
				serverId: entry.id,
				ok: false,
				transport,
				url: entry.config.url,
				status,
				wwwAuthenticate,
				resourceMetadataUrl,
				error: redact(error instanceof Error ? error.message : String(error)),
			};
		}
	}

	async listResources(serverId: string, signal?: AbortSignal): Promise<McpResourceListResult> {
		const entry = this.getServer(serverId);
		if (!entry) return { serverId, ok: false, resources: [], error: "server_not_found" };
		if (entry.config.disabled) return { serverId: entry.id, ok: false, resources: [], error: "server_disabled" };
		return this.withInitializedMcpClient(
			entry,
			async (client) => {
				const timeoutMs = entry.config.timeoutMs ?? DEFAULT_MCP_TIMEOUT_MS;
				const listed = await client.request("resources/list", {}, timeoutMs, signal);
				const resources = this.filterResources(listed?.resources);
				return { serverId: entry.id, ok: true, resources, stderrTail: client.stderrTail || undefined };
			},
			signal,
		).catch((error) => ({
			serverId: entry.id,
			ok: false,
			resources: [],
			error: redact(error instanceof Error ? error.message : String(error)),
		}));
	}

	async readResource(serverId: string, uri: string, signal?: AbortSignal): Promise<McpToolCallResult> {
		const entry = this.getServer(serverId);
		if (!entry) throw new Error(`MCP server not found: ${serverId}`);
		if (entry.config.disabled) throw new Error(`MCP server is disabled: ${entry.id}`);
		return this.withInitializedMcpClient(
			entry,
			async (client) => {
				const timeoutMs = entry.config.timeoutMs ?? DEFAULT_MCP_TIMEOUT_MS;
				const result = await client.request("resources/read", { uri }, timeoutMs, signal);
				const normalized = this.normalizeMcpContent(
					entry.id,
					"read_resource",
					this.resourceReadResultToToolContent(uri, result),
				);
				return {
					content: normalized.content,
					isError: false,
					details: {
						serverId: entry.id,
						toolName: "resources/read",
						isError: false,
						contentItems: normalized.content.length,
						artifacts: normalized.artifacts.length > 0 ? normalized.artifacts : undefined,
						stderrTail: client.stderrTail || undefined,
					},
				};
			},
			signal,
		);
	}

	async listPrompts(serverId: string, signal?: AbortSignal): Promise<McpPromptListResult> {
		const entry = this.getServer(serverId);
		if (!entry) return { serverId, ok: false, prompts: [], error: "server_not_found" };
		if (entry.config.disabled) return { serverId: entry.id, ok: false, prompts: [], error: "server_disabled" };
		return this.withInitializedMcpClient(
			entry,
			async (client) => {
				const timeoutMs = entry.config.timeoutMs ?? DEFAULT_MCP_TIMEOUT_MS;
				const listed = await client.request("prompts/list", {}, timeoutMs, signal);
				const prompts = this.filterPrompts(listed?.prompts);
				return { serverId: entry.id, ok: true, prompts, stderrTail: client.stderrTail || undefined };
			},
			signal,
		).catch((error) => ({
			serverId: entry.id,
			ok: false,
			prompts: [],
			error: redact(error instanceof Error ? error.message : String(error)),
		}));
	}

	async getPrompt(serverId: string, name: string, args?: unknown, signal?: AbortSignal): Promise<McpToolCallResult> {
		const entry = this.getServer(serverId);
		if (!entry) throw new Error(`MCP server not found: ${serverId}`);
		if (entry.config.disabled) throw new Error(`MCP server is disabled: ${entry.id}`);
		return this.withInitializedMcpClient(
			entry,
			async (client) => {
				const timeoutMs = entry.config.timeoutMs ?? DEFAULT_MCP_TIMEOUT_MS;
				const result = await client.request(
					"prompts/get",
					{ name, arguments: normalizeToolArgs(args) },
					timeoutMs,
					signal,
				);
				const normalized = this.normalizeMcpContent(
					entry.id,
					"get_prompt",
					this.promptGetResultToToolContent(name, result),
				);
				return {
					content: normalized.content,
					isError: false,
					details: {
						serverId: entry.id,
						toolName: "prompts/get",
						isError: false,
						contentItems: normalized.content.length,
						artifacts: normalized.artifacts.length > 0 ? normalized.artifacts : undefined,
						stderrTail: client.stderrTail || undefined,
					},
				};
			},
			signal,
		);
	}

	createProxyToolDefinitions(): ToolDefinition[] {
		return this.loadServers()
			.filter((entry) => this.shouldExposeTools(entry))
			.flatMap((entry) => {
				const serverId = entry.id;
				const callToolName = createMcpProxyToolName(serverId);
				const searchToolName = createMcpToolSearchToolName(serverId);
				const listResourcesToolName = createMcpResourceListToolName(serverId);
				const readResourceToolName = createMcpResourceReadToolName(serverId);
				const listPromptsToolName = createMcpPromptListToolName(serverId);
				const getPromptToolName = createMcpPromptGetToolName(serverId);
				return [
					{
						name: callToolName,
						label: `MCP ${serverId}`,
						description: `Call an allowed MCP tool on server '${serverId}'. Use /mcp ${serverId} or repi mcp probe ${serverId} to inspect available tool names.`,
						promptSnippet: `Call MCP server ${serverId} tools`,
						promptGuidelines: [
							`This is a proxy for MCP server '${serverId}'. Pass a tool name that the MCP server currently exposes in tools/list.`,
							'If a search/router result shows call_tool({ name: "target", args: {...} }), call this proxy with tool="call_tool" and arguments={"name":"target","args":{...}}.',
							"Do not call a discovered virtual/dynamic tool name directly unless it has first appeared in tools/list for this server.",
							"Respect allowedTools/blockedTools from ~/.repi/agent/mcp.json or project .repi/mcp.json.",
						],
						parameters: mcpProxyToolSchema,
						execute: async (_toolCallId, params, signal) => {
							const result = await this.callTool(serverId, params.tool, params.arguments ?? {}, signal);
							return toAgentToolResult(result);
						},
					} satisfies ToolDefinition<typeof mcpProxyToolSchema, McpToolCallDetails>,
					{
						name: searchToolName,
						label: `MCP ${serverId} tool search`,
						description: `Search MCP tools exposed by server '${serverId}' without registering every tool schema into context.`,
						promptSnippet: `Search MCP tools from ${serverId}`,
						promptGuidelines: [
							`Use this before calling '${callToolName}' when the exact MCP tool name is unknown.`,
							'If the search result recommends a wrapper command like call_tool({ name: "X", args: {...} }), route it through the MCP proxy as tool="call_tool".',
							"Keep includeSchema false unless the input schema is needed for the next call.",
						],
						parameters: mcpToolSearchSchema,
						execute: async (_toolCallId, params, signal) => {
							const result = await this.searchTools(
								serverId,
								params.query ?? "",
								{ limit: params.limit, includeSchema: params.includeSchema },
								signal,
							);
							if (!result.ok) throw new Error(result.error ?? "MCP tools/search failed");
							return {
								content: [{ type: "text", text: inlineMcpText(this.formatToolSearchResult(result)) }],
								details: { serverId, toolName: "tools/search", isError: false, contentItems: 1 },
							};
						},
					} satisfies ToolDefinition<typeof mcpToolSearchSchema, McpToolCallDetails>,
					{
						name: listResourcesToolName,
						label: `MCP ${serverId} resources`,
						description: `List MCP resources exposed by server '${serverId}'.`,
						promptSnippet: `List MCP resources from ${serverId}`,
						parameters: mcpResourceListSchema,
						execute: async (_toolCallId, _params, signal) => {
							// Foundational opt #138: forward the abort signal (the sibling
							// tools callTool/searchTools/readResource already do). Pre-fix
							// this dropped signal, so (a) a user cancel / dispose→abort
							// could not abort an in-flight resources/list call — it ran to
							// the 10s request timeout — and (b) with signal undefined into
							// withInitializedMcpClient the retry guard
							// `!signal?.aborted && isRetryableMcpError` evaluated true on a
							// server crash, triggering a retry spawn racing closeAll.
							const result = await this.listResources(serverId, signal);
							if (!result.ok) throw new Error(result.error ?? "MCP resources/list failed");
							const text = result.resources.length
								? result.resources
										.map((resource) =>
											[
												`uri=${resource.uri}`,
												resource.name ? `name=${resource.name}` : undefined,
												resource.mimeType ? `mimeType=${resource.mimeType}` : undefined,
												resource.description ? `description=${resource.description}` : undefined,
											]
												.filter(Boolean)
												.join("\n"),
										)
										.join("\n\n")
								: "No MCP resources found.";
							return {
								content: [{ type: "text", text }],
								details: { serverId, toolName: "resources/list", isError: false, contentItems: 1 },
							};
						},
					} satisfies ToolDefinition<typeof mcpResourceListSchema, McpToolCallDetails>,
					{
						name: readResourceToolName,
						label: `MCP ${serverId} read resource`,
						description: `Read an MCP resource URI from server '${serverId}'. Large text is stored as artifact.`,
						promptSnippet: `Read MCP resource from ${serverId}`,
						parameters: mcpResourceReadSchema,
						execute: async (_toolCallId, params, signal) => {
							const result = await this.readResource(serverId, params.uri, signal);
							return toAgentToolResult(result);
						},
					} satisfies ToolDefinition<typeof mcpResourceReadSchema, McpToolCallDetails>,
					{
						name: listPromptsToolName,
						label: `MCP ${serverId} prompts`,
						description: `List MCP prompts exposed by server '${serverId}'.`,
						promptSnippet: `List MCP prompts from ${serverId}`,
						parameters: mcpPromptListSchema,
						execute: async (_toolCallId, _params, signal) => {
							// opt #138: forward the abort signal — see listResources above.
							const result = await this.listPrompts(serverId, signal);
							if (!result.ok) throw new Error(result.error ?? "MCP prompts/list failed");
							const text = result.prompts.length
								? result.prompts
										.map((prompt) =>
											[
												`name=${prompt.name}`,
												prompt.description ? `description=${prompt.description}` : undefined,
												prompt.arguments ? `arguments=${JSON.stringify(prompt.arguments)}` : undefined,
											]
												.filter(Boolean)
												.join("\n"),
										)
										.join("\n\n")
								: "No MCP prompts found.";
							return {
								content: [{ type: "text", text: inlineMcpText(text) }],
								details: { serverId, toolName: "prompts/list", isError: false, contentItems: 1 },
							};
						},
					} satisfies ToolDefinition<typeof mcpPromptListSchema, McpToolCallDetails>,
					{
						name: getPromptToolName,
						label: `MCP ${serverId} get prompt`,
						description: `Get an MCP prompt by name from server '${serverId}'. Large prompt text is stored as artifact.`,
						promptSnippet: `Get MCP prompt from ${serverId}`,
						parameters: mcpPromptGetSchema,
						execute: async (_toolCallId, params, signal) => {
							const result = await this.getPrompt(serverId, params.name, params.arguments ?? {}, signal);
							return toAgentToolResult(result);
						},
					} satisfies ToolDefinition<typeof mcpPromptGetSchema, McpToolCallDetails>,
				];
			});
	}

	async createToolDefinitions(): Promise<ToolDefinition[]> {
		const definitions: ToolDefinition[] = [];
		const usedNames = new Set(this.createProxyToolDefinitions().map((definition) => definition.name));
		for (const entry of this.loadServers().filter(
			(candidate) => this.shouldExposeTools(candidate) && !candidate.config.deferToolSchemas,
		)) {
			const probe = await this.probeEntry(entry);
			if (!probe.ok) continue;
			for (const tool of probe.tools) {
				let runtimeName = createMcpToolName(entry.id, tool.name);
				if (usedNames.has(runtimeName)) runtimeName = `${runtimeName}__${shortHash(`${entry.id}/${tool.name}`)}`;
				usedNames.add(runtimeName);
				definitions.push(this.createToolDefinition(entry.id, runtimeName, tool));
			}
		}
		return definitions;
	}

	formatConfig(): string {
		const entries = this.loadServers();
		const lines = ["MCP servers:"];
		lines.push(`config_paths: ${this.configPaths().join(", ")}`);
		if (entries.length === 0) {
			lines.push("- none");
			lines.push(
				'example: create ~/.repi/agent/mcp.json with { "mcpServers": { "demo": { "transport": "stdio", "command": "node", "args": ["server.js"], "autoRegisterTools": true } } }',
			);
			return lines.join("\n");
		}
		for (const entry of entries) {
			const config = redactedConfig(entry.config);
			const transport = normalizeTransport(config);
			const target =
				transport === "stdio" ? [config.command, ...(config.args ?? [])].filter(Boolean).join(" ") : config.url;
			lines.push(
				`- ${entry.id} [${transport}${config.disabled ? ", disabled" : ""}${this.shouldExposeTools(entry) ? ", tools:auto" : ""}] ${target ?? "<missing-target>"}`,
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

	formatToolSearchResult(result: McpToolSearchResult): string {
		const lines = [
			`MCP tool search: ${result.serverId} [${result.ok ? "ok" : "fail"}] query=${JSON.stringify(result.query ?? "")} total=${result.total} limit=${result.limit}`,
		];
		if (result.error) lines.push(`error=${result.error}`);
		for (const tool of result.tools) {
			lines.push(`- ${tool.name}${tool.description ? ` — ${tool.description}` : ""}`);
			if (tool.inputSchema) lines.push(`  inputSchema=${JSON.stringify(tool.inputSchema)}`);
		}
		if (result.stderrTail) lines.push(`stderr_tail=${result.stderrTail.replace(/\s+/g, " ").slice(-500)}`);
		return lines.join("\n");
	}

	formatResources(result: McpResourceListResult): string {
		const lines = [`MCP resources: ${result.serverId} [${result.ok ? "ok" : "fail"}]`];
		if (result.error) lines.push(`error=${result.error}`);
		for (const resource of result.resources) {
			lines.push(`- ${resource.uri}${resource.name ? ` — ${resource.name}` : ""}`);
			if (resource.mimeType) lines.push(`  mimeType=${resource.mimeType}`);
			if (resource.description) lines.push(`  description=${resource.description}`);
		}
		if (result.stderrTail) lines.push(`stderr_tail=${result.stderrTail.replace(/\s+/g, " ").slice(-500)}`);
		return lines.join("\n");
	}

	formatPrompts(result: McpPromptListResult): string {
		const lines = [`MCP prompts: ${result.serverId} [${result.ok ? "ok" : "fail"}]`];
		if (result.error) lines.push(`error=${result.error}`);
		for (const prompt of result.prompts) {
			lines.push(`- ${prompt.name}${prompt.description ? ` — ${prompt.description}` : ""}`);
			if (prompt.arguments) lines.push(`  arguments=${JSON.stringify(prompt.arguments)}`);
		}
		if (result.stderrTail) lines.push(`stderr_tail=${result.stderrTail.replace(/\s+/g, " ").slice(-500)}`);
		return lines.join("\n");
	}

	formatToolResult(result: McpToolCallResult, label = "MCP result"): string {
		const lines = [
			`${label}: ${result.details.serverId}/${result.details.toolName} [${result.isError ? "fail" : "ok"}]`,
		];
		for (const item of result.content) {
			if (item.type === "text") lines.push(item.text);
			else lines.push(`[${item.type}:${item.mimeType || "unknown"}]`);
		}
		if (result.details.stderrTail)
			lines.push(`stderr_tail=${result.details.stderrTail.replace(/\s+/g, " ").slice(-500)}`);
		return lines.join("\n");
	}

	formatAuthInfo(result: McpAuthInfoResult): string {
		const lines = [`MCP auth info: ${result.serverId} [${result.ok ? "ok" : "fail"}] transport=${result.transport}`];
		if (result.url) lines.push(`url=${result.url}`);
		if (result.status) lines.push(`status=${result.status}`);
		if (result.wwwAuthenticate) lines.push(`wwwAuthenticate=${result.wwwAuthenticate}`);
		if (result.resourceMetadataUrl) lines.push(`resourceMetadataUrl=${result.resourceMetadataUrl}`);
		if (result.resourceMetadata) lines.push(`resourceMetadata=${JSON.stringify(result.resourceMetadata, null, 2)}`);
		if (result.error) lines.push(`error=${result.error}`);
		return lines.join("\n");
	}

	private createToolDefinition(serverId: string, runtimeName: string, tool: McpToolSummary): ToolDefinition {
		return {
			name: runtimeName,
			label: `MCP ${serverId}/${tool.name}`,
			description: tool.description ?? `Call MCP tool '${tool.name}' on server '${serverId}'.`,
			promptSnippet: `Call MCP tool ${serverId}/${tool.name}`,
			promptGuidelines: [
				`Routes to MCP server '${serverId}', original tool '${tool.name}'.`,
				"Use this when the MCP server is the most direct source of truth for the task.",
			],
			parameters: normalizeInputSchema(tool.inputSchema),
			execute: async (_toolCallId, params, signal) => {
				const result = await this.callTool(serverId, tool.name, params, signal);
				return toAgentToolResult(result);
			},
		};
	}

	private filterPrompts(rawPrompts: unknown): McpPromptSummary[] {
		const prompts = Array.isArray(rawPrompts) ? rawPrompts : [];
		return prompts
			.filter((prompt: any) => typeof prompt?.name === "string")
			.map((prompt: any) => ({
				name: prompt.name,
				description: typeof prompt.description === "string" ? prompt.description : undefined,
				arguments: Array.isArray(prompt.arguments) ? prompt.arguments : undefined,
			}));
	}

	private promptGetResultToToolContent(name: string, result: unknown): { content: Array<Record<string, unknown>> } {
		const description = isRecord(result) && typeof result.description === "string" ? result.description : undefined;
		const messages = isRecord(result) && Array.isArray(result.messages) ? result.messages : [];
		const textParts: string[] = [`prompt=${name}`];
		if (description) textParts.push(`description=${description}`);
		const content: Array<Record<string, unknown>> = [];
		for (const [index, message] of messages.entries()) {
			if (!isRecord(message)) continue;
			const role = typeof message.role === "string" ? message.role : "unknown";
			const messageContent = message.content;
			if (isRecord(messageContent) && messageContent.type === "text" && typeof messageContent.text === "string") {
				textParts.push(`\n[${index}] role=${role}\n${messageContent.text}`);
				continue;
			}
			if (
				isRecord(messageContent) &&
				messageContent.type === "image" &&
				typeof messageContent.data === "string" &&
				typeof messageContent.mimeType === "string"
			) {
				content.push({ type: "image", data: messageContent.data, mimeType: messageContent.mimeType });
				textParts.push(`\n[${index}] role=${role}\n[image:${messageContent.mimeType}]`);
				continue;
			}
			textParts.push(`\n[${index}] role=${role}\n${JSON.stringify(messageContent ?? message)}`);
		}
		content.unshift({ type: "text", text: textParts.join("\n") });
		return { content };
	}

	private filterResources(rawResources: unknown): McpResourceSummary[] {
		const resources = Array.isArray(rawResources) ? rawResources : [];
		return resources
			.filter((resource: any) => typeof resource?.uri === "string")
			.map((resource: any) => ({
				uri: resource.uri,
				name: typeof resource.name === "string" ? resource.name : undefined,
				description: typeof resource.description === "string" ? resource.description : undefined,
				mimeType: typeof resource.mimeType === "string" ? resource.mimeType : undefined,
			}));
	}

	private resourceReadResultToToolContent(uri: string, result: unknown): { content: Array<Record<string, unknown>> } {
		const contents = isRecord(result) && Array.isArray(result.contents) ? result.contents : [];
		const content: Array<Record<string, unknown>> = [];
		for (const item of contents) {
			if (!isRecord(item)) continue;
			const itemUri = typeof item.uri === "string" ? item.uri : uri;
			const mimeType = typeof item.mimeType === "string" ? item.mimeType : undefined;
			if (typeof item.text === "string") {
				content.push({
					type: "text",
					text: [`uri=${itemUri}`, mimeType ? `mimeType=${mimeType}` : undefined, "", item.text]
						.filter((part) => part !== undefined)
						.join("\n"),
				});
				continue;
			}
			if (typeof item.blob === "string") {
				if (mimeType?.startsWith("image/")) {
					content.push({ type: "image", data: item.blob, mimeType });
				} else {
					content.push({
						type: "text",
						text: [
							`uri=${itemUri}`,
							mimeType ? `mimeType=${mimeType}` : undefined,
							"encoding=base64",
							"",
							item.blob,
						]
							.filter((part) => part !== undefined)
							.join("\n"),
					});
				}
			}
		}
		return { content };
	}

	private normalizeMcpContent(serverId: string, toolName: string, result: unknown): NormalizedMcpContent {
		const content = isRecord(result) && Array.isArray(result.content) ? result.content : [];
		const normalized: McpToolCallResult["content"] = [];
		const artifacts: McpToolArtifact[] = [];
		for (const [index, item] of content.entries()) {
			if (!isRecord(item)) continue;
			if (item.type === "text" && typeof item.text === "string") {
				const redactedText = redact(item.text);
				if (redactedText.length > MCP_TOOL_ARTIFACT_THRESHOLD_CHARS) {
					const artifact = this.writeTextArtifact(serverId, toolName, index, redactedText);
					artifacts.push(artifact);
					const previewEnd = safeHeadEnd(redactedText, MCP_TOOL_INLINE_PREVIEW_CHARS);
					normalized.push({
						type: "text",
						text: `${redactedText.slice(0, previewEnd)}

[MCP output stored as artifact]
path=${artifact.path}
sha256=${artifact.sha256}
bytes=${artifact.bytes}
preview_chars=${artifact.previewChars}`,
					});
				} else {
					normalized.push({ type: "text", text: inlineMcpText(redactedText) });
				}
				continue;
			}
			if (item.type === "image" && typeof item.data === "string" && typeof item.mimeType === "string") {
				normalized.push({ type: "image", data: item.data, mimeType: item.mimeType });
				continue;
			}
			normalized.push({ type: "text", text: inlineMcpText(JSON.stringify(item)) });
		}
		if (normalized.length === 0) normalized.push({ type: "text", text: "MCP tool returned no content." });
		return { content: normalized, artifacts };
	}

	private writeTextArtifact(serverId: string, toolName: string, itemIndex: number, text: string): McpToolArtifact {
		const bytes = Buffer.byteLength(text, "utf8");
		const sha256 = createHash("sha256").update(text).digest("hex");
		const dir = join(this.agentDir, "recon", "mcp-artifacts", sanitizeToolNamePart(serverId, "server"));
		mkdirSync(dir, { recursive: true, mode: 0o700 });
		const fileName = `${Date.now()}-${sanitizeToolNamePart(toolName, "tool")}-${itemIndex}-${sha256.slice(0, 12)}.txt`;
		const path = join(dir, fileName);
		// Atomic temp+rename (same dir, 0o600 preserved) so a crash-torn write
		// cannot leave a partial artifact the model is pointed at. Same pattern as
		// opt #38/#41/#43 session/manifest/state atomic rewrites.
		atomicWriteFileSync(path, text, 0o600);
		return { path, sha256, bytes, previewChars: Math.min(MCP_TOOL_INLINE_PREVIEW_CHARS, text.length) };
	}

	private shouldExposeTools(entry: McpServerEntry): boolean {
		return !entry.config.disabled && (entry.config.autoRegisterTools === true || entry.config.enableTools === true);
	}

	private isToolAllowed(entry: McpServerEntry, toolName: string): boolean {
		const allowed = new Set(entry.config.allowedTools ?? []);
		const blocked = new Set(entry.config.blockedTools ?? []);
		const envAllowedTools = envCsv("REPI_MCP_ALLOWED_TOOLS");
		const envAllowed = new Set(
			envAllowedTools
				.filter((item) => !item.includes("/") || item.startsWith(`${entry.id}/`))
				.map((item) => (item.includes("/") ? item.slice(item.indexOf("/") + 1) : item)),
		);
		return (
			(allowed.size === 0 || allowed.has(toolName)) &&
			(envAllowed.size === 0 || envAllowed.has(toolName)) &&
			!blocked.has(toolName)
		);
	}

	private filterTools(entry: McpServerEntry, rawTools: unknown): McpToolSummary[] {
		const tools = Array.isArray(rawTools) ? rawTools : [];
		return tools
			.filter((tool: any) => typeof tool?.name === "string")
			.filter((tool: any) => this.isToolAllowed(entry, tool.name))
			.map((tool: any) => ({
				name: tool.name,
				description: typeof tool.description === "string" ? tool.description : undefined,
				inputSchema: tool.inputSchema,
			}));
	}

	private async withInitializedMcpClient<T>(
		entry: McpServerEntry,
		callback: (client: McpJsonRpcClient, init: any) => Promise<T>,
		signal?: AbortSignal,
	): Promise<T> {
		// opt #139: register a non-pooled (`pool:false`) stdio child's pid for the
		// duration of the callback so the exit-reap hook + closeAll can reach it.
		// See _inflightNonPooledPids. Runs the callback within a try/finally that
		// always unregisters + refreshes the hook, used for both the first attempt
		// and the retry so the retry child is tracked too.
		const runTracked = async (pooled: PooledMcpClient): Promise<T> => {
			const nonPooledPid = entry.config.pool === false ? pooled.client.childPid : undefined;
			if (nonPooledPid !== undefined) {
				this.addInflightPid(this._inflightNonPooledPids, pooled.key, nonPooledPid);
			}
			try {
				const result = await callback(pooled.client, pooled.init);
				this.schedulePooledClientClose(entry, pooled);
				return result;
			} finally {
				if (nonPooledPid !== undefined) {
					this.removeInflightPid(this._inflightNonPooledPids, pooled.key, nonPooledPid);
				}
			}
		};

		const pooled = await this.getPooledClient(entry, signal);
		try {
			return await runTracked(pooled);
		} catch (error) {
			// opt #276: only tear down the pooled client when the connection is
			// actually dead. A per-request `message.error` (e.g. a tools/call
			// returning "invalid params" / "not found") leaves the connection
			// HEALTHY — `pooled.client.isClosed === false` and the error is not
			// retryable. Pre-fix this catch closed the pooled client on EVERY
			// callback error, killing the stdio child and forcing a
			// spawn+initialize handshake on the next call to the same pooled
			// server — a perf/cost regression on every erroring tool call.
			// Re-pool the healthy client (mirror the success path) instead.
			await this.finalizePooledClientOnError(entry, pooled, error, signal);
			if (!signal?.aborted && !this._disposed && this.isRetryableMcpError(error)) {
				const retry = await this.getPooledClient(entry, signal, true);
				try {
					return await runTracked(retry);
				} catch (retryError) {
					await this.finalizePooledClientOnError(entry, retry, retryError, signal);
					throw retryError;
				}
			}
			throw error;
		}
	}

	/**
	 * Finalize a pooled client after a callback error (opt #276). Close it only
	 * when the connection is actually dead — the client was already marked
	 * closed (framing/exit/IO death) OR the error is a retryable transport
	 * error (timeout/ECONN/server-exited) that warrants a respawn. Otherwise the
	 * connection is healthy (a per-request protocol error) and the client is
	 * re-pooled via schedulePooledClientClose for reuse, mirroring the success
	 * path. For `pool:false` servers schedulePooledClientClose closes
	 * immediately, so non-pooled behavior is unchanged (fresh client per call).
	 */
	private async finalizePooledClientOnError(
		entry: McpServerEntry,
		pooled: PooledMcpClient,
		error: unknown,
		signal?: AbortSignal,
	): Promise<void> {
		const connectionFatal =
			pooled.client.isClosed || (!signal?.aborted && !this._disposed && this.isRetryableMcpError(error));
		if (connectionFatal) {
			if (this.clientPool.has(pooled.key)) await this.closePooledClient(pooled.key);
			else await pooled.client.close();
		} else {
			this.schedulePooledClientClose(entry, pooled);
		}
	}

	private async createInitializedClient(entry: McpServerEntry, signal?: AbortSignal): Promise<PooledMcpClient> {
		const key = this.poolKey(entry);
		const fingerprint = this.serverFingerprint(entry);
		const client: McpJsonRpcClient =
			normalizeTransport(entry.config) === "http"
				? new StreamableHttpJsonRpcClient(entry)
				: new StdioJsonRpcClient(entry);
		// The stdio child is now spawned (detached+unref'd). Record its pid so the
		// exit-reap hook and closeAll can reach it BEFORE the creation promise
		// resolves and the client is pooled. HTTP clients have no childPid.
		const childPid = client.childPid;
		if (childPid !== undefined) {
			this.addInflightPid(this._inflightChildPids, key, childPid);
		}
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
				signal,
			);
			await client.notify("notifications/initialized", undefined, timeoutMs, signal);
			return { key, fingerprint, client, init };
		} catch (error) {
			// On failure the success path (getPooledClient's createPromise
			// resolution) never runs, so remove OUR pid from the inflight map
			// here before closing the child (the success path removes it after
			// the createPromise resolves, reading the pid off the client).
			if (childPid !== undefined) this.removeInflightPid(this._inflightChildPids, key, childPid);
			await client.close();
			throw error;
		}
	}

	private async getPooledClient(
		entry: McpServerEntry,
		signal?: AbortSignal,
		forceNew = false,
	): Promise<PooledMcpClient> {
		// opt #141: refuse to spawn/resolve a client after closeAll(). A warm-pool
		// hit is also rejected because closeAll cleared clientPool and killed the
		// children — any `existing` here would be a stale closed client.
		if (this._disposed) throw new Error("MCP manager has been disposed");
		const key = this.poolKey(entry);
		const fingerprint = this.serverFingerprint(entry);
		const poolingEnabled = entry.config.pool !== false;
		const existing = this.clientPool.get(key);
		if (
			!forceNew &&
			poolingEnabled &&
			existing &&
			existing.fingerprint === fingerprint &&
			!existing.client.isClosed
		) {
			if (existing.idleTimer) clearTimeout(existing.idleTimer);
			existing.idleTimer = undefined;
			return existing;
		}
		if (existing) await this.closePooledClient(key);
		// Serialize creation per key: a second concurrent waiter on the same key
		// reuses the first's in-flight create instead of spawning a second child
		// that would overwrite (and orphan) the first. The map is only consulted
		// on the create path; the steady-state warm-pool hit returns `existing`
		// above and never reaches here.
		//
		// opt #234: gate inflight sharing on `poolingEnabled`. For `pool:false`
		// the inflight promise MUST NOT be shared — pool:false means "fresh
		// client per call". Pre-fix a second concurrent pool:false caller on the
		// same server reused the first's in-flight create (no warm pool exists
		// for pool:false, so `existing` was always undefined and the inflight
		// branch fired), so both callers got the SAME client. The first finisher's
		// schedulePooledClientClose then `client.close()`d the shared client
		// immediately while the second's tools/call was still in flight → the
		// second rejected "MCP client closed" (non-retryable data loss). Now each
		// pool:false caller spawns its own child; per-spawn pid tracking (Set per
		// key in _inflightChildPids/_inflightNonPooledPids) keeps closeAll + the
		// exit-reap hook able to reach every concurrent child.
		const inflight = poolingEnabled ? this._inflightClient.get(key) : undefined;
		if (inflight) return inflight;
		const createPromise = this.createInitializedClient(entry, signal).then(
			(created) => {
				this._inflightClient.delete(key);
				// Remove OUR pid from the init-window map now that the create has
				// resolved (createInitializedClient's catch removed it on failure).
				const pid = created.client.childPid;
				if (pid !== undefined) this.removeInflightPid(this._inflightChildPids, key, pid);
				return created;
			},
			(error) => {
				this._inflightClient.delete(key);
				// Pid already removed by createInitializedClient's catch; just
				// reconcile the exit-reap hook (the pre-fix `.finally` did this).
				this.refreshExitReapHook();
				throw error;
			},
		);
		// Only pooled servers publish the in-flight create for reuse by other
		// waiters; pool:false callers each spawn their own (opt #234).
		if (poolingEnabled) this._inflightClient.set(key, createPromise);
		const created = await createPromise;
		// opt #250: closeAll() may have run DURING the await (disposed set
		// synchronously first, then it SIGKILLed inflight children + cleared
		// clientPool). Pre-fix this newly-resolved client was neither in
		// _inflightChildPids (its pid was removed in the createPromise resolution
		// handler above before closeAll's reap could reach it) NOR in clientPool
		// yet, so closeAll missed it → the child leaked (detached+unref'd, kept
		// making LLM calls) AND we returned a live client to a caller whose
		// manager was already torn down. Re-check disposed after the await; if
		// true, close the orphan and reject non-retryably (matches getPooledClient's
		// top-of-method disposed guard). Safe on both pooled and pool:false paths.
		if (this._disposed) {
			void Promise.resolve(created.client.close()).catch(() => undefined);
			throw new Error("MCP manager has been disposed");
		}
		if (!poolingEnabled) return created;
		this.clientPool.set(key, created);
		this.refreshExitReapHook();
		return created;
	}

	private schedulePooledClientClose(entry: McpServerEntry, pooled: PooledMcpClient): void {
		if (entry.config.pool === false) {
			// (opt #127) fire-and-forget close must not leak an unhandled rejection
			// if close() ever throws — no global unhandledRejection handler exists.
			void Promise.resolve(pooled.client.close()).catch(() => undefined);
			return;
		}
		const idleMs = Math.max(0, entry.config.poolIdleMs ?? DEFAULT_MCP_POOL_IDLE_MS);
		if (pooled.idleTimer) clearTimeout(pooled.idleTimer);
		pooled.idleTimer = setTimeout(() => {
			// (opt #127) same defense: the idle-timer fire-and-forget close must
			// not surface a rejection. agent-session's closeAll already guards with
			// .catch; mirror it here so both fire-and-forget sites are bounded.
			void this.closePooledClient(pooled.key).catch(() => undefined);
		}, idleMs);
		pooled.idleTimer.unref?.();
	}

	async closeAll(): Promise<void> {
		// opt #141: mark disposed FIRST and synchronously so a racing retry or new
		// call concurrent with this closeAll cannot spawn a fresh child after we
		// begin tearing down. getPooledClient and the retry guard check this.
		this._disposed = true;
		// Reap stdio children still in flight (initialize handshake not yet
		// complete). They are not in `clientPool` so the pooled close loop below
		// misses them; without this a parent exit during initialize orphans the
		// detached+unref'd child (cost/quota leak). SIGKILL the process group
		// directly — the child 'close' handler then rejects the inflight
		// createPromise, which its resolution handler cleans up.
		for (const set of this._inflightChildPids.values()) {
			for (const pid of set) killProcessGroup(pid, "SIGKILL");
		}
		this._inflightChildPids.clear();
		// opt #139: reap non-pooled stdio children mid in-flight tool call too
		// (initialize is done so they aren't in _inflightChildPids, and pool:false
		// means they aren't in clientPool either). Without this a closeAll() during
		// a non-pooled call orphans the detached child. opt #234: the map is
		// Set-per-key so N concurrent pool:false calls are all reaped.
		for (const set of this._inflightNonPooledPids.values()) {
			for (const pid of set) killProcessGroup(pid, "SIGKILL");
		}
		this._inflightNonPooledPids.clear();
		this.refreshExitReapHook();
		const closeResults = await Promise.allSettled(
			[...this.clientPool.keys()].map((key) => this.closePooledClient(key)),
		);
		const closeErrors = closeResults
			.filter((result): result is PromiseRejectedResult => result.status === "rejected")
			.map((result) => result.reason);
		if (closeErrors.length > 0) {
			throw new AggregateError(closeErrors, "Failed to close all MCP clients");
		}
	}

	private async closePooledClient(key: string): Promise<void> {
		const pooled = this.clientPool.get(key);
		if (!pooled) return;
		this.clientPool.delete(key);
		if (pooled.idleTimer) clearTimeout(pooled.idleTimer);
		try {
			await pooled.client.close();
		} finally {
			this.refreshExitReapHook();
		}
	}

	/** Install/remove the process.on('exit') reap hook based on pool state. */
	private refreshExitReapHook(): void {
		const live = this.clientPool.size > 0 || this._inflightChildPids.size > 0 || this._inflightNonPooledPids.size > 0;
		if (live && !this._exitReapHook) {
			const hook = () => {
				for (const pooled of this.clientPool.values()) {
					const pid = pooled.client.childPid;
					if (pid) killProcessGroup(pid, "SIGKILL");
				}
				for (const set of this._inflightChildPids.values()) {
					for (const pid of set) killProcessGroup(pid, "SIGKILL");
				}
				// opt #139: non-pooled in-flight call children. opt #234: Set-per-key
				// so N concurrent pool:false calls are all reaped on process exit.
				for (const set of this._inflightNonPooledPids.values()) {
					for (const pid of set) killProcessGroup(pid, "SIGKILL");
				}
			};
			this._exitReapHook = hook;
			process.on("exit", hook);
		} else if (!live && this._exitReapHook) {
			process.off("exit", this._exitReapHook);
			this._exitReapHook = undefined;
		}
	}

	/**
	 * opt #234: add/remove a per-spawn pid to a `Map<string, Set<number>>`
	 * inflight tracker. Multiple concurrent `pool:false` calls on the same
	 * server key each register their own pid; the set holds every in-flight
	 * spawn so closeAll + the exit-reap hook reach all of them. The key is
	 * deleted when its set empties so `refreshExitReapHook`'s `map.size > 0`
	 * live-check stays accurate.
	 */
	private addInflightPid(map: Map<string, Set<number>>, key: string, pid: number): void {
		let set = map.get(key);
		if (!set) {
			set = new Set();
			map.set(key, set);
		}
		set.add(pid);
		this.refreshExitReapHook();
	}

	private removeInflightPid(map: Map<string, Set<number>>, key: string, pid: number): void {
		const set = map.get(key);
		if (set) {
			set.delete(pid);
			if (set.size === 0) map.delete(key);
		}
		this.refreshExitReapHook();
	}

	private poolKey(entry: McpServerEntry): string {
		return `${this.cwd}:${entry.sourcePath}:${entry.id}`;
	}

	private serverFingerprint(entry: McpServerEntry): string {
		return createHash("sha256")
			.update(
				JSON.stringify({
					id: entry.id,
					sourcePath: entry.sourcePath,
					config: entry.config,
					allowedServers: process.env.REPI_MCP_ALLOWED_SERVERS ?? "",
					allowedTools: process.env.REPI_MCP_ALLOWED_TOOLS ?? "",
				}),
			)
			.digest("hex");
	}

	private isRetryableMcpError(error: unknown): boolean {
		const message = error instanceof Error ? error.message : String(error);
		return /MCP server exited|MCP request timeout|MCP HTTP (?:404|408|409|429|500|502|503|504)|fetch failed|ECONN|socket|connection|reset|terminated|timeout/i.test(
			message,
		);
	}

	private async probeEntry(entry: McpServerEntry, signal?: AbortSignal): Promise<McpProbeResult> {
		const transport = normalizeTransport(entry.config);
		if (entry.config.disabled)
			return { serverId: entry.id, ok: false, transport, tools: [], error: "server_disabled" };

		let stderrTail = "";
		try {
			const result = await this.withInitializedMcpClient(
				entry,
				async (client, init) => {
					const timeoutMs = entry.config.timeoutMs ?? DEFAULT_MCP_TIMEOUT_MS;
					const listed = await client.request("tools/list", {}, timeoutMs, signal).catch((error) => ({ error }));
					const tools = this.filterTools(entry, listed?.tools);
					// Surface a tools/list failure (server inits but rejects tools/list —
					// `tools` is an optional MCP capability). Pre-fix the captured
					// `listed.error` was dropped and the probe reported ok:true with empty
					// tools, hiding the broken server as "healthy, no tools". ok stays true
					// (initialize-reachable) so probe.ok-gated callers behave identically;
					// only the error field is populated for callers/users that read it.
					const toolsListError =
						isRecord(listed) && typeof listed.error !== "undefined"
							? redact(listed.error instanceof Error ? listed.error.message : String(listed.error))
							: undefined;
					stderrTail = client.stderrTail;
					return {
						serverId: entry.id,
						ok: true,
						transport,
						command:
							transport === "stdio"
								? [entry.config.command, ...(entry.config.args ?? [])].filter(Boolean).join(" ")
								: undefined,
						url: transport === "http" ? entry.config.url : undefined,
						protocolVersion: typeof init?.protocolVersion === "string" ? init.protocolVersion : undefined,
						serverInfo: init?.serverInfo,
						capabilities: init?.capabilities,
						tools,
						stderrTail: client.stderrTail,
						error: toolsListError,
					} satisfies McpProbeResult;
				},
				signal,
			);
			return result;
		} catch (error) {
			return {
				serverId: entry.id,
				ok: false,
				transport,
				command:
					transport === "stdio"
						? [entry.config.command, ...(entry.config.args ?? [])].filter(Boolean).join(" ")
						: undefined,
				url: transport === "http" ? entry.config.url : undefined,
				tools: [],
				stderrTail,
				error: redact(error instanceof Error ? error.message : String(error)),
			};
		}
	}
}

export function createMcpManager(options: McpManagerOptions): McpManager {
	return new McpManager(options);
}

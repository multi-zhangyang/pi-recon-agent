import type { ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { join } from "node:path";
import { APP_NAME } from "../config.ts";
import type { AgentThreadRunManifest, AgentThreadStatus } from "./agent-thread-contract.ts";
import { atomicWriteFileSync } from "./tools/atomic-write.ts";

const AGENT_THREAD_STATUSES = new Set<AgentThreadStatus>([
	"planned",
	"running",
	"complete",
	"failed",
	"timeout",
	"stopped",
]);
const TERMINAL_AGENT_THREAD_STATUSES = new Set<AgentThreadStatus>(["complete", "failed", "timeout", "stopped"]);

export function isAgentThreadStatus(status: unknown): status is AgentThreadStatus {
	return typeof status === "string" && AGENT_THREAD_STATUSES.has(status as AgentThreadStatus);
}

export function isTerminalAgentThreadStatus(status: AgentThreadStatus | undefined): boolean {
	return status !== undefined && TERMINAL_AGENT_THREAD_STATUSES.has(status);
}

export function abortError(reason: unknown): Error {
	if (reason instanceof Error) return reason;
	const error = new Error(typeof reason === "string" && reason ? reason : "Agent thread aborted");
	error.name = "AbortError";
	return error;
}

/** Link caller cancellation with the manager lifecycle without mutating either signal. */
export function linkAbortSignals(signals: Array<AbortSignal | undefined>): {
	signal: AbortSignal;
	dispose: () => void;
} {
	const controller = new AbortController();
	const subscriptions: Array<{ signal: AbortSignal; listener: () => void }> = [];
	const abort = (signal: AbortSignal): void => {
		if (!controller.signal.aborted) controller.abort(signal.reason);
	};
	for (const signal of signals) {
		if (!signal) continue;
		if (signal.aborted) {
			abort(signal);
			break;
		}
		const listener = () => abort(signal);
		signal.addEventListener("abort", listener, { once: true });
		subscriptions.push({ signal, listener });
	}
	return {
		signal: controller.signal,
		dispose: () => {
			for (const { signal, listener } of subscriptions) signal.removeEventListener("abort", listener);
			subscriptions.length = 0;
		},
	};
}

function runtimeAgentThreadMaxConcurrency(): number {
	const raw = process.env.REPI_AGENT_THREAD_MAX_CONCURRENCY;
	if (raw === undefined || raw.trim() === "") return 4;
	const value = Number(raw);
	if (!Number.isFinite(value) || value < 1) return 4;
	return Math.min(32, Math.floor(value));
}

interface AgentThreadAdmission {
	signal: AbortSignal;
	resolve: (release: () => void) => void;
	reject: (error: Error) => void;
	onAbort: () => void;
}

/** Process-wide admission control, shared by the short-lived per-tool managers. */
class AgentThreadExecutionLimiter {
	private active = 0;
	private readonly pending: AgentThreadAdmission[] = [];

	acquire(signal: AbortSignal): Promise<() => void> {
		if (signal.aborted) return Promise.reject(abortError(signal.reason));
		if (this.active < runtimeAgentThreadMaxConcurrency()) return Promise.resolve(this.activate());
		return new Promise((resolve, reject) => {
			const admission: AgentThreadAdmission = {
				signal,
				resolve,
				reject,
				onAbort: () => {
					const index = this.pending.indexOf(admission);
					if (index >= 0) this.pending.splice(index, 1);
					reject(abortError(signal.reason));
				},
			};
			signal.addEventListener("abort", admission.onAbort, { once: true });
			this.pending.push(admission);
		});
	}

	private activate(): () => void {
		this.active++;
		let released = false;
		return () => {
			if (released) return;
			released = true;
			this.active = Math.max(0, this.active - 1);
			this.drain();
		};
	}

	private drain(): void {
		while (this.active < runtimeAgentThreadMaxConcurrency()) {
			const admission = this.pending.shift();
			if (!admission) return;
			admission.signal.removeEventListener("abort", admission.onAbort);
			if (admission.signal.aborted) {
				admission.reject(abortError(admission.signal.reason));
				continue;
			}
			admission.resolve(this.activate());
		}
	}
}

export const agentThreadExecutionLimiter = new AgentThreadExecutionLimiter();

function firstEnvValue(names: string[]): string | undefined {
	for (const name of names) {
		const value = process.env[name]?.trim();
		if (value) return value;
	}
	return undefined;
}

export function envSubagentModelOverride(): { provider?: string; model?: string } {
	const model = firstEnvValue(["REPI_SUBAGENT_MODEL"]);
	if (!model) return {};
	return {
		provider:
			firstEnvValue(["REPI_SUBAGENT_PROVIDER", "REPI_PROVIDER", "REPI_MODEL_PROVIDER", "REPI_PROVIDER_ID"]) ??
			"repi-env",
		model,
	};
}

const SECRET_PATTERNS: Array<[RegExp, string]> = [
	[/\bsk-[A-Za-z0-9_-]{8,}\b/g, "<redacted:api-key>"],
	[/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>"],
	[/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>"],
	[/\b(cfut_[A-Za-z0-9_-]{8,})\b/g, "<redacted:cloudflare-token>"],
	[/(API_KEY|AUTH_TOKEN|TOKEN|SECRET|PASSWORD)=([^\s]+)/gi, "$1=<redacted>"],
];

export function redact(text: string): string {
	let out = text;
	for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement);
	return out;
}

export async function sha256(text: string): Promise<string> {
	return createHash("sha256").update(text).digest("hex");
}

export function nowIso(): string {
	return new Date().toISOString();
}

export function killWorkerProcessTree(child: ChildProcess, signal: NodeJS.Signals): void {
	const pid = child.pid;
	if (!pid) return;
	if (process.platform !== "win32") {
		try {
			process.kill(-pid, signal);
			return;
		} catch {
			// Fall through to the direct child kill for races / non-detached fallbacks.
		}
	}
	try {
		child.kill(signal);
	} catch {
		// best-effort
	}
}

export function isChildProcessRunning(child: ChildProcess): boolean {
	return child.exitCode === null && child.signalCode === null;
}

export interface HandoffSnapshot {
	bytes: number;
	sha256: string;
	head: string;
	text: string;
}

export function readHandoffSnapshot(path: string, maxChars = 16000): HandoffSnapshot {
	const fd = openSync(path, "r");
	try {
		const before = fstatSync(fd);
		const hash = createHash("sha256");
		const headLimit = 8192;
		const tailLimit = Math.max(maxChars * 8, 65536);
		const head = Buffer.alloc(Math.min(headLimit, before.size));
		let headBytes = 0;
		let tail = Buffer.alloc(0);
		const chunk = Buffer.alloc(64 * 1024);
		let offset = 0;
		while (offset < before.size) {
			const bytes = readSync(fd, chunk, 0, Math.min(chunk.length, before.size - offset), offset);
			if (bytes <= 0) throw new Error("handoff changed while reading");
			const view = chunk.subarray(0, bytes);
			hash.update(view);
			if (headBytes < head.length) {
				const copyBytes = Math.min(head.length - headBytes, bytes);
				view.copy(head, headBytes, 0, copyBytes);
				headBytes += copyBytes;
			}
			if (bytes >= tailLimit) {
				tail = Buffer.from(view.subarray(bytes - tailLimit));
			} else {
				const combined = Buffer.concat([tail, view]);
				tail = combined.length > tailLimit ? Buffer.from(combined.subarray(combined.length - tailLimit)) : combined;
			}
			offset += bytes;
		}
		const after = fstatSync(fd);
		if (offset !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs) {
			throw new Error("handoff changed while reading");
		}
		let tailStart = 0;
		while (tailStart < tail.length && (tail[tailStart] & 0xc0) === 0x80) tailStart++;
		const decodedTail = tail.toString("utf8", tailStart);
		return {
			bytes: before.size,
			sha256: hash.digest("hex"),
			head: head.toString("utf8", 0, headBytes),
			text: decodedTail.length > maxChars ? decodedTail.slice(-maxChars) : decodedTail,
		};
	} finally {
		closeSync(fd);
	}
}

export function handoffManifestPatchFromSnapshot(
	snapshot: HandoffSnapshot,
	expected: { runId: string; missionId?: string; lineageSha256: string },
): Partial<AgentThreadRunManifest> {
	const field = (name: string): string | undefined => {
		const match = new RegExp(`^${name}:[ \\t]*([^\\r\\n]*)$`, "im").exec(snapshot.head);
		return match?.[1]?.trim();
	};
	const handoffRunId = field("run_id");
	const handoffMissionId = field("mission_id");
	const handoffLineageSha256 = field("lineage_sha256")?.toLowerCase();
	return {
		handoffPresent: true,
		handoffRecovered: false,
		handoffBytes: snapshot.bytes,
		handoffSha256: snapshot.sha256,
		handoffRunId,
		handoffMissionId,
		handoffLineageSha256,
		handoffLineageValid:
			handoffRunId === expected.runId &&
			handoffMissionId === (expected.missionId ?? "") &&
			handoffLineageSha256 === expected.lineageSha256.toLowerCase(),
	};
}

export async function handoffManifestPatch(
	handoffPath: string,
	expected: { runId: string; missionId?: string; lineageSha256: string },
): Promise<Partial<AgentThreadRunManifest>> {
	try {
		return handoffManifestPatchFromSnapshot(readHandoffSnapshot(handoffPath), expected);
	} catch {
		return { handoffPresent: false, handoffBytes: 0, handoffLineageValid: false };
	}
}

function safeIdPart(text: string): string {
	return text
		.toLowerCase()
		.replace(/[^a-z0-9._-]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 48);
}

export function makeRunId(specName: string): string {
	return `${new Date().toISOString().replace(/[:.]/g, "-")}-${safeIdPart(specName) || "agent"}-${randomBytes(4).toString("hex")}`;
}

export function mkdirp(path: string): void {
	mkdirSync(path, { recursive: true, mode: 0o700 });
}

const readTextMaxBytes = (maxChars: number): number => Math.max(maxChars * 8, 65536);

/** Read a text file, returning at most its last `maxChars` characters. */
export function readText(path: string, maxChars = 12000): string {
	try {
		const stat = statSync(path);
		const maxBytes = readTextMaxBytes(maxChars);
		if (stat.size <= maxBytes) {
			const raw = readFileSync(path, "utf8");
			return raw.length > maxChars ? raw.slice(-maxChars) : raw;
		}
		const len = Math.min(maxBytes, stat.size);
		const fd = openSync(path, "r");
		try {
			const buf = Buffer.alloc(len);
			const bytesRead = readSync(fd, buf, 0, len, stat.size - len);
			let start = 0;
			while (start < bytesRead && (buf[start] & 0xc0) === 0x80) start++;
			const raw = buf.toString("utf8", start, bytesRead);
			return raw.length > maxChars ? raw.slice(-maxChars) : raw;
		} finally {
			closeSync(fd);
		}
	} catch {
		return "";
	}
}

export function writeJson(path: string, value: unknown): void {
	atomicWriteFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function readJsonRecord(path: string): Record<string, unknown> | undefined {
	if (!existsSync(path)) return undefined;
	try {
		const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
		return isRecord(parsed) ? parsed : undefined;
	} catch {
		return undefined;
	}
}

export function formatCommandForDisplay(command: string, args: string[]): string {
	return [command, ...args].map((arg) => (/[\s"'`$]/.test(arg) ? JSON.stringify(arg) : arg)).join(" ");
}

export function resolveRepiBin(cwd: string, explicit?: string): string {
	if (explicit) return explicit;
	if (process.env.REPI_BIN_PATH) return process.env.REPI_BIN_PATH;
	const local = join(cwd, "repi");
	if (existsSync(local)) return local;
	return APP_NAME || "repi";
}

const DEFAULT_AGENT_THREAD_MAX_RUN_DIRS = 50;

export function runtimeAgentThreadMaxRunDirs(): number {
	const raw = process.env.REPI_AGENT_THREAD_MAX_RUN_DIRS;
	if (raw === undefined || raw.trim() === "") return DEFAULT_AGENT_THREAD_MAX_RUN_DIRS;
	const value = Number(raw);
	if (!Number.isFinite(value) || value < 0) return DEFAULT_AGENT_THREAD_MAX_RUN_DIRS;
	return Math.floor(value);
}

export function runtimeAgentThreadStopKillGraceMs(): number {
	const raw = process.env.REPI_AGENT_THREAD_STOP_KILL_GRACE_MS;
	if (raw === undefined || raw.trim() === "") return 2000;
	const value = Number(raw);
	if (!Number.isFinite(value) || value < 50) return 2000;
	return Math.min(30_000, Math.floor(value));
}

export function sanitizeMcpToolNamePart(value: string, fallback: string): string {
	const sanitized = value
		.replace(/[^A-Za-z0-9_]/g, "_")
		.replace(/_+/g, "_")
		.replace(/^_+|_+$/g, "");
	return (sanitized || fallback).slice(0, 64);
}

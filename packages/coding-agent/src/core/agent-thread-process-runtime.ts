import type { ChildProcess } from "node:child_process";
import { appendFileSync, writeFileSync } from "node:fs";
import { spawnProcess } from "../utils/child-process.ts";
import type { AgentThreadRunManifest, AgentThreadStatus } from "./agent-thread-contract.ts";
import {
	handoffManifestPatch,
	isChildProcessRunning,
	isTerminalAgentThreadStatus,
	killWorkerProcessTree,
	nowIso,
	readText,
	redact,
	sha256,
} from "./agent-thread-runtime.ts";
import { safeTailStart } from "./tools/truncate.ts";

export interface AgentThreadProcessRuntimeOptions {
	command: string;
	args: string[];
	cwd: string;
	env: NodeJS.ProcessEnv;
	runId: string;
	stdoutPath: string;
	stderrPath: string;
	handoffPath: string;
	timeoutMs: number;
	missionId?: string;
	lineageSha256: string;
	isDisposed: () => boolean;
	isPending: () => boolean;
	getManifest: () => AgentThreadRunManifest | undefined;
	updateManifest: (patch: Partial<AgentThreadRunManifest>) => void;
	onSettled: () => void;
}

export interface AgentThreadProcessRuntime {
	child: ChildProcess;
	timeoutTimer: NodeJS.Timeout;
}

const STDOUT_MEMORY_CAP_CHARS = 2 * 1024 * 1024;
const STDERR_MEMORY_CAP_CHARS = 512 * 1024;
const STDOUT_DISK_CAP_BYTES = 4 * 1024 * 1024;
const STDERR_DISK_CAP_BYTES = 1024 * 1024;
const TIMEOUT_KILL_GRACE_MS = 2000;

function utf8TailWithinBytes(text: string, maxBytes: number): string {
	if (Buffer.byteLength(text, "utf8") <= maxBytes) return text;
	const bytes = Buffer.from(text, "utf8");
	let start = Math.max(0, bytes.length - maxBytes);
	while (start < bytes.length && (bytes[start] & 0xc0) === 0x80) start++;
	return bytes.toString("utf8", start);
}

/**
 * Start one isolated REPI child and own its stream/timeout/close lifecycle.
 * The manager owns admission, persisted run discovery, and public controls;
 * this runtime owns the process-specific state that must settle exactly once.
 */
export function startAgentThreadProcess(options: AgentThreadProcessRuntimeOptions): AgentThreadProcessRuntime {
	const child = spawnProcess(options.command, options.args, {
		cwd: options.cwd,
		detached: process.platform !== "win32",
		env: options.env,
		stdio: ["ignore", "pipe", "pipe"],
	});
	// Node may emit an asynchronous spawn error before the manager has finished
	// publishing the run. Keep an early listener attached; the detailed listener
	// below records the final state after all lifecycle hooks exist.
	child.on("error", () => {});
	child.stdout?.setEncoding("utf8");
	child.stderr?.setEncoding("utf8");

	let stdout = "";
	let stderr = "";
	let stdoutDiskBytes = 0;
	let stderrDiskBytes = 0;

	const appendOutput = (
		path: string,
		text: string,
		memoryText: string,
		diskBytes: number,
		diskCapBytes: number,
	): number => {
		try {
			const textBytes = Buffer.byteLength(text, "utf8");
			if (diskBytes + textBytes > diskCapBytes) {
				const tail = utf8TailWithinBytes(memoryText, diskCapBytes);
				writeFileSync(path, tail, { encoding: "utf8", mode: 0o600 });
				return Buffer.byteLength(tail, "utf8");
			}
			appendFileSync(path, text, { encoding: "utf8", mode: 0o600 });
			return diskBytes + textBytes;
		} catch {
			return diskBytes;
		}
	};

	child.stdout?.on("data", (chunk: string | Buffer) => {
		const text = redact(String(chunk));
		stdout += text;
		if (stdout.length > STDOUT_MEMORY_CAP_CHARS) {
			stdout = stdout.slice(safeTailStart(stdout, stdout.length - STDOUT_MEMORY_CAP_CHARS));
		}
		stdoutDiskBytes = appendOutput(options.stdoutPath, text, stdout, stdoutDiskBytes, STDOUT_DISK_CAP_BYTES);
	});
	child.stderr?.on("data", (chunk: string | Buffer) => {
		const text = redact(String(chunk));
		stderr += text;
		if (stderr.length > STDERR_MEMORY_CAP_CHARS) {
			stderr = stderr.slice(safeTailStart(stderr, stderr.length - STDERR_MEMORY_CAP_CHARS));
		}
		stderrDiskBytes = appendOutput(options.stderrPath, text, stderr, stderrDiskBytes, STDERR_DISK_CAP_BYTES);
	});
	child.stdout?.on("error", () => {});
	child.stderr?.on("error", () => {});

	const timeoutTimer = setTimeout(() => {
		options.updateManifest({
			status: "timeout",
			error: `timeout_ms=${options.timeoutMs}`,
			cancelledAt: nowIso(),
			signal: "SIGTERM",
		});
		killWorkerProcessTree(child, "SIGTERM");
		setTimeout(() => {
			if (isChildProcessRunning(child)) killWorkerProcessTree(child, "SIGKILL");
		}, TIMEOUT_KILL_GRACE_MS).unref();
	}, options.timeoutMs);
	timeoutTimer.unref();

	child.on("error", (error) => {
		if (!options.isPending()) return;
		options.updateManifest({ status: "failed", error: redact(error.message), endedAt: nowIso() });
	});
	child.on("close", (code, signal) => {
		void finalizeAgentThreadProcess(options, timeoutTimer, code, signal);
	});

	return { child, timeoutTimer };
}

async function finalizeAgentThreadProcess(
	options: AgentThreadProcessRuntimeOptions,
	timeoutTimer: NodeJS.Timeout,
	code: number | null,
	signal: NodeJS.Signals | null,
): Promise<void> {
	try {
		clearTimeout(timeoutTimer);
		if (!options.isDisposed()) {
			let existing: AgentThreadRunManifest | undefined;
			try {
				existing = options.getManifest();
			} catch {
				existing = undefined;
			}
			const status: AgentThreadStatus = isTerminalAgentThreadStatus(existing?.status)
				? existing!.status
				: code === 0
					? "complete"
					: "failed";
			options.updateManifest({ status, endedAt: nowIso(), exitCode: code, signal });
			options.updateManifest({
				stdoutSha256: await sha256(readText(options.stdoutPath, STDOUT_MEMORY_CAP_CHARS)),
				stderrSha256: await sha256(readText(options.stderrPath, STDERR_MEMORY_CAP_CHARS)),
				...(await handoffManifestPatch(options.handoffPath, {
					runId: options.runId,
					missionId: options.missionId,
					lineageSha256: options.lineageSha256,
				})),
			});
		}
	} catch {
		if (!options.isDisposed()) {
			try {
				options.updateManifest({
					status: code === 0 ? "complete" : "failed",
					endedAt: nowIso(),
					exitCode: code,
					signal,
				});
				options.updateManifest({
					...(await handoffManifestPatch(options.handoffPath, {
						runId: options.runId,
						missionId: options.missionId,
						lineageSha256: options.lineageSha256,
					})),
				});
			} catch {
				// The manager still settles its caller below.
			}
		}
	} finally {
		clearTimeout(timeoutTimer);
		try {
			options.onSettled();
		} catch {
			// A listener cleanup must not leave the process run unresolved.
		}
	}
}

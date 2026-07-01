/**
 * Shared command execution utilities for extensions and custom tools.
 */

import { spawn } from "node:child_process";
import { waitForChildProcess } from "../utils/child-process.ts";
import { safeTailStart } from "./tools/truncate.ts";

/**
 * Options for executing shell commands.
 */
export interface ExecOptions {
	/** AbortSignal to cancel the command */
	signal?: AbortSignal;
	/** Timeout in milliseconds */
	timeout?: number;
	/** Working directory */
	cwd?: string;
	/**
	 * Per-stream byte cap for stdout/stderr. When a stream exceeds this, only the
	 * tail is kept and `truncated` is set on the result. An explicit value >0
	 * caps at that size; an explicit `0` DISABLES the cap (opt #50 JSON-caller
	 * contract — structured output must not be tail-truncated, since truncation
	 * breaks parsing). When unset, the cap falls back to the
	 * `REPI_EXEC_MAX_BYTES` env default (8MB, 0 = disable) so the recon `pi.exec`
	 * callers — which never pass `maxBytes` — are protected from runaway output
	 * (`objdump -d`, `strings`, `find /`) without each caller opting in. The
	 * `truncated` flag lets text callers detect a tail-trim.
	 */
	maxBytes?: number;
}

/**
 * Result of executing a shell command.
 */
export interface ExecResult {
	stdout: string;
	stderr: string;
	code: number;
	killed: boolean;
	/** True if stdout or stderr exceeded {@link ExecOptions.maxBytes} and was tail-truncated. */
	truncated?: boolean;
}

/**
 * Default per-stream byte cap applied when a caller does NOT pass an explicit
 * `maxBytes`. 8MB is high enough that normal recon output (disassembly of a
 * function, strings of a binary, a network-capture session) passes through
 * untruncated, but low enough that a runaway command (`objdump -d` on a huge
 * binary, `strings` on a firmware image, `find /`, an unfiltered log) is
 * tail-capped before it can OOM the agent. The model's view of exec output is
 * already capped at the agent-core context boundary (~256K chars, opt #15/#33),
 * so this default only bounds peak in-memory accumulation — it does not change
 * what the model ultimately sees for any output under 8MB. Override with
 * `REPI_EXEC_MAX_BYTES` (bytes, 0 = disable the default = legacy unbounded).
 */
const DEFAULT_EXEC_MAX_BYTES = 8 * 1024 * 1024;

/**
 * Map a child-process signal name to a shell-style exit code. POSIX shells
 * report a signal-killed process as `128 + signum`. `waitForChildProcess`
 * resolves with `code === null` whenever the process was terminated by a
 * signal (our abort/timeout SIGTERM/SIGKILL OR an external SIGKILL/OOM). The
 * old `code ?? 0` coerced that null to `0` = success, so callers branching on
 * `result.code !== 0` treated a timeout/abort/OOM kill as a successful run.
 * Never return 0 for a signal-killed process: a known signal maps to
 * `128 + signum`; an unknown signal maps to `128`; a missing signalCode (null)
 * maps to a non-zero sentinel `1`.
 */
function signalCodeToExitCode(signalCode: string | null | undefined): number {
	if (!signalCode) return 1;
	const signum = SIGNAL_NUMBERS[signalCode];
	return signum !== undefined ? 128 + signum : 128;
}

const SIGNAL_NUMBERS: Record<string, number> = {
	SIGHUP: 1,
	SIGINT: 2,
	SIGQUIT: 3,
	SIGILL: 4,
	SIGTRAP: 5,
	SIGABRT: 6,
	SIGBUS: 7,
	SIGFPE: 8,
	SIGKILL: 9,
	SIGUSR1: 10,
	SIGSEGV: 11,
	SIGUSR2: 12,
	SIGPIPE: 13,
	SIGALRM: 14,
	SIGTERM: 15,
};

/**
 * Resolve the per-stream byte cap. An explicit `maxBytes > 0` always wins; an
 * explicit `0` disables the cap (the opt #50 JSON-caller contract — structured
 * output must not be tail-truncated, since truncation breaks parsing); an
 * unset value falls back to the `REPI_EXEC_MAX_BYTES` env default (8MB, 0 =
 * disable).
 */
function resolveExecMaxBytes(explicit: number | undefined): number | undefined {
	if (explicit !== undefined) {
		return explicit > 0 ? explicit : undefined;
	}
	const raw = process.env.REPI_EXEC_MAX_BYTES;
	if (raw === undefined) return DEFAULT_EXEC_MAX_BYTES;
	const n = Math.floor(Number(raw));
	if (!Number.isFinite(n) || n < 0) return DEFAULT_EXEC_MAX_BYTES;
	return n > 0 ? n : undefined;
}

/**
 * Execute a shell command and return stdout/stderr/code.
 * Supports timeout and abort signal.
 */
export async function execCommand(
	command: string,
	args: string[],
	cwd: string,
	options?: ExecOptions,
): Promise<ExecResult> {
	return new Promise((resolve) => {
		const proc = spawn(command, args, {
			cwd,
			shell: false,
			stdio: ["ignore", "pipe", "pipe"],
		});

		let stdout = "";
		let stderr = "";
		// Incremental per-stream byte counters. The previous appendBounded
		// recomputed `Buffer.byteLength(current + chunk)` on EVERY data event,
		// re-encoding the whole accumulated string per chunk → O(n²) up to the
		// cap (a runaway `objdump -d` emitting many small chunks would burn CPU
		// re-encoding megabytes on each tick). Track the byte count incrementally
		// (Buffer.byteLength(chunk) only) and only slice from the front when the
		// cap is exceeded — mirroring the bash OutputAccumulator's incremental
		// tailBytes/totalDecodedBytes approach.
		let stdoutBytes = 0;
		let stderrBytes = 0;
		let killed = false;
		let truncated = false;
		let timeoutId: NodeJS.Timeout | undefined;
		let sigkillTimer: NodeJS.Timeout | undefined;
		const maxBytes = resolveExecMaxBytes(options?.maxBytes);

		// Tail-keep a growing output string at maxBytes so a runaway command
		// cannot OOM the agent. Keeps the most recent bytes (where errors/summaries
		// usually land); sets `truncated` so the caller can detect it.
		const appendBounded = (target: "stdout" | "stderr", chunk: string): void => {
			const chunkBytes = Buffer.byteLength(chunk, "utf-8");
			if (maxBytes === undefined) {
				if (target === "stdout") {
					stdout += chunk;
					stdoutBytes += chunkBytes;
				} else {
					stderr += chunk;
					stderrBytes += chunkBytes;
				}
				return;
			}
			const current = target === "stdout" ? stdout : stderr;
			const currentBytes = target === "stdout" ? stdoutBytes : stderrBytes;
			const next = current + chunk;
			const nextBytes = currentBytes + chunkBytes;
			if (nextBytes > maxBytes) {
				truncated = true;
				// Keep the tail: slice off enough bytes from the front to stay under
				// the cap. Slice on chars then trim to bytes to avoid splitting a
				// multi-byte sequence mid-codepoint.
				const over = nextBytes - maxBytes;
				let cut = 0;
				let cutBytes = 0;
				while (cutBytes < over && cut < next.length) {
					cutBytes += Buffer.byteLength(next[cut], "utf-8");
					cut += 1;
				}
				// Avoid beginning the retained tail on a lone low surrogate (opt #60): the
				// loop trims one code unit at a time, so `cut` can land on the low surrogate
				// of an astral-plane char whose high surrogate was just trimmed — `next[cut]`
				// indexes a single UTF-16 code unit and Buffer.byteLength of a lone low
				// surrogate is 3 (the UTF-8 encoding of the orphan), so the loop removes only
				// the high surrogate and the tail starts with the lone low surrogate →
				// `\uDCxx` fed to the model. safeTailStart advances past it.
				const safeCut = safeTailStart(next, cut);
				const tail = next.slice(safeCut);
				const tailBytes = Buffer.byteLength(tail, "utf-8");
				if (target === "stdout") {
					stdout = tail;
					stdoutBytes = tailBytes;
				} else {
					stderr = tail;
					stderrBytes = tailBytes;
				}
			} else if (target === "stdout") {
				stdout = next;
				stdoutBytes = nextBytes;
			} else {
				stderr = next;
				stderrBytes = nextBytes;
			}
		};

		const clearTimers = () => {
			if (timeoutId) {
				clearTimeout(timeoutId);
				timeoutId = undefined;
			}
			if (sigkillTimer) {
				clearTimeout(sigkillTimer);
				sigkillTimer = undefined;
			}
		};

		const killProcess = () => {
			if (!killed) {
				killed = true;
				proc.kill("SIGTERM");
				// Force kill after 5 seconds if SIGTERM doesn't work. unref + tracked
				// so a process that dies promptly under SIGTERM does not keep the Node
				// event loop alive for 5s, and the timer is cleared on resolve/catch.
				sigkillTimer = setTimeout(() => {
					if (proc.exitCode === null) {
						proc.kill("SIGKILL");
					}
				}, 5000);
				sigkillTimer.unref();
			}
		};

		// Handle abort signal
		if (options?.signal) {
			if (options.signal.aborted) {
				killProcess();
			} else {
				options.signal.addEventListener("abort", killProcess, { once: true });
			}
		}

		// Handle timeout
		if (options?.timeout && options.timeout > 0) {
			timeoutId = setTimeout(() => {
				killProcess();
			}, options.timeout);
		}

		proc.stdout?.on("data", (data) => {
			appendBounded("stdout", data.toString());
		});

		proc.stderr?.on("data", (data) => {
			appendBounded("stderr", data.toString());
		});

		// Wait for process termination without hanging on inherited stdio handles
		// held open by detached descendants.
		waitForChildProcess(proc)
			.then((code) => {
				clearTimers();
				if (options?.signal) {
					options.signal.removeEventListener("abort", killProcess);
				}
				// A null exit code means the process was terminated by a signal
				// (our abort/timeout SIGTERM/SIGKILL escalation OR an external
				// SIGKILL/OOM). The old `code ?? 0` coerced that to 0 = success, so
				// callers branching on `result.code !== 0` treated a timeout/abort
				// kill as a successful run. Map a signal kill to a shell-style
				// 128+signum (or a non-zero sentinel) — never to 0. The `killed`
				// flag is preserved so callers can still distinguish our kill.
				const resolvedCode = code !== null ? code : signalCodeToExitCode(proc.signalCode);
				resolve({ stdout, stderr, code: resolvedCode, killed, truncated: truncated || undefined });
			})
			.catch((_err) => {
				clearTimers();
				if (options?.signal) {
					options.signal.removeEventListener("abort", killProcess);
				}
				// Surface the spawn-failure reason (e.g. `spawn ls ENOENT`) when
				// stderr is empty. Previously the catch discarded _err entirely and
				// resolved with empty stdout/stderr + code 1, so the caller could not
				// distinguish "command not found" from "ran and returned 1 with no
				// output" — the actionable error string was lost (the #35
				// silent-error-swallowing pattern). Default-preserving: when stderr
				// already has content the message is unchanged; only the empty
				// spawn-failure case gains the reason. The resolve contract is kept
				// (no new rejection).
				resolve({
					stdout,
					stderr: stderr || (_err instanceof Error ? _err.message : String(_err)),
					code: 1,
					killed,
					truncated: truncated || undefined,
				});
			});
	});
}

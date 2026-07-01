interface StdoutTakeoverState {
	rawStdoutWrite: (chunk: string, callback?: (error?: Error | null) => void) => boolean;
	rawStderrWrite: (chunk: string, callback?: (error?: Error | null) => void) => boolean;
	originalStdoutWrite: typeof process.stdout.write;
}

let stdoutTakeoverState: StdoutTakeoverState | undefined;

const RAW_STDOUT_RETRY_DELAY_MS = 10;

// A stdio stream whose read end has closed (the consumer exited while the agent
// is still producing output — e.g. `repi -p "…" | head`, or the parent agent
// died and orphaned a headless child) emits one of these errno codes as an
// 'error' event. interactive-mode installs a handler that restores the terminal
// and exits; headless modes (print/json/rpc) write their protocol to a piped
// stdout and reach this guard instead.
const DEAD_STDIO_ERROR_CODES = new Set(["EIO", "EPIPE", "ENOTCONN"]);

let stdioErrorGuardInstalled = false;

let rawStdoutWriteTail: Promise<void> = Promise.resolve();

function getRawStdoutWrite(): StdoutTakeoverState["rawStdoutWrite"] {
	if (stdoutTakeoverState) {
		return stdoutTakeoverState.rawStdoutWrite;
	}
	return process.stdout.write.bind(process.stdout) as StdoutTakeoverState["rawStdoutWrite"];
}

async function writeRawStdoutChunk(text: string): Promise<void> {
	while (true) {
		try {
			await new Promise<void>((resolve, reject) => {
				try {
					getRawStdoutWrite()(text, (error) => {
						if (error) reject(error);
						else resolve();
					});
				} catch (error) {
					reject(error instanceof Error ? error : new Error(String(error)));
				}
			});
			return;
		} catch (error) {
			const writeError = error instanceof Error ? error : new Error(String(error));
			const code = (writeError as Error & { code?: unknown }).code;
			if (code !== "ENOBUFS" && code !== "EAGAIN" && code !== "EWOULDBLOCK") {
				throw writeError;
			}
			await new Promise<void>((resolve) => setTimeout(resolve, RAW_STDOUT_RETRY_DELAY_MS));
		}
	}
}

export function takeOverStdout(): void {
	if (stdoutTakeoverState) {
		return;
	}

	const rawStdoutWrite = process.stdout.write.bind(process.stdout) as StdoutTakeoverState["rawStdoutWrite"];
	const rawStderrWrite = process.stderr.write.bind(process.stderr) as StdoutTakeoverState["rawStderrWrite"];
	const originalStdoutWrite = process.stdout.write;

	process.stdout.write = ((
		chunk: string | Uint8Array,
		encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void),
		callback?: (error?: Error | null) => void,
	): boolean => {
		if (typeof encodingOrCallback === "function") {
			return rawStderrWrite(String(chunk), encodingOrCallback);
		}
		return rawStderrWrite(String(chunk), callback);
	}) as typeof process.stdout.write;

	stdoutTakeoverState = {
		rawStdoutWrite,
		rawStderrWrite,
		originalStdoutWrite,
	};
}

export function restoreStdout(): void {
	if (!stdoutTakeoverState) {
		return;
	}

	process.stdout.write = stdoutTakeoverState.originalStdoutWrite;
	stdoutTakeoverState = undefined;
}

export function isStdoutTakenOver(): boolean {
	return stdoutTakeoverState !== undefined;
}

export function writeRawStdout(text: string): void {
	if (text.length === 0) {
		return;
	}
	rawStdoutWriteTail = rawStdoutWriteTail.then(() => writeRawStdoutChunk(text));
	void rawStdoutWriteTail.catch(() => {
		process.exit(1);
	});
}

export async function waitForRawStdoutBackpressure(): Promise<void> {
	while (true) {
		const tail = rawStdoutWriteTail;
		await tail;
		if (tail === rawStdoutWriteTail) {
			return;
		}
	}
}

export async function flushRawStdout(): Promise<void> {
	await waitForRawStdoutBackpressure();
	await writeRawStdoutChunk("");
}

/**
 * Decide whether a stdio 'error' represents a dead downstream pipe (the read
 * end closed) and the process should exit. Pure/testable; the exit itself is
 * performed by installStdioErrorGuard's listener.
 */
export function isDeadStdioError(error: unknown): boolean {
	const code = (error as NodeJS.ErrnoException | null | undefined)?.code;
	return code !== undefined && DEAD_STDIO_ERROR_CODES.has(code);
}

interface StdioStreamLike {
	on(event: "error", listener: (error: unknown) => void): unknown;
}

/**
 * Attach best-effort 'error' listeners to stdout and stderr so a broken
 * downstream pipe does not crash the agent with `Unhandled 'error' event`.
 * `writeRawStdout` already exits(1) when a write callback receives an error,
 * but a stream can emit 'error' independently of a write call (the read end
 * closes between writes, or Node emits the socket 'error' alongside the write
 * callback) — with no listener that is an unhandled-'error'-event crash,
 * dumping a stack trace to the very pipe that is dead. On a dead-pipe code
 * (EIO/EPIPE/ENOTCONN) we exit(1) cleanly, matching the write-failure path;
 * other codes are swallowed best-effort (headless stderr may itself be dead, so
 * we do not log) and surfaced by the next failing write. Idempotent.
 *
 * This is the headless-mode counterpart of interactive-mode's terminalErrorHandler.
 *
 * @param streams Optional injectable streams for testing; defaults to
 *   process.stdout / process.stderr.
 */
export function installStdioErrorGuard(streams?: {
	stdout?: StdioStreamLike | null;
	stderr?: StdioStreamLike | null;
}): void {
	if (stdioErrorGuardInstalled) return;
	stdioErrorGuardInstalled = true;
	const handler = (error: unknown): void => {
		if (isDeadStdioError(error)) {
			process.exit(1);
		}
		// Non-pipe error: swallow. The next writeRawStdout attempt will fail and
		// exit(1). Continuing (rather than re-throwing) avoids an unhandled-'error'
		// crash on a stream that may already be unwritable.
	};
	const out = streams?.stdout ?? process.stdout;
	const err = streams?.stderr ?? process.stderr;
	if (out && typeof out.on === "function") {
		out.on("error", handler);
	}
	if (err && typeof err.on === "function") {
		err.on("error", handler);
	}
}

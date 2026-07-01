import { randomBytes } from "node:crypto";
import { createWriteStream, unlinkSync, type WriteStream } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { registerSessionResourceCleanup } from "@pi-recon/repi-ai";
import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, type TruncationResult, truncateTail } from "./truncate.ts";

export interface OutputAccumulatorOptions {
	maxLines?: number;
	maxBytes?: number;
	tempFilePrefix?: string;
	/**
	 * Session id that owns the temp file (opt #153). When provided, the temp
	 * file is unlinked when `cleanupSessionResources(sessionId)` fires (on
	 * newSession/fork/switchSession/dispose) instead of leaking in the OS tmpdir
	 * + in-memory Set until process exit. Critical for long-running rpc daemons
	 * that handle many sessions.
	 */
	sessionId?: string;
}

export interface OutputSnapshot {
	content: string;
	truncation: TruncationResult;
	fullOutputPath?: string;
}

function defaultTempFilePath(prefix: string): string {
	const id = randomBytes(8).toString("hex");
	return join(tmpdir(), `${prefix}-${id}.log`);
}

// Wall cap on awaiting a temp-file WriteStream's 'finish' (opt #64). The stream
// flushes to the OS tmpdir; on a stalled FS (NFS/hung mount/FUSE, or an fd stuck
// in uninterruptible I/O) neither 'finish' nor 'error' ever fires → the bash
// tool's `await closeTempFile()` (every run above the truncation threshold)
// never settles → the agent loop freezes forever. On timeout we destroy the
// stream (release the fd) and resolve flushed=false so the caller withholds the
// "Full output" path (the file may be partial). 0 disables (Infinity). Exported
// so bash-executor.ts (remote-bash path) shares the same ceiling.
export const TEMP_FILE_FLUSH_TIMEOUT_MS = (() => {
	const raw = process.env.REPI_TEMP_FILE_FLUSH_TIMEOUT_MS;
	if (raw === undefined) return 10_000;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return 10_000;
	return n === 0 ? Infinity : n;
})();

/**
 * Temp files persisted for the model to read back (truncated bash/grep output,
 * etc.). These live for the session — the model may `read`/`tail` them later —
 * but must not accumulate in the OS tmpdir forever. Tracked here and removed
 * best-effort at process exit. (A SIGKILL leaks them; the OS tmpdir reaper
 * handles that case eventually, which is no worse than before this tracking.)
 */
const persistedTempFiles = new Set<string>();
let exitCleanupRegistered = false;
function registerExitCleanup(): void {
	if (exitCleanupRegistered) return;
	exitCleanupRegistered = true;
	process.on("exit", () => {
		for (const path of persistedTempFiles) {
			try {
				unlinkSync(path);
			} catch {
				// Best-effort: file may already be gone or be on a read-only mount.
			}
		}
	});
}

// opt #153: per-session temp-file tracking. The exit handler above unlinks
// everything at process exit, but in a long-running rpc daemon that handles
// many sessions over its lifetime, temp files (one per bash overflow / pasted
// image) accumulated across sessions — leaking in the OS tmpdir AND in the
// in-memory Set until the process exited. Registering a session-resource
// cleanup unlinks a disposed session's temp files when
// `cleanupSessionResources(sessionId)` fires (on newSession/fork/switchSession/
// dispose), bounding growth to the live session. Files registered WITHOUT a
// sessionId (e.g. the remote-bash path) keep the legacy exit-only behavior.
const sessionTempFiles = new Map<string, Set<string>>();
let sessionCleanupRegistered = false;
function registerSessionCleanup(): void {
	if (sessionCleanupRegistered) return;
	sessionCleanupRegistered = true;
	registerSessionResourceCleanup((sessionId?: string) => {
		if (!sessionId) return;
		const files = sessionTempFiles.get(sessionId);
		if (!files) return;
		for (const p of files) {
			try {
				unlinkSync(p);
			} catch {
				// Best-effort: file may already be gone (read back + removed) or on
				// a read-only mount.
			}
			persistedTempFiles.delete(p);
		}
		sessionTempFiles.delete(sessionId);
	});
}

/**
 * Register a session-scoped temp file for best-effort unlink at process exit,
 * AND (when sessionId is provided) on session disposal via
 * cleanupSessionResources(sessionId). For paths the model may read back during
 * the session (bash/grep full-output logs) but must not accumulate in the OS
 * tmpdir forever across sessions. Idempotent and safe to call from other
 * modules (e.g. bash-executor) that create their own temp files outside the
 * OutputAccumulator.
 */
export function registerPersistedTempFile(filePath: string, sessionId?: string): void {
	registerExitCleanup();
	persistedTempFiles.add(filePath);
	if (sessionId) {
		registerSessionCleanup();
		let s = sessionTempFiles.get(sessionId);
		if (!s) {
			s = new Set();
			sessionTempFiles.set(sessionId, s);
		}
		s.add(filePath);
	}
}

function byteLength(text: string): number {
	return Buffer.byteLength(text, "utf-8");
}

/**
 * Incrementally tracks streaming output with bounded memory.
 *
 * Appends decode chunks with a streaming UTF-8 decoder, keeps only a decoded
 * tail for display snapshots, and opens a temp file when the full output needs
 * to be preserved.
 */
export class OutputAccumulator {
	private readonly maxLines: number;
	private readonly maxBytes: number;
	private readonly maxRollingBytes: number;
	private readonly tempFilePrefix: string;
	private readonly sessionId?: string;
	private readonly decoder = new TextDecoder();

	private rawChunks: Buffer[] = [];
	private tailText = "";
	private tailBytes = 0;
	private tailStartsAtLineBoundary = true;
	private totalRawBytes = 0;
	private totalDecodedBytes = 0;
	private completedLines = 0;
	private totalLines = 0;
	private currentLineBytes = 0;
	private hasOpenLine = false;
	private finished = false;

	private tempFilePath: string | undefined;
	private tempFileStream: WriteStream | undefined;
	// Set if the temp-file WriteStream errored mid-stream (disk full, EACCES,
	// read-only mount, etc.). A WriteStream emits "error" with NO listener →
	// uncaught → process crash; the listener in ensureTempFile records the
	// failure instead and nulls the stream so further appends degrade to the
	// rolling tail instead of crashing. snapshot() then withholds the broken
	// path so the model is never told to read a partial/missing temp file.
	private tempFileError: string | undefined;

	constructor(options: OutputAccumulatorOptions = {}) {
		this.maxLines = options.maxLines ?? DEFAULT_MAX_LINES;
		this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
		this.maxRollingBytes = Math.max(this.maxBytes * 2, 1);
		this.tempFilePrefix = options.tempFilePrefix ?? "pi-output";
		this.sessionId = options.sessionId;
	}

	append(data: Buffer): void {
		if (this.finished) {
			throw new Error("Cannot append to a finished output accumulator");
		}

		this.totalRawBytes += data.length;
		this.appendDecodedText(this.decoder.decode(data, { stream: true }));

		if (this.tempFileStream || this.shouldUseTempFile()) {
			this.ensureTempFile();
			// tempFileStream may have been nullled by an async write error in a
			// prior append; in that case drop the chunk (the rolling tail still
			// holds the recent output for the snapshot).
			if (this.tempFileStream && !this.tempFileError) {
				this.tempFileStream.write(data);
			}
		} else if (data.length > 0) {
			this.rawChunks.push(data);
		}
	}

	finish(): void {
		if (this.finished) {
			return;
		}
		this.finished = true;
		this.appendDecodedText(this.decoder.decode());
		if (this.shouldUseTempFile()) {
			this.ensureTempFile();
		}
	}

	snapshot(options: { persistIfTruncated?: boolean } = {}): OutputSnapshot {
		const tailTruncation = truncateTail(this.getSnapshotText(), {
			maxLines: this.maxLines,
			maxBytes: this.maxBytes,
		});
		const truncated = this.totalLines > this.maxLines || this.totalDecodedBytes > this.maxBytes;
		const truncatedBy = truncated
			? (tailTruncation.truncatedBy ?? (this.totalDecodedBytes > this.maxBytes ? "bytes" : "lines"))
			: null;
		const truncation: TruncationResult = {
			...tailTruncation,
			truncated,
			truncatedBy,
			totalLines: this.totalLines,
			totalBytes: this.totalDecodedBytes,
			maxLines: this.maxLines,
			maxBytes: this.maxBytes,
		};

		if (options.persistIfTruncated && truncation.truncated) {
			this.ensureTempFile();
		}

		return {
			content: truncation.content,
			truncation,
			// Withhold the path when the temp file errored mid-stream so the model
			// is never told to read a partial/missing "Full output" file.
			fullOutputPath: this.tempFileError ? undefined : this.tempFilePath,
		};
	}

	/**
	 * Flush the temp-file stream to disk and await 'finish' so the returned
	 * fullOutputPath is actually readable by the time the caller (the model)
	 * reads it. Resolves immediately if no stream was opened.
	 *
	 * Returns `true` iff the stream flushed cleanly (finish); `false` on a stream
	 * 'error' OR a wall-timeout (opt #64). NEVER rejects — a flush error is
	 * already recorded in `tempFileError` by the write listener, and a timeout
	 * destroys the stream and marks the temp file errored so the caller withholds
	 * the path. Previously this rejected on 'error', which could propagate out of
	 * the bash tool's catch-path `await finishOutput()` and crash the agent.
	 */
	async closeTempFile(): Promise<boolean> {
		if (!this.tempFileStream) {
			return true;
		}

		const stream = this.tempFileStream;
		this.tempFileStream = undefined;

		return new Promise<boolean>((resolve) => {
			let settled = false;
			let timer: NodeJS.Timeout | undefined;
			const cleanup = (): void => {
				if (timer) {
					clearTimeout(timer);
					timer = undefined;
				}
				stream.off("finish", onFinish);
				stream.off("error", onError);
			};
			const finish = (flushed: boolean): void => {
				if (settled) return;
				settled = true;
				cleanup();
				resolve(flushed);
			};
			const onFinish = (): void => finish(true);
			const onError = (): void => {
				// A flush error means the temp file is partial/missing — mark it so
				// any later snapshot withholds the path. Resolve false (don't reject).
				this.tempFileError = "temp file flush timed out";
				finish(false);
			};
			stream.once("error", onError);
			stream.once("finish", onFinish);
			// Wall timeout: on a stalled FS neither 'finish' nor 'error' fires.
			// Destroy the stream (releases the fd; fires no further events we care
			// about) and resolve false so the caller withholds the path.
			if (Number.isFinite(TEMP_FILE_FLUSH_TIMEOUT_MS) && TEMP_FILE_FLUSH_TIMEOUT_MS > 0) {
				timer = setTimeout(() => {
					this.tempFileError = "temp file flush timed out";
					try {
						stream.destroy();
					} catch {
						/* already closed */
					}
					finish(false);
				}, TEMP_FILE_FLUSH_TIMEOUT_MS);
			}
			stream.end();
		});
	}

	getLastLineBytes(): number {
		return this.currentLineBytes;
	}

	private appendDecodedText(text: string): void {
		if (text.length === 0) {
			return;
		}

		const bytes = byteLength(text);
		this.totalDecodedBytes += bytes;
		this.tailText += text;
		this.tailBytes += bytes;
		if (this.tailBytes > this.maxRollingBytes * 2) {
			this.trimTail();
		}

		let newlines = 0;
		let lastNewline = -1;
		for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) {
			newlines++;
			lastNewline = i;
		}
		if (newlines === 0) {
			this.currentLineBytes += bytes;
			this.hasOpenLine = true;
		} else {
			this.completedLines += newlines;
			const tail = text.slice(lastNewline + 1);
			this.currentLineBytes = byteLength(tail);
			this.hasOpenLine = tail.length > 0;
		}
		this.totalLines = this.completedLines + (this.hasOpenLine ? 1 : 0);
	}

	private trimTail(): void {
		const buffer = Buffer.from(this.tailText, "utf-8");
		if (buffer.length <= this.maxRollingBytes) {
			this.tailBytes = buffer.length;
			return;
		}

		let start = buffer.length - this.maxRollingBytes;
		while (start < buffer.length && (buffer[start] & 0xc0) === 0x80) {
			start++;
		}

		this.tailStartsAtLineBoundary = start === 0 ? this.tailStartsAtLineBoundary : buffer[start - 1] === 0x0a;
		this.tailText = buffer.subarray(start).toString("utf-8");
		this.tailBytes = byteLength(this.tailText);
	}

	private getSnapshotText(): string {
		if (this.tailStartsAtLineBoundary) {
			return this.tailText;
		}

		const firstNewline = this.tailText.indexOf("\n");
		return firstNewline === -1 ? this.tailText : this.tailText.slice(firstNewline + 1);
	}

	private shouldUseTempFile(): boolean {
		return (
			this.totalRawBytes > this.maxBytes || this.totalDecodedBytes > this.maxBytes || this.totalLines > this.maxLines
		);
	}

	private ensureTempFile(): void {
		if (this.tempFilePath) {
			return;
		}
		this.tempFilePath = defaultTempFilePath(this.tempFilePrefix);
		// Track for best-effort cleanup at process exit (and on session disposal
		// when a sessionId is bound — opt #153) so truncated-output temp files do
		// not accumulate in the OS tmpdir across sessions.
		registerPersistedTempFile(this.tempFilePath, this.sessionId);
		this.tempFileStream = createWriteStream(this.tempFilePath);
		// Attach a persistent error listener so a mid-stream write failure (disk
		// full, EACCES, read-only mount) degrades gracefully instead of emitting
		// an unhandled "error" event that crashes the agent process. Record the
		// failure, drop the stream (further appends fall back to the rolling
		// tail), and let snapshot() withhold the path.
		this.tempFileStream.on("error", (error: Error) => {
			this.tempFileError = error instanceof Error ? error.message : String(error);
			this.tempFileStream = undefined;
		});
		for (const chunk of this.rawChunks) {
			this.tempFileStream.write(chunk);
		}
		this.rawChunks = [];
	}
}

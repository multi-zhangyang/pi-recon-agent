/**
 * Bash command execution with streaming support and cancellation.
 *
 * This module provides a unified bash execution implementation used by:
 * - AgentSession.executeBash() for interactive and RPC modes
 * - Direct calls from modes that need bash execution
 */

import { randomBytes } from "node:crypto";
import { createWriteStream, type WriteStream } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stripAnsi } from "../utils/ansi.ts";
import { sanitizeBinaryOutput } from "../utils/shell.ts";
import type { BashOperations } from "./tools/bash.ts";
import { registerPersistedTempFile, TEMP_FILE_FLUSH_TIMEOUT_MS } from "./tools/output-accumulator.ts";
import { DEFAULT_MAX_BYTES, type TruncationResult, truncateHeadTail, truncateTail } from "./tools/truncate.ts";

/**
 * Select the bash output truncation strategy.
 *
 * - `REPI_BASH_TRUNCATE=head_tail`: keep head + tail with a middle-ellipsis
 *   marker (modern code-agent strategy — preserves early errors AND the final
 *   exit context). Recommended for long-running commands.
 * - default / `tail`: keep only the tail (legacy behavior).
 */
function truncateBashOutput(fullOutput: string): TruncationResult {
	const strategy = (process.env.REPI_BASH_TRUNCATE ?? "tail").trim().toLowerCase();
	if (strategy === "head_tail" || strategy === "head-tail" || strategy === "headtail") {
		return truncateHeadTail(fullOutput);
	}
	return truncateTail(fullOutput);
}

// ============================================================================
// Types
// ============================================================================

export interface BashExecutorOptions {
	/** Callback for streaming output chunks (already sanitized) */
	onChunk?: (chunk: string) => void;
	/** AbortSignal for cancellation */
	signal?: AbortSignal;
}

export interface BashResult {
	/** Combined stdout + stderr output (sanitized, possibly truncated) */
	output: string;
	/** Process exit code (undefined if killed/cancelled) */
	exitCode: number | undefined;
	/** Whether the command was cancelled via signal */
	cancelled: boolean;
	/** Whether the output was truncated */
	truncated: boolean;
	/** Path to temp file containing full output (if output exceeded truncation threshold) */
	fullOutputPath?: string;
}

// ============================================================================
// Implementation
// ============================================================================

/**
 * Execute a bash command using custom BashOperations.
 * Used for remote execution (SSH, containers, etc.).
 */
export async function executeBashWithOperations(
	command: string,
	cwd: string,
	operations: BashOperations,
	options?: BashExecutorOptions,
): Promise<BashResult> {
	const outputChunks: string[] = [];
	let outputBytes = 0;
	const maxOutputBytes = DEFAULT_MAX_BYTES * 2;

	let tempFilePath: string | undefined;
	let tempFileStream: WriteStream | undefined;
	// Set if the temp-file WriteStream errored mid-stream (disk full, EACCES,
	// read-only mount, ENOTDIR). Without a listener the "error" event is
	// uncaught and crashes the agent; the listener records the failure and
	// nulls the stream so further writes drop gracefully. The returned
	// fullOutputPath is then withheld so the model is never pointed at a
	// partial/missing "Full output" file.
	let tempFileError: string | undefined;
	let totalBytes = 0;

	const ensureTempFile = () => {
		if (tempFilePath) {
			return;
		}
		const id = randomBytes(8).toString("hex");
		tempFilePath = join(tmpdir(), `pi-bash-${id}.log`);
		// Track for best-effort unlink at process exit so overflow logs don't
		// accumulate in the OS tmpdir forever across sessions. The file is
		// session-scoped (the model may read it back), but must not leak permanently.
		registerPersistedTempFile(tempFilePath);
		tempFileStream = createWriteStream(tempFilePath);
		tempFileStream.on("error", (error: Error) => {
			tempFileError = error instanceof Error ? error.message : String(error);
			tempFileStream = undefined;
		});
		for (const chunk of outputChunks) {
			tempFileStream.write(chunk);
		}
	};

	// Flush the temp-file stream to disk and await 'finish' so the returned
	// fullOutputPath is actually readable by the time the caller (the model)
	// reads it. Resolves immediately if no stream was opened or it already
	// errored; never rejects (a flush error is already recorded in
	// tempFileError by the listener above). opt #64: a wall timeout destroys the
	// stream and sets tempFileError so the path is withheld — on a stalled FS
	// neither 'finish' nor 'error' fires and the await would hang forever.
	const closeTempFileStream = async (): Promise<void> => {
		const stream = tempFileStream;
		if (!stream) {
			return;
		}
		tempFileStream = undefined;
		await new Promise<void>((resolve) => {
			let settled = false;
			let timer: NodeJS.Timeout | undefined;
			const cleanup = (): void => {
				if (timer) {
					clearTimeout(timer);
					timer = undefined;
				}
				stream.off("finish", onFinish);
				stream.off("error", onFinish);
			};
			const finish = (): void => {
				if (settled) return;
				settled = true;
				cleanup();
				resolve();
			};
			const onFinish = (): void => finish();
			stream.once("error", onFinish);
			stream.once("finish", onFinish);
			if (Number.isFinite(TEMP_FILE_FLUSH_TIMEOUT_MS) && TEMP_FILE_FLUSH_TIMEOUT_MS > 0) {
				timer = setTimeout(() => {
					tempFileError = "temp file flush timed out";
					try {
						stream.destroy();
					} catch {
						/* already closed */
					}
					finish();
				}, TEMP_FILE_FLUSH_TIMEOUT_MS);
			}
			stream.end();
		});
	};

	const decoder = new TextDecoder();

	const onData = (data: Buffer) => {
		totalBytes += data.length;

		// Sanitize: strip ANSI, replace binary garbage, normalize newlines
		const text = sanitizeBinaryOutput(stripAnsi(decoder.decode(data, { stream: true }))).replace(/\r/g, "");

		// Start writing to temp file if exceeds threshold
		if (totalBytes > DEFAULT_MAX_BYTES) {
			ensureTempFile();
		}

		if (tempFileStream && !tempFileError) {
			tempFileStream.write(text);
		}

		// Keep rolling buffer
		outputChunks.push(text);
		outputBytes += text.length;
		while (outputBytes > maxOutputBytes && outputChunks.length > 1) {
			const removed = outputChunks.shift()!;
			outputBytes -= removed.length;
		}

		// Stream to callback
		if (options?.onChunk) {
			options.onChunk(text);
		}
	};

	try {
		const result = await operations.exec(command, cwd, {
			onData,
			signal: options?.signal,
		});

		const fullOutput = outputChunks.join("");
		const truncationResult = truncateBashOutput(fullOutput);
		if (truncationResult.truncated) {
			ensureTempFile();
		}
		await closeTempFileStream();
		const cancelled = options?.signal?.aborted ?? false;

		return {
			output: truncationResult.truncated ? truncationResult.content : fullOutput,
			exitCode: cancelled ? undefined : (result.exitCode ?? undefined),
			cancelled,
			truncated: truncationResult.truncated,
			fullOutputPath: tempFileError ? undefined : tempFilePath,
		};
	} catch (err) {
		// Check if it was an abort
		if (options?.signal?.aborted) {
			const fullOutput = outputChunks.join("");
			const truncationResult = truncateBashOutput(fullOutput);
			if (truncationResult.truncated) {
				ensureTempFile();
			}
			await closeTempFileStream();
			return {
				output: truncationResult.truncated ? truncationResult.content : fullOutput,
				exitCode: undefined,
				cancelled: true,
				truncated: truncationResult.truncated,
				fullOutputPath: tempFileError ? undefined : tempFilePath,
			};
		}

		await closeTempFileStream();

		throw err;
	}
}

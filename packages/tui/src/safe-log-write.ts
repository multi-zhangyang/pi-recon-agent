/**
 * Best-effort file log writer.
 *
 * Used at TUI render crash/debug sites where a log write happens BEFORE
 * terminal-state restoration (this.stop()). A bare mkdirSync+writeFileSync can
 * throw synchronously on EACCES/ENOSPC/EIO, skipping stop() and leaving the
 * terminal in raw mode (bracketed-paste/Kitty-keyboard active) — wedging the
 * user's shell. This helper swallows any write failure so the caller always
 * reaches its terminal-state-restore path.
 */

import * as fs from "node:fs";
import * as path from "node:path";

/**
 * Write `data` to `filePath`, creating parent dirs as needed. Never throws.
 * On failure, emits a one-line notice to stderr (best-effort, also swallowed).
 */
export function safeWriteLogFile(filePath: string, data: string): void {
	try {
		fs.mkdirSync(path.dirname(filePath), { recursive: true });
		fs.writeFileSync(filePath, data);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		try {
			console.error(`safeWriteLogFile: failed to write ${filePath}: ${msg}`);
		} catch {
			// Swallow — never throw out of a best-effort log writer.
		}
	}
}

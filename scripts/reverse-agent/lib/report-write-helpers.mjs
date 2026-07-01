/**
 * Shared helpers for writing one-shot RE report/artifact/output files with
 * bounded failure handling.
 *
 * Used by repi-bugreport / repi-mission / repi-doctor / model-inspect
 * (foundational opt #177). The bare `writeFileSync` (preceded by `mkdirSync`)
 * at each report-write site had NO try/catch — an ENOSPC/EACCES mid-write
 * threw uncaught and aborted the script MID-COLLECTION, discarding everything
 * gathered so far with no partial output. `safeWriteReport` wraps the write so
 * a failure becomes an observable stderr diagnostic + non-zero exit (and, for
 * bugreport, a stdout salvage) instead of a silent uncaught throw.
 *
 * Design note: the helper does NOT call `process.exit` directly. It delegates
 * failure handling to an injectable `onWriteError` callback whose default
 * emits a stderr diagnostic and exits non-zero. Tests inject a recorder so
 * they can assert behavior without tearing down the vitest process; the
 * scripts call the helper with the default (or a script-specific handler).
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Default failure handler: emit a stderr diagnostic and exit non-zero so the
 * failure is observable to callers (a shell pipeline, an agent host, CI).
 * Exported so non-write sites (e.g. a bare `mkdirSync` in repi-doctor's
 * --fix repair path) can reuse the exact same failure contract.
 */
export function defaultReportWriteError(message) {
	console.error(message);
	process.exit(1);
}

/**
 * Write `data` to `path` (creating the parent dir with mode 0o700 first when
 * `mkdir` is true). On success returns `true` and the caller owns any
 * post-write steps (e.g. `chmodSync`). On failure: builds a descriptive
 * `Error writing report to <path>: <err.message>` diagnostic, optionally
 * salvages the data to stdout (when `fallbackToStdout` is true, so a disk-full
 * does not discard the whole collection — the user can redirect stdout), then
 * invokes `onWriteError(message, { path, data, error })`. The default
 * `onWriteError` emits stderr + exits 1; inject a recorder for tests.
 *
 * @param {string} path   - destination report/artifact path
 * @param {string|Buffer} data - report content
 * @param {object} [options]
 * @param {function} [options.onWriteError]  - failure handler (default: stderr + exit 1)
 * @param {boolean}  [options.fallbackToStdout=false] - write data to stdout on failure
 * @param {boolean}  [options.mkdir=true]   - create parent dir before writing
 * @param {string}   [options.encoding="utf8"]
 * @param {number}   [options.mode=0o600]   - file mode for the written report
 * @returns {boolean} true on success, false on failure (after onWriteError runs)
 */
export function safeWriteReport(path, data, options = {}) {
	const {
		onWriteError = defaultReportWriteError,
		fallbackToStdout = false,
		mkdir = true,
		encoding = "utf8",
		mode = 0o600,
	} = options;
	try {
		if (mkdir) mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
		writeFileSync(path, data, { encoding, mode });
		return true;
	} catch (err) {
		const message = `Error writing report to ${path}: ${err instanceof Error ? err.message : String(err)}`;
		if (fallbackToStdout) {
			// Best-effort salvage: the gathered collection is written to stdout
			// so a disk-full does not discard it. Swallow write errors here —
			// the observable failure is still reported via onWriteError below.
			try {
				process.stdout.write(String(data));
			} catch {
				// best effort
			}
		}
		onWriteError(message, { path, data, error: err });
		return false;
	}
}

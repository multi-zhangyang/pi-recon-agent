/**
 * Shared confirmation-prompt helper for the repi bootstrap/uninstall scripts.
 *
 * Both scripts previously called `spawnSync("head", ["-1"], ...)` with NO
 * timeout to read a y/N answer from stdin. If stdin is open but never delivers
 * data (CI with a non-closing pipe, a container with stdin open but no TTY
 * input), `head -1` blocks forever → spawnSync blocks the whole Node process
 * → indefinite hang. The `--yes` flag bypasses the prompt, but the DEFAULT
 * path hung. (foundational opt #181)
 *
 * promptYesNo wraps the spawnSync with a bounded timeout so a stalled stdin
 * resolves instead of hanging the script.
 */

import { spawnSync } from "node:child_process";

/**
 * Prompt stdin for a single line, bounded by timeoutMs.
 *
 * @param promptText  Written to stdout before reading (caller may pre-write).
 * @param timeoutMs   spawnSync timeout (ms). 0 disables (not recommended).
 * @returns `{ answer, timedOut, error }`:
 *   - `answer`   — the trimmed stdout line ("" if none / timed out).
 *   - `timedOut` — true when spawnSync was killed by the timeout
 *                  (status === null && !error, OR signal === "SIGTERM").
 *   - `error`    — a spawn error (e.g. ENOENT for missing `head`), else null.
 */
export function promptYesNo(promptText, { timeoutMs = 30000 } = {}) {
	if (promptText) {
		process.stdout.write(promptText);
	}
	const r = spawnSync("head", ["-1"], {
		stdio: ["inherit", "pipe", "inherit"],
		encoding: "utf8",
		timeout: timeoutMs,
	});
	const error = r.error ?? null;
	// spawnSync sets status === null on timeout (and on spawn error). Disambiguate
	// via error: a timeout kill leaves r.error undefined and r.signal === "SIGTERM".
	const timedOut =
		(r.status === null && !r.error) || r.signal === "SIGTERM";
	const answer = (r.stdout || "").trim();
	return { answer, timedOut, error };
}

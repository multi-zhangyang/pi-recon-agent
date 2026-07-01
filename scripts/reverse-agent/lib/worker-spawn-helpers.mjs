/**
 * Shared helpers for spawning REPI worker subprocesses with bounded output
 * capture and guaranteed reaping.
 *
 * Used by repi-selfcheck.mjs (foundational opt #175). The same proven
 * SIGTERM→SIGKILL + rolling-tail pattern lives inline in
 * repi-swarm-llm-run.mjs; these helpers factor it out so the selfcheck can
 * be unit-tested without spawning the full REPI CLI.
 */

/**
 * Default per-stream worker output cap (1 MB), matching repi-swarm-llm-run.mjs.
 * Override via REPI_SELFCHECK_WORKER_MAX_BYTES; `0` disables the cap.
 */
export const DEFAULT_WORKER_MAX_BYTES = 1024 * 1024;

/**
 * Default SIGKILL-escalation grace window after SIGTERM (ms).
 * Override via REPI_SELFCHECK_WORKER_KILL_GRACE_MS; `0` escalates immediately.
 */
export const DEFAULT_WORKER_KILL_GRACE_MS = 2000;

/**
 * Resolve REPI_SELFCHECK_WORKER_MAX_BYTES into a positive byte cap or 0
 * (disable). Non-numeric / negative values fall back to the default.
 */
export function resolveWorkerMaxBytes(env = process.env, fallback = DEFAULT_WORKER_MAX_BYTES) {
	const raw = env.REPI_SELFCHECK_WORKER_MAX_BYTES;
	if (raw === undefined || raw === null || raw === "") return fallback;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return fallback;
	return Math.floor(n);
}

/**
 * Append `chunk` to a worker output buffer and keep only the rolling tail
 * when it exceeds `max` bytes. Returns the new buffer string.
 *
 * - `max <= 0` disables the cap (returns the unbounded concatenation), matching
 *   the REPI_SELFCHECK_WORKER_MAX_BYTES=0 opt-out.
 * - When under the cap the result is byte-identical to `buf + chunk`, so the
 *   normal-case worker output capture is unchanged.
 */
export function capWorkerBuffer(buf, chunk, max) {
	const next = buf + chunk;
	if (!(max > 0) || next.length <= max) return next;
	return next.slice(-max);
}

/**
 * Terminate a worker child with SIGTERM, then escalate to SIGKILL after
 * `graceMs` if it has not yet exited. Resolves once the child emits "close"
 * (or "error") with `{ code, signal, error }`, so the caller's Promise.all
 * cannot hang on a SIGTERM-ignoring worker.
 *
 * The grace timer is `.unref()`-ed and cleared on close, so it never keeps the
 * event loop alive nor fires after the child is gone. SIGTERM/SIGKILL errors
 * (already-dead child, zombie PID) are swallowed — the close/error listener is
 * the source of truth.
 */
export function killWorkerWithGrace(child, graceMs = DEFAULT_WORKER_KILL_GRACE_MS) {
	return new Promise((resolve) => {
		let settled = false;
		const graceTimer = setTimeout(() => {
			if (child.exitCode === null && child.signalCode === null) {
				try {
					child.kill("SIGKILL");
				} catch {
					/* already gone — close/error will settle */
				}
			}
		}, graceMs > 0 ? graceMs : 0).unref();
		const finish = (info) => {
			if (settled) return;
			settled = true;
			clearTimeout(graceTimer);
			resolve(info);
		};
		try {
			child.kill("SIGTERM");
		} catch {
			/* already gone — close/error will settle */
		}
		child.once("close", (code, signal) => finish({ code, signal, error: undefined }));
		child.once("error", (error) => finish({ code: null, signal: null, error: String(error?.message || error) }));
	});
}

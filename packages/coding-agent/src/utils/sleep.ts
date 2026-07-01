/**
 * Sleep helper that respects abort signal.
 */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
	return new Promise((resolve, reject) => {
		if (signal?.aborted) {
			reject(new Error("Aborted"));
			return;
		}

		// Named handler removed on BOTH settle paths. Without removal, every call
		// leaked one `abort` listener on signal for the signal's lifetime — on a
		// long-lived signal reused across many sleeps (e.g. a session/run signal
		// with N retries/backoffs) that's N leaked listeners → after ~10 Node
		// emits MaxListenersExceededWarning and abort dispatch degrades. (opt #119)
		const onAbort = () => {
			clearTimeout(timeout);
			signal?.removeEventListener("abort", onAbort);
			reject(new Error("Aborted"));
		};
		const timeout = setTimeout(() => {
			signal?.removeEventListener("abort", onAbort);
			resolve();
		}, ms);
		// opt #190: unref so a pending backoff timer cannot keep the event loop
		// alive after the run is aborted/finished (one-shot/print-mode exit would
		// otherwise block until the timer fires). The onAbort handler already
		// calls clearTimeout(timeout) so unref is safe on both settle paths.
		// Matches abortableSleep in agent-loop.ts.
		timeout.unref?.();
		signal?.addEventListener("abort", onAbort);
	});
}

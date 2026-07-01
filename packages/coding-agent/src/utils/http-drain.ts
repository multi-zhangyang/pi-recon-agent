/**
 * Release the underlying socket of a fetch {@link Response} whose body will not
 * be read (or has already been read for status/headers only).
 *
 * Node's `fetch` (undici) does NOT return a keep-alive connection to the pool
 * until the response body is fully consumed OR explicitly cancelled. A fast
 * 2xx/4xx response whose body is read for `status`/`headers` only — or thrown
 * away on a non-`ok` early-return / throw path — leaves the socket holding an
 * unread body until the GC finalizes the `Response`. That reclamation is
 * nondeterministic, and during the window the connection is unusable (and
 * counts against undici's per-host connection cap). `AbortSignal.timeout` only
 * releases the socket if the response never ARRIVES; a response that arrives
 * and is then ignored is NOT covered by it.
 *
 * `response.body.cancel()` signals end-of-interest so undici closes the socket
 * promptly. Safe to call on an already-consumed body (it will be `null` or the
 * cancel is a no-op) and on a locked/errored stream (swallowed).
 */
export async function drainResponseBody(response: Response): Promise<void> {
	try {
		await response.body?.cancel();
	} catch {
		// Best-effort teardown — a failure to cancel must not mask the caller's
		// real result or exception. The socket is still reclaimed by GC.
	}
}

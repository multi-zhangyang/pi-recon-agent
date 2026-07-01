/**
 * Call a provider `onResponse` hook; if it throws, cancel the response body so
 * the keep-alive socket is released before rethrowing.
 *
 * undici does NOT release a keep-alive socket until the response body is
 * consumed OR cancelled. Every streaming provider iterates the body in a
 * loop whose `finally` cancels on the normal / abort / mid-stream-throw path
 * (opt #67/#117). BUT `onResponse` runs BEFORE that iteration begins, so a
 * throwing `onResponse` (e.g. a throwing `after_provider_response` extension
 * handler) skips the iteration entirely → the body is never cancelled → the
 * socket is stranded until GC (counts against the per-host keep-alive cap; one
 * leaked socket per request if the handler throws consistently → eventual
 * socket exhaustion). Wrapping the call here cancels the body on that one
 * remaining throw path. cancel() is a no-op on an already-done/errored stream
 * and rejects on some error states — swallow. (opt #122)
 *
 * Same doctrine as opt #49 (HTTP response body drain) / opt #67 (anthropic SSE
 * body drain), applied to the pre-iteration `onResponse` throw path those opts
 * did not cover.
 */
export async function callOnResponseWithDrain(
	body: ReadableStream<Uint8Array> | null | undefined,
	call: () => unknown,
): Promise<void> {
	try {
		await call();
	} catch (error) {
		await body?.cancel().catch(() => {});
		throw error;
	}
}

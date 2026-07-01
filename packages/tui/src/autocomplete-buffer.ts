/**
 * Bounded append helper for the autocomplete fd-path child's stdout accumulation.
 *
 * The fd-path autocomplete child (packages/tui/src/autocomplete.ts) is spawned
 * asynchronously (NOT spawnSync, which has `maxBuffer`) and accumulates
 * `stdout += chunk` with no bound. fd already receives `--max-results N` to
 * bound the result count at the source, but as defense-in-depth we also cap the
 * accumulated buffer so a misbehaving fd (or a future caller that drops the
 * `--max-results` flag) cannot OOM the long-lived TUI process on a huge
 * monorepo. The user is typing interactively, so a truncated completion list is
 * acceptable. Mirrors the bounded-read doctrine (#34/#156/#163).
 *
 * `REPI_AUTOCOMPLETE_MAX_BYTES` env (default 2 MB, 0 = disable) bounds the
 * buffer; when disabled `resolveAutocompleteMaxBytes` returns `undefined` and
 * callers should use a plain unbounded append.
 */

const DEFAULT_AUTOCOMPLETE_MAX_BYTES = 2 * 1024 * 1024;

/**
 * Resolve the stdout accumulation byte cap. An explicit positive
 * `REPI_AUTOCOMPLETE_MAX_BYTES` wins; an explicit `0` disables the cap
 * (returns `undefined` → caller appends unbounded); an unset or invalid value
 * falls back to the 2 MB default.
 */
export function resolveAutocompleteMaxBytes(): number | undefined {
	const raw = process.env.REPI_AUTOCOMPLETE_MAX_BYTES;
	if (raw === undefined) return DEFAULT_AUTOCOMPLETE_MAX_BYTES;
	const n = Math.floor(Number(raw));
	if (!Number.isFinite(n) || n < 0) return DEFAULT_AUTOCOMPLETE_MAX_BYTES;
	return n > 0 ? n : undefined;
}

/**
 * Append `chunk` to `acc` without exceeding `max` bytes. Under-cap returns a
 * byte-identical concatenation; at/over-cap stops appending (returns `acc`
 * unchanged once the cap is reached). `max` must be a positive finite number.
 */
export function appendBounded(acc: string, chunk: string, max: number): string {
	const remaining = max - acc.length;
	if (remaining <= 0) return acc;
	if (chunk.length <= remaining) return acc + chunk;
	return acc + chunk.slice(0, remaining);
}

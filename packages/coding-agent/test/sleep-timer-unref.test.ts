// REPI opt #190 — coding-agent sleep() retry-backoff timer lacks .unref() →
// event-loop keepalive leak.
//
// Root cause: sleep() in utils/sleep.ts (used at agent-session.ts:3027 for
// retry/backoff) did `timeout = setTimeout(...)` with no unref. Sibling
// abortableSleep in agent-loop.ts:605-606 calls `timer.unref?.()`. A one-shot/
// print-mode run hitting a retryable error enters backoff; if aborted/finished
// while sleep pending, the process can't exit cleanly until the backoff timer
// fires (seconds to tens of seconds). Same class as opt #183 (codex sleep) /
// #182 (codex idle timer).
//
// Fix: `timeout.unref?.()` after the setTimeout (match abortableSleep). The
// onAbort handler already calls clearTimeout(timeout) so unref is safe on both
// settle paths.
//
// Test type: HONEST ROUTING PIN. The timer is internal to sleep() and NOT
// returned to the caller, so a behavioral hasRef()/keepalive assertion is
// INFEASIBLE without changing the public API (sleep returns Promise<void>,
// not the timer handle). Same constraint as opt #183. We assert by reading the
// source of sleep.ts that the sleep function body contains both `setTimeout`
// and `.unref` — the load-bearing invariant. Remove the `.unref()` → the
// routing assertion FAILS. Restore → passes.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const source = readFileSync(fileURLToPath(new URL("../src/utils/sleep.ts", import.meta.url)), "utf-8");

describe("sleep() retry-backoff timer is unref'd (opt #190 routing pin)", () => {
	it("the sleep function body calls setTimeout", () => {
		// Guards against a false PASS from a refactor that removed the timer.
		expect(source).toContain("setTimeout(");
	});

	it("the timer is unref'd so it cannot keep the event loop alive after abort/finish", () => {
		// Remove the `timeout.unref?.()` line → this assertion fails.
		expect(source).toContain("timeout.unref?.();");
	});

	it("the unref call is within the sleep function (between setTimeout and addEventListener)", () => {
		// Structural assertion: unref sits after the setTimeout and before the
		// abort listener is attached, confirming it applies to the backoff
		// timer (not some other timer). Revert/move it outside this region →
		// the slice assertion fails.
		const setTimeoutIdx = source.indexOf("const timeout = setTimeout(");
		expect(setTimeoutIdx).toBeGreaterThan(-1);
		const addListenerIdx = source.indexOf('signal?.addEventListener("abort", onAbort);', setTimeoutIdx);
		expect(addListenerIdx).toBeGreaterThan(setTimeoutIdx);
		const region = source.slice(setTimeoutIdx, addListenerIdx);
		expect(region).toContain("timeout.unref?.();");
	});
});

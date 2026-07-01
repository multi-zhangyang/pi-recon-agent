import { getEventListeners, setMaxListeners } from "node:events";
import { describe, expect, it } from "vitest";
import { sleep } from "../src/utils/sleep.ts";

// opt #119 — sleep() added an `abort` listener to signal but never removed it.
// Each call leaked one listener for the signal's lifetime. On a long-lived
// signal reused across many sleeps (a session/run signal with N retries or
// backoffs), that accumulated N leaked listeners → after ~10 Node emits
// MaxListenersExceededWarning and abort dispatch degrades. Fix: name the
// handler and removeEventListener on BOTH settle paths (timer resolve + abort).
//
// This test calls sleep() many times against ONE AbortController (all settling
// via the timer, none aborting) and asserts no listeners remain on the signal
// afterward. Pre-fix, all N listeners stay attached.

describe("sleep() removes its abort listener on settle (opt #119)", () => {
	it("leaves no abort listeners on the signal after timer-settled sleeps", async () => {
		const controller = new AbortController();
		// Suppress the MaxListenersExceededWarning that the PRE-fix path would emit
		// for 20 listeners on one signal, so the neuter run's stderr stays clean.
		setMaxListeners(50, controller.signal);

		const N = 20;
		await Promise.all(Array.from({ length: N }, () => sleep(5, controller.signal)));

		// The KEY invariant: every sleep removed its listener on settle.
		// Pre-fix: N listeners remain on the signal.
		const remaining = getEventListeners(controller.signal, "abort");
		expect(remaining).toHaveLength(0);
	});

	it("removes the listener on the abort path too", async () => {
		const controller = new AbortController();
		setMaxListeners(50, controller.signal);

		// A long sleep we abort mid-flight.
		const sleepPromise = sleep(10_000, controller.signal);
		controller.abort();
		await expect(sleepPromise).rejects.toThrow(/Aborted/);

		// The abort handler removed itself on firing.
		const remaining = getEventListeners(controller.signal, "abort");
		expect(remaining).toHaveLength(0);
	});
});

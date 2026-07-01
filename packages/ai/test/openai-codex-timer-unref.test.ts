import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
	closeOpenAICodexWebSocketSessions,
	scheduleSessionWebSocketExpiry,
} from "../src/providers/openai-codex-responses.ts";

// opt #182 + #183: two setTimeout timers in openai-codex-responses.ts lacked
// .unref(), so they kept the Node process alive past dispose when the dispose
// path was bypassed (uncaught error / process.exit skipping disposeRuntime).
// The sibling idle-read-timeout at line ~673 and agent-loop's abortableSleep
// both call timer.unref?.(); these two sites were missed.
//
// #182 — scheduleSessionWebSocketExpiry's idle TTL timer (5-min). Behavioral
//   pin: call the exported function with a fake entry and assert
//   idleTimer.hasRef() is false (.unref() makes hasRef() return false).
//   Neuter-pin: remove the .unref() line → hasRef() returns true → test FAILS.
//
// #183 — sleep()'s retry-backoff timer. The timer is internal to sleep() and
//   not returned, so a behavioral hasRef() pin is infeasible without an API
//   change. HONEST ROUTING PIN: assert the .unref() call is present in the
//   sleep function body by reading the source. Neuter-pin: remove the .unref()
//   line → the routing assertion FAILS.

const SRC_PATH = fileURLToPath(new URL("../src/providers/openai-codex-responses.ts", import.meta.url));
const SRC = readFileSync(SRC_PATH, "utf8");

function makeFakeSocket() {
	return {
		close() {},
		send() {},
		addEventListener() {},
		removeEventListener() {},
	};
}

describe("openai-codex-responses timer .unref() (opt #182 + #183)", () => {
	afterEach(() => {
		closeOpenAICodexWebSocketSessions();
	});

	it("#182 scheduleSessionWebSocketExpiry unrefs the idle TTL timer — behavioral pin via hasRef()", () => {
		const entry: { socket: unknown; busy: boolean; idleTimer?: { hasRef(): boolean } } = {
			socket: makeFakeSocket(),
			busy: false,
		};
		scheduleSessionWebSocketExpiry("opt182-sid", entry as never);
		expect(entry.idleTimer).toBeDefined();
		// .unref() makes hasRef() return false — the timer does not hold the event loop.
		expect(entry.idleTimer?.hasRef()).toBe(false);
		if (entry.idleTimer) {
			// Don't let the 5-min TTL timer fire during the rest of the suite.
			// Clearing requires the raw handle; cast to the Node Timeout shape.
			(entry.idleTimer as unknown as { ref(): unknown; unref(): unknown }).unref();
		}
	});

	it("#183 sleep() retry-backoff timer calls .unref() — routing pin (behavioral infeasible: timer is internal, not returned)", () => {
		// The sleep() timer is a local `const timeout` that is never returned,
		// so there is no handle to assert hasRef() on without changing the API.
		// This routing pin asserts the .unref() call is present at the sleep
		// site. Neuter-pin: remove the `timeout.unref?.();` line after the
		// setTimeout in sleep() → this assertion FAILS.
		const sleepIdx = SRC.indexOf("function sleep(");
		expect(sleepIdx).toBeGreaterThanOrEqual(0);
		// Slice a generous window covering the whole sleep function body
		// (the setTimeout sits ~14 lines below the function signature, after
		// the opt #119 abort-listener comment block).
		const sleepBody = SRC.slice(sleepIdx, sleepIdx + 1200);
		expect(sleepBody).toContain("setTimeout");
		expect(sleepBody).toContain("timeout.unref");
	});
});

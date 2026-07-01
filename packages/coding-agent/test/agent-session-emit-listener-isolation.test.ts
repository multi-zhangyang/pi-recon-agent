import { afterEach, describe, expect, it, vi } from "vitest";
import { createTestSession } from "./utilities.ts";

// opt #133: AgentSession._emit dispatched to UI event listeners with no
// per-listener try/catch (`for (const l of this._eventListeners) { l(event); }`).
// A throwing listener (a) aborted the dispatch so all later listeners were
// skipped and (b) the throw escaped synchronously — from a sync UI keybinding
// context (e.g. cycleThinkingLevel → _emit) that is uncaughtException (no
// global handler) → process crash. The fix wraps each listener call in
// try/catch (log + continue), mirroring event-bus.ts safeHandler / runner.ts
// emit. This test drives _emit via the public sync clearQueue() →
// _emitQueueUpdate path with a first listener that throws and a second that
// records, and asserts isolation + no crash.

describe("AgentSession _emit per-listener isolation (opt #133)", () => {
	const cleanups: Array<() => void> = [];

	afterEach(() => {
		while (cleanups.length > 0) {
			cleanups.pop()?.();
		}
	});

	it("a throwing listener does not abort dispatch or crash; later listeners still run", () => {
		const { session, cleanup } = createTestSession({ inMemory: true });
		cleanups.push(cleanup);

		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const received: string[] = [];

		session.subscribe((event) => {
			if (event.type === "queue_update") {
				throw new Error("boom from listener 1");
			}
		});
		session.subscribe((event) => {
			if (event.type === "queue_update") {
				received.push("listener2");
			}
		});

		// Pre-fix: clearQueue() throws synchronously (listener 1's throw escapes).
		// Post-fix: the throw is isolated; clearQueue() returns normally.
		expect(() => session.clearQueue()).not.toThrow();

		// The later listener still received the event despite the earlier throw.
		expect(received).toEqual(["listener2"]);

		// The listener error was logged, not silently swallowed.
		expect(errorSpy).toHaveBeenCalled();
		const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(" ");
		expect(logged).toMatch(/AgentSession event listener error/);
	});

	it("an ASYNC listener that rejects after an await does not leak an unhandledRejection (opt #136)", async () => {
		const { session, cleanup } = createTestSession({ inMemory: true });
		cleanups.push(cleanup);

		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const received: string[] = [];
		const unhandled: unknown[] = [];
		const onUnhandled = (reason: unknown) => unhandled.push(reason);
		process.on("unhandledRejection", onUnhandled);

		try {
			// listener1 is async and throws AFTER an await — the sync try/catch in
			// _emit cannot catch this (it only catches pre-await throws); only a
			// .catch on the returned thenable contains it. subscribeToAgent in
			// interactive-mode registers exactly this async shape.
			session.subscribe(async (event) => {
				if (event.type === "queue_update") {
					await Promise.resolve();
					throw new Error("async boom from listener 1");
				}
			});
			session.subscribe((event) => {
				if (event.type === "queue_update") {
					received.push("listener2");
				}
			});

			// Pre-fix (sync-only try/catch): the async rejection leaks →
			// unhandledRejection fires (no global handler → process crash).
			// Post-fix: the .catch on the returned promise contains it.
			expect(() => session.clearQueue()).not.toThrow();

			// Drain pending microtasks so a leaked rejection would have surfaced.
			await new Promise<void>((resolve) => queueMicrotask(resolve));
			await new Promise<void>((resolve) => setImmediate(resolve));

			expect(unhandled).toEqual([]);
			expect(received).toEqual(["listener2"]);
			expect(errorSpy).toHaveBeenCalled();
			const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(" ");
			expect(logged).toMatch(/AgentSession event listener error/);
		} finally {
			process.off("unhandledRejection", onUnhandled);
		}
	});
});

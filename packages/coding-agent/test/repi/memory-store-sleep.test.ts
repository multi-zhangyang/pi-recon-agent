import { afterEach, beforeEach, describe, expect, it } from "vitest";

// opt #82 — robust synchronous sleep. memoryStoreSleep used Atomics.wait on a fresh
// SharedArrayBuffer (a zero-CPU synchronous sleep), but SharedArrayBuffer can be unavailable
// in sandboxed/restricted runtimes (some containers/VMs disable it) and Atomics.wait can
// throw on a non-allowed agent. The lock-contention retry in withMemoryStoreLock that calls
// memoryStoreSleep is NOT otherwise try/catch-guarded, so a throw under contention would
// crash the deposit. #82 wraps the Atomics path in try/catch with a bounded busy-wait
// fallback (memoryStoreBusyWaitSleep) so lock contention never crashes the store.
//
// These tests prove (1) memoryStoreSleep is non-throwing and blocks for ~ms on the normal
// (Atomics) path, and (2) the busy-wait fallback is non-throwing and blocks for ~ms — the
// load-bearing robustness proof: even with the Atomics path unavailable, the sleep still
// works synchronously instead of throwing.

const { memoryStoreSleep, memoryStoreBusyWaitSleep } = await import("../../src/core/repi/memory-store.ts");

describe("repi/memory-store robust synchronous sleep (opt #82)", () => {
	beforeEach(() => {
		// No fs/env state — these are pure time functions.
	});

	afterEach(() => {
		// noop
	});

	it("memoryStoreSleep is non-throwing and blocks for ~ms (Atomics path)", () => {
		const ms = 45;
		const start = Date.now();
		expect(() => memoryStoreSleep(ms)).not.toThrow();
		const elapsed = Date.now() - start;
		// Synchronous sleep must block for at least ~ms (allow scheduler slack on the lower
		// bound) and complete promptly (upper bound catches an accidental infinite spin).
		expect(elapsed).toBeGreaterThanOrEqual(35);
		expect(elapsed).toBeLessThan(1500);
	});

	it("memoryStoreBusyWaitSleep (the fallback) is non-throwing and blocks for ~ms", () => {
		const ms = 45;
		const start = Date.now();
		expect(() => memoryStoreBusyWaitSleep(ms)).not.toThrow();
		const elapsed = Date.now() - start;
		expect(elapsed).toBeGreaterThanOrEqual(35);
		expect(elapsed).toBeLessThan(1500);
	});

	it("memoryStoreSleep with ms=0 returns promptly without throwing", () => {
		const start = Date.now();
		expect(() => memoryStoreSleep(0)).not.toThrow();
		expect(Date.now() - start).toBeLessThan(500);
	});

	it("memoryStoreSleep does not crash when SharedArrayBuffer is unavailable (fallback engages)", () => {
		// Simulate a sandboxed runtime that has disabled SharedArrayBuffer: the Atomics path
		// (`new SharedArrayBuffer(4)`) throws → the catch must engage the busy-wait fallback
		// instead of propagating the throw out of the lock-contention retry.
		const g = globalThis as { SharedArrayBuffer?: typeof SharedArrayBuffer };
		const orig = g.SharedArrayBuffer;
		g.SharedArrayBuffer = undefined;
		try {
			const start = Date.now();
			expect(() => memoryStoreSleep(30)).not.toThrow();
			const elapsed = Date.now() - start;
			expect(elapsed).toBeGreaterThanOrEqual(20);
			expect(elapsed).toBeLessThan(1500);
		} finally {
			g.SharedArrayBuffer = orig;
		}
	});
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { InteractiveMode } from "../src/modes/interactive/interactive-mode.ts";

// opt #136: shutdown() awaited this.runtimeHost.dispose() with no try/catch,
// and every caller invokes it fire-and-forget via `void this.shutdown()`. A
// throwing extension session_shutdown teardown would reject here →
// unhandledRejection (there is NO global handler in this repo) → process crash
// BEFORE this.stop() restores the terminal, leaving it in raw mode with no
// cursor. The fix wraps each runtimeHost.dispose() await in try/catch
// (log + proceed to terminal restore + exit). This test drives the non-signal
// shutdown path with a throwing dispose and asserts it is contained and the
// normal exit path still runs.

const EXIT = Symbol("process.exit");

type ShutdownCtx = {
	isShuttingDown: boolean;
	unregisterSignalHandlers: () => void;
	ui: { terminal: { drainInput: (ms: number) => Promise<void> } };
	stop: () => void;
	runtimeHost: { dispose: () => Promise<void> };
	sessionManager: { isPersisted: () => boolean };
};

describe("InteractiveMode.shutdown dispose-throw safety (opt #136)", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("contains a throwing runtimeHost.dispose() and still restores the terminal + exits", async () => {
		// Short-circuit process.exit(0) with a sentinel throw so the normal exit
		// path is observable without actually terminating the test process.
		const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
			throw EXIT;
		}) as (code?: string | number | null | undefined) => never) as ReturnType<typeof vi.spyOn>;
		void exitSpy;
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const stop = vi.fn();
		const drainInput = vi.fn(async () => {});
		const unregisterSignalHandlers = vi.fn();

		const ctx: ShutdownCtx = {
			isShuttingDown: false,
			unregisterSignalHandlers,
			ui: { terminal: { drainInput } },
			stop,
			runtimeHost: {
				dispose: vi.fn(async () => {
					throw new Error("dispose boom from extension teardown");
				}),
			},
			sessionManager: { isPersisted: () => false },
		};

		let thrown: unknown;
		try {
			await (
				InteractiveMode.prototype as unknown as {
					shutdown: (this: ShutdownCtx, options?: { fromSignal?: boolean }) => Promise<void>;
				}
			).shutdown.call(ctx);
		} catch (e) {
			thrown = e;
		}

		// Reached process.exit(0) — shutdown proceeded PAST the throwing dispose
		// to the normal exit. Pre-fix the await rejects with the dispose error and
		// never reaches process.exit, so `thrown` would be the Error, not EXIT.
		expect(thrown).toBe(EXIT);

		// Terminal restore ran (this.stop()) before exit.
		expect(stop).toHaveBeenCalled();

		// The dispose error was logged, not silently swallowed.
		expect(errorSpy).toHaveBeenCalled();
		const logged = errorSpy.mock.calls.map((c) => String(c[0])).join(" ");
		expect(logged).toMatch(/Extension dispose error during shutdown/);

		// dispose was actually invoked.
		expect(ctx.runtimeHost.dispose).toHaveBeenCalled();
	});
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { InteractiveMode } from "../src/modes/interactive/interactive-mode.ts";

// Foundational opt #268: registerSignalHandlers mirrored the uncaughtException
// handler but had NO unhandledRejection handler, and cli.ts called main(cliArgs)
// with no .catch(). An awaited rejection during interactive init (e.g. an
// extension session_start handler rejecting) is NOT a sync throw — it propagates
// as a rejected promise up run()→main() → unhandledRejection. With no global
// unhandledRejection handler anywhere in the repo, Node's default fires exit(1)
// WITHOUT calling uncaughtCrash → the terminal is left in raw mode with no cursor
// (ui.stop never runs), requiring `stty sane && reset` to recover. The fix
// prepends an unhandledRejection handler that routes to uncaughtCrash (same
// recovery as uncaughtException: ui.stop + terminal restore + exit). This test
// drives registerSignalHandlers with a fake ctx and emits a process-level
// unhandledRejection, asserting it reaches uncaughtCrash (ui.stop + exit) rather
// than being left to Node's default.

const EXIT = Symbol("process.exit");

type Ctx = {
	isShuttingDown: boolean;
	signalCleanupHandlers: Array<() => void>;
	unregisterSignalHandlers: () => void;
	uncaughtCrash: (error: Error) => never;
	ui: { stop: () => void };
};

describe("InteractiveMode.registerSignalHandlers routes unhandledRejection to uncaughtCrash (opt #268)", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("restores the terminal + exits on a process unhandledRejection", () => {
		const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
			throw EXIT;
		}) as (code?: string | number | null | undefined) => never) as ReturnType<typeof vi.spyOn>;
		void exitSpy;
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const stop = vi.fn();

		const proto = InteractiveMode.prototype as unknown as {
			registerSignalHandlers: (this: Ctx) => void;
			unregisterSignalHandlers: (this: Ctx) => void;
			uncaughtCrash: (this: Ctx, error: Error) => never;
		};

		// Snapshot existing listeners so the test is isolated from other handlers.
		const priorRejectionListeners = process.listeners("unhandledRejection");
		const priorExceptionListeners = process.listeners("uncaughtException");

		const ctx: Ctx = {
			isShuttingDown: false,
			signalCleanupHandlers: [],
			unregisterSignalHandlers: vi.fn(),
			// Bind the REAL uncaughtCrash so the test exercises the actual recovery
			// (ui.stop + unregister + exit), not a stub. registerSignalHandlers' arrow
			// looks up `this.uncaughtCrash` on ctx and calls it with this=ctx.
			uncaughtCrash: (error: Error) => proto.uncaughtCrash.call(ctx, error),
			ui: { stop },
		};

		let thrown: unknown;
		try {
			// Register the handlers (prepends unhandledRejection → uncaughtCrash).
			proto.registerSignalHandlers.call(ctx);

			// A handler IS now registered for unhandledRejection (opt #268).
			expect(process.listeners("unhandledRejection").length).toBeGreaterThan(priorRejectionListeners.length);

			// Emit a rejection as a non-Error reason (exercises the Error-coercion
			// branch: reason instanceof Error ? reason : new Error(String(reason))).
			// Cast to the base EventEmitter so `emit` resolves to the string-event
			// overload (process.emit's Signals overloads shadow "unhandledRejection").
			(process as unknown as NodeJS.EventEmitter).emit("unhandledRejection", "rejection boom from extension init");
		} catch (e) {
			thrown = e;
		} finally {
			// Remove the handlers we registered so they don't leak into other tests.
			try {
				proto.unregisterSignalHandlers.call(ctx);
			} catch {}
			// Restore listener arrays exactly (defensive: unregister should suffice).
			// Cast to the base EventEmitter so `off` resolves to the string-event
			// overload (process.off's Signals overloads shadow "unhandledRejection").
			const emitter = process as unknown as NodeJS.EventEmitter;
			for (const l of process.listeners("unhandledRejection")) {
				if (!priorRejectionListeners.includes(l)) emitter.off("unhandledRejection", l);
			}
			for (const l of process.listeners("uncaughtException")) {
				if (!priorExceptionListeners.includes(l)) emitter.off("uncaughtException", l);
			}
		}

		// uncaughtCrash ran process.exit(1) (sentinel) — pre-fix there was no
		// unhandledRejection handler, so process.emit would invoke NO listener and
		// `thrown` would stay undefined (Node's default exit never fires from a
		// synchronous process.emit in-process).
		expect(thrown).toBe(EXIT);

		// Terminal restore ran (ui.stop()) before exit — the core of the fix.
		expect(stop).toHaveBeenCalled();

		// The coerced reason was surfaced via console.error (uncaughtCrash logs it).
		expect(errorSpy).toHaveBeenCalled();
		const logged = errorSpy.mock.calls.map((c) => String(c)).join(" ");
		expect(logged).toMatch(/rejection boom from extension init/);
	});
});

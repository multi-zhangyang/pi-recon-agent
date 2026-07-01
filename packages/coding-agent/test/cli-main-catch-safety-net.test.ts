import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Foundational opt #268: cli.ts called main(cliArgs) with NO .catch(). main() is
// async; an awaited rejection inside it (extension session_start rejecting during
// interactive init, or a model-registry/session-manager load failure in headless
// modes) became an unhandledRejection. There is no global unhandledRejection
// handler, so Node's default exit(1) ran WITHOUT restoring stdout (headless
// takeover) — and in interactive mode the catch runs BEFORE interactive-mode's
// own unhandledRejection handler could restore the terminal. The fix wraps
// main(cliArgs) in .catch → restoreStdout() + surface the error to stderr +
// exit(1). This test mocks main to reject and asserts the safety net runs.

describe("cli.ts main().catch() safety net (opt #268)", () => {
	const restoreStdout = vi.hoisted(() => vi.fn());
	const mainFn = vi.hoisted(() => vi.fn());

	beforeEach(() => {
		restoreStdout.mockClear();
		mainFn.mockReset();
		// main() rejects — simulates an awaited rejection escaping main().
		mainFn.mockImplementation(() => Promise.reject(new Error("init boom from main")));
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.resetModules();
	});

	it("restores stdout + surfaces the error + exits when main() rejects", async () => {
		vi.mock("../src/main.ts", () => ({ main: mainFn }));
		vi.mock("../src/core/output-guard.ts", () => ({ restoreStdout }));
		vi.mock("../src/core/http-dispatcher.ts", () => ({ configureHttpDispatcher: () => {} }));
		vi.mock("../src/config.ts", () => ({ APP_NAME: "repi", IS_REPI_PRODUCT: false }));
		vi.mock("../src/cli/repi-bootstrap.ts", () => ({ bootstrapRepiCli: () => [] }));
		vi.mock("../src/cli/repi-product-commands.ts", () => ({ dispatchRepiProductCommand: () => {} }));

		const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
			// Don't actually exit; record the call. The catch's exit(1) is the
			// observable signal that the safety net ran.
		}) as (code?: string | number | null | undefined) => never) as ReturnType<typeof vi.spyOn>;
		void exitSpy;
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		// Importing cli.ts runs its top-level main(cliArgs).catch(...) — the catch
		// fires on the next microtask after main's rejection settles.
		await import("../src/cli.ts");
		// Drain the microtask queue so the .catch callback has run.
		await new Promise<void>((resolve) => queueMicrotask(() => resolve()));
		await new Promise<void>((resolve) => queueMicrotask(() => resolve()));

		// main was actually invoked (the entry point called it).
		expect(mainFn).toHaveBeenCalled();

		// The safety net restored stdout (headless takeover) before exiting.
		expect(restoreStdout).toHaveBeenCalled();

		// The error was surfaced to stderr (not silently swallowed).
		expect(errorSpy).toHaveBeenCalled();
		const logged = errorSpy.mock.calls.map((c) => String(c)).join(" ");
		expect(logged).toMatch(/exiting due to unhandled error/);
		expect(logged).toMatch(/init boom from main/);

		// process.exit(1) ran — the safety net's terminal exit.
		expect(exitSpy).toHaveBeenCalledWith(1);
	});
});

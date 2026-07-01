import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scheduleTimeoutWarning } from "../src/modes/print-mode.ts";

describe("scheduleTimeoutWarning", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("injects the warning exactly once when the timer fires and the run is not finished", () => {
		const inject = vi.fn();
		const cancel = scheduleTimeoutWarning({ warnAtMs: 1000, isFinished: () => false, inject });

		// Before the timer fires: no injection.
		vi.advanceTimersByTime(999);
		expect(inject).not.toHaveBeenCalled();

		vi.advanceTimersByTime(1);
		expect(inject).toHaveBeenCalledTimes(1);

		// Firing again later does NOT re-inject (one-shot).
		vi.advanceTimersByTime(5000);
		expect(inject).toHaveBeenCalledTimes(1);

		cancel();
	});

	it("does NOT inject if the run finished before the warn time", () => {
		const inject = vi.fn();
		let finished = false;
		const cancel = scheduleTimeoutWarning({ warnAtMs: 1000, isFinished: () => finished, inject });

		// Run completes cleanly 200ms before the warning would fire.
		vi.advanceTimersByTime(800);
		finished = true;
		vi.advanceTimersByTime(500);
		expect(inject).not.toHaveBeenCalled();

		cancel();
	});

	it("cancel prevents the injection entirely", () => {
		const inject = vi.fn();
		const cancel = scheduleTimeoutWarning({ warnAtMs: 1000, isFinished: () => false, inject });

		cancel();
		vi.advanceTimersByTime(10000);
		expect(inject).not.toHaveBeenCalled();
	});

	it("is a no-op when warnAtMs is non-positive (warning disabled)", () => {
		const inject = vi.fn();
		const cancel = scheduleTimeoutWarning({ warnAtMs: 0, isFinished: () => false, inject });
		vi.advanceTimersByTime(10000);
		expect(inject).not.toHaveBeenCalled();
		cancel();
	});
});

// Honest routing pin: the integration wiring in runPromptWithTimeout must
// actually schedule the warning and call session.steer with a checkpoint
// message. A behavioral end-to-end pin is infeasible here (print-mode builds
// its session internally via runtimeHost), so we assert the wiring is present
// in the source. Neuter-pin: remove the scheduleTimeoutWarning call or the
// session.steer(warning) line → these assertions fail.
describe("print-mode timeout-warning wiring (routing pin)", () => {
	it("runPromptWithTimeout wires scheduleTimeoutWarning + session.steer", async () => {
		const { readFileSync } = await import("node:fs");
		const { resolve } = await import("node:path");
		const src = readFileSync(resolve(import.meta.dirname, "../src/modes/print-mode.ts"), "utf8");
		expect(src).toContain("REPI_PRINT_TIMEOUT_WARN_LEAD_MS");
		expect(src).toContain("scheduleTimeoutWarning({");
		expect(src).toContain("session\n\t\t\t\t\t\t\t\t.steer(warning)");
		expect(src).toContain("cancelWarn?.()");
	});
});

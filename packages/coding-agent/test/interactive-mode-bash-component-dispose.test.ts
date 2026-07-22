import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { initTheme } from "../src/core/presentation/theme-runtime.ts";
import { BashExecutionComponent } from "../src/modes/interactive/components/bash-execution.ts";
import { InteractiveMode } from "../src/modes/interactive/interactive-mode.ts";

// opt #137: on session switch (renderCurrentSessionState) and compaction rebuild
// (renderSessionContext) the chatContainer is cleared but clear() does NOT
// dispose children. A bash command still "running" kept its Loader's 80ms
// animation setInterval firing requestRender() on a detached component (same
// leak class as opt #47). AND pendingBashComponents was never reset, so a later
// flushPendingBashComponents() in the new session would addChild() the PREVIOUS
// session's bash components → stale output rendered. Fix: BashExecutionComponent
// gains a dispose() (loader.stop + super.dispose) and interactive-mode gains
// clearPendingBashComponents() (dispose each + reset both refs), wired into both
// detach sites. This test drives clearPendingBashComponents with two real
// running bash components and asserts the loader intervals are cleared and the
// state is reset.

type FakeUi = { requestRender: (force?: boolean) => void };

type ClearBashCtx = {
	bashComponent: BashExecutionComponent | undefined;
	pendingBashComponents: BashExecutionComponent[];
};

describe("InteractiveMode.clearPendingBashComponents (opt #137)", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("disposes in-flight bash components (stops loader interval) and resets state", () => {
		const ui: FakeUi = { requestRender: () => {} };

		// Each BashExecutionComponent constructor starts a Loader whose 80ms
		// setInterval is now active (running status).
		const inFlight = new BashExecutionComponent("sleep 30", ui as unknown as never, false);
		const deferred = new BashExecutionComponent("echo hi", ui as unknown as never, false);

		// Spy on clearInterval AFTER construction so we only observe dispose-time
		// clears (not the constructor's own setInterval/clearInterval churn).
		const clearIntervalSpy = vi.spyOn(globalThis, "clearInterval");

		const ctx: ClearBashCtx = {
			bashComponent: inFlight,
			pendingBashComponents: [deferred],
		};

		(
			InteractiveMode.prototype as unknown as {
				clearPendingBashComponents: (this: ClearBashCtx) => void;
			}
		).clearPendingBashComponents.call(ctx);

		// Each component's Loader interval was cleared on dispose (leak fixed).
		// Two running components → at least two clearInterval calls.
		expect(clearIntervalSpy).toHaveBeenCalled();
		expect(clearIntervalSpy.mock.calls.length).toBeGreaterThanOrEqual(2);

		// State reset (stale-render fixed): no dangling references for a later
		// flushPendingBashComponents() to addChild into a new session.
		expect(ctx.bashComponent).toBeUndefined();
		expect(ctx.pendingBashComponents).toEqual([]);
	});
});

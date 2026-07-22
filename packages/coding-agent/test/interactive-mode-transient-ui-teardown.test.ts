import type { TUI } from "@pi-recon/repi-tui";
import { Loader } from "@pi-recon/repi-tui";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { initTheme } from "../src/core/presentation/theme-runtime.ts";
import { CountdownTimer } from "../src/modes/interactive/components/countdown-timer.ts";
import { InteractiveMode } from "../src/modes/interactive/interactive-mode.ts";

// opt #143: compaction_start / auto_retry_start swap defaultEditor.onEscape to a
// transient abort fn (abortCompaction / abortRetry) and create a Loader (80ms
// interval) + CountdownTimer (1s interval) that are NOT unref'd. The matching
// compaction_end / auto_retry_end events restore onEscape + stop the timers —
// but a session switch (newSession/fork/navigateTree/resume/clear) rebinds the
// event stream to the new session, so the old session's *_end never reaches
// this UI. Result: (1) the Loader/CountdownTimer intervals keep firing
// invalidate()+requestRender() on a detached status container for the whole new
// session (leak + spurious renders); (2) defaultEditor.onEscape stays bound to
// the transient `() => this.session.abortCompaction()` — and since this.session
// is a getter returning the CURRENT session, Escape in the new session calls
// abort on a session that isn't compacting (no-op/error) while the real
// interrupt handler is lost. teardownTransientUiState() mirrors the *_end
// cleanup (restore saved handler, dispose/stop + null timers, clear status) and
// is wired into renderCurrentSessionState so every switch path gets it. This
// test drives teardownTransientUiState with a real Loader + CountdownTimer + a
// swapped onEscape and asserts the intervals are cleared, onEscape is restored
// to the saved (normal) handler, and the transient state is nulled. Pre-fix
// (neuter the helper body to a no-op) the intervals stay live, onEscape stays
// the transient abort fn, and the assertions fail.

type FakeEditor = { onEscape?: () => void };
type FakeStatusContainer = { clear: () => void };

type TeardownCtx = {
	defaultEditor: FakeEditor;
	autoCompactionLoader: Loader | undefined;
	autoCompactionEscapeHandler?: () => void;
	retryLoader: Loader | undefined;
	retryCountdown: CountdownTimer | undefined;
	retryEscapeHandler?: () => void;
	statusContainer: FakeStatusContainer;
};

describe("InteractiveMode.teardownTransientUiState (opt #143)", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	function makeCtx(): TeardownCtx {
		const fakeTui = { requestRender: () => {} } as unknown as TUI;
		// The normal interrupt handler that setupKeyHandlers installed (uses the
		// this.session getter — opaque here, just needs identity for restore check).
		const normalEscape = () => {};
		const editor: FakeEditor = { onEscape: normalEscape };

		// Simulate compaction_start: save normal handler, swap to transient abort.
		const compactionCtx: TeardownCtx = {
			defaultEditor: editor,
			autoCompactionLoader: undefined,
			autoCompactionEscapeHandler: normalEscape,
			retryLoader: undefined,
			retryCountdown: undefined,
			retryEscapeHandler: undefined,
			statusContainer: { clear: () => {} },
		};
		// Swap onEscape to the transient compaction-abort fn (as compaction_start does).
		editor.onEscape = () => {};
		// Create the real Loader (starts an 80ms setInterval on construction).
		compactionCtx.autoCompactionLoader = new Loader(
			fakeTui,
			(s) => s,
			(s) => s,
			"Auto-compacting... (esc to cancel)",
		);

		// Now simulate auto_retry_start layered on top: save the CURRENT onEscape
		// (the compaction-abort fn), swap to retry-abort, create retryLoader +
		// retryCountdown. (In practice compaction/retry don't overlap, but layering
		// both exercises the dual-restore ordering: retry restored first, then
		// compaction's saved NORMAL handler wins last.)
		compactionCtx.retryEscapeHandler = editor.onEscape;
		editor.onEscape = () => {};
		compactionCtx.retryLoader = new Loader(
			fakeTui,
			(s) => s,
			(s) => s,
			"Retrying...",
		);
		compactionCtx.retryCountdown = new CountdownTimer(
			5000,
			fakeTui,
			() => {},
			() => {},
		);

		return compactionCtx;
	}

	it("stops the loader/countdown intervals, restores the normal onEscape, nulls transient state", () => {
		const ctx = makeCtx();
		const normalHandler = ctx.autoCompactionEscapeHandler!;
		const statusClearSpy = vi.spyOn(ctx.statusContainer, "clear");
		// Spy AFTER construction so we only observe teardown-time clears.
		const clearIntervalSpy = vi.spyOn(globalThis, "clearInterval");

		(
			InteractiveMode.prototype as unknown as {
				teardownTransientUiState: (this: TeardownCtx) => void;
			}
		).teardownTransientUiState.call(ctx);

		// Both the retry CountdownTimer (1s) and the two Loaders (80ms) had their
		// intervals cleared → clearInterval called for each. At minimum the
		// countdown + the two loaders.
		expect(clearIntervalSpy).toHaveBeenCalled();
		expect(clearIntervalSpy.mock.calls.length).toBeGreaterThanOrEqual(3);

		// onEscape restored to the NORMAL handler (compaction's saved handler wins
		// last), NOT left as the transient retry/compaction abort fn. This is the
		// core fix: Escape in the new session hits the real interrupt handler.
		expect(ctx.defaultEditor.onEscape).toBe(normalHandler);

		// Transient state nulled so a later teardown is a no-op + no stale refs.
		expect(ctx.autoCompactionLoader).toBeUndefined();
		expect(ctx.autoCompactionEscapeHandler).toBeUndefined();
		expect(ctx.retryLoader).toBeUndefined();
		expect(ctx.retryCountdown).toBeUndefined();
		expect(ctx.retryEscapeHandler).toBeUndefined();

		// Status container cleared (transient loader removed from the new view).
		expect(statusClearSpy).toHaveBeenCalled();
	});

	it("is a no-op when no transient state is active (safe on every switch)", () => {
		const editor: FakeEditor = { onEscape: () => {} };
		const normalEscape = editor.onEscape;
		const ctx: TeardownCtx = {
			defaultEditor: editor,
			autoCompactionLoader: undefined,
			autoCompactionEscapeHandler: undefined,
			retryLoader: undefined,
			retryCountdown: undefined,
			retryEscapeHandler: undefined,
			statusContainer: { clear: () => {} },
		};
		const clearIntervalSpy = vi.spyOn(globalThis, "clearInterval");

		(
			InteractiveMode.prototype as unknown as {
				teardownTransientUiState: (this: TeardownCtx) => void;
			}
		).teardownTransientUiState.call(ctx);

		// No timers to clear, no handler to restore — onEscape untouched.
		expect(clearIntervalSpy).not.toHaveBeenCalled();
		expect(ctx.defaultEditor.onEscape).toBe(normalEscape);
	});
});

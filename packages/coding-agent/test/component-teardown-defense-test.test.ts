import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BorderedLoader } from "../src/modes/interactive/components/bordered-loader.ts";
import { UserMessageSelectorComponent } from "../src/modes/interactive/components/user-message-selector.ts";

// opt #151 defense-in-depth siblings (opt #152): the round-2 teardown audit
// flagged three more component-teardown gaps the opt #143/#151 fixes missed.
// These are pattern-proven fixes (same doctrine as opt #47/#151) but each is
// pinned by its OWN test where the gap is deterministically observable:
//
// 1. BorderedLoader.dispose() tore down the inner loader but never aborted the
//    non-cancellable branch's own AbortController (signalController) → a
//    consumer awaiting `.signal` hung after the loader was dismissed. Fix:
//    `this.signalController?.abort()` in dispose.
// 2. UserMessageSelectorComponent / TreeSelectorComponent scheduled an
//    untracked `setTimeout(() => onCancel(), 100)` for the empty-list
//    auto-cancel path → if the picker was dismissed (showSelector's done() now
//    calls dispose) inside that 100ms window, onCancel fired on a detached
//    component. Fix: track the timer + clearTimeout in dispose (added dispose
//    override calling super.dispose() so child propagation is preserved).
//
// armin/daxnuts `setInterval(...).unref()` additions (defense-in-depth: a
// missed dispose can't keep the event loop alive) are NOT per-site tested —
// `.unref()` is a no-op semantically and the pattern is already proven by opt
// #47's bash interval. The two tests below cover the two observable gaps.

describe("BorderedLoader.dispose aborts the non-cancellable signal (opt #152)", () => {
	it("dispose() aborts signalController so an awaiter resolves instead of hanging", () => {
		type Ctx = {
			signalController?: AbortController;
			loader: { dispose: () => void } | { stop: () => void };
			cancellable: boolean;
		};
		const dispose = (BorderedLoader.prototype as unknown as { dispose: (this: Ctx) => void }).dispose;

		const controller = new AbortController();
		const ctx: Ctx = {
			signalController: controller,
			loader: { dispose: () => {} },
			cancellable: false,
		};

		expect(controller.signal.aborted).toBe(false);
		dispose.call(ctx);
		// With the fix, dispose aborts the controller. Without it, the signal
		// stays pending forever → an awaiter hangs after teardown.
		expect(controller.signal.aborted).toBe(true);
	});

	it("cancellable branch (no signalController) is unaffected", () => {
		type Ctx = {
			signalController?: AbortController;
			loader: { dispose: () => void };
			cancellable: boolean;
		};
		const dispose = (BorderedLoader.prototype as unknown as { dispose: (this: Ctx) => void }).dispose;

		const disposed: string[] = [];
		const ctx: Ctx = {
			signalController: undefined,
			loader: { dispose: () => disposed.push("loader") },
			cancellable: true,
		};

		dispose.call(ctx);
		expect(disposed).toEqual(["loader"]);
	});
});

describe("UserMessageSelectorComponent.dispose clears the empty-list auto-cancel timer (opt #152)", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("dispose() cancels a pending empty-list timer (no onCancel after detach)", () => {
		type Ctx = {
			emptyListTimer: ReturnType<typeof setTimeout> | null;
			children: unknown[];
		};
		const dispose = (UserMessageSelectorComponent.prototype as unknown as { dispose: (this: Ctx) => void }).dispose;

		let onCancelFired = false;
		// Schedule a 1000ms timer (mirrors the empty-list auto-cancel setTimeout).
		const ctx: Ctx = {
			emptyListTimer: setTimeout(() => {
				onCancelFired = true;
			}, 1000),
			children: [],
		};

		// Dismiss before the 1000ms timer fires (mirrors showSelector's done()).
		dispose.call(ctx);
		expect(onCancelFired).toBe(false);

		vi.advanceTimersByTime(2000);
		// With the fix, dispose cleared the timer → onCancel never fires on the
		// detached component. Without it, the timer fires at 1000ms → onCancel
		// fires after detach → this assertion fails.
		expect(onCancelFired).toBe(false);
	});
});

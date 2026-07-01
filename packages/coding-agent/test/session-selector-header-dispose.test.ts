import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SessionSelectorComponent } from "../src/modes/interactive/components/session-selector.ts";

// opt #151: SessionSelectorHeader schedules an auto-hide status timer
// (statusTimeout, 2-4s) that fires requestRender. It's a child of
// SessionSelectorComponent (a Container), and showSelector's done() discarded
// the selector via Container.clear() — a re-arrange primitive that does NOT
// dispose children. Container.dispose() propagates child.dispose?.(), but the
// header had NO dispose() → propagation short-circuited on
// `dispose?.() === undefined` → statusTimeout kept firing requestRender on a
// detached header 2-4s after the picker closed. Fix: header.dispose() calls
// clearStatusTimeout(), and showSelector's done() calls component.dispose?.()
// before clear(). This test pins the component→header propagation (the
// end-to-end path showSelector now relies on).
//
// The constructor triggers initial renders via its async session loaders
// (Promise.resolve([]) microtasks flush under fake timers), so each test
// baselines renders.length AFTER construction and asserts the DELTA from the
// status timer is what's pinned — not an absolute 0.

type ComponentWithHeader = {
	header: {
		setStatusMessage: (msg: { type: "info" | "error"; message: string } | null, autoHideMs?: number) => void;
	};
};

describe("SessionSelectorComponent dispose propagates to header status timer (opt #151)", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("dispose() clears the header's auto-hide status timer (no render after detach)", async () => {
		const renders: number[] = [];
		const requestRender = () => {
			renders.push(1);
		};

		const component = new SessionSelectorComponent(
			() => Promise.resolve([]),
			() => Promise.resolve([]),
			() => {},
			() => {},
			() => {},
			requestRender,
			{ renameSession: async () => {} },
		);
		// Flush constructor-initiated loader microtasks so the baseline is stable.
		await vi.advanceTimersByTimeAsync(0);
		const baseline = renders.length;

		const header = (component as unknown as ComponentWithHeader).header;
		// Schedule a 1000ms auto-hide status timer. setStatusMessage itself does
		// NOT call requestRender — only the timer callback does.
		header.setStatusMessage({ type: "error", message: "Rename failed" }, 1000);
		expect(renders.length).toBe(baseline);

		// Dismiss the selector (mirrors showSelector's done() → component.dispose()).
		component.dispose();

		// Advance past the 1000ms timer. With the fix, dispose cleared it → the
		// timer never fires → no render on the detached header.
		vi.advanceTimersByTime(2000);
		expect(renders.length).toBe(baseline);
	});

	it("without an early dispose, the status timer DOES fire (sanity: the timer is real)", async () => {
		const renders: number[] = [];
		const requestRender = () => {
			renders.push(1);
		};

		const component = new SessionSelectorComponent(
			() => Promise.resolve([]),
			() => Promise.resolve([]),
			() => {},
			() => {},
			() => {},
			requestRender,
		);
		await vi.advanceTimersByTimeAsync(0);
		const baseline = renders.length;

		(component as unknown as ComponentWithHeader).header.setStatusMessage({ type: "info", message: "hi" }, 500);
		expect(renders.length).toBe(baseline);

		vi.advanceTimersByTime(600);
		// The timer fired exactly once.
		expect(renders.length).toBe(baseline + 1);

		// Subsequent dispose is a no-op (timer already fired + cleared itself).
		component.dispose();
		vi.advanceTimersByTime(2000);
		expect(renders.length).toBe(baseline + 1);
	});
});

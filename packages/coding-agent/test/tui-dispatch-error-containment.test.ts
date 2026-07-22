import type { EditorTheme, TUI } from "@pi-recon/repi-tui";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../src/core/keybindings.ts";
import { getEditorTheme, initTheme } from "../src/core/presentation/theme-runtime.ts";
import { CustomEditor } from "../src/modes/interactive/components/custom-editor.ts";
import { SessionSelectorComponent } from "../src/modes/interactive/components/session-selector.ts";
import { TreeSelectorComponent } from "../src/modes/interactive/components/tree-selector.ts";

// opt #145: three TUI-layer dispatch sites dropped returned promises from async
// handlers (same class as opt #142's CustomEditor action-handler containment):
//   1. Editor.submitValue (tui editor.ts) → onSubmit (the Enter submit path;
//      onSubmit is interactive-mode's large async body w/ no top-level
//      try/catch — a rejecting submission path = unhandledRejection crashing
//      the host with the terminal in raw mode, OR a sync throw = uncaughtException).
//   2. TreeList confirm (tree-selector.ts) → onSelect (the navigateTree flow;
//      the pre-navigateTree showExtensionSelector/showExtensionEditor awaits
//      aren't in the handler's try/catch).
//   3. SessionList confirm (session-selector.ts) → onSelect (the resume-session
//      flow; handleResumeSession can throw on switchSession / missing-cwd).
// Each site now guards the dispatch (try/catch + .catch on a returned thenable)
// routing to an error sink (onSubmitError / onSelectError, console.error
// fallback). interactive-mode wires the sinks to showError + guards the
// Alt+Enter direct onSubmit call. These tests assert BOTH async-rejecting and
// sync-throwing handlers are contained (sink receives the error, no
// unhandledRejection/uncaughtException escapes).

// Drain microtasks + I/O so an async rejection (if it escaped) would surface on
// the unhandledRejection listener before we assert.
async function drain() {
	await new Promise<void>((resolve) => queueMicrotask(resolve));
	await new Promise<void>((resolve) => setImmediate(resolve));
	await new Promise<void>((resolve) => setImmediate(resolve));
}

describe("Editor.submitValue error containment (opt #145)", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	function makeEditor(): CustomEditor {
		const fakeTui = { requestRender: () => {}, terminal: { rows: 24, cols: 80 } } as unknown as TUI;
		const theme = getEditorTheme() as EditorTheme;
		return new CustomEditor(fakeTui, theme, new KeybindingsManager());
	}

	it("contains an async-rejecting onSubmit (routes to onSubmitError, no unhandledRejection)", async () => {
		const editor = makeEditor();
		let captured: unknown;
		editor.onSubmitError = (err) => {
			captured = err;
		};
		editor.onSubmit = async () => {
			await Promise.resolve();
			throw new Error("async boom from onSubmit");
		};

		const unhandled: unknown[] = [];
		const onUnhandled = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", onUnhandled);
		try {
			// Enter ("\r" = char 13 = tui.input.submit) → submitValue → onSubmit.
			editor.handleInput("\r");
			await drain();
		} finally {
			process.off("unhandledRejection", onUnhandled);
		}

		expect(unhandled).toEqual([]);
		expect(captured).toBeInstanceOf(Error);
		expect(String((captured as Error).message)).toContain("async boom");
	});

	it("contains a sync-throwing onSubmit (routes to onSubmitError, no throw escapes)", () => {
		const editor = makeEditor();
		let captured: unknown;
		editor.onSubmitError = (err) => {
			captured = err;
		};
		editor.onSubmit = () => {
			throw new Error("sync boom from onSubmit");
		};

		expect(() => editor.handleInput("\r")).not.toThrow();

		expect(captured).toBeInstanceOf(Error);
		expect(String((captured as Error).message)).toContain("sync boom");
	});

	it("falls back to console.error when onSubmitError is unset (still no escape)", async () => {
		const editor = makeEditor();
		const spy = vi.spyOn(console, "error").mockImplementation(() => {});
		editor.onSubmit = async () => {
			throw new Error("no-sink submit boom");
		};

		const unhandled: unknown[] = [];
		const onUnhandled = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", onUnhandled);
		try {
			editor.handleInput("\r");
			await drain();
		} finally {
			process.off("unhandledRejection", onUnhandled);
		}

		expect(unhandled).toEqual([]);
		expect(spy).toHaveBeenCalled();
		spy.mockRestore();
	});
});

// Selectors: runSelect is the guarded dispatch on TreeList / SessionList. Grab
// it off the inner list's prototype (TreeList / SessionList are package-private
// but reachable via the exported component's treeList / sessionList field) and
// drive it with a fake `this` that only carries the error sink — runSelect
// touches nothing else, so this exercises the real guard in isolation.
function treeRunSelect(): (this: { onSelectError?: (e: unknown) => void }, handler: () => void) => void {
	const selector = new TreeSelectorComponent(
		[],
		null,
		10,
		() => {},
		() => {},
	);
	const list = (selector as unknown as { treeList: { constructor: { prototype: { runSelect: unknown } } } }).treeList;
	return list.constructor.prototype.runSelect as (
		this: { onSelectError?: (e: unknown) => void },
		handler: () => void,
	) => void;
}

function sessionRunSelect(): (this: { onSelectError?: (e: unknown) => void }, handler: () => void) => void {
	const selector = new SessionSelectorComponent(
		() => Promise.resolve([]),
		() => Promise.resolve([]),
		() => {},
		() => {},
		() => {},
		() => {},
	);
	const list = (selector as unknown as { sessionList: { constructor: { prototype: { runSelect: unknown } } } })
		.sessionList;
	return list.constructor.prototype.runSelect as (
		this: { onSelectError?: (e: unknown) => void },
		handler: () => void,
	) => void;
}

describe("TreeList.runSelect error containment (opt #145)", () => {
	it("contains an async-rejecting onSelect (routes to onSelectError, no unhandledRejection)", async () => {
		let captured: unknown;
		const ctx = {
			onSelectError: (err: unknown) => {
				captured = err;
			},
		};
		const unhandled: unknown[] = [];
		const onUnhandled = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", onUnhandled);
		try {
			treeRunSelect().call(ctx, async () => {
				await Promise.resolve();
				throw new Error("tree async boom");
			});
			await drain();
		} finally {
			process.off("unhandledRejection", onUnhandled);
		}

		expect(unhandled).toEqual([]);
		expect(captured).toBeInstanceOf(Error);
		expect(String((captured as Error).message)).toContain("tree async boom");
	});

	it("falls back to console.error when onSelectError is unset (still no escape)", async () => {
		const spy = vi.spyOn(console, "error").mockImplementation(() => {});
		const ctx = {}; // no onSelectError
		const unhandled: unknown[] = [];
		const onUnhandled = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", onUnhandled);
		try {
			treeRunSelect().call(ctx, async () => {
				throw new Error("tree no-sink boom");
			});
			await drain();
		} finally {
			process.off("unhandledRejection", onUnhandled);
		}

		expect(unhandled).toEqual([]);
		expect(spy).toHaveBeenCalled();
		spy.mockRestore();
	});
});

describe("SessionList.runSelect error containment (opt #145)", () => {
	it("contains an async-rejecting onSelect (routes to onSelectError, no unhandledRejection)", async () => {
		let captured: unknown;
		const ctx = {
			onSelectError: (err: unknown) => {
				captured = err;
			},
		};
		const unhandled: unknown[] = [];
		const onUnhandled = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", onUnhandled);
		try {
			sessionRunSelect().call(ctx, async () => {
				await Promise.resolve();
				throw new Error("session async boom");
			});
			await drain();
		} finally {
			process.off("unhandledRejection", onUnhandled);
		}

		expect(unhandled).toEqual([]);
		expect(captured).toBeInstanceOf(Error);
		expect(String((captured as Error).message)).toContain("session async boom");
	});

	it("contains a sync-throwing onSelect (routes to onSelectError, no throw escapes)", () => {
		let captured: unknown;
		const ctx = {
			onSelectError: (err: unknown) => {
				captured = err;
			},
		};
		expect(() =>
			sessionRunSelect().call(ctx, () => {
				throw new Error("session sync boom");
			}),
		).not.toThrow();

		expect(captured).toBeInstanceOf(Error);
		expect(String((captured as Error).message)).toContain("session sync boom");
	});
});

import type { EditorTheme, TUI } from "@pi-recon/repi-tui";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../src/core/keybindings.ts";
import { CustomEditor } from "../src/modes/interactive/components/custom-editor.ts";
import { getEditorTheme, initTheme } from "../src/modes/interactive/theme/theme.ts";

// opt #142: the CustomEditor dispatch boundary (handleInput → handler()) called
// action handlers synchronously and dropped any returned promise. The repo has
// NO global unhandledRejection handler and interactive-mode's terminalErrorHandler
// (uncaughtCrash) only handles uncaughtException — so an ASYNC handler that
// rejected (e.g. handleFollowUp → session.prompt re-throws on expired auth /
// extension-input-handler throw) became an unhandledRejection that crashed the
// process WITHOUT restoring the terminal (raw mode stuck, cursor hidden) — strictly
// worse than a sync throw (which uncaughtCrash at least restores the terminal
// before exiting). A SYNC throw became an uncaughtException → uncaughtCrash exits
// the whole session for one transient throw. Fix: runHandler() wraps each handler
// invocation in try/catch (sync) + .catch on a returned thenable (async), routing
// to onActionError (mirrors the already-guarded extension-shortcut path). These
// tests drive handleInput with app.interrupt (Escape, "\x1b") bound to onEscape
// and assert BOTH an async-rejecting and a sync-throwing handler are contained
// (onActionError receives the error, no unhandledRejection/uncaughtException
// escapes). Pre-fix (neuter runHandler back to a bare handler() call) the async
// rejection escapes unhandled and onActionError is never called → the assertion
// fails (and vitest surfaces the unhandled rejection).

describe("CustomEditor action handler error containment (opt #142)", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	function makeEditor(): CustomEditor {
		const fakeTui = { requestRender: () => {}, terminal: { rows: 24, cols: 80 } } as unknown as TUI;
		const theme = getEditorTheme() as EditorTheme;
		return new CustomEditor(fakeTui, theme, new KeybindingsManager());
	}

	// Drain microtasks + I/O so an async rejection (if it escaped) would surface
	// on the unhandledRejection listener before we assert.
	async function drain() {
		await new Promise<void>((resolve) => queueMicrotask(resolve));
		await new Promise<void>((resolve) => setImmediate(resolve));
		await new Promise<void>((resolve) => setImmediate(resolve));
	}

	it("contains an async-rejecting handler (routes to onActionError, no unhandledRejection)", async () => {
		const editor = makeEditor();
		let captured: unknown;
		editor.onActionError = (err) => {
			captured = err;
		};
		editor.onEscape = async () => {
			await Promise.resolve();
			throw new Error("async boom from onEscape");
		};

		const unhandled: unknown[] = [];
		const onUnhandled = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", onUnhandled);
		try {
			// Escape → app.interrupt → onEscape via runHandler.
			editor.handleInput("\x1b");
			await drain();
		} finally {
			process.off("unhandledRejection", onUnhandled);
		}

		// runHandler attached a .catch to the async handler's returned promise → the
		// rejection was routed to onActionError, NOT dropped as unhandled.
		expect(unhandled).toEqual([]);
		expect(captured).toBeInstanceOf(Error);
		expect(String((captured as Error).message)).toContain("async boom");
	});

	it("contains a sync-throwing handler (routes to onActionError, no throw escapes handleInput)", () => {
		const editor = makeEditor();
		const consoleErrors: unknown[] = [];
		const spy = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
			consoleErrors.push(args);
		});
		let captured: unknown;
		editor.onActionError = (err) => {
			captured = err;
		};
		editor.onEscape = () => {
			throw new Error("sync boom from onEscape");
		};

		// Pre-fix the sync throw propagated out of handleInput → uncaughtException →
		// uncaughtCrash exits the session. runHandler's try/catch now contains it.
		expect(() => editor.handleInput("\x1b")).not.toThrow();

		expect(captured).toBeInstanceOf(Error);
		expect(String((captured as Error).message)).toContain("sync boom");
		// onActionError was set, so the console.error fallback is NOT used.
		expect(consoleErrors.find((a) => String(a).includes("CustomEditor"))).toBeUndefined();
		spy.mockRestore();
	});

	it("falls back to console.error when onActionError is unset (still no escape)", async () => {
		const editor = makeEditor();
		// No onActionError — runHandler must still contain the rejection.
		const spy = vi.spyOn(console, "error").mockImplementation(() => {});
		editor.onEscape = async () => {
			throw new Error("no-sink boom");
		};

		const unhandled: unknown[] = [];
		const onUnhandled = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", onUnhandled);
		try {
			editor.handleInput("\x1b");
			await drain();
		} finally {
			process.off("unhandledRejection", onUnhandled);
		}

		expect(unhandled).toEqual([]);
		expect(spy).toHaveBeenCalled();
		spy.mockRestore();
	});
});

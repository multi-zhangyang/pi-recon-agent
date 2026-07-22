import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { initTheme } from "../src/core/presentation/theme-runtime.ts";
import { InteractiveMode } from "../src/modes/interactive/interactive-mode.ts";

// opt #144: openExternalEditor awaited the spawned $EDITOR child with only
// 'error'/'close' listeners and NO timeout/abort. A wedged editor — $EDITOR
// misconfigured to a non-interactive / daemon process that never exits, or a
// GUI editor that keeps a child alive — leaves the Promise pending forever →
// the `finally { ui.start() }` never runs → the TUI is never restarted and the
// interactive session hangs (terminal was released via ui.stop(); the only
// escape is killing the agent). Fix: arm REPI_EXTERNAL_EDITOR_TIMEOUT_MS (env,
// default 0 = no timeout so legit long vim sessions are never interrupted); on
// timeout SIGTERM → SIGKILL after a 2s grace, resolve null so the finally
// restarts the TUI, and surface a warning. settle() is idempotent so a late
// 'close' after the kill is a no-op. These tests drive openExternalEditor via a
// fake `this` (ui/editor/showWarning stubs) with a real spawn: (1) a wedged
// `sleep 30` "editor" under a 200ms timeout is killed + the call resolves (does
// NOT hang) + ui.start() is called (finally ran) + showWarning received the
// timeout message; (2) no timeout set + a promptly-exiting `true` "editor" →
// resolves + ui.start() called + NO warning (baseline preserved, default-off).

type EditorCtx = {
	ui: { stop: () => void; start: () => void; requestRender: (force?: boolean) => void };
	editor: { getText: () => string; setText: (s: string) => void };
	showWarning: (msg: string) => void;
};

describe("InteractiveMode.openExternalEditor timeout (opt #144)", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	const originalEditor = process.env.EDITOR;
	const originalVisual = process.env.VISUAL;
	const originalTimeout = process.env.REPI_EXTERNAL_EDITOR_TIMEOUT_MS;

	afterEach(() => {
		vi.restoreAllMocks();
		if (originalEditor === undefined) delete process.env.EDITOR;
		else process.env.EDITOR = originalEditor;
		if (originalVisual === undefined) delete process.env.VISUAL;
		else process.env.VISUAL = originalVisual;
		if (originalTimeout === undefined) delete process.env.REPI_EXTERNAL_EDITOR_TIMEOUT_MS;
		else process.env.REPI_EXTERNAL_EDITOR_TIMEOUT_MS = originalTimeout;
	});

	function makeCtx(): EditorCtx & { warnings: string[]; started: number; setTexts: string[] } {
		const warnings: string[] = [];
		const setTexts: string[] = [];
		const ctx = {
			warnings,
			started: 0,
			setTexts,
			ui: {
				stop: () => {},
				start: () => {
					ctx.started++;
				},
				requestRender: () => {},
			},
			editor: {
				getText: () => "initial content",
				setText: (s: string) => {
					setTexts.push(s);
				},
			},
			showWarning: (msg: string) => {
				warnings.push(msg);
			},
		} as unknown as EditorCtx & { warnings: string[]; started: number; setTexts: string[] };
		return ctx;
	}

	it("kills a wedged editor on timeout, restarts the TUI, and warns (no hang)", async () => {
		// `delete` (not `= undefined`, which Node stringifies to "undefined") so
		// VISUAL is unset and EDITOR is used. `tail -f /dev/null` ignores the
		// appended tmpFile (which exists, written before spawn) and follows
		// /dev/null forever → a wedged editor that never exits on its own.
		delete process.env.VISUAL;
		process.env.EDITOR = "tail -f /dev/null";
		process.env.REPI_EXTERNAL_EDITOR_TIMEOUT_MS = "200";

		const ctx = makeCtx();

		// Race against a 10s safety deadline so a regression (no kill) fails the
		// test instead of hanging the suite.
		const callP = (
			InteractiveMode.prototype as unknown as {
				openExternalEditor: (this: EditorCtx) => Promise<void>;
			}
		).openExternalEditor.call(ctx);
		await Promise.race([
			callP,
			new Promise((_, reject) =>
				setTimeout(() => reject(new Error("openExternalEditor hung — timeout kill did not fire")), 10_000),
			),
		]);

		// The wedged editor was killed on timeout → the call resolved → the finally
		// ran ui.start() (TUI restarted, no hang).
		expect(ctx.started).toBe(1);
		// A timeout warning was surfaced.
		expect(ctx.warnings.length).toBe(1);
		expect(ctx.warnings[0]).toMatch(/timed out.*200ms/i);
		// status !== 0 (killed) → original text kept, setText NOT called.
		expect(ctx.setTexts).toEqual([]);
	});

	it("preserves baseline when no timeout is set (promptly-exiting editor, no warning)", async () => {
		delete process.env.VISUAL;
		process.env.EDITOR = "true"; // exits 0 immediately, ignores the file arg
		delete process.env.REPI_EXTERNAL_EDITOR_TIMEOUT_MS;

		const ctx = makeCtx();

		await Promise.race([
			(
				InteractiveMode.prototype as unknown as {
					openExternalEditor: (this: EditorCtx) => Promise<void>;
				}
			).openExternalEditor.call(ctx),
			new Promise((_, reject) => setTimeout(() => reject(new Error("openExternalEditor hung")), 10_000)),
		]);

		// Finally always restarts the TUI.
		expect(ctx.started).toBe(1);
		// No timeout → no warning.
		expect(ctx.warnings).toEqual([]);
		// `true` exits 0 → reads the unchanged temp file → setText(same content).
		expect(ctx.setTexts).toEqual(["initial content"]);
	});
});

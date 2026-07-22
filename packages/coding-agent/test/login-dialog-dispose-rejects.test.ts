import type { TUI } from "@pi-recon/repi-tui";
import { beforeAll, describe, expect, it } from "vitest";
import { initTheme } from "../src/core/presentation/theme-runtime.ts";
import { LoginDialogComponent } from "../src/modes/interactive/components/login-dialog.ts";

// opt #125 — showPrompt/showManualInput return Promises that settle only on
// onSubmit/Escape-cancel. If the dialog is torn down (session switch / rewind /
// mode teardown) without an explicit cancel, the pending promise never settles
// → the caller awaiting it (showApiKeyLoginDialog, OAuth flows) hangs forever.
// dispose() must reject the pending promise + abort. Same settle-on-teardown
// doctrine as opt #44/#120.

function createFakeTui(): TUI {
	return { requestRender: () => {} } as unknown as TUI;
}

beforeAll(() => {
	initTheme();
});

describe("LoginDialogComponent dispose rejects pending input (opt #125)", () => {
	it("rejects a pending showPrompt promise on dispose instead of hanging", async () => {
		const dialog = new LoginDialogComponent(createFakeTui(), "test-provider", () => {});

		const promptPromise = dialog.showPrompt("Enter API key:");
		// Give the promise a chance to register resolvers (synchronous in
		// showPrompt's executor, but await a microtask to be safe).
		await Promise.resolve();

		dialog.dispose();

		await expect(promptPromise).rejects.toThrow("Login dialog closed");
	});

	it("rejects a pending showManualInput promise on dispose", async () => {
		const dialog = new LoginDialogComponent(createFakeTui(), "test-provider", () => {});

		const inputPromise = dialog.showManualInput("Paste redirect URL:");
		await Promise.resolve();

		dialog.dispose();

		await expect(inputPromise).rejects.toThrow("Login dialog closed");
	});

	it("abort signal trips on dispose so polling loops stop", async () => {
		const dialog = new LoginDialogComponent(createFakeTui(), "test-provider", () => {});
		const { signal } = dialog;
		expect(signal.aborted).toBe(false);
		dialog.dispose();
		expect(signal.aborted).toBe(true);
	});

	it("dispose is idempotent (second dispose does not throw)", () => {
		const dialog = new LoginDialogComponent(createFakeTui(), "test-provider", () => {});
		dialog.dispose();
		expect(() => dialog.dispose()).not.toThrow();
	});
});

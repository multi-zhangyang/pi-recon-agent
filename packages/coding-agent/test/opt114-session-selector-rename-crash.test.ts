import { setKeybindings } from "@pi-recon/repi-tui";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../src/core/keybindings.ts";
import type { SessionInfo } from "../src/core/session-manager.ts";
import { SessionSelectorComponent } from "../src/modes/interactive/components/session-selector.ts";
import { initTheme } from "../src/modes/interactive/theme/theme.ts";

async function flushPromises(): Promise<void> {
	// confirmRename is async and called via a `void`-dropped onSubmit; flush
	// several microtask/macrotask layers so the rejection (or its absence) settles.
	for (let i = 0; i < 4; i++) {
		await new Promise<void>((resolve) => {
			setImmediate(resolve);
		});
	}
}

function makeSession(overrides: Partial<SessionInfo> & { id: string }): SessionInfo {
	return {
		path: overrides.path ?? `/tmp/${overrides.id}.jsonl`,
		id: overrides.id,
		cwd: overrides.cwd ?? "",
		name: overrides.name,
		created: overrides.created ?? new Date(0),
		modified: overrides.modified ?? new Date(0),
		messageCount: overrides.messageCount ?? 1,
		firstMessage: overrides.firstMessage ?? "hello",
		allMessagesText: overrides.allMessagesText ?? "hello",
	};
}

// Kitty keyboard protocol encoding for Ctrl+R
const CTRL_R = "\x1b[114;5u";

describe("session selector rename crash guard (opt #114)", () => {
	beforeAll(() => {
		initTheme("dark");
	});

	beforeEach(() => {
		// Ensure test isolation: keybindings are a global singleton
		setKeybindings(new KeybindingsManager());
	});

	it("a failing rename surfaces an error instead of crashing via unhandled rejection", async () => {
		const sessions = [makeSession({ id: "a", name: "Old" })];
		// renameSession rejects on a real-world filesystem error (EACCES/ENOENT/ENOSPC).
		const renameSession = vi.fn(async () => {
			throw new Error("EACCES: permission denied");
		});

		const keybindings = new KeybindingsManager();
		const selector = new SessionSelectorComponent(
			async () => sessions,
			async () => [],
			() => {},
			() => {},
			() => {},
			() => {},
			{ renameSession, showRenameHint: true, keybindings },
		);
		await flushPromises();

		// Enter rename mode on the selected session.
		selector.getSessionList().handleInput(CTRL_R);
		await flushPromises();
		expect(selector.render(120).join("\n")).toContain("Rename Session");

		// Capture any unhandled rejection (the bug path: `void confirmRename()`
		// drops the rejection → unhandledRejection → uncaughtException → exit).
		const unhandled: unknown[] = [];
		const handler = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", handler);
		try {
			// Type and submit the rename.
			selector.handleInput("X");
			selector.handleInput("\r");
			await flushPromises();

			// renameSession was attempted…
			expect(renameSession).toHaveBeenCalledTimes(1);
			// …and no rejection escaped to the process (the catch absorbed it).
			expect(unhandled).toHaveLength(0);
			// …rename mode was exited cleanly (finally still ran)…
			const output = selector.render(120).join("\n");
			expect(output).not.toContain("Rename Session");
			// …and the failure is surfaced inline as an error status.
			expect(output).toContain("Rename failed");
		} finally {
			process.off("unhandledRejection", handler);
		}
	});
});

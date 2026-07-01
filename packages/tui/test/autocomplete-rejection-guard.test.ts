import assert from "node:assert";
import { describe, it } from "node:test";
import type { AutocompleteProvider } from "../src/autocomplete.ts";
import { Editor } from "../src/components/editor.ts";
import { TUI } from "../src/tui.ts";
import { defaultEditorTheme } from "./test-themes.ts";
import { VirtualTerminal } from "./virtual-terminal.ts";

function createTestTUI(cols = 80, rows = 24): TUI {
	return new TUI(new VirtualTerminal(cols, rows));
}

async function flushAutocomplete(): Promise<void> {
	await Promise.resolve();
	await new Promise((resolve) => setImmediate(resolve));
}

function applyCompletion(
	lines: string[],
	cursorLine: number,
	cursorCol: number,
	item: { value: string },
	prefix: string,
): { lines: string[]; cursorLine: number; cursorCol: number } {
	const line = lines[cursorLine] || "";
	const before = line.slice(0, cursorCol - prefix.length);
	const after = line.slice(cursorCol);
	const newLines = [...lines];
	newLines[cursorLine] = before + item.value + after;
	return {
		lines: newLines,
		cursorLine,
		cursorCol: cursorCol - prefix.length + item.value.length,
	};
}

describe("Editor autocomplete rejection guard (opt #114)", () => {
	it("a rejecting provider does not crash the agent or poison the autocomplete chain", async () => {
		const editor = new Editor(createTestTUI(), defaultEditorTheme);

		// First getSuggestions call throws (extension-controlled completion code
		// can throw on arbitrary internal failures); subsequent calls succeed.
		let callCount = 0;
		const mockProvider: AutocompleteProvider = {
			getSuggestions: async () => {
				callCount += 1;
				if (callCount === 1) {
					throw new Error("extension completion exploded");
				}
				return {
					items: [
						{ value: "src/a.txt", label: "src/a.txt" },
						{ value: "src/b.txt", label: "src/b.txt" },
					],
					prefix: "src",
				};
			},
			applyCompletion,
		};
		editor.setAutocompleteProvider(mockProvider);

		// Capture any unhandled rejection (the bug path: `void
		// startAutocompleteRequest()` drops the rejected task → unhandledRejection
		// → uncaughtException → process.exit, AND the shared autocompleteRequestTask
		// chain stays poisoned so every later request throws again).
		const unhandled: unknown[] = [];
		const handler = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", handler);
		try {
			// First autocomplete request: provider throws.
			editor.handleInput("s");
			editor.handleInput("r");
			editor.handleInput("c");
			editor.handleInput("\t");
			await flushAutocomplete();
			await flushAutocomplete();

			// No rejection escaped to the process — the catch absorbed it.
			assert.strictEqual(unhandled.length, 0, "rejecting provider must not produce an unhandled rejection");

			// Second autocomplete request: the shared task chain must NOT be
			// poisoned by the prior rejection, so this request reaches
			// getSuggestions and shows the menu.
			editor.handleInput("\t");
			await flushAutocomplete();
			await flushAutocomplete();
			assert.strictEqual(callCount, 2, "second request must reach getSuggestions (chain not poisoned)");
			assert.strictEqual(editor.isShowingAutocomplete(), true, "autocomplete still works after a prior failure");
		} finally {
			process.off("unhandledRejection", handler);
		}
	});
});

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

describe("Editor dispose (FIX 2)", () => {
	it("dispose() cancels an open autocomplete menu (clears state)", async () => {
		const editor = new Editor(createTestTUI(), defaultEditorTheme);

		const mockProvider: AutocompleteProvider = {
			getSuggestions: async () => {
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

		// Type "src" and open the autocomplete menu (multiple suggestions -> menu shown).
		editor.handleInput("s");
		editor.handleInput("r");
		editor.handleInput("c");
		editor.handleInput("\t");
		await flushAutocomplete();

		assert.strictEqual(editor.isShowingAutocomplete(), true, "sanity: autocomplete menu is open");

		editor.dispose();

		assert.strictEqual(editor.isShowingAutocomplete(), false, "dispose() must cancel autocomplete UI state");
	});

	it("dispose() is defined and does not throw on a fresh editor", () => {
		const editor = new Editor(createTestTUI(), defaultEditorTheme);
		assert.equal(typeof editor.dispose, "function");
		editor.dispose();
	});
});

import assert from "node:assert";
import { describe, it } from "node:test";
import { SelectList } from "../src/components/select-list.ts";

const testTheme = {
	selectedPrefix: (text: string) => text,
	selectedText: (text: string) => text,
	description: (text: string) => text,
	scrollInfo: (text: string) => text,
	noMatch: (text: string) => text,
};

// Accessor for the memoized primary-column-width field (white-box check).
const getMemoizedWidth = (list: SelectList): number =>
	(list as unknown as { primaryColumnWidth: number }).primaryColumnWidth;

describe("SelectList primary column width memoization (FIX 7)", () => {
	it("computes and caches the primary column width in the constructor", () => {
		const items = [
			{ value: "short", label: "short" },
			{ value: "abcdefghijklmnop", label: "abcdefghijklmnop" },
		];
		// Bounds wide enough that the width tracks the widest visible label.
		const list = new SelectList(items, 5, testTheme, {
			minPrimaryColumnWidth: 2,
			maxPrimaryColumnWidth: 60,
		});

		// widest visible = max(visibleWidth("short")+2, visibleWidth("abcdefghijklmnop")+2) = 18
		assert.equal(getMemoizedWidth(list), 18, "constructor must memoize the computed width");
	});

	it("recomputes the cached width when setFilter changes filteredItems", () => {
		const items = [
			{ value: "short", label: "short" },
			{ value: "abcdefghijklmnop", label: "abcdefghijklmnop" },
		];
		const list = new SelectList(items, 5, testTheme, {
			minPrimaryColumnWidth: 2,
			maxPrimaryColumnWidth: 60,
		});
		assert.equal(getMemoizedWidth(list), 18, "sanity: initial width from both items");

		list.setFilter("short");
		// Only "short" remains -> widest visible = visibleWidth("short")+2 = 7
		assert.equal(getMemoizedWidth(list), 7, "setFilter must invalidate and recompute the cached width");

		list.setFilter("abcdef");
		// Only the long label remains -> 18 again
		assert.equal(getMemoizedWidth(list), 18, "setFilter recomputes when the long item is the only match");
	});

	it("render output is identical to the expected (memoized) width", () => {
		const items = [
			{ value: "a", label: "a", description: "first" },
			{ value: "bb", label: "bb", description: "second" },
		];
		const list = new SelectList(items, 5, testTheme, {
			minPrimaryColumnWidth: 12,
			maxPrimaryColumnWidth: 20,
		});
		const rendered = list.render(80);
		// Existing behavior: descriptions align at column 14 (prefix 2 + width 12).
		assert.equal(rendered[0].indexOf("first"), 14);
		assert.equal(rendered[1].indexOf("second"), 14);
	});
});

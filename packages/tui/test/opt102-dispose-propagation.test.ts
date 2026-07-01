import assert from "node:assert";
import { describe, it } from "node:test";
import { Box } from "../src/components/box.ts";
import { SettingsList } from "../src/components/settings-list.ts";
import type { Component } from "../src/tui.ts";
import { TUI } from "../src/tui.ts";
import { VirtualTerminal } from "./virtual-terminal.ts";

const identity = (s: string): string => s;

/** Minimal Component with a dispose spy, for asserting propagation through containers. */
class SpyComponent implements Component {
	disposeCalls = 0;
	render(_width: number): string[] {
		return [""];
	}
	invalidate(): void {
		// no cache
	}
	dispose(): void {
		this.disposeCalls += 1;
	}
}

function createTestTUI(): TUI {
	return new TUI(new VirtualTerminal(80, 24));
}

describe("Box dispose propagates to children (opt #102 F1)", () => {
	it("dispose() calls dispose() on every child", () => {
		const box = new Box(1, 1);
		const childA = new SpyComponent();
		const childB = new SpyComponent();
		box.addChild(childA);
		box.addChild(childB);

		(box as unknown as { dispose: () => void }).dispose();

		assert.equal(childA.disposeCalls, 1, "first child dispose must be called");
		assert.equal(childB.disposeCalls, 1, "second child dispose must be called");
	});

	it("dispose() is idempotent and clears children", () => {
		const box = new Box(1, 1);
		const child = new SpyComponent();
		box.addChild(child);
		const d = box as unknown as { dispose: () => void; children: Component[] };

		d.dispose();
		d.dispose(); // second call must not re-invoke the cleared children

		assert.equal(child.disposeCalls, 1, "child dispose called exactly once");
		assert.equal(d.children.length, 0, "children cleared after dispose");
	});

	it("a child that throws in dispose() does not skip the remaining children", () => {
		const box = new Box(1, 1);
		const throwing: Component = {
			render: () => [""],
			invalidate: () => {},
			dispose: () => {
				throw new Error("child teardown failed");
			},
		};
		const after = new SpyComponent();
		box.addChild(throwing);
		box.addChild(after);

		assert.doesNotThrow(() => {
			(box as unknown as { dispose: () => void }).dispose();
		});
		assert.equal(after.disposeCalls, 1, "remaining child dispose still called after a throwing sibling");
	});
});

describe("SettingsList dispose tears down the active submenu (opt #102 F2)", () => {
	const theme = {
		label: identity,
		value: identity,
		description: identity,
		cursor: ">",
		hint: identity,
	};

	it("dispose() disposes the active submenu component", () => {
		const list = new SettingsList(
			[],
			10,
			theme,
			() => {},
			() => {},
		);
		const submenu = new SpyComponent();
		// Inject an active submenu directly (the path activateItem() would set).
		(list as unknown as { submenuComponent: Component | null }).submenuComponent = submenu;

		assert.equal(submenu.disposeCalls, 0, "sanity: submenu not yet disposed");
		(list as unknown as { dispose: () => void }).dispose();
		assert.equal(submenu.disposeCalls, 1, "active submenu dispose must be called");
	});

	it("dispose() clears submenu state", () => {
		const list = new SettingsList(
			[],
			10,
			theme,
			() => {},
			() => {},
		);
		const submenu = new SpyComponent();
		const priv = list as unknown as {
			submenuComponent: Component | null;
			submenuItemIndex: number | null;
			dispose: () => void;
		};
		priv.submenuComponent = submenu;
		priv.submenuItemIndex = 3;

		priv.dispose();

		assert.equal(priv.submenuComponent, null, "submenuComponent cleared");
		assert.equal(priv.submenuItemIndex, null, "submenuItemIndex cleared");
	});

	it("dispose() is a no-op when no submenu is active", () => {
		const list = new SettingsList(
			[],
			10,
			theme,
			() => {},
			() => {},
		);
		assert.doesNotThrow(() => {
			(list as unknown as { dispose: () => void }).dispose();
		});
	});
});

// Keep createTestTUI referenced for symmetry with the rest of the test corpus
// (and future tests that build a full TUI). Voiding it avoids an unused warning.
void createTestTUI;

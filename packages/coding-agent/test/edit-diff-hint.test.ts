import { describe, expect, it } from "vitest";
import { getNotFoundHint } from "../src/core/tools/edit-diff.ts";

describe("getNotFoundHint", () => {
	it("returns empty string when oldText has no substantial anchor line", () => {
		expect(getNotFoundHint("anything", "\n\n  \n")).toBe("");
	});

	it("pinpoints the line when the first line matches exactly but the block diverges", () => {
		const content = 'import { a } from "a";\nimport { b } from "b";\nconst x = 1;\n';
		// First line matches exactly; second line differs (wrong module).
		const oldText = 'import { a } from "a";\nimport { c } from "c";\n';
		const hint = getNotFoundHint(content, oldText);
		expect(hint).toContain("line 1");
		expect(hint).toContain("did not match");
	});

	it("reports a normalized match when trailing whitespace/unicode differs", () => {
		// File uses a smart quote; oldText uses an ASCII quote.
		const content = "const msg = “hello”;\n";
		const oldText = 'const msg = "hello";\n';
		const hint = getNotFoundHint(content, oldText);
		expect(hint).toContain("line 1");
		// Source reports the normalized-match cause: trailing whitespace or unicode
		// quotes/dashes differ (wording refined from the old "normalizing" label).
		expect(hint.toLowerCase()).toContain("trailing whitespace");
	});

	it("reports an indentation mismatch when leading whitespace differs", () => {
		const content = "function f() {\n    return 1;\n}\n";
		// oldText uses a tab where the file uses 4 spaces; the trimmed text matches.
		const oldText = "\treturn 1;\n";
		const hint = getNotFoundHint(content, oldText);
		expect(hint).toContain("line 2");
		expect(hint.toLowerCase()).toContain("indentation");
	});

	it("locates a later anchor line when the first anchor is absent from the file", () => {
		const content = "alpha\nbeta\ngamma\ndelta\n";
		// First anchor not present; second anchor "gamma" is at line 3.
		const oldText = "zzz not here\ngamma\nmore missing\n";
		const hint = getNotFoundHint(content, oldText);
		expect(hint).toContain("line 3");
	});

	it("returns empty string when no anchor line is found in the file at all", () => {
		const content = "alpha\nbeta\n";
		const oldText = "completely different line one\ntotally different line two\n";
		expect(getNotFoundHint(content, oldText)).toBe("");
	});
});

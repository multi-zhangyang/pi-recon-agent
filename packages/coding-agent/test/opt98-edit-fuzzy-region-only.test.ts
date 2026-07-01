import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ExtensionContext } from "../src/core/extensions/types.ts";
import { createEditToolDefinition } from "../src/core/tools/edit.ts";
import { applyEditsToNormalizedContent, computeEditsDiff } from "../src/core/tools/edit-diff.ts";

// opt #98 F2: when ANY edit needed a fuzzy match, the old code rewrote the
// ENTIRE file in fuzzy-normalized space (trailing whitespace stripped,
// unicode quotes/dashes/spaces normalized everywhere) — a silent whole-file
// reformat. It also broke a second exact edit whose oldText contained
// trailing whitespace, throwing "not found" against the fuzzy-normalized base.
// Post-fix fuzzy normalization is applied ONLY to each fuzzy edit's matched
// region, mapped back to original offsets, and the replacement is spliced into
// the ORIGINAL content so every line outside the match is preserved
// byte-for-byte. baseContent is the original (un-reformatted) content, so the
// diff shows only the real edits.

const tempDirs: string[] = [];

function makeTempDir(): string {
	const dir = mkdtempSync(join(tmpdir(), "pi-edit-fuzzy-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

const NO_CTX = undefined as unknown as ExtensionContext;

describe("applyEditsToNormalizedContent fuzzy region-only normalization (F2)", () => {
	it("preserves trailing whitespace on unrelated lines (no whole-file reformat)", () => {
		// Line 1 has trailing spaces that force a fuzzy match (oldText omits
		// them); the unrelated "keep   " line must keep its trailing spaces.
		const content = "line1   \nline2XXX\nkeep   \n";
		const { baseContent, newContent } = applyEditsToNormalizedContent(
			content,
			[{ oldText: "line1\nline2XXX", newText: "REPLACED" }],
			"f.txt",
		);
		// The matched region "line1   \nline2XXX" is replaced; the unrelated
		// "keep   " line keeps its trailing whitespace byte-for-byte.
		expect(newContent).toBe("REPLACED\nkeep   \n");
		// baseContent is the ORIGINAL content — the diff will show only the real
		// edit, not a whole-file reformat.
		expect(baseContent).toBe(content);
	});

	it("preserves trailing whitespace on unrelated lines even when the fuzzy edit is later in the file", () => {
		const content = "keepA   \nkeepB  \nedit me please   \nkeepC \n";
		// oldText omits the trailing spaces on the edited line → fuzzy match.
		const { baseContent, newContent } = applyEditsToNormalizedContent(
			content,
			[{ oldText: "edit me please\nkeepC", newText: "DONE\nkeepC" }],
			"f.txt",
		);
		expect(newContent).toBe("keepA   \nkeepB  \nDONE\nkeepC \n");
		expect(baseContent).toBe(content);
	});

	it("a second exact edit with trailing whitespace still matches alongside a fuzzy edit", () => {
		// edit1 needs fuzzy (smart quotes in the file, ASCII in oldText).
		// edit2 is an EXACT match in the original but its oldText carries
		// trailing whitespace that the old whole-file-normalize base stripped
		// → edit2 threw "not found". Post-fix both edits splice into the
		// original and succeed.
		const content = "alpha “quoted”   \nbeta  \n";
		const { baseContent, newContent } = applyEditsToNormalizedContent(
			content,
			[
				{ oldText: 'alpha "quoted"', newText: "ALPHA" },
				{ oldText: "beta  ", newText: "BETA" },
			],
			"f.txt",
		);
		// edit1's matched region is 'alpha “quoted”' (the trailing spaces on
		// line 1 are NOT part of oldText, so they survive). edit2 replaces
		// 'beta  ' (its trailing spaces are part of oldText, so consumed).
		expect(newContent).toBe("ALPHA   \nBETA\n");
		expect(baseContent).toBe(content);
	});

	it("still applies an all-exact edit batch unchanged (no fuzzy needed)", () => {
		const content = "a\nb\nc\n";
		const { baseContent, newContent } = applyEditsToNormalizedContent(
			content,
			[
				{ oldText: "a", newText: "A" },
				{ oldText: "c", newText: "C" },
			],
			"f.txt",
		);
		expect(newContent).toBe("A\nb\nC\n");
		expect(baseContent).toBe(content);
	});

	it("still throws not-found for a genuinely missing edit", () => {
		const content = "a\nb\nc\n";
		expect(() => applyEditsToNormalizedContent(content, [{ oldText: "zzz", newText: "Z" }], "f.txt")).toThrow(
			/Could not find/,
		);
	});

	it("still throws duplicate for a non-unique fuzzy oldText", () => {
		const content = "foo   \nbar\nfoo   \n";
		expect(() => applyEditsToNormalizedContent(content, [{ oldText: "foo", newText: "F" }], "f.txt")).toThrow(
			/occurrences/,
		);
	});
});

describe("edit tool fuzzy region-only normalization (F2 integration)", () => {
	it("preserves unrelated lines' trailing whitespace through the full edit tool", async () => {
		const dir = makeTempDir();
		const file = join(dir, "f.txt");
		// Unrelated lines carry trailing whitespace; the edited line has
		// trailing spaces the model's oldText omits → fuzzy match.
		writeFileSync(file, "keepA   \nedit me   \nkeepB  \n");
		const def = createEditToolDefinition(dir);
		const result = await def.execute(
			"call-f2-int",
			{ path: file, edits: [{ oldText: "edit me", newText: "EDITED" }] },
			undefined,
			undefined,
			NO_CTX,
		);
		const text = result.content.map((c) => (c.type === "text" ? (c.text ?? "") : "")).join("");
		expect(text).toMatch(/Successfully replaced/);
		const onDisk = readFileSync(file, "utf-8");
		// Unrelated lines keep their trailing whitespace byte-for-byte.
		expect(onDisk).toBe("keepA   \nEDITED   \nkeepB  \n");
	});

	it("computeEditsDiff preview diff shows only the real edit (no whole-file reformat)", async () => {
		const dir = makeTempDir();
		const file = join(dir, "p.txt");
		writeFileSync(file, "keepA   \nedit me   \nkeepB  \n");
		const result = await computeEditsDiff(file, [{ oldText: "edit me", newText: "EDITED" }], dir);
		expect("error" in result).toBe(false);
		const diff = (result as { diff: string }).diff;
		// The diff must mention the edit...
		expect(diff).toContain("EDITED");
		// ...but must NOT show the unrelated "keepA" / "keepB" lines as removed
		// and re-added (which is the whole-file-reformat signature).
		expect(diff).not.toMatch(/-.*keepA.*\n-\s*\d+\s+keepA/);
	});
});

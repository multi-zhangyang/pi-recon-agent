import { describe, expect, it } from "vitest";
import { truncateForSummary } from "../src/core/compaction/utils.ts";
import { inlineMcpText } from "../src/core/mcp-manager.ts";
import { truncateMiddle } from "../src/core/repi/text.ts";
import { safeHeadEnd, safeTailStart, truncateLine } from "../src/core/tools/truncate.ts";

// Regression guard for opt #60 — head+tail / head-only truncators used `String.prototype.slice`
// with a code-unit index that can land INSIDE a UTF-16 surrogate pair (astral-plane chars: emoji,
// rare CJK ext B, math symbols — a high `\uD800-\uDBFF` + low `\uDC00-\uDFFF` pair). A cut between
// the pair yields a LONE surrogate. JSON.stringify does NOT throw — it emits a `\udXXX` escape, so
// the corrupted text silently reaches the LLM (Buffer.from / TextEncoder turn a lone surrogate into
// U+FFFD). CJK BMP and ASCII are single code units and are NOT breakers — only astral pairs are.
// Fix: safeHeadEnd/safeTailStart back up / advance past a split pair at each slice boundary; every
// model-facing truncator now slices through them.

/** A string contains a lone (unpaired) surrogate iff JSON.stringify escapes it as `\uXXXX` — valid
 * pairs are emitted as the raw character, lone surrogates as an escape. The marker text and ASCII
 * content contain no `\u`, so this is a clean detector for the corruption class. */
function hasLoneSurrogate(s: string): boolean {
	return JSON.stringify(s).includes("\\u");
}

// 'a'.repeat(54) + '😀' + 'b'.repeat(50): the emoji (U+1F600, surrogate pair) sits at code-unit
// indices 54 (high) and 55 (low). length = 54 + 2 + 50 = 106.
const PAIR_AT_54 = `${"a".repeat(54)}😀${"b".repeat(50)}`;

describe("safeHeadEnd / safeTailStart surrogate-pair boundary (opt #60)", () => {
	it("safeHeadEnd backs up past a high surrogate when the cut lands on its paired low surrogate", () => {
		// slice(0, 55): charCodeAt(54)=high, charCodeAt(55)=low → cut is mid-pair → back up to 54.
		expect(safeHeadEnd(PAIR_AT_54, 55)).toBe(54);
		// slice(0, safeHeadEnd(...)) yields no lone surrogate; pre-fix slice(0,55) ends with lone high.
		expect(hasLoneSurrogate(PAIR_AT_54.slice(0, safeHeadEnd(PAIR_AT_54, 55)))).toBe(false);
		expect(hasLoneSurrogate(PAIR_AT_54.slice(0, 55))).toBe(true); // the bug, pre-fix
	});

	it("safeHeadEnd leaves a non-split boundary unchanged", () => {
		// cut at 54: charCodeAt(53)='a' (not a high surrogate) → no split → unchanged.
		expect(safeHeadEnd(PAIR_AT_54, 54)).toBe(54);
		// cut at 56: charCodeAt(55)=low surrogate (not a high surrogate) → no split → unchanged.
		expect(safeHeadEnd(PAIR_AT_54, 56)).toBe(56);
	});

	it("safeHeadEnd is a no-op at the string boundaries", () => {
		expect(safeHeadEnd(PAIR_AT_54, 0)).toBe(0);
		expect(safeHeadEnd(PAIR_AT_54, PAIR_AT_54.length)).toBe(PAIR_AT_54.length);
		expect(safeHeadEnd("", 5)).toBe(5);
	});

	it("safeTailStart advances past a low surrogate when the tail starts on its paired high", () => {
		// slice(55): charCodeAt(54)=high, charCodeAt(55)=low → tail begins on lone low → advance to 56.
		expect(safeTailStart(PAIR_AT_54, 55)).toBe(56);
		expect(hasLoneSurrogate(PAIR_AT_54.slice(safeTailStart(PAIR_AT_54, 55)))).toBe(false);
		expect(hasLoneSurrogate(PAIR_AT_54.slice(55))).toBe(true); // the bug, pre-fix
	});

	it("safeTailStart leaves a non-split boundary unchanged", () => {
		// start at 54: charCodeAt(53)='a' → no split → unchanged (slice(54) keeps the valid pair).
		expect(safeTailStart(PAIR_AT_54, 54)).toBe(54);
		expect(hasLoneSurrogate(PAIR_AT_54.slice(54))).toBe(false);
		// start at 56: charCodeAt(55)=low (not a high surrogate) → no split → unchanged.
		expect(safeTailStart(PAIR_AT_54, 56)).toBe(56);
	});

	it("safeTailStart is a no-op at the string boundaries", () => {
		expect(safeTailStart(PAIR_AT_54, 0)).toBe(0);
		expect(safeTailStart(PAIR_AT_54, PAIR_AT_54.length)).toBe(PAIR_AT_54.length);
		expect(safeTailStart("", 0)).toBe(0);
	});
});

describe("truncateMiddle surrogate-safe head+tail (opt #60)", () => {
	// truncateMiddle: head = floor(limit*0.55), tail = floor(limit*0.35). limit=100 → head=55, tail=35.
	// PAIR_AT_54 (length 106): the pair straddles index 55 (high at 54, low at 55) → head cut is mid-pair.
	it("does not emit a lone surrogate when the head cut splits a pair", () => {
		const result = truncateMiddle(PAIR_AT_54, 100);
		expect(hasLoneSurrogate(result)).toBe(false);
		expect(result).toContain("<truncated");
	});

	it("does not emit a lone surrogate when the tail cut splits a pair", () => {
		// Place the pair so it straddles the tail start. limit=100 → tail=35, start = length-35.
		// length 146 → start=111. Put the emoji at 110-111: 'a'.repeat(110) + '😀' + 'b'.repeat(34) = 146.
		const text = `${"a".repeat(110)}😀${"b".repeat(34)}`;
		expect(text.length).toBe(146);
		const result = truncateMiddle(text, 100);
		expect(hasLoneSurrogate(result)).toBe(false);
	});
});

describe("truncateForSummary surrogate-safe head+tail (opt #60)", () => {
	// truncateForSummary: head = tail = floor(maxChars*0.45). maxChars=100 → head=45, tail=45.
	it("does not emit a lone surrogate when the head cut splits a pair", () => {
		// length 146, pair at 44-45 (high at 44, low at 45) → head cut at 45 is mid-pair.
		const text = `${"a".repeat(44)}😀${"b".repeat(100)}`;
		expect(text.length).toBe(146);
		const result = truncateForSummary(text, 100);
		expect(hasLoneSurrogate(result)).toBe(false);
		expect(result).toContain("more characters truncated");
	});

	it("does not emit a lone surrogate when the tail cut splits a pair", () => {
		// length 146, tail=45, start=101. pair at 100-101 (high at 100, low at 101).
		const text = `${"a".repeat(100)}😀${"b".repeat(44)}`;
		expect(text.length).toBe(146);
		const result = truncateForSummary(text, 100);
		expect(hasLoneSurrogate(result)).toBe(false);
	});
});

describe("truncateLine surrogate-safe head (opt #60)", () => {
	// truncateLine default maxChars=GREP_MAX_LINE_LENGTH=500.
	it("does not emit a lone surrogate when the line cut splits a pair", () => {
		// length 501, pair at 499-500 (high at 499, low at 500) → cut at 500 is mid-pair.
		const line = `${"a".repeat(499)}😀${"b".repeat(0)}`;
		expect(line.length).toBe(501);
		const { text, wasTruncated } = truncateLine(line);
		expect(wasTruncated).toBe(true);
		expect(hasLoneSurrogate(text)).toBe(false);
		expect(text.endsWith("... [truncated]")).toBe(true);
	});

	it("leaves a short line unchanged", () => {
		const { text, wasTruncated } = truncateLine("😀 short 😀 line 😀");
		expect(wasTruncated).toBe(false);
		expect(text).toBe("😀 short 😀 line 😀");
		expect(hasLoneSurrogate(text)).toBe(false);
	});
});

describe("inlineMcpText surrogate-safe head (opt #60)", () => {
	// inlineMcpText truncates at MCP_TOOL_FALLBACK_TRUNCATE_CHARS = 64000.
	it("does not emit a lone surrogate when the MCP output cut splits a pair", () => {
		// length 64101, pair at 63999-64000 (high at 63999, low at 64000) → cut at 64000 is mid-pair.
		const text = `${"a".repeat(63999)}😀${"b".repeat(100)}`;
		expect(text.length).toBe(64101);
		const result = inlineMcpText(text);
		expect(hasLoneSurrogate(result)).toBe(false);
		expect(result).toContain("truncated MCP tool output");
	});

	it("returns short output unchanged (no truncation, pair preserved)", () => {
		const result = inlineMcpText("ok 😀 ok");
		expect(result).toBe("ok 😀 ok");
		expect(hasLoneSurrogate(result)).toBe(false);
	});
});

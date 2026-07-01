import type { TextContent } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { capToolResultContent } from "../src/agent-loop.ts";
import { truncateForSummary } from "../src/harness/compaction/utils.ts";
import { safeHeadEnd, safeTailStart, truncateLine } from "../src/harness/utils/truncate.ts";

// Agent-package regression guard for opt #60 — the agent-core side of the surrogate-safe truncation
// fix. capToolResultContent is the defense-in-depth safety cap applied to EVERY tool result at the
// context boundary (agent-loop.ts, default 256K); a corrupt lone surrogate here reaches the LLM on
// every tool call. The agent harness truncateForSummary feeds the compaction summarizer; truncateLine
// feeds grep match lines. All now slice through safeHeadEnd/safeTailStart. See the coding-agent
// surrogate-safe-truncation.test.ts for the root-helper proof.

function hasLoneSurrogate(s: string): boolean {
	return JSON.stringify(s).includes("\\u");
}

const PAIR_AT_54 = `${"a".repeat(54)}😀${"b".repeat(50)}`;

describe("agent safeHeadEnd / safeTailStart (opt #60)", () => {
	it("safeHeadEnd backs up past a high surrogate at a mid-pair cut", () => {
		expect(safeHeadEnd(PAIR_AT_54, 55)).toBe(54);
		expect(hasLoneSurrogate(PAIR_AT_54.slice(0, safeHeadEnd(PAIR_AT_54, 55)))).toBe(false);
		expect(hasLoneSurrogate(PAIR_AT_54.slice(0, 55))).toBe(true);
	});

	it("safeTailStart advances past a low surrogate at a mid-pair tail start", () => {
		expect(safeTailStart(PAIR_AT_54, 55)).toBe(56);
		expect(hasLoneSurrogate(PAIR_AT_54.slice(safeTailStart(PAIR_AT_54, 55)))).toBe(false);
		expect(hasLoneSurrogate(PAIR_AT_54.slice(55))).toBe(true);
	});

	it("leave non-split and string-boundary cuts unchanged", () => {
		expect(safeHeadEnd(PAIR_AT_54, 54)).toBe(54);
		expect(safeTailStart(PAIR_AT_54, 56)).toBe(56);
		expect(safeHeadEnd(PAIR_AT_54, 0)).toBe(0);
		expect(safeTailStart(PAIR_AT_54, PAIR_AT_54.length)).toBe(PAIR_AT_54.length);
	});
});

describe("agent truncateForSummary surrogate-safe head+tail (opt #60)", () => {
	// head = tail = floor(maxChars*0.45); maxChars=100 → head=45, tail=45.
	it("does not emit a lone surrogate when the head cut splits a pair", () => {
		const text = `${"a".repeat(44)}😀${"b".repeat(100)}`; // pair at 44-45, length 146
		const result = truncateForSummary(text, 100);
		expect(hasLoneSurrogate(result)).toBe(false);
		expect(result).toContain("more characters truncated");
	});

	it("does not emit a lone surrogate when the tail cut splits a pair", () => {
		const text = `${"a".repeat(100)}😀${"b".repeat(44)}`; // pair at 100-101, length 146, tail start 101
		const result = truncateForSummary(text, 100);
		expect(hasLoneSurrogate(result)).toBe(false);
	});
});

describe("agent truncateLine surrogate-safe head (opt #60)", () => {
	it("does not emit a lone surrogate when the line cut splits a pair", () => {
		const line = `${"a".repeat(499)}😀`; // length 501, pair at 499-500, default maxChars 500
		const { text, wasTruncated } = truncateLine(line);
		expect(wasTruncated).toBe(true);
		expect(hasLoneSurrogate(text)).toBe(false);
		expect(text.endsWith("... [truncated]")).toBe(true);
	});
});

describe("capToolResultContent surrogate-safe head+tail (opt #60)", () => {
	// capToolResultContent: head = tail = floor(maxChars*0.45). Applied to every tool result block.
	it("does not emit a lone surrogate when the head cut splits a pair", () => {
		const text = `${"a".repeat(44)}😀${"b".repeat(100)}`; // pair at 44-45, length 146
		const content: TextContent[] = [{ type: "text", text }];
		const result = capToolResultContent(content, 100);
		expect(result).toHaveLength(1);
		const out = result[0];
		expect(out.type).toBe("text");
		if (out.type === "text") {
			expect(hasLoneSurrogate(out.text)).toBe(false);
			expect(out.text).toContain("safety cap");
		}
	});

	it("does not emit a lone surrogate when the tail cut splits a pair", () => {
		const text = `${"a".repeat(100)}😀${"b".repeat(44)}`; // pair at 100-101, length 146, tail start 101
		const content: TextContent[] = [{ type: "text", text }];
		const result = capToolResultContent(content, 100);
		expect(result).toHaveLength(1);
		const out = result[0];
		if (out.type === "text") {
			expect(hasLoneSurrogate(out.text)).toBe(false);
		}
	});

	it("leaves a short text block unchanged (no capping, pair preserved)", () => {
		const content: TextContent[] = [{ type: "text", text: "ok 😀 ok" }];
		const result = capToolResultContent(content, 100);
		expect(result).toBe(content); // unchanged reference → no truncation applied
	});
});

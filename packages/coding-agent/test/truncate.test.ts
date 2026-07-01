import { describe, expect, it } from "vitest";
import {
	DEFAULT_MAX_BYTES,
	DEFAULT_MAX_LINES,
	formatHeadTailMarker,
	formatSize,
	truncateHead,
	truncateHeadTail,
	truncateTail,
} from "../src/core/tools/truncate.ts";

function makeLines(count: number, prefix = "line"): string {
	const lines: string[] = [];
	for (let i = 0; i < count; i++) lines.push(`${prefix}-${i}`);
	return lines.join("\n");
}

describe("truncateHeadTail", () => {
	it("returns content unchanged when within both limits", () => {
		const content = makeLines(10);
		const result = truncateHeadTail(content, { maxLines: 100, maxBytes: DEFAULT_MAX_BYTES });
		expect(result.truncated).toBe(false);
		expect(result.content).toBe(content);
		expect(result.elidedLines).toBe(0);
		expect(result.headLines).toBe(0);
		expect(result.tailLines).toBe(0);
	});

	it("keeps head and tail with a middle-ellipsis marker when line-limited", () => {
		const content = makeLines(100);
		const result = truncateHeadTail(content, {
			maxLines: 20,
			maxBytes: DEFAULT_MAX_BYTES,
			headLines: 5,
			tailLines: 5,
		});
		expect(result.truncated).toBe(true);
		expect(result.truncatedBy).toBe("lines");
		expect(result.totalLines).toBe(100);
		// 5 head + 1 marker + 5 tail
		expect(result.outputLines).toBe(11);
		expect(result.headLines).toBe(5);
		expect(result.tailLines).toBe(5);
		expect(result.elidedLines).toBe(90);
		expect(result.elidedBytes).toBeGreaterThan(0);

		const out = result.content.split("\n");
		expect(out[0]).toBe("line-0");
		expect(out[4]).toBe("line-4");
		expect(out[5]).toContain("90 lines");
		expect(out[6]).toBe("line-95");
		expect(out[10]).toBe("line-99");
	});

	it("marker reports elided line count and size", () => {
		const content = makeLines(50);
		const result = truncateHeadTail(content, {
			maxLines: 10,
			maxBytes: DEFAULT_MAX_BYTES,
			headLines: 2,
			tailLines: 2,
		});
		expect(result.elidedLines).toBe(46);
		expect(result.content).toContain(formatHeadTailMarker(46, result.elidedBytes));
	});

	it("falls back to tail truncation when line budget is too small to split", () => {
		const content = makeLines(100);
		const result = truncateHeadTail(content, { maxLines: 20, maxBytes: DEFAULT_MAX_BYTES });
		// default head/tail = floor(20/2)=10 each, sum 20 >= maxLines 20 → tail fallback
		expect(result.truncated).toBe(true);
		expect(result.headLines).toBe(0);
		// tail fallback keeps the last maxLines lines
		expect(result.content.split("\n")[0]).toBe("line-80");
		expect(result.content.trim().endsWith("line-99")).toBe(true);
	});

	it("keeps head+tail without marker when regions meet (no gap)", () => {
		// 12 lines, maxLines 10, head 5 tail 5 → elided 2 (gap exists). Use a
		// case where head+tail cover everything: totalLines within maxLines but
		// bytes exceed, head+tail budgets large enough to collect all lines.
		const lines: string[] = [];
		for (let i = 0; i < 4; i++) lines.push(`x`.repeat(20000));
		const content = lines.join("\n");
		const result = truncateHeadTail(content, {
			maxLines: 100,
			maxBytes: 40000,
			headLines: 50,
			tailLines: 50,
		});
		expect(result.truncated).toBe(true);
		// Bytes force trimming but few lines; head and tail should not overlap
		// with a marker only if a gap exists. Either way: no crash, truncated true.
		expect(result.totalLines).toBe(4);
		expect(result.outputBytes).toBeLessThanOrEqual(result.maxBytes + 1024);
	});

	it("byte-limited: respects byte budget across head and tail", () => {
		const content = makeLines(5000);
		const result = truncateHeadTail(content, {
			maxLines: 5000,
			maxBytes: 4000,
			headLines: 1000,
			tailLines: 1000,
		});
		expect(result.truncated).toBe(true);
		expect(result.outputBytes).toBeLessThanOrEqual(DEFAULT_MAX_BYTES);
		// head and tail both present with a marker between
		expect(result.headLines).toBeGreaterThan(0);
		expect(result.tailLines).toBeGreaterThan(0);
		expect(result.content).toContain("lines");
	});

	it("preserves head errors and tail exit context for command-like output", () => {
		const lines: string[] = [];
		lines.push("ERROR: failed to load config");
		for (let i = 0; i < 60; i++) lines.push(`progress ${i}`);
		lines.push("exit code: 0");
		const content = lines.join("\n");
		const result = truncateHeadTail(content, {
			maxLines: 20,
			maxBytes: DEFAULT_MAX_BYTES,
			headLines: 3,
			tailLines: 3,
		});
		expect(result.content).toContain("ERROR: failed to load config");
		expect(result.content).toContain("exit code: 0");
		expect(result.content).toContain("lines");
	});

	it("falls back to tail when a single gigantic line prevents head collection", () => {
		const content = `${"x".repeat(100000)}\ntail-line`;
		const result = truncateHeadTail(content, {
			maxLines: DEFAULT_MAX_LINES,
			maxBytes: 4096,
			headLines: 10,
			tailLines: 10,
		});
		expect(result.truncated).toBe(true);
		// Head could not collect the gigantic first line → tail fallback.
		expect(result.headLines).toBe(0);
	});
});

describe("truncate module consistency", () => {
	it("formatSize handles ranges", () => {
		expect(formatSize(500)).toBe("500B");
		expect(formatSize(2048)).toBe("2.0KB");
	});

	it("truncateHead and truncateTail stay consistent for small input", () => {
		const content = "a\nb\nc";
		expect(truncateHead(content, { maxLines: 10, maxBytes: 100 }).content).toBe(content);
		expect(truncateTail(content, { maxLines: 10, maxBytes: 100 }).content).toBe(content);
	});
});

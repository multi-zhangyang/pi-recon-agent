/**
 * Shared truncation utilities for tool outputs.
 *
 * Truncation is based on two independent limits - whichever is hit first wins:
 * - Line limit (default: 2000 lines)
 * - Byte limit (default: 50KB)
 *
 * Never returns partial lines (except bash tail truncation edge case).
 */

export const DEFAULT_MAX_LINES = 2000;
export const DEFAULT_MAX_BYTES = 50 * 1024; // 50KB
export const GREP_MAX_LINE_LENGTH = 500; // Max chars per grep match line

export interface TruncationResult {
	/** The truncated content */
	content: string;
	/** Whether truncation occurred */
	truncated: boolean;
	/** Which limit was hit: "lines", "bytes", or null if not truncated */
	truncatedBy: "lines" | "bytes" | null;
	/** Total number of lines in the original content */
	totalLines: number;
	/** Total number of bytes in the original content */
	totalBytes: number;
	/** Number of complete lines in the truncated output */
	outputLines: number;
	/** Number of bytes in the truncated output */
	outputBytes: number;
	/** Whether the last line was partially truncated (only for tail truncation edge case) */
	lastLinePartial: boolean;
	/** Whether the first line exceeded the byte limit (for head truncation) */
	firstLineExceedsLimit: boolean;
	/** The max lines limit that was applied */
	maxLines: number;
	/** The max bytes limit that was applied */
	maxBytes: number;
}

export interface TruncationOptions {
	/** Maximum number of lines (default: 2000) */
	maxLines?: number;
	/** Maximum number of bytes (default: 50KB) */
	maxBytes?: number;
}

function splitLinesForCounting(content: string): string[] {
	if (content.length === 0) {
		return [];
	}
	const lines = content.split("\n");
	if (content.endsWith("\n")) {
		lines.pop();
	}
	return lines;
}

/**
 * Format bytes as human-readable size.
 */
export function formatSize(bytes: number): string {
	if (bytes < 1024) {
		return `${bytes}B`;
	} else if (bytes < 1024 * 1024) {
		return `${(bytes / 1024).toFixed(1)}KB`;
	} else {
		return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
	}
}

/**
 * Truncate content from the head (keep first N lines/bytes).
 * Suitable for file reads where you want to see the beginning.
 *
 * Never returns partial lines. If first line exceeds byte limit,
 * returns empty content with firstLineExceedsLimit=true.
 */
export function truncateHead(content: string, options: TruncationOptions = {}): TruncationResult {
	const maxLines = options.maxLines ?? DEFAULT_MAX_LINES;
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;

	const totalBytes = Buffer.byteLength(content, "utf-8");
	const lines = splitLinesForCounting(content);
	const totalLines = lines.length;

	// Check if no truncation needed
	if (totalLines <= maxLines && totalBytes <= maxBytes) {
		return {
			content,
			truncated: false,
			truncatedBy: null,
			totalLines,
			totalBytes,
			outputLines: totalLines,
			outputBytes: totalBytes,
			lastLinePartial: false,
			firstLineExceedsLimit: false,
			maxLines,
			maxBytes,
		};
	}

	// Check if first line alone exceeds byte limit
	const firstLineBytes = Buffer.byteLength(lines[0], "utf-8");
	if (firstLineBytes > maxBytes) {
		return {
			content: "",
			truncated: true,
			truncatedBy: "bytes",
			totalLines,
			totalBytes,
			outputLines: 0,
			outputBytes: 0,
			lastLinePartial: false,
			firstLineExceedsLimit: true,
			maxLines,
			maxBytes,
		};
	}

	// Collect complete lines that fit
	const outputLinesArr: string[] = [];
	let outputBytesCount = 0;
	let truncatedBy: "lines" | "bytes" = "lines";

	for (let i = 0; i < lines.length && i < maxLines; i++) {
		const line = lines[i];
		const lineBytes = Buffer.byteLength(line, "utf-8") + (i > 0 ? 1 : 0); // +1 for newline

		if (outputBytesCount + lineBytes > maxBytes) {
			truncatedBy = "bytes";
			break;
		}

		outputLinesArr.push(line);
		outputBytesCount += lineBytes;
	}

	// If we exited due to line limit
	if (outputLinesArr.length >= maxLines && outputBytesCount <= maxBytes) {
		truncatedBy = "lines";
	}

	const outputContent = outputLinesArr.join("\n");
	const finalOutputBytes = Buffer.byteLength(outputContent, "utf-8");

	return {
		content: outputContent,
		truncated: true,
		truncatedBy,
		totalLines,
		totalBytes,
		outputLines: outputLinesArr.length,
		outputBytes: finalOutputBytes,
		lastLinePartial: false,
		firstLineExceedsLimit: false,
		maxLines,
		maxBytes,
	};
}

/**
 * Truncate content from the tail (keep last N lines/bytes).
 * Suitable for bash output where you want to see the end (errors, final results).
 *
 * May return partial first line if the last line of original content exceeds byte limit.
 */
export function truncateTail(content: string, options: TruncationOptions = {}): TruncationResult {
	const maxLines = options.maxLines ?? DEFAULT_MAX_LINES;
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;

	const totalBytes = Buffer.byteLength(content, "utf-8");
	const lines = splitLinesForCounting(content);
	const totalLines = lines.length;

	// Check if no truncation needed
	if (totalLines <= maxLines && totalBytes <= maxBytes) {
		return {
			content,
			truncated: false,
			truncatedBy: null,
			totalLines,
			totalBytes,
			outputLines: totalLines,
			outputBytes: totalBytes,
			lastLinePartial: false,
			firstLineExceedsLimit: false,
			maxLines,
			maxBytes,
		};
	}

	// Work backwards from the end
	const outputLinesArr: string[] = [];
	let outputBytesCount = 0;
	let truncatedBy: "lines" | "bytes" = "lines";
	let lastLinePartial = false;

	for (let i = lines.length - 1; i >= 0 && outputLinesArr.length < maxLines; i--) {
		const line = lines[i];
		const lineBytes = Buffer.byteLength(line, "utf-8") + (outputLinesArr.length > 0 ? 1 : 0); // +1 for newline

		if (outputBytesCount + lineBytes > maxBytes) {
			truncatedBy = "bytes";
			// Edge case: if we haven't added ANY lines yet and this line exceeds maxBytes,
			// take the end of the line (partial)
			if (outputLinesArr.length === 0) {
				const truncatedLine = truncateStringToBytesFromEnd(line, maxBytes);
				outputLinesArr.unshift(truncatedLine);
				outputBytesCount = Buffer.byteLength(truncatedLine, "utf-8");
				lastLinePartial = true;
			}
			break;
		}

		outputLinesArr.unshift(line);
		outputBytesCount += lineBytes;
	}

	// If we exited due to line limit
	if (outputLinesArr.length >= maxLines && outputBytesCount <= maxBytes) {
		truncatedBy = "lines";
	}

	const outputContent = outputLinesArr.join("\n");
	const finalOutputBytes = Buffer.byteLength(outputContent, "utf-8");

	return {
		content: outputContent,
		truncated: true,
		truncatedBy,
		totalLines,
		totalBytes,
		outputLines: outputLinesArr.length,
		outputBytes: finalOutputBytes,
		lastLinePartial,
		firstLineExceedsLimit: false,
		maxLines,
		maxBytes,
	};
}

/**
 * Truncate a string to fit within a byte limit (from the end).
 * Handles multi-byte UTF-8 characters correctly.
 */
function truncateStringToBytesFromEnd(str: string, maxBytes: number): string {
	const buf = Buffer.from(str, "utf-8");
	if (buf.length <= maxBytes) {
		return str;
	}

	// Start from the end, skip maxBytes back
	let start = buf.length - maxBytes;

	// Find a valid UTF-8 boundary (start of a character)
	while (start < buf.length && (buf[start] & 0xc0) === 0x80) {
		start++;
	}

	return buf.slice(start).toString("utf-8");
}

/**
 * Adjust a UTF-16 code-unit slice boundary so it does not split a surrogate pair
 * (opt #60). Astral-plane characters (emoji, rare CJK ext B, math symbols) are
 * encoded as a high+low surrogate pair; a slice that lands between the two
 * yields a lone surrogate. JSON.stringify does NOT throw — it emits a `\udXXX`
 * escape, so the corrupted text silently reaches the LLM (and Buffer.from /
 * TextEncoder turn a lone surrogate into U+FFFD). CJK BMP and ASCII are single
 * code units and pass through unchanged.
 */
/**
 * `end` is an EXCLUSIVE upper bound for `slice(0, end)`. If the code unit just
 * before `end` is a high surrogate paired with a low surrogate at `end`, the
 * head would end on a lone high surrogate — back up one so the pair is excluded
 * entirely. Returns a safe `end` ≤ the input.
 */
export function safeHeadEnd(text: string, end: number): number {
	if (end <= 0 || end >= text.length) return end;
	const prev = text.charCodeAt(end - 1);
	if (prev >= 0xd800 && prev <= 0xdbff) {
		const cur = text.charCodeAt(end);
		if (cur >= 0xdc00 && cur <= 0xdfff) return end - 1;
	}
	return end;
}
/**
 * `start` is an INCLUSIVE lower bound for `slice(start)` / a resolved `slice(-n)`.
 * If the code unit just before `start` is a high surrogate paired with a low
 * surrogate at `start`, the tail would begin on a lone low surrogate — advance
 * one so the pair is excluded entirely. Returns a safe `start` ≥ the input.
 */
export function safeTailStart(text: string, start: number): number {
	if (start <= 0 || start >= text.length) return start;
	const prev = text.charCodeAt(start - 1);
	if (prev >= 0xd800 && prev <= 0xdbff) {
		const cur = text.charCodeAt(start);
		if (cur >= 0xdc00 && cur <= 0xdfff) return start + 1;
	}
	return start;
}

/**
 * Truncate a single line to max characters, adding [truncated] suffix.
 * Used for grep match lines.
 */
export function truncateLine(
	line: string,
	maxChars: number = GREP_MAX_LINE_LENGTH,
): { text: string; wasTruncated: boolean } {
	if (line.length <= maxChars) {
		return { text: line, wasTruncated: false };
	}
	return { text: `${line.slice(0, safeHeadEnd(line, maxChars))}... [truncated]`, wasTruncated: true };
}

/**
 * Options for {@link truncateHeadTail}.
 */
export interface HeadTailTruncationOptions extends TruncationOptions {
	/**
	 * Lines to keep from the head. Default: half of `maxLines` (min 10).
	 */
	headLines?: number;
	/**
	 * Lines to keep from the tail. Default: half of `maxLines` (min 10).
	 */
	tailLines?: number;
}

/**
 * Result of {@link truncateHeadTail}.
 */
export interface HeadTailTruncationResult extends TruncationResult {
	/** Lines kept from the head (0 when truncated=false or fallback to tail). */
	headLines: number;
	/** Lines kept from the tail. */
	tailLines: number;
	/** Lines elided between head and tail. */
	elidedLines: number;
	/** Approximate bytes elided between head and tail. */
	elidedBytes: number;
}

/** Bytes reserved for the middle-ellipsis marker line. */
const HEAD_TAIL_MARKER_RESERVE = 128;

/**
 * Build the middle-ellipsis marker line.
 */
export function formatHeadTailMarker(elidedLines: number, elidedBytes: number): string {
	return `... [${elidedLines} lines, ${formatSize(elidedBytes)} elided] ...`;
}

/**
 * Truncate content keeping both the head AND the tail, with a middle-ellipsis
 * marker line reporting how much was elided.
 *
 * This is the modern code-agent strategy for command output: keep the head
 * (early errors/banner) AND the tail (final result/exit context) so neither is
 * lost when output exceeds the budget. {@link truncateTail} keeps only the tail;
 * {@link truncateHead} keeps only the head.
 *
 * The byte budget is split evenly between head and tail (minus a small reserve
 * for the marker). Falls back to {@link truncateTail} when the line budget is
 * too small to split or when either region would collect nothing (e.g. a single
 * gigantic line), preserving the safe edge-case behavior of tail truncation.
 */
export function truncateHeadTail(content: string, options: HeadTailTruncationOptions = {}): HeadTailTruncationResult {
	const maxLines = options.maxLines ?? DEFAULT_MAX_LINES;
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;

	const totalBytes = Buffer.byteLength(content, "utf-8");
	const lines = splitLinesForCounting(content);
	const totalLines = lines.length;

	// No truncation needed.
	if (totalLines <= maxLines && totalBytes <= maxBytes) {
		return {
			content,
			truncated: false,
			truncatedBy: null,
			totalLines,
			totalBytes,
			outputLines: totalLines,
			outputBytes: totalBytes,
			lastLinePartial: false,
			firstLineExceedsLimit: false,
			maxLines,
			maxBytes,
			headLines: 0,
			tailLines: 0,
			elidedLines: 0,
			elidedBytes: 0,
		};
	}

	const defaultHalf = Math.max(10, Math.floor(maxLines / 2));
	const headLinesCap = options.headLines ?? defaultHalf;
	const tailLinesCap = options.tailLines ?? defaultHalf;

	// Line budget too small to split meaningfully → tail truncation keeps the
	// most decision-relevant (exit context) slice.
	if (headLinesCap < 1 || tailLinesCap < 1 || headLinesCap + tailLinesCap >= maxLines) {
		const fallback = truncateTail(content, { maxLines, maxBytes });
		return {
			...fallback,
			headLines: 0,
			tailLines: fallback.outputLines,
			elidedLines: Math.max(0, totalLines - fallback.outputLines),
			elidedBytes: Math.max(0, totalBytes - fallback.outputBytes),
		};
	}

	const headBytesBudget = Math.floor(maxBytes / 2);
	const tailBytesBudget = Math.max(0, maxBytes - headBytesBudget - HEAD_TAIL_MARKER_RESERVE);

	// Collect head lines forward.
	const headArr: string[] = [];
	let headBytes = 0;
	for (let i = 0; i < lines.length && headArr.length < headLinesCap; i++) {
		const line = lines[i];
		const lineBytes = Buffer.byteLength(line, "utf-8") + (i > 0 ? 1 : 0);
		if (headBytes + lineBytes > headBytesBudget) break;
		headArr.push(line);
		headBytes += lineBytes;
	}

	const headEndIdx = headArr.length;

	// Collect tail lines backward, never overlapping the head region.
	const tailArr: string[] = [];
	let tailBytes = 0;
	for (let i = lines.length - 1; i >= headEndIdx && tailArr.length < tailLinesCap; i--) {
		const line = lines[i];
		const lineBytes = Buffer.byteLength(line, "utf-8") + (tailArr.length > 0 ? 1 : 0);
		if (tailBytes + lineBytes > tailBytesBudget) break;
		tailArr.unshift(line);
		tailBytes += lineBytes;
	}

	// Degenerate: head or tail collected nothing (e.g. one gigantic line) → tail
	// fallback preserves the existing safe edge-case behavior.
	if (headArr.length === 0 || tailArr.length === 0) {
		const fallback = truncateTail(content, { maxLines, maxBytes });
		return {
			...fallback,
			headLines: 0,
			tailLines: fallback.outputLines,
			elidedLines: Math.max(0, totalLines - fallback.outputLines),
			elidedBytes: Math.max(0, totalBytes - fallback.outputBytes),
		};
	}

	const tailStartIdx = lines.length - tailArr.length;
	const elidedLines = Math.max(0, tailStartIdx - headEndIdx);
	const elidedBytes = Math.max(0, totalBytes - headBytes - tailBytes);

	// If head and tail meet with no gap, no marker is needed.
	if (elidedLines <= 0) {
		const combined = headArr.concat(tailArr).join("\n");
		const combinedBytes = Buffer.byteLength(combined, "utf-8");
		return {
			content: combined,
			truncated: true,
			truncatedBy: totalBytes > maxBytes ? "bytes" : "lines",
			totalLines,
			totalBytes,
			outputLines: headArr.length + tailArr.length,
			outputBytes: combinedBytes,
			lastLinePartial: false,
			firstLineExceedsLimit: false,
			maxLines,
			maxBytes,
			headLines: headArr.length,
			tailLines: tailArr.length,
			elidedLines: 0,
			elidedBytes: 0,
		};
	}

	const marker = formatHeadTailMarker(elidedLines, elidedBytes);
	const outputContent = `${headArr.join("\n")}\n${marker}\n${tailArr.join("\n")}`;
	const finalOutputBytes = Buffer.byteLength(outputContent, "utf-8");

	return {
		content: outputContent,
		truncated: true,
		truncatedBy: totalLines > maxLines ? "lines" : "bytes",
		totalLines,
		totalBytes,
		outputLines: headArr.length + 1 + tailArr.length,
		outputBytes: finalOutputBytes,
		lastLinePartial: false,
		firstLineExceedsLimit: false,
		maxLines,
		maxBytes,
		headLines: headArr.length,
		tailLines: tailArr.length,
		elidedLines,
		elidedBytes,
	};
}

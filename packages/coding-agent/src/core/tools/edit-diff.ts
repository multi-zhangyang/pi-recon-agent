/**
 * Shared diff computation utilities for the edit tool.
 * Used by both edit.ts (for execution) and tool-execution.ts (for preview rendering).
 */

import * as Diff from "diff";
import { constants } from "fs";
import { access, readFile, stat } from "fs/promises";
import { resolveToCwd } from "./path-utils.ts";

export function detectLineEnding(content: string): "\r\n" | "\n" {
	const crlfIdx = content.indexOf("\r\n");
	const lfIdx = content.indexOf("\n");
	if (lfIdx === -1) return "\n";
	if (crlfIdx === -1) return "\n";
	return crlfIdx < lfIdx ? "\r\n" : "\n";
}

export function normalizeToLF(text: string): string {
	return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

export function restoreLineEndings(text: string, ending: "\r\n" | "\n"): string {
	return ending === "\r\n" ? text.replace(/\n/g, "\r\n") : text;
}

/**
 * Normalize text for fuzzy matching. Applies progressive transformations:
 * - Strip trailing whitespace from each line
 * - Normalize smart quotes to ASCII equivalents
 * - Normalize Unicode dashes/hyphens to ASCII hyphen
 * - Normalize special Unicode spaces to regular space
 */
export function normalizeForFuzzyMatch(text: string): string {
	return (
		text
			.normalize("NFKC")
			// Strip trailing whitespace per line
			.split("\n")
			.map((line) => line.trimEnd())
			.join("\n")
			// Smart single quotes → '
			.replace(/[\u2018\u2019\u201A\u201B]/g, "'")
			// Smart double quotes → "
			.replace(/[\u201C\u201D\u201E\u201F]/g, '"')
			// Various dashes/hyphens → -
			// U+2010 hyphen, U+2011 non-breaking hyphen, U+2012 figure dash,
			// U+2013 en-dash, U+2014 em-dash, U+2015 horizontal bar, U+2212 minus
			.replace(/[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]/g, "-")
			// Special spaces → regular space
			// U+00A0 NBSP, U+2002-U+200A various spaces, U+202F narrow NBSP,
			// U+205F medium math space, U+3000 ideographic space
			.replace(/[\u00A0\u2002-\u200A\u202F\u205F\u3000]/g, " ")
	);
}

export interface FuzzyMatchResult {
	/** Whether a match was found */
	found: boolean;
	/** The index where the match starts (in the content that should be used for replacement) */
	index: number;
	/** Length of the matched text */
	matchLength: number;
	/** Whether fuzzy matching was used (false = exact match) */
	usedFuzzyMatch: boolean;
	/**
	 * The content to use for replacement operations.
	 * When exact match: original content. When fuzzy match: normalized content.
	 */
	contentForReplacement: string;
}

export interface Edit {
	oldText: string;
	newText: string;
}

interface MatchedEdit {
	editIndex: number;
	matchIndex: number;
	matchLength: number;
	newText: string;
}

export interface AppliedEditsResult {
	baseContent: string;
	newContent: string;
}

/**
 * Find oldText in content, trying exact match first, then fuzzy match.
 * When fuzzy matching is used, the returned contentForReplacement is the
 * fuzzy-normalized version of the content (trailing whitespace stripped,
 * Unicode quotes/dashes normalized to ASCII).
 */
export function fuzzyFindText(content: string, oldText: string): FuzzyMatchResult {
	// Try exact match first
	const exactIndex = content.indexOf(oldText);
	if (exactIndex !== -1) {
		return {
			found: true,
			index: exactIndex,
			matchLength: oldText.length,
			usedFuzzyMatch: false,
			contentForReplacement: content,
		};
	}

	// Try fuzzy match - work entirely in normalized space
	const fuzzyContent = normalizeForFuzzyMatch(content);
	const fuzzyOldText = normalizeForFuzzyMatch(oldText);
	const fuzzyIndex = fuzzyContent.indexOf(fuzzyOldText);

	if (fuzzyIndex === -1) {
		return {
			found: false,
			index: -1,
			matchLength: 0,
			usedFuzzyMatch: false,
			contentForReplacement: content,
		};
	}

	// When fuzzy matching, we work in the normalized space for replacement.
	// This means the output will have normalized whitespace/quotes/dashes,
	// which is acceptable since we're fixing minor formatting differences anyway.
	return {
		found: true,
		index: fuzzyIndex,
		matchLength: fuzzyOldText.length,
		usedFuzzyMatch: true,
		contentForReplacement: fuzzyContent,
	};
}

/** Strip UTF-8 BOM if present, return both the BOM (if any) and the text without it */
export function stripBom(content: string): { bom: string; text: string } {
	return content.startsWith("\uFEFF") ? { bom: "\uFEFF", text: content.slice(1) } : { bom: "", text: content };
}

function countOccurrences(content: string, oldText: string): number {
	const fuzzyContent = normalizeForFuzzyMatch(content);
	const fuzzyOldText = normalizeForFuzzyMatch(oldText);
	return fuzzyContent.split(fuzzyOldText).length - 1;
}

function getNotFoundError(path: string, editIndex: number, totalEdits: number, hint = ""): Error {
	const suffix = hint ? `${hint}` : "";
	if (totalEdits === 1) {
		return new Error(
			`Could not find the exact text in ${path}. The old text must match exactly including all whitespace and newlines.${suffix}`,
		);
	}
	return new Error(
		`Could not find edits[${editIndex}] in ${path}. The oldText must match exactly including all whitespace and newlines.${suffix}`,
	);
}

/**
 * Build an actionable hint for the not-found case by locating the closest
 * matching line of `oldText` in `content`. Modern edit tools point the model at
 * the line where divergence starts, name the likely cause (a later line
 * differs, trailing whitespace/unicode, or indentation), AND embed a small
 * snippet of the actual surrounding lines so the model can copy the exact text
 * and retry immediately — without a separate read round-trip.
 *
 * Returns "" when no usable anchor line is found.
 */
export function getNotFoundHint(content: string, oldText: string): string {
	const oldLines = oldText.split("\n");
	// Pick up to a few substantial anchor lines (trimmed length >= 4), in order.
	const anchors: { raw: string; trimmed: string }[] = [];
	for (const raw of oldLines) {
		const trimmed = raw.trim();
		if (trimmed.length >= 4) {
			anchors.push({ raw, trimmed });
			if (anchors.length >= 3) break;
		}
	}
	if (anchors.length === 0) return "";

	const contentLines = content.split("\n");
	const normContentLines = contentLines.map((l) => normalizeForFuzzyMatch(l));

	for (const anchor of anchors) {
		let lineNo = 0;
		let cause = "";
		// 1. Exact line match: the block diverges somewhere after this line.
		lineNo = contentLines.indexOf(anchor.raw) + 1;
		if (lineNo > 0) {
			cause = "the full block did not match — a later line or trailing whitespace likely differs";
		} else {
			// 2. Normalized match: trailing whitespace / unicode quotes/dashes differ.
			const normAnchor = normalizeForFuzzyMatch(anchor.raw);
			lineNo = normContentLines.indexOf(normAnchor) + 1;
			if (lineNo > 0) {
				cause =
					"the full block did not match — your oldText may use different trailing whitespace or unicode quotes/dashes than the file";
			} else {
				// 3. Trimmed match: leading indentation differs.
				lineNo = contentLines.findIndex((l) => l.trim() === anchor.trimmed) + 1;
				if (lineNo > 0) {
					cause = "the full block did not match — your oldText indentation differs from the file";
				}
			}
		}
		if (lineNo > 0) {
			return formatNotFoundHint(lineNo, cause, contentLines);
		}
	}
	return "";
}

/**
 * Format the not-found hint tail: a cause sentence plus a bounded snippet of the
 * real file lines around the located anchor line. The snippet lets the model
 * copy the exact text and retry without a read round-trip. Bounded by radius
 * (lines) and a hard char cap so a pathological long line can't bloat the error.
 */
function formatNotFoundHint(lineNo: number, cause: string, contentLines: string[]): string {
	const SNIPPET_RADIUS = 2;
	const SNIPPET_MAX_CHARS = 600;
	const start = Math.max(0, lineNo - 1 - SNIPPET_RADIUS);
	const end = Math.min(contentLines.length, lineNo - 1 + SNIPPET_RADIUS + 1);
	let snippet = contentLines.slice(start, end).join("\n");
	let truncNote = "";
	if (snippet.length > SNIPPET_MAX_CHARS) {
		snippet = snippet.slice(0, SNIPPET_MAX_CHARS);
		truncNote = " (truncated)";
	}
	return ` The first matching line of oldText is at line ${lineNo}; ${cause}. Surrounding lines${truncNote}:\n\`\`\`\n${snippet}\n\`\`\`\nRe-read around line ${lineNo} and retry with the exact text.`;
}

function getDuplicateError(path: string, editIndex: number, totalEdits: number, occurrences: number): Error {
	if (totalEdits === 1) {
		return new Error(
			`Found ${occurrences} occurrences of the text in ${path}. The text must be unique. Please provide more context to make it unique.`,
		);
	}
	return new Error(
		`Found ${occurrences} occurrences of edits[${editIndex}] in ${path}. Each oldText must be unique. Please provide more context to make it unique.`,
	);
}

function getEmptyOldTextError(path: string, editIndex: number, totalEdits: number): Error {
	if (totalEdits === 1) {
		return new Error(`oldText must not be empty in ${path}.`);
	}
	return new Error(`edits[${editIndex}].oldText must not be empty in ${path}.`);
}

function getNoChangeError(path: string, totalEdits: number): Error {
	if (totalEdits === 1) {
		return new Error(
			`No changes made to ${path}. The replacement produced identical content. This might indicate an issue with special characters or the text not existing as expected.`,
		);
	}
	return new Error(`No changes made to ${path}. The replacements produced identical content.`);
}

/**
 * Build a position map from the fuzzy-normalized form of `normalizedContent`
 * back to offsets in `normalizedContent`, so a match found in fuzzy space can be
 * spliced into the ORIGINAL content (preserving every byte outside the matched
 * region). Returns null when an offset-identity map is unsound.
 *
 * normalizeForFuzzyMatch composes: (1) NFKC, (2) per-line trimEnd, (3) several
 * 1:1 character replacements (smart quotes/dashes/special spaces → ASCII).
 * The 1:1 replacements preserve length and offsets, so they don't affect the
 * map. trimEnd removes trailing whitespace per line (length-changing but the
 * kept text is a prefix of each line, so positions map forward directly). NFKC
 * can change length (ligatures → multi-char, fullwidth → ASCII, combining
 * sequences composing); when it does, a simple identity offset map is unsound,
 * so we return null and the caller falls back to the legacy whole-file-normalize
 * path (rare for source code — NFKC is length-preserving for plain ASCII and
 * the smart-quote/dash/special-space cases the fuzzy path targets).
 */
function buildFuzzyOffsetMap(normalizedContent: string): { fuzzyContent: string; fuzzyToOriginal: number[] } | null {
	const nfkc = normalizedContent.normalize("NFKC");
	if (nfkc.length !== normalizedContent.length) {
		return null;
	}
	const lines = nfkc.split("\n");
	const fuzzyParts: string[] = [];
	// fuzzyToOriginal[i] = offset in normalizedContent (== nfkc here) where
	// fuzzyContent[i] starts. Length is fuzzyContent.length + 1 so a range
	// [s, e) maps to [fuzzyToOriginal[s], fuzzyToOriginal[e]).
	const fuzzyToOriginal: number[] = [];
	let offset = 0;
	for (let li = 0; li < lines.length; li++) {
		const line = lines[li];
		const kept = line.trimEnd();
		// trimEnd only removes a trailing suffix, so kept is a prefix of line
		// and kept[i] === line[i] for i < kept.length.
		for (let i = 0; i < kept.length; i++) {
			fuzzyToOriginal.push(offset + i);
			fuzzyParts.push(line[i]);
		}
		if (li < lines.length - 1) {
			// The "\n" separator is kept (it is not trailing whitespace); it
			// sits at offset + line.length in the original.
			fuzzyToOriginal.push(offset + line.length);
			fuzzyParts.push("\n");
			offset += line.length + 1;
		} else {
			offset += line.length;
		}
	}
	fuzzyToOriginal.push(offset);
	// Apply the 1:1 character replacements. They swap single chars for single
	// chars, so positions (and the map) are unchanged. Mirrors
	// normalizeForFuzzyMatch's replacements verbatim.
	let fuzzyContent = fuzzyParts.join("");
	fuzzyContent = fuzzyContent
		.replace(/[\u2018\u2019\u201A\u201B]/g, "'")
		.replace(/[\u201C\u201D\u201E\u201F]/g, '"')
		.replace(/[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]/g, "-")
		.replace(/[\u00A0\u2002-\u200A\u202F\u205F\u3000]/g, " ");
	return { fuzzyContent, fuzzyToOriginal };
}

/**
 * Apply one or more exact-text replacements to LF-normalized content.
 *
 * Each edit is matched against the ORIGINAL content (exact match first, then a
 * fuzzy match that tolerates trailing-whitespace and smart-quote/dash/space
 * drift). When a fuzzy match is needed, only the MATCHED REGION is taken in
 * fuzzy-normalized space and mapped back to original offsets via
 * {@link buildFuzzyOffsetMap}; the replacement is spliced into the original
 * content so every line outside the match is preserved byte-for-byte. Previously
 * ANY fuzzy edit rewrote the ENTIRE file in fuzzy-normalized space (trailing
 * whitespace stripped, unicode normalized everywhere) — a silent whole-file
 * reformat that also broke a second exact edit against the normalized base.
 *
 * `baseContent` is the original (un-reformatted) content, so the generated diff
 * shows only the real edits, not a whole-file reformat. When NFKC changes the
 * content length (rare), the offset map is unsound and we fall back to the
 * legacy whole-file-normalize path (no regression — just no byte-preservation
 * for that rare case).
 */
export function applyEditsToNormalizedContent(
	normalizedContent: string,
	edits: Edit[],
	path: string,
): AppliedEditsResult {
	const normalizedEdits = edits.map((edit) => ({
		oldText: normalizeToLF(edit.oldText),
		newText: normalizeToLF(edit.newText),
	}));

	for (let i = 0; i < normalizedEdits.length; i++) {
		if (normalizedEdits[i].oldText.length === 0) {
			throw getEmptyOldTextError(path, i, normalizedEdits.length);
		}
	}

	// First pass: exact-match every edit against the original content. If all
	// edits are exact and unique, we never need fuzzy normalization at all.
	const matchedEdits: MatchedEdit[] = [];
	const needsFuzzy: boolean[] = new Array(normalizedEdits.length).fill(false);
	for (let i = 0; i < normalizedEdits.length; i++) {
		const oldText = normalizedEdits[i].oldText;
		const idx = normalizedContent.indexOf(oldText);
		if (idx !== -1) {
			const occurrences = normalizedContent.split(oldText).length - 1;
			if (occurrences > 1) {
				throw getDuplicateError(path, i, normalizedEdits.length, occurrences);
			}
			matchedEdits.push({
				editIndex: i,
				matchIndex: idx,
				matchLength: oldText.length,
				newText: normalizedEdits[i].newText,
			});
		} else {
			needsFuzzy[i] = true;
		}
	}

	if (matchedEdits.length < normalizedEdits.length) {
		// At least one edit needs fuzzy matching. Build the offset map once.
		// If NFKC changed the content length, fall back to the legacy path.
		const map = buildFuzzyOffsetMap(normalizedContent);
		if (map === null) {
			return applyEditsLegacy(normalizedContent, normalizedEdits, path);
		}
		const { fuzzyContent, fuzzyToOriginal } = map;
		for (let i = 0; i < normalizedEdits.length; i++) {
			if (!needsFuzzy[i]) continue;
			const edit = normalizedEdits[i];
			const fuzzyOldText = normalizeForFuzzyMatch(edit.oldText);
			const fidx = fuzzyContent.indexOf(fuzzyOldText);
			if (fidx === -1) {
				throw getNotFoundError(path, i, normalizedEdits.length, getNotFoundHint(normalizedContent, edit.oldText));
			}
			const occurrences = fuzzyContent.split(fuzzyOldText).length - 1;
			if (occurrences > 1) {
				throw getDuplicateError(path, i, normalizedEdits.length, occurrences);
			}
			// Map the fuzzy match range [fidx, fidx + fuzzyOldText.length) back
			// to original-content offsets and splice there. The END is one past
			// the last MATCHED char (fuzzyToOriginal[last] + 1), NOT the position
			// of the next fuzzy char: when the match ends at a line boundary, the
			// next fuzzy char is the "\n" whose original offset sits PAST the
			// trailing whitespace stripped from that line, so using it would
			// over-extend the region and consume the edited line's trailing
			// whitespace (or, at EOF, swallow the final newline). Because the map
			// is only built when NFKC preserved the content length (identity char
			// correspondence), each fuzzy char is exactly one original char, so
			// +1 is the correct end offset.
			const lastFuzzyPos = fidx + fuzzyOldText.length - 1;
			const startOrig = fuzzyToOriginal[fidx];
			const endOrig = fuzzyToOriginal[lastFuzzyPos] + 1;
			matchedEdits.push({
				editIndex: i,
				matchIndex: startOrig,
				matchLength: endOrig - startOrig,
				newText: edit.newText,
			});
		}
	}

	matchedEdits.sort((a, b) => a.matchIndex - b.matchIndex);
	for (let i = 1; i < matchedEdits.length; i++) {
		const previous = matchedEdits[i - 1];
		const current = matchedEdits[i];
		if (previous.matchIndex + previous.matchLength > current.matchIndex) {
			throw new Error(
				`edits[${previous.editIndex}] and edits[${current.editIndex}] overlap in ${path}. Merge them into one edit or target disjoint regions.`,
			);
		}
	}

	// Splice replacements into the ORIGINAL content (not a normalized copy) so
	// every line outside a matched region is preserved byte-for-byte.
	let newContent = normalizedContent;
	for (let i = matchedEdits.length - 1; i >= 0; i--) {
		const edit = matchedEdits[i];
		newContent =
			newContent.substring(0, edit.matchIndex) +
			edit.newText +
			newContent.substring(edit.matchIndex + edit.matchLength);
	}

	if (normalizedContent === newContent) {
		throw getNoChangeError(path, normalizedEdits.length);
	}

	return { baseContent: normalizedContent, newContent };
}

/**
 * Legacy whole-file-normalize path. Used only when {@link buildFuzzyOffsetMap}
 * returns null (NFKC changed the content length, making the offset-identity map
 * unsound). This is the pre-F2 behavior: when any edit needs fuzzy matching,
 * the entire file is rewritten in fuzzy-normalized space. Preserved verbatim so
 * the rare NFKC-length-changing case does not regress.
 */
function applyEditsLegacy(normalizedContent: string, normalizedEdits: Edit[], path: string): AppliedEditsResult {
	const initialMatches = normalizedEdits.map((edit) => fuzzyFindText(normalizedContent, edit.oldText));
	const baseContent = initialMatches.some((match) => match.usedFuzzyMatch)
		? normalizeForFuzzyMatch(normalizedContent)
		: normalizedContent;

	const matchedEdits: MatchedEdit[] = [];
	for (let i = 0; i < normalizedEdits.length; i++) {
		const edit = normalizedEdits[i];
		const matchResult = fuzzyFindText(baseContent, edit.oldText);
		if (!matchResult.found) {
			throw getNotFoundError(path, i, normalizedEdits.length, getNotFoundHint(baseContent, edit.oldText));
		}

		const occurrences = countOccurrences(baseContent, edit.oldText);
		if (occurrences > 1) {
			throw getDuplicateError(path, i, normalizedEdits.length, occurrences);
		}

		matchedEdits.push({
			editIndex: i,
			matchIndex: matchResult.index,
			matchLength: matchResult.matchLength,
			newText: edit.newText,
		});
	}

	matchedEdits.sort((a, b) => a.matchIndex - b.matchIndex);
	for (let i = 1; i < matchedEdits.length; i++) {
		const previous = matchedEdits[i - 1];
		const current = matchedEdits[i];
		if (previous.matchIndex + previous.matchLength > current.matchIndex) {
			throw new Error(
				`edits[${previous.editIndex}] and edits[${current.editIndex}] overlap in ${path}. Merge them into one edit or target disjoint regions.`,
			);
		}
	}

	let newContent = baseContent;
	for (let i = matchedEdits.length - 1; i >= 0; i--) {
		const edit = matchedEdits[i];
		newContent =
			newContent.substring(0, edit.matchIndex) +
			edit.newText +
			newContent.substring(edit.matchIndex + edit.matchLength);
	}

	if (baseContent === newContent) {
		throw getNoChangeError(path, normalizedEdits.length);
	}

	return { baseContent, newContent };
}

/** Generate a standard unified patch. */
export function generateUnifiedPatch(path: string, oldContent: string, newContent: string, contextLines = 4): string {
	return Diff.createTwoFilesPatch(path, path, oldContent, newContent, undefined, undefined, {
		context: contextLines,
		headerOptions: Diff.FILE_HEADERS_ONLY,
	});
}

/**
 * Generate a display-oriented diff string with line numbers and context.
 * Returns both the diff string and the first changed line number (in the new file).
 */
export function generateDiffString(
	oldContent: string,
	newContent: string,
	contextLines = 4,
): { diff: string; firstChangedLine: number | undefined } {
	const parts = Diff.diffLines(oldContent, newContent);
	const output: string[] = [];

	const oldLines = oldContent.split("\n");
	const newLines = newContent.split("\n");
	const maxLineNum = Math.max(oldLines.length, newLines.length);
	const lineNumWidth = String(maxLineNum).length;

	let oldLineNum = 1;
	let newLineNum = 1;
	let lastWasChange = false;
	let firstChangedLine: number | undefined;

	for (let i = 0; i < parts.length; i++) {
		const part = parts[i];
		const raw = part.value.split("\n");
		if (raw[raw.length - 1] === "") {
			raw.pop();
		}

		if (part.added || part.removed) {
			// Capture the first changed line (in the new file)
			if (firstChangedLine === undefined) {
				firstChangedLine = newLineNum;
			}

			// Show the change
			for (const line of raw) {
				if (part.added) {
					const lineNum = String(newLineNum).padStart(lineNumWidth, " ");
					output.push(`+${lineNum} ${line}`);
					newLineNum++;
				} else {
					// removed
					const lineNum = String(oldLineNum).padStart(lineNumWidth, " ");
					output.push(`-${lineNum} ${line}`);
					oldLineNum++;
				}
			}
			lastWasChange = true;
		} else {
			// Context lines - only show a few before/after changes
			const nextPartIsChange = i < parts.length - 1 && (parts[i + 1].added || parts[i + 1].removed);
			const hasLeadingChange = lastWasChange;
			const hasTrailingChange = nextPartIsChange;

			if (hasLeadingChange && hasTrailingChange) {
				if (raw.length <= contextLines * 2) {
					for (const line of raw) {
						const lineNum = String(oldLineNum).padStart(lineNumWidth, " ");
						output.push(` ${lineNum} ${line}`);
						oldLineNum++;
						newLineNum++;
					}
				} else {
					const leadingLines = raw.slice(0, contextLines);
					const trailingLines = raw.slice(raw.length - contextLines);
					const skippedLines = raw.length - leadingLines.length - trailingLines.length;

					for (const line of leadingLines) {
						const lineNum = String(oldLineNum).padStart(lineNumWidth, " ");
						output.push(` ${lineNum} ${line}`);
						oldLineNum++;
						newLineNum++;
					}

					output.push(` ${"".padStart(lineNumWidth, " ")} ...`);
					oldLineNum += skippedLines;
					newLineNum += skippedLines;

					for (const line of trailingLines) {
						const lineNum = String(oldLineNum).padStart(lineNumWidth, " ");
						output.push(` ${lineNum} ${line}`);
						oldLineNum++;
						newLineNum++;
					}
				}
			} else if (hasLeadingChange) {
				const shownLines = raw.slice(0, contextLines);
				const skippedLines = raw.length - shownLines.length;

				for (const line of shownLines) {
					const lineNum = String(oldLineNum).padStart(lineNumWidth, " ");
					output.push(` ${lineNum} ${line}`);
					oldLineNum++;
					newLineNum++;
				}

				if (skippedLines > 0) {
					output.push(` ${"".padStart(lineNumWidth, " ")} ...`);
					oldLineNum += skippedLines;
					newLineNum += skippedLines;
				}
			} else if (hasTrailingChange) {
				const skippedLines = Math.max(0, raw.length - contextLines);
				if (skippedLines > 0) {
					output.push(` ${"".padStart(lineNumWidth, " ")} ...`);
					oldLineNum += skippedLines;
					newLineNum += skippedLines;
				}

				for (const line of raw.slice(skippedLines)) {
					const lineNum = String(oldLineNum).padStart(lineNumWidth, " ");
					output.push(` ${lineNum} ${line}`);
					oldLineNum++;
					newLineNum++;
				}
			} else {
				// Skip these context lines entirely
				oldLineNum += raw.length;
				newLineNum += raw.length;
			}

			lastWasChange = false;
		}
	}

	return { diff: output.join("\n"), firstChangedLine };
}

export interface EditDiffResult {
	diff: string;
	firstChangedLine: number | undefined;
}

export interface EditDiffError {
	error: string;
}

/**
 * Compute the diff for one or more edit operations without applying them.
 * Used for preview rendering in the TUI before the tool executes.
 */
export async function computeEditsDiff(
	path: string,
	edits: Edit[],
	cwd: string,
): Promise<EditDiffResult | EditDiffError> {
	const absolutePath = resolveToCwd(path, cwd);

	try {
		// Check if file exists and is readable
		try {
			await access(absolutePath, constants.R_OK);
			const fileStat = await stat(absolutePath);
			if ((fileStat.mode & 0o444) === 0) {
				const error = new Error("Permission denied") as NodeJS.ErrnoException;
				error.code = "EACCES";
				throw error;
			}
			// Reject non-regular files BEFORE readFile. `access` only checks mode
			// bits, so a FIFO/named pipe (or a device/socket) passes access — but
			// readFile on a FIFO blocks forever waiting for a writer → this preview
			// promise (fire-and-forget from edit.ts renderCall) hangs permanently.
			// Same guard as the read tool's opt #30 and the edit execute path.
			if (!fileStat.isFile()) {
				if (fileStat.isDirectory()) {
					return { error: `Could not edit file: ${path}. ${path} is a directory, not a file.` };
				}
				return {
					error: `Could not edit file: ${path}. ${path} is not a regular file (it is a device, FIFO, or socket). The edit tool cannot edit a special file — use bash instead.`,
				};
			}
		} catch (error: unknown) {
			// ENOENT: mirror the edit execute path's hint so the preview shows the
			// same actionable "use write" message the real edit would surface.
			if (error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT") {
				return {
					error: `Could not edit file: ${path}. Error code: ENOENT. ${path} does not exist. Use the write tool to create it, e.g. write ${path} with the full content.`,
				};
			}
			const errorMessage = error instanceof Error && "code" in error ? `Error code: ${error.code}` : String(error);
			return { error: `Could not edit file: ${path}. ${errorMessage}.` };
		}

		// Read the file
		const rawContent = await readFile(absolutePath, "utf-8");

		// Strip BOM before matching (LLM won't include invisible BOM in oldText)
		const { text: content } = stripBom(rawContent);
		const normalizedContent = normalizeToLF(content);
		const { baseContent, newContent } = applyEditsToNormalizedContent(normalizedContent, edits, path);

		// Generate the diff
		return generateDiffString(baseContent, newContent);
	} catch (err) {
		return { error: err instanceof Error ? err.message : String(err) };
	}
}

/**
 * Compute the diff for a single edit operation without applying it.
 * Kept as a convenience wrapper for single-edit callers.
 */
export async function computeEditDiff(
	path: string,
	oldText: string,
	newText: string,
	cwd: string,
): Promise<EditDiffResult | EditDiffError> {
	return computeEditsDiff(path, [{ oldText, newText }], cwd);
}

/**
 * Process @file CLI arguments into text content and image attachments
 */

import { access, open, readFile, stat } from "node:fs/promises";
import type { ImageContent } from "@pi-recon/repi-ai";
import chalk from "chalk";
import { resolve } from "path";
import { resolveReadPath } from "../core/tools/path-utils.ts";
import { formatSize } from "../core/tools/truncate.ts";
import { formatDimensionNote, resizeImage } from "../utils/image-resize.ts";
import { detectSupportedImageMimeTypeFromFile } from "../utils/mime.ts";

export interface ProcessedFiles {
	text: string;
	images: ImageContent[];
}

export interface ProcessFileOptions {
	/** Whether to auto-resize images to 2000x2000 max. Default: true */
	autoResizeImages?: boolean;
}

// opt #168: @file args inline the WHOLE file into the prompt (text branch) or
// load it into memory (image branch) with no upper bound — a multi-GB @file
// OOMs the process AND blows the model's token budget. Stat-size guard BEFORE
// readFile, reusing the SHARED REPI_READ_TEXT_FILE_MAX_BYTES knob (default
// 16 MB, 0 disables) so @file honors the same cap as the read tool (#34) and
// the repi readTextFile path. Consistent with opt #3 head+tail truncation and
// opt #15 tool-result cap. Text oversize → bounded head+tail read (open+read
// at offsets, never readFile-whole) with a middle-ellipsis marker; image
// oversize → refuse with a resize hint (binary image bytes can't be truncated
// meaningfully).
const DEFAULT_ATFILE_MAX_BYTES = 16 * 1024 * 1024;
function resolveAtFileMaxBytes(): number {
	const raw = process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
	if (raw !== undefined && raw.trim() !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed) && parsed >= 0) return Math.floor(parsed);
	}
	return DEFAULT_ATFILE_MAX_BYTES;
}

/**
 * Bounded head+tail read for an oversized text @file. Opens the file and reads
 * only the head and tail byte ranges (never readFile-whole), joining them with
 * a middle-ellipsis marker that reports the elided size. Mirrors the head+tail
 * doctrine of opt #3 / opt #15 but is byte-oriented (the inlined @file content
 * is sent to the model as a single string, so a byte budget is the faithful
 * cap; truncateHeadTail is line-oriented and would require loading the whole
 * file first, defeating the guard).
 */
async function readBoundedHeadTail(absolutePath: string, size: number, cap: number): Promise<string> {
	const markerReserve = 256;
	const budget = Math.max(0, cap - markerReserve);
	const headLen = Math.min(Math.floor(budget / 2), size);
	const tailLen = Math.min(budget - headLen, size - headLen);
	const fh = await open(absolutePath, "r");
	try {
		const headBuf = Buffer.alloc(headLen);
		if (headLen > 0) {
			await fh.read(headBuf, 0, headLen, 0);
		}
		const tailBuf = Buffer.alloc(tailLen);
		if (tailLen > 0) {
			await fh.read(tailBuf, 0, tailLen, size - tailLen);
		}
		const elidedBytes = size - headLen - tailLen;
		const marker = `\n... [${formatSize(elidedBytes)} elided, @file is ${formatSize(size)} > cap ${formatSize(cap)} (REPI_READ_TEXT_FILE_MAX_BYTES); use the read tool with offset/limit for full content, or raise the cap)] ...\n`;
		return `${headBuf.toString("utf-8")}${marker}${tailBuf.toString("utf-8")}`;
	} finally {
		await fh.close();
	}
}

/** Process @file arguments into text content and image attachments */
export async function processFileArguments(fileArgs: string[], options?: ProcessFileOptions): Promise<ProcessedFiles> {
	const autoResizeImages = options?.autoResizeImages ?? true;
	let text = "";
	const images: ImageContent[] = [];

	for (const fileArg of fileArgs) {
		// Expand and resolve path (handles ~ expansion and macOS screenshot Unicode spaces)
		const absolutePath = resolve(resolveReadPath(fileArg, process.cwd()));

		// Check if file exists
		try {
			await access(absolutePath);
		} catch {
			console.error(chalk.red(`Error: File not found: ${absolutePath}`));
			process.exit(1);
		}

		// Check if file is empty
		const stats = await stat(absolutePath);
		if (stats.size === 0) {
			// Skip empty files
			continue;
		}

		// opt #168: stat-size guard BEFORE readFile. @file inlines the whole
		// file into the prompt (text) or memory (image); an oversized @file
		// OOMs the process and blows the model's token budget. detect below is
		// a bounded 4100-byte sniff, safe on huge files.
		const mimeType = await detectSupportedImageMimeTypeFromFile(absolutePath);
		const cap = resolveAtFileMaxBytes();
		const oversized = cap > 0 && stats.size > cap;

		if (mimeType) {
			// Handle image file
			if (oversized) {
				console.error(
					chalk.red(
						`Error: Image file ${absolutePath} is ${formatSize(stats.size)}, exceeds the REPI_READ_TEXT_FILE_MAX_BYTES cap (${formatSize(cap)}); binary image bytes cannot be truncated — resize/downscale the image before attaching, raise the cap, or set REPI_READ_TEXT_FILE_MAX_BYTES=0 to disable the guard.`,
					),
				);
				process.exit(1);
			}
			const content = await readFile(absolutePath);

			let attachment: ImageContent;
			let dimensionNote: string | undefined;

			if (autoResizeImages) {
				const resized = await resizeImage(content, mimeType);
				if (!resized) {
					text += `<file name="${absolutePath}">[Image omitted: could not be resized below the inline image size limit.]</file>\n`;
					continue;
				}
				dimensionNote = formatDimensionNote(resized);
				attachment = {
					type: "image",
					mimeType: resized.mimeType,
					data: resized.data,
				};
			} else {
				attachment = {
					type: "image",
					mimeType,
					data: content.toString("base64"),
				};
			}

			images.push(attachment);

			// Add text reference to image with optional dimension note
			if (dimensionNote) {
				text += `<file name="${absolutePath}">${dimensionNote}</file>\n`;
			} else {
				text += `<file name="${absolutePath}"></file>\n`;
			}
		} else {
			// Handle text file
			try {
				let content: string;
				if (oversized) {
					// Bounded head+tail read: never readFile-whole the oversized
					// @file. Inlines a head+tail slice with a middle-ellipsis
					// marker into the prompt instead.
					content = await readBoundedHeadTail(absolutePath, stats.size, cap);
				} else {
					content = await readFile(absolutePath, "utf-8");
				}
				text += `<file name="${absolutePath}">\n${content}\n</file>\n`;
			} catch (error: unknown) {
				const message = error instanceof Error ? error.message : String(error);
				console.error(chalk.red(`Error: Could not read file ${absolutePath}: ${message}`));
				process.exit(1);
			}
		}
	}

	return { text, images };
}

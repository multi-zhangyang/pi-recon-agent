import { basename, dirname, isAbsolute, relative, resolve as resolvePath, sep } from "node:path";
import type { AgentTool } from "@pi-recon/repi-agent-core";
import type { Api, ImageContent, Model, TextContent } from "@pi-recon/repi-ai";
import { Text } from "@pi-recon/repi-tui";
import { constants } from "fs";
import { access as fsAccess, readFile as fsReadFile, stat as fsStat } from "fs/promises";
import { type Static, Type } from "typebox";
import { getReadmePath } from "../../config.ts";
import { keyHint, keyText } from "../../modes/interactive/components/keybinding-hints.ts";
import { getLanguageFromPath, highlightCode, type Theme } from "../../modes/interactive/theme/theme.ts";
import { formatDimensionNote, resizeImage } from "../../utils/image-resize.ts";
import { detectSupportedImageMimeTypeFromFile } from "../../utils/mime.ts";
import { formatPathRelativeToCwdOrAbsolute } from "../../utils/paths.ts";
import type { ToolDefinition, ToolRenderResultOptions } from "../extensions/types.ts";
import { resolveReadPathAsync, resolveToCwd } from "./path-utils.ts";
import { getTextOutput, renderToolPath, replaceTabs, str } from "./render-utils.ts";
import { wrapToolDefinition } from "./tool-definition-wrapper.ts";
import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, formatSize, type TruncationResult, truncateHead } from "./truncate.ts";

const readSchema = Type.Object({
	path: Type.String({ description: "Path to the file to read (relative or absolute)" }),
	offset: Type.Optional(Type.Number({ description: "Line number to start reading from (1-indexed)" })),
	limit: Type.Optional(Type.Number({ description: "Maximum number of lines to read" })),
});

export type ReadToolInput = Static<typeof readSchema>;

export interface ReadToolDetails {
	truncation?: TruncationResult;
}

interface CompactReadClassification {
	kind: "docs" | "resource" | "skill";
	label: string;
}

const COMPACT_RESOURCE_FILE_NAMES = new Set(["AGENTS.md", "AGENTS.MD", "CLAUDE.md", "CLAUDE.MD"]);

/**
 * Conservative binary-file detection: a NUL byte (0x00) in the leading bytes is
 * the standard heuristic used by grep/git/etc. Text files essentially never
 * contain NULs. Scanning a bounded prefix keeps this cheap even on huge files.
 */
const BINARY_SCAN_BYTES = 8192;
function isBinaryBuffer(buffer: Buffer): boolean {
	const scanLen = Math.min(buffer.length, BINARY_SCAN_BYTES);
	for (let i = 0; i < scanLen; i++) {
		if (buffer[i] === 0) return true;
	}
	return false;
}

/** A short, lowercase type hint derived from the file extension (or "binary"). */
function binaryTypeHint(path: string): string {
	const dot = path.lastIndexOf(".");
	if (dot === -1) return "binary";
	return path.slice(dot + 1).toLowerCase();
}

/**
 * Hard upper bound (bytes) on the size of a regular file the read tool will
 * load into memory. The read tool reads the WHOLE file into a Buffer, decodes
 * it to a string, and splits it into an array of ALL lines BEFORE applying
 * offset/limit/truncation (the pagination slices in memory too). So a
 * pathologically large file (a multi-GB log/core dump/minified bundle) would
 * exhaust memory and crash the agent — and even a medium file composed of many
 * tiny lines can blow up memory via the line-array allocation. Files at or
 * above this limit are rejected with an actionable bash-streaming hint
 * (head/tail/sed/grep) instead of being loaded. Override with
 * REPI_READ_MAX_FILE_BYTES; 0 disables the guard.
 */
const DEFAULT_MAX_READ_FILE_BYTES = 16 * 1024 * 1024;
function resolveMaxReadFileBytes(): number {
	const raw = process.env.REPI_READ_MAX_FILE_BYTES;
	if (raw !== undefined && raw.trim() !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed) && parsed >= 0) return Math.floor(parsed);
	}
	return DEFAULT_MAX_READ_FILE_BYTES;
}

/**
 * Pluggable operations for the read tool.
 * Override these to delegate file reading to remote systems (for example SSH).
 */
export interface ReadOperations {
	/** Read file contents as a Buffer */
	readFile: (absolutePath: string) => Promise<Buffer>;
	/** Check if file is readable (throw if not) */
	access: (absolutePath: string) => Promise<void>;
	/** Detect image MIME type, return null or undefined for non-images */
	detectImageMimeType?: (absolutePath: string) => Promise<string | null | undefined>;
	/**
	 * Stat the path. Used to reject non-regular files (devices, FIFOs, sockets)
	 * BEFORE readFile — reading a special file (e.g. /dev/zero, a named pipe)
	 * via readFile can hang indefinitely or return unbounded data, and the
	 * binary/NUL heuristic only runs AFTER the full read resolves. Optional:
	 * remote/custom ops may omit it, in which case the guard is skipped (the
	 * pre-existing EISDIR catch still covers directories on those backends).
	 */
	stat?: (absolutePath: string) => Promise<ReadFileStat>;
}

/**
 * Minimal stat shape the read tool needs. `fs.Stats` satisfies this, so the
 * default op can return the real Stats object; remote ops can synthesize it.
 */
export interface ReadFileStat {
	isFile: () => boolean;
	isDirectory: () => boolean;
	isBlockDevice: () => boolean;
	isCharacterDevice: () => boolean;
	isFIFO: () => boolean;
	isSocket: () => boolean;
	size: number;
}

const defaultReadOperations: ReadOperations = {
	readFile: (path) => fsReadFile(path),
	access: (path) => fsAccess(path, constants.R_OK),
	detectImageMimeType: detectSupportedImageMimeTypeFromFile,
	stat: (path) => fsStat(path),
};

export interface ReadToolOptions {
	/** Whether to auto-resize images to 2000x2000 max. Default: true */
	autoResizeImages?: boolean;
	/** Custom operations for file reading. Default: local filesystem */
	operations?: ReadOperations;
}

type ReadRenderArgs = { path?: string; file_path?: string; offset?: number; limit?: number };

function formatReadLineRange(args: ReadRenderArgs | undefined, theme: Theme): string {
	if (args?.offset === undefined && args?.limit === undefined) return "";
	const startLine = args.offset ?? 1;
	const endLine = args.limit !== undefined ? startLine + args.limit - 1 : "";
	return theme.fg("warning", `:${startLine}${endLine ? `-${endLine}` : ""}`);
}

function formatReadCall(args: ReadRenderArgs | undefined, theme: Theme, cwd: string): string {
	const pathDisplay = renderToolPath(str(args?.file_path ?? args?.path), theme, cwd);
	return `${theme.fg("toolTitle", theme.bold("read"))} ${pathDisplay}${formatReadLineRange(args, theme)}`;
}

function trimTrailingEmptyLines(lines: string[]): string[] {
	let end = lines.length;
	while (end > 0 && lines[end - 1] === "") {
		end--;
	}
	return lines.slice(0, end);
}

function getNonVisionImageNote(model: Model<Api> | undefined): string | undefined {
	if (!model || model.input.includes("image")) {
		return undefined;
	}
	return "[Current model does not support images. The image will be omitted from this request.]";
}

function toPosixPath(filePath: string): string {
	return filePath.split(sep).join("/");
}

function getPiDocsClassification(absolutePath: string): CompactReadClassification | undefined {
	const packageRoot = dirname(getReadmePath());
	const relativePath = relative(resolvePath(packageRoot), resolvePath(absolutePath));
	if (
		relativePath === "" ||
		relativePath === ".." ||
		relativePath.startsWith(`..${sep}`) ||
		isAbsolute(relativePath)
	) {
		return undefined;
	}

	const label = toPosixPath(relativePath);
	if (label === "README.md" || label.startsWith("docs/") || label.startsWith("examples/")) {
		return { kind: "docs", label };
	}
	return undefined;
}

function getCompactReadClassification(
	args: ReadRenderArgs | undefined,
	cwd: string,
): CompactReadClassification | undefined {
	const rawPath = str(args?.file_path ?? args?.path);
	if (!rawPath) return undefined;

	const absolutePath = resolveToCwd(rawPath, cwd);
	const fileName = basename(absolutePath);
	if (fileName === "SKILL.md") {
		return { kind: "skill", label: basename(dirname(absolutePath)) || fileName };
	}

	const docsClassification = getPiDocsClassification(absolutePath);
	if (docsClassification) return docsClassification;

	if (COMPACT_RESOURCE_FILE_NAMES.has(fileName)) {
		return { kind: "resource", label: formatPathRelativeToCwdOrAbsolute(absolutePath, cwd) };
	}

	return undefined;
}

function formatCompactReadCall(
	classification: CompactReadClassification,
	args: ReadRenderArgs | undefined,
	theme: Theme,
): string {
	const expandHint = theme.fg("dim", ` (${keyText("app.tools.expand")} to expand)`);
	if (classification.kind === "skill") {
		return (
			theme.fg("customMessageLabel", `\x1b[1m[skill]\x1b[22m `) +
			theme.fg("customMessageText", classification.label) +
			formatReadLineRange(args, theme) +
			expandHint
		);
	}

	return (
		theme.fg("toolTitle", theme.bold(`read ${classification.kind}`)) +
		" " +
		theme.fg("accent", classification.label) +
		formatReadLineRange(args, theme) +
		expandHint
	);
}

function formatReadResult(
	args: ReadRenderArgs | undefined,
	result: { content: (TextContent | ImageContent)[]; details?: ReadToolDetails },
	options: ToolRenderResultOptions,
	theme: Theme,
	showImages: boolean,
	_cwd: string,
	isError: boolean,
): string {
	if (!options.expanded && !isError) {
		return "";
	}

	const rawPath = str(args?.file_path ?? args?.path);
	const output = getTextOutput(result, showImages);
	const lang = rawPath ? getLanguageFromPath(rawPath) : undefined;
	const renderedLines = lang ? highlightCode(replaceTabs(output), lang) : output.split("\n");
	const lines = trimTrailingEmptyLines(renderedLines);
	const maxLines = options.expanded ? lines.length : 10;
	const displayLines = lines.slice(0, maxLines);
	const remaining = lines.length - maxLines;
	let text = `\n${displayLines.map((line) => (lang ? replaceTabs(line) : theme.fg("toolOutput", replaceTabs(line)))).join("\n")}`;
	if (remaining > 0) {
		text += `${theme.fg("muted", `\n... (${remaining} more lines,`)} ${keyHint("app.tools.expand", "to expand")}${theme.fg("muted", ")")}`;
	}

	const truncation = result.details?.truncation;
	if (truncation?.truncated) {
		if (truncation.firstLineExceedsLimit) {
			text += `\n${theme.fg("warning", `[First line exceeds ${formatSize(truncation.maxBytes ?? DEFAULT_MAX_BYTES)} limit]`)}`;
		} else if (truncation.truncatedBy === "lines") {
			text += `\n${theme.fg("warning", `[Truncated: showing ${truncation.outputLines} of ${truncation.totalLines} lines (${truncation.maxLines ?? DEFAULT_MAX_LINES} line limit)]`)}`;
		} else {
			text += `\n${theme.fg("warning", `[Truncated: ${truncation.outputLines} lines shown (${formatSize(truncation.maxBytes ?? DEFAULT_MAX_BYTES)} limit)]`)}`;
		}
	}
	return text;
}

export function createReadToolDefinition(
	cwd: string,
	options?: ReadToolOptions,
): ToolDefinition<typeof readSchema, ReadToolDetails | undefined> {
	const autoResizeImages = options?.autoResizeImages ?? true;
	const ops = options?.operations ?? defaultReadOperations;
	return {
		name: "read",
		label: "read",
		description: `Read the contents of a file. Supports text files and images (jpg, png, gif, webp). Images are sent as attachments. For text files, output is truncated to ${DEFAULT_MAX_LINES} lines or ${DEFAULT_MAX_BYTES / 1024}KB (whichever is hit first). Use offset/limit for large files. When you need the full file, continue with offset until complete.`,
		promptSnippet: "Read file contents",
		promptGuidelines: ["Use read to examine files instead of cat or sed."],
		parameters: readSchema,
		async execute(
			_toolCallId,
			{ path, offset, limit }: { path: string; offset?: number; limit?: number },
			signal?: AbortSignal,
			_onUpdate?,
			ctx?,
		) {
			return new Promise<{ content: (TextContent | ImageContent)[]; details: ReadToolDetails | undefined }>(
				(resolve, reject) => {
					if (signal?.aborted) {
						reject(new Error("Operation aborted"));
						return;
					}
					let aborted = false;
					const onAbort = () => {
						aborted = true;
						reject(new Error("Operation aborted"));
					};
					signal?.addEventListener("abort", onAbort, { once: true });

					(async () => {
						try {
							// Validate pagination params up front. offset:0 used to silently
							// become line 1; limit:0 yielded zero lines then fell into the
							// "N more lines" continuation branch with an empty body; limit:<0
							// produced a negative slice → same confusing empty-with-continue
							// output. Surface a clear validation error instead. Both are
							// 1-indexed and must be >= 1.
							if (offset !== undefined && offset < 1) {
								throw new Error("offset must be >= 1 (1-indexed).");
							}
							if (limit !== undefined && limit < 1) {
								throw new Error("limit must be >= 1.");
							}
							const absolutePath = await resolveReadPathAsync(path, cwd);
							if (aborted) return;
							// Check if file exists and is readable.
							await ops.access(absolutePath);
							if (aborted) return;
							// Reject non-regular files BEFORE readFile: reading a special file
							// (character/block device such as /dev/zero, a FIFO, a socket) via
							// readFile can hang indefinitely (no EOF) or return unbounded data,
							// and the binary/NUL heuristic only runs after the full read
							// resolves — too late. Directories are caught here too (the EISDIR
							// catch below remains as a fallback for ops without `stat`).
							if (ops.stat) {
								const fileStat = await ops.stat(absolutePath);
								if (aborted) return;
								if (!fileStat.isFile()) {
									if (fileStat.isDirectory()) {
										throw new Error(
											`${path} is a directory, not a file. Use the ls tool to list its contents instead, e.g. ls ${path}.`,
										);
									}
									throw new Error(
										`${path} is not a regular file (it is a special file: device, FIFO, or socket). The read tool only reads regular files — reading a special file can hang or return unbounded data. Inspect it with bash instead, e.g. \`file ${path}\`, \`head -c 1024 ${path}\`, or \`stat ${path}\`.`,
									);
								}
								// Reject pathologically large files BEFORE readFile loads them
								// into memory. The read tool materializes the whole file (Buffer +
								// decoded string + line array) before truncating, and offset/limit
								// slice in memory too, so a multi-GB file would OOM the agent. Steer
								// the model to bash, which streams (head/tail/sed/grep read only the
								// requested slice). Skipped when the guard is disabled (0) or when a
								// remote/custom ops omits stat (preserves its existing behavior).
								const maxReadFileBytes = resolveMaxReadFileBytes();
								if (maxReadFileBytes > 0 && fileStat.size > maxReadFileBytes) {
									throw new Error(
										`File ${path} is ${formatSize(fileStat.size)}, which exceeds the ${formatSize(maxReadFileBytes)} in-memory read limit. The read tool loads the entire file into memory before truncating (offset and limit also slice in memory), so reading it directly risks exhausting memory. Use bash to stream the parts you need instead, e.g. \`head -n 2000 ${path}\`, \`tail -n 2000 ${path}\`, \`sed -n 'START,ENDp' ${path}\`, or \`grep -n PATTERN ${path}\`.`,
									);
								}
							}
							const mimeType = ops.detectImageMimeType ? await ops.detectImageMimeType(absolutePath) : undefined;
							let content: (TextContent | ImageContent)[];
							let details: ReadToolDetails | undefined;
							const nonVisionImageNote = getNonVisionImageNote(ctx?.model);
							if (mimeType) {
								// Read image as binary.
								const buffer = await ops.readFile(absolutePath);
								if (autoResizeImages) {
									// Resize image if needed before sending it back to the model.
									const resized = await resizeImage(buffer, mimeType, undefined, signal);
									if (!resized) {
										let textNote = `Read image file [${mimeType}]\n[Image omitted: could not be resized below the inline image size limit.]`;
										if (nonVisionImageNote) textNote += `\n${nonVisionImageNote}`;
										content = [{ type: "text", text: textNote }];
									} else {
										const dimensionNote = formatDimensionNote(resized);
										let textNote = `Read image file [${resized.mimeType}]`;
										if (dimensionNote) textNote += `\n${dimensionNote}`;
										if (nonVisionImageNote) textNote += `\n${nonVisionImageNote}`;
										content = [
											{ type: "text", text: textNote },
											{ type: "image", data: resized.data, mimeType: resized.mimeType },
										];
									}
								} else {
									let textNote = `Read image file [${mimeType}]`;
									if (nonVisionImageNote) textNote += `\n${nonVisionImageNote}`;
									content = [
										{ type: "text", text: textNote },
										{ type: "image", data: buffer.toString("base64"), mimeType },
									];
								}
							} else {
								// Read text content.
								let buffer: Buffer;
								try {
									buffer = await ops.readFile(absolutePath);
								} catch (error: any) {
									// Reading a directory throws EISDIR on most backends. Surface an
									// actionable hint instead of a cryptic raw errno so the model
									// self-corrects to `ls`.
									if (error?.code === "EISDIR") {
										throw new Error(
											`${path} is a directory, not a file. Use the ls tool to list its contents instead, e.g. ls ${path}.`,
										);
									}
									throw error;
								}
								if (isBinaryBuffer(buffer)) {
									// Binary file: decoding as UTF-8 would produce garbage and waste
									// context. Point the model at the right inspection tools instead.
									// (For a RE harness this is the common case: ELF/PE/mach-o/archives.)
									const sizeNote = formatSize(buffer.length);
									const hint = binaryTypeHint(path);
									throw new Error(
										`File ${path} appears to be a binary file (${sizeNote}, .${hint}). Reading it as text would produce garbage. Inspect it with bash instead, e.g. \`file ${path}\`, \`strings ${path} | head\`, \`xxd ${path} | head\`, or a domain-specific disassembler.`,
									);
								}
								let textContent = buffer.toString("utf-8");
								// Strip a leading UTF-8 BOM (U+FEFF). It is invisible metadata; leaving
								// it in would surface as a stray char on line 1 and create a read/edit
								// mismatch — the edit tool strips BOM before matching, so oldText the
								// model copies from read output must also be BOM-free to match.
								if (textContent.charCodeAt(0) === 0xfeff) {
									textContent = textContent.slice(1);
								}
								const allLines = textContent.split("\n");
								// For a file ending in "\n", split() leaves a trailing "" that
								// inflates the count by 1. The phantom entry round-trips through
								// join("\n") correctly for content slicing, but using
								// allLines.length for the OOB check let offset = realLineCount+1
								// through (slice returned a phantom [""] → empty read with no
								// error and no continuation hint), and inflated the "Showing N of
								// M" / "more lines" notices by 1. Compute the real line count by
								// popping the trailing empty for endsWith("\n") (same logic as
								// truncate.ts splitLinesForCounting, which isn't exported).
								const lineCount =
									textContent.length === 0
										? 0
										: textContent.endsWith("\n")
											? allLines.length - 1
											: allLines.length;
								const totalFileLines = lineCount;
								// Apply offset if specified. Convert from 1-indexed input to 0-indexed array access.
								const startLine = offset ? Math.max(0, offset - 1) : 0;
								const startLineDisplay = startLine + 1;
								// Check if offset is out of bounds. Use the real line count so an
								// offset one past the last real line is rejected (not silently
								// treated as a valid empty read).
								if (startLine >= lineCount) {
									throw new Error(`Offset ${offset} is beyond end of file (${lineCount} lines total)`);
								}
								let selectedContent: string;
								let userLimitedLines: number | undefined;
								// If limit is specified by the user, honor it first. Otherwise truncateHead decides.
								if (limit !== undefined) {
									const endLine = Math.min(startLine + limit, lineCount);
									selectedContent = allLines.slice(startLine, endLine).join("\n");
									userLimitedLines = endLine - startLine;
								} else {
									selectedContent = allLines.slice(startLine).join("\n");
								}
								// Apply truncation, respecting both line and byte limits.
								const truncation = truncateHead(selectedContent);
								let outputText: string;
								if (truncation.firstLineExceedsLimit) {
									// First line alone exceeds the byte limit. Point the model at a bash fallback.
									const firstLineSize = formatSize(Buffer.byteLength(allLines[startLine], "utf-8"));
									outputText = `[Line ${startLineDisplay} is ${firstLineSize}, exceeds ${formatSize(DEFAULT_MAX_BYTES)} limit. Use bash: sed -n '${startLineDisplay}p' ${path} | head -c ${DEFAULT_MAX_BYTES}]`;
									details = { truncation };
								} else if (truncation.truncated) {
									// Truncation occurred. Build an actionable continuation notice.
									const endLineDisplay = startLineDisplay + truncation.outputLines - 1;
									const nextOffset = endLineDisplay + 1;
									outputText = truncation.content;
									if (truncation.truncatedBy === "lines") {
										outputText += `\n\n[Showing lines ${startLineDisplay}-${endLineDisplay} of ${totalFileLines}. Use offset=${nextOffset} to continue.]`;
									} else {
										outputText += `\n\n[Showing lines ${startLineDisplay}-${endLineDisplay} of ${totalFileLines} (${formatSize(DEFAULT_MAX_BYTES)} limit). Use offset=${nextOffset} to continue.]`;
									}
									details = { truncation };
								} else if (userLimitedLines !== undefined && startLine + userLimitedLines < lineCount) {
									// User-specified limit stopped early, but the file still has more content.
									const remaining = lineCount - (startLine + userLimitedLines);
									const nextOffset = startLine + userLimitedLines + 1;
									outputText = `${truncation.content}\n\n[${remaining} more lines in file. Use offset=${nextOffset} to continue.]`;
								} else {
									// No truncation and no remaining user-limited content.
									outputText = truncation.content;
								}
								content = [{ type: "text", text: outputText }];
							}

							if (aborted) return;
							signal?.removeEventListener("abort", onAbort);
							resolve({ content, details });
						} catch (error: any) {
							signal?.removeEventListener("abort", onAbort);
							if (!aborted) {
								// EISDIR can surface from either the image-magic probe or the text
								// readFile (both read the file header). Convert it to an actionable
								// hint so the model self-corrects to `ls` instead of seeing a raw errno.
								if (error?.code === "EISDIR") {
									reject(
										new Error(
											`${path} is a directory, not a file. Use the ls tool to list its contents instead, e.g. ls ${path}.`,
										),
									);
								} else {
									reject(error);
								}
							}
						}
					})();
				},
			);
		},
		renderCall(args, theme, context) {
			const text = (context.lastComponent as Text | undefined) ?? new Text("", 0, 0);
			const classification = !context.expanded ? getCompactReadClassification(args, context.cwd) : undefined;
			text.setText(
				classification
					? formatCompactReadCall(classification, args, theme)
					: formatReadCall(args, theme, context.cwd),
			);
			return text;
		},
		renderResult(result, options, theme, context) {
			const text = (context.lastComponent as Text | undefined) ?? new Text("", 0, 0);
			text.setText(
				formatReadResult(context.args, result, options, theme, context.showImages, context.cwd, context.isError),
			);
			return text;
		},
	};
}

export function createReadTool(cwd: string, options?: ReadToolOptions): AgentTool<typeof readSchema> {
	return wrapToolDefinition(createReadToolDefinition(cwd, options));
}

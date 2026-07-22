import type { AgentTool } from "@pi-recon/repi-agent-core";
import { Container, Text } from "@pi-recon/repi-tui";
import { mkdir as fsMkdir, stat as fsStat } from "fs/promises";
import { dirname } from "path";
import { type Static, Type } from "typebox";
import type { ToolDefinition, ToolRenderResultOptions } from "../extensions/types.ts";
import { themedKeyHint } from "../presentation/keybinding-hints.ts";
import { getLanguageFromPath, highlightCode } from "../presentation/syntax-highlight.ts";
import type { Theme } from "../presentation/theme.ts";
import { atomicWriteFile } from "./atomic-write.ts";
import { withFileMutationQueue } from "./file-mutation-queue.ts";
import { resolveToCwd } from "./path-utils.ts";
import type { ReadFileStat } from "./read.ts";
import { normalizeDisplayText, renderToolPath, replaceTabs, str } from "./render-utils.ts";
import { wrapToolDefinition } from "./tool-definition-wrapper.ts";

const writeSchema = Type.Object({
	path: Type.String({ description: "Path to the file to write (relative or absolute)" }),
	content: Type.String({ description: "Content to write to the file" }),
});

export type WriteToolInput = Static<typeof writeSchema>;

/**
 * Pluggable operations for the write tool.
 * Override these to delegate file writing to remote systems (for example SSH).
 */
export interface WriteOperations {
	/** Write content to a file */
	writeFile: (absolutePath: string, content: string) => Promise<void>;
	/** Create directory recursively */
	mkdir: (dir: string) => Promise<void>;
	/**
	 * Stat the path. Used to reject non-regular files (devices, FIFOs, sockets)
	 * BEFORE writing — `atomicWriteFile` writes a temp regular file then renames
	 * it over the target, and `rename(temp, fifo)` REPLACES the FIFO entry with
	 * a regular file, silently destroying the user's named pipe. `access` only
	 * checks mode bits so a FIFO passes. Optional: remote/custom ops may omit
	 * it, in which case the guard is skipped (preserves their behavior). Same
	 * doctrine as the read/edit tools' special-file guards (opt #30).
	 */
	stat?: (absolutePath: string) => Promise<ReadFileStat>;
}

const defaultWriteOperations: WriteOperations = {
	writeFile: (path, content) => atomicWriteFile(path, content),
	mkdir: (dir) => fsMkdir(dir, { recursive: true }).then(() => {}),
	stat: (path) => fsStat(path),
};

export interface WriteToolOptions {
	/** Custom operations for file writing. Default: local filesystem */
	operations?: WriteOperations;
}

type WriteHighlightCache = {
	rawPath: string | null;
	lang: string;
	rawContent: string;
	normalizedLines: string[];
	highlightedLines: string[];
};

class WriteCallRenderComponent extends Text {
	cache?: WriteHighlightCache;

	constructor() {
		super("", 0, 0);
	}
}

const WRITE_PARTIAL_FULL_HIGHLIGHT_LINES = 50;

function highlightSingleLine(line: string, lang: string, theme: Theme): string {
	const highlighted = highlightCode(line, theme, lang);
	return highlighted[0] ?? "";
}

function refreshWriteHighlightPrefix(cache: WriteHighlightCache, theme: Theme): void {
	const prefixCount = Math.min(WRITE_PARTIAL_FULL_HIGHLIGHT_LINES, cache.normalizedLines.length);
	if (prefixCount === 0) return;
	const prefixSource = cache.normalizedLines.slice(0, prefixCount).join("\n");
	const prefixHighlighted = highlightCode(prefixSource, theme, cache.lang);
	for (let i = 0; i < prefixCount; i++) {
		cache.highlightedLines[i] =
			prefixHighlighted[i] ?? highlightSingleLine(cache.normalizedLines[i] ?? "", cache.lang, theme);
	}
}

function rebuildWriteHighlightCacheFull(
	rawPath: string | null,
	fileContent: string,
	theme: Theme,
): WriteHighlightCache | undefined {
	const lang = rawPath ? getLanguageFromPath(rawPath) : undefined;
	if (!lang) return undefined;
	const displayContent = normalizeDisplayText(fileContent);
	const normalized = replaceTabs(displayContent);
	return {
		rawPath,
		lang,
		rawContent: fileContent,
		normalizedLines: normalized.split("\n"),
		highlightedLines: highlightCode(normalized, theme, lang),
	};
}

function updateWriteHighlightCacheIncremental(
	cache: WriteHighlightCache | undefined,
	rawPath: string | null,
	fileContent: string,
	theme: Theme,
): WriteHighlightCache | undefined {
	const lang = rawPath ? getLanguageFromPath(rawPath) : undefined;
	if (!lang) return undefined;
	if (!cache) return rebuildWriteHighlightCacheFull(rawPath, fileContent, theme);
	if (cache.lang !== lang || cache.rawPath !== rawPath)
		return rebuildWriteHighlightCacheFull(rawPath, fileContent, theme);
	if (!fileContent.startsWith(cache.rawContent)) return rebuildWriteHighlightCacheFull(rawPath, fileContent, theme);
	if (fileContent.length === cache.rawContent.length) return cache;

	const deltaRaw = fileContent.slice(cache.rawContent.length);
	const deltaDisplay = normalizeDisplayText(deltaRaw);
	const deltaNormalized = replaceTabs(deltaDisplay);
	cache.rawContent = fileContent;
	if (cache.normalizedLines.length === 0) {
		cache.normalizedLines.push("");
		cache.highlightedLines.push("");
	}

	const segments = deltaNormalized.split("\n");
	const lastIndex = cache.normalizedLines.length - 1;
	cache.normalizedLines[lastIndex] += segments[0];
	cache.highlightedLines[lastIndex] = highlightSingleLine(cache.normalizedLines[lastIndex], cache.lang, theme);
	for (let i = 1; i < segments.length; i++) {
		cache.normalizedLines.push(segments[i]);
		cache.highlightedLines.push(highlightSingleLine(segments[i], cache.lang, theme));
	}
	refreshWriteHighlightPrefix(cache, theme);
	return cache;
}

function trimTrailingEmptyLines(lines: string[]): string[] {
	let end = lines.length;
	while (end > 0 && lines[end - 1] === "") {
		end--;
	}
	return lines.slice(0, end);
}

function formatWriteCall(
	args: { path?: string; file_path?: string; content?: string } | undefined,
	options: ToolRenderResultOptions,
	theme: Theme,
	cache: WriteHighlightCache | undefined,
	cwd: string,
): string {
	const rawPath = str(args?.file_path ?? args?.path);
	const fileContent = str(args?.content);
	const pathDisplay = renderToolPath(rawPath, theme, cwd);
	let text = `${theme.fg("toolTitle", theme.bold("write"))} ${pathDisplay}`;

	if (fileContent === null) {
		text += `\n\n${theme.fg("error", "[invalid content arg - expected string]")}`;
	} else if (fileContent) {
		const lang = rawPath ? getLanguageFromPath(rawPath) : undefined;
		const renderedLines = lang
			? (cache?.highlightedLines ?? highlightCode(replaceTabs(normalizeDisplayText(fileContent)), theme, lang))
			: normalizeDisplayText(fileContent).split("\n");
		const lines = trimTrailingEmptyLines(renderedLines);
		const totalLines = lines.length;
		const maxLines = options.expanded ? lines.length : 10;
		const displayLines = lines.slice(0, maxLines);
		const remaining = lines.length - maxLines;
		text += `\n\n${displayLines.map((line) => (lang ? line : theme.fg("toolOutput", replaceTabs(line)))).join("\n")}`;
		if (remaining > 0) {
			text += `${theme.fg("muted", `\n... (${remaining} more lines, ${totalLines} total,`)} ${themedKeyHint(theme, "app.tools.expand", "to expand")}${theme.fg("muted", ")")}`;
		}
	}

	return text;
}

function formatWriteResult(
	result: { content: Array<{ type: string; text?: string; data?: string; mimeType?: string }>; isError?: boolean },
	theme: Theme,
): string | undefined {
	if (!result.isError) {
		return undefined;
	}
	const output = result.content
		.filter((c) => c.type === "text")
		.map((c) => c.text || "")
		.join("\n");
	if (!output) {
		return undefined;
	}
	return `\n${theme.fg("error", output)}`;
}

export function createWriteToolDefinition(
	cwd: string,
	options?: WriteToolOptions,
): ToolDefinition<typeof writeSchema, undefined> {
	const ops = options?.operations ?? defaultWriteOperations;
	return {
		name: "write",
		label: "write",
		description:
			"Write content to a file. Creates the file if it doesn't exist, overwrites if it does. Automatically creates parent directories.",
		promptSnippet: "Create or overwrite files",
		promptGuidelines: ["Use write only for new files or complete rewrites."],
		parameters: writeSchema,
		async execute(
			_toolCallId,
			{ path, content }: { path: string; content: string },
			signal?: AbortSignal,
			_onUpdate?,
			_ctx?,
		) {
			const absolutePath = resolveToCwd(path, cwd);
			const dir = dirname(absolutePath);
			return withFileMutationQueue(absolutePath, async () => {
				// Do not reject from an abort event listener here: that would release the
				// mutation queue while an in-flight filesystem operation may still finish.
				// Checking signal.aborted after each await observes the same aborts while
				// keeping the queue locked until the current operation has settled.
				const throwIfAborted = (): void => {
					if (signal?.aborted) throw new Error("Operation aborted");
				};

				throwIfAborted();
				// Reject non-regular files BEFORE writing. atomicWriteFile writes a
				// temp regular file then renames it over the target; `rename(temp,
				// fifo)` REPLACES the FIFO entry with a regular file — silently
				// destroying a named pipe (or socket/device). `access` only checks
				// mode bits so a FIFO passes; stat first. Same guard as the
				// read/edit tools (opt #30). Skipped for remote/custom ops that omit
				// `stat` (preserves their behavior). A directory is caught here too
				// so the error is clear instead of a raw EISDIR from mkdir/rename.
				if (ops.stat) {
					let targetStat: ReadFileStat | undefined;
					try {
						targetStat = await ops.stat(absolutePath);
					} catch {
						/* ENOENT (new file) or stat denied — proceed; write surfaces a real errno */
					}
					throwIfAborted();
					if (targetStat) {
						if (targetStat.isDirectory()) {
							throw new Error(`Could not write file: ${path}. ${path} is a directory, not a file.`);
						}
						if (!targetStat.isFile()) {
							throw new Error(
								`Could not write file: ${path}. ${path} is not a regular file (it is a device, FIFO, or socket). The write tool cannot write a special file — use bash instead.`,
							);
						}
					}
				}
				// Create parent directories if needed.
				await ops.mkdir(dir);
				throwIfAborted();

				// Write the file contents.
				await ops.writeFile(absolutePath, content);
				throwIfAborted();

				// Report the real UTF-8 byte count, not content.length (which is a
				// UTF-16 code-unit count and would under-report multi-byte text, e.g.
				// a 100-char CJK string is ~300 bytes but length reports 100).
				const byteLength = Buffer.byteLength(content, "utf-8");
				return {
					content: [{ type: "text", text: `Successfully wrote ${byteLength} bytes to ${path}` }],
					details: undefined,
				};
			});
		},
		renderCall(args, theme, context) {
			const renderArgs = args as { path?: string; file_path?: string; content?: string } | undefined;
			const rawPath = str(renderArgs?.file_path ?? renderArgs?.path);
			const fileContent = str(renderArgs?.content);
			const component =
				(context.lastComponent as WriteCallRenderComponent | undefined) ?? new WriteCallRenderComponent();
			if (fileContent !== null) {
				component.cache = context.argsComplete
					? rebuildWriteHighlightCacheFull(rawPath, fileContent, theme)
					: updateWriteHighlightCacheIncremental(component.cache, rawPath, fileContent, theme);
			} else {
				component.cache = undefined;
			}
			component.setText(
				formatWriteCall(
					renderArgs,
					{ expanded: context.expanded, isPartial: context.isPartial },
					theme,
					component.cache,
					context.cwd,
				),
			);
			return component;
		},
		renderResult(result, _options, theme, context) {
			const output = formatWriteResult({ ...result, isError: context.isError }, theme);
			if (!output) {
				const component = (context.lastComponent as Container | undefined) ?? new Container();
				component.clear();
				return component;
			}
			const text = (context.lastComponent as Text | undefined) ?? new Text("", 0, 0);
			text.setText(output);
			return text;
		},
	};
}

export function createWriteTool(cwd: string, options?: WriteToolOptions): AgentTool<typeof writeSchema> {
	return wrapToolDefinition(createWriteToolDefinition(cwd, options));
}

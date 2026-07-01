import { closeSync, openSync, readSync, statSync } from "node:fs";
import { readFile as fsReadFile, stat as fsStat } from "node:fs/promises";
import { createInterface } from "node:readline";
import type { AgentTool } from "@pi-recon/repi-agent-core";
import { Text } from "@pi-recon/repi-tui";
import { spawn } from "child_process";
import path from "path";
import { type Static, Type } from "typebox";
import { keyHint } from "../../modes/interactive/components/keybinding-hints.ts";
import type { Theme } from "../../modes/interactive/theme/theme.ts";
import { ensureTool } from "../../utils/tools-manager.ts";
import type { ToolDefinition, ToolRenderResultOptions } from "../extensions/types.ts";
import { resolveToCwd } from "./path-utils.ts";
import { getTextOutput, invalidArgText, shortenPath, str } from "./render-utils.ts";
import { wrapToolDefinition } from "./tool-definition-wrapper.ts";
import {
	DEFAULT_MAX_BYTES,
	formatSize,
	GREP_MAX_LINE_LENGTH,
	type TruncationResult,
	truncateHead,
	truncateLine,
} from "./truncate.ts";

const grepSchema = Type.Object({
	pattern: Type.String({ description: "Search pattern (regex or literal string)" }),
	path: Type.Optional(Type.String({ description: "Directory or file to search (default: current directory)" })),
	glob: Type.Optional(Type.String({ description: "Filter files by glob pattern, e.g. '*.ts' or '**/*.spec.ts'" })),
	ignoreCase: Type.Optional(Type.Boolean({ description: "Case-insensitive search (default: false)" })),
	literal: Type.Optional(
		Type.Boolean({ description: "Treat pattern as literal string instead of regex (default: false)" }),
	),
	context: Type.Optional(
		Type.Number({ description: "Number of lines to show before and after each match (default: 0)" }),
	),
	limit: Type.Optional(Type.Number({ description: "Maximum number of matches to return (default: 100)" })),
});

export type GrepToolInput = Static<typeof grepSchema>;
const DEFAULT_LIMIT = 100;

// Foundational opt #262: cap the model-supplied limit/context args. The schema
// is bare Type.Number with no upper bound, so a model passing limit:1e6 or
// context:1e5 made rg run until 1M matches (each pushed with its FULL lineText
// into `matches`) and formatBlock emit 2*context+1 lines per match → OOM
// BEFORE the agent-core tool-result cap (#15) could trim anything (that cap
// only bounds what reaches the model AFTER the tool returns, not the tool's
// own in-memory arrays). Also Math.floor so a fractional context can't produce
// fractional line numbers / drop the match line (the context loop iterates
// current=start..end and isMatchLine=current===lineNumber never matches a
// fractional current). Env-overridable; 0 disables the cap (no bound).
const DEFAULT_GREP_MAX_LIMIT = 10000;
const DEFAULT_GREP_MAX_CONTEXT = 50;
function resolveGrepMaxLimit(): number {
	const raw = process.env.REPI_GREP_MAX_LIMIT;
	if (raw === undefined) return DEFAULT_GREP_MAX_LIMIT;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return DEFAULT_GREP_MAX_LIMIT;
	return n === 0 ? Number.MAX_SAFE_INTEGER : Math.floor(n);
}
function resolveGrepMaxContext(): number {
	const raw = process.env.REPI_GREP_MAX_CONTEXT;
	if (raw === undefined) return DEFAULT_GREP_MAX_CONTEXT;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return DEFAULT_GREP_MAX_CONTEXT;
	return n === 0 ? Number.MAX_SAFE_INTEGER : Math.floor(n);
}

// Wall cap on awaiting the rg child (opt #65). rg is awaited via child.on("close")
// with abort the only early escape. On a hung FUSE/NFS mount, a pathological
// regex backtracking on a huge file, or a D-state rg, 'close' never fires — if
// the user doesn't abort (or SIGTERM can't reap a D-state process), the tool
// hangs forever and freezes the agent. rg is bounded by the match limit
// (stopChild on effectiveLimit) so a legitimate search exits well under this; the
// cap only fires on a genuinely hung process. On timeout we SIGKILL (escalate
// past the abort's SIGTERM) and settle. 0 disables (Infinity). Read lazily at
// execute time so the value can be tuned via env without a process restart (and
// exercised in tests without resetModules).
function getGrepTimeoutMs(): number {
	const raw = process.env.REPI_GREP_TIMEOUT_MS;
	if (raw === undefined) return 120_000;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return 120_000;
	return n === 0 ? Infinity : n;
}

// opt #166 — stat-first OOM guard cap (bytes) for the grep context-line read
// path (formatBlock → getFileLines). The old getFileLines did
// `ops.readFile(filePath)` of the WHOLE file then `.split("\n")` into an
// unbounded array cached in fileCache. When grep ran with context (-A/-B/-C,
// contextValue > 0), formatBlock called getFileLines for EVERY matched file to
// extract surrounding lines — a model grepping a pattern inside a multi-GB
// log/artifact loaded the ENTIRE file into memory (and cached it) before
// slicing the context window. The read-tool stat-guards this (#34/#156); the
// grep context path did NOT → OOM. Files at or below this cap keep the fast
// whole-read+cache path (byte-identical to the old behavior); larger files
// stream-skip to the matched line range and read ONLY the context window via
// positioned readSync (1 MB chunks, same doctrine as opt #158's hashFileSha256)
// and are NOT cached wholesale. Reuses the SHARED knob NAME
// REPI_READ_TEXT_FILE_MAX_BYTES (default 16 MB, 0 disables) so one env var
// bounds every whole-file text read path (read-tool #34, readTextFile #163,
// grep context #166) consistently. Read lazily at execute time so the value
// can be tuned via env without a process restart.
const DEFAULT_GREP_CONTEXT_MAX_FILE_BYTES = 16 * 1024 * 1024;
const GREP_CONTEXT_CHUNK_SIZE = 1024 * 1024;
/**
 * Foundational opt #256: bound a single pathological line in
 * {@link defaultGrepReadLineRange}. `pending` accumulates bytes until a newline
 * arrives; a file with one giant line (no newline for MBs — a minified/binary
 * file) grew `pending` unbounded → OOM. Once this many bytes buffer with no
 * newline, emit a head-truncated line and scan forward to the real newline so
 * lineNum stays correct. The caller truncates to GREP_MAX_LINE_LENGTH (500) for
 * display, so a 64KB head is far more than the model ever sees.
 */
const GREP_MAX_LINE_BUFFER = 64 * 1024;
function resolveGrepContextMaxFileBytes(): number {
	const raw = process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
	if (raw !== undefined && raw.trim() !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed) && parsed >= 0) return Math.floor(parsed);
	}
	return DEFAULT_GREP_CONTEXT_MAX_FILE_BYTES;
}

/**
 * Streaming bounded line-range read for oversized files (opt #166). Reads the
 * file in fixed {@link GREP_CONTEXT_CHUNK_SIZE} chunks via positioned readSync,
 * splits on `\n` (normalizing CRLF/CR → LF like the fast path's
 * `.replace(/\r\n/g,"\n").replace(/\r/g,"\n")`), and collects ONLY the lines in
 * the 1-indexed inclusive range [startLine, endLine]. Memory stays bounded to
 * one chunk regardless of file size; time is proportional to the byte offset of
 * endLine (stream-skip past earlier lines without retaining them). The returned
 * `baseLine` is startLine and `lines[i]` is the text of line `baseLine + i`.
 * Lines past EOF are simply absent from `lines` (caller treats missing as "").
 * Exposed so tests can force the oversized path against a real backing file.
 */
export function defaultGrepReadLineRange(
	absolutePath: string,
	startLine: number,
	endLine: number,
): { baseLine: number; lines: string[] } {
	const stat = statSync(absolutePath);
	const fd = openSync(absolutePath, "r");
	try {
		const buf = Buffer.alloc(GREP_CONTEXT_CHUNK_SIZE);
		let pos = 0;
		let pending: Buffer = Buffer.alloc(0);
		let lineNum = 1;
		const out: string[] = [];
		const emit = (text: string) => {
			const norm = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
			const parts = norm.split("\n");
			for (let i = 0; i < parts.length; i++) {
				if (lineNum >= startLine && lineNum <= endLine) out.push(parts[i]);
				lineNum++;
			}
		};
		while (pos < stat.size && lineNum <= endLine) {
			const n = readSync(fd, buf, 0, Math.min(GREP_CONTEXT_CHUNK_SIZE, stat.size - pos), pos);
			if (n <= 0) break;
			pos += n;
			pending = Buffer.concat([pending, buf.subarray(0, n)]);
			const lastNl = pending.lastIndexOf(0x0a);
			if (lastNl === -1) {
				// opt #256: no newline yet. A pathologically long line (no newline
				// for MBs — a minified/binary file) would grow `pending` unbounded
				// → OOM. Once we've buffered GREP_MAX_LINE_BUFFER bytes with no
				// newline, emit a head-truncated line (the caller truncates to
				// GREP_MAX_LINE_LENGTH for display anyway), then scan forward
				// discarding bytes until the real newline so lineNum stays correct
				// and pending can't grow further.
				if (pending.length > GREP_MAX_LINE_BUFFER) {
					emit(pending.toString("utf-8").slice(0, GREP_MAX_LINE_BUFFER));
					pending = Buffer.alloc(0);
					while (pos < stat.size) {
						const m = readSync(fd, buf, 0, Math.min(GREP_CONTEXT_CHUNK_SIZE, stat.size - pos), pos);
						if (m <= 0) break;
						pos += m;
						const nl = buf.subarray(0, m).indexOf(0x0a);
						if (nl !== -1) {
							pending = Buffer.from(buf.subarray(nl + 1, m));
							break;
						}
					}
				}
				continue; // no complete line yet; keep accumulating
			}
			const complete = pending.subarray(0, lastNl + 1);
			pending = pending.subarray(lastNl + 1);
			emit(complete.toString("utf-8"));
		}
		// Final partial line (no trailing newline) — emit whatever remains so the
		// line count mirrors `content.split("\n")`'s N+1 parts for N separators.
		if (lineNum <= endLine) emit(pending.toString("utf-8"));
		return { baseLine: startLine, lines: out };
	} finally {
		try {
			closeSync(fd);
		} catch {
			// Best-effort: fd may already be invalid.
		}
	}
}

export interface GrepToolDetails {
	truncation?: TruncationResult;
	matchLimitReached?: number;
	linesTruncated?: boolean;
}

/**
 * Pluggable operations for the grep tool.
 * Override these to delegate search to remote systems (for example SSH).
 */
export interface GrepOperations {
	/** Check if path is a directory. Throws if path does not exist. */
	isDirectory: (absolutePath: string) => Promise<boolean> | boolean;
	/** Read file contents for context lines */
	readFile: (absolutePath: string) => Promise<string> | string;
	/** opt #166 — stat-first size guard. Returns the file size in bytes. Used to
	 * decide between the fast whole-read path (size <= cap) and the bounded
	 * streaming {@link readLineRange} path (size > cap). Falls back to the fast
	 * path (treating the file as small) when absent. */
	statSize?: (absolutePath: string) => Promise<number> | number;
	/** opt #166 — bounded line-range read for oversized files. Returns the
	 * 1-indexed inclusive lines [startLine, endLine] WITHOUT loading the whole
	 * file into memory. `baseLine` is startLine; `lines[i]` is line
	 * `baseLine + i`. Lines past EOF are absent. Falls back to a degraded
	 * "(unable to read file)" context block when absent. */
	readLineRange?: (
		absolutePath: string,
		startLine: number,
		endLine: number,
	) => Promise<{ baseLine: number; lines: string[] }> | { baseLine: number; lines: string[] };
}

const defaultGrepOperations: GrepOperations = {
	isDirectory: async (p) => (await fsStat(p)).isDirectory(),
	readFile: (p) => fsReadFile(p, "utf-8"),
	statSize: (p) => statSync(p).size,
	readLineRange: (p, startLine, endLine) => defaultGrepReadLineRange(p, startLine, endLine),
};

export interface GrepToolOptions {
	/** Custom operations for grep. Default: local filesystem plus ripgrep */
	operations?: GrepOperations;
}

function formatGrepCall(
	args: { pattern: string; path?: string; glob?: string; limit?: number } | undefined,
	theme: Theme,
): string {
	const pattern = str(args?.pattern);
	const rawPath = str(args?.path);
	const path = rawPath !== null ? shortenPath(rawPath || ".") : null;
	const glob = str(args?.glob);
	const limit = args?.limit;
	const invalidArg = invalidArgText(theme);
	let text =
		theme.fg("toolTitle", theme.bold("grep")) +
		" " +
		(pattern === null ? invalidArg : theme.fg("accent", `/${pattern || ""}/`)) +
		theme.fg("toolOutput", ` in ${path === null ? invalidArg : path}`);
	if (glob) text += theme.fg("toolOutput", ` (${glob})`);
	if (limit !== undefined) text += theme.fg("toolOutput", ` limit ${limit}`);
	return text;
}

function formatGrepResult(
	result: {
		content: Array<{ type: string; text?: string; data?: string; mimeType?: string }>;
		details?: GrepToolDetails;
	},
	options: ToolRenderResultOptions,
	theme: Theme,
	showImages: boolean,
): string {
	const output = getTextOutput(result, showImages).trim();
	let text = "";
	if (output) {
		const lines = output.split("\n");
		const maxLines = options.expanded ? lines.length : 15;
		const displayLines = lines.slice(0, maxLines);
		const remaining = lines.length - maxLines;
		text += `\n${displayLines.map((line) => theme.fg("toolOutput", line)).join("\n")}`;
		if (remaining > 0) {
			text += `${theme.fg("muted", `\n... (${remaining} more lines,`)} ${keyHint("app.tools.expand", "to expand")}${theme.fg("muted", ")")}`;
		}
	}

	const matchLimit = result.details?.matchLimitReached;
	const truncation = result.details?.truncation;
	const linesTruncated = result.details?.linesTruncated;
	if (matchLimit || truncation?.truncated || linesTruncated) {
		const warnings: string[] = [];
		if (matchLimit) warnings.push(`${matchLimit} matches limit`);
		if (truncation?.truncated) warnings.push(`${formatSize(truncation.maxBytes ?? DEFAULT_MAX_BYTES)} limit`);
		if (linesTruncated) warnings.push("some lines truncated");
		text += `\n${theme.fg("warning", `[Truncated: ${warnings.join(", ")}]`)}`;
	}
	return text;
}

export function createGrepToolDefinition(
	cwd: string,
	options?: GrepToolOptions,
): ToolDefinition<typeof grepSchema, GrepToolDetails | undefined> {
	const customOps = options?.operations;
	return {
		name: "grep",
		label: "grep",
		description: `Search file contents for a pattern. Returns matching lines with file paths and line numbers. Respects .gitignore. Output is truncated to ${DEFAULT_LIMIT} matches or ${DEFAULT_MAX_BYTES / 1024}KB (whichever is hit first). Long lines are truncated to ${GREP_MAX_LINE_LENGTH} chars.`,
		promptSnippet: "Search file contents for patterns (respects .gitignore)",
		parameters: grepSchema,
		async execute(
			_toolCallId,
			{
				pattern,
				path: searchDir,
				glob,
				ignoreCase,
				literal,
				context,
				limit,
			}: {
				pattern: string;
				path?: string;
				glob?: string;
				ignoreCase?: boolean;
				literal?: boolean;
				context?: number;
				limit?: number;
			},
			signal?: AbortSignal,
			_onUpdate?,
			_ctx?,
		) {
			return new Promise((resolve, reject) => {
				if (signal?.aborted) {
					reject(new Error("Operation aborted"));
					return;
				}
				let settled = false;
				let wallTimer: NodeJS.Timeout | undefined;
				const settle = (fn: () => void) => {
					if (!settled) {
						settled = true;
						if (wallTimer) {
							clearTimeout(wallTimer);
							wallTimer = undefined;
						}
						fn();
					}
				};

				(async () => {
					try {
						const rgPath = await ensureTool("rg", true);
						if (!rgPath) {
							settle(() =>
								reject(
									new Error(
										"ripgrep (rg) is not available and could not be downloaded. Use the bash tool to search instead, e.g. bash 'grep -rn -- \"<pattern>\" <path>'.",
									),
								),
							);
							return;
						}

						const searchPath = resolveToCwd(searchDir || ".", cwd);
						const ops = customOps ?? defaultGrepOperations;
						let isDirectory: boolean;
						try {
							isDirectory = await ops.isDirectory(searchPath);
						} catch {
							settle(() => reject(new Error(`Path not found: ${searchPath}`)));
							return;
						}

						// opt #262 — cap + floor limit/context (see resolveGrepMaxLimit/Context).
						const contextValue = Math.min(
							Math.floor(context && context > 0 ? context : 0),
							resolveGrepMaxContext(),
						);
						const effectiveLimit = Math.min(
							Math.max(1, Math.floor(limit ?? DEFAULT_LIMIT)),
							resolveGrepMaxLimit(),
						);
						const formatPath = (filePath: string): string => {
							if (isDirectory) {
								const relative = path.relative(searchPath, filePath);
								if (relative && !relative.startsWith("..")) {
									return relative.replace(/\\/g, "/");
								}
							}
							return path.basename(filePath);
						};

						const fileCache = new Map<string, string[]>();
						// opt #166 — a uniform line accessor over either the cached whole-file
						// array (small files, byte-identical to the old behavior) or a bounded
						// streamed slice (oversized files). `maxLine` is the highest 1-indexed
						// line number available; `line(n)` returns "" for out-of-range n.
						interface LineAccessor {
							readonly maxLine: number;
							line: (n: number) => string;
						}
						const getFileLines = async (
							filePath: string,
							startLine: number,
							endLine: number,
						): Promise<LineAccessor> => {
							const cap = resolveGrepContextMaxFileBytes();
							let size = Infinity;
							if (ops.statSize) {
								try {
									size = await ops.statSize(filePath);
								} catch {
									size = Infinity;
								}
							}
							// Fast path: small file (or guard disabled via 0) → whole read + cache.
							// This is byte-identical to the old getFileLines behavior.
							if (cap === 0 || size <= cap) {
								let lines = fileCache.get(filePath);
								if (!lines) {
									try {
										const content = await ops.readFile(filePath);
										lines = content.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
									} catch {
										lines = [];
									}
									fileCache.set(filePath, lines);
								}
								return {
									maxLine: lines.length,
									line: (n) => lines[n - 1] ?? "",
								};
							}
							// Oversized → stream-skip to the matched range and read ONLY the
							// context window via positioned readSync. Do NOT cache wholesale —
							// the whole file must never enter memory; the bounded slice is
							// per-match and not worth caching.
							if (ops.readLineRange) {
								try {
									const { baseLine, lines } = await ops.readLineRange(filePath, startLine, endLine);
									const maxLine = baseLine + lines.length - 1;
									return {
										maxLine,
										line: (n) => (n >= baseLine && n <= maxLine ? lines[n - baseLine] : ""),
									};
								} catch {
									return { maxLine: 0, line: () => "" };
								}
							}
							// No streaming seam → degrade gracefully instead of OOMing.
							return { maxLine: 0, line: () => "" };
						};

						const args: string[] = ["--json", "--line-number", "--color=never", "--hidden"];
						if (ignoreCase) args.push("--ignore-case");
						if (literal) args.push("--fixed-strings");
						if (glob) args.push("--glob", glob);
						args.push("--", pattern, searchPath);

						const child = spawn(rgPath, args, { stdio: ["ignore", "pipe", "pipe"] });
						const rl = createInterface({ input: child.stdout });
						let stderr = "";
						let matchCount = 0;
						let matchLimitReached = false;
						let linesTruncated = false;
						let aborted = false;
						let killedDueToLimit = false;

						// Defense-in-depth: a stream-level 'error' on child.stdout/readline
						// (rare, usually paired with child "close") without a listener would
						// throw `Unhandled 'error' event`. Swallow; the child "error"/"close"
						// handlers own real failure reporting. Same guard on child.stderr:
						// it is a piped Readable that can emit 'error' independently
						// (EIO/EBADF/EPIPE) — opt #40 fixed stdout but missed stderr.
						rl.on("error", () => {});
						child.stdout?.on("error", () => {});
						child.stderr?.on("error", () => {});
						const outputLines: string[] = [];

						const cleanup = () => {
							rl.close();
							signal?.removeEventListener("abort", onAbort);
						};
						const stopChild = (dueToLimit = false) => {
							if (!child.killed) {
								killedDueToLimit = dueToLimit;
								child.kill();
							}
						};
						// Wall timeout (opt #65): SIGKILL on timeout (escalate past the
						// abort's SIGTERM — a D-state rg ignores SIGTERM). The late 'close'
						// is swallowed by the `settled` guard.
						const grepTimeoutMs = getGrepTimeoutMs();
						if (Number.isFinite(grepTimeoutMs) && grepTimeoutMs > 0) {
							wallTimer = setTimeout(() => {
								try {
									child.kill("SIGKILL");
								} catch {
									/* already dead */
								}
								settle(() =>
									reject(
										new Error(
											`grep timed out after ${grepTimeoutMs}ms (rg hung — likely a FUSE/NFS mount, pathological regex backtracking, or D-state process). Try narrowing the search path or use literal:true.`,
										),
									),
								);
							}, grepTimeoutMs);
						}
						const onAbort = () => {
							aborted = true;
							stopChild();
						};
						signal?.addEventListener("abort", onAbort, { once: true });
						child.stderr?.on("data", (chunk) => {
							stderr += chunk.toString();
						});

						const formatBlock = async (filePath: string, lineNumber: number): Promise<string[]> => {
							const relativePath = formatPath(filePath);
							const start = contextValue > 0 ? Math.max(1, lineNumber - contextValue) : lineNumber;
							const end = contextValue > 0 ? lineNumber + contextValue : lineNumber;
							// opt #166 — request only the needed [start, end] range so the
							// oversized streaming path reads a bounded window, not the whole file.
							const acc = await getFileLines(filePath, start, end);
							if (acc.maxLine === 0) return [`${relativePath}:${lineNumber}: (unable to read file)`];
							const endBounded = contextValue > 0 ? Math.min(acc.maxLine, end) : end;
							const block: string[] = [];
							for (let current = start; current <= endBounded; current++) {
								const lineText = acc.line(current);
								const sanitized = lineText.replace(/\r/g, "");
								const isMatchLine = current === lineNumber;
								// Truncate long lines so grep output stays compact.
								const { text: truncatedText, wasTruncated } = truncateLine(sanitized);
								if (wasTruncated) linesTruncated = true;
								if (isMatchLine) block.push(`${relativePath}:${current}: ${truncatedText}`);
								else block.push(`${relativePath}-${current}- ${truncatedText}`);
							}
							return block;
						};

						// Collect matches during streaming, then format them after rg exits.
						const matches: Array<{ filePath: string; lineNumber: number; lineText?: string }> = [];
						rl.on("line", (line) => {
							if (!line.trim() || matchCount >= effectiveLimit) return;
							let event: any;
							try {
								event = JSON.parse(line);
							} catch {
								return;
							}
							if (event.type === "match") {
								matchCount++;
								const filePath = event.data?.path?.text;
								const lineNumber = event.data?.line_number;
								const lineText = event.data?.lines?.text;
								if (filePath && typeof lineNumber === "number") {
									// opt #262 — truncate the line on push so `matches` holds
									// at most GREP_MAX_LINE_LENGTH chars/entry (bounded by
									// effectiveLimit) instead of full minified/matched lines
									// for the whole run. The close handler re-truncates
									// (idempotent) and this sets linesTruncated so the
									// "Some lines truncated" notice still fires. Only
									// truncate strings — a non-string lineText (e.g. a
									// proxy emitting lines.text as a number) is stored as-is
									// so the close handler's replace() throws the existing
									// TypeError caught by opt #121's try/catch (preserves
									// that settle-on-throw contract).
									if (typeof lineText === "string") {
										const { text: truncText, wasTruncated } = truncateLine(lineText);
										if (wasTruncated) linesTruncated = true;
										matches.push({ filePath, lineNumber, lineText: truncText });
									} else {
										matches.push({ filePath, lineNumber, lineText });
									}
								}
								if (matchCount >= effectiveLimit) {
									matchLimitReached = true;
									stopChild(true);
								}
							}
						});

						child.on("error", (error) => {
							cleanup();
							settle(() => reject(new Error(`Failed to run ripgrep: ${error.message}`)));
						});
						child.on("close", async (code) => {
							try {
								cleanup();
								if (aborted) {
									settle(() => reject(new Error("Operation aborted")));
									return;
								}
								if (!killedDueToLimit && code !== 0 && code !== 1) {
									const raw = stderr.trim();
									// Detect a malformed regex (rg exits 2 with a "regex parse error"
									// / "unclosed" / "unbalanced" / "repetition quantifier" message)
									// and convert the raw Rust parser error into an actionable hint:
									// either re-run with literal:true to treat the pattern as a plain
									// string, or escape the special chars. This is the most common
									// model-reachable mistake with this tool.
									if (
										/regex (parse error|error)|unbalanced|unclosed|repetition quantifier|nothing to repeat/i.test(
											raw,
										)
									) {
										settle(() =>
											reject(
												new Error(
													`Invalid regex pattern ${JSON.stringify(pattern)}: ${raw}\nHint: set literal:true to treat it as a plain string, or fix the regex (escape special chars like ( ) [ ] { } . * + ? | \\ ^ $ with a backslash).`,
												),
											),
										);
										return;
									}
									const errorMsg = raw || `ripgrep exited with code ${code}`;
									settle(() => reject(new Error(errorMsg)));
									return;
								}
								if (matchCount === 0) {
									settle(() =>
										resolve({ content: [{ type: "text", text: "No matches found" }], details: undefined }),
									);
									return;
								}

								// Format matches after streaming finishes so custom readFile() backends can be async.
								for (const match of matches) {
									if (contextValue === 0 && match.lineText !== undefined) {
										const relativePath = formatPath(match.filePath);
										const sanitized = match.lineText
											.replace(/\r\n/g, "\n")
											.replace(/\r/g, "")
											.replace(/\n$/, "");
										const { text: truncatedText, wasTruncated } = truncateLine(sanitized);
										if (wasTruncated) linesTruncated = true;
										outputLines.push(`${relativePath}:${match.lineNumber}: ${truncatedText}`);
									} else {
										const block = await formatBlock(match.filePath, match.lineNumber);
										outputLines.push(...block);
									}
								}

								const rawOutput = outputLines.join("\n");
								// Apply byte truncation. There is no line limit here because the match limit already capped rows.
								const truncation = truncateHead(rawOutput, { maxLines: Number.MAX_SAFE_INTEGER });
								let output = truncation.content;
								const details: GrepToolDetails = {};
								// Build actionable notices for truncation and match limits.
								const notices: string[] = [];
								if (matchLimitReached) {
									notices.push(
										`${effectiveLimit} matches limit reached. Use limit=${effectiveLimit * 2} for more, or refine pattern`,
									);
									details.matchLimitReached = effectiveLimit;
								}
								if (truncation.truncated) {
									notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
									details.truncation = truncation;
								}
								if (linesTruncated) {
									notices.push(
										`Some lines truncated to ${GREP_MAX_LINE_LENGTH} chars. Use read tool to see full lines`,
									);
									details.linesTruncated = true;
								}
								if (notices.length > 0) output += `\n\n[${notices.join(". ")}]`;
								settle(() =>
									resolve({
										content: [{ type: "text", text: output }],
										details: Object.keys(details).length > 0 ? details : undefined,
									}),
								);
							} catch (err) {
								// An async EventEmitter callback's returned promise is dropped by the
								// emitter — without this catch, a throw in the formatting loop (e.g.
								// formatBlock → path.relative/truncateLine, or a future edit) would
								// (1) never reach settle() → the outer Promise hangs forever → the
								// agent loop freezes on `await grep`, and (2) the dropped rejected
								// promise becomes unhandledRejection → process crash. settle() is
								// idempotent (the `settled` guard) so this is safe even if a prior
								// path already settled. (opt #121)
								settle(() => reject(err as Error));
							}
						});
					} catch (err) {
						settle(() => reject(err as Error));
					}
				})();
			});
		},
		renderCall(args, theme, context) {
			const text = (context.lastComponent as Text | undefined) ?? new Text("", 0, 0);
			text.setText(formatGrepCall(args, theme));
			return text;
		},
		renderResult(result, options, theme, context) {
			const text = (context.lastComponent as Text | undefined) ?? new Text("", 0, 0);
			text.setText(formatGrepResult(result as any, options, theme, context.showImages));
			return text;
		},
	};
}

export function createGrepTool(cwd: string, options?: GrepToolOptions): AgentTool<typeof grepSchema> {
	return wrapToolDefinition(createGrepToolDefinition(cwd, options));
}

import { createInterface } from "node:readline";
import type { AgentTool } from "@pi-recon/repi-agent-core";
import { Text } from "@pi-recon/repi-tui";
import { spawn } from "child_process";
import path from "path";
import { type Static, Type } from "typebox";
import { ensureTool } from "../../utils/tools-manager.ts";
import type { ToolDefinition, ToolRenderResultOptions } from "../extensions/types.ts";
import { themedKeyHint } from "../presentation/keybinding-hints.ts";
import type { Theme } from "../presentation/theme.ts";
import { pathExists, resolveToCwd } from "./path-utils.ts";
import { getTextOutput, invalidArgText, shortenPath, str } from "./render-utils.ts";
import { wrapToolDefinition } from "./tool-definition-wrapper.ts";
import { DEFAULT_MAX_BYTES, formatSize, type TruncationResult, truncateHead } from "./truncate.ts";

function toPosixPath(value: string): string {
	return value.split(path.sep).join("/");
}

const findSchema = Type.Object({
	pattern: Type.String({
		description: "Glob pattern to match files, e.g. '*.ts', '**/*.json', or 'src/**/*.spec.ts'",
	}),
	path: Type.Optional(Type.String({ description: "Directory to search in (default: current directory)" })),
	limit: Type.Optional(Type.Number({ description: "Maximum number of results (default: 1000)" })),
});

export type FindToolInput = Static<typeof findSchema>;

const DEFAULT_LIMIT = 1000;

// Foundational opt #264: the `limit` arg is a bare Type.Number with NO upper
// bound. A model passing `limit:1e8` made fd output up to 100M paths, each
// pushed into the `lines` array via rl.on("line") BEFORE the close handler
// truncates → OOM (the tool-result cap #15/#33 only trims what reaches the
// model AFTER the tool returns; it does NOT bound the tool's own in-memory
// array). Same class as grep opt #262. Cap env-overridable (REPI_FIND_MAX_LIMIT,
// default 10000, 0 disables → MAX_SAFE_INTEGER). Read lazily at execute time.
const DEFAULT_FIND_MAX_LIMIT = 10000;
function resolveFindMaxLimit(): number {
	const raw = process.env.REPI_FIND_MAX_LIMIT;
	if (raw === undefined) return DEFAULT_FIND_MAX_LIMIT;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return DEFAULT_FIND_MAX_LIMIT;
	return n === 0 ? Number.MAX_SAFE_INTEGER : Math.floor(n);
}

// Wall cap on awaiting the fd child (opt #65). fd is awaited via child.on("close")
// with abort the only early escape. On a hung FUSE/NFS mount or a D-state fd
// (uninterruptible I/O), 'close' never fires — if the user doesn't abort (or
// SIGTERM can't reap a D-state process), the tool hangs forever and freezes the
// agent. fd is bounded by --max-results so a legitimate search exits well under
// this; the cap only fires on a genuinely hung process. On timeout we SIGKILL
// (escalate past the abort's SIGTERM — a D-state process ignores SIGTERM) and
// settle. 0 disables (Infinity). Read lazily at execute time so the value can
// be tuned via env without a process restart (and exercised in tests without
// resetModules).
function getFindTimeoutMs(): number {
	const raw = process.env.REPI_FIND_TIMEOUT_MS;
	if (raw === undefined) return 120_000;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return 120_000;
	return n === 0 ? Infinity : n;
}

export interface FindToolDetails {
	truncation?: TruncationResult;
	resultLimitReached?: number;
}

/**
 * Pluggable operations for the find tool.
 * Override these to delegate file search to remote systems (for example SSH).
 */
export interface FindOperations {
	/** Check if path exists */
	exists: (absolutePath: string) => Promise<boolean> | boolean;
	/** Find files matching glob pattern. Returns relative or absolute paths. */
	glob: (pattern: string, cwd: string, options: { ignore: string[]; limit: number }) => Promise<string[]> | string[];
}

const defaultFindOperations: FindOperations = {
	exists: pathExists,
	// This is a placeholder. Actual fd execution happens in execute() when no custom glob is provided.
	glob: () => [],
};

export interface FindToolOptions {
	/** Custom operations for find. Default: local filesystem plus fd */
	operations?: FindOperations;
}

function formatFindCall(args: { pattern: string; path?: string; limit?: number } | undefined, theme: Theme): string {
	const pattern = str(args?.pattern);
	const rawPath = str(args?.path);
	const path = rawPath !== null ? shortenPath(rawPath || ".") : null;
	const limit = args?.limit;
	const invalidArg = invalidArgText(theme);
	let text =
		theme.fg("toolTitle", theme.bold("find")) +
		" " +
		(pattern === null ? invalidArg : theme.fg("accent", pattern || "")) +
		theme.fg("toolOutput", ` in ${path === null ? invalidArg : path}`);
	if (limit !== undefined) {
		text += theme.fg("toolOutput", ` (limit ${limit})`);
	}
	return text;
}

function formatFindResult(
	result: {
		content: Array<{ type: string; text?: string; data?: string; mimeType?: string }>;
		details?: FindToolDetails;
	},
	options: ToolRenderResultOptions,
	theme: Theme,
	showImages: boolean,
): string {
	const output = getTextOutput(result, showImages).trim();
	let text = "";
	if (output) {
		const lines = output.split("\n");
		const maxLines = options.expanded ? lines.length : 20;
		const displayLines = lines.slice(0, maxLines);
		const remaining = lines.length - maxLines;
		text += `\n${displayLines.map((line) => theme.fg("toolOutput", line)).join("\n")}`;
		if (remaining > 0) {
			text += `${theme.fg("muted", `\n... (${remaining} more lines,`)} ${themedKeyHint(theme, "app.tools.expand", "to expand")}${theme.fg("muted", ")")}`;
		}
	}

	const resultLimit = result.details?.resultLimitReached;
	const truncation = result.details?.truncation;
	if (resultLimit || truncation?.truncated) {
		const warnings: string[] = [];
		if (resultLimit) warnings.push(`${resultLimit} results limit`);
		if (truncation?.truncated) warnings.push(`${formatSize(truncation.maxBytes ?? DEFAULT_MAX_BYTES)} limit`);
		text += `\n${theme.fg("warning", `[Truncated: ${warnings.join(", ")}]`)}`;
	}
	return text;
}

export function createFindToolDefinition(
	cwd: string,
	options?: FindToolOptions,
): ToolDefinition<typeof findSchema, FindToolDetails | undefined> {
	const customOps = options?.operations;
	return {
		name: "find",
		label: "find",
		description: `Search for files by glob pattern. Returns matching file paths relative to the search directory. Respects .gitignore. Output is truncated to ${DEFAULT_LIMIT} results or ${DEFAULT_MAX_BYTES / 1024}KB (whichever is hit first).`,
		promptSnippet: "Find files by glob pattern (respects .gitignore)",
		promptGuidelines: [
			"Batch independent read-only probes in one turn and do not repeat identical probes unless state changed.",
		],
		readOnly: true,
		parameters: findSchema,
		async execute(
			_toolCallId,
			{ pattern, path: searchDir, limit }: { pattern: string; path?: string; limit?: number },
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
				let stopChild: (() => void) | undefined;
				let wallTimer: NodeJS.Timeout | undefined;
				const settle = (fn: () => void) => {
					if (settled) return;
					settled = true;
					if (wallTimer) {
						clearTimeout(wallTimer);
						wallTimer = undefined;
					}
					signal?.removeEventListener("abort", onAbort);
					stopChild = undefined;
					fn();
				};
				const onAbort = () => {
					stopChild?.();
					settle(() => reject(new Error("Operation aborted")));
				};
				signal?.addEventListener("abort", onAbort, { once: true });

				(async () => {
					try {
						const searchPath = resolveToCwd(searchDir || ".", cwd);
						const effectiveLimit = Math.min(
							Math.max(1, Math.floor(limit ?? DEFAULT_LIMIT)),
							resolveFindMaxLimit(),
						);
						const ops = customOps ?? defaultFindOperations;

						// If custom operations provide glob(), use that instead of fd.
						if (customOps?.glob) {
							if (!(await ops.exists(searchPath))) {
								settle(() => reject(new Error(`Path not found: ${searchPath}`)));
								return;
							}
							if (signal?.aborted) {
								settle(() => reject(new Error("Operation aborted")));
								return;
							}
							const results = await ops.glob(pattern, searchPath, {
								ignore: ["**/node_modules/**", "**/.git/**"],
								limit: effectiveLimit,
							});
							if (signal?.aborted) {
								settle(() => reject(new Error("Operation aborted")));
								return;
							}
							if (results.length === 0) {
								settle(() =>
									resolve({
										content: [{ type: "text", text: "No files found matching pattern" }],
										details: undefined,
									}),
								);
								return;
							}

							// Relativize paths against the search root for stable output.
							const relativized = results.map((p) => {
								if (p.startsWith(searchPath)) return toPosixPath(p.slice(searchPath.length + 1));
								return toPosixPath(path.relative(searchPath, p));
							});
							const resultLimitReached = relativized.length >= effectiveLimit;
							const rawOutput = relativized.join("\n");
							const truncation = truncateHead(rawOutput, { maxLines: Number.MAX_SAFE_INTEGER });
							let resultOutput = truncation.content;
							const details: FindToolDetails = {};
							const notices: string[] = [];
							if (resultLimitReached) {
								notices.push(
									`${effectiveLimit} results limit reached. Use limit=${effectiveLimit * 2} for more, or refine pattern`,
								);
								details.resultLimitReached = effectiveLimit;
							}
							if (truncation.truncated) {
								notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
								details.truncation = truncation;
							}
							if (notices.length > 0) {
								resultOutput += `\n\n[${notices.join(". ")}]`;
							}
							settle(() =>
								resolve({
									content: [{ type: "text", text: resultOutput }],
									details: Object.keys(details).length > 0 ? details : undefined,
								}),
							);
							return;
						}

						// Default implementation uses fd.
						const fdPath = await ensureTool("fd", true);
						if (signal?.aborted) {
							settle(() => reject(new Error("Operation aborted")));
							return;
						}
						if (!fdPath) {
							settle(() =>
								reject(
									new Error(
										"fd is not available and could not be downloaded. Use the bash tool to find files instead, e.g. bash 'find <path> -type f -name \"<glob>\"'.",
									),
								),
							);
							return;
						}

						// Build fd arguments. --no-require-git makes fd apply hierarchical .gitignore
						// semantics whether or not the search path is inside a git repository, without
						// leaking sibling-directory rules the way --ignore-file (a global source) would.
						const args: string[] = [
							"--glob",
							"--color=never",
							"--hidden",
							"--no-require-git",
							"--max-results",
							String(effectiveLimit),
						];

						// fd --glob matches against the basename unless --full-path is set; in --full-path
						// mode it matches against the absolute candidate path, so a path-containing
						// pattern like 'src/**/*.spec.ts' needs a leading '**/' to match anything.
						let effectivePattern = pattern;
						if (pattern.includes("/")) {
							args.push("--full-path");
							if (!pattern.startsWith("/") && !pattern.startsWith("**/") && pattern !== "**") {
								effectivePattern = `**/${pattern}`;
							}
						}
						args.push("--", effectivePattern, searchPath);

						const child = spawn(fdPath, args, { stdio: ["ignore", "pipe", "pipe"] });
						const rl = createInterface({ input: child.stdout });
						let stderr = "";
						const lines: string[] = [];

						// Defense-in-depth: a stream-level 'error' on child.stdout/readline
						// (rare, usually paired with child "close") without a listener would
						// throw `Unhandled 'error' event`. Swallow; the child "error"/"close"
						// handlers own real failure reporting. Same guard on child.stderr:
						// it is a piped Readable that can emit 'error' independently
						// (EIO/EBADF/EPIPE) — opt #40 fixed stdout but missed stderr.
						rl.on("error", () => {});
						child.stdout?.on("error", () => {});
						child.stderr?.on("error", () => {});

						stopChild = () => {
							if (!child.killed) {
								child.kill();
							}
						};

						// Wall timeout (opt #65): SIGKILL on timeout (escalate past the
						// abort's SIGTERM — a D-state fd ignores SIGTERM). The late 'close'
						// is swallowed by the `settled` guard.
						const findTimeoutMs = getFindTimeoutMs();
						if (Number.isFinite(findTimeoutMs) && findTimeoutMs > 0) {
							wallTimer = setTimeout(() => {
								try {
									child.kill("SIGKILL");
								} catch {
									/* already dead */
								}
								settle(() =>
									reject(
										new Error(
											`find timed out after ${findTimeoutMs}ms (fd hung — likely a FUSE/NFS mount or D-state process). Try narrowing the search path.`,
										),
									),
								);
							}, findTimeoutMs);
						}

						const cleanup = () => {
							rl.close();
						};

						child.stderr?.on("data", (chunk) => {
							stderr += chunk.toString();
						});

						rl.on("line", (line) => {
							lines.push(line);
						});

						child.on("error", (error) => {
							cleanup();
							settle(() => reject(new Error(`Failed to run fd: ${error.message}`)));
						});

						child.on("close", (code) => {
							try {
								cleanup();
								if (signal?.aborted) {
									settle(() => reject(new Error("Operation aborted")));
									return;
								}
								const output = lines.join("\n");
								if (code !== 0) {
									const raw = stderr.trim();
									// Detect a malformed glob pattern (fd exits non-zero with a
									// "glob parse error" / "unbalanced" / "unclosed" / "invalid
									// pattern" message) and convert it into an actionable hint to
									// escape the special glob chars or simplify the pattern.
									if (/glob (parse error|error)|unbalanced|unclosed|invalid pattern/i.test(raw)) {
										settle(() =>
											reject(
												new Error(
													`Invalid glob pattern ${JSON.stringify(pattern)}: ${raw}\nHint: escape special glob chars with a backslash, or simplify the pattern.`,
												),
											),
										);
										return;
									}
									// fd returns exit 0 for "no matches" AND for a --max-results
									// short-circuit, so a non-zero exit is a REAL error (permission
									// denied on a subdir, broken symlink, etc). Previously this was
									// only rejected when stdout was empty (`if (!output)`), which
									// silently demoted a real error that produced partial output to
									// success — misleading the model into treating an incomplete
									// search as exhaustive. Always reject on a non-zero fd exit.
									const errorMsg = raw || `fd exited with code ${code}`;
									settle(() => reject(new Error(errorMsg)));
									return;
								}
								if (!output) {
									settle(() =>
										resolve({
											content: [{ type: "text", text: "No files found matching pattern" }],
											details: undefined,
										}),
									);
									return;
								}

								const relativized: string[] = [];
								for (const rawLine of lines) {
									const line = rawLine.replace(/\r$/, "").trim();
									if (!line) continue;
									const hadTrailingSlash = line.endsWith("/") || line.endsWith("\\");
									let relativePath = line;
									if (line.startsWith(searchPath)) {
										relativePath = line.slice(searchPath.length + 1);
									} else {
										relativePath = path.relative(searchPath, line);
									}
									if (hadTrailingSlash && !relativePath.endsWith("/")) relativePath += "/";
									relativized.push(toPosixPath(relativePath));
								}

								const resultLimitReached = relativized.length >= effectiveLimit;
								const rawOutput = relativized.join("\n");
								const truncation = truncateHead(rawOutput, { maxLines: Number.MAX_SAFE_INTEGER });
								let resultOutput = truncation.content;
								const details: FindToolDetails = {};
								const notices: string[] = [];
								if (resultLimitReached) {
									notices.push(
										`${effectiveLimit} results limit reached. Use limit=${effectiveLimit * 2} for more, or refine pattern`,
									);
									details.resultLimitReached = effectiveLimit;
								}
								if (truncation.truncated) {
									notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
									details.truncation = truncation;
								}
								if (notices.length > 0) {
									resultOutput += `\n\n[${notices.join(". ")}]`;
								}
								settle(() =>
									resolve({
										content: [{ type: "text", text: resultOutput }],
										details: Object.keys(details).length > 0 ? details : undefined,
									}),
								);
							} catch (err) {
								// An EventEmitter 'close' callback's sync throw propagates out of the emitter
								// (uncaughtException — no global handler) and settle() is never reached, so the
								// outer Promise hangs forever and the agent loop freezes on `await find`.
								// settle() is idempotent (the `settled` guard) so this is safe even if a prior
								// path already settled. Mirrors opt #121 (grep close-handler throw). (opt #128)
								settle(() => reject(err as Error));
							}
						});
					} catch (e) {
						if (signal?.aborted) {
							settle(() => reject(new Error("Operation aborted")));
							return;
						}
						const error = e instanceof Error ? e : new Error(String(e));
						settle(() => reject(error));
					}
				})();
			});
		},
		renderCall(args, theme, context) {
			const text = (context.lastComponent as Text | undefined) ?? new Text("", 0, 0);
			text.setText(formatFindCall(args, theme));
			return text;
		},
		renderResult(result, options, theme, context) {
			const text = (context.lastComponent as Text | undefined) ?? new Text("", 0, 0);
			text.setText(formatFindResult(result as any, options, theme, context.showImages));
			return text;
		},
	};
}

export function createFindTool(cwd: string, options?: FindToolOptions): AgentTool<typeof findSchema> {
	return wrapToolDefinition(createFindToolDefinition(cwd, options));
}

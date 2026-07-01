import { closeSync, existsSync, openSync, readdirSync, readFileSync, readSync, statSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "path";
import { CONFIG_DIR_NAME } from "../config.ts";
import { parseFrontmatter } from "../utils/frontmatter.ts";
import { resolvePath } from "../utils/paths.ts";
import { createSyntheticSourceInfo, type SourceInfo } from "./source-info.ts";

/**
 * Represents a prompt template loaded from a markdown file
 */
export interface PromptTemplate {
	name: string;
	description: string;
	argumentHint?: string;
	content: string;
	sourceInfo: SourceInfo;
	filePath: string; // Absolute path to the template file
}

/**
 * Parse command arguments respecting quoted strings (bash-style)
 * Returns array of arguments
 */
export function parseCommandArgs(argsString: string): string[] {
	const args: string[] = [];
	let current = "";
	let inQuote: string | null = null;

	for (let i = 0; i < argsString.length; i++) {
		const char = argsString[i];

		if (inQuote) {
			if (char === inQuote) {
				inQuote = null;
			} else {
				current += char;
			}
		} else if (char === '"' || char === "'") {
			inQuote = char;
		} else if (/\s/.test(char)) {
			if (current) {
				args.push(current);
				current = "";
			}
		} else {
			current += char;
		}
	}

	if (current) {
		args.push(current);
	}

	return args;
}

/**
 * Substitute argument placeholders in template content
 * Supports:
 * - $1, $2, ... for positional args
 * - $@ and $ARGUMENTS for all args
 * - ${@:N} for args from Nth onwards (bash-style slicing)
 * - ${@:N:L} for L args starting from Nth
 *
 * Note: Replacement happens on the template string only. Argument values
 * containing patterns like $1, $@, or $ARGUMENTS are NOT recursively substituted.
 */
export function substituteArgs(content: string, args: string[]): string {
	let result = content;

	// Replace $1, $2, etc. with positional args FIRST (before wildcards)
	// This prevents wildcard replacement values containing $<digit> patterns from being re-substituted
	result = result.replace(/\$(\d+)/g, (_, num) => {
		const index = parseInt(num, 10) - 1;
		return args[index] ?? "";
	});

	// Replace ${@:start} or ${@:start:length} with sliced args (bash-style)
	// Process BEFORE simple $@ to avoid conflicts
	result = result.replace(/\$\{@:(\d+)(?::(\d+))?\}/g, (_, startStr, lengthStr) => {
		let start = parseInt(startStr, 10) - 1; // Convert to 0-indexed (user provides 1-indexed)
		// Treat 0 as 1 (bash convention: args start at 1)
		if (start < 0) start = 0;

		if (lengthStr) {
			const length = parseInt(lengthStr, 10);
			return args.slice(start, start + length).join(" ");
		}
		return args.slice(start).join(" ");
	});

	// Pre-compute all args joined (optimization)
	const allArgs = args.join(" ");

	// Replace $ARGUMENTS with all args joined (new syntax, aligns with Claude, Codex, OpenCode)
	result = result.replace(/\$ARGUMENTS/g, allArgs);

	// Replace $@ with all args joined (existing syntax)
	result = result.replace(/\$@/g, allArgs);

	return result;
}

// opt #169 — stat-first regular-file + size-cap guard for the readFileSync sites
// that load user-controlled files INTO THE SYSTEM PROMPT (every ancestor
// CLAUDE.md/AGENTS.md, --system-prompt/--append-system-prompt file args, every
// enabled SKILL.md and prompt template). The old code did unguarded
// readFileSync(path, "utf-8") with NO regular-file check and NO size guard
// (unlike the read tool, opt #34). A multi-GB CLAUDE.md or skill file OOMs the
// agent at startup/reload; pointing --system-prompt at a special file
// (/dev/zero, a FIFO, a device) makes readFileSync hang or grow unbounded.
// Doctrine mirrors the read-tool pre-readFile guards (#34/#30):
//   1. statSync regular-file check (reject isDirectory() || !isFile()) —
//      rejects /dev/zero, FIFOs, sockets, dirs — with an actionable error that
//      the caller's existing catch surfaces as a warning.
//   2. size cap using the SHARED REPI_READ_TEXT_FILE_MAX_BYTES knob (default
//      16 MB, 0 disables — same name as opt #163 storage.readTextFile, so one
//      cap governs all bounded-text read paths). Files <= cap keep the exact
//      readFileSync-utf8 path (byte-identical). Oversized files return a
//      BOUNDED head+tail with a truncation marker (faithful for system-prompt
//      inlining: a giant CLAUDE.md -> bounded head+tail) instead of loading the
//      whole file. Companion to opt #3 head+tail and opt #34/#163.
// The helper is LOCAL to this opt's file-set (NOT in repi/text.ts) to avoid
// merge conflicts with #166/#170, and imported by resource-loader.ts and
// skills.ts. prompt-templates.ts is the home because resource-loader already
// imports it (no new edge) and skills.ts -> prompt-templates.ts adds no cycle.
const DEFAULT_READ_TEXT_FILE_MAX_BYTES = 16 * 1024 * 1024;
function resolveReadTextFileMaxBytes(): number {
	const raw = process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
	if (raw !== undefined && raw.trim() !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed) && parsed >= 0) return Math.floor(parsed);
	}
	return DEFAULT_READ_TEXT_FILE_MAX_BYTES;
}

// One-shot stderr warning so an oversized system-prompt file is observable
// rather than silently truncated (matches opt #163's warnOverCap contract).
const overCapWarnedPaths = new Set<string>();
function warnOverCap(path: string, size: number, cap: number): void {
	if (overCapWarnedPaths.has(path)) return;
	overCapWarnedPaths.add(path);
	process.stderr.write(
		`repi: readBoundedTextFile "${path}" is ${size} bytes > cap ${cap} (REPI_READ_TEXT_FILE_MAX_BYTES); inlining bounded head+tail into system prompt\n`,
	);
}

// Streaming head+tail read: never loads the whole file. Reads the first and
// last `cap/2` bytes via positioned readSync and decodes UTF-8 (a split leading
// multi-byte sequence is left to String's replacement semantics — the body is
// observational, not parsed). Memory stays bounded to two cap/2 buffers.
function readBoundedHeadTailText(path: string, size: number, cap: number): string {
	const fd = openSync(path, "r");
	try {
		const half = Math.floor(cap / 2);
		const headLen = Math.min(half, size);
		const tailLen = Math.min(half, size - headLen);
		const headBuf = Buffer.alloc(headLen);
		let headRead = 0;
		while (headRead < headLen) {
			const n = readSync(fd, headBuf, headRead, headLen - headRead, headRead);
			if (n <= 0) break;
			headRead += n;
		}
		const tailBuf = Buffer.alloc(tailLen);
		let tailRead = 0;
		const tailStart = size - tailLen;
		while (tailRead < tailLen) {
			const n = readSync(fd, tailBuf, tailRead, tailLen - tailRead, tailStart + tailRead);
			if (n <= 0) break;
			tailRead += n;
		}
		const head = headBuf.subarray(0, headRead).toString("utf-8");
		const tail = tailBuf.subarray(0, tailRead).toString("utf-8");
		const marker = `\n...<truncated: file is ${size} bytes > REPI_READ_TEXT_FILE_MAX_BYTES cap ${cap}; showing first ${headRead} + last ${tailRead} bytes>...\n`;
		return `${head}${marker}${tail}`;
	} finally {
		try {
			closeSync(fd);
		} catch {
			// Best-effort: fd may already be invalid.
		}
	}
}

/**
 * Read a user-controlled text file that will be inlined into the system prompt,
 * with a regular-file check and a shared size cap. Throws an actionable Error
 * for non-regular files (directory/device/FIFO/socket); returns bounded
 * head+tail content with a marker for files over the cap; otherwise returns the
 * exact readFileSync-utf8 content (byte-identical). Exported for testing and
 * for reuse by resource-loader.ts and skills.ts (opt #169).
 */
export function readBoundedTextFile(path: string): string {
	const stats = statSync(path);
	if (stats.isDirectory() || !stats.isFile()) {
		throw new Error(
			`"${path}" is not a regular file (directory/device/FIFO/socket); refusing to load into system prompt. Hint: point the file arg at a regular text file.`,
		);
	}
	const cap = resolveReadTextFileMaxBytes();
	if (cap > 0 && stats.size > cap) {
		warnOverCap(path, stats.size, cap);
		return readBoundedHeadTailText(path, stats.size, cap);
	}
	return readFileSync(path, "utf-8");
}

// Exported for testing (opt #169).
export function loadTemplateFromFile(filePath: string, sourceInfo: SourceInfo): PromptTemplate | null {
	try {
		const rawContent = readBoundedTextFile(filePath);
		const { frontmatter, body } = parseFrontmatter<Record<string, string>>(rawContent);

		const name = basename(filePath).replace(/\.md$/, "");

		// Get description from frontmatter or first non-empty line
		let description = frontmatter.description || "";
		if (!description) {
			const firstLine = body.split("\n").find((line) => line.trim());
			if (firstLine) {
				// Truncate if too long
				description = firstLine.slice(0, 60);
				if (firstLine.length > 60) description += "...";
			}
		}

		return {
			name,
			description,
			...(frontmatter["argument-hint"] && { argumentHint: frontmatter["argument-hint"] }),
			content: body,
			sourceInfo,
			filePath,
		};
	} catch {
		return null;
	}
}

/**
 * Scan a directory for .md files (non-recursive) and load them as prompt templates.
 */
function loadTemplatesFromDir(dir: string, getSourceInfo: (filePath: string) => SourceInfo): PromptTemplate[] {
	const templates: PromptTemplate[] = [];

	if (!existsSync(dir)) {
		return templates;
	}

	try {
		const entries = readdirSync(dir, { withFileTypes: true });

		for (const entry of entries) {
			const fullPath = join(dir, entry.name);

			// For symlinks, check if they point to a file
			let isFile = entry.isFile();
			if (entry.isSymbolicLink()) {
				try {
					const stats = statSync(fullPath);
					isFile = stats.isFile();
				} catch {
					// Broken symlink, skip it
					continue;
				}
			}

			if (isFile && entry.name.endsWith(".md")) {
				const template = loadTemplateFromFile(fullPath, getSourceInfo(fullPath));
				if (template) {
					templates.push(template);
				}
			}
		}
	} catch {
		return templates;
	}

	return templates;
}

export interface LoadPromptTemplatesOptions {
	/** Working directory for project-local templates. */
	cwd: string;
	/** Agent config directory for global templates. */
	agentDir: string;
	/** Explicit prompt template paths (files or directories). */
	promptPaths: string[];
	/** Include default prompt directories. */
	includeDefaults: boolean;
}

/**
 * Load all prompt templates from:
 * 1. Global: agentDir/prompts/
 * 2. Project: cwd/{CONFIG_DIR_NAME}/prompts/
 * 3. Explicit prompt paths
 */
export function loadPromptTemplates(options: LoadPromptTemplatesOptions): PromptTemplate[] {
	const resolvedCwd = resolvePath(options.cwd);
	const resolvedAgentDir = resolvePath(options.agentDir);
	const promptPaths = options.promptPaths;
	const includeDefaults = options.includeDefaults;

	const templates: PromptTemplate[] = [];

	const globalPromptsDir = join(resolvedAgentDir, "prompts");
	const projectPromptsDir = resolve(resolvedCwd, CONFIG_DIR_NAME, "prompts");

	const isUnderPath = (target: string, root: string): boolean => {
		const normalizedRoot = resolve(root);
		if (target === normalizedRoot) {
			return true;
		}
		const prefix = normalizedRoot.endsWith(sep) ? normalizedRoot : `${normalizedRoot}${sep}`;
		return target.startsWith(prefix);
	};

	const getSourceInfo = (resolvedPath: string): SourceInfo => {
		if (isUnderPath(resolvedPath, globalPromptsDir)) {
			return createSyntheticSourceInfo(resolvedPath, {
				source: "local",
				scope: "user",
				baseDir: globalPromptsDir,
			});
		}
		if (isUnderPath(resolvedPath, projectPromptsDir)) {
			return createSyntheticSourceInfo(resolvedPath, {
				source: "local",
				scope: "project",
				baseDir: projectPromptsDir,
			});
		}
		return createSyntheticSourceInfo(resolvedPath, {
			source: "local",
			baseDir: statSync(resolvedPath).isDirectory() ? resolvedPath : dirname(resolvedPath),
		});
	};

	if (includeDefaults) {
		templates.push(...loadTemplatesFromDir(globalPromptsDir, getSourceInfo));
		templates.push(...loadTemplatesFromDir(projectPromptsDir, getSourceInfo));
	}

	// 3. Load explicit prompt paths
	for (const rawPath of promptPaths) {
		const resolvedPath = resolvePath(rawPath, resolvedCwd, { trim: true });
		if (!existsSync(resolvedPath)) {
			continue;
		}

		try {
			const stats = statSync(resolvedPath);
			if (stats.isDirectory()) {
				templates.push(...loadTemplatesFromDir(resolvedPath, getSourceInfo));
			} else if (stats.isFile() && resolvedPath.endsWith(".md")) {
				const template = loadTemplateFromFile(resolvedPath, getSourceInfo(resolvedPath));
				if (template) {
					templates.push(template);
				}
			}
		} catch {
			// Ignore read failures
		}
	}

	return templates;
}

/**
 * Expand a prompt template if it matches a template name.
 * Returns the expanded content or the original text if not a template.
 */
export function expandPromptTemplate(text: string, templates: PromptTemplate[]): string {
	if (!text.startsWith("/")) return text;

	const match = text.match(/^\/([^\s]+)(?:\s+([\s\S]*))?$/);
	if (!match) return text;

	const templateName = match[1];
	const argsString = match[2] ?? "";

	const template = templates.find((t) => t.name === templateName);
	if (template) {
		const args = parseCommandArgs(argsString);
		return substituteArgs(template.content, args);
	}

	return text;
}

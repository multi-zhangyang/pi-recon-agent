import { createHash } from "node:crypto";
import {
	appendFileSync,
	chmodSync,
	closeSync,
	mkdirSync,
	openSync,
	readdirSync,
	readFileSync,
	readSync,
	statSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { getAgentDir } from "../../config.ts";
import { atomicWriteFileSync } from "../tools/atomic-write.ts";
import { LruCache } from "./lru-cache.ts";
import { currentMissionSessionScope } from "./session-scope.ts";

export function reconDir(): string {
	return join(getAgentDir(), "recon");
}

export function reconArchiveDir(): string {
	return join(reconDir(), "archive");
}

export function missionPath(name: string): string {
	return join(reconDir(), "mission", name);
}

/**
 * Return the stable scope used by mission storage. A workspace-level scope was
 * historically enough for one process, but two resumed sessions in the same
 * workspace would overwrite `current.json`. Persistent CLI sessions add their
 * session file here so each runtime gets an independent mission pointer while
 * keeping the legacy path for SDK/in-memory callers that have no session file.
 */
export function missionStorageScope(): string {
	const workspace = process.env.REPI_MISSION_SCOPE?.trim() || process.cwd();
	const session = currentMissionSessionScope();
	return session ? `${workspace}\nsession:${session}` : workspace;
}

export function currentMissionPath(): string {
	const hasExplicitScope = Boolean(process.env.REPI_MISSION_SCOPE?.trim());
	const hasSessionScope = Boolean(currentMissionSessionScope());
	if (!hasExplicitScope && !hasSessionScope) return missionPath("current.json");
	const suffix = createHash("sha256").update(missionStorageScope()).digest("hex").slice(0, 16);
	return missionPath(`current-${suffix}.json`);
}

export function evidenceLedgerPath(): string {
	return join(reconDir(), "evidence", "ledger.md");
}

export function evidenceRunsDir(): string {
	return join(reconDir(), "evidence", "runs");
}

export function evidenceMapsDir(): string {
	return join(reconDir(), "evidence", "maps");
}

export function evidenceBrowserDir(): string {
	return join(reconDir(), "evidence", "browser");
}

export function evidenceWebAuthzDir(): string {
	return join(reconDir(), "evidence", "web-authz");
}

export function evidenceExploitLabDir(): string {
	return join(reconDir(), "evidence", "exploit-lab");
}

export function evidenceMobileRuntimeDir(): string {
	return join(reconDir(), "evidence", "mobile-runtime");
}

export function evidenceNativeRuntimeDir(): string {
	return join(reconDir(), "evidence", "native-runtime");
}

export function evidenceKernelDir(): string {
	return join(reconDir(), "evidence", "kernel");
}

export function evidenceGraphsDir(): string {
	return join(reconDir(), "evidence", "graphs");
}

export function evidenceChainsDir(): string {
	return join(reconDir(), "evidence", "chains");
}

export function evidenceDecisionsDir(): string {
	return join(reconDir(), "evidence", "decisions");
}

export function evidenceCampaignsDir(): string {
	return join(reconDir(), "evidence", "campaigns");
}

export function evidenceOperationsDir(): string {
	return join(reconDir(), "evidence", "operations");
}

export function evidenceDelegationsDir(): string {
	return join(reconDir(), "evidence", "delegations");
}

export function evidenceSwarmsDir(): string {
	return join(reconDir(), "evidence", "swarms");
}

export function evidenceSupervisorsDir(): string {
	return join(reconDir(), "evidence", "supervisor");
}

export function evidenceReflectionsDir(): string {
	return join(reconDir(), "evidence", "reflections");
}

export function evidenceContextsDir(): string {
	return join(reconDir(), "evidence", "contexts");
}

export function evidenceOperatorsDir(): string {
	return join(reconDir(), "evidence", "operators");
}

export function evidenceVerifiersDir(): string {
	return join(reconDir(), "evidence", "verifiers");
}

export function evidenceCompilersDir(): string {
	return join(reconDir(), "evidence", "compilers");
}

export function evidenceReplayersDir(): string {
	return join(reconDir(), "evidence", "replayers");
}

export function evidenceAutofixDir(): string {
	return join(reconDir(), "evidence", "autofix");
}

export function evidenceFailuresDir(): string {
	return join(reconDir(), "evidence", "failures");
}

export function evidenceRepairsDir(): string {
	return join(reconDir(), "evidence", "repairs");
}

export function evidenceClaimReleaseDir(): string {
	return join(reconDir(), "evidence", "claim-release");
}

export function evidenceProofLoopsDir(): string {
	return join(reconDir(), "evidence", "proof-loops");
}

export function evidenceProfileCheckDir(): string {
	return join(reconDir(), "evidence", "profile-checks");
}

export function evidenceToolchainDir(): string {
	return join(reconDir(), "evidence", "toolchain");
}

export function runtimeFailureLedgerPath(): string {
	return join(evidenceFailuresDir(), "ledger.jsonl");
}

/**
 * Compact `{signature: count}` summary of the runtime-failure ledger. The
 * ledger itself is an append-only audit log (capped + rotated); this summary is
 * the O(1) source of truth for per-signature attempt counts used by the
 * "exhausted after maxAttempts" decision. Keeping counts here (not by scanning
 * the ledger) lets the ledger be safely rotated without resetting attempt
 * counts — and removes the O(n) per-failure scan of the growing ledger.
 */
export function runtimeFailureSummaryPath(): string {
	return join(evidenceFailuresDir(), "summary.json");
}

export function runtimeRepairQueuePath(): string {
	return join(evidenceRepairsDir(), "queue.jsonl");
}

export function reportDir(): string {
	return join(reconDir(), "reports");
}

export function builtinSkillFilePath(): string {
	return join(reconDir(), "builtin", "reverse-pentest-orchestrator", "SKILL.md");
}

export function builtinPromptFilePath(name: string): string {
	return join(reconDir(), "builtin", "prompts", `${name}.md`);
}

export function toolIndexPath(): string {
	return join(reconDir(), "tools", "tool-index.md");
}

export type RepiBuiltinPromptDefault = {
	name: string;
	description: string;
	argumentHint?: string;
	content: string;
};

export type RepiStorageDefaultsOptions = {
	skillContent?: string;
	prompts?: RepiBuiltinPromptDefault[];
};

export function chmodPrivate(path: string, mode: number): void {
	try {
		chmodSync(path, mode);
	} catch {
		// Best-effort on non-POSIX filesystems.
	}
}

// Keep generated-resource snapshots bounded in long-lived RPC processes. The
// profile normally has only a handful of paths; 512 leaves room for custom
// prompt names without retaining unbounded user-provided paths.
const generatedFiles = new LruCache<string, string>(512);

function ensureGeneratedPrivateFile(path: string, content: string): void {
	if (generatedFiles.get(path) === content) return;
	if (readTextFile(path, "") !== content) writePrivateTextFile(path, content);
	else chmodPrivate(path, 0o600);
	generatedFiles.set(path, content);
}

export function writePrivateTextFile(path: string, content: string): void {
	// Atomic temp+rename (mode 0o600): this is the SHARED write path for all REPI
	// runtime artifacts — missions, evidence, and generated resources — and
	// appendPrivateTextFile does a read-modify-write through it. A
	// plain writeFileSync truncates then writes, so a crash (SIGKILL/OOM/SIGTERM)
	// mid-write leaves a truncated/partial file; readTextFile swallows the parse
	// failure and returns "" (graceful, no crash) but the playbook/mission/evidence
	// is SILENTLY LOST. temp+rename means a reader sees either the complete prior
	// content or the complete new content. chmodPrivate after the rename still
	// enforces 0o600 (atomicWriteFileSync preserves an existing target's mode).
	const parent = dirname(path);
	mkdirSync(parent, { recursive: true, mode: 0o700 });
	chmodPrivate(parent, 0o700);
	atomicWriteFileSync(path, content, 0o600);
	chmodPrivate(path, 0o600);
	textFileCache.delete(path);
	jsonObjectFileCache.delete(path);
}

// Bound shared text reads before allocating large strings or line arrays. Files
// at or above the cap return the caller's fallback so oversized local artifacts
// degrade gracefully instead of exhausting the process. Override with
// REPI_READ_TEXT_FILE_MAX_BYTES; 0 disables the guard.
const DEFAULT_READ_TEXT_FILE_MAX_BYTES = 16 * 1024 * 1024;
function resolveReadTextFileMaxBytes(): number {
	const raw = process.env.REPI_READ_TEXT_FILE_MAX_BYTES;
	if (raw !== undefined && raw.trim() !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed) && parsed >= 0) return Math.floor(parsed);
	}
	return DEFAULT_READ_TEXT_FILE_MAX_BYTES;
}

// Avoid repeating the same diagnostic when a path is read several times.
// Warning de-duplication is best-effort. Bound it so probing many oversized
// paths cannot itself become a process-lifetime leak.
const overCapWarnedPaths = new LruCache<string, true>(512);

function warnOverCap(path: string, size: number, cap: number): void {
	if (overCapWarnedPaths.has(path)) return;
	overCapWarnedPaths.set(path, true);
	// NOT a silent drop: a truncated ledger/note is observable here. The
	// missing/unreadable case stays silent per the existing catch contract.
	process.stderr.write(
		`repi: readTextFile "${path}" is ${size} bytes > cap ${cap} (REPI_READ_TEXT_FILE_MAX_BYTES); returning fallback, content not loaded\n`,
	);
}

export function readTextFile(path: string, fallback = ""): string {
	try {
		const size = statSync(path).size;
		const cap = resolveReadTextFileMaxBytes();
		if (cap > 0 && size > cap) {
			warnOverCap(path, size, cap);
			return fallback;
		}
		return readFileSync(path, "utf-8");
	} catch {
		return fallback;
	}
}

// A REPI RPC process can serve many projects. Retain hot artifacts, but evict
// the least-recently-used path once the process has seen enough distinct files.
// Eviction never changes file contents: it only causes a later stat/read miss.
const textFileCache = new LruCache<string, { mtimeMs: number; size: number; value: string }>(256);

/**
 * mtime+size-keyed cache for repeated reads of stable artifacts. A stat is
 * cheaper than reparsing unchanged content. Missing or unreadable files are
 * not cached, so a later write is observed immediately.
 */
export function readTextFileCached(path: string, fallback = ""): string {
	try {
		const stat = statSync(path);
		const mtimeMs = stat.mtimeMs;
		const size = stat.size;
		// opt #163 — same stat-first OOM guard as readTextFile. readTextFileCached
		// previously statSync'd only for the cache key, not to bound the read; a
		// huge file still paid the unbounded readFileSync + jsonl split. The
		// over-cap case returns fallback and is NOT cached (matching the missing-
		// file doctrine) so a later shrink below the cap is observed on the next
		// call.
		const cap = resolveReadTextFileMaxBytes();
		if (cap > 0 && size > cap) {
			warnOverCap(path, size, cap);
			return fallback;
		}
		const cached = textFileCache.get(path);
		if (cached && cached.mtimeMs === mtimeMs && cached.size === size) {
			return cached.value;
		}
		const value = readFileSync(path, "utf-8");
		textFileCache.set(path, { mtimeMs, size, value });
		return value;
	} catch {
		return fallback;
	}
}

export function appendPrivateTextFile(path: string, text: string): void {
	// True append (O(chunk) write + a 1-byte tail read) instead of read-modify-write
	// (O(file) read + O(file) atomic rewrite on EVERY append). This is the SHARED
	// append path for REPI append-only artifacts. The bytes appended are identical
	// to the caller's preformatted payload, so hash-chain verification is
	// unaffected; only the write mechanism changes.
	//
	// Newline-separator contract preserved EXACTLY: the old code joined
	// `${current}${current.endsWith("\n") ? "" : "\n"}${text}` where `current` is
	// `readTextFile(path)` → "" on a missing OR empty file. So a separator "\n" is
	// prepended unless the existing content ends with "\n" — INCLUDING the missing
	// / empty case ("" does not end with "\n"), which is the existing leading-blank-
	// line behavior (harmless for JSONL readers that filter(Boolean) and for
	// markdown). We detect "doesn't end with \n" with a 1-byte range read of the
	// last byte (openSync + readSync at offset size-1); a missing or size-0 file
	// gets the separator too, matching the old path.
	const parent = dirname(path);
	mkdirSync(parent, { recursive: true, mode: 0o700 });
	chmodPrivate(parent, 0o700);
	let prefix = "\n";
	try {
		const size = statSync(path).size;
		if (size > 0) {
			const fd = openSync(path, "r");
			try {
				const buf = Buffer.alloc(1);
				if (readSync(fd, buf, 0, 1, size - 1) > 0 && buf[0] === 0x0a) prefix = "";
			} finally {
				closeSync(fd);
			}
		}
	} catch {
		// missing/unreadable → keep prefix "\n" (matches old: "" doesn't end with \n).
	}
	// Crash safety: appendFileSync is not atomic and may leave a partial trailing
	// line. JSONL readers skip malformed lines and markdown journals are tolerant.
	// If append fails (for example on a filesystem without O_APPEND), fall back to
	// the atomic read-modify-write path below.
	try {
		appendFileSync(path, `${prefix}${text}`, { encoding: "utf8", mode: 0o600 });
		return;
	} catch {
		// Fall through to the atomic read-modify-write fallback.
	}
	const current = readTextFile(path);
	writePrivateTextFile(path, `${current}${current.endsWith("\n") ? "" : "\n"}${text}`);
}

export function ensureRepiStorage(options: RepiStorageDefaultsOptions = {}): void {
	const dirs = [reconDir()];
	if (options.skillContent !== undefined) dirs.push(dirname(builtinSkillFilePath()));
	if ((options.prompts?.length ?? 0) > 0) dirs.push(dirname(builtinPromptFilePath("placeholder")));
	for (const dir of dirs) {
		mkdirSync(dir, { recursive: true, mode: 0o700 });
		chmodPrivate(dir, 0o700);
	}
	if (options.skillContent !== undefined) {
		const skillFile = builtinSkillFilePath();
		const content = `---\nname: reverse-pentest-orchestrator\ndescription: Built-in REPI orchestrator for reverse engineering, CTF, pwn, web/API pentest, JS signing, mobile, firmware, cloud/container, identity/AD, DFIR, malware analysis, and agent/LLM boundary testing tasks.\n---\n\n${options.skillContent}\n`;
		ensureGeneratedPrivateFile(skillFile, content);
	}
	for (const prompt of options.prompts ?? []) {
		const promptFile = builtinPromptFilePath(prompt.name);
		const content = `---\ndescription: ${prompt.description}\nargument-hint: "${prompt.argumentHint ?? ""}"\n---\n${prompt.content}\n`;
		ensureGeneratedPrivateFile(promptFile, content);
	}
}

export function recentMarkdownArtifacts(dir: string, limit: number): string[] {
	try {
		return readdirSync(dir)
			.filter((file) => file.endsWith(".md"))
			.sort()
			.reverse()
			.slice(0, limit)
			.map((file) => join(dir, file));
	} catch {
		return [];
	}
}

export function artifactBasename(path: string): string {
	return path.split(/[/\\]/).pop() ?? path;
}

export function readJsonObjectFile<T>(path: string): T | undefined {
	try {
		return JSON.parse(readFileSync(path, "utf-8")) as T;
	} catch {
		return undefined;
	}
}

const jsonObjectFileCache = new LruCache<string, { mtimeMs: number; size: number; value: unknown }>(256);

/**
 * mtime+size-keyed cache of {@link readJsonObjectFile}. It avoids reparsing
 * unchanged JSON while preserving the undefined-on-error contract. Parse
 * failures are not cached, so repaired files are observed on the next read.
 */
export function readJsonObjectFileCached<T>(path: string): T | undefined {
	try {
		const stat = statSync(path);
		const mtimeMs = stat.mtimeMs;
		const size = stat.size;
		const cached = jsonObjectFileCache.get(path);
		if (cached && cached.mtimeMs === mtimeMs && cached.size === size) {
			return cached.value as T | undefined;
		}
		const value = JSON.parse(readFileSync(path, "utf-8")) as T;
		jsonObjectFileCache.set(path, { mtimeMs, size, value });
		return value;
	} catch {
		return undefined;
	}
}

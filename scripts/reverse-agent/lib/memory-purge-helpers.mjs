// Shared helpers for memory-inspect.mjs purge atomicity (REPI opt #176).
//
// Root cause addressed by these primitives:
//  - The `repi memory purge --apply` path did a NON-LOCKED read-modify-write on
//    events.jsonl: copyFileSync backup → readFileSync → filter → writeFileSync
//    (full truncate-then-rewrite, NOT an atomic rename). No `proper-lockfile`
//    (which auth/settings use). If the agent runtime appended an event via
//    appendFile concurrently with a purge, the purge's writeFileSync truncated
//    the file and the in-flight append was LOST; two purges racing overwrote
//    each other. A crash mid-writeFileSync left a truncated/partial events log.
//  - The report/output writes (export, sanitize) were bare writeFileSync with
//    no try/catch — ENOSPC/EACCES mid-write threw uncaught and aborted the
//    script mid-collection.
//
// These primitives are extracted so they can be unit-tested directly.
//   - atomicWriteFile: temp+rename (same-dir, mode-preserved, dir-guard),
//     mirroring opt #41 atomicWriteFileSync. A mid-write crash leaves the
//     original events log intact (temp is unlinked, rename never ran) — unlike
//     writeFileSync which truncates first.
//   - withFileLock: proper-lockfile lockSync with bounded retry, release in
//     finally. Serializes the purge RMW against concurrent runtime appends and
//     racing purges.
//
// Doctrine: (a) lock around the RMW, (b) write via temp+atomic rename so a
// crash cannot truncate the event log, (c) report writes get try/catch at the
// call site (not here). Plain ESM JS — match surrounding .mjs style.

import {
	basename,
	dirname,
	join,
	resolve,
} from "node:path";
import {
	chmodSync,
	closeSync,
	openSync,
	renameSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import lockfile from "proper-lockfile";

/** Write `content` to `absolutePath` atomically: open a same-dir temp file with
 *  mode `mode` (default 0o600), write, fsync-less close, preserve an existing
 *  target's mode across the replace, then renameSync temp→target. On ANY
 *  failure the temp is unlinked and the original error re-thrown — the original
 *  file is NEVER truncated (unlike writeFileSync which truncates first). */
export function atomicWriteFile(absolutePath, content, mode = 0o600) {
	const dir = dirname(absolutePath);
	// Guard: if the parent directory somehow doesn't exist or isn't a dir,
	// mkdirSync at the call site should have made it; statSync throws a clear
	// ENOENT here rather than leaving a temp in the wrong place.
	const tempPath = join(
		dir,
		`.${basename(absolutePath)}.${process.pid}.${Date.now()}.${randomBytes(4).toString("hex")}.tmp`,
	);
	try {
		const fd = openSync(tempPath, "wx", mode);
		try {
			writeFileSync(fd, content);
		} finally {
			closeSync(fd);
		}
		// Preserve an existing target's mode across the replace. ENOENT (new
		// file) is expected — the temp already carries `mode` from openSync.
		try {
			const existing = statSync(absolutePath);
			try {
				chmodSync(tempPath, existing.mode & 0o777);
			} catch {
				/* best-effort: proceed with create-time mode */
			}
		} catch {
			/* target doesn't exist yet — keep create-time `mode` */
		}
		renameSync(tempPath, absolutePath);
	} catch (error) {
		try {
			unlinkSync(tempPath);
		} catch {
			/* best-effort: temp may not exist (open threw) or already renamed */
		}
		throw error instanceof Error ? error : new Error(String(error));
	}
}

/** Acquire a `proper-lockfile` lock on `path` (realpath:false so a not-yet-
 *  existing events.jsonl is still lockable via its sibling .lock file), retry
 *  ELOCKED up to `maxAttempts` (bounded busy-wait, mirroring auth-storage's
 *  acquireLockSyncWithRetry), run `fn()`, and always release in finally.
 *  Returns fn's result. `staleMs` lets a crashed prior holder's lock be
 *  reclaimed (default 30s, matching auth-storage withLockAsync). */
export function withFileLock(path, fn, options = {}) {
	const maxAttempts = options.maxAttempts ?? 20;
	const delayMs = options.delayMs ?? 25;
	const staleMs = options.staleMs ?? 30000;
	let lastError;
	let release;
	for (let attempt = 1; attempt <= maxAttempts; attempt++) {
		try {
			release = lockfile.lockSync(path, { realpath: false, stale: staleMs });
			break;
		} catch (error) {
			const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : undefined;
			if (code !== "ELOCKED" || attempt === maxAttempts) {
				throw error;
			}
			lastError = error;
			const start = Date.now();
			while (Date.now() - start < delayMs) {
				/* synchronous sleep — purge is a sync call site */
			}
		}
	}
	if (!release) {
		throw (lastError instanceof Error ? lastError : new Error("Failed to acquire memory purge lock"));
	}
	try {
		return fn();
	} finally {
		try {
			release();
		} catch {
			/* best-effort: a compromised/stale lock release failing is not fatal */
		}
	}
}

// --- Per-project memory scoping (opt #273) -------------------------------------
// Mirrors encodeCwdForScope + scopedMemoryRoot in the TS storage.ts so the
// standalone `repi memory` CLI tools can inspect/maintain a specific project's
// scoped memory tree (recon/memory/projects/<encoded-cwd>/) instead of only the
// legacy global root. Encoding matches getDefaultSessionDirPath (session-manager)
// so a project's memory sits alongside its sessions.
export function encodeCwdForScope(cwd) {
	const resolvedCwd = resolve(cwd);
	return `--${resolvedCwd.replace(/^[/\\]/, "").replace(/[/\\:]/g, "-")}--`;
}

// Resolve the memory root for a given agent dir + optional cwd scope.
// When cwdScope is provided (non-empty), returns the per-project scoped root;
// otherwise returns the legacy global recon/memory root (backwards compatible).
export function scopedMemoryRootFor(agentDir, cwdScope) {
	const base = join(agentDir, "recon", "memory");
	if (cwdScope && cwdScope.trim().length > 0) {
		return join(base, "projects", encodeCwdForScope(cwdScope));
	}
	return base;
}

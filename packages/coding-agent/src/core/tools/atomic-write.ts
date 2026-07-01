import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, openSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { chmod, open as fsOpen, writeFile as fsWriteFile, lstat, realpath, rename, stat, unlink } from "fs/promises";

/**
 * Write `content` to `absolutePath` atomically: write to a uniquely-named temp
 * file in the SAME directory as the target, then rename it into place.
 *
 * A plain `fs.writeFile(target, content)` truncates the target in place and
 * streams bytes into it. If the process is killed mid-write — SIGKILL by the OOM
 * killer, SIGTERM, or a hard crash — the target is left with only a prefix of
 * the intended content: a truncated, corrupt file. For an agent that edits
 * source files this is a data-loss footgun: a half-written file can break a
 * build silently and the user may not notice which file was clobbered.
 *
 * `rename` is atomic on POSIX when source and destination live on the same
 * filesystem, which same-directory placement guarantees (no EXDEV). Readers
 * therefore see either the complete old content or the complete new content,
 * never a partial write. On any error the temp file is unlinked so no stale
 * artifact is left behind.
 *
 * Mode preservation: a plain writeFile on an existing file preserves its inode
 * and mode (it opens with O_TRUNC). A temp+rename would otherwise replace the
 * target's mode with the temp file's default (0o666 & ~umask), silently
 * dropping e.g. an executable bit or a restrictive 0o600. We stat the target and
 * chmod the temp file to match before renaming, so existing-file mode is
 * preserved. A missing target (new file) keeps the default mode — matching plain
 * writeFile behavior. Ownership is not touched (chown needs privileges and is
 * the same user in practice).
 *
 * fsync is intentionally omitted: the guarantee we want is crash-consistency of
 * the file *content* (no half-written bytes visible to a later read), not
 * durability across a power failure. fsync on every edit/write would add
 * latency for a guarantee the harness does not need.
 *
 * Caller responsibilities: the target's parent directory must already exist
 * (the write tool mkdir's it; the edit tool only runs on existing files), and
 * concurrent writes to the SAME path must be serialized by the caller (both
 * tools do this via withFileMutationQueue). Different paths are independent.
 */
export async function atomicWriteFile(absolutePath: string, content: string): Promise<void> {
	// Refuse to clobber a directory. Without this guard the temp file would be
	// created INSIDE the target directory and the rename would then fail with a
	// raw EISDIR/ENOTDIR errno after leaving a stray temp — a confusing error and
	// a needless temp artifact. Surface a clear, actionable message instead. This
	// also acts as a defensive net for the edit tool (which normally catches this
	// earlier at readFile). ENOENT (new file) is expected and falls through.
	let targetStat: { isDirectory: () => boolean } | undefined;
	try {
		targetStat = await stat(absolutePath);
	} catch {
		/* ENOENT (new file) or stat denied — proceed; write/rename surfaces a real errno if the path is bad */
	}
	if (targetStat?.isDirectory()) {
		throw new Error(`${absolutePath} is a directory, not a file.`);
	}

	// Preserve symlinks. `rename(temp, target)` over a symlink path replaces the
	// symlink ENTRY with a regular file: the link is broken and the file it
	// pointed to is left untouched — a silent data-integrity bug for symlinked
	// config/dotfiles (common in dev trees). The pre-atomic `fs.writeFile` wrote
	// *through* the link to its target; preserve that semantics by resolving the
	// target to its realpath and temp+rename the REAL file (same-dir as the real
	// file ⇒ same filesystem ⇒ still atomic). For a dangling symlink realpath
	// throws ENOENT: write directly through the link (creates the pointed-to
	// file, keeps the link); atomicity is lost only for this rare dangling case,
	// which is preferable to breaking the link. ENOENT at lstat (new file, no
	// symlink) falls through with effectivePath === absolutePath.
	let effectivePath = absolutePath;
	try {
		const linkStat = await lstat(absolutePath);
		if (linkStat.isSymbolicLink()) {
			try {
				effectivePath = await realpath(absolutePath);
			} catch {
				// Dangling symlink: write through the link rather than break it.
				// Pass an explicit 0o600 mode: a bare fsWriteFile(path, content,
				// "utf-8") creates the pointed-to file with 0o666 & ~umask ≈ 0o644
				// (world-readable), while the temp+rename path above explicitly
				// creates with 0o600. A write/edit through a dangling symlink
				// (e.g. a credential written to a symlinked config whose target
				// doesn't exist yet) would silently leak the secret on a
				// multi-user system. Match the temp path's mode so the dangling
				// case is no less private than the non-dangling one. Atomicity is
				// lost only for this rare dangling case, which is preferable to
				// breaking the link.
				await fsWriteFile(absolutePath, content, { encoding: "utf-8", mode: 0o600 });
				return;
			}
		}
	} catch {
		/* ENOENT (new file) — effectivePath stays absolutePath */
	}

	const dir = dirname(effectivePath);
	const tempPath = join(
		dir,
		`.${basename(effectivePath)}.${process.pid}.${Date.now()}.${randomBytes(4).toString("hex")}.tmp`,
	);
	try {
		// Create the temp with an explicit 0o600 mode. A bare
		// `fs.writeFile(temp, content)` creates the file with 0o666 & ~umask ≈
		// 0o644; for a NEW target there is no existing mode to chmod-copy, so the
		// renamed file would be world-readable — leaking secrets written via the
		// write/edit tools (auth tokens, private keys, REPI state). The sync
		// counterpart atomicWriteFileSync already uses 0o600; match it. Use
		// open("wx", 0o600) so the create+mode is atomic and we hold the fd for
		// the write.
		const fd = await fsOpen(tempPath, "wx", 0o600);
		try {
			await fd.writeFile(content, "utf-8");
		} finally {
			await fd.close();
		}
		// Preserve the existing target's mode so a temp+rename doesn't reset an
		// executable bit or a restrictive umask-independent mode. ENOENT (new file)
		// is expected and non-fatal: the temp keeps its 0o600 create-time mode.
		// Other stat errors are best-effort.
		try {
			const existing = await stat(effectivePath);
			try {
				await chmod(tempPath, existing.mode & 0o777);
			} catch {
				/* best-effort: proceed with 0o600 rather than failing the write */
			}
		} catch {
			/* target doesn't exist yet (new file) or stat denied — keep 0o600 */
		}
		await rename(tempPath, effectivePath);
	} catch (error) {
		try {
			await unlink(tempPath);
		} catch {
			/* best-effort: temp may not exist or may have been renamed already */
		}
		throw error;
	}
}

/**
 * Sync counterpart of {@link atomicWriteFile}. Write `content` to `absolutePath`
 * atomically: write to a uniquely-named temp file in the SAME directory as the
 * target, then rename it into place. `rename` is atomic on POSIX within the same
 * filesystem (same-directory placement guarantees no EXDEV), so readers see
 * either the complete old content or the complete new content, never a partial
 * write — a concurrent reader or a crash mid-write can't observe a truncated
 * file. On any error the temp file is unlinked. Mode of an existing target is
 * preserved; a NEW file is created with `mode` (default 0o600). fsync omitted
 * (crash-consistency of content, not power-loss durability — matches
 * atomicWriteFile).
 *
 * Use this for small metadata files written from synchronous call sites where a
 * torn write would corrupt state a concurrent reader observes (e.g. the
 * agent-thread run manifest, which is read-modify-written on every status
 * change and concurrently read by getRun/listRuns). For file edits/writes prefer
 * the async atomicWriteFile (symlink-aware). No symlink handling here:
 * temp+rename over a symlink would replace the link entry, so callers must pass
 * a real-file path.
 */
export function atomicWriteFileSync(absolutePath: string, content: string, mode = 0o600): void {
	const dir = dirname(absolutePath);
	const tempPath = join(
		dir,
		`.${basename(absolutePath)}.${process.pid}.${Date.now()}.${randomBytes(4).toString("hex")}.tmp`,
	);
	// Wrap the entire open→write→chmod→rename sequence in a single catch that
	// unlinks the temp on ANY failure. Previously only the renameSync step was
	// guarded: if writeFileSync threw mid-write (disk full, EIO, EROFS), the
	// finally closed the fd and the error propagated out of the function —
	// control never reached the rename catch, so the temp file (`.name.pid.ts.hex.tmp`)
	// was left permanently in the target dir. This affected EVERY
	// atomicWriteFileSync caller (manifest, trust, settings, mcp, repi/storage,
	// auth). The async atomicWriteFile already unlinks its temp in a catch
	// wrapping the whole write+rename; this mirrors that contract. Success path
	// and the existing rename-error cleanup are unchanged; only the previously
	// uncovered write/chmod-throw paths gain cleanup.
	try {
		const fd = openSync(tempPath, "wx", mode);
		try {
			writeFileSync(fd, content);
		} finally {
			closeSync(fd);
		}
		// Preserve an existing target's mode across the replace (a temp+rename
		// would otherwise reset it). ENOENT (new file) is expected — the temp
		// already has `mode` from openSync, which rename preserves.
		try {
			const existing = statSync(absolutePath);
			try {
				chmodSync(tempPath, existing.mode & 0o777);
			} catch {
				/* best-effort: proceed with the create-time mode */
			}
		} catch {
			/* target doesn't exist yet — keep the create-time `mode` */
		}
		renameSync(tempPath, absolutePath);
	} catch (error) {
		try {
			unlinkSync(tempPath);
		} catch {
			/* best-effort: temp may not exist (open threw) or may have been renamed already */
		}
		throw error instanceof Error ? error : new Error(String(error));
	}
}

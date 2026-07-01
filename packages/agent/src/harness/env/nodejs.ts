import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants, createReadStream, rmSync } from "node:fs";
import {
	access,
	appendFile,
	lstat,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	realpath,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import {
	DEFAULT_EXEC_MAX_BYTES,
	type ExecutionEnv,
	type ExecutionEnvExecOptions,
	ExecutionError,
	err,
	FileError,
	type FileInfo,
	type FileKind,
	ok,
	type Result,
	toError,
} from "../types.ts";
import { safeHeadEnd } from "../utils/truncate.ts";

function resolvePath(cwd: string, path: string): string {
	return isAbsolute(path) ? path : resolve(cwd, path);
}

/**
 * Resolve the captured-output byte cap for {@link NodeExecutionEnv.exec}. An explicit `maxBytes`
 * wins (with `0` meaning unbounded — explicit opt-out for callers that need the full string);
 * otherwise the `REPI_EXEC_MAX_BYTES` env value is used; otherwise the package default. The cap
 * bounds the `stdout`/`stderr` strings returned from exec so a runaway command cannot OOM the
 * agent process — streaming `onStdout`/`onStderr` callbacks still receive every chunk.
 */
function resolveExecMaxBytes(maxBytes: number | undefined): number {
	if (maxBytes !== undefined) return maxBytes;
	const envValue = process.env.REPI_EXEC_MAX_BYTES;
	if (envValue !== undefined && envValue !== "") {
		const parsed = Number(envValue);
		if (Number.isFinite(parsed) && parsed >= 0) return Math.floor(parsed);
	}
	return DEFAULT_EXEC_MAX_BYTES;
}

/**
 * Grace window after we SIGKILL the child before force-settling the exec promise. Normally the
 * child emits `close` within milliseconds of the kill and `settle` runs from the close handler.
 * But a killed process can stay in uninterruptible disk sleep (D-state — e.g. `find`/`dd` on a
 * hung FUSE/NFS mount) where SIGKILL is deferred until the I/O returns, so `close` never fires
 * and the promise would hang forever (and the abort-signal listener would leak). The grace timer
 * is armed when we initiate a kill and force-settles if `close` doesn't arrive first; `settle`
 * clears it on the normal close path so it costs nothing in the common case. Not unref'd: it is a
 * hard bound on the hang (up to {@link KILL_GRACE_MS} after a kill) and the loop is otherwise
 * released as soon as `close` arrives.
 */
const KILL_GRACE_MS = 2000;

function fileKindFromStats(stats: {
	isFile(): boolean;
	isDirectory(): boolean;
	isSymbolicLink(): boolean;
}): FileKind | undefined {
	if (stats.isFile()) return "file";
	if (stats.isDirectory()) return "directory";
	if (stats.isSymbolicLink()) return "symlink";
	return undefined;
}

function fileInfoFromStats(
	path: string,
	stats: { isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean; size: number; mtimeMs: number },
): Result<FileInfo, FileError> {
	const kind = fileKindFromStats(stats);
	if (!kind) return err(new FileError("invalid", "Unsupported file type", path));
	return ok({
		name: path.replace(/\/+$/, "").split("/").pop() ?? path,
		path,
		kind,
		size: stats.size,
		mtimeMs: stats.mtimeMs,
	});
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
	return error instanceof Error && "code" in error;
}

function toFileError(error: unknown, path?: string): FileError {
	if (error instanceof FileError) return error;
	const cause = toError(error);
	if (isNodeError(error)) {
		const message = error.message;
		switch (error.code) {
			case "ABORT_ERR":
				return new FileError("aborted", message, path, cause);
			case "ENOENT":
				return new FileError("not_found", message, path, cause);
			case "EACCES":
			case "EPERM":
				return new FileError("permission_denied", message, path, cause);
			case "ENOTDIR":
				return new FileError("not_directory", message, path, cause);
			case "EISDIR":
				return new FileError("is_directory", message, path, cause);
			case "EINVAL":
				return new FileError("invalid", message, path, cause);
		}
	}
	return new FileError("unknown", cause.message, path, cause);
}

function abortResult<TValue>(signal: AbortSignal | undefined, path?: string): Result<TValue, FileError> | undefined {
	return signal?.aborted ? err(new FileError("aborted", "aborted", path)) : undefined;
}

async function pathExists(path: string): Promise<boolean> {
	try {
		await access(path, constants.F_OK);
		return true;
	} catch {
		return false;
	}
}

export async function runCommand(
	command: string,
	args: string[],
	timeoutMs: number,
): Promise<{ stdout: string; status: number | null }> {
	return await new Promise((resolve) => {
		let stdout = "";
		let child: ReturnType<typeof spawn>;
		let settled = false;
		let killGraceTimer: ReturnType<typeof setTimeout> | undefined;
		try {
			child = spawn(command, args, {
				stdio: ["ignore", "pipe", "ignore"],
				windowsHide: true,
			});
		} catch {
			resolve({ stdout: "", status: null });
			return;
		}
		// Settle helper clears the kill-grace timer so the normal close/error path costs nothing.
		const settle = (value: { stdout: string; status: number | null }) => {
			if (timeout) clearTimeout(timeout);
			if (killGraceTimer) {
				clearTimeout(killGraceTimer);
				killGraceTimer = undefined;
			}
			if (settled) return;
			settled = true;
			resolve(value);
		};
		const timeout = setTimeout(() => {
			if (child.pid) killProcessTree(child.pid);
			// Mirror exec's kill-grace: a killed child can stay in uninterruptible disk sleep
			// (D-state — e.g. `which` traversing a hung FUSE/NFS mount) where SIGKILL is deferred
			// until the I/O returns, so `close` never fires and the promise would hang forever.
			// runCommand is used by findBashOnPath during resolveShellConfig on the first exec of
			// every session, so this hang blocks the entire first agent turn. Arm a NON-unref'd
			// force-settle timer (KILL_GRACE_MS) that resolves with status:null if `close` still
			// hasn't fired; settle clears it on the normal path. Not unref'd: it is the hard
			// bound on the hang (the outer timeout is unref'd so a forgotten runCommand doesn't
			// keep the loop alive, but the grace must fire once a kill has been initiated).
			if (!killGraceTimer) {
				killGraceTimer = setTimeout(() => {
					killGraceTimer = undefined;
					settle({ stdout, status: null });
				}, KILL_GRACE_MS);
			}
		}, timeoutMs);
		timeout.unref();
		child.stdout?.setEncoding("utf8");
		child.stdout?.on("data", (chunk: string) => {
			stdout += chunk;
		});
		// Stream-level 'error' on stdout (rare; usually paired with child "close")
		// without a listener throws `Unhandled 'error' event`. Swallow; the child
		// "error"/"close" handlers own real failure reporting.
		child.stdout?.on("error", () => {});
		child.on("error", () => {
			settle({ stdout: "", status: null });
		});
		child.on("close", (status) => {
			settle({ stdout, status });
		});
	});
}

async function findBashOnPath(): Promise<string | null> {
	const result =
		process.platform === "win32"
			? await runCommand("where", ["bash.exe"], 5000)
			: await runCommand("which", ["bash"], 5000);
	if (result.status !== 0 || !result.stdout) return null;
	const firstMatch = result.stdout.trim().split(/\r?\n/)[0];
	return firstMatch && (await pathExists(firstMatch)) ? firstMatch : null;
}

async function getShellConfig(
	customShellPath?: string,
): Promise<Result<{ shell: string; args: string[] }, ExecutionError>> {
	if (customShellPath) {
		if (await pathExists(customShellPath)) {
			return ok({ shell: customShellPath, args: ["-c"] });
		}
		return err(new ExecutionError("shell_unavailable", `Custom shell path not found: ${customShellPath}`));
	}
	if (process.platform === "win32") {
		const candidates: string[] = [];
		const programFiles = process.env.ProgramFiles;
		if (programFiles) candidates.push(`${programFiles}\\Git\\bin\\bash.exe`);
		const programFilesX86 = process.env["ProgramFiles(x86)"];
		if (programFilesX86) candidates.push(`${programFilesX86}\\Git\\bin\\bash.exe`);
		for (const candidate of candidates) {
			if (await pathExists(candidate)) {
				return ok({ shell: candidate, args: ["-c"] });
			}
		}
		const bashOnPath = await findBashOnPath();
		if (bashOnPath) {
			return ok({ shell: bashOnPath, args: ["-c"] });
		}
		return err(new ExecutionError("shell_unavailable", "No bash shell found"));
	}

	if (await pathExists("/bin/bash")) {
		return ok({ shell: "/bin/bash", args: ["-c"] });
	}
	const bashOnPath = await findBashOnPath();
	if (bashOnPath) {
		return ok({ shell: bashOnPath, args: ["-c"] });
	}
	return ok({ shell: "sh", args: ["-c"] });
}

function getShellEnv(baseEnv?: NodeJS.ProcessEnv, extraEnv?: Record<string, string>): NodeJS.ProcessEnv {
	return {
		...process.env,
		...baseEnv,
		...extraEnv,
	};
}

function killProcessTree(pid: number): void {
	if (process.platform === "win32") {
		try {
			const t = spawn("taskkill", ["/F", "/T", "/PID", String(pid)], {
				stdio: "ignore",
				detached: true,
				windowsHide: true,
			});
			// Swallow an async spawn "error" event (taskkill absent/broken) so
			// process-tree teardown on Windows does not crash the agent via an
			// unhandled "error" event the try/catch cannot capture.
			t.on("error", () => {});
			t.unref();
		} catch {
			// Ignore errors.
		}
		return;
	}

	try {
		process.kill(-pid, "SIGKILL");
	} catch {
		try {
			process.kill(pid, "SIGKILL");
		} catch {
			// Process already dead.
		}
	}
}

/**
 * Temp dirs created by createTempDir/createTempFile (each createTempFile makes
 * a fresh mkdtemp dir containing one file). The file inside is session-scoped
 * — the model may read it back (e.g. a bash full-output log) — but the wrapping
 * dir must not accumulate in the OS tmpdir forever. Tracked here and removed
 * best-effort at process exit. (A SIGKILL leaks them; the OS tmpdir reaper
 * handles that case eventually, which is no worse than before this tracking.)
 */
const createdTempDirs = new Set<string>();
let tempDirExitCleanupRegistered = false;
function registerTempDirExitCleanup(): void {
	if (tempDirExitCleanupRegistered) return;
	tempDirExitCleanupRegistered = true;
	process.on("exit", () => {
		for (const dir of createdTempDirs) {
			try {
				rmSync(dir, { recursive: true, force: true });
			} catch {
				// Best-effort: dir may already be gone or on a read-only mount.
			}
		}
	});
}

export class NodeExecutionEnv implements ExecutionEnv {
	cwd: string;
	private shellPath?: string;
	private shellEnv?: NodeJS.ProcessEnv;
	/**
	 * Lazily-created shared temp dir for {@link createTempFile}, so a session that produces many
	 * truncated-output temp files (each call used to mkdtemp a FRESH dir) makes one dir tree instead
	 * of N. Resolved once and cached (concurrent callers share the same mkdtemp); cleared on failure
	 * so the next call retries, and cleared by {@link cleanup} so a later call re-creates.
	 */
	private fileTempDirPromise: Promise<Result<string, FileError>> | null = null;
	/**
	 * Temp dirs owned by THIS env instance (opt #154). The module-level
	 * `createdTempDirs` set remains the process-exit safety net (it accumulates
	 * dirs from every env so the exit handler can reap leaked ones), but
	 * `cleanup()` now iterates only this instance's dirs — so one env's cleanup
	 * can no longer `rm` another live env's temp dir out from under it (the
	 * shared-set design made `cleanup()` unsafe to call while any other env was
	 * active, which is why no runtime caller wired it).
	 */
	private readonly instanceTempDirs = new Set<string>();

	/**
	 * Track a temp dir on both the instance set (for isolated `cleanup()`) and
	 * the module-level set (for the process-exit safety net). opt #154.
	 */
	private trackTempDir(dir: string): void {
		registerTempDirExitCleanup();
		createdTempDirs.add(dir);
		this.instanceTempDirs.add(dir);
	}

	constructor(options: { cwd: string; shellPath?: string; shellEnv?: NodeJS.ProcessEnv }) {
		this.cwd = options.cwd;
		this.shellPath = options.shellPath;
		this.shellEnv = options.shellEnv;
	}

	/**
	 * Lazily-cached resolved shell config. {@link getShellConfig} is invariant for the env's lifetime
	 * (shellPath is set in the constructor and never reassigned), but exec called it on EVERY
	 * invocation — an `access(2)` syscall per exec on Linux, or a spawned `which`/`where` subprocess
	 * per exec on systems without /bin/bash. Cached here so a session with N shell tool calls pays
	 * one resolution. On failure the cache is dropped so the next exec retries (don't cache a
	 * transient shell-unavailable forever).
	 */
	private shellConfigPromise?: Promise<Result<{ shell: string; args: string[] }, ExecutionError>>;

	private resolveShellConfig(): Promise<Result<{ shell: string; args: string[] }, ExecutionError>> {
		if (!this.shellConfigPromise) {
			this.shellConfigPromise = getShellConfig(this.shellPath);
			void this.shellConfigPromise.then((result) => {
				if (!result.ok) this.shellConfigPromise = undefined;
			});
		}
		return this.shellConfigPromise;
	}

	private ensureFileTempDir(): Promise<Result<string, FileError>> {
		if (!this.fileTempDirPromise) {
			this.fileTempDirPromise = (async () => {
				try {
					const dir = await mkdtemp(join(tmpdir(), "tmp-"));
					this.trackTempDir(dir);
					return ok(dir);
				} catch (error) {
					return err(toFileError(error));
				}
			})();
			// On failure, drop the cached promise so the next createTempFile retries instead of
			// caching the error forever.
			void this.fileTempDirPromise.then((result) => {
				if (!result.ok) this.fileTempDirPromise = null;
			});
		}
		return this.fileTempDirPromise;
	}

	async absolutePath(path: string): Promise<Result<string, FileError>> {
		return ok(resolvePath(this.cwd, path));
	}

	async joinPath(parts: string[]): Promise<Result<string, FileError>> {
		return ok(join(...parts));
	}

	async exec(
		command: string,
		options?: ExecutionEnvExecOptions,
	): Promise<
		Result<
			{ stdout: string; stderr: string; exitCode: number; stdoutTruncated: boolean; stderrTruncated: boolean },
			ExecutionError
		>
	> {
		if (options?.abortSignal?.aborted) return err(new ExecutionError("aborted", "aborted"));

		const cwd = options?.cwd ? resolvePath(this.cwd, options.cwd) : this.cwd;
		const shellConfig = await this.resolveShellConfig();
		if (!shellConfig.ok) return shellConfig;
		const maxBytes = resolveExecMaxBytes(options?.maxBytes);

		return await new Promise((resolvePromise) => {
			let stdout = "";
			let stderr = "";
			let stdoutTruncated = false;
			let stderrTruncated = false;
			let settled = false;
			let timedOut = false;
			let callbackError: ExecutionError | undefined;
			let child: ReturnType<typeof spawn> | undefined;
			let timeoutId: ReturnType<typeof setTimeout> | undefined;
			let killGraceTimer: ReturnType<typeof setTimeout> | undefined;

			const armKillGrace = (error: ExecutionError) => {
				if (killGraceTimer) return;
				killGraceTimer = setTimeout(() => {
					killGraceTimer = undefined;
					settle(err(error));
				}, KILL_GRACE_MS);
			};

			const onAbort = () => {
				if (child?.pid) {
					killProcessTree(child.pid);
				}
				armKillGrace(new ExecutionError("aborted", "aborted"));
			};

			const settle = (
				result: Result<
					{ stdout: string; stderr: string; exitCode: number; stdoutTruncated: boolean; stderrTruncated: boolean },
					ExecutionError
				>,
			) => {
				if (timeoutId) clearTimeout(timeoutId);
				if (killGraceTimer) {
					clearTimeout(killGraceTimer);
					killGraceTimer = undefined;
				}
				if (options?.abortSignal) options.abortSignal.removeEventListener("abort", onAbort);
				if (settled) return;
				settled = true;
				resolvePromise(result);
			};

			try {
				child = spawn(shellConfig.value.shell, [...shellConfig.value.args, command], {
					cwd,
					detached: process.platform !== "win32",
					env: getShellEnv(this.shellEnv, options?.env),
					stdio: ["ignore", "pipe", "pipe"],
					windowsHide: true,
				});
			} catch (error) {
				const cause = toError(error);
				settle(err(new ExecutionError("spawn_error", cause.message, cause)));
				return;
			}

			timeoutId =
				typeof options?.timeout === "number"
					? setTimeout(() => {
							timedOut = true;
							if (child?.pid) {
								killProcessTree(child.pid);
							}
							armKillGrace(new ExecutionError("timeout", `timeout:${options?.timeout}`));
						}, options.timeout * 1000)
					: undefined;

			if (options?.abortSignal) {
				if (options.abortSignal.aborted) {
					onAbort();
				} else {
					options.abortSignal.addEventListener("abort", onAbort, { once: true });
				}
			}

			child.stdout?.setEncoding("utf8");
			child.stderr?.setEncoding("utf8");
			child.stdout?.on("data", (chunk: string) => {
				// Bound the retained string at maxBytes (runaway-output OOM guard). The prefix up to
				// the cap is kept; once truncated we stop appending to `stdout` but still stream every
				// chunk to onStdout so streaming consumers (the only in-package caller) are unaffected.
				if (maxBytes > 0 && !stdoutTruncated) {
					stdout += chunk;
					if (stdout.length > maxBytes) {
						stdout = stdout.slice(0, safeHeadEnd(stdout, maxBytes));
						stdoutTruncated = true;
					}
				} else if (maxBytes <= 0) {
					stdout += chunk;
				}
				try {
					options?.onStdout?.(chunk);
				} catch (error) {
					const cause = toError(error);
					callbackError = new ExecutionError("callback_error", cause.message, cause);
					onAbort();
				}
			});
			child.stderr?.on("data", (chunk: string) => {
				if (maxBytes > 0 && !stderrTruncated) {
					stderr += chunk;
					if (stderr.length > maxBytes) {
						stderr = stderr.slice(0, safeHeadEnd(stderr, maxBytes));
						stderrTruncated = true;
					}
				} else if (maxBytes <= 0) {
					stderr += chunk;
				}
				try {
					options?.onStderr?.(chunk);
				} catch (error) {
					const cause = toError(error);
					callbackError = new ExecutionError("callback_error", cause.message, cause);
					onAbort();
				}
			});

			// Stream-level 'error' on stdout/stderr (rare; usually paired with
			// child "close") without a listener throws `Unhandled 'error' event`.
			// Swallow; the child "error"/"close" handlers own real failure reporting.
			child.stdout?.on("error", () => {});
			child.stderr?.on("error", () => {});

			child.on("error", (error) => {
				settle(err(new ExecutionError("spawn_error", error.message, error)));
			});

			child.on("close", (code, signal) => {
				if (callbackError) {
					settle(err(callbackError));
					return;
				}
				if (timedOut) {
					settle(err(new ExecutionError("timeout", `timeout:${options?.timeout}`)));
					return;
				}
				if (options?.abortSignal?.aborted) {
					settle(err(new ExecutionError("aborted", "aborted")));
					return;
				}
				// The child was terminated by an EXTERNAL signal (OOM killer, external kill, a
				// parent-group signal that bypasses our own timeout/abort paths): code === null and
				// signal is non-null. None of the guards above tripped (it wasn't our timeout/abort),
				// so `code ?? 0` would collapse the signal death into exitCode:0 and report a killed
				// command as successful. (runCommand does the opposite — `status !== 0` treats null
				// as failure — confirming `?? 0` is wrong here.) Surface the signal death as an error.
				if (code === null && signal) {
					settle(err(new ExecutionError("spawn_error", `Process killed by signal ${signal}`)));
					return;
				}
				settle(ok({ stdout, stderr, exitCode: code ?? 0, stdoutTruncated, stderrTruncated }));
			});
		});
	}

	async readTextFile(path: string, abortSignal?: AbortSignal): Promise<Result<string, FileError>> {
		const resolved = resolvePath(this.cwd, path);
		const aborted = abortResult<string>(abortSignal, resolved);
		if (aborted) return aborted;
		try {
			return ok(await readFile(resolved, { encoding: "utf8", signal: abortSignal }));
		} catch (error) {
			return err(toFileError(error, resolved));
		}
	}

	async readTextLines(
		path: string,
		options?: { maxLines?: number; abortSignal?: AbortSignal },
	): Promise<Result<string[], FileError>> {
		const resolved = resolvePath(this.cwd, path);
		const aborted = abortResult<string[]>(options?.abortSignal, resolved);
		if (aborted) return aborted;
		if (options?.maxLines !== undefined && options.maxLines <= 0) return ok([]);
		let stream: ReturnType<typeof createReadStream> | undefined;
		let lineReader: ReturnType<typeof createInterface> | undefined;
		try {
			stream = createReadStream(resolved, { encoding: "utf8", signal: options?.abortSignal });
			lineReader = createInterface({ input: stream, crlfDelay: Infinity });
			const lines: string[] = [];
			for await (const line of lineReader) {
				const loopAbort = abortResult<string[]>(options?.abortSignal, resolved);
				if (loopAbort) return loopAbort;
				lines.push(line);
				if (options?.maxLines !== undefined && lines.length >= options.maxLines) break;
			}
			const afterReadAbort = abortResult<string[]>(options?.abortSignal, resolved);
			if (afterReadAbort) return afterReadAbort;
			return ok(lines);
		} catch (error) {
			return err(toFileError(error, resolved));
		} finally {
			lineReader?.close();
			stream?.destroy();
		}
	}

	async readBinaryFile(path: string, abortSignal?: AbortSignal): Promise<Result<Uint8Array, FileError>> {
		const resolved = resolvePath(this.cwd, path);
		const aborted = abortResult<Uint8Array>(abortSignal, resolved);
		if (aborted) return aborted;
		try {
			return ok(await readFile(resolved, { signal: abortSignal }));
		} catch (error) {
			return err(toFileError(error, resolved));
		}
	}

	async writeFile(
		path: string,
		content: string | Uint8Array,
		abortSignal?: AbortSignal,
	): Promise<Result<void, FileError>> {
		const resolved = resolvePath(this.cwd, path);
		const aborted = abortResult<void>(abortSignal, resolved);
		if (aborted) return aborted;
		try {
			await mkdir(resolve(resolved, ".."), { recursive: true });
			const afterMkdirAbort = abortResult<void>(abortSignal, resolved);
			if (afterMkdirAbort) return afterMkdirAbort;
			await writeFile(resolved, content, { signal: abortSignal });
			return ok(undefined);
		} catch (error) {
			return err(toFileError(error, resolved));
		}
	}

	async appendFile(
		path: string,
		content: string | Uint8Array,
		abortSignal?: AbortSignal,
	): Promise<Result<void, FileError>> {
		const resolved = resolvePath(this.cwd, path);
		const aborted = abortResult<void>(abortSignal, resolved);
		if (aborted) return aborted;
		try {
			await mkdir(resolve(resolved, ".."), { recursive: true });
			const afterMkdirAbort = abortResult<void>(abortSignal, resolved);
			if (afterMkdirAbort) return afterMkdirAbort;
			await appendFile(resolved, content, { signal: abortSignal } as unknown as Parameters<typeof appendFile>[2]);
			return ok(undefined);
		} catch (error) {
			return err(toFileError(error, resolved));
		}
	}

	async fileInfo(path: string): Promise<Result<FileInfo, FileError>> {
		const resolved = resolvePath(this.cwd, path);
		try {
			return fileInfoFromStats(resolved, await lstat(resolved));
		} catch (error) {
			return err(toFileError(error, resolved));
		}
	}

	async listDir(path: string, abortSignal?: AbortSignal): Promise<Result<FileInfo[], FileError>> {
		const resolved = resolvePath(this.cwd, path);
		const aborted = abortResult<FileInfo[]>(abortSignal, resolved);
		if (aborted) return aborted;
		try {
			const entries = await readdir(resolved, { withFileTypes: true });
			const infos: FileInfo[] = [];
			for (const entry of entries) {
				const loopAbort = abortResult<FileInfo[]>(abortSignal, resolved);
				if (loopAbort) return loopAbort;
				const entryPath = resolve(resolved, entry.name);
				try {
					const info = fileInfoFromStats(entryPath, await lstat(entryPath));
					if (info.ok) infos.push(info.value);
				} catch (error) {
					return err(toFileError(error, entryPath));
				}
			}
			return ok(infos);
		} catch (error) {
			return err(toFileError(error, resolved));
		}
	}

	async canonicalPath(path: string): Promise<Result<string, FileError>> {
		const resolved = resolvePath(this.cwd, path);
		try {
			return ok(await realpath(resolved));
		} catch (error) {
			return err(toFileError(error, resolved));
		}
	}

	async exists(path: string): Promise<Result<boolean, FileError>> {
		const result = await this.fileInfo(path);
		if (result.ok) return ok(true);
		if (result.error.code === "not_found") return ok(false);
		return err(result.error);
	}

	async createDir(path: string, options?: { recursive?: boolean }): Promise<Result<void, FileError>> {
		const resolved = resolvePath(this.cwd, path);
		try {
			await mkdir(resolved, { recursive: options?.recursive ?? true });
			return ok(undefined);
		} catch (error) {
			return err(toFileError(error, resolved));
		}
	}

	async remove(path: string, options?: { recursive?: boolean; force?: boolean }): Promise<Result<void, FileError>> {
		const resolved = resolvePath(this.cwd, path);
		try {
			await rm(resolved, { recursive: options?.recursive ?? false, force: options?.force ?? false });
			return ok(undefined);
		} catch (error) {
			return err(toFileError(error, resolved));
		}
	}

	async createTempDir(prefix: string = "tmp-", abortSignal?: AbortSignal): Promise<Result<string, FileError>> {
		const aborted = abortResult<string>(abortSignal);
		if (aborted) return aborted;
		try {
			// fs.promises.mkdtemp does not accept a `signal` option, so rely on the abortResult
			// pre-check (mirrors writeFile's pre-check pattern) to honour an already-aborted signal
			// without creating the temp dir after the abort.
			const dir = await mkdtemp(join(tmpdir(), prefix));
			// Track for best-effort recursive removal at process exit (and on
			// this env's isolated cleanup()) so temp dirs don't accumulate across
			// sessions. Safe for session-scoped files too: exit only fires when
			// the agent process is done, so the model can no longer read them.
			this.trackTempDir(dir);
			return ok(dir);
		} catch (error) {
			return err(toFileError(error));
		}
	}

	async createTempFile(options?: {
		prefix?: string;
		suffix?: string;
		abortSignal?: AbortSignal;
	}): Promise<Result<string, FileError>> {
		const aborted = abortResult<string>(options?.abortSignal);
		if (aborted) return aborted;
		const dir = await this.ensureFileTempDir();
		if (!dir.ok) return dir;
		const afterDirAbort = abortResult<string>(options?.abortSignal);
		if (afterDirAbort) return afterDirAbort;
		const filePath = join(dir.value, `${options?.prefix ?? ""}${randomUUID()}${options?.suffix ?? ""}`);
		try {
			await writeFile(filePath, "", { signal: options?.abortSignal });
			return ok(filePath);
		} catch (error) {
			return err(toFileError(error, filePath));
		}
	}

	async cleanup(): Promise<void> {
		// Best-effort removal of THIS env's temp dirs only (opt #154). The
		// module-level `createdTempDirs` set is the process-exit safety net for
		// dirs from envs that are never explicitly cleaned; this iterates only
		// `instanceTempDirs` so one env's cleanup can't rm another live env's
		// dir. Each removed dir is also dropped from the exit set so the exit
		// handler doesn't double-rm. Safe to call mid-session only if the caller
		// is done with any session-scoped temp files this env created.
		for (const dir of this.instanceTempDirs) {
			try {
				await rm(dir, { recursive: true, force: true });
			} catch {
				// Best-effort: dir may already be gone or on a read-only mount.
			}
			createdTempDirs.delete(dir);
		}
		this.instanceTempDirs.clear();
		this.fileTempDirPromise = null;
	}
}

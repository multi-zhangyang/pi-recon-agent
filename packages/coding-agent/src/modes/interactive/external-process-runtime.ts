/**
 * External process and temporary-file boundaries used by interactive mode.
 *
 * InteractiveMode owns presentation state (TUI, editor, loaders). This module
 * owns the parts that must survive outside the TUI lifecycle: child-process
 * events, abort races, timeout cleanup, and temporary files. Keeping those
 * concerns here prevents a failed external command from leaving the terminal
 * in raw mode or leaking files into the system temp directory.
 */

import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { getShareViewerUrl } from "../../config.ts";
import { registerPersistedTempFile } from "../../core/tools/output-accumulator.ts";
import { extensionForImageMimeType, readClipboardImage } from "../../utils/clipboard-image.ts";

const EXTERNAL_EDITOR_SIGKILL_GRACE_MS = 2000;
const TMUX_QUERY_TIMEOUT_MS = 2000;

export type ExternalEditorResult =
	| { status: "no-editor"; warning: string }
	| { status: "unchanged" }
	| { status: "updated"; text: string }
	| { status: "timed-out"; warning: string };

export interface ExternalEditorOptions {
	/** Current editor command. Defaults to VISUAL, then EDITOR. */
	command?: string;
	/** Text to seed into the temporary markdown file. */
	text: string;
	/** Prefix used for the temporary file name and user-facing process output. */
	appName: string;
	/** Release and reacquire the terminal around the child process. */
	stopTerminal: () => void;
	startTerminal: () => void;
	/** Force the TUI to repaint after returning from an alternate screen. */
	requestRender: (full: boolean) => void;
	/** Optional process notice; defaults to stdout. */
	writeNotice?: (message: string) => void;
}

/**
 * Parse the opt-in editor timeout. Zero, malformed, and negative values keep
 * the historical unlimited-editor behavior.
 */
function externalEditorTimeoutMs(): number {
	const raw = process.env.REPI_EXTERNAL_EDITOR_TIMEOUT_MS;
	if (raw === undefined || raw.trim() === "") return 0;
	const value = Number(raw);
	if (!Number.isFinite(value) || value < 0) return 0;
	return Math.floor(value);
}

function removeFile(path: string): void {
	try {
		unlinkSync(path);
	} catch {
		// Temporary files are best effort. The command result must remain useful.
	}
}

function splitEditorCommand(command: string): [string, string[]] {
	// Keep compatibility with existing VISUAL/EDITOR values such as
	// `code --wait`; shell quoting is intentionally left to the configured
	// platform launcher, matching the previous interactive behavior.
	const [editor, ...args] = command.trim().split(/\s+/);
	return [editor ?? command, args];
}

interface ChildExit {
	code: number | null;
}

/** Wait for an editor child while containing late close/error events. */
function waitForEditor(command: string, args: string[], filePath: string): Promise<ChildExit & { timedOut: boolean }> {
	const timeoutMs = externalEditorTimeoutMs();
	return new Promise((resolve) => {
		let settled = false;
		let timedOut = false;
		let timeoutTimer: NodeJS.Timeout | undefined;
		let sigkillTimer: NodeJS.Timeout | undefined;

		const settle = (exit: ChildExit): void => {
			if (settled) return;
			settled = true;
			if (timeoutTimer) clearTimeout(timeoutTimer);
			if (sigkillTimer) clearTimeout(sigkillTimer);
			resolve({ ...exit, timedOut });
		};

		const child = spawn(command, [...args, filePath], {
			stdio: "inherit",
			shell: process.platform === "win32",
		});
		child.on("error", () => settle({ code: null }));
		child.on("close", (code) => settle({ code }));

		if (timeoutMs <= 0) return;
		timeoutTimer = setTimeout(() => {
			timedOut = true;
			try {
				child.kill("SIGTERM");
			} catch {
				// The close event will settle an already-dead process.
			}
			sigkillTimer = setTimeout(() => {
				try {
					child.kill("SIGKILL");
				} catch {
					// The process has already exited.
				}
			}, EXTERNAL_EDITOR_SIGKILL_GRACE_MS);
			sigkillTimer.unref?.();
		}, timeoutMs);
		timeoutTimer.unref?.();
	});
}

/**
 * Run the configured external editor and return the replacement text, if any.
 * The terminal is always restarted and repainted once a temporary file has
 * been created, including spawn failures and timeout kills.
 */
export async function runExternalEditor(options: ExternalEditorOptions): Promise<ExternalEditorResult> {
	const editorCommand = options.command ?? process.env.VISUAL ?? process.env.EDITOR;
	if (!editorCommand?.trim()) {
		return { status: "no-editor", warning: "No editor configured. Set $VISUAL or $EDITOR environment variable." };
	}

	const tmpFile = join(tmpdir(), `${options.appName}-editor-${Date.now()}.${options.appName}.md`);
	let terminalStopped = false;
	try {
		writeFileSync(tmpFile, options.text, "utf-8");
		options.stopTerminal();
		terminalStopped = true;

		const writeNotice = options.writeNotice ?? ((message: string) => process.stdout.write(message));
		writeNotice(
			`Launching external editor: ${editorCommand}\n${options.appName} will resume when the editor exits.\n`,
		);

		const [editor, args] = splitEditorCommand(editorCommand);
		const result = await waitForEditor(editor, args, tmpFile);
		if (result.timedOut) {
			const timeoutMs = externalEditorTimeoutMs();
			return {
				status: "timed-out",
				warning: `External editor timed out after ${timeoutMs}ms and was killed. Set REPI_EXTERNAL_EDITOR_TIMEOUT_MS to adjust (0 disables).`,
			};
		}
		if (result.code !== 0) {
			return { status: "unchanged" };
		}

		return { status: "updated", text: readFileSync(tmpFile, "utf-8").replace(/\n$/, "") };
	} finally {
		removeFile(tmpFile);
		if (terminalStopped) {
			try {
				options.startTerminal();
			} finally {
				options.requestRender(true);
			}
		}
	}
}

export type ShareGistResult =
	| { status: "success"; gistUrl: string; previewUrl: string }
	| { status: "cancelled" }
	| { status: "unavailable"; message: string }
	| { status: "error"; stage: "export" | "gist"; error: unknown };

export interface ShareGistOptions {
	/** Export callback supplied by the session layer. */
	exportHtml: (filePath: string) => Promise<unknown>;
	/** Abort signal owned by the interactive loader. */
	signal?: AbortSignal;
	/** App name used to isolate temporary files. */
	appName: string;
	/** Optional viewer URL builder for product-specific deployments. */
	viewerUrl?: (gistId: string) => string;
}

type CapturedGistProcess = {
	stdout: string;
	stderr: string;
	code: number | null;
	status: "completed" | "cancelled";
};

function checkGitHubCliAuth(): { ok: true } | { ok: false; message: string } {
	try {
		const result = spawnSync("gh", ["auth", "status"], { encoding: "utf-8" });
		if (result.error) {
			return { ok: false, message: "GitHub CLI (gh) is not installed. Install it from https://cli.github.com/" };
		}
		if (result.status !== 0) {
			return { ok: false, message: "GitHub CLI is not logged in. Run 'gh auth login' first." };
		}
		return { ok: true };
	} catch {
		return { ok: false, message: "GitHub CLI (gh) is not installed. Install it from https://cli.github.com/" };
	}
}

function captureGistProcess(filePath: string, signal?: AbortSignal): Promise<CapturedGistProcess> {
	return new Promise((resolve, reject) => {
		let settled = false;
		let stdout = "";
		let stderr = "";
		const proc = spawn("gh", ["gist", "create", "--public=false", filePath]);

		const cleanup = (): void => {
			signal?.removeEventListener("abort", onAbort);
		};
		const settle = (result: CapturedGistProcess): void => {
			if (settled) return;
			settled = true;
			cleanup();
			resolve(result);
		};
		const onAbort = (): void => {
			try {
				proc.kill();
			} catch {
				// The process may have exited between the signal and kill call.
			}
			settle({ stdout, stderr, code: null, status: "cancelled" });
		};

		proc.stdout?.on("data", (data) => {
			stdout += data.toString();
		});
		proc.stderr?.on("data", (data) => {
			stderr += data.toString();
		});
		// A killed child can emit stream errors after the abort handler. These
		// listeners are part of the process contract and prevent an unhandled
		// error from terminating the interactive host.
		proc.stdout?.on("error", () => {});
		proc.stderr?.on("error", () => {});
		proc.on("error", (error) => {
			if (settled) return;
			settled = true;
			cleanup();
			reject(error);
		});
		proc.on("close", (code) => settle({ stdout, stderr, code, status: "completed" }));

		if (signal?.aborted) {
			onAbort();
		} else {
			signal?.addEventListener("abort", onAbort, { once: true });
		}
	});
}

function removeDirectory(directory: string): void {
	try {
		rmSync(directory, { recursive: true, force: true });
	} catch {
		// Cleanup is best effort; the caller already has the command result.
	}
}

/** Export a session and publish it as a private GitHub gist. */
export async function createPrivateGist(options: ShareGistOptions): Promise<ShareGistResult> {
	const auth = checkGitHubCliAuth();
	if (!auth.ok) return { status: "unavailable", message: auth.message };

	const directory = join(tmpdir(), `${options.appName}-share-${randomUUID()}`);
	const filePath = join(directory, "session.html");
	try {
		mkdirSync(directory, { recursive: true });
		try {
			await options.exportHtml(filePath);
		} catch (error) {
			return { status: "error", stage: "export", error };
		}
		if (options.signal?.aborted) return { status: "cancelled" };

		let result: CapturedGistProcess;
		try {
			result = await captureGistProcess(filePath, options.signal);
		} catch (error) {
			return { status: "error", stage: "gist", error };
		}
		if (result.status === "cancelled") return { status: "cancelled" };
		if (result.code !== 0) {
			return { status: "error", stage: "gist", error: new Error(result.stderr.trim() || "Unknown error") };
		}

		const gistUrl = result.stdout.trim();
		const gistId = gistUrl.split("/").pop();
		if (!gistId) {
			return { status: "error", stage: "gist", error: new Error("Failed to parse gist ID from gh output") };
		}
		const viewerUrl = options.viewerUrl ?? getShareViewerUrl;
		return { status: "success", gistUrl, previewUrl: viewerUrl(gistId) };
	} catch (error) {
		return { status: "error", stage: "export", error };
	} finally {
		removeDirectory(directory);
	}
}

function readTmuxOption(option: string): Promise<string | undefined> {
	return new Promise((resolve) => {
		let settled = false;
		let stdout = "";
		const proc = spawn("tmux", ["show", "-gv", option], {
			stdio: ["ignore", "pipe", "ignore"],
		});
		const settle = (value: string | undefined): void => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve(value);
		};
		const timer = setTimeout(() => {
			try {
				proc.kill();
			} catch {
				// Already exited.
			}
			settle(undefined);
		}, TMUX_QUERY_TIMEOUT_MS);
		timer.unref?.();
		proc.stdout?.on("data", (data) => {
			stdout += data.toString();
		});
		proc.stdout?.on("error", () => {});
		proc.on("error", () => settle(undefined));
		proc.on("close", (code) => settle(code === 0 ? stdout.trim() : undefined));
	});
}

/** Return a tmux configuration warning, or undefined when tmux is unavailable. */
export async function getTmuxKeyboardWarning(env: NodeJS.ProcessEnv = process.env): Promise<string | undefined> {
	if (!env.TMUX) return undefined;
	const [extendedKeys, extendedKeysFormat] = await Promise.all([
		readTmuxOption("extended-keys"),
		readTmuxOption("extended-keys-format"),
	]);
	if (extendedKeys === undefined) return undefined;
	if (extendedKeys !== "on" && extendedKeys !== "always") {
		return "tmux extended-keys is off. Modified Enter keys may not work. Add `set -g extended-keys on` to ~/.tmux.conf and restart tmux.";
	}
	if (extendedKeysFormat === "xterm") {
		return "tmux extended-keys-format is xterm. Pi works best with csi-u. Add `set -g extended-keys-format csi-u` to ~/.tmux.conf and restart tmux.";
	}
	return undefined;
}

/**
 * Persist the current clipboard image and return its path for editor insertion.
 * The output accumulator owns lifecycle cleanup when the session exits.
 */
export async function persistClipboardImage(sessionId: string, appName = "pi"): Promise<string | undefined> {
	try {
		const image = await readClipboardImage();
		if (!image) return undefined;
		const extension = extensionForImageMimeType(image.mimeType) ?? "png";
		const filePath = join(tmpdir(), `${appName}-clipboard-${randomUUID()}.${extension}`);
		writeFileSync(filePath, Buffer.from(image.bytes));
		registerPersistedTempFile(filePath, sessionId);
		return filePath;
	} catch {
		// Clipboard access is optional and commonly denied by the host OS.
		return undefined;
	}
}

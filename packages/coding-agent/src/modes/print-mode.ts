/**
 * Print mode (single-shot): Send prompts, output result, exit.
 *
 * Used for:
 * - `pi -p "prompt"` - text output
 * - `pi --mode json "prompt"` - JSON event stream
 */

import { randomUUID } from "node:crypto";
import type { AssistantMessage, ImageContent } from "@pi-recon/repi-ai";
import type { AgentSessionEvent } from "../core/agent-session.ts";
import type { AgentSessionRuntime } from "../core/agent-session-runtime.ts";
import { headlessTheme } from "../core/extensions/headless-theme.ts";
import type { ExtensionUIContext } from "../core/extensions/types.ts";
import { flushRawStdout, writeRawStdout } from "../core/output-guard.ts";
import { killTrackedDetachedChildren } from "../utils/shell.ts";

/**
 * Options for print mode.
 */
export interface PrintModeOptions {
	/** Output mode: "text" for final response only, "json" for all events */
	mode: "text" | "json";
	/** Array of additional prompts to send after initialMessage */
	messages?: string[];
	/** First message to send (may contain @file content) */
	initialMessage?: string;
	/** Images to attach to the initial message */
	initialImages?: ImageContent[];
}

function envFlag(name: string, fallback: boolean): boolean {
	const value = process.env[name];
	if (value === undefined || value.trim() === "") return fallback;
	return /^(?:1|true|yes|on)$/i.test(value.trim());
}

function envPositiveInteger(name: string): number | undefined {
	const value = Number(process.env[name]);
	return Number.isFinite(value) && value > 0 ? Math.floor(value) : undefined;
}

/**
 * Like {@link envPositiveInteger} but accepts `0`. Used for the two grace knobs
 * (`REPI_PRINT_TIMEOUT_GRACE_MS`, `REPI_PRINT_TIMEOUT_TOOL_GRACE_MS`) so an
 * explicit `0` disables that grace even in product mode — letting an operator
 * hard-cap the wall timeout (fail-fast) instead of always falling back to the
 * product defaults. Unset/garbage still falls back to the default.
 */
function envNonNegativeInteger(name: string): number | undefined {
	const raw = process.env[name];
	if (raw === undefined || raw.trim() === "") return undefined;
	const value = Number(raw);
	if (!Number.isFinite(value) || value < 0) return undefined;
	return Math.floor(value);
}

function isRepiProductMode(): boolean {
	return process.env.REPI_PRODUCT === "1" || process.env.REPI_PRIMARY === "1";
}

function printProgressEnabled(mode: PrintModeOptions["mode"]): boolean {
	if (mode !== "text") return false;
	return envFlag("REPI_PRINT_PROGRESS", isRepiProductMode());
}

function printTimeoutMs(_mode: PrintModeOptions["mode"]): number | undefined {
	const configured = envPositiveInteger("REPI_PRINT_TIMEOUT_MS");
	if (configured !== undefined) return configured;
	return isRepiProductMode() ? 210_000 : undefined;
}

function printTimeoutGraceMs(_mode: PrintModeOptions["mode"]): number {
	const configured = envNonNegativeInteger("REPI_PRINT_TIMEOUT_GRACE_MS");
	if (configured !== undefined) return configured;
	return isRepiProductMode() ? 30_000 : 0;
}

/**
 * Grace granted when the wall timeout fires while a TOOL is mid-execution (e.g.
 * a long `re_subagent` child run). Without this, the wall timeout aborts the
 * host mid-tool and the in-flight tool's result is lost — the documented
 * failure where a host spawning a 180s+ reverser subagent gets killed at the
 * 210s default wall and never receives the handoff. Bounded: the abort fires
 * after this grace whether or not the tool finished, so total run time is
 * capped at timeoutMs + toolGraceMs. Default covers the 240s default subagent
 * `spawnThread` timeout plus the host's own post-tool turn work.
 */
function printTimeoutToolGraceMs(_mode: PrintModeOptions["mode"]): number {
	const configured = envNonNegativeInteger("REPI_PRINT_TIMEOUT_TOOL_GRACE_MS");
	if (configured !== undefined) return configured;
	return isRepiProductMode() ? 300_000 : 0;
}

/**
 * Lead time before the wall timeout at which REPI injects a checkpoint
 * warning into the agent's stream (via `session.steer`). Without this, a long
 * autonomous run (e.g. a real-API pentest) that discovers findings but hasn't
 * persisted them loses ALL of that work when the wall fires — the abort is
 * instantaneous and the model never gets a chance to write its report. The
 * steer is delivered at the next turn boundary, telling the model to persist
 * findings / write its report NOW and not start new long probes. `0` disables
 * (envNonNegativeInteger). Only schedules when a wall timeout is configured
 * and `timeoutMs - leadMs > 0`.
 */
function printTimeoutWarnLeadMs(_mode: PrintModeOptions["mode"]): number {
	const configured = envNonNegativeInteger("REPI_PRINT_TIMEOUT_WARN_LEAD_MS");
	if (configured !== undefined) return configured;
	return isRepiProductMode() ? 60_000 : 0;
}

/**
 * Schedule a one-shot checkpoint-warning injection `warnAtMs` ms from now.
 * Calls `inject()` exactly once when the timer fires, unless `isFinished()`
 * reports the run already completed (avoids warning after a clean finish).
 * Returns a cancel function (cleared in the caller's `finally`). Exported for
 * unit testing (fake-timer behavioral pin); the integration wiring in
 * {@link runPromptWithTimeout} calls `session.steer` with the warning text.
 * @returns cancel function; no-op if `warnAtMs` is non-positive.
 */
export function scheduleTimeoutWarning(opts: {
	warnAtMs: number;
	isFinished: () => boolean;
	inject: () => void;
}): () => void {
	if (!Number.isFinite(opts.warnAtMs) || opts.warnAtMs <= 0) return () => {};
	let warned = false;
	const handle = setTimeout(() => {
		if (warned || opts.isFinished()) return;
		warned = true;
		opts.inject();
	}, opts.warnAtMs);
	return () => clearTimeout(handle);
}

function printMaxTurns(_mode: PrintModeOptions["mode"]): number | undefined {
	const configured = envPositiveInteger("REPI_PRINT_MAX_TURNS");
	if (configured !== undefined) return configured;
	return isRepiProductMode() ? 10 : undefined;
}

function printMaxToolCalls(_mode: PrintModeOptions["mode"]): number | undefined {
	const configured = envPositiveInteger("REPI_PRINT_MAX_TOOL_CALLS");
	if (configured !== undefined) return configured;
	return isRepiProductMode() ? 48 : undefined;
}

/**
 * Whether text mode streams assistant text deltas live to stdout as they
 * arrive (modern print-mode UX) instead of writing the final assistant text
 * once at the end. Default OFF to preserve the deterministic single-output
 * behavior scripted/pipe consumers rely on. Opt-in via REPI_PRINT_STREAM_TEXT.
 */
function printStreamTextEnabled(mode: PrintModeOptions["mode"]): boolean {
	if (mode !== "text") return false;
	return envFlag("REPI_PRINT_STREAM_TEXT", false);
}

function printStatusEnabled(mode: PrintModeOptions["mode"]): boolean {
	if (mode !== "text") return false;
	return envFlag("REPI_PRINT_STATUS", false);
}

function formatPrintNotify(message: string, type?: "info" | "warning" | "error"): string {
	const prefix = type === "error" ? "error" : type === "warning" ? "warning" : "info";
	return `[repi:${prefix}] ${message}`;
}

function writeJsonExtensionUiRequest(payload: Record<string, unknown>): void {
	writeRawStdout(`${JSON.stringify({ type: "extension_ui_request", id: randomUUID(), ...payload })}\n`);
}

/**
 * Streaming assistant updates carry the complete accumulated message in both
 * `event.message` and `assistantMessageEvent.partial`. That is useful to a UI
 * renderer, but pathological for a JSONL client: every token repeats the full
 * prefix and turns an O(n) response into O(n^2) output. Print mode already
 * emits message_start/message_end/agent_end for complete snapshots, so keep
 * only the incremental assistant event in its machine-readable stream.
 */
function compactJsonEvent(event: AgentSessionEvent): unknown {
	if (event.type !== "message_update") return event;
	const assistantMessageEvent = { ...event.assistantMessageEvent } as Record<string, unknown>;
	delete assistantMessageEvent.partial;
	return { type: event.type, assistantMessageEvent };
}

function createPrintExtensionUIContext(mode: PrintModeOptions["mode"]): ExtensionUIContext {
	const notify = (message: string, type?: "info" | "warning" | "error"): void => {
		if (mode === "json") {
			writeJsonExtensionUiRequest({ method: "notify", message, notifyType: type });
			return;
		}
		console.error(formatPrintNotify(message, type));
	};

	const setStatus = (key: string, text: string | undefined): void => {
		if (mode === "json") {
			writeJsonExtensionUiRequest({ method: "setStatus", statusKey: key, statusText: text });
			return;
		}
		if (printStatusEnabled(mode)) console.error(`[repi:status] ${key}=${text ?? "<clear>"}`);
	};

	return {
		select: async () => undefined,
		confirm: async () => false,
		input: async () => undefined,
		notify,
		onTerminalInput: () => () => {},
		setStatus,
		setWorkingMessage: () => {},
		setWorkingVisible: () => {},
		setWorkingIndicator: () => {},
		setHiddenThinkingLabel: () => {},
		setWidget: () => {},
		setFooter: () => {},
		setHeader: () => {},
		setTitle: () => {},
		custom: async () => undefined as never,
		pasteToEditor: () => {},
		setEditorText: () => {},
		getEditorText: () => "",
		editor: async () => undefined,
		addAutocompleteProvider: () => {},
		setEditorComponent: () => {},
		getEditorComponent: () => undefined,
		get theme() {
			return headlessTheme;
		},
		getAllThemes: () => [],
		getTheme: () => undefined,
		setTheme: () => ({ success: false, error: "Print mode has no interactive theme UI" }),
		getToolsExpanded: () => false,
		setToolsExpanded: () => {},
	};
}

function eventProgressLine(event: AgentSessionEvent): string | undefined {
	switch (event.type) {
		case "agent_start":
			return "agent_start";
		case "agent_end":
			return event.willRetry ? "agent_end retry_pending=true" : "agent_end";
		case "turn_start":
			return "turn_start";
		case "turn_end":
			return "turn_end";
		case "message_start":
			return `message_start role=${event.message.role}`;
		case "message_end":
			return `message_end role=${event.message.role}`;
		case "tool_execution_start":
			return `tool_start name=${event.toolName}`;
		case "tool_execution_end":
			return `tool_end name=${event.toolName} error=${event.isError ? "true" : "false"}`;
		case "compaction_start":
			return `compaction_start reason=${event.reason}`;
		case "compaction_end":
			return `compaction_end reason=${event.reason} aborted=${event.aborted ? "true" : "false"}`;
		case "auto_retry_start":
			return `auto_retry_start attempt=${event.attempt}/${event.maxAttempts}`;
		case "auto_retry_end":
			return `auto_retry_end success=${event.success ? "true" : "false"}`;
		default:
			return undefined;
	}
}

/**
 * Run in print (single-shot) mode.
 * Sends prompts to the agent and outputs the result.
 */
export async function runPrintMode(runtimeHost: AgentSessionRuntime, options: PrintModeOptions): Promise<number> {
	const { mode, messages = [], initialMessage, initialImages } = options;
	let exitCode = 0;
	let session = runtimeHost.session;
	let unsubscribe: (() => void) | undefined;
	let disposed = false;
	// Set synchronously at the top of the signal handler. Without this, a second
	// signal during the abort→flush→dispose window re-enters the handler and
	// flushes partial assistant text / raw stdout a SECOND time (duplicate
	// output), AND the main prompt loop — whose in-flight `session.prompt` the
	// abort just resolved with an aborted stopReason — proceeds to the next
	// `runPromptWithTimeout` and starts a NEW prompt on a session the handler is
	// concurrently disposing → an un-persisted partial turn. Mirrors rpc-mode's
	// `shuttingDown` guard.
	let shuttingDown = false;
	const signalCleanupHandlers: Array<() => void> = [];
	const progressEnabled = printProgressEnabled(mode);
	const timeoutMs = printTimeoutMs(mode);
	const timeoutGraceMs = printTimeoutGraceMs(mode);
	const timeoutToolGraceMs = printTimeoutToolGraceMs(mode);
	const timeoutWarnLeadMs = printTimeoutWarnLeadMs(mode);
	const maxTurns = printMaxTurns(mode);
	const maxToolCalls = printMaxToolCalls(mode);
	const streamTextEnabled = printStreamTextEnabled(mode);
	const startedAt = Date.now();
	let lastProgress = "startup";
	let heartbeat: NodeJS.Timeout | undefined;
	let toolCallCount = 0;
	let guardAbortReason: string | undefined;
	let activeGuardReject: ((error: Error) => void) | undefined;
	let assistantMessageInProgress = false;
	// Number of tool calls currently executing (parallel batches can have >1).
	// Used to grant a bounded tool-execution grace when the wall timeout fires
	// mid-tool, so a long tool (e.g. re_subagent) isn't killed and its result lost.
	let toolInProgress = 0;
	// True when text deltas for the current assistant message have already been
	// written live to stdout (streamTextEnabled only). Used to suppress the
	// duplicate final write and to emit a terminating newline at message_end.
	let streamedAssistantText = false;
	let textOutputWritten = false;

	const emitProgress = (line: string): void => {
		if (!progressEnabled) return;
		lastProgress = line;
		const elapsed = Math.max(0, Math.round((Date.now() - startedAt) / 1000));
		console.error(`[repi:print] +${elapsed}s ${line}`);
	};

	const abortForGuard = (reason: string): void => {
		if (guardAbortReason) return;
		guardAbortReason = reason;
		emitProgress(`guard_abort reason=${reason}`);
		activeGuardReject?.(new Error(`REPI print guard aborted: ${reason}`));
		void session.abort().catch((error) => {
			console.error(`[repi:print] abort_error ${error instanceof Error ? error.message : String(error)}`);
		});
	};

	const runPromptWithTimeout = async (
		message: string,
		promptOptions?: Parameters<typeof session.prompt>[1],
	): Promise<void> => {
		// A signal fired during a prior prompt set shuttingDown and is aborting
		// the session / disposing the runtime. Don't start a new prompt on a
		// session that's being torn down — that turn would be aborted mid-stream
		// by dispose() and never persisted (partial un-persisted turn).
		if (shuttingDown) {
			emitProgress("prompt_skipped_shutdown");
			return;
		}
		toolCallCount = 0;
		guardAbortReason = undefined;
		activeGuardReject = undefined;
		assistantMessageInProgress = false;
		toolInProgress = 0;
		emitProgress(
			`prompt_start chars=${message.length} timeoutMs=${timeoutMs ?? "none"} timeoutGraceMs=${timeoutGraceMs} timeoutToolGraceMs=${timeoutToolGraceMs} maxTurns=${maxTurns ?? "none"} maxToolCalls=${maxToolCalls ?? "none"}`,
		);
		const previousMaxTurns = session.agent.maxTurns;
		const previousReserveFinalTurn = session.agent.reserveFinalTurn;
		if (maxTurns !== undefined) {
			session.agent.maxTurns = maxTurns;
			session.agent.reserveFinalTurn = true;
		}
		if (!timeoutMs && maxTurns === undefined && maxToolCalls === undefined) {
			await session.prompt(message, promptOptions);
			emitProgress("prompt_done");
			return;
		}

		let timer: NodeJS.Timeout | undefined;
		let finished = false;
		let cancelWarn: (() => void) | undefined;
		try {
			const races: Array<Promise<unknown>> = [session.prompt(message, promptOptions)];
			if (timeoutMs) {
				const warnAtMs = timeoutMs - timeoutWarnLeadMs;
				if (timeoutWarnLeadMs > 0 && warnAtMs > 0) {
					const warning = `[REPI time-budget] Wall timeout in ~${Math.round(timeoutWarnLeadMs / 1000)}s. Persist your findings and write your report to disk NOW. Finish the current step and save outputs; do not start new long probes.`;
					cancelWarn = scheduleTimeoutWarning({
						warnAtMs,
						isFinished: () => finished,
						inject: () => {
							emitProgress(`timeout_warn leadMs=${timeoutWarnLeadMs} remainingMs=${timeoutWarnLeadMs}`);
							// session.steer queues into the agent's stream with no streaming gate
							// (delivered at the next turn boundary) — safe to call mid-flight.
							void session
								.steer(warning)
								.catch((error) =>
									console.error(
										`[repi:print] timeout_warn_steer_error ${error instanceof Error ? error.message : String(error)}`,
									),
								);
						},
					});
				}
				races.push(
					new Promise<never>((_resolve, reject) => {
						const abortAfterTimeout = (
							kind: "timeout" | "timeout_grace_exhausted" | "timeout_tool_grace_exhausted",
						) => {
							emitProgress(`timeout timeoutMs=${timeoutMs} action=abort reason=${kind}`);
							void session.abort().catch((error) => {
								console.error(
									`[repi:print] abort_error ${error instanceof Error ? error.message : String(error)}`,
								);
							});
							reject(
								new Error(
									kind === "timeout_grace_exhausted"
										? `REPI print prompt timed out after ${timeoutMs}ms plus ${timeoutGraceMs}ms assistant grace`
										: kind === "timeout_tool_grace_exhausted"
											? `REPI print prompt timed out after ${timeoutMs}ms plus ${timeoutToolGraceMs}ms tool grace`
											: `REPI print prompt timed out after ${timeoutMs}ms`,
								),
							);
						};
						timer = setTimeout(() => {
							if (assistantMessageInProgress && timeoutGraceMs > 0) {
								emitProgress(`timeout timeoutMs=${timeoutMs} action=assistant_grace graceMs=${timeoutGraceMs}`);
								timer = setTimeout(() => abortAfterTimeout("timeout_grace_exhausted"), timeoutGraceMs);
								return;
							}
							if (toolInProgress > 0 && timeoutToolGraceMs > 0) {
								// A tool is mid-execution (e.g. a long re_subagent child). Aborting
								// now would kill the host and lose the in-flight tool's result. Grant
								// a bounded grace so the tool can finish; the abort fires after the
								// grace whether or not it did, capping total run time.
								emitProgress(
									`timeout timeoutMs=${timeoutMs} action=tool_grace graceMs=${timeoutToolGraceMs} tools=${toolInProgress}`,
								);
								timer = setTimeout(() => abortAfterTimeout("timeout_tool_grace_exhausted"), timeoutToolGraceMs);
								return;
							}
							abortAfterTimeout("timeout");
						}, timeoutMs);
					}),
				);
			}
			if (maxToolCalls !== undefined) {
				races.push(
					new Promise<never>((_resolve, reject) => {
						activeGuardReject = reject;
					}),
				);
			}
			await Promise.race(races);
			finished = true;
			emitProgress("prompt_done");
		} finally {
			finished = true;
			activeGuardReject = undefined;
			session.agent.maxTurns = previousMaxTurns;
			session.agent.reserveFinalTurn = previousReserveFinalTurn;
			if (timer) clearTimeout(timer);
			cancelWarn?.();
		}
	};

	const disposeRuntime = async (): Promise<void> => {
		if (disposed) return;
		disposed = true;
		unsubscribe?.();
		await runtimeHost.dispose();
	};

	const registerSignalHandlers = (): void => {
		// SIGINT (Ctrl+C) is handled explicitly (opt #62): previously only
		// SIGTERM/SIGHUP were, so Ctrl+C took the default-exit path (exit 130)
		// WITHOUT aborting the in-flight turn or flushing partial assistant text —
		// the exact data-loss class opt #2 fixed for SIGTERM/SIGHUP, reopened for
		// SIGINT. (opt #61 A2 reaps tracked detached children on the default-exit
		// path, but that safety net knows nothing of the session/assistant text, so
		// partial output was still lost.) Handling SIGINT here runs the same
		// abort→flush→write→exit path, exiting 130 (128+SIGINT=2).
		const signals: NodeJS.Signals[] = ["SIGTERM", "SIGINT"];
		if (process.platform !== "win32") {
			signals.push("SIGHUP");
		}

		for (const signal of signals) {
			const handler = () => {
				// A second signal while we're already flushing/disposing would
				// re-enter and duplicate the final stdout writes. Force-exit
				// immediately (matches rpc-mode's re-entrant shutdown path).
				if (shuttingDown) {
					const forceCode = signal === "SIGHUP" ? 129 : signal === "SIGINT" ? 130 : 143;
					process.exit(forceCode);
					return;
				}
				shuttingDown = true;
				killTrackedDetachedChildren();
				// Abort the in-flight turn, then give it a bounded moment to
				// finalize so partial assistant text commits and gets written
				// instead of being lost when we exit.
				void session
					.abort()
					.catch((error) => {
						console.error(`[repi:print] abort_error ${error instanceof Error ? error.message : String(error)}`);
					})
					.finally(() => {
						void flushAssistantText().finally(() => {
							// flushRawStdout drains the queued rawStdoutWriteTail. In text
							// mode flushAssistantText already calls it, but in json mode
							// flushAssistantText returns immediately (mode !== "text") and
							// the final agent_end/trailing event JSONL queued in the tail
							// would be lost on signal exit. Flush unconditionally — safe on
							// a dead pipe (writeRawStdout's tail .catch handles EPIPE).
							void flushRawStdout().finally(() => {
								void disposeRuntime().finally(() => {
									const exitCode = signal === "SIGHUP" ? 129 : signal === "SIGINT" ? 130 : 143;
									process.exit(exitCode);
								});
							});
						});
					});
			};
			process.on(signal, handler);
			signalCleanupHandlers.push(() => process.off(signal, handler));
		}
	};

	if (!initialMessage && messages.length === 0) {
		console.error('No prompt provided. Use `repi -p "..."` or pass a message.');
		await disposeRuntime();
		return 1;
	}

	registerSignalHandlers();

	const writeLastAssistantText = (): boolean => {
		if (mode !== "text") return false;
		// When live streaming is on, assistant text was already written to stdout
		// as deltas (or via the message_end fallback). Skip the duplicate final write.
		if (streamTextEnabled) return false;
		const state = session.state;
		const lastMessage = state.messages[state.messages.length - 1];
		if (lastMessage?.role !== "assistant") return false;

		let wroteText = false;
		for (const content of (lastMessage as AssistantMessage).content) {
			if (content.type === "text" && content.text.trim() !== "") {
				writeRawStdout(`${content.text}\n`);
				textOutputWritten = true;
				wroteText = true;
			}
		}
		return wroteText;
	};

	/**
	 * Give an in-flight assistant turn a bounded moment to finalize so its partial
	 * text commits to `state.messages` via `message_end` (abort/error paths emit
	 * `message_end` with the partial content accumulated so far). Then write
	 * whatever assistant text is now available.
	 *
	 * Without this, SIGTERM/SIGHUP/timeout/catch paths exit before the loop
	 * finalizes the streamed message, so the partial assistant text stays in
	 * `streamingMessage` and is lost — `writeLastAssistantText` alone would find
	 * no committed assistant message to write.
	 */
	const flushAssistantText = async (settleMs = 5000): Promise<boolean> => {
		if (mode !== "text") return false;
		try {
			const idle = session.agent.waitForIdle();
			const settle = new Promise<void>((resolve) => {
				const t = setTimeout(resolve, settleMs);
				t.unref?.();
			});
			await Promise.race([idle, settle]);
		} catch {
			// Best-effort flush; never let settlement errors suppress output.
		}
		const wrote = writeLastAssistantText();
		await flushRawStdout();
		return wrote;
	};

	runtimeHost.setRebindSession(async () => {
		await rebindSession();
	});

	const rebindSession = async (): Promise<void> => {
		session = runtimeHost.session;
		// Unsubscribe from the OLD session's event forwarding FIRST. Previously
		// the old `unsubscribe` ran AFTER `bindExtensions`, so if `bindExtensions`
		// threw (e.g. an extension `session_start` handler error) the old
		// session's forwarder was never removed (event-forwarding leak on the
		// prior session) AND no new subscription was established (events stopped
		// forwarding on the new session). Mirror rpc-mode's ordering: unsubscribe
		// old first, then wrap `bindExtensions` in a try and establish the new
		// subscription in a `finally` so the forwarder is always re-attached. On
		// the success path the order relative to `bindExtensions` is unchanged,
		// so `session_start` emitted inside `bindExtensions` still goes only to
		// extension handlers.
		unsubscribe?.();
		try {
			await session.bindExtensions({
				uiContext: createPrintExtensionUIContext(mode),
				mode: mode === "json" ? "json" : "print",
				commandContextActions: {
					waitForIdle: () => session.waitForIdle(),
					newSession: async (newSessionOptions) => runtimeHost.newSession(newSessionOptions),
					fork: async (entryId, forkOptions) => {
						const result = await runtimeHost.fork(entryId, forkOptions);
						return { cancelled: result.cancelled };
					},
					navigateTree: async (targetId, navigateOptions) => {
						const result = await session.navigateTree(targetId, {
							summarize: navigateOptions?.summarize,
							customInstructions: navigateOptions?.customInstructions,
							replaceInstructions: navigateOptions?.replaceInstructions,
							label: navigateOptions?.label,
						});
						return { cancelled: result.cancelled };
					},
					switchSession: async (sessionPath, switchOptions) => {
						return runtimeHost.switchSession(sessionPath, switchOptions);
					},
					reload: async () => {
						await session.reload();
					},
				},
				onError: (err) => {
					console.error(`Extension error (${err.extensionPath}): ${err.error}`);
				},
			});
		} finally {
			unsubscribe = session.subscribe((event) => {
				if (event.type === "message_start" && event.message.role === "assistant") {
					assistantMessageInProgress = true;
					streamedAssistantText = false;
				}
				if (event.type === "message_end" && event.message.role === "assistant") {
					assistantMessageInProgress = false;
					// Live-streaming text mode: terminate the streamed line, or — if no
					// deltas arrived (non-streaming provider / single-shot message) —
					// write the full text now as a fallback so nothing is lost.
					if (streamTextEnabled) {
						if (streamedAssistantText) {
							writeRawStdout("\n");
						} else {
							for (const block of (event.message as AssistantMessage).content) {
								if (block.type === "text" && block.text.trim() !== "") {
									writeRawStdout(`${block.text}\n`);
									textOutputWritten = true;
								}
							}
						}
						streamedAssistantText = false;
					}
				}
				if (event.type === "message_update" && streamTextEnabled) {
					const delta = event.assistantMessageEvent;
					if (delta.type === "text_delta" && event.message.role === "assistant") {
						writeRawStdout(delta.delta);
						textOutputWritten = true;
						streamedAssistantText = true;
					}
				}
				if (event.type === "tool_execution_start") {
					toolCallCount += 1;
					toolInProgress += 1;
					if (maxToolCalls !== undefined && toolCallCount > maxToolCalls) {
						abortForGuard(`max_tool_calls_exceeded:${toolCallCount}/${maxToolCalls}`);
					}
				}
				if (event.type === "tool_execution_end") {
					if (toolInProgress > 0) toolInProgress -= 1;
				}
				if (mode === "json") {
					writeRawStdout(`${JSON.stringify(compactJsonEvent(event))}\n`);
					return;
				}
				const line = eventProgressLine(event);
				if (line) {
					emitProgress(line);
				}
			});
		}
	};

	try {
		if (progressEnabled) {
			emitProgress(`start mode=${mode}`);
			heartbeat = setInterval(() => {
				const elapsed = Math.max(0, Math.round((Date.now() - startedAt) / 1000));
				console.error(`[repi:print] +${elapsed}s still_running last=${lastProgress}`);
			}, 15_000);
			heartbeat.unref?.();
		}

		if (mode === "json") {
			const header = session.sessionManager.getHeader();
			if (header) {
				writeRawStdout(`${JSON.stringify(header)}\n`);
			}
		}

		await rebindSession();

		if (initialMessage && !shuttingDown) {
			await runPromptWithTimeout(initialMessage, { images: initialImages });
		}

		for (const message of messages) {
			if (shuttingDown) break;
			await runPromptWithTimeout(message);
		}

		if (!shuttingDown) {
			const state = session.state;
			const lastMessage = state.messages[state.messages.length - 1];

			if (lastMessage?.role === "assistant") {
				const assistantMsg = lastMessage as AssistantMessage;
				if (assistantMsg.stopReason === "error" || assistantMsg.stopReason === "aborted") {
					if (mode === "text") {
						writeLastAssistantText();
						console.error(assistantMsg.errorMessage || `Request ${assistantMsg.stopReason}`);
					}
					exitCode = 1;
				} else if (mode === "text") {
					writeLastAssistantText();
				}
			}
		}

		return exitCode;
	} catch (error: unknown) {
		// Let the in-flight turn finalize so partial assistant text commits,
		// then write it before surfacing the error.
		await flushAssistantText();
		if (mode === "text" && guardAbortReason && !textOutputWritten) {
			writeRawStdout(
				`[REPI print guard] aborted: ${guardAbortReason}\nNo assistant text was produced before the guard fired. Increase REPI_PRINT_MAX_TURNS/REPI_PRINT_MAX_TOOL_CALLS or narrow the prompt.\n`,
			);
			await flushRawStdout();
		}
		console.error(error instanceof Error ? error.message : String(error));
		return 1;
	} finally {
		if (heartbeat) clearInterval(heartbeat);
		for (const cleanup of signalCleanupHandlers) {
			cleanup();
		}
		await disposeRuntime();
		await flushRawStdout();
	}
}

/**
 * Print mode (single-shot): Send prompts, output result, exit.
 *
 * Used for:
 * - `pi -p "prompt"` - text output
 * - `pi --mode json "prompt"` - JSON event stream
 */

import type { AssistantMessage, ImageContent } from "@pi-recon/repi-ai";
import type { AgentSessionEvent } from "../core/agent-session.ts";
import type { AgentSessionRuntime } from "../core/agent-session-runtime.ts";
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
	const configured = envPositiveInteger("REPI_PRINT_TIMEOUT_GRACE_MS");
	if (configured !== undefined) return configured;
	return isRepiProductMode() ? 30_000 : 0;
}

function printMaxTurns(_mode: PrintModeOptions["mode"]): number | undefined {
	const configured = envPositiveInteger("REPI_PRINT_MAX_TURNS");
	if (configured !== undefined) return configured;
	return isRepiProductMode() ? 24 : undefined;
}

function printMaxToolCalls(_mode: PrintModeOptions["mode"]): number | undefined {
	const configured = envPositiveInteger("REPI_PRINT_MAX_TOOL_CALLS");
	if (configured !== undefined) return configured;
	return isRepiProductMode() ? 80 : undefined;
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
	const signalCleanupHandlers: Array<() => void> = [];
	const progressEnabled = printProgressEnabled(mode);
	const timeoutMs = printTimeoutMs(mode);
	const timeoutGraceMs = printTimeoutGraceMs(mode);
	const maxTurns = printMaxTurns(mode);
	const maxToolCalls = printMaxToolCalls(mode);
	const startedAt = Date.now();
	let lastProgress = "startup";
	let heartbeat: NodeJS.Timeout | undefined;
	let turnCount = 0;
	let toolCallCount = 0;
	let guardAbortReason: string | undefined;
	let activeGuardReject: ((error: Error) => void) | undefined;
	let assistantMessageInProgress = false;

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
		turnCount = 0;
		toolCallCount = 0;
		guardAbortReason = undefined;
		activeGuardReject = undefined;
		assistantMessageInProgress = false;
		emitProgress(
			`prompt_start chars=${message.length} timeoutMs=${timeoutMs ?? "none"} timeoutGraceMs=${timeoutGraceMs} maxTurns=${maxTurns ?? "none"} maxToolCalls=${maxToolCalls ?? "none"}`,
		);
		if (!timeoutMs && maxTurns === undefined && maxToolCalls === undefined) {
			await session.prompt(message, promptOptions);
			emitProgress("prompt_done");
			return;
		}

		let timer: NodeJS.Timeout | undefined;
		try {
			const races: Array<Promise<unknown>> = [session.prompt(message, promptOptions)];
			if (timeoutMs) {
				races.push(
					new Promise<never>((_resolve, reject) => {
						const abortAfterTimeout = (kind: "timeout" | "timeout_grace_exhausted") => {
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
							abortAfterTimeout("timeout");
						}, timeoutMs);
					}),
				);
			}
			if (maxTurns !== undefined || maxToolCalls !== undefined) {
				races.push(
					new Promise<never>((_resolve, reject) => {
						activeGuardReject = reject;
					}),
				);
			}
			await Promise.race(races);
			emitProgress("prompt_done");
		} finally {
			activeGuardReject = undefined;
			if (timer) clearTimeout(timer);
		}
	};

	const disposeRuntime = async (): Promise<void> => {
		if (disposed) return;
		disposed = true;
		unsubscribe?.();
		await runtimeHost.dispose();
	};

	const registerSignalHandlers = (): void => {
		const signals: NodeJS.Signals[] = ["SIGTERM"];
		if (process.platform !== "win32") {
			signals.push("SIGHUP");
		}

		for (const signal of signals) {
			const handler = () => {
				killTrackedDetachedChildren();
				void disposeRuntime().finally(() => {
					process.exit(signal === "SIGHUP" ? 129 : 143);
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
		const state = session.state;
		const lastMessage = state.messages[state.messages.length - 1];
		if (lastMessage?.role !== "assistant") return false;

		let wroteText = false;
		for (const content of (lastMessage as AssistantMessage).content) {
			if (content.type === "text" && content.text.trim() !== "") {
				writeRawStdout(`${content.text}\n`);
				wroteText = true;
			}
		}
		return wroteText;
	};

	runtimeHost.setRebindSession(async () => {
		await rebindSession();
	});

	const rebindSession = async (): Promise<void> => {
		session = runtimeHost.session;
		await session.bindExtensions({
			mode: mode === "json" ? "json" : "print",
			commandContextActions: {
				waitForIdle: () => session.agent.waitForIdle(),
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

		unsubscribe?.();
		unsubscribe = session.subscribe((event) => {
			if (event.type === "message_start" && event.message.role === "assistant") assistantMessageInProgress = true;
			if (event.type === "message_end" && event.message.role === "assistant") assistantMessageInProgress = false;
			if (event.type === "turn_start") {
				turnCount += 1;
				if (maxTurns !== undefined && turnCount > maxTurns) {
					abortForGuard(`max_turns_exceeded:${turnCount}/${maxTurns}`);
				}
			}
			if (event.type === "tool_execution_start") {
				toolCallCount += 1;
				if (maxToolCalls !== undefined && toolCallCount > maxToolCalls) {
					abortForGuard(`max_tool_calls_exceeded:${toolCallCount}/${maxToolCalls}`);
				}
			}
			if (mode === "json") {
				writeRawStdout(`${JSON.stringify(event)}\n`);
				return;
			}
			const line = eventProgressLine(event);
			if (line) {
				emitProgress(line);
			}
		});
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

		if (initialMessage) {
			await runPromptWithTimeout(initialMessage, { images: initialImages });
		}

		for (const message of messages) {
			await runPromptWithTimeout(message);
		}

		if (mode === "text") {
			const state = session.state;
			const lastMessage = state.messages[state.messages.length - 1];

			if (lastMessage?.role === "assistant") {
				const assistantMsg = lastMessage as AssistantMessage;
				if (assistantMsg.stopReason === "error" || assistantMsg.stopReason === "aborted") {
					writeLastAssistantText();
					console.error(assistantMsg.errorMessage || `Request ${assistantMsg.stopReason}`);
					exitCode = 1;
				} else {
					writeLastAssistantText();
				}
			}
		}

		return exitCode;
	} catch (error: unknown) {
		writeLastAssistantText();
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

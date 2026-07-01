/**
 * RPC Client for programmatic access to the coding agent.
 *
 * Spawns the agent in RPC mode and provides a typed API for all operations.
 */

import { type ChildProcess, spawn } from "node:child_process";
import type { AgentEvent, AgentMessage, ThinkingLevel } from "@pi-recon/repi-agent-core";
import type { ImageContent } from "@pi-recon/repi-ai";
import type { SessionStats } from "../../core/agent-session.ts";
import type { BashResult } from "../../core/bash-executor.ts";
import type { CompactionResult } from "../../core/compaction/index.ts";
import { attachJsonlLineReader, serializeJsonLine } from "./jsonl.ts";
import type { RpcCommand, RpcResponse, RpcSessionState, RpcSlashCommand } from "./rpc-types.ts";

// ============================================================================
// Types
// ============================================================================

/** Distributive Omit that works with union types */
type DistributiveOmit<T, K extends keyof T> = T extends unknown ? Omit<T, K> : never;

/** RpcCommand without the id field (for internal send) */
type RpcCommandBody = DistributiveOmit<RpcCommand, "id">;

export interface RpcClientOptions {
	/** Path to the CLI entry point (default: searches for dist/cli.js) */
	cliPath?: string;
	/** Working directory for the agent */
	cwd?: string;
	/** Environment variables */
	env?: Record<string, string>;
	/** Provider to use */
	provider?: string;
	/** Model ID to use */
	model?: string;
	/** Additional CLI arguments */
	args?: string[];
}

export interface ModelInfo {
	provider: string;
	id: string;
	contextWindow: number;
	reasoning: boolean;
}

export type RpcEventListener = (event: AgentEvent) => void;

// ============================================================================
// RPC Client
// ============================================================================

// Tail-cap for the accumulated agent-process stderr. The RPC agent process is
// long-lived (a whole session) and emits stderr continuously (deprecation
// warnings, debug logs, repeated warnings); without a cap `this.stderr` grows
// unbounded for the session lifetime AND is embedded verbatim in every error
// message (exit/timeout/stdin-error). Keep the most-recent tail — that is what
// diagnoses a just-occurred exit/error — and bound both memory and error
// message size. Same doctrine as mcp-manager stderr (12KB) and agent-thread
// stderr (512KB): a stream you keep, capped.
const RPC_STDERR_TAIL_CHARS = 64 * 1024;

export class RpcClient {
	private process: ChildProcess | null = null;
	private stopReadingStdout: (() => void) | null = null;
	private eventListeners: RpcEventListener[] = [];
	private pendingRequests: Map<string, { resolve: (response: RpcResponse) => void; reject: (error: Error) => void }> =
		new Map();
	/** Active onEvent-based waiters (waitForIdle / collectEvents). Unlike
	 * `pendingRequests` (the send() map), these are NOT rejected by
	 * rejectPendingRequests — without exit-aware rejection they hang for the
	 * full 60s timeout when the agent process dies, since no agent_end ever
	 * arrives. Rejected en masse from the exit/error/stdin-error handlers. */
	private pendingWaiters: Set<{
		reject: (error: Error) => void;
		unsubscribe: () => void;
		timer: NodeJS.Timeout;
	}> = new Set();
	private requestId = 0;
	private stderr = "";
	private exitError: Error | null = null;
	private options: RpcClientOptions;
	/**
	 * Synchronous `process.on("exit")` reap hook (opt #61). The spawned RPC agent
	 * child is a full agent process; on parent exit (crash, SIGKILL, consumer
	 * forgets stop()) it is reparented to init and keeps making LLM API calls
	 * (cost/quota leak) — the same class opt #46 fixed for AgentThreadManager.
	 * `stop()` only runs when the consumer calls it. Idempotent install/remove.
	 */
	private exitHook: (() => void) | undefined;

	constructor(options: RpcClientOptions = {}) {
		this.options = options;
	}

	/**
	 * Start the RPC agent process.
	 */
	async start(): Promise<void> {
		if (this.process) {
			throw new Error("Client already started");
		}

		this.exitError = null;

		const cliPath = this.options.cliPath ?? "dist/cli.js";
		const args = ["--mode", "rpc"];

		if (this.options.provider) {
			args.push("--provider", this.options.provider);
		}
		if (this.options.model) {
			args.push("--model", this.options.model);
		}
		if (this.options.args) {
			args.push(...this.options.args);
		}

		const childProcess = spawn("node", [cliPath, ...args], {
			cwd: this.options.cwd,
			env: { ...process.env, ...this.options.env },
			stdio: ["pipe", "pipe", "pipe"],
		});
		this.process = childProcess;
		this.installExitHook();

		// Collect stderr for debugging. Tail-capped so a long-lived RPC agent
		// session emitting continuous stderr cannot grow `this.stderr` unbounded
		// (it is embedded in every error message below). Keeps the most-recent
		// tail, which is what diagnoses a just-occurred exit/error.
		childProcess.stderr?.on("data", (data) => {
			this.stderr += data.toString();
			if (this.stderr.length > RPC_STDERR_TAIL_CHARS) this.stderr = this.stderr.slice(-RPC_STDERR_TAIL_CHARS);
			process.stderr.write(data);
		});
		// A stream-level 'error' on the stderr pipe (EBADF/EIO on a closed/detached
		// handle) has no listener by default → `Unhandled 'error' event` crashes the
		// parent during RPC teardown. The child "error" handler covers spawn errors,
		// not the readable stream's own error. Swallow best-effort; stderr is
		// debug-only and already accumulated up to the error.
		childProcess.stderr?.on("error", () => {});

		childProcess.once("exit", (code, signal) => {
			if (this.process !== childProcess) return;
			const error = this.createProcessExitError(code, signal);
			this.exitError = error;
			this.rejectPendingRequests(error);
			this.rejectPendingWaiters(error);
		});
		childProcess.once("error", (error) => {
			if (this.process !== childProcess) return;
			const processError = new Error(`Agent process error: ${error.message}. Stderr: ${this.stderr}`);
			this.exitError = processError;
			this.rejectPendingRequests(processError);
			this.rejectPendingWaiters(processError);
		});
		childProcess.stdin?.on("error", (error) => {
			if (this.process !== childProcess) return;
			const stdinError =
				this.exitError ?? new Error(`Agent process stdin error: ${error.message}. Stderr: ${this.stderr}`);
			this.exitError = stdinError;
			this.rejectPendingRequests(stdinError);
			this.rejectPendingWaiters(stdinError);
		});

		// Set up strict JSONL reader for stdout.
		this.stopReadingStdout = attachJsonlLineReader(childProcess.stdout!, (line) => {
			this.handleLine(line);
		});

		// Wait a moment for process to initialize
		await new Promise((resolve) => setTimeout(resolve, 100));

		if (this.process.exitCode !== null) {
			const error = this.exitError ?? this.createProcessExitError(this.process.exitCode, this.process.signalCode);
			this.exitError = error;
			throw error;
		}
	}

	/**
	 * Stop the RPC agent process.
	 */
	async stop(): Promise<void> {
		if (!this.process) return;

		this.stopReadingStdout?.();
		this.stopReadingStdout = null;
		this.process.kill("SIGTERM");

		// Wait for process to exit
		await new Promise<void>((resolve) => {
			const timeout = setTimeout(() => {
				this.process?.kill("SIGKILL");
				resolve();
			}, 1000);

			this.process?.on("exit", () => {
				clearTimeout(timeout);
				resolve();
			});
		});

		this.process = null;

		// Reject any still-pending send() requests and onEvent waiters with a
		// "stopped" error. In the normal path the child's exit handler already
		// rejected+cleared both (so these loops are no-ops). But if the child
		// ignored SIGTERM and we SIGKILLed it, stop() nulled `this.process`
		// BEFORE the late exit fired, so the exit handler's
		// `if (this.process !== childProcess) return` guard skipped rejection
		// entirely — without this, an in-flight send() waited its full 30s timer
		// for a "Timeout waiting for response" and waitForIdle/collectEvents
		// waited their full 60s, all with a misleading timeout error instead of
		// an immediate "stopped". Rejecting here is safe in both paths: when the
		// exit handler already ran, both collections are empty. (opt #120)
		const stoppedError = new Error("Agent process stopped.");
		this.rejectPendingRequests(stoppedError);
		this.rejectPendingWaiters(stoppedError);
		this.removeExitHook();
	}

	/**
	 * Install the synchronous `process.on("exit")` reap hook (opt #61). Idempotent.
	 * Bounds the live exit-listener count: a fresh RpcClient per RPC session
	 * installs one and removes it on stop(), so no accumulation across sessions.
	 */
	private installExitHook(): void {
		if (this.exitHook) return;
		const hook = () => this.killChild("parent_exit");
		this.exitHook = hook;
		process.on("exit", hook);
	}

	private removeExitHook(): void {
		if (!this.exitHook) return;
		try {
			process.off("exit", this.exitHook);
		} catch {
			/* listener already gone */
		}
		this.exitHook = undefined;
	}

	/**
	 * SIGKILL the in-flight RPC agent child if it is still running. Called from
	 * the exit hook on parent exit (synchronous, best-effort) so the child is not
	 * reparented to init. No-op once the child has exited (`exitCode`/`signalCode`
	 * set). Mirrors AgentThreadManager.disposeChildren (opt #46).
	 */
	private killChild(reason: string): void {
		const child = this.process;
		if (!child) return;
		if (child.exitCode !== null || child.signalCode !== null) return;
		void reason;
		try {
			child.kill("SIGKILL");
		} catch {
			/* already dead — nothing to reap */
		}
		void reason;
	}

	/**
	 * Subscribe to agent events.
	 */
	onEvent(listener: RpcEventListener): () => void {
		this.eventListeners.push(listener);
		return () => {
			const index = this.eventListeners.indexOf(listener);
			if (index !== -1) {
				this.eventListeners.splice(index, 1);
			}
		};
	}

	/**
	 * Get collected stderr output (useful for debugging).
	 */
	getStderr(): string {
		return this.stderr;
	}

	// =========================================================================
	// Command Methods
	// =========================================================================

	/**
	 * Send a prompt to the agent.
	 * Returns immediately after sending; use onEvent() to receive streaming events.
	 * Use waitForIdle() to wait for completion.
	 */
	async prompt(message: string, images?: ImageContent[]): Promise<void> {
		await this.send({ type: "prompt", message, images });
	}

	/**
	 * Queue a steering message to interrupt the agent mid-run.
	 */
	async steer(message: string, images?: ImageContent[]): Promise<void> {
		await this.send({ type: "steer", message, images });
	}

	/**
	 * Queue a follow-up message to be processed after the agent finishes.
	 */
	async followUp(message: string, images?: ImageContent[]): Promise<void> {
		await this.send({ type: "follow_up", message, images });
	}

	/**
	 * Abort current operation.
	 */
	async abort(): Promise<void> {
		await this.send({ type: "abort" });
	}

	/**
	 * Start a new session, optionally with parent tracking.
	 * @param parentSession - Optional parent session path for lineage tracking
	 * @returns Object with `cancelled: true` if an extension cancelled the new session
	 */
	async newSession(parentSession?: string): Promise<{ cancelled: boolean }> {
		const response = await this.send({ type: "new_session", parentSession });
		return this.getData(response);
	}

	/**
	 * Get current session state.
	 */
	async getState(): Promise<RpcSessionState> {
		const response = await this.send({ type: "get_state" });
		return this.getData(response);
	}

	/**
	 * Set model by provider and ID.
	 */
	async setModel(provider: string, modelId: string): Promise<{ provider: string; id: string }> {
		const response = await this.send({ type: "set_model", provider, modelId });
		return this.getData(response);
	}

	/**
	 * Cycle to next model.
	 */
	async cycleModel(): Promise<{
		model: { provider: string; id: string };
		thinkingLevel: ThinkingLevel;
		isScoped: boolean;
	} | null> {
		const response = await this.send({ type: "cycle_model" });
		return this.getData(response);
	}

	/**
	 * Get list of available models.
	 */
	async getAvailableModels(): Promise<ModelInfo[]> {
		const response = await this.send({ type: "get_available_models" });
		return this.getData<{ models: ModelInfo[] }>(response).models;
	}

	/**
	 * Set thinking level.
	 */
	async setThinkingLevel(level: ThinkingLevel): Promise<void> {
		await this.send({ type: "set_thinking_level", level });
	}

	/**
	 * Cycle thinking level.
	 */
	async cycleThinkingLevel(): Promise<{ level: ThinkingLevel } | null> {
		const response = await this.send({ type: "cycle_thinking_level" });
		return this.getData(response);
	}

	/**
	 * Set steering mode.
	 */
	async setSteeringMode(mode: "all" | "one-at-a-time"): Promise<void> {
		await this.send({ type: "set_steering_mode", mode });
	}

	/**
	 * Set follow-up mode.
	 */
	async setFollowUpMode(mode: "all" | "one-at-a-time"): Promise<void> {
		await this.send({ type: "set_follow_up_mode", mode });
	}

	/**
	 * Compact session context.
	 */
	async compact(customInstructions?: string): Promise<CompactionResult> {
		const response = await this.send({ type: "compact", customInstructions });
		return this.getData(response);
	}

	/**
	 * Set auto-compaction enabled/disabled.
	 */
	async setAutoCompaction(enabled: boolean): Promise<void> {
		await this.send({ type: "set_auto_compaction", enabled });
	}

	/**
	 * Set auto-retry enabled/disabled.
	 */
	async setAutoRetry(enabled: boolean): Promise<void> {
		await this.send({ type: "set_auto_retry", enabled });
	}

	/**
	 * Abort in-progress retry.
	 */
	async abortRetry(): Promise<void> {
		await this.send({ type: "abort_retry" });
	}

	/**
	 * Execute a bash command.
	 */
	async bash(command: string): Promise<BashResult> {
		const response = await this.send({ type: "bash", command });
		return this.getData(response);
	}

	/**
	 * Abort running bash command.
	 */
	async abortBash(): Promise<void> {
		await this.send({ type: "abort_bash" });
	}

	/**
	 * Get session statistics.
	 */
	async getSessionStats(): Promise<SessionStats> {
		const response = await this.send({ type: "get_session_stats" });
		return this.getData(response);
	}

	/**
	 * Export session to HTML.
	 */
	async exportHtml(outputPath?: string): Promise<{ path: string }> {
		const response = await this.send({ type: "export_html", outputPath });
		return this.getData(response);
	}

	/**
	 * Switch to a different session file.
	 * @returns Object with `cancelled: true` if an extension cancelled the switch
	 */
	async switchSession(sessionPath: string): Promise<{ cancelled: boolean }> {
		const response = await this.send({ type: "switch_session", sessionPath });
		return this.getData(response);
	}

	/**
	 * Fork from a specific message.
	 * @returns Object with `text` (the message text) and `cancelled` (if extension cancelled)
	 */
	async fork(entryId: string): Promise<{ text: string; cancelled: boolean }> {
		const response = await this.send({ type: "fork", entryId });
		return this.getData(response);
	}

	/**
	 * Clone the current active branch into a new session.
	 * @returns Object with `cancelled: true` if an extension cancelled the clone
	 */
	async clone(): Promise<{ cancelled: boolean }> {
		const response = await this.send({ type: "clone" });
		return this.getData(response);
	}

	/**
	 * Get messages available for forking.
	 */
	async getForkMessages(): Promise<Array<{ entryId: string; text: string }>> {
		const response = await this.send({ type: "get_fork_messages" });
		return this.getData<{ messages: Array<{ entryId: string; text: string }> }>(response).messages;
	}

	/**
	 * Get text of last assistant message.
	 */
	async getLastAssistantText(): Promise<string | null> {
		const response = await this.send({ type: "get_last_assistant_text" });
		return this.getData<{ text: string | null }>(response).text;
	}

	/**
	 * Set the session display name.
	 */
	async setSessionName(name: string): Promise<void> {
		await this.send({ type: "set_session_name", name });
	}

	/**
	 * Get all messages in the session.
	 */
	async getMessages(): Promise<AgentMessage[]> {
		const response = await this.send({ type: "get_messages" });
		return this.getData<{ messages: AgentMessage[] }>(response).messages;
	}

	/**
	 * Get available commands (extension commands, prompt templates, skills).
	 */
	async getCommands(): Promise<RpcSlashCommand[]> {
		const response = await this.send({ type: "get_commands" });
		return this.getData<{ commands: RpcSlashCommand[] }>(response).commands;
	}

	// =========================================================================
	// Helpers
	// =========================================================================

	/**
	 * Wait for agent to become idle (no streaming).
	 * Resolves when agent_end event is received.
	 */
	waitForIdle(timeout = 60000): Promise<void> {
		return new Promise((resolve, reject) => {
			// Forward-declared so the timeout/event callbacks can deregister the
			// waiter. The callbacks only fire after this synchronous body finishes,
			// by which point `waiter` is assigned — no TDZ at call time.
			let waiter!: { reject: (error: Error) => void; unsubscribe: () => void; timer: NodeJS.Timeout };
			const timer = setTimeout(() => {
				waiter.unsubscribe();
				this.pendingWaiters.delete(waiter);
				reject(new Error(`Timeout waiting for agent to become idle. Stderr: ${this.stderr}`));
			}, timeout);

			const unsubscribe = this.onEvent((event) => {
				if (event.type === "agent_end") {
					clearTimeout(timer);
					waiter.unsubscribe();
					this.pendingWaiters.delete(waiter);
					resolve();
				}
			});
			waiter = { reject, unsubscribe, timer };
			this.pendingWaiters.add(waiter);
		});
	}

	/**
	 * Collect events until agent becomes idle.
	 */
	collectEvents(timeout = 60000): Promise<AgentEvent[]> {
		return new Promise((resolve, reject) => {
			const events: AgentEvent[] = [];
			let waiter!: { reject: (error: Error) => void; unsubscribe: () => void; timer: NodeJS.Timeout };
			const timer = setTimeout(() => {
				waiter.unsubscribe();
				this.pendingWaiters.delete(waiter);
				reject(new Error(`Timeout collecting events. Stderr: ${this.stderr}`));
			}, timeout);

			const unsubscribe = this.onEvent((event) => {
				events.push(event);
				if (event.type === "agent_end") {
					clearTimeout(timer);
					waiter.unsubscribe();
					this.pendingWaiters.delete(waiter);
					resolve(events);
				}
			});
			waiter = { reject, unsubscribe, timer };
			this.pendingWaiters.add(waiter);
		});
	}

	/**
	 * Send prompt and wait for completion, returning all events.
	 */
	async promptAndWait(message: string, images?: ImageContent[], timeout = 60000): Promise<AgentEvent[]> {
		const eventsPromise = this.collectEvents(timeout);
		await this.prompt(message, images);
		return eventsPromise;
	}

	// =========================================================================
	// Internal
	// =========================================================================

	private handleLine(line: string): void {
		try {
			const data = JSON.parse(line);

			// A response is never an event. Matched → resolve its pending request;
			// unmatched (a late reply whose send() already timed out and deleted the
			// pending entry) → drop it. Pre-fix an unmatched response fell through to
			// the event-listener broadcast and was dispatched to every listener as a
			// phantom AgentEvent (polluting collectEvents / waitForIdle consumers).
			if (data.type === "response") {
				const id = data.id;
				if (id && this.pendingRequests.has(id)) {
					const pending = this.pendingRequests.get(id)!;
					this.pendingRequests.delete(id);
					pending.resolve(data as RpcResponse);
				}
				return;
			}

			// Otherwise it's an event
			for (const listener of this.eventListeners) {
				// opt #148: wrap each listener so a throw doesn't abort the loop and
				// starve every subsequent listener for this event (and get swallowed
				// under the misleading outer "non-JSON lines" catch). A misbehaving
				// listener must not silence its siblings or drop the line dispatch.
				try {
					listener(data as AgentEvent);
				} catch (err) {
					console.error("rpc-client event listener threw:", err);
				}
			}
		} catch {
			// Ignore non-JSON lines
		}
	}

	private createProcessExitError(code: number | null, signal: NodeJS.Signals | null): Error {
		return new Error(`Agent process exited (code=${code} signal=${signal}). Stderr: ${this.stderr}`);
	}

	private rejectPendingRequests(error: Error): void {
		for (const pending of this.pendingRequests.values()) {
			pending.reject(error);
		}
		this.pendingRequests.clear();
	}

	/** Reject all active onEvent-based waiters (waitForIdle / collectEvents) with
	 * the process exit/error. Mirrors rejectPendingRequests for send() waiters.
	 * Clears the per-waiter 60s timeout and unsubscribes the listener so neither
	 * a leaked timer nor a stale listener survives the process death. */
	private rejectPendingWaiters(error: Error): void {
		for (const waiter of this.pendingWaiters) {
			clearTimeout(waiter.timer);
			waiter.unsubscribe();
			waiter.reject(error);
		}
		this.pendingWaiters.clear();
	}

	private async send(command: RpcCommandBody): Promise<RpcResponse> {
		const childProcess = this.process;
		const stdin = childProcess?.stdin;
		if (!childProcess || !stdin) {
			throw new Error("Client not started");
		}
		if (this.exitError) {
			throw this.exitError;
		}
		if (childProcess.exitCode !== null) {
			const error = this.createProcessExitError(childProcess.exitCode, childProcess.signalCode);
			this.exitError = error;
			throw error;
		}
		if (stdin.destroyed || !stdin.writable) {
			const error = new Error(`Agent process stdin is not writable. Stderr: ${this.stderr}`);
			this.exitError = error;
			throw error;
		}

		const id = `req_${++this.requestId}`;
		const fullCommand = { ...command, id } as RpcCommand;

		return new Promise((resolve, reject) => {
			const timeout = setTimeout(() => {
				this.pendingRequests.delete(id);
				reject(new Error(`Timeout waiting for response to ${command.type}. Stderr: ${this.stderr}`));
			}, 30000);

			this.pendingRequests.set(id, {
				resolve: (response) => {
					clearTimeout(timeout);
					resolve(response);
				},
				reject: (error) => {
					clearTimeout(timeout);
					reject(error);
				},
			});

			try {
				stdin.write(serializeJsonLine(fullCommand));
			} catch (error: unknown) {
				const writeError = error instanceof Error ? error : new Error(String(error));
				const pending = this.pendingRequests.get(id);
				this.pendingRequests.delete(id);
				pending?.reject(writeError);
			}
		});
	}

	private getData<T>(response: RpcResponse): T {
		if (!response.success) {
			const errorResponse = response as Extract<RpcResponse, { success: false }>;
			throw new Error(errorResponse.error);
		}
		// Type assertion: we trust response.data matches T based on the command sent.
		// This is safe because each public method specifies the correct T for its command.
		const successResponse = response as Extract<RpcResponse, { success: true; data: unknown }>;
		return successResponse.data as T;
	}
}

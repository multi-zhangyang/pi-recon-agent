/**
 * Manual and automatic session compaction runtime.
 *
 * AgentSession supplies live dependencies; this class owns the compaction
 * state machine, abort controllers, overflow recovery, and continuation policy.
 */

import type { Agent, ThinkingLevel } from "@pi-recon/repi-agent-core";
import type { AssistantMessage, Model, ProviderEnv, ProviderHeaders } from "@pi-recon/repi-ai";
import { isContextOverflow, streamSimple } from "@pi-recon/repi-ai";
import { formatNoModelSelectedMessage } from "./auth-guidance.ts";
import {
	type CompactionResult,
	calculateContextTokens,
	compact,
	estimateCompactionContext,
	estimateContextTokens,
	prepareCompaction,
	shouldCompact,
	stripTrailingErrorAssistants,
} from "./compaction/index.ts";
import type { ExtensionRunner, SessionBeforeCompactResult } from "./extensions/index.ts";
import type { ModelRegistry } from "./model-registry.ts";
import type { CompactionEntry, SessionManager } from "./session-manager.ts";
import type { SettingsManager } from "./settings-manager.ts";

export type AgentSessionCompactionEvent =
	| { type: "compaction_start"; reason: "manual" | "threshold" | "overflow" }
	| {
			type: "compaction_end";
			reason: "manual" | "threshold" | "overflow";
			result: CompactionResult | undefined;
			aborted: boolean;
			willRetry: boolean;
			errorMessage?: string;
	  };

export interface AgentSessionCompactionHost {
	readonly agent: Agent;
	readonly sessionManager: SessionManager;
	readonly settingsManager: SettingsManager;
	readonly modelRegistry: ModelRegistry;
	readonly extensionRunner: ExtensionRunner;
	readonly model: Model<any> | undefined;
	readonly thinkingLevel: ThinkingLevel;
	readonly disposed: boolean;
	emit(event: AgentSessionCompactionEvent): void;
	disconnectFromAgent(): void;
	reconnectToAgent(): void;
	prepareForManualCompaction(): Promise<void>;
	continueQueuedMessages(): Promise<void>;
	getCompactionRequestAuth(model: Model<any>): Promise<{
		apiKey?: string;
		headers?: ProviderHeaders;
		env?: ProviderEnv;
	}>;
}

/**
 * True only when the assistant predates the latest compaction boundary.
 * Equality is intentionally treated as post-compaction because timestamps have
 * millisecond granularity.
 */
export function isAssistantFromBeforeCompaction(
	assistantMessage: AssistantMessage,
	compactionEntry: CompactionEntry | null,
): boolean {
	return compactionEntry !== null && assistantMessage.timestamp < new Date(compactionEntry.timestamp).getTime();
}

export class AgentSessionCompactionRuntime {
	private readonly host: AgentSessionCompactionHost;
	private _compactionAbortController: AbortController | undefined;
	private _autoCompactionAbortController: AbortController | undefined;
	private _resumeAfterTurnBoundaryCompaction = false;
	private _overflowRecoveryAttempted = false;

	constructor(host: AgentSessionCompactionHost) {
		this.host = host;
	}

	get isCompacting(): boolean {
		return this._compactionAbortController !== undefined || this._autoCompactionAbortController !== undefined;
	}

	resetOverflowRecovery(): void {
		this._overflowRecoveryAttempted = false;
	}

	private get agent(): Agent {
		return this.host.agent;
	}

	private get sessionManager(): SessionManager {
		return this.host.sessionManager;
	}

	private get settingsManager(): SettingsManager {
		return this.host.settingsManager;
	}

	private get model(): Model<any> | undefined {
		return this.host.model;
	}

	private get thinkingLevel(): ThinkingLevel {
		return this.host.thinkingLevel;
	}

	private get _modelRegistry(): ModelRegistry {
		return this.host.modelRegistry;
	}

	private get _extensionRunner(): ExtensionRunner {
		return this.host.extensionRunner;
	}

	private get _disposed(): boolean {
		return this.host.disposed;
	}

	private _emit(event: AgentSessionCompactionEvent): void {
		this.host.emit(event);
	}

	private _disconnectFromAgent(): void {
		this.host.disconnectFromAgent();
	}

	private _reconnectToAgent(): void {
		this.host.reconnectToAgent();
	}

	private prepareForManualCompaction(): Promise<void> {
		return this.host.prepareForManualCompaction();
	}

	private _continueQueuedMessages(): Promise<void> {
		return this.host.continueQueuedMessages();
	}

	private _getCompactionRequestAuth(model: Model<any>): Promise<{
		apiKey?: string;
		headers?: ProviderHeaders;
		env?: ProviderEnv;
	}> {
		return this.host.getCompactionRequestAuth(model);
	}

	/**
	 * Manually compact the session context.
	 * Aborts current agent operation first.
	 * @param customInstructions Optional instructions for the compaction summary
	 */
	async compact(customInstructions?: string): Promise<CompactionResult> {
		if (this.isCompacting) throw new Error("Another compaction is already running");
		const controller = new AbortController();
		this._compactionAbortController = controller;
		let disconnected = false;
		let emittedStart = false;

		// Set by the session_compact emit below when an extension (e.g. REPI
		// auto-resume) queues a steering message with triggerTurn:false. Manual
		// compact() has no surrounding post-compaction while-loop (unlike
		// _runAutoCompaction, whose caller drains via _handlePostAgentRun), so a
		// queued steer would sit undelivered forever and the agent would never go
		// idle. We drain it explicitly in finally after reconnecting.
		let drainQueuedAfterCompaction = false;

		try {
			this._disconnectFromAgent();
			disconnected = true;
			await this.prepareForManualCompaction();
			if (this._disposed) throw new Error("Cannot compact: session has been disposed");
			if (controller.signal.aborted) throw new Error("Compaction cancelled");
			this._emit({ type: "compaction_start", reason: "manual" });
			emittedStart = true;

			if (!this.model) {
				throw new Error(formatNoModelSelectedMessage());
			}

			const { apiKey, headers, env } = await this._getCompactionRequestAuth(this.model);
			if (controller.signal.aborted) throw new Error("Compaction cancelled");

			const pathEntries = this.sessionManager.getBranch();
			const settings = this.settingsManager.getCompactionSettings();

			const preparation = prepareCompaction(pathEntries, settings, this.model?.contextWindow);
			if (!preparation) {
				// Check why we can't compact
				const lastEntry = pathEntries[pathEntries.length - 1];
				if (lastEntry?.type === "compaction") {
					throw new Error("Already compacted");
				}
				throw new Error("Nothing to compact (session too small)");
			}

			// opt #237: prepareCompaction returns a preparation for a small session
			// even when there is NOTHING to summarize — findCutPoint's backward walk
			// never reaches keepRecentTokens, so cutIndex stays at the first cut
			// point (the first user message) and the messagesToSummarize loop only
			// visits the session header (which yields no message) → messagesToSummarize
			// empty, non-split → turnPrefixMessages empty. Pre-fix the manual path
			// proceeded to compact() → generateSummary([]) → the LLM hallucinated a
			// summary for an empty conversation, appendCompaction wrote a compaction
			// entry pointing at the first message (nothing discarded, context GREW by
			// the boilerplate), and that hallucinated summary became previousSummary
			// for the next compaction, corrupting the iterative summary chain. The
			// auto path already guards this (agent-session.ts:2507 hasSummarizableHistory);
			// mirror it here. Throwing at the caller (not inside compact()) avoids the
			// auto path's try/catch surfacing a spurious "Auto-compaction failed" for
			// proactive auto-compaction.
			const hasSummarizableHistory =
				preparation.messagesToSummarize.length > 0 || preparation.turnPrefixMessages.length > 0;
			if (!hasSummarizableHistory) {
				throw new Error("Nothing to compact (session too small)");
			}

			let extensionCompaction: CompactionResult | undefined;
			let fromExtension = false;

			if (this._extensionRunner.hasHandlers("session_before_compact")) {
				const result = (await this._extensionRunner.emit({
					type: "session_before_compact",
					preparation,
					branchEntries: pathEntries,
					customInstructions,
					signal: controller.signal,
				})) as SessionBeforeCompactResult | undefined;
				if (controller.signal.aborted) throw new Error("Compaction cancelled");

				if (result?.cancel) {
					throw new Error("Compaction cancelled");
				}

				if (result?.compaction) {
					extensionCompaction = result.compaction;
					fromExtension = true;
				}
			}

			let summary: string;
			let firstKeptEntryId: string;
			let tokensBefore: number;
			let details: unknown;

			if (extensionCompaction) {
				// Extension provided compaction content
				summary = extensionCompaction.summary;
				firstKeptEntryId = extensionCompaction.firstKeptEntryId;
				tokensBefore = extensionCompaction.tokensBefore;
				details = extensionCompaction.details;
			} else {
				// Generate compaction result
				const result = await compact(
					preparation,
					this.model,
					apiKey,
					headers,
					customInstructions,
					controller.signal,
					this.thinkingLevel,
					this.agent.streamFn,
					env,
				);
				summary = result.summary;
				firstKeptEntryId = result.firstKeptEntryId;
				tokensBefore = result.tokensBefore;
				details = result.details;
			}

			const contextEstimate = estimateCompactionContext(pathEntries, {
				summary,
				firstKeptEntryId,
				tokensBefore,
			});
			if (contextEstimate.afterTokens >= contextEstimate.beforeTokens) {
				throw new Error(
					`Compaction did not reduce estimated context (${contextEstimate.beforeTokens} -> ${contextEstimate.afterTokens} tokens)`,
				);
			}

			if (controller.signal.aborted) {
				throw new Error("Compaction cancelled");
			}

			// opt #231: look up the saved compaction entry by the id appendCompaction
			// returns, NOT by .find(summary) over getEntries() — getEntries() returns
			// EVERY entry across ALL branches, so a prior compaction on this branch
			// or a forked sibling sharing the same summary text (templated/boilerplate
			// summaries) would make .find return the WRONG entry (stale id/timestamp/
			// firstKeptEntryId) → the session_compact event feeds consumers a wrong
			// compaction boundary.
			const compactionId = this.sessionManager.appendCompaction(
				summary,
				firstKeptEntryId,
				tokensBefore,
				details,
				fromExtension,
			);
			const sessionContext = this.sessionManager.buildSessionContext();
			this.agent.state.messages = sessionContext.messages;

			// Get the saved compaction entry for the extension event
			const savedCompactionEntry = this.sessionManager.getEntry(compactionId) as CompactionEntry | undefined;

			if (this._extensionRunner && savedCompactionEntry) {
				await this._extensionRunner.emit({
					type: "session_compact",
					compactionEntry: savedCompactionEntry,
					fromExtension,
				});
			}

			// A session_compact handler may have queued a steering message
			// (triggerTurn:false) expecting the session loop to drain it. Record
			// that here so finally can drain after reconnecting the agent.
			drainQueuedAfterCompaction = this.agent.hasQueuedMessages();

			const compactionResult = {
				summary,
				firstKeptEntryId,
				tokensBefore,
				details,
			};
			this._emit({
				type: "compaction_end",
				reason: "manual",
				result: compactionResult,
				aborted: false,
				willRetry: false,
			});
			return compactionResult;
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			if (emittedStart) {
				const aborted =
					controller.signal.aborted ||
					message === "Compaction cancelled" ||
					(error instanceof Error && error.name === "AbortError");
				this._emit({
					type: "compaction_end",
					reason: "manual",
					result: undefined,
					aborted,
					willRetry: false,
					errorMessage: aborted ? undefined : `Compaction failed: ${message}`,
				});
			}
			throw error;
		} finally {
			if (this._compactionAbortController === controller) this._compactionAbortController = undefined;
			// Guard the reconnect: if dispose() ran while compact() was suspended on
			// the summarization await, the in-flight `compact(...)` throws
			// AbortError → catch emits compaction_end (dropped, _eventListeners
			// cleared) → this finally would re-subscribe _handleAgentEvent to the
			// agent AFTER dispose() disconnected it, piping subsequent agent events
			// back into a torn-down session. Skip the reconnect when disposed.
			if (disconnected && !this._disposed) this._reconnectToAgent();
			// Drain any steering message a session_compact extension queued with
			// triggerTurn:false. This mirrors what _runAutoCompaction's caller does
			// via its post-compaction while-loop. Without this, manual compact()
			// leaves the queued steer undelivered and the agent never reaches idle.
			// Only drain on a successful compaction (the flag is set after the
			// session_compact emit in the try block); skip on the error/cancel paths
			// and if nothing is actually queued.
			// opt #232: also guard the drain itself with !this._disposed. dispose()
			// does NOT clear the agent's steer/followUp queues, so hasQueuedMessages()
			// can still be true after dispose (e.g. a session_compact handler called
			// ctx.switchSession() during the emit, or the user switched mid-emit).
			// _handlePostAgentRun's disposed-guard stops its while-loop, but
			// _continueQueuedMessages' FIRST agent.continue() runs BEFORE that guard
			// — so without this, one LLM run would still leak on the disposed session.
			if (drainQueuedAfterCompaction && !this._disposed && this.agent.hasQueuedMessages()) {
				// Best-effort: the compaction itself already succeeded and its
				// compaction_end event was emitted in the try block. The drain is a
				// post-compaction resume, not part of compaction — a catastrophic
				// throw here (e.g. a bug in the agent loop, which is otherwise
				// robust via the stream-rejection safety net) must NOT override the
				// successful compaction result or make compact() reject as if
				// compaction failed (which could trigger a double-compact). Swallow
				// so the compaction result stands; the session log retains whatever
				// the partial drain produced for the next prompt's retry loop. We do
				// NOT emit a second compaction_end (compaction ended once, in try).
				try {
					await this._continueQueuedMessages();
				} catch {
					// best-effort drain failed; compaction result preserved
				}
			}
		}
	}

	/**
	 * Cancel in-progress compaction (manual or auto).
	 */
	abortCompaction(): void {
		this._compactionAbortController?.abort();
		this._autoCompactionAbortController?.abort();
	}

	/**
	 * Check if compaction is needed and run it.
	 * Called after agent_end and before prompt submission.
	 *
	 * Two cases:
	 * 1. Overflow: LLM returned context overflow error, remove error message from agent state, compact, auto-retry
	 * 2. Threshold: Context over threshold, compact, NO auto-retry (user continues manually)
	 *
	 * @param assistantMessage The assistant message to check
	 * @param skipAbortedCheck If false, include aborted messages (for pre-prompt check). Default: true
	 */
	shouldStopAfterTurnForCompaction(assistantMessage: AssistantMessage): boolean {
		const settings = this.settingsManager.getCompactionSettings();
		if (!settings.enabled) return false;
		if (assistantMessage.stopReason === "aborted" || assistantMessage.stopReason === "error") return false;

		// Terminal turn (no tool-call blocks): the loop is ending naturally on
		// end_turn/stop — there is no "next provider request" to stop before.
		// Returning true here would be redundant for stopping (the loop stops on
		// a no-tool-call turn anyway) but it would set the post-compaction resume
		// flag (_resumeAfterTurnBoundaryCompaction). That flag then drives
		// `agent.continue()` → agentLoopContinue on a conversation whose last
		// message is THIS terminal assistant message → it throws "Cannot continue
		// from message role: assistant" → a SUCCESSFUL autonomous run exits with
		// code 1 (caught by print-mode's catch → EXIT=1). Surfaced by a real-API
		// compaction-stress run. Let the loop end naturally; the post-run
		// _handlePostAgentRun → _checkCompaction path still compacts as
		// housekeeping for the next prompt, but with the resume flag unset it
		// returns hasQueuedMessages()=false → no continue → no throw. (#204)
		const content = assistantMessage.content;
		if (!Array.isArray(content) || !content.some((c) => c.type === "toolCall")) return false;

		const contextWindow = this.model?.contextWindow ?? 0;
		if (!Number.isFinite(contextWindow) || contextWindow <= 0) return false;

		const sameModel =
			this.model && assistantMessage.provider === this.model.provider && assistantMessage.model === this.model.id;
		if (!sameModel) return false;

		const compactionEntry = this.sessionManager.getLatestCompactionOnBranch();
		const assistantIsFromBeforeCompaction = isAssistantFromBeforeCompaction(assistantMessage, compactionEntry);
		if (assistantIsFromBeforeCompaction) return false;

		// Count the just-produced tool results (trailing messages after this
		// assistant message in agent state) in addition to the last-request usage,
		// so a single large tool-result batch trips the proactive threshold NOW
		// instead of on the NEXT request. calculateContextTokens(usage) alone
		// reflects only the request that produced this assistant message — it
		// excludes the tool results executed this turn, which will be sent next
		// request. Without the trailing estimate, a tool batch that pushes the
		// next request past the threshold (or even over the window) is missed here
		// and falls to the reactive overflow path, costing the model a turn to a
		// preventable context-overflow error.
		//
		// Safety: the last usage in agent.state.messages is this assistant
		// message's (trailing messages are tool results with no usage), and the
		// assistantIsFromBeforeCompaction guard above guarantees it is
		// post-compaction, so no extra usage-source guard is needed (unlike the
		// error branch of _checkCompaction, which must guard a possibly-stale
		// last-usage from a kept pre-compaction message).
		const estimate = estimateContextTokens(this.agent.state.messages);
		const contextTokens =
			estimate.lastUsageIndex === null ? calculateContextTokens(assistantMessage.usage) : estimate.tokens;
		if (!shouldCompact(contextTokens, contextWindow, settings)) return false;

		this._resumeAfterTurnBoundaryCompaction = true;
		return true;
	}

	async checkCompaction(
		assistantMessage: AssistantMessage,
		skipAbortedCheck = true,
		willRetryOverflow = true,
	): Promise<boolean> {
		const settings = this.settingsManager.getCompactionSettings();
		if (!settings.enabled) return false;

		// Skip if message was aborted (user cancelled) - unless skipAbortedCheck is false
		if (skipAbortedCheck && assistantMessage.stopReason === "aborted") return false;

		const contextWindow = this.model?.contextWindow ?? 0;

		// Skip overflow check if the message came from a different model.
		// This handles the case where user switched from a smaller-context model (e.g. opus)
		// to a larger-context model (e.g. codex) - the overflow error from the old model
		// shouldn't trigger compaction for the new model.
		const sameModel =
			this.model && assistantMessage.provider === this.model.provider && assistantMessage.model === this.model.id;

		// Skip compaction checks if this assistant message is older than the latest
		// compaction boundary. This prevents a stale pre-compaction usage/error
		// from retriggering compaction on the first prompt after compaction.
		const compactionEntry = this.sessionManager.getLatestCompactionOnBranch();
		const assistantIsFromBeforeCompaction = isAssistantFromBeforeCompaction(assistantMessage, compactionEntry);
		if (assistantIsFromBeforeCompaction) {
			return false;
		}

		// Case 1: Overflow - LLM returned context overflow error
		if (sameModel && isContextOverflow(assistantMessage, contextWindow)) {
			if (this._overflowRecoveryAttempted) {
				this._emit({
					type: "compaction_end",
					reason: "overflow",
					result: undefined,
					aborted: false,
					willRetry: false,
					errorMessage:
						"Context overflow recovery failed after one compact-and-retry attempt. Try reducing context or switching to a larger-context model.",
				});
				return false;
			}

			this._overflowRecoveryAttempted = true;
			// Remove trailing error/aborted assistant message(s) from agent state
			// (they ARE saved to session for history, but we don't want them in
			// context for the retry). Strip ALL trailing ones — if multiple are
			// present, leaving any behind would make the post-compaction willRetry
			// path or the next continue see an error assistant as the last message
			// and refuse to continue.
			this.agent.state.messages = stripTrailingErrorAssistants(this.agent.state.messages);
			return await this.runAutoCompaction("overflow", willRetryOverflow);
		}

		// Case 2: Threshold - context is getting large
		// For errors or malformed all-zero usage, estimate from the last valid response.
		let contextTokens: number;
		const directContextTokens = calculateContextTokens(assistantMessage.usage);
		if (assistantMessage.stopReason === "error" || directContextTokens === 0) {
			const messages = this.agent.state.messages;
			const estimate = estimateContextTokens(messages);
			if (estimate.lastUsageIndex === null) return false; // No usage data at all
			// Verify the usage source is post-compaction. Kept pre-compaction messages
			// have stale usage reflecting the old (larger) context and would falsely
			// trigger compaction right after one just finished.
			const usageMsg = messages[estimate.lastUsageIndex];
			// opt #230: route through isAssistantFromBeforeCompaction (strict `<`,
			// not `<=`) — opt #226's doctrine: a same-ms post-compaction error
			// assistant must NOT be classified as stale (the compaction entry's
			// timestamp is Date.now() at append; a post-compaction error assistant
			// created in the same boundary ms is ambiguous, and `<=` silently skips
			// the overflow check → a preventable threshold compaction is missed).
			// The pre-compaction triggering assistant is always strictly earlier, so
			// strict `<` still catches it.
			if (
				usageMsg.role === "assistant" &&
				isAssistantFromBeforeCompaction(usageMsg as AssistantMessage, compactionEntry)
			) {
				return false;
			}
			contextTokens = estimate.tokens;
		} else {
			// Count the just-produced tool results (trailing messages after this
			// assistant message) in addition to the last-request usage, so a large
			// tool-result batch trips the threshold now rather than on the next
			// request (which would fall to the reactive overflow path and cost a
			// turn). The last usage in state is this post-compaction assistant
			// message's (assistantIsFromBeforeCompaction guarded it above), so the
			// extra usage-source guard the error branch needs is not required here.
			const estimate = estimateContextTokens(this.agent.state.messages);
			contextTokens = estimate.lastUsageIndex === null ? directContextTokens : estimate.tokens;
		}
		if (shouldCompact(contextTokens, contextWindow, settings)) {
			return await this.runAutoCompaction("threshold", false);
		}
		return false;
	}

	/**
	 * Internal: Run auto-compaction with events.
	 */
	async runAutoCompaction(reason: "overflow" | "threshold", willRetry: boolean): Promise<boolean> {
		const settings = this.settingsManager.getCompactionSettings();
		const resumeAfterTurnBoundary = this._resumeAfterTurnBoundaryCompaction;
		this._resumeAfterTurnBoundaryCompaction = false;

		this._emit({ type: "compaction_start", reason });
		this._autoCompactionAbortController = new AbortController();

		try {
			if (!this.model) {
				this._emit({
					type: "compaction_end",
					reason,
					result: undefined,
					aborted: false,
					willRetry: false,
				});
				return false;
			}

			let apiKey: string | undefined;
			let headers: ProviderHeaders | undefined;
			let env: ProviderEnv | undefined;
			if (this.agent.streamFn === streamSimple) {
				const authResult = await this._modelRegistry.getApiKeyAndHeaders(this.model);
				if (!authResult.ok || !authResult.apiKey) {
					this._emit({
						type: "compaction_end",
						reason,
						result: undefined,
						aborted: false,
						willRetry: false,
					});
					return false;
				}
				apiKey = authResult.apiKey;
				headers = authResult.headers;
			} else {
				({ apiKey, headers, env } = await this._getCompactionRequestAuth(this.model));
			}
			if (this._autoCompactionAbortController.signal.aborted) throw new Error("Compaction cancelled");

			const pathEntries = this.sessionManager.getBranch();

			const preparation = prepareCompaction(pathEntries, settings, this.model?.contextWindow);
			if (!preparation) {
				this._emit({
					type: "compaction_end",
					reason,
					result: undefined,
					aborted: false,
					willRetry: false,
				});
				return false;
			}

			const hasSummarizableHistory =
				preparation.messagesToSummarize.length > 0 || preparation.turnPrefixMessages.length > 0;
			if (!hasSummarizableHistory) {
				this._emit({
					type: "compaction_end",
					reason,
					result: undefined,
					aborted: false,
					willRetry: false,
				});
				return false;
			}

			let extensionCompaction: CompactionResult | undefined;
			let fromExtension = false;

			if (this._extensionRunner.hasHandlers("session_before_compact")) {
				const extensionResult = (await this._extensionRunner.emit({
					type: "session_before_compact",
					preparation,
					branchEntries: pathEntries,
					customInstructions: undefined,
					signal: this._autoCompactionAbortController.signal,
				})) as SessionBeforeCompactResult | undefined;
				if (this._autoCompactionAbortController.signal.aborted) throw new Error("Compaction cancelled");

				if (extensionResult?.cancel) {
					this._emit({
						type: "compaction_end",
						reason,
						result: undefined,
						aborted: true,
						willRetry: false,
					});
					return false;
				}

				if (extensionResult?.compaction) {
					extensionCompaction = extensionResult.compaction;
					fromExtension = true;
				}
			}

			let summary: string;
			let firstKeptEntryId: string;
			let tokensBefore: number;
			let details: unknown;

			if (extensionCompaction) {
				// Extension provided compaction content
				summary = extensionCompaction.summary;
				firstKeptEntryId = extensionCompaction.firstKeptEntryId;
				tokensBefore = extensionCompaction.tokensBefore;
				details = extensionCompaction.details;
			} else {
				// Generate compaction result
				const compactResult = await compact(
					preparation,
					this.model,
					apiKey,
					headers,
					undefined,
					this._autoCompactionAbortController.signal,
					this.thinkingLevel,
					this.agent.streamFn,
					env,
				);
				summary = compactResult.summary;
				firstKeptEntryId = compactResult.firstKeptEntryId;
				tokensBefore = compactResult.tokensBefore;
				details = compactResult.details;
			}

			const contextEstimate = estimateCompactionContext(pathEntries, {
				summary,
				firstKeptEntryId,
				tokensBefore,
			});
			if (contextEstimate.afterTokens >= contextEstimate.beforeTokens) {
				throw new Error(
					`Compaction did not reduce estimated context (${contextEstimate.beforeTokens} -> ${contextEstimate.afterTokens} tokens)`,
				);
			}

			if (this._autoCompactionAbortController.signal.aborted) {
				this._emit({
					type: "compaction_end",
					reason,
					result: undefined,
					aborted: true,
					willRetry: false,
				});
				return false;
			}

			// opt #231: look up the saved compaction entry by the id appendCompaction
			// returns, NOT by .find(summary) over getEntries() — getEntries() returns
			// EVERY entry across ALL branches, so a prior compaction sharing the same
			// summary text would make .find return the WRONG (stale) entry.
			const compactionId = this.sessionManager.appendCompaction(
				summary,
				firstKeptEntryId,
				tokensBefore,
				details,
				fromExtension,
			);
			const sessionContext = this.sessionManager.buildSessionContext();
			this.agent.state.messages = sessionContext.messages;

			// Get the saved compaction entry for the extension event
			const savedCompactionEntry = this.sessionManager.getEntry(compactionId) as CompactionEntry | undefined;

			if (this._extensionRunner && savedCompactionEntry) {
				await this._extensionRunner.emit({
					type: "session_compact",
					compactionEntry: savedCompactionEntry,
					fromExtension,
				});
			}

			const result: CompactionResult = {
				summary,
				firstKeptEntryId,
				tokensBefore,
				details,
			};
			this._emit({ type: "compaction_end", reason, result, aborted: false, willRetry });

			if (willRetry) {
				// Strip ALL trailing error/aborted assistant messages, not just the
				// last one. buildSessionContext() above rebuilt state.messages from
				// the SESSION, which retains every error assistant from prior
				// retryable failures (each _prepareRetry removes them from live state
				// but keeps them in the session for history). A single removal here
				// leaves an earlier error assistant as the new last message, so the
				// next runAgentLoopContinue throws "Cannot continue from message
				// role: assistant" — defeating overflow recovery whenever retries
				// precede an overflow.
				this.agent.state.messages = stripTrailingErrorAssistants(this.agent.state.messages);
				// opt #217: silent-overflow recovery. A SILENT overflow (z.ai
				// stopReason "stop" with usage.input > contextWindow; Xiaomi MiMo
				// stopReason "length" with output 0) is NOT "error"/"aborted", so
				// stripTrailingErrorAssistants leaves that assistant in place. When
				// it is a TERMINAL turn (no toolCall blocks) and no steering message
				// is queued, the while-loop's agent.continue() throws "Cannot
				// continue from message role: assistant" (agent.ts continue() guard
				// at ~line 467) — the reactive overflow path lacked the #204
				// terminal-turn guard that protects the proactive path. Inject a
				// continuation steer so the model retries with the reduced
				// (post-compaction) context instead of crashing. (REPI auto-resume
				// usually queues a steer already; this covers non-REPI mode and
				// exhausted resume budget.)
				const lastAfterStrip = this.agent.state.messages[this.agent.state.messages.length - 1];
				if (
					lastAfterStrip?.role === "assistant" &&
					!(lastAfterStrip as AssistantMessage).content.some((b) => b.type === "toolCall") &&
					!this.agent.hasQueuedMessages()
				) {
					this.agent.steer({ role: "user", content: "Continue.", timestamp: Date.now() });
				}
				return true;
			}

			// Auto-compaction can complete while follow-up/steering/custom messages are waiting.
			// Continue once so queued messages are delivered. If the low-level loop
			// stopped specifically to create a compaction boundary, continue even
			// without queued user messages; this resumes the autonomous tool loop.
			return resumeAfterTurnBoundary || this.agent.hasQueuedMessages();
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : "compaction failed";
			// Detect abort the same way manual compact() does: an AbortError thrown
			// by the summarization stream (compact()/generateSummary()) when the user
			// aborts mid-summarization skips the post-compact signal check above, so
			// without this detection the abort is misreported as a failure.
			const aborted =
				this._autoCompactionAbortController?.signal.aborted ||
				(error instanceof Error && error.name === "AbortError");
			this._emit({
				type: "compaction_end",
				reason,
				result: undefined,
				aborted,
				willRetry: false,
				errorMessage: aborted
					? undefined
					: reason === "overflow"
						? `Context overflow recovery failed: ${errorMessage}`
						: `Auto-compaction failed: ${errorMessage}`,
			});
			return false;
		} finally {
			this._resumeAfterTurnBoundaryCompaction = false;
			this._autoCompactionAbortController = undefined;
		}
	}
}

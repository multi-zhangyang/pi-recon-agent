import { randomUUID } from "node:crypto";
import type { AgentMessage } from "@pi-recon/repi-agent-core";
import type { AutocompleteItem } from "@pi-recon/repi-tui";
import { Type } from "typebox";
import type { ExtensionAPI, ExtensionContext, InputEvent, ToolCallEventResult } from "../extensions/types.ts";

export type RepiGoalStatus = "active" | "paused" | "budget_limited" | "complete";
type AgentStopReason = "stop" | "length" | "toolUse" | "error" | "aborted";
type GoalRecoveryKind = "provider_retry" | "compaction_retry";

export interface RepiGoalState {
	id: string;
	text: string;
	status: RepiGoalStatus;
	startedAt: number;
	updatedAt: number;
	iteration: number;
	tokenBudget?: number;
	tokensUsed: number;
	timeUsedSeconds: number;
	baselineTokens: number;
}

interface RepiGoalEntryData {
	version?: 1;
	goal?: RepiGoalState | null;
}

interface RepiGoalCommandResult {
	kind: "show" | "help" | "start" | "pause" | "resume" | "clear" | "edit";
	objective?: string;
	tokenBudget?: number;
}

interface ContinuationPending {
	goalId: string;
	iteration: number;
	marker: string;
	prompt: string;
}

interface GoalRecovery {
	goalId: string;
	kind: GoalRecoveryKind;
}

interface AssistantMessageLike {
	role: "assistant";
	stopReason?: AgentStopReason;
	errorMessage?: string;
	usage?: unknown;
}

interface RepiGoalRuntime {
	activeGoal?: RepiGoalState;
	/** Goal objective/rules are injected once per session generation, not every turn. */
	lastGoalSystemPromptKey?: string;
	completionStatusTimer?: ReturnType<typeof setTimeout>;
	continuationPending?: ContinuationPending;
	goalRecovery?: GoalRecovery;
	staleGoalToolCallsBlocked: boolean;
	cancelledContinuationMarkers: Set<string>;
	recoveryAttempts: Map<string, number>;
}

interface GoalCompleteDetails {
	goal: string;
	summary: string;
	status: "accepted" | "rejected";
	reason?: string;
}

type RepiGoalContext = Pick<
	ExtensionContext,
	"ui" | "mode" | "hasUI" | "cwd" | "sessionManager" | "isIdle" | "hasPendingMessages" | "abort" | "compact" | "model"
>;

const STATUS_KEY = "goal";
export const REPI_GOAL_STATE_ENTRY_TYPE = "repi-goal-state";
const LEGACY_PI_GOAL_STATE_ENTRY_TYPE = "goal-state";
const MAX_OBJECTIVE_LENGTH = 4_000;
const MAX_CANCELLED_CONTINUATION_PROMPTS = 20;
const PROVIDER_RETRY_BUDGET = 3;
const CONTINUATION_MARKER_PREFIX = "repi-goal-continuation:";
const CONTRADICTORY_COMPLETION_PATTERNS = [
	/(?<!could\s)\bnot\s+(?:yet\s+)?(?:complete|completed|done|finished)\b/i,
	/\bstill\s+(?:incomplete|failing|failing\s+tests?|fails?)\b/i,
	/\btests?\s+(?:still\s+)?fail(?:ing)?\b/i,
	/\bremaining\s+(?:work|tasks?|todo)\b/i,
] as const;
const NON_RETRYABLE_GOAL_ERROR_RE =
	/usage[_\s-]*limit|chatgpt usage limit|multi-auth rotation failed|credentials tried|unauthori[sz]ed|invalid api key|forbidden|permission denied/i;
const RETRYABLE_GOAL_ERROR_RE =
	/websocket closed|sse response headers timed out|headers timed out|provider returned error|overloaded|rate.?limit|too many requests|429|500|502|503|504|service unavailable|network|connection|socket|fetch failed|timeout|terminated/i;
const CONTEXT_OVERFLOW_RE =
	/context[_\s-]*(?:length|window|limit)|input exceeds|maximum context|too many tokens|token limit|reduce the length/i;

const GOAL_ARGUMENT_COMPLETIONS: readonly AutocompleteItem[] = [
	{ value: "pause", label: "pause", description: "Pause the active REPI goal" },
	{ value: "resume", label: "resume", description: "Resume a paused or budget-limited REPI goal" },
	{ value: "clear", label: "clear", description: "Clear the current REPI goal" },
	{ value: "edit", label: "edit", description: "Edit the current REPI goal objective" },
	{ value: "status", label: "status", description: "Show the current REPI goal" },
	{ value: "--tokens ", label: "--tokens", description: "Set a token budget before the goal" },
];
const EDIT_TOKEN_COMPLETION: AutocompleteItem = {
	value: "edit --tokens ",
	label: "--tokens",
	description: "Set a token budget before the updated goal",
};

export function installRepiGoalMode(pi: ExtensionAPI): void {
	const runtime: RepiGoalRuntime = {
		staleGoalToolCallsBlocked: false,
		cancelledContinuationMarkers: new Set<string>(),
		recoveryAttempts: new Map<string, number>(),
	};

	pi.registerTool({
		name: "goal_complete",
		label: "Goal Complete",
		description:
			"Mark the active REPI /goal as complete after all required work is finished and verified. Do not use for partial progress, blockers, failing checks, or unverified claims.",
		promptSnippet: "Mark the active REPI /goal as complete after fully finishing and verifying it",
		promptGuidelines: [
			"When a REPI /goal is active, keep working until the goal is complete; do not stop with only a plan, TODO list, partial progress, or suggested next steps.",
			"Before calling goal_complete, audit the active goal requirement by requirement against current files, command output, tests, runtime behavior, or external state.",
			"Call goal_complete only after the requested goal is fully implemented, verified, and no known required work remains; otherwise continue working.",
		],
		parameters: Type.Object({
			summary: Type.String({
				description:
					"What was completed and which evidence verified it. Do not report partial progress, blockers, failures, or remaining work here.",
			}),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const completedGoal = runtime.activeGoal;
			const goal = completedGoal?.text ?? "unknown goal";
			const summary = String(params.summary ?? "").trim();

			if (!completedGoal) {
				const rejection = "Goal completion rejected: no active /goal.";
				ctx.ui.notify(rejection, "warning");
				return {
					content: [{ type: "text" as const, text: rejection }],
					details: { goal, summary, status: "rejected", reason: "no active goal" } satisfies GoalCompleteDetails,
				};
			}

			const rejectionReason = !summary
				? "summary is empty"
				: isContradictoryCompletionSummary(summary)
					? "summary says the goal is not complete"
					: undefined;
			if (rejectionReason) {
				updateGoalUsage(completedGoal, ctx);
				persistGoal(pi, completedGoal);
				updateStatus(runtime, ctx, completedGoal);
				const rejection = `Goal completion rejected: ${rejectionReason}.`;
				ctx.ui.notify(rejection, "warning");
				return {
					content: [{ type: "text" as const, text: rejection }],
					details: { goal, summary, status: "rejected", reason: rejectionReason } satisfies GoalCompleteDetails,
				};
			}

			runtime.activeGoal = transitionGoal(completedGoal, "complete");
			updateGoalUsage(runtime.activeGoal, ctx);
			persistGoal(pi, runtime.activeGoal);
			clearActiveGoal(pi, runtime, ctx, { showStatus: false });
			showCompletionStatus(runtime, ctx);
			ctx.ui.notify(`Goal complete: ${goal}`, "info");

			return {
				content: [{ type: "text" as const, text: `Goal complete: ${summary}` }],
				details: { goal, summary, status: "accepted" } satisfies GoalCompleteDetails,
				terminate: true,
			};
		},
	});

	pi.registerCommand("goal", {
		description: "Run a REPI goal to completion: /goal [--tokens 100k] <goal_to_complete>",
		getArgumentCompletions: completeGoalArguments,
		handler: async (args, ctx) => {
			const result = parseGoalCommand(args);
			if (typeof result === "string") {
				ctx.ui.notify(result, "warning");
				return;
			}

			switch (result.kind) {
				case "help":
					showGoalHelp(pi, runtime, ctx);
					return;
				case "show":
					showGoal(pi, runtime, ctx);
					return;
				case "pause":
					pauseGoal(pi, runtime, ctx);
					return;
				case "resume":
					await resumeGoal(pi, runtime, ctx);
					return;
				case "clear":
					clearGoal(pi, runtime, ctx);
					return;
				case "edit":
					await editGoal(pi, runtime, result.objective ?? "", result.tokenBudget, ctx);
					return;
				case "start":
					await startGoal(pi, runtime, result.objective ?? "", result.tokenBudget, ctx);
					return;
			}
		},
	});

	pi.on("session_start", (_event, ctx) => {
		clearCompletionStatusTimer(runtime);
		clearContinuationTracking(runtime);
		clearGoalRecovery(runtime);
		clearStaleGoalToolCallBlock(runtime);
		runtime.recoveryAttempts.clear();
		runtime.lastGoalSystemPromptKey = undefined;
		runtime.activeGoal = loadGoalFromSession(ctx);
		if (runtime.activeGoal) updateStatus(runtime, ctx, runtime.activeGoal);
		else ctx.ui.setStatus(STATUS_KEY, undefined);
	});

	pi.on("session_tree", (_event, ctx) => {
		// Branch navigation changes the visible custom-entry history without
		// recreating the extension. Reload goal state so an old branch cannot
		// inject its objective or schedule continuation in the new branch.
		clearContinuationTracking(runtime);
		clearGoalRecovery(runtime);
		clearStaleGoalToolCallBlock(runtime);
		runtime.lastGoalSystemPromptKey = undefined;
		runtime.activeGoal = loadGoalFromSession(ctx);
		if (runtime.activeGoal) updateStatus(runtime, ctx, runtime.activeGoal);
		else ctx.ui.setStatus(STATUS_KEY, undefined);
	});

	pi.on("session_shutdown", (_event, ctx) => {
		if (runtime.activeGoal) persistGoal(pi, runtime.activeGoal);
		clearContinuationTracking(runtime);
		clearGoalRecovery(runtime);
		clearStaleGoalToolCallBlock(runtime);
		ctx.ui.setStatus(STATUS_KEY, undefined);
		clearCompletionStatusTimer(runtime);
	});

	pi.on("session_before_compact", (_event, ctx) => {
		if (!runtime.activeGoal || runtime.activeGoal.status !== "active") return;
		updateGoalUsage(runtime.activeGoal, ctx);
		cancelContinuationPending(runtime);
		persistGoal(pi, runtime.activeGoal);
		updateStatus(runtime, ctx, runtime.activeGoal);
	});

	pi.on("session_compact", async (_event, ctx) => {
		if (!runtime.activeGoal || runtime.activeGoal.status !== "active") {
			clearGoalRecovery(runtime);
			return;
		}
		const restoredGoal = loadGoalFromSession(ctx);
		if (restoredGoal?.id === runtime.activeGoal.id) runtime.activeGoal = restoredGoal;
		// Compaction can remove the original goal prompt from the transcript; the
		// next turn must receive the full objective/rules once to restore context.
		runtime.lastGoalSystemPromptKey = undefined;
		updateGoalUsage(runtime.activeGoal, ctx);
		persistGoal(pi, runtime.activeGoal);
		updateStatus(runtime, ctx, runtime.activeGoal);
		clearGoalRecoveryForGoal(runtime, runtime.activeGoal.id);
		if (ctx.hasPendingMessages()) return;
		await sendContinuationPrompt(pi, runtime, ctx, runtime.activeGoal);
	});

	pi.on("input", (event: InputEvent) => {
		if (event.source === "extension") {
			if (consumeCancelledContinuationPrompt(runtime, event.text)) return { action: "handled" as const };
			return;
		}
		clearGoalRecovery(runtime);
		clearStaleGoalToolCallBlock(runtime);
	});

	pi.on("tool_call", (): ToolCallEventResult | undefined => {
		if (!runtime.staleGoalToolCallsBlocked) return undefined;
		return {
			block: true,
			reason: "Blocked stale /goal tool call after the goal was paused, cleared, or interrupted.",
		};
	});

	pi.on("before_agent_start", (event, ctx) => {
		markContinuationDelivered(runtime, event.prompt);
		if (!runtime.activeGoal || runtime.activeGoal.status !== "active") return undefined;
		updateGoalUsage(runtime.activeGoal, ctx);
		updateStatus(runtime, ctx, runtime.activeGoal);
		const goalSystemPromptKey = `${runtime.activeGoal.id}\0${runtime.activeGoal.text}`;
		if (runtime.lastGoalSystemPromptKey === goalSystemPromptKey) return undefined;
		runtime.lastGoalSystemPromptKey = goalSystemPromptKey;
		return {
			systemPrompt: `${event.systemPrompt}\n\n${buildGoalSystemPrompt(runtime.activeGoal)}`,
		};
	});

	pi.on("agent_end", async (event, ctx) => {
		if (!runtime.activeGoal || runtime.activeGoal.status !== "active") return;

		const goalId = runtime.activeGoal.id;
		const finalAssistant = findFinalAssistantMessage(event.messages);
		runtime.activeGoal = incrementGoal(runtime.activeGoal);
		updateGoalUsage(runtime.activeGoal, ctx);

		if (finalAssistant?.stopReason === "aborted" || finalAssistant?.stopReason === "error") {
			if (isRetryableGoalInterruption(finalAssistant)) {
				const recoveryKind: GoalRecoveryKind = isGoalContextOverflow(finalAssistant)
					? "compaction_retry"
					: "provider_retry";
				runtime.goalRecovery = { goalId, kind: recoveryKind };
				cancelContinuationPending(runtime);
				persistGoal(pi, runtime.activeGoal);
				updateStatus(runtime, ctx, runtime.activeGoal);

				if (recoveryKind === "compaction_retry") {
					ctx.ui.notify("Goal hit context overflow; compacting then continuing.", "warning");
					ctx.compact({
						customInstructions:
							"Preserve the active REPI /goal ID and objective, status counts, decisive evidence, artifact paths, changed files, and one exact next command. Omit memory/retrieval/dispatcher/queue dumps and repeated system/capability packets. Resume goal mode after compaction.",
						onError: (error) => {
							ctx.ui.notify(
								`Goal compaction failed: ${formatError(error)}. Run /goal resume after fixing it.`,
								"error",
							);
						},
					});
					return;
				}

				const attempts = (runtime.recoveryAttempts.get(goalId) ?? 0) + 1;
				runtime.recoveryAttempts.set(goalId, attempts);
				if (attempts <= PROVIDER_RETRY_BUDGET && !ctx.hasPendingMessages()) {
					ctx.ui.notify(`Goal provider interruption; retrying (${attempts}/${PROVIDER_RETRY_BUDGET}).`, "warning");
					await sendContinuationPrompt(pi, runtime, ctx, runtime.activeGoal);
					return;
				}
			}

			clearGoalRecoveryForGoal(runtime, goalId);
			pauseGoalAfterAgentEnd(pi, runtime, ctx, runtime.activeGoal, finalAssistant);
			return;
		}

		clearGoalRecoveryForGoal(runtime, goalId);
		runtime.recoveryAttempts.delete(goalId);

		if (
			runtime.activeGoal.tokenBudget !== undefined &&
			runtime.activeGoal.tokensUsed >= runtime.activeGoal.tokenBudget
		) {
			cancelContinuationPending(runtime);
			runtime.activeGoal = transitionGoal(runtime.activeGoal, "budget_limited");
			persistGoal(pi, runtime.activeGoal);
			updateStatus(runtime, ctx, runtime.activeGoal);
			ctx.ui.notify(`Goal token budget reached: ${formatBudget(runtime.activeGoal)}`, "warning");
			return;
		}

		persistGoal(pi, runtime.activeGoal);
		updateStatus(runtime, ctx, runtime.activeGoal);

		const currentGoal = runtime.activeGoal;
		if (!currentGoal || currentGoal.id !== goalId || currentGoal.status !== "active") return;
		if (ctx.hasPendingMessages()) return;
		await sendContinuationPrompt(pi, runtime, ctx, currentGoal);
	});
}

async function startGoal(
	pi: ExtensionAPI,
	runtime: RepiGoalRuntime,
	objective: string,
	tokenBudget: number | undefined,
	ctx: RepiGoalContext,
): Promise<void> {
	const trimmedObjective = objective.trim();
	const validationError = validateObjective(trimmedObjective);
	if (validationError) {
		ctx.ui.notify(validationError, "warning");
		return;
	}

	const existingGoal = runtime.activeGoal?.status !== "complete" ? runtime.activeGoal : undefined;
	if (existingGoal) {
		const shouldReplace = await shouldReplaceExistingGoal(ctx, existingGoal, trimmedObjective);
		if (!shouldReplace) {
			ctx.ui.notify(`Goal kept: ${existingGoal.text}`, "info");
			return;
		}
	}

	cancelContinuationPending(runtime);
	clearGoalRecovery(runtime);
	clearStaleGoalToolCallBlock(runtime);
	runtime.activeGoal = createGoal(trimmedObjective, tokenBudget, currentTokenTotal(ctx));
	persistGoal(pi, runtime.activeGoal);
	updateStatus(runtime, ctx, runtime.activeGoal);
	ctx.ui.notify(existingGoal ? `Goal replaced: ${trimmedObjective}` : `Goal started: ${trimmedObjective}`, "info");
	await sendGoalPrompt(pi, runtime, ctx, runtime.activeGoal);
}

async function shouldReplaceExistingGoal(
	ctx: RepiGoalContext,
	existingGoal: RepiGoalState,
	newObjective: string,
): Promise<boolean> {
	if (!ctx.hasUI || ctx.mode !== "tui") return true;
	return ctx.ui.confirm("Replace REPI goal?", `Current goal: ${existingGoal.text}\n\nNew goal: ${newObjective}`, {
		timeout: 30_000,
	});
}

function pauseGoal(pi: ExtensionAPI, runtime: RepiGoalRuntime, ctx: RepiGoalContext): void {
	if (!runtime.activeGoal) {
		ctx.ui.notify("No active goal.", "info");
		return;
	}
	if (runtime.activeGoal.status !== "active") {
		ctx.ui.notify(`Goal is ${runtime.activeGoal.status}; only active goals can be paused.`, "warning");
		return;
	}
	cancelContinuationPending(runtime);
	blockStaleGoalToolCalls(runtime);
	abortCurrentTurn(ctx);
	runtime.activeGoal = transitionGoal(runtime.activeGoal, "paused");
	persistGoal(pi, runtime.activeGoal);
	updateStatus(runtime, ctx, runtime.activeGoal);
	ctx.ui.notify(`Goal paused: ${runtime.activeGoal.text}`, "info");
}

async function resumeGoal(pi: ExtensionAPI, runtime: RepiGoalRuntime, ctx: RepiGoalContext): Promise<void> {
	if (!runtime.activeGoal) {
		ctx.ui.notify("No active goal.", "info");
		return;
	}
	if (runtime.activeGoal.status !== "paused" && runtime.activeGoal.status !== "budget_limited") {
		ctx.ui.notify(
			`Goal is ${runtime.activeGoal.status}; only paused or budget-limited goals can be resumed.`,
			"warning",
		);
		return;
	}
	clearGoalRecovery(runtime);
	clearStaleGoalToolCallBlock(runtime);
	runtime.activeGoal = transitionGoal(runtime.activeGoal, "active");
	persistGoal(pi, runtime.activeGoal);
	updateStatus(runtime, ctx, runtime.activeGoal);
	if (runtime.activeGoal.status !== "active") {
		ctx.ui.notify(`Goal token budget is still reached: ${formatBudget(runtime.activeGoal)}`, "warning");
		return;
	}
	ctx.ui.notify(`Goal resumed: ${runtime.activeGoal.text}`, "info");
	await sendResumePrompt(pi, runtime, ctx, runtime.activeGoal);
}

function clearGoal(pi: ExtensionAPI, runtime: RepiGoalRuntime, ctx: RepiGoalContext): void {
	if (!runtime.activeGoal) {
		ctx.ui.notify("No active goal.", "info");
		cancelContinuationPending(runtime);
		clearGoalRecovery(runtime);
		persistClearedGoal(pi);
		ctx.ui.setStatus(STATUS_KEY, undefined);
		return;
	}

	const stoppedGoal = runtime.activeGoal.text;
	clearActiveGoal(pi, runtime, ctx);
	ctx.ui.notify(`Goal cleared: ${stoppedGoal}`, "warning");
}

async function editGoal(
	pi: ExtensionAPI,
	runtime: RepiGoalRuntime,
	objective: string,
	tokenBudget: number | undefined,
	ctx: RepiGoalContext,
): Promise<void> {
	const trimmedObjective = objective.trim();
	const validationError = validateObjective(trimmedObjective);
	if (validationError) {
		ctx.ui.notify(validationError, "warning");
		return;
	}
	if (!runtime.activeGoal) {
		ctx.ui.notify("No active goal. Use /goal <objective> to start one.", "warning");
		return;
	}

	updateGoalUsage(runtime.activeGoal, ctx);
	cancelContinuationPending(runtime);
	clearGoalRecovery(runtime);
	runtime.activeGoal = normalizeGoalForBudget({
		...runtime.activeGoal,
		text: trimmedObjective,
		status: editedGoalStatus(runtime.activeGoal.status),
		tokenBudget: tokenBudget ?? runtime.activeGoal.tokenBudget,
		updatedAt: Date.now(),
	});
	persistGoal(pi, runtime.activeGoal);
	updateStatus(runtime, ctx, runtime.activeGoal);
	ctx.ui.notify(`Goal updated: ${trimmedObjective}`, "info");
	if (runtime.activeGoal.status === "active") {
		clearStaleGoalToolCallBlock(runtime);
		await sendObjectiveUpdatedPrompt(pi, runtime, ctx, runtime.activeGoal);
	}
}

function showGoal(pi: ExtensionAPI, runtime: RepiGoalRuntime, ctx: RepiGoalContext): void {
	if (!runtime.activeGoal) {
		ctx.ui.notify(emptyGoalSummary(), "info");
		ctx.ui.setStatus(STATUS_KEY, undefined);
		return;
	}
	updateGoalUsage(runtime.activeGoal, ctx);
	persistGoal(pi, runtime.activeGoal);
	updateStatus(runtime, ctx, runtime.activeGoal);
	ctx.ui.notify(goalSummary(runtime.activeGoal), "info");
}

function showGoalHelp(pi: ExtensionAPI, runtime: RepiGoalRuntime, ctx: RepiGoalContext): void {
	if (runtime.activeGoal) {
		updateGoalUsage(runtime.activeGoal, ctx);
		persistGoal(pi, runtime.activeGoal);
		updateStatus(runtime, ctx, runtime.activeGoal);
	} else {
		ctx.ui.setStatus(STATUS_KEY, undefined);
	}
	const active = runtime.activeGoal ? `\n\nCurrent:\n${goalSummary(runtime.activeGoal)}` : "";
	ctx.ui.notify(
		[
			"REPI /goal runs a task until verified completion.",
			"",
			"Usage:",
			"  /goal [--tokens 100k] <objective>",
			"  /goal status",
			"  /goal pause | resume | clear",
			"  /goal edit [--tokens 100k] <objective>",
			"",
			"Completion:",
			"  The footer shows 🎯 active/paused/budget/complete.",
			"  The agent must call goal_complete only after requirement-by-requirement verification.",
			"",
			"Status panel:",
			"  /goal status shows footer preview, elapsed/token budget, progress bar, and the safest next command.",
			"",
			"Examples:",
			"  /goal --tokens 100k finish the release checklist",
			"  /goal status",
			"  /goal clear",
			"",
			"Non-TUI/RPC:",
			"  print/json/rpc modes emit notifications/status events and queue continuation as follow-up; no blocking confirm.",
		].join("\n") + active,
		"info",
	);
}

function pauseGoalAfterAgentEnd(
	pi: ExtensionAPI,
	runtime: RepiGoalRuntime,
	ctx: RepiGoalContext,
	goal: RepiGoalState,
	assistant: AssistantMessageLike | undefined,
): void {
	cancelContinuationPending(runtime);
	blockStaleGoalToolCalls(runtime);
	abortCurrentTurn(ctx);
	runtime.activeGoal = transitionGoal(goal, "paused");
	persistGoal(pi, runtime.activeGoal);
	updateStatus(runtime, ctx, runtime.activeGoal);

	const reason = assistant?.stopReason === "aborted" ? "interruption" : "agent error";
	const details = assistant?.errorMessage ? ` (${truncateNotification(assistant.errorMessage)})` : "";
	ctx.ui.notify(`Goal paused after ${reason}${details}. Run /goal resume to continue.`, "warning");
}

function createGoal(text: string, tokenBudget: number | undefined, baselineTokens: number): RepiGoalState {
	const now = Date.now();
	return {
		id: randomUUID(),
		text,
		status: "active",
		startedAt: now,
		updatedAt: now,
		iteration: 0,
		tokenBudget,
		tokensUsed: 0,
		timeUsedSeconds: 0,
		baselineTokens,
	};
}

function transitionGoal(goal: RepiGoalState, status: RepiGoalStatus): RepiGoalState {
	return normalizeGoalForBudget({ ...goal, status, updatedAt: Date.now() });
}

function normalizeGoalForBudget(goal: RepiGoalState): RepiGoalState {
	if (goal.status === "active" && goal.tokenBudget !== undefined && goal.tokensUsed >= goal.tokenBudget) {
		return { ...goal, status: "budget_limited" };
	}
	return goal;
}

function incrementGoal(goal: RepiGoalState): RepiGoalState {
	return { ...goal, iteration: goal.iteration + 1, updatedAt: Date.now() };
}

function editedGoalStatus(status: RepiGoalStatus): RepiGoalStatus {
	return status === "paused" ? "paused" : "active";
}

function updateGoalUsage(goal: RepiGoalState, ctx: RepiGoalContext): void {
	goal.tokensUsed = Math.max(0, currentTokenTotal(ctx) - goal.baselineTokens);
	goal.timeUsedSeconds = Math.max(0, Math.floor((Date.now() - goal.startedAt) / 1000));
	goal.updatedAt = Date.now();
}

async function sendGoalPrompt(
	pi: ExtensionAPI,
	runtime: RepiGoalRuntime,
	ctx: RepiGoalContext,
	goal: RepiGoalState,
): Promise<boolean> {
	return sendPrompt(pi, runtime, ctx, buildGoalPrompt(goal));
}

async function sendObjectiveUpdatedPrompt(
	pi: ExtensionAPI,
	runtime: RepiGoalRuntime,
	ctx: RepiGoalContext,
	goal: RepiGoalState,
): Promise<boolean> {
	return sendPrompt(pi, runtime, ctx, buildObjectiveUpdatedPrompt(goal));
}

async function sendResumePrompt(
	pi: ExtensionAPI,
	runtime: RepiGoalRuntime,
	ctx: RepiGoalContext,
	goal: RepiGoalState,
): Promise<boolean> {
	return sendPrompt(pi, runtime, ctx, buildResumePrompt(goal));
}

async function sendContinuationPrompt(
	pi: ExtensionAPI,
	runtime: RepiGoalRuntime,
	ctx: RepiGoalContext,
	goal: RepiGoalState,
): Promise<boolean> {
	if (runtime.continuationPending?.goalId === goal.id) return false;
	if (ctx.hasPendingMessages()) return false;

	const marker = continuationMarker(goal);
	const prompt = buildContinuePrompt(goal, marker);
	runtime.continuationPending = { goalId: goal.id, iteration: goal.iteration, marker, prompt };
	const sent = await sendPrompt(pi, runtime, ctx, prompt);
	if (!sent && runtime.continuationPending?.marker === marker) runtime.continuationPending = undefined;
	return sent;
}

async function sendPrompt(
	pi: ExtensionAPI,
	_runtime: RepiGoalRuntime,
	ctx: RepiGoalContext,
	prompt: string,
): Promise<boolean> {
	try {
		const sent = ctx.isIdle()
			? (pi.sendUserMessage(prompt) as void | Promise<void>)
			: (pi.sendUserMessage(prompt, { deliverAs: "followUp" }) as void | Promise<void>);
		await sent;
		return true;
	} catch (error) {
		ctx.ui.notify(`Goal prompt failed: ${formatError(error)}`, "error");
		return false;
	}
}

function persistGoal(pi: ExtensionAPI, goal: RepiGoalState): void {
	pi.appendEntry<RepiGoalEntryData>(REPI_GOAL_STATE_ENTRY_TYPE, { version: 1, goal });
}

function persistClearedGoal(pi: ExtensionAPI): void {
	pi.appendEntry<RepiGoalEntryData>(REPI_GOAL_STATE_ENTRY_TYPE, { version: 1, goal: null });
}

function loadGoalFromSession(ctx: RepiGoalContext): RepiGoalState | undefined {
	const branch = ctx.sessionManager.getBranch?.() ?? ctx.sessionManager.getEntries?.() ?? [];
	for (let index = branch.length - 1; index >= 0; index--) {
		const entry = branch[index] as { type?: string; customType?: string; data?: unknown };
		if (entry.type !== "custom") continue;
		if (entry.customType !== REPI_GOAL_STATE_ENTRY_TYPE && entry.customType !== LEGACY_PI_GOAL_STATE_ENTRY_TYPE)
			continue;
		const data = entry.data as RepiGoalEntryData | undefined;
		if (data?.goal === null) return undefined;
		if (isGoalState(data?.goal) && data.goal.status !== "complete") return data.goal;
	}
	return undefined;
}

function clearActiveGoal(
	pi: ExtensionAPI,
	runtime: RepiGoalRuntime,
	ctx: RepiGoalContext,
	options?: { showStatus?: boolean },
): void {
	cancelContinuationPending(runtime);
	clearGoalRecovery(runtime);
	runtime.activeGoal = undefined;
	persistClearedGoal(pi);
	if (options?.showStatus ?? true) ctx.ui.setStatus(STATUS_KEY, undefined);
}

function updateStatus(runtime: RepiGoalRuntime, ctx: RepiGoalContext, goal: RepiGoalState): void {
	clearCompletionStatusTimer(runtime);
	ctx.ui.setStatus(STATUS_KEY, formatGoalFooterStatus(goal));
}

function showCompletionStatus(runtime: RepiGoalRuntime, ctx: RepiGoalContext): void {
	clearCompletionStatusTimer(runtime);
	ctx.ui.setStatus(STATUS_KEY, "🎯 complete");
	const timer = setTimeout(() => {
		runtime.completionStatusTimer = undefined;
		try {
			ctx.ui.setStatus(STATUS_KEY, undefined);
		} catch {
			// Stale UI contexts after reload/session switch are harmless.
		}
	}, 8_000);
	if (typeof timer === "object" && "unref" in timer && typeof timer.unref === "function") timer.unref();
	runtime.completionStatusTimer = timer;
}

function clearCompletionStatusTimer(runtime: RepiGoalRuntime): void {
	if (!runtime.completionStatusTimer) return;
	clearTimeout(runtime.completionStatusTimer);
	runtime.completionStatusTimer = undefined;
}

export function formatGoalFooterStatus(goal: RepiGoalState | undefined): string | undefined {
	const status = formatGoalStatus(goal);
	return status ? `🎯 ${status}` : undefined;
}

export function formatGoalStatus(goal: RepiGoalState | undefined): string | undefined {
	if (!goal) return undefined;
	if (goal.status === "complete") return "complete";
	if (goal.status === "paused") return "paused";
	if (goal.status === "budget_limited") return `budget ${formatBudget(goal)}`;
	if (goal.tokenBudget !== undefined) return `active ${formatBudget(goal)}`;
	return `active ${formatDuration(goal.timeUsedSeconds)}`;
}

function formatBudget(goal: RepiGoalState): string {
	return `${formatTokenCount(goal.tokensUsed)}/${formatTokenCount(goal.tokenBudget ?? 0)}`;
}

function formatGoalProgressBar(percent: number): string {
	const bounded = Math.max(0, Math.min(100, Math.floor(percent)));
	const filled = Math.max(0, Math.min(10, Math.floor(bounded / 10)));
	return `[${"█".repeat(filled)}${"░".repeat(10 - filled)}]`;
}

function goalProgressLine(goal: RepiGoalState): string {
	if (goal.tokenBudget === undefined) {
		return `Progress: elapsed=${formatDuration(goal.timeUsedSeconds)} tokens=${formatTokenCount(goal.tokensUsed)}`;
	}
	const percent = goal.tokenBudget <= 0 ? 100 : Math.min(100, Math.floor((goal.tokensUsed / goal.tokenBudget) * 100));
	const remaining = Math.max(0, goal.tokenBudget - goal.tokensUsed);
	return `Budget: ${formatGoalProgressBar(percent)} ${percent}% used (${formatTokenCount(remaining)} remaining)`;
}

function goalSummary(goal: RepiGoalState): string {
	const footer = formatGoalFooterStatus(goal) ?? "🎯 <clear>";
	return [
		"🎯 REPI Goal Status",
		`Goal: ${goal.text}`,
		`Status: ${goal.status}`,
		`Footer: ${footer}`,
		`Iteration: ${goal.iteration}`,
		`Elapsed: ${formatDuration(goal.timeUsedSeconds)}`,
		`Tokens: ${goal.tokenBudget === undefined ? formatTokenCount(goal.tokensUsed) : formatBudget(goal)}`,
		goalProgressLine(goal),
		"Completion gate: goal_complete only after verified completion",
		`Next: ${goalCommandHint(goal.status)}`,
	].join("\n");
}

function emptyGoalSummary(): string {
	return [
		"🎯 REPI Goal Status",
		"Status: clear",
		"Footer: 🎯 <clear>",
		"No goal is currently set.",
		"Usage: /goal <objective>",
		"Next: /goal [--tokens 100k] <objective>",
	].join("\n");
}

function goalCommandHint(status: RepiGoalStatus): string {
	if (status === "active") return "/goal edit <objective>, /goal pause, /goal clear";
	if (status === "paused") return "/goal edit <objective>, /goal resume, /goal clear";
	return "/goal edit <objective>, /goal clear";
}

export function formatDuration(seconds: number): string {
	if (seconds < 60) return `${seconds}s`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m`;
	const hours = Math.floor(minutes / 60);
	return `${hours}h${minutes % 60}m`;
}

export function formatTokenCount(value: number): string {
	if (value < 1_000) return `${value}`;
	if (value < 1_000_000) return `${Number.isInteger(value / 1_000) ? value / 1_000 : (value / 1_000).toFixed(1)}k`;
	return `${Number.isInteger(value / 1_000_000) ? value / 1_000_000 : (value / 1_000_000).toFixed(1)}m`;
}

function buildGoalPrompt(goal: RepiGoalState): string {
	const budgetLine = goal.tokenBudget === undefined ? "" : `\nToken budget: ${formatTokenCount(goal.tokenBudget)}.`;
	return `Start the active REPI goal.\n${goalObjectiveBlock(goal)}${budgetLine}\nWork until verified completion; call goal_complete only after every requirement is checked.`;
}

function buildObjectiveUpdatedPrompt(goal: RepiGoalState): string {
	const budgetLine = goal.tokenBudget === undefined ? "" : `\nToken budget: ${formatBudget(goal)} used.`;
	return `The active REPI goal changed. Continue from the current verified state.\n${goalObjectiveBlock(goal)}${budgetLine}`;
}

function buildResumePrompt(goal: RepiGoalState): string {
	const budgetLine = goal.tokenBudget === undefined ? "" : `\nToken budget: ${formatBudget(goal)} used.`;
	return `The user resumed the active REPI goal. Continue from the current verified state.\n${goalObjectiveBlock(goal)}${budgetLine}`;
}

export function buildGoalSystemPrompt(goal: RepiGoalState): string {
	const budgetLine =
		goal.tokenBudget === undefined ? "" : `\n- Respect the goal token budget (${formatBudget(goal)} used).`;
	return `Active REPI goal:\n${goalObjectiveBlock(goal)}\nRules: keep working until every requirement is verified; treat live files, commands, tests, runtime, and network state as authoritative; call goal_complete only after the final checks.${budgetLine}`;
}

function buildContinuePrompt(goal: RepiGoalState, marker: string): string {
	return `Continue the active REPI goal from the current verified state (automatic continuation #${goal.iteration}). ${continuationMarkerComment(marker)}`;
}

function goalObjectiveBlock(goal: RepiGoalState): string {
	return `<goal_objective>\n${escapeXmlText(goal.text)}\n</goal_objective>`;
}

function currentTokenTotal(ctx: RepiGoalContext): number {
	const branch = ctx.sessionManager.getBranch?.() ?? ctx.sessionManager.getEntries?.() ?? [];
	let total = 0;
	for (const entry of branch) {
		if (entry.type !== "message" || entry.message.role !== "assistant") continue;
		const usage = entry.message.usage as { input?: number; output?: number } | undefined;
		total += usage?.input ?? 0;
		total += usage?.output ?? 0;
	}
	return total;
}

export function completeGoalArguments(argumentPrefix: string): AutocompleteItem[] | null {
	const prefix = argumentPrefix.trimStart();
	if (prefix === "") return [...GOAL_ARGUMENT_COMPLETIONS];

	const editOptionPrefix = /^edit\s+(\S*)$/.exec(prefix)?.[1];
	if (editOptionPrefix !== undefined) {
		return editOptionPrefix === "" || "--tokens".startsWith(editOptionPrefix) ? [EDIT_TOKEN_COMPLETION] : null;
	}

	if (/\s/.test(prefix)) return null;

	const matches = GOAL_ARGUMENT_COMPLETIONS.filter(
		(item) => item.value.startsWith(prefix) || item.label.startsWith(prefix),
	);
	return matches.length > 0 ? [...matches] : null;
}

export function parseGoalCommand(args: string): RepiGoalCommandResult | string {
	const tokens = tokenize(args.trim());
	if (tokens.length === 0) return { kind: "show" };

	const [first, ...rest] = tokens;
	if (first === "pause") return rest.length === 0 ? { kind: "pause" } : "Usage: /goal pause";
	if (first === "resume") return rest.length === 0 ? { kind: "resume" } : "Usage: /goal resume";
	if (first === "clear" || first === "stop") return rest.length === 0 ? { kind: "clear" } : "Usage: /goal clear";
	if (first === "status") return rest.length === 0 ? { kind: "show" } : "Usage: /goal status";
	if (first === "help") return rest.length === 0 ? { kind: "help" } : "Usage: /goal help";
	if (first === "edit") return parseObjective("edit", rest);
	return parseObjective("start", tokens);
}

function parseObjective(kind: "start" | "edit", tokens: string[]): RepiGoalCommandResult | string {
	let tokenBudget: number | undefined;
	const objectiveTokens = [...tokens];

	if (objectiveTokens[0] === "--tokens") {
		const rawBudget = objectiveTokens[1];
		if (!rawBudget) return "Usage: /goal --tokens 100k <goal_to_complete>";
		const parsedBudget = parseTokenBudget(rawBudget);
		if (parsedBudget === undefined) return `Invalid token budget: ${rawBudget}`;
		tokenBudget = parsedBudget;
		objectiveTokens.splice(0, 2);
	}

	if (objectiveTokens.length === 0) {
		return kind === "edit" ? "Usage: /goal edit <goal_to_complete>" : "Usage: /goal <goal_to_complete>";
	}

	return { kind, objective: objectiveTokens.join(" "), tokenBudget };
}

function tokenize(input: string): string[] {
	const tokens: string[] = [];
	let current = "";
	let quote: '"' | "'" | undefined;

	for (const char of input) {
		if (quote) {
			if (char === quote) quote = undefined;
			else current += char;
			continue;
		}
		if (char === '"' || char === "'") {
			quote = char;
			continue;
		}
		if (/\s/.test(char)) {
			if (current) tokens.push(current);
			current = "";
			continue;
		}
		current += char;
	}
	if (current) tokens.push(current);
	return tokens;
}

export function parseTokenBudget(value: string): number | undefined {
	const match = /^(\d+(?:\.\d+)?)([km])?$/iu.exec(value.trim());
	if (!match) return undefined;
	const amount = Number(match[1]);
	if (!Number.isFinite(amount) || amount <= 0) return undefined;
	const multiplier = match[2]?.toLowerCase() === "m" ? 1_000_000 : match[2]?.toLowerCase() === "k" ? 1_000 : 1;
	return Math.floor(amount * multiplier);
}

export function validateObjective(objective: string): string | undefined {
	const trimmed = objective.trim();
	if (!trimmed) return "Usage: /goal <goal_to_complete>";
	if (trimmed.length > MAX_OBJECTIVE_LENGTH) {
		return `Goal objective is too long (${trimmed.length}/${MAX_OBJECTIVE_LENGTH} characters). Put long instructions in a file and reference it from /goal instead.`;
	}
	return undefined;
}

export function isContradictoryCompletionSummary(summary: string): boolean {
	return CONTRADICTORY_COMPLETION_PATTERNS.some((pattern) => pattern.test(summary));
}

export function isRetryableGoalInterruption(assistant: AssistantMessageLike): boolean {
	if (assistant.stopReason !== "error") return false;
	if (!assistant.errorMessage) return false;
	if (NON_RETRYABLE_GOAL_ERROR_RE.test(assistant.errorMessage)) return false;
	return isGoalContextOverflow(assistant) || RETRYABLE_GOAL_ERROR_RE.test(assistant.errorMessage);
}

function isGoalContextOverflow(assistant: AssistantMessageLike): boolean {
	return Boolean(assistant.errorMessage && CONTEXT_OVERFLOW_RE.test(assistant.errorMessage));
}

export function findFinalAssistantMessage(messages: AgentMessage[] | unknown[]): AssistantMessageLike | undefined {
	for (let index = messages.length - 1; index >= 0; index--) {
		const message = messages[index];
		if (!message || typeof message !== "object") continue;
		const candidate = message as Record<string, unknown>;
		if (candidate.role !== "assistant") continue;
		return {
			role: "assistant",
			stopReason: isAgentStopReason(candidate.stopReason) ? candidate.stopReason : undefined,
			errorMessage: typeof candidate.errorMessage === "string" ? candidate.errorMessage : undefined,
			usage: candidate.usage,
		};
	}
	return undefined;
}

function isAgentStopReason(value: unknown): value is AgentStopReason {
	return ["stop", "length", "toolUse", "error", "aborted"].includes(String(value));
}

function clearContinuationTracking(runtime: RepiGoalRuntime): void {
	runtime.continuationPending = undefined;
	runtime.cancelledContinuationMarkers.clear();
}

function cancelContinuationPending(runtime: RepiGoalRuntime): void {
	if (runtime.continuationPending) rememberCancelledContinuationMarker(runtime, runtime.continuationPending.marker);
	runtime.continuationPending = undefined;
}

function rememberCancelledContinuationMarker(runtime: RepiGoalRuntime, marker: string): void {
	runtime.cancelledContinuationMarkers.add(marker);
	if (runtime.cancelledContinuationMarkers.size <= MAX_CANCELLED_CONTINUATION_PROMPTS) return;
	const oldest = runtime.cancelledContinuationMarkers.values().next().value;
	if (oldest) runtime.cancelledContinuationMarkers.delete(oldest);
}

function consumeCancelledContinuationPrompt(runtime: RepiGoalRuntime, prompt: string): boolean {
	const marker = extractContinuationMarker(prompt);
	return marker ? runtime.cancelledContinuationMarkers.delete(marker) : false;
}

function markContinuationDelivered(runtime: RepiGoalRuntime, prompt: string): void {
	const marker = extractContinuationMarker(prompt);
	if (marker && runtime.continuationPending?.marker === marker) runtime.continuationPending = undefined;
}

function continuationMarker(goal: RepiGoalState): string {
	return `${goal.id}:${goal.iteration}:${randomUUID()}`;
}

function continuationMarkerComment(marker: string): string {
	return `<!-- ${CONTINUATION_MARKER_PREFIX}${marker} -->`;
}

function extractContinuationMarker(prompt: string): string | undefined {
	const pattern = new RegExp(`<!--\\s*${escapeRegExpText(CONTINUATION_MARKER_PREFIX)}([^\\s>]+)\\s*-->`);
	return pattern.exec(prompt)?.[1];
}

function blockStaleGoalToolCalls(runtime: RepiGoalRuntime): void {
	runtime.staleGoalToolCallsBlocked = true;
}

function clearStaleGoalToolCallBlock(runtime: RepiGoalRuntime): void {
	runtime.staleGoalToolCallsBlocked = false;
}

function clearGoalRecovery(runtime: RepiGoalRuntime): void {
	runtime.goalRecovery = undefined;
}

function clearGoalRecoveryForGoal(runtime: RepiGoalRuntime, goalId: string): void {
	if (runtime.goalRecovery?.goalId === goalId) runtime.goalRecovery = undefined;
}

function abortCurrentTurn(ctx: RepiGoalContext): void {
	try {
		ctx.abort();
	} catch {
		// Best effort: stale tool-call guard still prevents follow-on work.
	}
}

function isGoalState(value: unknown): value is RepiGoalState {
	if (!value || typeof value !== "object") return false;
	const goal = value as Partial<RepiGoalState>;
	return (
		typeof goal.id === "string" &&
		typeof goal.text === "string" &&
		["active", "paused", "budget_limited", "complete"].includes(String(goal.status)) &&
		typeof goal.startedAt === "number" &&
		typeof goal.updatedAt === "number" &&
		typeof goal.iteration === "number" &&
		typeof goal.tokensUsed === "number" &&
		typeof goal.timeUsedSeconds === "number" &&
		typeof goal.baselineTokens === "number"
	);
}

function escapeXmlText(value: string): string {
	return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function escapeRegExpText(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function formatError(error: unknown): string {
	return truncateNotification(error instanceof Error ? error.message : String(error));
}

function truncateNotification(value: string): string {
	return value.length > 160 ? `${value.slice(0, 157)}...` : value;
}

import type { Model, Models } from "@pi-recon/repi-ai";
import { completeSimple } from "@pi-recon/repi-ai";
import type { AgentMessage } from "../../types.ts";
import {
	convertToLlm,
	createBranchSummaryMessage,
	createCompactionSummaryMessage,
	createCustomMessage,
} from "../messages.ts";
import type { BranchSummaryResult, Session, SessionTreeEntry } from "../types.ts";
import { BranchSummaryError, err, ok, type Result, SessionError } from "../types.ts";
import { estimateTokens, SUMMARIZATION_SYSTEM_PROMPT } from "./compaction.ts";
import { summaryInputTokenBudget, truncateSummaryToTokenBudget } from "./policy.ts";
import {
	computeFileLists,
	createFileOps,
	extractFileOpsFromMessage,
	type FileOperations,
	formatFileOperations,
	serializeConversation,
	stripFileOperationSections,
	truncateForSummary,
} from "./utils.ts";

/** File-operation details stored on generated branch summary entries. */
export interface BranchSummaryDetails {
	/** Files read while exploring the summarized branch. */
	readFiles: string[];
	/** Files modified while exploring the summarized branch. */
	modifiedFiles: string[];
}

export type { FileOperations } from "./utils.ts";

/** Prepared branch content for summarization. */
export interface BranchPreparation {
	/** Messages selected for the branch summary. */
	messages: AgentMessage[];
	/** File operations extracted from the branch. */
	fileOps: FileOperations;
	/** Estimated token count for selected messages. */
	totalTokens: number;
}

/** Entries selected for branch summarization. */
export interface CollectEntriesResult {
	/** Entries to summarize in chronological order. */
	entries: SessionTreeEntry[];
	/** Deepest common ancestor between the previous leaf and target entry. */
	commonAncestorId: string | null;
}

/** Options for generating a branch summary. */
export interface GenerateBranchSummaryOptions {
	/** Model used for summarization. */
	model: Model<any>;
	/** API key forwarded to the provider. */
	apiKey: string;
	/** Optional request headers forwarded to the provider. */
	headers?: Record<string, string>;
	/** Abort signal for the summarization request. */
	signal: AbortSignal;
	/** Optional instructions appended to or replacing the default prompt. */
	customInstructions?: string;
	/** Replace the default prompt with custom instructions instead of appending them. */
	replaceInstructions?: boolean;
	/** Tokens reserved for prompt and model output. Defaults to 16384. */
	reserveTokens?: number;
}

/** Options for provider-owned auth and dispatch through a Models runtime. */
export interface GenerateBranchSummaryModelsOptions {
	/** Provider collection used for the summarization request. */
	models: Models;
	/** Model used for summarization. */
	model: Model<any>;
	/** Abort signal for the summarization request. */
	signal: AbortSignal;
	/** Optional instructions appended to or replacing the default prompt. */
	customInstructions?: string;
	/** Replace the default prompt with custom instructions instead of appending them. */
	replaceInstructions?: boolean;
	/** Tokens reserved for prompt and model output. Defaults to 16384. */
	reserveTokens?: number;
}

/** Collect entries that should be summarized before navigating to a different session tree entry. */
export async function collectEntriesForBranchSummary(
	session: Session,
	oldLeafId: string | null,
	targetId: string,
): Promise<CollectEntriesResult> {
	if (!oldLeafId) {
		return { entries: [], commonAncestorId: null };
	}
	const oldPath = new Set((await session.getBranch(oldLeafId)).map((e) => e.id));
	const targetPath = await session.getBranch(targetId);
	let commonAncestorId: string | null = null;
	for (let i = targetPath.length - 1; i >= 0; i--) {
		if (oldPath.has(targetPath[i].id)) {
			commonAncestorId = targetPath[i].id;
			break;
		}
	}
	const entries: SessionTreeEntry[] = [];
	let current: string | null = oldLeafId;

	// Cycle guard: oldPath was built from getBranch(oldLeafId) whose getPathToRoot
	// already cycle-guards, but this walker follows parentId upward via getEntry
	// independently — a storage whose getPathToRoot lacks the visited Set (or data
	// mutated between the getBranch call and this loop) with A.parentId=B,
	// B.parentId=A would spin forever (event-loop-blocking CPU spin → OOM).
	// Convert a cycle into a typed invalid_session error instead of a hang,
	// mirroring the getPathToRoot cycle idiom (jsonl-storage / memory-storage).
	const visited = new Set<string>();
	while (current && current !== commonAncestorId) {
		if (visited.has(current)) {
			throw new SessionError("invalid_session", `Cycle detected at entry ${current}`);
		}
		visited.add(current);
		const entry = await session.getEntry(current);
		if (!entry) throw new SessionError("invalid_session", `Entry ${current} not found`);
		entries.push(entry as SessionTreeEntry);
		current = entry.parentId;
	}
	entries.reverse();

	return { entries, commonAncestorId };
}
function getMessageFromEntry(entry: SessionTreeEntry): AgentMessage | undefined {
	switch (entry.type) {
		case "message":
			if (entry.message.role === "toolResult") return undefined;
			return entry.message;

		case "custom_message":
			return createCustomMessage(entry.customType, entry.content, entry.display, entry.details, entry.timestamp);

		case "branch_summary":
			return createBranchSummaryMessage(entry.summary, entry.fromId, entry.timestamp);

		case "compaction":
			return createCompactionSummaryMessage(entry.summary, entry.tokensBefore, entry.timestamp);
		case "thinking_level_change":
		case "model_change":
		case "active_tools_change":
		case "custom":
		case "label":
		case "session_info":
		case "leaf":
			return undefined;
	}
}

/** Prepare branch entries for summarization within an optional token budget. */
export function prepareBranchEntries(entries: SessionTreeEntry[], tokenBudget: number = 0): BranchPreparation {
	const messages: AgentMessage[] = [];
	const fileOps = createFileOps();
	let totalTokens = 0;
	for (const entry of entries) {
		if (entry.type === "branch_summary" && !entry.fromHook && entry.details) {
			const details = entry.details as BranchSummaryDetails;
			if (Array.isArray(details.readFiles)) {
				for (const f of details.readFiles) fileOps.read.add(f);
			}
			if (Array.isArray(details.modifiedFiles)) {
				for (const f of details.modifiedFiles) {
					fileOps.edited.add(f);
				}
			}
		}
	}
	for (let i = entries.length - 1; i >= 0; i--) {
		const entry = entries[i];
		const message = getMessageFromEntry(entry);
		if (!message) continue;
		extractFileOpsFromMessage(message, fileOps);

		const tokens = estimateTokens(message);
		if (tokenBudget > 0 && totalTokens + tokens > tokenBudget) {
			if (entry.type === "compaction" || entry.type === "branch_summary") {
				if (totalTokens < tokenBudget * 0.9) {
					const summaryMessage = message as Extract<AgentMessage, { role: "branchSummary" | "compactionSummary" }>;
					const summary = truncateSummaryToTokenBudget(summaryMessage.summary, tokenBudget - totalTokens);
					if (summary) {
						const boundedMessage = { ...summaryMessage, summary };
						messages.unshift(boundedMessage);
						totalTokens += estimateTokens(boundedMessage);
					}
				}
			}
			break;
		}

		messages.unshift(message);
		totalTokens += tokens;
	}

	return { messages, fileOps, totalTokens };
}

const BRANCH_SUMMARY_PREAMBLE = `The user explored a different conversation branch before returning here.
Summary of that exploration:

`;

const BRANCH_SUMMARY_PROMPT = `Create a structured summary of this conversation branch for context when returning later.

Use this EXACT format:

## Goal
[What was the user trying to accomplish in this branch?]

## Constraints & Preferences
- [Any constraints, preferences, or requirements mentioned]
- [Or "(none)" if none were mentioned]

## Progress
### Done
- [x] [Completed tasks/changes]

### In Progress
- [ ] [Work that was started but not finished]

### Blocked
- [Issues preventing progress, if any]

## Key Decisions
- **[Decision]**: [Brief rationale]

## Next Steps
1. [What should happen next to continue this work]

Keep each section concise. Preserve exact file paths, function names, and error messages.
Omit repeated system/capability packets and verbose memory/retrieval/dispatcher/queue/worker payloads. Keep only mission/goal IDs, active lane, status counts, decisive evidence, artifact paths, and one exact next command.`;

const MAX_BRANCH_SUMMARY_CHARS = 12_000;
const MAX_BRANCH_INSTRUCTIONS_CHARS = 4_000;

/** Generate a summary for abandoned branch entries through a Models runtime. */
export function generateBranchSummary(
	entries: SessionTreeEntry[],
	options: GenerateBranchSummaryModelsOptions,
): Promise<Result<BranchSummaryResult, BranchSummaryError>>;
/** @deprecated Pass `models` so provider-owned auth is used. */
export function generateBranchSummary(
	entries: SessionTreeEntry[],
	options: GenerateBranchSummaryOptions,
): Promise<Result<BranchSummaryResult, BranchSummaryError>>;
export async function generateBranchSummary(
	entries: SessionTreeEntry[],
	options: GenerateBranchSummaryModelsOptions | GenerateBranchSummaryOptions,
): Promise<Result<BranchSummaryResult, BranchSummaryError>> {
	const { model, signal, customInstructions, replaceInstructions, reserveTokens = 16384 } = options;
	const contextWindow = model.contextWindow || 128000;
	const tokenBudget = summaryInputTokenBudget(contextWindow, reserveTokens);

	const { messages, fileOps } = prepareBranchEntries(entries, tokenBudget);

	if (messages.length === 0) {
		return ok({ summary: "No content to summarize", readFiles: [], modifiedFiles: [] });
	}
	const llmMessages = convertToLlm(messages);
	const conversationText = serializeConversation(llmMessages);
	const safeCustomInstructions = customInstructions?.trim()
		? truncateForSummary(customInstructions.trim(), MAX_BRANCH_INSTRUCTIONS_CHARS)
		: undefined;
	let instructions: string;
	if (replaceInstructions && safeCustomInstructions) {
		instructions = safeCustomInstructions;
	} else if (safeCustomInstructions) {
		instructions = `${BRANCH_SUMMARY_PROMPT}\n\nAdditional focus: ${safeCustomInstructions}`;
	} else {
		instructions = BRANCH_SUMMARY_PROMPT;
	}
	const promptText = `<conversation>\n${conversationText}\n</conversation>\n\n${instructions}`;

	const summarizationMessages = [
		{
			role: "user" as const,
			content: [{ type: "text" as const, text: promptText }],
			timestamp: Date.now(),
		},
	];
	const context = { systemPrompt: SUMMARIZATION_SYSTEM_PROMPT, messages: summarizationMessages };
	const response =
		"models" in options
			? await options.models.completeSimple(model, context, { signal, maxTokens: 2048 })
			: await completeSimple(model, context, {
					apiKey: options.apiKey,
					headers: options.headers,
					signal,
					maxTokens: 2048,
				});
	if (response.stopReason === "aborted") {
		return err(new BranchSummaryError("aborted", response.errorMessage || "Branch summary aborted"));
	}
	if (response.stopReason === "error") {
		return err(
			new BranchSummaryError(
				"summarization_failed",
				`Branch summary failed: ${response.errorMessage || "Unknown error"}`,
			),
		);
	}
	if (response.stopReason !== "stop") {
		return err(
			new BranchSummaryError(
				"summarization_failed",
				`Branch summary failed: incomplete model response (${response.stopReason})`,
			),
		);
	}

	const summaryText = response.content
		.filter((c): c is { type: "text"; text: string } => c.type === "text")
		.map((c) => c.text)
		.join("\n")
		.trim();
	if (!summaryText) {
		return err(new BranchSummaryError("summarization_failed", "Branch summary failed: model returned no text"));
	}
	let summary = truncateForSummary(
		stripFileOperationSections(BRANCH_SUMMARY_PREAMBLE + summaryText),
		MAX_BRANCH_SUMMARY_CHARS,
	);
	const { readFiles, modifiedFiles } = computeFileLists(fileOps);
	summary += formatFileOperations(readFiles, modifiedFiles);

	return ok({
		summary: summary || "No summary generated",
		readFiles,
		modifiedFiles,
	});
}

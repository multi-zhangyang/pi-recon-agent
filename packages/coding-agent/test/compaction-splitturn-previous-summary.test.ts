/**
 * opt #236 — compact() split-turn branch carries previousSummary forward when
 * there is nothing new to summarize (messagesToSummarize empty).
 *
 * Pre-fix the history-summary slot was
 *   `messagesToSummarize.length > 0 ? generateSummary(..., previousSummary, ...)
 *    : Promise.resolve("No prior history.")`
 * so when messagesToSummarize was empty, previousSummary was REPLACED with the
 * literal "No prior history." and never passed to generateSummary. This is
 * reachable in the orphaned-branch fallback (prepareCompaction sets
 * boundaryStart = prevCompactionIndex + 1 when the prev compaction's
 * firstKeptEntryId is off the current path): the cut can land so
 * messagesToSummarize is empty while isSplitTurn is true, turnPrefixMessages
 * is non-empty, AND previousSummary is the ONLY record of the pre-compaction
 * history. buildSessionContext emits only the latest compaction's summary, so
 * the prior history summary was permanently + silently lost from the context.
 *
 * Fix: `Promise.resolve(previousSummary ?? "No prior history.")` — carry the
 * prior summary forward into the merged result when there is nothing new to
 * summarize. The test builds a preparation directly (isSplitTurn=true,
 * messagesToSummarize=[], previousSummary="SECRET PRIOR HISTORY") and mocks
 * completeSimple for the turn-prefix summary; pre-fix the result summary
 * contains "No prior history." and NOT the secret; post-fix it carries it.
 */
import type { AgentMessage } from "@pi-recon/repi-agent-core";
import type { AssistantMessage, Model } from "@pi-recon/repi-ai";
import { describe, expect, it, vi } from "vitest";
import {
	type CompactionPreparation,
	compact,
	createFileOps,
	DEFAULT_COMPACTION_SETTINGS,
} from "../src/core/compaction/index.ts";

const { completeSimpleMock } = vi.hoisted(() => ({ completeSimpleMock: vi.fn() }));

vi.mock("@pi-recon/repi-ai", async (importOriginal) => {
	const actual = await importOriginal<typeof import("@pi-recon/repi-ai")>();
	return { ...actual, completeSimple: completeSimpleMock };
});

function createModel(): Model<"anthropic-messages"> {
	return {
		id: "test-model",
		name: "Test Model",
		api: "anthropic-messages",
		provider: "anthropic",
		baseUrl: "https://api.anthropic.com",
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 200000,
		maxTokens: 8192,
	};
}

const mockTurnPrefixResponse: AssistantMessage = {
	role: "assistant",
	content: [{ type: "text", text: "Turn prefix summary text." }],
	api: "anthropic-messages",
	provider: "anthropic",
	model: "test-model",
	usage: {
		input: 10,
		output: 10,
		cacheRead: 0,
		cacheWrite: 0,
		totalTokens: 20,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
	},
	stopReason: "stop",
	timestamp: Date.now(),
};

describe("opt #236: compact() split-turn carries previousSummary when nothing new to summarize", () => {
	it("previousSummary is preserved in the merged summary (not replaced with 'No prior history.')", async () => {
		completeSimpleMock.mockResolvedValue(mockTurnPrefixResponse);

		// Directly construct the orphaned-branch split-turn preparation: nothing
		// to summarize, but a prior history summary is present and must survive.
		const turnPrefix: AgentMessage[] = [{ role: "user", content: "in-flight turn prefix", timestamp: Date.now() }];
		const preparation: CompactionPreparation = {
			firstKeptEntryId: "kept-uuid",
			messagesToSummarize: [],
			turnPrefixMessages: turnPrefix,
			isSplitTurn: true,
			tokensBefore: 1000,
			previousSummary: "SECRET PRIOR HISTORY",
			fileOps: createFileOps(),
			settings: DEFAULT_COMPACTION_SETTINGS,
		};

		const result = await compact(preparation, createModel(), "test-key");

		// Post-fix: previousSummary carried forward → merged summary contains it.
		// Pre-fix: historyResult was "No prior history." → secret lost.
		expect(result.summary).toContain("SECRET PRIOR HISTORY");
		expect(result.summary).not.toContain("No prior history.");

		// The turn-prefix summary is still generated and merged in.
		expect(result.summary).toContain("Turn prefix summary text.");
		expect(result.firstKeptEntryId).toBe("kept-uuid");
	});
});

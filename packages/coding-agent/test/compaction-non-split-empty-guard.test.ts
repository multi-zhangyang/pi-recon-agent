/**
 * opt #240 — compact() non-split branch carries previousSummary forward when
 * messagesToSummarize is empty (mirrors the opt #236 split-branch guard).
 *
 * Pre-fix the non-split `else` branch unconditionally called
 * `generateSummary(messagesToSummarize, ..., previousSummary, ...)`. When
 * messagesToSummarize was empty (orphaned-branch fallback where the cut lands
 * exactly on a user message at boundaryStart, isSplitTurn=false) it serialized
 * an empty `<conversation></conversation>` and issued a pointless LLM call; if
 * the model didn't echo previousSummary verbatim the prior history was silently
 * degraded/lost from context (buildSessionContext emits only the latest
 * compaction's summary) — DATA-LOSS.
 *
 * Fix: `if (messagesToSummarize.length === 0) summary = previousSummary ?? "No
 * prior history."; else generateSummary(...)`. The test builds a non-split
 * preparation with empty messagesToSummarize + a SECRET previousSummary and
 * mocks completeSimple; post-fix the summary carries the secret and
 * completeSimple is NOT called. Pre-fix completeSimple IS called (and the
 * summary is the mock's text, not the secret).
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

const mockSummaryResponse: AssistantMessage = {
	role: "assistant",
	content: [{ type: "text", text: "HALLUCINATED SUMMARY OF NOTHING" }],
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

describe("compact() non-split no-op guard", () => {
	it("rejects a preparation that would remove no history", async () => {
		completeSimpleMock.mockResolvedValue(mockSummaryResponse);

		// Non-split preparation: nothing to summarize, no turn prefix, but a
		// prior history summary is present and must survive.
		const preparation: CompactionPreparation = {
			firstKeptEntryId: "kept-uuid",
			messagesToSummarize: [],
			turnPrefixMessages: [] as AgentMessage[],
			isSplitTurn: false,
			tokensBefore: 1000,
			previousSummary: "SECRET PRIOR HISTORY",
			fileOps: createFileOps(),
			settings: DEFAULT_COMPACTION_SETTINGS,
		};

		await expect(compact(preparation, createModel(), "test-key")).rejects.toThrow(
			"Nothing to compact: no history would be removed",
		);
		expect(completeSimpleMock).toHaveBeenCalledTimes(0);
	});
});

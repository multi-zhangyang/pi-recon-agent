import type { AgentMessage, StreamFn } from "@pi-recon/repi-agent-core";
import { createAssistantMessageEventStream, type Model } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { generateSummary } from "../src/core/compaction/index.ts";

// opt #132: `completeSummarization` does `await stream.result()`. `result()`
// resolves with an error AssistantMessage when the provider pushes a terminal
// "error" event (handled by the `stopReason === "error"` check in
// `generateSummary`). But it REJECTS when the underlying EventStream ends
// WITHOUT ever pushing a terminal done/error event — e.g. a misbehaving custom
// extension stream that completes without finalizing. Pre-fix that rejection
// propagated up through `generateSummary` as the raw "EventStream ended without
// a result" error (a possible unhandledRejection mid-compaction). The fix
// catches the rejection in `completeSummarization` and returns an error
// AssistantMessage so `generateSummary` surfaces "Summarization failed: ..."
// via the existing error path.

function createModel(): Model<"anthropic-messages"> {
	return {
		id: "claude-sonnet-4-6",
		name: "Claude Sonnet 4",
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

// Returns a stream that ends immediately WITHOUT pushing a terminal done/error
// event — so `.result()` rejects with "EventStream ended without a result".
function rejectingStreamFn(): StreamFn {
	return (() => {
		const stream = createAssistantMessageEventStream();
		stream.end();
		return stream;
	}) as StreamFn;
}

describe("completeSummarization result() rejection safety (opt #132)", () => {
	it("converts a result() rejection into a 'Summarization failed' error", async () => {
		const messages: AgentMessage[] = [{ role: "user", content: "Summarize this.", timestamp: Date.now() }];

		await expect(
			generateSummary(
				messages,
				createModel(),
				2000,
				"test-key",
				undefined,
				undefined,
				undefined,
				undefined,
				undefined,
				rejectingStreamFn(),
			),
		).rejects.toThrow(/Summarization failed/);
	});
});

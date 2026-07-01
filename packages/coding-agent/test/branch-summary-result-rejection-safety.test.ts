import type { AgentMessage, StreamFn } from "@pi-recon/repi-agent-core";
import { createAssistantMessageEventStream, type Model } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { generateBranchSummary } from "../src/core/compaction/branch-summarization.ts";
import type { SessionEntry } from "../src/core/session-manager.ts";

// opt #132: `generateBranchSummary` did `await (await streamFn(...)).result()`.
// `result()` rejects when the underlying EventStream ends WITHOUT a terminal
// done/error event (a misbehaving custom extension stream). Pre-fix that
// rejection propagated out of `generateBranchSummary` (the caller at
// agent-session.ts:3212 awaits it inside a branch-navigation flow — a
// rejection there is a possible unhandledRejection). The fix wraps the await in
// try/catch and returns the existing `{ error }` shape so the caller's
// `result.error` check (agent-session.ts:3225) handles it uniformly.

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

function rejectingStreamFn(): StreamFn {
	return (() => {
		const stream = createAssistantMessageEventStream();
		stream.end(); // no terminal event → .result() rejects
		return stream;
	}) as StreamFn;
}

const userMessage: AgentMessage = { role: "user", content: "do the thing", timestamp: Date.now() };

const entries: SessionEntry[] = [
	{
		type: "message",
		id: "entry-1",
		parentId: null,
		timestamp: new Date().toISOString(),
		message: userMessage,
	},
];

describe("generateBranchSummary result() rejection safety (opt #132)", () => {
	it("returns { error } when the stream result() rejects instead of propagating", async () => {
		const result = await generateBranchSummary(entries, {
			model: createModel(),
			apiKey: "test-key",
			signal: new AbortController().signal,
			streamFn: rejectingStreamFn(),
		});

		expect(result.error).toBeTruthy();
		expect(result.error).toMatch(/EventStream ended without a result/);
	});
});

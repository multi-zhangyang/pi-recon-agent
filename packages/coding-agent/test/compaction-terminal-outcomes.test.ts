import type { AgentMessage } from "@pi-recon/repi-agent-core";
import type { AssistantMessage, Model } from "@pi-recon/repi-ai";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateBranchSummary } from "../src/core/compaction/branch-summarization.ts";
import { type CompactionPreparation, compact, generateSummary } from "../src/core/compaction/index.ts";
import type { SessionEntry } from "../src/core/session-manager.ts";

const { completeSimpleMock } = vi.hoisted(() => ({
	completeSimpleMock: vi.fn(),
}));

vi.mock("@pi-recon/repi-ai", async (importOriginal) => {
	const actual = await importOriginal<typeof import("@pi-recon/repi-ai")>();
	return {
		...actual,
		completeSimple: completeSimpleMock,
	};
});

const model: Model<"anthropic-messages"> = {
	id: "summary-model",
	name: "Summary Model",
	api: "anthropic-messages",
	provider: "anthropic",
	baseUrl: "https://api.anthropic.com",
	reasoning: false,
	input: ["text"],
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
	contextWindow: 200_000,
	maxTokens: 8_192,
};

const messages: AgentMessage[] = [{ role: "user", content: "Summarize this.", timestamp: 1 }];

function branchEntry(id: string, content: string, parentId: string | null): SessionEntry {
	return {
		type: "message",
		id,
		parentId,
		timestamp: new Date().toISOString(),
		message: { role: "user", content, timestamp: 1 },
	};
}

function response(stopReason: AssistantMessage["stopReason"], text: string, errorMessage?: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
		api: model.api,
		provider: model.provider,
		model: model.id,
		usage: {
			input: 1,
			output: 1,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 2,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason,
		errorMessage,
		timestamp: 2,
	};
}

function splitTurnPreparation(): CompactionPreparation {
	return {
		firstKeptEntryId: "entry-keep",
		messagesToSummarize: [],
		turnPrefixMessages: messages,
		isSplitTurn: true,
		tokensBefore: 100,
		fileOps: { read: new Set(), written: new Set(), edited: new Set() },
		settings: { enabled: true, reserveTokens: 2_000, keepRecentTokens: 20 },
	};
}

describe("compaction summarization terminal outcomes", () => {
	beforeEach(() => {
		completeSimpleMock.mockReset();
	});

	it("returns a normal generated summary", async () => {
		completeSimpleMock.mockResolvedValue(response("stop", "summary-ok"));

		await expect(generateSummary(messages, model, 2_000, "test-key")).resolves.toBe("summary-ok");
	});

	it("rejects an error summary response", async () => {
		completeSimpleMock.mockResolvedValue(response("error", "must-not-be-used", "provider failed"));

		await expect(generateSummary(messages, model, 2_000, "test-key")).rejects.toThrow(
			"Summarization failed: provider failed",
		);
	});

	it("rejects an aborted summary response without relying on a signal", async () => {
		completeSimpleMock.mockResolvedValue(response("aborted", "must-not-be-used", "provider stopped"));

		await expect(generateSummary(messages, model, 2_000, "test-key")).rejects.toMatchObject({
			name: "AbortError",
			message: "provider stopped",
		});
	});

	it("continues and joins an incomplete length summary response", async () => {
		completeSimpleMock
			.mockResolvedValueOnce({
				...response("length", ""),
				content: [{ type: "thinking", thinking: "reasoning only" }],
			})
			.mockResolvedValueOnce(response("stop", "summary after continuation"));

		await expect(generateSummary(messages, model, 2_000, "test-key")).resolves.toBe("summary after continuation");
		expect(completeSimpleMock).toHaveBeenCalledTimes(2);
		const continuedContext = completeSimpleMock.mock.calls[1][1];
		expect(continuedContext.messages.at(-1)).toMatchObject({
			role: "user",
			content: [{ type: "text", text: expect.stringContaining("Continue the summary") }],
		});
	});

	it("rejects a summary that remains incomplete after bounded continuation", async () => {
		completeSimpleMock.mockResolvedValue(response("length", "partial summary"));

		await expect(generateSummary(messages, model, 2_000, "test-key")).rejects.toThrow(
			"Summarization failed: incomplete model response (length)",
		);
		expect(completeSimpleMock).toHaveBeenCalledTimes(4);
	});

	it("rejects an incomplete tool-use summary response", async () => {
		completeSimpleMock.mockResolvedValue(response("toolUse", "partial summary"));

		await expect(generateSummary(messages, model, 2_000, "test-key")).rejects.toThrow(
			"Summarization failed: incomplete model response (toolUse)",
		);
	});

	it("rejects a successful response with no usable text", async () => {
		completeSimpleMock.mockResolvedValue({
			...response("stop", "unused"),
			content: [{ type: "thinking", thinking: "reasoning only" }],
		});

		await expect(generateSummary(messages, model, 2_000, "test-key")).rejects.toThrow(
			"Summarization failed: model returned no text",
		);
	});

	it("returns a normal split-turn prefix summary", async () => {
		completeSimpleMock.mockResolvedValue(response("stop", "prefix-ok"));

		await expect(compact(splitTurnPreparation(), model, "test-key")).resolves.toMatchObject({
			summary: expect.stringContaining("prefix-ok"),
		});
	});

	it("rejects an error split-turn prefix response", async () => {
		completeSimpleMock.mockResolvedValue(response("error", "must-not-be-used", "prefix failed"));

		await expect(compact(splitTurnPreparation(), model, "test-key")).rejects.toThrow(
			"Turn prefix summarization failed: prefix failed",
		);
	});

	it("rejects an aborted split-turn prefix response without relying on a signal", async () => {
		completeSimpleMock.mockResolvedValue(response("aborted", "must-not-be-used", "prefix stopped"));

		await expect(compact(splitTurnPreparation(), model, "test-key")).rejects.toMatchObject({
			name: "AbortError",
			message: "prefix stopped",
		});
	});

	it("rejects an empty split-turn prefix summary", async () => {
		completeSimpleMock.mockResolvedValue(response("stop", "   "));

		await expect(compact(splitTurnPreparation(), model, "test-key")).rejects.toThrow(
			"Turn prefix summarization failed: model returned no text",
		);
	});

	it("bounds branch input when the configured reserve exceeds a small model window", async () => {
		let prompt = "";
		completeSimpleMock.mockImplementation((_model, context) => {
			const content = context.messages[0]?.content;
			prompt = Array.isArray(content) && content[0]?.type === "text" ? content[0].text : "";
			return response("stop", "branch-ok");
		});
		const oldContent = `OLD_MARKER_${"a".repeat(16_000)}`;
		const recentContent = `RECENT_MARKER_${"b".repeat(16_000)}`;

		const result = await generateBranchSummary(
			[branchEntry("old", oldContent, null), branchEntry("recent", recentContent, "old")],
			{
				model: { ...model, contextWindow: 8192 },
				apiKey: "test-key",
				signal: new AbortController().signal,
				reserveTokens: 16_384,
			},
		);

		expect(result.error).toBeUndefined();
		expect(prompt).toContain("RECENT_MARKER");
		expect(prompt).not.toContain("OLD_MARKER");
	});

	it.each([
		["length", "partial"],
		["toolUse", "partial"],
		["stop", "   "],
	] as const)("fails closed for a %s branch-summary response", async (stopReason, text) => {
		completeSimpleMock.mockResolvedValue(response(stopReason, text));

		const result = await generateBranchSummary([branchEntry("entry", "branch", null)], {
			model,
			apiKey: "test-key",
			signal: new AbortController().signal,
		});

		expect(result.error).toMatch(/Branch summary failed/);
	});
});

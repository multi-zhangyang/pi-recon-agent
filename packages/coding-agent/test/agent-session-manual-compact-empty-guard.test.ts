/**
 * opt #237 — manual /compact on a small session writes a hallucinated
 * compaction entry (MED DATA-LOSS).
 *
 * prepareCompaction returns a preparation for a small session EVEN WHEN there
 * is nothing to summarize: findCutPoint's backward walk never reaches
 * keepRecentTokens, so cutIndex stays at cutPoints[0] and then the
 * include-non-message-entries while-loop walks it back to the session header
 * (index 0). historyEnd = firstKeptEntryIndex = 0, so the messagesToSummarize
 * loop never iterates → messagesToSummarize empty; non-split → turnPrefixMessages
 * empty. The header has an id, so the `if (!firstKeptEntry?.id) return undefined`
 * guard does NOT trip → preparation is non-undefined → the manual path's
 * `if (!preparation)` guard (agent-session.ts:2104) does NOT catch it.
 *
 * Pre-fix the manual path proceeded to compact() → generateSummary([]) → the
 * LLM hallucinated a summary for an empty conversation, appendCompaction wrote a
 * compaction entry pointing at the header (nothing discarded, context GREW by
 * the boilerplate), and that hallucinated summary became previousSummary for the
 * next compaction, corrupting the iterative summary chain. The auto path guards
 * this (hasSummarizableHistory at agent-session.ts:2507); the manual path did not.
 *
 * Fix: mirror the auto path's hasSummarizableHistory check at the manual caller
 * (agent-session.ts:2112) — throw "Nothing to compact (session too small)" when
 * messagesToSummarize and turnPrefixMessages are both empty. Throwing at the
 * caller (not inside compact()) avoids the auto path's try/catch surfacing a
 * spurious "Auto-compaction failed" for proactive auto-compaction.
 *
 * The test seeds a small [user, assistant] session (well under the default
 * keepRecentTokens budget) and mocks completeSimple (the no-streamFn path
 * generateSummary uses) to return a hallucinated response. Post-fix:
 * session.compact() throws, completeSimple is NEVER called, and no compaction
 * entry is appended. Pre-fix (guard removed): session.compact() resolves,
 * completeSimple is called, and a hallucinated compaction entry is written.
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import type { AssistantMessage } from "@pi-recon/repi-ai";
import { getModel } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createTestResourceLoader } from "./utilities.ts";

const { completeSimpleMock } = vi.hoisted(() => ({ completeSimpleMock: vi.fn() }));

vi.mock("@pi-recon/repi-ai", async (importOriginal) => {
	const actual = await importOriginal<typeof import("@pi-recon/repi-ai")>();
	return { ...actual, completeSimple: completeSimpleMock };
});

// A hallucinated summary an LLM would produce for an empty conversation.
const hallucinatedSummary: AssistantMessage = {
	role: "assistant",
	content: [{ type: "text", text: "HALLUCINATED SUMMARY OF NOTHING" }],
	api: "anthropic-messages",
	provider: "anthropic",
	model: "claude-sonnet-4-5",
	usage: {
		input: 5,
		output: 5,
		cacheRead: 0,
		cacheWrite: 0,
		totalTokens: 10,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
	},
	stopReason: "stop",
	timestamp: Date.now(),
};

describe("opt #237: manual /compact on a small session does not hallucinate a compaction entry", () => {
	let session: AgentSession;
	let sessionManager: SessionManager;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `opt237-manual-compact-empty-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });

		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({
			initialState: { model, systemPrompt: "Test", tools: [] },
		});
		// null streamFn so compact() takes the completeSimple (mocked) path instead
		// of the default streamSimple → real Anthropic API call.
		(agent as { streamFn: unknown }).streamFn = undefined;

		sessionManager = SessionManager.inMemory();
		const settingsManager = SettingsManager.create(tempDir, tempDir);
		const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
		authStorage.setRuntimeApiKey("anthropic", "test-key");
		const modelRegistry = ModelRegistry.create(authStorage, tempDir);

		session = new AgentSession({
			agent,
			sessionManager,
			settingsManager,
			cwd: tempDir,
			modelRegistry,
			resourceLoader: createTestResourceLoader(),
		});

		// Seed a SMALL session: one user + one assistant, well under the default
		// keepRecentTokens budget → findCutPoint never reaches the budget →
		// messagesToSummarize empty, non-split → the bug condition.
		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});
		sessionManager.appendMessage({
			role: "assistant",
			content: [{ type: "text", text: "hi" }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "claude-sonnet-4-5",
			usage: {
				input: 1,
				output: 1,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 2,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: Date.now(),
		});

		completeSimpleMock.mockReset();
		completeSimpleMock.mockResolvedValue(hallucinatedSummary);
	});

	afterEach(() => {
		session.dispose();
		vi.restoreAllMocks();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("throws 'Nothing to compact' and does NOT call the LLM or write a compaction entry", async () => {
		// Post-fix: the hasSummarizableHistory guard throws before compact().
		await expect(session.compact()).rejects.toThrow(/Nothing to compact \(session too small\)/);

		// The LLM was never asked to summarize an empty conversation.
		expect(completeSimpleMock).not.toHaveBeenCalled();

		// No compaction entry was appended (no hallucinated entry on the branch).
		const compactionEntries = sessionManager.getEntries().filter((e) => e.type === "compaction");
		expect(compactionEntries).toHaveLength(0);
	}, 15000);

	it("skips threshold auto-compaction when the cut would remove no history", async () => {
		const events: Array<{ type: string; result?: unknown; errorMessage?: string }> = [];
		session.subscribe((event) => {
			if (event.type === "compaction_end") events.push(event);
		});
		const runAutoCompaction = (
			session as unknown as {
				_runAutoCompaction: (reason: "overflow" | "threshold", willRetry: boolean) => Promise<boolean>;
			}
		)._runAutoCompaction.bind(session);

		await expect(runAutoCompaction("threshold", false)).resolves.toBe(false);
		expect(completeSimpleMock).not.toHaveBeenCalled();
		expect(sessionManager.getEntries().filter((entry) => entry.type === "compaction")).toHaveLength(0);
		expect(events).toEqual([expect.objectContaining({ type: "compaction_end", result: undefined })]);
		expect(events[0]).not.toHaveProperty("errorMessage");
	}, 15000);
});

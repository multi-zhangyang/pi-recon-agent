/**
 * opt #246 — sendCustomMessage guard asymmetry vs prompt() (HIGH DATA-LOSS).
 *
 * prompt() guards `if (this.isStreaming || this.isRetrying || this.isCompacting)`
 * (agent-session.ts:1402). sendCustomMessage only checked `this.isStreaming`.
 * During compaction isStreaming=false, so a `sendCustomMessage(msg,
 * {triggerTurn:true})` from a session_before_compact/session_compact extension
 * handler fell through to `_runAgentPrompt(appMessage)` and started a concurrent
 * run on the pre-compaction state.messages snapshot; when compaction finished it
 * did `this.agent.state.messages = sessionContext.messages`, REPLACING the array
 * the concurrent run was pushing into → the injected message was OVERWRITTEN
 * (lost) and two runs raced. A plain (no-trigger) sendCustomMessage pushed into
 * state.messages directly, also clobbered on the swap.
 *
 * Fix: add `|| this.isCompacting || this.isRetrying` after the nextTurn branch,
 * routing to the steer/followUp queue (drained by the post-compaction resume
 * loop) instead of _runAgentPrompt / state.messages.push. nextTurn is exempt —
 * it pushes to _pendingNextTurnMessages, which compaction does not swap.
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { getModel } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createTestResourceLoader } from "./utilities.ts";

// Controllable mock: compact() returns a promise we resolve to suspend
// manual compact() mid-summarization, simulating an in-flight compaction.
let resolveCompact!: (value: {
	summary: string;
	firstKeptEntryId: string;
	tokensBefore: number;
	details: unknown;
}) => void;
let compactPromise!: Promise<{
	summary: string;
	firstKeptEntryId: string;
	tokensBefore: number;
	details: unknown;
}>;

vi.mock("../src/core/compaction/index.js", () => ({
	calculateContextTokens: (usage: {
		input: number;
		output: number;
		cacheRead: number;
		cacheWrite: number;
		totalTokens?: number;
	}) => usage.totalTokens ?? usage.input + usage.output + usage.cacheRead + usage.cacheWrite,
	collectEntriesForBranchSummary: () => ({ entries: [], commonAncestorId: null }),
	compact: () => compactPromise,
	estimateContextTokens: () => ({ tokens: 0, usageTokens: 0, trailingTokens: 0, lastUsageIndex: null }),
	generateBranchSummary: async () => ({ summary: "", aborted: false, readFiles: [], modifiedFiles: [] }),
	prepareCompaction: () => ({
		messagesToSummarize: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
		turnPrefixMessages: [],
	}),
	shouldCompact: () => true,
	stripTrailingErrorAssistants: (messages: Array<{ role: string }>) => messages,
}));

async function waitForCompacting(session: AgentSession, timeoutMs = 2000): Promise<void> {
	const start = Date.now();
	while (!session.isCompacting) {
		if (Date.now() - start > timeoutMs) throw new Error("compaction window never opened");
		await new Promise((resolve) => setTimeout(resolve, 1));
	}
}

describe("AgentSession sendCustomMessage during compaction guard (opt #246)", () => {
	let session: AgentSession;
	let sessionManager: SessionManager;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-sendcustom-compaction-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });

		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({
			initialState: { model, systemPrompt: "Test", tools: [] },
		});

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

		compactPromise = new Promise((resolve) => {
			resolveCompact = resolve;
		});
	});

	afterEach(() => {
		session.dispose();
		vi.restoreAllMocks();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true });
	});

	it("routes a triggerTurn sendCustomMessage during compaction to the steer queue, not _runAgentPrompt", async () => {
		// Mock agent.continue so the post-compaction drain of the queued steer
		// message does not start a real LLM run.
		const continueSpy = vi.spyOn(session.agent, "continue").mockImplementation(async () => {
			session.agent.clearAllQueues();
		});
		// _runAgentPrompt is the dangerous path — must NOT be called during compaction.
		const runPromptSpy = vi
			.spyOn(session as unknown as { _runAgentPrompt: (msg: unknown) => Promise<void> }, "_runAgentPrompt")
			.mockResolvedValue(undefined);

		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});

		const compactCall = session.compact();
		await waitForCompacting(session);
		expect(session.isCompacting).toBe(true);
		expect(session.isStreaming).toBe(false);

		// The exact dangerous call: an extension handler injecting a custom
		// message mid-compaction with triggerTurn:true. Pre-fix this fell through
		// to _runAgentPrompt and raced with the in-flight compaction.
		await session.sendCustomMessage(
			{ customType: "test-event", content: "injected-during-compaction", display: false },
			{ triggerTurn: true },
		);

		expect(runPromptSpy).not.toHaveBeenCalled();

		resolveCompact({ summary: "compacted", firstKeptEntryId: "entry-1", tokensBefore: 100, details: {} });
		await compactCall;

		// Exactly one compaction entry — no racing run produced a second.
		expect(sessionManager.getEntries().filter((e) => e.type === "compaction")).toHaveLength(1);
		// Drain of the queued steer ran continue (the message was preserved, not lost).
		expect(continueSpy).toHaveBeenCalled();
	}, 15000);

	it("does not push a no-trigger sendCustomMessage into state.messages during compaction (would be clobbered)", async () => {
		const continueSpy = vi.spyOn(session.agent, "continue").mockImplementation(async () => {
			session.agent.clearAllQueues();
		});
		const messagesBefore = session.agent.state.messages.length;

		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});

		const compactCall = session.compact();
		await waitForCompacting(session);

		// No triggerTurn, no deliverAs: pre-fix the final else pushed appMessage
		// into state.messages, which compaction then swapped out (lost).
		await session.sendCustomMessage({ customType: "test-event", content: "passive-injection", display: false });

		// Routed to the steer queue, not state.messages.
		expect(session.agent.state.messages.length).toBe(messagesBefore);

		resolveCompact({ summary: "compacted", firstKeptEntryId: "entry-1", tokensBefore: 100, details: {} });
		await compactCall;
		expect(continueSpy).toHaveBeenCalled();
	}, 15000);
});

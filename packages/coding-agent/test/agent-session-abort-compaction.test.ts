/**
 * Bug #4 — abort doesn't abort compaction + compact() finally re-subscribes agent after dispose().
 *
 * (a) abort() called abortRetry() + agent.abort() + waitForIdle() but NEVER
 * abortCompaction(). Compaction runs with no active agent run, so agent.abort()
 * is a no-op and waitForIdle() resolves immediately; a SIGINT/SIGTERM during
 * compaction did NOT stop the in-flight summarization LLM call (cost/quota leak)
 * until the later dispose()→abortCompaction(). Fix: abort() also calls
 * abortCompaction() (best-effort, guarded).
 *
 * (b) dispose() runs abortCompaction() → the in-flight compact()'s `await
 * compact(...)` throws AbortError → catch emits compaction_end (dropped,
 * _eventListeners cleared) → the finally ran _reconnectToAgent(),
 * re-subscribing _handleAgentEvent to the agent AFTER dispose() disconnected
 * it. Subsequent agent events flowed back into a torn-down session. Fix: guard
 * _reconnectToAgent() in compact()'s finally with the _disposed flag.
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
// compact() mid-summarization, simulating an in-flight compaction we can
// abort or dispose into.
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
	estimateCompactionContext: () => ({ beforeTokens: 2, afterTokens: 1 }),
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

type SessionInternals = {
	_compactionRuntime: { _compactionAbortController?: { signal: { aborted: boolean } } };
	_unsubscribeAgent?: () => void;
	_disposed: boolean;
};

describe("AgentSession abort/dispose during compaction (bug #4)", () => {
	let session: AgentSession;
	let sessionManager: SessionManager;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-abort-compaction-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("abort() aborts the in-flight compaction controller (bug #4a)", async () => {
		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});

		const compactCall = session.compact();
		await waitForCompacting(session);

		const internals = session as unknown as SessionInternals;
		const controller = internals._compactionRuntime._compactionAbortController;
		expect(controller).toBeDefined();
		expect(controller!.signal.aborted).toBe(false);

		// abort() must abort the compaction controller, not just the agent run.
		// Pre-fix, abortCompaction() was never called → signal stayed un-aborted
		// and the summarization LLM call kept running (cost/quota leak).
		await session.abort();
		expect(controller!.signal.aborted).toBe(true);

		// Let compact() unwind through the signal.aborted throw + finally.
		resolveCompact({ summary: "compacted", firstKeptEntryId: "entry-1", tokensBefore: 100, details: {} });
		await compactCall.catch(() => undefined);
	}, 15000);

	it("compact() finally does not re-subscribe to the agent after dispose() (bug #4b)", async () => {
		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});

		const compactCall = session.compact();
		await waitForCompacting(session);

		const internals = session as unknown as SessionInternals;
		// dispose() tears the session down: disconnects from agent, clears
		// listeners, aborts compaction, sets _disposed=true.
		session.dispose();
		expect(internals._disposed).toBe(true);
		expect(internals._unsubscribeAgent).toBeUndefined();

		// Resolve the suspended compact() mock. The real compact() method sees
		// signal.aborted → throws "Compaction cancelled" → catch emits
		// compaction_end (listeners empty, dropped) → finally runs. Pre-fix the
		// finally unconditionally called _reconnectToAgent(), re-subscribing
		// _handleAgentEvent to the agent AFTER dispose() disconnected it →
		// _unsubscribeAgent became defined again. Post-fix the _disposed guard
		// skips the reconnect.
		resolveCompact({ summary: "compacted", firstKeptEntryId: "entry-1", tokensBefore: 100, details: {} });
		await compactCall.catch(() => undefined);

		// The reconnect must NOT have re-subscribed after dispose.
		expect(internals._disposed).toBe(true);
		expect(internals._unsubscribeAgent).toBeUndefined();
	}, 15000);
});

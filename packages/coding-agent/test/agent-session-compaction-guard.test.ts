/**
 * Bug #3 — concurrent prompt() during compaction loses user message + double-compacts.
 *
 * The prompt() guard was `if (this.isStreaming || this.isRetrying)` — it did NOT
 * check isCompacting. During auto/manual compaction, isStreaming=false and
 * isRetrying=false, but isCompacting=true and no active agent run is held by the
 * compaction. A concurrent prompt() fell through to _runAgentPrompt and started a
 * real run on the pre-compaction state.messages snapshot; when compaction
 * finished it did `this.agent.state.messages = sessionContext.messages`,
 * REPLACING the array the concurrent run was pushing into → the second prompt()'s
 * user message was OVERWRITTEN (lost). Two concurrent compactions also clobbered
 * _autoCompactionAbortController → an un-cancellable compaction.
 *
 * Fix: add `|| this.isCompacting` to the guard so a concurrent prompt() during
 * compaction routes to the steer/followUp queue (same as during streaming).
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
	// A truthy preparation with a summarizable message so manual compact()
	// proceeds past the "Nothing to compact" guard to the `await compact(...)`.
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

describe("AgentSession prompt() during compaction guard (bug #3)", () => {
	let session: AgentSession;
	let sessionManager: SessionManager;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-compaction-guard-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("rejects a concurrent prompt() with no streamingBehavior during compaction (no race)", async () => {
		// Seed a user message so the branch has content for prepareCompaction.
		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});

		// Start manual compaction; it suspends on the deferred compact() mock.
		const compactCall = session.compact();
		await waitForCompacting(session);
		expect(session.isCompacting).toBe(true);
		expect(session.isStreaming).toBe(false);
		expect(session.isRetrying).toBe(false);

		// A concurrent prompt with no streamingBehavior must be rejected — pre-fix
		// it fell through to _runAgentPrompt and raced with the in-flight
		// compaction (clobbering state.messages and losing the user message).
		await expect(session.prompt("concurrent")).rejects.toThrow(/already processing/i);

		// Let compaction complete cleanly.
		resolveCompact({ summary: "compacted", firstKeptEntryId: "entry-1", tokensBefore: 100, details: {} });
		await compactCall;

		// Exactly one compaction entry — no double-compaction from a racing run.
		const compactionEntries = sessionManager.getEntries().filter((e) => e.type === "compaction");
		expect(compactionEntries).toHaveLength(1);
	}, 15000);

	it("queues a concurrent prompt() with streamingBehavior:'steer' during compaction", async () => {
		// Mock agent.continue so the post-compaction drain of the queued steer
		// message does not start a real LLM run (_handlePostAgentRun sees no
		// _lastAssistantMessage and exits its loop immediately).
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});

		const compactCall = session.compact();
		await waitForCompacting(session);

		// With streamingBehavior, the concurrent prompt queues (no throw, no race).
		await expect(session.prompt("concurrent", { streamingBehavior: "steer" })).resolves.toBeUndefined();

		// Let compaction finish; its finally drains the queued steer via continue.
		resolveCompact({ summary: "compacted", firstKeptEntryId: "entry-1", tokensBefore: 100, details: {} });
		await compactCall;

		// The drain ran at least one continue. The user message was queued and
		// drained, NOT lost to a clobbered state.messages.
		expect(continueSpy).toHaveBeenCalled();
		expect(sessionManager.getEntries().filter((e) => e.type === "compaction")).toHaveLength(1);
	}, 15000);
});

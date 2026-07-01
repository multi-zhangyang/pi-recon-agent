/**
 * opt #100 F3 — abort during auto-compaction reports "aborted" not "failed".
 *
 * When the user aborts while the summarization LLM stream is in flight,
 * compact()/generateSummary() throws an AbortError; the post-compact signal
 * check is skipped (throw), and the catch hardcoded aborted:false → emitted
 * "Auto-compaction failed: <abort message>". The fix detects abort the same way
 * manual compact() does and sets aborted:true with no errorMessage.
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { getModel } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession, type AgentSessionEvent } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createTestResourceLoader } from "./utilities.ts";

vi.mock("../src/core/compaction/index.js", () => ({
	calculateContextTokens: (usage: {
		input: number;
		output: number;
		cacheRead: number;
		cacheWrite: number;
		totalTokens?: number;
	}) => usage.totalTokens ?? usage.input + usage.output + usage.cacheRead + usage.cacheWrite,
	collectEntriesForBranchSummary: () => ({ entries: [], commonAncestorId: null }),
	// compact() throws an AbortError mid-summarization, simulating a user abort
	// while the summarization stream is in flight.
	compact: async () => {
		const err = new Error("The operation was aborted");
		err.name = "AbortError";
		throw err;
	},
	estimateContextTokens: () => ({ tokens: 0, usageTokens: 0, trailingTokens: 0, lastUsageIndex: null }),
	generateBranchSummary: async () => ({ summary: "", aborted: false, readFiles: [], modifiedFiles: [] }),
	prepareCompaction: () => ({ messagesToSummarize: [], turnPrefixMessages: [] }),
	shouldCompact: () => true,
	stripTrailingErrorAssistants: (messages: Array<{ role: string }>) => messages,
}));

describe("opt100 F3: auto-compaction abort reports aborted, not failed", () => {
	let session: AgentSession;
	let sessionManager: SessionManager;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-opt100-f3-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });

		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({
			initialState: { model, systemPrompt: "Test", tools: [] },
		});

		sessionManager = SessionManager.inMemory();
		const settingsManager = SettingsManager.create(tempDir, tempDir);
		settingsManager.applyOverrides({ compaction: { enabled: true, keepRecentTokens: 1, reserveTokens: 1000 } });
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
	});

	afterEach(() => {
		session.dispose();
		vi.restoreAllMocks();
		if (tempDir && existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true });
		}
	});

	it("compaction_end has aborted:true and no errorMessage when compact() throws AbortError", async () => {
		// Seed a user message so the branch has content for prepareCompaction.
		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});

		const events: AgentSessionEvent[] = [];
		session.subscribe((event) => {
			if (event.type === "compaction_end") {
				events.push(event);
			}
		});

		const runAutoCompaction = (
			session as unknown as {
				_runAutoCompaction: (reason: "overflow" | "threshold", willRetry: boolean) => Promise<boolean>;
			}
		)._runAutoCompaction.bind(session);

		// Reason="threshold" so the hasSummarizableHistory guard (overflow-only)
		// does not short-circuit before compact() is called.
		const result = await runAutoCompaction("threshold", false);

		// Auto-compaction returns false (did not complete / no retry).
		expect(result).toBe(false);
		expect(events).toHaveLength(1);
		const end = events[0] as {
			type: string;
			reason: string;
			aborted: boolean;
			errorMessage?: string;
			result: unknown;
		};
		expect(end.type).toBe("compaction_end");
		expect(end.reason).toBe("threshold");
		expect(end.aborted).toBe(true);
		expect(end.errorMessage).toBeUndefined();
		expect(end.result).toBeUndefined();
	});

	it("also reports aborted:true when the abort signal is fired before compact() throws", async () => {
		// Abort the controller right after _runAutoCompaction creates it, by
		// spying on the AbortController constructor's signal. Simpler: abort via
		// the public abort path through session.compact() is the manual path; for
		// the auto path, exercise the signal.aborted branch by pre-aborting.
		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});

		const events: AgentSessionEvent[] = [];
		session.subscribe((event) => {
			if (event.type === "compaction_end") {
				events.push(event);
			}
		});

		// Pre-abort the auto-compaction controller that _runAutoCompaction will
		// install, by patching AbortController so the signal starts aborted.
		const RealAbortController = globalThis.AbortController;
		class PreAbortedController extends RealAbortController {
			constructor() {
				super();
				this.abort();
			}
		}
		globalThis.AbortController = PreAbortedController as typeof AbortController;

		const runAutoCompaction = (
			session as unknown as {
				_runAutoCompaction: (reason: "overflow" | "threshold", willRetry: boolean) => Promise<boolean>;
			}
		)._runAutoCompaction.bind(session);

		try {
			await runAutoCompaction("threshold", false);
		} finally {
			globalThis.AbortController = RealAbortController;
		}

		const end = events.find(
			(e): e is Extract<AgentSessionEvent, { type: "compaction_end" }> => e.type === "compaction_end",
		);
		expect(end).toBeDefined();
		expect(end!.aborted).toBe(true);
		expect(end!.errorMessage).toBeUndefined();
	});
});

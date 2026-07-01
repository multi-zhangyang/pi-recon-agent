/**
 * opt #217 — reactive overflow recovery crashes on a silent-overflow terminal
 * assistant when no steer is queued.
 *
 * The #204 fix guarded the PROACTIVE (threshold) compaction path's terminal-turn
 * resume. The REACTIVE overflow path (`_runAutoCompaction("overflow", true)` →
 * the `if (willRetry)` branch) was NOT given the equivalent guard. A SILENT
 * overflow (z.ai `stopReason "stop"` with usage.input > contextWindow; Xiaomi
 * MiMo `stopReason "length"` with output 0 and input >= 0.99*contextWindow —
 * both detected by isContextOverflow) is neither "error" nor "aborted", so
 * `stripTrailingErrorAssistants` leaves that assistant in place. It is a
 * TERMINAL turn (no toolCall blocks — overflow turns never carry tool calls,
 * since stopReason would be "toolUse" otherwise). With no steering message
 * queued, the outer while-loop's `agent.continue()` then throws
 * "Cannot continue from message role: assistant" (agent.ts continue() guard).
 *
 * Fix: in the willRetry branch, after stripping, if the last message is a
 * terminal assistant and nothing is queued, inject a "Continue." steer so the
 * model retries with the reduced (post-compaction) context instead of
 * crashing. REPI auto-resume usually queues a steer already; this covers
 * non-REPI mode and exhausted resume budget.
 *
 * This test drives the private `_runAutoCompaction("overflow", true)` directly
 * with a mocked compaction module (compact succeeds, stripTrailingErrorAssistants
 * uses real error/aborted-only semantics) and spies buildSessionContext to
 * return a terminal assistant as the last post-compaction message — isolating
 * the willRetry branch's post-strip handling as the only variable.
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { type AssistantMessage, getModel, type Model } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createTestResourceLoader } from "./utilities.ts";

// stripTrailingErrorAssistants: REAL semantics — only "error"/"aborted" are
// removed. A silent-overflow "stop"/"length" assistant survives the strip,
// which is the crux of the bug.
vi.mock("../src/core/compaction/index.js", () => ({
	calculateContextTokens: (usage: {
		input: number;
		output: number;
		cacheRead: number;
		cacheWrite: number;
		totalTokens?: number;
	}) => usage.totalTokens ?? usage.input + usage.output + usage.cacheRead + usage.cacheWrite,
	collectEntriesForBranchSummary: () => ({ entries: [], commonAncestorId: null }),
	compact: async () => ({ summary: "compacted", firstKeptEntryId: "entry-1", tokensBefore: 100, details: {} }),
	estimateContextTokens: () => ({ tokens: 0, usageTokens: 0, trailingTokens: 0, lastUsageIndex: null }),
	generateBranchSummary: async () => ({ summary: "", aborted: false, readFiles: [], modifiedFiles: [] }),
	// Summarizable history so the overflow-only hasSummarizableHistory guard
	// does not short-circuit before compact() runs.
	prepareCompaction: () => ({
		messagesToSummarize: [{ role: "user", content: [{ type: "text", text: "hi" }], timestamp: 0 }],
		turnPrefixMessages: [],
	}),
	shouldCompact: () => true,
	stripTrailingErrorAssistants: (messages: Array<{ role: string; stopReason?: string }>) => {
		let end = messages.length;
		while (end > 0) {
			const last = messages[end - 1];
			if (last?.role === "assistant" && (last.stopReason === "error" || last.stopReason === "aborted")) {
				end--;
			} else break;
		}
		return end === messages.length ? messages : messages.slice(0, end);
	},
}));

type SessionInternals = {
	_runAutoCompaction: (reason: "overflow" | "threshold", willRetry: boolean) => Promise<boolean>;
};

describe("opt #217: silent-overflow terminal assistant gets a continuation steer", () => {
	let session: AgentSession;
	let sessionManager: SessionManager;
	let tempDir: string;
	let model: Model<"anthropic-messages">;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-opt217-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });

		model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({ initialState: { model, systemPrompt: "Test", tools: [] } });

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
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	function makeTerminalAssistant(stopReason: "stop" | "length"): AssistantMessage {
		return {
			role: "assistant",
			content: [{ type: "text", text: "final answer" }],
			api: model.api,
			provider: model.provider,
			model: model.id,
			usage: {
				input: 250_000,
				output: stopReason === "length" ? 0 : 100,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 250_100,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason,
			timestamp: Date.now(),
		};
	}

	function runOverflow(): Promise<boolean> {
		const internals = session as unknown as SessionInternals;
		return internals._runAutoCompaction("overflow", true);
	}

	it("injects a continuation steer for a z.ai-style stop silent-overflow terminal assistant", async () => {
		const terminal = makeTerminalAssistant("stop");
		// Seed a user entry so the branch has content for getBranch().
		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});
		// Post-compaction context ends with the terminal assistant (it survived
		// stripTrailingErrorAssistants because stopReason is "stop", not "error").
		vi.spyOn(sessionManager, "buildSessionContext").mockReturnValue({
			messages: [terminal],
			thinkingLevel: "off",
			model: null,
		});
		session.agent.state.messages = [terminal];

		const result = await runOverflow();

		// Recovery succeeded and a continuation steer is queued so the outer loop's
		// agent.continue() delivers it instead of throwing.
		expect(result).toBe(true);
		expect(session.agent.hasQueuedMessages()).toBe(true);
	});

	it("injects a continuation steer for a Xiaomi-MiMo-style length silent-overflow terminal assistant", async () => {
		const terminal = makeTerminalAssistant("length");
		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});
		vi.spyOn(sessionManager, "buildSessionContext").mockReturnValue({
			messages: [terminal],
			thinkingLevel: "off",
			model: null,
		});
		session.agent.state.messages = [terminal];

		const result = await runOverflow();

		expect(result).toBe(true);
		expect(session.agent.hasQueuedMessages()).toBe(true);
	});

	it("does NOT inject a second steer when one is already queued (no double-continue)", async () => {
		const terminal = makeTerminalAssistant("stop");
		sessionManager.appendMessage({
			role: "user",
			content: [{ type: "text", text: "hello" }],
			timestamp: Date.now(),
		});
		vi.spyOn(sessionManager, "buildSessionContext").mockReturnValue({
			messages: [terminal],
			thinkingLevel: "off",
			model: null,
		});
		session.agent.state.messages = [terminal];

		// Pre-queue a steer (e.g. REPI auto-resume already queued one).
		session.agent.steer({ role: "user", content: "resume", timestamp: Date.now() });
		const steeringQueue = (session.agent as unknown as { steeringQueue: { messages: unknown[] } }).steeringQueue;
		expect(steeringQueue.messages).toHaveLength(1);

		const result = await runOverflow();

		expect(result).toBe(true);
		// The pre-existing steer is still the only queued message — the fix must
		// not append a redundant "Continue." on top.
		expect(steeringQueue.messages).toHaveLength(1);
	});
});

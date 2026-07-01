/**
 * opt #204 — terminal-turn proactive-compaction resume crash.
 *
 * Found by a REAL-API compaction-stress run (kimchi/kimi-k2.7 with a small
 * contextWindow): a successful autonomous run that crossed the proactive
 * compaction threshold on its FINAL (end_turn, no tool calls) turn exited
 * with code 1 and `Cannot continue from message role: assistant`.
 *
 * Root cause: `_shouldStopAfterTurnForCompaction` (the agent-loop's
 * shouldStopAfterTurn hook) returned true on a terminal turn — redundant for
 * stopping (the loop breaks on a no-tool-call turn anyway) but it set
 * `_resumeAfterTurnBoundaryCompaction = true`. The post-run
 * `_handlePostAgentRun → _checkCompaction → _runAutoCompaction` then returned
 * `resumeAfterTurnBoundary || hasQueuedMessages()` = true, driving
 * `agent.continue()` → `agentLoopContinue` on a conversation whose last
 * message is the terminal assistant → throws "Cannot continue from message
 * role: assistant" → caught by print-mode's catch → EXIT=1.
 *
 * Fix: return false (without setting the resume flag) when the assistant turn
 * has no tool-call blocks — there is no "next provider request" to stop before;
 * the loop ends naturally and compaction runs as housekeeping without resuming.
 *
 * This test exercises the private hook directly with a mocked compaction
 * module (`shouldCompact` forced true) so the ONLY variable is the
 * terminal-vs-tool-call content of the assistant message.
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
	estimateContextTokens: (
		messages: Array<{
			role: string;
			usage?: { totalTokens?: number };
			stopReason?: string;
		}>,
	) => {
		for (let i = messages.length - 1; i >= 0; i--) {
			const msg = messages[i];
			if (msg.role === "assistant" && msg.stopReason !== "error" && msg.stopReason !== "aborted" && msg.usage) {
				const tokens = msg.usage.totalTokens ?? 0;
				return { tokens, usageTokens: tokens, trailingTokens: 0, lastUsageIndex: i };
			}
		}
		return { tokens: 0, usageTokens: 0, trailingTokens: 0, lastUsageIndex: null };
	},
	generateBranchSummary: async () => ({ summary: "", aborted: false, readFiles: [], modifiedFiles: [] }),
	prepareCompaction: () => ({ messagesToSummarize: [], turnPrefixMessages: [] }),
	// Force threshold crossed whenever there is any usage — isolates the
	// terminal-turn guard from threshold arithmetic.
	shouldCompact: (contextTokens: number) => contextTokens > 0,
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
	_shouldStopAfterTurnForCompaction: (assistantMessage: AssistantMessage) => boolean;
	_resumeAfterTurnBoundaryCompaction: boolean;
};

describe("opt #204: terminal-turn proactive-compaction resume crash", () => {
	let session: AgentSession;
	let tempDir: string;
	let model: Model<"anthropic-messages">;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-opt204-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });

		model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({ initialState: { model, systemPrompt: "Test", tools: [] } });

		const sessionManager = SessionManager.inMemory();
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
	});

	afterEach(() => {
		session.dispose();
		vi.restoreAllMocks();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	function makeAssistant(
		content: AssistantMessage["content"],
		stopReason: AssistantMessage["stopReason"],
	): AssistantMessage {
		return {
			role: "assistant",
			content,
			api: model.api,
			provider: model.provider,
			model: model.id,
			usage: {
				input: 900_000,
				output: 100_000,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 1_000_000,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason,
			timestamp: Date.now(),
		};
	}

	it("does NOT stop-to-resume on a terminal (no-tool-call) turn over the threshold", () => {
		const internals = session as unknown as SessionInternals;
		const terminal = makeAssistant([{ type: "text", text: "Task complete." }], "stop");
		// Place it as the last message so estimateContextTokens finds over-threshold usage.
		session.agent.state.messages = [terminal];

		// Must return false: there is no next provider request to stop before.
		// Pre-fix this returned true AND set the resume flag → doomed continue.
		expect(internals._shouldStopAfterTurnForCompaction(terminal)).toBe(false);
		// The toxic side effect must NOT have fired.
		expect(internals._resumeAfterTurnBoundaryCompaction).toBe(false);
	});

	it("still stops-to-resume on a tool-call turn over the threshold (positive case preserved)", () => {
		const internals = session as unknown as SessionInternals;
		const toolCallTurn = makeAssistant(
			[
				{ type: "text", text: "Running a probe." },
				{ type: "toolCall", id: "call_1", name: "bash", arguments: { command: "echo hi" } },
			],
			"toolUse",
		);
		session.agent.state.messages = [toolCallTurn];

		expect(internals._shouldStopAfterTurnForCompaction(toolCallTurn)).toBe(true);
		// Resume flag set so the post-compaction path resumes the tool loop.
		expect(internals._resumeAfterTurnBoundaryCompaction).toBe(true);
	});
});

/**
 * opt #230 — the THIRD compaction-guard site (the error-branch usage-source
 * guard in _checkCompaction) uses strict `<` via isAssistantFromBeforeCompaction,
 * not inline `<=`.
 *
 * opt #226 routed the two main sites through the strict-`<` helper but missed
 * this third one. The error branch guards `usageMsg` (messages[lastUsageIndex]),
 * a DIFFERENT message from the `assistantMessage` arg. When usageMsg's timestamp
 * EQUALS the compaction entry's timestamp (a post-compaction error assistant
 * created in the same boundary ms), pre-fix `<=` classified it as stale →
 * returned false → skipped the threshold check → a preventable compaction was
 * missed. Post-fix strict `<` proceeds to shouldCompact.
 *
 * We mock shouldCompact as a spy returning false so the run does not enter
 * _runAutoCompaction. Pre-fix: the stale-skip returns before shouldCompact is
 * ever called. Post-fix: shouldCompact IS called. The spy call count is the
 * distinguishing assertion.
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { type AssistantMessage, getModel } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createTestResourceLoader } from "./utilities.ts";

const { shouldCompactMock } = vi.hoisted(() => ({ shouldCompactMock: vi.fn(() => false) }));

vi.mock("../src/core/compaction/index.js", () => ({
	calculateContextTokens: (usage: {
		totalTokens?: number;
		input: number;
		output: number;
		cacheRead: number;
		cacheWrite: number;
	}) => usage.totalTokens ?? usage.input + usage.output + usage.cacheRead + usage.cacheWrite,
	collectEntriesForBranchSummary: () => ({ entries: [], commonAncestorId: null }),
	compact: () => new Promise(() => {}),
	estimateContextTokens: () => ({ tokens: 99999, usageTokens: 99999, trailingTokens: 0, lastUsageIndex: 0 }),
	generateBranchSummary: async () => ({ summary: "", aborted: false, readFiles: [], modifiedFiles: [] }),
	isContextOverflow: () => false,
	prepareCompaction: () => ({ messagesToSummarize: [], turnPrefixMessages: [] }),
	shouldCompact: shouldCompactMock,
	stripTrailingErrorAssistants: (messages: Array<{ role: string }>) => messages,
}));

function makeAssistant(
	opts: Partial<AssistantMessage> & { timestamp: number; stopReason: string; provider: string; model: string },
): AssistantMessage {
	return {
		role: "assistant",
		content: [],
		api: "anthropic-messages",
		provider: opts.provider,
		model: opts.model,
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: opts.stopReason,
		timestamp: opts.timestamp,
	};
}

describe("opt #230: _checkCompaction error-branch usage-source guard uses strict < (not <=)", () => {
	let session: AgentSession;
	let sessionManager: SessionManager;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-opt230-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });

		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({ initialState: { model, systemPrompt: "Test", tools: [] } });

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
	});

	afterEach(() => {
		session.dispose();
		vi.restoreAllMocks();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("a same-ms post-compaction usage source is NOT stale → proceeds to shouldCompact (not skipped)", async () => {
		// Append a compaction entry; read back its (Date.now-derived) timestamp.
		sessionManager.appendCompaction("summary", "kept-1", 1000);
		const compactionEntry = sessionManager.getLatestCompactionOnBranch();
		expect(compactionEntry).not.toBeNull();
		const compactMs = new Date(compactionEntry!.timestamp).getTime();

		const model = session.model!;
		// usageMsg: an assistant whose timestamp EQUALS the compaction boundary ms
		// (the bug case — pre-fix `<=` treated this as stale).
		const usageMsg = makeAssistant({
			timestamp: compactMs,
			stopReason: "stop",
			provider: model.provider,
			model: model.id,
		});
		// The error assistant arg is strictly POST-compaction so the OUTER guard
		// (line 2342) does not skip — the third site is the only thing that can
		// short-circuit.
		const errorAssistant = makeAssistant({
			timestamp: compactMs + 100,
			stopReason: "error",
			provider: model.provider,
			model: model.id,
		});

		// estimateContextTokens mock returns lastUsageIndex:0 → usageMsg.
		(session.agent.state as { messages: AssistantMessage[] }).messages = [usageMsg];

		shouldCompactMock.mockClear();
		const result = await (
			session as unknown as { _checkCompaction: (m: AssistantMessage, skip?: boolean) => Promise<boolean> }
		)._checkCompaction(errorAssistant, false);

		// Post-fix: strict `<` → usageMsg NOT stale → the error branch proceeds to
		// shouldCompact (which returns false → _checkCompaction returns false without
		// running a compaction). Pre-fix: inline `<=` → usageMsg stale → returned
		// false BEFORE calling shouldCompact.
		expect(shouldCompactMock).toHaveBeenCalled();
		expect(result).toBe(false);
	}, 15000);
});

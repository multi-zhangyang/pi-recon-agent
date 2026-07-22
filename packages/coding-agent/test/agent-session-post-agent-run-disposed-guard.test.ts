/**
 * opt #232 — post-dispose post-run processing is suppressed so a committed
 * assistant from before dispose does NOT trigger compaction / continue on the
 * disposed session (cost + divergence leak).
 *
 * Finding 1: _handlePostAgentRun had no _disposed guard. A _lastAssistantMessage
 * set before _disconnectFromAgent (assistant committed via message_end mid-tool-
 * execution, then the user switched session) survived disconnect and fed the
 * while-loop: _checkCompaction could trip the threshold → _runAutoCompaction on
 * the session the user just left (cost leak + appendCompaction divergence), or
 * hasQueuedMessages() → agent.continue (pure cost leak). Fix: bail at the top of
 * _handlePostAgentRun when disposed.
 *
 * Finding 3: compact()'s finally-drain condition missed !this._disposed.
 * dispose() does NOT clear the agent steer queues, so hasQueuedMessages() could
 * be true after dispose → _continueQueuedMessages → the FIRST agent.continue()
 * (which runs before _handlePostAgentRun's guard) leaked one LLM run. Fix: add
 * !this._disposed && to the drain condition.
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { type AssistantMessage, getModel } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { createExtensionRuntime, type Extension } from "../src/core/extensions/index.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createSyntheticSourceInfo } from "../src/core/source-info.ts";
import { createTestResourceLoader } from "./utilities.ts";

const shouldCompactMock = vi.hoisted(() => ({ shouldCompactMock: vi.fn(() => false) }));
// Controllable compact() promise so Test B can resolve it to reach the
// session_compact emit (where the extension disposes the session).
const compactDeferred = vi.hoisted(() => ({
	resolve: (_v: unknown) => {},
	promise: new Promise(() => {}),
}));

vi.mock("../src/core/compaction/index.js", () => ({
	calculateContextTokens: (usage: {
		totalTokens?: number;
		input: number;
		output: number;
		cacheRead: number;
		cacheWrite: number;
	}) => usage.totalTokens ?? usage.input + usage.output + usage.cacheRead + usage.cacheWrite,
	collectEntriesForBranchSummary: () => ({ entries: [], commonAncestorId: null }),
	compact: () =>
		new Promise((resolve) => {
			compactDeferred.resolve = resolve as unknown as (_v: unknown) => void;
		}),
	estimateCompactionContext: () => ({ beforeTokens: 2, afterTokens: 1 }),
	estimateContextTokens: () => ({ tokens: 99999, usageTokens: 99999, trailingTokens: 0, lastUsageIndex: 0 }),
	generateBranchSummary: async () => ({ summary: "", aborted: false, readFiles: [], modifiedFiles: [] }),
	isContextOverflow: () => false,
	prepareCompaction: () => ({
		messagesToSummarize: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
		turnPrefixMessages: [],
	}),
	shouldCompact: shouldCompactMock.shouldCompactMock,
	stripTrailingErrorAssistants: (messages: Array<{ role: string }>) => messages,
}));

function makeAssistant(model: { provider: string; id: string }): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text: "done" }],
		api: "anthropic-messages",
		provider: model.provider,
		model: model.id,
		usage: {
			input: 10,
			output: 10,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 20,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
		timestamp: Date.now(),
	};
}

describe("opt #232: post-dispose post-run processing suppressed", () => {
	let session: AgentSession;
	let sessionManager: SessionManager;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-opt232-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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

	it("Finding 1: a disposed session does NOT run _checkCompaction on the pre-dispose assistant", async () => {
		const model = session.model!;
		const msg = makeAssistant(model);
		// Simulate the assistant committing via message_end before disconnect.
		(session as unknown as { _lastAssistantMessage: AssistantMessage })._lastAssistantMessage = msg;
		// No compaction entry → _checkCompaction proceeds to the threshold branch
		// and calls shouldCompact. hasQueuedMessages false so the only post-run
		// action that could fire is the compaction check.
		vi.spyOn(session.agent, "hasQueuedMessages").mockReturnValue(false);
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		// Dispose AFTER the assistant committed (the leak trigger).
		session.dispose();

		shouldCompactMock.shouldCompactMock.mockClear();
		const result = await (
			session as unknown as { _handlePostAgentRun: () => Promise<boolean> }
		)._handlePostAgentRun();

		// Post-fix: the disposed guard returns false BEFORE _checkCompaction, so
		// shouldCompact is never called and continue never runs. Pre-fix:
		// _checkCompaction ran → shouldCompactMock was called.
		expect(result).toBe(false);
		expect(shouldCompactMock.shouldCompactMock).not.toHaveBeenCalled();
		expect(continueSpy).not.toHaveBeenCalled();
	});
});

describe("opt #232 Finding 3: compact() finally-drain skips a disposed session", () => {
	let session: AgentSession;
	let sessionManager: SessionManager;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-opt232f3-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });

		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({ initialState: { model, systemPrompt: "Test", tools: [] } });

		sessionManager = SessionManager.inMemory();
		const settingsManager = SettingsManager.create(tempDir, tempDir);
		const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
		authStorage.setRuntimeApiKey("anthropic", "test-key");
		const modelRegistry = ModelRegistry.create(authStorage, tempDir);

		// Extension whose session_compact handler disposes the session mid-emit
		// (simulating ctx.switchSession()/ctx.newSession() disposing the old
		// session during the session_compact emit). This is the Finding-3 trigger:
		// drainQueuedAfterCompaction is set AFTER the emit, so the flag is true,
		// but the session is already disposed.
		const disposeRef: { dispose?: () => void } = {};
		const handlers = new Map<string, ((...args: unknown[]) => Promise<unknown>)[]>();
		handlers.set("session_compact", [
			async () => {
				disposeRef.dispose?.();
				return undefined;
			},
		]);
		const extension: Extension = {
			path: "test-extension",
			resolvedPath: "/test/test-extension.ts",
			sourceInfo: createSyntheticSourceInfo("<test:test-extension>", { source: "test" }),
			handlers,
			tools: new Map(),
			messageRenderers: new Map(),
			commands: new Map(),
			flags: new Map(),
			shortcuts: new Map(),
		};
		const runtime = createExtensionRuntime();
		const resourceLoader = {
			...createTestResourceLoader(),
			getExtensions: () => ({ extensions: [extension], errors: [], runtime }),
		};

		session = new AgentSession({
			agent,
			sessionManager,
			settingsManager,
			cwd: tempDir,
			modelRegistry,
			resourceLoader,
		});
		disposeRef.dispose = () => session.dispose();
	});

	afterEach(() => {
		session.dispose();
		vi.restoreAllMocks();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("a session disposed during the session_compact emit does NOT drain via agent.continue", async () => {
		// Seed a user message so prepareCompaction has branch content.
		sessionManager.appendMessage({ role: "user", content: [{ type: "text", text: "hello" }], timestamp: Date.now() });
		// Queued steer present → drainQueuedAfterCompaction becomes true after emit.
		vi.spyOn(session.agent, "hasQueuedMessages").mockReturnValue(true);
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		const compactCall = session.compact();
		// Let compact() reach the compact() await and capture its resolver.
		await new Promise((r) => setTimeout(r, 0));
		await new Promise((r) => setTimeout(r, 0));
		// Resolve compact() → the path proceeds to appendCompaction + emit
		// session_compact, where the extension disposes the session. The finally
		// then evaluates the drain condition with _disposed=true.
		compactDeferred.resolve({ summary: "s", firstKeptEntryId: "k", tokensBefore: 100, details: {} });
		await compactCall;

		// Post-fix: drain condition has !this._disposed → skipped → no continue.
		// Pre-fix: drain ran → _continueQueuedMessages → agent.continue (leak).
		expect(continueSpy).not.toHaveBeenCalled();
	}, 15000);
});

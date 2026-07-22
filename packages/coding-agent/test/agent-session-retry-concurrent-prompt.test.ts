import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { type AssistantMessage, type AssistantMessageEvent, EventStream, getModel } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createTestResourceLoader } from "./utilities.ts";

// opt #118 — during auto-retry backoff, isStreaming is false (the previous run
// ended with agent_end; the retry is just awaiting its backoff sleep inside
// _handlePostAgentRun's while-loop). The isStreaming guard alone in prompt()
// let a concurrent prompt() through → it raced with the pending retry
// continuation (two control flows both calling agent.prompt/continue on the
// same state). Fix: prompt() treats isRetrying like isStreaming — require
// streamingBehavior to queue (the retried agent.continue() drains the steer
// queue), else reject.

class MockAssistantStream extends EventStream<AssistantMessageEvent, AssistantMessage> {
	constructor() {
		super(
			(event) => event.type === "done" || event.type === "error",
			(event) => {
				if (event.type === "done") return event.message;
				if (event.type === "error") return event.error;
				throw new Error("Unexpected event type");
			},
		);
	}
}

function createAssistantMessage(text: string, overrides?: Partial<AssistantMessage>): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
		api: "anthropic-messages",
		provider: "anthropic",
		model: "mock",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
		timestamp: Date.now(),
		...overrides,
	};
}

async function waitForRetry(session: AgentSession, timeoutMs = 2000): Promise<void> {
	const start = Date.now();
	while (!session.isRetrying) {
		if (Date.now() - start > timeoutMs) throw new Error("retry window never opened");
		await new Promise((resolve) => setTimeout(resolve, 1));
	}
}

describe("AgentSession prompt() during auto-retry backoff (opt #118)", () => {
	let session: AgentSession;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-retry-concurrent-${Date.now()}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		if (session) session.dispose();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true });
	});

	function createSession(options?: { failCount?: number; baseDelayMs?: number }): {
		session: AgentSession;
		getCallCount: () => number;
		getStreamingStates: () => boolean[];
	} {
		const failCount = options?.failCount ?? 99;
		const baseDelayMs = options?.baseDelayMs ?? 5000;
		let callCount = 0;
		const streamingStates: boolean[] = [];
		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({
			getApiKey: () => "test-key",
			initialState: { model, systemPrompt: "Test", tools: [] },
			streamFn: () => {
				callCount++;
				streamingStates.push(session?.isStreaming ?? false);
				const stream = new MockAssistantStream();
				queueMicrotask(() => {
					if (callCount <= failCount) {
						// Retryable error so the retry window opens.
						const msg = createAssistantMessage("", {
							stopReason: "error",
							errorMessage: "overloaded_error",
						});
						stream.push({ type: "start", partial: msg });
						stream.push({ type: "error", reason: "error", error: msg });
					} else {
						const msg = createAssistantMessage("Success");
						stream.push({ type: "start", partial: msg });
						stream.push({ type: "done", reason: "stop", message: msg });
					}
				});
				return stream;
			},
		});

		const sessionManager = SessionManager.inMemory();
		const settingsManager = SettingsManager.create(tempDir, tempDir);
		const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
		const modelRegistry = ModelRegistry.create(authStorage, tempDir);
		authStorage.setRuntimeApiKey("anthropic", "test-key");
		// Long backoff so the retry window stays open for the concurrent prompt.
		settingsManager.applyOverrides({ retry: { enabled: true, maxRetries: 3, baseDelayMs } });

		session = new AgentSession({
			agent,
			sessionManager,
			settingsManager,
			cwd: tempDir,
			modelRegistry,
			resourceLoader: createTestResourceLoader(),
		});

		return { session, getCallCount: () => callCount, getStreamingStates: () => [...streamingStates] };
	}

	it("rejects a concurrent prompt() with no streamingBehavior during retry backoff (no race)", async () => {
		const { session } = createSession();
		// Start a prompt that will fail and enter the retry backoff.
		const firstPromise = session.prompt("first");

		// Wait for the retry window to open (isStreaming is false, isRetrying true).
		await waitForRetry(session);
		expect(session.isRetrying).toBe(true);
		expect(session.isStreaming).toBe(false);

		// A concurrent prompt with no streamingBehavior must be rejected — pre-fix
		// it fell through to _runAgentPrompt and raced with the pending retry.
		await expect(session.prompt("concurrent")).rejects.toThrow(/already processing/i);

		// Abort the retry so the first prompt unwinds and the test completes.
		session.abortRetry();
		await firstPromise.catch(() => undefined);
	}, 15000);

	it("queues a concurrent prompt() with streamingBehavior:'steer' during retry backoff", async () => {
		// failCount=1: the retry itself succeeds, so the loop terminates instead
		// of re-sleeping (a steered message triggers a continuation → another
		// agent run; with failCount=99 that would re-enter retry and re-sleep).
		const { session, getCallCount, getStreamingStates } = createSession({ failCount: 1, baseDelayMs: 1000 });
		const firstPromise = session.prompt("first");
		await waitForRetry(session);

		// With streamingBehavior, the concurrent prompt queues (no throw, no race).
		await expect(session.prompt("concurrent", { streamingBehavior: "steer" })).resolves.toBeUndefined();

		// Let the retry succeed and the steered message drain; firstPromise resolves.
		await firstPromise;
		// The retried run + the steered continuation both ran.
		expect(getCallCount()).toBeGreaterThanOrEqual(2);
		// The controller only represents backoff. Once the retry request starts it
		// has been cleared, so active provider work must be observable as streaming.
		expect(getStreamingStates().slice(0, 2)).toEqual([true, true]);
		expect(session.isRetrying).toBe(false);
	}, 15000);
});

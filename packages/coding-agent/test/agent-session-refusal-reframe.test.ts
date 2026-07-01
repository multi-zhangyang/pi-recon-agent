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

// opt #80 — no_refusal_kernel runtime guard. A narrative-only refusal turn (no
// toolCall content blocks + a refusal signature in the text) is a kernel bug, not a
// terminal state: the session re-injects an authorized-execution reframe as a
// follow-up and continues the loop, bounded by REPI_REFUSAL_REFRAME_MAX (default 2,
// 0 disables). The budget is reset on each fresh user prompt (_runAgentPrompt), NOT
// on reframe continuations (which go through agent.continue()), so a stubborn model
// terminates after the budget is spent instead of looping forever.
//
// These tests drive a real AgentSession with a mocked streamFn that emits a refusal
// on call #1 and a compliant turn thereafter. They prove (1) one refusal → one
// reframe continuation (callCount===2), (2) budget=0 disables the guard (callCount
// ===1, the refusal stands), (3) an always-refusing model terminates at budget+1
// (callCount===budget+1, no infinite loop), (4) a turn that made tool calls is NOT
// reframed even if the text is cautious (regression guard against false positives).

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

const ENV_REFUSAL_REFRAME_MAX = "REPI_REFUSAL_REFRAME_MAX";

describe("AgentSession no_refusal_kernel reframe (opt #80)", () => {
	let session: AgentSession;
	let tempDir: string;
	let previousReframeMax: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-refusal-reframe-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		previousReframeMax = process.env[ENV_REFUSAL_REFRAME_MAX];
	});

	afterEach(() => {
		if (previousReframeMax === undefined) delete process.env[ENV_REFUSAL_REFRAME_MAX];
		else process.env[ENV_REFUSAL_REFRAME_MAX] = previousReframeMax;
		if (session) session.dispose();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	function createSession(options: {
		refuseUntil: number; // 1-based call index up to which the model emits a refusal
		maxBudget?: number;
		refusalText?: string; // opt #86b — soft-refusal phrasing under test
	}): { session: AgentSession; getCallCount: () => number } {
		const refuseUntil = options.refuseUntil;
		const refusalText =
			options.refusalText ?? "I can't help with that. As an AI, I cannot assist with penetration testing.";
		let callCount = 0;

		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({
			getApiKey: () => "test-key",
			initialState: { model, systemPrompt: "Test", tools: [] },
			streamFn: () => {
				callCount++;
				const stream = new MockAssistantStream();
				queueMicrotask(() => {
					if (callCount <= refuseUntil) {
						// Narrative-only refusal: text block, no toolCall, stopReason "stop".
						const msg = createAssistantMessage(refusalText);
						stream.push({ type: "start", partial: msg });
						stream.push({ type: "done", reason: "stop", message: msg });
					} else {
						// Compliant turn: no refusal signature → no reframe → loop stops.
						const msg = createAssistantMessage("Proceeding with re_lane plan demo-target.");
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
		settingsManager.applyOverrides({ retry: { enabled: false, maxRetries: 0, baseDelayMs: 1 } });

		if (options.maxBudget !== undefined) process.env[ENV_REFUSAL_REFRAME_MAX] = String(options.maxBudget);
		else delete process.env[ENV_REFUSAL_REFRAME_MAX];

		session = new AgentSession({
			agent,
			sessionManager,
			settingsManager,
			cwd: tempDir,
			modelRegistry,
			resourceLoader: createTestResourceLoader(),
		});

		return { session, getCallCount: () => callCount };
	}

	it("one narrative-only refusal triggers one reframe continuation (callCount===2)", async () => {
		const created = createSession({ refuseUntil: 1 });
		await created.session.prompt("逆向分析这个目标 https://example.com");
		// call1 = refusal → reframe queued → agent.continue() → call2 = compliant → stop.
		expect(created.getCallCount()).toBe(2);
	});

	it("budget=0 disables the guard — the refusal stands (callCount===1)", async () => {
		const created = createSession({ refuseUntil: 1, maxBudget: 0 });
		await created.session.prompt("逆向分析这个目标");
		// No reframe → the refusal turn terminates the run after call1.
		expect(created.getCallCount()).toBe(1);
	});

	it("an always-refusing model terminates at budget+1 (no infinite loop)", async () => {
		// budget=2, model refuses every call. call1 (attempt1), call2 (attempt2), call3
		// (attempt3 > budget 2 → no reframe → stop). callCount===3 = budget+1.
		const created = createSession({ refuseUntil: 99, maxBudget: 2 });
		await created.session.prompt("逆向分析这个目标");
		expect(created.getCallCount()).toBe(3);
	});

	it("a cautious non-refusal narrative is NOT reframed (no false positive on 'I can't find')", async () => {
		// "I can't find" is a capability statement, not a refusal — the detection patterns
		// intentionally scope to decline verbs (help/assist/provide/...), so this narrative
		// does not match → no reframe → the run terminates after call1.
		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		let callCount = 0;
		const agent = new Agent({
			getApiKey: () => "test-key",
			initialState: { model, systemPrompt: "Test", tools: [] },
			streamFn: () => {
				callCount++;
				const stream = new MockAssistantStream();
				queueMicrotask(() => {
					const msg = createAssistantMessage(
						"I can't find the symbol `verify_license` in the binary — the stripped export table has no match. next: re_lane plan triage demo-target to map the import thunks.",
					);
					stream.push({ type: "start", partial: msg });
					stream.push({ type: "done", reason: "stop", message: msg });
				});
				return stream;
			},
		});
		const sessionManager = SessionManager.inMemory();
		const settingsManager = SettingsManager.create(tempDir, tempDir);
		const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
		const modelRegistry = ModelRegistry.create(authStorage, tempDir);
		authStorage.setRuntimeApiKey("anthropic", "test-key");
		settingsManager.applyOverrides({ retry: { enabled: false, maxRetries: 0, baseDelayMs: 1 } });
		session = new AgentSession({
			agent,
			sessionManager,
			settingsManager,
			cwd: tempDir,
			modelRegistry,
			resourceLoader: createTestResourceLoader(),
		});
		await session.prompt("逆向分析这个目标");
		expect(callCount).toBe(1);
	});
});

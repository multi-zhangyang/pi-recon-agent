import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { type AssistantMessage, type AssistantMessageEvent, EventStream, getModel } from "@pi-recon/repi-ai";
import { describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createTestResourceLoader } from "./utilities.ts";

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

function createAssistantMessage(text: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
		api: "anthropic-messages",
		provider: "anthropic",
		model: "claude-sonnet-4-5",
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
	};
}

function createSession(): { session: AgentSession; cleanup: () => void } {
	const tempDir = join(tmpdir(), `pi-audit-f1-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	mkdirSync(tempDir, { recursive: true });

	const model = getModel("anthropic", "claude-sonnet-4-5");
	if (!model) throw new Error("Test model not found");

	const agent = new Agent({
		getApiKey: () => "test-key",
		initialState: { model, systemPrompt: "Test", tools: [] },
		streamFn: () => {
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				stream.push({ type: "done", reason: "stop", message: createAssistantMessage("ok") });
			});
			return stream;
		},
	});

	const sessionManager = SessionManager.inMemory();
	const settingsManager = SettingsManager.create(tempDir, tempDir);
	const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
	const modelRegistry = ModelRegistry.create(authStorage, tempDir);

	const session = new AgentSession({
		agent,
		sessionManager,
		settingsManager,
		cwd: tempDir,
		modelRegistry,
		resourceLoader: createTestResourceLoader(),
	});

	return {
		session,
		cleanup: () => {
			if (existsSync(tempDir)) rmSync(tempDir, { recursive: true });
		},
	};
}

describe("F1: AgentSession.dispose disposes _agentThreadManager", () => {
	it("disposes the lazily-created AgentThreadManager with reason session_replaced", () => {
		const { session, cleanup } = createSession();
		try {
			// Touch the lazy getter so the private _agentThreadManager field is
			// populated. Dispose must tear it down so its process.on("exit") reaper
			// hook is removed and in-flight children are killed.
			const manager = session.agentThreadManager;
			const disposeSpy = vi.spyOn(manager, "dispose");

			session.dispose();

			expect(disposeSpy).toHaveBeenCalledTimes(1);
			expect(disposeSpy).toHaveBeenCalledWith("session_replaced");
		} finally {
			cleanup();
		}
	});

	it("does not throw when agentThreadManager was never accessed (field undefined)", () => {
		const { session, cleanup } = createSession();
		try {
			// Never touch the getter — _agentThreadManager stays undefined. dispose
			// must skip the thread-manager cleanup without error.
			expect(() => session.dispose()).not.toThrow();
		} finally {
			cleanup();
		}
	});
});

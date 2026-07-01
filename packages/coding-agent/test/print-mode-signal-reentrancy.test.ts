import type { AssistantMessage } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it, vi } from "vitest";

const printIo = vi.hoisted(() => ({ killTracked: 0 }));

// Mock output-guard so the signal path's flushRawStdout is a no-op (we assert
// on session.abort / session.prompt call counts, not stdout).
vi.mock("../src/core/output-guard.ts", () => ({
	flushRawStdout: vi.fn(async () => {}),
	writeRawStdout: (_line: string) => {},
}));

// Mock shell so killTrackedDetachedChildren is a no-op in the signal handler.
vi.mock("../src/utils/shell.ts", () => ({
	killTrackedDetachedChildren: vi.fn(() => {
		printIo.killTracked += 1;
	}),
}));

import { runPrintMode } from "../src/modes/print-mode.ts";

type FakeSession = {
	sessionManager: { getHeader: () => object | undefined };
	agent: { waitForIdle: ReturnType<typeof vi.fn<() => Promise<void>>> };
	state: { messages: AssistantMessage[] };
	extensionRunner: { hasHandlers: (t: string) => boolean; emit: ReturnType<typeof vi.fn> };
	bindExtensions: ReturnType<typeof vi.fn>;
	subscribe: ReturnType<typeof vi.fn>;
	prompt: ReturnType<typeof vi.fn>;
	abort: ReturnType<typeof vi.fn>;
};

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

function createRuntimeHost(session: FakeSession) {
	return {
		session,
		newSession: vi.fn(async () => undefined),
		fork: vi.fn(async () => ({ selectedText: "" })),
		switchSession: vi.fn(async () => undefined),
		dispose: vi.fn(async () => {
			await session.extensionRunner.emit({ type: "session_shutdown", reason: "quit" });
		}),
		setRebindSession: vi.fn(),
	};
}

function makeSession(opts: { resolvePromptOnAbort?: () => void; pendingPrompt?: boolean }): {
	session: FakeSession;
	resolvePrompt: () => void;
} {
	const extensionRunner = {
		hasHandlers: (t: string) => t === "session_shutdown",
		emit: vi.fn(async () => {}),
	};
	let resolvePrompt: (() => void) | undefined;
	const session: FakeSession = {
		sessionManager: { getHeader: () => undefined },
		agent: { waitForIdle: vi.fn(async () => {}) },
		state: { messages: [createAssistantMessage("partial")] },
		extensionRunner,
		bindExtensions: vi.fn(async () => {}),
		subscribe: vi.fn(() => () => {}),
		prompt: vi.fn(
			() =>
				new Promise<void>((resolve) => {
					resolvePrompt = resolve;
				}),
		),
		abort: vi.fn(async () => {
			// Resolving the in-flight prompt lets the main loop proceed so we can
			// observe whether it starts a NEW prompt after the signal.
			opts.resolvePromptOnAbort?.();
			resolvePrompt?.();
		}),
	};
	return { session, resolvePrompt: () => resolvePrompt?.() };
}

describe("print-mode signal handler re-entrancy + no-new-prompt-after-shutdown (opt #199)", () => {
	afterEach(() => {
		vi.useRealTimers();
		vi.restoreAllMocks();
		printIo.killTracked = 0;
	});

	it("a second signal during the abort→flush window does NOT re-enter the handler (no duplicate abort/flush)", async () => {
		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation((() => {}) as (code?: string | number | null | undefined) => never) as ReturnType<
			typeof vi.spyOn
		>;

		const { session } = makeSession({});
		const runtimeHost = createRuntimeHost(session);

		const runPromise = runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "json",
			initialMessage: "hello",
		});
		await vi.waitFor(() => expect(session.subscribe).toHaveBeenCalled());

		// Fire the signal twice in rapid succession. Without the shuttingDown
		// guard the second emit re-enters the handler → session.abort is called a
		// SECOND time and flushRawStdout runs twice (duplicate stdout). With the
		// guard, the second emit force-exits before reaching session.abort.
		process.emit("SIGTERM", "SIGTERM");
		process.emit("SIGTERM", "SIGTERM");

		await vi.waitFor(() => expect(exitSpy).toHaveBeenCalled());

		// Exactly ONE abort — the second signal must not re-enter the handler.
		expect(session.abort).toHaveBeenCalledTimes(1);

		await runPromise;
		exitSpy.mockRestore();
	});

	it("does not start a new prompt on a session being disposed after a signal (no partial un-persisted turn)", async () => {
		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation((() => {}) as (code?: string | number | null | undefined) => never) as ReturnType<
			typeof vi.spyOn
		>;

		const { session } = makeSession({});
		const runtimeHost = createRuntimeHost(session);

		// Two messages: the first is in-flight when the signal fires; after abort
		// resolves it the main loop must NOT start the second prompt.
		const runPromise = runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "json",
			messages: ["m1", "m2"],
		});
		await vi.waitFor(() => expect(session.subscribe).toHaveBeenCalled());
		await vi.waitFor(() => expect(session.prompt).toHaveBeenCalledTimes(1));

		process.emit("SIGTERM", "SIGTERM");

		// abort() resolves the in-flight m1 prompt; the loop then considers m2.
		await vi.waitFor(() => expect(session.abort).toHaveBeenCalled());
		// Let the abort→flush→exit chain and the main loop settle.
		await vi.waitFor(() => expect(exitSpy).toHaveBeenCalled());

		// session.prompt must have been called exactly ONCE (m1 only). Without
		// the shuttingDown guard the loop starts m2 → a second session.prompt on
		// a session the handler is concurrently disposing.
		expect(session.prompt).toHaveBeenCalledTimes(1);

		await runPromise;
		exitSpy.mockRestore();
	});
});

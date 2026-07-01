import type { AssistantMessage } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it, vi } from "vitest";

const printIo = vi.hoisted(() => ({
	flushCalls: 0,
	outputLines: [] as string[],
	killTracked: 0,
}));

// Mock output-guard so we can observe flushRawStdout calls without touching the
// real stdout tail, and so writeRawStdout records lines instead of writing.
vi.mock("../src/core/output-guard.ts", () => ({
	flushRawStdout: vi.fn(async () => {
		printIo.flushCalls += 1;
	}),
	writeRawStdout: (line: string) => {
		printIo.outputLines.push(line);
	},
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

describe("F2: print-mode signal path flushes raw stdout in json mode", () => {
	let exitSpy: ReturnType<typeof vi.spyOn>;
	let exitCalled = false;

	afterEach(() => {
		vi.useRealTimers();
		vi.restoreAllMocks();
		printIo.flushCalls = 0;
		printIo.outputLines = [];
		printIo.killTracked = 0;
		exitCalled = false;
	});

	it("calls flushRawStdout on SIGTERM in json mode (not skipped because mode !== text)", async () => {
		exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
			exitCalled = true;
		}) as (code?: string | number | null | undefined) => never) as ReturnType<typeof vi.spyOn>;

		const extensionRunner = {
			hasHandlers: (t: string) => t === "session_shutdown",
			emit: vi.fn(async () => {}),
		};
		let resolvePrompt: (() => void) | undefined;
		const session: FakeSession = {
			sessionManager: { getHeader: () => undefined },
			agent: { waitForIdle: vi.fn(async () => {}) },
			state: { messages: [createAssistantMessage("done")] },
			extensionRunner,
			bindExtensions: vi.fn(async () => {}),
			subscribe: vi.fn(() => () => {}),
			prompt: vi.fn(
				() =>
					new Promise<void>((resolve) => {
						resolvePrompt = resolve;
					}),
			),
			abort: vi.fn(async () => {}),
		};
		const runtimeHost = createRuntimeHost(session);

		// Start print mode in json mode. The prompt stays pending so the signal
		// handler runs while the run is in-flight (before the finally cleanup
		// removes the signal listeners).
		const runPromise = runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "json",
			initialMessage: "hello",
		});

		// Wait for rebindSession to wire up the subscriber (ensures signal handlers
		// are registered by then too).
		await vi.waitFor(() => expect(session.subscribe).toHaveBeenCalled());

		const flushCallsBeforeSignal = printIo.flushCalls;
		// Emit SIGTERM to trigger the signal handler.
		process.emit("SIGTERM", "SIGTERM");

		// The signal path must flush raw stdout (the bug: json mode skipped it
		// because flushAssistantText returns immediately when mode !== "text").
		await vi.waitFor(() => {
			expect(printIo.flushCalls).toBeGreaterThan(flushCallsBeforeSignal);
			expect(exitCalled).toBe(true);
		});

		expect(printIo.killTracked).toBe(1);

		// Let the run finish so the promise settles and the test does not leak.
		resolvePrompt?.();
		await runPromise;

		exitSpy.mockRestore();
	});

	it("does not lose the trailing json event queued in rawStdoutWriteTail on signal exit", async () => {
		// Restore process.exit mock fresh for this test.
		exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
			exitCalled = true;
		}) as (code?: string | number | null | undefined) => never) as ReturnType<typeof vi.spyOn>;

		const { flushRawStdout } = await import("../src/core/output-guard.ts");
		const flushMock = flushRawStdout as unknown as { mock: { calls: unknown[] } };

		const extensionRunner = {
			hasHandlers: (t: string) => t === "session_shutdown",
			emit: vi.fn(async () => {}),
		};
		let resolvePrompt: (() => void) | undefined;
		const session: FakeSession = {
			sessionManager: { getHeader: () => undefined },
			agent: { waitForIdle: vi.fn(async () => {}) },
			state: { messages: [createAssistantMessage("done")] },
			extensionRunner,
			bindExtensions: vi.fn(async () => {}),
			subscribe: vi.fn(() => () => {}),
			prompt: vi.fn(
				() =>
					new Promise<void>((resolve) => {
						resolvePrompt = resolve;
					}),
			),
			abort: vi.fn(async () => {}),
		};
		const runtimeHost = createRuntimeHost(session);

		const runPromise = runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "json",
			initialMessage: "hello",
		});
		await vi.waitFor(() => expect(session.subscribe).toHaveBeenCalled());

		const callsBefore = flushMock.mock.calls.length;
		process.emit("SIGTERM", "SIGTERM");
		await vi.waitFor(() => expect(exitCalled).toBe(true));

		// The signal path invoked flushRawStdout at least once after the signal.
		expect(flushMock.mock.calls.length).toBeGreaterThan(callsBefore);

		resolvePrompt?.();
		await runPromise;

		exitSpy.mockRestore();
	});
});

describe("F3: print-mode SIGINT path flushes partial output and exits 130 (opt #62)", () => {
	// Before opt #62, SIGINT (Ctrl+C) was NOT in the signal-handler list — only
	// SIGTERM/SIGHUP. Ctrl+C took the default-exit path: no session.abort(), no
	// flushAssistantText(), no flushRawStdout() → partial assistant text was LOST
	// (the opt #2 data-loss class, reopened for SIGINT). Now SIGINT runs the same
	// abort→flush→write→exit path and exits 130 (128 + SIGINT=2).
	it("calls flushRawStdout and exits 130 on SIGINT in json mode", async () => {
		let exitCode: number | undefined;
		const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
			exitCode = code;
		}) as (code?: string | number | null | undefined) => never) as ReturnType<typeof vi.spyOn>;

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
			abort: vi.fn(async () => {}),
		};
		const runtimeHost = createRuntimeHost(session);

		const runPromise = runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "json",
			initialMessage: "hello",
		});
		await vi.waitFor(() => expect(session.subscribe).toHaveBeenCalled());

		const flushCallsBeforeSignal = printIo.flushCalls;
		process.emit("SIGINT", "SIGINT");

		await vi.waitFor(() => {
			expect(printIo.flushCalls).toBeGreaterThan(flushCallsBeforeSignal);
			expect(exitCode).toBe(130);
		});
		// The abort path ran (session.abort was invoked by the handler).
		expect(session.abort).toHaveBeenCalled();

		resolvePrompt?.();
		await runPromise;
		exitSpy.mockRestore();
	});
});

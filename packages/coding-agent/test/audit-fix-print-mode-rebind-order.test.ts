import type { AssistantMessage } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runPrintMode } from "../src/modes/print-mode.ts";

type FakeExtensionRunner = {
	hasHandlers: (eventType: string) => boolean;
	emit: ReturnType<typeof vi.fn<(event: unknown) => Promise<void>>>;
};

type FakeSession = {
	sessionManager: { getHeader: () => object | undefined };
	agent: { waitForIdle: ReturnType<typeof vi.fn<() => Promise<void>>> };
	state: { messages: AssistantMessage[] };
	extensionRunner: FakeExtensionRunner;
	bindExtensions: ReturnType<typeof vi.fn>;
	subscribe: ReturnType<typeof vi.fn<(listener: (event: unknown) => void) => () => void>>;
	prompt: ReturnType<typeof vi.fn>;
	reload: ReturnType<typeof vi.fn>;
	abort?: ReturnType<typeof vi.fn>;
};

type FakeRuntimeHost = {
	session: FakeSession;
	newSession: ReturnType<typeof vi.fn>;
	fork: ReturnType<typeof vi.fn>;
	switchSession: ReturnType<typeof vi.fn>;
	dispose: ReturnType<typeof vi.fn>;
	setRebindSession: ReturnType<typeof vi.fn>;
};

function createAssistantMessage(text: string): AssistantMessage {
	return {
		role: "assistant",
		content: [{ type: "text", text }],
		api: "openai-responses",
		provider: "openai",
		model: "gpt-4o-mini",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "stop",
		errorMessage: undefined,
		timestamp: Date.now(),
	};
}

function createRuntimeHost(assistantMessage: AssistantMessage): FakeRuntimeHost {
	const extensionRunner: FakeExtensionRunner = {
		hasHandlers: () => false,
		emit: vi.fn(async () => {}),
	};
	const state = { messages: [assistantMessage] };
	const session: FakeSession = {
		sessionManager: { getHeader: () => undefined },
		agent: { waitForIdle: vi.fn(async () => {}) },
		state,
		extensionRunner,
		bindExtensions: vi.fn(async () => {}),
		subscribe: vi.fn(() => () => {}),
		prompt: vi.fn(async () => {}),
		reload: vi.fn(async () => {}),
		abort: vi.fn(async () => {}),
	};
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

afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
	delete process.env.REPI_PRODUCT;
	delete process.env.REPI_PRINT_TIMEOUT_MS;
});

describe("print-mode rebindSession ordering (Finding F4)", () => {
	it("removes the old forwarder and attaches a new one even when bindExtensions throws", async () => {
		const runtimeHost = createRuntimeHost(createAssistantMessage("done"));
		const { session } = runtimeHost;
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		// Capture the rebind callback registered with the runtime host.
		let rebindFn: (() => Promise<void>) | undefined;
		runtimeHost.setRebindSession.mockImplementation((fn: () => Promise<void>) => {
			rebindFn = fn;
		});

		// Track every unsubscribe handle handed out by subscribe, and whether it
		// was invoked. unsubs[0] is the initial subscription established during
		// the startup rebind; unsubs[1] would be the re-established forwarder.
		const unsubs: Array<{ called: boolean }> = [];
		session.subscribe.mockImplementation(() => {
			const spy = { called: false };
			unsubs.push(spy);
			return () => {
				spy.called = true;
			};
		});

		// Hold the prompt pending so runPrintMode stays alive at the prompt stage
		// (past the startup rebind) while we trigger a second, failing rebind.
		let resolvePrompt: () => void = () => {};
		session.prompt.mockImplementation(
			() =>
				new Promise<void>((resolve) => {
					resolvePrompt = resolve;
				}),
		);

		const run = runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "text",
			initialMessage: "x",
		});

		// Wait for the startup rebindSession to complete (subscribe #1) and the
		// prompt to be awaited.
		await vi.waitFor(() => expect(unsubs.length).toBe(1));
		expect(rebindFn).toBeDefined();

		// Now make bindExtensions throw (e.g. an extension session_start error)
		// and trigger a rebind, as a session switch would.
		session.bindExtensions.mockImplementation(() => Promise.reject(new Error("extension session_start error")));
		await expect(rebindFn!()).rejects.toThrow("extension session_start error");

		// (a) The OLD session's event forwarder was removed even though
		//     bindExtensions threw (unsubscribe ran before bindExtensions).
		expect(unsubs[0].called).toBe(true);
		// (b) A NEW forwarder was attached on the new session even though
		//     bindExtensions threw (subscribe ran in the finally block).
		expect(unsubs.length).toBe(2);

		// Let runPrintMode finish cleanly.
		resolvePrompt();
		await run;
		errorSpy.mockRestore();
	});
});

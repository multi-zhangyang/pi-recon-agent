import type { AssistantMessage, ImageContent } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionShutdownEvent } from "../src/index.ts";
import { runPrintMode } from "../src/modes/print-mode.ts";

type EmitEvent = SessionShutdownEvent;

type FakeExtensionRunner = {
	hasHandlers: (eventType: string) => boolean;
	emit: ReturnType<typeof vi.fn<(event: EmitEvent) => Promise<void>>>;
};

type FakeSession = {
	sessionManager: { getHeader: () => object | undefined };
	agent: { waitForIdle: ReturnType<typeof vi.fn<() => Promise<void>>> };
	state: { messages: AssistantMessage[] };
	extensionRunner: FakeExtensionRunner;
	bindExtensions: ReturnType<typeof vi.fn>;
	subscribe: ReturnType<typeof vi.fn<(listener: (event: any) => void) => () => void>>;
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

function createAssistantMessage(options?: {
	text?: string;
	stopReason?: AssistantMessage["stopReason"];
	errorMessage?: string;
}): AssistantMessage {
	return {
		role: "assistant",
		content: options?.text ? [{ type: "text", text: options.text }] : [],
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
		stopReason: options?.stopReason ?? "stop",
		errorMessage: options?.errorMessage,
		timestamp: Date.now(),
	};
}

function createRuntimeHost(assistantMessage: AssistantMessage): FakeRuntimeHost {
	const extensionRunner: FakeExtensionRunner = {
		hasHandlers: (eventType: string) => eventType === "session_shutdown",
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
	delete process.env.REPI_PRIMARY;
	delete process.env.REPI_PRINT_PROGRESS;
	delete process.env.REPI_PRINT_TIMEOUT_MS;
	delete process.env.REPI_PRINT_TIMEOUT_GRACE_MS;
	delete process.env.REPI_PRINT_TIMEOUT_TOOL_GRACE_MS;
	delete process.env.REPI_PRINT_STREAM_TEXT;
});

describe("runPrintMode", () => {
	it("emits session_shutdown in text mode", async () => {
		const runtimeHost = createRuntimeHost(createAssistantMessage({ text: "done" }));
		const { session } = runtimeHost;
		const images: ImageContent[] = [{ type: "image", mimeType: "image/png", data: "abc" }];

		const exitCode = await runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "text",
			initialMessage: "Say done",
			initialImages: images,
		});

		expect(exitCode).toBe(0);
		expect(session.prompt).toHaveBeenCalledWith("Say done", { images });
		expect(session.extensionRunner.emit).toHaveBeenCalledTimes(1);
		expect(session.extensionRunner.emit).toHaveBeenCalledWith({ type: "session_shutdown", reason: "quit" });
	});

	it("emits session_shutdown in json mode", async () => {
		const runtimeHost = createRuntimeHost(createAssistantMessage({ text: "done" }));
		const { session } = runtimeHost;

		const exitCode = await runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "json",
			messages: ["hello"],
		});

		expect(exitCode).toBe(0);
		expect(session.prompt).toHaveBeenCalledWith("hello", undefined);
		expect(session.extensionRunner.emit).toHaveBeenCalledTimes(1);
		expect(session.extensionRunner.emit).toHaveBeenCalledWith({ type: "session_shutdown", reason: "quit" });
	});

	it("emits session_shutdown and returns non-zero on assistant error", async () => {
		const runtimeHost = createRuntimeHost(
			createAssistantMessage({ stopReason: "error", errorMessage: "provider failure" }),
		);
		const { session } = runtimeHost;
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const exitCode = await runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "text",
			initialMessage: "trigger provider failure",
		});

		expect(exitCode).toBe(1);
		expect(errorSpy).toHaveBeenCalledWith("provider failure");
		expect(session.extensionRunner.emit).toHaveBeenCalledTimes(1);
		expect(session.extensionRunner.emit).toHaveBeenCalledWith({ type: "session_shutdown", reason: "quit" });
	});

	it("allows a short assistant-output grace after print timeout", async () => {
		vi.useFakeTimers();
		process.env.REPI_PRODUCT = "1";
		process.env.REPI_PRINT_PROGRESS = "1";
		process.env.REPI_PRINT_TIMEOUT_MS = "10";
		process.env.REPI_PRINT_TIMEOUT_GRACE_MS = "50";
		const runtimeHost = createRuntimeHost(createAssistantMessage({ text: "" }));
		const { session } = runtimeHost;
		let listener: ((event: any) => void) | undefined;
		session.subscribe.mockImplementation((fn) => {
			listener = fn;
			return () => {};
		});
		session.prompt.mockImplementation(
			() =>
				new Promise<void>((resolve) => {
					listener?.({ type: "message_start", message: { role: "assistant" } });
					setTimeout(() => {
						session.state.messages = [createAssistantMessage({ text: "finished during grace" })];
						listener?.({ type: "message_end", message: { role: "assistant" } });
						resolve();
					}, 20);
				}),
		);
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const run = runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "text",
			initialMessage: "slow final",
		});
		await vi.advanceTimersByTimeAsync(25);
		const exitCode = await run;

		expect(exitCode).toBe(0);
		expect(session.abort).not.toHaveBeenCalled();
		expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("action=assistant_grace"));
	});

	it("allows a tool-execution grace after print timeout when a tool is mid-run", async () => {
		// Regression: the wall timeout used to abort the host immediately when a
		// tool was mid-execution (e.g. a long re_subagent), losing the in-flight
		// tool's result. With a tool grace, the wall fires → enters tool_grace →
		// the tool finishes during the grace → the prompt resolves and the abort
		// is cancelled, so the result is preserved.
		vi.useFakeTimers();
		process.env.REPI_PRODUCT = "1";
		process.env.REPI_PRINT_PROGRESS = "1";
		process.env.REPI_PRINT_TIMEOUT_MS = "10";
		process.env.REPI_PRINT_TIMEOUT_GRACE_MS = "0";
		process.env.REPI_PRINT_TIMEOUT_TOOL_GRACE_MS = "50";
		const runtimeHost = createRuntimeHost(createAssistantMessage({ text: "tool done" }));
		const { session } = runtimeHost;
		let listener: ((event: any) => void) | undefined;
		session.subscribe.mockImplementation((fn) => {
			listener = fn;
			return () => {};
		});
		session.prompt.mockImplementation(
			() =>
				new Promise<void>((resolve) => {
					listener?.({ type: "tool_execution_start", toolCallId: "t1", toolName: "re_subagent", args: {} });
					setTimeout(() => {
						listener?.({ type: "tool_execution_end", toolCallId: "t1", toolName: "re_subagent", args: {} });
						session.state.messages = [createAssistantMessage({ text: "tool done" })];
						resolve();
					}, 20);
				}),
		);
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const run = runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "text",
			initialMessage: "run subagent",
		});
		await vi.advanceTimersByTimeAsync(25);
		const exitCode = await run;

		expect(exitCode).toBe(0);
		expect(session.abort).not.toHaveBeenCalled();
		expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("action=tool_grace"));
	});

	it("aborts mid-tool when no tool grace is configured", async () => {
		// Confirms the grace is what prevents the mid-tool kill: with
		// REPI_PRINT_TIMEOUT_TOOL_GRACE_MS=0 the wall timeout aborts immediately
		// even though a tool is still running.
		vi.useFakeTimers();
		process.env.REPI_PRODUCT = "1";
		process.env.REPI_PRINT_PROGRESS = "1";
		process.env.REPI_PRINT_TIMEOUT_MS = "10";
		process.env.REPI_PRINT_TIMEOUT_GRACE_MS = "0";
		process.env.REPI_PRINT_TIMEOUT_TOOL_GRACE_MS = "0";
		const runtimeHost = createRuntimeHost(createAssistantMessage({ text: "" }));
		const { session } = runtimeHost;
		let listener: ((event: any) => void) | undefined;
		session.subscribe.mockImplementation((fn) => {
			listener = fn;
			return () => {};
		});
		session.prompt.mockImplementation(
			() =>
				new Promise<void>((resolve) => {
					listener?.({ type: "tool_execution_start", toolCallId: "t1", toolName: "re_subagent", args: {} });
					// The tool finishes well after the 10ms wall timeout, so the wall
					// fires mid-tool. With no tool grace, the abort is immediate.
					setTimeout(() => {
						listener?.({ type: "tool_execution_end", toolCallId: "t1", toolName: "re_subagent", args: {} });
						session.state.messages = [createAssistantMessage({ text: "tool done" })];
						resolve();
					}, 30);
				}),
		);
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const run = runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "text",
			initialMessage: "run subagent",
		});
		await vi.advanceTimersByTimeAsync(35);
		const exitCode = await run;

		// Wall timeout aborted the in-flight tool (no grace to save it).
		expect(session.abort).toHaveBeenCalledTimes(1);
		expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("action=abort reason=timeout"));
		expect(exitCode).toBe(1);
	});

	it("recovers partial assistant text on prompt rejection by waiting for idle", async () => {
		// Simulate an in-flight turn that gets aborted/errors: session.prompt
		// rejects, but the partial assistant message commits to state.messages
		// only once waitForIdle resolves (mirroring message_end on abort). The
		// catch path must await idle and write that partial text rather than
		// losing it.
		const runtimeHost = createRuntimeHost(createAssistantMessage({ text: "" }));
		const { session } = runtimeHost;
		session.prompt.mockImplementation(() => Promise.reject(new Error("stream blew up")));
		session.agent.waitForIdle.mockImplementation(async () => {
			session.state.messages = [createAssistantMessage({ text: "partial output recovered" })];
		});

		const written: string[] = [];
		const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation((chunk: any, encOrCb?: any, cb?: any) => {
			written.push(String(chunk));
			const callback = typeof encOrCb === "function" ? encOrCb : cb;
			if (typeof callback === "function") callback();
			return true;
		});
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const exitCode = await runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "text",
			initialMessage: "trigger mid-stream failure",
		});

		expect(exitCode).toBe(1);
		expect(errorSpy).toHaveBeenCalledWith("stream blew up");
		expect(session.agent.waitForIdle).toHaveBeenCalled();
		const combined = written.join("");
		expect(combined).toContain("partial output recovered");

		writeSpy.mockRestore();
		errorSpy.mockRestore();
	});

	it("streams assistant text deltas live to stdout when REPI_PRINT_STREAM_TEXT is set", async () => {
		// With live streaming on, text_delta events are written to stdout as they
		// arrive and the final writeLastAssistantText is suppressed (no duplicate).
		process.env.REPI_PRINT_STREAM_TEXT = "1";
		const runtimeHost = createRuntimeHost(createAssistantMessage({ text: "" }));
		const { session } = runtimeHost;
		let listener: ((event: any) => void) | undefined;
		session.subscribe.mockImplementation((fn) => {
			listener = fn;
			return () => {};
		});
		const finalMsg = createAssistantMessage({ text: "Hello world" });
		session.prompt.mockImplementation(
			() =>
				new Promise<void>((resolve) => {
					listener?.({ type: "message_start", message: { role: "assistant" } });
					listener?.({
						type: "message_update",
						message: { role: "assistant" },
						assistantMessageEvent: { type: "text_delta", contentIndex: 0, delta: "Hel", partial: finalMsg },
					});
					listener?.({
						type: "message_update",
						message: { role: "assistant" },
						assistantMessageEvent: { type: "text_delta", contentIndex: 0, delta: "lo world", partial: finalMsg },
					});
					session.state.messages = [finalMsg];
					listener?.({ type: "message_end", message: finalMsg });
					resolve();
				}),
		);

		const written: string[] = [];
		const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation((chunk: any, encOrCb?: any, cb?: any) => {
			written.push(String(chunk));
			const callback = typeof encOrCb === "function" ? encOrCb : cb;
			if (typeof callback === "function") callback();
			return true;
		});

		const exitCode = await runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "text",
			initialMessage: "stream me",
		});

		expect(exitCode).toBe(0);
		const combined = written.join("");
		// Both deltas streamed live.
		expect(combined).toContain("Hel");
		expect(combined).toContain("lo world");
		// The full text appears exactly once (deltas concatenated, no duplicate final write).
		const occurrences = combined.split("Hello world").length - 1;
		expect(occurrences).toBe(1);

		writeSpy.mockRestore();
	});

	it("falls back to writing full text at message_end when streaming is on but no deltas arrived", async () => {
		// A non-streaming provider emits no text_delta events; the message_end
		// fallback must still write the full assistant text so it is not lost.
		process.env.REPI_PRINT_STREAM_TEXT = "1";
		const runtimeHost = createRuntimeHost(createAssistantMessage({ text: "" }));
		const { session } = runtimeHost;
		let listener: ((event: any) => void) | undefined;
		session.subscribe.mockImplementation((fn) => {
			listener = fn;
			return () => {};
		});
		const finalMsg = createAssistantMessage({ text: "all at once" });
		session.prompt.mockImplementation(
			() =>
				new Promise<void>((resolve) => {
					listener?.({ type: "message_start", message: { role: "assistant" } });
					session.state.messages = [finalMsg];
					listener?.({ type: "message_end", message: finalMsg });
					resolve();
				}),
		);

		const written: string[] = [];
		const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation((chunk: any, encOrCb?: any, cb?: any) => {
			written.push(String(chunk));
			const callback = typeof encOrCb === "function" ? encOrCb : cb;
			if (typeof callback === "function") callback();
			return true;
		});

		const exitCode = await runPrintMode(runtimeHost as unknown as Parameters<typeof runPrintMode>[0], {
			mode: "text",
			initialMessage: "no deltas",
		});

		expect(exitCode).toBe(0);
		const combined = written.join("");
		expect(combined).toContain("all at once");

		writeSpy.mockRestore();
	});
});

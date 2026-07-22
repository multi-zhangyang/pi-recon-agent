import { afterEach, describe, expect, it, vi } from "vitest";
import type { AgentSessionRuntime } from "../src/core/agent-session-runtime.ts";

const rpcIo = vi.hoisted(() => ({
	outputLines: [] as string[],
	lineHandler: undefined as ((line: string) => void) | undefined,
	flushCalls: 0,
}));

vi.mock("../src/core/output-guard.ts", () => ({
	flushRawStdout: vi.fn(async () => {
		rpcIo.flushCalls += 1;
	}),
	takeOverStdout: vi.fn(),
	waitForRawStdoutBackpressure: vi.fn(async () => {}),
	writeRawStdout: (line: string) => {
		rpcIo.outputLines.push(line);
	},
}));

vi.mock("../src/core/presentation/theme-runtime.ts", () => ({ theme: {} }));

vi.mock("../src/modes/rpc/jsonl.ts", () => ({
	attachJsonlLineReader: vi.fn((_stream: NodeJS.ReadableStream, onLine: (line: string) => void) => {
		rpcIo.lineHandler = onLine;
		return () => {};
	}),
	serializeJsonLine: (value: unknown) => `${JSON.stringify(value)}\n`,
}));

vi.mock("../src/utils/shell.ts", () => ({
	killTrackedDetachedChildren: vi.fn(),
}));

import { runRpcMode } from "../src/modes/rpc/rpc-mode.ts";

type FakeSession = {
	sessionId: string;
	sessionFile: string;
	sessionName: string;
	model: unknown;
	thinkingLevel: string;
	isStreaming: boolean;
	isCompacting: boolean;
	steeringMode: string;
	followUpMode: string;
	autoCompactionEnabled: boolean;
	messages: unknown[];
	pendingMessageCount: number;
	prompt: ReturnType<typeof vi.fn>;
	abort: ReturnType<typeof vi.fn>;
	waitForIdle: ReturnType<typeof vi.fn>;
	agent: { waitForIdle: ReturnType<typeof vi.fn>; subscribe: ReturnType<typeof vi.fn> };
	extensionRunner: {
		getRegisteredCommands: () => never[];
		hasHandlers: () => boolean;
		emit: ReturnType<typeof vi.fn>;
	};
	resourceLoader: { getSkills: () => { skills: never[] } };
	promptTemplates: never[];
	modelRegistry: { getAvailable: ReturnType<typeof vi.fn> };
	sessionManager: { getLeafId: () => string; getHeader: () => undefined };
	bindExtensions: ReturnType<typeof vi.fn>;
	subscribe: ReturnType<typeof vi.fn>;
};

function makeFakeSession(id: string, opts?: { bindExtensionsThrow?: boolean }): FakeSession {
	return {
		sessionId: id,
		sessionFile: `/tmp/${id}.jsonl`,
		sessionName: id,
		model: undefined,
		thinkingLevel: "off",
		isStreaming: false,
		isCompacting: false,
		steeringMode: "all",
		followUpMode: "all",
		autoCompactionEnabled: false,
		messages: [],
		pendingMessageCount: 0,
		prompt: vi.fn(async (_message: string, options?: { preflightResult?: (success: boolean) => void }) => {
			options?.preflightResult?.(true);
		}),
		abort: vi.fn(async () => {}),
		waitForIdle: vi.fn(async () => {}),
		agent: {
			waitForIdle: vi.fn(async () => {}),
			subscribe: vi.fn(() => () => {}),
		},
		extensionRunner: {
			getRegisteredCommands: () => [],
			hasHandlers: () => false,
			emit: vi.fn(async () => {}),
		},
		resourceLoader: { getSkills: () => ({ skills: [] }) },
		promptTemplates: [],
		modelRegistry: { getAvailable: vi.fn(async () => []) },
		sessionManager: { getLeafId: () => id, getHeader: () => undefined },
		bindExtensions: vi.fn(async () => {
			if (opts?.bindExtensionsThrow) throw new Error("bindExtensions boom");
		}),
		subscribe: vi.fn(() => () => {}),
	};
}

interface FakeRuntime {
	session: FakeSession;
	newSession: ReturnType<typeof vi.fn>;
	switchSession: ReturnType<typeof vi.fn>;
	fork: ReturnType<typeof vi.fn>;
	dispose: ReturnType<typeof vi.fn>;
	setRebindSession: ReturnType<typeof vi.fn>;
	invokeRebind: () => Promise<void>;
}

function createFakeRuntime(startSession?: FakeSession): { runtime: FakeRuntime; holder: { current: FakeSession } } {
	const holder: { current: FakeSession } = { current: startSession ?? makeFakeSession("s1") };
	let rebindSession: ((session: FakeSession) => Promise<void>) | undefined;
	const runtime: FakeRuntime = {
		get session(): FakeSession {
			return holder.current;
		},
		newSession: vi.fn(async () => {
			holder.current = makeFakeSession("s-after-new");
			await runtime.invokeRebind();
			return { cancelled: false };
		}),
		switchSession: vi.fn(async () => ({ cancelled: false })),
		fork: vi.fn(async () => ({ cancelled: false, selectedText: "" })),
		dispose: vi.fn(async () => {}),
		setRebindSession: vi.fn((callback?: (session: FakeSession) => Promise<void>) => {
			rebindSession = callback;
		}),
		invokeRebind: async () => {
			await rebindSession?.(holder.current);
		},
	};
	return { runtime, holder };
}

async function startRpc(runtime: FakeRuntime): Promise<(line: string) => void> {
	rpcIo.outputLines = [];
	rpcIo.lineHandler = undefined;
	rpcIo.flushCalls = 0;
	void runRpcMode(runtime as unknown as AgentSessionRuntime);
	await vi.waitFor(() => expect(rpcIo.lineHandler).toBeDefined());
	return rpcIo.lineHandler!;
}

function parseOutput(): Record<string, unknown>[] {
	return rpcIo.outputLines
		.flatMap((line) => line.split("\n"))
		.filter((line) => line.trim().length > 0)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

function responsesFor(command: string, id: string): Record<string, unknown>[] {
	return parseOutput().filter((r) => r.id === id && r.type === "response" && r.command === command);
}

// Force any live runRpcMode instance to shut down so its signal/stdin listeners
// are removed (prevents cross-test interference). process.exit is mocked so the
// process keeps running; manual process.emit only calls JS listeners (safe even
// with none registered).
afterEach(async () => {
	const exitSpy = vi
		.spyOn(process, "exit")
		.mockImplementation((() => undefined) as (code?: string | number | null | undefined) => never);
	try {
		process.emit("SIGTERM", "SIGTERM");
		await new Promise((r) => setTimeout(r, 15));
	} finally {
		exitSpy.mockRestore();
	}
	rpcIo.outputLines = [];
	rpcIo.lineHandler = undefined;
	rpcIo.flushCalls = 0;
});

describe("F3: rebindSession subscribes even when bindExtensions throws", () => {
	it("establishes the new session subscription in the finally block", async () => {
		const s1 = makeFakeSession("s1");
		const { runtime, holder } = createFakeRuntime(s1);
		const s2 = makeFakeSession("s2", { bindExtensionsThrow: true });
		runtime.newSession.mockImplementation(async () => {
			holder.current = s2;
			await runtime.invokeRebind();
			return { cancelled: false };
		});

		const lineHandler = await startRpc(runtime);
		// s1 bindExtensions already called at startup.
		const s1BindCalls = s1.bindExtensions.mock.calls.length;

		lineHandler(JSON.stringify({ id: "n1", type: "new_session" }));

		// An error response is emitted because rebindSession's bindExtensions
		// throws and propagates out of handleCommand.
		await vi.waitFor(() => {
			const errResp = parseOutput().find((r) => r.id === "n1" && r.type === "response" && r.success === false);
			expect(errResp).toBeDefined();
		});

		// The new session (s2) was swapped in and bindExtensions threw, but the
		// finally block must still have subscribed to s2. Without the fix,
		// subscribe was after bindExtensions (no try/finally) and would NOT run.
		expect(s2.bindExtensions).toHaveBeenCalledTimes(1);
		expect(s2.subscribe).toHaveBeenCalledTimes(1);
		expect(s1.bindExtensions.mock.calls.length).toBe(s1BindCalls);
	});
});

describe("F4: shutdown flushes raw stdout unconditionally on SIGTERM", () => {
	it("calls flushRawStdout even when signal is SIGTERM", async () => {
		const { runtime } = createFakeRuntime();
		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation((() => undefined) as (code?: string | number | null | undefined) => never);
		try {
			await startRpc(runtime);
			expect(rpcIo.flushCalls).toBe(0);

			process.emit("SIGTERM", "SIGTERM");

			await vi.waitFor(() => expect(rpcIo.flushCalls).toBeGreaterThanOrEqual(1));
		} finally {
			exitSpy.mockRestore();
		}
	});

	// opt #62: SIGINT was previously NOT handled (only SIGTERM/SIGHUP), so Ctrl+C
	// took the default-exit path without running shutdown() → no graceful rpc
	// teardown / raw-stdout flush, and exit code was the default 130 only by
	// accident of the signal. Now SIGINT runs shutdown(130, "SIGINT").
	it("calls flushRawStdout and exits 130 on SIGINT (opt #62)", async () => {
		const { runtime } = createFakeRuntime();
		let exitCode: number | undefined;
		const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
			exitCode = code;
		}) as (code?: string | number | null | undefined) => never);
		try {
			await startRpc(runtime);
			expect(rpcIo.flushCalls).toBe(0);

			process.emit("SIGINT", "SIGINT");

			await vi.waitFor(() => {
				expect(rpcIo.flushCalls).toBeGreaterThanOrEqual(1);
				expect(exitCode).toBe(130);
			});
		} finally {
			exitSpy.mockRestore();
		}
	});
});

describe("F5: pending extension UI requests rejected on rebind/shutdown; editor gains a timeout escape", () => {
	it("rejects pending editor dialog with 'session replaced' on session rebind", async () => {
		const s1 = makeFakeSession("s1");
		const { runtime, holder } = createFakeRuntime(s1);
		runtime.newSession.mockImplementation(async () => {
			holder.current = makeFakeSession("s2");
			await runtime.invokeRebind();
			return { cancelled: false };
		});

		const lineHandler = await startRpc(runtime);

		await vi.waitFor(() => expect(s1.bindExtensions).toHaveBeenCalledTimes(1));
		const bound = s1.bindExtensions.mock.calls[0][0] as {
			uiContext: { editor: (t: string, p?: string) => Promise<string | undefined> };
		};
		const editorPromise = bound.uiContext.editor("Title", "prefill");

		// Promise should be pending before rebind. Attach a both-arms handler so
		// the eventual rejection is not reported as an unhandled rejection.
		let settled = false;
		void editorPromise.then(
			() => {
				settled = true;
			},
			() => {
				settled = true;
			},
		);
		await new Promise((r) => setTimeout(r, 5));
		expect(settled).toBe(false);

		lineHandler(JSON.stringify({ id: "n2", type: "new_session" }));

		await expect(editorPromise).rejects.toThrow("session replaced");
	});

	it("rejects pending editor dialog with 'RPC shutdown' on shutdown", async () => {
		const { runtime } = createFakeRuntime();
		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation((() => undefined) as (code?: string | number | null | undefined) => never);
		try {
			const _lineHandler = await startRpc(runtime);
			const s1 = runtime.session;
			await vi.waitFor(() => expect(s1.bindExtensions).toHaveBeenCalledTimes(1));
			const bound = s1.bindExtensions.mock.calls[0][0] as {
				uiContext: { editor: (t: string, p?: string) => Promise<string | undefined> };
			};
			const editorPromise = bound.uiContext.editor("Title", "prefill");

			process.emit("SIGTERM", "SIGTERM");

			await expect(editorPromise).rejects.toThrow("RPC shutdown");
		} finally {
			exitSpy.mockRestore();
		}
	});

	it("editor() honors an opts.timeout and resolves to undefined when it elapses", async () => {
		const { runtime } = createFakeRuntime();
		await startRpc(runtime);
		const s1 = runtime.session;
		await vi.waitFor(() => expect(s1.bindExtensions).toHaveBeenCalledTimes(1));
		const bound = s1.bindExtensions.mock.calls[0][0] as {
			uiContext: {
				editor: (t: string, p?: string, opts?: { timeout?: number }) => Promise<string | undefined>;
			};
		};

		const result = await bound.uiContext.editor("Title", "prefill", { timeout: 20 });
		expect(result).toBeUndefined();
	});
});

describe("F6: mutating session-replacement commands are serialized", () => {
	it("serializes two concurrent new_session lines so newSession never runs concurrently", async () => {
		const s1 = makeFakeSession("s1");
		const { runtime, holder } = createFakeRuntime(s1);

		let counter = 0;
		let concurrent = 0;
		let maxConcurrent = 0;
		runtime.newSession.mockImplementation(async () => {
			concurrent += 1;
			maxConcurrent = Math.max(maxConcurrent, concurrent);
			// Async gap between teardown and apply — without serialization a second
			// new_session enters here while the first is still awaiting, driving
			// maxConcurrent to 2.
			await new Promise((r) => setTimeout(r, 20));
			counter += 1;
			holder.current = makeFakeSession(`s-${counter}`);
			await runtime.invokeRebind();
			concurrent -= 1;
			return { cancelled: false };
		});

		const lineHandler = await startRpc(runtime);

		// Send two new_session lines back-to-back (simulating two JSONL lines in
		// one stdin chunk, each dispatched via `void handleInputLine(line)`).
		lineHandler(JSON.stringify({ id: "a", type: "new_session" }));
		lineHandler(JSON.stringify({ id: "b", type: "new_session" }));

		await vi.waitFor(() => {
			expect(responsesFor("new_session", "a")).toHaveLength(1);
			expect(responsesFor("new_session", "b")).toHaveLength(1);
		});

		// With serialization, the two newSession calls never overlap.
		expect(maxConcurrent).toBe(1);
		expect(runtime.newSession).toHaveBeenCalledTimes(2);
		// The final live session is the second replacement's session (consistent).
		expect(holder.current.sessionId).toBe("s-2");
	});
});

describe("F7: runtime-owned session replacement rebinds exactly once", () => {
	it("does not bind the replacement session a second time in the RPC command handler", async () => {
		const { runtime, holder } = createFakeRuntime();
		const lineHandler = await startRpc(runtime);

		lineHandler(JSON.stringify({ id: "single-rebind", type: "new_session" }));

		await vi.waitFor(() => {
			expect(responsesFor("new_session", "single-rebind")).toHaveLength(1);
		});
		expect(holder.current.sessionId).toBe("s-after-new");
		expect(holder.current.bindExtensions).toHaveBeenCalledTimes(1);
	});
});

describe("F8: stdin EOF drains accepted commands before shutdown", () => {
	it("emits a queued new_session response before disposing the runtime", async () => {
		const { runtime, holder } = createFakeRuntime();
		let releaseReplacement!: () => void;
		const replacementGate = new Promise<void>((resolve) => {
			releaseReplacement = resolve;
		});
		runtime.newSession.mockImplementation(async () => {
			await replacementGate;
			holder.current = makeFakeSession("s-after-eof");
			await runtime.invokeRebind();
			return { cancelled: false };
		});

		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation((() => undefined) as (code?: string | number | null | undefined) => never);
		try {
			const lineHandler = await startRpc(runtime);
			lineHandler(JSON.stringify({ id: "eof-new", type: "new_session" }));
			process.stdin.emit("end");

			await new Promise((resolve) => setTimeout(resolve, 10));
			expect(runtime.dispose).not.toHaveBeenCalled();
			expect(responsesFor("new_session", "eof-new")).toHaveLength(0);

			releaseReplacement();
			await vi.waitFor(() => {
				expect(responsesFor("new_session", "eof-new")).toHaveLength(1);
				expect(runtime.dispose).toHaveBeenCalledTimes(1);
			});
		} finally {
			exitSpy.mockRestore();
		}
	});

	it("waits for a fire-and-forget prompt to settle before disposing the runtime", async () => {
		const session = makeFakeSession("prompt-session");
		const { runtime } = createFakeRuntime(session);
		let releasePrompt!: () => void;
		const promptGate = new Promise<void>((resolve) => {
			releasePrompt = resolve;
		});
		session.prompt.mockImplementation(
			async (_message: string, options?: { preflightResult?: (success: boolean) => void }) => {
				options?.preflightResult?.(true);
				await promptGate;
			},
		);
		session.waitForIdle.mockImplementation(() => promptGate);

		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation((() => undefined) as (code?: string | number | null | undefined) => never);
		try {
			const lineHandler = await startRpc(runtime);
			lineHandler(JSON.stringify({ id: "eof-prompt", type: "prompt", message: "finish before EOF" }));
			await vi.waitFor(() => {
				expect(responsesFor("prompt", "eof-prompt")).toHaveLength(1);
			});
			process.stdin.emit("end");

			await new Promise((resolve) => setTimeout(resolve, 10));
			expect(runtime.dispose).not.toHaveBeenCalled();

			releasePrompt();
			await vi.waitFor(() => {
				expect(runtime.dispose).toHaveBeenCalledTimes(1);
			});
		} finally {
			exitSpy.mockRestore();
		}
	});

	it("aborts a stalled prompt when the configurable EOF drain timeout elapses", async () => {
		const session = makeFakeSession("stalled-session");
		const { runtime } = createFakeRuntime(session);
		session.prompt.mockImplementation(
			async (_message: string, options?: { preflightResult?: (success: boolean) => void }) => {
				options?.preflightResult?.(true);
				await new Promise<void>(() => {});
			},
		);
		session.waitForIdle.mockImplementation(() => new Promise<void>(() => {}));
		const previousTimeout = process.env.REPI_RPC_EOF_DRAIN_TIMEOUT_MS;
		process.env.REPI_RPC_EOF_DRAIN_TIMEOUT_MS = "20";

		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation((() => undefined) as (code?: string | number | null | undefined) => never);
		const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		try {
			const lineHandler = await startRpc(runtime);
			lineHandler(JSON.stringify({ id: "stalled-prompt", type: "prompt", message: "never settles" }));
			await vi.waitFor(() => {
				expect(responsesFor("prompt", "stalled-prompt")).toHaveLength(1);
			});
			process.stdin.emit("end");

			await vi.waitFor(() => {
				expect(session.abort).toHaveBeenCalledTimes(1);
				expect(runtime.dispose).toHaveBeenCalledTimes(1);
			});
			expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining("RPC EOF drain timed out after 20ms"));
		} finally {
			if (previousTimeout === undefined) delete process.env.REPI_RPC_EOF_DRAIN_TIMEOUT_MS;
			else process.env.REPI_RPC_EOF_DRAIN_TIMEOUT_MS = previousTimeout;
			stderrSpy.mockRestore();
			exitSpy.mockRestore();
		}
	});
});

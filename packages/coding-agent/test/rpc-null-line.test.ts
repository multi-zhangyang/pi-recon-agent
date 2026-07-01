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

vi.mock("../src/modes/interactive/theme/theme.ts", () => ({ theme: {} }));

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

function makeFakeSession(id: string): FakeSession {
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
		bindExtensions: vi.fn(async () => {}),
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
}

function createFakeRuntime(startSession?: FakeSession): { runtime: FakeRuntime; holder: { current: FakeSession } } {
	const holder: { current: FakeSession } = { current: startSession ?? makeFakeSession("s1") };
	const runtime: FakeRuntime = {
		get session(): FakeSession {
			return holder.current;
		},
		newSession: vi.fn(async () => {
			holder.current = makeFakeSession("s-after-new");
			return { cancelled: false };
		}),
		switchSession: vi.fn(async () => ({ cancelled: false })),
		fork: vi.fn(async () => ({ cancelled: false, selectedText: "" })),
		dispose: vi.fn(async () => {}),
		setRebindSession: vi.fn(),
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

describe("F2: handleInputLine survives a null JSON line", () => {
	it("emits a parse error and does not trigger unhandledRejection on `null` input", async () => {
		const { runtime } = createFakeRuntime();
		const lineHandler = await startRpc(runtime);

		let rejected = false;
		const rejectionHandler = () => {
			rejected = true;
		};
		process.on("unhandledRejection", rejectionHandler);
		try {
			// JSON.parse("null") === null; without the guard, `null.type` throws
			// TypeError inside the async handleInputLine → rejected promise → the
			// reader does `void handleInputLine(line)` → unhandledRejection.
			lineHandler("null");
			// Let the microtask queue drain so a rejected promise would surface.
			await new Promise((r) => setTimeout(r, 20));
			expect(rejected).toBe(false);

			const errResp = parseOutput().find(
				(r) => r.type === "response" && r.success === false && r.command === "parse",
			);
			expect(errResp).toBeDefined();
		} finally {
			process.off("unhandledRejection", rejectionHandler);
		}
	});
});

import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import type { AgentSessionRuntime } from "../src/core/agent-session-runtime.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { installRepiGoalMode, REPI_GOAL_STATE_ENTRY_TYPE } from "../src/core/repi/goal.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { runRpcMode } from "../src/modes/rpc/rpc-mode.ts";
import { createFauxStreamFn, type FauxResponseInput, fauxModel } from "./test-harness.ts";
import { createTestExtensionsResult, createTestResourceLoader } from "./utilities.ts";

const rpcIo = vi.hoisted(() => ({
	outputLines: [] as string[],
	lineHandler: undefined as ((line: string) => void) | undefined,
}));

vi.mock("../src/core/output-guard.js", () => ({
	flushRawStdout: vi.fn(async () => {}),
	takeOverStdout: vi.fn(),
	waitForRawStdoutBackpressure: vi.fn(async () => {}),
	writeRawStdout: (line: string) => {
		rpcIo.outputLines.push(line);
	},
}));

vi.mock("../src/modes/interactive/theme/theme.js", () => ({ theme: {} }));

vi.mock("../src/modes/rpc/jsonl.js", () => ({
	attachJsonlLineReader: vi.fn((_stream: NodeJS.ReadableStream, onLine: (line: string) => void) => {
		rpcIo.lineHandler = onLine;
		return () => {};
	}),
	serializeJsonLine: (value: unknown) => `${JSON.stringify(value)}\n`,
}));

type RpcLine = Record<string, unknown>;

function parseOutputLines(): RpcLine[] {
	return rpcIo.outputLines
		.flatMap((line) => line.split("\n"))
		.filter((line) => line.trim().length > 0)
		.map((line) => JSON.parse(line) as RpcLine);
}

function responseById(id: string): RpcLine | undefined {
	return parseOutputLines().find((record) => record.id === id && record.type === "response");
}

function extensionRequests(method: string): RpcLine[] {
	return parseOutputLines().filter((record) => record.type === "extension_ui_request" && record.method === method);
}

async function startGoalRpcHarness(
	responses: FauxResponseInput[] = [
		{
			toolCalls: [
				{
					name: "goal_complete",
					args: { summary: "Implemented and verified through the RPC goal harness." },
				},
			],
		},
	],
): Promise<{
	lineHandler: (line: string) => void;
	session: AgentSession;
	sessionManager: SessionManager;
	faux: ReturnType<typeof createFauxStreamFn>["state"];
	cleanup: () => Promise<void>;
}> {
	const tempDir = join(tmpdir(), `repi-goal-rpc-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	mkdirSync(tempDir, { recursive: true });

	const { streamFn, state: faux } = createFauxStreamFn(responses);
	const agent = new Agent({
		getApiKey: () => "faux-key",
		initialState: {
			model: fauxModel,
			systemPrompt: "RPC goal test assistant.",
			tools: [],
		},
		streamFn,
	});

	const sessionManager = SessionManager.inMemory();
	const settingsManager = SettingsManager.create(tempDir, tempDir);
	const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
	authStorage.setRuntimeApiKey(fauxModel.provider, "faux-key");
	const modelRegistry = ModelRegistry.create(authStorage, tempDir);
	const extensionsResult = await createTestExtensionsResult([installRepiGoalMode], tempDir);
	const resourceLoader = createTestResourceLoader({ extensionsResult });
	const session = new AgentSession({
		agent,
		sessionManager,
		settingsManager,
		cwd: tempDir,
		modelRegistry,
		resourceLoader,
	});

	const runtimeHost = {
		session,
		newSession: vi.fn(async () => ({ cancelled: true })),
		switchSession: vi.fn(async () => ({ cancelled: true })),
		fork: vi.fn(async () => ({ cancelled: true, selectedText: "" })),
		dispose: vi.fn(async () => {}),
		setRebindSession: vi.fn(),
	} as unknown as AgentSessionRuntime;

	void runRpcMode(runtimeHost);
	await vi.waitFor(() => expect(rpcIo.lineHandler).toBeDefined());

	return {
		lineHandler: rpcIo.lineHandler!,
		session,
		sessionManager,
		faux,
		cleanup: async () => {
			try {
				if (session.isStreaming) await session.abort();
			} catch {
				// Test cleanup must not mask the assertion failure.
			}
			session.dispose();
			if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
		},
	};
}

describe("REPI goal mode over RPC", () => {
	afterEach(() => {
		rpcIo.outputLines = [];
		rpcIo.lineHandler = undefined;
	});

	it("exposes /goal and goal_complete, then drives footer/status events through RPC", async () => {
		const harness = await startGoalRpcHarness();
		try {
			harness.lineHandler(JSON.stringify({ id: "commands", type: "get_commands" }));
			await vi.waitFor(() => expect(responseById("commands")).toBeDefined());
			const commands = responseById("commands")?.data as { commands?: Array<{ name: string }> } | undefined;
			expect(commands?.commands?.filter((command) => command.name === "goal")).toHaveLength(1);

			harness.lineHandler(JSON.stringify({ id: "tools", type: "get_tools" }));
			await vi.waitFor(() => expect(responseById("tools")).toBeDefined());
			const tools = responseById("tools")?.data as
				| { tools?: Array<{ name: string }>; activeToolNames?: string[] }
				| undefined;
			expect(tools?.tools?.filter((tool) => tool.name === "goal_complete")).toHaveLength(1);
			expect(tools?.activeToolNames).toContain("goal_complete");

			harness.lineHandler(
				JSON.stringify({ id: "goal", type: "prompt", message: "/goal --tokens 1k rpc status smoke" }),
			);

			await vi.waitFor(
				() => {
					expect(responseById("goal")).toMatchObject({ success: true, command: "prompt" });
					expect(
						extensionRequests("setStatus").some(
							(request) => request.statusKey === "goal" && request.statusText === "🎯 active 0/1k",
						),
					).toBe(true);
					expect(
						extensionRequests("setStatus").some(
							(request) => request.statusKey === "goal" && request.statusText === "🎯 complete",
						),
					).toBe(true);
				},
				{ timeout: 8_000 },
			);

			expect(extensionRequests("notify").map((request) => String(request.message))).toEqual(
				expect.arrayContaining(["Goal started: rpc status smoke", "Goal complete: rpc status smoke"]),
			);
			expect(JSON.stringify(harness.faux.contexts[0]?.messages ?? [])).toContain("rpc status smoke");
			expect(JSON.stringify(harness.faux.contexts[0] ?? {})).toContain("Active REPI /goal");
			expect(
				harness.sessionManager
					.getEntries()
					.some((entry) => entry.type === "custom" && entry.customType === REPI_GOAL_STATE_ENTRY_TYPE),
			).toBe(true);
			expect(
				harness.sessionManager
					.getEntries()
					.filter((entry) => entry.type === "custom" && entry.customType === REPI_GOAL_STATE_ENTRY_TYPE)
					.at(-1),
			).toMatchObject({ type: "custom", customType: REPI_GOAL_STATE_ENTRY_TYPE, data: { goal: null } });
		} finally {
			await harness.cleanup();
		}
	});

	it("returns /goal help and fresh status over RPC without starting a model turn", async () => {
		const harness = await startGoalRpcHarness();
		try {
			harness.lineHandler(JSON.stringify({ id: "goal-help", type: "prompt", message: "/goal help" }));
			harness.lineHandler(JSON.stringify({ id: "goal-status", type: "prompt", message: "/goal status" }));

			await vi.waitFor(() => {
				expect(responseById("goal-help")).toMatchObject({ success: true, command: "prompt" });
				expect(responseById("goal-status")).toMatchObject({ success: true, command: "prompt" });
			});

			const notifications = extensionRequests("notify").map((request) => String(request.message));
			expect(notifications.join("\n")).toContain("REPI /goal runs a task until verified completion.");
			expect(notifications.join("\n")).toContain("No goal is currently set.");
			expect(
				extensionRequests("setStatus").some(
					(request) => request.statusKey === "goal" && request.statusText === undefined,
				),
			).toBe(true);
			expect(harness.faux.contexts).toHaveLength(0);
			expect(
				harness.sessionManager
					.getEntries()
					.some((entry) => entry.type === "custom" && entry.customType === REPI_GOAL_STATE_ENTRY_TYPE),
			).toBe(false);
		} finally {
			await harness.cleanup();
		}
	});

	it("keeps RPC budget-limited goal lifecycle bounded without extra model turns", async () => {
		const harness = await startGoalRpcHarness([{ text: "still working", usage: { input: 100, output: 50 } }]);
		try {
			harness.lineHandler(
				JSON.stringify({ id: "goal-start", type: "prompt", message: "/goal --tokens 1 rpc budget lifecycle" }),
			);

			await vi.waitFor(
				() => {
					expect(responseById("goal-start")).toMatchObject({ success: true, command: "prompt" });
					expect(
						extensionRequests("setStatus").some(
							(request) =>
								request.statusKey === "goal" && String(request.statusText ?? "").startsWith("🎯 budget "),
						),
					).toBe(true);
				},
				{ timeout: 8_000 },
			);

			expect(harness.faux.callCount).toBe(1);

			harness.lineHandler(JSON.stringify({ id: "goal-status-active", type: "prompt", message: "/goal status" }));
			harness.lineHandler(JSON.stringify({ id: "goal-resume-budget", type: "prompt", message: "/goal resume" }));
			harness.lineHandler(JSON.stringify({ id: "goal-clear-budget", type: "prompt", message: "/goal clear" }));

			await vi.waitFor(() => {
				expect(responseById("goal-status-active")).toMatchObject({ success: true, command: "prompt" });
				expect(responseById("goal-resume-budget")).toMatchObject({ success: true, command: "prompt" });
				expect(responseById("goal-clear-budget")).toMatchObject({ success: true, command: "prompt" });
			});

			const notificationText = extensionRequests("notify")
				.map((request) => String(request.message))
				.join("\n");
			expect(notificationText).toContain("Goal: rpc budget lifecycle");
			expect(notificationText).toContain("Goal token budget is still reached:");
			expect(notificationText).toContain("Goal cleared: rpc budget lifecycle");
			expect(
				extensionRequests("setStatus").some(
					(request) => request.statusKey === "goal" && request.statusText === undefined,
				),
			).toBe(true);
			expect(harness.faux.callCount).toBe(1);
		} finally {
			await harness.cleanup();
		}
	});
});

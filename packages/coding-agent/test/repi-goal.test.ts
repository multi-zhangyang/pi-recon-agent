import type { AgentMessage } from "@pi-recon/repi-agent-core";
import { describe, expect, it, vi } from "vitest";
import type { ExtensionAPI, ExtensionContext } from "../src/core/extensions/types.ts";
import {
	buildGoalSystemPrompt,
	formatGoalFooterStatus,
	installRepiGoalMode,
	parseGoalCommand,
	parseTokenBudget,
	REPI_GOAL_STATE_ENTRY_TYPE,
	type RepiGoalState,
} from "../src/core/repi/goal.ts";

type Handler = (event: any, ctx: ExtensionContext) => any;

function createGoalState(overrides: Partial<RepiGoalState> = {}): RepiGoalState {
	const now = Date.now();
	return {
		id: "goal-1",
		text: "finish the harness",
		status: "active",
		startedAt: now,
		updatedAt: now,
		iteration: 0,
		tokensUsed: 0,
		timeUsedSeconds: 0,
		baselineTokens: 0,
		...overrides,
	};
}

function createHarness(initialEntries: any[] = []) {
	const commands = new Map<string, any>();
	const tools = new Map<string, any>();
	const handlers = new Map<string, Handler[]>();
	const sent: Array<{ content: string; options?: unknown }> = [];
	const entries = [...initialEntries];
	const notifications: Array<{ message: string; level?: string }> = [];
	const statuses = new Map<string, string | undefined>();
	const compact = vi.fn();
	const abort = vi.fn();

	const pi = {
		registerCommand(name: string, options: any) {
			commands.set(name, options);
		},
		registerTool(tool: any) {
			tools.set(tool.name, tool);
		},
		on(event: string, handler: Handler) {
			const list = handlers.get(event) ?? [];
			list.push(handler);
			handlers.set(event, list);
		},
		sendUserMessage(content: string, options?: unknown) {
			sent.push({ content, options });
		},
		appendEntry(customType: string, data?: unknown) {
			entries.push({ type: "custom", customType, data });
		},
		setSessionName() {},
		getSessionName() {
			return undefined;
		},
	} as unknown as ExtensionAPI;

	const ctx = {
		ui: {
			notify(message: string, level?: "info" | "warning" | "error") {
				notifications.push({ message, level });
			},
			confirm: vi.fn(async () => true),
			setStatus(key: string, value: string | undefined) {
				statuses.set(key, value);
			},
		},
		cwd: "/tmp/repi-goal-test",
		hasUI: true,
		mode: "tui",
		sessionManager: {
			getBranch: () => entries,
			getEntries: () => entries,
		},
		isIdle: () => true,
		hasPendingMessages: () => false,
		abort,
		compact,
		model: undefined,
		getContextUsage: () => undefined,
	} as unknown as ExtensionContext;

	installRepiGoalMode(pi);
	return { commands, tools, handlers, sent, entries, notifications, statuses, compact, abort, ctx };
}

describe("REPI built-in goal mode", () => {
	it("parses goal commands and token budgets", () => {
		expect(parseTokenBudget("100k")).toBe(100_000);
		expect(parseTokenBudget("1.5m")).toBe(1_500_000);
		expect(parseTokenBudget("bad")).toBeUndefined();
		expect(parseGoalCommand("--tokens 100k reverse target")).toEqual({
			kind: "start",
			objective: "reverse target",
			tokenBudget: 100_000,
		});
		expect(parseGoalCommand("edit 'new objective'")).toEqual({ kind: "edit", objective: "new objective" });
		expect(parseGoalCommand("help")).toEqual({ kind: "help" });
		expect(parseGoalCommand("pause now")).toBe("Usage: /goal pause");
	});

	it("registers /goal and sends an initial prompt with footer status", async () => {
		const harness = createHarness();
		expect(harness.commands.has("goal")).toBe(true);
		expect(harness.tools.has("goal_complete")).toBe(true);

		await harness.commands.get("goal").handler("--tokens 100k harden runtime", harness.ctx);

		expect(harness.sent).toHaveLength(1);
		expect(harness.sent[0].content).toContain("REPI goal mode is active");
		expect(harness.sent[0].content).toContain("harden runtime");
		expect(harness.statuses.get("goal")).toBe("🎯 active 0/100k");
		expect(harness.entries.at(-1)).toMatchObject({
			type: "custom",
			customType: REPI_GOAL_STATE_ENTRY_TYPE,
			data: { version: 1, goal: { text: "harden runtime", status: "active", tokenBudget: 100_000 } },
		});
	});

	it("adds goal rules to the system prompt and auto-continues after an unfinished turn", async () => {
		const harness = createHarness();
		await harness.commands.get("goal").handler("finish the harness", harness.ctx);

		const beforeAgentStart = harness.handlers.get("before_agent_start")![0];
		const promptResult = beforeAgentStart(
			{ type: "before_agent_start", prompt: "finish", systemPrompt: "base", images: undefined },
			harness.ctx,
		);
		expect(promptResult.systemPrompt).toContain("Active REPI /goal");
		expect(buildGoalSystemPrompt(createGoalState())).toContain("goal_complete");

		const agentEnd = harness.handlers.get("agent_end")![0];
		await agentEnd(
			{
				type: "agent_end",
				messages: [{ role: "assistant", stopReason: "stop", usage: { input: 10, output: 5 } }] as AgentMessage[],
			},
			harness.ctx,
		);

		expect(harness.sent).toHaveLength(2);
		expect(harness.sent[1].content).toContain("Continue the active REPI /goal");
		expect(harness.sent[1].content).toContain("repi-goal-continuation:");
	});

	it("pauses goal mode and blocks stale tool calls", async () => {
		const harness = createHarness();
		await harness.commands.get("goal").handler("finish the harness", harness.ctx);
		await harness.handlers.get("agent_end")![0](
			{ type: "agent_end", messages: [{ role: "assistant", stopReason: "stop" }] },
			harness.ctx,
		);
		const continuation = harness.sent[1].content;

		await harness.commands.get("goal").handler("pause", harness.ctx);

		expect(harness.abort).toHaveBeenCalled();
		expect(harness.statuses.get("goal")).toBe("🎯 paused");
		expect(harness.handlers.get("tool_call")![0]({ type: "tool_call", toolName: "bash" }, harness.ctx)).toMatchObject(
			{
				block: true,
			},
		);
		expect(
			harness.handlers.get("input")![0]({ type: "input", source: "extension", text: continuation }, harness.ctx),
		).toEqual({
			action: "handled",
		});
	});

	it("rejects contradictory completion summaries and accepts verified completion", async () => {
		const harness = createHarness();
		await harness.commands.get("goal").handler("finish the harness", harness.ctx);
		const tool = harness.tools.get("goal_complete");

		const rejected = await tool.execute("tool-1", { summary: "tests still fail" }, undefined, undefined, harness.ctx);
		expect(rejected.terminate).toBeUndefined();
		expect(rejected.details.status).toBe("rejected");
		expect(harness.statuses.get("goal")).toBe("🎯 active 0s");

		const accepted = await tool.execute(
			"tool-2",
			{ summary: "Implemented and verified with unit tests." },
			undefined,
			undefined,
			harness.ctx,
		);
		expect(accepted.terminate).toBe(true);
		expect(accepted.details.status).toBe("accepted");
		expect(harness.statuses.get("goal")).toBe("🎯 complete");
		expect(harness.entries.at(-1)).toMatchObject({ data: { goal: null } });
	});

	it("replaces an existing goal without a blocking confirm in print/no-UI mode", async () => {
		const harness = createHarness();
		harness.ctx.hasUI = false;
		harness.ctx.mode = "print";
		harness.ctx.ui.confirm = vi.fn(async () => false);

		harness.handlers.get("session_start")![0]({ type: "session_start", reason: "startup" }, harness.ctx);
		expect(harness.statuses.get("goal")).toBeUndefined();

		await harness.commands.get("goal").handler("first objective", harness.ctx);
		await harness.commands.get("goal").handler("second objective", harness.ctx);

		expect(harness.ctx.ui.confirm).not.toHaveBeenCalled();
		expect(harness.sent).toHaveLength(2);
		expect(harness.sent[1].content).toContain("second objective");
		expect(harness.entries.at(-1)).toMatchObject({
			type: "custom",
			customType: REPI_GOAL_STATE_ENTRY_TYPE,
			data: { version: 1, goal: { text: "second objective", status: "active" } },
		});
	});

	it("queues goal prompts as follow-up when print/RPC contexts are already busy", async () => {
		for (const mode of ["print", "rpc", "json"] as const) {
			const harness = createHarness();
			harness.ctx.hasUI = false;
			harness.ctx.mode = mode;
			harness.ctx.isIdle = () => false;

			await harness.commands.get("goal").handler(`${mode} busy objective`, harness.ctx);

			expect(harness.sent).toHaveLength(1);
			expect(harness.sent[0].content).toContain(`${mode} busy objective`);
			expect(harness.sent[0].options).toEqual({ deliverAs: "followUp" });
			expect(harness.statuses.get("goal")).toBe("🎯 active 0s");
		}
	});

	it("handles pause, resume, and clear deterministically in print/RPC/json non-TUI modes", async () => {
		for (const mode of ["print", "rpc", "json"] as const) {
			const harness = createHarness();
			harness.ctx.hasUI = false;
			harness.ctx.mode = mode;

			await harness.commands.get("goal").handler(`${mode} lifecycle objective`, harness.ctx);
			await harness.commands.get("goal").handler("pause", harness.ctx);

			expect(harness.abort).toHaveBeenCalled();
			expect(harness.statuses.get("goal")).toBe("🎯 paused");
			expect(harness.notifications.at(-1)?.message).toBe(`Goal paused: ${mode} lifecycle objective`);
			expect(
				harness.handlers.get("tool_call")![0]({ type: "tool_call", toolName: "bash" }, harness.ctx),
			).toMatchObject({ block: true });

			await harness.commands.get("goal").handler("resume", harness.ctx);

			expect(harness.statuses.get("goal")).toBe("🎯 active 0s");
			expect(harness.sent).toHaveLength(2);
			expect(harness.sent[1].content).toContain("explicitly resumed the paused REPI /goal");
			expect(harness.sent[1].content).toContain(`${mode} lifecycle objective`);
			expect(
				harness.handlers.get("tool_call")![0]({ type: "tool_call", toolName: "bash" }, harness.ctx),
			).toBeUndefined();

			await harness.commands.get("goal").handler("clear", harness.ctx);

			expect(harness.statuses.get("goal")).toBeUndefined();
			expect(harness.notifications.at(-1)?.message).toBe(`Goal cleared: ${mode} lifecycle objective`);
			expect(harness.entries.at(-1)).toMatchObject({
				type: "custom",
				customType: REPI_GOAL_STATE_ENTRY_TYPE,
				data: { version: 1, goal: null },
			});
		}
	});

	it("replaces an existing goal without waiting for RPC/non-TUI confirmation dialogs", async () => {
		for (const mode of ["rpc", "json"] as const) {
			const harness = createHarness();
			harness.ctx.hasUI = true;
			harness.ctx.mode = mode;
			harness.ctx.ui.confirm = vi.fn(async () => false);

			await harness.commands.get("goal").handler(`${mode} first objective`, harness.ctx);
			await harness.commands.get("goal").handler(`${mode} replacement objective`, harness.ctx);

			expect(harness.ctx.ui.confirm).not.toHaveBeenCalled();
			expect(harness.sent).toHaveLength(2);
			expect(harness.sent[1].content).toContain(`${mode} replacement objective`);
			expect(harness.entries.at(-1)).toMatchObject({
				type: "custom",
				customType: REPI_GOAL_STATE_ENTRY_TYPE,
				data: { version: 1, goal: { text: `${mode} replacement objective`, status: "active" } },
			});
		}
	});

	it("keeps a fresh profile without legacy goal state quiet in non-TUI startup/shutdown", () => {
		for (const mode of ["print", "rpc", "json"] as const) {
			const harness = createHarness();
			harness.ctx.hasUI = false;
			harness.ctx.mode = mode;

			harness.handlers.get("session_start")![0]({ type: "session_start", reason: "fresh" }, harness.ctx);
			expect(harness.sent).toHaveLength(0);
			expect(harness.statuses.get("goal")).toBeUndefined();
			expect(harness.entries.some((entry) => entry.customType === REPI_GOAL_STATE_ENTRY_TYPE)).toBe(false);

			harness.handlers.get("session_shutdown")![0]({ type: "session_shutdown" }, harness.ctx);
			expect(harness.statuses.get("goal")).toBeUndefined();
			expect(harness.entries.some((entry) => entry.customType === REPI_GOAL_STATE_ENTRY_TYPE)).toBe(false);
		}
	});

	it("surfaces goal command/status through an RPC-style extension context", async () => {
		const harness = createHarness();
		harness.ctx.hasUI = true;
		harness.ctx.mode = "rpc";

		await harness.commands.get("goal").handler("--tokens 1k rpc objective", harness.ctx);
		await harness.commands.get("goal").handler("status", harness.ctx);

		expect(harness.statuses.get("goal")).toBe("🎯 active 0/1k");
		expect(harness.notifications.map((item) => item.message).join("\n")).toContain("Goal: rpc objective");
	});

	it("stops auto-continuation at the token budget and keeps resume bounded", async () => {
		const harness = createHarness();
		await harness.commands.get("goal").handler("--tokens 1k budget objective", harness.ctx);
		harness.entries.push({
			type: "message",
			message: { role: "assistant", usage: { input: 800, output: 400 } },
		});

		await harness.handlers.get("agent_end")![0](
			{ type: "agent_end", messages: [{ role: "assistant", stopReason: "stop" }] },
			harness.ctx,
		);

		expect(harness.sent).toHaveLength(1);
		expect(harness.statuses.get("goal")).toBe("🎯 budget 1.2k/1k");
		expect(harness.notifications.at(-1)).toMatchObject({
			message: "Goal token budget reached: 1.2k/1k",
			level: "warning",
		});

		await harness.commands.get("goal").handler("resume", harness.ctx);

		expect(harness.sent).toHaveLength(1);
		expect(harness.statuses.get("goal")).toBe("🎯 budget 1.2k/1k");
		expect(harness.notifications.at(-1)?.message).toBe("Goal token budget is still reached: 1.2k/1k");
	});

	it("shows /goal help with current status without starting a turn", async () => {
		const harness = createHarness();

		await harness.commands.get("goal").handler("help", harness.ctx);
		expect(harness.sent).toHaveLength(0);
		expect(harness.notifications.at(-1)?.message).toContain("REPI /goal runs a task until verified completion.");

		await harness.commands.get("goal").handler("--tokens 2k help objective", harness.ctx);
		await harness.commands.get("goal").handler("help", harness.ctx);

		const help = harness.notifications.at(-1)?.message ?? "";
		expect(help).toContain("Current:");
		expect(help).toContain("Goal: help objective");
		expect(help).toContain("Tokens: 0/2k");
	});

	it("restores legacy pi-goal state into the REPI footer", () => {
		const legacyGoal = createGoalState({ status: "paused" });
		const harness = createHarness([{ type: "custom", customType: "goal-state", data: { goal: legacyGoal } }]);
		harness.handlers.get("session_start")![0]({ type: "session_start", reason: "startup" }, harness.ctx);
		expect(harness.statuses.get("goal")).toBe("🎯 paused");
		expect(formatGoalFooterStatus(legacyGoal)).toBe("🎯 paused");
	});
});

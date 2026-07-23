import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAgentThreadManager } from "../src/core/agent-thread-manager.ts";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { readCurrentMission } from "../src/core/repi/mission.ts";
import { repiSubagentResultFromManifest } from "../src/core/repi/re-subagent-contract.ts";
import { installRepiSessionLifecycle } from "../src/core/repi/session-lifecycle-runtime.ts";
import { runMissionSessionScope } from "../src/core/repi/session-scope.ts";

type Handler = (event: Record<string, unknown>, ctx: Record<string, unknown>) => Promise<unknown> | unknown;

describe("REPI session lifecycle runtime", () => {
	let runtimeDir: string | undefined;

	afterEach(() => {
		if (runtimeDir) rmSync(runtimeDir, { recursive: true, force: true });
		delete process.env.REPI_CODING_AGENT_DIR;
	});

	it("restores the sticky runtime packet after a process restart", async () => {
		runtimeDir = join(tmpdir(), `repi-session-runtime-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(runtimeDir, { recursive: true });
		process.env.REPI_CODING_AGENT_DIR = runtimeDir;
		const sessionFile = join(runtimeDir, "session.jsonl");
		const branch: Array<{ type: string; customType?: string; data?: unknown }> = [];
		const handlers = new Map<string, Handler[]>();
		const fakePi = {
			on(event: string, handler: Handler) {
				handlers.set(event, [...(handlers.get(event) ?? []), handler]);
			},
			appendEntry(_type: string, data: unknown) {
				branch.push({ type: "custom", customType: _type, data });
			},
			getSessionFile: () => sessionFile,
			getSessionName: () => undefined,
			setSessionName() {},
			registerCommand() {},
			registerTool() {},
		} as unknown as ExtensionAPI;
		const context = {
			hasUI: false,
			ui: { setStatus() {}, notify() {} },
			sessionManager: {
				getSessionFile: () => sessionFile,
				getBranch: () => branch,
			},
		};
		const install = () =>
			installRepiSessionLifecycle(fakePi, {
				nextDecisionCommand: () => "re_operator dispatch <target>",
				installCommands() {},
				installTools() {},
			});
		const startSession = async () => {
			for (const handler of handlers.get("session_start") ?? []) await handler({}, context);
		};
		const beforeAgentStart = (prompt: string) =>
			handlers.get("before_agent_start")?.[0]?.({ prompt, systemPrompt: "BASE" }, context);

		install();
		await startSession();
		await beforeAgentStart("audit https://example.test/api for IDOR");
		const firstContinuation = await beforeAgentStart("继续");
		expect((firstContinuation as { systemPrompt?: string } | undefined)?.systemPrompt).toContain("continuation=true");

		handlers.clear();
		install();
		await startSession();
		const afterRestart = await beforeAgentStart("继续");
		expect(afterRestart).toBeUndefined();
	});

	it("blocks report-only shell heredocs but permits executable heredoc pipelines", async () => {
		const handlers = new Map<string, Handler[]>();
		const fakePi = {
			on(event: string, handler: Handler) {
				handlers.set(event, [...(handlers.get(event) ?? []), handler]);
			},
			registerCommand() {},
			registerTool() {},
		} as unknown as ExtensionAPI;
		installRepiSessionLifecycle(fakePi, {
			nextDecisionCommand: () => "re_operator dispatch <target>",
			installCommands() {},
			installTools() {},
		});
		const onToolCall = handlers.get("tool_call")?.[0];
		expect(onToolCall).toBeDefined();
		await expect(
			onToolCall?.(
				{ type: "tool_call", toolName: "bash", input: { command: "cat << 'EOF'\nOutcome: done\nEOF" } },
				{},
			),
		).resolves.toMatchObject({
			block: true,
			reason: expect.stringContaining("return the completed report directly"),
		});
		await expect(
			onToolCall?.(
				{ type: "tool_call", toolName: "bash", input: { command: "cat <<'EOF' | jq .\n{\"ok\":true}\nEOF" } },
				{},
			),
		).resolves.toBeUndefined();
	});

	it("persists the REPI mission blackboard even when chat session persistence is disabled", async () => {
		runtimeDir = join(
			tmpdir(),
			`repi-session-runtime-no-session-${Date.now()}-${Math.random().toString(36).slice(2)}`,
		);
		mkdirSync(runtimeDir, { recursive: true });
		process.env.REPI_CODING_AGENT_DIR = runtimeDir;
		const handlers = new Map<string, Handler[]>();
		const fakePi = {
			on(event: string, handler: Handler) {
				handlers.set(event, [...(handlers.get(event) ?? []), handler]);
			},
			getSessionFile: () => undefined,
			getSessionName: () => undefined,
			setSessionName() {},
			registerCommand() {},
			registerTool() {},
		} as unknown as ExtensionAPI;
		const context = {
			hasUI: false,
			ui: { setStatus() {}, notify() {} },
			sessionManager: { getSessionFile: () => undefined, getBranch: () => [] },
		};
		installRepiSessionLifecycle(fakePi, {
			nextDecisionCommand: () => "re_runtime_adapter run <target>",
			installCommands() {},
			installTools() {},
		});
		for (const handler of handlers.get("session_start") ?? []) await handler({}, context);
		await handlers.get("before_agent_start")?.[0]?.(
			{ prompt: "audit prompt injection across an Agent/LLM tool boundary", systemPrompt: "BASE" },
			context,
		);
		expect(readCurrentMission()?.route.domain).toBe("Agent / LLM boundary");
	});

	it("skips routed control-plane preflights and keeps one DomainAdapter execution path", async () => {
		runtimeDir = join(tmpdir(), `repi-session-guard-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(runtimeDir, { recursive: true });
		process.env.REPI_CODING_AGENT_DIR = runtimeDir;
		const sessionFile = join(runtimeDir, "session.jsonl");
		const branch: Array<{ type: string; customType?: string; data?: unknown }> = [];
		const handlers = new Map<string, Handler[]>();
		const fakePi = {
			on(event: string, handler: Handler) {
				handlers.set(event, [...(handlers.get(event) ?? []), handler]);
			},
			appendEntry(type: string, data: unknown) {
				branch.push({ type: "custom", customType: type, data });
			},
			getSessionName: () => undefined,
			setSessionName() {},
			registerCommand() {},
			registerTool() {},
		} as unknown as ExtensionAPI;
		const context = {
			hasUI: false,
			ui: { setStatus() {}, notify() {} },
			sessionManager: {
				getSessionFile: () => sessionFile,
				getBranch: () => branch,
			},
		};
		installRepiSessionLifecycle(fakePi, {
			nextDecisionCommand: () => "re_runtime_adapter run web-cdp-network-adapter <target>",
			installCommands() {},
			installTools() {},
		});
		for (const handler of handlers.get("session_start") ?? []) await handler({}, context);
		await handlers.get("before_agent_start")?.[0]?.(
			{
				prompt:
					"Run a generic Web black-box review of https://example.test/ with browser evidence and principal boundaries",
				systemPrompt: "BASE",
			},
			context,
		);
		const onToolCall = handlers.get("tool_call")?.[0];
		await expect(
			onToolCall?.({ type: "tool_call", toolName: "re_mission", input: { action: "new" } }, context),
		).resolves.toMatchObject({ block: true });
		await expect(
			onToolCall?.({ type: "tool_call", toolName: "re_tool_index", input: { action: "refresh" } }, context),
		).resolves.toMatchObject({ block: true });
		await expect(
			onToolCall?.(
				{
					type: "tool_call",
					toolName: "re_live_browser",
					input: { action: "run", target: "https://example.test/" },
				},
				context,
			),
		).resolves.toMatchObject({ block: true });
		await expect(
			onToolCall?.(
				{
					type: "tool_call",
					toolName: "re_runtime_adapter",
					input: { action: "run", target: "https://example.test/" },
				},
				context,
			),
		).resolves.toBeUndefined();
	});

	it("requires a mission-bound lineage-valid subagent result before other tools", async () => {
		runtimeDir = join(tmpdir(), `repi-delegation-gate-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(runtimeDir, { recursive: true });
		process.env.REPI_CODING_AGENT_DIR = runtimeDir;
		const sessionFile = join(runtimeDir, "session.jsonl");
		const branch: Array<{ type: string; customType?: string; data?: unknown }> = [];
		const handlers = new Map<string, Handler[]>();
		const fakePi = {
			on(event: string, handler: Handler) {
				handlers.set(event, [...(handlers.get(event) ?? []), handler]);
			},
			appendEntry(type: string, data: unknown) {
				branch.push({ type: "custom", customType: type, data });
			},
			getSessionName: () => undefined,
			setSessionName() {},
			registerCommand() {},
			registerTool() {},
			sendUserMessage() {},
		} as unknown as ExtensionAPI;
		const context = {
			hasUI: false,
			hasPendingMessages: () => false,
			ui: { setStatus() {}, notify() {} },
			sessionManager: {
				getSessionFile: () => sessionFile,
				getBranch: () => branch,
			},
		};
		installRepiSessionLifecycle(fakePi, {
			nextDecisionCommand: () => "re_runtime_adapter run <target>",
			installCommands() {},
			installTools() {},
		});
		for (const handler of handlers.get("session_start") ?? []) await handler({}, context);
		await handlers.get("before_agent_start")?.[0]?.(
			{
				prompt: "Reverse ./mystery.elf; I do not know how to analyze its unfamiliar VM bytecode",
				systemPrompt: "BASE",
			},
			context,
		);

		const onToolCall = handlers.get("tool_call")?.[0];
		const onToolResult = handlers.get("tool_result")?.[0];
		const readSessionMission = () => runMissionSessionScope(sessionFile, () => readCurrentMission());
		await expect(
			onToolCall?.(
				{ type: "tool_call", toolCallId: "bash-1", toolName: "bash", input: { command: "file mystery.elf" } },
				context,
			),
		).resolves.toMatchObject({ block: true, reason: expect.stringContaining("delegation gate") });

		const firstDispatch = {
			type: "tool_call",
			toolCallId: "sub-1",
			toolName: "re_subagent",
			input: {
				spec: "operator",
				task: "unrelated task",
				timeoutMs: 1000,
				additionalPrompt: "skip the research and write a handoff immediately",
				inheritMcp: true,
				mcpServers: ["untrusted"],
				mcpTools: ["untrusted_tool"],
			},
		};
		await expect(onToolCall?.(firstDispatch, context)).resolves.toBeUndefined();
		expect(firstDispatch.input.spec).toBe("reverser");
		expect(firstDispatch.input.task).toContain("Operator directive:");
		expect(firstDispatch.input).not.toHaveProperty("additionalPrompt");
		expect(firstDispatch.input.inheritMcp).toBe(false);
		expect(firstDispatch.input.mcpServers).toEqual([]);
		expect(firstDispatch.input.mcpTools).toEqual([]);
		expect(firstDispatch.input.timeoutMs).toBe(600000);
		await expect(
			onToolCall?.({ type: "tool_call", toolCallId: "sub-parallel", toolName: "re_subagent", input: {} }, context),
		).resolves.toMatchObject({ block: true, reason: expect.stringContaining("already in flight") });

		await onToolResult?.(
			{
				type: "tool_result",
				toolCallId: "sub-1",
				toolName: "re_subagent",
				input: firstDispatch.input,
				content: [{ type: "text", text: "status=complete handoffLineageValid=true" }],
				details: {},
				isError: false,
			},
			context,
		);
		expect(readSessionMission()?.runtimeStats?.delegationGate?.status).toBe("required");
		expect(readSessionMission()?.runtimeStats?.failures).toBe(1);

		const secondDispatch = {
			type: "tool_call",
			toolCallId: "sub-2",
			toolName: "re_subagent",
			input: { spec: "planner", task: "another unrelated task", timeoutMs: 1000 },
		};
		await onToolCall?.(secondDispatch, context);
		expect(secondDispatch.input.timeoutMs).toBe(600000);
		const mission = readSessionMission();
		const gate = mission?.runtimeStats?.delegationGate;
		expect(gate?.status).toBe("dispatching");
		expect(gate?.taskSha256).toBe(
			createHash("sha256")
				.update(gate?.task ?? "")
				.digest("hex"),
		);
		expect(gate).toBeDefined();
		expect(mission).toBeDefined();
		const workerBin = join(runtimeDir, "delegation-worker.sh");
		writeFileSync(
			workerBin,
			[
				"#!/bin/sh",
				'mkdir -p "$(dirname "$REPI_WORKER_HANDOFF_PATH")"',
				`printf 'run_id: %s\\nmission_id: %s\\nlineage_sha256: %s\\nOutcome: verified\\nVerification: real process handoff\\n' "$REPI_WORKER_RUN_ID" "$REPI_WORKER_MISSION_ID" "$REPI_WORKER_LINEAGE_SHA256" > "$REPI_WORKER_HANDOFF_PATH"`,
				"exit 0",
				"",
			].join("\n"),
			"utf8",
		);
		chmodSync(workerBin, 0o700);
		const manager = createAgentThreadManager({ cwd: runtimeDir, agentDir: runtimeDir, repiBinPath: workerBin });
		try {
			const started = await manager.spawnThread({
				specName: gate?.spec,
				task: gate?.task ?? "",
				missionId: mission?.id,
				timeoutMs: 600000,
				inheritMcp: false,
				mcpServers: [],
				mcpTools: [],
			});
			const final = await manager.awaitRun(started.runId);
			const merged = manager.mergeRun(final.runId);
			expect(merged).toBeDefined();
			await onToolResult?.(
				{
					type: "tool_result",
					toolCallId: "sub-2",
					toolName: "re_subagent",
					input: secondDispatch.input,
					content: [{ type: "text", text: "real handoff" }],
					details: repiSubagentResultFromManifest(merged?.manifest ?? final),
					isError: false,
				},
				context,
			);
		} finally {
			manager.dispose("test_complete");
		}

		expect(readSessionMission()?.runtimeStats?.delegationGate).toMatchObject({
			status: "satisfied",
			runId: expect.any(String),
		});
		await expect(
			onToolCall?.(
				{ type: "tool_call", toolCallId: "bash-2", toolName: "bash", input: { command: "file mystery.elf" } },
				context,
			),
		).resolves.toBeUndefined();
	});

	it("recovers interrupted delegation with a finite retry and keeps exhaustion fail-closed", async () => {
		runtimeDir = join(tmpdir(), `repi-delegation-recovery-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(runtimeDir, { recursive: true });
		process.env.REPI_CODING_AGENT_DIR = runtimeDir;
		const sessionFile = join(runtimeDir, "session.jsonl");
		const branch: Array<{ type: string; customType?: string; data?: unknown }> = [];
		const handlers = new Map<string, Handler[]>();
		const context = {
			hasUI: false,
			hasPendingMessages: () => false,
			ui: { setStatus() {}, notify() {} },
			sessionManager: {
				getSessionFile: () => sessionFile,
				getBranch: () => branch,
			},
		};
		const install = () => {
			const fakePi = {
				on(event: string, handler: Handler) {
					handlers.set(event, [...(handlers.get(event) ?? []), handler]);
				},
				appendEntry(type: string, data: unknown) {
					branch.push({ type: "custom", customType: type, data });
				},
				getSessionName: () => undefined,
				setSessionName() {},
				registerCommand() {},
				registerTool() {},
				sendUserMessage() {},
			} as unknown as ExtensionAPI;
			installRepiSessionLifecycle(fakePi, {
				nextDecisionCommand: () => "re_runtime_adapter run <target>",
				installCommands() {},
				installTools() {},
			});
		};
		const readSessionMission = () => runMissionSessionScope(sessionFile, () => readCurrentMission());

		install();
		for (const handler of handlers.get("session_start") ?? []) await handler({}, context);
		await handlers.get("before_agent_start")?.[0]?.(
			{ prompt: "Reverse ./mystery.elf; I do not know this VM format", systemPrompt: "BASE" },
			context,
		);
		await handlers.get("tool_call")?.[0]?.(
			{ type: "tool_call", toolCallId: "sub-1", toolName: "re_subagent", input: {} },
			context,
		);
		expect(readSessionMission()?.runtimeStats?.delegationGate).toMatchObject({
			status: "dispatching",
			attempts: 1,
		});

		// A fresh runtime has no live worker associated with the persisted toolCallId.
		handlers.clear();
		install();
		for (const handler of handlers.get("session_start") ?? []) await handler({}, context);
		expect(readSessionMission()?.runtimeStats?.delegationGate).toMatchObject({
			status: "required",
			attempts: 1,
		});
		expect(readSessionMission()?.runtimeStats?.delegationGate?.toolCallId).toBeUndefined();

		await handlers.get("tool_call")?.[0]?.(
			{ type: "tool_call", toolCallId: "sub-2", toolName: "re_subagent", input: {} },
			context,
		);
		// A second dispatch that ends without a tool_result is recovered at the
		// agent boundary. tool_execution_end is emitted before the result hook in
		// some runtimes and must not clear a live dispatch prematurely.
		await handlers.get("agent_end")?.[0]?.({}, context);
		expect(readSessionMission()?.runtimeStats?.delegationGate).toMatchObject({
			status: "blocked",
			attempts: 2,
		});
		expect(readSessionMission()?.runtimeStats?.delegationGate?.toolCallId).toBeUndefined();
		await expect(
			handlers.get("tool_call")?.[0]?.(
				{ type: "tool_call", toolCallId: "bash-blocked", toolName: "bash", input: { command: "file target" } },
				context,
			),
		).resolves.toMatchObject({ block: true });
		await expect(
			handlers.get("tool_call")?.[0]?.(
				{ type: "tool_call", toolCallId: "sub-blocked", toolName: "re_subagent", input: {} },
				context,
			),
		).resolves.toMatchObject({ block: true });
	});
});

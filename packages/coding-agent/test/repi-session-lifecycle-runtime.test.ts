import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ExtensionAPI } from "../src/core/extensions/types.ts";
import { installRepiSessionLifecycle } from "../src/core/repi/session-lifecycle-runtime.ts";

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
});

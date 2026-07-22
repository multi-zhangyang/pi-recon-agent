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
});

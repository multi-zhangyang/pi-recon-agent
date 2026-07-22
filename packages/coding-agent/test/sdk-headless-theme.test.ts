import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { AgentSession } from "../src/core/agent-session.ts";
import { createAgentSessionFromServices, createAgentSessionServices } from "../src/core/agent-session-services.ts";
import { SessionManager } from "../src/core/session-manager.ts";

const GLOBAL_THEME_KEY = Symbol.for("@pi-recon/repi-coding-agent:theme");

describe("headless SDK extension theme", () => {
	let session: AgentSession | undefined;
	let cwd: string | undefined;

	afterEach(() => {
		session?.dispose();
		session = undefined;
		if (cwd) rmSync(cwd, { recursive: true, force: true });
		cwd = undefined;
	});

	it("runs session_start theme helpers without initializing the interactive theme", async () => {
		cwd = mkdtempSync(join(tmpdir(), "repi-sdk-headless-theme-"));
		const globals = globalThis as Record<symbol, unknown>;
		const previousTheme = globals[GLOBAL_THEME_KEY];
		Reflect.deleteProperty(globals, GLOBAL_THEME_KEY);

		let rendered: string[] | undefined;
		try {
			const services = await createAgentSessionServices({
				cwd,
				agentDir: cwd,
				resourceLoaderOptions: {
					extensionFactories: [
						(pi) => {
							pi.on("session_start", (_event, ctx) => {
								const theme = ctx.ui.theme;
								rendered = [
									theme.fg("accent", "foreground"),
									theme.bg("selectedBg", "background"),
									theme.bold("bold"),
									theme.italic("italic"),
									theme.underline("underline"),
									theme.inverse("inverse"),
									theme.strikethrough("strikethrough"),
									theme.getThinkingBorderColor("high")("thinking"),
									theme.getBashModeBorderColor()("bash"),
								];
							});
						},
					],
					noSkills: true,
					noPromptTemplates: true,
					noThemes: true,
				},
			});
			const created = await createAgentSessionFromServices({
				services,
				sessionManager: SessionManager.inMemory(cwd),
			});
			session = created.session;

			await expect(session.bindExtensions({})).resolves.toBeUndefined();

			expect(rendered).toEqual([
				"foreground",
				"background",
				"bold",
				"italic",
				"underline",
				"inverse",
				"strikethrough",
				"thinking",
				"bash",
			]);
			expect(globals[GLOBAL_THEME_KEY]).toBeUndefined();
		} finally {
			if (previousTheme === undefined) Reflect.deleteProperty(globals, GLOBAL_THEME_KEY);
			else globals[GLOBAL_THEME_KEY] = previousTheme;
		}
	});
});

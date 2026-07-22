/**
 * opt #247 — reload() did not invalidate the replaced ExtensionRunner (MED).
 *
 * dispose() invalidates the runner (:914) so a captured `pi`/command ctx throws
 * "stale" after replacement. reload() is the symmetric replacement path —
 * _buildRuntime() swaps in a fresh ExtensionRunner + runtime/ctx — but it did
 * NOT invalidate the old runner. A captured ctx from the pre-reload
 * session_start stayed "active": `assertActive()` did not throw and the old
 * runtime kept accepting flag/tool/command mutations, silently diverging from
 * the live session. Two audit agents independently flagged this asymmetry.
 *
 * Fix: capture the previous runner before _buildRuntime reassigns
 * this._extensionRunner and invalidate it after, mirroring dispose().
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { getApiProvider, getModel } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createTestResourceLoader } from "./utilities.ts";

const STALE_MESSAGE =
	"This extension ctx is stale after session replacement or reload. Do not use a captured pi or command ctx after ctx.newSession(), ctx.fork(), ctx.switchSession(), or ctx.reload(). For newSession, fork, and switchSession, move post-replacement work into withSession and use the ctx passed to withSession. For reload, do not use the old ctx after await ctx.reload().";

describe("AgentSession reload() invalidates the replaced ExtensionRunner (opt #247)", () => {
	let session: AgentSession;
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-reload-invalidate-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });

		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const agent = new Agent({
			initialState: { model, systemPrompt: "Test", tools: [] },
		});

		const sessionManager = SessionManager.inMemory();
		const settingsManager = SettingsManager.create(tempDir, tempDir);
		const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
		authStorage.setRuntimeApiKey("anthropic", "test-key");
		const modelRegistry = ModelRegistry.create(authStorage, tempDir);

		session = new AgentSession({
			agent,
			sessionManager,
			settingsManager,
			cwd: tempDir,
			modelRegistry,
			resourceLoader: createTestResourceLoader(),
		});
	});

	afterEach(() => {
		session.dispose();
		vi.restoreAllMocks();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("invalidates the pre-reload runner so a captured ctx throws stale after reload()", async () => {
		const previousRunner = session.extensionRunner;
		// Pre-reload the ctx is live.
		expect(() => previousRunner.createContext().cwd).not.toThrow();

		await session.reload();

		// Post-reload the OLD runner is stale — a captured ctx must throw, not
		// silently keep mutating the dead runtime. Pre-fix (no invalidate) this
		// did not throw and the old ctx stayed "active".
		expect(() => previousRunner.createContext().cwd).toThrow(STALE_MESSAGE);

		// The NEW runner is live.
		expect(session.extensionRunner).not.toBe(previousRunner);
		expect(() => session.extensionRunner.createContext().cwd).not.toThrow();
	}, 15000);

	it("does not clear another model registry's API layer during reload()", async () => {
		const otherRegistry = ModelRegistry.inMemory(AuthStorage.inMemory());
		const marker = "other-registry-survived-session-reload";
		otherRegistry.registerProvider("other-registry-provider", {
			api: "openai-completions",
			streamSimple: () => {
				throw new Error(marker);
			},
		});
		const model = getModel("anthropic", "claude-sonnet-4-5")!;
		const context = { messages: [] };

		try {
			await session.reload();
			expect(() =>
				getApiProvider("openai-completions")?.streamSimple({ ...model, api: "openai-completions" }, context),
			).toThrow(marker);
		} finally {
			otherRegistry.unregisterProvider("other-registry-provider");
		}
	}, 15000);
});

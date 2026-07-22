/**
 * opt #209 — cleanupSessionResources AggregateError escaped dispose().
 *
 * `cleanupSessionResources` (packages/ai/src/session-resources.ts) catches each
 * registered cleanup's error into an array, then `throw new AggregateError(
 * errors, "Failed to cleanup session resources")` if ANY threw. AgentSession
 * called it at the END of `dispose()` OUTSIDE any try/catch — violating
 * dispose's own stated doctrine ("Best-effort: never let a dispose error
 * escape", applied to the aborts at 866 and the thread-manager dispose at 892).
 * A single throwing cleanup (e.g. an output-accumulator/bash temp-file unlink
 * hitting EACCES/ENOSPC) escaped dispose() and crashed session replacement /
 * quit. Fix: guard the call with try/catch like the surrounding dispose
 * best-effort blocks.
 *
 * This test registers a cleanup that throws and asserts `dispose()` does NOT
 * throw. Pre-fix, dispose() re-threw the AggregateError.
 */
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@pi-recon/repi-agent-core";
import { getModel, type Model, registerSessionResourceCleanup } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { createTestResourceLoader } from "./utilities.ts";

describe("opt #209: dispose guards cleanupSessionResources AggregateError", () => {
	let session: AgentSession;
	let tempDir: string;
	let unregister: () => void;
	let disposed: boolean;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-opt209-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });

		const model = getModel("anthropic", "claude-sonnet-4-5") as Model<"anthropic-messages">;
		const agent = new Agent({ initialState: { model, systemPrompt: "Test", tools: [] } });

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
		disposed = false;
	});

	afterEach(() => {
		// Remove the throwing cleanup from the module-level registry so it
		// cannot leak into any later test in this file (a second dispose would
		// otherwise hit it again).
		unregister();
		vi.restoreAllMocks();
		if (tempDir && existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
	});

	it("does NOT throw when a registered session-resource cleanup throws", () => {
		// Register a cleanup that always throws — cleanupSessionResources will
		// aggregate this into an AggregateError and (pre-fix) re-throw it out of
		// dispose().
		unregister = registerSessionResourceCleanup(() => {
			throw new Error("cleanup boom (opt #209)");
		});

		// Post-fix: the call is guarded → dispose succeeds.
		// Pre-fix: this re-threw `AggregateError: Failed to cleanup session resources`.
		expect(() => {
			session.dispose();
			disposed = true;
		}).not.toThrow();
		expect(disposed).toBe(true);
	});

	it("still runs other (non-throwing) cleanups and does not throw", () => {
		let ran = false;
		unregister = registerSessionResourceCleanup(() => {
			ran = true;
		});

		expect(() => {
			session.dispose();
			disposed = true;
		}).not.toThrow();
		expect(disposed).toBe(true);
		// The non-throwing cleanup must still have executed (guard only swallows
		// the aggregate, does not skip the loop).
		expect(ran).toBe(true);
	});

	it("runs disposal side effects only once", () => {
		let cleanupCalls = 0;
		unregister = registerSessionResourceCleanup(() => {
			cleanupCalls++;
		});

		session.dispose();
		session.dispose();

		expect(cleanupCalls).toBe(1);
	});
});

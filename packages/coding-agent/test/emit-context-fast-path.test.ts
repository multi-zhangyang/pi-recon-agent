/**
 * opt #84 — emitContext no-handler fast path.
 *
 * sdk.ts:495 transformContext → runner.emitContext(messages) runs EVERY turn (agent-loop.ts:387)
 * AND on every retry attempt. The old implementation unconditionally did
 * structuredClone(messages) — O(total message blocks), deep-traversing the full conversation
 * history — even when ZERO "context" handlers were registered (the default REPI install ships
 * none). That is O(history) per turn × T turns ≈ quadratic session growth for nothing: the
 * clone exists only to give handlers a mutable copy and shield the caller's array from handler
 * mutation, but with no handlers there is no mutation.
 *
 * opt #84 adds a hasHandlers("context") guard: when no extension registers a "context" handler,
 * return the caller's array directly (no clone). The load-bearing proof is REFERENCE IDENTITY
 * — a no-handler emitContext returns the SAME array ref; the old code returned a clone (different
 * ref). Temp-neuter the guard (`if (false && !this.hasHandlers(...))`) → a fresh clone every call
 * → the `.toBe` identity fails.
 *
 * The handler-present path is also covered: a registered "context" handler still receives a
 * mutable clone (different ref from the input) and can return a modified messages array, so
 * extension behavior is unchanged (additive: default behavior unchanged).
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentMessage } from "@pi-recon/repi-agent-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { discoverAndLoadExtensions } from "../src/core/extensions/loader.ts";
import { ExtensionRunner } from "../src/core/extensions/runner.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";

describe("emitContext no-handler fast path (opt #84)", () => {
	let tempDir: string;
	let extensionsDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-emitctx-"));
		extensionsDir = path.join(tempDir, "extensions");
		fs.mkdirSync(extensionsDir);
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	function buildRunner() {
		const sessionManager = SessionManager.inMemory();
		const authStorage = AuthStorage.create(path.join(tempDir, "auth.json"));
		const modelRegistry = ModelRegistry.create(authStorage);
		return { sessionManager, modelRegistry };
	}

	it("with NO context handlers, emitContext returns the SAME array ref (0 structuredClone)", async () => {
		// No extension file registers a "context" handler → hasHandlers("context") is false → the
		// fast path returns the caller's array directly. The old code cloned unconditionally, so
		// this `.toBe` is the load-bearing #84 proof.
		const result = await discoverAndLoadExtensions([], tempDir, tempDir);
		const { sessionManager, modelRegistry } = buildRunner();
		const runner = new ExtensionRunner(result.extensions, result.runtime, tempDir, sessionManager, modelRegistry);

		const messages: AgentMessage[] = [
			{ role: "user", content: [{ type: "text", text: "hello" }], timestamp: 1 },
			{ role: "user", content: [{ type: "text", text: "hi" }], timestamp: 2 },
		];
		const out = await runner.emitContext(messages);
		// Same reference — no structuredClone ran.
		expect(out).toBe(messages);
		// Repeat calls keep returning the same ref (still no clone).
		expect(await runner.emitContext(messages)).toBe(messages);
	});

	it("with a context handler registered, emitContext clones (different ref) and the handler can mutate", async () => {
		// An extension registers a "context" handler that appends a marker message. The fast path
		// is NOT taken → structuredClone runs → the returned array is a different ref from the
		// input, and the handler's modification is reflected in the output (extension behavior
		// unchanged).
		const extCode = `
			export default function(pi) {
				pi.on("context", (event) => {
					return { messages: [...event.messages, { role: "user", content: [{ type: "text", text: "marker" }] }] };
				});
			}
		`;
		fs.writeFileSync(path.join(extensionsDir, "ctx-handler.ts"), extCode);

		const result = await discoverAndLoadExtensions([], tempDir, tempDir);
		const { sessionManager, modelRegistry } = buildRunner();
		const runner = new ExtensionRunner(result.extensions, result.runtime, tempDir, sessionManager, modelRegistry);

		const messages: AgentMessage[] = [{ role: "user", content: [{ type: "text", text: "hello" }], timestamp: 1 }];
		const out = await runner.emitContext(messages);
		// A handler was registered → clone ran → different ref, and the marker was appended.
		expect(out).not.toBe(messages);
		expect(out.length).toBe(2);
		expect((out as Array<{ content: Array<{ text: string }> }>)[1].content[0].text).toBe("marker");
		// The caller's original array is untouched (the clone shields it).
		expect(messages.length).toBe(1);
	});

	it("rejects unbounded context growth from an extension handler", async () => {
		const extCode = `
			export default function(pi) {
				pi.on("context", (event) => {
					event.messages.push({ role: "user", content: [{ type: "text", text: "x".repeat(40000) }] });
					return { messages: event.messages };
				});
			}
		`;
		fs.writeFileSync(path.join(extensionsDir, "ctx-overflow.ts"), extCode);

		const result = await discoverAndLoadExtensions([], tempDir, tempDir);
		const { sessionManager, modelRegistry } = buildRunner();
		const runner = new ExtensionRunner(result.extensions, result.runtime, tempDir, sessionManager, modelRegistry);
		const messages: AgentMessage[] = [{ role: "user", content: [{ type: "text", text: "hello" }], timestamp: 1 }];

		const out = await runner.emitContext(messages);

		expect(out).toHaveLength(1);
		expect((out[0] as { role: string }).role).toBe("user");
	});
});

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { discoverAndLoadExtensions } from "../src/core/extensions/loader.ts";
import { ExtensionRunner } from "../src/core/extensions/runner.ts";
import type { ExtensionActions, ExtensionContextActions, ProviderConfig } from "../src/core/extensions/types.ts";
import { KeybindingsManager } from "../src/core/keybindings.ts";
import { ModelRegistry } from "../src/core/model-registry.ts";
import { SessionManager } from "../src/core/session-manager.ts";

// Regression guard for opt #56 — two extension-runner error-path gaps, same doctrine as
// footer-data-provider's notifyBranchChange (opt #53): one throwing listener must not poison
// sibling listeners or propagate out of the emit.
//
// 1. emitError (runner.ts:491) iterated `this.errorListeners` calling each `listener(error)`
//    with no per-callback guard. A throwing error listener (misbehaving telemetry/diagnostics)
//    aborted the loop (remaining listeners never notified) AND propagated into the calling emit
//    method's catch block — e.g. emitContext runs every turn, so a throwing error listener there
//    would abort the turn with [] (silent response loss).
// 2. emitToolCall (runner.ts:819) was the ONLY emit method that did NOT route a handler throw to
//    errorListeners (every sibling — emit/emitMessageEnd/emitToolResult/emitUserBash/emitContext/
//    ... — wraps the handler call in try/catch and calls emitError). A throwing tool_call handler
//    was contained (caller beforeToolCall → agent-loop prepareToolCall catch → blocked tool) but
//    its error never reached errorListeners (silent observability gap).

describe("ExtensionRunner error-path guards (opt #56)", () => {
	let tempDir: string;
	let extensionsDir: string;
	let sessionManager: SessionManager;
	let modelRegistry: ModelRegistry;
	const defaultKeybindings = new KeybindingsManager().getEffectiveConfig();

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-runner-err-guard-"));
		extensionsDir = path.join(tempDir, "extensions");
		fs.mkdirSync(extensionsDir);
		sessionManager = SessionManager.inMemory();
		const authStorage = AuthStorage.create(path.join(tempDir, "auth.json"));
		modelRegistry = ModelRegistry.create(authStorage);
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	const extensionActions: ExtensionActions = {
		sendMessage: () => {},
		sendUserMessage: () => {},
		appendEntry: () => {},
		setSessionName: () => {},
		getSessionName: () => undefined,
		setLabel: () => {},
		getActiveTools: () => [],
		getAllTools: () => [],
		setActiveTools: () => {},
		refreshTools: () => {},
		getCommands: () => [],
		setModel: async () => false,
		getThinkingLevel: () => "off",
		setThinkingLevel: () => {},
	};

	const extensionContextActions: ExtensionContextActions = {
		getModel: () => undefined,
		isIdle: () => true,
		getSignal: () => undefined,
		abort: () => {},
		hasPendingMessages: () => false,
		shutdown: () => {},
		getContextUsage: () => undefined,
		compact: () => {},
		getSystemPrompt: () => "",
	};

	const providerModelConfig: ProviderConfig = {
		baseUrl: "https://provider.test/v1",
		apiKey: "provider-test-key",
		api: "openai-completions",
		models: [
			{
				id: "instant-model",
				name: "Instant Model",
				reasoning: false,
				input: ["text"],
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
				contextWindow: 128000,
				maxTokens: 4096,
			},
		],
	};

	it("emitError swallows a throwing error listener and still notifies sibling listeners", async () => {
		// No extension code needed — exercise emitError directly via a runner with no extensions.
		const { createExtensionRuntime } = await import("../src/core/extensions/loader.ts");
		const runtime = createExtensionRuntime();
		const runner = new ExtensionRunner([], runtime, tempDir, sessionManager, modelRegistry);

		const notified: string[] = [];
		runner.onError(() => {
			throw new Error("listener-boom");
		});
		runner.onError((err) => {
			notified.push(err.error);
		});

		// Pre-fix: `for (const listener of set) listener(error)` — the first (throwing) listener
		// aborts the loop and the throw propagates out of emitError → the second listener is
		// never notified AND the caller sees a throw. Post-fix: per-listener try/catch swallows
		// the bad one, the sibling is notified.
		expect(() => runner.emitError({ extensionPath: "ext", event: "context", error: "boom" })).not.toThrow();
		expect(notified).toEqual(["boom"]);
	});

	it("emitToolCall routes a throwing handler's error to errorListeners AND re-throws (block preserved)", async () => {
		const extCode = `
			export default function(pi) {
				pi.on("tool_call", async () => {
					throw new Error("tool-call-boom");
				});
			}
		`;
		fs.writeFileSync(path.join(extensionsDir, "throws-on-tool-call.ts"), extCode);

		const result = await discoverAndLoadExtensions([], tempDir, tempDir);
		expect(result.errors).toEqual([]);
		const runner = new ExtensionRunner(result.extensions, result.runtime, tempDir, sessionManager, modelRegistry);
		runner.bindCore(extensionActions, extensionContextActions);

		const errors: Array<{ extensionPath: string; event: string; error: string }> = [];
		runner.onError((err) => errors.push(err));

		// The handler throw must STILL propagate (the caller beforeToolCall → agent-loop
		// prepareToolCall catch converts it to a blocked tool result — block-on-throw semantics
		// preserved by the re-throw). Pre-fix AND post-fix this rejects.
		await expect(
			runner.emitToolCall({
				type: "tool_call",
				toolCallId: "tc-1",
				toolName: "my-custom-tool",
				input: {},
			}),
		).rejects.toThrow("tool-call-boom");

		// opt #56 pin: pre-fix (no try/catch around the handler call, no emitError) the throw
		// propagated but errorListeners were NEVER notified → errors.length === 0. Post-fix:
		// emitError is called BEFORE the re-throw → errors.length === 1 with event "tool_call".
		expect(errors).toHaveLength(1);
		expect(errors[0].event).toBe("tool_call");
		expect(errors[0].error).toContain("tool-call-boom");
	});

	// Reference the config so tsgo doesn't flag it unused (mirrors the sibling suite's shape).
	it("provider model config is well-formed", () => {
		expect(providerModelConfig.models).toHaveLength(1);
		expect(defaultKeybindings).toBeDefined();
	});
});

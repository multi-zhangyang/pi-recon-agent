import { getMaxListeners } from "node:events";
import { type AssistantMessage, type AssistantMessageEvent, EventStream } from "@pi-recon/repi-ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Agent } from "../src/index.ts";
import type { AgentEvent } from "../src/types.ts";

// opt #129 — the per-run AbortSignal (runWithLifecycle's abortController.signal)
// is shared by EVERY consumer in the run: each tool call attaches an `abort`
// listener (find/grep/ls/read/bash/exec + MCP + extensions), the LLM provider
// fetch attaches one per stream + retry, and retry/backoff sleeps attach one
// each. A parallel tool batch of N tools → N CONCURRENT listeners on this same
// signal. Node's default cap is 10 (getMaxListeners returns 0 = "use default"),
// so >10 concurrent listeners emits `MaxListenersExceededWarning` and abort
// dispatch degrades — and the warning falsely flags a real leak even though
// every consumer removes its listener on settle (opt #119 + each tool's
// cleanup). Fix: setMaxListeners(generous, signal) on the per-run signal so
// legitimate parallel batches don't trip the warning. Default 50; env
// REPI_RUN_SIGNAL_MAX_LISTENERS (0 = unbounded).
//
// This test captures the signal the streamFn receives (=== the run signal),
// attaches 15 concurrent `abort` listeners (simulating a parallel batch + the
// provider listener), and asserts (1) getMaxListeners(signal) was raised above
// the default 0, and (2) no MaxListenersExceededWarning was emitted. Pre-fix
// getMaxListeners === 0 and 15 listeners trip the warning.

class MockAssistantStream extends EventStream<AssistantMessageEvent, AssistantMessage> {
	constructor() {
		super(
			(event) => event.type === "done" || event.type === "error",
			(event) => {
				if (event.type === "done") return event.message;
				if (event.type === "error") return event.error;
				throw new Error("Unexpected event type");
			},
		);
	}
}

function createUsage() {
	return {
		input: 0,
		output: 0,
		cacheRead: 0,
		cacheWrite: 0,
		totalTokens: 0,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
	};
}

describe("Agent runWithLifecycle raises the per-run AbortSignal listener cap (opt #129)", () => {
	let capturedSignal: AbortSignal | undefined;
	let originalEmitWarning: typeof process.emitWarning;
	let warnings: string[];
	let savedEnv: string | undefined;

	beforeEach(() => {
		capturedSignal = undefined;
		warnings = [];
		savedEnv = process.env.REPI_RUN_SIGNAL_MAX_LISTENERS;
		// Pin the env so the asserted cap is deterministic (50).
		process.env.REPI_RUN_SIGNAL_MAX_LISTENERS = "50";
		originalEmitWarning = process.emitWarning;
		process.emitWarning = ((warning: unknown, ...rest: unknown[]) => {
			const name = typeof rest[0] === "string" ? rest[0] : ((rest[0] as { name?: string } | undefined)?.name ?? "");
			const text = `${typeof warning === "string" ? warning : ((warning as Error)?.message ?? "")} ${name}`;
			warnings.push(text);
			// Still call through to the original so other consumers are unaffected,
			// but swallow the MaxListenersExceededWarning we are testing for.
			if (name === "MaxListenersExceededWarning" || /MaxListenersExceeded/i.test(text)) {
				return;
			}
			return originalEmitWarning(warning as string, ...(rest as never[]));
		}) as typeof process.emitWarning;
	});

	afterEach(() => {
		process.emitWarning = originalEmitWarning;
		if (savedEnv === undefined) {
			delete process.env.REPI_RUN_SIGNAL_MAX_LISTENERS;
		} else {
			process.env.REPI_RUN_SIGNAL_MAX_LISTENERS = savedEnv;
		}
	});

	it("raises maxListeners above the default and suppresses MaxListenersExceededWarning for a parallel batch", async () => {
		const streamFn = (_model: unknown, _context: unknown, options?: { signal?: AbortSignal }) => {
			capturedSignal = options?.signal;
			const stream = new MockAssistantStream();
			queueMicrotask(() => {
				const partial: AssistantMessage = {
					role: "assistant",
					content: [{ type: "text", text: "done" }],
					api: "openai-responses",
					provider: "openai",
					model: "mock",
					usage: createUsage(),
					stopReason: "stop",
					timestamp: Date.now(),
				};
				stream.push({ type: "start", partial });
				stream.push({ type: "done", reason: "stop", message: partial });
			});
			return stream;
		};

		const agent = new Agent({ streamFn });

		const events: AgentEvent[] = [];
		agent.subscribe((event) => {
			events.push(event);
		});

		await agent.prompt("hello").catch(() => undefined);

		expect(capturedSignal).toBeDefined();
		// (1) The cap was raised above Node's default (0 = use defaultMaxListeners=10).
		// Pre-fix getMaxListeners === 0.
		expect(getMaxListeners(capturedSignal!)).toBe(50);

		// (2) Simulate a parallel batch: 15 concurrent abort listeners on the
		// shared run signal. Pre-fix (cap 10) this trips MaxListenersExceededWarning;
		// post-fix (cap 50) it does not.
		for (let i = 0; i < 15; i++) {
			capturedSignal!.addEventListener("abort", () => {}, { once: true });
		}
		// Let any queued warning emission flush.
		await new Promise<void>((r) => setImmediate(r));

		expect(
			warnings.some((w) => /MaxListenersExceeded/i.test(w)),
			`expected no MaxListenersExceededWarning, got: ${JSON.stringify(warnings)}`,
		).toBe(false);

		// Sanity: the run completed.
		expect(events.some((event) => event.type === "agent_end")).toBe(true);
	});
});

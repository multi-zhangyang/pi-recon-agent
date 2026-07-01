import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AssistantMessage, AssistantMessageEvent } from "../src/types.ts";

// opt #131: `forwardStream` (register-builtins.ts) bridges an inner provider/
// extension stream into the outer AssistantMessageEventStream returned to the
// agent loop via a fire-and-forget IIFE. Without a try/catch, a throw from the
// inner stream's async iterator (a misbehaving custom extension streamSimple
// that throws mid-iteration instead of pushing a terminal event) escapes the
// IIFE → unhandledRejection (no global handler) AND no terminal event is
// forwarded → the outer `.result()` hangs forever. The fix wraps the IIFE body
// in try/catch and, on throw, synthesizes an error AssistantMessage, pushes an
// "error" event, and ends the target so `.result()` resolves with the error.
//
// This exercises the lazy-wrapper path (createLazySimpleStream + forwardStream)
// via the exported streamSimpleAnthropic, mocking the anthropic module so its
// streamSimple returns a throwing async iterable.

const baseMessage: AssistantMessage = {
	role: "assistant",
	content: [],
	api: "anthropic-messages",
	provider: "anthropic",
	model: "claude-sonnet-4-6",
	usage: {
		input: 0,
		output: 0,
		cacheRead: 0,
		cacheWrite: 0,
		totalTokens: 0,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
	},
	stopReason: "stop",
	timestamp: 0,
};

vi.mock("../src/providers/anthropic.ts", () => {
	const throwingStreamSimple = () => {
		// Inner stream yields a start event then THROWS mid-iteration — never
		// pushes a terminal done/error event (the misbehaving-extension case).
		return (async function* (): AsyncGenerator<AssistantMessageEvent> {
			yield { type: "start", partial: baseMessage };
			throw new Error("boom from inner stream");
		})();
	};
	return {
		streamAnthropic: throwingStreamSimple,
		streamSimpleAnthropic: throwingStreamSimple,
	};
});

describe("forwardStream catch-block throw safety (opt #131)", () => {
	const unhandled: unknown[] = [];
	let handler: (reason: unknown) => void;

	beforeEach(() => {
		unhandled.length = 0;
		handler = (reason: unknown) => {
			unhandled.push(reason);
		};
		process.on("unhandledRejection", handler);
	});

	afterEach(() => {
		process.off("unhandledRejection", handler);
	});

	it("resolves outer .result() with an error message when the inner stream throws mid-iteration", async () => {
		const { streamSimpleAnthropic } = await import("../src/providers/register-builtins.ts");

		const model = {
			id: "claude-sonnet-4-6",
			name: "Claude Sonnet 4",
			api: "anthropic-messages",
			provider: "anthropic",
			baseUrl: "https://api.anthropic.com",
			reasoning: true,
			input: ["text"],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 200000,
			maxTokens: 8192,
		};

		const result = await streamSimpleAnthropic(model as never, {
			messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
		}).result();

		// Flush microtasks so any escaped IIFE rejection would surface.
		await new Promise((resolve) => setImmediate(resolve));
		await new Promise((resolve) => setImmediate(resolve));

		// The throw must NOT escape the forwardStream IIFE.
		expect(unhandled.length).toBe(0);
		// The outer stream must resolve with an error AssistantMessage (not hang).
		expect(result.stopReason).toBe("error");
		expect(typeof result.errorMessage).toBe("string");
		expect(result.errorMessage).toMatch(/boom from inner stream/);
	});
});

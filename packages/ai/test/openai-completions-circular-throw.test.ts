import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getModel } from "../src/models.ts";
import { streamSimple } from "../src/stream.ts";
import { registerOpenAIFixtures } from "./model-fixtures.ts";

registerOpenAIFixtures();

// opt #130: provider stream IIFEs catch errors and push an "error" event with
// `errorMessage`. The non-`Error` branch used bare `JSON.stringify(error)`.
// When a backend / proxy rejects with a NON-`Error` value that is circular
// (or BigInt / Proxy), `JSON.stringify` THROWS — and throwing INSIDE the catch
// block escapes the IIFE → the dropped IIFE promise rejects →
// `unhandledRejection` (there is NO global handler) AND the "error" event is
// never pushed (the throw happens before `stream.push({type:"error"...})`) so
// `.result()` either hangs or surfaces a crash. This is the MAIN GLM path
// (openai-completions). The fix routes the non-`Error` branch through
// `safeStringifyError`, which falls back to `String(error)` (never throws).

describe("openai-completions catch-block circular-throw safety", () => {
	const originalUnhandled: typeof process.listeners = process.listeners.bind(process);
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
		// Sanity: no stray listeners from this test should remain.
		expect(originalUnhandled("unhandledRejection")).toEqual(process.listeners("unhandledRejection"));
	});

	it("stringifies a circular non-Error rejection without unhandledRejection", async () => {
		vi.mock("openai", () => {
			class FakeOpenAI {
				chat = {
					completions: {
						create: () => {
							const promise = Promise.resolve({}) as Promise<unknown> & {
								withResponse: () => Promise<unknown>;
							};
							// Reject with a CIRCULAR plain object — not an Error instance.
							// `JSON.stringify` throws on this; `String()` does not.
							const circular: { a: number; self?: unknown } = { a: 1 };
							circular.self = circular;
							promise.withResponse = async () => {
								throw circular;
							};
							return promise;
						},
					},
				};
			}
			return { default: FakeOpenAI };
		});

		const { compat: _compat, ...baseModel } = getModel<"openai-responses">("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;

		const result = await streamSimple(
			model,
			{
				messages: [{ role: "user", content: "hi", timestamp: Date.now() }],
			},
			{ apiKey: "test" },
		).result();

		// Flush microtasks so any dropped IIFE rejection would surface.
		await new Promise((resolve) => setImmediate(resolve));
		await new Promise((resolve) => setImmediate(resolve));

		// The catch block must NOT throw out of the IIFE.
		expect(unhandled.length).toBe(0);
		// The "error" event must be pushed and surfaced via result().
		expect(result.stopReason).toBe("error");
		expect(typeof result.errorMessage).toBe("string");
		expect(result.errorMessage!.length).toBeGreaterThan(0);
	});
});

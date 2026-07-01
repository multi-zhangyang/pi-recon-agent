import { fauxAssistantMessage, registerFauxProvider } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { AgentHarness } from "../../src/harness/agent-harness.ts";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";
import { InMemorySessionStorage } from "../../src/harness/session/memory-storage.ts";
import { Session } from "../../src/harness/session/session.ts";

// opt #116 — mirror of the Agent.runWithLifecycle fix. executeTurn's catch
// called emitRunFailure but NEVER aborted the run's AbortController → on a
// mid-stream listener throw the in-flight LLM fetch kept streaming (cost/quota
// leak) and kept pushing into the EventStream queue (unbounded growth) after
// the consumer broke out of `for await`. Fix: capture wasAborted, abort the
// controller if not already aborted, then emitRunFailure with the ORIGINAL
// wasAborted.
//
// The harness subscribe() listener receives (event, signal) where signal is
// the run's abortController.signal. This test captures it on message_start,
// throws on the first message_update to trigger the mid-stream throw path,
// and asserts the captured signal is aborted after the turn. Pre-fix the
// signal stays unaborted.

const registrations: Array<{ unregister(): void }> = [];

afterEach(() => {
	for (const registration of registrations.splice(0)) {
		registration.unregister();
	}
});

describe("AgentHarness executeTurn aborts the fetch on a mid-stream listener throw (opt #116)", () => {
	it("aborts the run AbortController when a message_update listener throws mid-stream", async () => {
		const registration = registerFauxProvider();
		registrations.push(registration);
		// A text response streamed with deltas so message_update fires (the
		// faux provider chunks text via streamWithDeltas).
		registration.setResponses([() => fauxAssistantMessage("hello world body")]);

		const session = new Session(new InMemorySessionStorage());
		const harness = new AgentHarness({
			env: new NodeExecutionEnv({ cwd: process.cwd() }),
			session,
			model: registration.getModel(),
		});

		let capturedSignal: AbortSignal | undefined;
		harness.subscribe((event, signal) => {
			if (event.type === "message_start" && signal) {
				capturedSignal = signal;
			}
			if (event.type === "message_update") {
				throw new Error("listener exploded on message_update");
			}
		});

		// prompt resolves: the agent-loop catch commits the partial via
		// message_end, rethrows → executeTurn catch → emitRunFailure (committed
		// branch: turn_end + agent_end) returns the partial. The distinguishing
		// assertion is the captured signal, not the return value.
		await harness.prompt("hello").catch(() => undefined);

		expect(capturedSignal).toBeDefined();
		// The KEY invariant: the run's AbortController was aborted, cancelling
		// the in-flight fetch. Pre-fix executeTurn's catch never aborted.
		expect(capturedSignal!.aborted).toBe(true);
	});
});

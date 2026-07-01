import { fauxAssistantMessage, registerFauxProvider } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { AgentHarness } from "../../src/harness/agent-harness.ts";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";
import { InMemorySessionStorage } from "../../src/harness/session/memory-storage.ts";
import { Session } from "../../src/harness/session/session.ts";

// opt #92 (F2) — abort() was a no-op during turn setup.
//
// prompt()/skill()/promptFromTemplate() called startRunPromise() (arming the
// run promise waitForIdle blocks on) BEFORE await createTurnState(), but the
// AbortController was only created + assigned to this.runAbortController inside
// executeTurn — AFTER createTurnState, emitQueueUpdate, and the before_agent_start
// hook awaits. During that whole window this.runAbortController was undefined, so
// abort() called `?.abort()` (no-op) then awaited waitForIdle() → the run
// proceeded uninterrupted to a real provider request despite the caller's abort.
//
// The fix creates + assigns the AbortController in prompt/skill/promptFromTemplate
// immediately after startRunPromise (before createTurnState) and threads it into
// executeTurn. This test holds the run in the before_agent_start hook and asserts
// the controller is ALREADY armed when the hook fires, and that abort() during
// that window actually aborts the signal (no longer a no-op).

const registrations: Array<{ unregister(): void }> = [];

afterEach(() => {
	for (const registration of registrations.splice(0)) {
		registration.unregister();
	}
});

describe("AgentHarness abort window (F2)", () => {
	it("runAbortController is armed before createTurnState, so abort() during turn setup is not a no-op", async () => {
		const registration = registerFauxProvider();
		registrations.push(registration);

		let releaseHook: (() => void) | undefined;
		const hookGate = new Promise<void>((resolve) => {
			releaseHook = resolve;
		});
		let resolveHookFired: ((controller: AbortController | undefined) => void) | undefined;
		const hookFired = new Promise<AbortController | undefined>((resolve) => {
			resolveHookFired = resolve;
		});
		let providerSignalAborted: boolean | undefined;
		registration.setResponses([
			(_context, options) => {
				providerSignalAborted = options?.signal?.aborted;
				return fauxAssistantMessage("post-abort");
			},
		]);

		const harness = new AgentHarness({
			env: new NodeExecutionEnv({ cwd: process.cwd() }),
			session: new Session(new InMemorySessionStorage()),
			model: registration.getModel(),
		});
		harness.on("before_agent_start", () => {
			const controller = (harness as unknown as { runAbortController?: AbortController }).runAbortController;
			resolveHookFired?.(controller);
			return hookGate.then(() => undefined);
		});

		const promptPromise = harness.prompt("first");

		// The hook fires inside executeTurn (after createTurnState). The fix arms
		// runAbortController BEFORE createTurnState, so by the time the hook runs
		// the controller is already set. Without the fix it was undefined here.
		const controllerAtHook = await hookFired;
		expect(controllerAtHook).toBeInstanceOf(AbortController);
		expect(controllerAtHook?.signal.aborted).toBe(false);

		// abort() during the pre-stream window: the signal must actually abort
		// (was a no-op without the fix → signal stayed non-aborted → real request).
		const abortPromise = harness.abort(); // don't await yet — waitForIdle blocks on the held run
		expect(controllerAtHook?.signal.aborted).toBe(true);

		releaseHook?.(); // release the held run so it proceeds with the aborted signal
		await abortPromise;
		await promptPromise;

		// The provider request fired with an already-aborted signal — the early-arm
		// makes abort() before the stream honored. (Without the fix the signal was
		// non-aborted and a full real turn ran.)
		expect(providerSignalAborted).toBe(true);
	});
});

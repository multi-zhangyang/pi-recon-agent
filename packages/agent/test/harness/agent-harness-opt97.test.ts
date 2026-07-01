import { fauxAssistantMessage, fauxToolCall, registerFauxProvider } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { AgentHarness } from "../../src/harness/agent-harness.ts";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";
import { InMemorySessionStorage } from "../../src/harness/session/memory-storage.ts";
import { Session } from "../../src/harness/session/session.ts";
import type { AgentMessage } from "../../src/types.ts";
import { calculateTool } from "../utils/calculate.ts";

const registrations: Array<{ unregister(): void }> = [];

afterEach(() => {
	for (const registration of registrations.splice(0)) {
		registration.unregister();
	}
});

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
	let resolve = (_value: T) => {};
	const promise = new Promise<T>((resolvePromise) => {
		resolve = resolvePromise;
	});
	return { promise, resolve };
}

describe("AgentHarness opt #97", () => {
	it("emitRunFailure does not double-push a phantom message when a real assistant was already committed", async () => {
		const registration = registerFauxProvider();
		registrations.push(registration);
		registration.setResponses([
			() =>
				fauxAssistantMessage(fauxToolCall("calculate", { expression: "2 + 2" }, { id: "call-1" }), {
					stopReason: "toolUse",
				}),
		]);
		const session = new Session(new InMemorySessionStorage());
		let systemPromptCalls = 0;
		const harness = new AgentHarness({
			env: new NodeExecutionEnv({ cwd: process.cwd() }),
			session,
			model: registration.getModel(),
			tools: [calculateTool],
			// A function systemPrompt is re-evaluated on each createTurnState. The
			// second call happens inside prepareNextTurn (AFTER message_end + turn_end
			// have already fired for the tool-call turn). Throwing there routes to
			// emitRunFailure — which pre-fix synthesized a full phantom lifecycle
			// (message_start + message_end + turn_end + agent_end) on top of the real
			// committed assistant → a second message_end + a phantom message.
			systemPrompt: () => {
				systemPromptCalls++;
				if (systemPromptCalls > 1) throw new Error("systemPrompt exploded");
				return "You are helpful.";
			},
		});

		const events: string[] = [];
		const assistantMessageEnds: AgentMessage[] = [];
		harness.subscribe((event) => {
			events.push(event.type);
			if (event.type === "message_end" && event.message.role === "assistant") {
				assistantMessageEnds.push(event.message);
			}
		});

		await harness.prompt("hello");

		// Exactly one assistant message_end — the real committed tool-call message.
		expect(assistantMessageEnds).toHaveLength(1);
		// No phantom second turn_end / agent_end.
		expect(events.filter((type) => type === "turn_end")).toHaveLength(1);
		expect(events.filter((type) => type === "agent_end")).toHaveLength(1);
		// The persisted transcript has exactly one assistant (no phantom).
		const entries = await session.getEntries();
		const assistants = entries.filter((entry) => entry.type === "message" && entry.message.role === "assistant");
		expect(assistants).toHaveLength(1);
	});

	it("flushes pending session writes BEFORE emitting turn_end to subscribers", async () => {
		const registration = registerFauxProvider();
		registrations.push(registration);
		registration.setResponses([() => fauxAssistantMessage("ok")]);
		const session = new Session(new InMemorySessionStorage());
		const harness = new AgentHarness({
			env: new NodeExecutionEnv({ cwd: process.cwd() }),
			session,
			model: registration.getModel(),
		});
		let customSeenAtTurnEnd = false;
		harness.subscribe(async (event) => {
			if (event.type === "message_end" && event.message.role === "assistant") {
				// Queue a pending session write (phase != idle → pending, not direct).
				await harness.appendMessage({
					role: "custom",
					customType: "listener",
					content: "listener write",
					display: true,
					timestamp: Date.now(),
				} as AgentMessage);
			}
			if (event.type === "turn_end") {
				// Pre-fix: turn_end was emitted BEFORE the flush, so the pending
				// custom message was not yet in the session here. Post-fix: the
				// flush runs first, so a subscriber observing turn_end sees it.
				const entries = await session.getEntries();
				const roles = entries.flatMap((entry) => (entry.type === "message" ? [entry.message.role] : []));
				customSeenAtTurnEnd = roles.includes("custom");
			}
		});

		await harness.prompt("hello");
		expect(customSeenAtTurnEnd).toBe(true);
	});

	it("abort() aborts navigateTree's in-flight signal and awaits its completion", async () => {
		const registration = registerFauxProvider();
		registrations.push(registration);
		registration.setResponses([() => fauxAssistantMessage("first"), () => fauxAssistantMessage("second")]);
		const session = new Session(new InMemorySessionStorage());
		const harness = new AgentHarness({
			env: new NodeExecutionEnv({ cwd: process.cwd() }),
			session,
			model: registration.getModel(),
		});
		await harness.prompt("first");
		await harness.prompt("second");

		const entries = await session.getEntries();
		const target = entries.find((entry) => entry.type === "message" && entry.message.role === "user");
		if (!target) throw new Error("no user entry to navigate to");

		const captured = deferred<AbortSignal>();
		harness.on("session_before_tree", (event) => {
			captured.resolve(event.signal);
			// Hang until the signal aborts, then cancel — proving abort() reaches
			// the hook's signal (pre-fix the signal was an unreachable fresh
			// AbortController that abort() never touched → this never resolved).
			return new Promise<{ cancel: true }>((resolve) => {
				event.signal.addEventListener("abort", () => resolve({ cancel: true }), { once: true });
			});
		});

		const navPromise = harness.navigateTree(target.id, { summarize: false });
		// Wait for the hook to fire (signal captured).
		const signal = await captured.promise;

		// abort() must abort the signal AND await navigateTree's completion
		// (pre-fix runPromise was not armed → waitForIdle returned immediately
		// while navigateTree hung forever in the hook).
		await harness.abort();
		const result = await navPromise;

		expect(signal.aborted).toBe(true);
		expect(result.cancelled).toBe(true);
	});

	it("dispose() prevents further runs, aborts in-flight, and is idempotent", async () => {
		const registration = registerFauxProvider();
		registrations.push(registration);
		let releaseResponse: (() => void) | undefined;
		const responseReleased = new Promise<void>((resolve) => {
			releaseResponse = resolve;
		});
		registration.setResponses([
			async () => {
				await responseReleased;
				return fauxAssistantMessage("done");
			},
		]);
		const session = new Session(new InMemorySessionStorage());
		const harness = new AgentHarness({
			env: new NodeExecutionEnv({ cwd: process.cwd() }),
			session,
			model: registration.getModel(),
		});
		let agentEndAfterDispose = false;
		harness.subscribe((event) => {
			if (event.type === "agent_end") agentEndAfterDispose = true;
		});

		// Start a run and let it reach the in-flight provider call.
		const promptPromise = harness.prompt("hello");
		await new Promise((resolve) => setTimeout(resolve, 0));

		await harness.dispose();
		// Idempotent: a second dispose() does not throw.
		await expect(harness.dispose()).resolves.toBeUndefined();
		// Further runs are rejected.
		await expect(harness.prompt("after dispose")).rejects.toMatchObject({ code: "invalid_state" });

		// Release the held response so the background run unblocks; the disposed
		// harness dropped all subscribers so no late agent_end callback fires.
		releaseResponse?.();
		await promptPromise.catch(() => undefined);
		expect(agentEndAfterDispose).toBe(false);
	});
});

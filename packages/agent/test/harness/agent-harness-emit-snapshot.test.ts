import { fauxAssistantMessage, registerFauxProvider } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { AgentHarness } from "../../src/harness/agent-harness.ts";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";
import { InMemorySessionStorage } from "../../src/harness/session/memory-storage.ts";
import { Session } from "../../src/harness/session/session.ts";

// opt #135: AgentHarness.emitAny/emitOwn/emitHook iterated the LIVE subscriber
// Set (`for (const listener of this.getHandlers(SUBSCRIBER_EVENT_TYPE) ?? [])`).
// A listener that called subscribe() / the returned unsubscribe() during its
// own callback mutated that Set mid-iteration — and concurrent emitAny
// invocations from the parallel tool batch exposed two iterators to each
// other's mutations. V8 visits a Set entry added during iteration if the
// iterator hasn't passed it, so a handler registered mid-event would receive
// that SAME event (wrong), and a delete could skip a not-yet-visited handler
// or throw `Set modified during iteration`. The fix snapshots the handlers
// (Array.from) before iterating so mid-emit (un)subscribes only affect LATER
// events. This test registers listener2 from inside listener1's first callback
// and asserts listener2 does NOT receive the event it was registered during.

const registrations: Array<{ unregister(): void }> = [];

afterEach(() => {
	for (const registration of registrations.splice(0)) {
		registration.unregister();
	}
});

describe("AgentHarness emit subscriber-snapshot (opt #135)", () => {
	it("a handler subscribed mid-event does not receive the event it was subscribed during", async () => {
		const registration = registerFauxProvider();
		registrations.push(registration);
		registration.setResponses([() => fauxAssistantMessage("done")]);

		const harness = new AgentHarness({
			env: new NodeExecutionEnv({ cwd: process.cwd() }),
			session: new Session(new InMemorySessionStorage()),
			model: registration.getModel(),
		});

		let listener1First: string | undefined;
		let listener2First: string | undefined;
		let listener3First: string | undefined;

		// listener1 subscribes listener2 on the FIRST event it sees.
		harness.subscribe((event) => {
			if (listener1First === undefined) {
				listener1First = event.type;
				harness.subscribe((e2) => {
					// Only record the first event listener2 ever sees.
					if (listener2First === undefined) listener2First = e2.type;
				});
			}
		});

		// listener3 was registered BEFORE the run, so it is in the snapshot for
		// the first event and records that event's type as the reference.
		harness.subscribe((event) => {
			if (listener3First === undefined) listener3First = event.type;
		});

		await harness.prompt("hello");

		// Sanity: the run emitted at least one broadcast event.
		expect(listener1First).toBeDefined();
		expect(listener3First).toBeDefined();
		// listener1 and listener3 both saw the first event (same reference type).
		expect(listener1First).toBe(listener3First);

		// The discriminator: listener2 was registered DURING the first event.
		// With the snapshot fix it does NOT receive that event — its first event
		// is a LATER one. Pre-fix (live Set) V8 would visit the newly-added
		// listener2 in the same for-of, so listener2First === listener3First.
		expect(listener2First).toBeDefined();
		expect(listener2First).not.toBe(listener3First);
	});
});

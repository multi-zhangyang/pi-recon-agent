import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeRunId } from "../src/core/agent-thread-manager.ts";

// opt #274: makeRunId was `${ISO-ms}-${specName}` — two spawns of the same spec
// in the same millisecond (parallel re_subagent delegations) produced an
// IDENTICAL runId → identical runRoot → the second spawn truncated the first
// run's stdout/stderr/manifest and evicted the first child from the children
// map (orphaning it from the exit-hook reaper → cost leak; wrong manifest
// delivered to one caller). The fix appends a randomBytes(4) hex suffix so
// runRoot is unique per spawn. This test freezes the clock so both calls land
// in the same millisecond — without the random suffix the two runIds are
// identical and the test fails.

describe("makeRunId uniqueness (opt #274)", () => {
	beforeEach(() => {
		// Freeze `new Date()` so both makeRunId calls observe the same millisecond.
		vi.setSystemTime(new Date("2026-07-01T00:00:00.000Z"));
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("two same-spec same-millisecond runIds differ (random suffix prevents runRoot collision)", () => {
		const a = makeRunId("explorer");
		const b = makeRunId("explorer");
		expect(a).not.toBe(b);
	});

	it("two different-spec same-millisecond runIds differ", () => {
		const a = makeRunId("explorer");
		const b = makeRunId("reasoner");
		expect(a).not.toBe(b);
	});

	it("keeps the ISO-ms prefix + spec name for human sortability/identifiability", () => {
		const id = makeRunId("explorer");
		// Frozen clock → deterministic prefix; random suffix is the 8-hex tail.
		expect(id.startsWith("2026-07-01T00-00-00-000Z-explorer-")).toBe(true);
		expect(id.length).toBe("2026-07-01T00-00-00-000Z-explorer-".length + 8);
	});

	it("falls back to 'agent' when specName sanitizes to empty", () => {
		const id = makeRunId("!!!@#$%");
		expect(id.startsWith("2026-07-01T00-00-00-000Z-agent-")).toBe(true);
	});
});

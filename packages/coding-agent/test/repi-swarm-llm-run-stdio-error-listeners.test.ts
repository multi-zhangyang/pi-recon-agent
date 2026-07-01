// REPI opt #188 — repi-swarm-llm-run.mjs worker spawn stdio 'error' listeners.
//
// Root cause: the worker spawn pipes stdout/stderr (stdio:["ignore","pipe","pipe"])
// and attaches 'data' handlers but NO 'error' handlers on child.stdout/stderr.
// child.on("error",...) covers spawn failure but NOT a stream-level 'error' on
// the readable pipes. A Readable with no 'error' listener that emits 'error'
// (EIO/EPIPE when the worker is killed mid-output) → Unhandled 'error' event →
// crashes the whole orchestrator mid-pool (runPool finally cleanup never runs).
//
// Fix: swallow listeners `child.stdout?.on("error", () => {})` and
// `child.stderr?.on("error", () => {})` so the 'close' handler still resolves
// the worker with whatever was captured. Same doctrine as opt #36 (mcp-manager)
// / #40 (waitForChildProcess stdio).
//
// Test type: HONEST ROUTING PIN (behavioral). A behavioral integration test
// would require spawning the .mjs orchestrator (which itself spawns `repi`
// worker subprocesses) with a worker whose stdout emits 'error' after the first
// 'data' — too heavy/flaky for a unit test and the spawn is inline in the
// orchestrator (no extracted primitive to drive). The load-bearing invariant is
// that BOTH piped stdio streams have an 'error' listener attached. We assert
// that by reading the source. Revert either listener → its assertion FAILS.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const source = readFileSync(
	fileURLToPath(new URL("../../../scripts/reverse-agent/repi-swarm-llm-run.mjs", import.meta.url)),
	"utf-8",
);

describe("repi-swarm-llm-run worker spawn stdio 'error' listeners (opt #188 routing pin)", () => {
	it("attaches an 'error' swallower on child.stdout (the piped readable)", () => {
		// Revert the stdout listener → this assertion fails (the pattern is gone).
		expect(source).toContain('child.stdout?.on("error", () => {})');
	});

	it("attaches an 'error' swallower on child.stderr (the piped readable)", () => {
		// Revert the stderr listener → this assertion fails.
		expect(source).toContain('child.stderr?.on("error", () => {})');
	});

	it("still has the 'data' handlers and the child 'close'/'error' handlers (no accidental removal)", () => {
		// Guards against a false PASS from a sloppy edit that deleted the spawn
		// block entirely. The data handlers + child error/close handlers must
		// remain.
		expect(source).toContain('child.stdout.on("data",');
		expect(source).toContain('child.stderr.on("data",');
		expect(source).toContain('child.on("close",');
		expect(source).toContain('child.on("error",');
	});
});

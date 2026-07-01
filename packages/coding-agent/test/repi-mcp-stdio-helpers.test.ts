// REPI opt #173 — repi-mcp.mjs stdio child hardening helpers.
// Tests the extracted primitives in scripts/reverse-agent/lib/mcp-stdio-helpers.mjs:
//   - capStdioBuffer: rolling-tail byte cap on accumulated MCP stdio stdout
//   - killWithGrace: SIGTERM → SIGKILL escalation + await close
//   - safeWriteLine: idempotent stdin 'error' swallower + write
//   - drainHttpBody: best-effort Response.body drain (opt #49 doctrine)
//   - readHttpTextBounded: hard cap for HTTP MCP response bodies
//
// Each helper is temp-neuter-verified: reverting the fix makes the matching
// assertion fail with the documented error.

import { spawn } from "node:child_process";
import { describe, expect, test } from "vitest";

// Route the .mjs specifier through a non-literal const so tsgo does not try to
// resolve the plain JS module (TS7016 "no declaration file"). Matches the
// report-write-guard.test.ts pattern. Runtime still loads the real helper.
const MCP_HELPER = "../../../scripts/reverse-agent/lib/mcp-stdio-helpers.mjs";
const helpers = await import(MCP_HELPER);
const { capStdioBuffer, killWithGrace, safeWriteLine, drainHttpBody, readHttpTextBounded } = helpers;

describe("opt #173 capStdioBuffer", () => {
	test("byte-identical when under max", () => {
		const buf = capStdioBuffer("", "hello\n", 1024);
		expect(buf).toBe("hello\n");
		expect(buf.length).toBe(6);
	});

	test("appends across calls and stays identical under max", () => {
		let buf = "";
		buf = capStdioBuffer(buf, "abc", 100);
		buf = capStdioBuffer(buf, "def", 100);
		expect(buf).toBe("abcdef");
	});

	test("truncates to rolling tail when over max", () => {
		// Build a 2000-char string in 500-char chunks; cap at 1000.
		let buf = "";
		for (let i = 0; i < 4; i++) buf = capStdioBuffer(buf, "X".repeat(500), 1000);
		expect(buf.length).toBe(1000);
		// Tail: the last 1000 chars are all "X" from the final two chunks.
		expect(buf).toBe("X".repeat(1000));
	});

	test("keeps the most recent bytes (tail), not the head", () => {
		// "HEADHEADHEAD" is 12 chars; cap 10 -> slice(2) = "ADHEADHEAD".
		let buf = capStdioBuffer("", "HEADHEADHEAD", 10);
		expect(buf).toBe("ADHEADHEAD");
		expect(buf.length).toBe(10);
		// Append "TAIL" -> "ADHEADHEADTAIL" (14); cap 10 -> slice(4) = "ADHEADTAIL".
		buf = capStdioBuffer(buf, "TAIL", 10);
		expect(buf).toBe("ADHEADTAIL");
		expect(buf.length).toBe(10);
	});

	test("max === 0 disables the cap (unbounded)", () => {
		let buf = "";
		buf = capStdioBuffer(buf, "A".repeat(100000), 0);
		expect(buf.length).toBe(100000);
	});
});

describe("opt #173 killWithGrace", () => {
	test("escalates to SIGKILL when child ignores SIGTERM", async () => {
		// A child that installs a no-op SIGTERM handler — it will not exit on
		// SIGTERM and must be force-killed by the grace timer. The child
		// prints "ready" AFTER installing the handler so we can synchronize
		// (calling killWithGrace too early races Node startup and lets
		// SIGTERM land before the handler exists).
		const child = spawn(
			process.execPath,
			["-e", "process.on('SIGTERM', () => {}); process.stdout.write('ready\\n'); setInterval(() => {}, 1000);"],
			{ stdio: ["pipe", "pipe", "pipe"] },
		);

		// Wait until the child has installed its SIGTERM handler.
		await new Promise<void>((resolve) => {
			child.stdout.on("data", function onReady(c: Buffer) {
				if (c.toString().includes("ready")) {
					child.stdout.off("data", onReady);
					resolve();
				}
			});
		});

		const start = Date.now();
		const res = await killWithGrace(child, 300);
		const elapsed = Date.now() - start;

		// Must have force-killed (SIGKILL) since SIGTERM was ignored.
		expect(res.killed).toBe(true);
		expect(res.signalCode).toBe("SIGKILL");
		// Resolves after the child is actually dead (close fired).
		expect(child.exitCode).toBeNull();
		expect(child.signalCode).toBe("SIGKILL");
		// Bounded by grace + epsilon (safety net + close propagation).
		expect(elapsed).toBeLessThan(300 + 2000);
	}, 10000);

	test("resolves immediately when child already exited", async () => {
		const child = spawn(process.execPath, ["-e", "process.exit(0)"], { stdio: ["pipe", "pipe", "pipe"] });
		// Wait for natural exit.
		await new Promise<void>((r) => child.on("close", () => r()));
		expect(child.exitCode).toBe(0);
		const res = await killWithGrace(child, 5000);
		expect(res.killed).toBe(false);
		expect(res.exitCode).toBe(0);
	});
});

describe("opt #173 safeWriteLine", () => {
	test("writes a line to a live stdin", () => {
		const child = spawn(process.execPath, ["-e", "process.stdin.on('data',()=>{}); setInterval(()=>{},1000);"], {
			stdio: ["pipe", "pipe", "pipe"],
		});
		try {
			const ok = safeWriteLine(child.stdin, "ping\n");
			expect(ok).toBe(true);
			// Idempotent: a second write does not throw and does not re-attach.
			expect(safeWriteLine(child.stdin, "pong\n")).toBe(true);
		} finally {
			child.kill("SIGKILL");
		}
	});

	test("attaches an idempotent 'error' swallower so a destroyed-stdin EPIPE cannot crash", async () => {
		// Spawn a child that exits immediately, destroying the parent end of
		// stdin. Writing to the destroyed stream emits an asynchronous 'error'
		// (EPIPE / ERR_STREAM_DESTROYED); without a listener that is an
		// unhandled 'error' event crash. safeWriteLine attaches an idempotent
		// swallower (tagged so it attaches once) that absorbs it.
		const child = spawn(process.execPath, ["-e", "process.exit(0)"], { stdio: ["pipe", "pipe", "pipe"] });
		await new Promise<void>((r) => child.on("close", () => r()));

		const before = child.stdin.listenerCount("error");
		// First call attaches the swallower.
		expect(safeWriteLine(child.stdin, "after-death-1\n")).toBe(true);
		const afterFirst = child.stdin.listenerCount("error");
		expect(afterFirst).toBe(before + 1);
		// Second call does NOT re-attach (idempotent).
		expect(safeWriteLine(child.stdin, "after-death-2\n")).toBe(true);
		expect(child.stdin.listenerCount("error")).toBe(afterFirst);
		// Let any async 'error' fire — with the swallower it is caught, no
		// unhandled event. The test completing without throwing is the proof.
		await new Promise<void>((r) => setTimeout(r, 50));
	});

	test("returns false on null stdin", () => {
		expect(safeWriteLine(null, "x\n")).toBe(false);
	});
});

describe("opt #173 drainHttpBody", () => {
	test("cancels a Response body without throwing", async () => {
		let cancelled = false;
		const body = {
			cancel: async () => {
				cancelled = true;
			},
		};
		const response = { body };
		await drainHttpBody(response);
		expect(cancelled).toBe(true);
	});

	test("safe on null / missing body", async () => {
		await expect(drainHttpBody(null)).resolves.toBeUndefined();
		await expect(drainHttpBody({})).resolves.toBeUndefined();
		await expect(drainHttpBody({ body: null })).resolves.toBeUndefined();
	});

	test("swallows a cancel() that throws", async () => {
		const response = {
			body: {
				cancel: async () => {
					throw new Error("locked");
				},
			},
		};
		await expect(drainHttpBody(response)).resolves.toBeUndefined();
	});
});

describe("REPI MCP HTTP body hard cap", () => {
	test("reads a small response body", async () => {
		const response = new Response("hello");
		await expect(readHttpTextBounded(response, 1024, "unit_body")).resolves.toBe("hello");
	});

	test("rejects and cancels once the response exceeds the cap", async () => {
		let cancelled = false;
		const stream = new ReadableStream({
			start(controller) {
				controller.enqueue(new TextEncoder().encode("A".repeat(8)));
				controller.enqueue(new TextEncoder().encode("B".repeat(8)));
			},
			cancel() {
				cancelled = true;
			},
		});
		const response = new Response(stream);
		await expect(readHttpTextBounded(response, 10, "unit_body")).rejects.toThrow(/unit_body_too_large/);
		expect(cancelled).toBe(true);
	});

	test("maxBytes <= 0 disables the cap for explicit debugging", async () => {
		const response = new Response("X".repeat(2048));
		await expect(readHttpTextBounded(response, 0, "unit_body")).resolves.toHaveLength(2048);
	});
});

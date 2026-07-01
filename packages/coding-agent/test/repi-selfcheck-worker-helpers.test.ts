import { spawn } from "node:child_process";
import { describe, expect, it } from "vitest";

// Route the .mjs specifier through a non-literal const so tsgo does not try to
// resolve the plain JS module (TS7016 "no declaration file"). Matches the
// report-write-guard.test.ts pattern. Runtime still loads the real helper.
const WORKER_HELPER = "../../../scripts/reverse-agent/lib/worker-spawn-helpers.mjs";

/**
 * Spawns a node child that prints "ready" once its signal handlers are
 * installed, so the test does not race SIGTERM delivery with handler
 * registration (the helper sends SIGTERM synchronously on invocation).
 */
function spawnReadyChild(script: string) {
	// The signal handler must be installed BEFORE the readiness marker is
	// printed, so the test does not deliver SIGTERM before the handler exists.
	const child = spawn("node", ["-e", `(function(){ ${script} process.stdout.write("ready\\n"); })();`], {
		stdio: ["ignore", "pipe", "ignore"],
	});
	const ready = new Promise<void>((resolve) => {
		child.stdout.once("data", (d: Buffer) => {
			if (d.toString().includes("ready")) resolve();
		});
	});
	return { child, ready };
}

describe("repi-selfcheck worker-spawn-helpers (opt #175)", () => {
	it("capWorkerBuffer is byte-identical when under the cap", async () => {
		const mod = await import(WORKER_HELPER);
		const { capWorkerBuffer } = mod;
		expect(capWorkerBuffer("hello ", "world", 1024)).toBe("hello world");
		// exactly at the cap stays unchanged (<=, not <)
		expect(capWorkerBuffer("ab", "cd", 4)).toBe("abcd");
	});

	it("capWorkerBuffer keeps the rolling tail when over the cap", async () => {
		const mod = await import(WORKER_HELPER);
		const { capWorkerBuffer } = mod;
		const full = "0123456789ABCDEF";
		// append a chunk that pushes total over max -> last `max` bytes kept
		const result = capWorkerBuffer("0123456789", "ABCDEF", 8);
		expect(result).toBe(full.slice(-8));
		expect(result).toBe("89ABCDEF");
		// repeated appends stay bounded (rolling, not one-shot)
		let buf = "";
		const max = 10;
		for (let i = 0; i < 100; i++) buf = capWorkerBuffer(buf, `x=${i};`, max);
		expect(buf.length).toBe(max);
		expect(buf).toBe(
			Array.from({ length: 100 }, (_, i) => `x=${i};`)
				.join("")
				.slice(-max),
		);
	});

	it("capWorkerBuffer disables the cap when max <= 0", async () => {
		const mod = await import(WORKER_HELPER);
		const { capWorkerBuffer } = mod;
		expect(capWorkerBuffer("abc", "def", 0)).toBe("abcdef");
		expect(capWorkerBuffer("abc", "def", -1)).toBe("abcdef");
	});

	it("resolveWorkerMaxBytes honors env knob and fallback", async () => {
		const mod = await import(WORKER_HELPER);
		const { resolveWorkerMaxBytes, DEFAULT_WORKER_MAX_BYTES } = mod;
		expect(resolveWorkerMaxBytes({})).toBe(DEFAULT_WORKER_MAX_BYTES);
		expect(DEFAULT_WORKER_MAX_BYTES).toBe(1024 * 1024);
		expect(resolveWorkerMaxBytes({ REPI_SELFCHECK_WORKER_MAX_BYTES: "2048" })).toBe(2048);
		expect(resolveWorkerMaxBytes({ REPI_SELFCHECK_WORKER_MAX_BYTES: "0" })).toBe(0);
		// non-numeric / negative -> fallback
		expect(resolveWorkerMaxBytes({ REPI_SELFCHECK_WORKER_MAX_BYTES: "garbage" })).toBe(DEFAULT_WORKER_MAX_BYTES);
		expect(resolveWorkerMaxBytes({ REPI_SELFCHECK_WORKER_MAX_BYTES: "-5" })).toBe(DEFAULT_WORKER_MAX_BYTES);
	});

	it("killWorkerWithGrace escalates SIGTERM->SIGKILL for an ignoring child", async () => {
		const mod = await import(WORKER_HELPER);
		const { killWorkerWithGrace } = mod;
		// Child ignores SIGTERM; only SIGKILL can reap it.
		const { child, ready } = spawnReadyChild("process.on('SIGTERM',()=>{}); setInterval(()=>{}, 1000);");
		await ready;
		const graceMs = 500;
		const start = Date.now();
		const info = await killWorkerWithGrace(child, graceMs);
		const elapsed = Date.now() - start;
		// Resolved via close after SIGKILL, not via the ignored SIGTERM.
		expect(info.code).toBe(null);
		expect(info.signal).toBe("SIGKILL");
		// Dies within grace + epsilon (SIGKILL delivery + event loop turn).
		expect(elapsed).toBeLessThan(graceMs + 2000);
	});

	it("killWorkerWithGrace resolves cooperatively when child exits 0 on SIGTERM", async () => {
		const mod = await import(WORKER_HELPER);
		const { killWorkerWithGrace } = mod;
		// Child traps SIGTERM and exits 0 gracefully (cooperative shutdown).
		const { child, ready } = spawnReadyChild(
			"process.on('SIGTERM',()=>{ process.exit(0); }); setInterval(()=>{}, 1000);",
		);
		await ready;
		const info = await killWorkerWithGrace(child, 5000);
		expect(info.code).toBe(0);
		expect(info.signal).toBe(null);
		expect(info.error).toBe(undefined);
	});
});

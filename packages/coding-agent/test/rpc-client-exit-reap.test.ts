import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { RpcClient } from "../src/modes/rpc/rpc-client.ts";
import { killTrackedDetachedChildren, trackDetachedChildPid, untrackDetachedChildPid } from "../src/utils/shell.ts";

// Regression guard for opt #61 — process-exit / signal-teardown completeness.
// Two gaps:
//  (A1) RpcClient spawns a full agent child process but only `stop()` (an explicit
//       consumer call) ever killed it. A parent exit (crash, SIGKILL, forgotten
//       stop()) reparented the child to init and it kept making LLM API calls
//       (cost/quota leak) — the same class opt #46 fixed for AgentThreadManager.
//       Fix: a synchronous `process.on("exit")` reap hook SIGKILLs the in-flight
//       child. Mirrors AgentThreadManager.disposeChildren.
//  (A2) The per-mode signal handlers (print/rpc/interactive) reap tracked detached
//       bash children on SIGTERM/SIGHUP — but SIGINT (Ctrl+C) is NOT in their
//       handler lists, so Ctrl+C in print/rpc mode took the default-exit path
//       (exit 130) WITHOUT reaping → tracked detached children leaked. Fix:
//       `process.on("exit", killTrackedDetachedChildren)` at shell.ts module load
//       — fires on SIGINT-default / SIGHUP-default / process.exit / uncaughtException
//       (NOT SIGKILL) and is idempotent (the reaper clears the set).

const tempDirs: string[] = [];

function writeChildScript(contents: string): string {
	const dir = mkdtempSync(join(tmpdir(), "pi-rpc-client-exit-reap-"));
	tempDirs.push(dir);
	const path = join(dir, "child.mjs");
	writeFileSync(path, contents);
	return path;
}

/** Poll until `kill(pid, 0)` throws ESRCH (process no longer exists). */
async function waitForPidDead(pid: number, timeoutMs: number): Promise<boolean> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			process.kill(pid, 0);
		} catch {
			return true;
		}
		await new Promise<void>((resolve) => setTimeout(resolve, 25));
	}
	return false;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

describe("RpcClient process-exit reap hook (opt #61 A1)", () => {
	test("the exit hook SIGKILLs an in-flight RPC agent child on parent exit", async () => {
		// A child that stays alive forever (until reaped). start() waits 100ms then
		// confirms exitCode===null, so it resolves with the child still running.
		const client = new RpcClient({
			cliPath: writeChildScript(`
			setInterval(() => {}, 1000);
			process.stdin.resume();
		`),
		});
		await client.start();

		const internals = client as unknown as {
			process: { pid?: number; exitCode: number | null; signalCode: string | null } | null;
			exitHook: (() => void) | undefined;
		};
		const child = internals.process;
		expect(child).not.toBeNull();
		const pid = child!.pid;
		expect(pid).toBeTypeOf("number");
		// Sanity: the child is alive before the hook fires.
		expect(() => process.kill(pid!, 0)).not.toThrow();
		// The exit hook must be registered.
		expect(internals.exitHook).toBeTypeOf("function");
		// Simulate process exit: invoke the registered exit hook directly (the same
		// technique as audit-fix-mcp-inflight-reap.test.ts) without exiting the test.
		internals.exitHook!();

		const dead = await waitForPidDead(pid!, 4000);
		expect(dead).toBe(true);

		await client.stop();
	});

	test("killChild is a no-op once the child has already exited (no double-kill throw)", async () => {
		const client = new RpcClient({
			cliPath: writeChildScript(`
			process.stdin.once("data", () => process.exit(0));
			process.stdin.resume();
		`),
		});
		await client.start();
		// Trigger the child's own exit by sending any stdin byte.
		const internals = client as unknown as {
			process: { stdin: { write: (s: string) => void } } | null;
			exitHook: (() => void) | undefined;
		};
		internals.process!.stdin.write("x");
		// Wait for the child to exit.
		const childInternals = client as unknown as { process: { exitCode: number | null } | null };
		for (let i = 0; i < 50; i++) {
			if (childInternals.process?.exitCode !== null) break;
			await new Promise<void>((resolve) => setTimeout(resolve, 20));
		}
		expect(childInternals.process?.exitCode).toBe(0);
		// Firing the exit hook now must NOT throw (child already dead).
		expect(() => internals.exitHook!()).not.toThrow();
		await client.stop();
	});
});

describe("shell.ts exit reap of tracked detached children (opt #61 A2)", () => {
	test("killTrackedDetachedChildren SIGKILLs a tracked detached child", async () => {
		// Spawn a genuinely detached, unref'd child (the bash detached-child shape).
		const child = spawn(process.execPath, ["-e", "setInterval(()=>{}, 1000)"], {
			detached: true,
			stdio: "ignore",
		});
		child.unref();
		const pid = child.pid;
		expect(pid).toBeTypeOf("number");
		trackDetachedChildPid(pid!);
		// Sanity: alive.
		expect(() => process.kill(pid!, 0)).not.toThrow();
		// Invoke the reaper (the same function registered on process.on('exit')).
		killTrackedDetachedChildren();
		const dead = await waitForPidDead(pid!, 4000);
		expect(dead).toBe(true);
		// The set is cleared by the reaper; untrack is a hygiene no-op.
		untrackDetachedChildPid(pid!);
	});

	test("the reaper is registered as a process.on('exit') hook", () => {
		// The named-export reference must be in the exit listener list — this is the
		// wiring that closes the SIGINT / hard-exit gap (the reaper itself is tested
		// above; this pins that it actually fires on exit).
		expect(process.listeners("exit")).toContain(killTrackedDetachedChildren);
	});

	test("killTrackedDetachedChildren is idempotent (second fire is a no-op)", () => {
		// After clearing, a second call iterates an empty set. No throw, no-op.
		expect(() => killTrackedDetachedChildren()).not.toThrow();
	});
});

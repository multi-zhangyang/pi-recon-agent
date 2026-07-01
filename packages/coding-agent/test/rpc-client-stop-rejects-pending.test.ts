import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { RpcClient } from "../src/modes/rpc/rpc-client.ts";

// opt #120 — stop() only pendingRequests.clear()-ed (no rejection) and never
// touched pendingWaiters, relying on the child's exit handler to reject both.
// If the child ignored SIGTERM, stop() SIGKILLed it and nulled `this.process`
// BEFORE the late exit fired → the exit handler's `this.process !== childProcess`
// guard skipped rejection → in-flight send() waited 30s for a "Timeout" and
// waitForIdle/collectEvents waited 60s, all with a misleading timeout error
// instead of an immediate "stopped". Fix: stop() explicitly rejects both
// collections with a "stopped" error (no-op when the exit handler already ran).

const tempDirs: string[] = [];

function writeChildScript(contents: string): string {
	const dir = mkdtempSync(join(tmpdir(), "pi-rpc-client-stop-"));
	tempDirs.push(dir);
	const path = join(dir, "child.mjs");
	writeFileSync(path, contents);
	return path;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

/** Race `p` against a timeout. Returns whether `p` settled within `ms` and, if
 * it rejected, the error. Pre-fix the pending promises settled at 30s/60s →
 * `settled:false` at 5s; post-fix they reject with "stopped" in ~1s. */
async function settleWithin<T>(
	p: Promise<T>,
	ms: number,
): Promise<{ settled: boolean; rejected?: boolean; error?: Error }> {
	const sentinel = Symbol();
	let timer: NodeJS.Timeout | undefined;
	const timeout = new Promise<typeof sentinel>((resolve) => {
		timer = setTimeout(() => resolve(sentinel), ms);
	});
	const raced = await Promise.race([
		p.then(
			() => ({ settled: true, rejected: false }) as const,
			(error: Error) => ({ settled: true, rejected: true, error }) as const,
		),
		timeout,
	]);
	if (timer) clearTimeout(timer);
	if (raced === sentinel) return { settled: false };
	return raced as { settled: boolean; rejected?: boolean; error?: Error };
}

describe("RpcClient.stop() rejects pending waiters promptly (opt #120)", () => {
	// A child that ignores SIGTERM (so stop()'s 1s timeout fires → SIGKILL) and
	// never responds to stdin or emits anything on stdout. This forces the
	// SIGKILL-timeout path where the exit handler's guard skips rejection.
	const stubbornChild = `
process.on("SIGTERM", () => {});
process.stdin.resume();
setInterval(() => {}, 1_000_000);
// Signal readiness AFTER the SIGTERM handler is registered, so the test can
// wait for it before calling stop() — otherwise the SIGTERM can race ahead of
// handler registration (ESM eval) and the default disposition kills the child
// (exercising the exit-handler path, not the SIGKILL path we mean to test).
process.stderr.write("READY\\n");
`;

	/** Poll the child's accumulated stderr for the readiness marker (emitted after
	 * its SIGTERM handler is registered). Bounds the wait so a broken child fails
	 * fast instead of hanging the test. */
	async function waitForReady(client: RpcClient): Promise<void> {
		for (let i = 0; i < 100; i++) {
			if (client.getStderr().includes("READY")) return;
			await new Promise<void>((resolve) => setTimeout(resolve, 20));
		}
		throw new Error("stubborn child never signaled readiness");
	}

	test("an in-flight send() rejects with 'stopped' instead of waiting 30s for 'Timeout'", async () => {
		const client = new RpcClient({ cliPath: writeChildScript(stubbornChild) });
		await client.start();
		await waitForReady(client);

		// send() a request the child will never answer → stays pending.
		const commandsPromise = client.getCommands();

		const stopPromise = client.stop();
		// Race the in-flight request against 5s — pre-fix it waits 30s.
		const result = await settleWithin(
			commandsPromise.then(
				() => new Error("unexpectedly resolved"),
				(e) => {
					throw e;
				},
			),
			5000,
		);
		await stopPromise.catch(() => undefined);

		expect(result.settled).toBe(true);
		expect(result.rejected).toBe(true);
		expect(result.error?.message).toMatch(/stopped/i);
	});

	test("an in-flight waitForIdle rejects with 'stopped' instead of waiting 60s for 'Timeout'", async () => {
		const client = new RpcClient({ cliPath: writeChildScript(stubbornChild) });
		await client.start();
		await waitForReady(client);

		const idlePromise = client.waitForIdle(60000);
		await client.stop();

		const result = await settleWithin(
			idlePromise.then(
				() => new Error("unexpectedly resolved"),
				(e) => {
					throw e;
				},
			),
			5000,
		);

		expect(result.settled).toBe(true);
		expect(result.rejected).toBe(true);
		expect(result.error?.message).toMatch(/stopped/i);
	});
});

import { spawn } from "node:child_process";
import { describe, expect, it } from "vitest";
import { waitForChildProcess } from "../../src/utils/child-process.ts";

// Regression coverage for the stdio stream 'error' listener added to
// waitForChildProcess. A piped child's stdout/stderr can emit 'error'
// (EBADF/EIO/EPIPE — read end of the pipe closed, or a detached descendant
// holding the write end died abruptly) independently of the child's own
// 'error'/'exit'/'close'. Without a listener that is `Unhandled 'error' event`
// → crash. waitForChildProcess now attaches a swallow listener (opts #31/#36/#39
// doctrine) that marks the streams ended so finalization proceeds.

function spawnShortLived(ms: number): ReturnType<typeof spawn> {
	// Lives `ms` then exits 0; stdout is a real piped Readable.
	return spawn(process.execPath, ["-e", `setTimeout(()=>{process.exit(0)},${ms})`], {
		stdio: ["ignore", "pipe", "pipe"],
	});
}

describe("waitForChildProcess stdio stream-error handling", () => {
	it("resolves with the exit code on a normal child exit", async () => {
		const child = spawnShortLived(50);
		const code = await waitForChildProcess(child);
		expect(code).toBe(0);
	});

	it("does NOT crash with `Unhandled 'error' event` when stdout emits a stream error before exit, and still resolves", async () => {
		const child = spawnShortLived(300);
		// Start waiting first so the listeners are attached.
		const resultP = waitForChildProcess(child);
		// Synthesize the exact event the fix targets: a stream 'error' with no
		// write in flight, emitted while the child is still running. Pre-fix this
		// had no listener on child.stdout → Node throws `Unhandled 'error' event`
		// → worker crash. Post-fix the swallow listener handles it and the child's
		// later exit still resolves the promise.
		child.stdout?.emit("error", Object.assign(new Error("read EIO"), { code: "EIO" }));
		child.stderr?.emit("error", Object.assign(new Error("read EIO"), { code: "EIO" }));

		// Race against a hang — must resolve, not reject, not crash.
		const code = await Promise.race([
			resultP,
			new Promise<never>((_, reject) => setTimeout(() => reject(new Error("hung")), 4000)),
		]);
		expect(code).toBe(0);
	});
});

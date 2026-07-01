import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NodeExecutionEnv } from "../../src/harness/env/nodejs.ts";
import { getOrThrow } from "../../src/harness/types.ts";
import { createTempDir } from "./session-test-utils.ts";

// Mock node:child_process so exec's spawn returns a fake child whose stdout emits a data chunk but
// which NEVER emits "close" — simulating a killed process stuck in uninterruptible disk sleep
// (D-state, e.g. find/dd on a hung FUSE/NFS mount) where SIGKILL is deferred and "close" never
// fires. On Linux getShellConfig resolves /bin/bash via pathExists (no spawn), so the mock only
// intercepts the main exec child, not shell detection.
const fakeRef = vi.hoisted(() => ({ child: undefined as unknown }));

vi.mock("node:child_process", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:child_process")>();
	return {
		...actual,
		spawn: () => fakeRef.child,
	};
});

class FakeStream extends EventEmitter {
	setEncoding(): void {}
	// Emit a data chunk once a "data" listener attaches, simulating streaming output.
	override on(event: string, listener: (...args: unknown[]) => void): this {
		super.on(event, listener);
		if (event === "data") {
			setImmediate(() => this.emit("data", "streamed-chunk\n"));
		}
		return this;
	}
}

class FakeChild extends EventEmitter {
	// An unlikely-real pid so process.kill(-pid) throws ESRCH (caught by killProcessTree).
	pid = 999999;
	stdout = new FakeStream();
	stderr = new FakeStream();
	/** When set, emit "close" with this code once a "close" listener attaches (normal exit). When undefined, NEVER emit close (D-state hang). */
	private readonly closeCode?: number;
	constructor(closeCode?: number) {
		super();
		this.closeCode = closeCode;
	}
	// Emit close only after exec attaches its close listener (exec attaches it synchronously inside
	// the Promise executor, after getShellConfig resolves — so a constructor-time emit would fire
	// during the getShellConfig await and be lost).
	override on(event: string, listener: (...args: unknown[]) => void): this {
		super.on(event, listener);
		if (event === "close" && this.closeCode !== undefined) {
			setImmediate(() => this.emit("close", this.closeCode));
		}
		return this;
	}
}

afterEach(() => {
	fakeRef.child = undefined;
});

describe("NodeExecutionEnv.exec kill-grace fallback settle", () => {
	it("force-settles with an aborted error after the kill grace when close never fires (regression: exec promise hang + abort listener leak)", async () => {
		const root = createTempDir();
		const env = new NodeExecutionEnv({ cwd: root });
		fakeRef.child = new FakeChild();

		const controller = new AbortController();
		const streamedChunks: string[] = [];
		const promise = env.exec("hang-after-kill", {
			abortSignal: controller.signal,
			onStdout: (chunk) => {
				streamedChunks.push(chunk);
			},
		});
		// Let the async exec body run past getShellConfig and attach the data/close listeners.
		await new Promise((r) => setImmediate(r));

		controller.abort();
		// Without the kill-grace fallback this await would hang forever (close never fires); with it
		// the promise settles with an aborted error within KILL_GRACE_MS.
		const result = await promise;
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error).toMatchObject({ code: "aborted" });
		// Streaming callbacks did receive output before the abort.
		expect(streamedChunks.join("")).toContain("streamed-chunk");
	}, 10000);

	it("force-settles with a timeout error after the kill grace when close never fires", async () => {
		const root = createTempDir();
		const env = new NodeExecutionEnv({ cwd: root });
		fakeRef.child = new FakeChild();

		const promise = env.exec("hang-on-timeout", { timeout: 0.05 });
		await new Promise((r) => setImmediate(r));

		// The 50ms timeout fires, kills the child, and arms the grace; close never fires so the
		// grace force-settles with a timeout error (without it the await would hang forever).
		const result = await promise;
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error).toMatchObject({ code: "timeout" });
	}, 10000);

	it("still settles from close on the normal path (grace cleared, no double-settle)", async () => {
		// Sanity: the grace must not break the normal close path. A fake child that emits close with
		// exit code 0 settles with that code and the streaming callback fired; the grace timer is
		// cleared by settle so it never force-settles.
		fakeRef.child = new FakeChild(0);
		const root = createTempDir();
		const env = new NodeExecutionEnv({ cwd: root });
		let streamed = "";
		const result = getOrThrow(
			await env.exec("printf normal", {
				onStdout: (chunk) => {
					streamed += chunk;
				},
			}),
		);
		expect(result.exitCode).toBe(0);
		expect(result.stdoutTruncated).toBe(false);
		expect(streamed).toBe("streamed-chunk\n");
	}, 10000);
});

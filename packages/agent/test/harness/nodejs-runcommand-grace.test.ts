import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runCommand } from "../../src/harness/env/nodejs.ts";

// Mock node:child_process so runCommand's spawn returns a fake child that emits a stdout chunk
// but NEVER emits "close" — simulating a killed process stuck in uninterruptible disk sleep
// (D-state, e.g. `which` traversing a hung FUSE/NFS mount) where SIGKILL is deferred and "close"
// never fires. With the current (fixed) code the kill-grace timer force-settles the promise with
// status:null after KILL_GRACE_MS; without the fix the promise hangs forever.
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
	override on(event: string, listener: (...args: unknown[]) => void): this {
		super.on(event, listener);
		if (event === "data") {
			setImmediate(() => this.emit("data", "/usr/bin/bash\n"));
		}
		return this;
	}
}

class FakeChild extends EventEmitter {
	// An unlikely-real pid so process.kill(-pid)/process.kill(pid) in killProcessTree throw ESRCH
	// (caught) instead of killing a real process.
	pid = 999999;
	stdout = new FakeStream();
	stderr = undefined;
	// Intentionally NEVER emit "close" — the D-state hang scenario.
}

afterEach(() => {
	fakeRef.child = undefined;
});

describe("runCommand kill-grace fallback settle", () => {
	it("force-settles with status null after the kill grace when close never fires (regression: runCommand promise hang -> first exec hangs)", async () => {
		fakeRef.child = new FakeChild();

		const start = Date.now();
		// 100ms timeout. After it fires, killProcessTree is called (no-op on the fake pid), then the
		// kill-grace arms. Without the grace fallback the await below hangs forever -> vitest test
		// timeout -> FAIL. With the fix it resolves with status:null within ~timeout + KILL_GRACE_MS.
		const result = await runCommand("which", ["bash"], 100);
		const elapsed = Date.now() - start;

		expect(result.status).toBeNull();
		expect(result.stdout).toBe("/usr/bin/bash\n");
		// Resolved via grace (close never fired): elapsed >= grace arming point. Bounded well under
		// the test timeout; assert it did NOT hang and DID wait roughly until the grace fired.
		expect(elapsed).toBeGreaterThanOrEqual(100);
		expect(elapsed).toBeLessThan(4000);
	}, 5000);

	it("still resolves from close on the normal path (grace cleared, no double-settle)", async () => {
		// Sanity: the grace must not break the normal close path. A fake child that emits close with
		// exit code 0 settles with that code immediately; the grace timer is cleared by settle so it
		// never force-settles.
		const child = new FakeChild();
		child.pid = 999999;
		// Emit close once runCommand attaches its close listener (synchronously after spawn).
		const origOn = child.on.bind(child);
		child.on = ((event: string, listener: (...args: unknown[]) => void) => {
			origOn(event, listener);
			if (event === "close") {
				setImmediate(() => child.emit("close", 0));
			}
			return child;
		}) as typeof child.on;
		fakeRef.child = child;

		const result = await runCommand("which", ["bash"], 5000);
		expect(result.status).toBe(0);
		expect(result.stdout).toBe("/usr/bin/bash\n");
	}, 5000);
});

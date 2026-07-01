import assert from "node:assert";
import { describe, it } from "node:test";
import { StdinBuffer } from "../src/stdin-buffer.ts";

describe("StdinBuffer completion timeout unref (FIX 6)", () => {
	it("the completion timeout is unref'd so it doesn't keep the process alive", () => {
		const buffer = new StdinBuffer({ timeout: 50 });
		// Collect emitted sequences so handlers are wired.
		buffer.on("data", () => {});

		// Feed an escape sequence prefix that leaves a remainder in the buffer,
		// scheduling the completion timeout.
		buffer.process("\x1b");

		const timeout = (buffer as unknown as { timeout?: ReturnType<typeof setTimeout> }).timeout;
		assert.ok(timeout, "completion timeout must be scheduled");
		// hasRef() returns false after unref(); true otherwise.
		assert.equal(timeout!.hasRef(), false, "completion timeout must be unref'd");

		// Cleanup: destroy to clear the timeout and listeners.
		buffer.destroy();
	});
});

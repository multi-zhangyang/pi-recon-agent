import assert from "node:assert";
import { describe, it } from "node:test";
import { ProcessTerminal } from "../src/terminal.ts";

describe("ProcessTerminal progressInterval unref (FIX 5)", () => {
	it("setProgress(true) creates an unref'd keepalive interval", () => {
		const terminal = new ProcessTerminal();
		const previousWrite = process.stdout.write;
		process.stdout.write = (() => true) as typeof process.stdout.write;

		try {
			terminal.setProgress(true);

			const progressInterval = (terminal as unknown as { progressInterval?: ReturnType<typeof setInterval> })
				.progressInterval;
			assert.ok(progressInterval, "progress interval must be created");
			// hasRef() returns false after unref(); true otherwise.
			assert.equal(progressInterval!.hasRef(), false, "progress interval must be unref'd");
		} finally {
			try {
				terminal.stop();
			} finally {
				process.stdout.write = previousWrite;
			}
		}
	});
});

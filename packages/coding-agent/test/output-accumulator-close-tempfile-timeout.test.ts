import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";

// Regression guard for opt #64 — closeTempFile awaited a WriteStream's 'finish'/
// 'error' with NO timeout. On a stalled tmpdir FS (NFS/hung mount/FUSE, or an fd
// stuck in uninterruptible I/O) neither event ever fires → the bash tool's
// `await output.closeTempFile()` (every run above the truncation threshold, in
// both the main and catch paths) never settles → the agent loop freezes forever.
// Fix: a wall timeout (REPI_TEMP_FILE_FLUSH_TIMEOUT_MS, default 10s) destroys the
// stream and resolves flushed=false so the caller withholds the "Full output"
// path. closeTempFile now NEVER rejects (previously a stream 'error' rejected
// and could propagate out of the bash catch-path and crash the agent).

/** A stream that never emits 'finish' or 'error' — simulates a stalled FS flush. */
function stallStream(): EventEmitter & { write: () => boolean; end: () => void; destroy: () => void } {
	const ee = new EventEmitter();
	(ee as any).write = () => true;
	(ee as any).end = () => {}; // deliberately do NOT emit 'finish'
	(ee as any).destroy = () => {};
	return ee as any;
}

/** A well-behaved stream that emits 'finish' on end(). */
function finishingStream(): EventEmitter & { write: () => boolean; end: () => void; destroy: () => void } {
	const ee = new EventEmitter();
	(ee as any).write = () => true;
	(ee as any).end = () => {
		setImmediate(() => ee.emit("finish"));
	};
	(ee as any).destroy = () => {};
	return ee as any;
}

async function importAccumulator(timeoutMs: string) {
	vi.resetModules();
	vi.stubEnv("REPI_TEMP_FILE_FLUSH_TIMEOUT_MS", timeoutMs);
	const mod = await import("../src/core/tools/output-accumulator.ts");
	return mod.OutputAccumulator;
}

describe("OutputAccumulator.closeTempFile wall timeout (opt #64)", () => {
	it("a stalled stream is destroyed and resolves flushed=false after the wall timeout (does not hang)", async () => {
		const OutputAccumulator = await importAccumulator("200");
		const acc = new OutputAccumulator({ tempFilePrefix: "pi-test" });
		// Inject a stalled stream directly (the field set by ensureTempFile).
		(acc as any).tempFileStream = stallStream();
		(acc as any).tempFilePath = "/tmp/pi-test-stall.log";

		const start = Date.now();
		const flushed = await acc.closeTempFile();
		const elapsed = Date.now() - start;

		expect(flushed).toBe(false);
		// Resolved via the 200ms timer, not a hang.
		expect(elapsed).toBeGreaterThanOrEqual(180);
		expect(elapsed).toBeLessThan(4000);
		// The stream was destroyed (destroy called) and the field cleared.
		expect((acc as any).tempFileStream).toBeUndefined();
		// tempFileError set so the path is withheld downstream.
		expect((acc as any).tempFileError).toBeTruthy();
	}, 8000);

	it("a well-behaved stream resolves flushed=true quickly (no timeout needed)", async () => {
		const OutputAccumulator = await importAccumulator("10000");
		const acc = new OutputAccumulator({ tempFilePrefix: "pi-test" });
		(acc as any).tempFileStream = finishingStream();
		(acc as any).tempFilePath = "/tmp/pi-test-ok.log";

		const start = Date.now();
		const flushed = await acc.closeTempFile();
		const elapsed = Date.now() - start;

		expect(flushed).toBe(true);
		expect(elapsed).toBeLessThan(1000);
		expect((acc as any).tempFileError).toBeFalsy();
	}, 8000);

	it("resolves flushed=true immediately when no stream was opened", async () => {
		const OutputAccumulator = await importAccumulator("10000");
		const acc = new OutputAccumulator({ tempFilePrefix: "pi-test" });
		const flushed = await acc.closeTempFile();
		expect(flushed).toBe(true);
	});

	it("a stream 'error' during flush resolves flushed=false (never rejects) and marks tempFileError", async () => {
		const OutputAccumulator = await importAccumulator("10000");
		const acc = new OutputAccumulator({ tempFilePrefix: "pi-test" });
		const ee = new EventEmitter();
		(ee as any).write = () => true;
		// Emit 'error' on end() — simulates a mid-flush disk error.
		(ee as any).end = () => {
			setImmediate(() => ee.emit("error", new Error("EIO")));
		};
		(ee as any).destroy = () => {};
		(acc as any).tempFileStream = ee as any;
		(acc as any).tempFilePath = "/tmp/pi-test-err.log";

		// Must NOT reject (pre-fix it rejected and could crash the bash catch-path).
		const flushed = await acc.closeTempFile();
		expect(flushed).toBe(false);
		expect((acc as any).tempFileError).toBeTruthy();
	}, 8000);
});

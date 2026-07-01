import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { resizeImageInWorker } from "../src/utils/image-resize.ts";

// Regression guard for opt #63 — the image-resize worker had NO wall timeout
// and NO abort coverage. Photon WASM runs in the worker and does not yield to
// the event loop; a crafted/malformed image can drive it into a tight loop that
// never posts a result and never errors/exits → the Read tool's `await
// resizeImage` never settles → the agent loop freezes forever. `worker.terminate()`
// is a host-level forced kill that works even when the worker is stuck in WASM.
// Fix: a wall timeout + AbortSignal both forcibly terminate the worker and reject.

const tempDirs: string[] = [];

/** A worker script that NEVER posts a message, NEVER errors, NEVER exits — it
 * simulates a WASM tight-loop on a crafted image (the hang the cap defends). */
function writeHungWorker(): string {
	const dir = mkdtempSync(join(tmpdir(), "pi-image-resize-hang-"));
	tempDirs.push(dir);
	const path = join(dir, "hung-worker.mjs");
	// No 'message' listener, no exit — just keep the thread alive forever.
	writeFileSync(path, "setInterval(() => {}, 1000);\n");
	return path;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

describe("image-resize worker wall timeout + abort (opt #63)", () => {
	test("a hung worker is terminated and rejects after the wall timeout (does not hang forever)", async () => {
		const workerPath = writeHungWorker();
		const bytes = new Uint8Array([1, 2, 3]);
		const start = Date.now();
		// 400ms wall timeout — well under the 30s default, proves the cap fires.
		await expect(resizeImageInWorker(workerPath, bytes, "image/png", undefined, undefined, 400)).rejects.toThrow(
			/timed out after 400ms/,
		);
		const elapsed = Date.now() - start;
		// Resolved via the timer (not the 30s default) and did not hang: bounded.
		expect(elapsed).toBeGreaterThanOrEqual(380);
		expect(elapsed).toBeLessThan(5000);
	}, 4000);

	test("an abort signal terminates the worker immediately (before the wall timeout)", async () => {
		const workerPath = writeHungWorker();
		const bytes = new Uint8Array([1, 2, 3]);
		const controller = new AbortController();
		// Long wall timeout so the abort is what fires, not the timer.
		const promise = resizeImageInWorker(workerPath, bytes, "image/png", undefined, controller.signal, 30_000);
		// Abort shortly after starting.
		await new Promise<void>((resolve) => setTimeout(resolve, 50));
		controller.abort();
		const start = Date.now();
		await expect(promise).rejects.toThrow(/aborted/);
		const elapsed = Date.now() - start;
		// Abort path resolves in well under the 30s wall timeout.
		expect(elapsed).toBeLessThan(2000);
	}, 4000);

	test("a pre-aborted signal rejects before posting to the worker", async () => {
		const workerPath = writeHungWorker();
		const bytes = new Uint8Array([1, 2, 3]);
		const controller = new AbortController();
		controller.abort();
		await expect(
			resizeImageInWorker(workerPath, bytes, "image/png", undefined, controller.signal, 30_000),
		).rejects.toThrow(/aborted/);
	}, 4000);

	test("wall timeout disabled (Infinity) is honored — no timer armed (worker still settles via exit on terminate)", async () => {
		// With Infinity, no wall timer is armed. The hung worker would hang
		// forever, so instead verify a worker that exits on its own still resolves
		// normally when no timeout is set (the disabled-cap path is not a hang for
		// a well-behaved worker).
		const dir = mkdtempSync(join(tmpdir(), "pi-image-resize-ok-"));
		tempDirs.push(dir);
		const path = join(dir, "ok-worker.mjs");
		// A well-behaved worker: post a null result and exit.
		writeFileSync(
			path,
			'import { parentPort } from "node:worker_threads";\nparentPort.on("message", () => { parentPort.postMessage({ result: null }); parentPort.close(); });\n',
		);
		const bytes = new Uint8Array([1, 2, 3]);
		// Infinity = disabled wall timeout. Must still resolve (via the message).
		await expect(resizeImageInWorker(path, bytes, "image/png", undefined, undefined, Infinity)).resolves.toBeNull();
	});
});

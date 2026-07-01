import { Worker } from "node:worker_threads";
import { type ImageResizeOptions, type ResizedImage, resizeImageInProcess } from "./image-resize-core.ts";

export type { ImageResizeOptions, ResizedImage } from "./image-resize-core.ts";

interface ResizeImageWorkerResponse {
	result?: ResizedImage | null;
	error?: string;
}

// Wall-clock cap on a single image resize in a worker (opt #63). Photon WASM
// decoding/resizing/encoding runs in the worker and does NOT yield to the event
// loop; a crafted/malformed image can drive it into a tight loop that never
// posts a result and never errors/exits → the Read tool's `await resizeImage`
// never settles → the agent loop freezes forever. `worker.terminate()` is a
// host-level forced kill that works even when the worker is stuck in WASM (it
// fires the 'exit' event from the main thread), so a bounded timeout recovers
// the agent. 0 disables (Infinity) for users who want no ceiling.
const IMAGE_RESIZE_TIMEOUT_MS = (() => {
	const raw = process.env.REPI_IMAGE_RESIZE_TIMEOUT_MS;
	if (raw === undefined) return 30_000;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 0) return 30_000;
	return n === 0 ? Infinity : n;
})();

function toTransferableBytes(input: Uint8Array): Uint8Array<ArrayBuffer> {
	// Transfer detaches the buffer, so transfer a worker-owned copy and leave the
	// caller's bytes intact.
	return new Uint8Array(input);
}

function isResizeImageWorkerResponse(value: unknown): value is ResizeImageWorkerResponse {
	return value !== null && typeof value === "object";
}

function createResizeWorker(workerSpecifier: string | URL): Worker {
	return new Worker(workerSpecifier);
}

export async function resizeImageInWorker(
	workerSpecifier: string | URL,
	inputBytes: Uint8Array,
	mimeType: string,
	options?: ImageResizeOptions,
	signal?: AbortSignal,
	timeoutMs?: number,
): Promise<ResizedImage | null> {
	const wallTimeoutMs = timeoutMs ?? IMAGE_RESIZE_TIMEOUT_MS;
	const worker = createResizeWorker(workerSpecifier);
	try {
		const inputBytesForWorker = toTransferableBytes(inputBytes);
		return await new Promise<ResizedImage | null>((resolve, reject) => {
			let settled = false;
			let timer: NodeJS.Timeout | undefined;
			const cleanup = (): void => {
				if (timer) {
					clearTimeout(timer);
					timer = undefined;
				}
				if (signal) signal.removeEventListener("abort", onAbort);
			};
			const settle = (result: ResizedImage | null): void => {
				if (settled) return;
				settled = true;
				cleanup();
				resolve(result);
			};
			// `terminate` forces the worker to exit (host-level kill that works even
			// when the worker is stuck in a WASM tight loop); the resulting 'exit'
			// event is swallowed by the `settled` guard. Idempotent with the finally.
			const fail = (error: Error, terminate?: boolean): void => {
				if (settled) return;
				settled = true;
				cleanup();
				if (terminate) void worker.terminate().catch(() => undefined);
				reject(error);
			};
			const onAbort = (): void => fail(new Error("Image resize worker aborted"), true);

			worker.once("message", (message: unknown) => {
				if (!isResizeImageWorkerResponse(message)) {
					fail(new Error("Invalid image resize worker response"));
					return;
				}
				if (message.error) {
					fail(new Error(message.error));
					return;
				}
				settle(message.result ?? null);
			});
			worker.once("error", (error) => fail(error));
			worker.once("exit", (code) => {
				if (!settled) {
					fail(new Error(`Image resize worker exited with code ${code}`));
				}
			});

			// Wall timeout: WASM can tight-loop without yielding, so none of the
			// listeners above may ever fire for a crafted image. The timer forcibly
			// terminates the worker (which fires 'exit') and rejects. Only arm for a
			// finite positive ms (0 / Infinity = disabled).
			if (Number.isFinite(wallTimeoutMs) && wallTimeoutMs > 0) {
				timer = setTimeout(
					() => fail(new Error(`Image resize worker timed out after ${wallTimeoutMs}ms`), true),
					wallTimeoutMs,
				);
			}
			// Abort coverage: thread the Read tool's abort signal so an agent-level
			// abort terminates the worker instead of waiting for the wall timeout.
			if (signal) {
				if (signal.aborted) {
					fail(new Error("Image resize worker aborted"), true);
					return;
				}
				signal.addEventListener("abort", onAbort, { once: true });
			}

			worker.postMessage(
				{
					inputBytes: inputBytesForWorker,
					mimeType,
					options,
				},
				[inputBytesForWorker.buffer],
			);
		});
	} finally {
		void worker.terminate().catch(() => undefined);
	}
}

/**
 * Resize an image to fit within the specified max dimensions and encoded file size.
 * Runs Photon in a worker thread so WASM decoding, resizing, and encoding do not
 * block the TUI event loop. If the worker cannot be loaded (for example in some
 * Bun compiled executable layouts), fall back to in-process resizing so image
 * reads still work.
 */
export async function resizeImage(
	inputBytes: Uint8Array,
	mimeType: string,
	options?: ImageResizeOptions,
	signal?: AbortSignal,
): Promise<ResizedImage | null> {
	const isTypeScriptRuntime = import.meta.url.endsWith(".ts");
	const workerUrl = new URL(
		isTypeScriptRuntime ? "./image-resize-worker.ts" : "./image-resize-worker.js",
		import.meta.url,
	);

	// Bun compiled executables resolve worker entrypoints by string path, not via
	// new URL(..., import.meta.url). Try the string path first under Bun so the
	// release binary uses the embedded worker instead of falling back in-process.
	if (typeof process.versions.bun === "string") {
		try {
			return await resizeImageInWorker("./src/utils/image-resize-worker.ts", inputBytes, mimeType, options, signal);
		} catch {}
	}

	try {
		return await resizeImageInWorker(workerUrl, inputBytes, mimeType, options, signal);
	} catch {
		return resizeImageInProcess(inputBytes, mimeType, options);
	}
}

/**
 * Format a dimension note for resized images.
 * This helps the model understand the coordinate mapping.
 */
export function formatDimensionNote(result: ResizedImage): string | undefined {
	if (!result.wasResized) {
		return undefined;
	}

	const scale = result.originalWidth / result.width;
	return `[Image: original ${result.originalWidth}x${result.originalHeight}, displayed at ${result.width}x${result.height}. Multiply coordinates by ${scale.toFixed(2)} to map to original image.]`;
}

import { describe, expect, it, vi } from "vitest";

// Regression guard for opt #54: the kitty-graphics image-conversion path is fire-and-forget.
// tool-execution.ts:191 does `convertToPng(img.data, img.mimeType).then(...)` with NO `.catch`.
// Two gaps made a throw fatal (no global unhandledRejection handler exists → rejection crashes
// the agent):
//   1. convertToPng's `await loadPhoton()` was OUTSIDE its try/catch → if loadPhoton rejected,
//      convertToPng rejected → the `.then` dropped it → unhandledRejection → crash.
//   2. loadPhoton's `patchPhotonWasmRead()` was OUTSIDE its try/catch → if the fs patch threw,
//      the load IIFE rejected → loadPhoton rejected.
// opt #54 wraps both: convertToPng's whole body (incl. loadPhoton) is in try/catch → resolves
// null on any failure; loadPhoton's patchPhotonWasmRead is inside its try → resolves null on any
// failure. A defense-in-depth `.catch(() => {})` is also added at the fire-and-forget call site.
//
// `vi.doMock` (not hoisted) + `vi.resetModules` per test is the correct pattern: each test pins
// a different loadPhoton behavior, so the mock must apply only to that test's dynamic import.

async function importConvertToPng() {
	vi.resetModules();
	return await import("../src/utils/image-convert.ts");
}

describe("image-convert fire-and-forget rejection guards (opt #54)", () => {
	it("convertToPng resolves to null (does not reject) when loadPhoton rejects", async () => {
		// Mock loadPhoton to REJECT — pins the load-step guard. Pre-fix (loadPhoton awaited
		// OUTSIDE the try): convertToPng rejects with "photon-boom" → fire-and-forget caller
		// drops it → unhandledRejection → crash. Post-fix: caught → resolves null.
		vi.doMock("../src/utils/photon.ts", () => ({
			loadPhoton: () => Promise.reject(new Error("photon-boom")),
		}));
		const { convertToPng } = await importConvertToPng();

		// Non-PNG so the early `mimeType === "image/png"` return is skipped and loadPhoton runs.
		await expect(convertToPng("Zm9v", "image/jpeg")).resolves.toBeNull();
	});

	it("convertToPng still resolves to null when loadPhoton resolves null (unchanged contract)", async () => {
		vi.doMock("../src/utils/photon.ts", () => ({
			loadPhoton: () => Promise.resolve(null),
		}));
		const { convertToPng } = await importConvertToPng();

		await expect(convertToPng("Zm9v", "image/jpeg")).resolves.toBeNull();
	});

	it("loadPhoton resolves to null (does not reject) when the photon module import throws", async () => {
		// Mock the photon package so the dynamic `import("@silvia-odwyer/photon-node")` throws —
		// simulating a broken/missing WASM module. opt #54 wraps the WHOLE loadPhoton setup
		// (patchPhotonWasmRead + import) in try/catch so any failure resolves null, not rejects.
		vi.resetModules();
		vi.doMock("@silvia-odwyer/photon-node", () => {
			throw new Error("wasm-load-boom");
		});
		const { loadPhoton } = await import("../src/utils/photon.ts");

		await expect(loadPhoton()).resolves.toBeNull();
	});
});

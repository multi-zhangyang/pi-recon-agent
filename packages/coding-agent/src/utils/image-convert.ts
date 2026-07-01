import { applyExifOrientation } from "./exif-orientation.ts";
import { loadPhoton } from "./photon.ts";

/**
 * Convert image to PNG format for terminal display.
 * Kitty graphics protocol requires PNG format (f=100).
 */
export async function convertToPng(
	base64Data: string,
	mimeType: string,
): Promise<{ data: string; mimeType: string } | null> {
	// Already PNG, no conversion needed
	if (mimeType === "image/png") {
		return { data: base64Data, mimeType };
	}

	// opt #54 — the whole conversion path (including the `await loadPhoton()` that was
	// previously OUTSIDE this try) is wrapped so a photon load/initialization failure resolves
	// to null instead of rejecting. convertToPng is called fire-and-forget from tool-execution's
	// image render (`convertToPng(...).then(...)` with no `.catch`) — a rejection here would drop
	// to `unhandledRejection` and crash the agent (no global unhandledRejection handler exists).
	// The contract is "returns null when unavailable"; honoring it for the load step too.
	try {
		const photon = await loadPhoton();
		if (!photon) {
			// Photon not available, can't convert
			return null;
		}

		const bytes = new Uint8Array(Buffer.from(base64Data, "base64"));
		const rawImage = photon.PhotonImage.new_from_byteslice(bytes);
		const image = applyExifOrientation(photon, rawImage, bytes);
		if (image !== rawImage) rawImage.free();
		try {
			const pngBuffer = image.get_bytes();
			return {
				data: Buffer.from(pngBuffer).toString("base64"),
				mimeType: "image/png",
			};
		} finally {
			image.free();
		}
	} catch {
		// Photon load or conversion failed
		return null;
	}
}

import { FinishReason } from "@google/genai";
import { describe, expect, it } from "vitest";
import { mapStopReason } from "../src/providers/google-shared.ts";

// Regression guard for the google-shared mapStopReason throw bug. The `default`
// branch of the FinishReason enum switch used a `never` witness and
// `throw new Error(`Unhandled stop reason: ${_exhaustive}`)`. google.ts calls
// mapStopReason on every chunk with `candidate.finishReason`. At runtime
// @google/genai passes through server-issued finish reasons outside the SDK's
// compiled enum (Gemini has added IMAGE_SAFETY/LANGUAGE/etc. mid-stream). A
// single unknown value threw → caught by the outer catch in streamGoogle →
// stopReason="error" → EVERY text/thinking/tool block already streamed was
// DISCARDED and the turn reported as error. This was already fixed for
// openai-completions, openai-responses-shared, anthropic, and mistral; Google
// was missed. The raw-string variant mapStopReasonString already degrades
// gracefully (returns "error"). Fix: mirror the openai-responses-shared.ts
// witness pattern (`const _exhaustive: never = reason; void _exhaustive;`) but
// RETURN a StopReason instead of throwing — "error" to match mapStopReasonString.

describe("google-shared mapStopReason graceful unknown default", () => {
	it("returns a StopReason for an unknown/future finish reason instead of throwing", () => {
		// Pre-fix: this threw `Unhandled stop reason: <reason>` → outer catch in
		// streamGoogle discarded the whole response as stopReason:"error".
		// Post-fix: returns "error" gracefully (no throw), content already
		// streamed is preserved (no throw → outer catch not triggered).
		expect(() => mapStopReason("UNKNOWN_FUTURE_REASON" as never)).not.toThrow();
		expect(mapStopReason("UNKNOWN_FUTURE_REASON" as never)).toBe("error");
		expect(mapStopReason("IMAGE_SAFETY_FUTURE" as never)).toBe("error");
		expect(mapStopReason("LANGUAGE_FUTURE" as never)).toBe("error");
	});

	it("still maps known FinishReasons correctly (no behavior change)", () => {
		expect(mapStopReason(FinishReason.STOP)).toBe("stop");
		expect(mapStopReason(FinishReason.MAX_TOKENS)).toBe("length");
		expect(mapStopReason(FinishReason.SAFETY)).toBe("error");
		expect(mapStopReason(FinishReason.RECITATION)).toBe("error");
	});
});

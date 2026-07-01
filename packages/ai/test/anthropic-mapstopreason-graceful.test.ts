import { describe, expect, it } from "vitest";
import { mapStopReason } from "../src/providers/anthropic.ts";

// Regression guard for opt #179 — anthropic.ts mapStopReason's `default` branch said
// "Handle unknown stop reasons gracefully" but THREW. Anthropic has added new stop_reason
// values after SDK types shipped (pause_turn, refusal, sensitive). An unknown value →
// throw → the stream fn's outer catch discards the ENTIRE response as stopReason:"error",
// losing all content. Mistral's mapChatStopReason defaults to "stop"; this matches that.
// Fix: `return "stop"` (preserve content; treat unknown as a normal end). The comment is
// kept and now truthful.

describe("Anthropic mapStopReason graceful unknown default (opt #179)", () => {
	it("returns 'stop' for an unknown/future stop reason instead of throwing", () => {
		// Pre-fix: this threw `Unhandled stop reason: unknown_future_reason` → outer catch
		// discarded the whole response as stopReason:"error".
		// Post-fix: returns "stop", content preserved.
		expect(() => mapStopReason("unknown_future_reason" as never)).not.toThrow();
		expect(mapStopReason("unknown_future_reason" as never)).toBe("stop");
	});

	it("still maps known stop reasons correctly (no behavior change)", () => {
		expect(mapStopReason("end_turn")).toBe("stop");
		expect(mapStopReason("max_tokens")).toBe("length");
		expect(mapStopReason("tool_use")).toBe("toolUse");
		expect(mapStopReason("refusal")).toBe("error");
		expect(mapStopReason("pause_turn")).toBe("stop");
		expect(mapStopReason("stop_sequence")).toBe("stop");
		expect(mapStopReason("sensitive")).toBe("error");
	});
});

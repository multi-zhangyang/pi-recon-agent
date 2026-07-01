import { describe, expect, it } from "vitest";
import { mapStopReason } from "../src/providers/openai-responses-shared.ts";

// Regression guard for opt #180 — openai-responses-shared.ts mapStopReason's `default`
// branch used a `never`-exhaustiveness THROW: `const _exhaustive: never = status; throw
// new Error(...)`. If OpenAI adds a new ResponseStatus (or the SDK types lag the server
// runtime), the throw discards the ENTIRE response as stopReason:"error". The codex path
// normalizes unknown statuses to undefined BEFORE this (so it's unreachable from codex),
// but the direct openai-responses.ts path passes raw status through. Fix: KEEP the
// compile-time exhaustiveness witness (`const _exhaustive: never = status; void _exhaustive`)
// so TS still errors if a new enum member appears unhandled, BUT return "stop" at runtime
// instead of throwing — graceful degradation that preserves content.

describe("OpenAI Responses mapStopReason graceful unknown default (opt #180)", () => {
	it("returns 'stop' for an unknown/future status instead of throwing", () => {
		// Pre-fix: this threw `Unhandled stop reason: unknown_future_status` → outer catch
		// discarded the whole response as stopReason:"error".
		// Post-fix: returns "stop", content preserved.
		expect(() => mapStopReason("unknown_future_status" as never)).not.toThrow();
		expect(mapStopReason("unknown_future_status" as never)).toBe("stop");
	});

	it("returns 'stop' for undefined status (no behavior change)", () => {
		expect(mapStopReason(undefined)).toBe("stop");
	});

	it("still maps known statuses correctly (no behavior change)", () => {
		expect(mapStopReason("completed")).toBe("stop");
		expect(mapStopReason("incomplete")).toBe("length");
		expect(mapStopReason("failed")).toBe("error");
		expect(mapStopReason("cancelled")).toBe("error");
		expect(mapStopReason("in_progress")).toBe("stop");
		expect(mapStopReason("queued")).toBe("stop");
	});
});

/**
 * opt #207 — amazon-bedrock mapStopReason default "error" stripped valid
 * content for unknown/future stop reasons.
 *
 * The Bedrock StopReason enum (AWS SDK) has 9 members. The old switch handled
 * 5 (END_TURN/STOP_SEQUENCE→stop, MAX_TOKENS/MODEL_CONTEXT_WINDOW_EXCEEDED→
 * length, TOOL_USE→toolUse) and dumped the remaining 4 known error sentinels
 * (CONTENT_FILTERED, GUARDRAIL_INTERVENED, MALFORMED_MODEL_OUTPUT,
 * MALFORMED_TOOL_USE) PLUS any unknown/future member into `default: "error"`.
 *
 * For the 4 known sentinels "error" is correct. But if AWS adds a new BENIGN
 * StopReason (or the SDK enum lags the server), the successfully-streamed
 * content was reclassified as stopReason:"error" → stripTrailingErrorAssistants
 * stripped the valid assistant turn (conversation history loss) + a false
 * error event surfaced. This diverged from the round-8 graceful doctrine
 * (openai-completions #187, openai-responses #180, anthropic #179 — all
 * default "stop" for unknown). Google deliberately keeps "error" for unknown
 * (Gemini unknowns are usually safety blocks); Bedrock's enum is stable so
 * "stop" is the safer default.
 *
 * Fix: handle the 4 known error sentinels explicitly → "error"; change the
 * default to "stop" so only truly unknown (presumed benign) reasons preserve
 * content. mapStopReason was exported (additive) for direct behavioral test.
 */
import { describe, expect, it } from "vitest";
import { mapStopReason } from "../src/providers/amazon-bedrock.ts";

describe("amazon-bedrock mapStopReason graceful unknown default (opt #207)", () => {
	it("returns 'stop' for an unknown/future stop reason (content preserved)", () => {
		// Pre-fix: unknown → "error" → stripTrailingErrorAssistants stripped the
		// valid assistant turn. Post-fix: "stop", content preserved.
		expect(mapStopReason("unknown_future_reason")).toBe("stop");
		expect(mapStopReason("some_new_benign_reason")).toBe("stop");
	});

	it("returns 'stop' for undefined (no behavior change)", () => {
		expect(mapStopReason(undefined)).toBe("stop");
	});

	it("still maps the 5 originally-handled reasons correctly (no behavior change)", () => {
		expect(mapStopReason("end_turn")).toBe("stop");
		expect(mapStopReason("stop_sequence")).toBe("stop");
		expect(mapStopReason("max_tokens")).toBe("length");
		expect(mapStopReason("model_context_window_exceeded")).toBe("length");
		expect(mapStopReason("tool_use")).toBe("toolUse");
	});

	it("maps the 4 known error sentinels to 'error' (no behavior change vs pre-fix default)", () => {
		// These previously fell to `default: "error"`; now explicit so the
		// default can be graceful. Behavior unchanged for them.
		expect(mapStopReason("content_filtered")).toBe("error");
		expect(mapStopReason("guardrail_intervened")).toBe("error");
		expect(mapStopReason("malformed_model_output")).toBe("error");
		expect(mapStopReason("malformed_tool_use")).toBe("error");
	});
});

import { describe, expect, it } from "vitest";
import { mistralTerminalErrorMessage } from "../src/providers/mistral.ts";

// opt #274: streamMistral's post-consume terminal check was a single
// `if (stopReason === "aborted" || stopReason === "error") throw new Error("An unknown error occurred")`
// — which (a) discarded any errorMessage captured during streaming, diverging
// from the openai-completions path (`output.errorMessage || "Provider returned
// an error stop reason"`), and (b) reported "An unknown error occurred" for an
// abort (misleading). The fix: "aborted" → "Request was aborted"; "error" →
// preserve errorMessage else "Mistral returned an error finish reason".
// Extracted to mistralTerminalErrorMessage for unit testing.

describe("mistralTerminalErrorMessage (opt #274)", () => {
	it("returns null for non-terminal stop reasons (normal completion)", () => {
		expect(mistralTerminalErrorMessage("stop", undefined)).toBeNull();
		expect(mistralTerminalErrorMessage("toolUse", undefined)).toBeNull();
		expect(mistralTerminalErrorMessage("length", undefined)).toBeNull();
	});

	it("returns 'Request was aborted' for aborted stop reason", () => {
		expect(mistralTerminalErrorMessage("aborted", undefined)).toBe("Request was aborted");
		// abort message is authoritative — an errorMessage from streaming is
		// ignored for the abort case (matches openai-completions).
		expect(mistralTerminalErrorMessage("aborted", "some streaming error")).toBe("Request was aborted");
	});

	it("preserves a captured errorMessage for the error stop reason", () => {
		expect(mistralTerminalErrorMessage("error", "Provider finish_reason: content_filter")).toBe(
			"Provider finish_reason: content_filter",
		);
	});

	it("falls back to a descriptive finish-reason string when no errorMessage was captured", () => {
		// mapChatStopReason returns "error" without setting errorMessage, so this
		// is the common path. Pre-fix this was the uninformative
		// "An unknown error occurred".
		expect(mistralTerminalErrorMessage("error", undefined)).toBe("Mistral returned an error finish reason");
		expect(mistralTerminalErrorMessage("error", "")).toBe("Mistral returned an error finish reason");
	});
});

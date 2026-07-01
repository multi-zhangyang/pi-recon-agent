import { describe, expect, it } from "vitest";
import { terminalErrorMessage } from "../src/utils/error-stringify.ts";

// opt #275: six provider stream wrappers (google, anthropic, amazon-bedrock,
// azure-openai-responses, google-vertex, openai-responses) threw a generic
// `new Error("An unknown error occurred")` for BOTH abort AND error stop
// reasons — discarding any `output.errorMessage` captured during streaming
// (a content_filter / network_error finish-reason mapping, or the IIFE
// catch's safeStringifyError) and misreporting an abort as "unknown error".
// The shared terminalErrorMessage helper mirrors the openai-completions
// reference: "Request was aborted" for abort, the captured errorMessage (or a
// generic fallback) for error, null for non-terminal stop reasons. Each
// provider keeps the inline `stopReason === "aborted" || "error"` guard (so TS
// narrows stopReason for the `done` push) and uses this helper for the message.

describe("terminalErrorMessage (opt #275)", () => {
	it("returns 'Request was aborted' for an aborted stop reason (not 'An unknown error occurred')", () => {
		expect(terminalErrorMessage("aborted", undefined)).toBe("Request was aborted");
		// errorMessage is irrelevant for abort — the abort label wins.
		expect(terminalErrorMessage("aborted", "some captured error")).toBe("Request was aborted");
	});

	it("surfaces the captured errorMessage for an error stop reason", () => {
		expect(terminalErrorMessage("error", "Provider finish_reason: content_filter")).toBe(
			"Provider finish_reason: content_filter",
		);
	});

	it("falls back to a generic 'Provider returned an error stop reason' when errorMessage is absent", () => {
		expect(terminalErrorMessage("error", undefined)).toBe("Provider returned an error stop reason");
		expect(terminalErrorMessage("error", "")).toBe("Provider returned an error stop reason");
	});

	it("returns null for non-terminal stop reasons so the caller's inline guard preserves TS narrowing", () => {
		expect(terminalErrorMessage("stop", undefined)).toBeNull();
		expect(terminalErrorMessage("length", undefined)).toBeNull();
		expect(terminalErrorMessage("toolUse", undefined)).toBeNull();
		// errorMessage present but stopReason non-terminal → still null (no error to throw).
		expect(terminalErrorMessage("stop", "stale")).toBeNull();
	});
});

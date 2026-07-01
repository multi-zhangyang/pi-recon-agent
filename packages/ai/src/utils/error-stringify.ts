import type { StopReason } from "../types.ts";

/**
 * Safely stringify a thrown value for use in an error message.
 *
 * Provider stream IIFEs catch errors and push an "error" event with
 * `errorMessage`. Several used `JSON.stringify(error)` for the non-`Error`
 * branch — but a thrown value that is a circular / BigInt / Proxy object makes
 * `JSON.stringify` THROW, and throwing INSIDE the catch block escapes the
 * IIFE → the dropped IIFE promise rejects → `unhandledRejection` → process
 * crash (there is NO global unhandledRejection handler). That defeats the
 * catch on the MAIN GLM path (openai-completions) and several sibling
 * providers. Fall back to `String(error)` (which never throws) when
 * `JSON.stringify` fails. (opt #130)
 *
 * Prefer `error.message` when the value is an `Error`; only use this helper
 * for the non-`Error` branch.
 */
export function safeStringifyError(error: unknown): string {
	try {
		return JSON.stringify(error);
	} catch {
		try {
			return String(error);
		} catch {
			return "Unserializable error value";
		}
	}
}

/**
 * Format the terminal-error throw message for a provider stream IIFE's
 * `stopReason === "aborted" | "error"` guard. (opt #275)
 *
 * Six provider wrappers (google, anthropic, amazon-bedrock, azure-responses,
 * google-vertex, openai-responses) threw a generic
 * `new Error("An unknown error occurred")` for BOTH abort AND error stop
 * reasons — discarding any `output.errorMessage` captured during streaming
 * (a content_filter / network_error finish-reason mapping, or the IIFE catch's
 * `safeStringifyError`) and misreporting an abort as "unknown error". This
 * mirrors the openai-completions reference: "Request was aborted" for abort,
 * the captured `errorMessage` (or a generic fallback) for error, `null` for
 * non-terminal stop reasons.
 *
 * The caller keeps the inline `stopReason === "aborted" || "error"` guard
 * (NOT a `terminalMessage !== null` check) so TS narrows `stopReason` to
 * "length" | "stop" | "toolUse" for the subsequent `done` event push — a
 * `!== null` check broke that narrowing (tsgo TS2322). Use `as string` at the
 * throw site. This is generic error-message fidelity, NOT per-provider
 * special-casing (see [[repi-no-adapter-specialcasing]]).
 */
export function terminalErrorMessage(stopReason: StopReason, errorMessage: string | undefined): string | null {
	if (stopReason === "aborted") return "Request was aborted";
	if (stopReason === "error") return errorMessage || "Provider returned an error stop reason";
	return null;
}

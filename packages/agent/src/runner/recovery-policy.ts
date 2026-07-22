import type { AssistantMessage } from "@pi-recon/repi-ai";
import { isContextOverflow } from "@pi-recon/repi-ai";

const NON_RETRYABLE_ERROR_PATTERNS = [
	"401",
	"403",
	"invalid api key",
	"invalid_api_key",
	"unauthorized",
	"unauthorised",
	"authentication",
	"permission_denied",
	"forbidden",
	"usage limit",
	"usagelimit",
	"available balance",
	"out of budget",
	"quota",
	"billing",
	"insufficient_quota",
	"model not found",
	"model_not_found",
	"does not exist",
];

const TRANSIENT_ERROR_PATTERN =
	/overloaded|provider.?returned.?error|rate.?limit|too many requests|429|500|502|503|504|service.?unavailable|server.?error|internal.?error|network.?error|connection.?error|connection.?refused|connection.?lost|websocket.?closed|websocket.?error|other side closed|fetch failed|upstream.?connect|reset before headers|socket hang up|ended without|stream ended before message_stop|stream ended before a terminal response event|http2 request did not get a response|timed? out|timeout|terminated|retry delay/i;

export interface RetryDecisionOptions {
	contextWindow?: number;
	/** Pre-stream failures are safe to retry even when the provider supplied no useful error text. */
	allowUnknown?: boolean;
}

/** Provider-neutral retry classification shared by the core loop and application sessions. */
export function isRetryableAgentError(message: AssistantMessage, options: RetryDecisionOptions = {}): boolean {
	if (message.stopReason !== "error") return false;
	if (isContextOverflow(message, options.contextWindow ?? 0)) return false;
	const text = (message.errorMessage ?? "").trim().toLowerCase();
	if (NON_RETRYABLE_ERROR_PATTERNS.some((pattern) => text.includes(pattern))) return false;
	if (!text) return options.allowUnknown ?? false;
	return (options.allowUnknown ?? false) || TRANSIENT_ERROR_PATTERN.test(text);
}

import { afterEach, describe, expect, it } from "vitest";
import {
	closeOpenAICodexWebSocketSessions,
	getOpenAICodexWebSocketDebugStats,
	isWebSocketSseFallbackActive,
	recordWebSocketFailure,
	resetOpenAICodexWebSocketDebugStats,
} from "../src/providers/openai-codex-responses.ts";

// opt #147: closeOpenAICodexWebSocketSessions(sessionId) — the per-session
// cleanup registered via registerSessionResourceCleanup and fired by
// cleanupSessionResources(this.sessionId) on every newSession/fork/switchSession/
// reload — only cleared websocketSessionCache (the WS-connection cache, which has
// its own TTL). It left two per-session satellites, websocketDebugStats (Map) and
// websocketSseFallbackSessions (Set), untouched → one entry per unique sessionId
// accumulated forever (unbounded growth in a long-running rpc daemon / interactive
// session that forks/reloads repeatedly). The fix routes per-session close through
// resetOpenAICodexWebSocketDebugStats(sessionId), which deletes both satellites.

describe("OpenAI Codex WS debug-stats satellite trim on session cleanup (opt #147)", () => {
	afterEach(() => {
		resetOpenAICodexWebSocketDebugStats();
		closeOpenAICodexWebSocketSessions();
	});

	it("per-session close trims debug-stats + SSE-fallback satellites for that session only", () => {
		resetOpenAICodexWebSocketDebugStats();
		// Populate BOTH satellites for two sessions via a recorded WS failure.
		recordWebSocketFailure("session-A", new Error("boom-a"));
		recordWebSocketFailure("session-B", new Error("boom-b"));

		expect(getOpenAICodexWebSocketDebugStats("session-A")).toBeDefined();
		expect(getOpenAICodexWebSocketDebugStats("session-B")).toBeDefined();
		expect(isWebSocketSseFallbackActive("session-A")).toBe(true);
		expect(isWebSocketSseFallbackActive("session-B")).toBe(true);

		// Per-session cleanup of A only.
		closeOpenAICodexWebSocketSessions("session-A");

		expect(getOpenAICodexWebSocketDebugStats("session-A")).toBeUndefined();
		expect(isWebSocketSseFallbackActive("session-A")).toBe(false);
		// B untouched — per-session, not global.
		expect(getOpenAICodexWebSocketDebugStats("session-B")).toBeDefined();
		expect(isWebSocketSseFallbackActive("session-B")).toBe(true);
	});

	it("global close (no sessionId) still clears all satellites", () => {
		recordWebSocketFailure("session-X", new Error("boom-x"));
		expect(getOpenAICodexWebSocketDebugStats("session-X")).toBeDefined();
		expect(isWebSocketSseFallbackActive("session-X")).toBe(true);

		closeOpenAICodexWebSocketSessions();

		expect(getOpenAICodexWebSocketDebugStats("session-X")).toBeUndefined();
		expect(isWebSocketSseFallbackActive("session-X")).toBe(false);
	});
});

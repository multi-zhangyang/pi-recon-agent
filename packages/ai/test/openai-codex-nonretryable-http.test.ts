/**
 * Foundational opt #257 — openai-codex-responses must NOT retry non-retryable
 * HTTP statuses (400/401/403/422).
 *
 * Pre-fix the retry loop's catch block retried ANY thrown error whose message
 * didn't include "usage limit" — including the explicit `throw new Error(...)`
 * at the bottom of the try for a NON-retryable HTTP status (parsed to a friendly
 * message). So a 401 was re-sent on every attempt with exponential backoff
 * (1+2+4s), only surfacing after maxRetries+1 total requests, risking
 * auth-endpoint rate-limiting/lockout. Fix: a `nonRetryableHttp` flag set before
 * the explicit HTTP throw gates the catch-block retry (only network/fetch errors
 * retry).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { streamOpenAICodexResponses } from "../src/providers/openai-codex-responses.ts";
import type { Context, Model } from "../src/types.ts";

const originalAgentDir = process.env.PI_CODING_AGENT_DIR;

afterEach(() => {
	vi.unstubAllGlobals();
	if (originalAgentDir === undefined) {
		delete process.env.PI_CODING_AGENT_DIR;
	} else {
		process.env.PI_CODING_AGENT_DIR = originalAgentDir;
	}
	vi.useRealTimers();
	vi.restoreAllMocks();
});

function mockToken(): string {
	const payload = Buffer.from(
		JSON.stringify({ "https://api.openai.com/auth": { chatgpt_account_id: "acc_test" } }),
		"utf8",
	).toString("base64");
	return `aaa.${payload}.bbb`;
}

function codexModel(): Model<"openai-codex-responses"> {
	return {
		id: "gpt-5.1-codex",
		name: "GPT-5.1 Codex",
		api: "openai-codex-responses",
		provider: "openai-codex",
		baseUrl: "https://chatgpt.com/backend-api",
		reasoning: true,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 400000,
		maxTokens: 128000,
	};
}

describe("openai-codex non-retryable HTTP status (opt #257)", () => {
	it("does not retry a 401 Unauthorized (fetch called once)", async () => {
		process.env.PI_CODING_AGENT_DIR = "/tmp";
		const token = mockToken();

		const fetchMock = vi.fn(async (input: string | URL) => {
			const url = typeof input === "string" ? input : input.toString();
			if (url === "https://chatgpt.com/backend-api/codex/responses") {
				return new Response(JSON.stringify({ error: { message: "Unauthorized" } }), {
					status: 401,
					statusText: "Unauthorized",
				});
			}
			return new Response("not found", { status: 404 });
		});
		vi.stubGlobal("fetch", fetchMock);

		const context: Context = {
			systemPrompt: "You are a helpful assistant.",
			messages: [{ role: "user", content: "Say hello", timestamp: Date.now() }],
		};

		const result = await streamOpenAICodexResponses(codexModel(), context, {
			apiKey: token,
			transport: "sse",
			maxRetries: 3,
		}).result();

		// Pre-fix: 4 calls (1 + 3 retries). Post-fix: exactly 1.
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(result.stopReason).toBe("error");
		expect(result.errorMessage).toMatch(/Unauthorized/);
	});
});

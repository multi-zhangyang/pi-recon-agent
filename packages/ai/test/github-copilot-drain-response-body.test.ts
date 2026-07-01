import { afterEach, describe, expect, it, vi } from "vitest";
import { enableGitHubCopilotModel } from "../src/utils/oauth/github-copilot.ts";

// Regression guard for opt #57 — enableGitHubCopilotModel (github-copilot.ts:250) did
// `const response = await fetch(...); return response.ok;` reading ONLY response.ok and never
// consuming/cancelling the body. undici does NOT release the keep-alive socket until the body is
// consumed or cancelled → the socket was held against the per-host connection cap until GC. This
// is the opt #49 leak class. enableAllGitHubCopilotModels calls enableGitHubCopilotModel in a loop
// for N models right after login, so N sockets were stranded. The sibling fetchJson at line 94
// drains via response.text(); this was the inconsistent outlier. Fix: capture ok, then
// `await response.body?.cancel().catch(() => {})` before returning (cancel() is the cheaper drain
// for a body we never read).

const originalFetch = globalThis.fetch;

afterEach(() => {
	globalThis.fetch = originalFetch;
});

function mockFetch(response: { ok: boolean; status: number; body?: { cancel: () => Promise<void> } }): void {
	globalThis.fetch = vi.fn().mockResolvedValue(response) as unknown as typeof globalThis.fetch;
}

describe("enableGitHubCopilotModel drains the response body (opt #57)", () => {
	it("cancels the response body on success so undici releases the keep-alive socket", async () => {
		let cancelCalled = false;
		mockFetch({
			ok: true,
			status: 200,
			body: {
				cancel: async () => {
					cancelCalled = true;
				},
			},
		});

		const ok = await enableGitHubCopilotModel("tok", "claude-3.7-sonnet");

		expect(ok).toBe(true);
		// opt #57 pin: pre-fix the body was never cancelled (only response.ok was read) →
		// cancelCalled stays false. Post-fix: cancel() is awaited before returning.
		expect(cancelCalled).toBe(true);
	});

	it("cancels the response body on non-ok too (a 4xx/5xx body still strands a socket)", async () => {
		let cancelCalled = false;
		mockFetch({
			ok: false,
			status: 403,
			body: {
				cancel: async () => {
					cancelCalled = true;
				},
			},
		});

		const ok = await enableGitHubCopilotModel("tok", "claude-3.7-sonnet");

		expect(ok).toBe(false);
		expect(cancelCalled).toBe(true);
	});

	it("returns false when fetch rejects (drain path not reached, no crash)", async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("network down")) as unknown as typeof globalThis.fetch;

		const ok = await enableGitHubCopilotModel("tok", "claude-3.7-sonnet");

		expect(ok).toBe(false);
	});
});

import { findModel, getModel } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";

describe("coding-agent test model catalog", () => {
	it("registers the shared legacy getModel fixtures", () => {
		expect(getModel("anthropic", "claude-sonnet-4-5")).toMatchObject({
			api: "anthropic-messages",
			contextWindow: 200_000,
		});
		expect(getModel("openai-codex", "gpt-5.5")).toMatchObject({
			api: "openai-codex-responses",
			contextWindow: 272_000,
		});
	});

	it("does not synthesize unknown providers or model ids", () => {
		expect(findModel("anthropic", "fixture-unknown-model")).toBeUndefined();
		expect(findModel("fixture-unknown-provider", "claude-sonnet-4-5")).toBeUndefined();
	});
});

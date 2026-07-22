import { describe, expect, it } from "vitest";
import { calculateCost, getSupportedThinkingLevels } from "../src/models.ts";
import type { Model } from "../src/types.ts";

function model(overrides: Partial<Model<"openai-completions">> = {}): Model<"openai-completions"> {
	return {
		id: "pricing-test",
		name: "Pricing test",
		api: "openai-completions",
		provider: "test-provider",
		baseUrl: "https://example.test/v1",
		reasoning: false,
		input: ["text"],
		cost: { input: 1, output: 2, cacheRead: 0.5, cacheWrite: 3 },
		contextWindow: 128_000,
		maxTokens: 8_192,
		...overrides,
	};
}

describe("model pricing and thinking capabilities", () => {
	it("selects the highest matching request-wide pricing tier", () => {
		const usage = {
			input: 150,
			output: 10,
			cacheRead: 100,
			cacheWrite: 1,
			cacheWrite1h: 0,
			totalTokens: 261,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		};
		const result = calculateCost(
			model({
				cost: {
					input: 1,
					output: 2,
					cacheRead: 0.5,
					cacheWrite: 3,
					tiers: [
						{ inputTokensAbove: 200, input: 4, output: 5, cacheRead: 1, cacheWrite: 6 },
						{ inputTokensAbove: 100, input: 2, output: 3, cacheRead: 0.75, cacheWrite: 4 },
					],
				},
			}),
			usage,
		);

		// input + cacheRead + cacheWrite = 251, so the 200-token tier applies.
		expect(result.input).toBeCloseTo(0.0006);
		expect(result.output).toBeCloseTo(0.00005);
		expect(result.cacheRead).toBeCloseTo(0.0001);
		expect(result.cacheWrite).toBeCloseTo(0.000006);
		expect(result.total).toBeCloseTo(0.000756);
		expect(usage.cost).toBe(result);
	});

	it("keeps an exact threshold on the lower tier", () => {
		const usage = {
			input: 100,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 100,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		};
		calculateCost(
			model({
				cost: {
					input: 1,
					output: 0,
					cacheRead: 0,
					cacheWrite: 0,
					tiers: [{ inputTokensAbove: 100, input: 9, output: 0, cacheRead: 0, cacheWrite: 0 }],
				},
			}),
			usage,
		);
		expect(usage.cost.input).toBeCloseTo(0.0001);
	});

	it("prices one-hour cache writes at twice the selected input rate", () => {
		const usage = {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 10,
			cacheWrite1h: 4,
			totalTokens: 10,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		};
		calculateCost(model({ cost: { input: 5, output: 0, cacheRead: 0, cacheWrite: 7 } }), usage);
		expect(usage.cost.cacheWrite).toBe((7 * 6 + 5 * 2 * 4) / 1_000_000);
	});

	it("exposes max only when the model provides a max mapping", () => {
		const withoutMax = model({ reasoning: true, thinkingLevelMap: { high: "high", xhigh: "xhigh" } });
		const withMax = model({
			reasoning: true,
			thinkingLevelMap: { high: "high", xhigh: "xhigh", max: "max" },
		});
		expect(getSupportedThinkingLevels(withoutMax)).not.toContain("max");
		expect(getSupportedThinkingLevels(withMax)).toContain("max");
	});
});

import type { Usage } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import { calculateContextTokens } from "../src/core/compaction/index.ts";

// Regression guard for opt #58 — calculateContextTokens (compaction/compaction.ts:141) did a bare
// `usage.totalTokens || usage.input + usage.output + usage.usage.cacheRead + usage.cacheWrite` with
// NO undefined/NaN guard, typed `usage: Usage` (all fields required). At runtime the proxy transport
// can hand an AssistantMessage a missing/partial Usage (the proxy event `usage` comes from
// JSON.parse of an external server's SSE — the type is not enforced at the boundary). The post-turn
// compaction check (agent-session.ts:2140) calls `calculateContextTokens(assistantMessage.usage)`
// when estimateContextTokens finds no valid prior usage — with undefined usage a bare
// `usage.totalTokens` throws TypeError EVERY turn (silent crash), and a partial usage (no
// totalTokens) yields `input + output + undefined + undefined` = NaN, which the `Number.isFinite`
// guard in shouldCompact treats as "don't compact" → proactive compaction silently disabled →
// reactive overflow → lost turn (the exact class opt #32/#33 fixed, reopened for the proxy path).
// Fix: accept undefined/null → 0, coerce each field with `Number(x) || 0`, fall back to sum when
// totalTokens is missing/falsy/non-finite, return 0 on NaN. Defense-in-depth behind the opt #58
// source fix (normalizeProxyUsage) which ensures the proxy never emits a partial Usage.

describe("calculateContextTokens undefined/NaN guard (opt #58)", () => {
	it("returns 0 for undefined usage instead of throwing", () => {
		// Pre-fix: `usage.totalTokens` on undefined → TypeError: Cannot read properties of undefined.
		expect(() => calculateContextTokens(undefined)).not.toThrow();
		expect(calculateContextTokens(undefined)).toBe(0);
	});

	it("returns 0 for null usage", () => {
		expect(calculateContextTokens(null)).toBe(0);
	});

	it("recomputes from finite components when totalTokens is missing (no NaN)", () => {
		// Partial usage as a misbehaving proxy might send — no totalTokens, no cache fields.
		const partial = { input: 100, output: 50 } as unknown as Usage;
		// Pre-fix: `undefined || 100 + 50 + undefined + undefined` = NaN (Number(undefined) coerces
		// in `+` → NaN). Post-fix: missing fields → 0, sum = 150.
		const result = calculateContextTokens(partial);
		expect(Number.isFinite(result)).toBe(true);
		expect(result).toBe(150);
	});

	it("falls back to the component sum when totalTokens is 0 (preserves original || semantics)", () => {
		const usage = { input: 10, output: 5, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: zeroCost() } as Usage;
		// Original: `0 || (10+5+0+0)` = 15. Guarded version must match (0 is falsy → use sum).
		expect(calculateContextTokens(usage)).toBe(15);
	});

	it("uses a positive totalTokens when present", () => {
		const usage = { input: 10, output: 5, cacheRead: 0, cacheWrite: 0, totalTokens: 999, cost: zeroCost() } as Usage;
		expect(calculateContextTokens(usage)).toBe(999);
	});

	it("coerces non-numeric garbage fields to 0 instead of producing NaN", () => {
		const garbage = {
			input: "abc",
			output: "50",
			cacheRead: undefined,
			cacheWrite: null,
			totalTokens: "NaN",
		} as unknown as Usage;
		// Pre-fix: `"abc" + "50" + undefined + null` = "abc50null" (string concat) or NaN depending
		// on coercion; either way not a finite number. Post-fix: Number("abc")||0=0,
		// Number("50")||0=50 → 50.
		const result = calculateContextTokens(garbage);
		expect(Number.isFinite(result)).toBe(true);
		expect(result).toBe(50);
	});
});

function zeroCost(): Usage["cost"] {
	return { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 };
}

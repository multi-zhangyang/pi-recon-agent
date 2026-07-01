import { afterEach, describe, expect, it } from "vitest";
import { resolveMaxToolResultChars } from "../src/core/sdk.ts";

describe("resolveMaxToolResultChars — context-scaled tool-result cap", () => {
	const originalEnv = process.env.REPI_MAX_TOOL_RESULT_CHARS;

	afterEach(() => {
		if (originalEnv === undefined) {
			delete process.env.REPI_MAX_TOOL_RESULT_CHARS;
		} else {
			process.env.REPI_MAX_TOOL_RESULT_CHARS = originalEnv;
		}
	});

	it("honors an explicit option over env and context-scaling", () => {
		process.env.REPI_MAX_TOOL_RESULT_CHARS = "9999";
		expect(resolveMaxToolResultChars(12345, 100_000)).toBe(12345);
	});

	it("option 0 disables the cap (returns 0, not undefined)", () => {
		expect(resolveMaxToolResultChars(0, 100_000)).toBe(0);
	});

	it("honors the REPI_MAX_TOOL_RESULT_CHARS env over context-scaling when no option is given", () => {
		process.env.REPI_MAX_TOOL_RESULT_CHARS = "9999";
		expect(resolveMaxToolResultChars(undefined, 100_000)).toBe(9999);
	});

	it("scales the cap to ~10% of a small context window so one un-truncating tool result cannot overflow it", () => {
		delete process.env.REPI_MAX_TOOL_RESULT_CHARS;
		// 128K-token window → 10% = 12.8K tokens → ×4 chars/token = 51_200 chars.
		// Well under the 256K ceiling, so a single MCP/custom tool result is
		// capped at ~12.8K tokens and cannot push an 85%-full 128K context over.
		expect(resolveMaxToolResultChars(undefined, 128_000)).toBe(51_200);
	});

	it("keeps the 256K ceiling for large context windows (does not loosen beyond the existing default)", () => {
		delete process.env.REPI_MAX_TOOL_RESULT_CHARS;
		// 10M-token window → 10% = 1M tokens → ×4 = 4M chars, capped at 256K.
		expect(resolveMaxToolResultChars(undefined, 10_000_000)).toBe(256 * 1024);
	});

	it("tightens proportionally for very small windows", () => {
		delete process.env.REPI_MAX_TOOL_RESULT_CHARS;
		// 8K-token window → 10% = 800 tokens → ×4 = 3_200 chars.
		expect(resolveMaxToolResultChars(undefined, 8_000)).toBe(3_200);
	});

	it("returns undefined when the context window is unknown so the agent-loop applies its 256K default", () => {
		delete process.env.REPI_MAX_TOOL_RESULT_CHARS;
		expect(resolveMaxToolResultChars(undefined, undefined)).toBeUndefined();
		expect(resolveMaxToolResultChars(undefined, 0)).toBeUndefined();
		expect(resolveMaxToolResultChars(undefined, Number.NaN)).toBeUndefined();
	});

	it("returns undefined for a negative option (treated as unset)", () => {
		expect(resolveMaxToolResultChars(-1, 100_000)).toBeUndefined();
	});
});

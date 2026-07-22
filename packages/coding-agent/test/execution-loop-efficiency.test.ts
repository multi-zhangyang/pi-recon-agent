import { afterEach, describe, expect, it } from "vitest";
import { resolveMaxConsumedToolResultChars } from "../src/core/sdk.ts";
import { createReadOnlyToolDefinitions, createReadOnlyTools } from "../src/core/tools/index.ts";

const originalConsumedCap = process.env.REPI_MAX_CONSUMED_TOOL_RESULT_CHARS;
const originalProduct = process.env.REPI_PRODUCT;
const originalPrimary = process.env.REPI_PRIMARY;

afterEach(() => {
	if (originalConsumedCap === undefined) {
		delete process.env.REPI_MAX_CONSUMED_TOOL_RESULT_CHARS;
	} else {
		process.env.REPI_MAX_CONSUMED_TOOL_RESULT_CHARS = originalConsumedCap;
	}
	if (originalProduct === undefined) delete process.env.REPI_PRODUCT;
	else process.env.REPI_PRODUCT = originalProduct;
	if (originalPrimary === undefined) delete process.env.REPI_PRIMARY;
	else process.env.REPI_PRIMARY = originalPrimary;
});

describe("execution loop efficiency defaults", () => {
	it("scales consumed tool history to a bounded fraction of the model context", () => {
		delete process.env.REPI_MAX_CONSUMED_TOOL_RESULT_CHARS;
		expect(resolveMaxConsumedToolResultChars(undefined, 32_000)).toBe(32_000);
		expect(resolveMaxConsumedToolResultChars(undefined, 128_000)).toBe(128_000);
		expect(resolveMaxConsumedToolResultChars(undefined, 256_000)).toBe(256_000);
		expect(resolveMaxConsumedToolResultChars(undefined, 10_000_000)).toBe(256 * 1024);
	});

	it("uses a compact product budget for consumed history", () => {
		delete process.env.REPI_MAX_CONSUMED_TOOL_RESULT_CHARS;
		process.env.REPI_PRODUCT = "1";
		delete process.env.REPI_PRIMARY;
		expect(resolveMaxConsumedToolResultChars(undefined, 128_000)).toBe(32 * 1024);
		expect(resolveMaxConsumedToolResultChars(undefined, undefined)).toBe(32 * 1024);
	});

	it("honors explicit and environment overrides, including zero to disable", () => {
		process.env.REPI_MAX_CONSUMED_TOOL_RESULT_CHARS = "12000";
		expect(resolveMaxConsumedToolResultChars(undefined, 128_000)).toBe(12_000);
		expect(resolveMaxConsumedToolResultChars(4096, 128_000)).toBe(4096);
		expect(resolveMaxConsumedToolResultChars(0, 128_000)).toBe(0);
	});

	it("marks every built-in observation tool as read-only through both definition and runtime surfaces", () => {
		const definitions = createReadOnlyToolDefinitions("/tmp");
		const tools = createReadOnlyTools("/tmp");
		expect(definitions.map((tool) => tool.name)).toEqual(["read", "grep", "find", "ls"]);
		expect(definitions.every((tool) => tool.readOnly === true)).toBe(true);
		expect(tools.every((tool) => tool.readOnly === true)).toBe(true);
	});

	it("preserves conservative read-range coverage through the definition wrapper", () => {
		const definition = createReadOnlyToolDefinitions("/tmp").find((tool) => tool.name === "read");
		const tool = createReadOnlyTools("/tmp").find((candidate) => candidate.name === "read");
		expect(definition?.readOnlyProbeCovers).toBeTypeOf("function");
		expect(tool?.readOnlyProbeCovers).toBeTypeOf("function");
		const covered = { path: "source.ts", offset: 120, limit: 10 };
		expect(tool?.readOnlyProbeCovers?.({ path: "source.ts", offset: 100, limit: 100 }, covered)).toBe(true);
		expect(tool?.readOnlyProbeCovers?.({ path: "source.ts", offset: 150, limit: 100 }, covered)).toBe(false);
		expect(tool?.readOnlyProbeCovers?.({ path: "other.ts", offset: 100, limit: 100 }, covered)).toBe(false);
		expect(tool?.readOnlyProbeCovers?.({ path: "source.ts", offset: 100 }, covered)).toBe(false);
	});

	it("uses one shared batching guideline across the read-only tool set", () => {
		const definitions = createReadOnlyToolDefinitions("/tmp");
		const batchingGuidelines = definitions.flatMap((tool) =>
			(tool.promptGuidelines ?? []).filter((guideline) =>
				guideline.startsWith("Batch independent read-only probes"),
			),
		);
		expect(new Set(batchingGuidelines)).toEqual(
			new Set([
				"Batch independent read-only probes in one turn and do not repeat identical probes unless state changed.",
			]),
		);
	});
});

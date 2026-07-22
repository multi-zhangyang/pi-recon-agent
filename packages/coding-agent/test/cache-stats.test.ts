import type { AssistantMessage } from "@pi-recon/repi-ai";
import { describe, expect, it } from "vitest";
import {
	collectCacheMisses,
	computeCacheWaste,
	detectCacheMiss,
	type ModelPriceSource,
} from "../src/core/cache-stats.ts";
import { buildSessionContext, type SessionEntry } from "../src/core/session-manager.ts";

const zeroCost = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 };

const models: ModelPriceSource = {
	find: () => ({ cost: { input: 3, cacheRead: 0.3, cacheWrite: 3.75 } }),
};

function assistant(options: {
	input?: number;
	cacheRead?: number;
	cacheWrite?: number;
	cost?: Partial<typeof zeroCost>;
	model?: string;
	responseModel?: string;
	timestamp?: number;
}): AssistantMessage {
	return {
		role: "assistant",
		content: [],
		api: "anthropic-messages",
		provider: "test",
		model: options.model ?? "test-model",
		responseModel: options.responseModel,
		usage: {
			input: options.input ?? 0,
			output: 10,
			cacheRead: options.cacheRead ?? 0,
			cacheWrite: options.cacheWrite ?? 0,
			totalTokens: 0,
			cost: { ...zeroCost, ...options.cost },
		},
		stopReason: "stop",
		timestamp: options.timestamp ?? 0,
	} as AssistantMessage;
}

function entry(message: AssistantMessage, id = "x"): SessionEntry {
	return { type: "message", id, parentId: null, timestamp: "", message } as SessionEntry;
}

const turn1 = assistant({ cacheWrite: 100_000, cost: { cacheWrite: 0.375 }, timestamp: 0 });
const turn2 = assistant({
	cacheRead: 100_000,
	cacheWrite: 5_000,
	cost: { cacheRead: 0.03, cacheWrite: 0.01875 },
	timestamp: 60_000,
});

describe("computeCacheWaste", () => {
	it("accumulates missed tokens and cost across turns", () => {
		const turn3 = assistant({ cacheWrite: 110_000, cost: { cacheWrite: 0.4125 }, timestamp: 120_000 });
		const totals = computeCacheWaste([entry(turn1), entry(turn2), entry(turn3)], models);
		expect(totals).toMatchObject({ missedTokens: 105_000, missCount: 1 });
		expect(totals.missedCost).toBeCloseTo(0.36225, 5);
	});

	it("counts nothing for healthy sessions or providers without cache reporting", () => {
		expect(computeCacheWaste([entry(turn1), entry(turn2)], models).missCount).toBe(0);
		const a = assistant({ input: 100_000 });
		const b = assistant({ input: 110_000 });
		expect(computeCacheWaste([entry(a), entry(b)], models).missCount).toBe(0);
	});

	it.each(["compaction", "branch_summary"] as const)("resets attribution after %s", (type) => {
		const reset = { type, id: "reset", parentId: null, timestamp: "" } as SessionEntry;
		const afterReset = assistant({ cacheWrite: 20_000, cost: { cacheWrite: 0.075 } });
		expect(computeCacheWaste([entry(turn1), reset, entry(afterReset)], models).missCount).toBe(0);
	});

	it("counts concrete response-model switches", () => {
		const switched = assistant({
			cacheWrite: 100_000,
			cost: { cacheWrite: 0.375 },
			responseModel: "other-model",
		});
		const miss = detectCacheMiss([entry(turn1)], switched, models);
		expect(miss?.modelChanged).toBe(true);
	});

	it("applies an observed long-context pricing tier exactly once", () => {
		const tieredFullMiss = assistant({
			cacheWrite: 110_000,
			// Catalog write price is $3.75/M; this message was billed at the 2x tier.
			cost: { cacheWrite: 0.825 },
			timestamp: 120_000,
		});
		const miss = detectCacheMiss([entry(turn1), entry(turn2)], tieredFullMiss, models);
		// 105k * (($7.50 - $0.60) / 1M). A second tier multiplier would yield $1.512.
		expect(miss?.missedCost).toBeCloseTo(0.7245, 5);
	});
});

describe("assistant-message attribution", () => {
	it("maps a miss only to the exact persisted assistant object", () => {
		const missTurn = assistant({ cacheWrite: 110_000, cost: { cacheWrite: 0.4125 }, timestamp: 120_000 });
		const equalCopy = { ...missTurn } as AssistantMessage;
		const misses = collectCacheMisses([entry(turn1), entry(turn2), entry(missTurn)], models);
		expect(misses.get(missTurn)?.missedTokens).toBe(105_000);
		expect(misses.has(equalCopy)).toBe(false);
	});

	it("detects a just-completed message before persistence", () => {
		const missTurn = assistant({ cacheWrite: 110_000, cost: { cacheWrite: 0.4125 }, timestamp: 600_000 });
		const miss = detectCacheMiss([entry(turn1), entry(turn2)], missTurn, models);
		expect(miss).toMatchObject({ missedTokens: 105_000, idleMs: 540_000, modelChanged: false });
	});

	it("recomputes reference attribution after resume and a compaction boundary", () => {
		const postCompactionBase = assistant({ cacheWrite: 100_000, cost: { cacheWrite: 0.375 }, timestamp: 180_000 });
		const postCompactionMiss = assistant({
			cacheWrite: 110_000,
			cost: { cacheWrite: 0.4125 },
			timestamp: 240_000,
		});
		const persisted: SessionEntry[] = [
			{ ...entry(turn1, "turn-1"), parentId: null },
			{
				type: "compaction",
				id: "compact",
				parentId: "turn-1",
				timestamp: "",
				summary: "summary",
				firstKeptEntryId: "turn-1",
				tokensBefore: 100_000,
			},
			{ ...entry(postCompactionBase, "post-base"), parentId: "compact" },
			{ ...entry(postCompactionMiss, "post-miss"), parentId: "post-base" },
		];
		const resumed = JSON.parse(JSON.stringify(persisted)) as SessionEntry[];
		const rebuilt = buildSessionContext(resumed, "post-miss");
		const rebuiltMiss = rebuilt.messages.find(
			(message): message is AssistantMessage => message.role === "assistant" && message.timestamp === 240_000,
		);
		expect(rebuiltMiss).toBeDefined();
		expect(collectCacheMisses(resumed, models).get(rebuiltMiss!)?.missedTokens).toBe(100_000);
	});
});

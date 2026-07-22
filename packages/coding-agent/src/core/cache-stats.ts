import type { AssistantMessage } from "@pi-recon/repi-ai";
import type { SessionEntry } from "./session-manager.ts";

/** Anthropic's default prompt-cache TTL. */
export const CACHE_TTL_MS = 5 * 60 * 1000;

/** Per-turn differences at or below this are cache-breakpoint granularity noise. */
const NOISE_FLOOR_TOKENS = 1024;

export interface CacheMiss {
	/** Prompt tokens present in the previous request but not read from cache. */
	missedTokens: number;
	/** Extra dollars paid compared with a full cache hit. */
	missedCost: number;
	/** Milliseconds since the previous request refreshed the cache. */
	idleMs: number;
	/** Whether the concrete response model changed since the previous request. */
	modelChanged: boolean;
}

export interface CacheWasteTotals {
	missedTokens: number;
	missedCost: number;
	missCount: number;
}

/** Minimal pricing lookup implemented by ModelRegistry. Prices are dollars per million tokens. */
export interface ModelPriceSource {
	find(
		provider: string,
		modelId: string,
	): { cost: { input: number; cacheRead: number; cacheWrite: number } } | undefined;
}

interface PreviousRequest {
	promptTokens: number;
	modelKey: string;
	timestamp: number;
	/** Sticky cache support signal for providers that report reads but not writes. */
	reportedCache: boolean;
}

function count(value: unknown): number {
	return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}

function responseModelKey(message: AssistantMessage): string {
	return `${message.provider}/${message.responseModel ?? message.model}`;
}

/**
 * Resolve the counterfactual cache-read rate for a full-miss request.
 *
 * The message cost is authoritative and may already include a long-context or
 * service-tier multiplier. Scale the catalog cache-read price by the observed
 * prompt-cost multiplier exactly once instead of mixing tiered paid cost with
 * an untiered cache-read fallback.
 */
function fallbackCacheReadRate(
	message: AssistantMessage,
	models: ModelPriceSource,
	inputTokens: number,
	cacheWriteTokens: number,
	paidCost: number,
): number {
	const model = models.find(message.provider, message.model);
	if (!model) return 0;

	const basePaidCost =
		(inputTokens * count(model.cost.input) + cacheWriteTokens * count(model.cost.cacheWrite)) / 1_000_000;
	const observedMultiplier = basePaidCost > 0 && paidCost > 0 ? paidCost / basePaidCost : 1;
	return (count(model.cost.cacheRead) / 1_000_000) * observedMultiplier;
}

function detectMiss(
	previous: PreviousRequest | undefined,
	message: AssistantMessage,
	models: ModelPriceSource,
): CacheMiss | undefined {
	const usage = message.usage;
	const input = count(usage?.input);
	const cacheRead = count(usage?.cacheRead);
	const cacheWrite = count(usage?.cacheWrite);
	const promptTokens = input + cacheRead + cacheWrite;

	if (!previous || promptTokens <= 0 || (cacheRead + cacheWrite === 0 && !previous.reportedCache)) {
		return undefined;
	}

	const missedTokens = Math.min(previous.promptTokens, promptTokens) - cacheRead;
	if (missedTokens <= NOISE_FLOOR_TOKENS) return undefined;

	const inputCost = count(usage?.cost?.input);
	const cacheReadCost = count(usage?.cost?.cacheRead);
	const cacheWriteCost = count(usage?.cost?.cacheWrite);
	const paidTokens = input + cacheWrite;
	const paidCost = inputCost + cacheWriteCost;
	const paidPerToken = paidTokens > 0 ? paidCost / paidTokens : 0;
	const readPerToken =
		cacheRead > 0 && cacheReadCost > 0
			? cacheReadCost / cacheRead
			: fallbackCacheReadRate(message, models, input, cacheWrite, paidCost);

	return {
		missedTokens,
		missedCost: missedTokens * Math.max(0, paidPerToken - readPerToken),
		idleMs: Math.max(0, count(message.timestamp) - previous.timestamp),
		modelChanged: responseModelKey(message) !== previous.modelKey,
	};
}

function asPreviousRequest(message: AssistantMessage, reportedCache: boolean): PreviousRequest | undefined {
	const usage = message.usage;
	const input = count(usage?.input);
	const cacheRead = count(usage?.cacheRead);
	const cacheWrite = count(usage?.cacheWrite);
	const promptTokens = input + cacheRead + cacheWrite;
	if (promptTokens <= 0) return undefined;

	return {
		promptTokens,
		modelKey: responseModelKey(message),
		timestamp: count(message.timestamp),
		reportedCache: reportedCache || cacheRead + cacheWrite > 0,
	};
}

function scan(
	entries: SessionEntry[],
	models: ModelPriceSource,
): { previous: PreviousRequest | undefined; totals: CacheWasteTotals; misses: Map<AssistantMessage, CacheMiss> } {
	let previous: PreviousRequest | undefined;
	const totals: CacheWasteTotals = { missedTokens: 0, missedCost: 0, missCount: 0 };
	const misses = new Map<AssistantMessage, CacheMiss>();

	for (const entry of entries) {
		if (entry.type === "compaction" || entry.type === "branch_summary") {
			previous = undefined;
			continue;
		}
		if (entry.type !== "message" || entry.message.role !== "assistant") continue;

		const miss = detectMiss(previous, entry.message, models);
		if (miss) {
			totals.missedTokens += miss.missedTokens;
			totals.missedCost += miss.missedCost;
			totals.missCount += 1;
			misses.set(entry.message, miss);
		}
		previous = asPreviousRequest(entry.message, previous?.reportedCache ?? false) ?? previous;
	}

	return { previous, totals, misses };
}

/** Cumulative prompt tokens and cost re-billed because of cache misses. */
export function computeCacheWaste(entries: SessionEntry[], models: ModelPriceSource): CacheWasteTotals {
	return scan(entries, models).totals;
}

/** Cache misses keyed by the exact persisted assistant message object that incurred them. */
export function collectCacheMisses(
	entries: SessionEntry[],
	models: ModelPriceSource,
): Map<AssistantMessage, CacheMiss> {
	return scan(entries, models).misses;
}

/** Detect a miss before the just-completed message has been persisted. */
export function detectCacheMiss(
	entries: SessionEntry[],
	message: AssistantMessage,
	models: ModelPriceSource,
): CacheMiss | undefined {
	return detectMiss(scan(entries, models).previous, message, models);
}

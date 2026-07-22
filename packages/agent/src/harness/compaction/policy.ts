/** Runtime policy shared by the public harness and coding-agent compaction. */
export interface CompactionSettings {
	/** Enable automatic compaction decisions. */
	enabled: boolean;
	/** Tokens reserved for the summary prompt and output. */
	reserveTokens: number;
	/** Approximate recent-context tokens to keep after compaction. */
	keepRecentTokens: number;
	/** Proactive trigger as a percentage of the active context window. */
	triggerPercent?: number;
	/** Warning threshold used by context diagnostics and interactive UI. */
	warningPercent?: number;
}

/** Product-wide compaction defaults. Keep all runtime entrypoints on this object. */
export const DEFAULT_COMPACTION_SETTINGS: CompactionSettings = {
	enabled: true,
	reserveTokens: 16_384,
	keepRecentTokens: 36_000,
	triggerPercent: 85,
	warningPercent: 80,
};

/** Return the earliest valid token threshold configured for compaction. */
export function compactionTriggerTokens(contextWindow: number, settings: CompactionSettings): number {
	if (!Number.isFinite(contextWindow) || contextWindow <= 0) return Number.POSITIVE_INFINITY;

	const thresholds: number[] = [];
	const triggerPercent = settings.triggerPercent;
	if (
		typeof triggerPercent === "number" &&
		Number.isFinite(triggerPercent) &&
		triggerPercent > 0 &&
		triggerPercent < 100
	) {
		thresholds.push(Math.floor((contextWindow * triggerPercent) / 100));
	}

	const reserveTokens = Number.isFinite(settings.reserveTokens) ? Math.max(0, settings.reserveTokens) : 0;
	if (reserveTokens > 0 && reserveTokens < contextWindow) {
		thresholds.push(contextWindow - reserveTokens);
	}

	const positiveThresholds = thresholds.filter((threshold) => threshold > 0);
	const rawThreshold =
		positiveThresholds.length > 0 ? Math.min(...positiveThresholds) : Math.floor(contextWindow * 0.9);
	const floor = Math.min(Math.max(1024, Math.floor(contextWindow * 0.25)), Math.max(1, contextWindow - 1));
	return Math.max(rawThreshold, floor);
}

/** Return whether finite, positive context usage exceeds the configured threshold. */
export function shouldCompact(contextTokens: number, contextWindow: number, settings: CompactionSettings): boolean {
	if (!settings.enabled) return false;
	if (!Number.isFinite(contextTokens) || contextTokens <= 0) return false;
	if (!Number.isFinite(contextWindow) || contextWindow <= 0) return false;
	const threshold = compactionTriggerTokens(contextWindow, settings);
	if (!Number.isFinite(threshold) || threshold <= 0) return false;
	return contextTokens > threshold;
}

/**
 * Return a bounded input budget for summary requests.
 *
 * Invalid reserves, including reserves as large as the model window, fall back
 * to retaining 25% of the window for instructions and output. This always
 * returns a positive value because branch preparation treats non-positive
 * budgets as unlimited.
 */
export function summaryInputTokenBudget(contextWindow: number, reserveTokens: number): number {
	if (!Number.isFinite(contextWindow) || contextWindow <= 0) return 1;
	const normalizedReserve = Number.isFinite(reserveTokens) ? reserveTokens : 0;
	const effectiveReserve =
		normalizedReserve > 0 && normalizedReserve < contextWindow
			? normalizedReserve
			: Math.max(1, Math.floor(contextWindow * 0.25));
	return Math.max(1, Math.floor(contextWindow - effectiveReserve));
}

const SUMMARY_TRUNCATION_MARKER = "\n\n[summary truncated to fit the context budget]\n\n";

function avoidSplitSurrogate(text: string, index: number): number {
	if (index <= 0 || index >= text.length) return index;
	const previous = text.charCodeAt(index - 1);
	const next = text.charCodeAt(index);
	return previous >= 0xd800 && previous <= 0xdbff && next >= 0xdc00 && next <= 0xdfff ? index - 1 : index;
}

/** Bound summary text using the same four-characters-per-token heuristic as compaction. */
export function truncateSummaryToTokenBudget(summary: string, tokenBudget: number): string {
	if (!Number.isFinite(tokenBudget) || tokenBudget <= 0) return "";
	const maxChars = Math.max(1, Math.floor(tokenBudget) * 4);
	if (summary.length <= maxChars) return summary;
	if (maxChars <= SUMMARY_TRUNCATION_MARKER.length) {
		return summary.slice(0, avoidSplitSurrogate(summary, maxChars));
	}

	const retainedChars = maxChars - SUMMARY_TRUNCATION_MARKER.length;
	const headEnd = avoidSplitSurrogate(summary, Math.ceil(retainedChars / 2));
	const tailStart = avoidSplitSurrogate(summary, summary.length - Math.floor(retainedChars / 2));
	return `${summary.slice(0, headEnd)}${SUMMARY_TRUNCATION_MARKER}${summary.slice(tailStart)}`;
}

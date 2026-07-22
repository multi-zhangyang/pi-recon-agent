import { DEFAULT_MAX_TOOL_RESULT_CHARS } from "@pi-recon/repi-agent-core";

const MAX_CONSUMED_TOOL_RESULT_CHARS = 256 * 1024;
const REPI_MAX_CONSUMED_TOOL_RESULT_CHARS = 32 * 1024;
// Tool results are evidence pointers, not a second transcript. Keep the
// product default small enough that a few probes cannot dominate a turn.
const REPI_MAX_TOOL_RESULT_CHARS = 4 * 1024;

function isRepiProductMode(): boolean {
	return process.env.REPI_PRODUCT === "1" || process.env.REPI_PRIMARY === "1";
}

/** Resolve the assistant-turn cap from explicit options or REPI_MAX_TURNS. */
export function resolveMaxTurns(option?: number): number | undefined {
	if (typeof option === "number" && Number.isFinite(option) && option > 0) return Math.floor(option);
	const raw = process.env.REPI_MAX_TURNS;
	if (raw !== undefined && raw !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed) && parsed > 0) return Math.floor(parsed);
	}
	return undefined;
}

/** Resolve the length auto-continue cap. */
export function resolveLengthContinueMax(option?: number): number | undefined {
	if (typeof option === "number" && Number.isFinite(option)) return option > 0 ? Math.floor(option) : undefined;
	const raw = process.env.REPI_LENGTH_CONTINUE_MAX;
	if (raw !== undefined && raw !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed)) return parsed > 0 ? Math.floor(parsed) : undefined;
	}
	return isRepiProductMode() ? 3 : undefined;
}

/** Resolve the pre-stream transient-error retry cap. */
export function resolveStreamMaxRetries(option?: number): number | undefined {
	if (typeof option === "number" && Number.isFinite(option)) return option > 0 ? Math.floor(option) : undefined;
	const raw = process.env.REPI_STREAM_MAX_RETRIES;
	if (raw !== undefined && raw !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed)) return parsed > 0 ? Math.floor(parsed) : undefined;
	}
	return isRepiProductMode() ? 2 : undefined;
}

/** Resolve the defense-in-depth cap for one tool result. */
export function resolveMaxToolResultChars(option?: number, contextWindow?: number): number | undefined {
	if (typeof option === "number" && Number.isFinite(option)) return option >= 0 ? Math.floor(option) : undefined;
	const raw = process.env.REPI_MAX_TOOL_RESULT_CHARS;
	if (raw !== undefined && raw !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed)) return parsed >= 0 ? Math.floor(parsed) : undefined;
	}
	if (typeof contextWindow === "number" && Number.isFinite(contextWindow) && contextWindow > 0) {
		const scaled = Math.floor(contextWindow * 0.1 * 4);
		const ceiling = isRepiProductMode() ? REPI_MAX_TOOL_RESULT_CHARS : DEFAULT_MAX_TOOL_RESULT_CHARS;
		return Math.max(1, Math.min(scaled, ceiling));
	}
	return isRepiProductMode() ? REPI_MAX_TOOL_RESULT_CHARS : undefined;
}

/** Resolve the aggregate cap for tool results already consumed by the provider. */
export function resolveMaxConsumedToolResultChars(option?: number, contextWindow?: number): number | undefined {
	if (typeof option === "number" && Number.isFinite(option)) return option >= 0 ? Math.floor(option) : undefined;
	const raw = process.env.REPI_MAX_CONSUMED_TOOL_RESULT_CHARS;
	if (raw !== undefined && raw !== "") {
		const parsed = Number(raw);
		if (Number.isFinite(parsed)) return parsed >= 0 ? Math.floor(parsed) : undefined;
	}
	if (typeof contextWindow === "number" && Number.isFinite(contextWindow) && contextWindow > 0) {
		const scaled = Math.floor(contextWindow * 0.25 * 4);
		const ceiling = isRepiProductMode() ? REPI_MAX_CONSUMED_TOOL_RESULT_CHARS : MAX_CONSUMED_TOOL_RESULT_CHARS;
		return Math.max(1, Math.min(scaled, ceiling));
	}
	return isRepiProductMode() ? REPI_MAX_CONSUMED_TOOL_RESULT_CHARS : MAX_CONSUMED_TOOL_RESULT_CHARS;
}

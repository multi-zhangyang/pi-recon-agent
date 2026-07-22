import type { ImageContent, TextContent } from "@pi-recon/repi-ai";
import { safeHeadEnd, safeTailStart } from "../harness/utils/truncate.ts";
import type { AgentMessage } from "../types.ts";

/**
 * Upper bound for the provider-only projection of already-consumed tool
 * results. The effective default is context-scaled by
 * {@link defaultMaxConsumedToolResultChars}; this ceiling keeps very large
 * context models from replaying an unbounded amount of stale output. The
 * transcript and newest results remain unchanged.
 */
export const DEFAULT_MAX_CONSUMED_TOOL_RESULT_CHARS = 256 * 1024;

/** Maximum share of the aggregate consumed-result budget assigned to one result. */
const MAX_COMPACTED_RESULT_CHARS = 64 * 1024;

/**
 * Resolve the default provider projection budget for an active model.
 *
 * Keep roughly one quarter of the context window (using the same conservative
 * four-characters-per-token estimate used by compaction), capped at 256KiB.
 * This is intentionally generous enough to retain a normal 50KiB source/log
 * result in full while still bounding old output on long-running sessions.
 */
export function defaultMaxConsumedToolResultChars(contextWindow?: number): number {
	if (typeof contextWindow === "number" && Number.isFinite(contextWindow) && contextWindow > 0) {
		const scaled = Math.floor(contextWindow * 0.25 * 4);
		return Math.max(1, Math.min(scaled, DEFAULT_MAX_CONSUMED_TOOL_RESULT_CHARS));
	}
	return DEFAULT_MAX_CONSUMED_TOOL_RESULT_CHARS;
}

function truncateConsumedResultText(text: string, maxChars: number): string {
	if (maxChars <= 0) return "";
	if (text.length <= maxChars) return text;
	const marker = `\n\n[... ${text.length - maxChars} characters omitted from an earlier tool result after it was consumed ...]\n\n`;
	if (maxChars <= marker.length + 16) {
		return `[Earlier tool result omitted: ${text.length} chars]`.slice(0, maxChars);
	}
	const contentBudget = maxChars - marker.length;
	const head = Math.floor(contentBudget * 0.6);
	const tail = contentBudget - head;
	const headEnd = safeHeadEnd(text, head);
	const tailStart = safeTailStart(text, text.length - tail);
	return `${text.slice(0, headEnd)}${marker}${text.slice(tailStart)}`;
}

function compactConsumedResultContent(
	content: (TextContent | ImageContent)[],
	maxChars: number,
): (TextContent | ImageContent)[] {
	const text = content
		.filter((block): block is TextContent => block.type === "text")
		.map((block) => block.text)
		.join("\n\n");
	const imageCount = content.length - content.filter((block) => block.type === "text").length;
	const imageNote = imageCount > 0 ? `[${imageCount} earlier tool-result image(s) omitted after consumption]` : "";
	const combined = imageNote && text ? `${imageNote}\n\n${text}` : imageNote || text;
	return [{ type: "text", text: truncateConsumedResultText(combined, maxChars) }];
}

/**
 * Compact only tool results that have already been followed by another assistant
 * message. This is a provider-only projection: callers retain the original array,
 * result content, images, details, and UI/session evidence.
 */
export function compactConsumedToolResults(messages: AgentMessage[], maxChars: number): AgentMessage[] {
	if (maxChars <= 0) return messages;
	let lastAssistantIndex = -1;
	for (let index = messages.length - 1; index >= 0; index--) {
		if (messages[index].role === "assistant") {
			lastAssistantIndex = index;
			break;
		}
	}
	if (lastAssistantIndex < 0) return messages;

	let remaining = maxChars;
	let projected: AgentMessage[] | undefined;
	for (let index = lastAssistantIndex - 1; index >= 0; index--) {
		const message = messages[index];
		if (message.role !== "toolResult") continue;
		const originalChars = message.content.reduce(
			(total, block) => total + (block.type === "text" ? block.text.length : 0),
			0,
		);
		const hasImages = message.content.some((block) => block.type === "image");
		const allocation = Math.min(MAX_COMPACTED_RESULT_CHARS, remaining);
		if (!hasImages && originalChars <= allocation) {
			remaining -= originalChars;
			continue;
		}

		const content = compactConsumedResultContent(message.content, allocation);
		const projectedChars = content.reduce(
			(total, block) => total + (block.type === "text" ? block.text.length : 0),
			0,
		);
		remaining = Math.max(0, remaining - projectedChars);
		projected ??= messages.slice();
		projected[index] = { ...message, content };
	}
	return projected ?? messages;
}

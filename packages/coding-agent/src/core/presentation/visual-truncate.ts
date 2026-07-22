import { Text } from "@pi-recon/repi-tui";

export interface VisualTruncateResult {
	/** The visual lines to display. */
	visualLines: string[];
	/** Number of visual lines hidden from the beginning. */
	skippedCount: number;
}

/** Truncate text to the final visual lines for a fixed terminal width. */
export function truncateToVisualLines(
	text: string,
	maxVisualLines: number,
	width: number,
	paddingX = 0,
): VisualTruncateResult {
	if (!text) return { visualLines: [], skippedCount: 0 };

	const allVisualLines = new Text(text, paddingX, 0).render(width);
	if (allVisualLines.length <= maxVisualLines) {
		return { visualLines: allVisualLines, skippedCount: 0 };
	}

	return {
		visualLines: allVisualLines.slice(-maxVisualLines),
		skippedCount: allVisualLines.length - maxVisualLines,
	};
}

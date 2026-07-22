import { type RenderDiffOptions, renderDiff as renderDiffWithTheme } from "../../../core/presentation/diff.ts";
import { theme } from "../../../core/presentation/theme-runtime.ts";

export type { RenderDiffOptions } from "../../../core/presentation/diff.ts";

/** Interactive compatibility wrapper using the active singleton theme. */
export function renderDiff(diffText: string, options: RenderDiffOptions = {}): string {
	return renderDiffWithTheme(diffText, theme, options);
}

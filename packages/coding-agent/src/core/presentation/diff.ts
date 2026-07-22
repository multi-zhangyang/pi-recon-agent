import * as Diff from "diff";
import type { Theme } from "./theme.ts";

function parseDiffLine(line: string): { prefix: string; lineNum: string; content: string } | null {
	const match = line.match(/^([+-\s])(\s*\d*)\s(.*)$/);
	if (!match) return null;
	return { prefix: match[1], lineNum: match[2], content: match[3] };
}

function replaceTabs(text: string): string {
	return text.replace(/\t/g, "   ");
}

function renderIntraLineDiff(
	theme: Theme,
	oldContent: string,
	newContent: string,
): { removedLine: string; addedLine: string } {
	const wordDiff = Diff.diffWords(oldContent, newContent);
	let removedLine = "";
	let addedLine = "";
	let isFirstRemoved = true;
	let isFirstAdded = true;

	for (const part of wordDiff) {
		if (part.removed) {
			let value = part.value;
			if (isFirstRemoved) {
				const leadingWs = value.match(/^(\s*)/)?.[1] || "";
				value = value.slice(leadingWs.length);
				removedLine += leadingWs;
				isFirstRemoved = false;
			}
			if (value) removedLine += theme.inverse(value);
		} else if (part.added) {
			let value = part.value;
			if (isFirstAdded) {
				const leadingWs = value.match(/^(\s*)/)?.[1] || "";
				value = value.slice(leadingWs.length);
				addedLine += leadingWs;
				isFirstAdded = false;
			}
			if (value) addedLine += theme.inverse(value);
		} else {
			removedLine += part.value;
			addedLine += part.value;
		}
	}

	return { removedLine, addedLine };
}

export interface RenderDiffOptions {
	filePath?: string;
}

/** Render a unified diff with theme-aware line and intra-line colors. */
export function renderDiff(diffText: string, theme: Theme, _options: RenderDiffOptions = {}): string {
	const lines = diffText.split("\n");
	const result: string[] = [];
	let i = 0;

	while (i < lines.length) {
		const line = lines[i];
		const parsed = parseDiffLine(line);
		if (!parsed) {
			result.push(theme.fg("toolDiffContext", line));
			i++;
			continue;
		}

		if (parsed.prefix === "-") {
			const removedLines: Array<{ lineNum: string; content: string }> = [];
			while (i < lines.length) {
				const current = parseDiffLine(lines[i]);
				if (!current || current.prefix !== "-") break;
				removedLines.push({ lineNum: current.lineNum, content: current.content });
				i++;
			}

			const addedLines: Array<{ lineNum: string; content: string }> = [];
			while (i < lines.length) {
				const current = parseDiffLine(lines[i]);
				if (!current || current.prefix !== "+") break;
				addedLines.push({ lineNum: current.lineNum, content: current.content });
				i++;
			}

			if (removedLines.length === 1 && addedLines.length === 1) {
				const removed = removedLines[0];
				const added = addedLines[0];
				const intraLine = renderIntraLineDiff(theme, replaceTabs(removed.content), replaceTabs(added.content));
				result.push(theme.fg("toolDiffRemoved", `-${removed.lineNum} ${intraLine.removedLine}`));
				result.push(theme.fg("toolDiffAdded", `+${added.lineNum} ${intraLine.addedLine}`));
			} else {
				for (const removed of removedLines) {
					result.push(theme.fg("toolDiffRemoved", `-${removed.lineNum} ${replaceTabs(removed.content)}`));
				}
				for (const added of addedLines) {
					result.push(theme.fg("toolDiffAdded", `+${added.lineNum} ${replaceTabs(added.content)}`));
				}
			}
		} else if (parsed.prefix === "+") {
			result.push(theme.fg("toolDiffAdded", `+${parsed.lineNum} ${replaceTabs(parsed.content)}`));
			i++;
		} else {
			result.push(theme.fg("toolDiffContext", ` ${parsed.lineNum} ${replaceTabs(parsed.content)}`));
			i++;
		}
	}

	return result.join("\n");
}

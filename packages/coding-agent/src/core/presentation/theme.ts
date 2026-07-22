import type { SourceInfo } from "../source-info.ts";

export type ThemeColor =
	| "accent"
	| "border"
	| "borderAccent"
	| "borderMuted"
	| "success"
	| "error"
	| "warning"
	| "muted"
	| "dim"
	| "text"
	| "thinkingText"
	| "userMessageText"
	| "customMessageText"
	| "customMessageLabel"
	| "toolTitle"
	| "toolOutput"
	| "mdHeading"
	| "mdLink"
	| "mdLinkUrl"
	| "mdCode"
	| "mdCodeBlock"
	| "mdCodeBlockBorder"
	| "mdQuote"
	| "mdQuoteBorder"
	| "mdHr"
	| "mdListBullet"
	| "toolDiffAdded"
	| "toolDiffRemoved"
	| "toolDiffContext"
	| "syntaxComment"
	| "syntaxKeyword"
	| "syntaxFunction"
	| "syntaxVariable"
	| "syntaxString"
	| "syntaxNumber"
	| "syntaxType"
	| "syntaxOperator"
	| "syntaxPunctuation"
	| "thinkingOff"
	| "thinkingMinimal"
	| "thinkingLow"
	| "thinkingMedium"
	| "thinkingHigh"
	| "thinkingXhigh"
	| "bashMode";

export type ThemeBg =
	| "selectedBg"
	| "userMessageBg"
	| "customMessageBg"
	| "toolPendingBg"
	| "toolSuccessBg"
	| "toolErrorBg";

export type ThemeColorMode = "truecolor" | "256color";

/** Presentation contract shared by core, headless modes, and the interactive implementation. */
export interface Theme {
	readonly name?: string;
	readonly sourcePath?: string;
	sourceInfo?: SourceInfo;
	fg(color: ThemeColor, text: string): string;
	bg(color: ThemeBg, text: string): string;
	bold(text: string): string;
	italic(text: string): string;
	underline(text: string): string;
	inverse(text: string): string;
	strikethrough(text: string): string;
	getFgAnsi(color: ThemeColor): string;
	getBgAnsi(color: ThemeBg): string;
	getColorMode(): ThemeColorMode;
	getThinkingBorderColor(level: "off" | "minimal" | "low" | "medium" | "high" | "xhigh"): (text: string) => string;
	getBashModeBorderColor(): (text: string) => string;
}

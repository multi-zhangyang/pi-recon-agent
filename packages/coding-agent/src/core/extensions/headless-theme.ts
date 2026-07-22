import type { Theme } from "../presentation/theme.ts";

const identity = (text: string): string => text;

// Headless SDK/print/RPC sessions do not initialize the interactive theme singleton.
// Keep the extension theme contract usable without emitting terminal escape sequences.
const headlessThemeSurface = {
	name: "headless",
	fg: (_color, text) => text,
	bg: (_color, text) => text,
	bold: identity,
	italic: identity,
	underline: identity,
	inverse: identity,
	strikethrough: identity,
	getFgAnsi: () => "",
	getBgAnsi: () => "",
	getColorMode: () => "truecolor" as const,
	getThinkingBorderColor: () => identity,
	getBashModeBorderColor: () => identity,
} satisfies Theme;

export const headlessTheme: Theme = headlessThemeSurface;

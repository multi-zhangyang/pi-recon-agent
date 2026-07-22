import { highlight, supportsLanguage } from "../../utils/syntax-highlight.ts";
import type { Theme } from "./theme.ts";

type CliHighlightTheme = Record<string, (text: string) => string>;
const cachedThemes = new WeakMap<object, CliHighlightTheme>();

function buildCliHighlightTheme(theme: Theme): CliHighlightTheme {
	return {
		keyword: (text) => theme.fg("syntaxKeyword", text),
		built_in: (text) => theme.fg("syntaxType", text),
		literal: (text) => theme.fg("syntaxNumber", text),
		number: (text) => theme.fg("syntaxNumber", text),
		regexp: (text) => theme.fg("syntaxString", text),
		string: (text) => theme.fg("syntaxString", text),
		comment: (text) => theme.fg("syntaxComment", text),
		doctag: (text) => theme.fg("syntaxComment", text),
		meta: (text) => theme.fg("muted", text),
		function: (text) => theme.fg("syntaxFunction", text),
		title: (text) => theme.fg("syntaxFunction", text),
		class: (text) => theme.fg("syntaxType", text),
		type: (text) => theme.fg("syntaxType", text),
		tag: (text) => theme.fg("syntaxPunctuation", text),
		name: (text) => theme.fg("syntaxKeyword", text),
		attr: (text) => theme.fg("syntaxVariable", text),
		variable: (text) => theme.fg("syntaxVariable", text),
		params: (text) => theme.fg("syntaxVariable", text),
		operator: (text) => theme.fg("syntaxOperator", text),
		punctuation: (text) => theme.fg("syntaxPunctuation", text),
		emphasis: (text) => theme.italic(text),
		strong: (text) => theme.bold(text),
		link: (text) => theme.underline(text),
		addition: (text) => theme.fg("toolDiffAdded", text),
		deletion: (text) => theme.fg("toolDiffRemoved", text),
	};
}

function getCliHighlightTheme(theme: Theme): CliHighlightTheme {
	let cached = cachedThemes.get(theme);
	if (!cached) {
		cached = buildCliHighlightTheme(theme);
		cachedThemes.set(theme, cached);
	}
	return cached;
}

/** Highlight code without consulting the interactive theme singleton. */
export function highlightCode(code: string, theme: Theme, lang?: string): string[] {
	const validLang = lang && supportsLanguage(lang) ? lang : undefined;
	if (!validLang) return code.split("\n").map((line) => theme.fg("mdCodeBlock", line));

	try {
		return highlight(code, {
			language: validLang,
			ignoreIllegals: true,
			theme: getCliHighlightTheme(theme),
		}).split("\n");
	} catch {
		return code.split("\n").map((line) => theme.fg("mdCodeBlock", line));
	}
}

const EXTENSION_LANGUAGES: Record<string, string> = {
	ts: "typescript",
	tsx: "typescript",
	js: "javascript",
	jsx: "javascript",
	mjs: "javascript",
	cjs: "javascript",
	py: "python",
	rb: "ruby",
	rs: "rust",
	go: "go",
	java: "java",
	kt: "kotlin",
	swift: "swift",
	c: "c",
	h: "c",
	cpp: "cpp",
	cc: "cpp",
	cxx: "cpp",
	hpp: "cpp",
	cs: "csharp",
	php: "php",
	sh: "bash",
	bash: "bash",
	zsh: "bash",
	fish: "fish",
	ps1: "powershell",
	sql: "sql",
	html: "html",
	htm: "html",
	css: "css",
	scss: "scss",
	sass: "sass",
	less: "less",
	json: "json",
	yaml: "yaml",
	yml: "yaml",
	toml: "toml",
	xml: "xml",
	md: "markdown",
	markdown: "markdown",
	dockerfile: "dockerfile",
	makefile: "makefile",
	cmake: "cmake",
	lua: "lua",
	perl: "perl",
	r: "r",
	scala: "scala",
	clj: "clojure",
	ex: "elixir",
	exs: "elixir",
	erl: "erlang",
	hs: "haskell",
	ml: "ocaml",
	vim: "vim",
	graphql: "graphql",
	proto: "protobuf",
	tf: "hcl",
	hcl: "hcl",
};

export function getLanguageFromPath(filePath: string): string | undefined {
	const ext = filePath.split(".").pop()?.toLowerCase();
	return ext ? EXTENSION_LANGUAGES[ext] : undefined;
}

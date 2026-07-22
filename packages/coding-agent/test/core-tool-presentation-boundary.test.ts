import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createToolHtmlRenderer } from "../src/core/export-html/tool-renderer.ts";
import { headlessTheme } from "../src/core/extensions/headless-theme.ts";
import type { ToolDefinition } from "../src/core/extensions/types.ts";
import { createBashToolDefinition } from "../src/core/tools/bash.ts";
import { createReadToolDefinition } from "../src/core/tools/read.ts";
import { createWriteToolDefinition } from "../src/core/tools/write.ts";

const CORE_TOOL_FILES = ["bash", "edit", "find", "grep", "ls", "read", "write"];

function collectTypeScriptFiles(directory: string): string[] {
	return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
		const path = join(directory, entry.name);
		if (entry.isDirectory()) return collectTypeScriptFiles(path);
		return entry.isFile() && entry.name.endsWith(".ts") ? [path] : [];
	});
}

describe("core tool presentation boundary", () => {
	it("does not import interactive mode from built-in tool definitions", () => {
		for (const name of CORE_TOOL_FILES) {
			const source = readFileSync(join(import.meta.dirname, "../src/core/tools", `${name}.ts`), "utf8");
			expect(source, name).not.toContain("modes/interactive");
		}
	});

	it("keeps the complete core runtime independent from interactive mode", () => {
		const coreDirectory = join(import.meta.dirname, "../src/core");
		for (const filePath of collectTypeScriptFiles(coreDirectory)) {
			const source = readFileSync(filePath, "utf8");
			expect(source, filePath).not.toMatch(/from\s+["'][^"']*modes\/interactive/);
		}
	});

	it("renders built-in tools with an injected headless theme", () => {
		const cwd = process.cwd();
		const definitions = new Map<string, ToolDefinition>([
			["bash", createBashToolDefinition(cwd) as unknown as ToolDefinition],
			["read", createReadToolDefinition(cwd) as unknown as ToolDefinition],
			["write", createWriteToolDefinition(cwd) as unknown as ToolDefinition],
		]);
		const renderer = createToolHtmlRenderer({
			getToolDefinition: (name) => definitions.get(name),
			theme: headlessTheme,
			cwd,
		});

		expect(renderer.renderCall("bash-call", "bash", { command: "printf ok" })).toContain("$ printf ok");
		expect(
			renderer.renderResult("bash-call", "bash", [{ type: "text", text: "ok" }], undefined, false)?.expanded,
		).toContain("ok");

		expect(
			renderer.renderCall("write-call", "write", {
				path: "example.ts",
				content: "const answer = 42;",
			}),
		).toContain("const answer = 42;");

		renderer.renderCall("read-call", "read", { path: "example.ts" });
		expect(
			renderer.renderResult("read-call", "read", [{ type: "text", text: "const answer = 42;" }], undefined, false)
				?.expanded,
		).toContain("const answer = 42;");
	});
});

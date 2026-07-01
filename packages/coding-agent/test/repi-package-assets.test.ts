import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
	scripts: Record<string, string>;
};
const productCommandsSource = readFileSync(new URL("../src/cli/repi-product-commands.ts", import.meta.url), "utf8");
const scriptsRoot = fileURLToPath(new URL("../../../scripts/reverse-agent/", import.meta.url));

function productCommandScripts(): string[] {
	return [
		...new Set([...productCommandsSource.matchAll(/script:\s*"([^"]+\.mjs)"/g)].map((match) => match[1])),
	].sort();
}

describe("REPI packaged reverse-agent assets", () => {
	it("copy-assets includes every script reachable from product commands", () => {
		const copyAssets = packageJson.scripts["copy-assets"];
		for (const script of productCommandScripts()) {
			expect(copyAssets, `${script} must be copied into dist/reverse-agent`).toContain(
				`../../scripts/reverse-agent/${script}`,
			);
		}
	});

	it("copy-assets includes the reverse-agent lib directory when bundled scripts import ./lib helpers", () => {
		const copyAssets = packageJson.scripts["copy-assets"];
		const scriptsNeedingLib = productCommandScripts().filter((script) =>
			readFileSync(`${scriptsRoot}${script}`, "utf8").includes("./lib/"),
		);
		expect(scriptsNeedingLib.length).toBeGreaterThan(0);
		expect(copyAssets).toContain("dist/reverse-agent/lib");
		expect(copyAssets).toContain("../../scripts/reverse-agent/lib/*.mjs");
	});
});

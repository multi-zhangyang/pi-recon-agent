import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
	files: string[];
	scripts: Record<string, string>;
};
const productCommandsSource = readFileSync(new URL("../src/cli/repi-product-commands.ts", import.meta.url), "utf8");
const scriptsRoot = fileURLToPath(new URL("../../../scripts/reverse-agent/", import.meta.url));
const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const rootPackageJson = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as {
	scripts: Record<string, string>;
};
const releaseSmokeSource = readFileSync(join(repoRoot, "scripts/reverse-agent/repi-release-tarball-smoke.mjs"), "utf8");
const cleanProductionDistScript = join(repoRoot, "scripts/clean-production-dist.mjs");
const packedSourceClosureScript = join(repoRoot, "scripts/reverse-agent/lib/packed-source-closure.mjs");
const releaseManifestScript = join(repoRoot, "scripts/reverse-agent/repi-release-manifest.mjs");

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

	it("packages lifecycle wrappers alongside the product command scripts", () => {
		const copyAssets = packageJson.scripts["copy-assets"];
		for (const script of ["repi-bootstrap.mjs", "repi-commands.mjs", "repi-uninstall.mjs"]) {
			expect(copyAssets, `${script} must be available to the npm bin`).toContain(
				`../../scripts/reverse-agent/${script}`,
			);
			expect(readFileSync(`${scriptsRoot}${script}`, "utf8")).toContain("#!/usr/bin/env node");
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

	it("cleans production dist trees before root builds and release smoke rebuilds", () => {
		expect(rootPackageJson.scripts["clean:production-dist"]).toBe("node scripts/clean-production-dist.mjs .");
		expect(rootPackageJson.scripts.build).toMatch(/^npm run clean:production-dist && /);
		expect(releaseSmokeSource).toContain('run("clean:production-dist", process.execPath');
		expect(releaseSmokeSource).toContain("findPackedOutputsWithoutSources");
	});

	it("installs the four release tarballs with the documented global npm command", () => {
		expect(releaseSmokeSource).toContain("npm-install:four-tarballs-global");
		expect(releaseSmokeSource).toContain('"install", "--global", "--prefix"');
		expect(releaseSmokeSource).toContain("...tarballs.values()");
		expect(releaseSmokeSource).not.toContain("overrides: dependencies");
	});

	it("keeps development source maps out of every release tarball", () => {
		for (const directory of ["tui", "ai", "agent", "coding-agent"]) {
			const metadata = JSON.parse(readFileSync(join(repoRoot, "packages", directory, "package.json"), "utf8")) as {
				files: string[];
			};
			expect(metadata.files, `${directory} package files`).toContain("!dist/**/*.map");
		}
		expect(packageJson.files).toContain("!dist/**/*.map");
		expect(releaseSmokeSource).toContain("packed source map:");
	});

	it("writes a same-version release manifest with hashes and one install command", () => {
		const fixtureRoot = mkdtempSync(join(tmpdir(), "repi-release-manifest-test-"));
		try {
			const expectedPackages = ["ai", "agent", "tui", "coding-agent"].map((directory) => {
				const metadata = JSON.parse(
					readFileSync(join(repoRoot, "packages", directory, "package.json"), "utf8"),
				) as {
					name: string;
					version: string;
				};
				const filename = `${metadata.name.replace(/^@/, "").replaceAll("/", "-")}-${metadata.version}.tgz`;
				writeFileSync(join(fixtureRoot, filename), `fixture:${metadata.name}\n`);
				return { ...metadata, filename };
			});

			const result = spawnSync(process.execPath, [releaseManifestScript, repoRoot, fixtureRoot], {
				encoding: "utf8",
			});
			expect(result.status, result.stderr).toBe(0);
			const manifest = JSON.parse(readFileSync(join(fixtureRoot, "repi-release-manifest.json"), "utf8")) as {
				allTarballsRequired: boolean;
				install: { argv: string[] };
				packages: Array<{ filename: string; sha256: string }>;
			};
			expect(manifest.allTarballsRequired).toBe(true);
			expect(manifest.install.argv.slice(0, 3)).toEqual(["npm", "install", "-g"]);
			expect(manifest.install.argv.slice(3)).toEqual(expectedPackages.map((pkg) => `./${pkg.filename}`));
			expect(manifest.packages).toHaveLength(4);
			expect(manifest.packages.every((pkg) => /^[a-f0-9]{64}$/.test(pkg.sha256))).toBe(true);

			rmSync(join(fixtureRoot, expectedPackages.at(-1)!.filename));
			const incomplete = spawnSync(process.execPath, [releaseManifestScript, repoRoot, fixtureRoot], {
				encoding: "utf8",
			});
			expect(incomplete.status).toBe(1);
			expect(incomplete.stderr).toContain("missing release tarball");
		} finally {
			rmSync(fixtureRoot, { force: true, recursive: true });
		}
	});

	it("does not pack orphaned dist files after production cleanup", () => {
		const fixtureRoot = mkdtempSync(join(tmpdir(), "repi-clean-dist-test-"));
		try {
			for (const packageName of ["tui", "ai", "agent", "coding-agent"]) {
				const packageRoot = join(fixtureRoot, "packages", packageName);
				mkdirSync(join(packageRoot, "src"), { recursive: true });
				mkdirSync(join(packageRoot, "dist"), { recursive: true });
				writeFileSync(join(packageRoot, "src", "current.ts"), "export const current = true;\n");
				writeFileSync(join(packageRoot, "dist", "removed-source.js"), "export const stale = true;\n");
			}

			const clean = spawnSync(process.execPath, [cleanProductionDistScript, fixtureRoot], {
				encoding: "utf8",
			});
			expect(clean.status, clean.stderr).toBe(0);

			const codingAgentRoot = join(fixtureRoot, "packages", "coding-agent");
			expect(existsSync(join(codingAgentRoot, "src", "current.ts"))).toBe(true);
			expect(existsSync(join(codingAgentRoot, "dist", "removed-source.js"))).toBe(false);
			mkdirSync(join(codingAgentRoot, "dist"), { recursive: true });
			writeFileSync(join(codingAgentRoot, "dist", "current.js"), "export const current = true;\n");
			writeFileSync(
				join(codingAgentRoot, "package.json"),
				`${JSON.stringify({ name: "repi-clean-dist-fixture", version: "1.0.0", files: ["dist"] })}\n`,
			);

			const packed = spawnSync("npm", ["pack", "--dry-run", "--ignore-scripts", "--json"], {
				cwd: codingAgentRoot,
				encoding: "utf8",
			});
			expect(packed.status, packed.stderr).toBe(0);
			const manifest = JSON.parse(packed.stdout) as Array<{ files: Array<{ path: string }> }>;
			const paths = manifest[0]?.files.map((file) => file.path) ?? [];
			expect(paths).toContain("dist/current.js");
			expect(paths).not.toContain("dist/removed-source.js");

			const validClosure = spawnSync(process.execPath, [packedSourceClosureScript, codingAgentRoot], {
				encoding: "utf8",
				input: packed.stdout,
			});
			expect(validClosure.status, validClosure.stderr).toBe(0);

			writeFileSync(join(codingAgentRoot, "dist", "removed-source.js"), "export const stale = true;\n");
			const stalePack = spawnSync("npm", ["pack", "--dry-run", "--ignore-scripts", "--json"], {
				cwd: codingAgentRoot,
				encoding: "utf8",
			});
			expect(stalePack.status, stalePack.stderr).toBe(0);
			const invalidClosure = spawnSync(process.execPath, [packedSourceClosureScript, codingAgentRoot], {
				encoding: "utf8",
				input: stalePack.stdout,
			});
			expect(invalidClosure.status).toBe(1);
			expect(JSON.parse(invalidClosure.stdout)).toEqual({
				ok: false,
				staleOutputs: ["dist/removed-source.js"],
			});
		} finally {
			rmSync(fixtureRoot, { force: true, recursive: true });
		}
	});
});

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	findRepiProductCommand,
	isRepiPackageUninstallInvocation,
	isRepiProductCommand,
	normalizeRepiProductCommandArgs,
	REPI_PRODUCT_COMMANDS,
	resolveRepiProductScript,
} from "../src/cli/repi-product-commands.ts";

describe("REPI product command routing", () => {
	const originalRepoRoot = process.env.REPI_REPO_ROOT;

	afterEach(() => {
		vi.restoreAllMocks();
		if (originalRepoRoot === undefined) delete process.env.REPI_REPO_ROOT;
		else process.env.REPI_REPO_ROOT = originalRepoRoot;
	});

	it("keeps the packaged command set in sync with lifecycle wrappers", () => {
		expect(isRepiProductCommand("mcp")).toBe(true);
		expect(isRepiProductCommand("bootstrap")).toBe(true);
		expect(isRepiProductCommand("commands")).toBe(true);
		expect(isRepiProductCommand("uninstall")).toBe(true);
		expect(REPI_PRODUCT_COMMANDS.has("memory")).toBe(false);
	});

	it("routes uninstall sources back to the extension package manager", () => {
		expect(isRepiPackageUninstallInvocation(["npm:@scope/tool"])).toBe(true);
		expect(isRepiPackageUninstallInvocation(["--local", "./tool"])).toBe(true);
		expect(isRepiPackageUninstallInvocation(["--approve", "npm:tool"])).toBe(true);
		expect(isRepiPackageUninstallInvocation(["--help"])).toBe(false);
		expect(isRepiPackageUninstallInvocation(["--apply"])).toBe(false);
		expect(isRepiPackageUninstallInvocation(["--source", "/tmp/repi-checkout"])).toBe(false);
		expect(isRepiPackageUninstallInvocation(["--source=/tmp/repi-checkout"])).toBe(false);
	});

	it("finds product commands after launcher flags without consuming their subcommands", () => {
		expect(findRepiProductCommand(["--offline", "doctor", "--json"])).toEqual({ command: "doctor", index: 1 });
		expect(findRepiProductCommand(["--mode", "json", "swarm", "run", "target"])).toEqual({
			command: "swarm",
			index: 2,
		});
		expect(findRepiProductCommand(["--offline", "--list-models"])).toBeUndefined();
	});

	it("does not route prompt values as product commands", () => {
		expect(findRepiProductCommand(["-p", "doctor"])).toBeUndefined();
		expect(findRepiProductCommand(["--print", "engage"])).toBeUndefined();
		expect(findRepiProductCommand(["--message", "doctor"])).toBeUndefined();
		expect(findRepiProductCommand(["--model", "doctor", "-p", "status"])).toBeUndefined();
	});

	it("consumes short value flags before a real product command", () => {
		expect(findRepiProductCommand(["-p", "a prompt", "doctor"])).toBeUndefined();
		expect(findRepiProductCommand(["-n", "doctor", "health", "--json"])).toEqual({ command: "health", index: 2 });
		expect(findRepiProductCommand(["--unknown", "value", "swarm", "status"])).toEqual({ command: "swarm", index: 2 });
	});

	it("keeps nested subcommands ahead of launcher flags", () => {
		expect(normalizeRepiProductCommandArgs("swarm", ["--offline", "run", "target", "--workers", "1"])).toEqual([
			"run",
			"target",
			"--workers",
			"1",
			"--offline",
		]);
		expect(normalizeRepiProductCommandArgs("model", ["--mode", "json", "list"])).toEqual(["list", "--mode", "json"]);
		expect(normalizeRepiProductCommandArgs("swarm", ["--offline", "--help"])).toEqual(["--help", "--offline"]);
		expect(normalizeRepiProductCommandArgs("doctor", ["--offline", "target"])).toEqual(["--offline", "target"]);
	});

	it("does not resolve product scripts from a same-named cwd tree", () => {
		const hostileRoot = mkdtempSync(join(tmpdir(), "repi-product-cwd-"));
		try {
			const hostileScripts = join(hostileRoot, "scripts", "reverse-agent");
			mkdirSync(hostileScripts, { recursive: true });
			const hostileDoctor = join(hostileScripts, "repi-doctor.mjs");
			writeFileSync(hostileDoctor, "// hostile cwd script\n");
			delete process.env.REPI_REPO_ROOT;
			vi.spyOn(process, "cwd").mockReturnValue(hostileRoot);

			const resolved = resolveRepiProductScript("repi-doctor.mjs");
			expect(resolved?.scriptPath).toBeTruthy();
			expect(resolved?.scriptPath).not.toBe(hostileDoctor);
			expect(resolved?.scriptPath).toMatch(/scripts[\\/]reverse-agent[\\/]repi-doctor\.mjs$/);
		} finally {
			rmSync(hostileRoot, { recursive: true, force: true });
		}
	});

	it("honors an explicit REPI_REPO_ROOT source checkout", () => {
		const sourceRoot = mkdtempSync(join(tmpdir(), "repi-product-source-"));
		try {
			const sourceScripts = join(sourceRoot, "scripts", "reverse-agent");
			mkdirSync(sourceScripts, { recursive: true });
			const sourceDoctor = join(sourceScripts, "repi-doctor.mjs");
			writeFileSync(sourceDoctor, "// explicit source script\n");
			process.env.REPI_REPO_ROOT = sourceRoot;

			expect(resolveRepiProductScript("repi-doctor.mjs")).toEqual({
				scriptPath: sourceDoctor,
				commandRoot: sourceRoot,
			});
		} finally {
			rmSync(sourceRoot, { recursive: true, force: true });
		}
	});
});

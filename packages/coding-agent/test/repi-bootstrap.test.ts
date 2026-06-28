import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { bootstrapRepiCli } from "../src/cli/repi-bootstrap.ts";

const ENV_KEYS = [
	"REPI_CODING_AGENT_DIR",
	"REPI_CODING_AGENT_APP_NAME",
	"REPI_CODING_AGENT_CONFIG_DIR",
	"REPI_PRIMARY",
	"REPI_PRODUCT",
	"REPI_SKIP_VERSION_CHECK",
	"REPI_SKIP_PACKAGE_UPDATE_CHECK",
	"REPI_TELEMETRY",
	"REPI_OFFLINE",
	"PI_SKIP_VERSION_CHECK",
	"PI_SKIP_PACKAGE_UPDATE_CHECK",
	"PI_TELEMETRY",
	"REPI_IMPORT_PI_PROFILE",
	"REPI_IMPORT_PI_AUTH",
] as const;

describe("bootstrapRepiCli", () => {
	let previousEnv: Partial<Record<(typeof ENV_KEYS)[number], string>>;
	let agentDir: string;

	beforeEach(() => {
		previousEnv = {};
		for (const key of ENV_KEYS) {
			previousEnv[key] = process.env[key];
			delete process.env[key];
		}
		agentDir = mkdtempSync(join(tmpdir(), "repi-bootstrap-"));
		process.env.REPI_CODING_AGENT_DIR = agentDir;
	});

	afterEach(() => {
		rmSync(agentDir, { recursive: true, force: true });
		for (const key of ENV_KEYS) {
			const value = previousEnv[key];
			if (value === undefined) {
				delete process.env[key];
			} else {
				process.env[key] = value;
			}
		}
	});

	test("defaults to the REPI kernel without forcing clean-room trust overrides", () => {
		const args = bootstrapRepiCli(["--offline"]);

		expect(args).toEqual(["--recon", "--offline"]);
		expect(args).not.toContain("--no-approve");
		expect(args).not.toContain("--no-context-files");
		expect(args).not.toContain("--no-extensions");
		expect(args).not.toContain("--no-skills");
		expect(args).not.toContain("--no-prompt-templates");
	});

	test("keeps explicit clean-room mode available for one run", () => {
		const args = bootstrapRepiCli(["--clean-room", "--offline"]);

		expect(args).toEqual([
			"--recon",
			"--no-extensions",
			"--no-skills",
			"--no-prompt-templates",
			"--no-approve",
			"--no-context-files",
			"--offline",
		]);
	});

	test("does not rewrite package commands", () => {
		expect(bootstrapRepiCli(["list", "--offline"])).toEqual(["list", "--offline"]);
	});

	test("accepts legacy project context flags as no-op compatibility flags", () => {
		expect(bootstrapRepiCli(["--project-context", "--with-project-resources", "--offline"])).toEqual([
			"--recon",
			"--offline",
		]);
	});
});

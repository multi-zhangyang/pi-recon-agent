import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { bootstrapRepiCli, invalidRepiEnvModelApi, missingRepiEnvModelConfig } from "../src/cli/repi-bootstrap.ts";

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
	"REPI_PRINT_PROGRESS",
	"REPI_PRINT_TIMEOUT_MS",
	"REPI_PRINT_TIMEOUT_GRACE_MS",
	"REPI_PRINT_TIMEOUT_TOOL_GRACE_MS",
	"REPI_PRINT_MAX_TURNS",
	"REPI_PRINT_MAX_TOOL_CALLS",
	"REPI_STDIN_READ_TIMEOUT_MS",
	"REPI_BASH_DEFAULT_TIMEOUT_SECONDS",
	"REPI_CONTEXT_FILES",
	"REPI_ALLOW_BROWSER_COOKIES",
	"PI_SKIP_VERSION_CHECK",
	"PI_SKIP_PACKAGE_UPDATE_CHECK",
	"PI_TELEMETRY",
	"PI_OFFLINE",
	"PI_ALLOW_BROWSER_COOKIES",
	"REPI_IMPORT_PI_PROFILE",
	"REPI_IMPORT_PI_AUTH",
	"REPI_BASE_URL",
	"REPI_MODEL_BASE_URL",
	"REPI_MODEL",
	"REPI_MODEL_ID",
	"REPI_MODEL_API",
	"REPI_API",
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

	test("sets a bounded print budget with a reserved synthesis turn", () => {
		bootstrapRepiCli(["--offline"]);

		expect(process.env.REPI_PRINT_MAX_TURNS).toBe("10");
		expect(process.env.REPI_PRINT_MAX_TOOL_CALLS).toBe("48");
	});

	test("preserves explicit print budget overrides", () => {
		process.env.REPI_PRINT_MAX_TURNS = "7";
		process.env.REPI_PRINT_MAX_TOOL_CALLS = "19";

		bootstrapRepiCli(["--offline"]);

		expect(process.env.REPI_PRINT_MAX_TURNS).toBe("7");
		expect(process.env.REPI_PRINT_MAX_TOOL_CALLS).toBe("19");
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

	test("keeps product-command words inside print prompts", () => {
		expect(bootstrapRepiCli(["-p", "doctor"])).toEqual(["--recon", "-p", "doctor"]);
		expect(bootstrapRepiCli(["--print", "engage"])).toEqual(["--recon", "--print", "engage"]);
		expect(bootstrapRepiCli(["--message", "status"])).toEqual(["--recon", "--message", "status"]);
	});

	test("enables trusted project context only when explicitly requested", () => {
		expect(bootstrapRepiCli(["--project-context", "--with-project-resources", "--offline"])).toEqual([
			"--recon",
			"--offline",
		]);
		expect(process.env.REPI_CONTEXT_FILES).toBe("1");
	});

	test("detects incomplete REPI env-only model config before falling back to saved models", () => {
		expect(missingRepiEnvModelConfig({ REPI_MODEL: "vendor/model" })).toEqual(["REPI_BASE_URL"]);
		expect(missingRepiEnvModelConfig({ REPI_BASE_URL: "https://gateway.example/v1" })).toEqual(["REPI_MODEL"]);
		expect(
			missingRepiEnvModelConfig({ REPI_ENDPOINT: "https://gateway.example/v1", REPI_MODEL_ID: "vendor/model" }),
		).toEqual([]);
		expect(
			missingRepiEnvModelConfig({
				REPI_BASE_URL: "https://gateway.example/v1",
				REPI_MODEL: "vendor/model",
				REPI_MODEL_API: "openai-compatible",
			}),
		).toEqual([]);
		expect(missingRepiEnvModelConfig({})).toEqual([]);
	});

	test("detects invalid REPI_MODEL_API values instead of silently using the wrong wire format", () => {
		expect(invalidRepiEnvModelApi({ REPI_MODEL_API: "openai-compatible" })).toBeUndefined();
		expect(invalidRepiEnvModelApi({ REPI_MODEL_API: "response" })).toBeUndefined();
		expect(invalidRepiEnvModelApi({ REPI_MODEL_API: "anthropic" })).toBeUndefined();
		expect(invalidRepiEnvModelApi({ REPI_MODEL_API: "totally-custom-json" })).toBe("totally-custom-json");
		expect(invalidRepiEnvModelApi({ REPI_PROTOCOL: "openai-responses" })).toBeUndefined();
		expect(invalidRepiEnvModelApi({ REPI_MODEL_PROTOCOL: "totally-custom-json" })).toBe("totally-custom-json");
	});
});

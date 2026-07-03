import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const MODEL_INSPECT = fileURLToPath(new URL("../../../scripts/reverse-agent/model-inspect.mjs", import.meta.url));
const REPI_MODEL_ENV_NAMES = [
	"REPI_AUTH_TOKEN",
	"REPI_API_KEY",
	"REPI_MODEL_API_KEY",
	"REPI_BASE_URL",
	"REPI_MODEL_BASE_URL",
	"REPI_MODEL",
	"REPI_MODEL_ID",
	"REPI_MODEL_API",
	"REPI_API",
	"REPI_PROVIDER",
	"REPI_MODEL_PROVIDER",
	"REPI_PROVIDER_ID",
	"REPI_CONTEXT_WINDOW",
	"REPI_MODEL_CONTEXT_WINDOW",
	"REPI_MAX_TOKENS",
	"REPI_MODEL_MAX_TOKENS",
	"REPI_MAX_OUTPUT_TOKENS",
	"REPI_SUBAGENT_MODEL",
];

describe("repi model argument parsing", () => {
	let tempRoot: string;
	let agentDir: string;
	let workspace: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-model-args-"));
		agentDir = join(tempRoot, "agent");
		workspace = join(tempRoot, "workspace");
		mkdirSync(agentDir, { recursive: true });
		mkdirSync(workspace, { recursive: true });
		writeFileSync(
			join(agentDir, "models.json"),
			`${JSON.stringify(
				{
					providers: {
						alpha: {
							api: "openai-completions",
							baseUrl: "https://example.invalid/v1",
							apiKey: "$ALPHA_KEY",
							models: [{ id: "model-a", contextWindow: 8192, maxTokens: 1024, cost: {} }],
						},
					},
				},
				null,
				2,
			)}\n`,
		);
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	function run(args: string[], env: Record<string, string> = {}) {
		const cleanEnv = { ...process.env };
		for (const name of REPI_MODEL_ENV_NAMES) delete cleanEnv[name];
		const result = spawnSync(process.execPath, [MODEL_INSPECT, workspace, ...args, "--json"], {
			encoding: "utf8",
			env: { ...cleanEnv, REPI_CODING_AGENT_DIR: agentDir, ...env },
			timeout: 10_000,
		});
		return { result, json: JSON.parse(result.stdout) as Record<string, unknown> };
	}

	it("accepts provider/model as positionals for the default command", () => {
		const { result, json } = run(["default", "alpha", "model-a"]);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(json).toMatchObject({ ok: true, provider: "alpha", model: "model-a" });
		expect(JSON.parse(readFileSync(join(agentDir, "settings.json"), "utf8"))).toMatchObject({
			defaultProvider: "alpha",
			defaultModel: "model-a",
		});
	});

	it("accepts a positional model after a --provider flag", () => {
		const { result, json } = run(["default", "--provider", "alpha", "model-a"]);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(json).toMatchObject({ ok: true, provider: "alpha", model: "model-a" });
	});

	it("does not mistake flag values for missing positionals", () => {
		const { result, json } = run(["default", "--model", "model-a"]);
		expect(result.status).toBe(1);
		expect(json).toMatchObject({
			ok: false,
			error: "model default requires --provider <id> --model <id>",
		});
	});

	it("lists an environment-only model provider without leaking the base URL by default", () => {
		const { result, json } = run(["list"], {
			REPI_AUTH_TOKEN: "env-only-key",
			REPI_BASE_URL: "https://env-gateway.example.invalid/v1",
			REPI_MODEL: "env-main-model",
			REPI_MODEL_API: "anthropic",
			REPI_CONTEXT_WINDOW: "262144",
			REPI_SUBAGENT_MODEL: "env-worker-model",
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(json).toMatchObject({
			ok: true,
			baseUrlHidden: true,
		});
		const rows = json.rows as Array<Record<string, unknown>>;
		expect(rows).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					provider: "repi-env",
					model: "env-main-model",
					api: "anthropic-messages",
					contextWindow: 262144,
					auth: "$REPI_AUTH_TOKEN:set",
				}),
				expect.objectContaining({
					provider: "repi-env",
					model: "env-worker-model",
					api: "anthropic-messages",
				}),
			]),
		);
		const envRow = rows.find((row) => row.provider === "repi-env" && row.model === "env-main-model");
		expect(envRow?.baseUrl).toMatch(/^<redacted:url:/);
		expect(envRow?.baseUrl).not.toContain("env-gateway");
	});

	it("adds the Baseten Kimi K2.7 Code preset without leaking the key or URL by default", () => {
		const cleanEnv = { ...process.env };
		for (const name of REPI_MODEL_ENV_NAMES) delete cleanEnv[name];
		const result = spawnSync(
			process.execPath,
			[
				MODEL_INSPECT,
				workspace,
				"add",
				"--preset",
				"baseten-kimi-k2.7-code",
				"--api-key-stdin",
				"--set-default",
				"--json",
			],
			{
				encoding: "utf8",
				env: { ...cleanEnv, REPI_CODING_AGENT_DIR: agentDir },
				input: "baseten-test-key\n",
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			preset: string;
			provider: string;
			model: string;
			baseUrl: string;
			authWritten: boolean;
		};
		expect(report).toMatchObject({
			ok: true,
			preset: "baseten-kimi-k2.7-code",
			provider: "baseten-kimi",
			model: "moonshotai/Kimi-K2.7-Code",
			authWritten: true,
		});
		expect(report.baseUrl).toMatch(/^<redacted:url:/);
		expect(report.baseUrl).not.toContain("baseten");
		const models = JSON.parse(readFileSync(join(agentDir, "models.json"), "utf8")) as {
			providers: Record<
				string,
				{ baseUrl: string; api: string; apiKey: string; models: Array<{ id: string; contextWindow: number }> }
			>;
		};
		expect(models.providers["baseten-kimi"]).toMatchObject({
			baseUrl: "https://inference.baseten.co/v1",
			api: "openai-completions",
			apiKey: "$REPI_BASETEN_KIMI_API_KEY",
		});
		expect(models.providers["baseten-kimi"].models[0]).toMatchObject({
			id: "moonshotai/Kimi-K2.7-Code",
			contextWindow: 262144,
		});
		expect(JSON.parse(readFileSync(join(agentDir, "auth.json"), "utf8"))).toMatchObject({
			"baseten-kimi": { type: "api_key", key: "baseten-test-key" },
		});
		expect(JSON.parse(readFileSync(join(agentDir, "settings.json"), "utf8"))).toMatchObject({
			defaultProvider: "baseten-kimi",
			defaultModel: "moonshotai/Kimi-K2.7-Code",
		});
	});
});

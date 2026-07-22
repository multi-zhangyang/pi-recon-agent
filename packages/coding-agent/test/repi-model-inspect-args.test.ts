import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const MODEL_INSPECT = fileURLToPath(new URL("../../../scripts/reverse-agent/model-inspect.mjs", import.meta.url));
const REPI_LAUNCHER = fileURLToPath(new URL("../../../repi", import.meta.url));
const REPI_MODEL_ENV_NAMES = [
	"REPI_AUTH_TOKEN",
	"REPI_API_KEY",
	"REPI_MODEL_API_KEY",
	"REPI_TOKEN",
	"REPI_MODEL_TOKEN",
	"REPI_BASE_URL",
	"REPI_MODEL_BASE_URL",
	"REPI_API_BASE_URL",
	"REPI_ENDPOINT",
	"REPI_MODEL_ENDPOINT",
	"REPI_MODEL",
	"REPI_MODEL_ID",
	"REPI_MODEL_API",
	"REPI_API",
	"REPI_PROTOCOL",
	"REPI_MODEL_PROTOCOL",
	"REPI_PROVIDER",
	"REPI_MODEL_PROVIDER",
	"REPI_PROVIDER_ID",
	"REPI_PROVIDER_NAME",
	"REPI_MODEL_PROVIDER_NAME",
	"REPI_MODEL_NAME",
	"REPI_CONTEXT_WINDOW",
	"REPI_MODEL_CONTEXT_WINDOW",
	"REPI_AUTO_COMPACT_WINDOW",
	"REPI_MODEL_AUTO_COMPACT_WINDOW",
	"REPI_CONTEXT_LENGTH",
	"REPI_MODEL_CONTEXT_LENGTH",
	"REPI_MAX_TOKENS",
	"REPI_MODEL_MAX_TOKENS",
	"REPI_MAX_OUTPUT_TOKENS",
	"REPI_MODEL_MAX_OUTPUT_TOKENS",
	"REPI_OUTPUT_TOKEN_LIMIT",
	"REPI_SUBAGENT_MODEL",
	"REPI_SUBAGENT_MODEL_NAME",
	"REPI_MODEL_INPUT",
	"REPI_INPUT",
	"REPI_MODEL_INPUT_MODALITIES",
	"REPI_INPUT_MODALITIES",
	"REPI_MODEL_REASONING",
	"REPI_REASONING",
	"REPI_HEADERS",
	"REPI_PROVIDER_HEADERS",
	"REPI_MODEL_HEADERS",
	"REPI_COMPAT",
	"REPI_MODEL_COMPAT",
	"REPI_MODEL_THINKING_LEVEL_MAP",
	"REPI_THINKING_LEVEL_MAP",
	"REPI_AUTH_HEADER",
	"REPI_MODEL_AUTH_HEADER",
	"REPI_MODEL_COST_INPUT",
	"REPI_COST_INPUT",
	"REPI_MODEL_INPUT_PRICE",
	"REPI_INPUT_PRICE",
	"REPI_MODEL_COST_OUTPUT",
	"REPI_COST_OUTPUT",
	"REPI_MODEL_OUTPUT_PRICE",
	"REPI_OUTPUT_PRICE",
	"REPI_MODEL_COST_CACHE_READ",
	"REPI_COST_CACHE_READ",
	"REPI_MODEL_CACHE_READ_PRICE",
	"REPI_CACHE_READ_PRICE",
	"REPI_MODEL_COST_CACHE_WRITE",
	"REPI_COST_CACHE_WRITE",
	"REPI_MODEL_CACHE_WRITE_PRICE",
	"REPI_CACHE_WRITE_PRICE",
	"REPI_MODEL_COST_TIERS",
	"REPI_COST_TIERS",
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
							models: [
								{
									id: "model-a",
									contextWindow: 8192,
									maxTokens: 1024,
									cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
								},
							],
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

	function runCliList(env: Record<string, string> = {}) {
		const cleanEnv = { ...process.env };
		for (const name of REPI_MODEL_ENV_NAMES) delete cleanEnv[name];
		return spawnSync(process.execPath, [MODEL_INSPECT, workspace, "list", "--cli-format"], {
			encoding: "utf8",
			env: { ...cleanEnv, REPI_CODING_AGENT_DIR: agentDir, ...env },
			timeout: 10_000,
		});
	}

	function runText(args: string[], env: Record<string, string> = {}) {
		const cleanEnv = { ...process.env };
		for (const name of REPI_MODEL_ENV_NAMES) delete cleanEnv[name];
		return spawnSync(process.execPath, [MODEL_INSPECT, workspace, ...args], {
			encoding: "utf8",
			env: { ...cleanEnv, REPI_CODING_AGENT_DIR: agentDir, ...env },
			timeout: 10_000,
		});
	}

	it("prints the lightweight CLI table only for models with configured auth", () => {
		const unavailable = runCliList();
		expect(unavailable.status, `${unavailable.stderr}\n${unavailable.stdout}`).toBe(0);
		expect(unavailable.stdout).toContain("No models available");
		expect(unavailable.stdout).not.toContain("\nalpha  ");

		writeFileSync(
			join(agentDir, "auth.json"),
			`${JSON.stringify({ alpha: { type: "api_key", key: "saved-key" } }, null, 2)}\n`,
		);
		const available = runCliList();
		expect(available.status, `${available.stderr}\n${available.stdout}`).toBe(0);
		expect(available.stdout).toContain("provider  model");
		expect(available.stdout).toContain("alpha     model-a");
		expect(available.stdout).toContain("8.2K");
	});

	it("prints the authenticated env-only model in the lightweight CLI table", () => {
		const result = runCliList({
			REPI_AUTH_TOKEN: "env-only-key",
			REPI_BASE_URL: "https://env-gateway.example.invalid/v1",
			REPI_MODEL: "env-main-model",
			REPI_CONTEXT_WINDOW: "262144",
			REPI_MODEL_INPUT: "text,image",
			REPI_MODEL_REASONING: "true",
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(result.stdout).toContain("repi-env  env-main-model  262.1K");
		expect(result.stdout).toContain("yes       yes");
		expect(result.stdout).not.toContain("env-gateway");
	});

	it("keeps top-level list-model search patterns on the fuzzy CLI path", () => {
		writeFileSync(
			join(agentDir, "auth.json"),
			`${JSON.stringify({ alpha: { type: "api_key", key: "saved-key" } }, null, 2)}\n`,
		);
		const cleanEnv = { ...process.env };
		for (const name of REPI_MODEL_ENV_NAMES) delete cleanEnv[name];
		const result = spawnSync(REPI_LAUNCHER, ["--offline", "--list-models", "model-a"], {
			encoding: "utf8",
			env: { ...cleanEnv, REPI_CODING_AGENT_DIR: agentDir, REPI_USE_SOURCE: "1" },
			timeout: 10_000,
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(result.stdout).toContain("alpha     model-a");
	});

	it("rejects an invalid env model API before the lightweight launcher path", () => {
		const cleanEnv = { ...process.env };
		for (const name of REPI_MODEL_ENV_NAMES) delete cleanEnv[name];
		const result = spawnSync(REPI_LAUNCHER, ["--offline", "--list-models"], {
			encoding: "utf8",
			env: {
				...cleanEnv,
				REPI_CODING_AGENT_DIR: agentDir,
				REPI_AUTH_TOKEN: "env-only-key",
				REPI_BASE_URL: "https://env-gateway.example.invalid/v1",
				REPI_MODEL: "env-main-model",
				REPI_MODEL_API: "unsupported-wire-format",
			},
			timeout: 10_000,
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(2);
		expect(result.stderr).toContain("REPI env model config is incomplete or invalid");
		expect(result.stderr).toContain('invalid: REPI_MODEL_API="unsupported-wire-format"');
	});

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

	it("reports the effective REPI env-only model status without leaking the base URL", () => {
		const { result, json } = run(["status"], {
			REPI_AUTH_TOKEN: "env-only-key",
			REPI_BASE_URL: "https://status-gateway.example.invalid/v1",
			REPI_PROVIDER: "status-env",
			REPI_MODEL: "status-main-model",
			REPI_MODEL_API: "openai-responses",
			REPI_AUTO_COMPACT_WINDOW: "131072",
			REPI_MAX_TOKENS: "12000",
			REPI_SUBAGENT_MODEL: "status-worker-model",
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(json).toMatchObject({
			ok: true,
			env: {
				enabled: true,
				provider: "status-env",
				model: "status-main-model",
				api: "openai-responses",
				authEnv: "REPI_AUTH_TOKEN",
				authPresent: true,
				contextWindow: 131072,
				autoCompactWindow: 131072,
				maxTokens: 12000,
				subagentModel: "status-worker-model",
			},
			effective: {
				source: "REPI_* environment",
				provider: "status-env",
				model: "status-main-model",
				api: "openai-responses",
				contextWindow: 131072,
				maxTokens: 12000,
			},
		});
		expect((json.env as Record<string, unknown>).baseUrl).toMatch(/^<redacted:url:/);
		expect((json.env as Record<string, unknown>).baseUrl).not.toContain("status-gateway");
	});

	it("reports all four env pricing rates and tiers consistently", () => {
		const tiers = JSON.stringify([
			{ inputTokensAbove: 1000, input: 0.2, output: 1.2, cacheRead: 0.02, cacheWrite: 0.25 },
			{ inputTokensAbove: 10000, input: 0.1, output: 0.8, cacheRead: 0.01, cacheWrite: 0.15 },
		]);
		const env = {
			REPI_AUTH_TOKEN: "env-only-key",
			REPI_BASE_URL: "https://pricing-gateway.example.invalid/v1",
			REPI_MODEL: "pricing-model",
			REPI_MODEL_COST_INPUT: "0.25",
			REPI_MODEL_COST_OUTPUT: "1.5",
			REPI_MODEL_COST_CACHE_READ: "0.025",
			REPI_MODEL_COST_CACHE_WRITE: "0.3",
			REPI_MODEL_COST_TIERS: tiers,
		};
		const status = run(["status"], env);
		expect(status.result.status, `${status.result.stderr}\n${status.result.stdout}`).toBe(0);
		expect(status.json).toMatchObject({
			env: {
				cost: {
					input: 0.25,
					output: 1.5,
					cacheRead: 0.025,
					cacheWrite: 0.3,
					tiers: JSON.parse(tiers),
				},
			},
			effective: { cost: { input: 0.25, output: 1.5, cacheRead: 0.025, cacheWrite: 0.3 } },
		});

		const list = run(["list"], env);
		expect(list.result.status, `${list.result.stderr}\n${list.result.stdout}`).toBe(0);
		const row = (list.json.rows as Array<Record<string, unknown>>).find(
			(candidate) => candidate.model === "pricing-model",
		);
		expect(row?.cost).toEqual({
			input: 0.25,
			output: 1.5,
			cacheRead: 0.025,
			cacheWrite: 0.3,
			tiers: JSON.parse(tiers),
		});

		const cli = runCliList(env);
		expect(cli.status, `${cli.stderr}\n${cli.stdout}`).toBe(0);
		expect(cli.stdout).toContain("0.25/1.5/0.025/0.3+2t");

		const statusText = runText(["status"], env);
		expect(statusText.status, `${statusText.stderr}\n${statusText.stdout}`).toBe(0);
		expect(statusText.stdout).toContain(
			"effective.cost=input:0.25/output:1.5/cacheRead:0.025/cacheWrite:0.3/tiers:2",
		);
		const listText = runText(["list"], env);
		expect(listText.status, `${listText.stderr}\n${listText.stdout}`).toBe(0);
		expect(listText.stdout).toContain("cost=input:0.25/output:1.5/cacheRead:0.025/cacheWrite:0.3/tiers:2");

		writeFileSync(join(agentDir, "settings.json"), "{}\n");
		const doctor = run(["doctor"], env);
		expect(doctor.result.status, `${doctor.result.stderr}\n${doctor.result.stdout}`).toBe(0);
		const provider = (doctor.json.providers as Array<{ id: string; models: Array<{ cost: unknown }> }>).find(
			(candidate) => candidate.id === "repi-env",
		);
		expect(provider?.models[0]?.cost).toEqual({
			input: 0.25,
			output: 1.5,
			cacheRead: 0.025,
			cacheWrite: 0.3,
			tiers: JSON.parse(tiers),
		});
		const doctorText = runText(["doctor"], env);
		expect(doctorText.status, `${doctorText.stderr}\n${doctorText.stdout}`).toBe(0);
		expect(doctorText.stdout).toContain("cost=input:0.25/output:1.5/cacheRead:0.025/cacheWrite:0.3/tiers:2");
	});

	it("reports rich env metadata without exposing header values", () => {
		const env = {
			REPI_TOKEN: "alternate-token",
			REPI_ENDPOINT: "https://metadata-gateway.example.invalid/v1",
			REPI_MODEL: "metadata-model",
			REPI_PROTOCOL: "openai-compatible",
			REPI_CONTEXT_LENGTH: "200000",
			REPI_MODEL_MAX_OUTPUT_TOKENS: "24000",
			REPI_MODEL_INPUT_MODALITIES: '["text","image"]',
			REPI_MODEL_REASONING: "true",
			REPI_HEADERS: '{"X-Tenant":"sensitive-tenant-value"}',
			REPI_MODEL_HEADERS: '{"X-Route":"sensitive-route-value"}',
			REPI_COMPAT: '{"supportsDeveloperRole":false}',
			REPI_MODEL_COMPAT: '{"supportsUsageInStreaming":false}',
			REPI_MODEL_THINKING_LEVEL_MAP: '{"high":"max","xhigh":null}',
			REPI_AUTH_HEADER: "yes",
		};
		const status = run(["status"], env);
		expect(status.result.status, `${status.result.stderr}\n${status.result.stdout}`).toBe(0);
		expect(status.json).toMatchObject({
			env: {
				authEnv: "REPI_TOKEN",
				authPresent: true,
				contextWindow: 200000,
				maxTokens: 24000,
				input: ["text", "image"],
				reasoning: true,
				authHeader: true,
				headers: { provider: ["X-Tenant"], model: ["X-Route"] },
				compatConfigured: { provider: true, model: true },
				thinkingLevelMapConfigured: true,
			},
		});
		expect(status.result.stdout).not.toContain("sensitive-tenant-value");
		expect(status.result.stdout).not.toContain("sensitive-route-value");

		const list = run(["list"], env);
		expect(list.result.status, `${list.result.stderr}\n${list.result.stdout}`).toBe(0);
		const row = (list.json.rows as Array<Record<string, unknown>>).find(
			(candidate) => candidate.model === "metadata-model",
		);
		expect(row).toMatchObject({
			api: "openai-completions",
			contextWindow: 200000,
			maxTokens: 24000,
			input: ["text", "image"],
			reasoning: true,
		});
	});

	it("rejects malformed rich env metadata and numeric fields", () => {
		for (const [name, value, expected] of [
			["REPI_HEADERS", '{"X-Bad":1}', "invalid REPI_HEADERS.X-Bad"],
			["REPI_MODEL_COMPAT", "[]", "invalid REPI_MODEL_COMPAT"],
			["REPI_MODEL_THINKING_LEVEL_MAP", '{"ultra":"max"}', "unknown thinking level"],
			["REPI_MODEL_REASONING", "sometimes", "invalid REPI_MODEL_REASONING"],
			["REPI_CONTEXT_WINDOW", "not-a-number", "invalid REPI_CONTEXT_WINDOW"],
			["REPI_MODEL_COST_INPUT", "free", "invalid REPI_MODEL_COST_INPUT"],
		] as const) {
			const status = run(["status"], {
				REPI_AUTH_TOKEN: "env-only-key",
				REPI_BASE_URL: "https://metadata-gateway.example.invalid/v1",
				REPI_MODEL: "metadata-model",
				[name]: value,
			});
			expect(status.result.status, `${name}: ${status.result.stderr}\n${status.result.stdout}`).toBe(1);
			expect(JSON.stringify(status.json)).toContain(expected);
		}
	});

	it("uses the highest matching env pricing tier for model cost estimates", () => {
		const env = {
			REPI_AUTH_TOKEN: "env-only-key",
			REPI_BASE_URL: "https://pricing-gateway.example.invalid/v1",
			REPI_MODEL: "pricing-model",
			REPI_MODEL_COST_INPUT: "1",
			REPI_MODEL_COST_OUTPUT: "2",
			REPI_MODEL_COST_CACHE_READ: "3",
			REPI_MODEL_COST_CACHE_WRITE: "4",
			REPI_COST_TIERS: JSON.stringify([
				{ inputTokensAbove: 1000, input: 10, output: 20, cacheRead: 30, cacheWrite: 40 },
			]),
		};
		const { result, json } = run(
			["cost", "--model", "pricing-model", "--input-tokens", "1001", "--output-tokens", "2"],
			env,
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(json).toMatchObject({
			baseRates: { input: 1, output: 2, cacheRead: 3, cacheWrite: 4 },
			rates: { input: 10, output: 20, cacheRead: 30, cacheWrite: 40 },
			selectedTier: { inputTokensAbove: 1000 },
			estimatedUsd: (1001 * 10 + 2 * 20) / 1_000_000,
		});
	});

	it("fails status and list when pricing tiers are malformed", () => {
		const env = {
			REPI_AUTH_TOKEN: "env-only-key",
			REPI_BASE_URL: "https://pricing-gateway.example.invalid/v1",
			REPI_MODEL: "pricing-model",
			REPI_MODEL_COST_TIERS: "not-json",
		};
		const status = run(["status"], env);
		expect(status.result.status).toBe(1);
		expect(status.json).toMatchObject({
			ok: false,
			env: { costError: "invalid REPI_MODEL_COST_TIERS: expected a JSON array" },
		});
		const list = run(["list"], env);
		expect(list.result.status).toBe(1);
		expect(list.json.error).toContain("invalid REPI_MODEL_COST_TIERS");
	});

	it("warns when REPI_BASE_URL shape does not match the selected SDK wire format", () => {
		const openai = run(["status"], {
			REPI_AUTH_TOKEN: "env-only-key",
			REPI_BASE_URL: "https://status-gateway.example.invalid",
			REPI_MODEL: "status-main-model",
			REPI_MODEL_API: "openai-compatible",
		});
		expect(openai.result.status, `${openai.result.stderr}\n${openai.result.stdout}`).toBe(0);
		expect(JSON.stringify(openai.json.diagnostics)).toContain("usually ends with /v1");

		const anthropic = run(["status"], {
			REPI_AUTH_TOKEN: "env-only-key",
			REPI_BASE_URL: "https://status-gateway.example.invalid/v1",
			REPI_MODEL: "status-main-model",
			REPI_MODEL_API: "anthropic",
		});
		expect(anthropic.result.status, `${anthropic.result.stderr}\n${anthropic.result.stdout}`).toBe(0);
		expect(JSON.stringify(anthropic.json.diagnostics)).toContain("usually omits /v1");
	});

	it("fails model status on invalid REPI_MODEL_API instead of silently selecting chat completions", () => {
		const { result, json } = run(["status"], {
			REPI_AUTH_TOKEN: "env-only-key",
			REPI_BASE_URL: "https://status-gateway.example.invalid/v1",
			REPI_MODEL: "status-main-model",
			REPI_MODEL_API: "custom-wire-format",
		});
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(1);
		expect(json).toMatchObject({
			ok: false,
			env: {
				enabled: true,
				model: "status-main-model",
				rawApi: "custom-wire-format",
				invalidApi: "custom-wire-format",
			},
		});
		expect(JSON.stringify(json.diagnostics)).toContain("env-model-api");
		expect(JSON.stringify(json.diagnostics)).toContain("REPI_MODEL_API is invalid");
	});

	it("rejects removed provider presets and requires explicit model configuration", () => {
		const cleanEnv = { ...process.env };
		for (const name of REPI_MODEL_ENV_NAMES) delete cleanEnv[name];
		const result = spawnSync(
			process.execPath,
			[MODEL_INSPECT, workspace, "add", "--preset", "baseten-kimi-k2.7-code", "--json"],
			{
				encoding: "utf8",
				env: { ...cleanEnv, REPI_CODING_AGENT_DIR: agentDir },
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(1);
		const report = JSON.parse(result.stdout) as { ok: boolean; error: string };
		expect(report.ok).toBe(false);
		expect(report.error).toContain("provider presets have been removed");
		expect(report.error).toContain("--provider --api --base-url --model");
	});

	it("resets saved model profile while preserving auth by default", () => {
		writeFileSync(
			join(agentDir, "settings.json"),
			`${JSON.stringify(
				{
					defaultProvider: "alpha",
					defaultModel: "model-a",
					defaultThinkingLevel: "high",
					enabledModels: ["alpha/model-a"],
					ui: { density: "compact" },
				},
				null,
				2,
			)}\n`,
		);
		writeFileSync(
			join(agentDir, "auth.json"),
			`${JSON.stringify({ alpha: { type: "api_key", key: "secret" } }, null, 2)}\n`,
		);

		const missingConfirm = run(["reset"]);
		expect(missingConfirm.result.status).toBe(1);
		expect(missingConfirm.json).toMatchObject({ ok: false });
		expect(String(missingConfirm.json.error)).toContain("requires --yes");

		const { result, json } = run(["reset", "--yes"]);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		expect(json).toMatchObject({
			ok: true,
			preservedAuth: true,
			before: { providerCount: 1, modelCount: 1 },
			after: { providerCount: 0, modelCount: 0 },
		});
		expect(JSON.parse(readFileSync(join(agentDir, "models.json"), "utf8"))).toEqual({ providers: {} });
		expect(JSON.parse(readFileSync(join(agentDir, "auth.json"), "utf8"))).toMatchObject({
			alpha: { type: "api_key", key: "secret" },
		});
		const settings = JSON.parse(readFileSync(join(agentDir, "settings.json"), "utf8")) as Record<string, unknown>;
		expect(settings.defaultProvider).toBeUndefined();
		expect(settings.defaultModel).toBeUndefined();
		expect(settings.defaultThinkingLevel).toBeUndefined();
		expect(settings.enabledModels).toBeUndefined();
		expect(settings.ui).toEqual({ density: "compact" });
	});

	it("adds an explicit provider without leaking the key or URL by default", () => {
		const cleanEnv = { ...process.env };
		for (const name of REPI_MODEL_ENV_NAMES) delete cleanEnv[name];
		const result = spawnSync(
			process.execPath,
			[
				MODEL_INSPECT,
				workspace,
				"add",
				"--provider",
				"explicit-gateway",
				"--api",
				"openai-completions",
				"--base-url",
				"https://gateway.example.invalid/v1",
				"--model",
				"vendor/model",
				"--api-key-stdin",
				"--set-default",
				"--json",
			],
			{
				encoding: "utf8",
				env: { ...cleanEnv, REPI_CODING_AGENT_DIR: agentDir },
				input: "explicit-test-key\n",
				timeout: 10_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			ok: boolean;
			preset: null;
			provider: string;
			model: string;
			baseUrl: string;
			authWritten: boolean;
		};
		expect(report).toMatchObject({
			ok: true,
			preset: null,
			provider: "explicit-gateway",
			model: "vendor/model",
			authWritten: true,
		});
		expect(report.baseUrl).toMatch(/^<redacted:url:/);
		expect(report.baseUrl).not.toContain("gateway.example");
		const models = JSON.parse(readFileSync(join(agentDir, "models.json"), "utf8")) as {
			providers: Record<
				string,
				{ baseUrl: string; api: string; apiKey: string; models: Array<{ id: string; contextWindow: number }> }
			>;
		};
		expect(models.providers["explicit-gateway"]).toMatchObject({
			baseUrl: "https://gateway.example.invalid/v1",
			api: "openai-completions",
			apiKey: "$REPI_EXPLICIT_GATEWAY_API_KEY",
		});
		expect(models.providers["explicit-gateway"].models[0]).toMatchObject({
			id: "vendor/model",
			contextWindow: 262144,
		});
		expect(JSON.parse(readFileSync(join(agentDir, "auth.json"), "utf8"))).toMatchObject({
			"explicit-gateway": { type: "api_key", key: "explicit-test-key" },
		});
		expect(JSON.parse(readFileSync(join(agentDir, "settings.json"), "utf8"))).toMatchObject({
			defaultProvider: "explicit-gateway",
			defaultModel: "vendor/model",
		});
	});
});

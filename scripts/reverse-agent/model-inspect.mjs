#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { safeWriteReport } from "./lib/report-write-helpers.mjs";

const rawArgs = process.argv.slice(2);
const knownCommands = new Set([
	"doctor",
	"status",
	"list",
	"cost",
	"add",
	"edit",
	"remove",
	"login",
	"test",
	"default",
	"reset",
	"export",
	"import",
	"help",
]);
let root = process.cwd();
if (rawArgs[0] && !rawArgs[0].startsWith("--") && !knownCommands.has(rawArgs[0])) {
	root = resolve(rawArgs.shift());
}
const helpRequested = rawArgs.includes("--help") || rawArgs.includes("-h");
const command = helpRequested ? "help" : rawArgs[0] && !rawArgs[0].startsWith("--") ? rawArgs.shift() : "doctor";
const json = rawArgs.includes("--json");
const fix = rawArgs.includes("--fix");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const modelsPath = join(agentDir, "models.json");
const authPath = join(agentDir, "auth.json");
const settingsPath = join(agentDir, "settings.json");
const allowedApis = new Set(["openai-completions", "openai-responses", "anthropic-messages"]);
const envModelApiAliases = new Set([
	"openai-compatible",
	"openai-chat",
	"chat",
	"chat-completions",
	"openai-completions",
	"response",
	"responses",
	"openai-response",
	"openai-responses",
	"anthropic",
	"claude",
	"anthropic-compatible",
	"anthropic-messages",
]);
const envBaseUrlNames = [
	"REPI_BASE_URL",
	"REPI_MODEL_BASE_URL",
	"REPI_API_BASE_URL",
	"REPI_ENDPOINT",
	"REPI_MODEL_ENDPOINT",
];
const envApiNames = ["REPI_MODEL_API", "REPI_API", "REPI_PROTOCOL", "REPI_MODEL_PROTOCOL"];
const envAuthNames = ["REPI_AUTH_TOKEN", "REPI_API_KEY", "REPI_MODEL_API_KEY", "REPI_TOKEN", "REPI_MODEL_TOKEN"];
const envContextNames = [
	"REPI_CONTEXT_WINDOW",
	"REPI_MODEL_CONTEXT_WINDOW",
	"REPI_AUTO_COMPACT_WINDOW",
	"REPI_MODEL_AUTO_COMPACT_WINDOW",
	"REPI_CONTEXT_LENGTH",
	"REPI_MODEL_CONTEXT_LENGTH",
];
const envMaxTokensNames = [
	"REPI_MAX_TOKENS",
	"REPI_MODEL_MAX_TOKENS",
	"REPI_MAX_OUTPUT_TOKENS",
	"REPI_MODEL_MAX_OUTPUT_TOKENS",
	"REPI_OUTPUT_TOKEN_LIMIT",
];
const envInputNames = ["REPI_MODEL_INPUT", "REPI_INPUT", "REPI_MODEL_INPUT_MODALITIES", "REPI_INPUT_MODALITIES"];

function usage() {
	return `Usage:
  repi model doctor [--fix] [--json]
  repi model status [--show-urls] [--json]
  repi model list [--provider <id>] [--model <id>] [--show-urls] [--json]
  repi model add --provider <id> --api <openai-completions|openai-responses|anthropic-messages> --base-url <url> --model <id> [--api-key-stdin] [--set-default] [options]
  repi model edit --provider <id> [--model <id>] [options]
  repi model remove --provider <id> [--model <id>] [--json]
  repi model login --provider <id> --api-key-stdin
  repi model default --provider <id> --model <id>
  repi model reset --yes [--delete-auth] [--json]
  repi model test --provider <id> --model <id> [--timeout-ms N]
  repi model cost --provider <id> --model <id> --input-tokens N --output-tokens N [--cache-read-tokens N] [--cache-write-tokens N]
  repi model export [--output <path>] [--json]
  repi model import --input <path|-> [--merge|--replace] [--json] [--stdin-timeout-ms N] [--stdin-max-bytes N]

Environment-only model setup is the recommended default path (Claude Code style, REPI-specific names):
  export REPI_AUTH_TOKEN=sk-...
  export REPI_BASE_URL=https://gateway.example/v1
  export REPI_PROVIDER=gateway                  # optional; footer/provider id
  export REPI_MODEL=vendor/model
  export REPI_MODEL_API=openai-compatible   # aliases: openai-completions, openai-responses, response, anthropic
  export REPI_CONTEXT_WINDOW=262144
  export REPI_AUTO_COMPACT_WINDOW=262144    # alias of REPI_CONTEXT_WINDOW
  export REPI_MAX_TOKENS=16384
  export REPI_MODEL_INPUT=text,image         # comma-separated: text,image
  export REPI_MODEL_REASONING=true
  export REPI_HEADERS='{"X-Tenant":"$TENANT_ID"}'
  export REPI_MODEL_HEADERS='{"X-Model-Route":"code"}'
  export REPI_COMPAT='{"supportsDeveloperRole":false}'
  export REPI_MODEL_THINKING_LEVEL_MAP='{"high":"high","xhigh":null}'
  export REPI_AUTH_HEADER=false
  export REPI_MODEL_COST_INPUT=0.25          # USD per 1M input tokens
  export REPI_MODEL_COST_OUTPUT=1.50         # USD per 1M output tokens
  export REPI_MODEL_COST_CACHE_READ=0.025    # USD per 1M cache-read tokens
  export REPI_MODEL_COST_CACHE_WRITE=0.30    # USD per 1M cache-write tokens
  export REPI_MODEL_COST_TIERS='[{"inputTokensAbove":128000,"input":0.20,"output":1.20,"cacheRead":0.02,"cacheWrite":0.25}]'
  export REPI_SUBAGENT_MODEL=vendor/subagent-model
  repi --approve -p "..."

model status shows the effective REPI_* env-only provider, base URL redaction state, API style, model id, context window, max tokens, and shell-quote/config mistakes without making a network call.
Pricing is in USD per 1M tokens. The four REPI_MODEL_COST_* variables also accept REPI_COST_*, REPI_MODEL_*_PRICE, and REPI_*_PRICE aliases; REPI_MODEL_COST_TIERS also accepts REPI_COST_TIERS and uses JSON objects with inputTokensAbove/input/output/cacheRead/cacheWrite.
REPI_HEADERS/REPI_MODEL_HEADERS, REPI_COMPAT/REPI_MODEL_COMPAT, and REPI_MODEL_THINKING_LEVEL_MAP accept JSON. Status reports header names and configuration flags without printing header values.
Base URL note: OpenAI-compatible/Responses SDKs usually expect REPI_BASE_URL=https://host/v1; Anthropic-compatible SDKs usually expect REPI_BASE_URL=https://host because the SDK appends /v1/messages.
model doctor is offline: it parses ~/.repi/agent/models.json plus REPI_* env-only providers, checks provider/model metadata, local auth, context window and cost fields; --fix repairs safe local config issues but does not auto-pick a settings default provider/model.
model list hides provider base URLs by default to avoid leaking private gateway endpoints into screenshots/logs; add --show-urls for local troubleshooting.
model add writes ~/.repi/agent/models.json and can store a local credential immediately with --api-key-stdin; model login writes/updates ~/.repi/agent/auth.json locally. Provider presets are intentionally not shipped; use REPI_* env or explicit --provider/--base-url/--model values.
model reset clears saved model/provider/default selection pollution from ~/.repi/agent while preserving auth.json by default. Add --delete-auth only when you intentionally want to wipe stored credentials too.
For shell-history safety, pass API keys through --api-key-stdin. Plain --api-key is rejected unless REPI_ALLOW_INSECURE_API_KEY_ARG=1.
model export never exports local API keys; model import preserves/creates env-ref apiKey fields and never writes auth.json.
`;
}

function readJson(path) {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch (error) {
		return { __error: error instanceof Error ? error.message : String(error) };
	}
}

function readJsonObject(path, fallback = {}) {
	if (!existsSync(path)) return fallback;
	const parsed = readJson(path);
	if (parsed?.__error) throw new Error(`${path}: ${parsed.__error}`);
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${path}: expected JSON object`);
	return parsed;
}

function writeJsonFile(path, data, mode = 0o600) {
	// opt #177: route through safeWriteReport so an ENOSPC/EACCES mid-write
	// (models.json / auth.json / settings.json / export output) is an
	// observable stderr diagnostic + non-zero exit instead of a bare uncaught
	// throw that aborts the model-inspect output with no partial result.
	const written = safeWriteReport(path, `${JSON.stringify(data, null, 2)}\n`, { mode });
	if (written) {
		try {
			chmodSync(path, mode);
		} catch {
			// Best-effort on non-POSIX filesystems.
		}
	}
}

function flagValue(args, names, fallback = "") {
	const list = Array.isArray(names) ? names : [names];
	for (let index = 0; index < args.length; index++) {
		for (const name of list) {
			if (args[index] === name) return args[index + 1] ?? fallback;
			if (args[index].startsWith(`${name}=`)) return args[index].slice(name.length + 1);
		}
	}
	return fallback;
}

function boundedIntFlag(args, names, fallback, min, max) {
	const value = flagValue(args, names, "");
	const parsed = value ? Number.parseInt(value, 10) : fallback;
	if (!Number.isFinite(parsed)) return fallback;
	return Math.max(min, Math.min(max, parsed));
}

function modelStdinTimeoutMs() {
	return boundedIntFlag(
		rawArgs,
		["--stdin-timeout-ms", "--stdin-timeout"],
		Number.parseInt(process.env.REPI_MODEL_STDIN_TIMEOUT_MS || process.env.REPI_STDIN_READ_TIMEOUT_MS || "30000", 10),
		50,
		10 * 60 * 1000,
	);
}

function modelStdinMaxBytes(fallback) {
	return boundedIntFlag(
		rawArgs,
		["--stdin-max-bytes", "--stdin-bytes"],
		Number.parseInt(process.env.REPI_MODEL_STDIN_MAX_BYTES || String(fallback), 10),
		1,
		64 * 1024 * 1024,
	);
}

function readStdinBounded(label, { maxBytes = 1024 * 1024 } = {}) {
	const timeoutMs = modelStdinTimeoutMs();
	const limit = modelStdinMaxBytes(maxBytes);
	const result = spawnSync("head", ["-c", String(limit + 1)], {
		stdio: ["inherit", "pipe", "pipe"],
		timeout: timeoutMs,
		maxBuffer: limit + 1024,
	});
	const timedOut = result.error?.code === "ETIMEDOUT" || result.signal === "SIGTERM" || (result.status === null && !result.stdout);
	if (timedOut) {
		throw new Error(`${label} stdin read timed out after ${timeoutMs}ms; close stdin, pipe the value, or pass a file`);
	}
	if (result.error) throw new Error(`${label} stdin reader failed: ${result.error.message || String(result.error)}`);
	if (result.status !== 0) {
		const stderr = String(result.stderr ?? "").trim();
		throw new Error(`${label} stdin reader exited ${result.status}${stderr ? `: ${stderr}` : ""}`);
	}
	const body = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(String(result.stdout ?? ""), "utf8");
	if (body.length > limit) throw new Error(`${label} stdin exceeds max bytes (${limit})`);
	return body.toString("utf8");
}

function insecureApiKeyArgAllowed() {
	return process.env.REPI_ALLOW_INSECURE_API_KEY_ARG === "1";
}

function numberFlag(args, names, fallback = 0) {
	const value = flagValue(args, names, "");
	const parsed = Number(value);
	return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function intFlag(args, names, fallback, min, max) {
	const value = flagValue(args, names, "");
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed)) return fallback;
	return Math.max(min, Math.min(max, parsed));
}

function boolFlag(args, names, fallback = false) {
	const value = flagValue(args, names, "");
	if (!value) return fallback;
	if (/^(?:1|true|yes|y|on)$/i.test(value)) return true;
	if (/^(?:0|false|no|n|off)$/i.test(value)) return false;
	return fallback;
}

function hasFlag(args, names) {
	const list = Array.isArray(names) ? names : [names];
	return args.some((arg) => list.some((name) => arg === name || arg.startsWith(`${name}=`)));
}

function hash(value) {
	return createHash("sha256").update(String(value ?? "")).digest("hex").slice(0, 16);
}

function maybeNumberFlag(args, names) {
	if (!hasFlag(args, names)) return undefined;
	return numberFlag(args, names, 0);
}

function maybeIntFlag(args, names, min, max) {
	if (!hasFlag(args, names)) return undefined;
	const value = flagValue(args, names, "");
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed)) return undefined;
	return Math.max(min, Math.min(max, parsed));
}

const valueFlags = new Set([
	"--provider",
	"--model",
	"--api",
	"--base-url",
	"--baseUrl",
	"--api-key-env",
	"--env",
	"--api-key",
	"--provider-name",
	"--model-name",
	"--name",
	"--id",
	"--input",
	"-i",
	"--output",
	"-o",
	"--timeout-ms",
	"--input-tokens",
	"--output-tokens",
	"--cache-read-tokens",
	"--cache-write-tokens",
	"--input-cost",
	"--cost-input",
	"--output-cost",
	"--cost-output",
	"--cache-read-cost",
	"--cost-cache-read",
	"--cache-write-cost",
	"--cost-cache-write",
	"--context-window",
	"--context",
	"--max-tokens",
	"--max-output",
	"--stdin-timeout-ms",
	"--stdin-timeout",
	"--stdin-max-bytes",
	"--stdin-bytes",
]);

function positional(args, offset = 0) {
	const out = [];
	for (let index = 0; index < args.length; index++) {
		const arg = args[index];
		if (arg === "--") {
			out.push(...args.slice(index + 1));
			break;
		}
		if (arg.startsWith("--")) {
			const flag = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;
			if (!arg.includes("=") && valueFlags.has(flag)) index += 1;
			continue;
		}
		if (arg.startsWith("-") && valueFlags.has(arg)) {
			index += 1;
			continue;
		}
		out.push(arg);
	}
	return out[offset];
}

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.trim();
}

function showUrls() {
	return rawArgs.includes("--show-urls") || rawArgs.includes("--show-base-url") || rawArgs.includes("--show-base-urls");
}

function displayUrl(value) {
	const text = redact(value);
	if (!text) return "";
	return showUrls() ? text : `<redacted:url:${hash(text)}>`;
}

function envRef(apiKey) {
	if (typeof apiKey !== "string") return { kind: "missing", env: null, present: false };
	if (apiKey.startsWith("$")) {
		const env = apiKey.slice(1);
		return { kind: "env", env, present: Boolean(process.env[env]) };
	}
	return { kind: "literal", env: null, present: true };
}

function isCloudflareProviderConfig(providerId, provider) {
	const text = `${providerId} ${provider?.baseUrl ?? ""}`.toLowerCase();
	return text.includes("cloudflare") || text.includes("api.cloudflare.com") || text.includes("gateway.ai.cloudflare.com");
}

function cloudflareModelIdIssues(providerId, provider, modelId) {
	const id = String(modelId ?? "");
	if (!isCloudflareProviderConfig(providerId, provider)) return [];
	const issues = [];
	const cfOccurrences = (id.match(/@cf\//g) || []).length;
	if (cfOccurrences > 1) {
		issues.push('cloudflare model id contains repeated "@cf/" prefix; expected e.g. @cf/moonshotai/kimi-k2.7-code');
	}
	if (/moonshotai\/kimi-@cf\//.test(id)) {
		issues.push('cloudflare model id looks concatenated; expected @cf/moonshotai/kimi-k2.7-code');
	}
	return issues;
}

function storedAuthStatus(authData, providerId) {
	const credential = authData && typeof authData === "object" ? authData[providerId] : undefined;
	if (!credential || typeof credential !== "object") return { configured: false, source: "none" };
	if (credential.type === "api_key" && typeof credential.key === "string" && credential.key.length > 0)
		return { configured: true, source: "auth.json:api_key" };
	if (credential.type === "oauth") return { configured: true, source: "auth.json:oauth" };
	return { configured: false, source: "invalid-auth-entry" };
}

function nonNegativeNumber(value, fallback = 0) {
	const parsed = Number(value);
	return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function costOf(model = {}, provider = {}) {
	const modelCost = model?.cost && typeof model.cost === "object" ? model.cost : {};
	const providerCost = provider?.cost && typeof provider.cost === "object" ? provider.cost : {};
	const tiers = Array.isArray(modelCost.tiers)
		? modelCost.tiers
		: Array.isArray(providerCost.tiers)
			? providerCost.tiers
			: undefined;
	return {
		input: nonNegativeNumber(modelCost.input ?? providerCost.input),
		output: nonNegativeNumber(modelCost.output ?? providerCost.output),
		cacheRead: nonNegativeNumber(modelCost.cacheRead ?? providerCost.cacheRead),
		cacheWrite: nonNegativeNumber(modelCost.cacheWrite ?? providerCost.cacheWrite),
		...(tiers ? { tiers } : {}),
	};
}

function costRatesForUsage(cost, tokens) {
	const selectedTier = selectedCostTier(cost, tokens);
	return selectedTier
		? {
				input: nonNegativeNumber(selectedTier.input),
				output: nonNegativeNumber(selectedTier.output),
				cacheRead: nonNegativeNumber(selectedTier.cacheRead),
				cacheWrite: nonNegativeNumber(selectedTier.cacheWrite),
			}
		: {
				input: nonNegativeNumber(cost?.input),
				output: nonNegativeNumber(cost?.output),
				cacheRead: nonNegativeNumber(cost?.cacheRead),
				cacheWrite: nonNegativeNumber(cost?.cacheWrite),
			};
}

function selectedCostTier(cost, tokens) {
	let selectedTier;
	let threshold = -1;
	const inputUsage = Number(tokens?.input ?? 0) + Number(tokens?.cacheRead ?? 0) + Number(tokens?.cacheWrite ?? 0);
	for (const tier of cost?.tiers ?? []) {
		if (!tier || typeof tier !== "object") continue;
		const tierThreshold = Number(tier.inputTokensAbove);
		if (Number.isFinite(tierThreshold) && inputUsage > tierThreshold && tierThreshold > threshold) {
			selectedTier = tier;
			threshold = tierThreshold;
		}
	}
	return selectedTier;
}

function costText(cost) {
	const text = `input:${cost.input}/output:${cost.output}/cacheRead:${cost.cacheRead}/cacheWrite:${cost.cacheWrite}`;
	return cost?.tiers?.length ? `${text}/tiers:${cost.tiers.length}` : text;
}

function loadProviders() {
	const envProvider = envOnlyProviderConfig();
	const envError = envProvider?.configError ?? null;
	const withEnvProvider = (providers) =>
		envProvider ? { ...(providers && typeof providers === "object" ? providers : {}), [envProvider.providerId]: envProvider.provider } : providers;
	if (!existsSync(modelsPath)) return { providers: withEnvProvider({}), parseError: null, envError, missing: true };
	const parsed = readJson(modelsPath);
	if (parsed?.__error) return { providers: withEnvProvider({}), parseError: parsed.__error, envError, missing: false };
	const providers = parsed?.providers && typeof parsed.providers === "object" && !Array.isArray(parsed.providers) ? parsed.providers : {};
	return { providers: withEnvProvider(providers), parseError: null, envError, missing: false };
}

function listModelsProbe() {
	const result = spawnSync(join(root, "repi"), ["--offline", "--list-models"], {
		cwd: root,
		env: {
			...process.env,
			REPI_OFFLINE: "1",
			REPI_SKIP_VERSION_CHECK: "1",
			REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
			REPI_TELEMETRY: "0",
		},
		encoding: "utf8",
		timeout: 25_000,
		maxBuffer: 2 * 1024 * 1024,
	});
	return {
		exit: result.status ?? 1,
		stdoutPreview: redact((result.stdout ?? "").slice(0, 800).replace(/\s+/g, " ")),
		stderrPreview: redact((result.stderr ?? "").slice(0, 800).replace(/\s+/g, " ")),
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
}

function normalizeCloudflareModelId(providerId, provider, modelId) {
	const id = String(modelId ?? "").trim();
	if (!isCloudflareProviderConfig(providerId, provider)) return id;
	if (/moonshotai\/kimi-@cf\/moonshotai\/kimi-k2\.7-code/.test(id)) return "@cf/moonshotai/kimi-k2.7-code";
	if ((id.match(/@cf\//g) || []).length > 1) {
		const last = id.lastIndexOf("@cf/");
		if (last >= 0) return id.slice(last);
	}
	return id;
}

function modelExistsInProvider(provider, modelId) {
	return Array.isArray(provider?.models) && provider.models.some((model) => model?.id === modelId);
}

function defaultStatusFor(providers, settings, listModels) {
	const providerId = settings?.defaultProvider;
	const modelId = settings?.defaultModel;
	if (!providerId && !modelId) return { configured: false, ok: true, providerId: null, modelId: null, message: "not configured; REPI_* environment variables are the preferred default path" };
	if (!providerId || !modelId) return { configured: true, ok: false, providerId: providerId ?? null, modelId: modelId ?? null, message: "defaultProvider/defaultModel must be set together" };
	const provider = providers[providerId];
	if (provider) {
		return {
			configured: true,
			ok: modelExistsInProvider(provider, modelId),
			providerId,
			modelId,
			message: modelExistsInProvider(provider, modelId) ? "configured model exists" : "default model is not present under configured provider",
		};
	}
	const listText = `${listModels?.stdoutPreview ?? ""}\n${listModels?.stderrPreview ?? ""}`;
	const visible = listText.includes(providerId) && listText.includes(modelId);
	return {
		configured: true,
		ok: visible,
		providerId,
		modelId,
		message: visible ? "visible in runtime model list" : "default provider/model not visible in runtime model list",
	};
}

function repairModelConfig() {
	const actions = [];
	const loaded = loadProviders();
	const modelsConfig = readJsonObject(modelsPath, { providers: {} });
	if (!modelsConfig.providers || typeof modelsConfig.providers !== "object" || Array.isArray(modelsConfig.providers)) modelsConfig.providers = {};
	const authData = readJsonObject(authPath, {});
	let modelsChanged = false;
	let authChanged = false;
	for (const [providerId, provider] of Object.entries(modelsConfig.providers)) {
		if (!provider || typeof provider !== "object") continue;
		const key = envRef(provider.apiKey);
		if (key.kind === "literal") {
			const existing = storedAuthStatus(authData, providerId);
			if (!existing.configured && typeof provider.apiKey === "string" && provider.apiKey.length > 0) {
				authData[providerId] = { type: "api_key", key: provider.apiKey };
				authChanged = true;
			}
			provider.apiKey = `$${providerEnvName(providerId)}`;
			modelsChanged = true;
			actions.push({ id: `literal-api-key:${providerId}`, status: "fixed", detail: "moved literal credential to auth.json and left an env-style fallback reference in models.json" });
		}
		if (Array.isArray(provider.models)) {
			for (const model of provider.models) {
				const before = model?.id;
				const after = normalizeCloudflareModelId(providerId, provider, before);
				if (after && before !== after) {
					model.id = after;
					modelsChanged = true;
					actions.push({ id: `cloudflare-model-id:${providerId}`, status: "fixed", detail: "normalized duplicated @cf model id" });
				}
			}
		}
	}
	const settings = readJsonObject(settingsPath, {});
	const listModels = listModelsProbe();
	const status = defaultStatusFor(modelsConfig.providers, settings, listModels);
	if (!status.ok) {
		if (settings.defaultProvider !== undefined || settings.defaultModel !== undefined) {
			delete settings.defaultProvider;
			delete settings.defaultModel;
			writeJsonFile(settingsPath, settings, 0o600);
			actions.push({ id: "default-model", status: "fixed", detail: "removed invalid legacy settings default; use REPI_PROVIDER/REPI_MODEL/REPI_BASE_URL env vars for the default model" });
		} else {
			actions.push({ id: "default-model", status: "skipped", detail: "no settings default configured; use REPI_PROVIDER/REPI_MODEL/REPI_BASE_URL env vars" });
		}
	}
	if (modelsChanged) writeJsonFile(modelsPath, modelsConfig, 0o600);
	if (authChanged) writeJsonFile(authPath, authData, 0o600);
	return { actions, loadedBefore: loaded };
}

function buildDoctorReport() {
	const fixReport = fix ? repairModelConfig() : { actions: [] };
	const loaded = loadProviders();
	const authData = readJson(authPath);
	const settings = readJson(settingsPath);
	const providerRows = [];
	const diagnostics = [];
	let modelCount = 0;
	if (loaded.parseError) diagnostics.push({ level: "fail", id: "models-json-parse", message: loaded.parseError });
	if (loaded.envError) diagnostics.push({ level: "fail", id: "env-model-cost", message: loaded.envError });
	if (settings?.__error) diagnostics.push({ level: "fail", id: "settings-json-parse", message: settings.__error });
	if (loaded.missing) diagnostics.push({ level: "warn", id: "models-json-missing", message: `${modelsPath} not found; use REPI_* environment variables for the default env-only provider, or create models.json for persistent providers` });
	for (const [providerId, provider] of Object.entries(loaded.providers)) {
		const api = provider.api;
		const key = envRef(provider.apiKey);
		const storedAuth = storedAuthStatus(authData, providerId);
		const authConfigured = storedAuth.configured || key.present;
		const models = Array.isArray(provider.models) ? provider.models : [];
		modelCount += models.length;
		const issues = [];
		if (!allowedApis.has(api)) issues.push(`unsupported api=${api}`);
		if (typeof provider.baseUrl !== "string" || !provider.baseUrl) issues.push("missing baseUrl");
		if (key.kind === "literal") issues.push("apiKey is literal in models.json; run `repi model doctor --fix` to move it to auth.json");
		if (key.kind === "missing" && !storedAuth.configured) issues.push("missing apiKey env reference or auth.json credential");
		if (key.kind === "env" && !key.present && !storedAuth.configured) issues.push(`env ${key.env} is not set and no auth.json credential exists`);
		if (!models.length) issues.push("provider has no models[]");
		const modelRows = models.map((model) => {
			const cost = costOf(model, provider);
			const modelIssues = [];
			if (!model.id) modelIssues.push("missing id");
			modelIssues.push(...cloudflareModelIdIssues(providerId, provider, model.id));
			if (!Number.isFinite(Number(model.contextWindow)) || Number(model.contextWindow) <= 0) modelIssues.push("missing/invalid contextWindow");
			if (!Number.isFinite(Number(model.maxTokens)) || Number(model.maxTokens) <= 0) modelIssues.push("missing/invalid maxTokens");
			if (!model.cost) modelIssues.push("missing model.cost; cost display falls back to provider/zero");
			return {
				id: redact(model.id),
				contextWindow: Number(model.contextWindow ?? 0),
				maxTokens: Number(model.maxTokens ?? 0),
				reasoning: model.reasoning ?? null,
				cost,
				issues: modelIssues,
			};
		});
		providerRows.push({
			id: providerId,
			api,
			baseUrl: displayUrl(provider.baseUrl),
			baseUrlHidden: !showUrls(),
			apiKey: storedAuth.configured
				? `${storedAuth.source} (local credential; ${key.kind === "env" ? `models fallback $${key.env} ${key.present ? "set" : "not set"}` : `models ${key.kind}`})`
				: key.kind === "env"
					? `$${key.env} (${key.present ? "set" : "missing"})`
					: key.kind,
			authConfigured,
			models: modelRows,
			issues,
		});
	}
	const listModels = listModelsProbe();
	const defaultModel = defaultStatusFor(loaded.providers, settings, listModels);
	if (!defaultModel.ok) diagnostics.push({ level: "fail", id: "default-model", message: defaultModel.message });
	if (listModels.exit !== 0)
		diagnostics.push({
			level: "warn",
			id: "list-models",
			message: listModels.stderrPreview || listModels.error || "list-models failed",
		});
	return {
		kind: "repi-model-doctor-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		root,
		agentDir,
		modelsPath,
		authPath,
		settingsPath,
		fix,
		fixActions: fixReport.actions,
		defaultModel,
		providerCount: providerRows.length,
		modelCount,
		providers: providerRows,
		listModels,
		diagnostics,
		ok: !diagnostics.some((item) => item.level === "fail") && providerRows.every((row) => !row.issues.some((issue) => issue.startsWith("unsupported") || issue.startsWith("missing baseUrl"))),
	};
}

function findModel(providers, providerId, modelId) {
	for (const [id, provider] of Object.entries(providers)) {
		if (providerId && id !== providerId) continue;
		for (const model of Array.isArray(provider.models) ? provider.models : []) {
			if (!modelId || model.id === modelId) return { providerId: id, provider, model };
		}
	}
	return undefined;
}

function buildCostReport() {
	const loaded = loadProviders();
	if (loaded.envError) {
		return {
			kind: "repi-model-cost-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: loaded.envError,
		};
	}
	const providerId = flagValue(rawArgs, "--provider");
	const modelId = flagValue(rawArgs, "--model");
	const inputTokens = numberFlag(rawArgs, ["--input-tokens", "--input"], 0);
	const outputTokens = numberFlag(rawArgs, ["--output-tokens", "--output"], 0);
	const cacheReadTokens = numberFlag(rawArgs, ["--cache-read-tokens", "--cache-read"], 0);
	const cacheWriteTokens = numberFlag(rawArgs, ["--cache-write-tokens", "--cache-write"], 0);
	const found = findModel(loaded.providers, providerId, modelId);
	if (!found) {
		return {
			kind: "repi-model-cost-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: `model not found; provider=${providerId || "<first>"} model=${modelId || "<first>"}`,
		};
	}
	const cost = costOf(found.model, found.provider);
	const tokens = { input: inputTokens, output: outputTokens, cacheRead: cacheReadTokens, cacheWrite: cacheWriteTokens };
	const rates = costRatesForUsage(cost, tokens);
	const selectedTier = selectedCostTier(cost, tokens);
	const total =
		(inputTokens * rates.input +
			outputTokens * rates.output +
			cacheReadTokens * rates.cacheRead +
			cacheWriteTokens * rates.cacheWrite) /
		1_000_000;
	return {
		kind: "repi-model-cost-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		provider: found.providerId,
		model: found.model.id,
		unit: "USD per 1M tokens",
		tokens,
		baseRates: {
			input: cost.input,
			output: cost.output,
			cacheRead: cost.cacheRead,
			cacheWrite: cost.cacheWrite,
		},
		rates,
		costTiers: cost.tiers ?? [],
		selectedTier: selectedTier ?? null,
		estimatedUsd: total,
	};
}

function modelRowsForList(providers, authData, providerFilter, modelFilter) {
	return Object.entries(providers).flatMap(([providerId, provider]) => {
		if (providerFilter && providerId !== providerFilter) return [];
		const storedAuth = storedAuthStatus(authData, providerId);
		const key = envRef(provider.apiKey);
		return (Array.isArray(provider.models) ? provider.models : [])
			.filter((model) => !modelFilter || model?.id === modelFilter)
			.map((model) => ({
			provider: providerId,
			model: redact(model.id),
			api: provider.api,
			baseUrl: displayUrl(provider.baseUrl),
			baseUrlHidden: !showUrls(),
			auth: storedAuth.configured ? storedAuth.source : key.kind === "env" ? `$${key.env}:${key.present ? "set" : "missing"}` : key.kind,
			contextWindow: Number(model.contextWindow ?? 0),
			maxTokens: Number(model.maxTokens ?? 0),
			reasoning: model.reasoning ?? null,
			input: Array.isArray(model.input) ? model.input : [],
			cost: costOf(model, provider),
		}));
	});
}

function buildListReport() {
	const loaded = loadProviders();
	const authData = readJson(authPath);
	const providerFilter = flagValue(rawArgs, "--provider") || undefined;
	const modelFilter = flagValue(rawArgs, "--model") || undefined;
	const rows = modelRowsForList(loaded.providers, authData, providerFilter, modelFilter);
	const providerMissing = Boolean(providerFilter && !Object.prototype.hasOwnProperty.call(loaded.providers, providerFilter));
	const filterMissing = !loaded.parseError && (providerMissing || Boolean(modelFilter && rows.length === 0));
	return {
		kind: "repi-model-list-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: !loaded.parseError && !loaded.envError && !filterMissing,
		agentDir,
		modelsPath,
		authPath,
		provider: providerFilter ?? null,
		model: modelFilter ?? null,
		baseUrlHidden: !showUrls(),
		providerCount: providerFilter ? (Object.prototype.hasOwnProperty.call(loaded.providers, providerFilter) ? 1 : 0) : Object.keys(loaded.providers).length,
		modelCount: rows.length,
		rows,
		error:
			loaded.parseError ??
			loaded.envError ??
			(filterMissing ? `model list found no rows for provider=${providerFilter ?? "<any>"} model=${modelFilter ?? "<any>"}` : undefined),
	};
}

function configValueEnvNames(value) {
	const names = [];
	for (let index = 0; index < value.length; index++) {
		if (value[index] !== "$") continue;
		const next = value[index + 1];
		if (next === "$" || next === "!") {
			index++;
			continue;
		}
		if (next === "{") {
			const end = value.indexOf("}", index + 2);
			if (end < 0) continue;
			const name = value.slice(index + 2, end);
			if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && !names.includes(name)) names.push(name);
			index = end;
			continue;
		}
		const match = value.slice(index + 1).match(/^[A-Za-z_][A-Za-z0-9_]*/);
		if (match) {
			if (!names.includes(match[0])) names.push(match[0]);
			index += match[0].length;
		}
	}
	return names;
}

function configuredConfigValue(value) {
	if (typeof value !== "string") return false;
	if (value.startsWith("!")) return true;
	return configValueEnvNames(value).every((name) => Boolean(process.env[name]));
}

function providerHasConfiguredAuth(provider, authData, providerId) {
	const credential = authData && typeof authData === "object" ? authData[providerId] : undefined;
	if (credential?.type === "oauth") return false;
	if (credential?.type === "api_key") return configuredConfigValue(credential.key) && credential.key.length > 0;
	return configuredConfigValue(provider?.apiKey);
}

function buildCliListReport() {
	const loaded = loadProviders();
	const authData = existsSync(authPath) ? readJson(authPath) : {};
	if (authData?.__error) {
		return {
			kind: "repi-cli-model-list-report",
			schemaVersion: 1,
			ok: false,
			rows: [],
			error: `${authPath}: ${authData.__error}`,
		};
	}
	const rows = modelRowsForList(loaded.providers, authData, undefined, undefined).filter((row) =>
		providerHasConfiguredAuth(loaded.providers[row.provider], authData, row.provider),
	);
	const rawEnvApi = firstEnv(envApiNames);
	const invalidEnvApi = invalidModelApi(rawEnvApi);
	const warnings = [];
	if (loaded.parseError) warnings.push(`errors loading models.json:\n${loaded.parseError}`);
	if (loaded.envError) warnings.push(loaded.envError);
	if (invalidEnvApi) {
		warnings.push(
			`Provider "${firstEnv(["REPI_PROVIDER", "REPI_MODEL_PROVIDER", "REPI_PROVIDER_ID"]) || "repi-env"}": invalid REPI_MODEL_API=${JSON.stringify(invalidEnvApi)}; allowed openai-compatible|openai-responses|anthropic`,
		);
	}
	return {
		kind: "repi-cli-model-list-report",
		schemaVersion: 1,
		ok: !loaded.envError,
		rows,
		warnings,
		error: loaded.envError ?? undefined,
	};
}

function envStatusReport() {
	const baseUrl = firstEnv(envBaseUrlNames);
	const model = firstEnv(["REPI_MODEL", "REPI_MODEL_ID"]);
	const provider = firstEnv(["REPI_PROVIDER", "REPI_MODEL_PROVIDER", "REPI_PROVIDER_ID"]) || "repi-env";
	const rawApi = firstEnv(envApiNames);
	const api = normalizeModelApi(rawApi);
	const invalidApi = invalidModelApi(rawApi);
	const authEnv = firstEnvEntry(envAuthNames)?.name ?? "REPI_AUTH_TOKEN";
	const contextConfig = envInt(envContextNames, 262144, 1024, 1048576);
	const maxTokensConfig = envInt(envMaxTokensNames, 16384, 64, 131072);
	const inputConfig = parseEnvInput(firstEnv(envInputNames));
	const reasoningConfig = envBool(["REPI_MODEL_REASONING", "REPI_REASONING"]);
	const authHeaderConfig = firstEnvEntry(["REPI_AUTH_HEADER", "REPI_MODEL_AUTH_HEADER"])
		? envBool(["REPI_AUTH_HEADER", "REPI_MODEL_AUTH_HEADER"])
		: { value: undefined, error: null };
	const providerHeaders = parseEnvJsonObject(["REPI_HEADERS", "REPI_PROVIDER_HEADERS"], validateHeaders);
	const modelHeaders = parseEnvJsonObject(["REPI_MODEL_HEADERS"], validateHeaders);
	const providerCompat = parseEnvJsonObject(["REPI_COMPAT"]);
	const modelCompat = parseEnvJsonObject(["REPI_MODEL_COMPAT"]);
	const thinkingLevelMap = parseEnvJsonObject(
		["REPI_MODEL_THINKING_LEVEL_MAP", "REPI_THINKING_LEVEL_MAP"],
		validateThinkingLevelMap,
	);
	const subagentModel = firstEnv(["REPI_SUBAGENT_MODEL"]) || null;
	const costConfig = envCostConfig();
	const enabled = Boolean(baseUrl && model);
	const issues = [];
	if (!baseUrl) issues.push("REPI_BASE_URL is missing");
	if (!model) issues.push("REPI_MODEL is missing");
	if (!process.env[authEnv]) issues.push(`${authEnv} is missing`);
	if (invalidApi) {
		issues.push(
			`REPI_MODEL_API is invalid: ${invalidApi}; allowed openai-compatible|openai-responses|anthropic`,
		);
	}
	if (enabled) {
		for (const error of [
			costConfig.error,
			contextConfig.error,
			maxTokensConfig.error,
			inputConfig.error,
			reasoningConfig.error,
			authHeaderConfig.error,
			providerHeaders.error,
			modelHeaders.error,
			providerCompat.error,
			modelCompat.error,
			thinkingLevelMap.error,
		]) {
			if (error) issues.push(error);
		}
	}
	const baseUrlText = String(baseUrl ?? "").replace(/\/+$/, "");
	if (baseUrlText) {
		if ((api === "openai-completions" || api === "openai-responses") && !baseUrlText.endsWith("/v1")) {
			issues.push("REPI_BASE_URL for openai-compatible/openai-responses usually ends with /v1");
		}
		if (api === "anthropic-messages" && baseUrlText.endsWith("/v1")) {
			issues.push("REPI_BASE_URL for anthropic usually omits /v1 because the SDK appends /v1/messages");
		}
	}
	for (const [name, value] of Object.entries({
		REPI_BASE_URL: baseUrl,
		REPI_MODEL: model,
		REPI_PROVIDER: provider,
		REPI_SUBAGENT_MODEL: subagentModel,
	})) {
		if (typeof value === "string" && /['"]/.test(value)) issues.push(`${name} contains a quote character; check shell export quoting`);
	}
	return {
		enabled,
		provider,
		model: model ?? null,
		api,
		rawApi: rawApi ?? null,
		invalidApi,
		baseUrl: baseUrl ? displayUrl(baseUrl) : null,
		baseUrlHidden: !showUrls(),
		authEnv,
		authPresent: Boolean(process.env[authEnv]),
		contextWindow: contextConfig.value,
		autoCompactWindow: contextConfig.value,
		maxTokens: maxTokensConfig.value,
		subagentModel,
		input: inputConfig.input,
		reasoning: reasoningConfig.value,
		authHeader: authHeaderConfig.value ?? false,
		headers: {
			provider: providerHeaders.value ? Object.keys(providerHeaders.value) : [],
			model: modelHeaders.value ? Object.keys(modelHeaders.value) : [],
		},
		compatConfigured: {
			provider: Boolean(providerCompat.value),
			model: Boolean(modelCompat.value),
		},
		thinkingLevelMapConfigured: Boolean(thinkingLevelMap.value),
		cost: costConfig.cost,
		costError: costConfig.error,
		issues,
	};
}

function buildStatusReport() {
	const loaded = loadProviders();
	const settings = readJson(settingsPath);
	const env = envStatusReport();
	const defaultModel = defaultStatusFor(loaded.providers, settings, { stdoutPreview: "", stderrPreview: "", exit: 0 });
	const effective = env.enabled
		? {
				source: "REPI_* environment",
				provider: env.provider,
				model: env.model,
				api: env.api,
				contextWindow: env.contextWindow,
				maxTokens: env.maxTokens,
				cost: env.cost,
			}
		: defaultModel.configured
			? {
					source: "settings.json default",
					provider: defaultModel.providerId,
					model: defaultModel.modelId,
					api: loaded.providers?.[defaultModel.providerId]?.api ?? "unknown",
					contextWindow:
						loaded.providers?.[defaultModel.providerId]?.models?.find((candidate) => candidate?.id === defaultModel.modelId)
							?.contextWindow ?? null,
					maxTokens:
						loaded.providers?.[defaultModel.providerId]?.models?.find((candidate) => candidate?.id === defaultModel.modelId)
							?.maxTokens ?? null,
					cost: (() => {
						const provider = loaded.providers?.[defaultModel.providerId];
						const model = provider?.models?.find((candidate) => candidate?.id === defaultModel.modelId);
						return model ? costOf(model, provider) : null;
					})(),
				}
			: {
					source: "unset",
					provider: null,
					model: null,
					api: null,
					contextWindow: null,
					maxTokens: null,
				cost: null,
			};
	const diagnostics = [];
	if (loaded.parseError) diagnostics.push({ level: "fail", id: "models-json-parse", message: loaded.parseError });
	if (loaded.envError && !env.issues.includes(loaded.envError)) {
		diagnostics.push({ level: "fail", id: "env-model-metadata", message: loaded.envError });
	}
	for (const issue of env.issues) {
		const invalidApi = issue.startsWith("REPI_MODEL_API is invalid:");
		const invalidMetadata = issue.startsWith("invalid REPI_");
		diagnostics.push({
			level: invalidApi || invalidMetadata ? "fail" : env.enabled ? "warn" : "info",
			id: invalidApi ? "env-model-api" : invalidMetadata ? "env-model-metadata" : "env-model",
			message: issue,
		});
	}
	if (!env.enabled && !defaultModel.configured)
		diagnostics.push({
			level: "info",
			id: "env-model-example",
			message: "set REPI_AUTH_TOKEN, REPI_BASE_URL, REPI_MODEL, and optional REPI_MODEL_API to choose a model without editing models.json",
		});
	return {
		kind: "repi-model-status-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		root,
		agentDir,
		modelsPath,
		settingsPath,
		env,
		defaultModel,
		effective,
		providerCount: Object.keys(loaded.providers).length,
		diagnostics,
		ok: !diagnostics.some((item) => item.level === "fail"),
	};
}

function providerEnvName(providerId) {
	return `REPI_${String(providerId)
		.toUpperCase()
		.replace(/[^A-Z0-9]+/g, "_")
		.replace(/^_+|_+$/g, "")}_API_KEY`;
}

function firstEnv(names) {
	return firstEnvEntry(names)?.value;
}

function firstEnvEntry(names) {
	for (const name of names) {
		const value = process.env[name]?.trim();
		if (value) return { name, value };
	}
	return undefined;
}

function normalizeModelApi(value) {
	const normalized = String(value || "openai-completions").trim().toLowerCase().replace(/_/g, "-");
	if (["openai-compatible", "openai-chat", "chat", "chat-completions", "openai-completions"].includes(normalized)) {
		return "openai-completions";
	}
	if (["response", "responses", "openai-response", "openai-responses"].includes(normalized)) return "openai-responses";
	if (["anthropic", "claude", "anthropic-compatible", "anthropic-messages"].includes(normalized)) {
		return "anthropic-messages";
	}
	return allowedApis.has(normalized) ? normalized : "openai-completions";
}

function invalidModelApi(value) {
	if (!value) return null;
	const normalized = String(value).trim().toLowerCase().replace(/_/g, "-");
	return envModelApiAliases.has(normalized) ? null : value;
}

function envInt(names, fallback, min, max) {
	const entry = firstEnvEntry(names);
	if (!entry) return { value: fallback, error: null };
	const parsed = Number(entry.value);
	if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
		return { value: fallback, error: `invalid ${entry.name}: expected an integer between ${min} and ${max}` };
	}
	return { value: parsed, error: null };
}

function envNumber(names, fallback = 0, min = 0) {
	const entry = firstEnvEntry(names);
	if (!entry) return { value: fallback, error: null };
	const parsed = Number(entry.value);
	return Number.isFinite(parsed) && parsed >= min
		? { value: parsed, error: null }
		: { value: fallback, error: `invalid ${entry.name}: expected a number greater than or equal to ${min}` };
}

function parseEnvCostTiers(value) {
	if (!value) return { tiers: undefined, error: null };
	let parsed;
	try {
		parsed = JSON.parse(value);
	} catch {
		return { tiers: undefined, error: "invalid REPI_MODEL_COST_TIERS: expected a JSON array" };
	}
	if (!Array.isArray(parsed)) {
		return { tiers: undefined, error: "invalid REPI_MODEL_COST_TIERS: expected a JSON array" };
	}
	const tiers = [];
	for (let index = 0; index < parsed.length; index++) {
		const tier = parsed[index];
		if (!tier || typeof tier !== "object" || Array.isArray(tier)) {
			return { tiers: undefined, error: `invalid REPI_MODEL_COST_TIERS[${index}]: expected an object` };
		}
		for (const field of ["input", "output", "cacheRead", "cacheWrite"]) {
			if (typeof tier[field] !== "number" || !Number.isFinite(tier[field]) || tier[field] < 0) {
				return {
					tiers: undefined,
					error: `invalid REPI_MODEL_COST_TIERS[${index}].${field}: expected a non-negative number`,
				};
			}
		}
		if (!Number.isSafeInteger(tier.inputTokensAbove) || tier.inputTokensAbove < 0) {
			return {
				tiers: undefined,
				error: `invalid REPI_MODEL_COST_TIERS[${index}].inputTokensAbove: expected a non-negative integer`,
			};
		}
		tiers.push({
			inputTokensAbove: tier.inputTokensAbove,
			input: tier.input,
			output: tier.output,
			cacheRead: tier.cacheRead,
			cacheWrite: tier.cacheWrite,
		});
	}
	return { tiers, error: null };
}

function envCostConfig() {
	const parsedTiers = parseEnvCostTiers(firstEnv(["REPI_MODEL_COST_TIERS", "REPI_COST_TIERS"]));
	const input = envNumber(["REPI_MODEL_COST_INPUT", "REPI_COST_INPUT", "REPI_MODEL_INPUT_PRICE", "REPI_INPUT_PRICE"]);
	const output = envNumber(["REPI_MODEL_COST_OUTPUT", "REPI_COST_OUTPUT", "REPI_MODEL_OUTPUT_PRICE", "REPI_OUTPUT_PRICE"]);
	const cacheRead = envNumber([
		"REPI_MODEL_COST_CACHE_READ",
		"REPI_COST_CACHE_READ",
		"REPI_MODEL_CACHE_READ_PRICE",
		"REPI_CACHE_READ_PRICE",
	]);
	const cacheWrite = envNumber([
		"REPI_MODEL_COST_CACHE_WRITE",
		"REPI_COST_CACHE_WRITE",
		"REPI_MODEL_CACHE_WRITE_PRICE",
		"REPI_CACHE_WRITE_PRICE",
	]);
	return {
		cost: {
			input: input.value,
			output: output.value,
			cacheRead: cacheRead.value,
			cacheWrite: cacheWrite.value,
			...(parsedTiers.tiers ? { tiers: parsedTiers.tiers } : {}),
		},
		error: [parsedTiers.error, input.error, output.error, cacheRead.error, cacheWrite.error].find(Boolean) ?? null,
	};
}

function envBool(names, fallback = false) {
	const entry = firstEnvEntry(names);
	if (!entry) return { value: fallback, error: null };
	if (/^(?:1|true|yes|y|on)$/i.test(entry.value)) return { value: true, error: null };
	if (/^(?:0|false|no|n|off)$/i.test(entry.value)) return { value: false, error: null };
	return { value: fallback, error: `invalid ${entry.name}: expected a boolean` };
}

function parseEnvJsonObject(names, validate) {
	const entry = firstEnvEntry(names);
	if (!entry) return { value: undefined, error: null };
	let parsed;
	try {
		parsed = JSON.parse(entry.value);
	} catch {
		return { value: undefined, error: `invalid ${entry.name}: expected a JSON object` };
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		return { value: undefined, error: `invalid ${entry.name}: expected a JSON object` };
	}
	const error = validate?.(parsed, entry.name);
	return error ? { value: undefined, error } : { value: parsed, error: null };
}

function validateHeaders(headers, variableName) {
	for (const [name, value] of Object.entries(headers)) {
		if (typeof value !== "string" && value !== null) {
			return `invalid ${variableName}.${name}: expected a string or null`;
		}
	}
	return null;
}

function validateThinkingLevelMap(map, variableName) {
	const levels = new Set(["off", "minimal", "low", "medium", "high", "xhigh", "max"]);
	for (const [level, value] of Object.entries(map)) {
		if (!levels.has(level)) return `invalid ${variableName}.${level}: unknown thinking level`;
		if (typeof value !== "string" && value !== null) {
			return `invalid ${variableName}.${level}: expected a string or null`;
		}
	}
	return null;
}

function parseEnvInput(value) {
	if (!value) return { input: ["text"], error: null };
	let items;
	if (value.startsWith("[")) {
		try {
			items = JSON.parse(value);
		} catch {
			return { input: ["text"], error: "invalid REPI_MODEL_INPUT: expected comma-separated values or a JSON array" };
		}
		if (!Array.isArray(items)) return { input: ["text"], error: "invalid REPI_MODEL_INPUT: expected a JSON array" };
	} else {
		items = value.split(",").map((item) => item.trim());
	}
	const normalized = items.map((item) => String(item).trim());
	if (!normalized.length || normalized.some((item) => item !== "text" && item !== "image")) {
		return { input: ["text"], error: 'invalid REPI_MODEL_INPUT: allowed modalities are "text" and "image"' };
	}
	return { input: [...new Set(normalized)], error: null };
}

function envOnlyProviderConfig() {
	const baseUrl = firstEnv(envBaseUrlNames);
	const model = firstEnv(["REPI_MODEL", "REPI_MODEL_ID"]);
	if (!baseUrl || !model) return undefined;
	const providerId = firstEnv(["REPI_PROVIDER", "REPI_MODEL_PROVIDER", "REPI_PROVIDER_ID"]) || "repi-env";
	if (invalidModelApi(firstEnv(envApiNames))) return undefined;
	const apiKeyEnv = firstEnvEntry(envAuthNames)?.name ?? "REPI_AUTH_TOKEN";
	const costConfig = envCostConfig();
	const inputConfig = parseEnvInput(firstEnv(envInputNames));
	const reasoningConfig = envBool(["REPI_MODEL_REASONING", "REPI_REASONING"]);
	const contextConfig = envInt(envContextNames, 262144, 1024, 1048576);
	const maxTokensConfig = envInt(envMaxTokensNames, 16384, 64, 131072);
	const authHeaderConfig = firstEnvEntry(["REPI_AUTH_HEADER", "REPI_MODEL_AUTH_HEADER"])
		? envBool(["REPI_AUTH_HEADER", "REPI_MODEL_AUTH_HEADER"])
		: { value: undefined, error: null };
	const providerHeaders = parseEnvJsonObject(["REPI_HEADERS", "REPI_PROVIDER_HEADERS"], validateHeaders);
	const modelHeaders = parseEnvJsonObject(["REPI_MODEL_HEADERS"], validateHeaders);
	const providerCompat = parseEnvJsonObject(["REPI_COMPAT"]);
	const modelCompat = parseEnvJsonObject(["REPI_MODEL_COMPAT"]);
	const thinkingLevelMap = parseEnvJsonObject(
		["REPI_MODEL_THINKING_LEVEL_MAP", "REPI_THINKING_LEVEL_MAP"],
		validateThinkingLevelMap,
	);
	const configError = [
		costConfig.error,
		inputConfig.error,
		reasoningConfig.error,
		contextConfig.error,
		maxTokensConfig.error,
		authHeaderConfig.error,
		providerHeaders.error,
		modelHeaders.error,
		providerCompat.error,
		modelCompat.error,
		thinkingLevelMap.error,
	].find(Boolean);
	const models = [model, firstEnv(["REPI_SUBAGENT_MODEL"])]
		.filter(Boolean)
		.filter((value, index, values) => values.indexOf(value) === index)
		.map((id) => ({
			id,
			name: id === model ? firstEnv(["REPI_MODEL_NAME"]) || id : firstEnv(["REPI_SUBAGENT_MODEL_NAME"]) || id,
			input: inputConfig.input,
			cost: costConfig.cost,
			contextWindow: contextConfig.value,
			maxTokens: maxTokensConfig.value,
			reasoning: reasoningConfig.value,
			...(thinkingLevelMap.value ? { thinkingLevelMap: thinkingLevelMap.value } : {}),
			...(modelHeaders.value ? { headers: modelHeaders.value } : {}),
			...(modelCompat.value ? { compat: modelCompat.value } : {}),
		}));
	return {
		providerId,
		configError,
		provider: {
			name: firstEnv(["REPI_PROVIDER_NAME", "REPI_MODEL_PROVIDER_NAME"]) || "REPI environment model",
			api: normalizeModelApi(firstEnv(envApiNames)),
			baseUrl,
			apiKey: `$${apiKeyEnv}`,
			...(providerHeaders.value ? { headers: providerHeaders.value } : {}),
			...(providerCompat.value ? { compat: providerCompat.value } : {}),
			...(authHeaderConfig.value !== undefined ? { authHeader: authHeaderConfig.value } : {}),
			models,
			__source: "environment",
		},
	};
}

function removedPresetError(args) {
	if (!hasFlag(args, "--preset")) return undefined;
	const preset = flagValue(args, "--preset", "");
	return `provider presets have been removed; configure the model explicitly with --provider --api --base-url --model, or use REPI_AUTH_TOKEN/REPI_BASE_URL/REPI_MODEL/REPI_MODEL_API. Received --preset${preset ? ` ${preset}` : ""}.`;
}

function inputList(value) {
	const items = String(value || "text")
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
	return items.length ? items : ["text"];
}

function costFromFlags(args) {
	return {
		input: numberFlag(args, ["--input-cost", "--cost-input"], 0),
		output: numberFlag(args, ["--output-cost", "--cost-output"], 0),
		cacheRead: numberFlag(args, ["--cache-read-cost", "--cost-cache-read"], 0),
		cacheWrite: numberFlag(args, ["--cache-write-cost", "--cost-cache-write"], 0),
	};
}

function costPatchFromFlags(args, previous = {}) {
	const next = { ...previous };
	const patch = {
		input: maybeNumberFlag(args, ["--input-cost", "--cost-input"]),
		output: maybeNumberFlag(args, ["--output-cost", "--cost-output"]),
		cacheRead: maybeNumberFlag(args, ["--cache-read-cost", "--cost-cache-read"]),
		cacheWrite: maybeNumberFlag(args, ["--cache-write-cost", "--cost-cache-write"]),
	};
	for (const [key, value] of Object.entries(patch)) {
		if (value !== undefined) next[key] = value;
	}
	return next;
}

function upsertDefaultSetting(providerId, modelId) {
	const settingsPath = join(agentDir, "settings.json");
	const settings = readJsonObject(settingsPath, {});
	settings.defaultProvider = providerId;
	settings.defaultModel = modelId;
	writeJsonFile(settingsPath, settings, 0o600);
	return settingsPath;
}

function buildAddReport() {
	const presetError = removedPresetError(rawArgs);
	if (presetError) {
		return {
			kind: "repi-model-add-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: presetError,
		};
	}
	const providerId = flagValue(rawArgs, "--provider") || positional(rawArgs, 0);
	const modelId = flagValue(rawArgs, "--model");
	const api = flagValue(rawArgs, "--api", "openai-completions");
	const baseUrl = flagValue(rawArgs, ["--base-url", "--baseUrl"], "");
	if (!providerId || !modelId || !baseUrl || !api) {
		return {
			kind: "repi-model-add-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model add requires --provider <id> --base-url <url> --model <id> [--api <style>]",
		};
	}
	if (!allowedApis.has(api)) {
		return {
			kind: "repi-model-add-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: `unsupported api=${api}; allowed=${[...allowedApis].join(",")}`,
		};
	}
	const apiKeyEnv = flagValue(rawArgs, ["--api-key-env", "--env"], providerEnvName(providerId));
	let apiKey = flagValue(rawArgs, "--api-key");
	if (apiKey && !insecureApiKeyArgAllowed()) {
		return {
			kind: "repi-model-add-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "plain --api-key is disabled to avoid shell history/process-list leaks; use --api-key-stdin, or set REPI_ALLOW_INSECURE_API_KEY_ARG=1 explicitly",
		};
	}
	if (!apiKey && rawArgs.includes("--api-key-stdin")) {
		try {
			apiKey = readStdinBounded("model add api key", { maxBytes: 64 * 1024 }).trim();
		} catch (error) {
			return {
				kind: "repi-model-add-report",
				schemaVersion: 1,
				generatedAt: new Date().toISOString(),
				ok: false,
				error: error instanceof Error ? error.message : String(error),
			};
		}
	}
	if (!/^[A-Z_][A-Z0-9_]*$/.test(apiKeyEnv)) {
		return {
			kind: "repi-model-add-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: `invalid api key env name: ${apiKeyEnv}`,
		};
	}
	const modelsConfig = readJsonObject(modelsPath, { providers: {} });
	if (!modelsConfig.providers || typeof modelsConfig.providers !== "object" || Array.isArray(modelsConfig.providers)) {
		modelsConfig.providers = {};
	}
	const previousProvider = modelsConfig.providers[providerId] && typeof modelsConfig.providers[providerId] === "object" ? modelsConfig.providers[providerId] : {};
	const modelEntry = {
		id: modelId,
		name: flagValue(rawArgs, ["--model-name", "--name"], modelId),
		input: inputList(flagValue(rawArgs, "--input", "text")),
		cost: costFromFlags(rawArgs),
		contextWindow: intFlag(rawArgs, ["--context-window", "--context"], 262144, 1024, 1048576),
		maxTokens: intFlag(rawArgs, ["--max-tokens", "--max-output"], 16384, 64, 131072),
		reasoning: rawArgs.includes("--reasoning") ? boolFlag(rawArgs, "--reasoning", true) : boolFlag(rawArgs, "--reasoning", false),
	};
	const oldModels = Array.isArray(previousProvider.models) ? previousProvider.models : [];
	const nextModels = [...oldModels.filter((model) => model?.id !== modelId), modelEntry];
	const authHeader =
		rawArgs.includes("--auth-header") || rawArgs.includes("--authHeader")
			? boolFlag(rawArgs, ["--auth-header", "--authHeader"], true)
			: previousProvider.authHeader;
	modelsConfig.providers[providerId] = {
		...previousProvider,
		name: flagValue(rawArgs, "--provider-name", previousProvider.name ?? providerId),
		baseUrl,
		api,
		apiKey: `$${apiKeyEnv}`,
		...(authHeader === undefined ? {} : { authHeader }),
		models: nextModels,
	};
	writeJsonFile(modelsPath, modelsConfig, 0o600);
	let authWritten = false;
	if (apiKey) {
		const auth = readJsonObject(authPath, {});
		auth[providerId] = { type: "api_key", key: apiKey };
		writeJsonFile(authPath, auth, 0o600);
		authWritten = true;
	}
	let settingsPath = undefined;
	if (rawArgs.includes("--set-default") || rawArgs.includes("--default")) settingsPath = upsertDefaultSetting(providerId, modelId);
	return {
		kind: "repi-model-add-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		preset: null,
		provider: providerId,
		model: modelId,
		api,
		baseUrl: displayUrl(baseUrl),
		baseUrlHidden: !showUrls(),
		apiKey: `$${apiKeyEnv}`,
		apiKeyEnvPresent: Boolean(process.env[apiKeyEnv]),
		authWritten,
		modelsPath,
		authPath,
		settingsPath,
		next: [
			...(authWritten || process.env[apiKeyEnv] ? [] : [`repi model login --provider ${providerId} --api-key-stdin`]),
			`repi model test --provider ${providerId} --model ${modelId}`,
			`repi --provider ${providerId} --model ${modelId}`,
		],
	};
}

function buildEditReport() {
	const providerId = flagValue(rawArgs, "--provider") || positional(rawArgs, 0);
	const modelId = flagValue(rawArgs, "--model");
	if (!providerId) {
		return {
			kind: "repi-model-edit-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model edit requires --provider <id> [--model <id>]",
		};
	}
	const modelsConfig = readJsonObject(modelsPath, { providers: {} });
	const provider = modelsConfig.providers?.[providerId];
	if (!provider || typeof provider !== "object") {
		return {
			kind: "repi-model-edit-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: `provider not found: ${providerId}`,
		};
	}
	const beforeModelCount = Array.isArray(provider.models) ? provider.models.length : 0;
	if (hasFlag(rawArgs, "--provider-name")) provider.name = flagValue(rawArgs, "--provider-name", provider.name);
	if (hasFlag(rawArgs, ["--base-url", "--baseUrl"])) provider.baseUrl = flagValue(rawArgs, ["--base-url", "--baseUrl"], provider.baseUrl);
	if (hasFlag(rawArgs, "--api")) {
		const api = flagValue(rawArgs, "--api", provider.api);
		if (!allowedApis.has(api)) {
			return {
				kind: "repi-model-edit-report",
				schemaVersion: 1,
				generatedAt: new Date().toISOString(),
				ok: false,
				error: `unsupported api=${api}; allowed=${[...allowedApis].join(",")}`,
			};
		}
		provider.api = api;
	}
	if (hasFlag(rawArgs, ["--api-key-env", "--env"])) {
		const apiKeyEnv = flagValue(rawArgs, ["--api-key-env", "--env"], providerEnvName(providerId));
		if (!/^[A-Z_][A-Z0-9_]*$/.test(apiKeyEnv)) {
			return {
				kind: "repi-model-edit-report",
				schemaVersion: 1,
				generatedAt: new Date().toISOString(),
				ok: false,
				error: `invalid api key env name: ${apiKeyEnv}`,
			};
		}
		provider.apiKey = `$${apiKeyEnv}`;
	}
	if (hasFlag(rawArgs, ["--auth-header", "--authHeader"])) provider.authHeader = boolFlag(rawArgs, ["--auth-header", "--authHeader"], true);
	if (!modelId) {
		writeJsonFile(modelsPath, modelsConfig, 0o600);
		return {
			kind: "repi-model-edit-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: true,
			provider: providerId,
			modelsPath,
			changed: ["provider"],
			beforeModelCount,
			next: [`repi model doctor`, `repi model list --provider ${providerId}`],
		};
	}
	const models = Array.isArray(provider.models) ? provider.models : [];
	const index = models.findIndex((model) => model?.id === modelId);
	if (index < 0) {
		return {
			kind: "repi-model-edit-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: `model not found: ${providerId}/${modelId}`,
		};
	}
	const model = { ...models[index] };
	if (hasFlag(rawArgs, ["--model-name", "--name"])) model.name = flagValue(rawArgs, ["--model-name", "--name"], model.name ?? model.id);
	if (hasFlag(rawArgs, "--id")) model.id = flagValue(rawArgs, "--id", model.id);
	if (hasFlag(rawArgs, "--input")) model.input = inputList(flagValue(rawArgs, "--input", "text"));
	const contextWindow = maybeIntFlag(rawArgs, ["--context-window", "--context"], 1024, 1048576);
	if (contextWindow !== undefined) model.contextWindow = contextWindow;
	const maxTokens = maybeIntFlag(rawArgs, ["--max-tokens", "--max-output"], 64, 131072);
	if (maxTokens !== undefined) model.maxTokens = maxTokens;
	if (hasFlag(rawArgs, "--reasoning")) model.reasoning = boolFlag(rawArgs, "--reasoning", true);
	model.cost = costPatchFromFlags(rawArgs, model.cost ?? {});
	models[index] = model;
	provider.models = models;
	writeJsonFile(modelsPath, modelsConfig, 0o600);
	return {
		kind: "repi-model-edit-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		provider: providerId,
		model: model.id,
		modelsPath,
		changed: ["provider", "model"],
		next: [`repi model doctor`, `repi model test --provider ${providerId} --model ${model.id}`],
	};
}

function buildRemoveReport() {
	const providerId = flagValue(rawArgs, "--provider") || positional(rawArgs, 0);
	const modelId = flagValue(rawArgs, "--model") || positional(rawArgs, providerId && positional(rawArgs, 0) === providerId ? 1 : 0);
	if (!providerId) {
		return {
			kind: "repi-model-remove-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model remove requires --provider <id> [--model <id>]",
		};
	}
	const modelsConfig = readJsonObject(modelsPath, { providers: {} });
	if (!modelsConfig.providers?.[providerId]) {
		return {
			kind: "repi-model-remove-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: `provider not found: ${providerId}`,
		};
	}
	if (!modelId || modelId === providerId) {
		delete modelsConfig.providers[providerId];
		writeJsonFile(modelsPath, modelsConfig, 0o600);
		return {
			kind: "repi-model-remove-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: true,
			provider: providerId,
			removed: "provider",
			modelsPath,
			next: ["repi model list", "repi model doctor"],
		};
	}
	const provider = modelsConfig.providers[providerId];
	const models = Array.isArray(provider.models) ? provider.models : [];
	const before = models.length;
	provider.models = models.filter((model) => model?.id !== modelId);
	if (provider.models.length === before) {
		return {
			kind: "repi-model-remove-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: `model not found: ${providerId}/${modelId}`,
		};
	}
	writeJsonFile(modelsPath, modelsConfig, 0o600);
	return {
		kind: "repi-model-remove-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		provider: providerId,
		model: modelId,
		removed: "model",
		beforeModelCount: before,
		afterModelCount: provider.models.length,
		modelsPath,
		next: ["repi model list", "repi model doctor"],
	};
}

function sanitizeProviderConfig(providerId, provider) {
	const next = { ...(provider && typeof provider === "object" ? provider : {}) };
	if (typeof next.apiKey !== "string" || !next.apiKey.startsWith("$")) {
		next.apiKey = `$${providerEnvName(providerId)}`;
	}
	if (!Array.isArray(next.models)) next.models = [];
	next.models = next.models.map((model) => ({
		...model,
		id: String(model?.id ?? "").trim(),
		name: model?.name ?? model?.id,
		input: Array.isArray(model?.input) ? model.input : inputList(model?.input),
		contextWindow: Number(model?.contextWindow ?? 262144),
		maxTokens: Number(model?.maxTokens ?? 16384),
		cost: costOf(model, next),
	})).filter((model) => model.id);
	return next;
}

function sanitizedConfigForExport() {
	const loaded = loadProviders();
	const providers = {};
	for (const [providerId, provider] of Object.entries(loaded.providers)) providers[providerId] = sanitizeProviderConfig(providerId, provider);
	return { providers };
}

function buildExportReport() {
	const output = flagValue(rawArgs, ["--output", "-o"]);
	const config = sanitizedConfigForExport();
	if (output) writeJsonFile(resolve(output), config, 0o600);
	return {
		kind: "repi-model-export-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		modelsPath,
		outputPath: output ? resolve(output) : null,
		providerCount: Object.keys(config.providers).length,
		modelCount: Object.values(config.providers).reduce((sum, provider) => sum + (Array.isArray(provider.models) ? provider.models.length : 0), 0),
		exportedConfig: config,
		redaction: "auth.json is not exported; literal apiKey fields are converted to $REPI_<PROVIDER>_API_KEY env refs",
	};
}

function buildImportReport() {
	const input = flagValue(rawArgs, ["--input", "-i"]) || positional(rawArgs, 0);
	if (!input) {
		return {
			kind: "repi-model-import-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model import requires --input <path|->",
		};
	}
	let imported;
	try {
		imported = JSON.parse(input === "-" ? readStdinBounded("model import", { maxBytes: 4 * 1024 * 1024 }) : readFileSync(resolve(input), "utf8"));
	} catch (error) {
		return {
			kind: "repi-model-import-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: `failed to read import JSON: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	const importedProviders = imported?.providers && typeof imported.providers === "object" && !Array.isArray(imported.providers) ? imported.providers : undefined;
	if (!importedProviders) {
		return {
			kind: "repi-model-import-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "import JSON must contain a providers object",
		};
	}
	const current = rawArgs.includes("--replace") ? { providers: {} } : readJsonObject(modelsPath, { providers: {} });
	if (!current.providers || typeof current.providers !== "object" || Array.isArray(current.providers)) current.providers = {};
	const importedIds = [];
	for (const [providerId, provider] of Object.entries(importedProviders)) {
		current.providers[providerId] = sanitizeProviderConfig(providerId, provider);
		importedIds.push(providerId);
	}
	writeJsonFile(modelsPath, current, 0o600);
	return {
		kind: "repi-model-import-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		modelsPath,
		authPath,
		mode: rawArgs.includes("--replace") ? "replace" : "merge",
		importedProviders: importedIds,
		next: ["repi model list", "repi model login --provider <id> --api-key-stdin", "repi model doctor"],
	};
}

function buildLoginReport() {
	const providerId = flagValue(rawArgs, "--provider") || positional(rawArgs, 0);
	if (!providerId) {
		return {
			kind: "repi-model-login-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model login requires --provider <id>",
		};
	}
	let apiKey = flagValue(rawArgs, "--api-key");
	if (apiKey && !insecureApiKeyArgAllowed()) {
		return {
			kind: "repi-model-login-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "plain --api-key is disabled to avoid shell history/process-list leaks; use --api-key-stdin, or set REPI_ALLOW_INSECURE_API_KEY_ARG=1 explicitly",
		};
	}
	if (!apiKey && rawArgs.includes("--api-key-stdin")) {
		try {
			apiKey = readStdinBounded("model login api key", { maxBytes: 64 * 1024 }).trim();
		} catch (error) {
			return {
				kind: "repi-model-login-report",
				schemaVersion: 1,
				generatedAt: new Date().toISOString(),
				ok: false,
				error: error instanceof Error ? error.message : String(error),
			};
		}
	}
	if (!apiKey) {
		return {
			kind: "repi-model-login-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model login requires --api-key-stdin",
		};
	}
	const auth = readJsonObject(authPath, {});
	auth[providerId] = { type: "api_key", key: apiKey };
	writeJsonFile(authPath, auth, 0o600);
	return {
		kind: "repi-model-login-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		provider: providerId,
		authPath,
		next: [`repi model test --provider ${providerId} --model <model-id>`],
	};
}

function buildDefaultReport() {
	const providerId = flagValue(rawArgs, "--provider") || positional(rawArgs, 0);
	const modelId = flagValue(rawArgs, "--model") || positional(rawArgs, providerId && positional(rawArgs, 0) === providerId ? 1 : 0);
	if (!providerId || !modelId) {
		return {
			kind: "repi-model-default-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model default requires --provider <id> --model <id>",
		};
	}
	const loaded = loadProviders();
	if (loaded.providers?.[providerId] && !modelExistsInProvider(loaded.providers[providerId], modelId)) {
		return {
			kind: "repi-model-default-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			provider: providerId,
			model: modelId,
			error: `model not found under provider ${providerId}; run repi model list --provider ${providerId}`,
		};
	}
	const settingsPath = upsertDefaultSetting(providerId, modelId);
	return {
		kind: "repi-model-default-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		provider: providerId,
		model: modelId,
		settingsPath,
		next: ["repi model doctor", "repi"],
	};
}

function modelConfigStats(config) {
	const providers =
		config?.providers && typeof config.providers === "object" && !Array.isArray(config.providers)
			? config.providers
			: {};
	return {
		providerCount: Object.keys(providers).length,
		modelCount: Object.values(providers).reduce(
			(sum, provider) => sum + (Array.isArray(provider?.models) ? provider.models.length : 0),
			0,
		),
	};
}

function existingJsonObject(path) {
	if (!existsSync(path)) return { existed: false, data: {}, parseError: null };
	const parsed = readJson(path);
	if (parsed?.__error) return { existed: true, data: {}, parseError: parsed.__error };
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		return { existed: true, data: {}, parseError: "expected JSON object" };
	}
	return { existed: true, data: parsed, parseError: null };
}

function buildResetReport() {
	const confirmed = hasFlag(rawArgs, ["--yes", "--force", "-y"]);
	const deleteAuth = hasFlag(rawArgs, ["--delete-auth", "--wipe-auth"]);
	if (!confirmed) {
		return {
			kind: "repi-model-reset-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model reset requires --yes (or --force); it clears saved providers/default model selection. auth.json is preserved unless --delete-auth is set.",
			agentDir,
			modelsPath,
			settingsPath,
			authPath,
			next: ["repi model reset --yes", "repi model status"],
		};
	}

	const beforeModels = existingJsonObject(modelsPath);
	const beforeSettings = existingJsonObject(settingsPath);
	const beforeAuth = existingJsonObject(authPath);
	const beforeStats = modelConfigStats(beforeModels.data);
	const settings = { ...beforeSettings.data };
	const removedSettings = [];
	for (const key of ["defaultProvider", "defaultModel", "defaultThinkingLevel", "enabledModels"]) {
		if (Object.prototype.hasOwnProperty.call(settings, key)) {
			delete settings[key];
			removedSettings.push(key);
		}
	}

	writeJsonFile(modelsPath, { providers: {} }, 0o600);
	writeJsonFile(settingsPath, settings, 0o600);
	if (deleteAuth) {
		writeJsonFile(authPath, {}, 0o600);
	}

	return {
		kind: "repi-model-reset-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		agentDir,
		modelsPath,
		settingsPath,
		authPath,
		preservedAuth: !deleteAuth,
		deletedAuth: deleteAuth,
		before: {
			modelsJsonExisted: beforeModels.existed,
			modelsJsonParseError: beforeModels.parseError,
			providerCount: beforeStats.providerCount,
			modelCount: beforeStats.modelCount,
			settingsJsonExisted: beforeSettings.existed,
			settingsJsonParseError: beforeSettings.parseError,
			authJsonExisted: beforeAuth.existed,
			authJsonParseError: beforeAuth.parseError,
		},
		after: {
			providerCount: 0,
			modelCount: 0,
			removedSettings,
		},
		next: [
			'export REPI_AUTH_TOKEN="sk-..." REPI_BASE_URL="https://gateway.example/v1" REPI_MODEL="vendor/model" REPI_MODEL_API="openai-compatible"',
			"repi model status",
			"repi --list-models",
		],
	};
}

function buildTestReport() {
	const providerId = flagValue(rawArgs, "--provider") || positional(rawArgs, 0);
	const modelId = flagValue(rawArgs, "--model") || positional(rawArgs, providerId && positional(rawArgs, 0) === providerId ? 1 : 0);
	const testTimeoutMs = intFlag(rawArgs, "--timeout-ms", 120_000, 5000, 30 * 60 * 1000);
	if (!providerId || !modelId) {
		return {
			kind: "repi-model-test-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model test requires --provider <id> --model <id>",
		};
	}
	const result = spawnSync(
		join(root, "repi"),
		[
			"--approve",
			"--provider",
			providerId,
			"--model",
			modelId,
			"--thinking",
			"off",
			"--no-session",
			"--no-tools",
			"-p",
			"Reply exactly: REPI_MODEL_OK",
		],
		{
			cwd: root,
			env: {
				...process.env,
				REPI_SKIP_VERSION_CHECK: "1",
				REPI_SKIP_PACKAGE_UPDATE_CHECK: "1",
				REPI_TELEMETRY: "0",
				REPI_PRINT_PROGRESS: "0",
			},
			encoding: "utf8",
			timeout: testTimeoutMs,
			maxBuffer: 4 * 1024 * 1024,
		},
	);
	const stdout = redact(result.stdout ?? "");
	const stderr = redact(result.stderr ?? "");
	const exit = result.status ?? (result.signal ? 128 : 1);
	return {
		kind: "repi-model-test-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: exit === 0 && /REPI_MODEL_OK/.test(stdout),
		provider: providerId,
		model: modelId,
		exit,
		signal: result.signal,
		timeoutMs: testTimeoutMs,
		stdoutTail: stdout.slice(-2000),
		stderrTail: stderr.slice(-2000),
		error: result.error ? String(result.error.message || result.error) : undefined,
	};
}

function printDoctor(report) {
	console.log("REPI Model Doctor");
	console.log(`modelsPath: ${report.modelsPath}`);
	console.log(`authPath: ${report.authPath}`);
	if (report.settingsPath) console.log(`settingsPath: ${report.settingsPath}`);
	if (report.defaultModel) console.log(`default: ${report.defaultModel.providerId ?? "<unset>"}/${report.defaultModel.modelId ?? "<unset>"} :: ${report.defaultModel.ok ? "ok" : "bad"} (${report.defaultModel.message})`);
	for (const action of report.fixActions ?? []) console.log(`${action.status === "fixed" ? "FIXED" : "FIX"} ${action.id}: ${action.detail}`);
	console.log(`providers=${report.providerCount} models=${report.modelCount} listModelsExit=${report.listModels.exit}`);
		for (const provider of report.providers) {
		console.log(`- ${provider.id}: api=${provider.api} baseUrl=${provider.baseUrl} apiKey=${provider.apiKey}`);
		for (const issue of provider.issues) console.log(`  WARN ${issue}`);
		for (const model of provider.models) {
			console.log(`  model=${model.id} ctx=${model.contextWindow} max=${model.maxTokens} cost=${costText(model.cost)}`);
			for (const tier of model.cost.tiers ?? []) {
				console.log(`    tier inputTokensAbove:${tier.inputTokensAbove} ${costText(tier)}`);
			}
			for (const issue of model.issues) console.log(`    WARN ${issue}`);
		}
	}
	for (const diagnostic of report.diagnostics) console.log(`${diagnostic.level.toUpperCase()} ${diagnostic.id}: ${diagnostic.message}`);
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
}

function printCost(report) {
	if (!report.ok) {
		console.error(report.error);
		return;
	}
	console.log("REPI Model Cost");
	console.log(`provider=${report.provider} model=${report.model}`);
	console.log(`rates(USD/1M): input=${report.rates.input} output=${report.rates.output} cacheRead=${report.rates.cacheRead} cacheWrite=${report.rates.cacheWrite}`);
	if (report.selectedTier) console.log(`selectedTier=inputTokensAbove:${report.selectedTier.inputTokensAbove}`);
	if (report.costTiers?.length) console.log(`configuredTiers=${report.costTiers.length}`);
	console.log(`tokens: input=${report.tokens.input} output=${report.tokens.output} cacheRead=${report.tokens.cacheRead} cacheWrite=${report.tokens.cacheWrite}`);
	console.log(`estimatedUsd=${report.estimatedUsd.toFixed(8)}`);
}

function printList(report) {
	if (!report.ok) {
		console.error(report.error);
		return;
	}
	console.log("REPI Model List");
	console.log(`modelsPath=${report.modelsPath}`);
	console.log(`providers=${report.providerCount} models=${report.modelCount}`);
	if (!report.rows.length) {
		console.log("No configured custom models.");
		console.log("next: repi model add --provider openai-compatible --api openai-completions --base-url https://gateway.example/v1 --model provider/model-id");
		return;
	}
	for (const row of report.rows) {
		console.log(`- ${row.provider}/${row.model} api=${row.api} ctx=${row.contextWindow} max=${row.maxTokens} auth=${row.auth}`);
		console.log(`  baseUrl=${row.baseUrl}`);
		console.log(`  cost=${costText(row.cost)}`);
		for (const tier of row.cost.tiers ?? []) {
			console.log(`  tier inputTokensAbove:${tier.inputTokensAbove} ${costText(tier)}`);
		}
	}
}

function formatTokenCount(count) {
	if (count >= 1_000_000) {
		const millions = count / 1_000_000;
		return millions % 1 === 0 ? `${millions}M` : `${millions.toFixed(1)}M`;
	}
	if (count >= 1_000) {
		const thousands = count / 1_000;
		return thousands % 1 === 0 ? `${thousands}K` : `${thousands.toFixed(1)}K`;
	}
	return count.toString();
}

function printCliList(report) {
	if (!report.ok) {
		console.error(report.error);
		return;
	}
	for (const warning of report.warnings) console.error(`Warning: ${warning}`);
	if (!report.rows.length) {
		console.log(`No models available. Configure a model with REPI_* environment variables (Claude Code-style) or ~/.repi/agent/models.json. See:
  ${join(root, "packages", "coding-agent", "docs", "repi-runtime-configuration.md")}
  ${join(root, "packages", "coding-agent", "docs", "model-provider-formats.md")}

Quick env-only path:
  export REPI_AUTH_TOKEN=sk-...
  export REPI_BASE_URL=https://gateway.example/v1
  export REPI_PROVIDER=gateway  # optional; footer/provider id
  export REPI_MODEL=vendor/model-id
  export REPI_MODEL_API=openai-compatible
  export REPI_AUTO_COMPACT_WINDOW=262144  # optional alias of REPI_CONTEXT_WINDOW
  repi --list-models
  repi -p "Reply exactly: REPI_OK"`);
		return;
	}

	const rows = report.rows
		.map((row) => ({
			provider: row.provider,
			model: row.model,
			context: formatTokenCount(row.contextWindow),
			maxOut: formatTokenCount(row.maxTokens),
			thinking: row.reasoning ? "yes" : "no",
			images: row.input.includes("image") ? "yes" : "no",
			pricing: `${row.cost.input}/${row.cost.output}/${row.cost.cacheRead}/${row.cost.cacheWrite}${row.cost.tiers?.length ? `+${row.cost.tiers.length}t` : ""}`,
		}))
		.sort((left, right) => left.provider.localeCompare(right.provider) || left.model.localeCompare(right.model));
	const headers = {
		provider: "provider",
		model: "model",
		context: "context",
		maxOut: "max-out",
		thinking: "thinking",
		images: "images",
		pricing: "cost in/out/read/write ($/1M)",
	};
	const widths = Object.fromEntries(
		Object.entries(headers).map(([key, label]) => [key, Math.max(label.length, ...rows.map((row) => row[key].length))]),
	);
	const line = (row) =>
		[
			row.provider.padEnd(widths.provider),
			row.model.padEnd(widths.model),
			row.context.padEnd(widths.context),
			row.maxOut.padEnd(widths.maxOut),
			row.thinking.padEnd(widths.thinking),
			row.images.padEnd(widths.images),
			row.pricing.padEnd(widths.pricing),
		].join("  ");
	console.log(line(headers));
	for (const row of rows) console.log(line(row));
}

function printStatus(report) {
	console.log("REPI Model Status");
	console.log(`effective=${report.effective.source} provider=${report.effective.provider ?? "<unset>"} model=${report.effective.model ?? "<unset>"}`);
	if (report.effective.api) console.log(`api=${report.effective.api}`);
	if (report.effective.contextWindow) console.log(`contextWindow=${report.effective.contextWindow} maxTokens=${report.effective.maxTokens}`);
	if (report.effective.cost) console.log(`effective.cost=${costText(report.effective.cost)}`);
	console.log(`env.enabled=${report.env.enabled} env.provider=${report.env.provider} env.model=${report.env.model ?? "<unset>"}`);
	console.log(`env.baseUrl=${report.env.baseUrl ?? "<unset>"} auth=${report.env.authEnv}:${report.env.authPresent ? "set" : "missing"}`);
	console.log(
		`env.metadata=input:${report.env.input.join(",")}/reasoning:${report.env.reasoning}/authHeader:${report.env.authHeader}/providerHeaders:${report.env.headers.provider.join(",") || "none"}/modelHeaders:${report.env.headers.model.join(",") || "none"}/providerCompat:${report.env.compatConfigured.provider}/modelCompat:${report.env.compatConfigured.model}/thinkingMap:${report.env.thinkingLevelMapConfigured}`,
	);
	console.log(`env.cost=${costText(report.env.cost)}`);
	for (const tier of report.env.cost.tiers ?? []) {
		console.log(`env.cost.tier inputTokensAbove:${tier.inputTokensAbove} ${costText(tier)}`);
	}
	if (report.env.subagentModel) console.log(`env.subagentModel=${report.env.subagentModel}`);
	for (const diagnostic of report.diagnostics ?? []) console.log(`${diagnostic.level.toUpperCase()} ${diagnostic.id}: ${diagnostic.message}`);
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
}

function printExport(report) {
	if (!report.ok) {
		console.error(report.error);
		return;
	}
	if (report.outputPath) {
		console.log("REPI Model Export");
		console.log(`output=${report.outputPath}`);
		console.log(`providers=${report.providerCount} models=${report.modelCount}`);
		console.log(report.redaction);
		return;
	}
	console.log(JSON.stringify(report.exportedConfig, null, 2));
}

function printMutationReport(title, report) {
	if (!report.ok) {
		// `error` is only set when the spawned child itself fails to launch
		// (e.g. ENOENT). For a model `test` that runs but the provider returns
		// an HTTP error, `error` is undefined and the useful diagnostics are
		// `exit` + `stderrTail` — print those instead of a bare `undefined`.
		if (report.error) console.error(report.error);
		if (report.exit !== undefined) {
			console.error(`exit=${report.exit} ok=${report.ok}`);
			if (report.stdoutTail) console.error(`stdout: ${report.stdoutTail.replace(/\n/g, "\\n").slice(-800)}`);
			if (report.stderrTail) console.error(`stderr: ${report.stderrTail.replace(/\n/g, "\\n").slice(-800)}`);
		}
		console.error(`verdict: ${report.ok ? "pass" : "fail"}`);
		return;
	}
	console.log(title);
	if (report.preset) console.log(`preset=${report.preset}`);
	if (report.provider) console.log(`provider=${report.provider}`);
	if (report.model) console.log(`model=${report.model}`);
	if (report.api) console.log(`api=${report.api}`);
	if (report.baseUrl) console.log(`baseUrl=${report.baseUrl}`);
	if (report.apiKey) console.log(`apiKey=${report.apiKey}${report.apiKeyEnvPresent ? " (env set)" : " (env missing)"}`);
	if (report.modelsPath) console.log(`modelsPath=${report.modelsPath}`);
	if (report.authPath) console.log(`authPath=${report.authPath}${report.authWritten ? " (updated)" : ""}`);
	if (report.settingsPath) console.log(`settingsPath=${report.settingsPath}`);
	if (report.removed) console.log(`removed=${report.removed}`);
	if (report.mode) console.log(`mode=${report.mode}`);
	if (report.importedProviders) console.log(`importedProviders=${report.importedProviders.join(",")}`);
	if (report.exit !== undefined) {
		console.log(`exit=${report.exit} ok=${report.ok}`);
		if (report.stdoutTail) console.log(`stdout: ${report.stdoutTail.replace(/\n/g, "\\n").slice(-800)}`);
		if (report.stderrTail) console.log(`stderr: ${report.stderrTail.replace(/\n/g, "\\n").slice(-800)}`);
	}
	for (const next of report.next ?? []) console.log(`next: ${next}`);
	console.log(`verdict: ${report.ok ? "pass" : "fail"}`);
}

if (command === "help" || command === "--help" || command === "-h") {
	console.log(usage());
	process.exit(0);
}
if (
	![
		"doctor",
		"status",
		"list",
		"cost",
		"add",
		"edit",
		"remove",
		"login",
		"test",
		"default",
		"reset",
		"export",
		"import",
	].includes(command)
) {
	console.error(`Unknown model command: ${command}`);
	console.error(usage());
	process.exit(2);
}

const report =
	command === "list" && rawArgs.includes("--cli-format")
		? buildCliListReport()
		: command === "status"
		? buildStatusReport()
		: command === "list"
		? buildListReport()
		: command === "cost"
		? buildCostReport()
		: command === "add"
			? buildAddReport()
			: command === "edit"
				? buildEditReport()
				: command === "remove"
					? buildRemoveReport()
					: command === "login"
						? buildLoginReport()
						: command === "default"
							? buildDefaultReport()
							: command === "reset"
								? buildResetReport()
								: command === "test"
									? buildTestReport()
									: command === "export"
										? buildExportReport()
										: command === "import"
											? buildImportReport()
											: buildDoctorReport();
if (json) console.log(JSON.stringify(report, null, 2));
else if (command === "list" && rawArgs.includes("--cli-format")) printCliList(report);
else if (command === "status") printStatus(report);
else if (command === "list") printList(report);
else if (command === "cost") printCost(report);
else if (command === "add") printMutationReport("REPI Model Add", report);
else if (command === "edit") printMutationReport("REPI Model Edit", report);
else if (command === "remove") printMutationReport("REPI Model Remove", report);
else if (command === "login") printMutationReport("REPI Model Login", report);
else if (command === "default") printMutationReport("REPI Model Default", report);
else if (command === "reset") printMutationReport("REPI Model Reset", report);
else if (command === "test") printMutationReport("REPI Model Test", report);
else if (command === "export") printExport(report);
else if (command === "import") printMutationReport("REPI Model Import", report);
else printDoctor(report);
process.exit(report.ok ? 0 : 1);

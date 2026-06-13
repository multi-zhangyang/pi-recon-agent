#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

const rawArgs = process.argv.slice(2);
const knownCommands = new Set(["doctor", "status", "list", "cost", "add", "edit", "remove", "login", "test", "default", "export", "import", "help"]);
let root = process.cwd();
if (rawArgs[0] && !rawArgs[0].startsWith("--") && !knownCommands.has(rawArgs[0])) {
	root = resolve(rawArgs.shift());
}
const helpRequested = rawArgs.includes("--help") || rawArgs.includes("-h");
const command = helpRequested ? "help" : rawArgs[0] && !rawArgs[0].startsWith("--") ? rawArgs.shift() : "doctor";
const json = rawArgs.includes("--json");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const modelsPath = join(agentDir, "models.json");
const authPath = join(agentDir, "auth.json");
const allowedApis = new Set(["openai-completions", "openai-responses", "anthropic-messages"]);

function usage() {
	return `Usage:
  repi model doctor [--json]
  repi model list [--provider <id>] [--model <id>] [--show-urls] [--json]
  repi model add --provider <id> --api <openai-completions|openai-responses|anthropic-messages> --base-url <url> --model <id> [options]
  repi model edit --provider <id> [--model <id>] [options]
  repi model remove --provider <id> [--model <id>] [--json]
  repi model login --provider <id> --api-key <key>
  repi model login --provider <id> --api-key-stdin
  repi model default --provider <id> --model <id>
  repi model test --provider <id> --model <id> [--timeout-ms N]
  repi model cost --provider <id> --model <id> --input-tokens N --output-tokens N [--cache-read-tokens N] [--cache-write-tokens N]
  repi model export [--output <path>] [--json]
  repi model import --input <path|-> [--merge|--replace] [--json]

model doctor is offline: it parses ~/.repi/agent/models.json, checks provider/model metadata, env-key references, context window and cost fields.
model list hides provider base URLs by default to avoid leaking private gateway endpoints into screenshots/logs; add --show-urls for local troubleshooting.
model add writes ~/.repi/agent/models.json with env-ref credentials by default; model login writes ~/.repi/agent/auth.json locally.
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
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`, { encoding: "utf8", mode });
	try {
		chmodSync(path, mode);
	} catch {
		// Best-effort on non-POSIX filesystems.
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

function positional(args, offset = 0) {
	return args.filter((arg) => !arg.startsWith("--"))[offset];
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

function storedAuthStatus(authData, providerId) {
	const credential = authData && typeof authData === "object" ? authData[providerId] : undefined;
	if (!credential || typeof credential !== "object") return { configured: false, source: "none" };
	if (credential.type === "api_key" && typeof credential.key === "string" && credential.key.length > 0)
		return { configured: true, source: "auth.json:api_key" };
	if (credential.type === "oauth") return { configured: true, source: "auth.json:oauth" };
	return { configured: false, source: "invalid-auth-entry" };
}

function costOf(model, provider) {
	return {
		input: Number(model.cost?.input ?? provider.cost?.input ?? 0),
		output: Number(model.cost?.output ?? provider.cost?.output ?? 0),
		cacheRead: Number(model.cost?.cacheRead ?? provider.cost?.cacheRead ?? 0),
		cacheWrite: Number(model.cost?.cacheWrite ?? provider.cost?.cacheWrite ?? 0),
	};
}

function loadProviders() {
	if (!existsSync(modelsPath)) return { providers: {}, parseError: null, missing: true };
	const parsed = readJson(modelsPath);
	if (parsed?.__error) return { providers: {}, parseError: parsed.__error, missing: false };
	const providers = parsed?.providers && typeof parsed.providers === "object" && !Array.isArray(parsed.providers) ? parsed.providers : {};
	return { providers, parseError: null, missing: false };
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

function buildDoctorReport() {
	const loaded = loadProviders();
	const authData = readJson(authPath);
	const providerRows = [];
	const diagnostics = [];
	let modelCount = 0;
	if (loaded.parseError) diagnostics.push({ level: "fail", id: "models-json-parse", message: loaded.parseError });
	if (loaded.missing) diagnostics.push({ level: "warn", id: "models-json-missing", message: `${modelsPath} not found; built-in providers may still work` });
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
		if (key.kind === "literal") issues.push("apiKey is literal in models.json; prefer auth.json or $ENV_NAME");
		if (key.kind === "missing" && !storedAuth.configured) issues.push("missing apiKey env reference or auth.json credential");
		if (key.kind === "env" && !key.present && !storedAuth.configured) issues.push(`env ${key.env} is not set and no auth.json credential exists`);
		if (!models.length) issues.push("provider has no models[]");
		const modelRows = models.map((model) => {
			const cost = costOf(model, provider);
			const modelIssues = [];
			if (!model.id) modelIssues.push("missing id");
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
				? `${storedAuth.source} (${key.kind === "env" ? `models ref $${key.env}; env ${key.present ? "set" : "missing"}` : `models ${key.kind}`})`
				: key.kind === "env"
					? `$${key.env} (${key.present ? "set" : "missing"})`
					: key.kind,
			authConfigured,
			models: modelRows,
			issues,
		});
	}
	const listModels = listModelsProbe();
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
	const total =
		(inputTokens * cost.input +
			outputTokens * cost.output +
			cacheReadTokens * cost.cacheRead +
			cacheWriteTokens * cost.cacheWrite) /
		1_000_000;
	return {
		kind: "repi-model-cost-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		ok: true,
		provider: found.providerId,
		model: found.model.id,
		unit: "USD per 1M tokens",
		tokens: { input: inputTokens, output: outputTokens, cacheRead: cacheReadTokens, cacheWrite: cacheWriteTokens },
		rates: cost,
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
		ok: !loaded.parseError && !filterMissing,
		agentDir,
		modelsPath,
		authPath,
		provider: providerFilter ?? null,
		model: modelFilter ?? null,
		baseUrlHidden: !showUrls(),
		providerCount: providerFilter ? (Object.prototype.hasOwnProperty.call(loaded.providers, providerFilter) ? 1 : 0) : Object.keys(loaded.providers).length,
		modelCount: rows.length,
		rows,
		error: loaded.parseError ?? (filterMissing ? `model list found no rows for provider=${providerFilter ?? "<any>"} model=${modelFilter ?? "<any>"}` : undefined),
	};
}

function providerEnvName(providerId) {
	return `REPI_${String(providerId)
		.toUpperCase()
		.replace(/[^A-Z0-9]+/g, "_")
		.replace(/^_+|_+$/g, "")}_API_KEY`;
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
	const providerId = flagValue(rawArgs, "--provider") ?? positional(rawArgs, 0);
	const modelId = flagValue(rawArgs, "--model");
	const api = flagValue(rawArgs, "--api", "openai-completions");
	const baseUrl = flagValue(rawArgs, ["--base-url", "--baseUrl"]);
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
	const apiKey = flagValue(rawArgs, "--api-key");
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
			...(authWritten || process.env[apiKeyEnv] ? [] : [`export ${apiKeyEnv}=...`]),
			`repi model test --provider ${providerId} --model ${modelId}`,
			`repi --provider ${providerId} --model ${modelId}`,
		],
	};
}

function buildEditReport() {
	const providerId = flagValue(rawArgs, "--provider") ?? positional(rawArgs, 0);
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
	const providerId = flagValue(rawArgs, "--provider") ?? positional(rawArgs, 0);
	const modelId = flagValue(rawArgs, "--model") ?? positional(rawArgs, providerId && positional(rawArgs, 0) === providerId ? 1 : 0);
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
		cost: {
			input: Number(model?.cost?.input ?? next.cost?.input ?? 0),
			output: Number(model?.cost?.output ?? next.cost?.output ?? 0),
			cacheRead: Number(model?.cost?.cacheRead ?? next.cost?.cacheRead ?? 0),
			cacheWrite: Number(model?.cost?.cacheWrite ?? next.cost?.cacheWrite ?? 0),
		},
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
	const input = flagValue(rawArgs, ["--input", "-i"]) ?? positional(rawArgs, 0);
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
		imported = JSON.parse(input === "-" ? readFileSync(0, "utf8") : readFileSync(resolve(input), "utf8"));
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
	const providerId = flagValue(rawArgs, "--provider") ?? positional(rawArgs, 0);
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
	if (!apiKey && rawArgs.includes("--api-key-stdin")) {
		apiKey = readFileSync(0, "utf8").trim();
	}
	if (!apiKey) {
		return {
			kind: "repi-model-login-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model login requires --api-key <key> or --api-key-stdin",
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
		keyPreview: redact(apiKey),
		next: [`repi model test --provider ${providerId} --model <model-id>`],
	};
}

function buildDefaultReport() {
	const providerId = flagValue(rawArgs, "--provider") ?? positional(rawArgs, 0);
	const modelId = flagValue(rawArgs, "--model") ?? positional(rawArgs, providerId && positional(rawArgs, 0) === providerId ? 1 : 0);
	if (!providerId || !modelId) {
		return {
			kind: "repi-model-default-report",
			schemaVersion: 1,
			generatedAt: new Date().toISOString(),
			ok: false,
			error: "model default requires --provider <id> --model <id>",
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

function buildTestReport() {
	const providerId = flagValue(rawArgs, "--provider") ?? positional(rawArgs, 0);
	const modelId = flagValue(rawArgs, "--model") ?? positional(rawArgs, providerId && positional(rawArgs, 0) === providerId ? 1 : 0);
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
	console.log(`providers=${report.providerCount} models=${report.modelCount} listModelsExit=${report.listModels.exit}`);
	for (const provider of report.providers) {
		console.log(`- ${provider.id}: api=${provider.api} baseUrl=${provider.baseUrl} apiKey=${provider.apiKey}`);
		for (const issue of provider.issues) console.log(`  WARN ${issue}`);
		for (const model of provider.models) {
			console.log(
				`  model=${model.id} ctx=${model.contextWindow} max=${model.maxTokens} cost=input:${model.cost.input}/output:${model.cost.output}/cacheRead:${model.cost.cacheRead}/cacheWrite:${model.cost.cacheWrite}`,
			);
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
		console.log(`  cost=input:${row.cost.input}/output:${row.cost.output}/cacheRead:${row.cost.cacheRead}/cacheWrite:${row.cost.cacheWrite}`);
	}
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
		console.error(report.error);
		return;
	}
	console.log(title);
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
	if (report.keyPreview) console.log(`key=${report.keyPreview}`);
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
if (!["doctor", "status", "list", "cost", "add", "edit", "remove", "login", "test", "default", "export", "import"].includes(command)) {
	console.error(`Unknown model command: ${command}`);
	console.error(usage());
	process.exit(2);
}

const report =
	command === "list"
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
							: command === "test"
								? buildTestReport()
								: command === "export"
									? buildExportReport()
									: command === "import"
										? buildImportReport()
										: buildDoctorReport();
if (json) console.log(JSON.stringify(report, null, 2));
else if (command === "list") printList(report);
else if (command === "cost") printCost(report);
else if (command === "add") printMutationReport("REPI Model Add", report);
else if (command === "edit") printMutationReport("REPI Model Edit", report);
else if (command === "remove") printMutationReport("REPI Model Remove", report);
else if (command === "login") printMutationReport("REPI Model Login", report);
else if (command === "default") printMutationReport("REPI Model Default", report);
else if (command === "test") printMutationReport("REPI Model Test", report);
else if (command === "export") printExport(report);
else if (command === "import") printMutationReport("REPI Model Import", report);
else printDoctor(report);
process.exit(report.ok ? 0 : 1);

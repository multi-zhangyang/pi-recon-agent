#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

const rawArgs = process.argv.slice(2);
const knownCommands = new Set(["doctor", "status", "cost", "help"]);
let root = process.cwd();
if (rawArgs[0] && !rawArgs[0].startsWith("--") && !knownCommands.has(rawArgs[0])) {
	root = resolve(rawArgs.shift());
}
const helpRequested = rawArgs.includes("--help") || rawArgs.includes("-h");
const command = helpRequested ? "help" : rawArgs[0] && !rawArgs[0].startsWith("--") ? rawArgs.shift() : "doctor";
const json = rawArgs.includes("--json");
const agentDir = process.env.REPI_CODING_AGENT_DIR || process.env.REPI_AGENT_DIR || join(homedir(), ".repi", "agent");
const modelsPath = join(agentDir, "models.json");
const allowedApis = new Set(["openai-completions", "openai-responses", "anthropic-messages"]);

function usage() {
	return `Usage:
  repi model doctor [--json]
  repi model cost --provider <id> --model <id> --input-tokens N --output-tokens N [--cache-read-tokens N] [--cache-write-tokens N]

model doctor is offline: it parses ~/.repi/agent/models.json, checks provider/model metadata, env-key references, context window and cost fields.
`;
}

function readJson(path) {
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch (error) {
		return { __error: error instanceof Error ? error.message : String(error) };
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

function redact(value) {
	return String(value ?? "")
		.replace(/\bsk-[A-Za-z0-9._-]{8,}\b/g, "<redacted:api-key>")
		.replace(/\bghp_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.replace(/\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, "<redacted:github-token>")
		.trim();
}

function envRef(apiKey) {
	if (typeof apiKey !== "string") return { kind: "missing", env: null, present: false };
	if (apiKey.startsWith("$")) {
		const env = apiKey.slice(1);
		return { kind: "env", env, present: Boolean(process.env[env]) };
	}
	return { kind: "literal", env: null, present: true };
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
	const providerRows = [];
	const diagnostics = [];
	let modelCount = 0;
	if (loaded.parseError) diagnostics.push({ level: "fail", id: "models-json-parse", message: loaded.parseError });
	if (loaded.missing) diagnostics.push({ level: "warn", id: "models-json-missing", message: `${modelsPath} not found; built-in providers may still work` });
	for (const [providerId, provider] of Object.entries(loaded.providers)) {
		const api = provider.api;
		const key = envRef(provider.apiKey);
		const models = Array.isArray(provider.models) ? provider.models : [];
		modelCount += models.length;
		const issues = [];
		if (!allowedApis.has(api)) issues.push(`unsupported api=${api}`);
		if (typeof provider.baseUrl !== "string" || !provider.baseUrl) issues.push("missing baseUrl");
		if (key.kind === "literal") issues.push("apiKey is literal; use $ENV_NAME");
		if (key.kind === "missing") issues.push("missing apiKey env reference");
		if (key.kind === "env" && !key.present) issues.push(`env ${key.env} is not set`);
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
			baseUrl: redact(provider.baseUrl),
			apiKey: key.kind === "env" ? `$${key.env} (${key.present ? "set" : "missing"})` : key.kind,
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

function printDoctor(report) {
	console.log("REPI Model Doctor");
	console.log(`modelsPath: ${report.modelsPath}`);
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

if (command === "help" || command === "--help" || command === "-h") {
	console.log(usage());
	process.exit(0);
}
if (command !== "doctor" && command !== "status" && command !== "cost") {
	console.error(`Unknown model command: ${command}`);
	console.error(usage());
	process.exit(2);
}

const report = command === "cost" ? buildCostReport() : buildDoctorReport();
if (json) console.log(JSON.stringify(report, null, 2));
else if (command === "cost") printCost(report);
else printDoctor(report);
process.exit(report.ok ? 0 : 1);

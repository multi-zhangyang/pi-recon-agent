import type { Api, Model, ModelCostTier, ProviderHeaders, ThinkingLevelMap } from "@pi-recon/repi-ai";
import type { ProviderConfigInput } from "./provider-composer.ts";

const ENV_MODEL_APIS = new Set<Api>(["openai-completions", "openai-responses", "anthropic-messages"]);
const ENV_MODEL_API_ALIASES = new Set([
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

export const REPI_MODEL_BASE_URL_ENV_NAMES = [
	"REPI_BASE_URL",
	"REPI_MODEL_BASE_URL",
	"REPI_API_BASE_URL",
	"REPI_ENDPOINT",
	"REPI_MODEL_ENDPOINT",
] as const;
export const REPI_MODEL_API_ENV_NAMES = ["REPI_MODEL_API", "REPI_API", "REPI_PROTOCOL", "REPI_MODEL_PROTOCOL"] as const;

/** Environment keys forwarded to isolated worker sessions and supported by the env-only provider. */
export const REPI_MODEL_ENV_VARIABLES = [
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
	"REPI_PROVIDER",
	"REPI_MODEL_PROVIDER",
	"REPI_PROVIDER_ID",
	"REPI_PROVIDER_NAME",
	"REPI_MODEL_PROVIDER_NAME",
	"REPI_MODEL",
	"REPI_MODEL_ID",
	"REPI_MODEL_NAME",
	"REPI_MODEL_API",
	"REPI_API",
	"REPI_PROTOCOL",
	"REPI_MODEL_PROTOCOL",
	"REPI_SUBAGENT_MODEL",
	"REPI_SUBAGENT_MODEL_NAME",
	"REPI_MODEL_INPUT",
	"REPI_INPUT",
	"REPI_MODEL_INPUT_MODALITIES",
	"REPI_INPUT_MODALITIES",
	"REPI_MODEL_REASONING",
	"REPI_REASONING",
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
] as const;

type EnvEntry = { name: string; value: string };

function firstEnvEntry(names: readonly string[]): EnvEntry | undefined {
	for (const name of names) {
		const value = process.env[name]?.trim();
		if (value) return { name, value };
	}
	return undefined;
}

function firstEnvValue(names: readonly string[]): string | undefined {
	return firstEnvEntry(names)?.value;
}

function normalizeEnvModelApi(value: string | undefined): Api {
	const normalized = String(value ?? "openai-completions")
		.trim()
		.toLowerCase()
		.replace(/_/g, "-");
	if (["openai-compatible", "openai-chat", "chat", "chat-completions", "openai-completions"].includes(normalized)) {
		return "openai-completions";
	}
	if (["response", "responses", "openai-response", "openai-responses"].includes(normalized)) {
		return "openai-responses";
	}
	if (["anthropic", "claude", "anthropic-compatible", "anthropic-messages"].includes(normalized)) {
		return "anthropic-messages";
	}
	return ENV_MODEL_APIS.has(normalized as Api) ? (normalized as Api) : "openai-completions";
}

function invalidEnvModelApi(value: string | undefined): string | undefined {
	if (!value?.trim()) return undefined;
	const normalized = value.trim().toLowerCase().replace(/_/g, "-");
	return ENV_MODEL_API_ALIASES.has(normalized) ? undefined : value;
}

function envInt(names: readonly string[], fallback: number, min: number, max: number): number {
	const entry = firstEnvEntry(names);
	if (!entry) return fallback;
	const parsed = Number(entry.value);
	if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
		throw new Error(`invalid ${entry.name}: expected an integer between ${min} and ${max}`);
	}
	return parsed;
}

function envNumber(names: readonly string[], fallback = 0, min = 0): number {
	const entry = firstEnvEntry(names);
	if (!entry) return fallback;
	const parsed = Number(entry.value);
	if (!Number.isFinite(parsed) || parsed < min) {
		throw new Error(`invalid ${entry.name}: expected a number greater than or equal to ${min}`);
	}
	return parsed;
}

function envCostTiers(value: string | undefined): ModelCostTier[] | undefined {
	if (!value) return undefined;
	let parsed: unknown;
	try {
		parsed = JSON.parse(value);
	} catch (error) {
		throw new Error("invalid REPI_MODEL_COST_TIERS: expected a JSON array", { cause: error });
	}
	if (!Array.isArray(parsed)) {
		throw new Error("invalid REPI_MODEL_COST_TIERS: expected a JSON array");
	}
	return parsed.map((tier, index) => {
		if (typeof tier !== "object" || tier === null || Array.isArray(tier)) {
			throw new Error(`invalid REPI_MODEL_COST_TIERS[${index}]: expected an object`);
		}
		const record = tier as Record<string, unknown>;
		const rateFields = ["input", "output", "cacheRead", "cacheWrite"] as const;
		for (const field of rateFields) {
			const fieldValue = record[field];
			if (typeof fieldValue !== "number" || !Number.isFinite(fieldValue) || fieldValue < 0) {
				throw new Error(`invalid REPI_MODEL_COST_TIERS[${index}].${field}: expected a non-negative number`);
			}
		}
		const threshold = record.inputTokensAbove;
		if (typeof threshold !== "number" || !Number.isSafeInteger(threshold) || threshold < 0) {
			throw new Error(`invalid REPI_MODEL_COST_TIERS[${index}].inputTokensAbove: expected a non-negative integer`);
		}
		return {
			inputTokensAbove: threshold,
			input: record.input as number,
			output: record.output as number,
			cacheRead: record.cacheRead as number,
			cacheWrite: record.cacheWrite as number,
		};
	});
}

function envBool(names: readonly string[], fallback = false): boolean {
	const entry = firstEnvEntry(names);
	if (!entry) return fallback;
	if (/^(?:1|true|yes|y|on)$/i.test(entry.value)) return true;
	if (/^(?:0|false|no|n|off)$/i.test(entry.value)) return false;
	throw new Error(`invalid ${entry.name}: expected a boolean`);
}

function envInputList(value: string | undefined): ("text" | "image")[] {
	if (!value) return ["text"];
	const items = value.startsWith("[")
		? (() => {
				let parsed: unknown;
				try {
					parsed = JSON.parse(value);
				} catch (error) {
					throw new Error("invalid REPI_MODEL_INPUT: expected comma-separated values or a JSON array", {
						cause: error,
					});
				}
				if (!Array.isArray(parsed)) throw new Error("invalid REPI_MODEL_INPUT: expected a JSON array");
				return parsed;
			})()
		: value.split(",").map((item) => item.trim());
	const normalized = items.map((item) => String(item).trim());
	if (!normalized.length || normalized.some((item) => item !== "text" && item !== "image")) {
		throw new Error('invalid REPI_MODEL_INPUT: allowed modalities are "text" and "image"');
	}
	return [...new Set(normalized)] as ("text" | "image")[];
}

function parseJsonObject(value: string, variableName: string): Record<string, unknown> {
	let parsed: unknown;
	try {
		parsed = JSON.parse(value);
	} catch (error) {
		throw new Error(`invalid ${variableName}: expected a JSON object`, { cause: error });
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw new Error(`invalid ${variableName}: expected a JSON object`);
	}
	return parsed as Record<string, unknown>;
}

function envHeaders(names: readonly string[]): ProviderHeaders | undefined {
	const entry = firstEnvEntry(names);
	if (!entry) return undefined;
	const parsed = parseJsonObject(entry.value, entry.name);
	const headers: ProviderHeaders = {};
	for (const [name, value] of Object.entries(parsed)) {
		if (typeof value !== "string" && value !== null) {
			throw new Error(`invalid ${entry.name}.${name}: expected a string or null`);
		}
		headers[name] = value;
	}
	return headers;
}

function envCompat(names: readonly string[]): Model<Api>["compat"] | undefined {
	const entry = firstEnvEntry(names);
	if (!entry) return undefined;
	return parseJsonObject(entry.value, entry.name) as Model<Api>["compat"];
}

function envThinkingLevelMap(names: readonly string[]): ThinkingLevelMap | undefined {
	const entry = firstEnvEntry(names);
	if (!entry) return undefined;
	const parsed = parseJsonObject(entry.value, entry.name);
	const allowed = new Set(["off", "minimal", "low", "medium", "high", "xhigh", "max"]);
	const result: ThinkingLevelMap = {};
	for (const [level, value] of Object.entries(parsed)) {
		if (!allowed.has(level)) throw new Error(`invalid ${entry.name}.${level}: unknown thinking level`);
		if (typeof value !== "string" && value !== null) {
			throw new Error(`invalid ${entry.name}.${level}: expected a string or null`);
		}
		result[level as keyof ThinkingLevelMap] = value;
	}
	return result;
}

function envProviderId(): string {
	return firstEnvValue(["REPI_PROVIDER", "REPI_MODEL_PROVIDER", "REPI_PROVIDER_ID"]) ?? "repi-env";
}

/** Build the explicit REPI environment provider without loading generated models. */
export function getRepiEnvProviderConfig(): { providerName: string; config: ProviderConfigInput } | undefined {
	const baseUrl = firstEnvValue(REPI_MODEL_BASE_URL_ENV_NAMES);
	const primaryModel = firstEnvValue(["REPI_MODEL", "REPI_MODEL_ID"]);
	const hasEnvModelSelection =
		REPI_MODEL_BASE_URL_ENV_NAMES.some((name) => Boolean(process.env[name]?.trim())) ||
		["REPI_MODEL", "REPI_MODEL_ID", ...REPI_MODEL_API_ENV_NAMES].some((name) => Boolean(process.env[name]?.trim()));
	if (!baseUrl || !primaryModel) {
		if (!hasEnvModelSelection) return undefined;
		const missing = [...(primaryModel ? [] : ["REPI_MODEL"]), ...(baseUrl ? [] : ["REPI_BASE_URL"])];
		throw new Error(`REPI env model config is incomplete; missing: ${missing.join(", ")}`);
	}

	const rawApi = firstEnvValue(REPI_MODEL_API_ENV_NAMES);
	const invalidApi = invalidEnvModelApi(rawApi);
	if (invalidApi) {
		throw new Error(
			`invalid REPI_MODEL_API=${JSON.stringify(invalidApi)}; allowed openai-compatible|openai-responses|anthropic`,
		);
	}
	const api = normalizeEnvModelApi(rawApi);
	const apiKeyEntry = firstEnvEntry([
		"REPI_AUTH_TOKEN",
		"REPI_API_KEY",
		"REPI_MODEL_API_KEY",
		"REPI_TOKEN",
		"REPI_MODEL_TOKEN",
	]);
	const apiKeyEnv = apiKeyEntry?.name ?? "REPI_AUTH_TOKEN";
	const modelIds = [primaryModel, firstEnvValue(["REPI_SUBAGENT_MODEL"])].filter(
		(value, index, values): value is string => Boolean(value) && values.indexOf(value) === index,
	);
	const input = envInputList(
		firstEnvValue(["REPI_MODEL_INPUT", "REPI_INPUT", "REPI_MODEL_INPUT_MODALITIES", "REPI_INPUT_MODALITIES"]),
	);
	const contextWindow = envInt(
		[
			"REPI_CONTEXT_WINDOW",
			"REPI_MODEL_CONTEXT_WINDOW",
			"REPI_AUTO_COMPACT_WINDOW",
			"REPI_MODEL_AUTO_COMPACT_WINDOW",
			"REPI_CONTEXT_LENGTH",
			"REPI_MODEL_CONTEXT_LENGTH",
		],
		262144,
		1024,
		1048576,
	);
	const maxTokens = envInt(
		[
			"REPI_MAX_TOKENS",
			"REPI_MODEL_MAX_TOKENS",
			"REPI_MAX_OUTPUT_TOKENS",
			"REPI_MODEL_MAX_OUTPUT_TOKENS",
			"REPI_OUTPUT_TOKEN_LIMIT",
		],
		16384,
		64,
		131072,
	);
	const reasoning = envBool(["REPI_MODEL_REASONING", "REPI_REASONING"], false);
	const costTiers = envCostTiers(firstEnvValue(["REPI_MODEL_COST_TIERS", "REPI_COST_TIERS"]));
	const providerHeaders = envHeaders(["REPI_HEADERS", "REPI_PROVIDER_HEADERS"]);
	const modelHeaders = envHeaders(["REPI_MODEL_HEADERS"]);
	const providerCompat = envCompat(["REPI_COMPAT"]);
	const modelCompat = envCompat(["REPI_MODEL_COMPAT"]);
	const thinkingLevelMap = envThinkingLevelMap(["REPI_MODEL_THINKING_LEVEL_MAP", "REPI_THINKING_LEVEL_MAP"]);
	const authHeader = firstEnvEntry(["REPI_AUTH_HEADER", "REPI_MODEL_AUTH_HEADER"])
		? envBool(["REPI_AUTH_HEADER", "REPI_MODEL_AUTH_HEADER"])
		: undefined;
	const cost = {
		input: envNumber(["REPI_MODEL_COST_INPUT", "REPI_COST_INPUT", "REPI_MODEL_INPUT_PRICE", "REPI_INPUT_PRICE"]),
		output: envNumber(["REPI_MODEL_COST_OUTPUT", "REPI_COST_OUTPUT", "REPI_MODEL_OUTPUT_PRICE", "REPI_OUTPUT_PRICE"]),
		cacheRead: envNumber([
			"REPI_MODEL_COST_CACHE_READ",
			"REPI_COST_CACHE_READ",
			"REPI_MODEL_CACHE_READ_PRICE",
			"REPI_CACHE_READ_PRICE",
		]),
		cacheWrite: envNumber([
			"REPI_MODEL_COST_CACHE_WRITE",
			"REPI_COST_CACHE_WRITE",
			"REPI_MODEL_CACHE_WRITE_PRICE",
			"REPI_CACHE_WRITE_PRICE",
		]),
		...(costTiers ? { tiers: costTiers } : {}),
	};
	const providerName = envProviderId();
	return {
		providerName,
		config: {
			name: firstEnvValue(["REPI_PROVIDER_NAME", "REPI_MODEL_PROVIDER_NAME"]) ?? "REPI environment model",
			baseUrl,
			apiKey: `$${apiKeyEnv}`,
			api,
			...(providerHeaders ? { headers: providerHeaders } : {}),
			...(providerCompat ? { compat: providerCompat } : {}),
			...(authHeader !== undefined ? { authHeader } : {}),
			models: modelIds.map((id) => ({
				id,
				name:
					id === primaryModel
						? (firstEnvValue(["REPI_MODEL_NAME"]) ?? id)
						: (firstEnvValue(["REPI_SUBAGENT_MODEL_NAME"]) ?? id),
				reasoning,
				...(thinkingLevelMap ? { thinkingLevelMap } : {}),
				input,
				cost,
				contextWindow,
				maxTokens,
				...(modelHeaders ? { headers: modelHeaders } : {}),
				...(modelCompat ? { compat: modelCompat } : {}),
			})),
		},
	};
}

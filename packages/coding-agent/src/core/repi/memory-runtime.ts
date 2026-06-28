import { join } from "node:path";
import { getAgentDir } from "../../config.ts";
import { readJsonObjectFile } from "./storage.ts";

export type RepiMemoryStartupDigestMode = "off" | "status" | "scoped" | "full";
export type RepiMemoryAutoDepositMode = "off" | "high-value" | "all";
export type RepiMemoryContextMode = "off" | "scoped" | "global";
export type RepiMemoryScopePolicy = "session" | "workspace" | "target" | "global" | "mission+workspace+target";

export type RepiMemoryRuntimeSettings = {
	mode: "off" | "scoped" | "global";
	autoRecall: boolean;
	autoInject: boolean;
	rawAutoInject: boolean;
	autoDepositMode: RepiMemoryAutoDepositMode;
	startupDigest: RepiMemoryStartupDigestMode;
	contextMemoryMode: RepiMemoryContextMode;
	includeGlobalMemoryInContextPack: boolean;
	activeRecall: boolean;
	scopePolicy: RepiMemoryScopePolicy;
	maxInjectedTokens: number;
	startupBudgetTokens: number;
	contextPackBudgetTokens: number;
	maxStartupItems: number;
	minRecallScore: number;
	rawTranscriptRetention: "external-only" | "inline";
};

function isPlainRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function envBoolean(name: string): boolean | undefined {
	const raw = process.env[name];
	if (raw === undefined) return undefined;
	if (/^(?:1|true|yes|on)$/i.test(raw.trim())) return true;
	if (/^(?:0|false|no|off)$/i.test(raw.trim())) return false;
	return undefined;
}

function envString(name: string): string | undefined {
	const raw = process.env[name];
	return raw === undefined || !raw.trim() ? undefined : raw;
}

function booleanSetting(value: unknown): boolean | undefined {
	return typeof value === "boolean" ? value : undefined;
}

function stringSetting(value: unknown): string | undefined {
	return typeof value === "string" ? value : undefined;
}

function numberSetting(value: unknown): number | undefined {
	return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export function normalizeMemoryStartupDigest(value: unknown): RepiMemoryStartupDigestMode {
	const raw = String(value ?? "scoped")
		.trim()
		.toLowerCase();
	if (raw === "off" || raw === "disabled" || raw === "none") return "off";
	if (raw === "full" || raw === "legacy" || raw === "raw") return "full";
	if (raw === "status") return "status";
	return "scoped";
}

export function normalizeMemoryMode(value: unknown): "off" | "scoped" | "global" {
	const raw = String(value ?? "scoped")
		.trim()
		.toLowerCase();
	if (raw === "off" || raw === "disabled" || raw === "none") return "off";
	if (raw === "global" || raw === "legacy" || raw === "full") return "global";
	return "scoped";
}

export function normalizeMemoryContextMode(value: unknown): RepiMemoryContextMode {
	const raw = String(value ?? "scoped")
		.trim()
		.toLowerCase();
	if (raw === "off" || raw === "disabled" || raw === "none") return "off";
	if (raw === "global" || raw === "full" || raw === "legacy") return "global";
	return "scoped";
}

export function normalizeMemoryAutoDepositMode(value: unknown): RepiMemoryAutoDepositMode {
	if (typeof value === "boolean") return value ? "high-value" : "off";
	const raw = String(value ?? "high-value")
		.trim()
		.toLowerCase();
	if (raw === "0" || raw === "false" || raw === "no" || raw === "off" || raw === "disabled" || raw === "none")
		return "off";
	if (raw === "1" || raw === "true" || raw === "yes" || raw === "on" || raw === "high" || raw === "high_value")
		return "high-value";
	if (raw === "all" || raw === "raw" || raw === "legacy") return "all";
	return "high-value";
}

export function normalizeMemoryScopePolicy(value: unknown): RepiMemoryScopePolicy {
	const raw = String(value ?? "mission+workspace+target")
		.trim()
		.toLowerCase();
	if (raw === "session" || raw === "workspace" || raw === "target" || raw === "global") return raw;
	return "mission+workspace+target";
}

export function normalizeMemoryRetention(value: unknown): "external-only" | "inline" {
	return String(value ?? "external-only")
		.trim()
		.toLowerCase() === "inline"
		? "inline"
		: "external-only";
}

function boundedPositiveInteger(value: unknown, fallback: number, min = 200, max = 20_000): number {
	const parsed = typeof value === "number" ? value : Number(value);
	if (!Number.isFinite(parsed)) return fallback;
	return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function boundedScore(value: unknown, fallback: number): number {
	const parsed = typeof value === "number" ? value : Number(value);
	if (!Number.isFinite(parsed)) return fallback;
	return Math.max(0, Math.min(1, parsed > 1 ? parsed / 100 : parsed));
}

export function repiMemorySettings(): RepiMemoryRuntimeSettings {
	const settings = readJsonObjectFile<Record<string, unknown>>(join(getAgentDir(), "settings.json")) ?? {};
	const memory = isPlainRecord(settings.memory) ? settings.memory : {};
	const mode = normalizeMemoryMode(envString("REPI_MEMORY_MODE") ?? stringSetting(memory.mode));
	const includeGlobalMemoryInContextPack =
		envBoolean("REPI_MEMORY_CONTEXT_PACK") ?? booleanSetting(memory.includeGlobalMemoryInContextPack) ?? false;
	const contextMemoryMode = includeGlobalMemoryInContextPack
		? "global"
		: normalizeMemoryContextMode(envString("REPI_MEMORY_CONTEXT_MODE") ?? stringSetting(memory.contextMemoryMode));
	return {
		mode,
		autoRecall: envBoolean("REPI_MEMORY_AUTO_RECALL") ?? booleanSetting(memory.autoRecall) ?? mode !== "off",
		autoInject: envBoolean("REPI_MEMORY_AUTO_INJECT") ?? booleanSetting(memory.autoInject) ?? false,
		rawAutoInject: envBoolean("REPI_MEMORY_RAW_AUTO_INJECT") ?? booleanSetting(memory.rawAutoInject) ?? false,
		autoDepositMode: normalizeMemoryAutoDepositMode(
			envString("REPI_MEMORY_AUTO_DEPOSIT_MODE") ??
				envString("REPI_MEMORY_AUTO_DEPOSIT") ??
				envString("REPI_MEMORY_AUTO_WRITEBACK") ??
				memory.autoDeposit ??
				memory.autoWriteback,
		),
		startupDigest: normalizeMemoryStartupDigest(
			process.env.REPI_MEMORY_STARTUP_DIGEST ?? stringSetting(memory.startupDigest) ?? "scoped",
		),
		contextMemoryMode,
		includeGlobalMemoryInContextPack,
		activeRecall: envBoolean("REPI_MEMORY_ACTIVE_RECALL") ?? booleanSetting(memory.activeRecall) ?? false,
		scopePolicy: normalizeMemoryScopePolicy(
			process.env.REPI_MEMORY_SCOPE_POLICY ?? stringSetting(memory.scopePolicy),
		),
		maxInjectedTokens: boundedPositiveInteger(
			process.env.REPI_MEMORY_MAX_INJECTED_TOKENS ?? numberSetting(memory.maxInjectedTokens),
			1200,
		),
		startupBudgetTokens: boundedPositiveInteger(
			process.env.REPI_MEMORY_STARTUP_BUDGET_TOKENS ?? numberSetting(memory.startupBudgetTokens),
			800,
		),
		contextPackBudgetTokens: boundedPositiveInteger(
			process.env.REPI_MEMORY_CONTEXT_BUDGET_TOKENS ?? numberSetting(memory.contextPackBudgetTokens),
			1200,
		),
		maxStartupItems: boundedPositiveInteger(
			process.env.REPI_MEMORY_MAX_STARTUP_ITEMS ?? numberSetting(memory.maxStartupItems),
			5,
			0,
			24,
		),
		minRecallScore: boundedScore(
			process.env.REPI_MEMORY_MIN_RECALL_SCORE ?? numberSetting(memory.minRecallScore),
			0.35,
		),
		rawTranscriptRetention: normalizeMemoryRetention(memory.rawTranscriptRetention),
	};
}

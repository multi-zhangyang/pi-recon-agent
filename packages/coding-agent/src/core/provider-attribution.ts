import { type Api, type Model, mergeProviderHeaders, type ProviderHeaders } from "@pi-recon/repi-ai";
import { APP_NAME, IS_REPI_PRODUCT } from "../config.ts";
import type { SettingsManager } from "./settings-manager.ts";
import { isInstallTelemetryEnabled } from "./telemetry.ts";

const OPENROUTER_HOST = "openrouter.ai";
const NVIDIA_NIM_HOST = "integrate.api.nvidia.com";
const CLOUDFLARE_API_HOST = "api.cloudflare.com";
const CLOUDFLARE_AI_GATEWAY_HOST = "gateway.ai.cloudflare.com";
const OPENCODE_HOST = "opencode.ai";

function matchesHost(baseUrl: string, expectedHost: string): boolean {
	try {
		return new URL(baseUrl).hostname === expectedHost;
	} catch {
		return false;
	}
}

function isOpenRouterModel(model: Model<Api>): boolean {
	return model.provider === "openrouter" || model.baseUrl.includes(OPENROUTER_HOST);
}

function isNvidiaNimModel(model: Model<Api>): boolean {
	return model.provider === "nvidia" || matchesHost(model.baseUrl, NVIDIA_NIM_HOST);
}

function isCloudflareModel(model: Model<Api>): boolean {
	return (
		model.provider === "cloudflare-workers-ai" ||
		model.provider === "cloudflare-ai-gateway" ||
		matchesHost(model.baseUrl, CLOUDFLARE_API_HOST) ||
		matchesHost(model.baseUrl, CLOUDFLARE_AI_GATEWAY_HOST)
	);
}

function getDefaultAttributionHeaders(
	model: Model<Api>,
	settingsManager: SettingsManager,
): Record<string, string> | undefined {
	if (!isInstallTelemetryEnabled(settingsManager)) {
		return undefined;
	}

	if (isOpenRouterModel(model)) {
		if (IS_REPI_PRODUCT) {
			return {
				"X-OpenRouter-Title": APP_NAME,
				"X-OpenRouter-Categories": "cli-agent",
			};
		}
		return {
			"HTTP-Referer": "https://pi.dev",
			"X-OpenRouter-Title": "pi",
			"X-OpenRouter-Categories": "cli-agent",
		};
	}

	if (isNvidiaNimModel(model)) {
		return {
			"X-BILLING-INVOKE-ORIGIN": IS_REPI_PRODUCT ? "repi" : "Pi",
		};
	}

	if (isCloudflareModel(model)) {
		return {
			"User-Agent": IS_REPI_PRODUCT ? "repi-coding-agent" : "repi-coding-agent",
		};
	}

	return undefined;
}

function getSessionHeaders(model: Model<Api>, sessionId: string | undefined): Record<string, string> | undefined {
	if (!sessionId) return undefined;
	if (
		model.provider !== "opencode" &&
		model.provider !== "opencode-go" &&
		!matchesHost(model.baseUrl, OPENCODE_HOST)
	) {
		return undefined;
	}
	return { "x-opencode-session": sessionId, "x-opencode-client": IS_REPI_PRODUCT ? APP_NAME : "pi" };
}

export function mergeProviderAttributionHeaders(
	model: Model<Api>,
	settingsManager: SettingsManager,
	sessionId: string | undefined,
	...headerSources: Array<ProviderHeaders | undefined>
): ProviderHeaders | undefined {
	return mergeProviderHeaders(
		getSessionHeaders(model, sessionId),
		getDefaultAttributionHeaders(model, settingsManager),
		...headerSources,
	);
}

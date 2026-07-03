import { join } from "node:path";
import { getDocsPath, IS_REPI_PRODUCT } from "../config.ts";

const UNKNOWN_PROVIDER = "unknown";

export function getProviderLoginHelp(): string {
	if (IS_REPI_PRODUCT) {
		return [
			"Configure a model with REPI_* environment variables (Claude Code-style) or ~/.repi/agent/models.json. See:",
			`  ${join(getDocsPath(), "repi-runtime-configuration.md")}`,
			`  ${join(getDocsPath(), "model-provider-formats.md")}`,
			"",
			"Quick env-only path:",
			"  export REPI_AUTH_TOKEN=sk-...",
			"  export REPI_BASE_URL=https://gateway.example/v1",
			"  export REPI_MODEL=vendor/model-id",
			"  export REPI_MODEL_API=openai-compatible",
			"  export REPI_AUTO_COMPACT_WINDOW=262144  # optional alias of REPI_CONTEXT_WINDOW",
			"  repi --list-models",
			'  repi -p "Reply exactly: REPI_OK"',
			"",
			"REPI does not load upstream pi's large built-in model catalog by default; set REPI_LOAD_BUILTIN_MODELS=1 only for legacy compatibility.",
		].join("\n");
	}
	return [
		"Use /login to log into a provider via OAuth or API key. See:",
		`  ${join(getDocsPath(), "providers.md")}`,
		`  ${join(getDocsPath(), "models.md")}`,
	].join("\n");
}

export function formatNoModelsAvailableMessage(): string {
	return `No models available. ${getProviderLoginHelp()}`;
}

export function formatNoModelSelectedMessage(): string {
	return `No model selected.\n\n${getProviderLoginHelp()}\n\nThen use /model to select a model.`;
}

export function formatNoApiKeyFoundMessage(provider: string): string {
	const providerDisplay = provider === UNKNOWN_PROVIDER ? "the selected model" : provider;
	return `No API key found for ${providerDisplay}.\n\n${getProviderLoginHelp()}`;
}

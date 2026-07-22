/**
 * Model registry - manages explicit models, dynamic providers, and request auth.
 */

import {
	type AnthropicMessagesCompat,
	type Api,
	type AssistantMessageEventStream,
	type Context,
	type Model,
	mergeProviderHeaders,
	type OAuthProviderInterface,
	type OpenAICompletionsCompat,
	type OpenAIResponsesCompat,
	type ProviderHeaders,
	registerApiProvider,
	registerBuiltInApiProviders,
	type SimpleStreamOptions,
	unregisterApiProviders,
} from "@pi-recon/repi-ai";
import {
	registerBuiltInOAuthProviders,
	registerOAuthProvider,
	unregisterOAuthProviders,
} from "@pi-recon/repi-ai/oauth";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { getAgentDir } from "../config.ts";
import { warnDeprecation } from "../utils/deprecation.ts";
import { stripJsonComments } from "../utils/json.ts";
import { normalizePath } from "../utils/paths.ts";
import type { AuthStatus, AuthStorage } from "./auth-storage.ts";
import { formatModelConfigValidationPath, type ModelsJson, validateModelsConfig } from "./model-config.ts";
import type { ModelRuntime } from "./model-runtime.ts";
import type { ProviderConfigInput as RuntimeProviderConfigInput } from "./provider-composer.ts";
import { getRepiEnvProviderConfig } from "./repi-env-provider.ts";
import {
	clearConfigValueCache,
	getConfigValueEnvVarNames,
	isCommandConfigValue,
	isConfigValueConfigured,
	isLegacyEnvVarNameConfigValue,
	resolveConfigValueOrThrow,
	resolveConfigValueUncached,
	resolveHeadersOrThrow,
} from "./resolve-config-value.ts";

type ModelsConfig = ModelsJson;

let nextModelRegistrySourceId = 0;

/** Provider request auth/headers resolved outside the static model metadata. */
interface ProviderRequestConfig {
	apiKey?: string;
	headers?: ProviderHeaders;
	authHeader?: boolean;
}

function repiEnvProviderConfig(): { providerName: string; config: ProviderConfigInput } | undefined {
	return getRepiEnvProviderConfig();
}

function migrateLegacyRegisterProviderConfigValue(providerName: string, field: string, value: string): string {
	if (!isLegacyEnvVarNameConfigValue(value)) return value;
	warnDeprecation(
		`registerProvider("${providerName}") ${field} value "${value}" is treated as a legacy environment variable reference. This will no longer be detected as an environment variable reference in a future release. Pass "$${value}" instead.`,
	);
	return `$${value}`;
}

function migrateLegacyRegisterProviderHeaders(
	providerName: string,
	field: string,
	headers: ProviderHeaders | undefined,
): ProviderHeaders | undefined {
	if (!headers) return undefined;
	let migratedHeaders: ProviderHeaders | undefined;
	for (const [key, value] of Object.entries(headers)) {
		if (value === null) continue;
		const migratedValue = migrateLegacyRegisterProviderConfigValue(providerName, `${field} header "${key}"`, value);
		if (migratedValue === value) continue;
		migratedHeaders ??= { ...headers };
		migratedHeaders[key] = migratedValue;
	}
	return migratedHeaders ?? headers;
}

function migrateLegacyRegisterProviderConfigValues(
	providerName: string,
	config: ProviderConfigInput,
): ProviderConfigInput {
	let migratedConfig: ProviderConfigInput | undefined;

	const setMigratedConfigValue = <TKey extends keyof ProviderConfigInput>(
		key: TKey,
		value: ProviderConfigInput[TKey],
	) => {
		migratedConfig ??= { ...config };
		migratedConfig[key] = value;
	};

	if (config.apiKey) {
		const apiKey = migrateLegacyRegisterProviderConfigValue(providerName, "apiKey", config.apiKey);
		if (apiKey !== config.apiKey) {
			setMigratedConfigValue("apiKey", apiKey);
		}
	}

	const headers = migrateLegacyRegisterProviderHeaders(providerName, "headers", config.headers);
	if (headers !== config.headers) {
		setMigratedConfigValue("headers", headers);
	}

	if (config.models) {
		let models: ProviderConfigInput["models"] | undefined;
		for (let index = 0; index < config.models.length; index++) {
			const model = config.models[index];
			const modelHeaders = migrateLegacyRegisterProviderHeaders(
				providerName,
				`model "${model.id}" headers`,
				model.headers,
			);
			if (modelHeaders === model.headers) continue;
			models ??= [...config.models];
			models[index] = { ...model, headers: modelHeaders };
		}
		if (models) {
			setMigratedConfigValue("models", models);
		}
	}

	return migratedConfig ?? config;
}

export type ResolvedRequestAuth =
	| {
			ok: true;
			apiKey?: string;
			headers?: ProviderHeaders;
	  }
	| {
			ok: false;
			error: string;
	  };

/** Result of loading explicit models from models.json. */
interface CustomModelsResult {
	models: Model<Api>[];
	error: string | undefined;
}

function emptyCustomModelsResult(error?: string): CustomModelsResult {
	return { models: [], error };
}

function mergeCompat(
	baseCompat: Model<Api>["compat"],
	overrideCompat: Model<Api>["compat"],
): Model<Api>["compat"] | undefined {
	if (!overrideCompat) return baseCompat;

	const base = baseCompat as OpenAICompletionsCompat | OpenAIResponsesCompat | AnthropicMessagesCompat | undefined;
	const override = overrideCompat as OpenAICompletionsCompat | OpenAIResponsesCompat | AnthropicMessagesCompat;
	const merged = { ...base, ...override } as OpenAICompletionsCompat | OpenAIResponsesCompat | AnthropicMessagesCompat;

	const baseCompletions = base as OpenAICompletionsCompat | undefined;
	const overrideCompletions = override as OpenAICompletionsCompat;
	const mergedCompletions = merged as OpenAICompletionsCompat;

	if (baseCompletions?.openRouterRouting || overrideCompletions.openRouterRouting) {
		mergedCompletions.openRouterRouting = {
			...baseCompletions?.openRouterRouting,
			...overrideCompletions.openRouterRouting,
		};
	}

	if (baseCompletions?.vercelGatewayRouting || overrideCompletions.vercelGatewayRouting) {
		mergedCompletions.vercelGatewayRouting = {
			...baseCompletions?.vercelGatewayRouting,
			...overrideCompletions.vercelGatewayRouting,
		};
	}

	return merged as Model<Api>["compat"];
}

const defaultModelCost = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };

function toRuntimeProviderConfig(config: ProviderConfigInput): RuntimeProviderConfigInput {
	return {
		...config,
		models: config.models?.map((model) => ({
			...model,
			name: model.name ?? model.id,
			reasoning: model.reasoning ?? false,
			input: model.input ?? ["text"],
			cost: model.cost ?? defaultModelCost,
			contextWindow: model.contextWindow ?? 128000,
			maxTokens: model.maxTokens ?? 16384,
		})),
	};
}

/** Clear the config value command cache. Exported for testing. */
export const clearApiKeyCache = clearConfigValueCache;

/**
 * Model registry - loads and manages models, resolves API keys via AuthStorage.
 */
export class ModelRegistry {
	private models: Model<Api>[] = [];
	private providerRequestConfigs: Map<string, ProviderRequestConfig> = new Map();
	private modelRequestHeaders: Map<string, ProviderHeaders> = new Map();
	private registeredProviders: Map<string, ProviderConfigInput> = new Map();
	private loadError: string | undefined = undefined;
	readonly authStorage: AuthStorage;
	private modelsJsonPath: string | undefined;
	private readonly runtime: ModelRuntime | undefined;
	private readonly globalRegistrationSource: string;

	/**
	 * Runtime-backed sessions can still receive an explicit model object from an
	 * SDK caller that is not part of the runtime catalog (for example a faux/test
	 * provider). Keep those models on the legacy AuthStorage/API-registry path;
	 * known runtime providers use the canonical provider/auth path below.
	 */
	private hasRuntimeProvider(provider: string): boolean {
		return this.runtime?.getProvider(provider) !== undefined;
	}

	private constructor(authStorage: AuthStorage, modelsJsonPath: string | undefined, runtime?: ModelRuntime) {
		this.authStorage = authStorage;
		this.modelsJsonPath = modelsJsonPath ? normalizePath(modelsJsonPath) : undefined;
		this.runtime = runtime;
		this.globalRegistrationSource = `coding-agent:model-registry:${++nextModelRegistrySourceId}`;
		if (!runtime) this.loadModels();
	}

	static create(authStorage: AuthStorage, modelsJsonPath: string = join(getAgentDir(), "models.json")): ModelRegistry {
		return new ModelRegistry(authStorage, modelsJsonPath);
	}

	static inMemory(authStorage: AuthStorage): ModelRegistry {
		return new ModelRegistry(authStorage, undefined);
	}

	/** Compatibility facade backed by the canonical ModelRuntime. */
	static fromRuntime(authStorage: AuthStorage, runtime: ModelRuntime): ModelRegistry {
		return new ModelRegistry(authStorage, undefined, runtime);
	}

	isBackedBy(runtime: ModelRuntime): boolean {
		return this.runtime === runtime;
	}

	/**
	 * Reload models from disk/env (explicit models.json + REPI_* env-only provider).
	 */
	refresh(): void | Promise<void> {
		if (this.runtime) {
			this.loadError = undefined;
			return this.runtime.reloadConfig().catch((error) => {
				this.loadError = error instanceof Error ? error.message : String(error);
			});
		}
		this.providerRequestConfigs.clear();
		this.modelRequestHeaders.clear();
		this.loadError = undefined;

		// Rebuild only registrations owned by this instance. Other sessions and SDK
		// registries share the process-level compatibility tables and must survive.
		unregisterApiProviders(this.globalRegistrationSource);
		unregisterOAuthProviders(this.globalRegistrationSource);
		registerBuiltInApiProviders();
		registerBuiltInOAuthProviders();

		this.loadModels();

		for (const [providerName, config] of this.registeredProviders.entries()) {
			// One bad extension provider must not prevent the remaining registrations
			// from being restored after this instance refreshes its owned layers.
			try {
				this.applyProviderConfig(providerName, config);
			} catch (error) {
				this.loadError = `Provider "${providerName}" failed to apply config: ${
					error instanceof Error ? error.message : String(error)
				}`;
			}
		}
	}

	/**
	 * Get any error from loading models.json (undefined if no error).
	 */
	getError(): string | undefined {
		const runtimeError = this.runtime?.getError();
		return (
			[this.loadError, runtimeError].filter((error): error is string => Boolean(error)).join("\n\n") || undefined
		);
	}

	private loadModels(): void {
		// Load explicit models from models.json. REPI intentionally does not expose
		// upstream pi's generated provider/model catalog at runtime; every runnable
		// model must come from REPI_* environment variables, models.json, or a
		// dynamically registered extension provider.
		const { models: customModels, error } = this.modelsJsonPath
			? this.loadCustomModels(this.modelsJsonPath)
			: emptyCustomModelsResult();

		if (error) {
			this.loadError = error;
			// Keep any already-loadable catalog/env models even if custom models failed to load.
		}

		let combined = [...customModels];

		// Let OAuth providers modify their models (e.g., update baseUrl)
		for (const oauthProvider of this.authStorage.getOAuthProviders()) {
			const cred = this.authStorage.get(oauthProvider.id);
			if (cred?.type === "oauth" && oauthProvider.modifyModels) {
				// opt #244: a throwing OAuth provider (built-in or extension) used
				// to propagate out of loadModels → the ModelRegistry constructor /
				// refresh() → startup crash. Every other external-input path here
				// is wrapped (loadCustomModels, getApiKeyAndHeaders); mirror it.
				// Keep `combined` unchanged and surface the failure via loadError.
				try {
					combined = oauthProvider.modifyModels(combined, cred);
				} catch (error) {
					this.loadError = `OAuth provider "${oauthProvider.id}" failed to modify models: ${
						error instanceof Error ? error.message : String(error)
					}`;
				}
			}
		}

		this.models = combined;
		let envProvider: { providerName: string; config: ProviderConfigInput } | undefined;
		try {
			envProvider = repiEnvProviderConfig();
		} catch (error) {
			this.loadError = `REPI environment model provider failed to apply: ${
				error instanceof Error ? error.message : String(error)
			}`;
		}
		if (envProvider) {
			try {
				this.applyProviderConfig(envProvider.providerName, envProvider.config);
			} catch (error) {
				this.loadError = `REPI environment model provider failed to apply: ${
					error instanceof Error ? error.message : String(error)
				}`;
			}
		}
	}

	private loadCustomModels(modelsJsonPath: string): CustomModelsResult {
		if (!existsSync(modelsJsonPath)) {
			return emptyCustomModelsResult();
		}

		try {
			const content = readFileSync(modelsJsonPath, "utf-8");
			const parsed = JSON.parse(stripJsonComments(content)) as unknown;

			if (!validateModelsConfig.Check(parsed)) {
				const errors =
					validateModelsConfig
						.Errors(parsed)
						.map((error) => `  - ${formatModelConfigValidationPath(error)}: ${error.message}`)
						.join("\n") || "Unknown schema error";
				return emptyCustomModelsResult(`Invalid models.json schema:\n${errors}\n\nFile: ${modelsJsonPath}`);
			}

			const config = parsed as ModelsConfig;

			// Additional validation
			this.validateConfig(config);

			for (const [providerName, providerConfig] of Object.entries(config.providers)) {
				this.storeProviderRequestConfig(providerName, providerConfig);
			}

			return { models: this.parseModels(config), error: undefined };
		} catch (error) {
			if (error instanceof SyntaxError) {
				return emptyCustomModelsResult(`Failed to parse models.json: ${error.message}\n\nFile: ${modelsJsonPath}`);
			}
			return emptyCustomModelsResult(
				`Failed to load models.json: ${error instanceof Error ? error.message : error}\n\nFile: ${modelsJsonPath}`,
			);
		}
	}

	private validateConfig(config: ModelsConfig): void {
		for (const [providerName, providerConfig] of Object.entries(config.providers)) {
			const hasProviderApi = !!providerConfig.api;
			const models = providerConfig.models ?? [];
			if (models.length === 0) {
				throw new Error(
					`Provider ${providerName}: must define explicit "models". REPI only loads env, models.json, and extension-registered models.`,
				);
			}

			if (!providerConfig.baseUrl && models.some((modelDef) => !modelDef.baseUrl)) {
				throw new Error(
					`Provider ${providerName}: "baseUrl" is required at provider level unless every model defines its own "baseUrl".`,
				);
			}
			if (!providerConfig.apiKey) {
				throw new Error(`Provider ${providerName}: "apiKey" is required when defining models.`);
			}

			for (const modelDef of models) {
				const hasModelApi = !!modelDef.api;

				if (!hasProviderApi && !hasModelApi) {
					throw new Error(
						`Provider ${providerName}, model ${modelDef.id}: no "api" specified. Set at provider or model level.`,
					);
				}

				if (!modelDef.id) throw new Error(`Provider ${providerName}: model missing "id"`);
				if (modelDef.contextWindow !== undefined && modelDef.contextWindow <= 0) {
					throw new Error(`Provider ${providerName}, model ${modelDef.id}: invalid contextWindow`);
				}
				if (modelDef.maxTokens !== undefined && modelDef.maxTokens <= 0) {
					throw new Error(`Provider ${providerName}, model ${modelDef.id}: invalid maxTokens`);
				}
			}
		}
	}

	private parseModels(config: ModelsConfig): Model<Api>[] {
		const models: Model<Api>[] = [];

		for (const [providerName, providerConfig] of Object.entries(config.providers)) {
			const modelDefs = providerConfig.models ?? [];

			for (const modelDef of modelDefs) {
				const api = modelDef.api ?? providerConfig.api;
				const baseUrl = modelDef.baseUrl ?? providerConfig.baseUrl;
				if (!api || !baseUrl) continue;

				const compat = mergeCompat(providerConfig.compat, modelDef.compat);
				this.storeModelHeaders(providerName, modelDef.id, modelDef.headers);

				models.push({
					id: modelDef.id,
					name: modelDef.name ?? modelDef.id,
					api: api as Api,
					provider: providerName,
					baseUrl,
					reasoning: modelDef.reasoning ?? false,
					thinkingLevelMap: modelDef.thinkingLevelMap,
					input: (modelDef.input ?? ["text"]) as ("text" | "image")[],
					cost: modelDef.cost ?? defaultModelCost,
					contextWindow: modelDef.contextWindow ?? 128000,
					maxTokens: modelDef.maxTokens ?? 16384,
					headers: undefined,
					compat,
				} as Model<Api>);
			}
		}

		return models;
	}

	/**
	 * Get all explicitly configured models (models.json + REPI_* env-only + dynamic providers).
	 * If models.json had errors, returns the remaining loadable model sources.
	 */
	getAll(): Model<Api>[] {
		return this.runtime ? [...this.runtime.getModels()] : this.models;
	}

	/**
	 * Get only models that have auth configured.
	 * This is a fast check that doesn't refresh OAuth tokens.
	 */
	getAvailable(): Model<Api>[] {
		return this.getAll().filter((model) => this.hasConfiguredAuth(model));
	}

	/**
	 * Find a model by provider and ID.
	 */
	find(provider: string, modelId: string): Model<Api> | undefined {
		return (
			this.runtime?.getModel(provider, modelId) ??
			this.models.find((m) => m.provider === provider && m.id === modelId)
		);
	}

	/**
	 * Resolve the currently active model after dynamic provider registration.
	 *
	 * REPI does not load an implicit built-in catalog into ModelRegistry, so a
	 * session can legitimately hold a model object that is not present in
	 * `this.models` (for example a caller passed `getModel(...)` directly). A
	 * registerProvider("anthropic", { baseUrl }) override must still affect that
	 * active model immediately; otherwise the next request keeps using the stale
	 * base URL until the user reloads or switches models.
	 */
	resolveActiveModel<TApi extends Api>(model: Model<TApi>): Model<TApi> {
		const runtimeModel = this.runtime?.getModel(model.provider, model.id);
		if (runtimeModel) return runtimeModel as Model<TApi>;
		const registeredModel = this.find(model.provider, model.id);
		if (registeredModel) {
			return registeredModel as Model<TApi>;
		}

		const providerConfig =
			this.runtime?.getRegisteredProviderConfig(model.provider) ?? this.registeredProviders.get(model.provider);
		if (!providerConfig) {
			return model;
		}

		let changed = false;
		const resolved: Model<Api> = { ...model };
		if (providerConfig.baseUrl && providerConfig.baseUrl !== model.baseUrl) {
			resolved.baseUrl = providerConfig.baseUrl;
			changed = true;
		}
		if (providerConfig.api && providerConfig.api !== model.api) {
			resolved.api = providerConfig.api;
			changed = true;
		}
		if (providerConfig.compat) {
			resolved.compat = mergeCompat(model.compat, providerConfig.compat);
			changed = true;
		}

		return changed ? (resolved as Model<TApi>) : model;
	}

	/**
	 * Get API key for a model.
	 */
	hasConfiguredAuth(model: Model<Api>): boolean {
		if (this.runtime && this.hasRuntimeProvider(model.provider)) {
			const provider = this.runtime.getProvider(model.provider);
			if (!provider) return false;
			const runtimeStatus = this.runtime.getProviderAuthStatus(model.provider);
			if (runtimeStatus.source === "runtime") return runtimeStatus.configured;
			const directStatus = this.authStorage.getAuthStatus(model.provider, {
				includeEnvironment: false,
				includeFallback: false,
			});
			if (directStatus.source === "runtime") return Boolean(provider.auth.apiKey);
			const credential = this.authStorage.get(model.provider);
			if (credential?.type === "api_key") return Boolean(provider.auth.apiKey);
			if (credential?.type === "oauth") return Boolean(provider.auth.oauth);
			return this.runtime.hasConfiguredAuth(model.provider);
		}
		const providerApiKey = this.providerRequestConfigs.get(model.provider)?.apiKey;
		return (
			this.authStorage.hasAuth(model.provider, { includeEnvironment: false, includeFallback: false }) ||
			(providerApiKey !== undefined && isConfigValueConfigured(providerApiKey))
		);
	}

	private getModelRequestKey(provider: string, modelId: string): string {
		return `${provider}:${modelId}`;
	}

	private storeProviderRequestConfig(
		providerName: string,
		config: {
			apiKey?: string;
			headers?: ProviderHeaders;
			authHeader?: boolean;
		},
	): void {
		if (!config.apiKey && !config.headers && !config.authHeader) {
			return;
		}

		this.providerRequestConfigs.set(providerName, {
			apiKey: config.apiKey,
			headers: config.headers,
			authHeader: config.authHeader,
		});
	}

	private storeModelHeaders(providerName: string, modelId: string, headers?: ProviderHeaders): void {
		const key = this.getModelRequestKey(providerName, modelId);
		if (!headers || Object.keys(headers).length === 0) {
			this.modelRequestHeaders.delete(key);
			return;
		}
		this.modelRequestHeaders.set(key, headers);
	}

	/**
	 * Get API key and request headers for a model.
	 */
	async getApiKeyAndHeaders(model: Model<Api>): Promise<ResolvedRequestAuth> {
		try {
			if (this.runtime && this.hasRuntimeProvider(model.provider)) {
				const runtimeModel = this.runtime.getModel(model.provider, model.id) ?? model;
				const resolution = await this.runtime.getAuth(runtimeModel);
				if (!resolution) return { ok: false, error: `No API key found for "${model.provider}"` };
				return {
					ok: true,
					apiKey: resolution.auth.apiKey,
					headers: resolution.auth.headers,
				};
			}
			const providerConfig = this.providerRequestConfigs.get(model.provider);
			const apiKeyFromAuthStorage = await this.authStorage.getApiKey(model.provider, {
				includeEnvironment: false,
				includeFallback: false,
			});
			const apiKey =
				apiKeyFromAuthStorage ??
				(providerConfig?.apiKey
					? resolveConfigValueOrThrow(providerConfig.apiKey, `API key for provider "${model.provider}"`)
					: undefined);

			const providerHeaders = resolveHeadersOrThrow(providerConfig?.headers, `provider "${model.provider}"`);
			const modelHeaders = resolveHeadersOrThrow(
				this.modelRequestHeaders.get(this.getModelRequestKey(model.provider, model.id)),
				`model "${model.provider}/${model.id}"`,
			);

			let headers = mergeProviderHeaders(model.headers, providerHeaders, modelHeaders);

			if (providerConfig?.authHeader) {
				if (!apiKey) {
					return { ok: false, error: `No API key found for "${model.provider}"` };
				}
				headers = mergeProviderHeaders(headers, { Authorization: `Bearer ${apiKey}` });
			}

			return {
				ok: true,
				apiKey,
				headers: headers && Object.keys(headers).length > 0 ? headers : undefined,
			};
		} catch (error) {
			return {
				ok: false,
				error: error instanceof Error ? error.message : String(error),
			};
		}
	}

	/**
	 * Return auth status for a provider, including request auth configured in models.json.
	 * This intentionally does not execute command-backed config values.
	 */
	getProviderAuthStatus(provider: string): AuthStatus {
		if (this.runtime && this.hasRuntimeProvider(provider)) {
			const runtimeStatus = this.runtime.getProviderAuthStatus(provider);
			const runtimeProvider = this.runtime.getProvider(provider);
			if (!runtimeProvider) return runtimeStatus;
			if (runtimeStatus.source === "runtime") return runtimeStatus;
			const directStatus = this.authStorage.getAuthStatus(provider, {
				includeEnvironment: false,
				includeFallback: false,
			});
			if (directStatus.source === "runtime") {
				return runtimeProvider.auth.apiKey ? directStatus : { configured: false };
			}
			const credential = this.authStorage.get(provider);
			if (credential?.type === "api_key" && runtimeProvider.auth.apiKey) return directStatus;
			if (credential?.type === "oauth" && runtimeProvider.auth.oauth) return directStatus;
			if (credential) return { configured: false };
			return runtimeStatus;
		}
		const authStatus = this.authStorage.getAuthStatus(provider, {
			includeEnvironment: false,
			includeFallback: false,
		});
		if (authStatus.source) {
			return authStatus;
		}

		const providerApiKey = this.providerRequestConfigs.get(provider)?.apiKey;
		if (!providerApiKey) {
			return authStatus;
		}

		if (isCommandConfigValue(providerApiKey)) {
			return { configured: true, source: "models_json_command" };
		}

		const envVarNames = getConfigValueEnvVarNames(providerApiKey);
		if (envVarNames.length > 0) {
			return isConfigValueConfigured(providerApiKey)
				? { configured: true, source: "environment", label: envVarNames.join(", ") }
				: { configured: false };
		}

		return { configured: true, source: "models_json_key" };
	}

	/**
	 * Get display name for a provider.
	 */
	getProviderDisplayName(provider: string): string {
		const runtimeProvider = this.runtime?.getProvider(provider);
		if (runtimeProvider) return runtimeProvider.name;
		const registeredProvider = this.registeredProviders.get(provider);
		const oauthProvider = this.authStorage.getOAuthProviders().find((p) => p.id === provider);

		return registeredProvider?.name ?? registeredProvider?.oauth?.name ?? oauthProvider?.name ?? provider;
	}

	/**
	 * Get API key for a provider.
	 */
	async getApiKeyForProvider(provider: string): Promise<string | undefined> {
		// opt #245: the sibling getApiKeyAndHeaders wraps its body in try/catch
		// and converts any throw into {ok:false,error}. This method did the same
		// authStorage.getApiKey + config-value resolution with NO try/catch, so
		// an OAuth provider.getApiKey rejection (auth-storage non-refresh branch)
		// propagated to the caller as an unhandled rejection. Mirror the
		// "resolution failed → undefined" contract the rest of the file uses.
		try {
			if (this.runtime && this.hasRuntimeProvider(provider)) {
				return (await this.runtime.getAuth(provider))?.auth.apiKey;
			}
			const apiKey = await this.authStorage.getApiKey(provider, {
				includeEnvironment: false,
				includeFallback: false,
			});
			if (apiKey !== undefined) {
				return apiKey;
			}

			const providerApiKey = this.providerRequestConfigs.get(provider)?.apiKey;
			return providerApiKey ? resolveConfigValueUncached(providerApiKey) : undefined;
		} catch {
			return undefined;
		}
	}

	/**
	 * Check if a model is using OAuth credentials (subscription).
	 */
	isUsingOAuth(model: Model<Api>): boolean {
		if (this.runtime && this.hasRuntimeProvider(model.provider)) return this.runtime.isUsingOAuth(model.provider);
		const cred = this.authStorage.get(model.provider);
		return cred?.type === "oauth";
	}

	/**
	 * Register a provider dynamically (from extensions).
	 *
	 * If provider has models: replaces all existing explicit models for this provider.
	 * If provider has only baseUrl/headers: updates currently registered models for that provider.
	 * If provider has oauth: registers OAuth provider for /login support.
	 */
	registerProvider(providerName: string, config: ProviderConfigInput): void {
		if (this.runtime) {
			this.runtime.registerProvider(
				providerName,
				toRuntimeProviderConfig(migrateLegacyRegisterProviderConfigValues(providerName, config)),
			);
			return;
		}
		const migratedConfig = migrateLegacyRegisterProviderConfigValues(providerName, config);
		this.validateProviderConfig(providerName, migratedConfig);
		this.applyProviderConfig(providerName, migratedConfig);
		this.upsertRegisteredProvider(providerName, migratedConfig);
	}

	/**
	 * Unregister a previously registered provider.
	 *
	 * Removes the provider from the registry and reloads explicit models from disk/env.
	 * Also resets dynamic OAuth and API stream registrations before reapplying
	 * remaining dynamic providers.
	 * Has no effect if the provider was never registered.
	 */
	unregisterProvider(providerName: string): void {
		if (this.runtime) {
			this.runtime.unregisterProvider(providerName);
			return;
		}
		if (!this.registeredProviders.has(providerName)) return;
		this.registeredProviders.delete(providerName);
		this.refresh();
	}

	/**
	 * Upsert a provider config into registeredProviders.
	 * If the provider is already registered, defined values in the incoming config
	 * override existing ones; undefined values are preserved from the stored config.
	 * If the provider is not registered, the incoming config is stored as-is.
	 */
	private upsertRegisteredProvider(providerName: string, config: ProviderConfigInput): void {
		const existing = this.registeredProviders.get(providerName);
		if (!existing) {
			this.registeredProviders.set(providerName, config);
			return;
		}
		for (const k of Object.keys(config) as (keyof ProviderConfigInput)[]) {
			if (config[k] !== undefined) {
				(existing as Record<string, unknown>)[k] = config[k];
			}
		}
	}

	private validateProviderConfig(providerName: string, config: ProviderConfigInput): void {
		if (config.streamSimple && !config.api) {
			throw new Error(`Provider ${providerName}: "api" is required when registering streamSimple.`);
		}

		if (!config.models || config.models.length === 0) {
			return;
		}

		if (!config.baseUrl && config.models.some((modelDef) => !modelDef.baseUrl)) {
			throw new Error(
				`Provider ${providerName}: "baseUrl" is required at provider level unless every model defines its own "baseUrl".`,
			);
		}
		if (!config.apiKey && !config.oauth) {
			throw new Error(`Provider ${providerName}: "apiKey" or "oauth" is required when defining models.`);
		}

		for (const modelDef of config.models) {
			// Foundational opt #269: validate that modelDef.id is a non-empty
			// string. The schema-validated models.json path already requires a
			// non-empty model id, but the
			// extension registerProvider path flows through THIS validator only —
			// it previously checked only `api`. A model with `id: undefined` (an
			// extension that forgot the field) or `id: 123` (typed wrong) entered
			// `this.models` verbatim (applyProviderConfig stores `id: modelDef.id`)
			// and then crashed model resolution with `TypeError: Cannot read
			// properties of undefined (reading 'toLowerCase')` at
			// model-resolver.ts findExactModelReferenceMatch/tryMatchModel
			// (`model.id.toLowerCase()` / `b.id.localeCompare(a.id)`) — uncaught,
			// aborting --list-models / startup / any resolve. Same class as opt #44
			// (undefined.localeCompare on a missing manifest field). Mirror the
			// schema constraint at the extension entry gate so the bad model is
			// rejected before it can poison the model table.
			if (typeof modelDef.id !== "string" || modelDef.id.trim().length === 0) {
				throw new Error(
					`Provider ${providerName}, model ${JSON.stringify(modelDef.id)}: "id" must be a non-empty string.`,
				);
			}

			const api = modelDef.api || config.api;
			if (!api) {
				throw new Error(`Provider ${providerName}, model ${modelDef.id}: no "api" specified.`);
			}
			if (modelDef.contextWindow !== undefined && modelDef.contextWindow <= 0) {
				throw new Error(`Provider ${providerName}, model ${modelDef.id}: invalid contextWindow`);
			}
			if (modelDef.maxTokens !== undefined && modelDef.maxTokens <= 0) {
				throw new Error(`Provider ${providerName}, model ${modelDef.id}: invalid maxTokens`);
			}
		}
	}

	private applyProviderConfig(providerName: string, config: ProviderConfigInput): void {
		// Register OAuth provider if provided
		if (config.oauth) {
			// Ensure the OAuth provider ID matches the provider name
			const oauthProvider: OAuthProviderInterface = {
				...config.oauth,
				id: providerName,
			};
			registerOAuthProvider(oauthProvider, this.globalRegistrationSource);
		}

		if (config.streamSimple) {
			const streamSimple = config.streamSimple;
			registerApiProvider(
				{
					api: config.api!,
					stream: (model, context, options) => streamSimple(model, context, options as SimpleStreamOptions),
					streamSimple,
				},
				this.globalRegistrationSource,
			);
		}

		this.storeProviderRequestConfig(providerName, config);

		if (config.models && config.models.length > 0) {
			// Full replacement: remove existing models for this provider
			this.models = this.models.filter((m) => m.provider !== providerName);

			// Parse and add new models
			for (const modelDef of config.models) {
				const api = modelDef.api || config.api;
				const baseUrl = modelDef.baseUrl ?? config.baseUrl;
				if (!baseUrl) {
					throw new Error(`Provider ${providerName}, model ${modelDef.id}: no "baseUrl" specified.`);
				}
				this.storeModelHeaders(providerName, modelDef.id, modelDef.headers);

				this.models.push({
					id: modelDef.id,
					name: modelDef.name ?? modelDef.id,
					api: api as Api,
					provider: providerName,
					baseUrl,
					reasoning: modelDef.reasoning ?? false,
					thinkingLevelMap: modelDef.thinkingLevelMap,
					input: modelDef.input ?? ["text"],
					cost: modelDef.cost ?? defaultModelCost,
					contextWindow: modelDef.contextWindow ?? 128000,
					maxTokens: modelDef.maxTokens ?? 16384,
					headers: undefined,
					compat: mergeCompat(config.compat, modelDef.compat),
				} as Model<Api>);
			}

			// Apply OAuth modifyModels if credentials exist (e.g., to update baseUrl)
			if (config.oauth?.modifyModels) {
				const cred = this.authStorage.get(providerName);
				if (cred?.type === "oauth") {
					this.models = config.oauth.modifyModels(this.models, cred);
				}
			}
		} else if (config.baseUrl || config.headers || config.compat || config.api) {
			// Override-only: update existing models. Request headers are resolved per request.
			this.models = this.models.map((m) => {
				if (m.provider !== providerName) return m;
				return {
					...m,
					api: (config.api ?? m.api) as Api,
					baseUrl: config.baseUrl ?? m.baseUrl,
					compat: mergeCompat(m.compat, config.compat),
				};
			});
		}
	}
}

/**
 * Input type for registerProvider API.
 */
export interface ProviderConfigInput {
	name?: string;
	baseUrl?: string;
	apiKey?: string;
	api?: Api;
	/** Provider-level compatibility metadata. Model-level compat overrides these fields. */
	compat?: Model<Api>["compat"];
	streamSimple?: (model: Model<Api>, context: Context, options?: SimpleStreamOptions) => AssistantMessageEventStream;
	headers?: ProviderHeaders;
	authHeader?: boolean;
	/** OAuth provider for /login support */
	oauth?: Omit<OAuthProviderInterface, "id">;
	models?: Array<{
		id: string;
		name?: string;
		api?: Api;
		baseUrl?: string;
		reasoning?: boolean;
		thinkingLevelMap?: Model<Api>["thinkingLevelMap"];
		input?: ("text" | "image")[];
		cost?: { input: number; output: number; cacheRead: number; cacheWrite: number };
		contextWindow?: number;
		maxTokens?: number;
		headers?: ProviderHeaders;
		compat?: Model<Api>["compat"];
	}>;
}

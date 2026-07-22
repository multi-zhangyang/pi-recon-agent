import {
	type Api,
	type ApiKeyAuth,
	type AssistantMessageEventStream,
	type AuthContext,
	type AuthInteraction,
	type AuthResult,
	type Context,
	type Credential,
	lazyStream,
	type Model,
	type ModelAuth,
	mergeProviderHeaders,
	type OAuthAuth,
	type OAuthCredentials,
	type OAuthLoginCallbacks,
	type Provider,
	type ProviderHeaders,
	type RefreshModelsContext,
	type SimpleStreamOptions,
	type StreamOptions,
} from "@pi-recon/repi-ai";
import { getApiProvider } from "@pi-recon/repi-ai/compat";
import type { ModelConfig, ModelsJsonModel, ModelsJsonProvider } from "./model-config.ts";
import {
	clearConfigValueCache,
	getConfigValueEnvVarNames,
	isCommandConfigValue,
	isConfigValueConfigured,
	resolveConfigValueOrThrow,
	resolveHeadersOrThrow,
} from "./resolve-config-value.ts";

export interface ExtensionOAuthConfig {
	name: string;
	/** @deprecated Retained for extension source compatibility; ignored by canonical auth flows. */
	usesCallbackServer?: boolean;
	login(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials>;
	refreshToken(credentials: OAuthCredentials): Promise<OAuthCredentials>;
	getApiKey(credentials: OAuthCredentials): string;
	modifyModels?(models: Model<Api>[], credentials: OAuthCredentials): Model<Api>[];
}

/** Input type for the extension registerProvider API. */
export interface ProviderConfigInput {
	name?: string;
	baseUrl?: string;
	apiKey?: string;
	api?: Api;
	compat?: Model<Api>["compat"];
	streamSimple?: (model: Model<Api>, context: Context, options?: SimpleStreamOptions) => AssistantMessageEventStream;
	headers?: ProviderHeaders;
	authHeader?: boolean;
	oauth?: ExtensionOAuthConfig;
	models?: Array<{
		id: string;
		name: string;
		api?: Api;
		baseUrl?: string;
		reasoning: boolean;
		thinkingLevelMap?: Model<Api>["thinkingLevelMap"];
		input: ("text" | "image")[];
		cost: Model<Api>["cost"];
		contextWindow: number;
		maxTokens: number;
		headers?: ProviderHeaders;
		compat?: Model<Api>["compat"];
	}>;
	refreshModels?(context: RefreshModelsContext): Promise<NonNullable<ProviderConfigInput["models"]>>;
}

export type AuthStatus = {
	configured: boolean;
	source?: "stored" | "runtime" | "environment" | "fallback" | "models_json_key" | "models_json_command";
	label?: string;
};

export const clearApiKeyCache = clearConfigValueCache;

function mergeCompat(base: Model<Api>["compat"], override: Model<Api>["compat"]): Model<Api>["compat"] {
	if (!override) return base;
	const merged = { ...base, ...override } as NonNullable<Model<Api>["compat"]>;
	const baseNested = base as Record<string, unknown> | undefined;
	const overrideNested = override as Record<string, unknown>;
	const mergedNested = merged as Record<string, unknown>;
	for (const key of ["openRouterRouting", "vercelGatewayRouting", "chatTemplateKwargs"] as const) {
		const baseValue = baseNested?.[key];
		const overrideValue = overrideNested[key];
		if (
			(typeof baseValue === "object" && baseValue !== null) ||
			(typeof overrideValue === "object" && overrideValue !== null)
		) {
			mergedNested[key] = { ...(baseValue as object | undefined), ...(overrideValue as object | undefined) };
		}
	}
	return merged;
}

function modelFromJson(
	providerId: string,
	definition: ModelsJsonModel,
	providerConfig: ModelsJsonProvider,
	defaults: Model<Api> | undefined,
): Model<Api> {
	const api = definition.api ?? providerConfig.api ?? defaults?.api;
	if (!api) {
		throw new Error(
			`Provider ${providerId}, model ${definition.id}: no "api" specified. Set at provider or model level.`,
		);
	}
	const baseUrl = definition.baseUrl ?? providerConfig.baseUrl ?? defaults?.baseUrl;
	if (!baseUrl) throw new Error(`Provider ${providerId}: "baseUrl" is required when defining custom models.`);
	if (definition.contextWindow !== undefined && definition.contextWindow <= 0) {
		throw new Error(`Provider ${providerId}, model ${definition.id}: invalid contextWindow`);
	}
	if (definition.maxTokens !== undefined && definition.maxTokens <= 0) {
		throw new Error(`Provider ${providerId}, model ${definition.id}: invalid maxTokens`);
	}
	return {
		id: definition.id,
		name: definition.name ?? definition.id,
		api: api as Api,
		provider: providerId,
		baseUrl,
		reasoning: definition.reasoning ?? false,
		thinkingLevelMap: definition.thinkingLevelMap,
		input: (definition.input ?? ["text"]) as ("text" | "image")[],
		cost: definition.cost ?? { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: definition.contextWindow ?? 128000,
		maxTokens: definition.maxTokens ?? 16384,
		headers: undefined,
		compat: mergeCompat(providerConfig.compat, definition.compat),
	};
}

function applyModelsJson(
	providerId: string,
	baseModels: readonly Model<Api>[],
	config: ModelsJsonProvider | undefined,
): Model<Api>[] {
	if (!config) return [...baseModels];
	if (
		!config.models?.length &&
		!config.name &&
		!config.baseUrl &&
		!config.api &&
		!config.headers &&
		!config.compat &&
		!config.apiKey &&
		config.authHeader === undefined
	) {
		throw new Error(`Provider ${providerId}: provider configuration has no effective fields.`);
	}

	const models: Model<Api>[] = baseModels.map((model) => ({
		...model,
		api: config.api ?? model.api,
		baseUrl: config.baseUrl ?? model.baseUrl,
		compat: mergeCompat(model.compat, config.compat),
	}));
	for (const definition of config.models ?? []) {
		const existingIndex = models.findIndex((model) => model.id === definition.id);
		const defaults = existingIndex >= 0 ? models[existingIndex] : models[0];
		const model = modelFromJson(providerId, definition, config, defaults);
		if (existingIndex >= 0) models[existingIndex] = model;
		else models.push(model);
	}
	return models;
}

function applyExtension(
	providerId: string,
	models: readonly Model<Api>[],
	config: ProviderConfigInput | undefined,
): Model<Api>[] {
	if (!config) return [...models];
	if (!config.models) {
		return models.map((model) => ({
			...model,
			api: config.api ?? model.api,
			baseUrl: config.baseUrl ?? model.baseUrl,
			compat: mergeCompat(model.compat, config.compat),
		}));
	}
	validateExtensionModels(providerId, config.models);
	return config.models.map((definition) => {
		const defaults = models.find((model) => model.id === definition.id) ?? models[0];
		const api = definition.api ?? config.api ?? defaults?.api;
		if (!api) {
			throw new Error(
				`Provider ${providerId}, model ${definition.id}: no "api" specified. Set at provider or model level.`,
			);
		}
		const baseUrl = definition.baseUrl ?? config.baseUrl ?? defaults?.baseUrl;
		if (!baseUrl) throw new Error(`Provider ${providerId}: "baseUrl" is required when defining custom models.`);
		return {
			...definition,
			api,
			provider: providerId,
			baseUrl,
			headers: undefined,
			compat: mergeCompat(config.compat ?? defaults?.compat, definition.compat),
		};
	});
}

/** Validate untrusted extension model metadata before it can enter resolution. */
function validateExtensionModels(providerId: string, models: ProviderConfigInput["models"]): void {
	if (!Array.isArray(models)) {
		throw new Error(`Provider ${providerId}: "models" must be an array.`);
	}
	for (const rawModel of models as unknown[]) {
		if (typeof rawModel !== "object" || rawModel === null) {
			throw new Error(`Provider ${providerId}: model definition must be an object.`);
		}
		const model = rawModel as Record<string, unknown>;
		const id = model.id;
		if (typeof id !== "string" || id.trim().length === 0) {
			throw new Error(`Provider ${providerId}, model ${JSON.stringify(id)}: "id" must be a non-empty string.`);
		}
		for (const field of ["contextWindow", "maxTokens"] as const) {
			const value = model[field];
			if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
				throw new Error(`Provider ${providerId}, model ${id}: invalid ${field}`);
			}
		}
	}
}

function adaptOAuth(config: ExtensionOAuthConfig): OAuthAuth {
	return {
		name: config.name,
		login: async (callbacks) => {
			const credential = await config.login({
				onAuth: (info) => callbacks.notify({ type: "auth_url", ...info }),
				onDeviceCode: (info) => callbacks.notify({ type: "device_code", ...info }),
				onPrompt: (prompt) => callbacks.prompt({ type: "text", ...prompt }),
				onProgress: (message) => callbacks.notify({ type: "progress", message }),
				onManualCodeInput: () => callbacks.prompt({ type: "manual_code", message: "Paste the authorization code" }),
				onSelect: (prompt) => callbacks.prompt({ type: "select", ...prompt }),
				signal: callbacks.signal,
			});
			return { ...credential, type: "oauth" };
		},
		refresh: async (credential) => ({ ...(await config.refreshToken(credential)), type: "oauth" }),
		toAuth: async (credential) => ({ apiKey: config.getApiKey(credential) }),
	};
}

function withConfiguredAuth(auth: ModelAuth, headers: ProviderHeaders | undefined, authHeader: boolean): ModelAuth {
	let mergedHeaders = mergeProviderHeaders(auth.headers, headers);
	if (authHeader) {
		if (!auth.apiKey) throw new Error("authHeader requires a resolved API key");
		mergedHeaders = mergeProviderHeaders(mergedHeaders, { Authorization: `Bearer ${auth.apiKey}` });
	}
	return { ...auth, headers: mergedHeaders };
}

function configuredApiKey(
	config: ModelsJsonProvider | undefined,
	extension: ProviderConfigInput | undefined,
): string | undefined {
	return extension?.apiKey ?? config?.apiKey;
}

function configuredHeaders(
	config: ModelsJsonProvider | undefined,
	extension: ProviderConfigInput | undefined,
): ProviderHeaders | undefined {
	return mergeProviderHeaders(config?.headers, extension?.headers);
}

async function configContextEnv(
	values: readonly (string | null)[],
	ctx: AuthContext,
	explicit?: Record<string, string>,
): Promise<Record<string, string> | undefined> {
	const env = { ...explicit };
	for (const name of new Set(values.flatMap((value) => (value === null ? [] : getConfigValueEnvVarNames(value))))) {
		if (env[name] !== undefined) continue;
		const value = await ctx.env(name);
		if (value !== undefined) env[name] = value;
	}
	return Object.keys(env).length > 0 ? env : undefined;
}

function composeApiKeyAuth(
	providerId: string,
	base: Provider | undefined,
	config: ModelsJsonProvider | undefined,
	extension: ProviderConfigInput | undefined,
): ApiKeyAuth | undefined {
	const inherited = base?.auth.apiKey;
	const rawKey = configuredApiKey(config, extension);
	const oauth = extension?.oauth ?? base?.auth.oauth;
	// OAuth-only providers get no fabricated API-key login method.
	if (!inherited && rawKey === undefined && oauth) return undefined;
	const rawHeaders = configuredHeaders(config, extension);
	const authHeader = extension?.authHeader ?? config?.authHeader ?? false;
	return {
		name: inherited?.name ?? "API key",
		login:
			inherited?.login ??
			(async (interaction: AuthInteraction) => ({
				type: "api_key",
				key: await interaction.prompt({ type: "secret", message: "Enter API key" }),
			})),
		check: async (input) => {
			if (input.credential) {
				if (inherited?.check) return inherited.check(input);
				if (input.credential.key) return { type: "api_key", source: "stored credential" };
				const resolved = await inherited?.resolve(input);
				return resolved ? { type: "api_key", source: resolved.source } : undefined;
			}
			if (rawKey !== undefined) {
				if (isCommandConfigValue(rawKey)) return { type: "api_key", source: "configured API key" };
				const envNames = getConfigValueEnvVarNames(rawKey);
				for (const name of envNames) {
					if ((await input.ctx.env(name)) === undefined) return undefined;
				}
				return { type: "api_key", source: "configured API key" };
			}
			if (inherited?.check) return inherited.check(input);
			const resolved = await inherited?.resolve(input);
			return resolved ? { type: "api_key", source: resolved.source } : undefined;
		},
		resolve: async (input) => {
			let result: AuthResult | undefined;
			if (input.credential) {
				result = inherited
					? await inherited.resolve(input)
					: input.credential.key
						? { auth: { apiKey: input.credential.key }, env: input.credential.env, source: "stored credential" }
						: undefined;
			} else if (rawKey !== undefined) {
				const env = await configContextEnv([rawKey], input.ctx);
				const key = resolveConfigValueOrThrow(rawKey, `API key for provider "${providerId}"`, env);
				result = inherited
					? await inherited.resolve({ ...input, credential: { type: "api_key", key } })
					: { auth: { apiKey: key }, source: "configured API key" };
			} else {
				result = await inherited?.resolve(input);
			}
			if (!result) return undefined;
			const explicitEnv = { ...(input.credential?.env ?? {}), ...(result.env ?? {}) };
			const headerEnv = await configContextEnv(Object.values(rawHeaders ?? {}), input.ctx, explicitEnv);
			const headers = resolveHeadersOrThrow(rawHeaders, `provider "${providerId}"`, headerEnv);
			return { ...result, auth: withConfiguredAuth(result.auth, headers, authHeader) };
		},
	};
}

function composeOAuthAuth(
	providerId: string,
	base: Provider | undefined,
	config: ModelsJsonProvider | undefined,
	extension: ProviderConfigInput | undefined,
): OAuthAuth | undefined {
	const oauth = extension?.oauth ? adaptOAuth(extension.oauth) : base?.auth.oauth;
	if (!oauth) return undefined;
	const rawHeaders = configuredHeaders(config, extension);
	const authHeader = extension?.authHeader ?? config?.authHeader ?? false;
	return {
		...oauth,
		toAuth: async (credential) => {
			const auth = await oauth.toAuth(credential);
			const env = credential.env;
			const headers = resolveHeadersOrThrow(
				rawHeaders,
				`provider "${providerId}"`,
				typeof env === "object" && env !== null ? (env as Record<string, string>) : undefined,
			);
			return withConfiguredAuth(auth, headers, authHeader);
		},
	};
}

function rawModelHeaders(
	model: Model<Api>,
	config: ModelsJsonProvider | undefined,
	extension: ProviderConfigInput | undefined,
): ProviderHeaders | undefined {
	const definition = config?.models?.find((entry) => entry.id === model.id);
	const extensionModel = extension?.models?.find((entry) => entry.id === model.id);
	return mergeProviderHeaders(definition?.headers, extensionModel?.headers);
}

export function validateExtensionProvider(
	providerId: string,
	base: Provider | undefined,
	modelsConfig: ModelsJsonProvider | undefined,
	extension: ProviderConfigInput,
): void {
	if (extension.streamSimple && !extension.api) {
		throw new Error(`Provider ${providerId}: "api" is required when registering streamSimple.`);
	}
	applyExtension(providerId, applyModelsJson(providerId, base?.getModels() ?? [], modelsConfig), extension);
}

/** Compose base, models.json, and extension layers without reading credentials. */
export function composeModelProvider(
	providerId: string,
	base: Provider | undefined,
	modelConfig: ModelConfig,
	extension: ProviderConfigInput | undefined,
): Provider {
	const config = modelConfig.getProvider(providerId);
	let extensionOAuthCredential: OAuthCredentials | undefined;
	let refreshedExtensionModels: ProviderConfigInput["models"];
	let nextRefreshGeneration = 0;
	let latestCommittedRefreshGeneration = 0;
	const currentExtension = (): ProviderConfigInput | undefined =>
		extension && refreshedExtensionModels ? { ...extension, models: refreshedExtensionModels } : extension;
	const getModels = () => {
		let models = applyExtension(
			providerId,
			applyModelsJson(providerId, base?.getModels() ?? [], config),
			currentExtension(),
		);
		if (extensionOAuthCredential && extension?.oauth?.modifyModels) {
			models = extension.oauth.modifyModels(models, extensionOAuthCredential);
		}
		return models;
	};
	// Validate eagerly so registration/reload reports structural errors immediately.
	getModels();
	const apiKey = composeApiKeyAuth(providerId, base, config, extension);
	const oauth = composeOAuthAuth(providerId, base, config, extension);
	if (!apiKey && !oauth) throw new Error(`Provider ${providerId}: no authentication method configured.`);

	const supportsBaseApi = (model: Model<Api>) => base?.getModels().some((entry) => entry.api === model.api) ?? false;
	const streamWith = (
		model: Model<Api>,
		context: Context,
		options: StreamOptions | undefined,
		simple: boolean,
	): AssistantMessageEventStream =>
		lazyStream(model, async () => {
			if (extension?.streamSimple && model.api === extension.api) {
				return extension.streamSimple(model, context, options as SimpleStreamOptions);
			}
			if (base && supportsBaseApi(model)) {
				return simple
					? base.streamSimple(model, context, options as SimpleStreamOptions)
					: base.stream(model, context, options);
			}
			const api = getApiProvider(model.api);
			if (!api) throw new Error(`No API provider registered for api: ${model.api}`);
			return simple
				? api.streamSimple(model, context, options as SimpleStreamOptions)
				: api.stream(model, context, options);
		});

	return {
		id: providerId,
		name: extension?.name ?? config?.name ?? base?.name ?? extension?.oauth?.name ?? providerId,
		baseUrl: extension?.baseUrl ?? config?.baseUrl ?? base?.baseUrl,
		headers: base?.headers,
		auth: { ...(apiKey ? { apiKey } : {}), ...(oauth ? { oauth } : {}) },
		getModels,
		refreshModels:
			base?.refreshModels || extension?.refreshModels || extension?.oauth?.modifyModels
				? async (context) => {
						const generation = ++nextRefreshGeneration;
						await base?.refreshModels?.(context);
						if (context.signal?.aborted) return;
						let refreshed: ProviderConfigInput["models"] | undefined;
						if (extension?.refreshModels) {
							refreshed = await extension.refreshModels(context);
							if (context.signal?.aborted) return;
							// Validate before publishing the new synchronous list.
							applyExtension(providerId, applyModelsJson(providerId, base?.getModels() ?? [], config), {
								...extension,
								models: refreshed,
							});
						}
						if (context.signal?.aborted || generation < latestCommittedRefreshGeneration) return;
						latestCommittedRefreshGeneration = generation;
						if (refreshed) {
							refreshedExtensionModels = refreshed;
							// `extension` is ModelRuntime's private effective config object. Keeping
							// it current lets request-time header resolution see dynamic models.
							extension!.models = refreshed;
						}
						extensionOAuthCredential = context.credential?.type === "oauth" ? context.credential : undefined;
					}
				: undefined,
		filterModels: base?.filterModels
			? (models, credential: Credential | undefined) => base.filterModels!(models, credential)
			: undefined,
		stream: (model, context, options) => streamWith(model, context, options, false),
		streamSimple: (model, context, options) => streamWith(model, context, options, true),
	};
}

export function resolveConfiguredModelHeaders(
	model: Model<Api>,
	config: ModelsJsonProvider | undefined,
	extension: ProviderConfigInput | undefined,
	env?: Record<string, string>,
): ProviderHeaders | undefined {
	return mergeProviderHeaders(
		model.headers,
		resolveHeadersOrThrow(rawModelHeaders(model, config, extension), `model "${model.provider}/${model.id}"`, env),
	);
}

export interface CompatibilityRequestConfig {
	headers?: ProviderHeaders;
	authHeader: boolean;
}

export function resolveCompatibilityRequestConfig(
	model: Model<Api>,
	config: ModelsJsonProvider | undefined,
	extension: ProviderConfigInput | undefined,
): CompatibilityRequestConfig {
	const configured = resolveHeadersOrThrow(
		mergeProviderHeaders(configuredHeaders(config, extension), rawModelHeaders(model, config, extension)),
		`model "${model.provider}/${model.id}"`,
	);
	return {
		headers: mergeProviderHeaders(model.headers, configured),
		authHeader: extension?.authHeader ?? config?.authHeader ?? false,
	};
}

export function configuredRequestAuthStatus(
	config: ModelsJsonProvider | undefined,
	extension: ProviderConfigInput | undefined,
): AuthStatus | undefined {
	const value = configuredApiKey(config, extension);
	if (value === undefined) return undefined;
	if (isCommandConfigValue(value)) return { configured: true, source: "models_json_command" };
	const names = getConfigValueEnvVarNames(value);
	if (names.length > 0) {
		return isConfigValueConfigured(value)
			? { configured: true, source: "environment", label: names.join(", ") }
			: { configured: false };
	}
	return { configured: true, source: extension?.apiKey !== undefined ? "fallback" : "models_json_key" };
}

import { lazyStream } from "./api/lazy.ts";
import { defaultProviderAuthContext } from "./auth/context.ts";
import { InMemoryCredentialStore } from "./auth/credential-store.ts";
import { type AuthResolutionOverrides, ModelsError, resolveProviderAuth } from "./auth/resolve.ts";
import type {
	AuthCheck,
	AuthContext,
	AuthInteraction,
	AuthResult,
	AuthType,
	Credential,
	CredentialStore,
	ProviderAuth,
} from "./auth/types.ts";
import { InMemoryModelsStore, type ModelsStore, type ProviderModelsStore } from "./models-store.ts";
import type {
	Api,
	ApiStreamOptions,
	AssistantMessage,
	AssistantMessageEventStream,
	Context,
	Model,
	ModelCostRates,
	ModelThinkingLevel,
	ProviderApi,
	ProviderApiMap,
	ProviderHeaders,
	ProviderStreams,
	SimpleStreamOptions,
	StreamOptions,
	Usage,
} from "./types.ts";
import { mergeProviderHeaders } from "./utils/headers.ts";

export { ModelsError, type ModelsErrorCode } from "./auth/resolve.ts";

export interface RefreshModelsContext {
	/** Effective configured credential. OAuth is refreshed before network access. */
	credential?: Credential;
	/** Persistent catalog storage scoped to this provider. */
	store: ProviderModelsStore;
	/** False for cache-only restoration. */
	allowNetwork: boolean;
	/** Bypass provider freshness checks when network access is allowed. */
	force?: boolean;
	signal?: AbortSignal;
}

export interface ModelsRefreshOptions {
	allowNetwork?: boolean;
	/** Bypass provider freshness checks when network access is allowed. */
	force?: boolean;
	signal?: AbortSignal;
}

export interface ModelsRefreshResult {
	aborted: boolean;
	errors: ReadonlyMap<string, Error>;
}

/** Runtime unit that owns a model list, authentication, and stream dispatch. */
export interface Provider<TApi extends Api = Api> {
	readonly id: string;
	readonly name: string;
	readonly baseUrl?: string;
	readonly headers?: ProviderHeaders;
	readonly auth: ProviderAuth;

	/** Current last-known models. Runtime aggregation treats throws as an empty list. */
	getModels(): readonly Model<TApi>[];

	/** Restore a stored catalog and optionally refresh it from the network. */
	refreshModels?(context: RefreshModelsContext): Promise<void>;

	/** Optional credential-specific availability policy. */
	filterModels?(models: readonly Model<TApi>[], credential: Credential | undefined): readonly Model<TApi>[];

	stream<T extends TApi>(
		model: Model<T>,
		context: Context,
		options?: ApiStreamOptions<T>,
	): AssistantMessageEventStream;

	streamSimple(model: Model<TApi>, context: Context, options?: SimpleStreamOptions): AssistantMessageEventStream;
}

export interface ModelsStreamTransforms {
	/** Runs once after auth, model, and explicit request headers have been assembled. */
	transformHeaders?: (headers: ProviderHeaders) => ProviderHeaders | Promise<ProviderHeaders>;
}

export type ModelsApiStreamOptions<TApi extends Api> = ApiStreamOptions<TApi> & ModelsStreamTransforms;
export type ModelsSimpleStreamOptions = SimpleStreamOptions & ModelsStreamTransforms;

export interface Models {
	getProviders(): readonly Provider[];
	getProvider(id: string): Provider | undefined;
	getModels(provider?: string): readonly Model<Api>[];
	getModel(provider: string, id: string): Model<Api> | undefined;

	/** Refresh every configured dynamic provider concurrently. */
	refresh(options?: ModelsRefreshOptions): Promise<ModelsRefreshResult>;

	/** Check configuration without refreshing OAuth credentials. */
	checkAuth(providerId: string): Promise<AuthCheck | undefined>;

	/** Return models belonging to providers with complete auth configuration. */
	getAvailable(providerId?: string): Promise<readonly Model<Api>[]>;

	getAuth(providerId: string, overrides?: AuthResolutionOverrides): Promise<AuthResult | undefined>;
	getAuth(model: Model<Api>, overrides?: AuthResolutionOverrides): Promise<AuthResult | undefined>;

	login(providerId: string, type: AuthType, interaction: AuthInteraction): Promise<Credential>;
	logout(providerId: string): Promise<void>;

	stream<TApi extends Api>(
		model: Model<TApi>,
		context: Context,
		options?: ModelsApiStreamOptions<TApi>,
	): AssistantMessageEventStream;

	complete<TApi extends Api>(
		model: Model<TApi>,
		context: Context,
		options?: ModelsApiStreamOptions<TApi>,
	): Promise<AssistantMessage>;

	streamSimple(model: Model<Api>, context: Context, options?: ModelsSimpleStreamOptions): AssistantMessageEventStream;
	completeSimple(model: Model<Api>, context: Context, options?: ModelsSimpleStreamOptions): Promise<AssistantMessage>;
}

export interface MutableModels extends Models {
	setProvider(provider: Provider): void;
	deleteProvider(id: string): void;
	clearProviders(): void;
}

export interface CreateModelsOptions {
	credentials?: CredentialStore;
	modelsStore?: ModelsStore;
	authContext?: AuthContext;
}

class ModelsImpl implements MutableModels {
	private providers = new Map<string, Provider>();
	private providerStores = new Map<string, ProviderModelsStore>();
	private credentials: CredentialStore;
	private modelsStore: ModelsStore;
	private authContext: AuthContext;

	constructor(options?: CreateModelsOptions) {
		this.credentials = options?.credentials ?? new InMemoryCredentialStore();
		this.modelsStore = options?.modelsStore ?? new InMemoryModelsStore();
		this.authContext = options?.authContext ?? defaultProviderAuthContext();
	}

	setProvider(provider: Provider): void {
		this.providers.set(provider.id, provider);
	}

	deleteProvider(id: string): void {
		this.providers.delete(id);
	}

	clearProviders(): void {
		this.providers.clear();
	}

	getProviders(): readonly Provider[] {
		return Array.from(this.providers.values());
	}

	getProvider(id: string): Provider | undefined {
		return this.providers.get(id);
	}

	getModels(provider?: string): readonly Model<Api>[] {
		if (provider !== undefined) {
			const entry = this.providers.get(provider);
			if (!entry) return [];
			try {
				return entry.getModels();
			} catch {
				return [];
			}
		}

		const models: Model<Api>[] = [];
		for (const entry of this.providers.values()) {
			try {
				models.push(...entry.getModels());
			} catch {
				// Provider discovery is best effort; direct provider calls retain precise errors.
			}
		}
		return models;
	}

	getModel(provider: string, id: string): Model<Api> | undefined {
		return this.getModels(provider).find((model) => model.id === id);
	}

	private getProviderStore(providerId: string): ProviderModelsStore {
		const existing = this.providerStores.get(providerId);
		if (existing) return existing;
		const store: ProviderModelsStore = {
			read: () => this.modelsStore.read(providerId),
			write: (entry) => this.modelsStore.write(providerId, entry),
			delete: () => this.modelsStore.delete(providerId),
		};
		this.providerStores.set(providerId, store);
		return store;
	}

	async refresh(options: ModelsRefreshOptions = {}): Promise<ModelsRefreshResult> {
		const allowNetwork = options.allowNetwork ?? true;
		const errors = new Map<string, Error>();
		const refreshable = Array.from(this.providers.values()).filter(
			(provider): provider is Provider & Required<Pick<Provider, "refreshModels">> =>
				provider.refreshModels !== undefined,
		);

		await Promise.all(
			refreshable.map(async (provider) => {
				if (options.signal?.aborted) return;
				const store = this.getProviderStore(provider.id);
				let stored: Credential | undefined;
				try {
					stored = await this.readCredential(provider.id);
					const credential = await this.resolveRefreshCredential(provider, stored, allowNetwork, options.signal);
					await provider.refreshModels({
						credential: credential ?? stored,
						store,
						// An unconfigured provider cannot authenticate a network refresh,
						// but its provider-owned cache is still useful at startup.
						allowNetwork: allowNetwork && credential !== undefined,
						force: options.force,
						signal: options.signal,
					});
				} catch (error) {
					if (!options.signal?.aborted) {
						errors.set(
							provider.id,
							error instanceof Error
								? error
								: new ModelsError("model_source", `Model refresh failed for ${provider.id}`, { cause: error }),
						);
					}
					try {
						await provider.refreshModels({
							credential: stored,
							store,
							allowNetwork: false,
							signal: options.signal,
						});
					} catch {
						// Keep the original failure; cache restoration is best effort here.
					}
				}
			}),
		);

		return { aborted: options.signal?.aborted ?? false, errors };
	}

	private async resolveRefreshCredential(
		provider: Provider,
		stored: Credential | undefined,
		allowNetwork: boolean,
		signal?: AbortSignal,
	): Promise<Credential | undefined> {
		if (stored?.type === "oauth") {
			const oauth = provider.auth.oauth;
			if (!oauth) return undefined;
			if (!allowNetwork || Date.now() < stored.expires) return stored;
			if (signal?.aborted) return undefined;
			const post = await this.credentials.modify(provider.id, async (current) => {
				if (current?.type !== "oauth" || Date.now() < current.expires) return undefined;
				return oauth.refresh(current, signal);
			});
			return post?.type === "oauth" ? post : undefined;
		}

		const apiKey = provider.auth.apiKey;
		if (!apiKey) return undefined;
		const credential = stored?.type === "api_key" ? stored : undefined;
		const result = await apiKey.resolve({ ctx: this.authContext, credential });
		if (!result) return undefined;
		return { type: "api_key", key: result.auth.apiKey, env: result.env };
	}

	private async readCredential(providerId: string): Promise<Credential | undefined> {
		try {
			return await this.credentials.read(providerId);
		} catch (error) {
			throw new ModelsError("auth", `Credential store read failed for ${providerId}`, { cause: error });
		}
	}

	private async checkProviderAuth(
		provider: Provider,
		credential: Credential | undefined,
	): Promise<AuthCheck | undefined> {
		if (credential?.type === "oauth") {
			return provider.auth.oauth ? { source: "OAuth", type: "oauth" } : undefined;
		}

		const apiKey = provider.auth.apiKey;
		if (!apiKey) return undefined;
		if (apiKey.check) {
			try {
				return await apiKey.check({
					ctx: this.authContext,
					credential: credential?.type === "api_key" ? credential : undefined,
				});
			} catch (error) {
				throw new ModelsError("auth", `API key auth check failed for provider ${provider.id}`, { cause: error });
			}
		}

		const resolution = await resolveProviderAuth(provider, this.credentials, this.authContext);
		return resolution ? { source: resolution.source, type: "api_key" } : undefined;
	}

	async checkAuth(providerId: string): Promise<AuthCheck | undefined> {
		const provider = this.providers.get(providerId);
		if (!provider) return undefined;
		return this.checkProviderAuth(provider, await this.readCredential(providerId));
	}

	async getAvailable(providerId?: string): Promise<readonly Model<Api>[]> {
		const providers = providerId
			? [this.providers.get(providerId)].filter((provider) => provider !== undefined)
			: this.getProviders();
		const checks = await Promise.all(
			providers.map(async (provider) => {
				const credential = await this.readCredential(provider.id);
				return { provider, credential, auth: await this.checkProviderAuth(provider, credential) };
			}),
		);
		return checks.flatMap(({ provider, credential, auth }) => {
			if (!auth) return [];
			const models = this.getModels(provider.id);
			return provider.filterModels?.(models, credential) ?? models;
		});
	}

	getAuth(providerId: string, overrides?: AuthResolutionOverrides): Promise<AuthResult | undefined>;
	getAuth(model: Model<Api>, overrides?: AuthResolutionOverrides): Promise<AuthResult | undefined>;
	async getAuth(
		providerOrModel: string | Model<Api>,
		overrides?: AuthResolutionOverrides,
	): Promise<AuthResult | undefined> {
		const providerId = typeof providerOrModel === "string" ? providerOrModel : providerOrModel.provider;
		const provider = this.providers.get(providerId);
		if (!provider) return undefined;
		const result = await resolveProviderAuth(provider, this.credentials, this.authContext, overrides);
		if (!result) return undefined;
		const modelHeaders = typeof providerOrModel === "string" ? undefined : providerOrModel.headers;
		return {
			...result,
			auth: {
				...result.auth,
				baseUrl: result.auth.baseUrl ?? provider.baseUrl,
				headers: mergeProviderHeaders(provider.headers, result.auth.headers, modelHeaders),
			},
		};
	}

	async login(providerId: string, type: AuthType, interaction: AuthInteraction): Promise<Credential> {
		const provider = this.providers.get(providerId);
		if (!provider) throw new ModelsError("provider", `Unknown provider: ${providerId}`);
		const method = type === "oauth" ? provider.auth.oauth : provider.auth.apiKey;
		if (!method?.login) {
			throw new ModelsError("auth", `${provider.name} does not support ${type} login`);
		}
		const credential = await method.login(interaction);
		try {
			await this.credentials.modify(providerId, async () => credential);
		} catch (error) {
			throw new ModelsError("auth", `Credential store modify failed for ${providerId}`, { cause: error });
		}
		return credential;
	}

	async logout(providerId: string): Promise<void> {
		try {
			await this.credentials.delete(providerId);
		} catch (error) {
			throw new ModelsError("auth", `Credential store delete failed for ${providerId}`, { cause: error });
		}
	}

	private requireProvider(model: Model<Api>): Provider {
		const provider = this.providers.get(model.provider);
		if (!provider) throw new ModelsError("provider", `Unknown provider: ${model.provider}`);
		return provider;
	}

	private async applyAuth<TOptions extends StreamOptions & ModelsStreamTransforms>(
		model: Model<Api>,
		options: TOptions | undefined,
	): Promise<{ requestModel: Model<Api>; requestOptions: StreamOptions | undefined }> {
		this.requireProvider(model);
		const resolution = await this.getAuth(model, { apiKey: options?.apiKey, env: options?.env });
		if (!resolution) throw new ModelsError("auth", `Provider is not configured: ${model.provider}`);

		let headers = mergeProviderHeaders(resolution.auth.headers, options?.headers);
		if (options?.transformHeaders) headers = await options.transformHeaders(headers ?? {});
		const env = resolution.env || options?.env ? { ...(resolution.env ?? {}), ...(options?.env ?? {}) } : undefined;
		const { headers: _modelHeaders, ...modelWithoutHeaders } = model;
		const requestModel = {
			...modelWithoutHeaders,
			baseUrl: resolution.auth.baseUrl ?? model.baseUrl,
		} as Model<Api>;
		const { transformHeaders: _transformHeaders, apiKey: _requestApiKey, ...providerOptions } = options ?? {};
		const requestOptions = {
			...providerOptions,
			...(resolution.auth.apiKey !== undefined ? { apiKey: resolution.auth.apiKey } : {}),
			headers,
			env,
		} as StreamOptions;
		return { requestModel, requestOptions };
	}

	stream<TApi extends Api>(
		model: Model<TApi>,
		context: Context,
		options?: ModelsApiStreamOptions<TApi>,
	): AssistantMessageEventStream {
		return lazyStream(model, async () => {
			const provider = this.requireProvider(model);
			const { requestModel, requestOptions } = await this.applyAuth(
				model,
				options as ModelsApiStreamOptions<Api> | undefined,
			);
			return provider.stream(requestModel as Model<TApi>, context, requestOptions as ApiStreamOptions<TApi>);
		});
	}

	async complete<TApi extends Api>(
		model: Model<TApi>,
		context: Context,
		options?: ModelsApiStreamOptions<TApi>,
	): Promise<AssistantMessage> {
		return this.stream(model, context, options).result();
	}

	streamSimple(model: Model<Api>, context: Context, options?: ModelsSimpleStreamOptions): AssistantMessageEventStream {
		return lazyStream(model, async () => {
			const provider = this.requireProvider(model);
			const { requestModel, requestOptions } = await this.applyAuth(model, options);
			return provider.streamSimple(requestModel, context, requestOptions as SimpleStreamOptions);
		});
	}

	async completeSimple(
		model: Model<Api>,
		context: Context,
		options?: ModelsSimpleStreamOptions,
	): Promise<AssistantMessage> {
		return this.streamSimple(model, context, options).result();
	}
}

export function createModels(options?: CreateModelsOptions): MutableModels {
	return new ModelsImpl(options);
}

export interface CreateProviderOptions<TApi extends Api = Api> {
	id: string;
	/** Display name. Defaults to the provider id. */
	name?: string;
	baseUrl?: string;
	headers?: ProviderHeaders;
	auth: ProviderAuth;
	/** Static baseline models. A function preserves compatibility with externally managed catalogs. */
	models: readonly Model<TApi>[] | (() => readonly Model<TApi>[]);
	/**
	 * Fetch a dynamic overlay. createProvider owns cache restoration, persistence, and refresh deduplication.
	 * Mutually exclusive with refreshModels.
	 */
	fetchModels?: (context: RefreshModelsContext) => Promise<readonly Model<TApi>[]>;
	/**
	 * Advanced compatibility hook for providers that manage their own catalog lifecycle.
	 * Mutually exclusive with fetchModels.
	 */
	refreshModels?: Provider<TApi>["refreshModels"];
	filterModels?: Provider<TApi>["filterModels"];
	/** One implementation for all models, or implementations keyed by model API. */
	api: ProviderStreams | Partial<Record<TApi, ProviderStreams>>;
}

interface RefreshIntent {
	store: ProviderModelsStore;
	allowNetwork: boolean;
	force: boolean;
	signal?: AbortSignal;
	credential?: Credential;
}

function structurallyEqual(left: unknown, right: unknown, seen = new WeakMap<object, object>()): boolean {
	if (Object.is(left, right)) return true;
	if (typeof left !== "object" || left === null || typeof right !== "object" || right === null) return false;
	const previous = seen.get(left);
	if (previous === right) return true;
	seen.set(left, right);
	if (Array.isArray(left) || Array.isArray(right)) {
		if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
		return left.every((value, index) => structurallyEqual(value, right[index], seen));
	}
	const leftKeys = Object.keys(left).sort();
	const rightKeys = Object.keys(right).sort();
	if (leftKeys.length !== rightKeys.length || leftKeys.some((key, index) => key !== rightKeys[index])) return false;
	return leftKeys.every((key) =>
		structurallyEqual((left as Record<string, unknown>)[key], (right as Record<string, unknown>)[key], seen),
	);
}

function sameRefreshIntent(left: RefreshIntent, right: RefreshIntent): boolean {
	return (
		left.store === right.store &&
		left.allowNetwork === right.allowNetwork &&
		left.force === right.force &&
		left.signal === right.signal &&
		structurallyEqual(left.credential, right.credential)
	);
}

/** Build a provider from catalog, auth, and stream components. */
export function createProvider<TApi extends Api = Api>(input: CreateProviderOptions<TApi>): Provider<TApi> {
	if (input.fetchModels && input.refreshModels) {
		throw new ModelsError("model_source", `Provider ${input.id} cannot configure both fetchModels and refreshModels`);
	}

	const baselineModels = input.models;
	let dynamicModels: readonly Model<TApi>[] = [];
	let refreshGeneration = 0;
	let publishedGeneration = 0;
	const inflightRefreshes: Array<RefreshIntent & { promise: Promise<void> }> = [];
	const fetchModels = input.fetchModels;
	const currentModels = (): readonly Model<TApi>[] => {
		const baseline = typeof baselineModels === "function" ? baselineModels() : baselineModels;
		const merged = [...baseline];
		const indexesById = new Map(merged.map((model, index) => [model.id, index]));
		for (const model of dynamicModels) {
			const index = indexesById.get(model.id);
			if (index === undefined) {
				indexesById.set(model.id, merged.length);
				merged.push(model);
			} else {
				merged[index] = model;
			}
		}
		return merged;
	};
	const single =
		typeof (input.api as ProviderStreams).stream === "function" ? (input.api as ProviderStreams) : undefined;
	const byApi = single ? undefined : (input.api as Partial<Record<string, ProviderStreams>>);

	const dispatch = (
		model: Model<Api>,
		run: (streams: ProviderStreams) => AssistantMessageEventStream,
	): AssistantMessageEventStream => {
		const streams = single ?? byApi?.[model.api];
		if (!streams) {
			return lazyStream(model, async () => {
				throw new ModelsError("stream", `Provider ${input.id} has no API implementation for "${model.api}"`);
			});
		}
		return run(streams);
	};

	return {
		id: input.id,
		name: input.name ?? input.id,
		baseUrl: input.baseUrl,
		headers: input.headers,
		auth: input.auth,
		getModels: currentModels,
		refreshModels: fetchModels
			? (context) => {
					const intent: RefreshIntent = {
						store: context.store,
						allowNetwork: context.allowNetwork,
						force: context.force ?? false,
						signal: context.signal,
						credential: context.credential,
					};
					const existing = inflightRefreshes.find((entry) => sameRefreshIntent(entry, intent));
					if (existing) return existing.promise;
					const generation = ++refreshGeneration;
					const promise = (async () => {
						try {
							const stored = await context.store.read();
							if (stored && generation >= publishedGeneration) {
								dynamicModels = stored.models
									.filter((model) => model.provider === input.id)
									.map((model) => model as Model<TApi>);
								publishedGeneration = generation;
							}
							if (!context.allowNetwork || context.signal?.aborted) return;

							const refreshed = await fetchModels(context);
							if (context.signal?.aborted || generation < publishedGeneration) return;
							dynamicModels = refreshed;
							publishedGeneration = generation;
							await context.store.write({ models: refreshed, checkedAt: Date.now() });
						} finally {
							const index = inflightRefreshes.findIndex((entry) => entry.promise === promise);
							if (index >= 0) inflightRefreshes.splice(index, 1);
						}
					})();
					inflightRefreshes.push({ ...intent, promise });
					return promise;
				}
			: input.refreshModels,
		filterModels: input.filterModels,
		stream: (model, context, options) =>
			dispatch(model, (streams) => streams.stream(model, context, options as StreamOptions)),
		streamSimple: (model, context, options) =>
			dispatch(model, (streams) => streams.streamSimple(model, context, options)),
	};
}

/** Runtime type guard for dynamically discovered models. */
export function hasApi<TApi extends Api>(model: Model<Api>, api: TApi): model is Model<TApi> {
	return model.api === api;
}

/**
 * Optional process-local catalog for hosts that explicitly provide one.
 * REPI does not populate this registry from a generated model file; its model
 * declarations come from models.json or REPI_* environment metadata instead.
 */
const modelRegistry: Map<string, Map<string, Model<Api>>> = new Map();

export type ExternalModelCatalog = Readonly<{
	[provider: string]: Readonly<{
		[modelId: string]: Model<Api>;
	}>;
}>;

export function registerModelCatalog(catalog: ExternalModelCatalog, options: { replace?: boolean } = {}): void {
	if (options.replace !== false) modelRegistry.clear();
	for (const [provider, models] of Object.entries(catalog)) {
		const providerModels = modelRegistry.get(provider) ?? new Map<string, Model<Api>>();
		for (const [id, model] of Object.entries(models)) providerModels.set(id, model);
		modelRegistry.set(provider, providerModels);
	}
}

export function clearModelCatalog(): void {
	modelRegistry.clear();
}

/**
 * Legacy lookup shape. The return type retains transport hints for existing
 * callers, but the process-local catalog is empty until a host registers it.
 * Use `findModel` when absence must be represented in the type.
 */
export function getModel<TProvider extends keyof ProviderApiMap>(
	provider: TProvider,
	modelId: string,
): Model<ProviderApi<TProvider>>;
export function getModel<TApi extends Api = Api>(provider: string, modelId: string): Model<TApi>;
export function getModel<TApi extends Api = Api>(provider: string, modelId: string): Model<TApi> {
	return modelRegistry.get(provider)?.get(modelId) as Model<TApi>;
}

export function findModel<TProvider extends keyof ProviderApiMap>(
	provider: TProvider,
	modelId: string,
): Model<ProviderApi<TProvider>> | undefined;
export function findModel<TApi extends Api = Api>(provider: string, modelId: string): Model<TApi> | undefined;
export function findModel<TApi extends Api = Api>(provider: string, modelId: string): Model<TApi> | undefined {
	return modelRegistry.get(provider)?.get(modelId) as Model<TApi> | undefined;
}

export function getProviders(): string[] {
	return [...modelRegistry.keys()];
}

export function getModels<TProvider extends keyof ProviderApiMap>(provider: TProvider): Model<ProviderApi<TProvider>>[];
export function getModels<TApi extends Api = Api>(provider: string): Model<TApi>[];
export function getModels<TApi extends Api = Api>(provider: string): Model<TApi>[] {
	return [...(modelRegistry.get(provider)?.values() ?? [])] as Model<TApi>[];
}

export function calculateCost<TApi extends Api>(model: Model<TApi>, usage: Usage): Usage["cost"] {
	const inputTokens = usage.input + usage.cacheRead + usage.cacheWrite;
	let rates: ModelCostRates = model.cost;
	let matchedThreshold = -1;
	for (const tier of model.cost.tiers ?? []) {
		if (inputTokens > tier.inputTokensAbove && tier.inputTokensAbove > matchedThreshold) {
			rates = tier;
			matchedThreshold = tier.inputTokensAbove;
		}
	}

	// Anthropic charges 2x base input for 1h cache writes.
	const longWrite = usage.cacheWrite1h ?? 0;
	const shortWrite = usage.cacheWrite - longWrite;
	usage.cost.input = (rates.input / 1000000) * usage.input;
	usage.cost.output = (rates.output / 1000000) * usage.output;
	usage.cost.cacheRead = (rates.cacheRead / 1000000) * usage.cacheRead;
	usage.cost.cacheWrite = (rates.cacheWrite * shortWrite + rates.input * 2 * longWrite) / 1000000;
	usage.cost.total = usage.cost.input + usage.cost.output + usage.cost.cacheRead + usage.cost.cacheWrite;
	return usage.cost;
}

const EXTENDED_THINKING_LEVELS: ModelThinkingLevel[] = ["off", "minimal", "low", "medium", "high", "xhigh", "max"];

export function getSupportedThinkingLevels<TApi extends Api>(model: Model<TApi>): ModelThinkingLevel[] {
	if (!model.reasoning) return ["off"];

	return EXTENDED_THINKING_LEVELS.filter((level) => {
		const mapped = model.thinkingLevelMap?.[level];
		if (mapped === null) return false;
		if (level === "xhigh" || level === "max") return mapped !== undefined;
		return true;
	});
}

export function clampThinkingLevel<TApi extends Api>(
	model: Model<TApi>,
	level: ModelThinkingLevel,
): ModelThinkingLevel {
	const availableLevels = getSupportedThinkingLevels(model);
	if (availableLevels.includes(level)) return level;

	const requestedIndex = EXTENDED_THINKING_LEVELS.indexOf(level);
	if (requestedIndex === -1) return availableLevels[0] ?? "off";

	for (let i = requestedIndex; i < EXTENDED_THINKING_LEVELS.length; i++) {
		const candidate = EXTENDED_THINKING_LEVELS[i];
		if (availableLevels.includes(candidate)) return candidate;
	}
	for (let i = requestedIndex - 1; i >= 0; i--) {
		const candidate = EXTENDED_THINKING_LEVELS[i];
		if (availableLevels.includes(candidate)) return candidate;
	}
	return availableLevels[0] ?? "off";
}

/**
 * Check if two models are equal by comparing both their id and provider.
 * Returns false if either model is null or undefined.
 */
export function modelsAreEqual<TApi extends Api>(
	a: Model<TApi> | null | undefined,
	b: Model<TApi> | null | undefined,
): boolean {
	if (!a || !b) return false;
	return a.id === b.id && a.provider === b.provider;
}

import { join } from "node:path";
import {
	type Api,
	type ApiStreamOptions,
	type AssistantMessage,
	type AssistantMessageEventStream,
	type AuthCheck,
	type AuthContext,
	type AuthInteraction,
	type AuthResult,
	type AuthType,
	type Context,
	type Credential,
	type CredentialInfo,
	type CredentialStore,
	createModels,
	lazyStream,
	type Model,
	type Models,
	type ModelsApiStreamOptions,
	ModelsError,
	type ModelsRefreshOptions,
	type ModelsRefreshResult,
	type ModelsSimpleStreamOptions,
	type ModelsStore,
	type ModelsStreamTransforms,
	type MutableModels,
	mergeProviderHeaders,
	type Provider,
	type ProviderEnv,
	type SimpleStreamOptions,
	type StreamOptions,
} from "@pi-recon/repi-ai";
import { registerOAuthProvider, unregisterOAuthProviders } from "@pi-recon/repi-ai/oauth";
import { getAgentDir } from "../config.ts";
import { AuthStorage, type CredentialStoreChange } from "./auth-storage.ts";
import { ModelConfig } from "./model-config.ts";
import { FileModelsStore, getModelsStorePath, InMemoryCodingAgentModelsStore } from "./models-store.ts";
import {
	type AuthStatus,
	type CompatibilityRequestConfig,
	composeModelProvider,
	configuredRequestAuthStatus,
	type ProviderConfigInput,
	resolveCompatibilityRequestConfig,
	resolveConfiguredModelHeaders,
	validateExtensionProvider,
} from "./provider-composer.ts";
import { getRepiEnvProviderConfig } from "./repi-env-provider.ts";
import { RuntimeCredentials } from "./runtime-credentials.ts";

interface ModelRuntimeSnapshot {
	all: readonly Model<Api>[];
	available: readonly Model<Api>[];
	configuredProviders: ReadonlySet<string>;
	credentialProviders: ReadonlySet<string>;
	credentialTypes: ReadonlyMap<string, AuthType>;
	auth: ReadonlyMap<string, AuthCheck | undefined>;
}

let nextModelRuntimeSourceId = 0;

export interface CreateModelRuntimeOptions {
	/** Credential persistence. Defaults to the existing locked auth.json store. */
	credentials?: CredentialStore;
	authPath?: string;
	modelsPath?: string | null;
	modelsStore?: ModelsStore;
	modelsStorePath?: string;
	/** Explicit provider roots. Omit to use no generated/built-in catalog. */
	providers?: readonly Provider[];
	/** Injectable provider environment/filesystem context for hosts and tests. */
	authContext?: AuthContext;
	allowModelNetwork?: boolean;
	modelRefreshTimeoutMs?: number;
}

export interface ModelRuntimeAuthOverrides {
	apiKey?: string;
	env?: ProviderEnv;
}

function isTruthyEnvFlag(value: string | undefined): boolean {
	if (!value) return false;
	return value === "1" || value.toLowerCase() === "true" || value.toLowerCase() === "yes";
}

function modelNetworkEnabledByDefault(): boolean {
	const offline = process.env.REPI_OFFLINE ?? process.env.PI_OFFLINE;
	return !isTruthyEnvFlag(offline);
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

/**
 * Credential-aware model/provider runtime. Configuration composition remains
 * credential-blind; this class is the sole request auth/header/env assembler.
 */
export class ModelRuntime implements Models {
	private readonly models: MutableModels;
	private readonly credentials: RuntimeCredentials;
	private readonly baseProviders = new Map<string, Provider>();
	private readonly nativeExtensionProviders = new Map<string, Provider>();
	private readonly extensionProviders = new Map<string, ProviderConfigInput>();
	private environmentProvider: { providerId: string; config: ProviderConfigInput } | undefined;
	private readonly compositionErrors = new Map<string, string>();
	private readonly modelsPath: string | undefined;
	private readonly allowModelNetwork: boolean;
	private readonly globalRegistrationSource: string;
	private readonly unsubscribeCredentialChanges: () => void;
	private disposed = false;
	private config: ModelConfig;
	private snapshot: ModelRuntimeSnapshot = {
		all: [],
		available: [],
		configuredProviders: new Set(),
		credentialProviders: new Set(),
		credentialTypes: new Map(),
		auth: new Map(),
	};
	private availabilityRefresh: Promise<void> | undefined;
	private availabilityError: string | undefined;
	private environmentProviderError: string | undefined;
	private refreshErrors = new Map<string, Error>();
	private refreshFailure: string | undefined;
	private refreshEpoch = 0;
	private credentialEpoch = 0;
	private readonly refreshEpochBySignal = new WeakMap<AbortSignal, number>();
	private readonly refreshControllers = new Set<AbortController>();
	private catalogsFrozen = false;

	private constructor(
		credentials: RuntimeCredentials,
		config: ModelConfig,
		modelsPath: string | undefined,
		modelsStore: ModelsStore,
		providers: readonly Provider[],
		allowModelNetwork: boolean,
		authContext: AuthContext | undefined,
	) {
		this.credentials = credentials;
		this.config = config;
		this.modelsPath = modelsPath;
		this.allowModelNetwork = allowModelNetwork;
		this.globalRegistrationSource = `coding-agent:model-runtime:${++nextModelRuntimeSourceId}`;
		this.unsubscribeCredentialChanges = this.credentials.subscribe((change) => this.handleCredentialChange(change));
		for (const provider of providers) this.baseProviders.set(provider.id, provider);
		this.models = createModels({ credentials, modelsStore, authContext });
		this.rebuildProviders();
	}

	/** Release credential listeners and process-global compatibility registrations owned by this runtime. */
	dispose(): void {
		if (this.disposed) return;
		this.disposed = true;
		this.refreshEpoch++;
		this.credentialEpoch++;
		for (const controller of this.refreshControllers) {
			controller.abort(new Error("Model runtime disposed"));
		}
		this.refreshControllers.clear();
		try {
			this.unsubscribeCredentialChanges();
		} finally {
			try {
				this.credentials.dispose();
			} finally {
				unregisterOAuthProviders(this.globalRegistrationSource);
			}
		}
	}

	static async create(options: CreateModelRuntimeOptions = {}): Promise<ModelRuntime> {
		const persistentCredentials = options.credentials ?? AuthStorage.create(options.authPath).asCredentialStore();
		const modelsPath =
			options.modelsPath === null ? undefined : (options.modelsPath ?? join(getAgentDir(), "models.json"));
		const config = await ModelConfig.load(modelsPath);
		const modelsStore =
			options.modelsStore ??
			(modelsPath
				? new FileModelsStore(options.modelsStorePath ?? getModelsStorePath(modelsPath))
				: new InMemoryCodingAgentModelsStore());
		const allowModelNetwork = options.allowModelNetwork ?? modelNetworkEnabledByDefault();
		const credentials = new RuntimeCredentials(persistentCredentials);
		let runtime: ModelRuntime;
		try {
			runtime = new ModelRuntime(
				credentials,
				config,
				modelsPath,
				modelsStore,
				options.providers ?? [],
				allowModelNetwork,
				options.authContext,
			);
		} catch (error) {
			credentials.dispose();
			throw error;
		}

		try {
			runtime.reloadEnvironmentProvider();
			runtime.rebuildProviders();

			const controller = new AbortController();
			const timeoutMs = options.modelRefreshTimeoutMs ?? 15_000;
			const startupRefresh = (async () => {
				await runtime.refresh({ allowNetwork: false, signal: controller.signal });
				if (allowModelNetwork && !controller.signal.aborted) {
					await runtime.refresh({ allowNetwork: true, signal: controller.signal });
				}
			})();
			if (!allowModelNetwork || timeoutMs <= 0) {
				await startupRefresh;
				return runtime;
			}

			let timeout: ReturnType<typeof setTimeout> | undefined;
			const deadline = new Promise<"timeout">((resolve) => {
				timeout = setTimeout(() => {
					controller.abort(new Error(`Model refresh timed out after ${timeoutMs}ms`));
					runtime.expireStartupRefresh(timeoutMs);
					resolve("timeout");
				}, timeoutMs);
			});
			try {
				const outcome = await Promise.race([startupRefresh.then(() => "complete" as const), deadline]);
				if (outcome === "timeout") void startupRefresh.catch(() => {});
			} finally {
				if (timeout) clearTimeout(timeout);
			}
			return runtime;
		} catch (error) {
			try {
				runtime.dispose();
			} catch {
				// Preserve the initialization error after best-effort cleanup.
			}
			throw error;
		}
	}

	private invalidateRefreshEpoch(): void {
		this.refreshEpoch++;
		this.availabilityRefresh = undefined;
	}

	private expireStartupRefresh(timeoutMs: number): void {
		this.invalidateRefreshEpoch();
		this.freezeModelCatalogs();
		this.refreshFailure = `Model refresh timed out after ${timeoutMs}ms`;
	}

	private freezeModelCatalogs(): void {
		if (this.catalogsFrozen) return;
		for (const provider of this.models.getProviders()) {
			let catalog: readonly Model<Api>[];
			try {
				catalog = structuredClone([...provider.getModels()]);
			} catch {
				catalog = [];
			}
			this.models.setProvider({
				id: provider.id,
				name: provider.name,
				baseUrl: provider.baseUrl,
				headers: provider.headers,
				auth: provider.auth,
				getModels: () => catalog,
				filterModels: provider.filterModels
					? (models, credential) => provider.filterModels!(models, credential)
					: undefined,
				stream: (model, context, streamOptions) => provider.stream(model, context, streamOptions),
				streamSimple: (model, context, streamOptions) => provider.streamSimple(model, context, streamOptions),
			});
		}
		this.catalogsFrozen = true;
		this.updateModelSnapshot();
	}

	private restoreLiveProviders(): void {
		if (!this.catalogsFrozen) return;
		this.catalogsFrozen = false;
		this.rebuildProviders();
	}

	private protectProvider(provider: Provider): Provider {
		return {
			id: provider.id,
			name: provider.name,
			baseUrl: provider.baseUrl,
			headers: provider.headers,
			auth: provider.auth,
			getModels: () => provider.getModels(),
			refreshModels: provider.refreshModels
				? async (context) => {
						const epoch = context.signal ? this.refreshEpochBySignal.get(context.signal) : undefined;
						const isCurrent = () =>
							!this.disposed &&
							(epoch === undefined || (epoch === this.refreshEpoch && context.signal?.aborted !== true));
						await provider.refreshModels!({
							...context,
							store: {
								read: () => context.store.read(),
								write: (entry) => (isCurrent() ? context.store.write(entry) : Promise.resolve()),
								delete: () => (isCurrent() ? context.store.delete() : Promise.resolve()),
							},
						});
					}
				: undefined,
			filterModels: provider.filterModels
				? (models, credential) => provider.filterModels!(models, credential)
				: undefined,
			stream: (model, context, streamOptions) => provider.stream(model, context, streamOptions),
			streamSimple: (model, context, streamOptions) => provider.streamSimple(model, context, streamOptions),
		};
	}

	private providerIds(): Set<string> {
		return new Set([
			...this.baseProviders.keys(),
			...this.nativeExtensionProviders.keys(),
			...this.config.getProviderIds(),
			...(this.environmentProvider ? [this.environmentProvider.providerId] : []),
			...this.extensionProviders.keys(),
		]);
	}

	private providerOverlay(providerId: string): ProviderConfigInput | undefined {
		const environment =
			this.environmentProvider?.providerId === providerId ? this.environmentProvider.config : undefined;
		const extension = this.extensionProviders.get(providerId);
		if (!environment) return extension;
		if (!extension) return environment;
		const effective: ProviderConfigInput = { ...environment };
		for (const [key, value] of Object.entries(extension)) {
			if (value !== undefined) (effective as Record<string, unknown>)[key] = value;
		}
		return effective;
	}

	private reloadEnvironmentProvider(): void {
		this.environmentProvider = undefined;
		this.environmentProviderError = undefined;
		let providerId = "REPI environment";
		try {
			const environment = getRepiEnvProviderConfig();
			if (!environment) return;
			providerId = environment.providerName;
			this.environmentProvider = { providerId, config: environment.config };
		} catch (error) {
			this.environmentProviderError = `Provider "${providerId}": ${errorMessage(error)}`;
		}
	}

	private baseProvider(providerId: string): Provider | undefined {
		return this.nativeExtensionProviders.get(providerId) ?? this.baseProviders.get(providerId);
	}

	private recomposeProvider(providerId: string): void {
		const base = this.baseProvider(providerId);
		const extension = this.providerOverlay(providerId);
		if (!base && !this.config.getProvider(providerId) && !extension) {
			this.models.deleteProvider(providerId);
			this.compositionErrors.delete(providerId);
			return;
		}
		if (base && !this.config.getProvider(providerId) && !extension) {
			this.models.setProvider(this.protectProvider(base));
			this.compositionErrors.delete(providerId);
			return;
		}

		try {
			this.models.setProvider(this.protectProvider(composeModelProvider(providerId, base, this.config, extension)));
			this.compositionErrors.delete(providerId);
		} catch (error) {
			this.compositionErrors.set(providerId, errorMessage(error));
			if (base) this.models.setProvider(this.protectProvider(base));
			else this.models.deleteProvider(providerId);
		}
	}

	private rebuildProviders(): void {
		this.models.clearProviders();
		this.compositionErrors.clear();
		for (const providerId of this.providerIds()) this.recomposeProvider(providerId);
		this.updateModelSnapshot();
	}

	private syncExtensionOAuthProviders(): void {
		unregisterOAuthProviders(this.globalRegistrationSource);
		if (this.disposed) return;
		for (const [providerId, config] of this.extensionProviders) {
			if (config.oauth) {
				registerOAuthProvider({ ...config.oauth, id: providerId }, this.globalRegistrationSource);
			}
		}
	}

	private updateModelSnapshot(): void {
		const all = [...this.models.getModels()];
		this.snapshot = {
			...this.snapshot,
			all,
			available: all.filter((model) => this.snapshot.configuredProviders.has(model.provider)),
		};
	}

	private handleCredentialChange(change: CredentialStoreChange): void {
		if (this.disposed) return;
		this.credentialEpoch++;
		const provider = this.models.getProvider(change.providerId);
		const auth = new Map(this.snapshot.auth);
		const configuredProviders = new Set(this.snapshot.configuredProviders);
		const credentialProviders = new Set(this.snapshot.credentialProviders);
		const credentialTypes = new Map(this.snapshot.credentialTypes);

		if (change.credentialType === undefined) {
			credentialProviders.delete(change.providerId);
			credentialTypes.delete(change.providerId);
			auth.delete(change.providerId);
			configuredProviders.delete(change.providerId);

			const configured = configuredRequestAuthStatus(
				this.config.getProvider(change.providerId),
				this.providerOverlay(change.providerId),
			);
			if (configured?.configured && provider?.auth.apiKey) {
				auth.set(change.providerId, {
					type: "api_key",
					source: configured.label ?? configured.source,
				});
				configuredProviders.add(change.providerId);
			}
		} else {
			credentialProviders.add(change.providerId);
			credentialTypes.set(change.providerId, change.credentialType);
			const supported =
				change.credentialType === "api_key" ? Boolean(provider?.auth.apiKey) : Boolean(provider?.auth.oauth);
			if (supported) {
				auth.set(change.providerId, {
					type: change.credentialType,
					source:
						change.source === "runtime"
							? "runtime API key"
							: change.credentialType === "oauth"
								? "OAuth"
								: "stored credential",
				});
				configuredProviders.add(change.providerId);
			} else {
				auth.delete(change.providerId);
				configuredProviders.delete(change.providerId);
			}
		}

		this.snapshot = {
			...this.snapshot,
			auth,
			configuredProviders,
			credentialProviders,
			credentialTypes,
			available: this.snapshot.all.filter((model) => configuredProviders.has(model.provider)),
		};

		void this.queueAvailabilityRefresh(this.availabilityRefresh, this.refreshEpoch, this.credentialEpoch).catch(
			() => {},
		);
	}

	private async runAvailabilityRefresh(epoch: number, credentialEpoch = this.credentialEpoch): Promise<void> {
		if (this.disposed) return;
		const providers = this.models.getProviders();
		const [available, checks, credentials] = await Promise.all([
			this.models.getAvailable(),
			Promise.all(
				providers.map(
					async (provider): Promise<[string, AuthCheck | undefined]> => [
						provider.id,
						await this.models.checkAuth(provider.id),
					],
				),
			),
			this.credentials.list(),
		]);
		const auth = new Map(checks);
		const configuredProviders = new Set(
			checks
				.filter((entry): entry is [string, AuthCheck] => entry[1] !== undefined)
				.map(([providerId]) => providerId),
		);
		if (this.disposed || epoch !== this.refreshEpoch || credentialEpoch !== this.credentialEpoch) return;
		this.snapshot = {
			all: [...this.models.getModels()],
			available: [...available],
			configuredProviders,
			credentialProviders: new Set(credentials.map((entry) => entry.providerId)),
			credentialTypes: new Map(credentials.map((entry) => [entry.providerId, entry.type])),
			auth,
		};
		this.availabilityError = undefined;
	}

	private queueAvailabilityRefresh(
		after: Promise<void> | undefined,
		epoch = this.refreshEpoch,
		credentialEpoch = this.credentialEpoch,
	): Promise<void> {
		if (this.disposed) return Promise.resolve();
		const refresh = (after ?? Promise.resolve())
			.catch(() => {})
			.then(() => this.runAvailabilityRefresh(epoch, credentialEpoch));
		const recorded = refresh.catch((error) => {
			if (epoch === this.refreshEpoch && credentialEpoch === this.credentialEpoch) {
				this.availabilityError = errorMessage(error);
			}
			throw error;
		});
		const tracked = recorded.finally(() => {
			if (this.availabilityRefresh === tracked) this.availabilityRefresh = undefined;
		});
		this.availabilityRefresh = tracked;
		return tracked;
	}

	private refreshAvailability(): Promise<void> {
		return (
			this.availabilityRefresh ?? this.queueAvailabilityRefresh(undefined, this.refreshEpoch, this.credentialEpoch)
		);
	}

	private forceRefreshAvailability(epoch: number): Promise<void> {
		return this.queueAvailabilityRefresh(this.availabilityRefresh, epoch, this.credentialEpoch);
	}

	private refreshInBackground(): void {
		if (this.disposed) return;
		void this.refresh({ allowNetwork: false }).catch(() => {});
	}

	private assertActive(): void {
		if (this.disposed) throw new Error("Model runtime has been disposed");
	}

	getProviders(): readonly Provider[] {
		return this.models.getProviders();
	}

	getProvider(providerId: string): Provider | undefined {
		return this.models.getProvider(providerId);
	}

	getModels(providerId?: string): readonly Model<Api>[] {
		return this.models.getModels(providerId);
	}

	getModel(providerId: string, modelId: string): Model<Api> | undefined {
		return this.models.getModel(providerId, modelId);
	}

	checkAuth(providerId: string): Promise<AuthCheck | undefined> {
		this.assertActive();
		return this.models.checkAuth(providerId);
	}

	async getAvailable(providerId?: string): Promise<readonly Model<Api>[]> {
		this.assertActive();
		if (providerId) {
			if (this.availabilityRefresh) {
				await this.availabilityRefresh;
				return this.snapshot.available.filter((model) => model.provider === providerId);
			}
			try {
				const available = await this.models.getAvailable(providerId);
				return available;
			} catch (error) {
				this.availabilityError = errorMessage(error);
				throw error;
			}
		}
		await this.refreshAvailability();
		return this.snapshot.available;
	}

	getAvailableSnapshot(): readonly Model<Api>[] {
		return this.snapshot.available;
	}

	getError(): string | undefined {
		const errors: string[] = [];
		const configError = this.config.getError();
		if (configError) errors.push(configError);
		for (const [providerId, error] of this.compositionErrors) {
			errors.push(`Provider "${providerId}": ${error}`);
		}
		if (this.environmentProviderError) errors.push(this.environmentProviderError);
		for (const [providerId, error] of this.refreshErrors) {
			errors.push(`Model refresh "${providerId}": ${error.message}`);
		}
		if (this.refreshFailure) errors.push(`Model refresh: ${this.refreshFailure}`);
		if (this.availabilityError) errors.push(`Availability refresh: ${this.availabilityError}`);
		return errors.length > 0 ? errors.join("\n\n") : undefined;
	}

	getRegisteredProviderConfig(providerId: string): ProviderConfigInput | undefined {
		return this.extensionProviders.get(providerId);
	}

	getRegisteredProviderIds(): readonly string[] {
		return [...new Set([...this.extensionProviders.keys(), ...this.nativeExtensionProviders.keys()])];
	}

	getRegisteredNativeProvider(providerId: string): Provider | undefined {
		return this.nativeExtensionProviders.get(providerId);
	}

	/** @internal Compatibility projection for the staged ModelRegistry migration. */
	getCompatibilityRequestConfig(model: Model<Api>): CompatibilityRequestConfig {
		return resolveCompatibilityRequestConfig(
			model,
			this.config.getProvider(model.provider),
			this.providerOverlay(model.provider),
		);
	}

	isUsingOAuth(providerId: string): boolean {
		return this.snapshot.auth.get(providerId)?.type === "oauth";
	}

	hasConfiguredAuth(providerId: string): boolean {
		if (!this.snapshot.configuredProviders.has(providerId)) return false;
		const credentialType = this.snapshot.credentialTypes.get(providerId);
		const provider = this.models.getProvider(providerId);
		if (credentialType === "api_key") return Boolean(provider?.auth.apiKey);
		if (credentialType === "oauth") return Boolean(provider?.auth.oauth);
		return true;
	}

	getAuth(providerId: string, overrides?: ModelRuntimeAuthOverrides): Promise<AuthResult | undefined>;
	getAuth(model: Model<Api>, overrides?: ModelRuntimeAuthOverrides): Promise<AuthResult | undefined>;
	async getAuth(
		providerOrModel: string | Model<Api>,
		overrides: ModelRuntimeAuthOverrides = {},
	): Promise<AuthResult | undefined> {
		this.assertActive();
		if (typeof providerOrModel === "string") return this.models.getAuth(providerOrModel, overrides);
		const resolution = await this.models.getAuth(providerOrModel, overrides);
		if (!resolution) return undefined;
		const configuredHeaders = resolveConfiguredModelHeaders(
			providerOrModel,
			this.config.getProvider(providerOrModel.provider),
			this.providerOverlay(providerOrModel.provider),
			{ ...(resolution.env ?? {}), ...(overrides.env ?? {}) },
		);
		return {
			...resolution,
			auth: {
				...resolution.auth,
				headers: mergeProviderHeaders(resolution.auth.headers, configuredHeaders),
			},
		};
	}

	async setRuntimeApiKey(providerId: string, apiKey: string): Promise<void> {
		this.assertActive();
		this.credentials.setRuntimeApiKey(providerId, apiKey);
		await this.refresh({ allowNetwork: this.allowModelNetwork });
	}

	async removeRuntimeApiKey(providerId: string): Promise<void> {
		this.assertActive();
		this.credentials.removeRuntimeApiKey(providerId);
		await this.refresh({ allowNetwork: this.allowModelNetwork });
	}

	listCredentials(): Promise<readonly CredentialInfo[]> {
		this.assertActive();
		return this.credentials.list();
	}

	getProviderAuthStatus(providerId: string): AuthStatus {
		const provider = this.models.getProvider(providerId);
		if (this.credentials.hasRuntimeApiKey(providerId)) {
			return provider?.auth.apiKey ? { configured: true, source: "runtime" } : { configured: false };
		}
		const credentialType = this.snapshot.credentialTypes.get(providerId);
		if (credentialType === "api_key" && !provider?.auth.apiKey) return { configured: false };
		if (credentialType === "oauth" && !provider?.auth.oauth) return { configured: false };
		const check = this.snapshot.auth.get(providerId);
		if (!check) return { configured: false };
		if (this.snapshot.credentialProviders.has(providerId)) {
			return {
				configured: true,
				source: this.credentials.getCredentialSource(providerId) === "runtime" ? "runtime" : "stored",
			};
		}
		const configured = configuredRequestAuthStatus(
			this.config.getProvider(providerId),
			this.providerOverlay(providerId),
		);
		if (configured?.configured) return configured;
		return { configured: true, source: "environment", label: check.source };
	}

	private async prepareRequest(
		model: Model<Api>,
		options: (StreamOptions & ModelsStreamTransforms) | undefined,
	): Promise<{ provider: Provider; model: Model<Api>; options: StreamOptions }> {
		this.assertActive();
		const provider = this.models.getProvider(model.provider);
		if (!provider) throw new ModelsError("provider", `Unknown provider: ${model.provider}`);
		const resolution = await this.getAuth(model, { apiKey: options?.apiKey, env: options?.env });
		this.assertActive();
		if (!resolution) throw new ModelsError("auth", `Provider is not configured: ${model.provider}`);

		const { transformHeaders, apiKey: _apiKey, ...providerOptions } = options ?? {};
		let headers = mergeProviderHeaders(resolution.auth.headers, providerOptions.headers);
		if (transformHeaders) headers = await transformHeaders(headers ?? {});
		this.assertActive();
		const env =
			resolution.env || providerOptions.env
				? { ...(resolution.env ?? {}), ...(providerOptions.env ?? {}) }
				: undefined;
		const { headers: _consumedModelHeaders, ...modelWithoutHeaders } = model;
		return {
			provider,
			model: {
				...modelWithoutHeaders,
				baseUrl: resolution.auth.baseUrl ?? model.baseUrl,
			} as Model<Api>,
			options: {
				...providerOptions,
				apiKey: resolution.auth.apiKey,
				headers,
				env,
			},
		};
	}

	stream<TApi extends Api>(
		model: Model<TApi>,
		context: Context,
		options?: ModelsApiStreamOptions<TApi>,
	): AssistantMessageEventStream {
		return lazyStream(model, async () => {
			const prepared = await this.prepareRequest(
				model,
				options as (StreamOptions & ModelsStreamTransforms) | undefined,
			);
			this.assertActive();
			return prepared.provider.stream(
				prepared.model as Model<TApi>,
				context,
				prepared.options as ApiStreamOptions<TApi>,
			);
		});
	}

	complete<TApi extends Api>(
		model: Model<TApi>,
		context: Context,
		options?: ModelsApiStreamOptions<TApi>,
	): Promise<AssistantMessage> {
		return this.stream(model, context, options).result();
	}

	streamSimple(model: Model<Api>, context: Context, options?: ModelsSimpleStreamOptions): AssistantMessageEventStream {
		return lazyStream(model, async () => {
			const prepared = await this.prepareRequest(model, options);
			this.assertActive();
			return prepared.provider.streamSimple(prepared.model, context, prepared.options as SimpleStreamOptions);
		});
	}

	completeSimple(model: Model<Api>, context: Context, options?: ModelsSimpleStreamOptions): Promise<AssistantMessage> {
		return this.streamSimple(model, context, options).result();
	}

	async login(providerId: string, type: AuthType, interaction: AuthInteraction): Promise<Credential> {
		this.assertActive();
		const credential = await this.models.login(providerId, type, interaction);
		await this.refresh({ allowNetwork: this.allowModelNetwork });
		return credential;
	}

	async logout(providerId: string): Promise<void> {
		this.assertActive();
		await this.models.logout(providerId);
		if (this.disposed) return;
		this.recomposeProvider(providerId);
		await this.refresh({ allowNetwork: this.allowModelNetwork });
	}

	async reloadConfig(): Promise<void> {
		this.assertActive();
		this.invalidateRefreshEpoch();
		this.restoreLiveProviders();
		const config = await ModelConfig.load(this.modelsPath);
		if (this.disposed) return;
		this.config = config;
		this.reloadEnvironmentProvider();
		this.rebuildProviders();
		this.syncExtensionOAuthProviders();
		await this.refresh({ allowNetwork: this.allowModelNetwork });
	}

	async refresh(options: ModelsRefreshOptions = {}): Promise<ModelsRefreshResult> {
		if (this.disposed) return { aborted: true, errors: new Map() };
		this.restoreLiveProviders();
		const epoch = ++this.refreshEpoch;
		const operationController = new AbortController();
		const externalSignal = options.signal;
		const abortOperation = () => operationController.abort(externalSignal?.reason);
		if (externalSignal?.aborted) abortOperation();
		else externalSignal?.addEventListener("abort", abortOperation, { once: true });
		const refreshOptions: ModelsRefreshOptions = {
			...options,
			allowNetwork: options.allowNetwork ?? this.allowModelNetwork,
			signal: operationController.signal,
		};
		this.refreshEpochBySignal.set(operationController.signal, epoch);
		this.refreshControllers.add(operationController);
		let result: ModelsRefreshResult;
		try {
			result = await this.models.refresh(refreshOptions);
		} catch (error) {
			if (epoch === this.refreshEpoch && !operationController.signal.aborted) {
				this.refreshFailure = errorMessage(error);
			}
			throw error;
		} finally {
			this.refreshEpochBySignal.delete(operationController.signal);
			this.refreshControllers.delete(operationController);
			externalSignal?.removeEventListener("abort", abortOperation);
		}
		if (this.disposed || epoch !== this.refreshEpoch || result.aborted) return result;
		this.refreshErrors = new Map(result.errors);
		this.refreshFailure = undefined;
		this.updateModelSnapshot();
		try {
			await this.forceRefreshAvailability(epoch);
		} catch {
			// The precise failure remains available through getError().
		}
		return result;
	}

	registerNativeProvider(provider: Provider): void {
		this.assertActive();
		if (typeof provider.id !== "string" || !provider.id.trim()) {
			throw new Error("Provider id must not be empty.");
		}
		this.invalidateRefreshEpoch();
		this.restoreLiveProviders();
		this.extensionProviders.delete(provider.id);
		this.nativeExtensionProviders.set(provider.id, provider);
		this.syncExtensionOAuthProviders();
		this.recomposeProvider(provider.id);
		this.updateModelSnapshot();
		this.refreshInBackground();
	}

	registerProvider(providerId: string, config: ProviderConfigInput): void {
		this.assertActive();
		this.registerProviderConfig(providerId, config, true);
	}

	private registerProviderConfig(providerId: string, config: ProviderConfigInput, scheduleRefresh: boolean): void {
		if (typeof providerId !== "string" || !providerId.trim()) {
			throw new Error("Provider id must not be empty.");
		}
		if (scheduleRefresh) {
			this.invalidateRefreshEpoch();
			this.restoreLiveProviders();
		}
		const previous = this.extensionProviders.get(providerId);
		const effective: ProviderConfigInput = { ...previous };
		for (const [key, value] of Object.entries(config)) {
			if (value !== undefined) (effective as Record<string, unknown>)[key] = value;
		}
		const environment =
			this.environmentProvider?.providerId === providerId ? this.environmentProvider.config : undefined;
		const effectiveOverlay: ProviderConfigInput = { ...environment, ...effective };
		validateExtensionProvider(
			providerId,
			this.baseProviders.get(providerId),
			this.config.getProvider(providerId),
			effectiveOverlay,
		);
		this.nativeExtensionProviders.delete(providerId);
		this.extensionProviders.set(providerId, effective);
		this.syncExtensionOAuthProviders();
		this.recomposeProvider(providerId);
		this.updateModelSnapshot();

		const provider = this.models.getProvider(providerId);
		const credentialType = this.snapshot.credentialTypes.get(providerId);
		const compatibleCredential =
			credentialType === "api_key"
				? Boolean(provider?.auth.apiKey)
				: credentialType === "oauth"
					? Boolean(provider?.auth.oauth)
					: false;
		const configured = configuredRequestAuthStatus(this.config.getProvider(providerId), effectiveOverlay);
		if (compatibleCredential || (!credentialType && configured?.configured)) {
			const configuredProviders = new Set(this.snapshot.configuredProviders).add(providerId);
			const auth = new Map(this.snapshot.auth);
			if (!auth.get(providerId)) {
				auth.set(providerId, {
					type: effective.oauth && !effective.apiKey ? "oauth" : "api_key",
					source: "configured provider",
				});
			}
			this.snapshot = {
				...this.snapshot,
				auth,
				configuredProviders,
				available: this.snapshot.all.filter((model) => configuredProviders.has(model.provider)),
			};
		} else if (credentialType && !compatibleCredential) {
			const auth = new Map(this.snapshot.auth);
			auth.delete(providerId);
			const configuredProviders = new Set(this.snapshot.configuredProviders);
			configuredProviders.delete(providerId);
			this.snapshot = {
				...this.snapshot,
				auth,
				configuredProviders,
				available: this.snapshot.all.filter((model) => configuredProviders.has(model.provider)),
			};
		}
		if (scheduleRefresh) this.refreshInBackground();
	}

	unregisterProvider(providerId: string): void {
		this.assertActive();
		this.invalidateRefreshEpoch();
		this.restoreLiveProviders();
		this.extensionProviders.delete(providerId);
		this.nativeExtensionProviders.delete(providerId);
		this.syncExtensionOAuthProviders();
		this.recomposeProvider(providerId);
		this.updateModelSnapshot();
		this.refreshInBackground();
	}
}

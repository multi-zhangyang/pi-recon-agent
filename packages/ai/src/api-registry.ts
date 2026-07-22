import type {
	Api,
	AssistantMessageEventStream,
	Context,
	Model,
	SimpleStreamOptions,
	StreamFunction,
	StreamOptions,
} from "./types.ts";

export type ApiStreamFunction = (
	model: Model<Api>,
	context: Context,
	options?: StreamOptions,
) => AssistantMessageEventStream;

export type ApiStreamSimpleFunction = (
	model: Model<Api>,
	context: Context,
	options?: SimpleStreamOptions,
) => AssistantMessageEventStream;

export interface ApiProvider<TApi extends Api = Api, TOptions extends StreamOptions = StreamOptions> {
	api: TApi;
	stream: StreamFunction<TApi, TOptions>;
	streamSimple: StreamFunction<TApi, SimpleStreamOptions>;
}

interface ApiProviderInternal {
	api: Api;
	stream: ApiStreamFunction;
	streamSimple: ApiStreamSimpleFunction;
}

type RegisteredApiProvider = {
	provider: ApiProviderInternal;
	sourceId?: string;
};

const apiProviderRegistry = new Map<string, RegisteredApiProvider[]>();

function activeApiProvider(entries: readonly RegisteredApiProvider[] | undefined): RegisteredApiProvider | undefined {
	return entries?.[entries.length - 1];
}

function wrapStream<TApi extends Api, TOptions extends StreamOptions>(
	api: TApi,
	stream: StreamFunction<TApi, TOptions>,
): ApiStreamFunction {
	return (model, context, options) => {
		if (model.api !== api) {
			throw new Error(`Mismatched api: ${model.api} expected ${api}`);
		}
		return stream(model as Model<TApi>, context, options as TOptions);
	};
}

function wrapStreamSimple<TApi extends Api>(
	api: TApi,
	streamSimple: StreamFunction<TApi, SimpleStreamOptions>,
): ApiStreamSimpleFunction {
	return (model, context, options) => {
		if (model.api !== api) {
			throw new Error(`Mismatched api: ${model.api} expected ${api}`);
		}
		return streamSimple(model as Model<TApi>, context, options);
	};
}

export function registerApiProvider<TApi extends Api, TOptions extends StreamOptions>(
	provider: ApiProvider<TApi, TOptions>,
	sourceId?: string,
): void {
	registerApiProviderEntry(provider, sourceId, false);
}

/** Register a fallback layer that remains below existing overrides for the same API. */
export function registerFallbackApiProvider<TApi extends Api, TOptions extends StreamOptions>(
	provider: ApiProvider<TApi, TOptions>,
	sourceId?: string,
): void {
	registerApiProviderEntry(provider, sourceId, true);
}

function registerApiProviderEntry<TApi extends Api, TOptions extends StreamOptions>(
	provider: ApiProvider<TApi, TOptions>,
	sourceId: string | undefined,
	fallback: boolean,
): void {
	const registered: RegisteredApiProvider = {
		provider: {
			api: provider.api,
			stream: wrapStream(provider.api, provider.stream),
			streamSimple: wrapStreamSimple(provider.api, provider.streamSimple),
		},
		sourceId,
	};
	const entries = apiProviderRegistry.get(provider.api) ?? [];
	const retained = entries.filter((entry) => entry.sourceId !== sourceId);
	apiProviderRegistry.set(provider.api, fallback ? [registered, ...retained] : [...retained, registered]);
}

export function getApiProvider(api: Api): ApiProviderInternal | undefined {
	return activeApiProvider(apiProviderRegistry.get(api))?.provider;
}

export function getApiProviders(): ApiProviderInternal[] {
	return Array.from(apiProviderRegistry.values(), (entries) => activeApiProvider(entries)?.provider).filter(
		(provider): provider is ApiProviderInternal => provider !== undefined,
	);
}

export function unregisterApiProviders(sourceId: string): void {
	for (const [api, entries] of apiProviderRegistry.entries()) {
		const retained = entries.filter((entry) => entry.sourceId !== sourceId);
		if (retained.length > 0) apiProviderRegistry.set(api, retained);
		else apiProviderRegistry.delete(api);
	}
}

export function clearApiProviders(): void {
	apiProviderRegistry.clear();
}

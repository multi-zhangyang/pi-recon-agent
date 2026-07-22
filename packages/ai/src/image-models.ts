import type { ImagesApi, ImagesModel, ImagesProvider } from "./types.ts";

/**
 * Optional process-local image catalog for hosts that explicitly provide one.
 * REPI does not populate this registry from a generated model file.
 */
const imageModelRegistry: Map<string, Map<string, ImagesModel<ImagesApi>>> = new Map();

export type ExternalImageModelCatalog = Readonly<Record<string, Readonly<Record<string, ImagesModel<ImagesApi>>>>>;

export function registerImageModelCatalog(
	catalog: ExternalImageModelCatalog,
	options: { replace?: boolean } = {},
): void {
	if (options.replace !== false) imageModelRegistry.clear();
	for (const [provider, models] of Object.entries(catalog)) {
		const providerModels = imageModelRegistry.get(provider) ?? new Map<string, ImagesModel<ImagesApi>>();
		for (const [id, model] of Object.entries(models)) providerModels.set(id, model);
		imageModelRegistry.set(provider, providerModels);
	}
}

export function clearImageModelCatalog(): void {
	imageModelRegistry.clear();
}

export function getImageModel<TApi extends ImagesApi = ImagesApi>(
	provider: string,
	modelId: string,
): ImagesModel<TApi> {
	return imageModelRegistry.get(provider)?.get(modelId) as ImagesModel<TApi>;
}

export function getImageProviders(): ImagesProvider[] {
	return Array.from(imageModelRegistry.keys());
}

export function getImageModels<TApi extends ImagesApi = ImagesApi>(provider: string): ImagesModel<TApi>[] {
	const models = imageModelRegistry.get(provider);
	return models ? (Array.from(models.values()) as ImagesModel<TApi>[]) : [];
}
